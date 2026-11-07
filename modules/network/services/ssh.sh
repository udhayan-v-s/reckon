#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# SSH Enumeration Module (modules/network/services/ssh.sh)
#
# Performs comprehensive SSH service reconnaissance: identification banner
# grabbing, protocol version verification, public host key extraction
# (RSA, ECDSA, ED25519), and cryptographic auditing of key exchange,
# cipher, and MAC algorithms for deprecated or insecure configurations.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - ssh_banner.txt (raw SSH identification banner)
#   - ssh_host_keys.txt (extracted public host keys)
#   - ssh_ciphers.txt (supported cryptographic algorithms)
#   - nmap_ssh_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: ssh2-enum-algos, ssh-hostkey, ssh-auth-methods)
#   - ssh-keyscan (public host key extraction)
#   - ssh-audit (optional advanced cryptographic auditor)
#   - nc (lightweight raw banner grabber)
#

set -o nounset

SSH_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$SSH_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
SSH_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
SSH_KEYSCAN_BIN="${RECKON_MOCK_KEYSCAN_BIN:-ssh-keyscan}"
SSH_AUDIT_BIN="${RECKON_MOCK_AUDIT_BIN:-ssh-audit}"

# Main module execution function.
ssh_main() {
    # Initialize execution context using service common library.
    if ! svc_mod_init "$@"; then
        return 1
    fi

    # Resolve target SSH ports from upstream artifacts or defaults.
    if ! svc_mod_resolve_ports "ssh" "22" "ssh"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "ssh" "SSH Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${SSH_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "ssh" "SSH Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local keyscan_available=false
    local audit_available=false
    local tools_used=()

    tools_used+=("nmap")
    if net_mod_has_tool "$SSH_KEYSCAN_BIN"; then
        keyscan_available=true
        tools_used+=("ssh-keyscan")
    fi
    if net_mod_has_tool "$SSH_AUDIT_BIN"; then
        audit_available=true
        tools_used+=("ssh-audit")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "ssh" "SSH Enumeration" "$tools_str"

    # Artifact destinations.
    local banner_file="${NET_TASK_DIR}/ssh_banner.txt"
    local hostkeys_file="${NET_TASK_DIR}/ssh_host_keys.txt"
    local ciphers_file="${NET_TASK_DIR}/ssh_ciphers.txt"
    : > "$banner_file"
    : > "$hostkeys_file"
    : > "$ciphers_file"

    local total_findings=0

    # Iterate over all resolved SSH ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: SSH Service Interrogation"

        # ---------------------------------------------------------------------
        # 1. Identification Banner Acquisition
        # ---------------------------------------------------------------------
        local raw_banner=""
        raw_banner="$(svc_mod_banner_grab "$SVC_TARGET" "$port" 3)"

        local proto_ver="Unknown"
        local sw_ver="Unknown"
        local os_platform="Unknown"

        if [[ -n "$raw_banner" ]]; then
            printf 'Port %s: %s\n' "$port" "$raw_banner" >> "$banner_file"
            net_mod_write_kv "Identification Banner" "$raw_banner"

            # Parse SSH-proto-software comments
            if [[ "$raw_banner" =~ ^SSH-([0-9.]+)-([^[:space:]]+)[[:space:]]*(.*)$ ]]; then
                proto_ver="SSH-${BASH_REMATCH[1]}"
                sw_ver="${BASH_REMATCH[2]}"
                local extra="${BASH_REMATCH[3]}"
                if [[ -n "$extra" ]]; then
                    os_platform="$extra"
                fi
            fi

            net_mod_write_kv "Protocol Version" "$proto_ver"
            net_mod_write_kv "Software Identity" "$sw_ver"
            if [[ "$os_platform" != "Unknown" ]]; then
                net_mod_write_kv "Reported Platform" "$os_platform"
            fi

            # Check for legacy SSHv1 vulnerability
            if [[ "$proto_ver" == *"1."* || "$proto_ver" == *"1.99"* ]]; then
                (( total_findings += 1 ))
                net_mod_write_raw "  [SECURITY WARN] Legacy protocol version detected ($proto_ver) - vulnerable to MITM."
            fi
        else
            net_mod_write_kv "Identification Banner" "None (no response received)"
        fi

        # ---------------------------------------------------------------------
        # 2. Host Key Collection via ssh-keyscan
        # ---------------------------------------------------------------------
        if [[ "$keyscan_available" == true ]]; then
            local keyscan_tmp="${NET_TASK_DIR}/keyscan_${port}.tmp"
            "$SSH_KEYSCAN_BIN" -p "$port" -T 5 "$SVC_TARGET" > "$keyscan_tmp" 2>/dev/null || true
            if [[ -s "$keyscan_tmp" ]]; then
                cat "$keyscan_tmp" >> "$hostkeys_file"
            fi
            rm -f "$keyscan_tmp"
        fi

        # ---------------------------------------------------------------------
        # 3. Cryptographic Auditing & Host Key Fingerprinting via Nmap NSE
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_ssh_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "--script" "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local -a kex_list=()
        local -a cipher_list=()
        local -a mac_list=()
        local -a hostkeys_parsed=()
        local -a auth_methods=()
        local -a security_warnings=()

        if [[ -f "$nmap_out" ]]; then
            local cur_section=""
            local line

            while IFS= read -r line || [[ -n "$line" ]]; do
                local clean_line="${line#|}"
                clean_line="${clean_line#_}"
                clean_line="${clean_line#"${clean_line%%[![:space:]]*}"}" # trim leading whitespace

                case "$clean_line" in
                    "kex_algorithms:"*) cur_section="kex"; continue ;;
                    "server_host_key_algorithms:"*) cur_section="hostkey_algos"; continue ;;
                    "encryption_algorithms:"*) cur_section="ciphers"; continue ;;
                    "mac_algorithms:"*) cur_section="macs"; continue ;;
                    "compression_algorithms:"*) cur_section="comp"; continue ;;
                    "ssh-hostkey:"*) cur_section="hostkeys"; continue ;;
                    "ssh-auth-methods:"*|"Supported authentication methods:"*) cur_section="auth"; continue ;;
                esac

                case "$cur_section" in
                    kex)
                        if [[ "$clean_line" =~ ^[a-zA-Z0-9@_.-]+$ ]]; then
                            kex_list+=("$clean_line")
                            if [[ "$clean_line" == *"group1-sha1"* || "$clean_line" == *"group-exchange-sha1"* ]]; then
                                security_warnings+=("KEX: $clean_line (weak SHA-1 / small DH group)")
                            fi
                        fi
                        ;;
                    ciphers)
                        if [[ "$clean_line" =~ ^[a-zA-Z0-9@_.-]+$ ]]; then
                            cipher_list+=("$clean_line")
                            if [[ "$clean_line" == *"3des"* || "$clean_line" == *"arcfour"* || "$clean_line" == *"cbc"* ]]; then
                                security_warnings+=("Cipher: $clean_line (weak / CBC mode)")
                            fi
                        fi
                        ;;
                    macs)
                        if [[ "$clean_line" =~ ^[a-zA-Z0-9@_.-]+$ ]]; then
                            mac_list+=("$clean_line")
                            if [[ "$clean_line" == *"md5"* || "$clean_line" == *"96"* ]]; then
                                security_warnings+=("MAC: $clean_line (insecure MD5 / truncated 96-bit MAC)")
                            fi
                        fi
                        ;;
                    hostkeys)
                        if [[ "$clean_line" =~ ^([0-9]+)[[:space:]]+([^[:space:]]+)[[:space:]]+\(([a-zA-Z0-9_-]+)\) ]]; then
                            hostkeys_parsed+=("${BASH_REMATCH[3]} (${BASH_REMATCH[1]} bits): ${BASH_REMATCH[2]}")
                        fi
                        ;;
                    auth)
                        if [[ "$clean_line" == "publickey" || "$clean_line" == "password" || "$clean_line" == "keyboard-interactive" ]]; then
                            auth_methods+=("$clean_line")
                        fi
                        ;;
                esac
            done < "$nmap_out"
        fi

        # Document Host Keys
        if (( ${#hostkeys_parsed[@]} > 0 )); then
            net_mod_write_raw ""
            net_mod_write_raw "  Discovered Host Public Keys:"
            local hk
            for hk in "${hostkeys_parsed[@]}"; do
                net_mod_write_raw "    - $hk"
            done
        fi

        # Document Cryptographic Algorithms
        if (( ${#kex_list[@]} > 0 || ${#cipher_list[@]} > 0 )); then
            net_mod_write_raw ""
            net_mod_write_raw "  Cryptographic Algorithm Configuration:"
            if (( ${#auth_methods[@]} > 0 )); then
                local IFS=', '
                net_mod_write_raw "    Authentication Methods: ${auth_methods[*]}"
            fi
            if (( ${#kex_list[@]} > 0 )); then
                local IFS=', '
                net_mod_write_raw "    Key Exchange (KEX)    : ${kex_list[*]}"
                printf 'Port %s KEX: %s\n' "$port" "${kex_list[*]}" >> "$ciphers_file"
            fi
            if (( ${#cipher_list[@]} > 0 )); then
                local IFS=', '
                net_mod_write_raw "    Encryption Ciphers    : ${cipher_list[*]}"
                printf 'Port %s Ciphers: %s\n' "$port" "${cipher_list[*]}" >> "$ciphers_file"
            fi
            if (( ${#mac_list[@]} > 0 )); then
                local IFS=', '
                net_mod_write_raw "    MAC Algorithms        : ${mac_list[*]}"
                printf 'Port %s MACs: %s\n' "$port" "${mac_list[*]}" >> "$ciphers_file"
            fi
        fi

        # Document Security Findings
        if (( ${#security_warnings[@]} > 0 )); then
            (( total_findings += ${#security_warnings[@]} ))
            net_mod_write_raw ""
            net_mod_write_raw "  Cryptographic Security Weaknesses:"
            local w
            for w in "${security_warnings[@]}"; do
                net_mod_write_raw "    [WARN] $w"
            done
        fi

        # 4. Optional advanced audit via ssh-audit if available.
        if [[ "$audit_available" == true ]]; then
            local audit_out="${NET_TASK_DIR}/ssh_audit_${port}.txt"
            "$SSH_AUDIT_BIN" -p "$port" "$SVC_TARGET" > "$audit_out" 2>/dev/null || true
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "SSH audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "SSH audit completed. No insecure algorithms identified."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ssh_main "$@"
fi
