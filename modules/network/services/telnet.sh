#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Telnet Enumeration Module (modules/network/services/telnet.sh)
#
# Interrogates legacy Telnet services: banner grabbing, protocol option
# inspection, login prompt detection, encryption support verification,
# and NTLM authentication information disclosure auditing.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - telnet_banner.txt (raw Telnet welcome banner and login prompts)
#   - nmap_telnet_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: telnet-encryption, telnet-ntlm-info)
#   - nc (raw socket connection and banner acquisition)
#

set -o nounset

TELNET_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$TELNET_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
TELNET_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
TELNET_NC_BIN="${RECKON_MOCK_NC_BIN:-nc}"

# Main module execution function.
telnet_main() {
    # Initialize execution context using service common library.
    if ! svc_mod_init "$@"; then
        return 1
    fi

    # Resolve target Telnet ports from upstream artifacts or defaults.
    if ! svc_mod_resolve_ports "telnet" "23" "telnet"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "telnet" "Telnet Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${TELNET_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "telnet" "Telnet Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local tools_used=()
    tools_used+=("nmap")
    if net_mod_has_tool "$TELNET_NC_BIN"; then
        tools_used+=("nc")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "telnet" "Telnet Enumeration" "$tools_str"

    local banner_file="${NET_TASK_DIR}/telnet_banner.txt"
    : > "$banner_file"

    local total_findings=0

    # Iterate over all resolved Telnet ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: Telnet Service Interrogation"

        # ---------------------------------------------------------------------
        # 1. Raw Banner & Welcome Message Acquisition
        # ---------------------------------------------------------------------
        local raw_banner=""
        raw_banner="$(svc_mod_banner_grab "$SVC_TARGET" "$port" 3)"

        if [[ -n "$raw_banner" ]]; then
            printf '=== Port %s Banner ===\n%s\n\n' "$port" "$raw_banner" >> "$banner_file"
            net_mod_write_raw "  Discovered Welcome Banner:"
            local b_line
            while IFS= read -r b_line || [[ -n "$b_line" ]]; do
                net_mod_write_raw "    $b_line"
            done <<< "$raw_banner"

            # Check for extracted system hints
            if [[ "$raw_banner" == *"login:"* || "$raw_banner" == *"Username:"* || "$raw_banner" == *"Password:"* ]]; then
                net_mod_write_raw ""
                net_mod_write_raw "  Service State            : Interactive login prompt detected."
            fi
            if [[ "$raw_banner" =~ (Linux|Ubuntu|Debian|FreeBSD|Cisco|MikroTik|Solaris|Windows) ]]; then
                net_mod_write_raw "  Extracted System Hint    : ${BASH_REMATCH[1]}"
            fi
        else
            net_mod_write_kv "Discovered Banner" "None (no response received upon connection)"
        fi

        # ---------------------------------------------------------------------
        # 2. Nmap NSE Script Probing (Encryption & NTLM Info)
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_telnet_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "-sV"
            "--script" "telnet-encryption,telnet-ntlm-info"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local encryption_supported=false
        local ntlm_domain=""
        local ntlm_server=""
        local ntlm_dns=""

        if [[ -f "$nmap_out" ]]; then
            while IFS= read -r line || [[ -n "$line" ]]; do
                if [[ "$line" == *"telnet-encryption:"* && "$line" != *"not supported"* ]]; then
                    encryption_supported=true
                fi
                if [[ "$line" == *"Target_Name: "* ]]; then
                    ntlm_domain="${line#*Target_Name: }"
                fi
                if [[ "$line" == *"NetBIOS_Server_Name: "* ]]; then
                    ntlm_server="${line#*NetBIOS_Server_Name: }"
                fi
                if [[ "$line" == *"DNS_Domain_Name: "* ]]; then
                    ntlm_dns="${line#*DNS_Domain_Name: }"
                fi
            done < "$nmap_out"
        fi

        # Document Protocol Security Evaluation
        net_mod_write_raw ""
        net_mod_write_raw "  Protocol Security Evaluation:"
        if [[ "$encryption_supported" == true ]]; then
            net_mod_write_raw "    Encryption Status      : Supported (telnet-encryption option negotiated)."
        else
            (( total_findings += 1 ))
            net_mod_write_raw "    Encryption Status      : Not Supported (Cleartext Transmission)."
            net_mod_write_raw "    [SECURITY RISK] Cleartext Protocol: Authentication credentials, commands, and data"
            net_mod_write_raw "                    are transmitted unencrypted and vulnerable to network interception."
        fi

        if [[ -n "$ntlm_domain" || -n "$ntlm_server" || -n "$ntlm_dns" ]]; then
            (( total_findings += 1 ))
            net_mod_write_raw ""
            net_mod_write_raw "  NTLM Information Disclosure:"
            [[ -n "$ntlm_domain" ]] && net_mod_write_raw "    Target Domain          : $ntlm_domain"
            [[ -n "$ntlm_server" ]] && net_mod_write_raw "    Server NetBIOS Name    : $ntlm_server"
            [[ -n "$ntlm_dns" ]] && net_mod_write_raw "    DNS Domain Name        : $ntlm_dns"
            net_mod_write_raw "    [SECURITY NOTICE] Internal infrastructure naming leaked via NTLM challenge."
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "Telnet audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "Telnet audit completed."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    telnet_main "$@"
fi
