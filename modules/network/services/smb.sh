#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# SMB Enumeration Module (modules/network/services/smb.sh)
#
# Interrogates Server Message Block / CIFS file sharing services:
# operating system identification, NetBIOS/domain infrastructure discovery,
# SMB message signing security evaluation (relay vulnerability check),
# and share enumeration including anonymous/null-session access audits.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - smb_os.txt (extracted operating system, computer, and domain info)
#   - smb_shares.txt (enumerated network shares and access permissions)
#   - smb_security.txt (SMB security mode and message signing status)
#   - nmap_smb_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: smb-os-discovery, smb-security-mode, smb2-security-mode, smb-enum-shares, smb2-time)
#   - smbclient (share listing and null-session access client)
#   - enum4linux-ng (optional advanced SMB/RPC interrogator)
#

set -o nounset

SMB_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$SMB_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
SMB_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
SMB_SMBCLIENT_BIN="${RECKON_MOCK_SMBCLIENT_BIN:-smbclient}"
SMB_ENUM4LINUX_BIN="${RECKON_MOCK_ENUM4LINUX_BIN:-enum4linux-ng}"

# Main module execution function.
smb_main() {
    # Initialize execution context using service common library.
    if ! svc_mod_init "$@"; then
        return 1
    fi

    # Resolve target SMB ports from upstream artifacts or defaults (445, 139).
    if ! svc_mod_resolve_ports "smb" "445,139" "(microsoft-ds|netbios-ssn|smb)"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "smb" "SMB Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${SMB_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "smb" "SMB Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local smbclient_available=false
    local enum4linux_available=false
    local tools_used=()

    tools_used+=("nmap")
    if net_mod_has_tool "$SMB_SMBCLIENT_BIN"; then
        smbclient_available=true
        tools_used+=("smbclient")
    fi
    if net_mod_has_tool "$SMB_ENUM4LINUX_BIN"; then
        enum4linux_available=true
        tools_used+=("enum4linux-ng")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "smb" "SMB Enumeration" "$tools_str"

    local os_file="${NET_TASK_DIR}/smb_os.txt"
    local shares_file="${NET_TASK_DIR}/smb_shares.txt"
    local security_file="${NET_TASK_DIR}/smb_security.txt"
    : > "$os_file"
    : > "$shares_file"
    : > "$security_file"

    local total_findings=0

    # Iterate over all resolved SMB ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: SMB Service Interrogation"

        # ---------------------------------------------------------------------
        # 1. Nmap NSE SMB Interrogation
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_smb_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "--script" "smb-os-discovery,smb-security-mode,smb2-security-mode,smb-enum-shares,smb2-time"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local os_detected=""
        local comp_name=""
        local netbios_name=""
        local domain_name=""
        local fqdn=""
        local sys_time=""

        local signing_required=false
        local signing_evaluated=false
        local signing_raw=""

        local cur_share=""
        local cur_share_type=""
        local cur_share_comment=""
        local cur_share_anon="<none>"
        local in_shares_block=false
        local -a shares_list=()
        local -a anon_accessible_shares=()

        if [[ -f "$nmap_out" ]]; then
            local line
            while IFS= read -r line || [[ -n "$line" ]]; do
                local clean_line="${line#|}"
                clean_line="${clean_line#_}"
                clean_line="${clean_line#"${clean_line%%[![:space:]]*}"}" # trim leading whitespace

                # --- Section 1: OS & Host Discovery ---
                if [[ "$clean_line" =~ ^OS:[[:space:]]*(.*)$ ]]; then
                    os_detected="${BASH_REMATCH[1]}"
                elif [[ "$clean_line" =~ ^Computer[[:space:]]+name:[[:space:]]*(.*)$ ]]; then
                    comp_name="${BASH_REMATCH[1]}"
                elif [[ "$clean_line" =~ ^NetBIOS[[:space:]]+computer[[:space:]]+name:[[:space:]]*(.*)$ ]]; then
                    netbios_name="${BASH_REMATCH[1]}"
                    # Strip hex suffix e.g. \x00
                    netbios_name="${netbios_name%%\\*}"
                elif [[ "$clean_line" =~ ^(Domain[[:space:]]+name|Workgroup):[[:space:]]*(.*)$ ]]; then
                    domain_name="${BASH_REMATCH[2]}"
                    domain_name="${domain_name%%\\*}"
                elif [[ "$clean_line" =~ ^FQDN:[[:space:]]*(.*)$ ]]; then
                    fqdn="${BASH_REMATCH[1]}"
                elif [[ "$clean_line" =~ ^System[[:space:]]+time:[[:space:]]*(.*)$ ]]; then
                    sys_time="${BASH_REMATCH[1]}"
                fi

                # --- Section 2: Security Mode & SMB Signing ---
                if [[ "$clean_line" == *"message_signing:"* || "$clean_line" == *"Message signing"* ]]; then
                    signing_evaluated=true
                    signing_raw="$clean_line"
                    if [[ "$clean_line" == *"disabled"* || "$clean_line" == *"enabled but not required"* || "$clean_line" == *"not required"* ]]; then
                        signing_required=false
                    elif [[ "$clean_line" == *"required"* ]]; then
                        signing_required=true
                    fi
                fi

                # --- Section 3: Share Enumeration ---
                if [[ "$line" == *"smb-enum-shares:"* ]]; then
                    in_shares_block=true
                    continue
                fi

                if [[ "$in_shares_block" == true ]]; then
                    # Check for share name header e.g. "  \\192.168.1.1\Public:" or "  \\192.168.1.1\ADMIN$:"
                    if [[ "$line" =~ ^\|[[:space:]]+\\\\([^\\:]+)\\([^:]+): ]]; then
                        # Save previous share if present
                        if [[ -n "$cur_share" ]]; then
                            shares_list+=("$cur_share|$cur_share_type|$cur_share_comment|$cur_share_anon")
                            if [[ "$cur_share_anon" == *"READ"* || "$cur_share_anon" == *"WRITE"* ]]; then
                                anon_accessible_shares+=("$cur_share ($cur_share_anon)")
                            fi
                        fi
                        cur_share="${BASH_REMATCH[2]}"
                        cur_share_type="Unknown"
                        cur_share_comment=""
                        cur_share_anon="<none>"
                        continue
                    elif [[ "$line" =~ ^[a-zA-Z0-9|_-]+: ]] && [[ "$line" != *"smb-enum-shares:"* ]]; then
                        in_shares_block=false
                    fi

                    if [[ "$clean_line" =~ ^Type:[[:space:]]*(.*)$ ]]; then
                        cur_share_type="${BASH_REMATCH[1]}"
                    elif [[ "$clean_line" =~ ^Comment:[[:space:]]*(.*)$ ]]; then
                        cur_share_comment="${BASH_REMATCH[1]}"
                    elif [[ "$clean_line" =~ ^Anonymous[[:space:]]+access:[[:space:]]*(.*)$ ]]; then
                        cur_share_anon="${BASH_REMATCH[1]}"
                    fi
                fi
            done < "$nmap_out"

            # Flush last share
            if [[ -n "$cur_share" ]]; then
                shares_list+=("$cur_share|$cur_share_type|$cur_share_comment|$cur_share_anon")
                if [[ "$cur_share_anon" == *"READ"* || "$cur_share_anon" == *"WRITE"* ]]; then
                    anon_accessible_shares+=("$cur_share ($cur_share_anon)")
                fi
            fi
        fi

        # ---------------------------------------------------------------------
        # 2. smbclient Share Discovery (Supplementary / Fallback)
        # ---------------------------------------------------------------------
        if [[ "$smbclient_available" == true ]]; then
            local smbclient_out="${NET_TASK_DIR}/smbclient_${port}.tmp"
            "$SMB_SMBCLIENT_BIN" -N -L "//$SVC_TARGET" -p "$port" > "$smbclient_out" 2>/dev/null || true
            if [[ -s "$smbclient_out" ]]; then
                local in_share_table=false
                local smb_line
                while IFS= read -r smb_line || [[ -n "$smb_line" ]]; do
                    if [[ "$smb_line" =~ ^[[:space:]]*Sharename[[:space:]]+Type[[:space:]]+Comment ]]; then
                        in_share_table=true
                        continue
                    elif [[ "$smb_line" =~ ^[[:space:]]*--- ]]; then
                        continue
                    elif [[ "$smb_line" =~ ^[[:space:]]*SMB1 ]]; then
                        in_share_table=false
                    fi

                    if [[ "$in_share_table" == true ]]; then
                        if [[ "$smb_line" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]+([A-Za-z]+)[[:space:]]*(.*)$ ]]; then
                            local sc_name="${BASH_REMATCH[1]}"
                            local sc_type="${BASH_REMATCH[2]}"
                            local sc_comment="${BASH_REMATCH[3]}"

                            # Check if share already parsed
                            local already_found=false
                            local sh
                            for sh in "${shares_list[@]}"; do
                                if [[ "$sh" == "$sc_name|"* ]]; then
                                    already_found=true
                                    break
                                fi
                            done
                            if [[ "$already_found" == false && "$sc_name" != "Reconnecting" && "$sc_name" != "Server" ]]; then
                                shares_list+=("$sc_name|$sc_type|$sc_comment|<untested>")
                            fi
                        fi
                    fi
                done < "$smbclient_out"
            fi
            rm -f "$smbclient_out"
        fi

        # ---------------------------------------------------------------------
        # 3. Document Findings in Artifacts and Report
        # ---------------------------------------------------------------------

        # Record Operating System & Infrastructure Details
        if [[ -n "$os_detected" || -n "$comp_name" || -n "$domain_name" ]]; then
            net_mod_write_raw "  Infrastructure & OS Identification:"
            [[ -n "$os_detected" ]] && net_mod_write_kv "OS Version" "$os_detected"
            [[ -n "$comp_name" ]] && net_mod_write_kv "Computer Name" "$comp_name"
            [[ -n "$netbios_name" && "$netbios_name" != "$comp_name" ]] && net_mod_write_kv "NetBIOS Name" "$netbios_name"
            [[ -n "$domain_name" ]] && net_mod_write_kv "Domain / Workgroup" "$domain_name"
            [[ -n "$fqdn" ]] && net_mod_write_kv "FQDN" "$fqdn"
            [[ -n "$sys_time" ]] && net_mod_write_kv "System Clock" "$sys_time"

            {
                printf 'Port %s Infrastructure:\n' "$port"
                [[ -n "$os_detected" ]] && printf '  OS: %s\n' "$os_detected"
                [[ -n "$comp_name" ]] && printf '  Computer Name: %s\n' "$comp_name"
                [[ -n "$netbios_name" ]] && printf '  NetBIOS Name: %s\n' "$netbios_name"
                [[ -n "$domain_name" ]] && printf '  Domain/Workgroup: %s\n' "$domain_name"
                [[ -n "$fqdn" ]] && printf '  FQDN: %s\n' "$fqdn"
                [[ -n "$sys_time" ]] && printf '  System Time: %s\n' "$sys_time"
                printf '\n'
            } >> "$os_file"
        fi

        # Record SMB Signing Security Evaluation
        net_mod_write_raw ""
        net_mod_write_raw "  SMB Security & Message Signing:"
        if [[ "$signing_evaluated" == true ]]; then
            if [[ "$signing_required" == true ]]; then
                net_mod_write_raw "    Message Signing        : Required (Enforced)"
                printf 'Port %s Signing: Required (Enforced)\n' "$port" >> "$security_file"
            else
                (( total_findings += 1 ))
                net_mod_write_raw "    Message Signing        : Not Required / Disabled"
                net_mod_write_raw "    [SECURITY WARN] SMB Signing Not Required: System is vulnerable to SMB relay"
                net_mod_write_raw "                    and NTLM authentication interception attacks."
                printf 'Port %s Signing: Not Required / Disabled (Vulnerable to relay)\n' "$port" >> "$security_file"
            fi
            if [[ -n "$signing_raw" ]]; then
                printf '  Raw: %s\n' "$signing_raw" >> "$security_file"
            fi
        else
            net_mod_write_raw "    Message Signing        : Not evaluated by target"
        fi

        # Record Enumerated Shares & Anonymous Access
        if (( ${#shares_list[@]} > 0 )); then
            net_mod_write_raw ""
            net_mod_write_raw "  Discovered Network Shares:"
            printf 'Port %s Shares:\n' "$port" >> "$shares_file"

            local item
            for item in "${shares_list[@]}"; do
                local s_name="${item%%|*}"
                local rest="${item#*|}"
                local s_type="${rest%%|*}"
                rest="${rest#*|}"
                local s_comm="${rest%%|*}"
                local s_anon="${rest#*|}"

                local share_desc="    - \\\\${SVC_TARGET}\\${s_name} (Type: ${s_type})"
                [[ -n "$s_comm" ]] && share_desc="${share_desc} [${s_comm}]"
                share_desc="${share_desc} (Anonymous: ${s_anon})"
                net_mod_write_raw "$share_desc"

                printf '  \\\\%s\\%s\tType: %s\tAnonymous: %s\tComment: %s\n' \
                    "$SVC_TARGET" "$s_name" "$s_type" "$s_anon" "$s_comm" >> "$shares_file"
            done

            if (( ${#anon_accessible_shares[@]} > 0 )); then
                (( total_findings += ${#anon_accessible_shares[@]} ))
                net_mod_write_raw ""
                net_mod_write_raw "  Anonymous Share Access Findings:"
                local acc
                for acc in "${anon_accessible_shares[@]}"; do
                    net_mod_write_raw "    [SECURITY RISK] Unauthenticated Access Permitted: $acc"
                done
            fi
        fi

        # 4. Optional advanced audit via enum4linux-ng
        if [[ "$enum4linux_available" == true ]]; then
            local enum_out="${NET_TASK_DIR}/smb_enum4linux_${port}.txt"
            "$SMB_ENUM4LINUX_BIN" -A "$SVC_TARGET" > "$enum_out" 2>/dev/null || true
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "SMB audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "SMB audit completed. No insecure configuration identified."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    smb_main "$@"
fi
