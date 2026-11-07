#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# FTP Enumeration Module (modules/network/services/ftp.sh)
#
# Interrogates File Transfer Protocol (FTP) services: banner identification,
# software and version disclosure, anonymous authentication testing,
# accessible directory listing, SYST system identification, and FTP bounce
# attack vulnerability verification.
#
# Supported target types:
#   ipv4, hostname, domain
#
# Downstream artifacts generated:
#   - ftp_banner.txt (raw FTP identification banner)
#   - ftp_anon.txt (anonymous access verification and file listing)
#   - nmap_ftp_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: ftp-anon, ftp-bounce, ftp-syst)
#   - nc (raw TCP socket connection and banner acquisition)
#   - curl (optional directory query verification)
#

set -o nounset

FTP_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$FTP_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
FTP_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
FTP_NC_BIN="${RECKON_MOCK_NC_BIN:-nc}"
FTP_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Main module execution function.
ftp_main() {
    # Initialize execution context using service common library.
    if ! svc_mod_init "$@"; then
        return 1
    fi

    # Resolve target FTP ports from upstream artifacts or defaults.
    if ! svc_mod_resolve_ports "ftp" "21" "ftp"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "ftp" "FTP Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${FTP_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "ftp" "FTP Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local tools_used=()
    tools_used+=("nmap")
    if net_mod_has_tool "$FTP_NC_BIN"; then
        tools_used+=("nc")
    fi
    if net_mod_has_tool "$FTP_CURL_BIN"; then
        tools_used+=("curl")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "ftp" "FTP Enumeration" "$tools_str"

    local banner_file="${NET_TASK_DIR}/ftp_banner.txt"
    local anon_file="${NET_TASK_DIR}/ftp_anon.txt"
    : > "$banner_file"
    : > "$anon_file"

    local total_findings=0

    # Iterate over all resolved FTP ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: FTP Service Interrogation"

        # ---------------------------------------------------------------------
        # 1. Identification Banner Acquisition
        # ---------------------------------------------------------------------
        local raw_banner=""
        raw_banner="$(svc_mod_banner_grab "$SVC_TARGET" "$port" 3)"

        local sw_identity="Unknown"
        if [[ -n "$raw_banner" ]]; then
            printf 'Port %s: %s\n' "$port" "$raw_banner" >> "$banner_file"
            net_mod_write_kv "Service Banner" "$raw_banner"

            # Parse common FTP daemon signatures
            if [[ "$raw_banner" =~ (vsFTPd[[:space:]]+[0-9.]+|ProFTPD[[:space:]]+[0-9.]+|Pure-FTPd[[:space:]]*[0-9.]*|FileZilla[[:space:]]+Server[[:space:]]*[0-9.]*|Microsoft[[:space:]]+FTP[[:space:]]+Service) ]]; then
                sw_identity="${BASH_REMATCH[1]}"
                net_mod_write_kv "Software Identity" "$sw_identity"
            fi
        else
            net_mod_write_kv "Service Banner" "None (no response received upon connection)"
        fi

        # ---------------------------------------------------------------------
        # 2. Nmap NSE Probing (ftp-anon, ftp-bounce, ftp-syst)
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_ftp_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "--script" "ftp-anon,ftp-bounce,ftp-syst"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local anon_allowed=false
        local syst_info=""
        local bounce_working=false
        local in_anon_block=false
        local -a dir_entries=()
        local line

        if [[ -f "$nmap_out" ]]; then
            while IFS= read -r line || [[ -n "$line" ]]; do
                local clean_line="${line#|}"
                clean_line="${clean_line#_}"
                clean_line="${clean_line#"${clean_line%%[![:space:]]*}"}"

                # Detect ftp-anon section header
                if [[ "$line" == *"ftp-anon:"* ]]; then
                    in_anon_block=true
                    if [[ "$line" =~ [Aa]nonymous.*(allowed|permitted|FTP[[:space:]]+code[[:space:]]+230) ]]; then
                        anon_allowed=true
                    fi
                    continue
                fi

                # Parse ftp-anon directory listing contents
                if [[ "$in_anon_block" == true ]]; then
                    if [[ "$line" =~ ^\|[[:space:]]+([-dcbpsl][-rwxsStT]{9}[[:space:]]+.*)$ ]]; then
                        dir_entries+=("${BASH_REMATCH[1]}")
                        continue
                    elif [[ "$line" =~ ^\|_[[:space:]]*([-dcbpsl][-rwxsStT]{9}[[:space:]]+.*)$ ]]; then
                        dir_entries+=("${BASH_REMATCH[1]}")
                        in_anon_block=false
                    elif [[ "$line" =~ ^[a-zA-Z0-9|_-]+: ]] || [[ "$clean_line" =~ ^(ftp-syst|ftp-bounce): ]]; then
                        in_anon_block=false
                    fi
                fi

                # Detect ftp-syst response
                if [[ "$clean_line" =~ ^UNIX[[:space:]]+Type:[[:space:]]*(.*)$ ]]; then
                    syst_info="UNIX Type: ${BASH_REMATCH[1]}"
                elif [[ "$clean_line" =~ ^Windows_NT[[:space:]]*(.*)$ ]]; then
                    syst_info="Windows_NT ${BASH_REMATCH[1]}"
                fi

                # Detect ftp-bounce vulnerability
                if [[ "$line" == *"ftp-bounce:"* && "$line" == *"bounce working"* ]]; then
                    bounce_working=true
                fi
            done < "$nmap_out"
        fi

        # Document System Information
        if [[ -n "$syst_info" ]]; then
            net_mod_write_kv "System Type (SYST)" "$syst_info"
        fi

        # Document Anonymous FTP Access Evaluation
        net_mod_write_raw ""
        net_mod_write_raw "  Anonymous Authentication Evaluation:"
        if [[ "$anon_allowed" == true ]]; then
            (( total_findings += 1 ))
            net_mod_write_raw "    Authentication Status  : PERMITTED (Anonymous login allowed)"
            net_mod_write_raw "    [SECURITY WARN] Anonymous FTP Login Permitted: Unauthenticated users can log in"
            net_mod_write_raw "                    and browse or retrieve directory contents."
            printf 'Port %s: Anonymous login permitted\n' "$port" >> "$anon_file"

            if (( ${#dir_entries[@]} > 0 )); then
                net_mod_write_raw ""
                net_mod_write_raw "    Exposed Directory Contents:"
                local de
                for de in "${dir_entries[@]}"; do
                    net_mod_write_raw "      $de"
                    printf '  %s\n' "$de" >> "$anon_file"
                done
            fi
        else
            net_mod_write_raw "    Authentication Status  : Disabled / Authentication Required"
        fi

        # Document FTP Bounce Attack Status
        if [[ "$bounce_working" == true ]]; then
            (( total_findings += 1 ))
            net_mod_write_raw ""
            net_mod_write_raw "  FTP Bounce Attack Evaluation:"
            net_mod_write_raw "    Bounce State           : Vulnerable (PORT command accepted for foreign hosts)"
            net_mod_write_raw "    [SECURITY WARN] FTP Bounce Attack Supported: Service can be abused as a proxy"
            net_mod_write_raw "                    for port scanning internal or foreign network hosts."
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "FTP audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "FTP audit completed. No insecure configuration identified."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    ftp_main "$@"
fi
