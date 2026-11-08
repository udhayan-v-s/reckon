#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTP Enumeration Module (modules/network/services/http.sh)
#
# Interrogates HTTP web services: identification of web server software
# and versions, technology stack fingerprinting via response headers,
# HTTP methods enumeration and dangerous method detection (PUT, DELETE, TRACE),
# page title extraction, and security header posture evaluation.
#
# Supported target types:
#   ipv4, hostname, domain, url_http, url_https
#
# Downstream artifacts generated:
#   - http_headers.txt (raw HTTP response headers per port)
#   - http_methods.txt (discovered allowed and potentially dangerous HTTP methods)
#   - nmap_http_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: http-title, http-methods, http-server-header)
#   - curl (HTTP header inspection and status line verification)
#

set -o nounset

HTTP_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$HTTP_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HTTP_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
HTTP_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Main module execution function.
http_main() {
    # Initialize execution context using service common library (allowing URL targets).
    if ! svc_mod_init "$1" "$2" "$3" true; then
        return 1
    fi

    # Resolve target HTTP ports from upstream artifacts or defaults (80, 8080).
    if ! svc_mod_resolve_ports "http" "80,8080" "(http|http-alt|http-proxy|apache|nginx|lighttpd)"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "http" "HTTP Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${HTTP_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "http" "HTTP Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local curl_available=false
    local tools_used=()

    tools_used+=("nmap")
    if net_mod_has_tool "$HTTP_CURL_BIN"; then
        curl_available=true
        tools_used+=("curl")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "http" "HTTP Enumeration" "$tools_str"

    local headers_file="${NET_TASK_DIR}/http_headers.txt"
    local methods_file="${NET_TASK_DIR}/http_methods.txt"
    : > "$headers_file"
    : > "$methods_file"

    local total_findings=0

    # Iterate over all resolved HTTP ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: HTTP Service Interrogation"

        local req_path="/"
        if [[ -n "${SVC_URL_PATH:-}" && "${SVC_URL_PATH:-}" != "/" ]]; then
            req_path="$SVC_URL_PATH"
        fi
        local query_url="http://${SVC_TARGET}:${port}${req_path}"

        # ---------------------------------------------------------------------
        # 1. HTTP Response Header & Technology Inspection via curl
        # ---------------------------------------------------------------------
        local http_status="Unknown"
        local server_header=""
        local powered_by=""
        local redirect_loc=""
        local has_xfo=false
        local has_xcto=false
        local has_csp=false

        if [[ "$curl_available" == true ]]; then
            local curl_tmp="${NET_TASK_DIR}/curl_http_${port}.tmp"
            "$HTTP_CURL_BIN" -I -s -S --max-time 5 "$query_url" > "$curl_tmp" 2>/dev/null || true

            if [[ -s "$curl_tmp" ]]; then
                {
                    printf '=== Port %s: %s ===\n' "$port" "$query_url"
                    cat "$curl_tmp"
                    printf '\n'
                } >> "$headers_file"

                local h_line
                while IFS= read -r h_line || [[ -n "$h_line" ]]; do
                    # Strip trailing CR
                    h_line="${h_line%$'\r'}"

                    if [[ "$h_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}[[:space:]]*.*)$ ]]; then
                        http_status="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Ss]erver:[[:space:]]*(.*)$ ]]; then
                        server_header="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Xx]-[Pp]owered-[Bb]y:[[:space:]]*(.*)$ ]]; then
                        powered_by="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Ll]ocation:[[:space:]]*(.*)$ ]]; then
                        redirect_loc="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Xx]-[Ff]rame-[Oo]ptions: ]]; then
                        has_xfo=true
                    elif [[ "$h_line" =~ ^[Xx]-[Cc]ontent-[Tt]ype-[Oo]ptions: ]]; then
                        has_xcto=true
                    elif [[ "$h_line" =~ ^[Cc]ontent-[Ss]ecurity-[Pp]olicy: ]]; then
                        has_csp=true
                    fi
                done < "$curl_tmp"
            fi
            rm -f "$curl_tmp"
        fi

        # Document HTTP Response & Server Metadata
        net_mod_write_kv "Target URL" "$query_url"
        net_mod_write_kv "Response Status" "$http_status"
        [[ -n "$server_header" ]] && net_mod_write_kv "Server Banner" "$server_header"
        [[ -n "$powered_by" ]] && net_mod_write_kv "X-Powered-By" "$powered_by"
        [[ -n "$redirect_loc" ]] && net_mod_write_kv "Redirect Location" "$redirect_loc"

        # ---------------------------------------------------------------------
        # 2. Nmap NSE Script Probing (http-title, http-methods, http-server-header)
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_http_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "--script" "http-title,http-methods,http-server-header"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local page_title=""
        local -a supported_methods=()
        local -a dangerous_methods=()

        if [[ -f "$nmap_out" ]]; then
            local line

            while IFS= read -r line || [[ -n "$line" ]]; do
                local clean_line="${line#|}"
                clean_line="${clean_line#_}"
                clean_line="${clean_line#"${clean_line%%[![:space:]]*}"}" # trim leading whitespace

                # Parse http-title
                if [[ "$clean_line" =~ ^http-title:[[:space:]]*(.*)$ ]]; then
                    page_title="${BASH_REMATCH[1]}"
                elif [[ "$clean_line" =~ ^Supported[[:space:]]+Methods:[[:space:]]*(.*)$ ]]; then
                    local m_str="${BASH_REMATCH[1]}"
                    local m
                    for m in $m_str; do
                        supported_methods+=("$m")
                        if [[ "$m" == "PUT" || "$m" == "DELETE" || "$m" == "TRACE" ]]; then
                            dangerous_methods+=("$m")
                        fi
                    done
                fi

                # If http-server-header found and server_header was empty
                if [[ -z "$server_header" && "$clean_line" =~ ^http-server-header:[[:space:]]*(.*)$ ]]; then
                    server_header="${BASH_REMATCH[1]}"
                    net_mod_write_kv "Server (NSE)" "$server_header"
                fi
            done < "$nmap_out"
        fi

        # Document Page Title
        if [[ -n "$page_title" ]]; then
            net_mod_write_kv "HTML Page Title" "$page_title"
        fi

        # Document HTTP Methods
        if (( ${#supported_methods[@]} > 0 )); then
            local IFS=','
            local methods_joined="${supported_methods[*]}"
            methods_joined="${methods_joined//,/, }"
            net_mod_write_kv "Allowed Methods" "$methods_joined"
            printf 'Port %s Allowed Methods: %s\n' "$port" "$methods_joined" >> "$methods_file"

            if (( ${#dangerous_methods[@]} > 0 )); then
                (( total_findings += ${#dangerous_methods[@]} ))
                local d_joined="${dangerous_methods[*]}"
                d_joined="${d_joined//,/, }"
                printf 'Port %s Insecure Methods: %s\n' "$port" "$d_joined" >> "$methods_file"
                net_mod_write_raw ""
                net_mod_write_raw "  HTTP Method Security Evaluation:"
                local dm
                for dm in "${dangerous_methods[@]}"; do
                    if [[ "$dm" == "TRACE" ]]; then
                        net_mod_write_raw "    [SECURITY WARN] Insecure HTTP Method TRACE Enabled: Potential Cross-Site Tracing (XST)."
                    else
                        net_mod_write_raw "    [SECURITY WARN] Insecure HTTP Method $dm Enabled: File manipulation may be permitted."
                    fi
                done
            fi
        fi

        # ---------------------------------------------------------------------
        # 3. Security Header Analysis
        # ---------------------------------------------------------------------
        if [[ "$curl_available" == true && "$http_status" != "Unknown" ]]; then
            local -a missing_sec_headers=()
            [[ "$has_xfo" == false ]] && missing_sec_headers+=("X-Frame-Options (Clickjacking defense)")
            [[ "$has_xcto" == false ]] && missing_sec_headers+=("X-Content-Type-Options (MIME sniffing defense)")
            [[ "$has_csp" == false ]] && missing_sec_headers+=("Content-Security-Policy (XSS/injection defense)")

            if (( ${#missing_sec_headers[@]} > 0 )); then
                (( total_findings += ${#missing_sec_headers[@]} ))
                net_mod_write_raw ""
                net_mod_write_raw "  Security Header Posture:"
                local msh
                for msh in "${missing_sec_headers[@]}"; do
                    net_mod_write_raw "    [SECURITY NOTICE] Missing Header: $msh"
                done
            fi
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "HTTP audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "HTTP audit completed."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    http_main "$@"
fi
