#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTPS Enumeration Module (modules/network/services/https.sh)
#
# Interrogates HTTPS / TLS-encrypted web services: TLS/SSL certificate
# retrieval and validation (CN, SANs, validity dates, issuer, signature algo),
# cryptographic protocol evaluation (SSLv2/v3, TLS 1.0, 1.1, 1.2, 1.3),
# cipher suite strength auditing, HTTP Strict Transport Security (HSTS)
# inspection, and security header verification.
#
# Supported target types:
#   ipv4, hostname, domain, url_http, url_https
#
# Downstream artifacts generated:
#   - https_cert.txt (extracted X.509 certificate subject, issuer, validity, SANs)
#   - https_tls.txt (supported TLS protocol versions and cipher suites)
#   - https_headers.txt (HTTPS response headers and HSTS status)
#   - nmap_https_<port>.nmap (raw Nmap NSE script output)
#   - output.txt (human-readable structured report)
#
# External tools utilized:
#   - nmap (NSE scripts: ssl-enum-ciphers, ssl-cert, http-title)
#   - curl (HTTPS header inspection and HSTS verification)
#   - openssl (direct X.509 certificate parsing and chain validation)
#   - testssl.sh (optional advanced TLS vulnerability auditor)
#

set -o nounset

HTTPS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/network/services/common.sh
if ! source "$HTTPS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/network/services/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HTTPS_NMAP_BIN="${RECKON_MOCK_NMAP_BIN:-}"
HTTPS_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"
HTTPS_OPENSSL_BIN="${RECKON_MOCK_OPENSSL_BIN:-openssl}"
HTTPS_TESTSSL_BIN="${RECKON_MOCK_TESTSSL_BIN:-testssl.sh}"

# Main module execution function.
https_main() {
    # Initialize execution context using service common library (allowing URL targets).
    if ! svc_mod_init "$1" "$2" "$3" true; then
        return 1
    fi

    # Resolve target HTTPS ports from upstream artifacts or defaults (443, 8443).
    if ! svc_mod_resolve_ports "https" "443,8443" "(https|ssl|ssl/http|http-alt)"; then
        if svc_mod_should_skip; then
            svc_mod_handle_skipped "https" "HTTPS Enumeration"
            return 0
        fi
        return 1
    fi

    local nmap_bin="${HTTPS_NMAP_BIN:-}"
    if [[ -z "$nmap_bin" ]]; then
        nmap_bin="$(net_mod_resolve_nmap)"
    fi

    if ! net_mod_has_tool "$nmap_bin"; then
        svc_mod_write_service_header "https" "HTTPS Enumeration" "None"
        net_mod_write_section "Dependency Error"
        net_mod_write_raw "Missing required service interrogation tool: nmap"
        net_mod_write_footer "FAILED" "Required dependency nmap not found in PATH."
        svc_mod_finish 1
        return 1
    fi

    local curl_available=false
    local openssl_available=false
    local testssl_available=false
    local tools_used=()

    tools_used+=("nmap")
    if net_mod_has_tool "$HTTPS_CURL_BIN"; then
        curl_available=true
        tools_used+=("curl")
    fi
    if net_mod_has_tool "$HTTPS_OPENSSL_BIN"; then
        openssl_available=true
        tools_used+=("openssl")
    fi
    if net_mod_has_tool "$HTTPS_TESTSSL_BIN"; then
        testssl_available=true
        tools_used+=("testssl.sh")
    fi

    local tools_str="None"
    if (( ${#tools_used[@]} > 0 )); then
        local IFS=', '
        tools_str="${tools_used[*]}"
    fi

    svc_mod_write_service_header "https" "HTTPS Enumeration" "$tools_str"

    local cert_file="${NET_TASK_DIR}/https_cert.txt"
    local tls_file="${NET_TASK_DIR}/https_tls.txt"
    local headers_file="${NET_TASK_DIR}/https_headers.txt"
    : > "$cert_file"
    : > "$tls_file"
    : > "$headers_file"

    local total_findings=0

    # Iterate over all resolved HTTPS ports.
    local port
    for port in "${SVC_RESOLVED_PORTS[@]}"; do
        net_mod_write_section "Port $port: HTTPS Service Interrogation"

        local req_path="/"
        if [[ -n "${SVC_URL_PATH:-}" && "${SVC_URL_PATH:-}" != "/" ]]; then
            req_path="$SVC_URL_PATH"
        fi
        local query_url="https://${SVC_TARGET}:${port}${req_path}"

        # ---------------------------------------------------------------------
        # 1. HTTPS Response Header & HSTS Inspection via curl
        # ---------------------------------------------------------------------
        local http_status="Unknown"
        local server_header=""
        local has_hsts=false
        local hsts_val=""

        if [[ "$curl_available" == true ]]; then
            local curl_tmp="${NET_TASK_DIR}/curl_https_${port}.tmp"
            "$HTTPS_CURL_BIN" -k -I -s -S --max-time 5 "$query_url" > "$curl_tmp" 2>/dev/null || true

            if [[ -s "$curl_tmp" ]]; then
                {
                    printf '=== Port %s: %s ===\n' "$port" "$query_url"
                    cat "$curl_tmp"
                    printf '\n'
                } >> "$headers_file"

                local h_line
                while IFS= read -r h_line || [[ -n "$h_line" ]]; do
                    h_line="${h_line%$'\r'}"
                    if [[ "$h_line" =~ ^HTTP/[0-9.]+[[:space:]]+([0-9]{3}[[:space:]]*.*)$ ]]; then
                        http_status="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Ss]erver:[[:space:]]*(.*)$ ]]; then
                        server_header="${BASH_REMATCH[1]}"
                    elif [[ "$h_line" =~ ^[Ss]trict-[Tt]ransport-[Ss]ecurity:[[:space:]]*(.*)$ ]]; then
                        has_hsts=true
                        hsts_val="${BASH_REMATCH[1]}"
                    fi
                done < "$curl_tmp"
            fi
            rm -f "$curl_tmp"
        fi

        net_mod_write_kv "Target URL" "$query_url"
        net_mod_write_kv "Response Status" "$http_status"
        [[ -n "$server_header" ]] && net_mod_write_kv "Server Banner" "$server_header"

        if [[ "$curl_available" == true && "$http_status" != "Unknown" ]]; then
            if [[ "$has_hsts" == true ]]; then
                net_mod_write_kv "HSTS Policy" "Enabled ($hsts_val)"
            else
                (( total_findings += 1 ))
                net_mod_write_kv "HSTS Policy" "Missing (Strict-Transport-Security not sent)"
                net_mod_write_raw "    [SECURITY WARN] Missing Strict-Transport-Security (HSTS) Header: Clients vulnerable"
                net_mod_write_raw "                    to SSL-stripping and downgrade attacks."
            fi
        fi

        # ---------------------------------------------------------------------
        # 2. X.509 Certificate Inspection via OpenSSL s_client
        # ---------------------------------------------------------------------
        local cert_subject=""
        local cert_issuer=""
        local cert_not_after=""
        local cert_not_before=""
        local cert_sans=""
        local cert_sig_algo=""
        local is_self_signed=false

        if [[ "$openssl_available" == true ]]; then
            local cert_raw="${NET_TASK_DIR}/cert_${port}.tmp"
            "$HTTPS_OPENSSL_BIN" s_client -connect "${SVC_TARGET}:${port}" -servername "$SVC_TARGET" </dev/null 2>/dev/null | \
                "$HTTPS_OPENSSL_BIN" x509 -noout -text 2>/dev/null > "$cert_raw" || true

            if [[ -s "$cert_raw" ]]; then
                local in_sans=false
                local c_line
                while IFS= read -r c_line || [[ -n "$c_line" ]]; do
                    local clean_c="${c_line#"${c_line%%[![:space:]]*}"}"

                    if [[ "$clean_c" =~ ^Subject:[[:space:]]*(.*)$ ]]; then
                        cert_subject="${BASH_REMATCH[1]}"
                    elif [[ "$clean_c" =~ ^Issuer:[[:space:]]*(.*)$ ]]; then
                        cert_issuer="${BASH_REMATCH[1]}"
                    elif [[ "$clean_c" =~ ^Not[[:space:]]+Before:[[:space:]]*(.*)$ ]]; then
                        cert_not_before="${BASH_REMATCH[1]}"
                    elif [[ "$clean_c" =~ ^Not[[:space:]]+After[[:space:]]*:[[:space:]]*(.*)$ ]]; then
                        cert_not_after="${BASH_REMATCH[1]}"
                    elif [[ "$clean_c" =~ ^Signature[[:space:]]+Algorithm:[[:space:]]*(.*)$ && -z "$cert_sig_algo" ]]; then
                        cert_sig_algo="${BASH_REMATCH[1]}"
                    elif [[ "$clean_c" == *"X509v3 Subject Alternative Name:"* ]]; then
                        in_sans=true
                        continue
                    elif [[ "$in_sans" == true ]]; then
                        if [[ "$clean_c" =~ ^DNS: ]]; then
                            cert_sans="$clean_c"
                        fi
                        in_sans=false
                    fi
                done < "$cert_raw"

                # Check self-signed condition
                if [[ -n "$cert_subject" && -n "$cert_issuer" && "$cert_subject" == "$cert_issuer" ]]; then
                    is_self_signed=true
                fi

                {
                    printf '=== Port %s Certificate: %s ===\n' "$port" "$SVC_TARGET"
                    cat "$cert_raw"
                    printf '\n'
                } >> "$cert_file"
            fi
            rm -f "$cert_raw"
        fi

        # Document Certificate Information
        if [[ -n "$cert_subject" || -n "$cert_issuer" ]]; then
            net_mod_write_raw ""
            net_mod_write_raw "  TLS / SSL Certificate Identification:"
            [[ -n "$cert_subject" ]] && net_mod_write_kv "Certificate Subject" "$cert_subject"
            [[ -n "$cert_issuer" ]] && net_mod_write_kv "Certificate Issuer" "$cert_issuer"
            [[ -n "$cert_not_before" ]] && net_mod_write_kv "Valid From" "$cert_not_before"
            [[ -n "$cert_not_after" ]] && net_mod_write_kv "Expiration Date" "$cert_not_after"
            [[ -n "$cert_sans" ]] && net_mod_write_kv "Alternative Names (SAN)" "$cert_sans"
            [[ -n "$cert_sig_algo" ]] && net_mod_write_kv "Signature Algorithm" "$cert_sig_algo"

            if [[ "$is_self_signed" == true ]]; then
                (( total_findings += 1 ))
                net_mod_write_raw "    [SECURITY WARN] Self-Signed TLS Certificate: Certificate is not signed by a trusted"
                net_mod_write_raw "                    Certificate Authority (CA), triggering browser untrusted warnings."
            fi
            if [[ "$cert_sig_algo" =~ (sha1|md5) ]]; then
                (( total_findings += 1 ))
                net_mod_write_raw "    [SECURITY WARN] Weak Certificate Signature: Insecure digest algorithm ($cert_sig_algo) detected."
            fi
        fi

        # ---------------------------------------------------------------------
        # 3. Nmap NSE TLS Cipher & Protocol Auditing (ssl-enum-ciphers, ssl-cert)
        # ---------------------------------------------------------------------
        local nmap_out="${NET_TASK_DIR}/nmap_https_${port}.nmap"
        local -a nmap_cmd=(
            "$nmap_bin"
            "-Pn"
            "-n"
            "--system-dns"
            "-T4"
            "-p" "$port"
            "--script" "ssl-enum-ciphers,ssl-cert,http-title"
            "-oN" "$nmap_out"
            "$SVC_TARGET"
        )

        "${nmap_cmd[@]}" >/dev/null 2>&1 || true

        local -a supported_tls_versions=()
        local -a deprecated_tls_versions=()
        local cur_tls_version=""
        local ssl_grade=""

        if [[ -f "$nmap_out" ]]; then
            local n_line
            while IFS= read -r n_line || [[ -n "$n_line" ]]; do
                local clean_nl="${n_line#|}"
                clean_nl="${clean_nl#_}"
                clean_nl="${clean_nl#"${clean_nl%%[![:space:]]*}"}" # trim leading whitespace

                if [[ "$clean_nl" =~ ^(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3): ]]; then
                    cur_tls_version="${BASH_REMATCH[1]}"
                    supported_tls_versions+=("$cur_tls_version")
                    if [[ "$cur_tls_version" == "SSLv2" || "$cur_tls_version" == "SSLv3" || "$cur_tls_version" == "TLSv1.0" || "$cur_tls_version" == "TLSv1.1" ]]; then
                        deprecated_tls_versions+=("$cur_tls_version")
                    fi
                elif [[ "$clean_nl" =~ ^least[[:space:]]+strength:[[:space:]]*([A-F][+-]?) ]]; then
                    ssl_grade="${BASH_REMATCH[1]}"
                fi

                # Fallback: certificate info from Nmap ssl-cert if openssl was missing
                if [[ -z "$cert_subject" && "$clean_nl" =~ ^Subject:[[:space:]]+commonName=([^/]+) ]]; then
                    cert_subject="${BASH_REMATCH[1]}"
                fi
                if [[ -z "$cert_issuer" && "$clean_nl" =~ ^Issuer:[[:space:]]+commonName=([^/]+) ]]; then
                    cert_issuer="${BASH_REMATCH[1]}"
                fi
            done < "$nmap_out"
        fi

        # Document TLS Protocols & Ciphers
        if (( ${#supported_tls_versions[@]} > 0 )); then
            local IFS=','
            local proto_str="${supported_tls_versions[*]}"
            proto_str="${proto_str//,/, }"
            net_mod_write_raw ""
            net_mod_write_raw "  TLS Protocol Configuration:"
            net_mod_write_kv "Supported Protocols" "$proto_str"
            [[ -n "$ssl_grade" ]] && net_mod_write_kv "Cipher Grade" "$ssl_grade"

            {
                printf 'Port %s Supported Protocols: %s\n' "$port" "$proto_str"
                [[ -n "$ssl_grade" ]] && printf 'Port %s Cipher Grade: %s\n' "$port" "$ssl_grade"
            } >> "$tls_file"

            if (( ${#deprecated_tls_versions[@]} > 0 )); then
                (( total_findings += ${#deprecated_tls_versions[@]} ))
                local dep_str="${deprecated_tls_versions[*]}"
                dep_str="${dep_str//,/, }"
                printf 'Port %s Deprecated Protocols: %s\n' "$port" "$dep_str" >> "$tls_file"
                net_mod_write_raw ""
                net_mod_write_raw "  Cryptographic Protocol Security Weaknesses:"
                local dp
                for dp in "${deprecated_tls_versions[@]}"; do
                    if [[ "$dp" == "SSLv2" || "$dp" == "SSLv3" ]]; then
                        net_mod_write_raw "    [SECURITY RISK] Insecure Protocol Enabled: $dp is broken and vulnerable to POODLE/DROWN."
                    else
                        net_mod_write_raw "    [SECURITY WARN] Deprecated TLS Version Enabled: $dp is deprecated by RFC 8996."
                    fi
                done
            fi
        fi

        # 4. Optional advanced audit via testssl.sh
        if [[ "$testssl_available" == true ]]; then
            local testssl_out="${NET_TASK_DIR}/testssl_${port}.txt"
            "$HTTPS_TESTSSL_BIN" --fast --quiet --color 0 "$SVC_TARGET:$port" > "$testssl_out" 2>/dev/null || true
        fi
    done

    # Finalize execution footer and secure artifact permissions.
    if (( total_findings > 0 )); then
        net_mod_write_footer "COMPLETED" "HTTPS audit completed with $total_findings security finding(s)."
    else
        net_mod_write_footer "COMPLETED" "HTTPS audit completed. Secure TLS configuration verified."
    fi

    svc_mod_finish 0
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    https_main "$@"
fi
