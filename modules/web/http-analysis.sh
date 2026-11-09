#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web HTTP Security Analysis Module (modules/web/http-analysis.sh)
#
# Audits HTTP response headers for missing security controls, information
# leakage, CORS misconfigurations (arbitrary origin reflection), and HTTP
# verb/method tampering risks.
#
# Supported target types:
#   url_http, url_https, hostname, domain, ipv4
#
# Primary External Tool:
#   - curl (native HTTP header & verb interrogation engine)
#

set -o nounset

HTTP_ANALYSIS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$HTTP_ANALYSIS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HTTP_ANALYSIS_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Main entry point for the HTTP Security Analysis module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_http, url_https, hostname, domain, ipv4)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_http_analysis_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Initialize web execution context with supported target types.
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" url_http url_https hostname domain ipv4 || init_rc=$?
    if (( init_rc == 2 )); then
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "http-analysis" "HTTP Response and Security Analysis"

    local analysis_file="${task_dir}/http_analysis.txt"
    : > "$analysis_file"

    local curl_bin="${RECKON_MOCK_CURL_BIN:-${HTTP_ANALYSIS_CURL_BIN:-curl}}"
    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve target domain/host
    local domain_base="${WEB_URL_HOST:-$WEB_TARGET}"
    domain_base="${domain_base%:*}"

    # Resolve candidate target URLs
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)
    if (( ${#candidate_urls[@]} == 0 )); then
        if [[ "$WEB_TARGET_TYPE" == "url_https" ]]; then
            candidate_urls=("https://${domain_base}")
        elif [[ "$WEB_TARGET_TYPE" == "url_http" ]]; then
            candidate_urls=("http://${domain_base}")
        else
            candidate_urls=("https://${domain_base}" "http://${domain_base}")
        fi
    fi

    local probe_url="${candidate_urls[0]}"

    web_mod_write_section "Analysis Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Base Domain" "$domain_base"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Probe Endpoint" "$probe_url"

    local headers_tmp="${task_dir}/.headers.tmp"
    "$curl_bin" -s -k -I -m 6 -A "$user_agent" "$probe_url" > "$headers_tmp" 2>/dev/null || true

    local -a header_findings=()
    local -a missing_headers=()
    local -a info_leak_headers=()

    # 1. Security Headers Audit
    local -a sec_headers=(
        "Strict-Transport-Security"
        "Content-Security-Policy"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Referrer-Policy"
        "Permissions-Policy"
    )

    local sh
    for sh in "${sec_headers[@]}"; do
        local h_val=""
        if [[ -f "$headers_tmp" && -s "$headers_tmp" ]]; then
            h_val="$(grep -i "^${sh}:" "$headers_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
        fi

        if [[ -n "$h_val" ]]; then
            header_findings+=("${sh}"$'\t'"PRESENT"$'\t'"${h_val}")
            printf 'HEADER\t%s\tPRESENT\t%s\n' "$sh" "$h_val" >> "$analysis_file"
        else
            missing_headers+=("$sh")
            printf 'HEADER\t%s\tMISSING\t-\n' "$sh" >> "$analysis_file"
        fi
    done

    # Information Leakage Headers
    local -a info_headers=(
        "Server"
        "X-Powered-By"
        "X-AspNet-Version"
        "X-AspNetMvc-Version"
    )

    local ih
    for ih in "${info_headers[@]}"; do
        local i_val=""
        if [[ -f "$headers_tmp" && -s "$headers_tmp" ]]; then
            i_val="$(grep -i "^${ih}:" "$headers_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
        fi
        if [[ -n "$i_val" ]]; then
            info_leak_headers+=("${ih}: ${i_val}")
            printf 'DISCLOSURE\t%s\t%s\n' "$ih" "$i_val" >> "$analysis_file"
        fi
    done
    rm -f "$headers_tmp"

    # 2. CORS Misconfiguration Audit
    local cors_origin="https://reckon-cors-test.evil.local"
    local cors_tmp="${task_dir}/.cors.tmp"
    "$curl_bin" -s -k -I -m 6 -A "$user_agent" -H "Origin: ${cors_origin}" "$probe_url" > "$cors_tmp" 2>/dev/null || true

    local acao=""
    local acac=""
    if [[ -f "$cors_tmp" && -s "$cors_tmp" ]]; then
        acao="$(grep -i '^Access-Control-Allow-Origin:' "$cors_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
        acac="$(grep -i '^Access-Control-Allow-Credentials:' "$cors_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
    fi
    rm -f "$cors_tmp"

    local cors_status="Secure (No CORS reflection)"
    local cors_risk="LOW"
    if [[ "$acao" == "$cors_origin" ]]; then
        if [[ "$acac" == "true" ]]; then
            cors_status="Vulnerable: Arbitrary Origin Reflected with Credentials Allowed!"
            cors_risk="HIGH"
        else
            cors_status="Vulnerable: Arbitrary Origin Reflected (ACAC: false)"
            cors_risk="MEDIUM"
        fi
    elif [[ "$acao" == "*" ]]; then
        cors_status="Permissive: Access-Control-Allow-Origin wildcard (*)"
        cors_risk="LOW"
    fi
    printf 'CORS\t%s\t%s\t%s\t%s\n' "$acao" "$acac" "$cors_risk" "$cors_status" >> "$analysis_file"

    # 3. HTTP Methods & Verb Tampering
    local options_tmp="${task_dir}/.options.tmp"
    "$curl_bin" -s -k -X OPTIONS -I -m 6 -A "$user_agent" "$probe_url" > "$options_tmp" 2>/dev/null || true

    local allow_header=""
    if [[ -f "$options_tmp" && -s "$options_tmp" ]]; then
        allow_header="$(grep -i -E '^(Allow|Public):' "$options_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
    fi
    rm -f "$options_tmp"


    # Explicitly test dangerous HTTP methods: TRACE, PUT, DELETE
    local -a tested_verbs=("GET" "POST" "OPTIONS" "HEAD" "TRACE" "PUT" "DELETE")
    local -a verb_results=()
    local v
    for v in "${tested_verbs[@]}"; do
        local v_code
        v_code="$("$curl_bin" -s -k -X "$v" -I -m 4 -o /dev/null -w "%{http_code}\n" -A "$user_agent" "$probe_url" 2>/dev/null || true)"
        [[ -z "$v_code" ]] && v_code="000"

        case "$v_code" in
            200|204|201)
                verb_results+=("${v} [HTTP ${v_code}]")
                printf 'METHOD\t%s\t%s\tENABLED\n' "$v" "$v_code" >> "$analysis_file"
                ;;
            405|501)
                printf 'METHOD\t%s\t%s\tDISABLED\n' "$v" "$v_code" >> "$analysis_file"
                ;;
            *)
                printf 'METHOD\t%s\t%s\tBLOCKED\n' "$v" "$v_code" >> "$analysis_file"
                ;;
        esac
    done

    # Format human-readable output report
    web_mod_write_section "Security Headers Audit"
    web_mod_write_kv "Headers Evaluated" "${#sec_headers[@]}"
    web_mod_write_kv "Present Headers" "${#header_findings[@]}"
    web_mod_write_kv "Missing Headers" "${#missing_headers[@]}"

    if (( ${#header_findings[@]} > 0 )); then
        web_mod_write_raw "  Configured Security Headers:"
        local h_rec
        for h_rec in "${header_findings[@]}"; do
            local h_name="${h_rec%%$'\t'*}"
            local h_val="${h_rec##*$'\t'}"
            web_mod_write_raw "    - $h_name: $h_val"
        done
    fi

    if (( ${#missing_headers[@]} > 0 )); then
        web_mod_write_raw "  Missing Security Headers:"
        local m
        for m in "${missing_headers[@]}"; do
            web_mod_write_raw "    - $m"
        done
    fi

    if (( ${#info_leak_headers[@]} > 0 )); then
        web_mod_write_section "Information Disclosure Headers"
        local leak
        for leak in "${info_leak_headers[@]}"; do
            web_mod_write_raw "    - $leak"
        done
    fi

    web_mod_write_section "CORS Configuration Audit"
    web_mod_write_kv "Tested Origin" "$cors_origin"
    web_mod_write_kv "Access-Control-Allow-Origin" "${acao:-(none)}"
    web_mod_write_kv "Access-Control-Allow-Credentials" "${acac:-(none)}"
    web_mod_write_kv "CORS Risk Assessment" "$cors_risk - $cors_status"

    web_mod_write_section "HTTP Methods Audit"
    if [[ -n "$allow_header" ]]; then
        web_mod_write_kv "Advertised Methods (Allow)" "$allow_header"
    fi
    web_mod_write_kv "Active Methods Discovered" "${#verb_results[@]}"
    if (( ${#verb_results[@]} > 0 )); then
        web_mod_write_raw "  Responsive Methods:"
        local vr
        for vr in "${verb_results[@]}"; do
            web_mod_write_raw "    - $vr"
        done
    fi

    local footer_msg="Audit complete: ${#header_findings[@]}/${#sec_headers[@]} security headers configured, CORS status: ${cors_risk}."
    web_mod_write_footer "COMPLETED" "$footer_msg"

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_http_analysis_run "$@"
fi
