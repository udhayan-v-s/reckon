#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Application Firewall (WAF) Detection Module (modules/web/waf.sh)
#
# Identifies the presence and vendor of Web Application Firewalls (Cloudflare,
# AWS WAF, Akamai, Imperva Incapsula, ModSecurity, F5 BIG-IP, Sucuri, etc.).
#
# Supported target types:
#   url_http, url_https, hostname, domain, ipv4
#
# Primary External Tool:
#   - wafw00f (specialized WAF fingerprinting toolkit)
#
# Fallback Engine:
#   - curl (native response header, block page, and security cookie heuristics)
#

set -o nounset

WAF_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$WAF_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
WAF_WAFW00F_BIN="${RECKON_MOCK_WAFW00F_BIN:-wafw00f}"
WAF_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Parse WAFW00F standard text output for detected WAF names.
# Output lines often look like:
#   [+] The site http://example.com is behind Cloudflare (Cloudflare Inc.) WAF.
#   [+] The site http://example.com is behind AWS WAF (Amazon) WAF.
#   [-] No WAF detected by the generic detection
_waf_parse_wafw00f_output() {
    local out_file="$1"
    [[ ! -f "$out_file" ]] && return 0

    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue

        if [[ "$line" =~ is[[:space:]]+behind[[:space:]]+(.+)[[:space:]]+WAF\.?$ ]]; then
            local waf_info="${BASH_REMATCH[1]}"
            local waf_name="$waf_info"
            local waf_vendor="-"

            if [[ "$waf_info" =~ ^([^(]+)[[:space:]]*\(([^)]+)\) ]]; then
                waf_name="${BASH_REMATCH[1]}"
                waf_vendor="${BASH_REMATCH[2]}"
            fi

            # Clean trailing/leading spaces
            waf_name="${waf_name#"${waf_name%%[![:space:]]*}"}"
            waf_name="${waf_name%"${waf_name##*[![:space:]]}"}"

            printf '%s\t%s\tActive\tWAFW00F fingerprint\n' "$waf_name" "$waf_vendor"
        fi
    done < "$out_file"
}

# Heuristic signature inspection when WAFW00F is absent or inconclusive.
_waf_inspect_headers_fallback() {
    local head_file="$1"
    local body_file="$2"
    [[ ! -f "$head_file" ]] && return 0

    local head_content
    head_content="$(cat "$head_file" 2>/dev/null || true)"

    local body_sample=""
    if [[ -f "$body_file" && -s "$body_file" ]]; then
        body_sample="$(head -c 65536 "$body_file" 2>/dev/null || true)"
    fi

    # 1. Cloudflare
    if grep -q -i 'cf-ray:' <<< "$head_content" || \
       grep -q -i 'Server:[[:space:]]*cloudflare' <<< "$head_content" || \
       grep -q -i '__cfduid' <<< "$head_content"; then
        printf 'Cloudflare\tCloudflare Inc.\tActive\tcf-ray header and Cloudflare Server banner\n'
        return 0
    fi

    # 2. AWS WAF / CloudFront
    if grep -q -i 'X-Amz-Cf-Id:' <<< "$head_content" || \
       grep -q -i 'x-amzn-waf-action:' <<< "$head_content" || \
       grep -q -i 'Server:[[:space:]]*CloudFront' <<< "$head_content"; then
        printf 'AWS WAF\tAmazon Web Services\tActive\tAWS CloudFront and WAF response headers\n'
        return 0
    fi

    # 3. Akamai
    if grep -q -i 'Server:[[:space:]]*AkamaiGHost' <<< "$head_content" || \
       grep -q -i 'X-Akamai-Transformed:' <<< "$head_content" || \
       grep -q -i 'ak_bmsc' <<< "$head_content"; then
        printf 'Akamai\tAkamai Technologies\tActive\tAkamaiGHost server banner and tracking headers\n'
        return 0
    fi

    # 4. Imperva / Incapsula
    if grep -q -i 'X-Iinfo:' <<< "$head_content" || \
       grep -q -i 'X-CDN:[[:space:]]*Incapsula' <<< "$head_content" || \
       grep -q -i 'incap_ses' <<< "$head_content"; then
        printf 'Imperva Incapsula\tImperva\tActive\tX-Iinfo and Incapsula session headers\n'
        return 0
    fi

    # 5. Sucuri
    if grep -q -i 'X-Sucuri-ID:' <<< "$head_content" || \
       grep -q -i 'Server:[[:space:]]*Sucuri/Cloudproxy' <<< "$head_content" || \
       grep -q -i 'X-Sucuri-Block:' <<< "$head_content"; then
        printf 'Sucuri CloudProxy\tSucuri\tActive\tSucuri proxy headers\n'
        return 0
    fi

    # 6. F5 BIG-IP ASM
    if grep -q -i 'X-WA-INFO:' <<< "$head_content" || \
       grep -q -i 'Server:[[:space:]]*BigIP' <<< "$head_content" || \
       grep -E -q -i 'Set-Cookie:[[:space:]]*TS[0-9a-f]{8}=' <<< "$head_content"; then
        printf 'F5 BIG-IP ASM\tF5 Networks\tActive\tBIG-IP tracking cookies and headers\n'
        return 0
    fi

    # 7. ModSecurity
    if grep -q -i 'mod_security' <<< "$head_content" || \
       grep -q -i 'ModSecurity' <<< "$body_sample"; then
        printf 'ModSecurity\tTrustwave / OWASP\tActive\tModSecurity server banner / block page signature\n'
        return 0
    fi

    # 8. Fastly
    if grep -q -i 'Fastly-Debug-Digest:' <<< "$head_content" || \
       grep -q -i 'X-Fastly-Request-ID:' <<< "$head_content" || \
       grep -q -i 'X-Served-By:[[:space:]]*cache-' <<< "$head_content"; then
        printf 'Fastly\tFastly\tActive\tFastly edge cache and request tracking headers\n'
        return 0
    fi
}

# Main module runner function.
module_waf_run() {
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

    web_mod_write_header "waf" "WAF Detection"

    local waf_file="${task_dir}/waf_detected.txt"
    : > "$waf_file"

    local wafw00f_bin="${RECKON_MOCK_WAFW00F_BIN:-${WAF_WAFW00F_BIN:-wafw00f}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${WAF_CURL_BIN:-curl}}"

    local has_wafw00f=false
    if [[ "$wafw00f_bin" != "none" ]] && web_mod_has_tool "$wafw00f_bin"; then
        has_wafw00f=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve candidate URLs to inspect (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)

    local engine_name="wafw00f"
    [[ "$has_wafw00f" == false ]] && engine_name="curl header heuristics"

    web_mod_write_section "Inspection Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Engine" "$engine_name"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_waf_tmp="${task_dir}/.raw_waf.tmp"
    : > "$raw_waf_tmp"

    if [[ "$has_wafw00f" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local url
        for url in "${candidate_urls[@]}"; do
            [[ -z "$url" ]] && continue
            local wafw00f_out="${task_dir}/.wafw00f.tmp"

            "$wafw00f_bin" -a --no-colors "$url" > "$wafw00f_out" 2>/dev/null || true

            if [[ -f "$wafw00f_out" && -s "$wafw00f_out" ]]; then
                _waf_parse_wafw00f_output "$wafw00f_out" >> "$raw_waf_tmp"
                rm -f "$wafw00f_out"
            fi
        done
    fi

    # Fallback to curl heuristics if wafw00f is missing or found no WAF.
    if [[ ! -s "$raw_waf_tmp" ]] && web_mod_has_tool "$curl_bin"; then
        local endpoint
        for endpoint in "${candidate_urls[@]}"; do
            [[ -z "$endpoint" ]] && continue
            local head_tmp="${task_dir}/.waf_head.tmp"
            local body_tmp="${task_dir}/.waf_body.tmp"

            local curl_rc=0
            "$curl_bin" -s -S -k -L --max-time 6 -D "$head_tmp" -o "$body_tmp" \
                        -A "$user_agent" "$endpoint" 2>/dev/null || curl_rc=$?

            if (( curl_rc == 0 )) && [[ -f "$head_tmp" && -s "$head_tmp" ]]; then
                _waf_inspect_headers_fallback "$head_tmp" "$body_tmp" >> "$raw_waf_tmp"
            fi
            rm -f "$head_tmp" "$body_tmp"
        done
    fi

    # Deduplicate discovered WAF entries.
    local -a detected_records=()
    if [[ -s "$raw_waf_tmp" ]]; then
        local name vendor status evidence
        while IFS=$'\t' read -r name vendor status evidence || [[ -n "$name" ]]; do
            [[ -z "$name" ]] && continue
            [[ -z "$vendor" ]] && vendor="-"
            [[ -z "$status" ]] && status="Active"
            [[ -z "$evidence" ]] && evidence="Signature match"

            local record="${name}"$'\t'"${vendor}"$'\t'"${status}"$'\t'"${evidence}"
            local exists=false
            local existing
            for existing in "${detected_records[@]}"; do
                if [[ "$existing" == "$record" ]]; then
                    exists=true
                    break
                fi
            done
            if [[ "$exists" == false ]]; then
                detected_records+=("$record")
                printf '%s\t%s\t%s\t%s\n' "$name" "$vendor" "$status" "$evidence" >> "$waf_file"
            fi
        done < "$raw_waf_tmp"
    fi
    rm -f "$raw_waf_tmp"

    # Write structured output report.
    web_mod_write_section "Detected Web Application Firewalls"
    web_mod_write_kv "Total WAFs Detected" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        local rec r_name r_vendor r_status r_evidence
        for rec in "${detected_records[@]}"; do
            IFS=$'\t' read -r r_name r_vendor r_status r_evidence <<< "$rec"
            web_mod_write_raw "  WAF Platform             : $r_name"
            web_mod_write_raw "    Vendor                 : $r_vendor"
            web_mod_write_raw "    Protection Status      : $r_status"
            web_mod_write_raw "    Detection Evidence     : $r_evidence"
            web_mod_write_raw ""
        done
        web_mod_write_footer "COMPLETED" "Identified ${#detected_records[@]} active Web Application Firewall system(s)."
    else
        web_mod_write_kv "Status" "No Web Application Firewall (WAF) detected on target."
        web_mod_write_footer "COMPLETED" "No WAF protections detected."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_waf_run "$@"
fi
