#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Technology Fingerprinting Module (modules/web/technology.sh)
#
# Identifies web application frameworks, content delivery networks, web servers,
# programming languages, and client-side JavaScript libraries.
#
# Supported target types:
#   url_http, url_https, hostname, domain, ipv4
#
# Primary External Tool:
#   - whatweb (comprehensive web technology fingerprinting engine)
#
# Fallback Engine:
#   - curl (native response header, server banner, and meta tag inspection)
#

set -o nounset

TECH_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$TECH_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
TECH_WHATWEB_BIN="${RECKON_MOCK_WHATWEB_BIN:-whatweb}"
TECH_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Clean and extract individual plugin entries from WhatWeb brief output format:
# Input: http://example.com [200 OK] Apache[2.4.41], Country[US], HTTPServer[Ubuntu Linux][Apache/2.4.41], jQuery[3.5.1]
_tech_parse_whatweb_line() {
    local line="$1"
    [[ -z "$line" ]] && return 0

    # Strip the leading URL and status code bracket [200 OK]
    local rest="$line"
    local lead_regex='^https?://[^[:space:]]+[[:space:]]+\[[0-9]+[^]]*\][[:space:]]*(.*)$'
    if [[ "$rest" =~ $lead_regex ]]; then
        rest="${BASH_REMATCH[1]}"
    fi

    # Split by comma-space delimiter and extract technology tags
    local IFS=','
    local -a raw_items=()
    read -r -a raw_items <<< "$rest"

    local item name details
    local item_regex='^([A-Za-z0-9_.-]+)\[([^]]*)\](\[([^]]*)\])?'
    local fallback_regex='^([A-Za-z0-9_.-]+)'
    for item in "${raw_items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -z "$item" ]] && continue

        # Ignore noisy generic location or IP metadata tags
        case "$item" in
            Country\[*|IP\[*|Title\[*|Unassigned\[*|Cookies\[*)
                continue
                ;;
        esac

        # Pattern: PluginName[Version/Details][Extra]
        if [[ "$item" =~ $item_regex ]]; then
            name="${BASH_REMATCH[1]}"
            details="${BASH_REMATCH[2]}"
            local extra="${BASH_REMATCH[4]:-}"
            if [[ -n "$extra" && "$extra" != "$details" ]]; then
                details="${details} (${extra})"
            fi
            [[ -z "$details" ]] && details="-"
            printf '%s\t%s\n' "$name" "$details"
        elif [[ "$item" =~ $fallback_regex ]]; then
            printf '%s\t-\n' "${BASH_REMATCH[1]}"
        fi
    done
}

# Native header inspection heuristics when WhatWeb is absent or returns empty.
_tech_inspect_headers_fallback() {
    local header_file="$1"
    local body_file="$2"
    [[ ! -f "$header_file" ]] && return 0

    # Web Server inspection
    local server_header
    server_header="$(grep -i '^Server:' "$header_file" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
    if [[ -n "$server_header" ]]; then
        printf 'Server\t%s\n' "$server_header"
        if [[ "$server_header" =~ Apache/?([0-9.]*) ]]; then
            printf 'Apache\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$server_header" =~ nginx/?([0-9.]*) ]]; then
            printf 'nginx\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$server_header" =~ Microsoft-IIS/?([0-9.]*) ]]; then
            printf 'Microsoft-IIS\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$server_header" =~ Caddy/?([0-9.]*) ]]; then
            printf 'Caddy\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$server_header" =~ LiteSpeed ]]; then
            printf 'LiteSpeed\t-\n'
        fi
        if [[ "$server_header" =~ cloudflare ]]; then
            printf 'Cloudflare\t-\n'
        fi
    fi

    # Powered-by headers (PHP, Express, ASP.NET, etc.)
    local powered_by
    powered_by="$(grep -i '^X-Powered-By:' "$header_file" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
    if [[ -n "$powered_by" ]]; then
        printf 'X-Powered-By\t%s\n' "$powered_by"
        if [[ "$powered_by" =~ PHP/?([0-9.]*) ]]; then
            printf 'PHP\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$powered_by" =~ Express ]]; then
            printf 'Express.js\t-\n'
        fi
        if [[ "$powered_by" =~ ASP\.NET ]]; then
            printf 'ASP.NET\t-\n'
        fi
    fi

    # Body heuristics: JavaScript libraries and meta generators
    if [[ -f "$body_file" && -s "$body_file" ]]; then
        local body_sample
        body_sample="$(head -c 65536 "$body_file" 2>/dev/null || true)"

        if [[ "$body_sample" =~ jquery[-.]([0-9.]+)?(\.min)?\.js ]]; then
            printf 'jQuery\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$body_sample" =~ bootstrap[-.]([0-9.]+)?(\.min)?\.(js|css) ]]; then
            printf 'Bootstrap\t%s\n' "${BASH_REMATCH[1]:--}"
        fi
        if [[ "$body_sample" =~ react(\.production|\.development)?(\.min)?\.js || "$body_sample" =~ data-reactroot ]]; then
            printf 'React\t-\n'
        fi
        if [[ "$body_sample" =~ vue(\.min)?\.js ]]; then
            printf 'Vue.js\t-\n'
        fi
        if [[ "$body_sample" =~ angular(\.min)?\.js ]]; then
            printf 'Angular\t-\n'
        fi
    fi
}

# Main module runner function.
module_technology_run() {
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

    web_mod_write_header "technology" "Technology Fingerprinting"

    local tech_file="${task_dir}/technologies.txt"
    : > "$tech_file"

    local whatweb_bin="${RECKON_MOCK_WHATWEB_BIN:-${TECH_WHATWEB_BIN:-whatweb}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${TECH_CURL_BIN:-curl}}"

    local has_whatweb=false
    if [[ "$whatweb_bin" != "none" ]] && web_mod_has_tool "$whatweb_bin"; then
        has_whatweb=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve candidate URLs to inspect (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)

    local engine_name="whatweb"
    [[ "$has_whatweb" == false ]] && engine_name="curl fallback heuristics"

    web_mod_write_section "Fingerprinting Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Engine" "$engine_name"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_tech_tmp="${task_dir}/.raw_tech.tmp"
    : > "$raw_tech_tmp"

    if [[ "$has_whatweb" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local whatweb_out="${task_dir}/.whatweb.tmp"
        "$whatweb_bin" --color=never \
                       --log-brief="$whatweb_out" \
                       --user-agent="$user_agent" \
                       -a 1 \
                       "${candidate_urls[@]}" >/dev/null 2>&1 || true

        if [[ -f "$whatweb_out" && -s "$whatweb_out" ]]; then
            local ww_line
            while IFS= read -r ww_line || [[ -n "$ww_line" ]]; do
                _tech_parse_whatweb_line "$ww_line" >> "$raw_tech_tmp"
            done < "$whatweb_out"
            rm -f "$whatweb_out"
        fi
    fi

    # Fallback to curl inspection if whatweb is missing or returned zero findings.
    if [[ ! -s "$raw_tech_tmp" ]] && web_mod_has_tool "$curl_bin"; then
        local endpoint
        for endpoint in "${candidate_urls[@]}"; do
            [[ -z "$endpoint" ]] && continue
            local head_tmp="${task_dir}/.head.tmp"
            local body_tmp="${task_dir}/.body.tmp"

            local curl_rc=0
            "$curl_bin" -s -S -k -L --max-time 6 -D "$head_tmp" -o "$body_tmp" \
                        -A "$user_agent" "$endpoint" 2>/dev/null || curl_rc=$?

            if (( curl_rc == 0 )) && [[ -f "$head_tmp" ]]; then
                _tech_inspect_headers_fallback "$head_tmp" "$body_tmp" >> "$raw_tech_tmp"
            fi
            rm -f "$head_tmp" "$body_tmp"
        done
    fi

    # Deduplicate and sort discovered technologies.
    local -a detected_records=()
    if [[ -s "$raw_tech_tmp" ]]; then
        local name ver
        while IFS=$'\t' read -r name ver || [[ -n "$name" ]]; do
            name="${name#"${name%%[![:space:]]*}"}"
            name="${name%"${name##*[![:space:]]}"}"
            ver="${ver#"${ver%%[![:space:]]*}"}"
            ver="${ver%"${ver##*[![:space:]]}"}"
            [[ -z "$name" ]] && continue
            [[ -z "$ver" ]] && ver="-"

            local record="${name}"$'\t'"${ver}"
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
                printf '%s\t%s\n' "$name" "$ver" >> "$tech_file"
            fi
        done < "$raw_tech_tmp"
    fi
    rm -f "$raw_tech_tmp"

    # Write structured output report.
    web_mod_write_section "Identified Technologies"
    web_mod_write_kv "Total Detected" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        web_mod_write_raw "  Detected Stack & Components:"
        local rec r_name r_ver
        for rec in "${detected_records[@]}"; do
            r_name="${rec%%$'\t'*}"
            r_ver="${rec##*$'\t'}"
            if [[ "$r_ver" != "-" ]]; then
                web_mod_write_raw "    - ${r_name} (${r_ver})"
            else
                web_mod_write_raw "    - ${r_name}"
            fi
        done
        web_mod_write_footer "COMPLETED" "Identified ${#detected_records[@]} technology stack component(s)."
    else
        web_mod_write_kv "Status" "No technologies or framework signatures detected."
        web_mod_write_footer "COMPLETED" "No technologies identified."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_technology_run "$@"
fi
