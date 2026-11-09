#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Content Management System (CMS) Detection Module (modules/web/cms.sh)
#
# Identifies Content Management Systems (WordPress, Drupal, Joomla, Ghost,
# Magento, Shopify, PrestaShop, Typo3, etc.) and exposed version metadata.
#
# Supported target types:
#   url_http, url_https, hostname, domain, ipv4
#
# Primary External Tool:
#   - whatweb (CMS and web platform detection plugins)
#
# Fallback Engine:
#   - curl (heuristic meta generator, path signature, and cookie inspection)
#

set -o nounset

CMS_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$CMS_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
CMS_WHATWEB_BIN="${RECKON_MOCK_WHATWEB_BIN:-whatweb}"
CMS_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Canonical CMS platform identifiers recognized by WhatWeb and signature heuristics.
readonly _CMS_PLATFORMS=(
    "WordPress"
    "Joomla"
    "Drupal"
    "Ghost"
    "Magento"
    "Shopify"
    "PrestaShop"
    "TYPO3"
    "Moodle"
    "Bitrix"
    "OpenCart"
    "vBulletin"
    "phpBB"
    "MediaWiki"
    "Discourse"
    "Squarespace"
    "Wix"
)

# Extract CMS records from WhatWeb brief output format.
_cms_parse_whatweb_line() {
    local line="$1"
    [[ -z "$line" ]] && return 0

    local rest="$line"
    if [[ "$rest" =~ ^https?://[^[:space:]]+[[:space:]]+\[[0-9]+[^]]*\][[:space:]]*(.*)$ ]]; then
        rest="${BASH_REMATCH[1]}"
    fi

    local IFS=','
    local -a raw_items=()
    read -r -a raw_items <<< "$rest"

    local item cms_target
    for item in "${raw_items[@]}"; do
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [[ -z "$item" ]] && continue

        for cms_target in "${_CMS_PLATFORMS[@]}"; do
            # Case-insensitive comparison against known CMS names
            local item_lower cms_lower
            item_lower="$(printf '%s' "$item" | tr '[:upper:]' '[:lower:]')"
            cms_lower="$(printf '%s' "$cms_target" | tr '[:upper:]' '[:lower:]')"

            if [[ "$item_lower" =~ ^${cms_lower}(\[([^]]*)\])? ]]; then
                local ver="${BASH_REMATCH[2]:--}"
                printf '%s\t%s\tHigh\tWhatWeb plugin match\n' "$cms_target" "$ver"
                break
            fi
        done
    done
}

# Heuristic signature inspection when WhatWeb is absent or inconclusive.
_cms_inspect_heuristics() {
    local head_file="$1"
    local body_file="$2"

    # 1. Header and cookie inspection
    if [[ -f "$head_file" && -s "$head_file" ]]; then
        if grep -q -i 'Set-Cookie:.*wp-settings' "$head_file" || grep -q -i 'X-Pingback:.*xmlrpc\.php' "$head_file"; then
            printf 'WordPress\t-\tHigh\tWordPress header/cookie signature\n'
            return 0
        fi
        if grep -q -i 'X-Drupal-Cache' "$head_file" || grep -q -i 'X-Generator:.*Drupal' "$head_file"; then
            printf 'Drupal\t-\tHigh\tDrupal response header\n'
            return 0
        fi
    fi

    [[ ! -f "$body_file" ]] && return 0
    local body_sample
    body_sample="$(head -c 131072 "$body_file" 2>/dev/null || true)"

    # 1. Meta generator inspection (standard HTML tag)
    local gen=""
    if grep -q -i '<meta[^>]*generator' <<< "$body_sample"; then
        gen="$(grep -i -o '<meta[^>]*>' <<< "$body_sample" | grep -i 'generator' | sed -e 's/.*content=["'\'']//' -e 's/["'\''].*//' | head -n 1 || true)"
    fi

    if [[ -n "$gen" ]]; then
        local cms_cand
        for cms_cand in "${_CMS_PLATFORMS[@]}"; do
            local gen_lower cand_lower
            gen_lower="$(printf '%s' "$gen" | tr '[:upper:]' '[:lower:]')"
            cand_lower="$(printf '%s' "$cms_cand" | tr '[:upper:]' '[:lower:]')"
            if [[ "$gen_lower" =~ ${cand_lower}[[:space:]]*([0-9.]*) ]]; then
                local gen_ver="${BASH_REMATCH[1]:--}"
                printf '%s\t%s\tHigh\tMeta Generator tag (%s)\n' "$cms_cand" "$gen_ver" "$gen"
                return 0
            fi
        done
    fi

    # 2. WordPress heuristics
    if [[ "$body_sample" =~ wp-content/ || "$body_sample" =~ wp-includes/ || "$body_sample" =~ /wp-json/ ]]; then
        local wp_ver="-"
        if [[ "$body_sample" =~ ver=([0-9]+\.[0-9]+(\.[0-9]+)?) ]]; then
            wp_ver="${BASH_REMATCH[1]}"
        fi
        printf 'WordPress\t%s\tHigh\twp-content and asset signatures\n' "$wp_ver"
        return 0
    fi

    # 3. Joomla heuristics
    if [[ "$body_sample" =~ media/system/js || "$body_sample" =~ /components/com_ ]]; then
        printf 'Joomla\t-\tMedium\tSystem component asset paths\n'
        return 0
    fi

    # 4. Drupal heuristics
    if [[ "$body_sample" =~ Drupal\.settings || "$body_sample" =~ sites/default/files || "$body_sample" =~ misc/drupal\.js ]]; then
        printf 'Drupal\t-\tHigh\tDrupal JavaScript object and file paths\n'
        return 0
    fi

    # 5. Ghost heuristics
    if [[ "$body_sample" =~ ghost-root ]] || grep -q -i '<meta[^>]*ghost-' <<< "$body_sample"; then
        printf 'Ghost\t-\tHigh\tGhost asset and meta tags\n'
        return 0
    fi

    # 6. Shopify heuristics
    if [[ "$body_sample" =~ cdn\.shopify\.com || "$body_sample" =~ Shopify\.theme ]]; then
        printf 'Shopify\t-\tHigh\tShopify CDN and theme signatures\n'
        return 0
    fi

    # 7. Magento heuristics
    if [[ "$body_sample" =~ Mage\.Cookies || "$body_sample" =~ /skin/frontend/ ]]; then
        printf 'Magento\t-\tHigh\tMage JavaScript objects and skin paths\n'
        return 0
    fi
}

# Main module runner function.
module_cms_run() {
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

    web_mod_write_header "cms" "CMS Detection"

    local cms_file="${task_dir}/cms_detected.txt"
    : > "$cms_file"

    local whatweb_bin="${RECKON_MOCK_WHATWEB_BIN:-${CMS_WHATWEB_BIN:-whatweb}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${CMS_CURL_BIN:-curl}}"

    local has_whatweb=false
    if [[ "$whatweb_bin" != "none" ]] && web_mod_has_tool "$whatweb_bin"; then
        has_whatweb=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve candidate URLs (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)

    local engine_name="whatweb"
    [[ "$has_whatweb" == false ]] && engine_name="curl signature heuristics"

    web_mod_write_section "Detection Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Engine" "$engine_name"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_cms_tmp="${task_dir}/.raw_cms.tmp"
    : > "$raw_cms_tmp"

    if [[ "$has_whatweb" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local whatweb_out="${task_dir}/.whatweb_cms.tmp"
        "$whatweb_bin" --color=never \
                       --log-brief="$whatweb_out" \
                       --user-agent="$user_agent" \
                       -a 1 \
                       "${candidate_urls[@]}" >/dev/null 2>&1 || true

        if [[ -f "$whatweb_out" && -s "$whatweb_out" ]]; then
            local ww_line
            while IFS= read -r ww_line || [[ -n "$ww_line" ]]; do
                _cms_parse_whatweb_line "$ww_line" >> "$raw_cms_tmp"
            done < "$whatweb_out"
            rm -f "$whatweb_out"
        fi
    fi

    # Fallback to targeted signature inspection if whatweb found nothing or is absent.
    if [[ ! -s "$raw_cms_tmp" ]] && web_mod_has_tool "$curl_bin"; then
        local endpoint
        for endpoint in "${candidate_urls[@]}"; do
            [[ -z "$endpoint" ]] && continue
            local head_tmp="${task_dir}/.cms_head.tmp"
            local body_tmp="${task_dir}/.cms_body.tmp"

            local curl_rc=0
            "$curl_bin" -s -S -k -L --max-time 6 -D "$head_tmp" -o "$body_tmp" \
                        -A "$user_agent" "$endpoint" 2>/dev/null || curl_rc=$?

            if (( curl_rc == 0 )) && [[ -f "$body_tmp" && -s "$body_tmp" ]]; then
                _cms_inspect_heuristics "$head_tmp" "$body_tmp" >> "$raw_cms_tmp"
            fi
            rm -f "$head_tmp" "$body_tmp"
        done
    fi

    # Deduplicate discovered CMS entries.
    local -a detected_records=()
    if [[ -s "$raw_cms_tmp" ]]; then
        local name ver conf evid
        while IFS=$'\t' read -r name ver conf evid || [[ -n "$name" ]]; do
            [[ -z "$name" ]] && continue
            [[ -z "$ver" ]] && ver="-"
            [[ -z "$conf" ]] && conf="High"
            [[ -z "$evid" ]] && evid="Signature match"

            local record="${name}"$'\t'"${ver}"$'\t'"${conf}"$'\t'"${evid}"
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
                printf '%s\t%s\t%s\t%s\n' "$name" "$ver" "$conf" "$evid" >> "$cms_file"
            fi
        done < "$raw_cms_tmp"
    fi
    rm -f "$raw_cms_tmp"

    # Write report sections.
    web_mod_write_section "Detected CMS Platforms"
    web_mod_write_kv "Total CMS Detected" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        local rec r_name r_ver r_conf r_evid
        for rec in "${detected_records[@]}"; do
            IFS=$'\t' read -r r_name r_ver r_conf r_evid <<< "$rec"
            web_mod_write_raw "  CMS Platform             : $r_name"
            web_mod_write_raw "    Version                : $r_ver"
            web_mod_write_raw "    Confidence             : $r_conf"
            web_mod_write_raw "    Evidence               : $r_evid"
            web_mod_write_raw ""
        done
        web_mod_write_footer "COMPLETED" "Detected ${#detected_records[@]} Content Management System platform(s)."
    else
        web_mod_write_kv "Status" "No CMS signatures (WordPress, Drupal, Joomla, etc.) identified."
        web_mod_write_footer "COMPLETED" "No CMS platforms detected."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_cms_run "$@"
fi
