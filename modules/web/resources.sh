#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Resource Discovery Module (modules/web/resources.sh)
#
# Inspects well-known site metadata, crawling policy directives, security
# disclosure policies, OpenID configs, and favicon cryptographic hashes.
#
# Supported target types:
#   url_http, url_https, hostname, domain
#
# Primary External Tool:
#   - curl (native HTTP resource inspection and hashing)
#

set -o nounset

RESOURCES_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$RESOURCES_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
RESOURCES_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Main entry point for the Web Resource Discovery module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_http, url_https, hostname, domain)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_resources_run() {
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

    web_mod_write_header "resources" "Web Resource and Metadata Discovery"

    local resources_file="${task_dir}/resources.txt"
    : > "$resources_file"

    local curl_bin="${RECKON_MOCK_CURL_BIN:-${RESOURCES_CURL_BIN:-curl}}"
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

    local base_url="${candidate_urls[0]}"
    base_url="${base_url%/}"

    web_mod_write_section "Resource Probing Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Base Domain" "$domain_base"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Base URL" "$base_url"

    local -a discovered_resources=()
    local -a disallow_rules=()
    local sitemap_url=""
    local sitemap_count=0
    local security_contact=""
    local favicon_hash=""

    # 1. Probing /robots.txt
    local robots_tmp="${task_dir}/.robots.tmp"
    local robots_status
    robots_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$robots_tmp" -w "%{http_code}" "${base_url}/robots.txt" 2>/dev/null || true)"

    if [[ "$robots_status" == "200" && -s "$robots_tmp" ]]; then
        local r_size
        r_size="$(wc -c < "$robots_tmp" | tr -d ' ')"
        discovered_resources+=("/robots.txt [HTTP 200, ${r_size} bytes]")

        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$line" =~ ^[[:space:]]*Disallow:[[:space:]]*(.*) ]]; then
                local rule="${BASH_REMATCH[1]}"
                rule="${rule%$'\r'}"
                [[ -n "$rule" ]] && disallow_rules+=("$rule")
            elif [[ "$line" =~ ^[[:space:]]*Sitemap:[[:space:]]*(.*) ]]; then
                local s_map="${BASH_REMATCH[1]}"
                sitemap_url="${s_map%$'\r'}"
            fi
        done < "$robots_tmp"

        local disallow_summary="Disallow rules: ${#disallow_rules[@]}"
        printf '/robots.txt\t200\t%s\t%s\n' "$r_size" "$disallow_summary" >> "$resources_file"
    else
        printf '/robots.txt\t%s\t-\tNot found\n' "${robots_status:-404}" >> "$resources_file"
    fi
    rm -f "$robots_tmp"

    # 2. Probing /sitemap.xml
    local sitemap_target="${sitemap_url:-${base_url}/sitemap.xml}"
    local sitemap_tmp="${task_dir}/.sitemap.tmp"
    local sitemap_status
    sitemap_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$sitemap_tmp" -w "%{http_code}" "$sitemap_target" 2>/dev/null || true)"

    if [[ "$sitemap_status" == "200" && -s "$sitemap_tmp" ]]; then
        local sm_size
        sm_size="$(wc -c < "$sitemap_tmp" | tr -d ' ')"
        sitemap_count="$(grep -c '<loc>' "$sitemap_tmp" 2>/dev/null || true)"
        discovered_resources+=("/sitemap.xml [HTTP 200, ${sitemap_count} URLs listed]")
        printf '/sitemap.xml\t200\t%s\tTotal URLs: %s\n' "$sm_size" "$sitemap_count" >> "$resources_file"
    else
        printf '/sitemap.xml\t%s\t-\tNot found\n' "${sitemap_status:-404}" >> "$resources_file"
    fi
    rm -f "$sitemap_tmp"

    # 3. Probing Security Disclosure Policy (security.txt)
    local sec_txt_tmp="${task_dir}/.security_txt.tmp"
    local sec_status
    sec_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$sec_txt_tmp" -w "%{http_code}" "${base_url}/.well-known/security.txt" 2>/dev/null || true)"

    if [[ "$sec_status" != "200" ]]; then
        sec_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$sec_txt_tmp" -w "%{http_code}" "${base_url}/security.txt" 2>/dev/null || true)"
    fi

    if [[ "$sec_status" == "200" && -s "$sec_txt_tmp" ]]; then
        local sec_size
        sec_size="$(wc -c < "$sec_txt_tmp" | tr -d ' ')"
        security_contact="$(grep -i '^[[:space:]]*Contact:' "$sec_txt_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
        discovered_resources+=("security.txt [HTTP 200, Contact: ${security_contact:-Defined}]")
        printf '/.well-known/security.txt\t200\t%s\tContact: %s\n' "$sec_size" "${security_contact:-(none)}" >> "$resources_file"
    else
        printf '/.well-known/security.txt\t%s\t-\tNot found\n' "${sec_status:-404}" >> "$resources_file"
    fi
    rm -f "$sec_txt_tmp"

    # 4. Probing OpenID / OAuth Configuration
    local oidc_tmp="${task_dir}/.oidc.tmp"
    local oidc_status
    oidc_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$oidc_tmp" -w "%{http_code}" "${base_url}/.well-known/openid-configuration" 2>/dev/null || true)"

    if [[ "$oidc_status" == "200" && -s "$oidc_tmp" ]]; then
        local oidc_size
        oidc_size="$(wc -c < "$oidc_tmp" | tr -d ' ')"
        discovered_resources+=("/.well-known/openid-configuration [HTTP 200, ${oidc_size} bytes]")
        printf '/.well-known/openid-configuration\t200\t%s\tOAuth/OIDC Configuration Discovered\n' "$oidc_size" >> "$resources_file"
    else
        printf '/.well-known/openid-configuration\t%s\t-\tNot found\n' "${oidc_status:-404}" >> "$resources_file"
    fi
    rm -f "$oidc_tmp"

    # 5. Probing Favicon and Calculating Cryptographic Hashes
    local fav_tmp="${task_dir}/.favicon.ico.tmp"
    local fav_status
    fav_status="$("$curl_bin" -s -k -m 5 -L -A "$user_agent" -o "$fav_tmp" -w "%{http_code}" "${base_url}/favicon.ico" 2>/dev/null || true)"

    if [[ "$fav_status" == "200" && -s "$fav_tmp" ]]; then
        local fav_size
        fav_size="$(wc -c < "$fav_tmp" | tr -d ' ')"
        local fav_md5
        fav_md5="$(md5sum "$fav_tmp" 2>/dev/null | awk '{print $1}' || true)"
        favicon_hash="$fav_md5"

        discovered_resources+=("/favicon.ico [HTTP 200, MD5: ${fav_md5}]")
        printf '/favicon.ico\t200\t%s\tMD5: %s\n' "$fav_size" "$fav_md5" >> "$resources_file"
    else
        printf '/favicon.ico\t%s\t-\tNot found\n' "${fav_status:-404}" >> "$resources_file"
    fi
    rm -f "$fav_tmp"

    # Format human-readable output report
    web_mod_write_section "Discovered Metadata Resources"
    web_mod_write_kv "Total Discovered" "${#discovered_resources[@]}"

    if (( ${#discovered_resources[@]} > 0 )); then
        local res
        for res in "${discovered_resources[@]}"; do
            web_mod_write_raw "    - $res"
        done
    fi

    if (( ${#disallow_rules[@]} > 0 )); then
        web_mod_write_section "robots.txt Disallow Rules"
        local d_count=0
        local rule
        for rule in "${disallow_rules[@]}"; do
            web_mod_write_raw "    - $rule"
            (( d_count += 1 ))
            (( d_count >= 15 )) && break
        done
    fi

    if [[ -n "$favicon_hash" ]]; then
        web_mod_write_section "Favicon Cryptographic Hashes"
        web_mod_write_kv "MD5 Hash" "$favicon_hash"
    fi

    local footer_msg="Discovered ${#discovered_resources[@]} standard web metadata resource(s)."
    if (( ${#discovered_resources[@]} == 0 )); then
        footer_msg="No standard web metadata resources discovered."
    fi

    web_mod_write_footer "COMPLETED" "$footer_msg"

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_resources_run "$@"
fi
