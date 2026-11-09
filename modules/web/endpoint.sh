#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web API and Endpoint Extraction Module (modules/web/endpoint.sh)
#
# Extracts RESTful API routes, GraphQL endpoints, authentication handlers,
# and JavaScript fetch/AJAX URIs from target web pages, client-side bundles,
# and upstream crawling artifacts.
#
# Supported target types:
#   url_http, url_https, hostname, domain
#
# Primary External Tool:
#   - katana (ProjectDiscovery web crawler endpoint extractor)
#
# Fallback Engine:
#   - curl (native API pattern & JavaScript route regex inspection)
#

set -o nounset

ENDPOINT_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$ENDPOINT_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
ENDPOINT_KATANA_BIN="${RECKON_MOCK_KATANA_BIN:-katana}"
ENDPOINT_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Classify an extracted endpoint into a logical security category.
#
# Arguments:
#   $1 - endpoint path or URI
#
# Output:
#   Category identifier on stdout: API, AUTH, ADMIN, or GENERAL
_endpoint_classify() {
    local ep="$1"
    local lower_ep
    lower_ep="$(printf '%s\n' "$ep" | tr '[:upper:]' '[:lower:]')"

    case "$lower_ep" in
        *"/admin"*|*"/manage"*|*"/dashboard"*|*"/cpanel"*|*"/panel"*)
            printf '%s\n' "ADMIN"
            ;;
        *"/auth"*|*"/login"*|*"/logout"*|*"/oauth"*|*"/token"*|*"/register"*|*"/signin"*|*"/signup"*)
            printf '%s\n' "AUTH"
            ;;
        *"/api/"*|*"/v1/"*|*"/v2/"*|*"/v3/"*|*"/graphql"*|*"/rest/"*|*"/swagger"*|*"/openapi"*)
            printf '%s\n' "API"
            ;;
        *)
            printf '%s\n' "GENERAL"
            ;;
    esac
}

# Normalize an extracted endpoint candidate string.
#
# Arguments:
#   $1 - raw candidate token
#
# Output:
#   Clean normalized path on stdout, or return 1 if invalid
_endpoint_normalize() {
    local ep="$1"

    # Strip surrounding quotes and whitespace
    ep="${ep#"${ep%%[![:space:]]*}"}"
    ep="${ep%"${ep##*[![:space:]]}"}"
    ep="${ep#[\"\']}"
    ep="${ep%[\"\']}"
    ep="${ep%$'\r'}"

    # Discard non-endpoint candidates
    case "$ep" in
        ""|"#"*|"javascript:"*|"mailto:"*|"tel:"*|"data:"*)
            return 1
            ;;
        *"<"*|*">"*|*" "*|*"\\"*|*"{"*|*"}"*)
            return 1
            ;;
        "//"*)
            return 1
            ;;
        *.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.css|*.woff|*.woff2)
            return 1
            ;;
    esac

    # If full URL, extract path and query
    if [[ "$ep" =~ ^https?://[^/]+(/.*)?$ ]]; then
        ep="${BASH_REMATCH[1]:-/}"
    fi

    # Ensure path starts with /
    if [[ "$ep" != "/"* ]]; then
        ep="/${ep}"
    fi

    # Strip fragment anchor
    ep="${ep%%\#*}"

    [[ -z "$ep" || "$ep" == "/" ]] && return 1

    printf '%s\n' "$ep"
    return 0
}

# Main entry point for the Web API and Endpoint Extraction module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_http, url_https, hostname, domain)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_endpoint_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Initialize web execution context with supported target types.
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" url_http url_https hostname domain || init_rc=$?
    if (( init_rc == 2 )); then
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "endpoint" "Web API and Endpoint Extraction"

    local endpoint_file="${task_dir}/endpoints.txt"
    : > "$endpoint_file"

    local katana_bin="${RECKON_MOCK_KATANA_BIN:-${ENDPOINT_KATANA_BIN:-katana}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${ENDPOINT_CURL_BIN:-curl}}"

    local has_katana=false
    if [[ "$katana_bin" != "none" ]] && web_mod_has_tool "$katana_bin"; then
        has_katana=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve target domain/host
    local domain_base="${WEB_URL_HOST:-$WEB_TARGET}"
    domain_base="${domain_base%:*}"

    # Collect seed targets from upstream artifacts and candidate endpoints
    local -a seed_urls=()

    # 1. Check upstream crawled URLs from crawl module
    local upstream_crawl="${WEB_PARENT_DIR}/crawl/crawled_urls.txt"
    if [[ -f "$upstream_crawl" && -s "$upstream_crawl" ]]; then
        local c_line
        local c_count=0
        while IFS= read -r c_line || [[ -n "$c_line" ]]; do
            [[ -z "$c_line" ]] && continue
            seed_urls+=("$c_line")
            (( c_count += 1 ))
            (( c_count >= 20 )) && break
        done < "$upstream_crawl"
    fi

    # 2. Check upstream historical URLs from historical-urls module
    local upstream_hist="${WEB_PARENT_DIR}/historical-urls/historical_urls.txt"
    if [[ -f "$upstream_hist" && -s "$upstream_hist" && ${#seed_urls[@]} -lt 25 ]]; then
        local h_line
        local h_count=0
        while IFS= read -r h_line || [[ -n "$h_line" ]]; do
            [[ -z "$h_line" ]] && continue
            seed_urls+=("$h_line")
            (( h_count += 1 ))
            (( h_count >= 15 )) && break
        done < "$upstream_hist"
    fi

    # 3. Add base target URLs if seeds are empty
    if (( ${#seed_urls[@]} == 0 )); then
        mapfile -t seed_urls < <(web_mod_get_target_urls)
    fi

    if (( ${#seed_urls[@]} == 0 )); then
        if [[ "$WEB_TARGET_TYPE" == "url_https" ]]; then
            seed_urls=("https://${domain_base}")
        elif [[ "$WEB_TARGET_TYPE" == "url_http" ]]; then
            seed_urls=("http://${domain_base}")
        else
            seed_urls=("http://${domain_base}" "https://${domain_base}")
        fi
    fi

    local engine_name="katana"
    [[ "$has_katana" == false ]] && engine_name="curl regex API and route inspection"

    web_mod_write_section "Extraction Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Base Domain" "$domain_base"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Extraction Engine" "$engine_name"
    web_mod_write_kv "Seed URLs Inspected" "${#seed_urls[@]}"

    local raw_endpoints_tmp="${task_dir}/.raw_endpoints.tmp"
    : > "$raw_endpoints_tmp"

    # 1. Primary Engine: katana endpoint mode
    if [[ "$has_katana" == true && ${#seed_urls[@]} -gt 0 ]]; then
        local seed
        for seed in "${seed_urls[@]}"; do
            [[ -z "$seed" ]] && continue
            local katana_ep="${task_dir}/.katana_ep.tmp"

            "$katana_bin" -u "$seed" -em apis,endpoints -silent -nc -o "$katana_ep" 2>/dev/null || \
                "$katana_bin" -u "$seed" -d 1 -silent -nc -o "$katana_ep" 2>/dev/null || true

            if [[ -f "$katana_ep" && -s "$katana_ep" ]]; then
                cat "$katana_ep" >> "$raw_endpoints_tmp"
                rm -f "$katana_ep"
            fi
        done
    fi

    # 2. Fallback Engine: native regex endpoint extraction from HTML & JS
    if [[ "$has_katana" == false ]] && web_mod_has_tool "$curl_bin"; then
        local seed
        local inspected_count=0
        local max_inspect=20

        for seed in "${seed_urls[@]}"; do
            [[ -z "$seed" ]] && continue
            (( inspected_count += 1 ))
            (( inspected_count > max_inspect )) && break

            # If seed already contains an endpoint path, record it directly
            if [[ "$seed" =~ ^https?://[^/]+(/api/[^[:space:]]+|/v[0-9]/[^[:space:]]+|/auth/[^[:space:]]+|/admin/[^[:space:]]+) ]]; then
                printf '%s\n' "${BASH_REMATCH[1]}" >> "$raw_endpoints_tmp"
            fi

            local page_body="${task_dir}/.curl_ep_page.tmp"
            "$curl_bin" -s -k -m 4 -L -A "$user_agent" "$seed" > "$page_body" 2>/dev/null || true

            if [[ -f "$page_body" && -s "$page_body" ]]; then
                # Pattern 1: REST API and versioned paths
                grep -o -E '["'\'']/(api|v[0-9]+|graphql|rest|auth|admin|oauth|user|users|token|login|logout|settings|dashboard)/[^"'\''>[:space:]]+["'\'']' "$page_body" 2>/dev/null >> "$raw_endpoints_tmp" || true

                # Pattern 2: fetch() and axios calls
                grep -o -E 'fetch\(["'\''][^"'\'']+["'\'']' "$page_body" 2>/dev/null | sed -E 's/^fetch\(["'\'']//; s/["'\'']$//' >> "$raw_endpoints_tmp" || true
                grep -o -E 'axios\.(get|post|put|delete|patch)\(["'\''][^"'\'']+["'\'']' "$page_body" 2>/dev/null | sed -E 's/^axios\.[a-z]+\(["'\'']//; s/["'\'']$//' >> "$raw_endpoints_tmp" || true

                # Pattern 3: ajax / url properties
                grep -o -E 'url:[[:space:]]*["'\''][^"'\'']+["'\'']' "$page_body" 2>/dev/null | sed -E 's/^url:[[:space:]]*["'\'']//; s/["'\'']$//' >> "$raw_endpoints_tmp" || true

                # Check if page references external .js script bundles
                local -a js_links=()
                mapfile -t js_links < <(grep -o -E 'src=["'\''][^"'\'']+\.js(\?[^"'\'']*)?["'\'']' "$page_body" 2>/dev/null | sed -E 's/^src=["'\'']//; s/["'\'']$//' | head -n 5)

                local js_ref
                for js_ref in "${js_links[@]}"; do
                    [[ -z "$js_ref" ]] && continue
                    local js_url="$js_ref"
                    if [[ "$js_ref" == "/"* ]]; then
                        local scheme_auth
                        if [[ "$seed" =~ ^(https?://[^/]+) ]]; then
                            scheme_auth="${BASH_REMATCH[1]}"
                            js_url="${scheme_auth}${js_ref}"
                        fi
                    fi

                    if [[ "$js_url" =~ ^https?:// ]]; then
                        local js_body="${task_dir}/.curl_js_bundle.tmp"
                        "$curl_bin" -s -k -m 4 -L -A "$user_agent" "$js_url" > "$js_body" 2>/dev/null || true
                        if [[ -f "$js_body" && -s "$js_body" ]]; then
                            grep -o -E '["'\'']/(api|v[0-9]+|graphql|auth|admin|oauth)/[^"'\''>[:space:]]+["'\'']' "$js_body" 2>/dev/null >> "$raw_endpoints_tmp" || true
                            grep -o -E 'fetch\(["'\''][^"'\'']+["'\'']' "$js_body" 2>/dev/null | sed -E 's/^fetch\(["'\'']//; s/["'\'']$//' >> "$raw_endpoints_tmp" || true
                            grep -o -E 'axios\.(get|post|put|delete|patch)\(["'\''][^"'\'']+["'\'']' "$js_body" 2>/dev/null | sed -E 's/^axios\.[a-z]+\(["'\'']//; s/["'\'']$//' >> "$raw_endpoints_tmp" || true
                            rm -f "$js_body"
                        fi
                    fi
                done

                rm -f "$page_body"
            fi
        done
    fi

    # 3. Deduplicate, classify, and sort discovered endpoints
    local -a unique_records=()
    local -a api_records=()
    local -a auth_records=()
    local -a admin_records=()
    local -a general_records=()

    if [[ -s "$raw_endpoints_tmp" ]]; then
        local raw_line
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            local clean_ep
            if clean_ep="$(_endpoint_normalize "$raw_line")"; then
                local category
                category="$(_endpoint_classify "$clean_ep")"

                local rec="${clean_ep}"$'\t'"${category}"
                local exists=false
                local item
                for item in "${unique_records[@]}"; do
                    if [[ "$item" == "$rec" ]]; then
                        exists=true
                        break
                    fi
                done

                if [[ "$exists" == false ]]; then
                    unique_records+=("$rec")

                    case "$category" in
                        API)     api_records+=("$clean_ep") ;;
                        AUTH)    auth_records+=("$clean_ep") ;;
                        ADMIN)   admin_records+=("$clean_ep") ;;
                        GENERAL) general_records+=("$clean_ep") ;;
                    esac
                fi
            fi
        done < "$raw_endpoints_tmp"
    fi

    rm -f "$raw_endpoints_tmp"

    # Write unique endpoints to artifact file
    if (( ${#unique_records[@]} > 0 )); then
        local -a sorted_records=()
        mapfile -t sorted_records < <(printf '%s\n' "${unique_records[@]}" | sort -u)
        local r
        for r in "${sorted_records[@]}"; do
            printf '%s\n' "$r" >> "$endpoint_file"
        done
    fi

    # Format human-readable output report
    web_mod_write_section "Endpoint Findings"
    web_mod_write_kv "Total Endpoints Discovered" "${#unique_records[@]}"
    web_mod_write_kv "REST API & Routes" "${#api_records[@]}"
    web_mod_write_kv "Authentication Endpoints" "${#auth_records[@]}"
    web_mod_write_kv "Administrative Endpoints" "${#admin_records[@]}"
    web_mod_write_kv "General Web Endpoints" "${#general_records[@]}"

    if (( ${#unique_records[@]} > 0 )); then
        if (( ${#api_records[@]} > 0 )); then
            web_mod_write_raw "  Discovered REST & API Routes:"
            local a_count=0
            local a_ep
            for a_ep in "${api_records[@]}"; do
                web_mod_write_raw "    - $a_ep [API]"
                (( a_count += 1 ))
                (( a_count >= 10 )) && break
            done
        fi

        if (( ${#auth_records[@]} > 0 )); then
            web_mod_write_raw "  Authentication Endpoints:"
            local au_count=0
            local au_ep
            for au_ep in "${auth_records[@]}"; do
                web_mod_write_raw "    - $au_ep [AUTH]"
                (( au_count += 1 ))
                (( au_count >= 5 )) && break
            done
        fi

        if (( ${#admin_records[@]} > 0 )); then
            web_mod_write_raw "  Administrative Endpoints:"
            local ad_count=0
            local ad_ep
            for ad_ep in "${admin_records[@]}"; do
                web_mod_write_raw "    - $ad_ep [ADMIN]"
                (( ad_count += 1 ))
                (( ad_count >= 5 )) && break
            done
        fi

        web_mod_write_footer "COMPLETED" "Extracted ${#unique_records[@]} endpoint(s) (${#api_records[@]} API, ${#auth_records[@]} Auth, ${#admin_records[@]} Admin)."
    else
        web_mod_write_kv "Status" "No API routes or endpoints identified."
        web_mod_write_footer "COMPLETED" "No endpoints discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_endpoint_run "$@"
fi
