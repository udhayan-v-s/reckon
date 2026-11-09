#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Historical URL Discovery Module (modules/web/historical-urls.sh)
#
# Passively queries public web archives, search index caches, and endpoint
# registries to extract historical URLs, parameters, endpoints, and assets.
#
# Supported target types:
#   domain, hostname, url_http, url_https
#
# Primary External Tool:
#   - gau (GetAllURLs - queries AlienVault OTX, Wayback Machine, Common Crawl)
#
# Fallback Engine:
#   - curl (native API interrogation of Wayback Machine CDX and AlienVault OTX)
#

set -o nounset

HIST_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$HIST_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HISTORICAL_GAU_BIN="${RECKON_MOCK_GAU_BIN:-gau}"
HISTORICAL_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Extract host from URL.
_hist_extract_host() {
    local u="$1"
    local rem="${u#*://}"
    local h="${rem%%/*}"
    h="${h%:*}"
    printf '%s\n' "$h"
}

# Check if a URL matches sensitive or high-value file extensions.
#
# Arguments:
#   $1 - URL to check
#
# Returns:
#   0 if sensitive, 1 otherwise
_hist_is_sensitive_file() {
    local test_url="$1"
    local clean_path="${test_url%%\?*}"
    clean_path="${clean_path%%\#*}"

    case "$clean_path" in
        *.php|*.asp|*.aspx|*.jsp|*.json|*.xml|*.sql|*.bak|*.conf|*.config|*.env|*.log|*.yaml|*.yml|*.txt|*.tar|*.gz|*.zip|*.db|*.sqlite)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Main entry point for the Historical URL Discovery module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (domain, hostname, url_http, url_https)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_historical_urls_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Initialize web execution context with supported target types.
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" domain hostname url_http url_https || init_rc=$?
    if (( init_rc == 2 )); then
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "historical-urls" "Historical URL Discovery"

    local hist_file="${task_dir}/historical_urls.txt"
    : > "$hist_file"

    local gau_bin="${RECKON_MOCK_GAU_BIN:-${HISTORICAL_GAU_BIN:-gau}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${HISTORICAL_CURL_BIN:-curl}}"

    local has_gau=false
    if [[ "$gau_bin" != "none" ]] && web_mod_has_tool "$gau_bin"; then
        has_gau=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve query domain
    local query_domain="${WEB_URL_HOST:-$WEB_TARGET}"
    query_domain="${query_domain%:*}"

    local engine_name="gau (GetAllURLs)"
    [[ "$has_gau" == false ]] && engine_name="curl archive APIs (Wayback Machine CDX & AlienVault OTX)"

    web_mod_write_section "Reconnaissance Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Query Domain" "$query_domain"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Extraction Engine" "$engine_name"
    web_mod_write_kv "Archive Sources" "Wayback Machine, AlienVault OTX, Common Crawl"

    local raw_urls_tmp="${task_dir}/.raw_hist_urls.tmp"
    : > "$raw_urls_tmp"

    # 1. Primary Engine: gau execution
    if [[ "$has_gau" == true ]]; then
        local gau_out="${task_dir}/.gau_out.tmp"
        "$gau_bin" --threads 5 "$query_domain" > "$gau_out" 2>/dev/null || \
            "$gau_bin" "$query_domain" > "$gau_out" 2>/dev/null || true

        if [[ -f "$gau_out" && -s "$gau_out" ]]; then
            cat "$gau_out" >> "$raw_urls_tmp"
            rm -f "$gau_out"
        fi
    fi

    # 2. Fallback Engine: native curl public archive queries
    if [[ "$has_gau" == false ]] && web_mod_has_tool "$curl_bin"; then
        # Query 1: Wayback Machine CDX API
        local wb_url="https://web.archive.org/cdx/search/cdx?url=*.${query_domain}/*&output=text&fl=original&collapse=urlkey&limit=500"
        "$curl_bin" -s -k -m 8 -A "$user_agent" "$wb_url" >> "$raw_urls_tmp" 2>/dev/null || true

        # Query 2: AlienVault OTX API
        local otx_url="https://otx.alienvault.com/api/v1/indicators/domain/${query_domain}/url_list?limit=500"
        local otx_tmp="${task_dir}/.otx_raw.tmp"
        "$curl_bin" -s -k -m 8 -A "$user_agent" "$otx_url" > "$otx_tmp" 2>/dev/null || true

        if [[ -f "$otx_tmp" && -s "$otx_tmp" ]]; then
            if web_mod_has_tool "jq"; then
                jq -r '.url_list[]?.url // empty' "$otx_tmp" >> "$raw_urls_tmp" 2>/dev/null || true
            else
                grep -o '"url": *"[^"]*"' "$otx_tmp" | cut -d'"' -f4 >> "$raw_urls_tmp" 2>/dev/null || true
            fi
            rm -f "$otx_tmp"
        fi
    fi

    # 3. Filter, sanitize, and classify discovered URLs
    local -a unique_urls=()
    local -a unique_paths=()
    local -a param_urls=()
    local -a sensitive_urls=()

    if [[ -s "$raw_urls_tmp" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            line="${line%$'\r'}"
            [[ -z "$line" ]] && continue

            # Validate basic URL structure
            if [[ "$line" =~ ^https?:// ]]; then
                # Check target domain alignment
                local u_domain
                u_domain="$(_hist_extract_host "$line")"
                u_domain="${u_domain%:*}"

                if [[ "$u_domain" == "$query_domain" || "$u_domain" == *."$query_domain" ]]; then
                    # Check deduplication
                    local exists=false
                    local item
                    for item in "${unique_urls[@]}"; do
                        if [[ "$item" == "$line" ]]; then
                            exists=true
                            break
                        fi
                    done

                    if [[ "$exists" == false ]]; then
                        unique_urls+=("$line")

                        # Path extraction
                        local clean_p="${line%%\?*}"
                        clean_p="${clean_p%%\#*}"
                        local p_exists=false
                        for item in "${unique_paths[@]}"; do
                            if [[ "$item" == "$clean_p" ]]; then
                                p_exists=true
                                break
                            fi
                        done
                        [[ "$p_exists" == false ]] && unique_paths+=("$clean_p")

                        # Parameter detection
                        if [[ "$line" == *"?"* ]]; then
                            param_urls+=("$line")
                        fi

                        # Sensitive file detection
                        if _hist_is_sensitive_file "$line"; then
                            sensitive_urls+=("$line")
                        fi
                    fi
                fi
            fi
        done < "$raw_urls_tmp"
    fi

    rm -f "$raw_urls_tmp"

    # Write unique URLs to artifact file
    if (( ${#unique_urls[@]} > 0 )); then
        local -a sorted_urls=()
        mapfile -t sorted_urls < <(printf '%s\n' "${unique_urls[@]}" | sort -u)
        local u
        for u in "${sorted_urls[@]}"; do
            printf '%s\n' "$u" >> "$hist_file"
        done
    fi

    # Format human-readable output report
    web_mod_write_section "Historical URL Findings"
    web_mod_write_kv "Total URLs Discovered" "${#unique_urls[@]}"
    web_mod_write_kv "Unique Paths/Endpoints" "${#unique_paths[@]}"
    web_mod_write_kv "URLs with Parameters" "${#param_urls[@]}"
    web_mod_write_kv "Sensitive Files Detected" "${#sensitive_urls[@]}"

    if (( ${#unique_urls[@]} > 0 )); then
        web_mod_write_raw "  Sample Discovered Endpoints:"
        local sample_count=0
        local u
        for u in "${unique_urls[@]}"; do
            web_mod_write_raw "    - $u"
            ((sample_count += 1))
            (( sample_count >= 15 )) && break
        done

        if (( ${#sensitive_urls[@]} > 0 )); then
            web_mod_write_raw "  Sensitive Files Detected:"
            local sens_count=0
            local su
            for su in "${sensitive_urls[@]}"; do
                web_mod_write_raw "    - $su"
                ((sens_count += 1))
                (( sens_count >= 10 )) && break
            done
        fi

        web_mod_write_footer "COMPLETED" "Discovered ${#unique_urls[@]} historical URL(s) across public archives."
    else
        web_mod_write_kv "Status" "No historical URLs discovered across public archives."
        web_mod_write_footer "COMPLETED" "No historical URLs discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_historical_urls_run "$@"
fi
