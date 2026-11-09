#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Spidering and Link Crawling Module (modules/web/crawl.sh)
#
# Recursively crawls target web applications to discover internal links,
# client-side routes, referenced JavaScript assets, and static media files.
#
# Supported target types:
#   url_http, url_https, hostname, domain
#
# Primary External Tool:
#   - katana (ProjectDiscovery high-performance web crawler)
#
# Fallback Engine:
#   - curl (native HTML anchor/link parser and recursive scoped spider)
#

set -o nounset

CRAWL_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$CRAWL_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
CRAWL_KATANA_BIN="${RECKON_MOCK_KATANA_BIN:-katana}"
CRAWL_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Normalize and resolve a relative or absolute link against a base URL.
#
# Arguments:
#   $1 - candidate link extracted from HTML
#   $2 - current base URL where the link was found
#
# Output:
#   Normalized absolute URL on stdout, or return 1 if non-HTTP or anchor
_crawl_normalize_link() {
    local link="$1"
    local base_url="$2"

    # Trim whitespace, quotes, and carriage returns
    link="${link#"${link%%[![:space:]]*}"}"
    link="${link%"${link##*[![:space:]]}"}"
    link="${link%$'\r'}"
    link="${link#[\"\']}"
    link="${link%[\"\']}"

    # Discard empty, fragment anchors, or non-HTTP protocols
    case "$link" in
        ""|"#"*|"javascript:"*|"mailto:"*|"tel:"*|"data:"*)
            return 1
            ;;
    esac

    # Strip URL fragment identifiers
    link="${link%%\#*}"
    [[ -z "$link" ]] && return 1

    # Extract base scheme and authority (host[:port])
    local base_scheme="http"
    local base_auth=""
    local base_path="/"

    if [[ "$base_url" =~ ^(https?)://([^/]+)(/.*)?$ ]]; then
        base_scheme="${BASH_REMATCH[1]}"
        base_auth="${BASH_REMATCH[2]}"
        base_path="${BASH_REMATCH[3]:-/}"
    fi

    # Case 1: Already absolute HTTP/HTTPS URL
    if [[ "$link" =~ ^https?:// ]]; then
        printf '%s\n' "$link"
        return 0
    fi

    # Case 2: Protocol-relative URL (//example.com/path)
    if [[ "$link" == "//"* ]]; then
        printf '%s:%s\n' "$base_scheme" "$link"
        return 0
    fi

    # Case 3: Root-relative URL (/path)
    if [[ "$link" == "/"* ]]; then
        printf '%s://%s%s\n' "$base_scheme" "$base_auth" "$link"
        return 0
    fi

    # Case 4: Relative to current directory path
    local dir_part="${base_path%/*}"
    [[ -z "$dir_part" || "$dir_part" == "/" ]] && dir_part=""
    printf '%s://%s%s/%s\n' "$base_scheme" "$base_auth" "$dir_part" "$link"
    return 0
}

# Extract host name from URL.
_crawl_extract_host() {
    local u="$1"
    local rem="${u#*://}"
    local h="${rem%%/*}"
    h="${h%:*}"
    printf '%s\n' "$h"
}

# Main entry point for the Web Spidering and Link Crawling module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_http, url_https, hostname, domain)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_crawl_run() {
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

    web_mod_write_header "crawl" "Web Spidering and Link Crawling"

    local crawl_file="${task_dir}/crawled_urls.txt"
    : > "$crawl_file"

    local katana_bin="${RECKON_MOCK_KATANA_BIN:-${CRAWL_KATANA_BIN:-katana}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${CRAWL_CURL_BIN:-curl}}"

    local has_katana=false
    if [[ "$katana_bin" != "none" ]] && web_mod_has_tool "$katana_bin"; then
        has_katana=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve target domain/host
    local domain_base="${WEB_URL_HOST:-$WEB_TARGET}"
    domain_base="${domain_base%:*}"

    # Resolve candidate target URLs (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)
    if (( ${#candidate_urls[@]} == 0 )); then
        if [[ "$WEB_TARGET_TYPE" == "url_https" ]]; then
            candidate_urls=("https://${domain_base}")
        elif [[ "$WEB_TARGET_TYPE" == "url_http" ]]; then
            candidate_urls=("http://${domain_base}")
        else
            candidate_urls=("http://${domain_base}" "https://${domain_base}")
        fi
    fi

    local engine_name="katana"
    [[ "$has_katana" == false ]] && engine_name="curl recursive HTML link spider"

    web_mod_write_section "Crawling Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Base Domain" "$domain_base"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Crawling Engine" "$engine_name"
    web_mod_write_kv "Seed Endpoints" "${#candidate_urls[@]}"

    local raw_crawled_tmp="${task_dir}/.raw_crawled.tmp"
    : > "$raw_crawled_tmp"

    # 1. Primary Engine: katana crawler
    if [[ "$has_katana" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local seed
        for seed in "${candidate_urls[@]}"; do
            [[ -z "$seed" ]] && continue
            local katana_out="${task_dir}/.katana_out.tmp"

            "$katana_bin" -u "$seed" -d 2 -jc -kf all -silent -nc -o "$katana_out" 2>/dev/null || \
                "$katana_bin" -u "$seed" -silent -nc -o "$katana_out" 2>/dev/null || true

            if [[ -f "$katana_out" && -s "$katana_out" ]]; then
                cat "$katana_out" >> "$raw_crawled_tmp"
                rm -f "$katana_out"
            fi
        done
    fi

    # 2. Fallback Engine: native recursive curl HTML spider
    if [[ "$has_katana" == false ]] && web_mod_has_tool "$curl_bin"; then
        local -a queue=("${candidate_urls[@]}")
        local -a visited=()
        local max_crawled=60
        local crawl_count=0

        while (( ${#queue[@]} > 0 && crawl_count < max_crawled )); do
            local current_url="${queue[0]}"
            queue=("${queue[@]:1}")
            [[ -z "$current_url" ]] && continue

            # Check if already visited
            local already_visited=false
            local v
            for v in "${visited[@]}"; do
                if [[ "$v" == "$current_url" ]]; then
                    already_visited=true
                    break
                fi
            done
            [[ "$already_visited" == true ]] && continue

            visited+=("$current_url")
            printf '%s\n' "$current_url" >> "$raw_crawled_tmp"
            (( crawl_count += 1 ))

            # Fetch page content
            local html_tmp="${task_dir}/.curl_crawl_page.tmp"
            "$curl_bin" -s -k -m 4 -L -A "$user_agent" "$current_url" > "$html_tmp" 2>/dev/null || true

            if [[ -f "$html_tmp" && -s "$html_tmp" ]]; then
                # Extract links from href, src, action attributes
                local raw_links_tmp="${task_dir}/.page_links.tmp"
                grep -o -E '(href|src|action)=["'\''][^"'\''>]+["'\'']' "$html_tmp" 2>/dev/null | \
                    sed -E 's/^(href|src|action)=["'\'']//; s/["'\'']$//' > "$raw_links_tmp" || true

                if [[ -f "$raw_links_tmp" && -s "$raw_links_tmp" ]]; then
                    local raw_link
                    while IFS= read -r raw_link || [[ -n "$raw_link" ]]; do
                        local resolved_url
                        if resolved_url="$(_crawl_normalize_link "$raw_link" "$current_url")"; then
                            # Check domain boundary
                            local u_host
                            u_host="$(_crawl_extract_host "$resolved_url")"
                            if [[ "$u_host" == "$domain_base" || "$u_host" == *."$domain_base" ]]; then
                                # Record discovered link
                                printf '%s\n' "$resolved_url" >> "$raw_crawled_tmp"

                                # Enqueue web pages for recursive exploration
                                local clean_path="${resolved_url%%\?*}"
                                case "$clean_path" in
                                    *.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.css|*.woff|*.woff2|*.pdf|*.zip|*.gz|*.mp4)
                                        # Do not spider binary/static assets
                                        ;;
                                    *)
                                        if (( ${#queue[@]} < 30 )); then
                                            queue+=("$resolved_url")
                                        fi
                                        ;;
                                esac
                            fi
                        fi
                    done < "$raw_links_tmp"
                    rm -f "$raw_links_tmp"
                fi
                rm -f "$html_tmp"
            fi
        done
    fi

    # 3. Filter, sanitize, and classify discovered crawled URLs
    local -a unique_crawled=()
    local -a js_assets=()
    local -a media_assets=()
    local -a web_pages=()

    if [[ -s "$raw_crawled_tmp" ]]; then
        local line
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            line="${line%$'\r'}"
            [[ -z "$line" ]] && continue

            if [[ "$line" =~ ^https?:// ]]; then
                local u_host
                u_host="$(_crawl_extract_host "$line")"
                if [[ "$u_host" == "$domain_base" || "$u_host" == *."$domain_base" ]]; then
                    local exists=false
                    local item
                    for item in "${unique_crawled[@]}"; do
                        if [[ "$item" == "$line" ]]; then
                            exists=true
                            break
                        fi
                    done

                    if [[ "$exists" == false ]]; then
                        unique_crawled+=("$line")

                        local path_part="${line%%\?*}"
                        case "$path_part" in
                            *.js)
                                js_assets+=("$line")
                                ;;
                            *.css|*.png|*.jpg|*.jpeg|*.gif|*.svg|*.ico|*.woff|*.woff2)
                                media_assets+=("$line")
                                ;;
                            *)
                                web_pages+=("$line")
                                ;;
                        esac
                    fi
                fi
            fi
        done < "$raw_crawled_tmp"
    fi

    rm -f "$raw_crawled_tmp"

    # Write unique crawled URLs to artifact file
    if (( ${#unique_crawled[@]} > 0 )); then
        local -a sorted_crawled=()
        mapfile -t sorted_crawled < <(printf '%s\n' "${unique_crawled[@]}" | sort -u)
        local u
        for u in "${sorted_crawled[@]}"; do
            printf '%s\n' "$u" >> "$crawl_file"
        done
    fi

    # Format human-readable output report
    web_mod_write_section "Crawling Findings"
    web_mod_write_kv "Total URLs Crawled" "${#unique_crawled[@]}"
    web_mod_write_kv "Web Pages / Routes" "${#web_pages[@]}"
    web_mod_write_kv "JavaScript Bundles" "${#js_assets[@]}"
    web_mod_write_kv "Static Media Assets" "${#media_assets[@]}"

    if (( ${#unique_crawled[@]} > 0 )); then
        web_mod_write_raw "  Discovered Web Pages & Routes:"
        local p_count=0
        local p
        for p in "${web_pages[@]}"; do
            web_mod_write_raw "    - $p"
            (( p_count += 1 ))
            (( p_count >= 15 )) && break
        done

        if (( ${#js_assets[@]} > 0 )); then
            web_mod_write_raw "  Referenced JavaScript Files:"
            local js_count=0
            local j
            for j in "${js_assets[@]}"; do
                web_mod_write_raw "    - $j"
                (( js_count += 1 ))
                (( js_count >= 10 )) && break
            done
        fi

        web_mod_write_footer "COMPLETED" "Crawled ${#unique_crawled[@]} URL(s) (${#web_pages[@]} pages, ${#js_assets[@]} scripts)."
    else
        web_mod_write_kv "Status" "No web links discovered during crawl."
        web_mod_write_footer "COMPLETED" "No links discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_crawl_run "$@"
fi
