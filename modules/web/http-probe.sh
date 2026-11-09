#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTP Probing Module (modules/web/http-probe.sh)
#
# Probes target hosts and URLs for responsive HTTP and HTTPS web services.
# Extracts HTTP status codes, HTML page titles, web server banners, content
# lengths, and redirect locations.
#
# Supported target types:
#   ipv4, hostname, domain, url_http, url_https
#
# Primary External Tool:
#   - httpx / httpx-toolkit (ProjectDiscovery HTTP probe toolkit)
#
# Fallback Engine:
#   - curl (native HTTP header & response analysis)
#

set -o nounset

HTTP_PROBE_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$HTTP_PROBE_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
HTTP_PROBE_HTTPX_BIN="${RECKON_MOCK_HTTPX_BIN:-}"
HTTP_PROBE_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Resolve the preferred ProjectDiscovery httpx binary.
_http_probe_resolve_httpx() {
    if [[ "${HTTP_PROBE_ENGINE:-}" == "curl" || "${HTTP_PROBE_HTTPX_BIN:-}" == "none" ]]; then
        return 1
    fi

    if [[ -n "${HTTP_PROBE_HTTPX_BIN:-}" ]]; then
        if web_mod_has_tool "$HTTP_PROBE_HTTPX_BIN"; then
            printf '%s\n' "$HTTP_PROBE_HTTPX_BIN"
            return 0
        fi
        return 1
    fi

    # On Kali/Debian, ProjectDiscovery httpx is packaged as httpx-toolkit.
    if web_mod_has_tool "httpx-toolkit"; then
        printf '%s\n' "httpx-toolkit"
        return 0
    fi

    # Check if standard httpx is the ProjectDiscovery version.
    if web_mod_has_tool "httpx"; then
        if httpx -silent -version >/dev/null 2>&1 || httpx -h 2>&1 | grep -q -i "projectdiscovery"; then
            printf '%s\n' "httpx"
            return 0
        fi
    fi

    return 1
}

# Extract HTML title from a response body string.
_http_probe_extract_title() {
    local html="$1"
    local title=""
    local title_regex='<title[^>]*>([^<]+)</title>'
    if [[ "$html" =~ $title_regex ]]; then
        title="${BASH_REMATCH[1]}"
        # Trim leading and trailing whitespace and carriage returns
        title="${title#"${title%%[![:space:]]*}"}"
        title="${title%"${title##*[![:space:]]}"}"
        title="${title//$'\r'/}"
        title="${title//$'\n'/ }"
    fi
    printf '%s\n' "$title"
}

# Main module runner function.
module_http_probe_run() {
    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    # Initialize web execution context with supported target types.
    local init_rc=0
    web_mod_init "$target" "$t_type" "$task_dir" ipv4 hostname domain url_http url_https || init_rc=$?
    if (( init_rc == 2 )); then
        # Incompatible target was gracefully skipped with notice written by web_mod_init.
        return 0
    elif (( init_rc != 0 )); then
        return 1
    fi

    web_mod_write_header "http-probe" "HTTP Probing"

    local live_web_file="${task_dir}/live_web.txt"
    local probed_urls_file="${task_dir}/probed_urls.txt"
    : > "$live_web_file"
    : > "$probed_urls_file"

    local httpx_bin=""
    local engine_type="httpx"
    if ! httpx_bin="$(_http_probe_resolve_httpx)"; then
        httpx_bin=""
        engine_type="curl"
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Determine list of candidate URLs to probe.
    local -a candidate_urls=()
    if web_mod_is_url; then
        candidate_urls=("$WEB_FULL_URL")
    else
        # Collect candidate URLs: check upstream ports first, then defaults.
        local -a upstream_ports=()
        mapfile -t upstream_ports < <(web_mod_get_upstream_open_ports)

        if (( ${#upstream_ports[@]} > 0 )); then
            local p
            for p in "${upstream_ports[@]}"; do
                [[ -z "$p" ]] && continue
                if (( p == 443 || p == 8443 || p == 9443 )); then
                    candidate_urls+=("https://${WEB_URL_HOST}:${p}")
                elif (( p == 80 )); then
                    candidate_urls+=("http://${WEB_URL_HOST}")
                else
                    candidate_urls+=("http://${WEB_URL_HOST}:${p}")
                    candidate_urls+=("https://${WEB_URL_HOST}:${p}")
                fi
            done
        else
            # Default probing candidates: standard web ports.
            candidate_urls=(
                "https://${WEB_URL_HOST}"
                "http://${WEB_URL_HOST}"
                "https://${WEB_URL_HOST}:8443"
                "http://${WEB_URL_HOST}:8080"
            )
        fi
    fi

    web_mod_write_section "Probing Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Probing Engine" "$engine_type"
    web_mod_write_kv "Candidate Endpoints" "${#candidate_urls[@]}"

    local -a live_records=()
    local -a live_urls=()

    # Probe execution.
    if [[ -n "$httpx_bin" ]]; then
        # Create temporary input list for httpx.
        local targets_input="${task_dir}/.candidates.tmp"
        printf '%s\n' "${candidate_urls[@]}" > "$targets_input"

        # Run httpx with status code, title, web server, and content length flags.
        local httpx_output="${task_dir}/.httpx.tmp"
        "$httpx_bin" -l "$targets_input" \
                     -silent \
                     -no-color \
                     -status-code \
                     -title \
                     -web-server \
                     -content-length \
                     -location \
                     -H "User-Agent: $user_agent" > "$httpx_output" 2>/dev/null || true

        rm -f "$targets_input"

        if [[ -f "$httpx_output" ]]; then
            local line url
            while IFS= read -r line || [[ -n "$line" ]]; do
                [[ -z "$line" ]] && continue
                # Line format: <url> [<status>] [<title>] [<server>] [<content_length>] [<location>]
                url="${line%% *}"
                live_urls+=("$url")
                live_records+=("$line")
            done < "$httpx_output"
            rm -f "$httpx_output"
        fi
    else
        # Fallback Engine: native curl probing.
        local cand_url
        for cand_url in "${candidate_urls[@]}"; do
            [[ -z "$cand_url" ]] && continue

            # Fetch headers and status code with curl.
            local header_file="${task_dir}/.curl_head.tmp"
            local body_file="${task_dir}/.curl_body.tmp"

            local curl_rc=0
            "$HTTP_PROBE_CURL_BIN" -s -S -k -L --max-time 5 -D "$header_file" -o "$body_file" \
                                   -A "$user_agent" "$cand_url" 2>/dev/null || curl_rc=$?

            if (( curl_rc == 0 )) && [[ -f "$header_file" && -s "$header_file" ]]; then
                # Extract HTTP status code from the final response block.
                local status_code=""
                status_code="$(grep -E '^HTTP/[0-9.]+[[:space:]]+[0-9]{3}' "$header_file" | tail -n 1 | awk '{print $2}' || true)"

                if [[ -n "$status_code" ]]; then
                    # Extract Server header if present.
                    local server_header=""
                    server_header="$(grep -i '^Server:' "$header_file" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"

                    # Extract Content-Length if present.
                    local content_len=""
                    content_len="$(grep -i '^Content-Length:' "$header_file" | tail -n 1 | awk '{print $2}' | tr -d '\r' || true)"
                    if [[ -z "$content_len" && -f "$body_file" ]]; then
                        content_len="$(wc -c < "$body_file" | tr -d ' ')"
                    fi

                    # Extract title from body.
                    local title_str=""
                    if [[ -f "$body_file" && -s "$body_file" ]]; then
                        local body_sample
                        body_sample="$(head -c 65536 "$body_file" 2>/dev/null || true)"
                        title_str="$(_http_probe_extract_title "$body_sample")"
                    fi

                    local rec="$cand_url [$status_code]"
                    [[ -n "$title_str" ]] && rec="$rec [$title_str]"
                    [[ -n "$server_header" ]] && rec="$rec [$server_header]"
                    [[ -n "$content_len" ]] && rec="$rec [$content_len]"

                    live_urls+=("$cand_url")
                    live_records+=("$rec")
                fi
            fi

            rm -f "$header_file" "$body_file"
        done
    fi

    # Write output artifacts and report.
    web_mod_write_section "Live Web Endpoints"
    web_mod_write_kv "Total Live Endpoints" "${#live_urls[@]}"

    if (( ${#live_urls[@]} > 0 )); then
        web_mod_write_raw "  Discovered Endpoints     :"
        local idx
        for idx in "${!live_urls[@]}"; do
            local clean_url="${live_urls[idx]}"
            local detail_rec="${live_records[idx]}"

            printf '%s\n' "$clean_url" >> "$live_web_file"
            printf '%s\n' "$detail_rec" >> "$probed_urls_file"
            web_mod_write_raw "    - $detail_rec"
        done
        web_mod_write_footer "COMPLETED" "Identified ${#live_urls[@]} responsive web endpoint(s)."
    else
        web_mod_write_kv "Status" "No responsive HTTP/HTTPS services identified on target."
        web_mod_write_footer "COMPLETED" "No live web endpoints detected."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_http_probe_run "$@"
fi
