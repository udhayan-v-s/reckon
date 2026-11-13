#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Virtual Host Enumeration Module (modules/web/vhost.sh)
#
# Discovers hidden or non-public virtual hosts hosted on target infrastructure
# by testing HTTP Host header routing against baseline server responses.
#
# Supported target types:
#   url_http, url_https, hostname, domain
#
# Primary External Tool:
#   - ffuf (high-speed HTTP Host header fuzzer)
#
# Fallback Engine:
#   - curl (native Host header interrogation and response differential analysis)
#

set -o nounset

VHOST_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$VHOST_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
VHOST_FFUF_BIN="${RECKON_MOCK_FFUF_BIN:-ffuf}"
VHOST_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Built-in fallback wordlist of common virtual host and environment subdomains.
readonly _VHOST_BUILTIN_WORDLIST=(
    "admin"
    "api"
    "app"
    "auth"
    "backend"
    "beta"
    "billing"
    "blog"
    "cdn"
    "chat"
    "ci"
    "cloud"
    "corp"
    "dashboard"
    "db"
    "demo"
    "dev"
    "developer"
    "development"
    "docs"
    "email"
    "forum"
    "gateway"
    "git"
    "gitlab"
    "grafana"
    "help"
    "internal"
    "intranet"
    "jenkins"
    "jira"
    "kibana"
    "login"
    "mail"
    "manage"
    "management"
    "monitor"
    "monitoring"
    "m"
    "mobile"
    "old"
    "panel"
    "portal"
    "private"
    "prod"
    "production"
    "proxy"
    "qa"
    "remote"
    "router"
    "secure"
    "server"
    "service"
    "services"
    "sso"
    "stage"
    "staging"
    "static"
    "status"
    "support"
    "test"
    "testing"
    "uat"
    "vpn"
    "web"
    "webmail"
    "wiki"
    "www"
)

# Resolve the wordlist to use for virtual host fuzzing.
#
# Arguments:
#   $1 - fallback file path to populate if no system wordlist is available
#
# Output:
#   Path to resolved wordlist file on stdout
_vhost_resolve_wordlist() {
    local fallback_file="${1:-}"

    # 1. Configured CLI/config wordlist
    local configured_wordlist="${CONFIG_EFFECTIVE_WORDLIST:-${CLI_WORDLIST:-}}"
    if [[ -n "$configured_wordlist" && -f "$configured_wordlist" && -r "$configured_wordlist" ]]; then
        printf '%s\n' "$configured_wordlist"
        return 0
    fi

    # 2. Standard system wordlists
    local -a candidate_paths=(
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        "/usr/share/wordlists/seclists/Discovery/DNS/namelist.txt"
        "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
    )

    local candidate
    for candidate in "${candidate_paths[@]}"; do
        if [[ -f "$candidate" && -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    # 3. Built-in fallback wordlist
    if [[ -n "$fallback_file" ]]; then
        printf '%s\n' "${_VHOST_BUILTIN_WORDLIST[@]}" > "$fallback_file"
        printf '%s\n' "$fallback_file"
        return 0
    fi

    return 1
}

# Prepare FQDN candidates list from wordlist and base domain.
#
# Arguments:
#   $1 - input wordlist path
#   $2 - base domain (e.g. example.com)
#   $3 - output file path
_vhost_prepare_candidates() {
    local in_file="$1"
    local base_domain="$2"
    local out_file="$3"

    : > "$out_file"

    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" || "$line" == "#"* ]] && continue

        if [[ "$line" == *"."* ]]; then
            printf '%s\n' "$line" >> "$out_file"
        else
            printf '%s.%s\n' "$line" "$base_domain" >> "$out_file"
        fi
    done < "$in_file"
}

# Main entry point for the Virtual Host Enumeration module.
#
# Arguments:
#   $1 - target specification
#   $2 - target type (url_http, url_https, hostname, domain)
#   $3 - task output directory
#
# Returns:
#   0 on success (or clean skip), 1 on initialization failure
module_vhost_run() {
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

    web_mod_write_header "vhost" "Virtual Host Enumeration"

    local vhost_file="${task_dir}/vhosts.txt"
    : > "$vhost_file"

    local ffuf_bin="${RECKON_MOCK_FFUF_BIN:-${VHOST_FFUF_BIN:-ffuf}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${VHOST_CURL_BIN:-curl}}"

    local has_ffuf=false
    if [[ "$ffuf_bin" != "none" ]] && web_mod_has_tool "$ffuf_bin"; then
        has_ffuf=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve base domain
    local domain_base="${WEB_URL_HOST:-$WEB_TARGET}"
    domain_base="${domain_base%:*}"

    # Resolve wordlist path and prepare candidate FQDN list
    local builtin_tmp="${task_dir}/.builtin_vhost.tmp"
    local wordlist_path
    wordlist_path="$(_vhost_resolve_wordlist "$builtin_tmp")"

    local candidates_tmp="${task_dir}/.vhost_candidates.tmp"
    _vhost_prepare_candidates "$wordlist_path" "$domain_base" "$candidates_tmp"

    local total_words
    total_words="$(wc -l < "$candidates_tmp" | tr -d ' ')"

    # Resolve target endpoints (prefers upstream live_web.txt).
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

    local engine_name="ffuf"
    [[ "$has_ffuf" == false ]] && engine_name="curl Host header inspection"

    web_mod_write_section "Fuzzing Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Base Domain" "$domain_base"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Fuzzing Engine" "$engine_name"
    web_mod_write_kv "Wordlist" "$wordlist_path"
    web_mod_write_kv "Candidates Count" "$total_words"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_vhosts_tmp="${task_dir}/.raw_vhosts.tmp"
    : > "$raw_vhosts_tmp"

    local timeout_val="${CONFIG_EFFECTIVE_TIMEOUT:-${CLI_TIMEOUT:-10}}"
    local threads_val="${CONFIG_EFFECTIVE_THREADS:-${CLI_THREADS:-10}}"

    # 1. Primary FFUF execution
    if [[ "$has_ffuf" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            base_url="${base_url%/}"

            # Measure baseline response with a random non-existent host header
            local baseline_host="reckon-baseline-${RANDOM}-${RANDOM}.${domain_base}"
            local baseline_resp
            baseline_resp="$("$curl_bin" -s -k -m 4 -o /dev/null -w "%{http_code}\t%{size_download}\n" \
                            -A "$user_agent" -H "Host: ${baseline_host}" "$base_url" 2>/dev/null || true)"

            local baseline_len=""
            if [[ "$baseline_resp" =~ ^([0-9]{3})[[:space:]]+([0-9]+) ]]; then
                baseline_len="${BASH_REMATCH[2]}"
            fi

            local ffuf_json="${task_dir}/.ffuf_vhost.json"
            local -a ffuf_cmd=(
                "$ffuf_bin"
                -w "${candidates_tmp}:FUZZ"
                -u "${base_url}"
                -H "Host: FUZZ"
                -H "User-Agent: $user_agent"
                "-mc" "200,204,301,302,307,401,403,405"
                -s
                -o "$ffuf_json"
                -of json
                -timeout "$timeout_val"
                -t "$threads_val"
            )

            # Apply baseline content length filter if baseline length is known and non-zero
            if [[ -n "$baseline_len" && "$baseline_len" -gt 0 ]]; then
                ffuf_cmd+=(-fs "$baseline_len")
            fi

            "${ffuf_cmd[@]}" >/dev/null 2>&1 || true

            if [[ -f "$ffuf_json" && -s "$ffuf_json" ]]; then
                if web_mod_has_tool "jq"; then
                    jq -r '.results[]? | "\(.input.FUZZ // .input.HOST // .url)\t\(.status)\t\(.length)\t\(.redirectlocation // "-")"' "$ffuf_json" >> "$raw_vhosts_tmp" 2>/dev/null || true
                else
                    # Fallback JSON parsing using grep/awk
                    grep -o '"input": *{[^}]*}' "$ffuf_json" | while IFS= read -r f_match; do
                        local f_host
                        f_host="$(printf '%s\n' "$f_match" | cut -d'"' -f6)"
                        [[ -n "$f_host" ]] && printf '%s\t200\t-\t-\n' "$f_host" >> "$raw_vhosts_tmp"
                    done
                fi
                rm -f "$ffuf_json"
            fi
        done
    fi

    # 2. Fallback to native curl Host header interrogation if ffuf is absent.
    if [[ "$has_ffuf" == false ]] && web_mod_has_tool "$curl_bin"; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            base_url="${base_url%/}"

            # Baseline probe
            local baseline_host="reckon-baseline-${RANDOM}-${RANDOM}.${domain_base}"
            local head_base="${task_dir}/.curl_base_head.tmp"
            "$curl_bin" -s -S -k -I --max-time 4 -D "$head_base" -o /dev/null \
                        -A "$user_agent" -H "Host: ${baseline_host}" "$base_url" 2>/dev/null || true

            local base_code=""
            local base_size=""
            if [[ -f "$head_base" && -s "$head_base" ]]; then
                base_code="$(grep -E '^HTTP/[0-9.]+[[:space:]]+[0-9]{3}' "$head_base" | tail -n 1 | awk '{print $2}' || true)"
                base_size="$(grep -i '^Content-Length:' "$head_base" | tail -n 1 | awk '{print $2}' | tr -d '\r' || true)"
            fi
            rm -f "$head_base"

            local candidate
            local curl_count=0
            while IFS= read -r candidate || [[ -n "$candidate" ]]; do
                [[ -z "$candidate" ]] && continue
                (( curl_count += 1 ))
                (( curl_count > 100 )) && break

                local head_tmp="${task_dir}/.curl_vhost_head.tmp"
                local curl_rc=0

                "$curl_bin" -s -S -k -I --max-time 4 -D "$head_tmp" -o /dev/null \
                            -A "$user_agent" -H "Host: ${candidate}" "$base_url" 2>/dev/null || curl_rc=$?

                if (( curl_rc == 0 )) && [[ -f "$head_tmp" && -s "$head_tmp" ]]; then
                    local status_code
                    status_code="$(grep -E '^HTTP/[0-9.]+[[:space:]]+[0-9]{3}' "$head_tmp" | tail -n 1 | awk '{print $2}' || true)"

                    case "$status_code" in
                        200|204|301|302|307|401|403|405)
                            local cl
                            cl="$(grep -i '^Content-Length:' "$head_tmp" | tail -n 1 | awk '{print $2}' | tr -d '\r' || true)"
                            [[ -z "$cl" ]] && cl="-"

                            local redir
                            redir="$(grep -i '^Location:' "$head_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
                            [[ -z "$redir" ]] && redir="-"

                            # Differ from baseline status or size
                            if [[ "$status_code" != "$base_code" ]] || { [[ -n "$base_size" ]] && [[ "$cl" != "$base_size" && "$cl" != "-" ]]; }; then
                                printf '%s\t%s\t%s\t%s\n' "$candidate" "$status_code" "$cl" "$redir" >> "$raw_vhosts_tmp"
                            fi
                            ;;
                    esac
                fi
                rm -f "$head_tmp"
            done < "$candidates_tmp"
        done
    fi

    # Deduplicate discovered virtual host entries.
    local -a detected_records=()
    if [[ -s "$raw_vhosts_tmp" ]]; then
        local vh code len redir
        while IFS=$'\t' read -r vh code len redir || [[ -n "$vh" ]]; do
            [[ -z "$vh" ]] && continue
            # Ignore random baseline hosts
            [[ "$vh" == *"reckon-baseline"* ]] && continue

            [[ -z "$code" ]] && code="200"
            [[ -z "$len" ]] && len="-"
            [[ -z "$redir" ]] && redir="-"

            local record="${vh}"$'\t'"${code}"$'\t'"${len}"$'\t'"${redir}"
            local exists=false
            local item
            for item in "${detected_records[@]}"; do
                if [[ "$item" == "$record" ]]; then
                    exists=true
                    break
                fi
            done
            if [[ "$exists" == false ]]; then
                detected_records+=("$record")
            fi
        done < "$raw_vhosts_tmp"
    fi

    rm -f "$raw_vhosts_tmp" "$builtin_tmp" "$candidates_tmp"

    # Write discovered virtual hosts to artifact file
    local rec
    for rec in "${detected_records[@]}"; do
        printf '%s\n' "$rec" >> "$vhost_file"
    done

    # Format human-readable output report
    web_mod_write_section "Virtual Host Findings"
    web_mod_write_kv "Total Candidates" "$total_words"
    web_mod_write_kv "Virtual Hosts Discovered" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        web_mod_write_raw "  Discovered Virtual Hosts :"
        for rec in "${detected_records[@]}"; do
            local f_vh f_code f_len f_redir
            f_vh="${rec%%$'\t'*}"
            local rem="${rec#*$'\t'}"
            f_code="${rem%%$'\t'*}"
            rem="${rem#*$'\t'}"
            f_len="${rem%%$'\t'*}"
            f_redir="${rem#*$'\t'}"

            local extra="Status: $f_code, Size: $f_len"
            if [[ "$f_redir" != "-" ]]; then
                extra="$extra, Redirect: $f_redir"
            fi
            web_mod_write_raw "    - $f_vh ($extra)"
        done
        web_mod_write_footer "COMPLETED" "Discovered ${#detected_records[@]} virtual host(s) for target."
    else
        web_mod_write_kv "Status" "No virtual hosts discovered for target domain."
        web_mod_write_footer "COMPLETED" "No virtual hosts discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_vhost_run "$@"
fi
