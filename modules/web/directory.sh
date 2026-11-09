#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Directory Enumeration Module (modules/web/directory.sh)
#
# Discovers hidden web directories, administrative portals, and API paths
# using dictionary-based fuzzing and path interrogation.
#
# Supported target types:
#   url_http, url_https, hostname, domain
#
# Primary External Tool:
#   - ffuf (high-speed web fuzzer)
#
# Fallback Engine:
#   - curl (native HTTP header & status inspection)
#

set -o nounset

DIR_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$DIR_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
DIR_FFUF_BIN="${RECKON_MOCK_FFUF_BIN:-ffuf}"
DIR_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Built-in fallback wordlist of common web directories and administrative paths.
readonly _DIR_BUILTIN_WORDLIST=(
    "admin"
    "administrator"
    "api"
    "app"
    "assets"
    "backup"
    "backups"
    "bin"
    "cgi-bin"
    "config"
    "configuration"
    "css"
    "dashboard"
    "data"
    "database"
    "dev"
    "development"
    "dist"
    "docs"
    "documentation"
    "download"
    "downloads"
    "etc"
    "files"
    "images"
    "img"
    "include"
    "includes"
    "js"
    "lib"
    "login"
    "logs"
    "manage"
    "management"
    "media"
    "panel"
    "portal"
    "private"
    "public"
    "root"
    "scripts"
    "secure"
    "server-status"
    "src"
    "staging"
    "static"
    "temp"
    "test"
    "tests"
    "tmp"
    "upload"
    "uploads"
    "user"
    "users"
    "v1"
    "v2"
    "web"
    "webadmin"
    "wp-admin"
    "wp-content"
    "wp-includes"
)

# Resolve the wordlist to use for directory fuzzing.
#
# Hierarchy:
#   1. Explicit user CLI / configuration wordlist (--wordlist / CONFIG_EFFECTIVE_WORDLIST)
#   2. Standard system wordlists (/usr/share/wordlists/dirb/common.txt, etc.)
#   3. Built-in curated fallback wordlist
#
# Arguments:
#   $1 - destination path where wordlist file should be placed if generated
#
# Outputs:
#   Resolved wordlist file path on stdout
_dir_resolve_wordlist() {
    local dest_tmp="$1"
    local use_builtin_only="${2:-false}"

    # 1. Configured CLI wordlist
    local configured_wordlist="${CONFIG_EFFECTIVE_WORDLIST:-${CLI_WORDLIST:-}}"
    if [[ -n "$configured_wordlist" && -f "$configured_wordlist" && -r "$configured_wordlist" ]]; then
        printf '%s\n' "$configured_wordlist"
        return 0
    fi

    # 2. Standard system wordlists on Kali/Debian (when fast engine ffuf is available)
    if [[ "$use_builtin_only" != true ]]; then
        local sys_wordlist
        for sys_wordlist in \
            "/usr/share/wordlists/dirb/common.txt" \
            "/usr/share/seclists/Discovery/Web-Content/common.txt" \
            "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"; do
            if [[ -f "$sys_wordlist" && -r "$sys_wordlist" ]]; then
                printf '%s\n' "$sys_wordlist"
                return 0
            fi
        done
    fi

    # 3. Built-in fallback wordlist generated in destination path
    printf '%s\n' "${_DIR_BUILTIN_WORDLIST[@]}" > "$dest_tmp"
    printf '%s\n' "$dest_tmp"
    return 0
}

# Main module runner function.
module_directory_run() {
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

    web_mod_write_header "directory" "Directory Enumeration"

    local dir_file="${task_dir}/directories.txt"
    : > "$dir_file"

    local ffuf_bin="${RECKON_MOCK_FFUF_BIN:-${DIR_FFUF_BIN:-ffuf}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${DIR_CURL_BIN:-curl}}"

    local has_ffuf=false
    if [[ "$ffuf_bin" != "none" ]] && web_mod_has_tool "$ffuf_bin"; then
        has_ffuf=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve wordlist path (uses compact built-in wordlist if running native curl fallback)
    local builtin_tmp="${task_dir}/.builtin_wordlist.tmp"
    local wordlist_path
    local curl_only=false
    [[ "$has_ffuf" == false ]] && curl_only=true
    wordlist_path="$(_dir_resolve_wordlist "$builtin_tmp" "$curl_only")"

    local total_words
    total_words="$(wc -l < "$wordlist_path" | tr -d ' ')"

    # Resolve target endpoints (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)

    local engine_name="ffuf"
    [[ "$has_ffuf" == false ]] && engine_name="curl dictionary fuzzing"

    web_mod_write_section "Fuzzing Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Fuzzing Engine" "$engine_name"
    web_mod_write_kv "Wordlist" "$wordlist_path"
    web_mod_write_kv "Wordlist Count" "$total_words"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_dirs_tmp="${task_dir}/.raw_dirs.tmp"
    : > "$raw_dirs_tmp"

    if [[ "$has_ffuf" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            # Strip trailing slash from base URL
            base_url="${base_url%/}"

            local ffuf_json="${task_dir}/.ffuf_dir.json"
            "$ffuf_bin" -w "${wordlist_path}:FUZZ" \
                        -u "${base_url}/FUZZ" \
                        -mc 200,204,301,302,307,401,403 \
                        -s \
                        -o "$ffuf_json" \
                        -of json \
                        -H "User-Agent: $user_agent" >/dev/null 2>&1 || true

            if [[ -f "$ffuf_json" && -s "$ffuf_json" ]]; then
                if web_mod_has_tool "jq"; then
                    jq -r '.results[]? | "\(.input.FUZZ // .url)\t\(.status)\t\(.length)\t\(.redirectlocation // "-")"' "$ffuf_json" >> "$raw_dirs_tmp" 2>/dev/null || true
                else
                    # Fallback JSON parsing using grep/sed
                    grep -o '"url": *"[^"]*"' "$ffuf_json" | cut -d'"' -f4 | while IFS= read -r f_url; do
                        [[ -n "$f_url" ]] && printf '%s\t200\t-\t-\n' "$f_url" >> "$raw_dirs_tmp"
                    done
                fi
                rm -f "$ffuf_json"
            fi
        done
    fi

    # Fallback to curl dictionary inspection if ffuf is absent or yielded no findings.
    if [[ ! -s "$raw_dirs_tmp" ]] && web_mod_has_tool "$curl_bin"; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            base_url="${base_url%/}"

            # Limit wordlist size for native curl fallback
            local word
            local curl_count=0
            while IFS= read -r word || [[ -n "$word" ]]; do
                word="${word#"${word%%[![:space:]]*}"}"
                word="${word%"${word##*[![:space:]]}"}"
                [[ -z "$word" || "$word" == "#"* ]] && continue
                (( curl_count += 1 ))
                (( curl_count > 100 )) && break

                local probe_url="${base_url}/${word}/"
                local head_tmp="${task_dir}/.curl_dir_head.tmp"
                local curl_rc=0

                "$curl_bin" -s -S -k -I --max-time 4 -D "$head_tmp" -o /dev/null \
                            -A "$user_agent" "$probe_url" 2>/dev/null || curl_rc=$?

                if (( curl_rc == 0 )) && [[ -f "$head_tmp" && -s "$head_tmp" ]]; then
                    local status_code
                    status_code="$(grep -E '^HTTP/[0-9.]+[[:space:]]+[0-9]{3}' "$head_tmp" | tail -n 1 | awk '{print $2}' || true)"

                    case "$status_code" in
                        200|204|301|302|307|401|403)
                            local cl
                            cl="$(grep -i '^Content-Length:' "$head_tmp" | tail -n 1 | awk '{print $2}' | tr -d '\r' || true)"
                            [[ -z "$cl" ]] && cl="-"

                            local redir
                            redir="$(grep -i '^Location:' "$head_tmp" | tail -n 1 | cut -d: -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/\r//' || true)"
                            [[ -z "$redir" ]] && redir="-"

                            printf '%s\t%s\t%s\t%s\n' "/${word}/" "$status_code" "$cl" "$redir" >> "$raw_dirs_tmp"
                            ;;
                    esac
                fi
                rm -f "$head_tmp"
            done < "$wordlist_path"
        done
    fi

    # Deduplicate discovered directory entries.
    local -a detected_records=()
    if [[ -s "$raw_dirs_tmp" ]]; then
        local path code len redir
        while IFS=$'\t' read -r path code len redir || [[ -n "$path" ]]; do
            [[ -z "$path" ]] && continue
            [[ -z "$code" ]] && code="200"
            [[ -z "$len" ]] && len="-"
            [[ -z "$redir" ]] && redir="-"

            # Ensure path begins with /
            [[ "$path" != /* && "$path" != http* ]] && path="/${path}"

            local record="${path}"$'\t'"${code}"$'\t'"${len}"$'\t'"${redir}"
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
                printf '%s\t%s\t%s\t%s\n' "$path" "$code" "$len" "$redir" >> "$dir_file"
            fi
        done < "$raw_dirs_tmp"
    fi

    rm -f "$raw_dirs_tmp" "$builtin_tmp"

    # Write structured output report.
    web_mod_write_section "Discovered Web Directories"
    web_mod_write_kv "Total Discovered" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        web_mod_write_raw "  Discovered Paths         :"
        local rec r_path r_code r_len r_redir
        for rec in "${detected_records[@]}"; do
            IFS=$'\t' read -r r_path r_code r_len r_redir <<< "$rec"
            local entry_desc="    - ${r_path} [HTTP ${r_code}]"
            [[ "$r_len" != "-" ]] && entry_desc="${entry_desc} (Size: ${r_len})"
            [[ "$r_redir" != "-" ]] && entry_desc="${entry_desc} -> ${r_redir}"
            web_mod_write_raw "$entry_desc"
        done
        web_mod_write_footer "COMPLETED" "Discovered ${#detected_records[@]} accessible directory path(s)."
    else
        web_mod_write_kv "Status" "No accessible directories identified on target."
        web_mod_write_footer "COMPLETED" "No directories discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_directory_run "$@"
fi
