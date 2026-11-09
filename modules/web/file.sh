#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web File Enumeration Module (modules/web/file.sh)
#
# Discovers sensitive, hidden, configuration, and backup files across target
# web servers using dictionary fuzzing and targeted file signature probing.
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

FILE_MOD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=modules/web/common.sh
if ! source "$FILE_MOD_DIR/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh.\n' >&2
    exit 1
fi

# Override hooks for unit testing and mock execution.
FILE_FFUF_BIN="${RECKON_MOCK_FFUF_BIN:-ffuf}"
FILE_CURL_BIN="${RECKON_MOCK_CURL_BIN:-curl}"

# Built-in curated sensitive file paths to discover.
readonly _FILE_BUILTIN_TARGETS=(
    # Environment & Secret Leaks
    ".env"
    ".env.local"
    ".env.production"
    ".env.bak"
    ".env.example"
    # Version Control Metadata
    ".git/HEAD"
    ".git/config"
    ".gitignore"
    ".svn/entries"
    # Web & Server Configurations
    ".htaccess"
    ".htpasswd"
    "web.config"
    "crossdomain.xml"
    "clientaccesspolicy.xml"
    # Application & CMS Configurations
    "config.php"
    "config.inc.php"
    "configuration.php"
    "wp-config.php"
    "wp-config.php.bak"
    "wp-config.php.old"
    "settings.py"
    "database.yml"
    "db.conf"
    # Database Dumps & Backups
    "database.sql"
    "dump.sql"
    "backup.sql"
    "db.sql"
    "schema.sql"
    "backup.zip"
    "backup.tar.gz"
    "site.zip"
    "www.zip"
    # Credentials & Keys
    "id_rsa"
    "id_rsa.pub"
    "id_ecdsa"
    ".ssh/authorized_keys"
    # Diagnostic & Information Disclosure
    "phpinfo.php"
    "info.php"
    "test.php"
    "robots.txt"
    "sitemap.xml"
    ".well-known/security.txt"
    # Package Manifests
    "package.json"
    "composer.json"
    "composer.lock"
    "requirements.txt"
    "Dockerfile"
    "docker-compose.yml"
)

# Classify a discovered file based on its path and sensitivity risk.
_file_classify_path() {
    local path="$1"
    case "$path" in
        *.env*|*.git*|*id_rsa*|*.htpasswd*|*.sql|*.zip|*.tar.gz)
            printf '%s\n' "CRITICAL (Credential / Secret Leak)"
            ;;
        *config*|*settings*|*database.yml*)
            printf '%s\n' "HIGH (Configuration File)"
            ;;
        *phpinfo*|*info.php*|*test.php*)
            printf '%s\n' "MEDIUM (Diagnostic / Info Disclosure)"
            ;;
        *robots.txt*|*sitemap.xml*|*.well-known/*)
            printf '%s\n' "LOW (Standard Web Metadata)"
            ;;
        *)
            printf '%s\n' "INFO (Accessible Resource)"
            ;;
    esac
}

# Resolve the wordlist to use for file enumeration.
#
# Arguments:
#   $1 - destination path where wordlist file should be placed if generated
#
# Outputs:
#   Resolved wordlist file path on stdout
_file_resolve_wordlist() {
    local dest_tmp="$1"

    local configured_wordlist="${CONFIG_EFFECTIVE_WORDLIST:-${CLI_WORDLIST:-}}"
    if [[ -n "$configured_wordlist" && -f "$configured_wordlist" && -r "$configured_wordlist" ]]; then
        printf '%s\n' "$configured_wordlist"
        return 0
    fi

    # Generate the curated sensitive files list in the destination path
    printf '%s\n' "${_FILE_BUILTIN_TARGETS[@]}" > "$dest_tmp"
    printf '%s\n' "$dest_tmp"
    return 0
}

# Main module runner function.
module_file_run() {
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

    web_mod_write_header "file" "File Enumeration"

    local file_out="${task_dir}/files.txt"
    : > "$file_out"

    local ffuf_bin="${RECKON_MOCK_FFUF_BIN:-${FILE_FFUF_BIN:-ffuf}}"
    local curl_bin="${RECKON_MOCK_CURL_BIN:-${FILE_CURL_BIN:-curl}}"

    local has_ffuf=false
    if [[ "$ffuf_bin" != "none" ]] && web_mod_has_tool "$ffuf_bin"; then
        has_ffuf=true
    fi

    local user_agent
    user_agent="$(web_mod_get_user_agent)"

    # Resolve wordlist path
    local builtin_tmp="${task_dir}/.builtin_files.tmp"
    local wordlist_path
    wordlist_path="$(_file_resolve_wordlist "$builtin_tmp")"

    local total_words
    total_words="$(wc -l < "$wordlist_path" | tr -d ' ')"

    # Resolve target endpoints (prefers upstream live_web.txt).
    local -a candidate_urls=()
    mapfile -t candidate_urls < <(web_mod_get_target_urls)

    local engine_name="ffuf"
    [[ "$has_ffuf" == false ]] && engine_name="curl dictionary inspection"

    web_mod_write_section "Enumeration Configuration"
    web_mod_write_kv "Target" "$WEB_TARGET"
    web_mod_write_kv "Target Type" "$WEB_TARGET_TYPE"
    web_mod_write_kv "Engine" "$engine_name"
    web_mod_write_kv "Wordlist" "$wordlist_path"
    web_mod_write_kv "Wordlist Count" "$total_words"
    web_mod_write_kv "Endpoints Scanned" "${#candidate_urls[@]}"

    local raw_files_tmp="${task_dir}/.raw_files.tmp"
    : > "$raw_files_tmp"

    if [[ "$has_ffuf" == true && ${#candidate_urls[@]} -gt 0 ]]; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            base_url="${base_url%/}"

            local ffuf_json="${task_dir}/.ffuf_file.json"
            "$ffuf_bin" -w "${wordlist_path}:FUZZ" \
                        -u "${base_url}/FUZZ" \
                        -mc 200,204,301,302,401,403 \
                        -s \
                        -o "$ffuf_json" \
                        -of json \
                        -H "User-Agent: $user_agent" >/dev/null 2>&1 || true

            if [[ -f "$ffuf_json" && -s "$ffuf_json" ]]; then
                if web_mod_has_tool "jq"; then
                    jq -r '.results[]? | "\(.input.FUZZ // .url)\t\(.status)\t\(.length)"' "$ffuf_json" >> "$raw_files_tmp" 2>/dev/null || true
                else
                    grep -o '"url": *"[^"]*"' "$ffuf_json" | cut -d'"' -f4 | while IFS= read -r f_url; do
                        [[ -n "$f_url" ]] && printf '%s\t200\t-\n' "$f_url" >> "$raw_files_tmp"
                    done
                fi
                rm -f "$ffuf_json"
            fi
        done
    fi

    # Fallback to curl inspection if ffuf is absent or returned zero findings.
    if [[ ! -s "$raw_files_tmp" ]] && web_mod_has_tool "$curl_bin"; then
        local base_url
        for base_url in "${candidate_urls[@]}"; do
            [[ -z "$base_url" ]] && continue
            base_url="${base_url%/}"

            local line
            local curl_count=0
            while IFS= read -r line || [[ -n "$line" ]]; do
                line="${line#"${line%%[![:space:]]*}"}"
                line="${line%"${line##*[![:space:]]}"}"
                [[ -z "$line" || "$line" == "#"* ]] && continue
                (( curl_count += 1 ))
                (( curl_count > 100 )) && break

                # Clean leading slash from fuzz word
                local f_path="${line#/}"
                local probe_url="${base_url}/${f_path}"
                local head_tmp="${task_dir}/.curl_file_head.tmp"
                local curl_rc=0

                "$curl_bin" -s -S -k -I --max-time 4 -D "$head_tmp" -o /dev/null \
                            -A "$user_agent" "$probe_url" 2>/dev/null || curl_rc=$?

                if (( curl_rc == 0 )) && [[ -f "$head_tmp" && -s "$head_tmp" ]]; then
                    local status_code
                    status_code="$(grep -E '^HTTP/[0-9.]+[[:space:]]+[0-9]{3}' "$head_tmp" | tail -n 1 | awk '{print $2}' || true)"

                    case "$status_code" in
                        200|204|301|302|401|403)
                            local cl
                            cl="$(grep -i '^Content-Length:' "$head_tmp" | tail -n 1 | awk '{print $2}' | tr -d '\r' || true)"
                            [[ -z "$cl" ]] && cl="-"
                            printf '%s\t%s\t%s\n' "/${f_path}" "$status_code" "$cl" >> "$raw_files_tmp"
                            ;;
                    esac
                fi
                rm -f "$head_tmp"
            done < "$wordlist_path"
        done
    fi

    # Deduplicate discovered files and append classification tags.
    local -a detected_records=()
    if [[ -s "$raw_files_tmp" ]]; then
        local path code len
        while IFS=$'\t' read -r path code len || [[ -n "$path" ]]; do
            [[ -z "$path" ]] && continue
            [[ -z "$code" ]] && code="200"
            [[ -z "$len" ]] && len="-"

            # Ensure path begins with /
            [[ "$path" != /* && "$path" != http* ]] && path="/${path}"

            local classification
            classification="$(_file_classify_path "$path")"

            local record="${path}"$'\t'"${code}"$'\t'"${len}"$'\t'"${classification}"
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
                printf '%s\t%s\t%s\t%s\n' "$path" "$code" "$len" "$classification" >> "$file_out"
            fi
        done < "$raw_files_tmp"
    fi

    rm -f "$raw_files_tmp" "$builtin_tmp"

    # Write structured output report.
    web_mod_write_section "Accessible Web Files"
    web_mod_write_kv "Total Discovered" "${#detected_records[@]}"

    if (( ${#detected_records[@]} > 0 )); then
        web_mod_write_raw "  Discovered Files         :"
        local rec r_path r_code r_len r_class
        for rec in "${detected_records[@]}"; do
            IFS=$'\t' read -r r_path r_code r_len r_class <<< "$rec"
            local entry_desc="    - ${r_path} [HTTP ${r_code}]"
            [[ "$r_len" != "-" ]] && entry_desc="${entry_desc} (Size: ${r_len})"
            entry_desc="${entry_desc} [${r_class}]"
            web_mod_write_raw "$entry_desc"
        done
        web_mod_write_footer "COMPLETED" "Discovered ${#detected_records[@]} accessible file(s)."
    else
        web_mod_write_kv "Status" "No accessible files or sensitive extensions discovered."
        web_mod_write_footer "COMPLETED" "No files discovered."
    fi

    web_mod_finish 0
}

# Execute main function when invoked as a script.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    module_file_run "$@"
fi
