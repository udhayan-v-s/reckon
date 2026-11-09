#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Reconnaissance Module Shared Framework (modules/web/common.sh)
#
# Provides a shared framework and specialized utility functions for all
# web reconnaissance and discovery modules (http-probe, subdomain, technology,
# cms, waf, etc.).
#
# Key Capabilities:
#   - Robust target deconstruction and URL normalization across URL, domain, and IP targets
#   - Base URL, full URL, scheme, host, port, path, and query extraction
#   - Correlation with upstream discovery artifacts (open_ports.txt, services.txt, live_web.txt)
#   - Standardized user-agent and tool selection helpers
#   - Uniform reconnaissance header, section, key-value, and completion formatting
#   - Secure permission enforcement on all generated web task artifacts
#

# Exported module context variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_MODULES_WEB_COMMON_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_MODULES_WEB_COMMON_LOADED=1

# Web module runtime context variables.
WEB_TARGET=""
WEB_TARGET_TYPE=""
WEB_TASK_DIR=""
WEB_OUTPUT_FILE=""
WEB_PARENT_DIR=""
WEB_MOD_ERROR=""

# Deconstructed URL and target components.
WEB_URL_SCHEME=""
WEB_URL_HOST=""
WEB_URL_PORT=""
WEB_URL_PATH=""
WEB_URL_QUERY=""
WEB_BASE_URL=""
WEB_FULL_URL=""
WEB_RESOLVED_URLS=()

# Upstream discovery artifact references.
WEB_UPSTREAM_OPEN_PORTS_FILE=""
WEB_UPSTREAM_SERVICES_FILE=""
WEB_UPSTREAM_PROBED_URLS_FILE=""
WEB_UPSTREAM_LIVE_WEB_FILE=""
WEB_UPSTREAM_SUBDOMAINS_FILE=""
WEB_UPSTREAM_RESOLVED_SUBDOMAINS_FILE=""

# Standardized User-Agent for RECKON web requests.
readonly WEB_DEFAULT_USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 RECKON-Recon/1.0"

# Normalize a URL or endpoint string into standard RFC-compliant form.
#
# Arguments:
#   $1 - raw URL string
#
# Output:
#   Normalized URL on stdout
#
# Returns:
#   0 on success, 1 on invalid/empty input
web_mod_normalize_url() {
    local raw="${1:-}"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"

    if [[ -z "$raw" ]]; then
        return 1
    fi

    local scheme=""
    local rest=""
    if [[ "$raw" =~ ^([hH][tT][tT][pP][sS]?)://(.*)$ ]]; then
        scheme="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
        rest="${BASH_REMATCH[2]}"
    else
        scheme="http"
        rest="$raw"
    fi

    # Separate host:port from path and query.
    local host_port=""
    local path_query=""
    if [[ "$rest" == *"/"* ]]; then
        host_port="${rest%%/*}"
        path_query="/${rest#*/}"
    else
        host_port="$rest"
        path_query="/"
    fi

    # Separate host and port.
    local host_part="$host_port"
    local port_part=""
    if [[ "$host_port" == *":"* ]]; then
        host_part="${host_port%%:*}"
        port_part="${host_port##*:}"
    fi

    # Strip default port numbers (80 for http, 443 for https).
    if [[ ( "$scheme" == "http" && "$port_part" == "80" ) || ( "$scheme" == "https" && "$port_part" == "443" ) ]]; then
        port_part=""
    fi

    # Normalize host to lowercase.
    host_part="$(printf '%s' "$host_part" | tr '[:upper:]' '[:lower:]')"

    if [[ -n "$port_part" ]]; then
        printf '%s://%s:%s%s\n' "$scheme" "$host_part" "$port_part" "$path_query"
    else
        printf '%s://%s%s\n' "$scheme" "$host_part" "$path_query"
    fi

    return 0
}

# Initialize the web module execution context from positional arguments.
#
# Arguments:
#   $1 - target string
#   $2 - target type (url_http, url_https, domain, hostname, ipv4)
#   $3 - task output directory path
#   $@ - (optional) compatible target types allowed by the caller module
#
# Returns:
#   0 on success, 1 on argument/directory error, 2 on target type incompatibility
web_mod_init() {
    WEB_MOD_ERROR=""
    WEB_TARGET=""
    WEB_TARGET_TYPE=""
    WEB_TASK_DIR=""
    WEB_OUTPUT_FILE=""
    WEB_PARENT_DIR=""
    WEB_URL_SCHEME=""
    WEB_URL_HOST=""
    WEB_URL_PORT=""
    WEB_URL_PATH=""
    WEB_URL_QUERY=""
    WEB_BASE_URL=""
    WEB_FULL_URL=""
    WEB_RESOLVED_URLS=()

    if (( $# < 3 )); then
        WEB_MOD_ERROR="Insufficient arguments: expected target, target_type, and task_dir."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi

    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"
    shift 3
    local -a allowed_types=("$@")

    if [[ -z "$target" ]]; then
        WEB_MOD_ERROR="Target string cannot be empty."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi

    if [[ -z "$t_type" ]]; then
        WEB_MOD_ERROR="Target type cannot be empty."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi

    if [[ -z "$task_dir" ]]; then
        WEB_MOD_ERROR="Task output directory cannot be empty."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi

    # Check caller-specified target type compatibility constraints if supplied.
    if (( ${#allowed_types[@]} > 0 )); then
        local matched=false
        local allowed
        for allowed in "${allowed_types[@]}"; do
            if [[ "$t_type" == "$allowed" ]]; then
                matched=true
                break
            fi
        done
        if [[ "$matched" == false ]]; then
            WEB_MOD_ERROR="Target type '$t_type' is incompatible with this module (requires: ${allowed_types[*]})."
            # Still ensure task directory exists so output notice can be logged.
            mkdir -p "$task_dir" 2>/dev/null || true
            WEB_OUTPUT_FILE="${task_dir}/output.txt"
            {
                printf '================================================================================\n'
                printf 'RECKON Web Reconnaissance - Execution Notice\n'
                printf 'Target: %s | Type: %s\n' "$target" "$t_type"
                printf '================================================================================\n'
                printf 'Status: SKIPPED\n'
                printf 'Reason: %s\n' "$WEB_MOD_ERROR"
                printf '================================================================================\n'
            } > "$WEB_OUTPUT_FILE"
            chmod 0640 "$WEB_OUTPUT_FILE" 2>/dev/null || true
            return 2
        fi
    fi

    # Ensure task directory exists with secure 0750 permissions.
    if [[ ! -d "$task_dir" ]]; then
        if ! mkdir -p "$task_dir" 2>/dev/null; then
            WEB_MOD_ERROR="Failed to create task directory: $task_dir"
            printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
            return 1
        fi
        chmod 0750 "$task_dir" 2>/dev/null || true
    fi

    WEB_TARGET="$target"
    WEB_TARGET_TYPE="$t_type"
    WEB_TASK_DIR="$task_dir"
    WEB_OUTPUT_FILE="${task_dir}/output.txt"
    WEB_PARENT_DIR="$(dirname "$task_dir")"

    # Set references to upstream reconnaissance artifacts.
    WEB_UPSTREAM_OPEN_PORTS_FILE="${WEB_PARENT_DIR}/port/open_ports.txt"
    WEB_UPSTREAM_SERVICES_FILE="${WEB_PARENT_DIR}/service/services.txt"
    WEB_UPSTREAM_PROBED_URLS_FILE="${WEB_PARENT_DIR}/http-probe/probed_urls.txt"
    WEB_UPSTREAM_LIVE_WEB_FILE="${WEB_PARENT_DIR}/http-probe/live_web.txt"
    WEB_UPSTREAM_SUBDOMAINS_FILE="${WEB_PARENT_DIR}/subdomain/subdomains.txt"
    WEB_UPSTREAM_RESOLVED_SUBDOMAINS_FILE="${WEB_PARENT_DIR}/subdomain/resolved_subdomains.txt"

    # Deconstruct target components.
    if [[ "$t_type" == "url_http" || "$t_type" == "url_https" ]]; then
        local proto="${target%%://*}"
        local remainder="${target#*://}"
        local host_port=""
        local path_query=""

        if [[ "$remainder" == *"/"* ]]; then
            host_port="${remainder%%/*}"
            path_query="/${remainder#*/}"
        else
            host_port="$remainder"
            path_query="/"
        fi

        local path_part="$path_query"
        local query_part=""
        if [[ "$path_query" == *"?"* ]]; then
            path_part="${path_query%%\?*}"
            query_part="${path_query#*\?}"
        fi

        local host_part="$host_port"
        local port_part=""
        if [[ "$host_port" == *":"* ]]; then
            host_part="${host_port%%:*}"
            port_part="${host_port##*:}"
        fi

        if [[ -z "$port_part" ]]; then
            if [[ "$proto" == "https" ]]; then
                port_part="443"
            else
                port_part="80"
            fi
        fi

        WEB_URL_SCHEME="$proto"
        WEB_URL_HOST="$host_part"
        WEB_URL_PORT="$port_part"
        WEB_URL_PATH="$path_part"
        WEB_URL_QUERY="$query_part"

        # Construct standard base URL (omitting default port numbers).
        if [[ ( "$proto" == "http" && "$port_part" == "80" ) || ( "$proto" == "https" && "$port_part" == "443" ) ]]; then
            WEB_BASE_URL="${proto}://${host_part}"
        else
            WEB_BASE_URL="${proto}://${host_part}:${port_part}"
        fi

        if [[ -n "$query_part" ]]; then
            WEB_FULL_URL="${WEB_BASE_URL}${path_part}?${query_part}"
        else
            WEB_FULL_URL="${WEB_BASE_URL}${path_part}"
        fi

        WEB_RESOLVED_URLS=("$WEB_FULL_URL")
    else
        # Discrete host, domain, or IP target.
        WEB_URL_SCHEME=""
        WEB_URL_HOST="$target"
        WEB_URL_PORT=""
        WEB_URL_PATH="/"
        WEB_URL_QUERY=""
        WEB_BASE_URL="http://${target}"
        WEB_FULL_URL="http://${target}/"

        # Provide candidate endpoints: prefer HTTPS then HTTP.
        WEB_RESOLVED_URLS=("https://${target}" "http://${target}")
    fi

    return 0
}

# Target classification predicates.
web_mod_is_url() {
    [[ "$WEB_TARGET_TYPE" == "url_http" || "$WEB_TARGET_TYPE" == "url_https" ]]
}

web_mod_is_https() {
    [[ "$WEB_URL_SCHEME" == "https" || "$WEB_TARGET_TYPE" == "url_https" ]]
}

web_mod_is_domain() {
    [[ "$WEB_TARGET_TYPE" == "domain" || "$WEB_TARGET_TYPE" == "hostname" ]]
}

web_mod_is_ip() {
    [[ "$WEB_TARGET_TYPE" == "ipv4" ]]
}

# Resolve candidate target URLs for scanning.
#
# Preference hierarchy:
#   1. Explicit target URL (if target was url_http or url_https)
#   2. Live URLs from upstream http-probe (live_web.txt)
#   3. Web ports from upstream services.txt or open_ports.txt
#   4. Default candidates: https://<host> and http://<host>
#
# Output:
#   One or more URLs on stdout, one per line
web_mod_get_target_urls() {
    if web_mod_is_url; then
        printf '%s\n' "$WEB_FULL_URL"
        return 0
    fi

    # 1. Check upstream live web endpoints from http-probe.
    if [[ -f "$WEB_UPSTREAM_LIVE_WEB_FILE" && -s "$WEB_UPSTREAM_LIVE_WEB_FILE" ]]; then
        local url
        local found=false
        while IFS= read -r url || [[ -n "$url" ]]; do
            url="${url#"${url%%[![:space:]]*}"}"
            url="${url%"${url##*[![:space:]]}"}"
            if [[ -n "$url" ]]; then
                printf '%s\n' "$url"
                found=true
            fi
        done < "$WEB_UPSTREAM_LIVE_WEB_FILE"
        if [[ "$found" == true ]]; then
            return 0
        fi
    fi

    # 2. Check upstream open ports and services for known web services.
    local -a web_ports=()
    if [[ -f "$WEB_UPSTREAM_SERVICES_FILE" && -s "$WEB_UPSTREAM_SERVICES_FILE" ]]; then
        local line port svc proto
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Expected format: <port>/<proto>\t<status>\t<service>\t[version]
            if [[ "$line" =~ ^([0-9]+)/(tcp|udp)[[:space:]]+open[[:space:]]+([^[:space:]]+) ]]; then
                port="${BASH_REMATCH[1]}"
                svc="${BASH_REMATCH[3]}"
                case "$svc" in
                    http|https|http-proxy|http-alt|https-alt|ssl/http|ssl/https)
                        web_ports+=("$port")
                        ;;
                esac
            fi
        done < "$WEB_UPSTREAM_SERVICES_FILE"
    fi

    if (( ${#web_ports[@]} > 0 )); then
        local p
        for p in "${web_ports[@]}"; do
            if (( p == 443 || p == 8443 || p == 9443 )); then
                printf 'https://%s:%s\n' "$WEB_URL_HOST" "$p"
            elif (( p == 80 )); then
                printf 'http://%s\n' "$WEB_URL_HOST"
            else
                printf 'http://%s:%s\n' "$WEB_URL_HOST" "$p"
            fi
        done
        return 0
    fi

    # 3. Default fallback candidates.
    printf 'https://%s\n' "$WEB_URL_HOST"
    printf 'http://%s\n' "$WEB_URL_HOST"
    return 0
}

# Read open TCP ports from upstream network discovery.
#
# Output:
#   Open port numbers on stdout, one per line
web_mod_get_upstream_open_ports() {
    if [[ -f "$WEB_UPSTREAM_OPEN_PORTS_FILE" && -s "$WEB_UPSTREAM_OPEN_PORTS_FILE" ]]; then
        sort -u -n "$WEB_UPSTREAM_OPEN_PORTS_FILE" 2>/dev/null || true
    fi
}

# Read subdomains from upstream discovery.
#
# Output:
#   Discovered subdomains on stdout, one per line
web_mod_get_upstream_subdomains() {
    if [[ -f "$WEB_UPSTREAM_RESOLVED_SUBDOMAINS_FILE" && -s "$WEB_UPSTREAM_RESOLVED_SUBDOMAINS_FILE" ]]; then
        awk '{print $1}' "$WEB_UPSTREAM_RESOLVED_SUBDOMAINS_FILE" | sort -u
    elif [[ -f "$WEB_UPSTREAM_SUBDOMAINS_FILE" && -s "$WEB_UPSTREAM_SUBDOMAINS_FILE" ]]; then
        sort -u "$WEB_UPSTREAM_SUBDOMAINS_FILE"
    fi
}

# Standardized User-Agent string.
web_mod_get_user_agent() {
    printf '%s\n' "${RECKON_USER_AGENT:-$WEB_DEFAULT_USER_AGENT}"
}

# Tool execution inspection and selection.
web_mod_has_tool() {
    local tool="${1:-}"
    [[ -n "$tool" ]] && command -v "$tool" >/dev/null 2>&1
}

web_mod_require_tool() {
    local tool="${1:-}"
    if ! web_mod_has_tool "$tool"; then
        WEB_MOD_ERROR="Required tool '$tool' is not available in PATH."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi
    return 0
}

web_mod_select_tool() {
    local primary="${1:-}"
    local fallback="${2:-}"

    if web_mod_has_tool "$primary"; then
        printf '%s\n' "$primary"
        return 0
    elif web_mod_has_tool "$fallback"; then
        printf '%s\n' "$fallback"
        return 0
    else
        WEB_MOD_ERROR="Neither '$primary' nor '$fallback' is available in PATH."
        printf 'Error: %s\n' "$WEB_MOD_ERROR" >&2
        return 1
    fi
}

# Structured Output Writers.

web_mod_write_header() {
    local mod_id="${1:-unknown}"
    local mod_name="${2:-Web Reconnaissance}"
    local date_str
    date_str="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")"

    {
        printf '%s\n' '================================================================================'
        printf 'RECKON Web Reconnaissance - %s (%s)\n' "$mod_name" "$mod_id"
        printf 'Target: %s | Type: %s | Date: %s\n' "$WEB_TARGET" "$WEB_TARGET_TYPE" "$date_str"
        printf '%s\n' '================================================================================'
    } >> "${WEB_OUTPUT_FILE:-/dev/null}"
}

web_mod_write_section() {
    local section_title="${1:-Section}"
    {
        printf '\n[--- %s ---]\n' "$section_title"
    } >> "${WEB_OUTPUT_FILE:-/dev/null}"
}

web_mod_write_kv() {
    local key="${1:-}"
    local val="${2:-}"
    {
        printf '  %-24s : %s\n' "$key" "$val"
    } >> "${WEB_OUTPUT_FILE:-/dev/null}"
}

web_mod_write_raw() {
    local text="${1:-}"
    printf '%s\n' "$text" >> "${WEB_OUTPUT_FILE:-/dev/null}"
}

web_mod_write_footer() {
    local status="${1:-COMPLETED}"
    local summary="${2:-Module execution finished.}"

    {
        printf '%s\n' '--------------------------------------------------------------------------------'
        printf 'Status: %s | %s\n' "$status" "$summary"
        printf '%s\n' '================================================================================'
    } >> "${WEB_OUTPUT_FILE:-/dev/null}"
}

# Finalize execution, enforce secure permissions, and return exit code.
#
# Arguments:
#   $1 - exit code (default: 0)
#
# Returns:
#   Supplied exit code
web_mod_finish() {
    local exit_code="${1:-0}"

    if [[ -d "${WEB_TASK_DIR:-}" ]]; then
        # Ensure 0640 permissions on all text artifacts in the task directory.
        find "$WEB_TASK_DIR" -maxdepth 1 -type f -name "*.txt" -exec chmod 0640 {} + 2>/dev/null || true
    fi

    return "$exit_code"
}
