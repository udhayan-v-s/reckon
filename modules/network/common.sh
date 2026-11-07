#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Network Reconnaissance Module Shared Library
#

# Exported module context variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_MODULES_NETWORK_COMMON_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_MODULES_NETWORK_COMMON_LOADED=1

# Network module runtime context variables.
NET_TARGET=""
NET_TARGET_TYPE=""
NET_TASK_DIR=""
NET_OUTPUT_FILE=""
NET_MOD_ERROR=""

# Initialize the module execution context from positional arguments.
#
# Arguments:
#   $1 - target string
#   $2 - target type (ipv4, ipv4_cidr, ipv4_range, hostname, domain, url_http, url_https)
#   $3 - task output directory path
#
# Returns:
#   0 on success, 1 on invalid or missing arguments
net_mod_init() {
    NET_MOD_ERROR=""
    NET_TARGET=""
    NET_TARGET_TYPE=""
    NET_TASK_DIR=""
    NET_OUTPUT_FILE=""

    if (( $# < 3 )); then
        NET_MOD_ERROR="Insufficient arguments: expected target, target_type, and task_dir."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi

    local target="${1:-}"
    local t_type="${2:-}"
    local task_dir="${3:-}"

    if [[ -z "$target" ]]; then
        NET_MOD_ERROR="Target string cannot be empty."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi

    if [[ -z "$t_type" ]]; then
        NET_MOD_ERROR="Target type cannot be empty."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi

    if [[ -z "$task_dir" ]]; then
        NET_MOD_ERROR="Task output directory cannot be empty."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi

    # Ensure task directory exists with secure permissions.
    if [[ ! -d "$task_dir" ]]; then
        if ! mkdir -p "$task_dir" 2>/dev/null; then
            NET_MOD_ERROR="Failed to create task directory: $task_dir"
            printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
            return 1
        fi
        chmod 0750 "$task_dir" 2>/dev/null || true
    fi

    NET_TARGET="$target"
    NET_TARGET_TYPE="$t_type"
    NET_TASK_DIR="$task_dir"
    NET_OUTPUT_FILE="${task_dir}/output.txt"

    return 0
}

# Check if a command or binary tool is available in PATH.
#
# Arguments:
#   $1 - binary tool name
#
# Returns:
#   0 if available and executable, 1 otherwise
net_mod_has_tool() {
    local tool="${1:-}"
    [[ -n "$tool" ]] && command -v "$tool" >/dev/null 2>&1
}

# Verify that a required tool is installed, or report an error.
#
# Arguments:
#   $1 - required binary tool name
#
# Returns:
#   0 if available, 1 if missing
net_mod_require_tool() {
    local tool="${1:-}"

    if ! net_mod_has_tool "$tool"; then
        NET_MOD_ERROR="Required tool '$tool' is not available in PATH."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi
    return 0
}

# Select between a primary tool and a fallback tool based on availability.
#
# Arguments:
#   $1 - primary tool name
#   $2 - fallback tool name
#
# Output:
#   Name of the chosen tool binary on stdout
#
# Returns:
#   0 if a tool was found, 1 if both are missing
net_mod_select_tool() {
    local primary="${1:-}"
    local fallback="${2:-}"

    if net_mod_has_tool "$primary"; then
        printf '%s\n' "$primary"
        return 0
    elif net_mod_has_tool "$fallback"; then
        printf '%s\n' "$fallback"
        return 0
    else
        NET_MOD_ERROR="Neither '$primary' nor '$fallback' is available in PATH."
        printf 'Error: %s\n' "$NET_MOD_ERROR" >&2
        return 1
    fi
}

# Determine if the target is an IP-based target (IPv4, CIDR, or range).
#
# Returns:
#   0 if IP-based, 1 otherwise
net_mod_is_ip() {
    case "$NET_TARGET_TYPE" in
        ipv4|ipv4_cidr|ipv4_range)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Determine if the target is a CIDR block.
#
# Returns:
#   0 if CIDR, 1 otherwise
net_mod_is_cidr() {
    [[ "$NET_TARGET_TYPE" == "ipv4_cidr" ]]
}

# Determine if the target is an IPv4 range.
#
# Returns:
#   0 if range, 1 otherwise
net_mod_is_range() {
    [[ "$NET_TARGET_TYPE" == "ipv4_range" ]]
}

# Determine if the target represents a subnet or multi-host block.
#
# Returns:
#   0 if subnet (CIDR or range), 1 otherwise
net_mod_is_subnet() {
    case "$NET_TARGET_TYPE" in
        ipv4_cidr|ipv4_range)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Determine if the target represents a single discrete host (single IP, domain, or hostname).
#
# Returns:
#   0 if single host, 1 otherwise
net_mod_is_single_host() {
    case "$NET_TARGET_TYPE" in
        ipv4|domain|hostname)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Determine if the target is a domain name or hostname.
#
# Returns:
#   0 if domain or hostname, 1 otherwise
net_mod_is_domain() {
    case "$NET_TARGET_TYPE" in
        domain|hostname)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Write standard reconnaissance header to the module output artifact.
#
# Arguments:
#   $1 - module identifier (e.g., "host", "dns")
#   $2 - module display title (e.g., "Host Discovery")
net_mod_write_header() {
    local mod_id="${1:-unknown}"
    local mod_name="${2:-Reconnaissance}"
    local date_str
    date_str="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date +"%Y-%m-%d %H:%M:%S")"

    {
        printf '%s\n' '================================================================================'
        printf 'RECKON Network Reconnaissance - %s (%s)\n' "$mod_name" "$mod_id"
        printf 'Target: %s | Type: %s | Date: %s\n' "$NET_TARGET" "$NET_TARGET_TYPE" "$date_str"
        printf '%s\n' '================================================================================'
    } >> "${NET_OUTPUT_FILE:-/dev/null}"
}

# Write a structured section banner to the module output artifact.
#
# Arguments:
#   $1 - section title
net_mod_write_section() {
    local section_title="${1:-Section}"
    {
        printf '\n[--- %s ---]\n' "$section_title"
    } >> "${NET_OUTPUT_FILE:-/dev/null}"
}

# Write an aligned key-value pair to the module output artifact.
#
# Arguments:
#   $1 - key name
#   $2 - value
net_mod_write_kv() {
    local key="${1:-}"
    local val="${2:-}"
    {
        printf '  %-24s : %s\n' "$key" "$val"
    } >> "${NET_OUTPUT_FILE:-/dev/null}"
}

# Append raw text or data block to the module output artifact.
#
# Arguments:
#   $1 - raw text to append
net_mod_write_raw() {
    local text="${1:-}"
    printf '%s\n' "$text" >> "${NET_OUTPUT_FILE:-/dev/null}"
}

# Write standard reconnaissance completion footer to the module output artifact.
#
# Arguments:
#   $1 - completion status (e.g., "COMPLETED", "FAILED")
#   $2 - summary message
net_mod_write_footer() {
    local status="${1:-COMPLETED}"
    local summary="${2:-Module execution finished.}"

    {
        printf '%s\n' '--------------------------------------------------------------------------------'
        printf 'Status: %s | %s\n' "$status" "$summary"
        printf '%s\n' '================================================================================'
    } >> "${NET_OUTPUT_FILE:-/dev/null}"
}

# Complete module execution, enforce output permissions, and return status code.
#
# Arguments:
#   $1 - exit code (default: 0)
#
# Returns:
#   Supplied exit code
net_mod_finish() {
    local exit_code="${1:-0}"

    if [[ -n "$NET_OUTPUT_FILE" && -f "$NET_OUTPUT_FILE" ]]; then
        chmod 0640 "$NET_OUTPUT_FILE" 2>/dev/null || true
    fi

    return "$exit_code"
}
