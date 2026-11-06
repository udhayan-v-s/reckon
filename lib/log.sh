#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Logging framework library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_LIB_LOG_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_LOG_LOADED=1

# Resolve library directory and source terminal presentation library.
LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1

# shellcheck source=lib/term.sh
if [[ -f "$LIB_DIR/term.sh" ]]; then
    source "$LIB_DIR/term.sh"
fi

# Logging configuration state.
LOG_VERBOSE=false
LOG_QUIET=false
LOG_DEBUG=false
LOG_FILE=""

# Initialize or reset logging framework state.
#
# Arguments:
#   $1 - verbose mode (true/false, default: false)
#   $2 - quiet mode (true/false, default: false)
#   $3 - debug mode (true/false, default: false)
#   $4 - log file path (optional, default: "")
#
# Returns:
#   0 always
log_init() {
    LOG_VERBOSE="${1:-false}"
    LOG_QUIET="${2:-false}"
    LOG_DEBUG="${3:-false}"
    LOG_FILE="${4:-}"
    return 0
}

# Explicit state setters.
log_set_file()    { LOG_FILE="${1:-}"; return 0; }
log_set_debug()   { LOG_DEBUG="${1:-false}"; return 0; }
log_set_verbose() { LOG_VERBOSE="${1:-false}"; return 0; }
log_set_quiet()   { LOG_QUIET="${1:-false}"; return 0; }

# Internal helper: append a timestamped, ANSI-stripped entry to LOG_FILE.
#
# Arguments:
#   $1 - severity label (INFO, WARN, ERROR, DEBUG, SUCCESS)
#   $2 - log message
_log_write_file() {
    local level="${1:-INFO}"
    local msg="${2:-}"
    local timestamp
    local clean_msg
    local log_dir

    if [[ -z "$LOG_FILE" ]]; then
        return 0
    fi

    # Format timestamp using Bash built-in (microsecond-fast, zero forks).
    printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' -1

    # Ensure message is stripped of ANSI escape sequences.
    if declare -F term_strip_ansi >/dev/null 2>&1; then
        clean_msg="$(term_strip_ansi "$msg")"
    else
        clean_msg="$msg"
    fi

    # Create destination directory if needed.
    log_dir="$(dirname -- "$LOG_FILE")"
    if [[ -n "$log_dir" && "$log_dir" != "." && ! -d "$log_dir" ]]; then
        mkdir -p -- "$log_dir" 2>/dev/null || :
    fi

    # Write log record to file.
    printf '[%s] [%s] %s\n' "$timestamp" "$level" "$clean_msg" >> "$LOG_FILE" 2>/dev/null || :
    return 0
}

# Log an informational message (stdout).
# Suppressed in quiet mode.
#
# Arguments:
#   $1 - message to log
log_info() {
    local msg="${1:-}"

    if [[ "$LOG_QUIET" != true ]]; then
        local tag="[INFO]"
        if declare -F term_cyan >/dev/null 2>&1; then
            tag="$(term_cyan "[INFO]")"
        fi
        printf '%s %s\n' "$tag" "$msg"
    fi

    _log_write_file "INFO" "$msg"
    return 0
}

# Log a positive outcome or discovery finding (stdout).
# Suppressed in quiet mode.
#
# Arguments:
#   $1 - message to log
log_success() {
    local msg="${1:-}"

    if [[ "$LOG_QUIET" != true ]]; then
        local tag="[+]"
        if declare -F term_green >/dev/null 2>&1; then
            tag="$(term_green "[+]")"
        fi
        printf '%s %s\n' "$tag" "$msg"
    fi

    _log_write_file "SUCCESS" "$msg"
    return 0
}

# Log a warning message (stderr).
# Emitted in all modes including quiet mode.
#
# Arguments:
#   $1 - warning message to log
log_warn() {
    local msg="${1:-}"
    local tag="[WARN]"

    if declare -F term_yellow >/dev/null 2>&1; then
        tag="$(term_yellow "[WARN]")"
    fi

    printf '%s %s\n' "$tag" "$msg" >&2
    _log_write_file "WARN" "$msg"
    return 0
}

# Log an error message (stderr).
# Emitted in all modes including quiet mode.
#
# Arguments:
#   $1 - error message to log
log_error() {
    local msg="${1:-}"
    local tag="[ERROR]"

    if declare -F term_red >/dev/null 2>&1; then
        tag="$(term_red "[ERROR]")"
    fi

    printf '%s %s\n' "$tag" "$msg" >&2
    _log_write_file "ERROR" "$msg"
    return 0
}

# Log a debugging message (stderr).
# Emitted only when debug mode is enabled.
#
# Arguments:
#   $1 - debug message to log
log_debug() {
    local msg="${1:-}"

    if [[ "$LOG_DEBUG" == true ]]; then
        local tag="[DEBUG]"
        if declare -F term_dim >/dev/null 2>&1; then
            tag="$(term_dim "[DEBUG]")"
        fi
        printf '%s %s\n' "$tag" "$msg" >&2
        _log_write_file "DEBUG" "$msg"
    fi

    return 0
}
