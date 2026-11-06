#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Safe command execution wrapper library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_LIB_EXEC_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_EXEC_LOADED=1

# Execution metadata and results.
EXEC_EXIT_CODE=0
EXEC_DURATION=0
EXEC_TIMED_OUT=false
EXEC_ERROR=""
EXEC_STDOUT=""
EXEC_STDERR=""

# Execute a command safely using array expansion with stream routing and timeout support.
#
# Arguments:
#   $1 - destination for stdout ("" for /dev/null, "-" for stdout, or file path)
#   $2 - destination for stderr ("" for /dev/null, "-" for stderr, or file path)
#   $3 - timeout in seconds (0 or empty for unlimited)
#   $4... - command and its arguments as separate array elements
#
# Returns:
#   Exit code of the executed command (or 124 on timeout, 1 on argument failure)
exec_run() {
    local stdout_dest="${1:-}"
    local stderr_dest="${2:-}"
    local timeout_sec="${3:-0}"

    EXEC_ERROR=""
    EXEC_TIMED_OUT=false
    EXEC_EXIT_CODE=0
    EXEC_DURATION=0

    # Validate argument count.
    if (( $# < 4 )); then
        EXEC_ERROR="exec_run requires stdout_dest, stderr_dest, timeout, and a command."
        return 1
    fi

    shift 3
    local cmd=("$@")

    if (( ${#cmd[@]} == 0 )) || [[ -z "${cmd[0]}" ]]; then
        EXEC_ERROR="No command binary specified for execution."
        return 1
    fi

    # Wrap with GNU timeout if a positive integer timeout is specified and timeout is available.
    if [[ "$timeout_sec" =~ ^[1-9][0-9]*$ ]] && command -v timeout >/dev/null 2>&1; then
        cmd=("timeout" "-k" "5s" "${timeout_sec}s" "${cmd[@]}")
    fi

    local out_target="/dev/null"
    local err_target="/dev/null"

    [[ -n "$stdout_dest" ]] && out_target="$stdout_dest"
    [[ -n "$stderr_dest" ]] && err_target="$stderr_dest"

    local start_time=$SECONDS

    # Execute command with safe stream redirection.
    # Arguments are preserved literally through array expansion ("${cmd[@]}").
    if [[ "$out_target" == "-" && "$err_target" == "-" ]]; then
        "${cmd[@]}"
    elif [[ "$out_target" == "-" ]]; then
        "${cmd[@]}" 2>"$err_target"
    elif [[ "$err_target" == "-" ]]; then
        "${cmd[@]}" >"$out_target"
    else
        "${cmd[@]}" >"$out_target" 2>"$err_target"
    fi
    EXEC_EXIT_CODE=$?

    EXEC_DURATION=$(( SECONDS - start_time ))

    # Check for timeout termination (GNU timeout exit code 124).
    if [[ "$timeout_sec" =~ ^[1-9][0-9]*$ ]] && (( EXEC_EXIT_CODE == 124 )); then
        EXEC_TIMED_OUT=true
    fi

    return "$EXEC_EXIT_CODE"
}

# Execute a command safely and capture its standard output and error into variables.
#
# Arguments:
#   $1 - timeout in seconds (0 or empty for unlimited)
#   $2... - command and its arguments
#
# Output:
#   Populates EXEC_STDOUT and EXEC_STDERR
#
# Returns:
#   Exit code of the executed command
exec_capture() {
    local timeout_sec="${1:-0}"

    EXEC_STDOUT=""
    EXEC_STDERR=""

    if (( $# < 2 )); then
        EXEC_ERROR="exec_capture requires timeout and a command."
        return 1
    fi

    shift 1

    local tmp_dir="${TMPDIR:-/tmp}"
    local out_file
    local err_file

    if ! out_file="$(mktemp "${tmp_dir}/reckon_exec_out.XXXXXX" 2>/dev/null)"; then
        EXEC_ERROR="Unable to create temporary output file for exec_capture."
        return 1
    fi

    if ! err_file="$(mktemp "${tmp_dir}/reckon_exec_err.XXXXXX" 2>/dev/null)"; then
        rm -f -- "$out_file" 2>/dev/null || :
        EXEC_ERROR="Unable to create temporary error file for exec_capture."
        return 1
    fi

    exec_run "$out_file" "$err_file" "$timeout_sec" "$@"
    local status=$?

    EXEC_STDOUT="$(cat "$out_file" 2>/dev/null)" || EXEC_STDOUT=""
    EXEC_STDERR="$(cat "$err_file" 2>/dev/null)" || EXEC_STDERR=""

    rm -f -- "$out_file" "$err_file" 2>/dev/null || :

    return "$status"
}

# Execute a command silently with both stdout and stderr discarded to /dev/null.
#
# Arguments:
#   $1... - command and its arguments
#
# Returns:
#   Exit code of the executed command
exec_silent() {
    if (( $# == 0 )); then
        return 1
    fi
    exec_run "" "" 0 "$@"
}

# Check if the last executed command was terminated due to a timeout.
#
# Returns:
#   0 if timed out, 1 otherwise
exec_is_timed_out() {
    [[ "$EXEC_TIMED_OUT" == true ]]
}
