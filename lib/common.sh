#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Common system and utility helpers library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_LIB_COMMON_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_COMMON_LOADED=1

# Last error message recorded by library functions.
COMMON_ERROR=""

# Check if an external binary command exists in PATH.
#
# Arguments:
#   $1 - command name
#
# Returns:
#   0 if command is available and executable, 1 otherwise
common_has_command() {
    local cmd="${1:-}"
    [[ -n "$cmd" ]] && command -v -- "$cmd" >/dev/null 2>&1
}

# Require that an external binary command is available in PATH.
#
# Arguments:
#   $1 - command name
#   $2 - optional installation hint or context
#
# Returns:
#   0 if available, 1 if missing (populates COMMON_ERROR)
common_require_command() {
    local cmd="${1:-}"
    local hint="${2:-}"

    COMMON_ERROR=""

    if [[ -z "$cmd" ]]; then
        COMMON_ERROR="Command name cannot be empty."
        return 1
    fi

    if ! common_has_command "$cmd"; then
        if [[ -n "$hint" ]]; then
            COMMON_ERROR="Required external tool not found: '$cmd' ($hint)"
        else
            COMMON_ERROR="Required external tool not found: '$cmd'"
        fi
        return 1
    fi

    return 0
}

# Check if a value is an integer (positive, zero, or negative).
#
# Arguments:
#   $1 - candidate value
#
# Returns:
#   0 if integer, 1 otherwise
common_is_integer() {
    local val="${1:-}"
    [[ "$val" =~ ^[+-]?[0-9]+$ ]]
}

# Check if a value is a strictly positive integer (>= 1).
# Rejects 0, negatives, and non-integers.
#
# Arguments:
#   $1 - candidate value
#
# Returns:
#   0 if positive integer, 1 otherwise
common_is_positive_integer() {
    local val="${1:-}"
    [[ "$val" =~ ^[1-9][0-9]*$ ]]
}

# Check if a value is a non-negative integer (>= 0).
# Accepts 0 and positive integers; rejects negatives and non-integers.
#
# Arguments:
#   $1 - candidate value
#
# Returns:
#   0 if non-negative integer, 1 otherwise
common_is_non_negative_integer() {
    local val="${1:-}"
    [[ "$val" =~ ^(0|[1-9][0-9]*)$ ]]
}

# Trim leading and trailing whitespace from a string.
#
# Arguments:
#   $1 - input string
#
# Output:
#   Trimmed string on stdout
common_trim() {
    local str="${1:-}"
    # Strip leading whitespace using pattern stripping
    str="${str#"${str%%[![:space:]]*}"}"
    # Strip trailing whitespace using pattern stripping
    str="${str%"${str##*[![:space:]]}"}"
    printf '%s\n' "$str"
}

# Convert an ASCII string to lowercase.
#
# Arguments:
#   $1 - input string
#
# Output:
#   Lowercased string on stdout
common_to_lower() {
    local str="${1:-}"
    printf '%s\n' "${str,,}"
}

# Convert an ASCII string to uppercase.
#
# Arguments:
#   $1 - input string
#
# Output:
#   Uppercased string on stdout
common_to_upper() {
    local str="${1:-}"
    printf '%s\n' "${str^^}"
}

# Check if an array contains an exact matching element.
#
# Arguments:
#   $1    - needle to search for
#   $2... - elements of the array
#
# Returns:
#   0 if found, 1 if not found
common_contains_element() {
    local needle="${1:-}"
    shift || return 1
    local item

    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done

    return 1
}

# Check if a directory is completely empty (contains no files, dirs, or dotfiles).
#
# Arguments:
#   $1 - directory path
#
# Returns:
#   0 if directory exists and is empty
#   1 if non-empty, not a directory, or unreadable
common_is_empty_dir() {
    local dir="${1:-}"

    if [[ ! -d "$dir" || ! -r "$dir" ]]; then
        return 1
    fi

    local entries=()
    local prev_nullglob=false
    local prev_dotglob=false

    shopt -q nullglob && prev_nullglob=true
    shopt -q dotglob && prev_dotglob=true

    shopt -s nullglob dotglob
    entries=("$dir"/*)

    [[ "$prev_nullglob" == false ]] && shopt -u nullglob
    [[ "$prev_dotglob" == false ]] && shopt -u dotglob

    (( ${#entries[@]} == 0 ))
}
