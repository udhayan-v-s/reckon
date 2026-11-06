#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Filesystem operations and security library
#

# Cross-function and library-exported state variables.
# shellcheck disable=SC2034

set -o nounset

# Include guard to prevent duplicate loading.
if [[ -n "${_RECKON_LIB_FS_LOADED:-}" ]]; then
    return 0
fi
readonly _RECKON_LIB_FS_LOADED=1

# Track created temporary files and directories for automatic cleanup.
_FS_TEMP_FILES=()
_FS_TEMP_DIRS=()

# Ensure a directory exists with secure permissions.
#
# Arguments:
#   $1 - target directory path
#   $2 - optional octal permissions (default: 0750)
#
# Returns:
#   0 on success (directory exists and is writable)
#   1 on failure (cannot create, not a directory, or not writable)
fs_ensure_dir() {
    local dir="${1:-}"
    local mode="${2:-0750}"

    if [[ -z "$dir" ]]; then
        return 1
    fi

    # If target already exists as a directory, check write permissions.
    if [[ -d "$dir" ]]; then
        if [[ -w "$dir" ]]; then
            return 0
        fi
        return 1
    fi

    # If target exists but is not a directory (e.g. regular file), reject.
    if [[ -e "$dir" ]]; then
        return 1
    fi

    # Create directory hierarchy.
    if ! mkdir -p -- "$dir" 2>/dev/null; then
        return 1
    fi

    # Apply permissions.
    chmod "$mode" -- "$dir" 2>/dev/null || :

    # Verify directory is writable.
    [[ -d "$dir" && -w "$dir" ]]
}

# Resolve a path to its canonical, absolute form.
#
# Arguments:
#   $1 - path to canonicalize
#
# Output:
#   Canonical absolute path on stdout
#
# Returns:
#   0 on success, 1 on invalid path
fs_canonical_path() {
    local path="${1:-}"

    if [[ -z "$path" ]]; then
        return 1
    fi

    # Use realpath if available.
    if command -v realpath >/dev/null 2>&1; then
        realpath -q -- "$path"
    else
        # Fallback to cd and pwd resolution.
        (
            local target_dir
            local base_name
            if [[ -d "$path" ]]; then
                cd -- "$path" 2>/dev/null && pwd -P
            else
                target_dir="$(dirname -- "$path")"
                base_name="$(basename -- "$path")"
                cd -- "$target_dir" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$base_name"
            fi
        )
    fi
}

# Verify that a target path is strictly contained within a base directory.
# Protects against directory traversal attacks (e.g. ../../etc/shadow).
#
# Arguments:
#   $1 - allowed base directory
#   $2 - candidate target path
#
# Returns:
#   0 if target is within base directory
#   1 if target escapes base directory or paths cannot be resolved
fs_is_within_dir() {
    local base="${1:-}"
    local target="${2:-}"
    local canon_base
    local canon_target

    if [[ -z "$base" || -z "$target" ]]; then
        return 1
    fi

    canon_base="$(fs_canonical_path "$base")" || return 1
    canon_target="$(fs_canonical_path "$target")" || return 1

    # Check whether canon_target matches or begins with canon_base/.
    if [[ "$canon_target" == "$canon_base" || "$canon_target" == "$canon_base"/* ]]; then
        return 0
    fi

    return 1
}

# Create a secure temporary file tracked for cleanup.
#
# Arguments:
#   $1 - optional destination variable name (sets variable via printf -v to avoid subshell loss)
#   $2 - optional filename prefix (default: reckon)
#
# Output:
#   Prints path on stdout if destination variable name is empty
#
# Returns:
#   0 on success, 1 on failure
fs_mktemp_file() {
    local var_name="${1:-}"
    local prefix="${2:-reckon}"
    local tmp_dir="${TMPDIR:-/tmp}"
    local tmp_file

    if ! tmp_file="$(mktemp "${tmp_dir}/${prefix}_file.XXXXXX" 2>/dev/null)"; then
        return 1
    fi

    chmod 0600 "$tmp_file" 2>/dev/null || :
    _FS_TEMP_FILES+=("$tmp_file")

    if [[ -n "$var_name" ]]; then
        printf -v "$var_name" '%s' "$tmp_file"
    else
        printf '%s\n' "$tmp_file"
    fi
    return 0
}

# Create a secure temporary directory tracked for cleanup.
#
# Arguments:
#   $1 - optional destination variable name (sets variable via printf -v to avoid subshell loss)
#   $2 - optional directory prefix (default: reckon)
#
# Output:
#   Prints path on stdout if destination variable name is empty
#
# Returns:
#   0 on success, 1 on failure
fs_mktemp_dir() {
    local var_name="${1:-}"
    local prefix="${2:-reckon}"
    local tmp_dir="${TMPDIR:-/tmp}"
    local tmp_subdir

    if ! tmp_subdir="$(mktemp -d "${tmp_dir}/${prefix}_dir.XXXXXX" 2>/dev/null)"; then
        return 1
    fi

    chmod 0700 "$tmp_subdir" 2>/dev/null || :
    _FS_TEMP_DIRS+=("$tmp_subdir")

    if [[ -n "$var_name" ]]; then
        printf -v "$var_name" '%s' "$tmp_subdir"
    else
        printf '%s\n' "$tmp_subdir"
    fi
    return 0
}

# Manually register an existing path to be removed on fs_cleanup_temp.
#
# Arguments:
#   $1 - file or directory path
#
# Returns:
#   0 on success, 1 on empty argument
fs_track_temp() {
    local path="${1:-}"

    if [[ -z "$path" ]]; then
        return 1
    fi

    if [[ -d "$path" ]]; then
        _FS_TEMP_DIRS+=("$path")
    else
        _FS_TEMP_FILES+=("$path")
    fi
    return 0
}

# Remove all temporary files and directories tracked by this library.
#
# Returns:
#   0 always
fs_cleanup_temp() {
    local item

    for item in "${_FS_TEMP_FILES[@]}"; do
        if [[ -f "$item" ]]; then
            rm -f -- "$item" 2>/dev/null || :
        fi
    done
    _FS_TEMP_FILES=()

    for item in "${_FS_TEMP_DIRS[@]}"; do
        if [[ -d "$item" ]]; then
            rm -rf -- "$item" 2>/dev/null || :
        fi
    done
    _FS_TEMP_DIRS=()

    return 0
}

# Check if a file exists, is a regular file, and is readable.
#
# Arguments:
#   $1 - file path
#
# Returns:
#   0 if readable regular file, 1 otherwise
fs_is_readable_file() {
    local file="${1:-}"
    [[ -n "$file" && -f "$file" && -r "$file" ]]
}

# Check if a directory exists and is writable.
#
# Arguments:
#   $1 - directory path
#
# Returns:
#   0 if writable directory, 1 otherwise
fs_is_writable_dir() {
    local dir="${1:-}"
    [[ -n "$dir" && -d "$dir" && -w "$dir" ]]
}

# Check if a regular file exists and is empty (size 0).
#
# Arguments:
#   $1 - file path
#
# Returns:
#   0 if empty regular file, 1 otherwise
fs_is_empty_file() {
    local file="${1:-}"
    [[ -n "$file" && -f "$file" && ! -s "$file" ]]
}

# Retrieve the size of a regular file in bytes.
#
# Arguments:
#   $1 - file path
#
# Output:
#   Size in bytes on stdout
#
# Returns:
#   0 on success, 1 if file does not exist
fs_file_size() {
    local file="${1:-}"
    local raw_size

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    raw_size="$(wc -c < "$file" 2>/dev/null)" || return 1
    # Strip any surrounding whitespace.
    printf '%s\n' "${raw_size//[[:space:]]/}"
    return 0
}
