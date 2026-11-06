#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Filesystem operations and security library unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/fs.sh
if ! source "$PROJECT_ROOT/lib/fs.sh"; then
    printf 'Error: Unable to load filesystem library component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-fs-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
    fs_cleanup_temp
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Filesystem library unit tests completed."
}

printf '%s\n' "RECKON - Filesystem Library Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Directory Creation & Permissions (fs_ensure_dir)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Directory Creation & Permissions (fs_ensure_dir)"

# Test 1: Create a simple non-existent directory
target_dir="$TEST_ROOT/simple_dir"
if fs_ensure_dir "$target_dir" 0750 && [[ -d "$target_dir" && -w "$target_dir" ]]; then
    pass "fs_ensure_dir creates non-existent directory with write permissions"
else
    fail "fs_ensure_dir failed to create simple directory"
fi

# Test 2: Create a nested directory hierarchy (mkdir -p)
nested_dir="$TEST_ROOT/level1/level2/level3"
if fs_ensure_dir "$nested_dir" 0750 && [[ -d "$nested_dir" ]]; then
    pass "fs_ensure_dir creates nested directory hierarchies"
else
    fail "fs_ensure_dir failed to create nested directory hierarchy"
fi

# Test 3: Idempotent success when directory already exists
if fs_ensure_dir "$target_dir" 0750; then
    pass "fs_ensure_dir succeeds idempotently on existing directory"
else
    fail "fs_ensure_dir failed on already existing directory"
fi

# Test 4: Rejects target when path exists as a regular file
clashing_file="$TEST_ROOT/clashing_file.txt"
touch "$clashing_file"
if ! fs_ensure_dir "$clashing_file" 0750; then
    pass "fs_ensure_dir rejects target path when it exists as a regular file"
else
    fail "fs_ensure_dir succeeded when target path was a regular file"
fi

# Test 5: Rejects empty argument
if ! fs_ensure_dir ""; then
    pass "fs_ensure_dir rejects empty directory argument"
else
    fail "fs_ensure_dir accepted empty directory argument"
fi

# -----------------------------------------------------------------------------
# UT-02: Path Canonicalization (fs_canonical_path)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Path Canonicalization (fs_canonical_path)"

# Test 6: Canonicalize relative path containing . and ..
mkdir -p "$TEST_ROOT/a/b/c"
canon="$(fs_canonical_path "$TEST_ROOT/a/b/../b/c/.")"
if [[ -n "$canon" && "$canon" == "$TEST_ROOT/a/b/c" ]]; then
    pass "fs_canonical_path resolves relative dots to clean absolute path"
else
    fail "fs_canonical_path failed relative dot resolution: '$canon'"
fi

# Test 7: Canonicalize existing directory
canon="$(fs_canonical_path "$TEST_ROOT/a")"
if [[ "$canon" == "$TEST_ROOT/a" ]]; then
    pass "fs_canonical_path resolves absolute directory path"
else
    fail "fs_canonical_path failed on absolute directory: '$canon'"
fi

# Test 8: Rejects empty path
if ! fs_canonical_path ""; then
    pass "fs_canonical_path rejects empty path argument"
else
    fail "fs_canonical_path accepted empty path argument"
fi

# -----------------------------------------------------------------------------
# UT-03: Directory Traversal Protection (fs_is_within_dir)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Directory Traversal Protection (fs_is_within_dir)"
base_dir="$TEST_ROOT/sandbox"
mkdir -p "$base_dir/allowed_sub"
touch "$base_dir/allowed_sub/output.json"

# Test 9: Subdirectory is confirmed within base
if fs_is_within_dir "$base_dir" "$base_dir/allowed_sub"; then
    pass "fs_is_within_dir accepts valid subdirectory within base"
else
    fail "fs_is_within_dir rejected valid subdirectory"
fi

# Test 10: Nested file is confirmed within base
if fs_is_within_dir "$base_dir" "$base_dir/allowed_sub/output.json"; then
    pass "fs_is_within_dir accepts valid nested file path"
else
    fail "fs_is_within_dir rejected valid nested file"
fi

# Test 11: Directory traversal attempt escaping base is blocked
traversal_attempt="$base_dir/allowed_sub/../../outside.txt"
if ! fs_is_within_dir "$base_dir" "$traversal_attempt"; then
    pass "fs_is_within_dir blocks path traversal escaping base directory"
else
    fail "fs_is_within_dir allowed traversal path to escape base directory"
fi

# Test 12: Completely external absolute path is blocked
if ! fs_is_within_dir "$base_dir" "/etc/passwd"; then
    pass "fs_is_within_dir blocks unrelated external system paths"
else
    fail "fs_is_within_dir allowed external system path"
fi

# Test 13: Empty arguments rejected
if ! fs_is_within_dir "" "$base_dir"; then
    pass "fs_is_within_dir rejects empty arguments"
else
    fail "fs_is_within_dir accepted empty arguments"
fi

# -----------------------------------------------------------------------------
# UT-04: Temporary File & Directory Tracking (fs_mktemp_*, fs_cleanup_temp)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Temporary File & Directory Tracking (fs_mktemp_*, fs_cleanup_temp)"

# Test 14: Create temporary file with destination variable (avoids subshell loss)
tfile=""
fs_mktemp_file tfile "test"
if [[ -n "$tfile" && -f "$tfile" && -r "$tfile" && -w "$tfile" ]]; then
    pass "fs_mktemp_file creates accessible temporary file and assigns to variable"
else
    fail "fs_mktemp_file failed to create temporary file"
fi

# Test 15: Create temporary directory with destination variable
tdir=""
fs_mktemp_dir tdir "test"
if [[ -n "$tdir" && -d "$tdir" && -r "$tdir" && -w "$tdir" ]]; then
    pass "fs_mktemp_dir creates accessible temporary directory and assigns to variable"
else
    fail "fs_mktemp_dir failed to create temporary directory"
fi

# Test 16: Temporary items exist before cleanup
if [[ -f "$tfile" && -d "$tdir" ]]; then
    pass "Temporary items remain tracked and present before cleanup"
else
    fail "Temporary items disappeared before cleanup"
fi

# Test 17: Cleanup removes all tracked temporary files and directories
fs_cleanup_temp
if [[ ! -f "$tfile" && ! -d "$tdir" ]]; then
    pass "fs_cleanup_temp removes all tracked temporary files and directories"
else
    fail "fs_cleanup_temp failed to remove temporary artifacts"
fi

# Test 18: Output on stdout when variable name is omitted
stdout_temp="$(fs_mktemp_file "" "test_out")"
if [[ -n "$stdout_temp" && -f "$stdout_temp" ]]; then
    pass "fs_mktemp_file prints path to stdout when variable name is omitted"
    rm -f -- "$stdout_temp"
else
    fail "fs_mktemp_file failed to print path to stdout"
fi

# Test 19: Manual tracking with fs_track_temp
manual_temp="$TEST_ROOT/manual_temp.txt"
touch "$manual_temp"
fs_track_temp "$manual_temp"
fs_cleanup_temp
if [[ ! -f "$manual_temp" ]]; then
    pass "fs_track_temp registers external temporary files for cleanup"
else
    fail "fs_track_temp failed to remove registered path on cleanup"
fi

# -----------------------------------------------------------------------------
# UT-05: File State & Size Helpers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: File State & Size Helpers"

# Test 20: fs_is_readable_file identifies readable file
sample_file="$TEST_ROOT/sample.txt"
printf 'Hello RECKON' > "$sample_file"
if fs_is_readable_file "$sample_file"; then
    pass "fs_is_readable_file returns 0 for readable regular file"
else
    fail "fs_is_readable_file failed on readable regular file"
fi

# Test 21: fs_is_readable_file rejects directory
if ! fs_is_readable_file "$TEST_ROOT"; then
    pass "fs_is_readable_file rejects directory path"
else
    fail "fs_is_readable_file accepted directory path as a file"
fi

# Test 22: fs_is_readable_file rejects non-existent path
if ! fs_is_readable_file "$TEST_ROOT/non_existent.txt"; then
    pass "fs_is_readable_file rejects non-existent path"
else
    fail "fs_is_readable_file accepted non-existent path"
fi

# Test 23: fs_is_writable_dir identifies writable directory
if fs_is_writable_dir "$TEST_ROOT"; then
    pass "fs_is_writable_dir returns 0 for writable directory"
else
    fail "fs_is_writable_dir failed on writable directory"
fi

# Test 24: fs_is_empty_file identifies empty file
empty_file="$TEST_ROOT/empty.txt"
touch "$empty_file"
if fs_is_empty_file "$empty_file"; then
    pass "fs_is_empty_file returns 0 for zero-byte file"
else
    fail "fs_is_empty_file failed on zero-byte file"
fi

# Test 25: fs_is_empty_file returns 1 for non-empty file
if ! fs_is_empty_file "$sample_file"; then
    pass "fs_is_empty_file returns 1 for non-empty file"
else
    fail "fs_is_empty_file returned 0 for non-empty file"
fi

# Test 26: fs_file_size returns accurate byte count
size="$(fs_file_size "$sample_file")"
if [[ "$size" == "12" ]]; then
    pass "fs_file_size returns accurate byte count"
else
    fail "fs_file_size returned '$size', expected 12"
fi

# Test 27: fs_file_size returns 1 for non-existent file
if ! fs_file_size "$TEST_ROOT/missing.txt"; then
    pass "fs_file_size returns 1 for non-existent file"
else
    fail "fs_file_size succeeded on non-existent file"
fi

test_summary
