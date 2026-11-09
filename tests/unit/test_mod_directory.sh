#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Directory Enumeration Module Unit Tests (test_mod_directory.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/directory.sh
if ! source "$PROJECT_ROOT/modules/web/directory.sh"; then
    printf 'Error: Unable to load modules/web/directory.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-dir-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

cleanup() {
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

PASS_COUNT=0
FAIL_COUNT=0

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Web directory enumeration module unit tests completed."
}

printf '%s\n' "RECKON - Web Directory Enumeration Module Unit Tests"
printf '%s\n' "----------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_directory_run "example.com" "domain" 2>/dev/null; then
    fail "module_directory_run accepted fewer than 3 arguments"
else
    pass "module_directory_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_directory_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_directory_run accepted empty target"
else
    pass "module_directory_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_directory_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_directory_run accepted empty target type"
else
    pass "module_directory_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_directory_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_directory_run accepted empty task directory"
else
    pass "module_directory_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/directory"
mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

DIR_FFUF_BIN="$mock_empty" \
DIR_CURL_BIN="$mock_empty" \
module_directory_run "corp.local" "domain" "$task_compat_dom"
if [[ -f "${task_compat_dom}/output.txt" ]] && grep -q "Directory Enumeration" "${task_compat_dom}/output.txt"; then
    pass "module_directory_run accepts valid domain target"
else
    fail "module_directory_run failed on domain target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/directory"
if module_directory_run "10.0.0.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_directory_run skips multi-host CIDR block with execution notice"
    else
        fail "module_directory_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_directory_run returned error code on CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: FFUF Primary Engine Directory Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: FFUF Primary Engine Directory Fuzzing"

mock_ffuf="$TEST_ROOT/bin/mock_ffuf"
cat <<'EOF' > "$mock_ffuf"
#!/usr/bin/env bash
out_json=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_json="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_json" ]]; then
    cat <<'JSON_EOF' > "$out_json"
{
  "results": [
    {
      "input": {"FUZZ": "admin"},
      "status": 301,
      "length": 178,
      "redirectlocation": "http://corp.local/admin/",
      "url": "http://corp.local/admin"
    },
    {
      "input": {"FUZZ": "api"},
      "status": 200,
      "length": 512,
      "redirectlocation": "",
      "url": "http://corp.local/api"
    },
    {
      "input": {"FUZZ": "portal"},
      "status": 403,
      "length": 256,
      "redirectlocation": "",
      "url": "http://corp.local/portal"
    }
  ]
}
JSON_EOF
fi
exit 0
EOF
chmod +x "$mock_ffuf"

task_dir_ffuf="$TEST_ROOT/targets/ffuf_test/directory"
DIR_FFUF_BIN="$mock_ffuf" \
module_directory_run "http://corp.local" "url_http" "$task_dir_ffuf"

if [[ -f "${task_dir_ffuf}/directories.txt" ]] && \
   grep -q -E "^/admin"$'\t'"301" "${task_dir_ffuf}/directories.txt" && \
   grep -q -E "^/api"$'\t'"200" "${task_dir_ffuf}/directories.txt" && \
   grep -q -E "^/portal"$'\t'"403" "${task_dir_ffuf}/directories.txt"; then
    pass "FFUF engine extracts and writes discovered directories into directories.txt"
else
    fail "FFUF engine failed to write expected directories into directories.txt"
fi

if [[ -f "${task_dir_ffuf}/output.txt" ]] && \
   grep -q "Total Discovered.*3" "${task_dir_ffuf}/output.txt" && \
   grep -q "/admin \[HTTP 301\]" "${task_dir_ffuf}/output.txt"; then
    pass "Formats comprehensive summary report with discovered directories"
else
    fail "Formatted output report mismatch in $task_dir_ffuf"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Fuzzing"

mock_curl_dir="$TEST_ROOT/bin/mock_curl_dir"
cat <<'EOF' > "$mock_curl_dir"
#!/usr/bin/env bash
head_dest=""
probe_url="${@: -1}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$probe_url" =~ /admin/ ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n' > "$head_dest"
    exit 0
elif [[ "$probe_url" =~ /login/ ]]; then
    printf 'HTTP/1.1 302 Found\r\nLocation: /auth/login\r\nContent-Length: 0\r\n\r\n' > "$head_dest"
    exit 0
fi
exit 1
EOF
chmod +x "$mock_curl_dir"

task_dir_curl="$TEST_ROOT/targets/curl_dir_test/directory"
DIR_FFUF_BIN="none" \
DIR_CURL_BIN="$mock_curl_dir" \
module_directory_run "http://fallback.corp" "url_http" "$task_dir_curl"

if [[ -f "${task_dir_curl}/directories.txt" ]] && \
   grep -q "/admin/" "${task_dir_curl}/directories.txt" && \
   grep -q "/login/" "${task_dir_curl}/directories.txt"; then
    pass "Fallback heuristics discover web directories using native curl inspection"
else
    fail "Fallback heuristics failed to detect directories"
fi

# -----------------------------------------------------------------------------
# UT-05: Wordlist Selection Hierarchy
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Wordlist Selection Hierarchy"

custom_wl="$TEST_ROOT/custom_wordlist.txt"
printf 'custom1\ncustom2\ncustom3\n' > "$custom_wl"

task_dir_wl="$TEST_ROOT/targets/wl_test/directory"
CONFIG_EFFECTIVE_WORDLIST="$custom_wl" \
DIR_FFUF_BIN="$mock_empty" \
DIR_CURL_BIN="$mock_empty" \
module_directory_run "http://corp.local" "url_http" "$task_dir_wl"

if [[ -f "${task_dir_wl}/output.txt" ]] && \
   grep -q "Wordlist.*custom_wordlist.txt" "${task_dir_wl}/output.txt" && \
   grep -q "Wordlist Count.*3" "${task_dir_wl}/output.txt"; then
    pass "Honors explicitly configured wordlist from CONFIG_EFFECTIVE_WORDLIST"
else
    fail "Custom wordlist resolution mismatch in $task_dir_wl"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Directories Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Directories Discovered"

task_dir_dead="$TEST_ROOT/targets/dead_dir/directory"
DIR_FFUF_BIN="none" \
DIR_CURL_BIN="$mock_empty" \
module_directory_run "dead.domain" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No accessible directories identified on target." "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/directories.txt" ]]; then
    pass "Handles empty directory discovery results cleanly with exit code 0"
else
    fail "Empty directory discovery handling mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_ffuf" 2>/dev/null || stat -f '%p' "$task_dir_ffuf" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_ffuf}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/output.txt" 2>/dev/null)"
dirs_perms="$(stat -c '%a' "${task_dir_ffuf}/directories.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/directories.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$dirs_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all directory artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms dirs=$dirs_perms"
fi

test_summary
