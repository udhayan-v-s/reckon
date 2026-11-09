#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web File Enumeration Module Unit Tests (test_mod_file.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/file.sh
if ! source "$PROJECT_ROOT/modules/web/file.sh"; then
    printf 'Error: Unable to load modules/web/file.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-file-test.XXXXXX")" || {
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

    printf '%s\n' "Web file enumeration module unit tests completed."
}

printf '%s\n' "RECKON - Web File Enumeration Module Unit Tests"
printf '%s\n' "-----------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_file_run "example.com" "domain" 2>/dev/null; then
    fail "module_file_run accepted fewer than 3 arguments"
else
    pass "module_file_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_file_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_file_run accepted empty target"
else
    pass "module_file_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_file_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_file_run accepted empty target type"
else
    pass "module_file_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_file_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_file_run accepted empty task directory"
else
    pass "module_file_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/file"
mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

FILE_FFUF_BIN="$mock_empty" \
FILE_CURL_BIN="$mock_empty" \
module_file_run "corp.local" "domain" "$task_compat_dom"
if [[ -f "${task_compat_dom}/output.txt" ]] && grep -q "File Enumeration" "${task_compat_dom}/output.txt"; then
    pass "module_file_run accepts valid domain target"
else
    fail "module_file_run failed on domain target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/file"
if module_file_run "10.0.0.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_file_run skips multi-host CIDR block with execution notice"
    else
        fail "module_file_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_file_run returned error code on CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: FFUF Primary Engine File Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: FFUF Primary Engine File Fuzzing"

mock_ffuf_file="$TEST_ROOT/bin/mock_ffuf_file"
cat <<'EOF' > "$mock_ffuf_file"
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
      "input": {"FUZZ": ".env"},
      "status": 200,
      "length": 340,
      "url": "http://corp.local/.env"
    },
    {
      "input": {"FUZZ": "wp-config.php.bak"},
      "status": 200,
      "length": 1520,
      "url": "http://corp.local/wp-config.php.bak"
    },
    {
      "input": {"FUZZ": "robots.txt"},
      "status": 200,
      "length": 120,
      "url": "http://corp.local/robots.txt"
    }
  ]
}
JSON_EOF
fi
exit 0
EOF
chmod +x "$mock_ffuf_file"

task_dir_ffuf="$TEST_ROOT/targets/ffuf_file_test/file"
FILE_FFUF_BIN="$mock_ffuf_file" \
module_file_run "http://corp.local" "url_http" "$task_dir_ffuf"

if [[ -f "${task_dir_ffuf}/files.txt" ]] && \
   grep -q -E "^/.env"$'\t'"200"$'\t'"340" "${task_dir_ffuf}/files.txt" && \
   grep -q -E "^/wp-config.php.bak"$'\t'"200" "${task_dir_ffuf}/files.txt" && \
   grep -q "CRITICAL" "${task_dir_ffuf}/files.txt"; then
    pass "FFUF engine extracts and classifies accessible files into files.txt"
else
    fail "FFUF engine failed to write expected files into files.txt"
fi

if [[ -f "${task_dir_ffuf}/output.txt" ]] && \
   grep -q "Total Discovered.*3" "${task_dir_ffuf}/output.txt" && \
   grep -q "/.env \[HTTP 200\]" "${task_dir_ffuf}/output.txt"; then
    pass "Formats comprehensive summary report with file classifications"
else
    fail "Formatted output report mismatch in $task_dir_ffuf"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Fuzzing"

mock_curl_file="$TEST_ROOT/bin/mock_curl_file"
cat <<'EOF' > "$mock_curl_file"
#!/usr/bin/env bash
head_dest=""
probe_url="${@: -1}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$probe_url" =~ /\.git/HEAD ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 45\r\n\r\n' > "$head_dest"
    exit 0
elif [[ "$probe_url" =~ /database\.sql ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 50420\r\n\r\n' > "$head_dest"
    exit 0
fi
exit 1
EOF
chmod +x "$mock_curl_file"

task_dir_curl="$TEST_ROOT/targets/curl_file_test/file"
FILE_FFUF_BIN="none" \
FILE_CURL_BIN="$mock_curl_file" \
module_file_run "http://fallback.corp" "url_http" "$task_dir_curl"

if [[ -f "${task_dir_curl}/files.txt" ]] && \
   grep -q "/.git/HEAD" "${task_dir_curl}/files.txt" && \
   grep -q "/database.sql" "${task_dir_curl}/files.txt"; then
    pass "Fallback heuristics discover sensitive files using native curl inspection"
else
    fail "Fallback heuristics failed to detect sensitive files"
fi

# -----------------------------------------------------------------------------
# UT-05: Wordlist Selection Hierarchy
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Wordlist Selection Hierarchy"

custom_wl="$TEST_ROOT/custom_files.txt"
printf 'file1.txt\nfile2.bak\nfile3.json\n' > "$custom_wl"

task_dir_wl="$TEST_ROOT/targets/wl_test/file"
CONFIG_EFFECTIVE_WORDLIST="$custom_wl" \
FILE_FFUF_BIN="$mock_empty" \
FILE_CURL_BIN="$mock_empty" \
module_file_run "http://corp.local" "url_http" "$task_dir_wl"

if [[ -f "${task_dir_wl}/output.txt" ]] && \
   grep -q "Wordlist.*custom_files.txt" "${task_dir_wl}/output.txt" && \
   grep -q "Wordlist Count.*3" "${task_dir_wl}/output.txt"; then
    pass "Honors explicitly configured wordlist from CONFIG_EFFECTIVE_WORDLIST"
else
    fail "Custom wordlist resolution mismatch in $task_dir_wl"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Files Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Files Discovered"

task_dir_dead="$TEST_ROOT/targets/dead_file/file"
FILE_FFUF_BIN="none" \
FILE_CURL_BIN="$mock_empty" \
module_file_run "dead.domain" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No accessible files or sensitive extensions discovered." "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/files.txt" ]]; then
    pass "Handles empty file discovery results cleanly with exit code 0"
else
    fail "Empty file discovery handling mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_ffuf" 2>/dev/null || stat -f '%p' "$task_dir_ffuf" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_ffuf}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/output.txt" 2>/dev/null)"
files_perms="$(stat -c '%a' "${task_dir_ffuf}/files.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/files.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$files_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all file enumeration artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms files=$files_perms"
fi

test_summary
