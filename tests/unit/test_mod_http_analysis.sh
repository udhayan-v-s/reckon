#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web HTTP Security Analysis Module Unit Tests (test_mod_http_analysis.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/http-analysis.sh
if ! source "$PROJECT_ROOT/modules/web/http-analysis.sh"; then
    printf 'Error: Unable to load modules/web/http-analysis.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-http-test.XXXXXX")" || {
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

    printf '%s\n' "Web HTTP security analysis module unit tests completed."
}

printf '%s\n' "RECKON - Web HTTP Security Analysis Module Unit Tests"
printf '%s\n' "-----------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_http_analysis_run "example.com" "domain" 2>/dev/null; then
    fail "module_http_analysis_run accepted fewer than 3 arguments"
else
    pass "module_http_analysis_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_http_analysis_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_http_analysis_run accepted empty target"
else
    pass "module_http_analysis_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_http_analysis_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_http_analysis_run accepted empty target type"
else
    pass "module_http_analysis_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_http_analysis_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_http_analysis_run accepted empty task directory"
else
    pass "module_http_analysis_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/http-analysis"
if HTTP_ANALYSIS_CURL_BIN="$mock_empty" \
   module_http_analysis_run "corp.local" "domain" "$task_compat_dom"; then
    pass "module_http_analysis_run accepts valid domain target"
else
    fail "module_http_analysis_run failed for valid domain target"
fi

# Test 2: Supported IPv4 target returns 0
task_compat_ip="$TEST_ROOT/targets/ip_test/http-analysis"
if HTTP_ANALYSIS_CURL_BIN="$mock_empty" \
   module_http_analysis_run "10.0.0.1" "ipv4" "$task_compat_ip"; then
    pass "module_http_analysis_run accepts valid IPv4 target"
else
    fail "module_http_analysis_run failed for valid IPv4 target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/http-analysis"
if HTTP_ANALYSIS_CURL_BIN="$mock_empty" \
   module_http_analysis_run "10.0.0.0/8" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_http_analysis_run skips multi-host CIDR block with execution notice"
    else
        fail "module_http_analysis_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_http_analysis_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: Security Headers Inspection & Evaluation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Security Headers Inspection & Evaluation"

mock_curl_headers="$TEST_ROOT/bin/mock_curl_headers"
cat <<'EOF' > "$mock_curl_headers"
#!/usr/bin/env bash
req_origin=""
method="GET"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -H)
            if [[ "$2" =~ ^Origin:[[:space:]]*(.*) ]]; then
                req_origin="${BASH_REMATCH[1]}"
            fi
            shift 2
            ;;
        -X) method="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$method" == "OPTIONS" ]]; then
    printf 'HTTP/1.1 200 OK\r\nAllow: GET, POST, OPTIONS, HEAD\r\n\r\n'
    exit 0
fi

if [[ -n "$req_origin" ]]; then
    printf 'HTTP/1.1 200 OK\r\n'
    printf 'Access-Control-Allow-Origin: %s\r\n' "$req_origin"
    printf 'Access-Control-Allow-Credentials: true\r\n\r\n'
    exit 0
fi

cat <<'HDR_EOF'
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Server: Apache/2.4.51 (Debian)
X-Powered-By: PHP/8.1.2

HDR_EOF
exit 0
EOF
chmod +x "$mock_curl_headers"

task_dir_sec="$TEST_ROOT/targets/sec_test/http-analysis"
HTTP_ANALYSIS_CURL_BIN="$mock_curl_headers" \
module_http_analysis_run "https://sec.corp" "url_https" "$task_dir_sec"

if [[ -f "${task_dir_sec}/http_analysis.txt" ]] && \
   grep -q -E "^HEADER"$'\t'"Strict-Transport-Security"$'\t'"PRESENT" "${task_dir_sec}/http_analysis.txt" && \
   grep -q -E "^HEADER"$'\t'"Content-Security-Policy"$'\t'"MISSING" "${task_dir_sec}/http_analysis.txt" && \
   grep -q -E "^DISCLOSURE"$'\t'"Server"$'\t'"Apache" "${task_dir_sec}/http_analysis.txt"; then
    pass "Audits presence and absence of security headers and logs information disclosure"
else
    fail "Security header evaluation mismatch in http_analysis.txt"
fi

if [[ -f "${task_dir_sec}/output.txt" ]] && \
   grep -q "Present Headers.*3" "${task_dir_sec}/output.txt" && \
   grep -q "Strict-Transport-Security:" "${task_dir_sec}/output.txt"; then
    pass "Formats comprehensive summary report with header counts"
else
    fail "Formatted output report mismatch in $task_dir_sec"
fi

# -----------------------------------------------------------------------------
# UT-04: CORS Misconfiguration Testing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: CORS Misconfiguration Testing"

if grep -q -E "^CORS"$'\t'".*HIGH.*Vulnerable" "${task_dir_sec}/http_analysis.txt"; then
    pass "Detects and flags high-severity arbitrary origin reflection with credentials"
else
    fail "CORS vulnerability detection failed"
fi

# -----------------------------------------------------------------------------
# UT-05: HTTP Methods & Verbs Testing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: HTTP Methods & Verbs Testing"

if grep -q "METHOD" "${task_dir_sec}/http_analysis.txt" && \
   grep -q "Advertised Methods (Allow).*GET, POST, OPTIONS, HEAD" "${task_dir_sec}/output.txt"; then
    pass "Extracts advertised HTTP methods and logs verb status"
else
    fail "HTTP methods audit failed"
fi

# -----------------------------------------------------------------------------
# UT-06: Clean Inactive State
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Clean Inactive State"

task_dir_empty="$TEST_ROOT/targets/empty_test/http-analysis"
HTTP_ANALYSIS_CURL_BIN="$mock_empty" \
module_http_analysis_run "empty.org" "domain" "$task_dir_empty"

if [[ -f "${task_dir_empty}/http_analysis.txt" ]] && \
   grep -q "Audit complete" "${task_dir_empty}/output.txt"; then
    pass "Handles empty server response cleanly with exit code 0"
else
    fail "Clean empty state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_sec" 2>/dev/null || stat -f '%p' "$task_dir_sec" 2>/dev/null)"
analysis_perm="$(stat -c '%a' "${task_dir_sec}/http_analysis.txt" 2>/dev/null || stat -f '%p' "${task_dir_sec}/http_analysis.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_sec}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_sec}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
analysis_perm="${analysis_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$analysis_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all http-analysis artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, analysis=$analysis_perm, output=$out_perm"
fi

test_summary
