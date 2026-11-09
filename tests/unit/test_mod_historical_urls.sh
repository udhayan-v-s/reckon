#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Historical URL Discovery Module Unit Tests (test_mod_historical_urls.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/historical-urls.sh
if ! source "$PROJECT_ROOT/modules/web/historical-urls.sh"; then
    printf 'Error: Unable to load modules/web/historical-urls.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-hist-test.XXXXXX")" || {
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

    printf '%s\n' "Web historical URL discovery module unit tests completed."
}

printf '%s\n' "RECKON - Web Historical URL Discovery Module Unit Tests"
printf '%s\n' "-------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_historical_urls_run "example.com" "domain" 2>/dev/null; then
    fail "module_historical_urls_run accepted fewer than 3 arguments"
else
    pass "module_historical_urls_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_historical_urls_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_historical_urls_run accepted empty target"
else
    pass "module_historical_urls_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_historical_urls_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_historical_urls_run accepted empty target type"
else
    pass "module_historical_urls_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_historical_urls_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_historical_urls_run accepted empty task directory"
else
    pass "module_historical_urls_run rejects empty task directory"
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
task_compat_dom="$TEST_ROOT/targets/dom_test/historical-urls"
if HISTORICAL_GAU_BIN="$mock_empty" HISTORICAL_CURL_BIN="$mock_empty" \
   module_historical_urls_run "archive.local" "domain" "$task_compat_dom"; then
    pass "module_historical_urls_run accepts valid domain target"
else
    fail "module_historical_urls_run failed for valid domain target"
fi

# Test 2: Supported hostname target returns 0
task_compat_host="$TEST_ROOT/targets/host_test/historical-urls"
if HISTORICAL_GAU_BIN="$mock_empty" HISTORICAL_CURL_BIN="$mock_empty" \
   module_historical_urls_run "web.archive.local" "hostname" "$task_compat_host"; then
    pass "module_historical_urls_run accepts valid hostname target"
else
    fail "module_historical_urls_run failed for valid hostname target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/historical-urls"
if HISTORICAL_GAU_BIN="$mock_empty" HISTORICAL_CURL_BIN="$mock_empty" \
   module_historical_urls_run "10.0.0.0/24" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_historical_urls_run skips multi-host CIDR block with execution notice"
    else
        fail "module_historical_urls_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_historical_urls_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: GAU Primary Engine Historical URL Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: GAU Primary Engine Historical URL Extraction"

mock_gau="$TEST_ROOT/bin/mock_gau"
cat <<'EOF' > "$mock_gau"
#!/usr/bin/env bash
target="${@: -1}"
cat <<URL_EOF
https://${target}/index.php
https://${target}/login?redirect=admin
https://${target}/api/v1/users?id=123
https://${target}/backup/database.sql
https://${target}/config.json
https://sub.${target}/docs/readme.txt
https://external-domain.com/unrelated
URL_EOF
exit 0
EOF
chmod +x "$mock_gau"

task_dir_gau="$TEST_ROOT/targets/gau_test/historical-urls"
HISTORICAL_GAU_BIN="$mock_gau" \
HISTORICAL_CURL_BIN="$mock_empty" \
module_historical_urls_run "corp.local" "domain" "$task_dir_gau"

if [[ -f "${task_dir_gau}/historical_urls.txt" ]] && \
   grep -q "https://corp.local/index.php" "${task_dir_gau}/historical_urls.txt" && \
   grep -q "https://corp.local/backup/database.sql" "${task_dir_gau}/historical_urls.txt" && \
   grep -q "https://sub.corp.local/docs/readme.txt" "${task_dir_gau}/historical_urls.txt"; then
    pass "GAU engine extracts and populates in-scope URLs in historical_urls.txt"
else
    fail "GAU engine failed to write expected URLs into historical_urls.txt"
fi

if [[ -f "${task_dir_gau}/output.txt" ]] && \
   grep -q "Total URLs Discovered.*6" "${task_dir_gau}/output.txt" && \
   grep -q "URLs with Parameters.*2" "${task_dir_gau}/output.txt" && \
   grep -q "Sensitive Files Detected.*4" "${task_dir_gau}/output.txt"; then
    pass "Formats comprehensive summary report with parameter and sensitivity statistics"
else
    fail "Formatted output report mismatch in $task_dir_gau"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Public Web Archive Querying
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Public Web Archive Querying"

mock_curl_hist="$TEST_ROOT/bin/mock_curl_hist"
cat <<'EOF' > "$mock_curl_hist"
#!/usr/bin/env bash
query_url="${@: -1}"
if [[ "$query_url" =~ web\.archive\.org ]]; then
    cat <<'WB_EOF'
https://fallback.org/old-page.html
https://fallback.org/secret.conf
https://fallback.org/admin/portal.php?u=admin
WB_EOF
    exit 0
elif [[ "$query_url" =~ alienvault\.com ]]; then
    cat <<'OTX_EOF'
{
  "url_list": [
    {"url": "https://fallback.org/api/legacy.json"},
    {"url": "https://dev.fallback.org/test.html"}
  ]
}
OTX_EOF
    exit 0
fi
exit 1
EOF
chmod +x "$mock_curl_hist"

task_dir_curl="$TEST_ROOT/targets/curl_hist_test/historical-urls"
HISTORICAL_GAU_BIN="none" \
HISTORICAL_CURL_BIN="$mock_curl_hist" \
module_historical_urls_run "fallback.org" "domain" "$task_dir_curl"

if [[ -f "${task_dir_curl}/historical_urls.txt" ]] && \
   grep -q "https://fallback.org/secret.conf" "${task_dir_curl}/historical_urls.txt" && \
   grep -q "https://fallback.org/api/legacy.json" "${task_dir_curl}/historical_urls.txt" && \
   grep -q "https://dev.fallback.org/test.html" "${task_dir_curl}/historical_urls.txt"; then
    pass "Fallback heuristics extract historical URLs from Wayback and AlienVault APIs"
else
    fail "Fallback heuristics failed to extract archive URLs"
fi

# -----------------------------------------------------------------------------
# UT-05: Domain Filtering & Sanitization
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Domain Filtering & Sanitization"

if grep -q "external-domain.com" "${task_dir_gau}/historical_urls.txt"; then
    fail "Out-of-scope third-party URL was not filtered from historical_urls.txt"
else
    pass "Filters out out-of-scope third-party URLs from discovered archive findings"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Historical URLs Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Historical URLs Discovered"

task_dir_empty="$TEST_ROOT/targets/empty_test/historical-urls"
HISTORICAL_GAU_BIN="$mock_empty" \
HISTORICAL_CURL_BIN="$mock_empty" \
module_historical_urls_run "empty.org" "domain" "$task_dir_empty"

if [[ -f "${task_dir_empty}/historical_urls.txt" ]] && [[ ! -s "${task_dir_empty}/historical_urls.txt" ]] && \
   grep -q "No historical URLs discovered" "${task_dir_empty}/output.txt"; then
    pass "Handles empty historical URL discovery results cleanly with exit code 0"
else
    fail "Clean empty historical URL discovery state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_gau" 2>/dev/null || stat -f '%p' "$task_dir_gau" 2>/dev/null)"
hist_perm="$(stat -c '%a' "${task_dir_gau}/historical_urls.txt" 2>/dev/null || stat -f '%p' "${task_dir_gau}/historical_urls.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_gau}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_gau}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
hist_perm="${hist_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$hist_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all historical URL artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, hist=$hist_perm, output=$out_perm"
fi

test_summary
