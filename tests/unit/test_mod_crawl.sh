#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Spidering and Link Crawling Module Unit Tests (test_mod_crawl.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/crawl.sh
if ! source "$PROJECT_ROOT/modules/web/crawl.sh"; then
    printf 'Error: Unable to load modules/web/crawl.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-crawl-test.XXXXXX")" || {
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

    printf '%s\n' "Web spidering and crawling module unit tests completed."
}

printf '%s\n' "RECKON - Web Spidering and Link Crawling Module Unit Tests"
printf '%s\n' "----------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_crawl_run "example.com" "domain" 2>/dev/null; then
    fail "module_crawl_run accepted fewer than 3 arguments"
else
    pass "module_crawl_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_crawl_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_crawl_run accepted empty target"
else
    pass "module_crawl_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_crawl_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_crawl_run accepted empty target type"
else
    pass "module_crawl_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_crawl_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_crawl_run accepted empty task directory"
else
    pass "module_crawl_run rejects empty task directory"
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
task_compat_dom="$TEST_ROOT/targets/dom_test/crawl"
if CRAWL_KATANA_BIN="$mock_empty" CRAWL_CURL_BIN="$mock_empty" \
   module_crawl_run "corp.local" "domain" "$task_compat_dom"; then
    pass "module_crawl_run accepts valid domain target"
else
    fail "module_crawl_run failed for valid domain target"
fi

# Test 2: Supported URL target returns 0
task_compat_url="$TEST_ROOT/targets/url_test/crawl"
if CRAWL_KATANA_BIN="$mock_empty" CRAWL_CURL_BIN="$mock_empty" \
   module_crawl_run "http://corp.local" "url_http" "$task_compat_url"; then
    pass "module_crawl_run accepts valid URL target"
else
    fail "module_crawl_run failed for valid URL target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/crawl"
if CRAWL_KATANA_BIN="$mock_empty" CRAWL_CURL_BIN="$mock_empty" \
   module_crawl_run "172.16.0.0/16" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_crawl_run skips multi-host CIDR block with execution notice"
    else
        fail "module_crawl_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_crawl_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: Katana Primary Engine Web Crawling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Katana Primary Engine Web Crawling"

mock_katana="$TEST_ROOT/bin/mock_katana"
cat <<'EOF' > "$mock_katana"
#!/usr/bin/env bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    cat <<'KATANA_EOF' > "$out_file"
http://corp.local/
http://corp.local/about
http://corp.local/products
http://corp.local/assets/app.js
http://corp.local/assets/style.css
https://sub.corp.local/portal
KATANA_EOF
fi
exit 0
EOF
chmod +x "$mock_katana"

task_dir_katana="$TEST_ROOT/targets/katana_test/crawl"
CRAWL_KATANA_BIN="$mock_katana" \
CRAWL_CURL_BIN="$mock_empty" \
module_crawl_run "corp.local" "domain" "$task_dir_katana"

if [[ -f "${task_dir_katana}/crawled_urls.txt" ]] && \
   grep -q "http://corp.local/about" "${task_dir_katana}/crawled_urls.txt" && \
   grep -q "http://corp.local/assets/app.js" "${task_dir_katana}/crawled_urls.txt" && \
   grep -q "https://sub.corp.local/portal" "${task_dir_katana}/crawled_urls.txt"; then
    pass "Katana engine extracts and writes discovered URLs into crawled_urls.txt"
else
    fail "Katana engine failed to write expected URLs into crawled_urls.txt"
fi

if [[ -f "${task_dir_katana}/output.txt" ]] && \
   grep -q "Total URLs Crawled.*6" "${task_dir_katana}/output.txt" && \
   grep -q "JavaScript Bundles.*1" "${task_dir_katana}/output.txt"; then
    pass "Formats comprehensive summary report with page and script counts"
else
    fail "Formatted output report mismatch in $task_dir_katana"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback HTML Link Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback HTML Link Extraction"

mock_curl_crawl="$TEST_ROOT/bin/mock_curl_crawl"
cat <<'EOF' > "$mock_curl_crawl"
#!/usr/bin/env bash
req_url="${@: -1}"
cat <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <link rel="stylesheet" href="/css/site.css">
    <script src="/js/bundle.js"></script>
</head>
<body>
    <a href="/login">Sign In</a>
    <a href="docs/api.html">API Docs</a>
    <a href="http://fallback.corp/pricing">Pricing</a>
    <a href="https://external-tracker.com/pixel">Out of scope</a>
    <form action="/auth/submit" method="POST"></form>
</body>
</html>
HTML_EOF
exit 0
EOF
chmod +x "$mock_curl_crawl"

task_dir_curl="$TEST_ROOT/targets/curl_crawl_test/crawl"
CRAWL_KATANA_BIN="none" \
CRAWL_CURL_BIN="$mock_curl_crawl" \
module_crawl_run "http://fallback.corp" "url_http" "$task_dir_curl"

if [[ -f "${task_dir_curl}/crawled_urls.txt" ]] && \
   grep -q "http://fallback.corp/login" "${task_dir_curl}/crawled_urls.txt" && \
   grep -q "http://fallback.corp/js/bundle.js" "${task_dir_curl}/crawled_urls.txt" && \
   grep -q "http://fallback.corp/auth/submit" "${task_dir_curl}/crawled_urls.txt"; then
    pass "Fallback heuristics parse HTML attributes and normalize relative links"
else
    fail "Fallback heuristics failed to extract and normalize HTML links"
fi

# -----------------------------------------------------------------------------
# UT-05: Domain Scope Boundary Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Domain Scope Boundary Enforcement"

if grep -q "external-tracker.com" "${task_dir_curl}/crawled_urls.txt"; then
    fail "Out-of-scope third-party link was included in crawled_urls.txt"
else
    pass "Filters out out-of-scope external URLs from crawled results"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Crawled URLs
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Crawled URLs"

task_dir_empty="$TEST_ROOT/targets/empty_test/crawl"
CRAWL_KATANA_BIN="$mock_empty" \
CRAWL_CURL_BIN="$mock_empty" \
module_crawl_run "empty.org" "domain" "$task_dir_empty"

if [[ -f "${task_dir_empty}/crawled_urls.txt" ]] && [[ ! -s "${task_dir_empty}/crawled_urls.txt" ]] && \
   grep -q "No web links discovered" "${task_dir_empty}/output.txt"; then
    pass "Handles empty crawl results cleanly with exit code 0"
else
    fail "Clean empty crawl state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_katana" 2>/dev/null || stat -f '%p' "$task_dir_katana" 2>/dev/null)"
crawl_perm="$(stat -c '%a' "${task_dir_katana}/crawled_urls.txt" 2>/dev/null || stat -f '%p' "${task_dir_katana}/crawled_urls.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_katana}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_katana}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
crawl_perm="${crawl_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$crawl_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all crawl artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, crawl=$crawl_perm, output=$out_perm"
fi

test_summary
