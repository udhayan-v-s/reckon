#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Content Management System (CMS) Detection Module Unit Tests (test_mod_cms.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/cms.sh
if ! source "$PROJECT_ROOT/modules/web/cms.sh"; then
    printf 'Error: Unable to load modules/web/cms.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-cms-test.XXXXXX")" || {
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

    printf '%s\n' "CMS detection module unit tests completed."
}

printf '%s\n' "RECKON - CMS Detection Module Unit Tests"
printf '%s\n' "----------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_cms_run "example.com" "domain" 2>/dev/null; then
    fail "module_cms_run accepted fewer than 3 arguments"
else
    pass "module_cms_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_cms_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_cms_run accepted empty target"
else
    pass "module_cms_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_cms_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_cms_run accepted empty target type"
else
    pass "module_cms_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_cms_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_cms_run accepted empty task directory"
else
    pass "module_cms_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/cms"
mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

CMS_WHATWEB_BIN="$mock_empty" \
CMS_CURL_BIN="$mock_empty" \
module_cms_run "corp.local" "domain" "$task_compat_dom"
if [[ -f "${task_compat_dom}/output.txt" ]] && grep -q "CMS Detection" "${task_compat_dom}/output.txt"; then
    pass "module_cms_run accepts valid domain target"
else
    fail "module_cms_run failed on domain target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/cms"
if module_cms_run "10.0.0.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_cms_run skips multi-host CIDR block with execution notice"
    else
        fail "module_cms_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_cms_run returned error code on CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: WhatWeb CMS Engine Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: WhatWeb CMS Engine Detection"

mock_whatweb_cms="$TEST_ROOT/bin/mock_whatweb_cms"
cat <<'EOF' > "$mock_whatweb_cms"
#!/usr/bin/env bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-brief=*) out_file="${1#*=}"; shift ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    printf 'http://blog.corp.local [200 OK] WordPress[6.2.2], HTTPServer[Apache/2.4.41], Title[Company Blog]\n' > "$out_file"
fi
exit 0
EOF
chmod +x "$mock_whatweb_cms"

task_dir_ww="$TEST_ROOT/targets/ww_test/cms"
CMS_WHATWEB_BIN="$mock_whatweb_cms" \
module_cms_run "http://blog.corp.local" "url_http" "$task_dir_ww"

if [[ -f "${task_dir_ww}/cms_detected.txt" ]] && \
   grep -q -E "^WordPress"$'\t'"6.2.2"$'\t'"High" "${task_dir_ww}/cms_detected.txt"; then
    pass "WhatWeb engine extracts and writes detected CMS into cms_detected.txt"
else
    fail "WhatWeb engine failed to extract expected CMS into cms_detected.txt"
fi

if [[ -f "${task_dir_ww}/output.txt" ]] && \
   grep -q "CMS Platform.*: WordPress" "${task_dir_ww}/output.txt" && \
   grep -q "Version.*: 6.2.2" "${task_dir_ww}/output.txt"; then
    pass "Formats comprehensive summary report with CMS details"
else
    fail "Formatted output report mismatch in $task_dir_ww"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Heuristics - WordPress
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Heuristics - WordPress"

mock_curl_wp="$TEST_ROOT/bin/mock_curl_wp"
cat <<'EOF' > "$mock_curl_wp"
#!/usr/bin/env bash
head_dest=""
body_dest=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        -o) body_dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$head_dest" ]]; then
    printf 'HTTP/1.1 200 OK\r\nSet-Cookie: wp-settings-time-1=12345; path=/\r\n\r\n' > "$head_dest"
fi
if [[ -n "$body_dest" ]]; then
    printf '<html><head><link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css?ver=6.1.1" /></head><body>WordPress Site</body></html>' > "$body_dest"
fi
exit 0
EOF
chmod +x "$mock_curl_wp"

task_dir_curl_wp="$TEST_ROOT/targets/curl_wp_test/cms"
CMS_WHATWEB_BIN="none" \
CMS_CURL_BIN="$mock_curl_wp" \
module_cms_run "http://fallback.wp" "url_http" "$task_dir_curl_wp"

if [[ -f "${task_dir_curl_wp}/cms_detected.txt" ]] && \
   grep -q "WordPress" "${task_dir_curl_wp}/cms_detected.txt"; then
    pass "Fallback heuristics detect WordPress from headers and asset paths"
else
    fail "Fallback heuristics failed to detect WordPress"
fi

# -----------------------------------------------------------------------------
# UT-05: Native Curl Fallback Heuristics - Meta Generator (Drupal)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Native Curl Fallback Heuristics - Meta Generator"

mock_curl_drupal="$TEST_ROOT/bin/mock_curl_drupal"
cat <<'EOF' > "$mock_curl_drupal"
#!/usr/bin/env bash
head_dest=""
body_dest=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        -o) body_dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$head_dest" ]]; then
    printf 'HTTP/1.1 200 OK\r\nX-Generator: Drupal 9\r\n\r\n' > "$head_dest"
fi
if [[ -n "$body_dest" ]]; then
    printf '<html><head><meta name="generator" content="Drupal 9 (https://www.drupal.org)" /></head><body>Drupal Page</body></html>' > "$body_dest"
fi
exit 0
EOF
chmod +x "$mock_curl_drupal"

task_dir_drupal="$TEST_ROOT/targets/curl_drupal_test/cms"
CMS_WHATWEB_BIN="none" \
CMS_CURL_BIN="$mock_curl_drupal" \
module_cms_run "http://drupal.corp" "url_http" "$task_dir_drupal"

if [[ -f "${task_dir_drupal}/cms_detected.txt" ]] && \
   grep -q "Drupal" "${task_dir_drupal}/cms_detected.txt"; then
    pass "Fallback heuristics extract CMS and version from meta generator tag"
else
    fail "Fallback heuristics failed to detect Drupal from meta tag"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No CMS Detected
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No CMS Detected"

task_dir_dead="$TEST_ROOT/targets/dead_cms/cms"
CMS_WHATWEB_BIN="none" \
CMS_CURL_BIN="$mock_empty" \
module_cms_run "dead.domain" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No CMS signatures (WordPress, Drupal, Joomla, etc.) identified." "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/cms_detected.txt" ]]; then
    pass "Handles empty CMS detection results cleanly with code 0"
else
    fail "Empty CMS detection handling mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_ww" 2>/dev/null || stat -f '%p' "$task_dir_ww" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_ww}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_ww}/output.txt" 2>/dev/null)"
cms_perms="$(stat -c '%a' "${task_dir_ww}/cms_detected.txt" 2>/dev/null || stat -f '%p' "${task_dir_ww}/cms_detected.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$cms_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all CMS artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms cms=$cms_perms"
fi

test_summary
