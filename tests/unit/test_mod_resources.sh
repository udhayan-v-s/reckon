#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Resource Discovery Module Unit Tests (test_mod_resources.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/resources.sh
if ! source "$PROJECT_ROOT/modules/web/resources.sh"; then
    printf 'Error: Unable to load modules/web/resources.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-res-test.XXXXXX")" || {
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

    printf '%s\n' "Web resource discovery module unit tests completed."
}

printf '%s\n' "RECKON - Web Resource Discovery Module Unit Tests"
printf '%s\n' "-------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_resources_run "example.com" "domain" 2>/dev/null; then
    fail "module_resources_run accepted fewer than 3 arguments"
else
    pass "module_resources_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_resources_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_resources_run accepted empty target"
else
    pass "module_resources_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_resources_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_resources_run accepted empty target type"
else
    pass "module_resources_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_resources_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_resources_run accepted empty task directory"
else
    pass "module_resources_run rejects empty task directory"
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
task_compat_dom="$TEST_ROOT/targets/dom_test/resources"
if RESOURCES_CURL_BIN="$mock_empty" \
   module_resources_run "corp.local" "domain" "$task_compat_dom"; then
    pass "module_resources_run accepts valid domain target"
else
    fail "module_resources_run failed for valid domain target"
fi

# Test 2: Supported URL target returns 0
task_compat_url="$TEST_ROOT/targets/url_test/resources"
if RESOURCES_CURL_BIN="$mock_empty" \
   module_resources_run "https://corp.local" "url_https" "$task_compat_url"; then
    pass "module_resources_run accepts valid URL target"
else
    fail "module_resources_run failed for valid URL target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/resources"
if RESOURCES_CURL_BIN="$mock_empty" \
   module_resources_run "10.0.0.0/24" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_resources_run skips multi-host CIDR block with execution notice"
    else
        fail "module_resources_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_resources_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: Robots.txt & Sitemap.xml Discovery
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Robots.txt & Sitemap.xml Discovery"

mock_curl_res="$TEST_ROOT/bin/mock_curl_res"
cat <<'EOF' > "$mock_curl_res"
#!/usr/bin/env bash
dest=""
w_flag=""
req_url="${@: -1}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) dest="$2"; shift 2 ;;
        -w) w_flag="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$req_url" =~ /robots\.txt ]]; then
    cat <<'ROBOTS_EOF' > "$dest"
User-agent: *
Disallow: /admin/
Disallow: /api/private/
Sitemap: https://corp.local/sitemap.xml
ROBOTS_EOF
    printf '200'
    exit 0
elif [[ "$req_url" =~ /sitemap\.xml ]]; then
    cat <<'SITEMAP_EOF' > "$dest"
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://corp.local/</loc></url>
  <url><loc>https://corp.local/products</loc></url>
  <url><loc>https://corp.local/about</loc></url>
</urlset>
SITEMAP_EOF
    printf '200'
    exit 0
elif [[ "$req_url" =~ /security\.txt ]]; then
    cat <<'SEC_EOF' > "$dest"
Contact: mailto:security@corp.local
Expires: 2027-01-01T00:00:00.000Z
SEC_EOF
    printf '200'
    exit 0
elif [[ "$req_url" =~ /openid-configuration ]]; then
    printf '{"issuer":"https://corp.local"}' > "$dest"
    printf '200'
    exit 0
elif [[ "$req_url" =~ /favicon\.ico ]]; then
    printf 'MOCK_FAVICON_DATA' > "$dest"
    printf '200'
    exit 0
fi

printf '404'
exit 0
EOF
chmod +x "$mock_curl_res"

task_dir_res="$TEST_ROOT/targets/res_test/resources"
RESOURCES_CURL_BIN="$mock_curl_res" \
module_resources_run "https://corp.local" "url_https" "$task_dir_res"

if [[ -f "${task_dir_res}/resources.txt" ]] && \
   grep -q "/robots.txt"$'\t'"200" "${task_dir_res}/resources.txt" && \
   grep -q "/sitemap.xml"$'\t'"200" "${task_dir_res}/resources.txt"; then
    pass "Inspects robots.txt and sitemap.xml and records in resources.txt"
else
    fail "robots.txt or sitemap.xml inspection mismatch"
fi

if [[ -f "${task_dir_res}/output.txt" ]] && \
   grep -q "robots.txt Disallow Rules" "${task_dir_res}/output.txt" && \
   grep -q "/admin/" "${task_dir_res}/output.txt"; then
    pass "Formats comprehensive summary report with parsed disallow directives"
else
    fail "Summary report disallow directives mismatch"
fi

# -----------------------------------------------------------------------------
# UT-04: Security.txt & OpenID Configuration Discovery
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Security.txt & OpenID Configuration Discovery"

if grep -q "security.txt"$'\t'"200" "${task_dir_res}/resources.txt" && \
   grep -q "/openid-configuration"$'\t'"200" "${task_dir_res}/resources.txt"; then
    pass "Identifies security.txt and OpenID configuration endpoints"
else
    fail "security.txt or openid-configuration discovery mismatch"
fi

# -----------------------------------------------------------------------------
# UT-05: Favicon Hashing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Favicon Hashing"

if grep -q "favicon.ico"$'\t'"200" "${task_dir_res}/resources.txt" && \
   grep -q "Favicon Cryptographic Hashes" "${task_dir_res}/output.txt" && \
   grep -q "MD5 Hash" "${task_dir_res}/output.txt"; then
    pass "Fetches favicon.ico and computes cryptographic hash for OSINT"
else
    fail "Favicon hashing inspection failed"
fi

# -----------------------------------------------------------------------------
# UT-06: Clean Inactive State
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Clean Inactive State"

mock_curl_404="$TEST_ROOT/bin/mock_curl_404"
cat <<'EOF' > "$mock_curl_404"
#!/usr/bin/env bash
printf '404'
exit 0
EOF
chmod +x "$mock_curl_404"

task_dir_empty="$TEST_ROOT/targets/empty_test/resources"
RESOURCES_CURL_BIN="$mock_curl_404" \
module_resources_run "https://empty.org" "url_https" "$task_dir_empty"

if [[ -f "${task_dir_empty}/resources.txt" ]] && \
   grep -q "No standard web metadata resources discovered" "${task_dir_empty}/output.txt"; then
    pass "Handles all 404 metadata responses cleanly with exit code 0"
else
    fail "Clean inactive state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_res" 2>/dev/null || stat -f '%p' "$task_dir_res" 2>/dev/null)"
res_perm="$(stat -c '%a' "${task_dir_res}/resources.txt" 2>/dev/null || stat -f '%p' "${task_dir_res}/resources.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_res}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_res}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
res_perm="${res_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$res_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all resource artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, res=$res_perm, output=$out_perm"
fi

test_summary
