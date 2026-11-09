#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Application Firewall (WAF) Detection Module Unit Tests (test_mod_waf.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/waf.sh
if ! source "$PROJECT_ROOT/modules/web/waf.sh"; then
    printf 'Error: Unable to load modules/web/waf.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-waf-test.XXXXXX")" || {
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

    printf '%s\n' "WAF detection module unit tests completed."
}

printf '%s\n' "RECKON - WAF Detection Module Unit Tests"
printf '%s\n' "----------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_waf_run "example.com" "domain" 2>/dev/null; then
    fail "module_waf_run accepted fewer than 3 arguments"
else
    pass "module_waf_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_waf_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_waf_run accepted empty target"
else
    pass "module_waf_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_waf_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_waf_run accepted empty target type"
else
    pass "module_waf_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_waf_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_waf_run accepted empty task directory"
else
    pass "module_waf_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/waf"
mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

WAF_WAFW00F_BIN="$mock_empty" \
WAF_CURL_BIN="$mock_empty" \
module_waf_run "corp.local" "domain" "$task_compat_dom"
if [[ -f "${task_compat_dom}/output.txt" ]] && grep -q "WAF Detection" "${task_compat_dom}/output.txt"; then
    pass "module_waf_run accepts valid domain target"
else
    fail "module_waf_run failed on domain target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/waf"
if module_waf_run "10.0.0.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_waf_run skips multi-host CIDR block with execution notice"
    else
        fail "module_waf_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_waf_run returned error code on CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: WAFW00F Primary Engine Detection
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: WAFW00F Primary Engine Detection"

mock_wafw00f="$TEST_ROOT/bin/mock_wafw00f"
cat <<'EOF' > "$mock_wafw00f"
#!/usr/bin/env bash
target="${@: -1}"
printf 'Checking %s\n' "$target"
printf '[+] The site %s is behind Cloudflare (Cloudflare Inc.) WAF.\n' "$target"
exit 0
EOF
chmod +x "$mock_wafw00f"

task_dir_wafw00f="$TEST_ROOT/targets/wafw00f_test/waf"
WAF_WAFW00F_BIN="$mock_wafw00f" \
module_waf_run "http://corp.local" "url_http" "$task_dir_wafw00f"

if [[ -f "${task_dir_wafw00f}/waf_detected.txt" ]] && \
   grep -q -E "^Cloudflare"$'\t'"Cloudflare Inc."$'\t'"Active" "${task_dir_wafw00f}/waf_detected.txt"; then
    pass "WAFW00F engine extracts and writes detected WAF into waf_detected.txt"
else
    fail "WAFW00F engine failed to extract expected WAF into waf_detected.txt"
fi

if [[ -f "${task_dir_wafw00f}/output.txt" ]] && \
   grep -q "WAF Platform.*: Cloudflare" "${task_dir_wafw00f}/output.txt" && \
   grep -q "Vendor.*: Cloudflare Inc." "${task_dir_wafw00f}/output.txt"; then
    pass "Formats comprehensive summary report with WAF details"
else
    fail "Formatted output report mismatch in $task_dir_wafw00f"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Heuristics - Cloudflare & AWS WAF
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Heuristics - Cloudflare"

mock_curl_cf="$TEST_ROOT/bin/mock_curl_cf"
cat <<'EOF' > "$mock_curl_cf"
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
    printf 'HTTP/1.1 200 OK\r\nServer: cloudflare\r\ncf-ray: 7d123456789-IAD\r\n\r\n' > "$head_dest"
fi
if [[ -n "$body_dest" ]]; then
    printf '<html><body>Protected by Cloudflare</body></html>' > "$body_dest"
fi
exit 0
EOF
chmod +x "$mock_curl_cf"

task_dir_curl_cf="$TEST_ROOT/targets/curl_cf_test/waf"
WAF_WAFW00F_BIN="none" \
WAF_CURL_BIN="$mock_curl_cf" \
module_waf_run "http://fallback.cf" "url_http" "$task_dir_curl_cf"

if [[ -f "${task_dir_curl_cf}/waf_detected.txt" ]] && \
   grep -q "Cloudflare" "${task_dir_curl_cf}/waf_detected.txt"; then
    pass "Fallback heuristics detect Cloudflare from server banner and cf-ray header"
else
    fail "Fallback heuristics failed to detect Cloudflare"
fi

# -----------------------------------------------------------------------------
# UT-05: Native Curl Fallback Heuristics - Akamai
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Native Curl Fallback Heuristics - Akamai"

mock_curl_akamai="$TEST_ROOT/bin/mock_curl_akamai"
cat <<'EOF' > "$mock_curl_akamai"
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
    printf 'HTTP/1.1 200 OK\r\nServer: AkamaiGHost\r\nX-Akamai-Transformed: 9 1000 0 pmb=mRUM,1\r\n\r\n' > "$head_dest"
fi
if [[ -n "$body_dest" ]]; then
    printf '<html><body>Akamai Edge Server</body></html>' > "$body_dest"
fi
exit 0
EOF
chmod +x "$mock_curl_akamai"

task_dir_akamai="$TEST_ROOT/targets/curl_akamai_test/waf"
WAF_WAFW00F_BIN="none" \
WAF_CURL_BIN="$mock_curl_akamai" \
module_waf_run "http://akamai.corp" "url_http" "$task_dir_akamai"

if [[ -f "${task_dir_akamai}/waf_detected.txt" ]] && \
   grep -q "Akamai" "${task_dir_akamai}/waf_detected.txt"; then
    pass "Fallback heuristics detect Akamai from AkamaiGHost header"
else
    fail "Fallback heuristics failed to detect Akamai"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No WAF Detected
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No WAF Detected"

task_dir_dead="$TEST_ROOT/targets/dead_waf/waf"
WAF_WAFW00F_BIN="none" \
WAF_CURL_BIN="$mock_empty" \
module_waf_run "dead.domain" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No Web Application Firewall (WAF) detected on target." "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/waf_detected.txt" ]]; then
    pass "Handles empty WAF detection results cleanly with code 0"
else
    fail "Empty WAF detection handling mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_wafw00f" 2>/dev/null || stat -f '%p' "$task_dir_wafw00f" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_wafw00f}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_wafw00f}/output.txt" 2>/dev/null)"
waf_perms="$(stat -c '%a' "${task_dir_wafw00f}/waf_detected.txt" 2>/dev/null || stat -f '%p' "${task_dir_wafw00f}/waf_detected.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$waf_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all WAF artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms waf=$waf_perms"
fi

test_summary
