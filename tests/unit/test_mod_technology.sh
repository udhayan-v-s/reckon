#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Technology Fingerprinting Module Unit Tests (test_mod_technology.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/technology.sh
if ! source "$PROJECT_ROOT/modules/web/technology.sh"; then
    printf 'Error: Unable to load modules/web/technology.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-tech-test.XXXXXX")" || {
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

    printf '%s\n' "Web technology fingerprinting module unit tests completed."
}

printf '%s\n' "RECKON - Web Technology Fingerprinting Module Unit Tests"
printf '%s\n' "--------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_technology_run "example.com" "domain" 2>/dev/null; then
    fail "module_technology_run accepted fewer than 3 arguments"
else
    pass "module_technology_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_technology_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_technology_run accepted empty target"
else
    pass "module_technology_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_technology_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_technology_run accepted empty target type"
else
    pass "module_technology_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_technology_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_technology_run accepted empty task directory"
else
    pass "module_technology_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/technology"
mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

TECH_WHATWEB_BIN="$mock_empty" \
TECH_CURL_BIN="$mock_empty" \
module_technology_run "corp.local" "domain" "$task_compat_dom"
if [[ -f "${task_compat_dom}/output.txt" ]] && grep -q "Technology Fingerprinting" "${task_compat_dom}/output.txt"; then
    pass "module_technology_run accepts valid domain target"
else
    fail "module_technology_run failed on domain target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/technology"
if module_technology_run "10.0.0.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_technology_run skips multi-host CIDR block with execution notice"
    else
        fail "module_technology_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_technology_run returned error code on CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: WhatWeb Primary Engine Fingerprinting
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: WhatWeb Primary Engine Fingerprinting"

mock_whatweb="$TEST_ROOT/bin/mock_whatweb"
cat <<'EOF' > "$mock_whatweb"
#!/usr/bin/env bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-brief=*)
            out_file="${1#*=}"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -n "$out_file" ]]; then
    printf 'http://corp.local [200 OK] Apache[2.4.41], Country[US], HTTPServer[Ubuntu Linux][Apache/2.4.41], IP[10.10.1.5], PHP[7.4.3], Title[Test Portal], jQuery[3.5.1]\n' > "$out_file"
fi
exit 0
EOF
chmod +x "$mock_whatweb"

task_dir_ww="$TEST_ROOT/targets/ww_test/technology"
TECH_WHATWEB_BIN="$mock_whatweb" \
module_technology_run "http://corp.local" "url_http" "$task_dir_ww"

if [[ -f "${task_dir_ww}/technologies.txt" ]] && \
   grep -q -E "^Apache"$'\t'"2.4.41" "${task_dir_ww}/technologies.txt" && \
   grep -q -E "^PHP"$'\t'"7.4.3" "${task_dir_ww}/technologies.txt" && \
   grep -q -E "^jQuery"$'\t'"3.5.1" "${task_dir_ww}/technologies.txt"; then
    pass "WhatWeb engine extracts and normalizes stack components into technologies.txt"
else
    fail "WhatWeb engine failed to extract expected components into technologies.txt"
fi

if [[ -f "${task_dir_ww}/output.txt" ]] && \
   grep -q "Total Detected.*[3-9]" "${task_dir_ww}/output.txt" && \
   grep -q "Apache (2.4.41)" "${task_dir_ww}/output.txt"; then
    pass "Formats comprehensive summary report with detected technologies"
else
    fail "Formatted output report mismatch in $task_dir_ww"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Heuristics
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Heuristics"

mock_curl_tech="$TEST_ROOT/bin/mock_curl_tech"
cat <<'EOF' > "$mock_curl_tech"
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
    printf 'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: Express\r\n\r\n' > "$head_dest"
fi
if [[ -n "$body_dest" ]]; then
    printf '<html><head><script src="/assets/react.production.min.js"></script></head><body><div id="root">App</div></body></html>' > "$body_dest"
fi
exit 0
EOF
chmod +x "$mock_curl_tech"

task_dir_curl="$TEST_ROOT/targets/curl_tech_test/technology"
TECH_WHATWEB_BIN="non_existent" \
TECH_CURL_BIN="$mock_curl_tech" \
module_technology_run "http://fallback.corp" "url_http" "$task_dir_curl"

if [[ -f "${task_dir_curl}/technologies.txt" ]] && \
   grep -q "nginx" "${task_dir_curl}/technologies.txt" && \
   grep -q "Express.js" "${task_dir_curl}/technologies.txt" && \
   grep -q "React" "${task_dir_curl}/technologies.txt"; then
    pass "Fallback heuristics extract web server, framework, and JavaScript library"
else
    fail "Fallback heuristics failed to detect expected components"
fi

# -----------------------------------------------------------------------------
# UT-05: Upstream live_web.txt Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Upstream live_web.txt Integration"

parent_target="$TEST_ROOT/targets/upstream_parent"
mkdir -p "${parent_target}/http-probe" "${parent_target}/technology"
printf 'https://parent.corp:8443\n' > "${parent_target}/http-probe/live_web.txt"

mock_ww_upstream="$TEST_ROOT/bin/mock_ww_upstream"
cat <<'EOF' > "$mock_ww_upstream"
#!/usr/bin/env bash
target="${@: -1}"
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-brief=*) out_file="${1#*=}"; shift ;;
        *) shift ;;
    esac
done
if [[ "$target" =~ :8443 ]] && [[ -n "$out_file" ]]; then
    printf 'https://parent.corp:8443 [200 OK] Caddy[2.6.4], Title[Secure Portal]\n' > "$out_file"
fi
exit 0
EOF
chmod +x "$mock_ww_upstream"

TECH_WHATWEB_BIN="$mock_ww_upstream" \
module_technology_run "parent.corp" "domain" "${parent_target}/technology"

if [[ -f "${parent_target}/technology/technologies.txt" ]] && \
   grep -q "Caddy" "${parent_target}/technology/technologies.txt"; then
    pass "Prioritizes upstream live_web.txt endpoints for technology scanning"
else
    fail "Upstream live_web.txt integration failed"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Technologies Detected
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Technologies Detected"

task_dir_dead="$TEST_ROOT/targets/dead_tech/technology"
TECH_WHATWEB_BIN="$mock_empty" \
TECH_CURL_BIN="$mock_empty" \
module_technology_run "dead.domain" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No technologies or framework signatures detected." "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/technologies.txt" ]]; then
    pass "Handles empty technology results cleanly with code 0"
else
    fail "Empty technology results handling mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_ww" 2>/dev/null || stat -f '%p' "$task_dir_ww" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_ww}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_ww}/output.txt" 2>/dev/null)"
tech_perms="$(stat -c '%a' "${task_dir_ww}/technologies.txt" 2>/dev/null || stat -f '%p' "${task_dir_ww}/technologies.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$tech_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all technology artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms tech=$tech_perms"
fi

test_summary
