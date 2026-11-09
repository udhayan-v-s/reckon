#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web API and Endpoint Extraction Module Unit Tests (test_mod_endpoint.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/endpoint.sh
if ! source "$PROJECT_ROOT/modules/web/endpoint.sh"; then
    printf 'Error: Unable to load modules/web/endpoint.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-ep-test.XXXXXX")" || {
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

    printf '%s\n' "Web endpoint extraction module unit tests completed."
}

printf '%s\n' "RECKON - Web API and Endpoint Extraction Module Unit Tests"
printf '%s\n' "----------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_endpoint_run "example.com" "domain" 2>/dev/null; then
    fail "module_endpoint_run accepted fewer than 3 arguments"
else
    pass "module_endpoint_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_endpoint_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_endpoint_run accepted empty target"
else
    pass "module_endpoint_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_endpoint_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_endpoint_run accepted empty target type"
else
    pass "module_endpoint_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_endpoint_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_endpoint_run accepted empty task directory"
else
    pass "module_endpoint_run rejects empty task directory"
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
task_compat_dom="$TEST_ROOT/targets/dom_test/endpoint"
if ENDPOINT_KATANA_BIN="$mock_empty" ENDPOINT_CURL_BIN="$mock_empty" \
   module_endpoint_run "corp.local" "domain" "$task_compat_dom"; then
    pass "module_endpoint_run accepts valid domain target"
else
    fail "module_endpoint_run failed for valid domain target"
fi

# Test 2: Supported URL target returns 0
task_compat_url="$TEST_ROOT/targets/url_test/endpoint"
if ENDPOINT_KATANA_BIN="$mock_empty" ENDPOINT_CURL_BIN="$mock_empty" \
   module_endpoint_run "https://corp.local" "url_https" "$task_compat_url"; then
    pass "module_endpoint_run accepts valid URL target"
else
    fail "module_endpoint_run failed for valid URL target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/endpoint"
if ENDPOINT_KATANA_BIN="$mock_empty" ENDPOINT_CURL_BIN="$mock_empty" \
   module_endpoint_run "192.168.0.0/16" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_endpoint_run skips multi-host CIDR block with execution notice"
    else
        fail "module_endpoint_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_endpoint_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: Katana Primary Engine Endpoint Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Katana Primary Engine Endpoint Extraction"

mock_katana_ep="$TEST_ROOT/bin/mock_katana_ep"
cat <<'EOF' > "$mock_katana_ep"
#!/usr/bin/env bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    cat <<'EP_EOF' > "$out_file"
/api/v1/users
/api/v2/items
/auth/token
/admin/dashboard
/about/team
EP_EOF
fi
exit 0
EOF
chmod +x "$mock_katana_ep"

task_dir_katana="$TEST_ROOT/targets/katana_test/endpoint"
ENDPOINT_KATANA_BIN="$mock_katana_ep" \
ENDPOINT_CURL_BIN="$mock_empty" \
module_endpoint_run "corp.local" "domain" "$task_dir_katana"

if [[ -f "${task_dir_katana}/endpoints.txt" ]] && \
   grep -q -E "^/api/v1/users"$'\t'"API" "${task_dir_katana}/endpoints.txt" && \
   grep -q -E "^/auth/token"$'\t'"AUTH" "${task_dir_katana}/endpoints.txt" && \
   grep -q -E "^/admin/dashboard"$'\t'"ADMIN" "${task_dir_katana}/endpoints.txt"; then
    pass "Katana engine extracts and classifies endpoints into endpoints.txt"
else
    fail "Katana engine failed to write classified endpoints into endpoints.txt"
fi

if [[ -f "${task_dir_katana}/output.txt" ]] && \
   grep -q "Total Endpoints Discovered.*5" "${task_dir_katana}/output.txt" && \
   grep -q "REST API & Routes.*2" "${task_dir_katana}/output.txt"; then
    pass "Formats comprehensive summary report with endpoint categorization"
else
    fail "Formatted output report mismatch in $task_dir_katana"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback JavaScript & HTML Endpoint Parsing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback JavaScript & HTML Endpoint Parsing"

mock_curl_ep="$TEST_ROOT/bin/mock_curl_ep"
cat <<'EOF' > "$mock_curl_ep"
#!/usr/bin/env bash
req_url="${@: -1}"
if [[ "$req_url" =~ \.js ]]; then
    cat <<'JS_EOF'
const apiHost = "/api/v1";
function login(u, p) {
    return axios.post('/auth/login', {username: u, password: p});
}
function fetchProfile() {
    return fetch('/api/v1/users/profile');
}
function getAdminMetrics() {
    return fetch('/admin/metrics');
}
JS_EOF
    exit 0
else
    cat <<'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <script src="/static/app.js"></script>
</head>
<body>
    <form action="/auth/submit" method="POST"></form>
    <a href="/api/v2/status">Status</a>
</body>
</html>
HTML_EOF
    exit 0
fi
EOF
chmod +x "$mock_curl_ep"

task_dir_curl="$TEST_ROOT/targets/curl_ep_test/endpoint"
ENDPOINT_KATANA_BIN="none" \
ENDPOINT_CURL_BIN="$mock_curl_ep" \
module_endpoint_run "http://fallback.corp" "url_http" "$task_dir_curl"

if [[ -f "${task_dir_curl}/endpoints.txt" ]] && \
   grep -q -E "^/auth/login"$'\t'"AUTH" "${task_dir_curl}/endpoints.txt" && \
   grep -q -E "^/api/v1/users/profile"$'\t'"API" "${task_dir_curl}/endpoints.txt" && \
   grep -q -E "^/admin/metrics"$'\t'"ADMIN" "${task_dir_curl}/endpoints.txt"; then
    pass "Fallback heuristics parse endpoints and routes from HTML and referenced JavaScript"
else
    fail "Fallback heuristics failed to extract and classify endpoints"
fi

# -----------------------------------------------------------------------------
# UT-05: Upstream Reconnaissance Artifact Ingestion
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Upstream Reconnaissance Artifact Ingestion"

task_dir_up="$TEST_ROOT/targets/upstream_test/endpoint"
crawl_dir="$TEST_ROOT/targets/upstream_test/crawl"
mkdir -p "$crawl_dir"
cat <<'UP_EOF' > "${crawl_dir}/crawled_urls.txt"
http://upstream.corp/api/v1/checkout
http://upstream.corp/dashboard/orders
UP_EOF

ENDPOINT_KATANA_BIN="none" \
ENDPOINT_CURL_BIN="$mock_empty" \
module_endpoint_run "http://upstream.corp" "url_http" "$task_dir_up"

if [[ -f "${task_dir_up}/endpoints.txt" ]] && \
   grep -q "/api/v1/checkout" "${task_dir_up}/endpoints.txt"; then
    pass "Ingests and parses endpoints from upstream crawling artifacts"
else
    fail "Failed to ingest endpoints from upstream crawl artifact"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Endpoints Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Endpoints Discovered"

task_dir_empty="$TEST_ROOT/targets/empty_test/endpoint"
ENDPOINT_KATANA_BIN="$mock_empty" \
ENDPOINT_CURL_BIN="$mock_empty" \
module_endpoint_run "empty.org" "domain" "$task_dir_empty"

if [[ -f "${task_dir_empty}/endpoints.txt" ]] && [[ ! -s "${task_dir_empty}/endpoints.txt" ]] && \
   grep -q "No endpoints discovered" "${task_dir_empty}/output.txt"; then
    pass "Handles empty endpoint discovery results cleanly with exit code 0"
else
    fail "Clean empty endpoint state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_katana" 2>/dev/null || stat -f '%p' "$task_dir_katana" 2>/dev/null)"
ep_perm="$(stat -c '%a' "${task_dir_katana}/endpoints.txt" 2>/dev/null || stat -f '%p' "${task_dir_katana}/endpoints.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_katana}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_katana}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
ep_perm="${ep_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$ep_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all endpoint artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, ep=$ep_perm, output=$out_perm"
fi

test_summary
