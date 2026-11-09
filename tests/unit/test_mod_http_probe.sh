#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTP Probing Module Unit Tests (test_mod_http_probe.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/http-probe.sh
if ! source "$PROJECT_ROOT/modules/web/http-probe.sh"; then
    printf 'Error: Unable to load modules/web/http-probe.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-http-probe-test.XXXXXX")" || {
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

    printf '%s\n' "HTTP probing module unit tests completed."
}

printf '%s\n' "RECKON - HTTP Probing Module Unit Tests"
printf '%s\n' "---------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_http_probe_run "example.com" "domain" 2>/dev/null; then
    fail "module_http_probe_run accepted fewer than 3 arguments"
else
    pass "module_http_probe_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_http_probe_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_http_probe_run accepted empty target"
else
    pass "module_http_probe_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_http_probe_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_http_probe_run accepted empty target type"
else
    pass "module_http_probe_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_http_probe_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_http_probe_run accepted empty task directory"
else
    pass "module_http_probe_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported types return 0
task_compat_url="$TEST_ROOT/targets/url_test/http-probe"
if module_http_probe_run "http://example.com" "url_http" "$task_compat_url"; then
    pass "module_http_probe_run accepts url_http target"
else
    fail "module_http_probe_run rejected valid url_http target"
fi

# Test 2: Incompatible multi-host CIDR skipped gracefully
task_incompat_cidr="$TEST_ROOT/targets/cidr_test/http-probe"
if module_http_probe_run "192.168.1.0/24" "ipv4_cidr" "$task_incompat_cidr"; then
    if [[ -f "${task_incompat_cidr}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_cidr}/output.txt"; then
        pass "module_http_probe_run skips multi-host CIDR block with execution notice"
    else
        fail "module_http_probe_run did not write SKIPPED notice for CIDR"
    fi
else
    fail "module_http_probe_run failed on incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: HTTPX Primary Engine Probing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: HTTPX Primary Engine Probing"

# Create mock httpx binary
mock_httpx="$TEST_ROOT/bin/mock_httpx"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_httpx"
#!/usr/bin/env bash
# Mock httpx binary
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l)
            list_file="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r host || [[ -n "$host" ]]; do
        if [[ "$host" =~ :8443 ]]; then
            printf '%s [200] [Corp Admin VPN] [Apache/2.4.41] [1024] [https://corp.local/]\n' "$host"
        elif [[ "$host" =~ :8080 ]]; then
            printf '%s [302] [Redirect Page] [nginx/1.18.0] [256] [https://corp.local:8443/]\n' "$host"
        fi
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$mock_httpx"

task_dir_httpx="$TEST_ROOT/targets/httpx_test/http-probe"
HTTP_PROBE_HTTPX_BIN="$mock_httpx" \
module_http_probe_run "corp.local" "domain" "$task_dir_httpx"

if [[ -f "${task_dir_httpx}/live_web.txt" ]] && \
   grep -q "https://corp.local:8443" "${task_dir_httpx}/live_web.txt" && \
   grep -q "http://corp.local:8080" "${task_dir_httpx}/live_web.txt"; then
    pass "httpx engine populates live_web.txt with responsive endpoints"
else
    fail "httpx engine failed to populate live_web.txt"
fi

if [[ -f "${task_dir_httpx}/probed_urls.txt" ]] && \
   grep -q "Corp Admin VPN" "${task_dir_httpx}/probed_urls.txt"; then
    pass "httpx engine records title, server, and status in probed_urls.txt"
else
    fail "httpx engine failed to record detailed results in probed_urls.txt"
fi

# -----------------------------------------------------------------------------
# UT-04: Curl Fallback Engine Probing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Curl Fallback Engine Probing"

# Create mock curl binary
mock_curl="$TEST_ROOT/bin/mock_curl"
cat <<'EOF' > "$mock_curl"
#!/usr/bin/env bash
header_dest=""
body_dest=""
target_url=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) header_dest="$2"; shift 2 ;;
        -o) body_dest="$2"; shift 2 ;;
        http*) target_url="$1"; shift ;;
        *) shift ;;
    esac
done

if [[ "$target_url" =~ (http|https)://fallback.test ]]; then
    if [[ -n "$header_dest" ]]; then
        printf 'HTTP/1.1 200 OK\r\nServer: Caddy/2.6.4\r\nContent-Length: 512\r\n\r\n' > "$header_dest"
    fi
    if [[ -n "$body_dest" ]]; then
        printf '<html><head><title>Caddy Gateway App</title></head><body><h1>OK</h1></body></html>' > "$body_dest"
    fi
    exit 0
fi
exit 1
EOF
chmod +x "$mock_curl"

task_dir_curl="$TEST_ROOT/targets/curl_test/http-probe"
# Pass "none" to force curl fallback engine
HTTP_PROBE_HTTPX_BIN="none" \
HTTP_PROBE_CURL_BIN="$mock_curl" \
module_http_probe_run "fallback.test" "domain" "$task_dir_curl"

if [[ -f "${task_dir_curl}/live_web.txt" ]] && \
   grep -q "fallback.test" "${task_dir_curl}/live_web.txt"; then
    pass "Curl fallback engine discovers responsive web endpoints"
else
    fail "Curl fallback engine failed to populate live_web.txt"
fi

if [[ -f "${task_dir_curl}/probed_urls.txt" ]] && \
   grep -q "Caddy Gateway App" "${task_dir_curl}/probed_urls.txt" && \
   grep -q "Caddy/2.6.4" "${task_dir_curl}/probed_urls.txt"; then
    pass "Curl fallback engine extracts HTML title and Server banner"
else
    fail "Curl fallback engine failed to extract title and banner"
fi

# -----------------------------------------------------------------------------
# UT-05: Upstream Port Correlation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Upstream Port Correlation"

target_dir_ports="$TEST_ROOT/targets/upstream_ports_target"
mkdir -p "${target_dir_ports}/port" "${target_dir_ports}/http-probe"
printf '9000\n9443\n' > "${target_dir_ports}/port/open_ports.txt"

mock_httpx_ports="$TEST_ROOT/bin/mock_httpx_ports"
cat <<'EOF' > "$mock_httpx_ports"
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l) list_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r host || [[ -n "$host" ]]; do
        if [[ "$host" =~ :9443 ]]; then
            printf '%s [200] [Microservice API] [Go-http-server] [128]\n' "$host"
        fi
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$mock_httpx_ports"

HTTP_PROBE_HTTPX_BIN="$mock_httpx_ports" \
module_http_probe_run "ports.local" "domain" "${target_dir_ports}/http-probe"

if [[ -f "${target_dir_ports}/http-probe/live_web.txt" ]] && \
   grep -q "https://ports.local:9443" "${target_dir_ports}/http-probe/live_web.txt"; then
    pass "Probes custom open ports derived from upstream open_ports.txt"
else
    fail "Upstream open ports correlation failed"
fi

# -----------------------------------------------------------------------------
# UT-06: Direct URL Target Probing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Direct URL Target Probing"

mock_httpx_url="$TEST_ROOT/bin/mock_httpx_url"
cat <<'EOF' > "$mock_httpx_url"
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l) list_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r host || [[ -n "$host" ]]; do
        printf '%s [200] [Single URL Test] [nginx] [500]\n' "$host"
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$mock_httpx_url"

task_dir_single_url="$TEST_ROOT/targets/single_url/http-probe"
HTTP_PROBE_HTTPX_BIN="$mock_httpx_url" \
module_http_probe_run "https://example.com:8443/app/dashboard" "url_https" "$task_dir_single_url"

if [[ -f "${task_dir_single_url}/live_web.txt" ]] && \
   grep -q "https://example.com:8443/app/dashboard" "${task_dir_single_url}/live_web.txt"; then
    pass "Direct URL target probes single explicit URL"
else
    fail "Direct URL target probing mismatch"
fi

# -----------------------------------------------------------------------------
# UT-07: Inactive / Unresponsive Target
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Inactive / Unresponsive Target"

mock_httpx_dead="$TEST_ROOT/bin/mock_httpx_dead"
cat <<'EOF' > "$mock_httpx_dead"
#!/usr/bin/env bash
# Simulates dead target: outputs nothing
exit 0
EOF
chmod +x "$mock_httpx_dead"

task_dir_dead="$TEST_ROOT/targets/dead_target/http-probe"
HTTP_PROBE_HTTPX_BIN="$mock_httpx_dead" \
module_http_probe_run "dead.internal" "domain" "$task_dir_dead"

if [[ -f "${task_dir_dead}/output.txt" ]] && \
   grep -q "No responsive HTTP/HTTPS services identified" "${task_dir_dead}/output.txt" && \
   [[ ! -s "${task_dir_dead}/live_web.txt" ]]; then
    pass "Handles unresponsive target gracefully with zero live web endpoints"
else
    fail "Inactive target handling mismatch in $task_dir_dead"
fi

# -----------------------------------------------------------------------------
# UT-08: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_httpx" 2>/dev/null || stat -f '%p' "$task_dir_httpx" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_httpx}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_httpx}/output.txt" 2>/dev/null)"
live_perms="$(stat -c '%a' "${task_dir_httpx}/live_web.txt" 2>/dev/null || stat -f '%p' "${task_dir_httpx}/live_web.txt" 2>/dev/null)"
probed_perms="$(stat -c '%a' "${task_dir_httpx}/probed_urls.txt" 2>/dev/null || stat -f '%p' "${task_dir_httpx}/probed_urls.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$live_perms" =~ 640$ && "$probed_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all generated artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms live=$live_perms probed=$probed_perms"
fi

test_summary
