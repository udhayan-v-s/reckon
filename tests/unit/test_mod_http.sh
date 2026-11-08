#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTP Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

HTTP_MODULE="$PROJECT_ROOT/modules/network/services/http.sh"
readonly HTTP_MODULE

if [[ ! -f "$HTTP_MODULE" || ! -x "$HTTP_MODULE" ]]; then
    printf 'Error: HTTP module missing or not executable at %s\n' "$HTTP_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-http-test.XXXXXX")" || {
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

    printf '%s\n' "HTTP module unit tests completed."
}

printf '%s\n' "RECKON - HTTP Module Unit Tests"
printf '%s\n' "-------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$HTTP_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "http module rejects execution with insufficient arguments (< 3)"
else
    fail "http module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$HTTP_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "http module rejects empty target argument"
else
    fail "http module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$HTTP_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "http module rejects empty target type argument"
else
    fail "http module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$HTTP_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "http module rejects empty task directory argument"
else
    fail "http module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$HTTP_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "http module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "http module did not write expected failure notice for CIDR target"
    fi
else
    fail "http module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$HTTP_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "http module rejects multi-host IPv4 range target"
else
    fail "http module succeeded on incompatible ipv4_range target"
fi

# -----------------------------------------------------------------------------
# UT-03: Dependency & Tool Availability
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Dependency & Tool Availability"

# Test 7: Reports failure when nmap is not available in PATH
TASK_DIR_NO_TOOL="$TEST_ROOT/no_tool"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="/nonexistent/bin/nmap_missing"
    "$HTTP_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "http module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "http module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mocks (Mock Nmap, Mock Curl)
# -----------------------------------------------------------------------------
MOCK_BIN_DIR="$TEST_ROOT/mock_bin"
mkdir -p "$MOCK_BIN_DIR"

MOCK_NMAP_BIN="$MOCK_BIN_DIR/mock_nmap.sh"
cat > "$MOCK_NMAP_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ -n "${MOCK_NMAP_ARGS_LOG:-}" ]]; then
    printf '%s\n' "$*" >> "$MOCK_NMAP_ARGS_LOG"
fi

out_path=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -oN) out_path="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_path" ]]; then
    if [[ "${MOCK_HTTP_MODE:-insecure}" == "insecure" ]]; then
        cat > "$out_path" <<'NMAP_INSECURE_EOF'
PORT   STATE SERVICE
80/tcp open  http
| http-title: Test Web Server Home
|_Requested resource was /index.html
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS PUT DELETE TRACE
| http-server-header: Apache/2.4.52 (Ubuntu)
NMAP_INSECURE_EOF
    else
        cat > "$out_path" <<'NMAP_CLEAN_EOF'
PORT   STATE SERVICE
80/tcp open  http
| http-title: Secure Portal
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-server-header: nginx/1.22.0
NMAP_CLEAN_EOF
    fi
fi

exit 0
EOF
chmod +x "$MOCK_NMAP_BIN"

MOCK_CURL_BIN="$MOCK_BIN_DIR/mock_curl.sh"
cat > "$MOCK_CURL_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ -n "${MOCK_CURL_ARGS_LOG:-}" ]]; then
    printf '%s\n' "$*" >> "$MOCK_CURL_ARGS_LOG"
fi

if [[ "${MOCK_HTTP_MODE:-insecure}" == "insecure" ]]; then
    cat <<'CURL_INSECURE_EOF'
HTTP/1.1 200 OK
Date: Sun, 08 Nov 2026 03:00:00 GMT
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1.2
Content-Type: text/html; charset=UTF-8
Content-Length: 1024
Connection: keep-alive
CURL_INSECURE_EOF
else
    cat <<'CURL_SECURE_EOF'
HTTP/1.1 200 OK
Date: Sun, 08 Nov 2026 03:00:00 GMT
Server: nginx/1.22.0
Content-Type: text/html; charset=UTF-8
Content-Length: 512
Connection: keep-alive
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
CURL_SECURE_EOF
fi

exit 0
EOF
chmod +x "$MOCK_CURL_BIN"

ARGS_LOG="$TEST_ROOT/http_args.log"
CURL_LOG="$TEST_ROOT/curl_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 8: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/http"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/http" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'http'.*is not open" "$TARGET_ZERO/http/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/http/output.txt"; then
    pass "http module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "http module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 9: Skips when open_ports.txt has other ports open but HTTP ports (80/8080) are closed
TARGET_NO_HTTP="$TEST_ROOT/target_no_http"
mkdir -p "$TARGET_NO_HTTP/port" "$TARGET_NO_HTTP/http"
printf "22\n21\n3306\n" > "$TARGET_NO_HTTP/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_HTTP/http" >/dev/null 2>&1
)
no_http_exit=$?

if (( no_http_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'http'.*is not open" "$TARGET_NO_HTTP/http/output.txt"; then
    pass "http module skips scan when upstream open_ports.txt does not include HTTP ports"
else
    fail "http module failed to skip when HTTP ports are closed (exit: $no_http_exit)"
fi

# Test 10: Targets port 80 resolved from upstream open_ports.txt
TARGET_PORT_80="$TEST_ROOT/target_port_80"
mkdir -p "$TARGET_PORT_80/port" "$TARGET_PORT_80/http"
printf "80\n" > "$TARGET_PORT_80/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.3" "ipv4" "$TARGET_PORT_80/http" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 80" "$ARGS_LOG" && \
   grep -q "Target Ports.*80" "$TARGET_PORT_80/http/output.txt"; then
    pass "http module targets port 80 resolved from upstream open_ports.txt"
else
    fail "http module failed to target port 80 from open_ports.txt"
fi

# Test 11: Resolves non-standard HTTP port (8000) from upstream services.txt
TARGET_ALT="$TEST_ROOT/target_alt"
mkdir -p "$TARGET_ALT/service" "$TARGET_ALT/http"
printf "8000/tcp\topen\thttp-alt\tNode.js Express\n" > "$TARGET_ALT/service/services.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.4" "ipv4" "$TARGET_ALT/http" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 8000" "$ARGS_LOG" && \
   grep -q "Port 8000: HTTP Service Interrogation" "$TARGET_ALT/http/output.txt"; then
    pass "http module discovers and targets non-standard port 8000 from upstream services.txt"
else
    fail "http module failed to target alternate HTTP port from services.txt"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default ports 80, 8080
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.5" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 80" "$ARGS_LOG" && grep -q -- "-p 8080" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "http module falls back to default ports 80 and 8080 in standalone execution mode"
else
    fail "http module standalone execution did not target default ports"
fi

# Test 13: Respects CONFIG_EFFECTIVE_PORTS CLI override
TARGET_OVERRIDE="$TEST_ROOT/target_override"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="8888"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTP_MODULE" "10.0.0.6" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 8888" "$ARGS_LOG"; then
    pass "http module respects custom port specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "http module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: URL Target Handling & Path Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: URL Target Handling & Path Extraction"

# Test 14: Accepts url_http target and extracts target host, port, and query URL
TARGET_URL_DIR="$TEST_ROOT/target_url"
rm -f "$ARGS_LOG" "$CURL_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export MOCK_CURL_ARGS_LOG="$CURL_LOG"
    "$HTTP_MODULE" "http://portal.local:8080/app/login" "url_http" "$TARGET_URL_DIR" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 8080" "$ARGS_LOG" && grep -q "portal.local" "$ARGS_LOG" && \
   [[ -f "$CURL_LOG" ]] && grep -q "http://portal.local:8080/app/login" "$CURL_LOG" && \
   grep -q "Target URL.*http://portal.local:8080/app/login" "$TARGET_URL_DIR/output.txt"; then
    pass "http module accepts url_http target and extracts hostname, port, and URL path"
else
    fail "http module failed to process url_http target input"
fi

# -----------------------------------------------------------------------------
# UT-07: HTTP Response Header & Security Header Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: HTTP Response Header & Security Header Auditing"

# Test 15: Audits response headers and identifies missing clickjacking and MIME headers
TARGET_INSECURE="$TEST_ROOT/target_insecure"
mkdir -p "$TARGET_INSECURE/port" "$TARGET_INSECURE/http"
printf "80\n" > "$TARGET_INSECURE/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_HTTP_MODE="insecure"
    "$HTTP_MODULE" "web.internal" "domain" "$TARGET_INSECURE/http" >/dev/null 2>&1
)
if [[ -f "$TARGET_INSECURE/http/http_headers.txt" ]] && \
   grep -q "Server: Apache/2.4.52" "$TARGET_INSECURE/http/http_headers.txt" && \
   grep -q "Server Banner.*Apache/2.4.52" "$TARGET_INSECURE/http/output.txt" && \
   grep -q "X-Powered-By.*PHP/8.1.2" "$TARGET_INSECURE/http/output.txt" && \
   grep -q "\[SECURITY NOTICE\] Missing Header: X-Frame-Options" "$TARGET_INSECURE/http/output.txt" && \
   grep -q "\[SECURITY NOTICE\] Missing Header: X-Content-Type-Options" "$TARGET_INSECURE/http/output.txt"; then
    pass "http module records response headers and identifies missing security headers"
else
    fail "http module failed to audit HTTP response headers properly"
fi

# Test 16: Recognizes hardened HTTP security headers
TARGET_HARDENED="$TEST_ROOT/target_hardened"
mkdir -p "$TARGET_HARDENED/port" "$TARGET_HARDENED/http"
printf "80\n" > "$TARGET_HARDENED/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_HTTP_MODE="hardened"
    "$HTTP_MODULE" "secure.internal" "domain" "$TARGET_HARDENED/http" >/dev/null 2>&1
)
if grep -q "Server Banner.*nginx/1.22.0" "$TARGET_HARDENED/http/output.txt" && \
   ! grep -q "\[SECURITY NOTICE\] Missing Header:" "$TARGET_HARDENED/http/output.txt"; then
    pass "http module recognizes presence of XFO, XCTO, and CSP security headers"
else
    fail "http module failed to recognize hardened HTTP security headers"
fi

# -----------------------------------------------------------------------------
# UT-08: HTTP Methods & Insecure Method Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: HTTP Methods & Insecure Method Auditing"

# Test 17: Detects dangerous HTTP methods (PUT, DELETE, TRACE)
if [[ -f "$TARGET_INSECURE/http/http_methods.txt" ]] && \
   grep -q "Insecure Methods: PUT, DELETE, TRACE" "$TARGET_INSECURE/http/http_methods.txt" && \
   grep -q "\[SECURITY WARN\] Insecure HTTP Method TRACE Enabled" "$TARGET_INSECURE/http/output.txt" && \
   grep -q "\[SECURITY WARN\] Insecure HTTP Method PUT Enabled" "$TARGET_INSECURE/http/output.txt" && \
   grep -q "\[SECURITY WARN\] Insecure HTTP Method DELETE Enabled" "$TARGET_INSECURE/http/output.txt"; then
    pass "http module detects dangerous HTTP methods (PUT, DELETE, TRACE) and issues warnings"
else
    fail "http module failed to identify dangerous HTTP methods"
fi

# Test 18: Extracts HTML page title
if grep -q "HTML Page Title.*Test Web Server Home" "$TARGET_INSECURE/http/output.txt"; then
    pass "http module extracts and documents HTML page title"
else
    fail "http module failed to extract HTML page title"
fi

# -----------------------------------------------------------------------------
# UT-09: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Secure Permissions & Artifact Integrity"

# Test 19: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_INSECURE/http"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all http task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

# Test 20: Aggregated findings count is reflected in execution footer
if grep -q "HTTP audit completed with 6 security finding(s)." "$TARGET_INSECURE/http/output.txt"; then
    pass "http module aggregates method and header findings in execution footer"
else
    fail "http module execution footer findings count mismatch"
fi

test_summary
