#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# HTTPS Enumeration Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

HTTPS_MODULE="$PROJECT_ROOT/modules/network/services/https.sh"
readonly HTTPS_MODULE

if [[ ! -f "$HTTPS_MODULE" || ! -x "$HTTPS_MODULE" ]]; then
    printf 'Error: HTTPS module missing or not executable at %s\n' "$HTTPS_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-https-test.XXXXXX")" || {
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

    printf '%s\n' "HTTPS module unit tests completed."
}

printf '%s\n' "RECKON - HTTPS Module Unit Tests"
printf '%s\n' "--------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$HTTPS_MODULE" "192.168.1.1" "ipv4" >/dev/null 2>&1; then
    pass "https module rejects execution with insufficient arguments (< 3)"
else
    fail "https module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$HTTPS_MODULE" "" "ipv4" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "https module rejects empty target argument"
else
    fail "https module accepted empty target"
fi

# Test 3: Rejects execution with empty target type
TASK_DIR_2="$TEST_ROOT/task_out_2"
if ! "$HTTPS_MODULE" "192.168.1.1" "" "$TASK_DIR_2" >/dev/null 2>&1; then
    pass "https module rejects empty target type argument"
else
    fail "https module accepted empty target type"
fi

# Test 4: Rejects execution with empty task directory
if ! "$HTTPS_MODULE" "192.168.1.1" "ipv4" "" >/dev/null 2>&1; then
    pass "https module rejects empty task directory argument"
else
    fail "https module accepted empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 5: Rejects ipv4_cidr target type
TASK_DIR_CIDR="$TEST_ROOT/incompat_cidr"
if ! "$HTTPS_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_CIDR" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_CIDR/output.txt" ]] && grep -q "not a single discrete host" "$TASK_DIR_CIDR/output.txt"; then
        pass "https module rejects multi-host CIDR block with incompatible target notice"
    else
        fail "https module did not write expected failure notice for CIDR target"
    fi
else
    fail "https module succeeded on incompatible ipv4_cidr target"
fi

# Test 6: Rejects ipv4_range target type
TASK_DIR_RANGE="$TEST_ROOT/incompat_range"
if ! "$HTTPS_MODULE" "10.0.0.1-50" "ipv4_range" "$TASK_DIR_RANGE" >/dev/null 2>&1; then
    pass "https module rejects multi-host IPv4 range target"
else
    fail "https module succeeded on incompatible ipv4_range target"
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
    "$HTTPS_MODULE" "192.168.1.1" "ipv4" "$TASK_DIR_NO_TOOL" >/dev/null 2>&1
)
no_tool_exit=$?
if (( no_tool_exit != 0 )) && [[ -f "$TASK_DIR_NO_TOOL/output.txt" ]] && grep -q "Missing required service interrogation tool: nmap" "$TASK_DIR_NO_TOOL/output.txt"; then
    pass "https module exits non-zero and records missing tool error when nmap is unavailable"
else
    fail "https module did not handle missing nmap tool properly (exit: $no_tool_exit)"
fi

# -----------------------------------------------------------------------------
# Setup Mocks (Mock Nmap, Mock Curl, Mock OpenSSL)
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
    if [[ "${MOCK_HTTPS_MODE:-insecure}" == "insecure" ]]; then
        cat > "$out_path" <<'NMAP_INSECURE_EOF'
PORT    STATE SERVICE
443/tcp open  ssl/https
| ssl-enum-ciphers: 
|   SSLv3: 
|     ciphers: 
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA - grade: F
|     least strength: F
|   TLSv1.0: 
|     ciphers: 
|       TLS_RSA_WITH_AES_128_CBC_SHA - grade: C
|     least strength: C
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - grade: A
|     least strength: A
|_  least strength: F
NMAP_INSECURE_EOF
    else
        cat > "$out_path" <<'NMAP_SECURE_EOF'
PORT    STATE SERVICE
443/tcp open  ssl/https
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 - grade: A
|     least strength: A
|   TLSv1.3: 
|     ciphers: 
|       TLS_AES_256_GCM_SHA384 - grade: A
|     least strength: A
|_  least strength: A
NMAP_SECURE_EOF
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

if [[ "${MOCK_HTTPS_MODE:-insecure}" == "insecure" ]]; then
    cat <<'CURL_INSECURE_EOF'
HTTP/1.1 200 OK
Date: Sun, 08 Nov 2026 03:00:00 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Type: text/html
Content-Length: 1024
CURL_INSECURE_EOF
else
    cat <<'CURL_SECURE_EOF'
HTTP/1.1 200 OK
Date: Sun, 08 Nov 2026 03:00:00 GMT
Server: nginx/1.22.0
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Type: text/html
Content-Length: 512
CURL_SECURE_EOF
fi

exit 0
EOF
chmod +x "$MOCK_CURL_BIN"

MOCK_OPENSSL_BIN="$MOCK_BIN_DIR/mock_openssl.sh"
cat > "$MOCK_OPENSSL_BIN" <<'EOF'
#!/usr/bin/env bash
set -o nounset

if [[ "${1:-}" == "s_client" ]]; then
    cat <<'CERT_X509_RAW'
-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIUExampleCertificateData...
-----END CERTIFICATE-----
CERT_X509_RAW
    exit 0
fi

if [[ "${1:-}" == "x509" ]]; then
    if [[ "${MOCK_CERT_MODE:-self_signed}" == "self_signed" ]]; then
        cat <<'X509_SELF_SIGNED_EOF'
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1234567890 (0x499602d2)
        Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN = dev.corp.local
        Validity
            Not Before: Nov  1 00:00:00 2026 GMT
            Not After : Nov  1 00:00:00 2027 GMT
        Subject: CN = dev.corp.local
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:dev.corp.local, DNS:localhost
X509_SELF_SIGNED_EOF
    else
        cat <<'X509_CA_EOF'
Certificate:
    Data:
        Version: 3 (0x2)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Nov  1 00:00:00 2026 GMT
            Not After : Jan 30 00:00:00 2027 GMT
        Subject: CN = secure.prod.com
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:secure.prod.com, DNS:api.prod.com
X509_CA_EOF
    fi
    exit 0
fi

exit 0
EOF
chmod +x "$MOCK_OPENSSL_BIN"

ARGS_LOG="$TEST_ROOT/https_args.log"
CURL_LOG="$TEST_ROOT/curl_args.log"

# -----------------------------------------------------------------------------
# UT-04: Upstream Port & Service Integration
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Upstream Port & Service Integration"

# Test 8: Skips when upstream open_ports.txt reports 0 open ports
TARGET_ZERO="$TEST_ROOT/target_zero"
mkdir -p "$TARGET_ZERO/port" "$TARGET_ZERO/https"
: > "$TARGET_ZERO/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.1" "ipv4" "$TARGET_ZERO/https" >/dev/null 2>&1
)
zero_exit=$?

if (( zero_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'https'.*is not open" "$TARGET_ZERO/https/output.txt" && \
   grep -q "COMPLETED | Service not active on target." "$TARGET_ZERO/https/output.txt"; then
    pass "https module cleanly skips active interrogation when upstream open_ports.txt is empty"
else
    fail "https module did not handle empty upstream ports correctly (exit: $zero_exit)"
fi

# Test 9: Skips when open_ports.txt has other ports open but HTTPS ports (443/8443) are closed
TARGET_NO_HTTPS="$TEST_ROOT/target_no_https"
mkdir -p "$TARGET_NO_HTTPS/port" "$TARGET_NO_HTTPS/https"
printf "80\n22\n21\n" > "$TARGET_NO_HTTPS/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.2" "ipv4" "$TARGET_NO_HTTPS/https" >/dev/null 2>&1
)
no_https_exit=$?

if (( no_https_exit == 0 )) && [[ ! -f "$ARGS_LOG" ]] && \
   grep -q "verified service 'https'.*is not open" "$TARGET_NO_HTTPS/https/output.txt"; then
    pass "https module skips scan when upstream open_ports.txt does not include HTTPS ports"
else
    fail "https module failed to skip when HTTPS ports are closed (exit: $no_https_exit)"
fi

# Test 10: Targets port 443 resolved from upstream open_ports.txt
TARGET_PORT_443="$TEST_ROOT/target_port_443"
mkdir -p "$TARGET_PORT_443/port" "$TARGET_PORT_443/https"
printf "443\n" > "$TARGET_PORT_443/port/open_ports.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.3" "ipv4" "$TARGET_PORT_443/https" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 443" "$ARGS_LOG" && \
   grep -q "Target Ports.*443" "$TARGET_PORT_443/https/output.txt"; then
    pass "https module targets port 443 resolved from upstream open_ports.txt"
else
    fail "https module failed to target port 443 from open_ports.txt"
fi

# Test 11: Resolves non-standard HTTPS port (8443) from upstream services.txt
TARGET_ALT="$TEST_ROOT/target_alt"
mkdir -p "$TARGET_ALT/service" "$TARGET_ALT/https"
printf "8443/tcp\topen\tssl/http\tApache Tomcat\n" > "$TARGET_ALT/service/services.txt"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.4" "ipv4" "$TARGET_ALT/https" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 8443" "$ARGS_LOG" && \
   grep -q "Port 8443: HTTPS Service Interrogation" "$TARGET_ALT/https/output.txt"; then
    pass "https module discovers and targets non-standard port 8443 from upstream services.txt"
else
    fail "https module failed to target alternate HTTPS port from services.txt"
fi

# -----------------------------------------------------------------------------
# UT-05: Standalone Execution & Port Override Fallback
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Standalone Execution & Port Override Fallback"

# Test 12: Standalone execution falls back to default ports 443 and 8443
TARGET_STANDALONE="$TEST_ROOT/target_standalone"
rm -f "$ARGS_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.5" "ipv4" "$TARGET_STANDALONE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 443" "$ARGS_LOG" && grep -q -- "-p 8443" "$ARGS_LOG" && \
   grep -q "Port Resolution.*Canonical default port(s)" "$TARGET_STANDALONE/output.txt"; then
    pass "https module falls back to default ports 443 and 8443 in standalone execution mode"
else
    fail "https module standalone execution did not target default ports"
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
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export CONFIG_EFFECTIVE_PORTS="9443"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    "$HTTPS_MODULE" "10.0.0.6" "ipv4" "$TARGET_OVERRIDE" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 9443" "$ARGS_LOG"; then
    pass "https module respects custom port specified in CONFIG_EFFECTIVE_PORTS"
else
    fail "https module failed to honor CONFIG_EFFECTIVE_PORTS override"
fi

# -----------------------------------------------------------------------------
# UT-06: URL Target Handling & Path Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: URL Target Handling & Path Extraction"

# Test 14: Accepts url_https target and extracts target host, port, and query URL
TARGET_URL_DIR="$TEST_ROOT/target_url"
rm -f "$ARGS_LOG" "$CURL_LOG"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_NMAP_ARGS_LOG="$ARGS_LOG"
    # shellcheck disable=SC2030,SC2031
    export MOCK_CURL_ARGS_LOG="$CURL_LOG"
    "$HTTPS_MODULE" "https://secure.local:8443/console" "url_https" "$TARGET_URL_DIR" >/dev/null 2>&1
)
if [[ -f "$ARGS_LOG" ]] && grep -q -- "-p 8443" "$ARGS_LOG" && grep -q "secure.local" "$ARGS_LOG" && \
   [[ -f "$CURL_LOG" ]] && grep -q "https://secure.local:8443/console" "$CURL_LOG" && \
   grep -q "Target URL.*https://secure.local:8443/console" "$TARGET_URL_DIR/output.txt"; then
    pass "https module accepts url_https target and extracts hostname, port, and URL path"
else
    fail "https module failed to process url_https target input"
fi

# -----------------------------------------------------------------------------
# UT-07: X.509 Certificate Retrieval & Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: X.509 Certificate Retrieval & Validation"

# Test 15: Audits self-signed certificate and detects weak SHA-1 signature
TARGET_INSECURE="$TEST_ROOT/target_insecure"
mkdir -p "$TARGET_INSECURE/port" "$TARGET_INSECURE/https"
printf "443\n" > "$TARGET_INSECURE/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_HTTPS_MODE="insecure"
    # shellcheck disable=SC2030,SC2031
    export MOCK_CERT_MODE="self_signed"
    "$HTTPS_MODULE" "dev.corp.local" "domain" "$TARGET_INSECURE/https" >/dev/null 2>&1
)
if [[ -f "$TARGET_INSECURE/https/https_cert.txt" ]] && \
   grep -q "Certificate Subject.*CN = dev.corp.local" "$TARGET_INSECURE/https/output.txt" && \
   grep -q "Certificate Issuer.*CN = dev.corp.local" "$TARGET_INSECURE/https/output.txt" && \
   grep -q "\[SECURITY WARN\] Self-Signed TLS Certificate" "$TARGET_INSECURE/https/output.txt" && \
   grep -q "\[SECURITY WARN\] Weak Certificate Signature.*sha1WithRSAEncryption" "$TARGET_INSECURE/https/output.txt"; then
    pass "https module detects self-signed certificate and weak digest signature algorithm"
else
    fail "https module failed to audit X.509 certificate properly"
fi

# Test 16: Recognizes valid CA-signed certificate
TARGET_CA="$TEST_ROOT/target_ca"
mkdir -p "$TARGET_CA/port" "$TARGET_CA/https"
printf "443\n" > "$TARGET_CA/port/open_ports.txt"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL_BIN"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL_BIN"
    # shellcheck disable=SC2030,SC2031
    export MOCK_HTTPS_MODE="secure"
    # shellcheck disable=SC2030,SC2031
    export MOCK_CERT_MODE="ca_signed"
    "$HTTPS_MODULE" "secure.prod.com" "domain" "$TARGET_CA/https" >/dev/null 2>&1
)
if grep -q "Certificate Issuer.*Let's Encrypt" "$TARGET_CA/https/output.txt" && \
   ! grep -q "\[SECURITY WARN\] Self-Signed" "$TARGET_CA/https/output.txt"; then
    pass "https module recognizes trusted CA issuer and suppresses self-signed warning"
else
    fail "https module failed to handle CA-signed certificate"
fi

# -----------------------------------------------------------------------------
# UT-08: TLS Protocol & Cipher Suite Security Auditing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: TLS Protocol & Cipher Suite Security Auditing"

# Test 17: Detects deprecated and broken protocols (SSLv3, TLSv1.0)
if [[ -f "$TARGET_INSECURE/https/https_tls.txt" ]] && \
   grep -q "Supported Protocols: SSLv3, TLSv1.0, TLSv1.2" "$TARGET_INSECURE/https/https_tls.txt" && \
   grep -q "\[SECURITY RISK\] Insecure Protocol Enabled: SSLv3" "$TARGET_INSECURE/https/output.txt" && \
   grep -q "\[SECURITY WARN\] Deprecated TLS Version Enabled: TLSv1.0" "$TARGET_INSECURE/https/output.txt"; then
    pass "https module detects broken SSLv3 and deprecated TLSv1.0 and issues security warnings"
else
    fail "https module failed to audit TLS protocol versions properly"
fi

# -----------------------------------------------------------------------------
# UT-09: HSTS Header Posture Evaluation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: HSTS Header Posture Evaluation"

# Test 18: Detects missing HSTS header and issues warning
if grep -q "HSTS Policy.*Missing" "$TARGET_INSECURE/https/output.txt" && \
   grep -q "\[SECURITY WARN\] Missing Strict-Transport-Security (HSTS) Header" "$TARGET_INSECURE/https/output.txt"; then
    pass "https module detects missing HSTS header and issues security warning"
else
    fail "https module failed to detect missing HSTS header"
fi

# Test 19: Recognizes active HSTS policy
if grep -q "HSTS Policy.*Enabled" "$TARGET_CA/https/output.txt" && \
   ! grep -q "\[SECURITY WARN\] Missing Strict-Transport-Security" "$TARGET_CA/https/output.txt"; then
    pass "https module recognizes active HSTS policy and suppresses HSTS warning"
else
    fail "https module failed to recognize active HSTS policy"
fi

# -----------------------------------------------------------------------------
# UT-10: Secure Permissions & Artifact Integrity
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Secure Permissions & Artifact Integrity"

# Test 20: All generated artifact files have 0640 permissions
non_compliant_perms=0
for f in "$TARGET_INSECURE/https"/*; do
    if [[ -f "$f" ]]; then
        file_perm="$(stat -c '%a' "$f")"
        if [[ "$file_perm" != "640" ]]; then
            non_compliant_perms=$(( non_compliant_perms + 1 ))
        fi
    fi
done

if (( non_compliant_perms == 0 )); then
    pass "all https task artifacts enforce secure 0640 permissions"
else
    fail "found $non_compliant_perms file(s) without required 0640 permissions"
fi

test_summary
