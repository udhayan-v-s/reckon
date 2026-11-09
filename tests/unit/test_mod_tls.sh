#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web SSL/TLS Security Analysis Module Unit Tests (test_mod_tls.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/tls.sh
if ! source "$PROJECT_ROOT/modules/web/tls.sh"; then
    printf 'Error: Unable to load modules/web/tls.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-tls-test.XXXXXX")" || {
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

    printf '%s\n' "Web SSL/TLS security analysis module unit tests completed."
}

printf '%s\n' "RECKON - Web SSL/TLS Security Analysis Module Unit Tests"
printf '%s\n' "--------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_tls_run "example.com" "domain" 2>/dev/null; then
    fail "module_tls_run accepted fewer than 3 arguments"
else
    pass "module_tls_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_tls_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_tls_run accepted empty target"
else
    pass "module_tls_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_tls_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_tls_run accepted empty target type"
else
    pass "module_tls_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_tls_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_tls_run accepted empty task directory"
else
    pass "module_tls_run rejects empty task directory"
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

# Test 1: Supported HTTPS URL returns 0
task_compat_url="$TEST_ROOT/targets/https_test/tls"
if TLS_TESTSSL_BIN="$mock_empty" TLS_OPENSSL_BIN="$mock_empty" \
   module_tls_run "https://corp.local" "url_https" "$task_compat_url"; then
    pass "module_tls_run accepts valid HTTPS URL target"
else
    fail "module_tls_run failed for valid HTTPS target"
fi

# Test 2: Incompatible HTTP URL target cleanly skipped with 0
task_compat_http="$TEST_ROOT/targets/http_test/tls"
if TLS_TESTSSL_BIN="$mock_empty" TLS_OPENSSL_BIN="$mock_empty" \
   module_tls_run "http://corp.local" "url_http" "$task_compat_http"; then
    if [[ -f "${task_compat_http}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_http}/output.txt"; then
        pass "module_tls_run skips plain HTTP target with execution notice"
    else
        fail "module_tls_run did not generate skip notice for plain HTTP"
    fi
else
    fail "module_tls_run returned non-zero for plain HTTP target"
fi

# Test 3: Incompatible CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/tls"
if TLS_TESTSSL_BIN="$mock_empty" TLS_OPENSSL_BIN="$mock_empty" \
   module_tls_run "10.0.0.0/24" "ipv4_cidr" "$task_compat_cidr"; then
    pass "module_tls_run skips CIDR block with exit code 0"
else
    fail "module_tls_run returned non-zero for CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: Testssl.sh Primary Engine Execution
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Testssl.sh Primary Engine Execution"

mock_testssl="$TEST_ROOT/bin/mock_testssl"
cat <<'EOF' > "$mock_testssl"
#!/usr/bin/env bash
cat <<'TESTSSL_EOF'
Testing protocols via sockets

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

Testing server's certificate

 Certificate Validity (UTC)   Valid until: 2027-12-31
 Common Name (CN)             corp.local
 Issuer                       DigiCert Global Root CA
 Subject Alt Names (SANs)     corp.local, www.corp.local
TESTSSL_EOF
exit 0
EOF
chmod +x "$mock_testssl"

task_dir_testssl="$TEST_ROOT/targets/testssl_test/tls"
TLS_TESTSSL_BIN="$mock_testssl" \
TLS_OPENSSL_BIN="$mock_empty" \
module_tls_run "https://corp.local" "url_https" "$task_dir_testssl"

if [[ -f "${task_dir_testssl}/tls_audit.txt" ]] && \
   grep -q "TLS 1.2.*offered" "${task_dir_testssl}/tls_audit.txt" && \
   grep -q "TLS 1.3.*offered" "${task_dir_testssl}/tls_audit.txt"; then
    pass "Testssl engine captures protocol versions in tls_audit.txt"
else
    fail "Testssl protocol audit mismatch"
fi

if [[ -f "${task_dir_testssl}/cert_info.txt" ]] && \
   grep -q "Common Name.*corp.local" "${task_dir_testssl}/cert_info.txt"; then
    pass "Testssl engine writes certificate details into cert_info.txt"
else
    fail "Testssl certificate info mismatch"
fi

# -----------------------------------------------------------------------------
# UT-04: Native OpenSSL Fallback Parsing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native OpenSSL Fallback Parsing"

mock_openssl="$TEST_ROOT/bin/mock_openssl"
cat <<'EOF' > "$mock_openssl"
#!/usr/bin/env bash
subcmd="$1"
shift

if [[ "$subcmd" == "s_client" ]]; then
    has_tls12=false
    has_tls13=false
    for arg in "$@"; do
        [[ "$arg" == "-tls1_2" ]] && has_tls12=true
        [[ "$arg" == "-tls1_3" ]] && has_tls13=true
        [[ "$arg" == "-ssl2" || "$arg" == "-ssl3" || "$arg" == "-tls1" || "$arg" == "-tls1_1" ]] && exit 1
    done

    if [[ "$has_tls12" == true || "$has_tls13" == true ]]; then
        printf 'CONNECTED(00000003)\r\n'
        printf 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\r\n'
        printf 'Protocol  : TLSv1.3\r\n'
        exit 0
    fi

    # Certificate dump invocation
    cat <<'CERT_EOF'
-----BEGIN CERTIFICATE-----
MIIEczCCA1ugAwIBAgIQAf2...
-----END CERTIFICATE-----
CERT_EOF
    exit 0
elif [[ "$subcmd" == "x509" ]]; then
    cat <<'X509_EOF'
Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = Let's Encrypt, CN = R3
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Apr  1 00:00:00 2026 GMT
        Subject: CN = fallback.corp
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:fallback.corp, DNS:www.fallback.corp
X509_EOF
    exit 0
fi
exit 1
EOF
chmod +x "$mock_openssl"

task_dir_openssl="$TEST_ROOT/targets/openssl_test/tls"
TLS_TESTSSL_BIN="none" \
TLS_OPENSSL_BIN="$mock_openssl" \
module_tls_run "https://fallback.corp" "url_https" "$task_dir_openssl"

if [[ -f "${task_dir_openssl}/cert_info.txt" ]] && \
   grep -q "Subject: CN = fallback.corp" "${task_dir_openssl}/cert_info.txt" && \
   grep -q "Issuer: C = US, O = Let's Encrypt, CN = R3" "${task_dir_openssl}/cert_info.txt" && \
   grep -q "DNS:fallback.corp" "${task_dir_openssl}/cert_info.txt"; then
    pass "Fallback openssl extracts X.509 certificate metadata and SANs"
else
    fail "OpenSSL certificate metadata parsing failed"
fi

if [[ -f "${task_dir_openssl}/tls_audit.txt" ]] && \
   grep -q -E "^TLSv1\.3"$'\t'"SUPPORTED"$'\t' "${task_dir_openssl}/tls_audit.txt" && \
   grep -q -E "^SSLv3"$'\t'"NOT_SUPPORTED" "${task_dir_openssl}/tls_audit.txt"; then
    pass "Fallback openssl performs protocol handshake negotiation"
else
    fail "OpenSSL protocol negotiation audit failed"
fi

# -----------------------------------------------------------------------------
# UT-05: Protocol Vulnerability Summary Reporting
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Protocol Vulnerability Summary Reporting"

if [[ -f "${task_dir_openssl}/output.txt" ]] && \
   grep -q "TLS audit complete: 0 critical protocol vulnerabilities identified" "${task_dir_openssl}/output.txt"; then
    pass "Correctly summarizes secure TLS state in human-readable footer"
else
    fail "TLS summary report footer mismatch"
fi

# -----------------------------------------------------------------------------
# UT-06: Clean Inactive State
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Clean Inactive State"

task_dir_empty="$TEST_ROOT/targets/empty_test/tls"
TLS_TESTSSL_BIN="$mock_empty" \
TLS_OPENSSL_BIN="$mock_empty" \
module_tls_run "https://empty.org" "url_https" "$task_dir_empty"

if [[ -f "${task_dir_empty}/tls_audit.txt" ]] && \
   grep -q "TLS Configuration" "${task_dir_empty}/output.txt"; then
    pass "Handles empty handshake response cleanly with exit code 0"
else
    fail "Clean empty TLS state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_openssl" 2>/dev/null || stat -f '%p' "$task_dir_openssl" 2>/dev/null)"
cert_perm="$(stat -c '%a' "${task_dir_openssl}/cert_info.txt" 2>/dev/null || stat -f '%p' "${task_dir_openssl}/cert_info.txt" 2>/dev/null)"
audit_perm="$(stat -c '%a' "${task_dir_openssl}/tls_audit.txt" 2>/dev/null || stat -f '%p' "${task_dir_openssl}/tls_audit.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_openssl}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_openssl}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
cert_perm="${cert_perm: -3}"
audit_perm="${audit_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$cert_perm" == "640" && "$audit_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all TLS artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, cert=$cert_perm, audit=$audit_perm, output=$out_perm"
fi

test_summary
