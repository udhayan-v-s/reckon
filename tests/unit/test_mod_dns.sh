#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# DNS Reconnaissance Module Unit Tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

DNS_MODULE="$PROJECT_ROOT/modules/network/dns.sh"
readonly DNS_MODULE

if [[ ! -f "$DNS_MODULE" || ! -x "$DNS_MODULE" ]]; then
    printf 'Error: DNS reconnaissance module missing or not executable at %s\n' "$DNS_MODULE" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-dns-test.XXXXXX")" || {
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

    printf '%s\n' "DNS reconnaissance module unit tests completed."
}

printf '%s\n' "RECKON - DNS Reconnaissance Module Unit Tests"
printf '%s\n' "---------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Target Type Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Target Type Validation"

# Test 1: Rejects execution with insufficient arguments (< 3)
if ! "$DNS_MODULE" "example.com" "domain" >/dev/null 2>&1; then
    pass "dns module rejects execution with insufficient arguments (< 3)"
else
    fail "dns module accepted execution with only 2 arguments"
fi

# Test 2: Rejects execution with empty target
TASK_DIR_1="$TEST_ROOT/task_out_1"
if ! "$DNS_MODULE" "" "domain" "$TASK_DIR_1" >/dev/null 2>&1; then
    pass "dns module rejects empty target argument"
else
    fail "dns module accepted empty target"
fi

# Test 3: Rejects incompatible target type (e.g. ipv4_cidr)
TASK_DIR_INCOMPAT="$TEST_ROOT/incompat_target"
if ! "$DNS_MODULE" "192.168.1.0/24" "ipv4_cidr" "$TASK_DIR_INCOMPAT" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_INCOMPAT/output.txt" ]] && grep -q "Incompatible target type" "$TASK_DIR_INCOMPAT/output.txt"; then
        pass "dns module rejects incompatible target types (e.g. ipv4_cidr) and records failure"
    else
        fail "dns module did not write expected failure notice in output.txt"
    fi
else
    fail "dns module succeeded when invoked against incompatible ipv4_cidr target"
fi

# Test 3b: Accepts raw IPv4 target for reverse DNS lookup
TASK_DIR_IPV4="$TEST_ROOT/ipv4_target"
if "$DNS_MODULE" "93.184.216.34" "ipv4" "$TASK_DIR_IPV4" >/dev/null 2>&1; then
    if [[ -f "$TASK_DIR_IPV4/dns_records.txt" && -f "$TASK_DIR_IPV4/output.txt" ]] && \
       grep -q "Reverse DNS (PTR Lookup)" "$TASK_DIR_IPV4/output.txt"; then
        pass "dns module accepts raw IPv4 target and performs reverse DNS lookup"
    else
        fail "dns module failed to generate reverse DNS output for IPv4 target"
    fi
else
    fail "dns module failed when invoked against valid IPv4 target"
fi

# -----------------------------------------------------------------------------
# UT-02: Record Resolution via Mocked Dig
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Record Resolution via Mocked Dig"

MOCK_DIG_SCRIPT="$TEST_ROOT/mock_dig.sh"
cat > "$MOCK_DIG_SCRIPT" <<'EOF'
#!/usr/bin/env bash
# Mock dig dispatcher supporting +short and AXFR queries

# Handle reverse lookup (-x)
for arg in "$@"; do
    if [[ "$arg" == "-x" ]]; then
        ip="${@: -1}"
        if [[ "$ip" == "93.184.216.34" ]]; then
            printf "example.com.\n"
        fi
        exit 0
    fi
done

# Handle AXFR
if [[ "$*" == *"AXFR"* ]]; then
    # If queried against vulnerable nameserver, return mock zone
    if [[ "$*" == *"@vuln-ns.example.com"* ]]; then
        cat <<'ZONE'
example.com. IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
example.com. IN NS vuln-ns.example.com.
internal.example.com. IN A 10.10.10.5
secret.example.com. IN A 10.10.10.99
example.com. IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
ZONE
        exit 0
    else
        printf ";; Transfer failed.\n"
        exit 1
    fi
fi

# Standard +short queries
# Target domain is the last argument
domain="${@: -1}"
# Query type is second-to-last argument
qtype="${@: -2:1}"

case "$qtype" in
    A)
        printf "93.184.216.34\n"
        ;;
    AAAA)
        printf "2606:2800:220:1:248:1893:25c8:1946\n"
        ;;
    NS)
        printf "ns1.example.com.\nns2.example.com.\n"
        ;;
    MX)
        printf "10 mail.example.com.\n20 backup.example.com.\n"
        ;;
    TXT)
        printf "\"v=spf1 -all\"\n\"google-site-verification=abc123xyz\"\n"
        ;;
    SOA)
        printf "ns1.example.com. hostmaster.example.com. 2024010101 7200 3600 1209600 3600\n"
        ;;
    CNAME)
        # None for apex domain
        ;;
    *)
        ;;
esac
exit 0
EOF
chmod +x "$MOCK_DIG_SCRIPT"

TASK_DIR_SECURE="$TEST_ROOT/dns_secure"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DIG_BIN="$MOCK_DIG_SCRIPT"
    "$DNS_MODULE" "example.com" "domain" "$TASK_DIR_SECURE" >/dev/null 2>&1
)
dns_status=$?

# Test 4: Resolves A and AAAA records, including reverse PTR lookup
if (( dns_status == 0 )) && \
   grep -q "93.184.216.34 (PTR: example.com.)" "$TASK_DIR_SECURE/output.txt" && \
   grep -q "2606:2800:220:1:248:1893:25c8:1946" "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module resolves A and AAAA records with reverse PTR annotations"
else
    fail "dns module failed to parse A/AAAA records or PTR annotation"
fi

# Test 5: Resolves NS nameservers
if grep -q "ns1.example.com." "$TASK_DIR_SECURE/output.txt" && \
   grep -q "ns2.example.com." "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module resolves and lists all authoritative name servers (NS)"
else
    fail "dns module failed to list NS records in output.txt"
fi

# Test 6: Resolves MX mail exchanger records
if grep -q "10 mail.example.com." "$TASK_DIR_SECURE/output.txt" && \
   grep -q "20 backup.example.com." "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module resolves and lists mail exchanger (MX) records"
else
    fail "dns module failed to list MX records in output.txt"
fi

# Test 7: Resolves TXT SPF and verification records
if grep -q "v=spf1 -all" "$TASK_DIR_SECURE/output.txt" && \
   grep -q "google-site-verification=abc123xyz" "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module resolves and lists TXT verification and SPF records"
else
    fail "dns module failed to list TXT records in output.txt"
fi

# Test 8: Resolves SOA authority records
if grep -q "ns1.example.com. hostmaster.example.com." "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module extracts and logs primary Start of Authority (SOA) record"
else
    fail "dns module failed to extract SOA record in output.txt"
fi

# Test 9: CNAME alias record resolution
TASK_DIR_CNAME="$TEST_ROOT/dns_cname"
MOCK_DIG_CNAME="$TEST_ROOT/mock_dig_cname.sh"
cat > "$MOCK_DIG_CNAME" <<'EOF'
#!/usr/bin/env bash
qtype="${@: -2:1}"
if [[ "$qtype" == "CNAME" ]]; then
    printf "cdn.cloudflare.net.\n"
elif [[ "$qtype" == "A" ]]; then
    printf "104.16.1.1\n"
fi
exit 0
EOF
chmod +x "$MOCK_DIG_CNAME"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DIG_BIN="$MOCK_DIG_CNAME"
    "$DNS_MODULE" "shop.example.com" "hostname" "$TASK_DIR_CNAME" >/dev/null 2>&1
)
if grep -q "CNAME Record             : cdn.cloudflare.net." "$TASK_DIR_CNAME/output.txt"; then
    pass "dns module detects and documents canonical name (CNAME) aliases"
else
    fail "dns module failed to document CNAME alias"
fi

# -----------------------------------------------------------------------------
# UT-03: Zone Transfer (AXFR) Security Checks
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Zone Transfer (AXFR) Security Checks"

# Test 10: Reports secure status when nameservers refuse AXFR
if grep -q "Zone Transfer Status     : Secure (AXFR refused or unavailable on tested nameservers)" "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module verifies nameservers and reports Secure when AXFR queries are refused"
else
    fail "dns module failed to report secure AXFR status in output.txt"
fi

# Test 11: Detects and documents vulnerable zone transfers
TASK_DIR_VULN="$TEST_ROOT/dns_vuln"
MOCK_DIG_VULN="$TEST_ROOT/mock_dig_vuln.sh"
cat > "$MOCK_DIG_VULN" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"AXFR"* ]]; then
    cat <<'ZONE'
example.com. IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
example.com. IN NS vuln-ns.example.com.
internal-hr.example.com. IN A 10.10.10.5
secret-vault.example.com. IN A 10.10.10.99
example.com. IN SOA ns1.example.com. admin.example.com. 1 7200 3600 1209600 3600
ZONE
    exit 0
fi

qtype="${@: -2:1}"
case "$qtype" in
    NS)
        printf "vuln-ns.example.com.\n"
        ;;
    A)
        printf "93.184.216.34\n"
        ;;
    *)
        ;;
esac
exit 0
EOF
chmod +x "$MOCK_DIG_VULN"

(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DIG_BIN="$MOCK_DIG_VULN"
    "$DNS_MODULE" "example.com" "domain" "$TASK_DIR_VULN" >/dev/null 2>&1
)

if grep -q "VULNERABLE (Zone transfer succeeded on: vuln-ns.example.com)" "$TASK_DIR_VULN/output.txt" && \
   [[ -f "$TASK_DIR_VULN/zone_transfer_vuln-ns.example.com.txt" ]] && \
   grep -q "secret-vault.example.com." "$TASK_DIR_VULN/zone_transfer_vuln-ns.example.com.txt"; then
    pass "dns module flags vulnerable AXFR zone transfers and saves leaked records to file"
else
    fail "dns module failed to capture vulnerable zone transfer finding"
fi

# -----------------------------------------------------------------------------
# UT-04: Structured Artifacts & File Permissions
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Structured Artifacts & File Permissions"

# Test 12: Generates clean tab-delimited dns_records.txt
if [[ -f "$TASK_DIR_SECURE/dns_records.txt" ]] && \
   grep -q -P "^A\t93.184.216.34" "$TASK_DIR_SECURE/dns_records.txt" && \
   grep -q -P "^NS\tns1.example.com." "$TASK_DIR_SECURE/dns_records.txt" && \
   grep -q -P "^MX\t10 mail.example.com." "$TASK_DIR_SECURE/dns_records.txt"; then
    pass "dns module generates structured tab-separated dns_records.txt artifact"
else
    fail "dns module missing expected tab-separated records in dns_records.txt"
fi

# Test 13: Standardized output.txt structure with header, sections, and footer
if grep -q "RECKON Network Reconnaissance - DNS Reconnaissance (dns)" "$TASK_DIR_SECURE/output.txt" && \
   grep -q "\[--- Address Records (A / AAAA) ---\]" "$TASK_DIR_SECURE/output.txt" && \
   grep -q "\[--- Name Servers (NS) ---\]" "$TASK_DIR_SECURE/output.txt" && \
   grep -q "Status: COMPLETED" "$TASK_DIR_SECURE/output.txt"; then
    pass "dns module generates standard output.txt with header, sections, and footer"
else
    fail "dns module output.txt structural mismatch"
fi

# Test 14: Verifies secure permissions (0640) on generated artifacts
rec_perm="$(stat -c "%a" "$TASK_DIR_SECURE/dns_records.txt" 2>/dev/null || stat -f "%Lp" "$TASK_DIR_SECURE/dns_records.txt" 2>/dev/null)"
out_perm="$(stat -c "%a" "$TASK_DIR_SECURE/output.txt" 2>/dev/null || stat -f "%Lp" "$TASK_DIR_SECURE/output.txt" 2>/dev/null)"
if [[ "$rec_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "dns module sets secure permissions (0640) on generated artifacts"
else
    fail "dns module artifact permissions mismatch: records=$rec_perm, output=$out_perm (expected 640)"
fi

test_summary
