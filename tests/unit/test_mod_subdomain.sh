#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Subdomain Enumeration Module Unit Tests (test_mod_subdomain.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/subdomain.sh
if ! source "$PROJECT_ROOT/modules/web/subdomain.sh"; then
    printf 'Error: Unable to load modules/web/subdomain.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-subdomain-test.XXXXXX")" || {
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

    printf '%s\n' "Subdomain enumeration module unit tests completed."
}

printf '%s\n' "RECKON - Subdomain Enumeration Module Unit Tests"
printf '%s\n' "------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_subdomain_run "example.com" "domain" 2>/dev/null; then
    fail "module_subdomain_run accepted fewer than 3 arguments"
else
    pass "module_subdomain_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_subdomain_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_subdomain_run accepted empty target"
else
    pass "module_subdomain_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_subdomain_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_subdomain_run accepted empty target type"
else
    pass "module_subdomain_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_subdomain_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_subdomain_run accepted empty task directory"
else
    pass "module_subdomain_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

# Test 1: Supported domain target returns 0
task_compat_domain="$TEST_ROOT/targets/domain_test/subdomain"
mock_empty_subfinder="$TEST_ROOT/bin/mock_empty_subfinder"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty_subfinder"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty_subfinder"

SUBDOMAIN_SUBFINDER_BIN="$mock_empty_subfinder" \
SUBDOMAIN_CURL_BIN="$mock_empty_subfinder" \
SUBDOMAIN_DIG_BIN="$mock_empty_subfinder" \
module_subdomain_run "corp.local" "domain" "$task_compat_domain"
if [[ -f "${task_compat_domain}/output.txt" ]] && grep -q "RECKON Web Reconnaissance - Subdomain Enumeration" "${task_compat_domain}/output.txt"; then
    pass "module_subdomain_run accepts valid domain target"
else
    fail "module_subdomain_run failed on domain target"
fi

# Test 2: Incompatible IPv4 target skipped gracefully with notice
task_incompat_ip="$TEST_ROOT/targets/ip_test/subdomain"
if module_subdomain_run "192.168.1.1" "ipv4" "$task_incompat_ip"; then
    if [[ -f "${task_incompat_ip}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_ip}/output.txt"; then
        pass "module_subdomain_run gracefully skips IPv4 target with execution notice"
    else
        fail "module_subdomain_run did not write SKIPPED notice for IPv4"
    fi
else
    fail "module_subdomain_run returned error code for IPv4 target"
fi

# Test 3: Incompatible URL target skipped gracefully
task_incompat_url="$TEST_ROOT/targets/url_test/subdomain"
if module_subdomain_run "http://example.com" "url_http" "$task_incompat_url"; then
    if [[ -f "${task_incompat_url}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_incompat_url}/output.txt"; then
        pass "module_subdomain_run gracefully skips URL target with execution notice"
    else
        fail "module_subdomain_run did not write SKIPPED notice for URL"
    fi
else
    fail "module_subdomain_run returned error code for URL target"
fi

# -----------------------------------------------------------------------------
# UT-03: Subfinder & DNSX Primary Engines
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Subfinder & DNSX Primary Engines"

mock_subfinder="$TEST_ROOT/bin/mock_subfinder"
cat <<'EOF' > "$mock_subfinder"
#!/usr/bin/env bash
printf 'api.corp.local\n'
printf 'vpn.corp.local\n'
printf 'mail.corp.local\n'
printf 'www.corp.local\n'
printf 'dev.corp.local\n'
exit 0
EOF
chmod +x "$mock_subfinder"

mock_dnsx="$TEST_ROOT/bin/mock_dnsx"
cat <<'EOF' > "$mock_dnsx"
#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l) list_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r sub || [[ -n "$sub" ]]; do
        case "$sub" in
            api.corp.local) printf '%s [10.10.1.50]\n' "$sub" ;;
            vpn.corp.local) printf '%s [10.10.1.51]\n' "$sub" ;;
            www.corp.local) printf '%s [10.10.1.80]\n' "$sub" ;;
            mail.corp.local) printf '%s [10.10.1.25]\n' "$sub" ;;
            dev.corp.local) printf '%s\n' "$sub" ;; # unresolved
        esac
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$mock_dnsx"

task_dir_engines="$TEST_ROOT/targets/primary_engines/subdomain"
SUBDOMAIN_SUBFINDER_BIN="$mock_subfinder" \
SUBDOMAIN_DNSX_BIN="$mock_dnsx" \
module_subdomain_run "corp.local" "domain" "$task_dir_engines"

if [[ -f "${task_dir_engines}/subdomains.txt" ]] && \
   grep -q "^api.corp.local$" "${task_dir_engines}/subdomains.txt" && \
   grep -q "^vpn.corp.local$" "${task_dir_engines}/subdomains.txt" && \
   grep -q "^www.corp.local$" "${task_dir_engines}/subdomains.txt"; then
    pass "Subfinder engine enumerates unique discovered subdomains into subdomains.txt"
else
    fail "Subfinder engine failed to populate subdomains.txt"
fi

if [[ -f "${task_dir_engines}/resolved_subdomains.txt" ]] && \
   grep -q "api.corp.local.*10.10.1.50" "${task_dir_engines}/resolved_subdomains.txt" && \
   grep -q "vpn.corp.local.*10.10.1.51" "${task_dir_engines}/resolved_subdomains.txt"; then
    pass "DNSX engine resolves subdomains with IP addresses into resolved_subdomains.txt"
else
    fail "DNSX engine failed to populate resolved_subdomains.txt"
fi

if [[ -f "${task_dir_engines}/output.txt" ]] && \
   grep -q "Discovery Engine.*subfinder" "${task_dir_engines}/output.txt" && \
   grep -q "Resolver Engine.*dnsx" "${task_dir_engines}/output.txt" && \
   grep -q "Total Discovered.*5" "${task_dir_engines}/output.txt"; then
    pass "Formats comprehensive summary report with engine names and totals"
else
    fail "Formatted output report mismatch in $task_dir_engines"
fi

# -----------------------------------------------------------------------------
# UT-04: Subdomain Sanitization & Scope Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Subdomain Sanitization & Scope Validation"

mock_subfinder_dirty="$TEST_ROOT/bin/mock_subfinder_dirty"
cat <<'EOF' > "$mock_subfinder_dirty"
#!/usr/bin/env bash
printf '*.corp.local\n'             # Wildcard should be sanitized
printf 'API.CORP.LOCAL\n'           # Uppercase should be lowercased
printf 'evil-corp.com\n'            # Out of scope domain should be ignored
printf 'sub.another.com\n'          # Out of scope domain should be ignored
printf 'portal.corp.local\r\n'      # Trailing CR should be stripped
exit 0
EOF
chmod +x "$mock_subfinder_dirty"

task_dir_clean="$TEST_ROOT/targets/clean_test/subdomain"
SUBDOMAIN_SUBFINDER_BIN="$mock_subfinder_dirty" \
SUBDOMAIN_DNSX_BIN="non_existent" \
SUBDOMAIN_DIG_BIN="non_existent" \
module_subdomain_run "corp.local" "domain" "$task_dir_clean"

if [[ -f "${task_dir_clean}/subdomains.txt" ]] && \
   grep -q "^corp.local$" "${task_dir_clean}/subdomains.txt" && \
   grep -q "^api.corp.local$" "${task_dir_clean}/subdomains.txt" && \
   grep -q "^portal.corp.local$" "${task_dir_clean}/subdomains.txt" && \
   ! grep -q "evil-corp.com" "${task_dir_clean}/subdomains.txt" && \
   ! grep -q "another.com" "${task_dir_clean}/subdomains.txt"; then
    pass "Sanitizes wildcards, lowercases FQDNs, and strictly enforces root domain scope"
else
    fail "Sanitization or domain scope filtering failed"
fi

# -----------------------------------------------------------------------------
# UT-05: Fallback Certificate Transparency & Dictionary Discovery
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Fallback Certificate Transparency & Dictionary Discovery"

mock_curl_crt="$TEST_ROOT/bin/mock_curl_crt"
cat <<'EOF' > "$mock_curl_crt"
#!/usr/bin/env bash
# Simulates crt.sh JSON response
cat <<'JSON'
[
  {"name_value": "auth.example.com\nadmin.example.com"},
  {"name_value": "cloud.example.com"}
]
JSON
exit 0
EOF
chmod +x "$mock_curl_crt"

mock_dig_resolver="$TEST_ROOT/bin/mock_dig_resolver"
cat <<'EOF' > "$mock_dig_resolver"
#!/usr/bin/env bash
host_arg="${@: -1}"
case "$host_arg" in
    www.example.com) printf '93.184.216.34\n' ;;
    mail.example.com) printf '93.184.216.35\n' ;;
    *) exit 1 ;;
esac
exit 0
EOF
chmod +x "$mock_dig_resolver"

task_dir_fallback="$TEST_ROOT/targets/fallback_test/subdomain"
SUBDOMAIN_SUBFINDER_BIN="non_existent" \
SUBDOMAIN_DNSX_BIN="non_existent" \
SUBDOMAIN_CURL_BIN="$mock_curl_crt" \
SUBDOMAIN_DIG_BIN="$mock_dig_resolver" \
module_subdomain_run "example.com" "domain" "$task_dir_fallback"

if [[ -f "${task_dir_fallback}/subdomains.txt" ]] && \
   grep -q "auth.example.com" "${task_dir_fallback}/subdomains.txt" && \
   grep -q "admin.example.com" "${task_dir_fallback}/subdomains.txt" && \
   grep -q "cloud.example.com" "${task_dir_fallback}/subdomains.txt" && \
   grep -q "www.example.com" "${task_dir_fallback}/subdomains.txt"; then
    pass "Discovers subdomains via fallback crt.sh certificate logs and dictionary probing"
else
    fail "Fallback crt.sh and dictionary discovery mismatch"
fi

# -----------------------------------------------------------------------------
# UT-06: Native Dig DNS Fallback Resolver
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Native Dig DNS Fallback Resolver"

if [[ -f "${task_dir_fallback}/resolved_subdomains.txt" ]] && \
   grep -q "www.example.com.*93.184.216.34" "${task_dir_fallback}/resolved_subdomains.txt"; then
    pass "Resolves subdomains with native dig resolver when dnsx is absent"
else
    fail "Native dig resolver failed to resolve subdomains"
fi

# -----------------------------------------------------------------------------
# UT-07: Inactive / No Subdomains Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Inactive / No Subdomains Discovered"

mock_dead_sub="$TEST_ROOT/bin/mock_dead_sub"
cat <<'EOF' > "$mock_dead_sub"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_dead_sub"

task_dir_dead_sub="$TEST_ROOT/targets/dead_sub/subdomain"
SUBDOMAIN_SUBFINDER_BIN="$mock_dead_sub" \
SUBDOMAIN_CURL_BIN="$mock_dead_sub" \
SUBDOMAIN_DIG_BIN="$mock_dead_sub" \
module_subdomain_run "empty.domain" "domain" "$task_dir_dead_sub"

if [[ -f "${task_dir_dead_sub}/output.txt" ]] && \
   grep -q "No subdomains identified for target domain." "${task_dir_dead_sub}/output.txt" && \
   [[ ! -s "${task_dir_dead_sub}/subdomains.txt" ]]; then
    pass "Handles empty discovery results cleanly with exit code 0"
else
    fail "Empty discovery handling mismatch in $task_dir_dead_sub"
fi

# -----------------------------------------------------------------------------
# UT-08: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Artifact Permission Enforcement"

dir_perms="$(stat -c '%a' "$task_dir_engines" 2>/dev/null || stat -f '%p' "$task_dir_engines" 2>/dev/null)"
out_perms="$(stat -c '%a' "${task_dir_engines}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_engines}/output.txt" 2>/dev/null)"
subs_perms="$(stat -c '%a' "${task_dir_engines}/subdomains.txt" 2>/dev/null || stat -f '%p' "${task_dir_engines}/subdomains.txt" 2>/dev/null)"
res_perms="$(stat -c '%a' "${task_dir_engines}/resolved_subdomains.txt" 2>/dev/null || stat -f '%p' "${task_dir_engines}/resolved_subdomains.txt" 2>/dev/null)"

if [[ "$dir_perms" =~ 750$ && "$out_perms" =~ 640$ && "$subs_perms" =~ 640$ && "$res_perms" =~ 640$ ]]; then
    pass "Enforces 0750 directory and 0640 permissions across all subdomain artifacts"
else
    fail "Permissions check failed: dir=$dir_perms out=$out_perms subs=$subs_perms res=$res_perms"
fi

test_summary
