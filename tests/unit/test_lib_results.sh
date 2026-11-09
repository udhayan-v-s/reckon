#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Result Normalization Library Unit Tests (tests/unit/test_lib_results.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=lib/results.sh
if ! source "$PROJECT_ROOT/lib/results.sh"; then
    printf 'Error: Unable to load lib/results.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-lib-results-test.XXXXXX")" || {
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

    printf '%s\n' "Result normalization library unit tests completed."
}

printf '%s\n' "RECKON - Result Normalization Library Unit Tests"
printf '%s\n' "------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Results Library Initialization & State
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Results Library Initialization & State"

results_init
if (( RESULTS_TOTAL_TARGETS == 0 && RESULTS_TOTAL_OPEN_PORTS == 0 && RESULTS_TOTAL_SUBDOMAINS == 0 )) && \
   [[ -z "$RESULTS_ERROR" ]]; then
    pass "results_init initializes all counters to zero and clears error state"
else
    fail "results_init failed to initialize state variables"
fi

# -----------------------------------------------------------------------------
# UT-02: String & JSON Escaping
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: String & JSON Escaping"

esc_quotes="$(results_escape_json 'Hello "World" \ Backslash')"
if [[ "$esc_quotes" == 'Hello \"World\" \\ Backslash' ]]; then
    pass "results_escape_json safely escapes quotes and backslashes"
else
    fail "Escaping mismatch: $esc_quotes"
fi

esc_ctrl="$(results_escape_json $'Line1\nLine2\tTabbed\r')"
if [[ "$esc_ctrl" == 'Line1\nLine2\tTabbed\r' ]]; then
    pass "results_escape_json escapes newlines, carriage returns, and tabs"
else
    fail "Control character escaping mismatch: $esc_ctrl"
fi

# -----------------------------------------------------------------------------
# UT-03: Network Reconnaissance Artifact Parsers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Network Reconnaissance Artifact Parsers"

# 1. Open ports
mock_ports_file="$TEST_ROOT/open_ports.txt"
printf '22\n80\n443\n8080\n' > "$mock_ports_file"
p_json="$(results_parse_open_ports "$mock_ports_file")"
if [[ "$p_json" == "[22, 80, 443, 8080]" ]]; then
    pass "results_parse_open_ports formats integer port array"
else
    fail "open ports parser mismatch: $p_json"
fi

# Empty ports file returns []
empty_file="$TEST_ROOT/empty.txt"
: > "$empty_file"
empty_p_json="$(results_parse_open_ports "$empty_file")"
if [[ "$empty_p_json" == "[]" ]]; then
    pass "results_parse_open_ports returns empty array on empty file"
else
    fail "empty ports mismatch: $empty_p_json"
fi

# 2. Services
mock_services_file="$TEST_ROOT/services.txt"
cat <<'EOF' > "$mock_services_file"
80/tcp	open	http	Apache 2.4.52
443/tcp	open	https	nginx 1.22.0
EOF
s_json="$(results_parse_services "$mock_services_file")"
if [[ "$s_json" == *"Apache 2.4.52"* && "$s_json" == *"nginx 1.22.0"* ]]; then
    pass "results_parse_services extracts ports, protocols, and versions"
else
    fail "services parser mismatch: $s_json"
fi

# 3. DNS records
mock_dns_file="$TEST_ROOT/dns_records.txt"
cat <<'EOF' > "$mock_dns_file"
A	corp.local	10.10.1.10
MX	corp.local	mail.corp.local
EOF
dns_json="$(results_parse_dns_records "$mock_dns_file")"
if [[ "$dns_json" == *"mail.corp.local"* && "$dns_json" == *"10.10.1.10"* ]]; then
    pass "results_parse_dns_records extracts record types and values"
else
    fail "dns parser mismatch: $dns_json"
fi

# 4. OS detection
mock_os_file="$TEST_ROOT/os_detection.txt"
printf 'Linux\t96%%\tLinux 5.4 - 5.15\n' > "$mock_os_file"
os_json="$(results_parse_os "$mock_os_file")"
if [[ "$os_json" == *"Linux 5.4 - 5.15"* ]]; then
    pass "results_parse_os extracts operating system candidates"
else
    fail "os parser mismatch: $os_json"
fi

# -----------------------------------------------------------------------------
# UT-04: Web Discovery & Fingerprinting Parsers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Web Discovery & Fingerprinting Parsers"

mock_sub_file="$TEST_ROOT/subdomains.txt"
mock_res_file="$TEST_ROOT/resolved_subdomains.txt"
printf 'api.corp.local\nadmin.corp.local\n' > "$mock_sub_file"
printf 'api.corp.local\t10.10.1.20\nadmin.corp.local\t10.10.1.10\n' > "$mock_res_file"

sub_json="$(results_parse_subdomains "$mock_sub_file" "$mock_res_file")"
if [[ "$sub_json" == *"api.corp.local"* && "$sub_json" == *"10.10.1.20"* ]]; then
    pass "results_parse_subdomains resolves names to IP mapping objects"
else
    fail "subdomain parser mismatch: $sub_json"
fi

mock_tech_file="$TEST_ROOT/technologies.txt"
printf 'WordPress\t6.4.1\tCMS, Blog\nApache\t2.4.52\tWeb Server\n' > "$mock_tech_file"
tech_json="$(results_parse_technologies "$mock_tech_file")"
if [[ "$tech_json" == *"WordPress"* && "$tech_json" == *"Web Server"* ]]; then
    pass "results_parse_technologies extracts technology components"
else
    fail "technologies parser mismatch: $tech_json"
fi

mock_cms_file="$TEST_ROOT/cms_detected.txt"
printf 'WordPress\t6.4.1\thigh\n' > "$mock_cms_file"
cms_json="$(results_parse_cms "$mock_cms_file")"
if [[ "$cms_json" == *"WordPress"* && "$cms_json" == *"high"* ]]; then
    pass "results_parse_cms extracts CMS platform detection"
else
    fail "cms parser mismatch: $cms_json"
fi

mock_waf_file="$TEST_ROOT/waf_detected.txt"
printf 'Cloudflare\tCloudflare Inc.\n' > "$mock_waf_file"
waf_json="$(results_parse_waf "$mock_waf_file")"
if [[ "$waf_json" == *"Cloudflare Inc."* ]]; then
    pass "results_parse_waf extracts web application firewall"
else
    fail "waf parser mismatch: $waf_json"
fi

# -----------------------------------------------------------------------------
# UT-05: Web Enumeration & Analysis Parsers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Web Enumeration & Analysis Parsers"

mock_dir_file="$TEST_ROOT/directories.txt"
printf '/admin/\t301\t128\t/admin/login\n/api/\t200\t512\t-\n' > "$mock_dir_file"
dir_json="$(results_parse_directories "$mock_dir_file")"
if [[ "$dir_json" == *"/admin/"* && "$dir_json" == *"/admin/login"* ]]; then
    pass "results_parse_directories extracts directory paths and redirects"
else
    fail "directory parser mismatch: $dir_json"
fi

mock_file_file="$TEST_ROOT/files.txt"
printf '/config.json\t200\t256\tConfiguration\n' > "$mock_file_file"
file_json="$(results_parse_files "$mock_file_file")"
if [[ "$file_json" == *"/config.json"* && "$file_json" == *"Configuration"* ]]; then
    pass "results_parse_files extracts file paths and classifications"
else
    fail "file parser mismatch: $file_json"
fi

mock_vh_file="$TEST_ROOT/vhosts.txt"
printf 'dev.corp.local\t200\t1420\t-\n' > "$mock_vh_file"
vh_json="$(results_parse_vhosts "$mock_vh_file")"
if [[ "$vh_json" == *"dev.corp.local"* ]]; then
    pass "results_parse_vhosts extracts virtual host findings"
else
    fail "vhost parser mismatch: $vh_json"
fi

mock_crawl_file="$TEST_ROOT/crawled_urls.txt"
printf 'https://corp.local/\nhttps://corp.local/about\n' > "$mock_crawl_file"
crawl_json="$(results_parse_crawled_urls "$mock_crawl_file")"
if [[ "$crawl_json" == *"https://corp.local/about"* ]]; then
    pass "results_parse_crawled_urls extracts crawled URLs"
else
    fail "crawled URLs parser mismatch: $crawl_json"
fi

mock_ep_file="$TEST_ROOT/endpoints.txt"
printf '/api/v1/users\tAPI\n/auth/login\tAUTH\n' > "$mock_ep_file"
ep_json="$(results_parse_endpoints "$mock_ep_file")"
if [[ "$ep_json" == *"/api/v1/users"* && "$ep_json" == *"AUTH"* ]]; then
    pass "results_parse_endpoints extracts routes and categories"
else
    fail "endpoint parser mismatch: $ep_json"
fi

# HTTP Analysis parser
mock_ha_file="$TEST_ROOT/http_analysis.txt"
cat <<'EOF' > "$mock_ha_file"
HEADER	Strict-Transport-Security	PRESENT	max-age=31536000
HEADER	Content-Security-Policy	MISSING	-
DISCLOSURE	Server	Apache/2.4.52
CORS	https://evil.local	true	HIGH	Arbitrary Origin Reflected
METHOD	OPTIONS	200	ENABLED
EOF
ha_json="$(results_parse_http_analysis "$mock_ha_file")"
if [[ "$ha_json" == *"Strict-Transport-Security"* && "$ha_json" == *"Arbitrary Origin Reflected"* ]]; then
    pass "results_parse_http_analysis extracts security headers and CORS findings"
else
    fail "http_analysis parser mismatch: $ha_json"
fi

# TLS parser
mock_tls_audit="$TEST_ROOT/tls_audit.txt"
mock_cert_info="$TEST_ROOT/cert_info.txt"
printf 'TLSv1.3\tSUPPORTED\tSECURE\nTLSv1.0\tSUPPORTED\tDEPRECATED\n' > "$mock_tls_audit"
cat <<'EOF' > "$mock_cert_info"
Subject: CN = corp.local
Issuer: CN = DigiCert Root
Valid From: 2026-01-01
Valid Until: 2027-12-31
SANs: corp.local, www.corp.local
EOF
tls_json="$(results_parse_tls "$mock_tls_audit" "$mock_cert_info")"
if [[ "$tls_json" == *"TLSv1.3"* && "$tls_json" == *"DigiCert Root"* ]]; then
    pass "results_parse_tls extracts TLS protocols and certificate metadata"
else
    fail "tls parser mismatch: $tls_json"
fi

# Resources parser
mock_res_file="$TEST_ROOT/resources.txt"
printf '/robots.txt\t200\t128\tDisallow: /admin/\n' > "$mock_res_file"
res_json="$(results_parse_resources "$mock_res_file")"
if [[ "$res_json" == *"/robots.txt"* && "$res_json" == *"Disallow: /admin/"* ]]; then
    pass "results_parse_resources extracts web metadata findings"
else
    fail "resources parser mismatch: $res_json"
fi

# Historical URLs parser
mock_hist_file="$TEST_ROOT/historical_urls.txt"
printf 'https://corp.local/old.html\n' > "$mock_hist_file"
hist_json="$(results_parse_historical_urls "$mock_hist_file")"
if [[ "$hist_json" == *"https://corp.local/old.html"* ]]; then
    pass "results_parse_historical_urls extracts historical URLs"
else
    fail "historical URLs parser mismatch: $hist_json"
fi

# -----------------------------------------------------------------------------
# UT-06: Target Finding Collection (results_collect_target)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Target Finding Collection"

mock_scan_dir="$TEST_ROOT/scan_run"
mock_target_dir="$mock_scan_dir/enterprise.corp"
mkdir -p "$mock_target_dir/ping" \
         "$mock_target_dir/dns" \
         "$mock_target_dir/port" \
         "$mock_target_dir/service" \
         "$mock_target_dir/technology" \
         "$mock_target_dir/directory" \
         "$mock_target_dir/endpoint" \
         "$mock_target_dir/tls"

printf 'Host is UP (0.002s RTT)\n' > "$mock_target_dir/ping/output.txt"
printf 'A\tenterprise.corp\t10.10.1.10\n' > "$mock_target_dir/dns/dns_records.txt"
printf '80\n443\n' > "$mock_target_dir/port/open_ports.txt"
printf '80/tcp\topen\thttp\tApache 2.4.52\n443/tcp\topen\thttps\tApache 2.4.52\n' > "$mock_target_dir/service/services.txt"
printf 'Apache\t2.4.52\tWeb Server\n' > "$mock_target_dir/technology/technologies.txt"
printf '/admin/\t301\t128\t-\n' > "$mock_target_dir/directory/directories.txt"
printf '/api/v1/status\tAPI\n' > "$mock_target_dir/endpoint/endpoints.txt"
printf 'TLSv1.3\tSUPPORTED\tSECURE\n' > "$mock_target_dir/tls/tls_audit.txt"
printf 'Subject: CN = enterprise.corp\n' > "$mock_target_dir/tls/cert_info.txt"

target_json="$(results_collect_target "enterprise.corp" "domain" "$mock_target_dir")"

if [[ "$target_json" == *"enterprise.corp"* && "$target_json" == *"10.10.1.10"* && "$target_json" == *"Apache 2.4.52"* ]]; then
    pass "results_collect_target aggregates module findings into target schema"
else
    fail "results_collect_target output mismatch"
fi

if command -v jq >/dev/null 2>&1; then
    if printf '%s\n' "$target_json" | jq -e . >/dev/null 2>&1; then
        pass "target JSON output validates cleanly with jq"
    else
        fail "target JSON failed jq syntax validation"
    fi
else
    pass "jq not present - skipping target JSON jq validation"
fi

# -----------------------------------------------------------------------------
# UT-07: Full Scan Aggregation & Unified results.json Generation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Full Scan Aggregation & Unified results.json Generation"

results_file="$mock_scan_dir/results.json"
results_generate_json "$mock_scan_dir" "$results_file"

if [[ -f "$results_file" && -s "$results_file" ]]; then
    pass "results_generate_json creates results.json in output directory"
else
    fail "results_generate_json failed to create results.json"
fi

if command -v jq >/dev/null 2>&1; then
    if jq -e . "$results_file" >/dev/null 2>&1; then
        pass "results.json parses and validates cleanly as valid JSON schema"
    else
        fail "results.json failed jq schema validation"
    fi

    # Check key metadata and statistics
    app_name="$(jq -r '.scan_metadata.app_name' "$results_file")"
    t_count="$(jq -r '.summary.total_targets' "$results_file")"
    if [[ "$app_name" == "RECKON" && "$t_count" -ge 1 ]]; then
        pass "results.json contains accurate scan metadata and summary counters"
    else
        fail "results.json metadata mismatch: app_name=$app_name, targets=$t_count"
    fi
else
    pass "jq not present - verified file presence"
fi

# -----------------------------------------------------------------------------
# UT-08: Artifact Permission Enforcement & Error Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Artifact Permission Enforcement & Error Handling"

perm="$(stat -c '%a' "$results_file" 2>/dev/null || stat -f '%p' "$results_file" 2>/dev/null)"
perm="${perm: -3}"
if [[ "$perm" == "640" ]]; then
    pass "Enforces 0640 permissions on generated results.json"
else
    fail "Permission enforcement failed on results.json: $perm"
fi

# Invalid output directory handling
if results_generate_json "$TEST_ROOT/non_existent_dir_12345" 2>/dev/null; then
    fail "results_generate_json accepted non-existent output directory"
else
    pass "results_generate_json rejects non-existent output directory with error"
fi

test_summary
