#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Reconnaissance Shared Framework Unit Tests (test_web_common.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/common.sh
if ! source "$PROJECT_ROOT/modules/web/common.sh"; then
    printf 'Error: Unable to load modules/web/common.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-web-common-test.XXXXXX")" || {
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

    printf '%s\n' "Web reconnaissance shared framework unit tests completed."
}

printf '%s\n' "RECKON - Web Reconnaissance Shared Framework Unit Tests"
printf '%s\n' "------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Framework Loading & Include Guard
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Framework Loading & Include Guard"

# Test 1: Include guard is set
if [[ "${_RECKON_MODULES_WEB_COMMON_LOADED:-}" == "1" ]]; then
    pass "Include guard _RECKON_MODULES_WEB_COMMON_LOADED is initialized"
else
    fail "Include guard _RECKON_MODULES_WEB_COMMON_LOADED is not set"
fi

# Test 2: Idempotent re-sourcing guard
# shellcheck source=modules/web/common.sh
if source "$PROJECT_ROOT/modules/web/common.sh"; then
    pass "Re-sourcing modules/web/common.sh succeeds idempotently"
else
    fail "Re-sourcing modules/web/common.sh failed"
fi

# -----------------------------------------------------------------------------
# UT-02: Context Initialization & Argument Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Context Initialization & Argument Validation"

# Test 1: Reject insufficient arguments
if web_mod_init "http://example.com" "url_http" 2>/dev/null; then
    fail "web_mod_init accepted fewer than 3 arguments"
else
    pass "web_mod_init rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if web_mod_init "" "url_http" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "web_mod_init accepted empty target"
else
    pass "web_mod_init rejects empty target"
fi

# Test 3: Reject empty target type
if web_mod_init "http://example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "web_mod_init accepted empty target type"
else
    pass "web_mod_init rejects empty target type"
fi

# Test 4: Reject empty task directory
if web_mod_init "http://example.com" "url_http" "" 2>/dev/null; then
    fail "web_mod_init accepted empty task directory"
else
    pass "web_mod_init rejects empty task directory"
fi

# Test 5: Successfully initialize valid URL context
task_dir1="$TEST_ROOT/targets/http_example.com/http-probe"
if web_mod_init "http://example.com" "url_http" "$task_dir1"; then
    if [[ "$WEB_TARGET" == "http://example.com" && \
          "$WEB_TARGET_TYPE" == "url_http" && \
          "$WEB_TASK_DIR" == "$task_dir1" && \
          "$WEB_OUTPUT_FILE" == "${task_dir1}/output.txt" && \
          -d "$task_dir1" ]]; then
        pass "web_mod_init initializes context variables and creates task directory"
    else
        fail "web_mod_init did not set expected context variables"
    fi
else
    fail "web_mod_init failed on valid URL arguments"
fi

# Test 6: Verify task directory created with 0750 permissions
dir_perms="$(stat -c '%a' "$task_dir1" 2>/dev/null || stat -f '%p' "$task_dir1" 2>/dev/null)"
if [[ "$dir_perms" =~ 750$ ]]; then
    pass "web_mod_init enforces 0750 permissions on task directory"
else
    fail "Task directory permissions expected 0750, got $dir_perms"
fi

# -----------------------------------------------------------------------------
# UT-03: URL Target Deconstruction & Parsing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: URL Target Deconstruction & Parsing"

# Test 1: Standard HTTP URL
task_dir_http="$TEST_ROOT/targets/http_test/probe"
web_mod_init "http://example.com/api" "url_http" "$task_dir_http"
if [[ "$WEB_URL_SCHEME" == "http" && \
      "$WEB_URL_HOST" == "example.com" && \
      "$WEB_URL_PORT" == "80" && \
      "$WEB_URL_PATH" == "/api" && \
      "$WEB_BASE_URL" == "http://example.com" && \
      "$WEB_FULL_URL" == "http://example.com/api" ]]; then
    pass "Deconstructs standard HTTP URL with implicit port 80"
else
    fail "Standard HTTP URL deconstruction mismatch: host=$WEB_URL_HOST port=$WEB_URL_PORT path=$WEB_URL_PATH base=$WEB_BASE_URL"
fi

# Test 2: Non-standard HTTP URL with port
task_dir_http_port="$TEST_ROOT/targets/http_port_test/probe"
web_mod_init "http://web.corp.local:8080/dashboard" "url_http" "$task_dir_http_port"
if [[ "$WEB_URL_SCHEME" == "http" && \
      "$WEB_URL_HOST" == "web.corp.local" && \
      "$WEB_URL_PORT" == "8080" && \
      "$WEB_URL_PATH" == "/dashboard" && \
      "$WEB_BASE_URL" == "http://web.corp.local:8080" && \
      "$WEB_FULL_URL" == "http://web.corp.local:8080/dashboard" ]]; then
    pass "Deconstructs non-standard HTTP URL with explicit port 8080"
else
    fail "Non-standard HTTP URL deconstruction mismatch: port=$WEB_URL_PORT base=$WEB_BASE_URL"
fi

# Test 3: Standard HTTPS URL with query parameters
task_dir_https="$TEST_ROOT/targets/https_test/probe"
web_mod_init "https://secure.example.com/login?token=xyz123" "url_https" "$task_dir_https"
if [[ "$WEB_URL_SCHEME" == "https" && \
      "$WEB_URL_HOST" == "secure.example.com" && \
      "$WEB_URL_PORT" == "443" && \
      "$WEB_URL_PATH" == "/login" && \
      "$WEB_URL_QUERY" == "token=xyz123" && \
      "$WEB_BASE_URL" == "https://secure.example.com" && \
      "$WEB_FULL_URL" == "https://secure.example.com/login?token=xyz123" ]]; then
    pass "Deconstructs HTTPS URL with query parameters and implicit port 443"
else
    fail "HTTPS URL with query mismatch: host=$WEB_URL_HOST port=$WEB_URL_PORT query=$WEB_URL_QUERY"
fi

# Test 4: Non-standard HTTPS URL with custom port
task_dir_https_port="$TEST_ROOT/targets/https_port_test/probe"
web_mod_init "https://vpn.corp.local:8443/" "url_https" "$task_dir_https_port"
if [[ "$WEB_URL_SCHEME" == "https" && \
      "$WEB_URL_HOST" == "vpn.corp.local" && \
      "$WEB_URL_PORT" == "8443" && \
      "$WEB_BASE_URL" == "https://vpn.corp.local:8443" && \
      "$WEB_FULL_URL" == "https://vpn.corp.local:8443/" ]]; then
    pass "Deconstructs non-standard HTTPS URL with custom port 8443"
else
    fail "Custom HTTPS port mismatch: base=$WEB_BASE_URL full=$WEB_FULL_URL"
fi

# Test 5: IPv4 URL target
task_dir_ip_url="$TEST_ROOT/targets/ip_url_test/probe"
web_mod_init "http://192.168.1.50:3000/app" "url_http" "$task_dir_ip_url"
if [[ "$WEB_URL_SCHEME" == "http" && \
      "$WEB_URL_HOST" == "192.168.1.50" && \
      "$WEB_URL_PORT" == "3000" && \
      "$WEB_URL_PATH" == "/app" && \
      "$WEB_BASE_URL" == "http://192.168.1.50:3000" ]]; then
    pass "Deconstructs IPv4 URL target with custom port"
else
    fail "IPv4 URL mismatch: host=$WEB_URL_HOST port=$WEB_URL_PORT base=$WEB_BASE_URL"
fi

# -----------------------------------------------------------------------------
# UT-04: Non-URL Target Deconstruction (Domain, Hostname, IPv4)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Non-URL Target Deconstruction"

# Test 1: Domain target
task_dir_domain="$TEST_ROOT/targets/domain_test/subdomain"
web_mod_init "example.com" "domain" "$task_dir_domain"
if [[ "$WEB_URL_HOST" == "example.com" && \
      "$WEB_URL_PATH" == "/" && \
      "${#WEB_RESOLVED_URLS[@]}" -eq 2 && \
      "${WEB_RESOLVED_URLS[0]}" == "https://example.com" && \
      "${WEB_RESOLVED_URLS[1]}" == "http://example.com" ]]; then
    pass "Deconstructs domain target and produces candidate HTTPS/HTTP URLs"
else
    fail "Domain target mismatch: host=$WEB_URL_HOST urls=${WEB_RESOLVED_URLS[*]}"
fi

# Test 2: IPv4 discrete target
task_dir_ip="$TEST_ROOT/targets/ip_test/technology"
web_mod_init "10.10.10.20" "ipv4" "$task_dir_ip"
if [[ "$WEB_URL_HOST" == "10.10.10.20" && \
      "$WEB_TARGET_TYPE" == "ipv4" && \
      "${WEB_RESOLVED_URLS[0]}" == "https://10.10.10.20" ]]; then
    pass "Deconstructs IPv4 target with candidate URLs"
else
    fail "IPv4 target mismatch: host=$WEB_URL_HOST urls=${WEB_RESOLVED_URLS[*]}"
fi

# -----------------------------------------------------------------------------
# UT-05: Target Classification Predicates
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Target Classification Predicates"

# Test 1: web_mod_is_url
web_mod_init "http://example.com" "url_http" "$task_dir1"
if web_mod_is_url; then
    pass "web_mod_is_url returns 0 for url_http"
else
    fail "web_mod_is_url failed for url_http"
fi

web_mod_init "example.com" "domain" "$task_dir_domain"
if ! web_mod_is_url; then
    pass "web_mod_is_url returns 1 for domain target"
else
    fail "web_mod_is_url returned 0 for domain target"
fi

# Test 2: web_mod_is_https
web_mod_init "https://example.com" "url_https" "$task_dir1"
if web_mod_is_https; then
    pass "web_mod_is_https returns 0 for url_https"
else
    fail "web_mod_is_https failed for url_https"
fi

web_mod_init "http://example.com" "url_http" "$task_dir1"
if ! web_mod_is_https; then
    pass "web_mod_is_https returns 1 for url_http"
else
    fail "web_mod_is_https returned 0 for url_http"
fi

# Test 3: web_mod_is_domain
web_mod_init "sub.domain.local" "domain" "$task_dir_domain"
if web_mod_is_domain; then
    pass "web_mod_is_domain returns 0 for domain target"
else
    fail "web_mod_is_domain failed for domain target"
fi

web_mod_init "192.168.1.1" "ipv4" "$task_dir_ip"
if ! web_mod_is_domain; then
    pass "web_mod_is_domain returns 1 for ipv4 target"
else
    fail "web_mod_is_domain returned 0 for ipv4 target"
fi

# Test 4: web_mod_is_ip
if web_mod_is_ip; then
    pass "web_mod_is_ip returns 0 for ipv4 target"
else
    fail "web_mod_is_ip failed for ipv4 target"
fi

web_mod_init "example.com" "domain" "$task_dir_domain"
if ! web_mod_is_ip; then
    pass "web_mod_is_ip returns 1 for domain target"
else
    fail "web_mod_is_ip returned 0 for domain target"
fi

# -----------------------------------------------------------------------------
# UT-06: Target Type Compatibility Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Target Type Compatibility Enforcement"

# Test 1: Compatible target accepted
task_dir_compat="$TEST_ROOT/targets/compat_test/subdomain"
if web_mod_init "example.com" "domain" "$task_dir_compat" domain; then
    pass "web_mod_init accepts target matching allowed type constraint"
else
    fail "web_mod_init rejected compatible target type"
fi

# Test 2: Incompatible target returns 2 and writes SKIPPED notice
task_dir_incompat="$TEST_ROOT/targets/incompat_test/subdomain"
ret_code=0
web_mod_init "http://example.com" "url_http" "$task_dir_incompat" domain || ret_code=$?
if (( ret_code == 2 )); then
    if [[ -f "${task_dir_incompat}/output.txt" ]] && grep -q "Status: SKIPPED" "${task_dir_incompat}/output.txt"; then
        pass "web_mod_init returns 2 and writes SKIPPED artifact on type mismatch"
    else
        fail "web_mod_init did not write SKIPPED notice to output.txt"
    fi
else
    fail "web_mod_init expected return code 2 for incompatible type, got $ret_code"
fi

# -----------------------------------------------------------------------------
# UT-07: URL Normalization (web_mod_normalize_url)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: URL Normalization"

# Test 1: Prepend http:// if scheme missing
norm1="$(web_mod_normalize_url "example.com/test")"
if [[ "$norm1" == "http://example.com/test" ]]; then
    pass "Prepends http:// when scheme is absent"
else
    fail "Scheme normalization expected 'http://example.com/test', got '$norm1'"
fi

# Test 2: Strip default port 80 for http
norm2="$(web_mod_normalize_url "http://example.com:80/index.html")"
if [[ "$norm2" == "http://example.com/index.html" ]]; then
    pass "Strips redundant port 80 from http URL"
else
    fail "Redundant port 80 normalization failed, got '$norm2'"
fi

# Test 3: Strip default port 443 for https
norm3="$(web_mod_normalize_url "https://example.com:443/login")"
if [[ "$norm3" == "https://example.com/login" ]]; then
    pass "Strips redundant port 443 from https URL"
else
    fail "Redundant port 443 normalization failed, got '$norm3'"
fi

# Test 4: Preserve non-default ports
norm4="$(web_mod_normalize_url "http://app.internal:8080/api")"
if [[ "$norm4" == "http://app.internal:8080/api" ]]; then
    pass "Preserves non-standard port 8080"
else
    fail "Non-standard port preservation failed, got '$norm4'"
fi

# Test 5: Lowercase host and standardize empty path to '/'
norm5="$(web_mod_normalize_url "HTTPS://EXAMPLE.COM")"
if [[ "$norm5" == "https://example.com/" ]]; then
    pass "Lowercases hostname and standardizes empty path to '/'"
else
    fail "Host lowercasing/path normalization failed, got '$norm5'"
fi

# Test 6: Empty input rejection
if web_mod_normalize_url "   "; then
    fail "web_mod_normalize_url accepted whitespace-only string"
else
    pass "web_mod_normalize_url rejects empty/whitespace input"
fi

# -----------------------------------------------------------------------------
# UT-08: Candidate Target URL Resolution (web_mod_get_target_urls)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Candidate Target URL Resolution"

# Test 1: Explicit URL target returns full target URL
task_dir_url_res="$TEST_ROOT/targets/url_res/probe"
web_mod_init "https://app.example.com:9000/console" "url_https" "$task_dir_url_res"
mapfile -t res_urls < <(web_mod_get_target_urls)
if [[ "${#res_urls[@]}" -eq 1 && "${res_urls[0]}" == "https://app.example.com:9000/console" ]]; then
    pass "web_mod_get_target_urls returns explicit target URL"
else
    fail "Explicit URL resolution mismatch, got ${res_urls[*]}"
fi

# Test 2: Domain target with upstream live_web.txt returns live probed endpoints
target_parent="$TEST_ROOT/targets/parent_domain"
mkdir -p "${target_parent}/http-probe" "${target_parent}/technology"
printf 'https://parent.domain:8443\nhttp://parent.domain:8080\n' > "${target_parent}/http-probe/live_web.txt"

web_mod_init "parent.domain" "domain" "${target_parent}/technology"
mapfile -t upstream_live < <(web_mod_get_target_urls)
if [[ "${#upstream_live[@]}" -eq 2 && \
      "${upstream_live[0]}" == "https://parent.domain:8443" && \
      "${upstream_live[1]}" == "http://parent.domain:8080" ]]; then
    pass "web_mod_get_target_urls prioritizes upstream live_web.txt endpoints"
else
    fail "Upstream live_web.txt priority mismatch, got: ${upstream_live[*]}"
fi

# Test 3: Domain target with upstream services.txt extracts web ports
target_parent2="$TEST_ROOT/targets/parent_services"
mkdir -p "${target_parent2}/service" "${target_parent2}/cms"
printf '80/tcp\topen\thttp\tApache 2.4.41\n443/tcp\topen\tssl/https\tnginx 1.18.0\n8080/tcp\topen\thttp-proxy\tSquid\n22/tcp\topen\tssh\tOpenSSH\n' > "${target_parent2}/service/services.txt"

web_mod_init "services.domain" "domain" "${target_parent2}/cms"
mapfile -t svc_urls < <(web_mod_get_target_urls)
if [[ "${#svc_urls[@]}" -eq 3 && \
      "${svc_urls[0]}" == "http://services.domain" && \
      "${svc_urls[1]}" == "https://services.domain:443" && \
      "${svc_urls[2]}" == "http://services.domain:8080" ]]; then
    pass "web_mod_get_target_urls discovers web endpoints from upstream services.txt"
else
    fail "services.txt endpoint extraction mismatch, got: ${svc_urls[*]}"
fi

# -----------------------------------------------------------------------------
# UT-09: Upstream Reconnaissance Artifact Extraction
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-09: Upstream Reconnaissance Artifact Extraction"

# Test 1: Extract open ports
mkdir -p "${target_parent2}/port"
printf '80\n443\n8080\n22\n' > "${target_parent2}/port/open_ports.txt"
web_mod_init "services.domain" "domain" "${target_parent2}/cms"
mapfile -t ports < <(web_mod_get_upstream_open_ports)
if [[ "${#ports[@]}" -eq 4 && "${ports[0]}" == "22" && "${ports[3]}" == "8080" ]]; then
    pass "web_mod_get_upstream_open_ports extracts sorted numerical open ports"
else
    fail "Open ports extraction mismatch, got: ${ports[*]}"
fi

# Test 2: Extract subdomains
mkdir -p "${target_parent}/subdomain"
printf 'api.parent.domain\t192.168.1.10\nadmin.parent.domain\t192.168.1.11\n' > "${target_parent}/subdomain/resolved_subdomains.txt"
web_mod_init "parent.domain" "domain" "${target_parent}/technology"
mapfile -t subs < <(web_mod_get_upstream_subdomains)
if [[ "${#subs[@]}" -eq 2 && "${subs[0]}" == "admin.parent.domain" && "${subs[1]}" == "api.parent.domain" ]]; then
    pass "web_mod_get_upstream_subdomains extracts unique subdomains from resolved artifacts"
else
    fail "Subdomains extraction mismatch, got: ${subs[*]}"
fi

# -----------------------------------------------------------------------------
# UT-10: Tool Inspection & User Agent Helpers
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-10: Tool Inspection & User Agent Helpers"

# Test 1: web_mod_has_tool
if web_mod_has_tool "bash" && ! web_mod_has_tool "non_existent_reckon_binary_xyz"; then
    pass "web_mod_has_tool accurately detects binary presence and absence"
else
    fail "web_mod_has_tool failed"
fi

# Test 2: web_mod_require_tool
if web_mod_require_tool "bash"; then
    pass "web_mod_require_tool succeeds on available tool"
else
    fail "web_mod_require_tool failed on bash"
fi

if ! web_mod_require_tool "non_existent_tool_abc" 2>/dev/null; then
    pass "web_mod_require_tool fails and sets error on missing tool"
else
    fail "web_mod_require_tool succeeded on non-existent tool"
fi

# Test 3: web_mod_select_tool
selected1="$(web_mod_select_tool "bash" "cat")"
if [[ "$selected1" == "bash" ]]; then
    pass "web_mod_select_tool chooses primary when available"
else
    fail "web_mod_select_tool primary selection mismatch: $selected1"
fi

selected2="$(web_mod_select_tool "missing_primary_binary" "bash")"
if [[ "$selected2" == "bash" ]]; then
    pass "web_mod_select_tool falls back when primary is missing"
else
    fail "web_mod_select_tool fallback selection mismatch: $selected2"
fi

# Test 4: web_mod_get_user_agent
ua_default="$(web_mod_get_user_agent)"
if [[ "$ua_default" =~ RECKON-Recon ]]; then
    pass "web_mod_get_user_agent returns default RECKON User-Agent"
else
    fail "User-Agent mismatch: $ua_default"
fi

ua_override="$(RECKON_USER_AGENT="CustomScanner/2.0" web_mod_get_user_agent)"
if [[ "$ua_override" == "CustomScanner/2.0" ]]; then
    pass "web_mod_get_user_agent honors RECKON_USER_AGENT override"
else
    fail "User-Agent override mismatch: $ua_override"
fi

# -----------------------------------------------------------------------------
# UT-11: Structured Output Writers & File Permissions
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-11: Structured Output Writers & File Permissions"

task_dir_writers="$TEST_ROOT/targets/writers/waf"
web_mod_init "http://example.com" "url_http" "$task_dir_writers"

web_mod_write_header "waf" "WAF Detection"
web_mod_write_section "Detected Signatures"
web_mod_write_kv "Firewall" "Cloudflare"
web_mod_write_kv "Confidence" "High (100%)"
web_mod_write_raw "  Raw Header: cf-ray: 12345-IAD"
web_mod_write_footer "COMPLETED" "WAF detected successfully."

# Write a secondary artifact file
printf 'Cloudflare\n' > "${task_dir_writers}/waf_detected.txt"

web_mod_finish 0

if [[ -f "$WEB_OUTPUT_FILE" ]] && \
   grep -q "RECKON Web Reconnaissance - WAF Detection (waf)" "$WEB_OUTPUT_FILE" && \
   grep -q "Firewall                 : Cloudflare" "$WEB_OUTPUT_FILE" && \
   grep -q "Status: COMPLETED | WAF detected successfully." "$WEB_OUTPUT_FILE"; then
    pass "Structured output writers format header, sections, KV pairs, and footer"
else
    fail "Structured output writers formatting mismatch in $WEB_OUTPUT_FILE"
fi

# Test permissions on task directory artifacts
out_perms="$(stat -c '%a' "$WEB_OUTPUT_FILE" 2>/dev/null || stat -f '%p' "$WEB_OUTPUT_FILE" 2>/dev/null)"
sec_perms="$(stat -c '%a' "${task_dir_writers}/waf_detected.txt" 2>/dev/null || stat -f '%p' "${task_dir_writers}/waf_detected.txt" 2>/dev/null)"
if [[ "$out_perms" =~ 640$ && "$sec_perms" =~ 640$ ]]; then
    pass "web_mod_finish enforces 0640 permissions on all text artifacts"
else
    fail "Artifact permissions expected 0640, got out=$out_perms sec=$sec_perms"
fi

test_summary
