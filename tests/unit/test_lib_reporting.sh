#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Reporting Engine Unit Tests (tests/unit/test_lib_reporting.sh)
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

# shellcheck source=lib/reporting.sh
if ! source "$PROJECT_ROOT/lib/reporting.sh"; then
    printf 'Error: Unable to load lib/reporting.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-lib-reporting-test.XXXXXX")" || {
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

    printf '%s\n' "Reporting engine unit tests completed."
}

printf '%s\n' "RECKON - Reporting Engine Unit Tests"
printf '%s\n' "------------------------------------"

# Setup mock scan output directory with sample target findings
MOCK_OUTPUT_DIR="$TEST_ROOT/scan_run"
MOCK_TARGET_DIR="$MOCK_OUTPUT_DIR/enterprise.corp"

mkdir -p "$MOCK_TARGET_DIR/ping" \
         "$MOCK_TARGET_DIR/dns" \
         "$MOCK_TARGET_DIR/port" \
         "$MOCK_TARGET_DIR/service" \
         "$MOCK_TARGET_DIR/os" \
         "$MOCK_TARGET_DIR/subdomain" \
         "$MOCK_TARGET_DIR/technology" \
         "$MOCK_TARGET_DIR/cms" \
         "$MOCK_TARGET_DIR/waf" \
         "$MOCK_TARGET_DIR/directory" \
         "$MOCK_TARGET_DIR/file" \
         "$MOCK_TARGET_DIR/vhost" \
         "$MOCK_TARGET_DIR/crawl" \
         "$MOCK_TARGET_DIR/endpoint" \
         "$MOCK_TARGET_DIR/http-analysis" \
         "$MOCK_TARGET_DIR/tls" \
         "$MOCK_TARGET_DIR/resources" \
         "$MOCK_TARGET_DIR/historical-urls"

printf 'Host is UP (0.002s RTT)\n' > "$MOCK_TARGET_DIR/ping/output.txt"
printf 'A\tenterprise.corp\t10.10.1.10\nMX\tenterprise.corp\tmail.corp.local\n' > "$MOCK_TARGET_DIR/dns/dns_records.txt"
printf '80\n443\n' > "$MOCK_TARGET_DIR/port/open_ports.txt"
cat <<'EOF' > "$MOCK_TARGET_DIR/service/services.txt"
80/tcp	open	http	Apache 2.4.52
443/tcp	open	https	nginx 1.22.0
EOF
printf 'Linux\t96%%\tLinux 5.4 - 5.15\n' > "$MOCK_TARGET_DIR/os/os_detection.txt"
printf 'api.corp.local\t10.10.1.20\n' > "$MOCK_TARGET_DIR/subdomain/resolved_subdomains.txt"
printf 'WordPress\t6.4.1\tCMS, Blog\n' > "$MOCK_TARGET_DIR/technology/technologies.txt"
printf 'WordPress\t6.4.1\thigh\n' > "$MOCK_TARGET_DIR/cms/cms_detected.txt"
printf 'Cloudflare\tCloudflare Inc.\n' > "$MOCK_TARGET_DIR/waf/waf_detected.txt"
printf '/admin/\t301\t128\t/admin/login\n' > "$MOCK_TARGET_DIR/directory/directories.txt"
printf '/config.json\t200\t256\tConfiguration\n' > "$MOCK_TARGET_DIR/file/files.txt"
printf 'dev.corp.local\t200\t1420\t-\n' > "$MOCK_TARGET_DIR/vhost/vhosts.txt"
printf 'https://enterprise.corp/\nhttps://enterprise.corp/about\n' > "$MOCK_TARGET_DIR/crawl/crawled_urls.txt"
printf '/api/v1/users\tAPI\n/auth/login\tAUTH\n' > "$MOCK_TARGET_DIR/endpoint/endpoints.txt"
cat <<'EOF' > "$MOCK_TARGET_DIR/http-analysis/http_analysis.txt"
HEADER	Strict-Transport-Security	PRESENT	max-age=31536000
HEADER	Content-Security-Policy	MISSING	-
DISCLOSURE	Server	Apache/2.4.52
CORS	https://evil.local	true	HIGH	Arbitrary Origin Reflected
METHOD	OPTIONS	200	ENABLED
EOF
cat <<'EOF' > "$MOCK_TARGET_DIR/tls/tls_audit.txt"
TLSv1.3	SUPPORTED	SECURE
TLSv1.0	SUPPORTED	DEPRECATED
EOF
cat <<'EOF' > "$MOCK_TARGET_DIR/tls/cert_info.txt"
Subject: CN = enterprise.corp
Issuer: CN = DigiCert Root
Valid From: 2026-01-01
Valid Until: 2027-12-31
SANs: enterprise.corp, www.enterprise.corp
EOF
printf '/robots.txt\t200\t128\tDisallow: /admin/\n' > "$MOCK_TARGET_DIR/resources/resources.txt"
printf 'https://enterprise.corp/archive.zip\n' > "$MOCK_TARGET_DIR/historical-urls/historical_urls.txt"

# -----------------------------------------------------------------------------
# UT-01: Reporting Initialization & State Reset
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Reporting Initialization & State Reset"

reporting_init
if [[ -z "$REPORTING_ERROR" && ${#REPORTING_GENERATED_FILES[@]} -eq 0 ]]; then
    pass "reporting_init resets error and generated file list"
else
    fail "reporting_init state mismatch"
fi

# -----------------------------------------------------------------------------
# UT-02: Markdown Report Exporter (reporting_export_markdown)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Markdown Report Exporter"

md_out="$MOCK_OUTPUT_DIR/report.md"
reporting_export_markdown "$MOCK_OUTPUT_DIR" "$md_out"

if [[ -f "$md_out" && -s "$md_out" ]]; then
    pass "reporting_export_markdown creates non-empty report.md"
else
    fail "reporting_export_markdown failed to generate report.md"
fi

md_content="$(cat "$md_out")"

if [[ "$md_content" == *"# RECKON Reconnaissance Assessment Report"* && \
      "$md_content" == *"## Executive Summary"* && \
      "$md_content" == *"## Target: enterprise.corp"* ]]; then
    pass "Markdown report contains header, executive summary, and target sections"
else
    fail "Markdown report missing core structural sections"
fi

if [[ "$md_content" == *"Apache 2.4.52"* && \
      "$md_content" == *"Strict-Transport-Security"* && \
      "$md_content" == *"Content-Security-Policy"* && \
      "$md_content" == *"Arbitrary Origin Reflected"* && \
      "$md_content" == *"DigiCert Root"* ]]; then
    pass "Markdown report contains parsed network, service, and security findings"
else
    fail "Markdown report missing key module findings"
fi

# -----------------------------------------------------------------------------
# UT-03: Plain Text Report Exporter (reporting_export_text)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Plain Text Report Exporter"

txt_out="$MOCK_OUTPUT_DIR/report.txt"
reporting_export_text "$MOCK_OUTPUT_DIR" "$txt_out"

if [[ -f "$txt_out" && -s "$txt_out" ]]; then
    pass "reporting_export_text creates non-empty report.txt"
else
    fail "reporting_export_text failed to generate report.txt"
fi

txt_content="$(cat "$txt_out")"

if [[ "$txt_content" == *"RECKON RECONNAISSANCE ASSESSMENT REPORT"* && \
      "$txt_content" == *"TARGET: enterprise.corp"* && \
      "$txt_content" == *"[+] OPEN PORTS & SERVICES:"* && \
      "$txt_content" == *"[+] SECURITY ANALYSIS & AUDITS:"* ]]; then
    pass "Plain text report contains structured ASCII banners and module groups"
else
    fail "Plain text report missing expected ASCII banners or findings"
fi

if [[ "$txt_content" == *"10.10.1.10"* && "$txt_content" == *"api.corp.local"* && "$txt_content" == *"/admin/"* ]]; then
    pass "Plain text report formats DNS, subdomains, and content discoveries"
else
    fail "Plain text report missing host details"
fi

# -----------------------------------------------------------------------------
# UT-04: Standalone HTML Dashboard Exporter (reporting_export_html)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Standalone HTML Dashboard Exporter"

html_out="$MOCK_OUTPUT_DIR/report.html"
reporting_export_html "$MOCK_OUTPUT_DIR" "$html_out"

if [[ -f "$html_out" && -s "$html_out" ]]; then
    pass "reporting_export_html creates non-empty report.html"
else
    fail "reporting_export_html failed to generate report.html"
fi

html_content="$(cat "$html_out")"

if [[ "$html_content" == *"<!DOCTYPE html>"* && \
      "$html_content" == *"<html>"* || "$html_content" == *"<html lang=\"en\">"* ]] && \
   [[ "$html_content" == *"</html>"* && \
      "$html_content" == *"Executive Summary"* && \
      "$html_content" == *"metric-card"* ]]; then
    pass "HTML report contains valid HTML5 document structure and metric cards"
else
    fail "HTML report missing HTML5 tags or dashboard elements"
fi

if [[ "$html_content" == *"enterprise.corp"* && \
      "$html_content" == *"Apache 2.4.52"* && \
      "$html_content" == *"badge-present"* && \
      "$html_content" == *"badge-missing"* ]]; then
    pass "HTML report contains styled badges and findings tables"
else
    fail "HTML report missing findings or styled badge elements"
fi

# -----------------------------------------------------------------------------
# UT-05: Multi-Format Report Dispatcher (reporting_generate)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Multi-Format Report Dispatcher"

GEN_DIR="$TEST_ROOT/gen_multi"
mkdir -p "$GEN_DIR"
cp -r "$MOCK_TARGET_DIR" "$GEN_DIR/"

reporting_generate "$GEN_DIR" "MD,TXT,HTML,JSON" "custom_report"

if [[ -f "$GEN_DIR/custom_report.md" && \
      -f "$GEN_DIR/custom_report.txt" && \
      -f "$GEN_DIR/custom_report.html" && \
      -f "$GEN_DIR/results.json" ]]; then
    pass "reporting_generate creates all requested format artifacts simultaneously"
else
    fail "reporting_generate failed to create requested multi-format artifacts"
fi

if (( ${#REPORTING_GENERATED_FILES[@]} >= 4 )); then
    pass "reporting_generate registers all generated file paths in REPORTING_GENERATED_FILES"
else
    fail "REPORTING_GENERATED_FILES tracking incomplete: ${#REPORTING_GENERATED_FILES[@]}"
fi

# -----------------------------------------------------------------------------
# UT-06: File Permission Enforcement (0640)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: File Permission Enforcement"

get_perm() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%p' "$1" 2>/dev/null
}

p_md="$(get_perm "$GEN_DIR/custom_report.md")"
p_txt="$(get_perm "$GEN_DIR/custom_report.txt")"
p_html="$(get_perm "$GEN_DIR/custom_report.html")"

p_md="${p_md: -3}"
p_txt="${p_txt: -3}"
p_html="${p_html: -3}"

if [[ "$p_md" == "640" && "$p_txt" == "640" && "$p_html" == "640" ]]; then
    pass "Enforces 0640 permissions on all exported reports (MD, TXT, HTML)"
else
    fail "Permission mismatch on reports: md=$p_md, txt=$p_txt, html=$p_html"
fi

# -----------------------------------------------------------------------------
# UT-07: Error Handling & Missing Directory Validation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Error Handling & Validation"

if reporting_generate "$TEST_ROOT/non_existent_folder_xyz" 2>/dev/null; then
    fail "reporting_generate accepted non-existent directory"
else
    pass "reporting_generate rejects non-existent directory with error"
fi

if reporting_generate "$GEN_DIR" "UNSUPPORTED_FORMAT_XYZ" 2>/dev/null; then
    fail "reporting_generate accepted unsupported format"
else
    pass "reporting_generate rejects unsupported format with error"
fi

test_summary
