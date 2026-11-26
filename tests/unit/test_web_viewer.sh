#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Standalone Web Viewer (report.html) integrity & offline safety tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

REPORT_HTML="$PROJECT_ROOT/report.html"
readonly REPORT_HTML

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

    printf '%s\n' "Web viewer integrity & offline safety tests completed."
}

printf '%s\n' "RECKON - Web Viewer (report.html) Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# WV-01: File Presence & HTML5 Structure
# -----------------------------------------------------------------------------
printf '\n%s\n' "WV-01: File Presence & HTML5 Structure"

if [[ -f "$REPORT_HTML" && -s "$REPORT_HTML" ]]; then
    pass "report.html exists and is non-empty"
else
    fail "report.html is missing or empty"
fi

for tag in "<!DOCTYPE html>" "<html" "<head>" "<style>" "</style>" "<body>" "<script>" "</script>" "</html>"; do
    if grep -qF "$tag" "$REPORT_HTML"; then
        pass "Contains required structural tag: $tag"
    else
        fail "Missing required structural tag: $tag"
    fi
done

# -----------------------------------------------------------------------------
# WV-02: Offline Self-Containment (Zero External Assets)
# -----------------------------------------------------------------------------
printf '\n%s\n' "WV-02: Offline Self-Containment"

if grep -Eqi '<script[^>]+src=' "$REPORT_HTML"; then
    fail "Found external <script src=...> tag (violates offline-only constraint)"
else
    pass "No external <script src=...> tags found"
fi

if grep -Eqi '<link[^>]+href=["'\'']https?://' "$REPORT_HTML"; then
    fail "Found external <link href=http...> tag (violates offline-only constraint)"
else
    pass "No external <link href=http...> tags found"
fi

if grep -Eqi '(fonts\.googleapis\.com|cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com)' "$REPORT_HTML"; then
    fail "Found external CDN reference in report.html"
else
    pass "No external CDN references found"
fi

if grep -Eqi '(fetch\(|XMLHttpRequest|navigator\.sendBeacon)' "$REPORT_HTML"; then
    fail "Found network request API usage in report.html"
else
    pass "No network request APIs (fetch/XHR/sendBeacon) used"
fi

# -----------------------------------------------------------------------------
# WV-03: Multi-Format Parsers & Interactive Dashboard Components
# -----------------------------------------------------------------------------
printf '\n%s\n' "WV-03: Parsers & Dashboard Components"

for symbol in \
    "uploadZone" \
    "fileInput" \
    "handleFile" \
    "detectFormat" \
    "parseJson" \
    "normalizeJsonSchema" \
    "parseMarkdown" \
    "markdownToHtml" \
    "parseText" \
    "renderDashboard" \
    "renderTargetSection" \
    "switchTarget" \
    "renderNetworkSection" \
    "renderWebSection" \
    "renderSecurityAuditSection" \
    "applyDashboardFilters" \
    "bindTableSorting" \
    "switchViewMode" \
    "loadDemoData" \
    "exportPdf" \
    "escapeHtml"
do
    if grep -qF "$symbol" "$REPORT_HTML"; then
        pass "Component/handler present: $symbol"
    else
        fail "Missing component/handler: $symbol"
    fi
done

# -----------------------------------------------------------------------------
# WV-04: Print / PDF Export Stylesheet Verification
# -----------------------------------------------------------------------------
printf '\n%s\n' "WV-04: Print & PDF Stylesheet"

for css_rule in "@page" "@media print" "print-color-adjust" "print-classification-bar" "break-inside: avoid"; do
    if grep -qF "$css_rule" "$REPORT_HTML"; then
        pass "Print CSS rule present: $css_rule"
    else
        fail "Missing print CSS rule: $css_rule"
    fi
done

# -----------------------------------------------------------------------------
# WV-05: Deep Script & Balanced Tag Verification
# -----------------------------------------------------------------------------
printf '\n%s\n' "WV-05: Deep Script & Tag Balance"

if command -v python3 >/dev/null 2>&1; then
    if python3 -c '
import re, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    html = f.read()
styles = re.findall(r"<style>(.*?)</style>", html, re.DOTALL)
scripts = re.findall(r"<script>(.*?)</script>", html, re.DOTALL)
assert len(styles) == 1, f"Expected 1 <style> block, found {len(styles)}"
assert len(scripts) == 1, f"Expected 1 <script> block, found {len(scripts)}"
assert "ReckonApp" in scripts[0], "ReckonApp missing from <script>"
' "$REPORT_HTML"; then
        pass "Single self-contained <style> and <script> blocks verified"
    else
        fail "Style/script block balance verification failed"
    fi
else
    pass "Skipped Python3 deep check (python3 not installed)"
fi

test_summary
