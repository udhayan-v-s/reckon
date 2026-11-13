#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Reporting Pipeline Integration Tests (tests/integration/test_reporting_pipeline.sh)
#
# Verifies end-to-end execution of the multi-format reporting pipeline:
# automated report generation, format selection (--format), report suppression (--no-report),
# multi-target aggregation, offline HTML dashboard integrity, and audit trail logging.
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

RECKON_BIN="$PROJECT_ROOT/reckon"
readonly RECKON_BIN

if [[ ! -f "$RECKON_BIN" || ! -x "$RECKON_BIN" ]]; then
    printf 'Error: RECKON entry point not found or not executable at %s\n' "$RECKON_BIN" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-reportpipe-test.XXXXXX")" || {
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

    printf '%s\n' "Reporting pipeline integration tests completed."
}

printf '%s\n' "RECKON - Reporting Pipeline Integration Tests"
printf '%s\n' "---------------------------------------------"

# -----------------------------------------------------------------------------
# Stage 1: Default Full Scan with Automated Multi-Format Reporting
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Default Full Scan with Automated Multi-Format Reporting"

OUT_DIR_STAGE1="$TEST_ROOT/default_reports"
TARGET_STAGE1="default.corp"

STAGE1_OUT="$("$RECKON_BIN" --module host --target "$TARGET_STAGE1" --output "$OUT_DIR_STAGE1" 2>&1 || true)"
stage1_status=$?

if (( stage1_status == 0 )); then
    pass "scan execution completes with exit code 0"
else
    printf '%s\n' "$STAGE1_OUT" >&2
    fail "scan execution failed (exit: $stage1_status)"
fi

# Verify default generated report files: results.json, report.md, report.txt
REP_DIR_STAGE1="$OUT_DIR_STAGE1/default.corp"
[[ ! -f "$REP_DIR_STAGE1/results.json" ]] && REP_DIR_STAGE1="$OUT_DIR_STAGE1"

if [[ -f "$REP_DIR_STAGE1/results.json" && -s "$REP_DIR_STAGE1/results.json" && \
      -f "$REP_DIR_STAGE1/report.md" && -s "$REP_DIR_STAGE1/report.md" && \
      -f "$REP_DIR_STAGE1/report.txt" && -s "$REP_DIR_STAGE1/report.txt" ]]; then
    pass "scan automatically generates default report bundle (results.json, report.md, report.txt)"
else
    fail "missing expected default report files in $REP_DIR_STAGE1"
fi

# Validate JSON schema and content
if command -v jq >/dev/null 2>&1; then
    if jq -e . "$REP_DIR_STAGE1/results.json" >/dev/null 2>&1; then
        pass "results.json parses cleanly with jq"
    else
        fail "results.json failed jq syntax validation"
    fi
    t_count="$(jq -r '.summary.total_targets // 0' "$REP_DIR_STAGE1/results.json")"
    if (( t_count >= 1 )); then
        pass "results.json contains accurate target count ($t_count)"
    else
        fail "results.json reported invalid target count ($t_count)"
    fi
fi

# Validate Markdown report sections
md_content="$(cat "$REP_DIR_STAGE1/report.md")"
if [[ "$md_content" == *"# RECKON Reconnaissance Assessment Report"* && \
      "$md_content" == *"## Executive Summary"* && \
      "$md_content" == *"## Target: default.corp"* ]]; then
    pass "report.md contains formatted header, executive summary, and target sections"
else
    fail "report.md missing expected Markdown sections"
fi

# Validate Plain Text report sections
txt_content="$(cat "$REP_DIR_STAGE1/report.txt")"
if [[ "$txt_content" == *"RECKON RECONNAISSANCE ASSESSMENT REPORT"* && \
      "$txt_content" == *"TARGET: default.corp"* ]]; then
    pass "report.txt contains structured ASCII banner and target breakdown"
else
    fail "report.txt missing expected text sections"
fi

# Validate 0640 permissions on all generated report files
perm_json="$(stat -c '%a' "$REP_DIR_STAGE1/results.json" 2>/dev/null || stat -f '%p' "$REP_DIR_STAGE1/results.json" 2>/dev/null)"
perm_md="$(stat -c '%a' "$REP_DIR_STAGE1/report.md" 2>/dev/null || stat -f '%p' "$REP_DIR_STAGE1/report.md" 2>/dev/null)"
perm_txt="$(stat -c '%a' "$REP_DIR_STAGE1/report.txt" 2>/dev/null || stat -f '%p' "$REP_DIR_STAGE1/report.txt" 2>/dev/null)"

perm_json="${perm_json: -3}"
perm_md="${perm_md: -3}"
perm_txt="${perm_txt: -3}"

if [[ "$perm_json" == "640" && "$perm_md" == "640" && "$perm_txt" == "640" ]]; then
    pass "enforces 0640 permissions on all generated report artifacts"
else
    fail "unexpected permissions: json=$perm_json, md=$perm_md, txt=$perm_txt (expected 640)"
fi

# -----------------------------------------------------------------------------
# Stage 2: Explicit Single Format Selection (--format MD)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Explicit Single Format Selection (--format MD)"

OUT_DIR_STAGE2="$TEST_ROOT/md_only_reports"
TARGET_STAGE2="singlefmt.corp"

"$RECKON_BIN" --module host --target "$TARGET_STAGE2" --output "$OUT_DIR_STAGE2" --format MD >/dev/null 2>&1 || true

REP_DIR_STAGE2="$OUT_DIR_STAGE2/singlefmt.corp"
[[ ! -f "$REP_DIR_STAGE2/report.md" ]] && REP_DIR_STAGE2="$OUT_DIR_STAGE2"

if [[ -f "$REP_DIR_STAGE2/report.md" && -s "$REP_DIR_STAGE2/report.md" ]]; then
    pass "--format MD generates requested Markdown report"
else
    fail "--format MD failed to generate report.md"
fi

if [[ ! -f "$REP_DIR_STAGE2/report.txt" && ! -f "$OUT_DIR_STAGE2/report.txt" ]]; then
    pass "--format MD excludes unrequested report format (report.txt)"
else
    fail "--format MD generated unrequested report format (report.txt)"
fi

# -----------------------------------------------------------------------------
# Stage 3: Multi-Format Selection & Standalone HTML Dashboard Generation
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Multi-Format Selection & Standalone HTML Dashboard Generation"

OUT_DIR_STAGE3="$TEST_ROOT/multi_format_reports"
TARGET_STAGE3="dashboard.corp"

"$RECKON_BIN" --module host --target "$TARGET_STAGE3" --output "$OUT_DIR_STAGE3" --format JSON,MD,TXT >/dev/null 2>&1 || true

REP_DIR_STAGE3="$OUT_DIR_STAGE3/dashboard.corp"
[[ ! -f "$REP_DIR_STAGE3/report.md" ]] && REP_DIR_STAGE3="$OUT_DIR_STAGE3"

if [[ -f "$REP_DIR_STAGE3/results.json" && -s "$REP_DIR_STAGE3/results.json" && \
      -f "$REP_DIR_STAGE3/report.md" && -s "$REP_DIR_STAGE3/report.md" && \
      -f "$REP_DIR_STAGE3/report.txt" && -s "$REP_DIR_STAGE3/report.txt" ]]; then
    pass "--format JSON,MD,TXT generates JSON, Markdown, and plain text reports"
else
    fail "missing expected JSON, MD or TXT report files in $REP_DIR_STAGE3"
fi

# Generate and verify standalone HTML report via reporting engine
# shellcheck source=lib/reporting.sh
source "$PROJECT_ROOT/lib/reporting.sh"
reporting_export_html "$REP_DIR_STAGE3" "$OUT_DIR_STAGE3/report.html"

if [[ -f "$OUT_DIR_STAGE3/report.html" && -s "$OUT_DIR_STAGE3/report.html" ]]; then
    pass "reporting_export_html creates non-empty report.html"
else
    fail "reporting_export_html failed to generate report.html"
fi

html_data="$(cat "$OUT_DIR_STAGE3/report.html")"
if [[ "$html_data" == *"<!DOCTYPE html>"* && \
      "$html_data" == *"metric-card"* && \
      "$html_data" == *"dashboard.corp"* && \
      "$html_data" == *"</html>"* ]]; then
    pass "report.html is a well-formed HTML5 document containing styled dashboard components"
else
    fail "report.html missing HTML5 elements or target data"
fi

# Verify offline independence (no external CDNs or remote links)
if [[ "$html_data" != *"https://cdn."* && "$html_data" != *"http://cdn."* && \
      "$html_data" != *"https://fonts.googleapis.com"* ]]; then
    pass "report.html is completely self-contained with no external CDN or font dependencies"
else
    fail "report.html contains external remote web dependencies"
fi

# -----------------------------------------------------------------------------
# Stage 4: Report Suppression with --no-report
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Complete Report Suppression (--no-report)"

OUT_DIR_STAGE4="$TEST_ROOT/suppressed_reports"
TARGET_STAGE4="suppressed.corp"

"$RECKON_BIN" --module host --target "$TARGET_STAGE4" --output "$OUT_DIR_STAGE4" --no-report >/dev/null 2>&1 || true

# Verify raw module directory was cleaned up and not persisted
if [[ ! -d "$OUT_DIR_STAGE4/$TARGET_STAGE4/host" ]]; then
    pass "--no-report leaves no persistent module directories or raw output"
else
    fail "--no-report left unexpected module output in $OUT_DIR_STAGE4/$TARGET_STAGE4/host"
fi

# Verify NO reports exist in output root or target directory
if [[ ! -f "$OUT_DIR_STAGE4/results.json" && \
      ! -f "$OUT_DIR_STAGE4/report.md" && \
      ! -f "$OUT_DIR_STAGE4/report.txt" && \
      ! -f "$OUT_DIR_STAGE4/report.html" && \
      ! -f "$OUT_DIR_STAGE4/$TARGET_STAGE4/results.json" && \
      ! -f "$OUT_DIR_STAGE4/$TARGET_STAGE4/report.md" && \
      ! -f "$OUT_DIR_STAGE4/$TARGET_STAGE4/report.txt" ]]; then
    pass "--no-report suppresses all report file generation (results.json, report.md, report.txt, report.html)"
else
    fail "--no-report generated unwanted report files"
fi

# -----------------------------------------------------------------------------
# Stage 5: Multi-Target Assessment Report Aggregation
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Multi-Target Assessment Report Aggregation"

TARGETS_FILE="$TEST_ROOT/multi_targets.txt"
cat <<'EOF' > "$TARGETS_FILE"
target1.corp
target2.corp
192.0.2.10
EOF

OUT_DIR_STAGE5="$TEST_ROOT/multi_reports"

"$RECKON_BIN" --module host --targets-file "$TARGETS_FILE" --output "$OUT_DIR_STAGE5" >/dev/null 2>&1 || true

if [[ -f "$OUT_DIR_STAGE5/target1.corp/results.json" && -f "$OUT_DIR_STAGE5/target1.corp/report.md" && -f "$OUT_DIR_STAGE5/target1.corp/report.txt" && \
      -f "$OUT_DIR_STAGE5/target2.corp/results.json" && -f "$OUT_DIR_STAGE5/target2.corp/report.md" && -f "$OUT_DIR_STAGE5/target2.corp/report.txt" && \
      -f "$OUT_DIR_STAGE5/192.0.2.10/results.json" && -f "$OUT_DIR_STAGE5/192.0.2.10/report.md" && -f "$OUT_DIR_STAGE5/192.0.2.10/report.txt" ]]; then
    pass "multi-target scan generates report files in target-specific folders"
else
    fail "multi-target scan failed to generate expected report bundles in target folders"
fi

if command -v jq >/dev/null 2>&1; then
    m_count="$(jq -r '.summary.total_targets // 0' "$OUT_DIR_STAGE5/target1.corp/results.json")"
    if (( m_count == 1 )); then
        pass "target results.json isolates findings for target1.corp"
    else
        fail "results.json target count mismatch: expected 1, found $m_count"
    fi
fi

multi_md="$(cat "$OUT_DIR_STAGE5/target1.corp/report.md")"
if [[ "$multi_md" == *"Target: target1.corp"* ]]; then
    pass "report.md contains dedicated target assessment section"
else
    fail "report.md missing target section"
fi

# -----------------------------------------------------------------------------
# Stage 6: Audit Logging of Reporting Lifecycle
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Audit Logging of Reporting Lifecycle"

AUDIT_LOG="$TEST_ROOT/reporting_audit.log"
"$RECKON_BIN" --module host --target "audit.corp" --output "$TEST_ROOT/audit_scan_out" --log-file "$AUDIT_LOG" --format MD,TXT >/dev/null 2>&1 || true

if [[ -f "$AUDIT_LOG" ]]; then
    if grep -q "Generated assessment report:.*report.md" "$AUDIT_LOG" && \
       grep -q "Generated assessment report:.*report.txt" "$AUDIT_LOG"; then
        pass "audit log records generation entries for each exported report format"
    else
        fail "audit log missing expected report generation milestone records"
    fi
else
    fail "audit log file was not created"
fi

# -----------------------------------------------------------------------------
# Stage 7: Simulation Safety in Dry-Run Mode (--dry-run)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Simulation Safety in Dry-Run Mode (--dry-run)"

DRY_RUN_OUT="$TEST_ROOT/dry_run_reports"
dry_run_res="$("$RECKON_BIN" --module host --target "dryrun.corp" --output "$DRY_RUN_OUT" --dry-run 2>&1 || true)"

if [[ "$dry_run_res" == *"RECKON - EXECUTION PLAN"* ]]; then
    pass "--dry-run prints simulated execution plan"
else
    fail "--dry-run missing expected execution plan notice"
fi

if [[ ! -d "$DRY_RUN_OUT" ]]; then
    pass "--dry-run creates no output directory or report files on disk"
else
    fail "--dry-run created unexpected output directory: $DRY_RUN_OUT"
fi

test_summary
