#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Error Handling, Retries & Dependency Failure Resilience Integration Tests
# (tests/integration/test_error_resilience.sh)
#
# Verifies robust error resilience and recovery across the RECKON execution engine:
# 1. Per-task execution timeout enforcement (--timeout <seconds>).
# 2. Transient task failure retry and automatic recovery (--retries <count>).
# 3. Exhausted task retries on persistent failure (--retries <count>).
# 4. Multi-module scan continuation across partial task failures.
# 5. Non-critical dependency fallback resilience (whatweb -> curl, ffuf -> curl).
# 6. Target unreachability and clean reporting without unhandled exceptions.
# 7. Audit log error trail diagnostics and structured execution summary.
# 8. Argument and scan planning error rejection (exit code 2).
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

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-error-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

cleanup() {
    # Terminate any lingering background test jobs
    local job_pids
    job_pids="$(jobs -p 2>/dev/null || true)"
    if [[ -n "$job_pids" ]]; then
        local -a pids_arr=()
        read -r -a pids_arr <<< "$job_pids"
        if (( ${#pids_arr[@]} > 0 )); then
            kill -9 "${pids_arr[@]}" 2>/dev/null || true
        fi
    fi
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

    printf '%s\n' "Error handling and resilience integration tests completed successfully."
}

printf '%s\n' "RECKON - Error Handling, Retries & Dependency Resilience Tests"
printf '%s\n' "-------------------------------------------------------------"

# -----------------------------------------------------------------------------
# Stage 1: Per-Task Timeout Enforcement (--timeout <sec>)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Per-Task Timeout Enforcement (--timeout 1)"

OUT_DIR_STAGE1="$TEST_ROOT/stage1_timeout"
LOG_STAGE1="$TEST_ROOT/stage1.log"
MOCK_SLOW_FPING="$TEST_ROOT/mock_slow_fping.sh"

cat > "$MOCK_SLOW_FPING" << 'EOF'
#!/usr/bin/env bash
sleep 10
exit 0
EOF
chmod 0755 "$MOCK_SLOW_FPING"

stage1_start=$SECONDS
stage1_exit=0
RECKON_MOCK_FPING_BIN="$MOCK_SLOW_FPING" \
"$RECKON_BIN" --module host --target 192.0.2.1 --timeout 1 --output "$OUT_DIR_STAGE1" --log-file "$LOG_STAGE1" >/dev/null 2>&1 || stage1_exit=$?
stage1_duration=$(( SECONDS - stage1_start ))

if (( stage1_duration < 5 )); then
    pass "scan terminated worker within timeout threshold (${stage1_duration}s < 5s)"
else
    fail "scan exceeded timeout threshold (${stage1_duration}s >= 5s)"
fi

if (( stage1_exit == 1 )); then
    pass "scan exited with code 1 indicating timed-out task failure"
else
    fail "scan exited with code $stage1_exit on timeout (expected 1)"
fi

if grep -q "Module 'host' timed out after 1s" "$LOG_STAGE1" 2>/dev/null; then
    pass "audit log records per-task timeout warning"
else
    fail "audit log missing timeout warning message"
fi

if [[ -f "$OUT_DIR_STAGE1/results.json" && -s "$OUT_DIR_STAGE1/results.json" && \
      -f "$OUT_DIR_STAGE1/report.md" && -s "$OUT_DIR_STAGE1/report.md" ]]; then
    pass "reporting engine generates normalized results and markdown report despite task timeout"
else
    fail "reporting artifacts missing following task timeout"
fi

# -----------------------------------------------------------------------------
# Stage 2: Transient Task Failure & Automatic Retry Recovery (--retries 1)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Transient Task Failure & Automatic Retry Recovery (--retries 1)"

OUT_DIR_STAGE2="$TEST_ROOT/stage2_retry"
LOG_STAGE2="$TEST_ROOT/stage2.log"
MOCK_RETRY_NMAP="$TEST_ROOT/mock_retry_nmap.sh"
STAGE2_COUNT_FILE="$TEST_ROOT/stage2_invocations.txt"
printf '0\n' > "$STAGE2_COUNT_FILE"

cat > "$MOCK_RETRY_NMAP" << EOF
#!/usr/bin/env bash
current_inv="\$(cat "$STAGE2_COUNT_FILE")"
printf '%s\n' "\$(( current_inv + 1 ))" > "$STAGE2_COUNT_FILE"

if (( current_inv == 0 )); then
    printf 'Error: Temporary connection reset by peer on attempt 1\n' >&2
    exit 2
fi

# Attempt 2: generate mock gnmap output
prev=""
for arg in "\$@"; do
    if [[ "\$prev" == "-oG" ]]; then
        printf 'Host: 192.0.2.1 () Ports: 80/open/tcp//http//\n' > "\$arg"
    fi
    prev="\$arg"
done
exit 0
EOF
chmod 0755 "$MOCK_RETRY_NMAP"

stage2_exit=0
RECKON_MOCK_NMAP_BIN="$MOCK_RETRY_NMAP" \
"$RECKON_BIN" --module port --target 192.0.2.1 --retries 1 --output "$OUT_DIR_STAGE2" --log-file "$LOG_STAGE2" >/dev/null 2>&1 || stage2_exit=$?
stage2_invocations="$(cat "$STAGE2_COUNT_FILE" 2>/dev/null || echo 0)"

if (( stage2_invocations == 2 )); then
    pass "failed task was re-dispatched exactly once for --retries 1 (invocations: $stage2_invocations)"
else
    fail "task invocation count mismatch for --retries 1 (got $stage2_invocations, expected 2)"
fi

if grep -q "failed (code 2). Retrying (1/1)..." "$LOG_STAGE2" 2>/dev/null; then
    pass "audit log records task retry warning notice"
else
    fail "audit log missing retry warning notice"
fi

if (( stage2_exit == 0 )); then
    pass "scan execution completes with exit code 0 upon retry recovery"
else
    fail "scan execution failed with code $stage2_exit despite recovery (expected 0)"
fi

if grep -q "Module 'port' completed for target '192.0.2.1'" "$LOG_STAGE2" 2>/dev/null; then
    pass "audit log records successful completion following retry"
else
    fail "audit log missing task completion record after retry"
fi

# -----------------------------------------------------------------------------
# Stage 3: Exhausted Task Retries on Persistent Failure (--retries 2)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Exhausted Task Retries on Persistent Failure (--retries 2)"

OUT_DIR_STAGE3="$TEST_ROOT/stage3_exhausted"
LOG_STAGE3="$TEST_ROOT/stage3.log"
MOCK_FAIL_NMAP="$TEST_ROOT/mock_fail_nmap.sh"
STAGE3_COUNT_FILE="$TEST_ROOT/stage3_invocations.txt"
printf '0\n' > "$STAGE3_COUNT_FILE"

cat > "$MOCK_FAIL_NMAP" << EOF
#!/usr/bin/env bash
current_inv="\$(cat "$STAGE3_COUNT_FILE")"
printf '%s\n' "\$(( current_inv + 1 ))" > "$STAGE3_COUNT_FILE"
printf 'Persistent fatal I/O error\n' >&2
exit 2
EOF
chmod 0755 "$MOCK_FAIL_NMAP"

stage3_exit=0
RECKON_MOCK_NMAP_BIN="$MOCK_FAIL_NMAP" \
"$RECKON_BIN" --module port --target 192.0.2.1 --retries 2 --output "$OUT_DIR_STAGE3" --log-file "$LOG_STAGE3" >/dev/null 2>&1 || stage3_exit=$?
stage3_invocations="$(cat "$STAGE3_COUNT_FILE" 2>/dev/null || echo 0)"

if (( stage3_invocations == 3 )); then
    pass "task re-attempted initial run plus 2 retries (total invocations: $stage3_invocations)"
else
    fail "task invocation count mismatch for --retries 2 (got $stage3_invocations, expected 3)"
fi

if grep -q "Retrying (1/2)..." "$LOG_STAGE3" 2>/dev/null && \
   grep -q "Retrying (2/2)..." "$LOG_STAGE3" 2>/dev/null; then
    pass "audit log records sequential retry attempts (1/2 and 2/2)"
else
    fail "audit log missing sequential retry attempt logs"
fi

if (( stage3_exit == 1 )); then
    pass "scan execution exits with code 1 when all retries are exhausted"
else
    fail "scan execution exited with code $stage3_exit on exhausted retries (expected 1)"
fi

if grep -q "Module 'port' failed with exit code 2 for target '192.0.2.1'" "$LOG_STAGE3" 2>/dev/null; then
    pass "audit log records module failure after exhausted retries"
else
    fail "audit log missing module failure record"
fi

# -----------------------------------------------------------------------------
# Stage 4: Multi-Module Pipeline Continuation Across Partial Failure
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Multi-Module Pipeline Continuation Across Partial Failure"

OUT_DIR_STAGE4="$TEST_ROOT/stage4_continuation"
LOG_STAGE4="$TEST_ROOT/stage4.log"

stage4_exit=0
RECKON_MOCK_NMAP_BIN="$MOCK_FAIL_NMAP" \
"$RECKON_BIN" --module port,dns --target "failover.corp" --output "$OUT_DIR_STAGE4" --log-file "$LOG_STAGE4" >/dev/null 2>&1 || stage4_exit=$?

if (( stage4_exit == 1 )); then
    pass "scan overall exit code is 1 due to partial task failure in pipeline"
else
    fail "scan overall exit code was $stage4_exit (expected 1)"
fi

# Verify port directory recorded failure output
if [[ -f "$OUT_DIR_STAGE4/failover.corp/port/output.txt" ]] && \
   grep -q "Status: FAILED" "$OUT_DIR_STAGE4/failover.corp/port/output.txt" 2>/dev/null; then
    pass "failed module recorded FAILED status in task output"
else
    fail "failed module missing task failure artifact"
fi

# Verify dns directory executed and succeeded despite upstream port failure
if [[ -f "$OUT_DIR_STAGE4/failover.corp/dns/output.txt" ]] && \
   grep -q "DNS Reconnaissance" "$OUT_DIR_STAGE4/failover.corp/dns/output.txt" 2>/dev/null; then
    pass "pipeline continued execution and completed downstream module (dns)"
else
    fail "pipeline failed to execute downstream module (dns) after upstream failure"
fi

# Verify results.json exists and captures the scan state
if [[ -f "$OUT_DIR_STAGE4/results.json" && -s "$OUT_DIR_STAGE4/results.json" ]]; then
    pass "aggregated results.json generated successfully despite partial pipeline failure"
else
    fail "results.json not generated after partial pipeline failure"
fi

# -----------------------------------------------------------------------------
# Stage 5: Non-Critical Tool Dependency Fallback Resilience
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Non-Critical Tool Dependency Fallback Resilience"

OUT_DIR_STAGE5="$TEST_ROOT/stage5_fallbacks"
MOCK_CURL_FALLBACK="$TEST_ROOT/mock_curl_fallback.sh"

cat > "$MOCK_CURL_FALLBACK" << 'EOF'
#!/usr/bin/env bash
head_dest=""
for arg in "$@"; do
    if [[ "$arg" == "-D" ]]; then
        head_flag=true
    elif [[ "${head_flag:-}" == "true" ]]; then
        head_dest="$arg"
        unset head_flag
    fi
done

if [[ -n "$head_dest" ]]; then
    printf 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.56\r\nX-Powered-By: PHP/8.1\r\nContent-Length: 512\r\n\r\n' > "$head_dest"
fi
printf '<html><head><title>Test Portal</title></head><body>Welcome to Fallback App</body></html>\n'
exit 0
EOF
chmod 0755 "$MOCK_CURL_FALLBACK"

# Test 5A: Technology module falls back from missing whatweb to native curl heuristics
stage5a_exit=0
RECKON_MOCK_WHATWEB_BIN="none" \
RECKON_MOCK_CURL_BIN="$MOCK_CURL_FALLBACK" \
"$RECKON_BIN" --module technology --target "http://fallback.test" --output "$OUT_DIR_STAGE5" >/dev/null 2>&1 || stage5a_exit=$?

if (( stage5a_exit == 0 )); then
    pass "technology module completes cleanly when whatweb is absent (exit code: 0)"
else
    fail "technology module failed when whatweb is absent (exit: $stage5a_exit)"
fi

TECH_OUT_STAGE5="$OUT_DIR_STAGE5/http_fallback.test/technology/output.txt"
if [[ -f "$TECH_OUT_STAGE5" ]] && grep -q "curl fallback heuristics" "$TECH_OUT_STAGE5" 2>/dev/null; then
    pass "technology module engages native curl fallback heuristics engine"
else
    fail "technology module output missing curl fallback engine description"
fi

# Test 5B: Directory module falls back from missing ffuf to native curl dictionary fuzzing
stage5b_exit=0
RECKON_MOCK_FFUF_BIN="none" \
RECKON_MOCK_CURL_BIN="$MOCK_CURL_FALLBACK" \
"$RECKON_BIN" --module directory --target "http://fallback.test" --output "$OUT_DIR_STAGE5" >/dev/null 2>&1 || stage5b_exit=$?

if (( stage5b_exit == 0 )); then
    pass "directory module completes cleanly when ffuf is absent (exit code: 0)"
else
    fail "directory module failed when ffuf is absent (exit: $stage5b_exit)"
fi

DIR_OUT_STAGE5="$OUT_DIR_STAGE5/http_fallback.test/directory/output.txt"
if [[ -f "$DIR_OUT_STAGE5" ]] && grep -q "curl dictionary fuzzing" "$DIR_OUT_STAGE5" 2>/dev/null; then
    pass "directory module engages native curl dictionary fuzzing engine"
else
    fail "directory module output missing curl dictionary fuzzing engine description"
fi

# -----------------------------------------------------------------------------
# Stage 6: Target Unreachability & Clean Error Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Target Unreachability & Clean Error Handling"

OUT_DIR_STAGE6="$TEST_ROOT/stage6_unreachable"
MOCK_QUIET_FPING="$TEST_ROOT/mock_quiet_fping.sh"

cat > "$MOCK_QUIET_FPING" << 'EOF'
#!/usr/bin/env bash
# Inactive host returns exit code 1 with no live hosts
exit 1
EOF
chmod 0755 "$MOCK_QUIET_FPING"

stage6_exit=0
RECKON_MOCK_FPING_BIN="$MOCK_QUIET_FPING" \
"$RECKON_BIN" --module host --target "192.0.2.254" --output "$OUT_DIR_STAGE6" >/dev/null 2>&1 || stage6_exit=$?

if (( stage6_exit == 0 )); then
    pass "scan execution completes cleanly with code 0 on unreachable target"
else
    fail "scan execution exited with unexpected code $stage6_exit on unreachable target"
fi

HOST_OUT_STAGE6="$OUT_DIR_STAGE6/192.0.2.254/host/output.txt"
if [[ -f "$HOST_OUT_STAGE6" ]] && grep -q -E "Total Live Hosts.*0|No live hosts detected" "$HOST_OUT_STAGE6" 2>/dev/null; then
    pass "unreachable host correctly parsed as 0 discovered live hosts without engine crash"
else
    fail "host output missing or malformed for unreachable target"
fi

# -----------------------------------------------------------------------------
# Stage 7: Audit Log Diagnostics Trail & Summary Metrics
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Audit Log Diagnostics Trail & Summary Metrics"

OUT_DIR_STAGE7="$TEST_ROOT/stage7_audit"
LOG_STAGE7="$TEST_ROOT/stage7_audit.log"

RECKON_MOCK_NMAP_BIN="$MOCK_FAIL_NMAP" \
"$RECKON_BIN" --module port,dns --target "audit.corp" --output "$OUT_DIR_STAGE7" --log-file "$LOG_STAGE7" >/dev/null 2>&1 || true

if grep -q -E '\[[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] \[ERROR\]' "$LOG_STAGE7" 2>/dev/null; then
    pass "audit log contains ISO timestamped [ERROR] level diagnostics"
else
    fail "audit log missing structured ERROR entries"
fi

if grep -q "Scan execution finished" "$LOG_STAGE7" 2>/dev/null; then
    pass "audit log contains formal scan execution finished summary line"
else
    fail "audit log missing execution finished summary line"
fi

if grep -q "completed: 1, failed: 1, timeouts: 0, exit code: 1" "$LOG_STAGE7" 2>/dev/null; then
    pass "execution summary accurately records task metrics (completed: 1, failed: 1, exit: 1)"
else
    fail "execution summary reported inaccurate task counts in audit log"
fi

# -----------------------------------------------------------------------------
# Stage 8: Argument & Planning Error Resilience (Exit Code 2)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 8: Argument & Planning Error Resilience (Exit Code 2)"

# Test 8A: Invalid module identifier rejected with exit code 2
stage8a_status=0
STAGE8A_OUT="$("$RECKON_BIN" --module non_existent_mod --target 192.0.2.1 2>&1)" || stage8a_status=$?

if (( stage8a_status == 2 )); then
    pass "invalid module identifier rejected with CLI exit code 2"
else
    fail "invalid module produced exit code $stage8a_status (expected 2)"
fi

if [[ "$STAGE8A_OUT" == *"Invalid module"* || "$STAGE8A_OUT" == *"Error"* ]]; then
    pass "invalid module error message emitted to stderr"
else
    fail "missing expected error message for invalid module"
fi

# Test 8B: Incompatible target and module combination rejected during planning
stage8b_status=0
STAGE8B_OUT="$("$RECKON_BIN" --module subdomain --target 192.0.2.1 2>&1)" || stage8b_status=$?

if (( stage8b_status == 2 )); then
    pass "incompatible target and module selection rejected with exit code 2"
else
    fail "incompatible target/module selection produced exit code $stage8b_status (expected 2)"
fi

if [[ "$STAGE8B_OUT" == *"compatible"* || "$STAGE8B_OUT" == *"Error"* ]]; then
    pass "incompatible target/module error explanation emitted to stderr"
else
    fail "missing expected explanation for incompatible target/module selection"
fi

# -----------------------------------------------------------------------------
# Test Summary & Clean Exit
# -----------------------------------------------------------------------------
test_summary
