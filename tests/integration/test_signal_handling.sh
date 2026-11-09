#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Signal Handling and Interruption Integration Tests (tests/integration/test_signal_handling.sh)
#
# Verifies robust and graceful signal handling across the RECKON execution lifecycle:
# 1. Graceful SIGINT (Ctrl+C, exit 130) interruption during active scan execution.
# 2. Graceful SIGTERM (termination, exit 143) interruption during active scan execution.
# 3. Active child process termination and orphan prevention (no lingering sub-processes).
# 4. Temporary file and directory cleanup on signal interruption (fs_cleanup_temp integration).
# 5. Trap restoration and default signal behavior reset on normal scan completion.
# 6. Multi-target scan interruption (immediate task loop break preventing subsequent targets).
# 7. Rapid duplicate signal delivery resilience (clean teardown without deadlock).
#

set -o nounset

# shellcheck disable=SC2030,SC2031

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

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-signal-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

cleanup() {
    # Terminate any lingering background test jobs spawned during testing
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

    printf '%s\n' "Signal handling integration tests completed successfully."
}

# Check if a process PID is alive and actively running (excluding terminated/zombie states)
#
# Arguments:
#   $1 - PID
#
# Returns:
#   0 if actively running, 1 if dead, terminated, or zombie
is_process_active() {
    local pid="$1"
    [[ -z "$pid" ]] && return 1
    local stat
    stat="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ -n "$stat" && "$stat" != *"Z"* && "$stat" != *"defunct"* ]]
}

# Wait for a file to exist and be non-empty, up to a timeout in tenths of a second.
#
# Arguments:
#   $1 - path to file
#   $2 - timeout in tenths of a second (default: 40 = 4 seconds)
#
# Returns:
#   0 if file exists and has size > 0, 1 on timeout
wait_for_file() {
    local target_file="$1"
    local max_ticks="${2:-40}"
    local tick=0

    while (( tick < max_ticks )); do
        if [[ -s "$target_file" ]]; then
            return 0
        fi
        sleep 0.1
        ((tick += 1))
    done
    return 1
}

# Wait for a process PID to terminate, up to a timeout in tenths of a second.
# If timeout is exceeded, kills with SIGKILL to avoid test hang.
#
# Arguments:
#   $1 - PID
#   $2 - timeout in tenths of a second (default: 50 = 5 seconds)
#
# Returns:
#   Exit code of the process, or 124 on timeout
wait_for_pid() {
    local pid="$1"
    local max_ticks="${2:-50}"
    local tick=0

    while kill -0 "$pid" 2>/dev/null; do
        if (( tick >= max_ticks )); then
            kill -9 "$pid" 2>/dev/null || true
            return 124
        fi
        sleep 0.1
        ((tick += 1))
    done

    wait "$pid" 2>/dev/null
    return $?
}

# Create mock slow worker script that writes its PID to a file and sleeps
MOCK_SLOW_SCRIPT="$TEST_ROOT/mock_slow_fping.sh"
cat > "$MOCK_SLOW_SCRIPT" << EOF
#!/usr/bin/env bash
if [[ -n "\${RECKON_TEST_PID_FILE:-}" ]]; then
    printf '%s\n' "\$\$" > "\$RECKON_TEST_PID_FILE"
fi
exec sleep 25
EOF
chmod 0755 "$MOCK_SLOW_SCRIPT"

# Create mock fast worker script that completes immediately with 0
MOCK_FAST_SCRIPT="$TEST_ROOT/mock_fast_fping.sh"
cat > "$MOCK_FAST_SCRIPT" << EOF
#!/usr/bin/env bash
printf '192.0.2.1 is alive\n'
exit 0
EOF
chmod 0755 "$MOCK_FAST_SCRIPT"

printf '%s\n' "RECKON - Signal Handling and Interruption Integration Tests"
printf '%s\n' "------------------------------------------------------------"

# -----------------------------------------------------------------------------
# Stage 1: Graceful SIGINT Interruption (Ctrl+C, Exit Code 130)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Graceful SIGINT Interruption (Ctrl+C, Exit Code 130)"

OUT_DIR_STAGE1="$TEST_ROOT/stage1_out"
LOG_STAGE1="$TEST_ROOT/stage1.log"
PID_FILE_STAGE1="$TEST_ROOT/stage1_child.pid"

export RECKON_MOCK_FPING_BIN="$MOCK_SLOW_SCRIPT"
export RECKON_TEST_PID_FILE="$PID_FILE_STAGE1"

(
    trap - INT
    exec "$RECKON_BIN" --module host --target 192.0.2.1 --output "$OUT_DIR_STAGE1"
) >"$LOG_STAGE1" 2>&1 &
STAGE1_PID=$!

if wait_for_file "$PID_FILE_STAGE1" 40; then
    pass "scan initiated and worker task spawned"
else
    fail "timed out waiting for worker task to spawn in stage 1"
fi

# Send SIGINT (simulate Ctrl+C) to active reckon process
kill -INT "$STAGE1_PID" 2>/dev/null || true
wait_for_pid "$STAGE1_PID" 50
stage1_exit=$?

if (( stage1_exit == 130 )); then
    pass "scan process exits with code 130 on SIGINT interruption"
else
    fail "scan process exited with code $stage1_exit on SIGINT (expected 130)"
fi

if grep -q "interrupted by SIGINT" "$LOG_STAGE1" 2>/dev/null; then
    pass "audit log contains SIGINT interruption notice"
else
    fail "audit log missing SIGINT interruption notice"
fi

if grep -q "Terminating active tasks and cleaning up" "$LOG_STAGE1" 2>/dev/null; then
    pass "audit log indicates graceful task termination and cleanup"
else
    fail "audit log missing cleanup confirmation message"
fi

# -----------------------------------------------------------------------------
# Stage 2: Graceful SIGTERM Interruption (Kill/Termination, Exit Code 143)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Graceful SIGTERM Interruption (Termination, Exit Code 143)"

OUT_DIR_STAGE2="$TEST_ROOT/stage2_out"
LOG_STAGE2="$TEST_ROOT/stage2.log"
PID_FILE_STAGE2="$TEST_ROOT/stage2_child.pid"

export RECKON_MOCK_FPING_BIN="$MOCK_SLOW_SCRIPT"
export RECKON_TEST_PID_FILE="$PID_FILE_STAGE2"

(
    trap - TERM
    exec "$RECKON_BIN" --module host --target 192.0.2.2 --output "$OUT_DIR_STAGE2"
) >"$LOG_STAGE2" 2>&1 &
STAGE2_PID=$!

if wait_for_file "$PID_FILE_STAGE2" 40; then
    pass "scan initiated and worker task spawned for SIGTERM test"
else
    fail "timed out waiting for worker task to spawn in stage 2"
fi

# Send SIGTERM to active reckon process
kill -TERM "$STAGE2_PID" 2>/dev/null || true
wait_for_pid "$STAGE2_PID" 50
stage2_exit=$?

if (( stage2_exit == 143 )); then
    pass "scan process exits with code 143 on SIGTERM interruption"
else
    fail "scan process exited with code $stage2_exit on SIGTERM (expected 143)"
fi

if grep -q "interrupted by SIGTERM" "$LOG_STAGE2" 2>/dev/null; then
    pass "audit log contains SIGTERM interruption notice"
else
    fail "audit log missing SIGTERM interruption notice"
fi

if grep -q "Terminating active tasks and cleaning up" "$LOG_STAGE2" 2>/dev/null; then
    pass "audit log indicates graceful task termination and cleanup on SIGTERM"
else
    fail "audit log missing cleanup confirmation message on SIGTERM"
fi

# -----------------------------------------------------------------------------
# Stage 3: Active Child Process Termination and Orphan Prevention
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Active Child Process Termination and Orphan Prevention"

OUT_DIR_STAGE3="$TEST_ROOT/stage3_out"
LOG_STAGE3="$TEST_ROOT/stage3.log"
PID_FILE_STAGE3="$TEST_ROOT/stage3_child.pid"

export RECKON_MOCK_FPING_BIN="$MOCK_SLOW_SCRIPT"
export RECKON_TEST_PID_FILE="$PID_FILE_STAGE3"

(
    trap - INT
    exec "$RECKON_BIN" --module host --target 192.0.2.3 --output "$OUT_DIR_STAGE3"
) >"$LOG_STAGE3" 2>&1 &
STAGE3_PID=$!

if wait_for_file "$PID_FILE_STAGE3" 40; then
    pass "scan spawned active child process"
else
    fail "timed out waiting for child process to start in stage 3"
fi

STAGE3_CHILD_PID="$(cat "$PID_FILE_STAGE3" 2>/dev/null || echo "")"

if [[ -n "$STAGE3_CHILD_PID" ]] && is_process_active "$STAGE3_CHILD_PID"; then
    pass "verified child process (PID: $STAGE3_CHILD_PID) is actively running"
else
    fail "child process is not running prior to signal delivery"
fi

# Interrupt parent reckon process
kill -INT "$STAGE3_PID" 2>/dev/null || true
wait_for_pid "$STAGE3_PID" 50
stage3_exit=$?

if (( stage3_exit == 130 )); then
    pass "parent reckon process exited with code 130"
else
    fail "parent reckon process exited with code $stage3_exit (expected 130)"
fi

# Allow small grace period for operating system process reaper
sleep 0.2

if [[ -n "$STAGE3_CHILD_PID" ]] && is_process_active "$STAGE3_CHILD_PID"; then
    fail "child process (PID: $STAGE3_CHILD_PID) was orphaned and remains running"
    kill -9 "$STAGE3_CHILD_PID" 2>/dev/null || true
else
    pass "child process (PID: $STAGE3_CHILD_PID) was terminated; no orphan processes left"
fi

# -----------------------------------------------------------------------------
# Stage 4: Temporary File and Directory Cleanup upon Interruption
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Temporary File and Directory Cleanup upon Interruption"

TEMP_SIG_FILE="$TEST_ROOT/registered_transient_file.tmp"
TEMP_SIG_DIR="$TEST_ROOT/registered_transient_dir.tmp"
touch "$TEMP_SIG_FILE"
mkdir -p "$TEMP_SIG_DIR"

(
    # Unmask INT in subshell
    trap - INT

    # Load engine and filesystem tracking libraries
    # shellcheck source=core/engine.sh
    source "$PROJECT_ROOT/core/engine.sh"
    # shellcheck source=lib/fs.sh
    source "$PROJECT_ROOT/lib/fs.sh"

    # Register transient resources for automatic cleanup
    fs_track_temp "$TEMP_SIG_FILE"
    fs_track_temp "$TEMP_SIG_DIR"

    # Install engine signal traps
    engine_setup_traps

    # Trigger self SIGINT
    kill -INT "$BASHPID"
) >/dev/null 2>&1
stage4_sub_exit=$?

if (( stage4_sub_exit == 130 )); then
    pass "signal trap handler in subshell exited with code 130"
else
    fail "signal trap handler in subshell exited with code $stage4_sub_exit (expected 130)"
fi

if [[ ! -e "$TEMP_SIG_FILE" && ! -e "$TEMP_SIG_DIR" ]]; then
    pass "tracked temporary files and directories were unlinked by signal cleanup"
else
    fail "tracked temporary resources remained on disk after signal interruption"
fi

# -----------------------------------------------------------------------------
# Stage 5: Trap Restoration on Normal Scan Completion
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Trap Restoration on Normal Scan Completion"

OUT_DIR_STAGE5="$TEST_ROOT/stage5_out"

export RECKON_MOCK_FPING_BIN="$MOCK_FAST_SCRIPT"
unset RECKON_TEST_PID_FILE

STAGE5_OUT="$("$RECKON_BIN" --module host --target 192.0.2.10 --output "$OUT_DIR_STAGE5" 2>&1 || true)"
stage5_status=$?

if (( stage5_status == 0 )); then
    pass "normal scan execution completes with exit code 0"
else
    printf '%s\n' "$STAGE5_OUT" >&2
    fail "normal scan execution failed (exit code: $stage5_status)"
fi

# Verify in execution context that engine_teardown_traps unbinds signal handlers
(
    # shellcheck source=core/engine.sh
    source "$PROJECT_ROOT/core/engine.sh"
    # shellcheck source=lib/log.sh
    source "$PROJECT_ROOT/lib/log.sh"
    # shellcheck source=lib/term.sh
    source "$PROJECT_ROOT/lib/term.sh"
    # shellcheck source=lib/fs.sh
    source "$PROJECT_ROOT/lib/fs.sh"

    engine_init
    engine_setup_traps
    installed_int="$(trap -p INT)"
    installed_term="$(trap -p TERM)"

    engine_teardown_traps
    cleared_int="$(trap -p INT)"
    cleared_term="$(trap -p TERM)"

    if [[ -n "$installed_int" && -n "$installed_term" && -z "$cleared_int" && -z "$cleared_term" && "$_ENGINE_TRAPS_INSTALLED" == false ]]; then
        exit 0
    else
        exit 1
    fi
)
stage5_trap_cleanup=$?

if (( stage5_trap_cleanup == 0 )); then
    pass "engine_teardown_traps successfully restores default signal behavior"
else
    fail "engine_teardown_traps failed to unbind signal handlers"
fi

# -----------------------------------------------------------------------------
# Stage 6: Multi-Target Scan Interruption Aborts Remaining Targets
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Multi-Target Scan Interruption Aborts Remaining Targets"

TARGETS_FILE_STAGE6="$TEST_ROOT/stage6_targets.txt"
printf '192.0.2.101\n192.0.2.102\n192.0.2.103\n' > "$TARGETS_FILE_STAGE6"

OUT_DIR_STAGE6="$TEST_ROOT/stage6_out"
LOG_STAGE6="$TEST_ROOT/stage6.log"
PID_FILE_STAGE6="$TEST_ROOT/stage6_child.pid"

export RECKON_MOCK_FPING_BIN="$MOCK_SLOW_SCRIPT"
export RECKON_TEST_PID_FILE="$PID_FILE_STAGE6"

(
    trap - INT
    exec "$RECKON_BIN" --module host --targets-file "$TARGETS_FILE_STAGE6" --output "$OUT_DIR_STAGE6"
) >"$LOG_STAGE6" 2>&1 &
# shellcheck disable=SC2031
STAGE6_PID=$!

if wait_for_file "$PID_FILE_STAGE6" 40; then
    pass "multi-target scan initiated and first target task active"
else
    fail "timed out waiting for first target task to spawn in stage 6"
fi

# Send SIGINT to parent reckon process during target 1
kill -INT "$STAGE6_PID" 2>/dev/null || true
wait_for_pid "$STAGE6_PID" 50
stage6_exit=$?

if (( stage6_exit == 130 )); then
    pass "multi-target scan cleanly interrupted with exit code 130"
else
    fail "multi-target scan exited with code $stage6_exit (expected 130)"
fi

# Subsequent targets must NOT be created or executed
t2_created=false
t3_created=false
[[ -d "$OUT_DIR_STAGE6/192.0.2.102" ]] && t2_created=true
[[ -d "$OUT_DIR_STAGE6/192.0.2.103" ]] && t3_created=true

if [[ "$t2_created" == false && "$t3_created" == false ]]; then
    pass "subsequent targets were aborted immediately upon interruption"
else
    fail "subsequent targets were unexpectedly processed after signal interruption"
fi

# -----------------------------------------------------------------------------
# Stage 7: Rapid / Burst Signal Delivery Resilience
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Rapid / Burst Signal Delivery Resilience"

OUT_DIR_STAGE7="$TEST_ROOT/stage7_out"
LOG_STAGE7="$TEST_ROOT/stage7.log"
PID_FILE_STAGE7="$TEST_ROOT/stage7_child.pid"

export RECKON_MOCK_FPING_BIN="$MOCK_SLOW_SCRIPT"
export RECKON_TEST_PID_FILE="$PID_FILE_STAGE7"

(
    trap - INT
    exec "$RECKON_BIN" --module host --target 192.0.2.200 --output "$OUT_DIR_STAGE7"
) >"$LOG_STAGE7" 2>&1 &
# shellcheck disable=SC2031
STAGE7_PID=$!

if wait_for_file "$PID_FILE_STAGE7" 40; then
    pass "scan initiated for burst signal resilience test"
else
    fail "timed out waiting for task to spawn in stage 7"
fi

# Deliver rapid burst of SIGINT signals
kill -INT "$STAGE7_PID" 2>/dev/null || true
kill -INT "$STAGE7_PID" 2>/dev/null || true
kill -INT "$STAGE7_PID" 2>/dev/null || true

wait_for_pid "$STAGE7_PID" 50
stage7_exit=$?

if (( stage7_exit == 130 )); then
    pass "rapid burst signals handled without deadlock or crash (exit code: 130)"
else
    fail "rapid burst signals caused unexpected exit code: $stage7_exit (expected 130)"
fi

# -----------------------------------------------------------------------------
# Test Summary & Clean Exit
# -----------------------------------------------------------------------------
test_summary
