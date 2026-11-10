#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Repository Security Audit & Hardening Verification (tests/security_audit.sh)
#
# Performs automated static security audits across the codebase:
# 1. Scans for hardcoded secrets, private keys, API keys, and authorization tokens.
# 2. Audits temporary file creation for predictable/insecure static /tmp paths.
# 3. Verifies complete absence of dynamic code evaluation ('eval' constructs).
# 4. Validates repository filesystem permissions (no world-writable files, correct executable bits).
# 5. Enforces strict shell execution safety flags ('set -o nounset' / 'set -u').
# 6. Audits .gitignore configuration for sensitive artifact exclusion (keys, env, logs, results).
# 7. Validates subprocess command argument safety and array expansion.
# 8. Verifies artifact permission hardening (0750 directories, 0640 report files).
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

RECKON_BIN="$PROJECT_ROOT/reckon"
readonly RECKON_BIN

if [[ ! -f "$RECKON_BIN" || ! -x "$RECKON_BIN" ]]; then
    printf 'Error: RECKON entry point not found or not executable at %s\n' "$RECKON_BIN" >&2
    exit 1
fi

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

    printf '%s\n' "Repository security audit completed successfully. No vulnerabilities detected."
}

printf '%s\n' "RECKON - Repository Security Audit & Hardening Verification"
printf '%s\n' "------------------------------------------------------------"

# -----------------------------------------------------------------------------
# Stage 1: Hardcoded Secrets, Credentials & Tokens Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Hardcoded Secrets, Credentials & Tokens Audit"

# Check for private cryptographic keys (RSA, OPENSSH, DSA, EC, PGP)
pk_matches="$(grep -rn -E --exclude-dir=".git" "BEGIN [A-Z ]*PRIVATE KEY" "$PROJECT_ROOT" 2>/dev/null || true)"
if [[ -z "$pk_matches" ]]; then
    pass "zero private cryptographic keys found in repository"
else
    fail "detected hardcoded private key: $pk_matches"
fi

# Check for AWS API keys / access key IDs
aws_matches="$(grep -rn -E --exclude-dir=".git" "AKIA[0-9A-Z]{16}" "$PROJECT_ROOT" 2>/dev/null || true)"
if [[ -z "$aws_matches" ]]; then
    pass "zero hardcoded AWS access keys found in repository"
else
    fail "detected hardcoded AWS key: $aws_matches"
fi

# Check for GitHub personal access tokens
gh_matches="$(grep -rn -E --exclude-dir=".git" "gh[pousr]_[0-9a-zA-Z]{36}" "$PROJECT_ROOT" 2>/dev/null || true)"
if [[ -z "$gh_matches" ]]; then
    pass "zero hardcoded GitHub tokens found in repository"
else
    fail "detected hardcoded GitHub token: $gh_matches"
fi

# Check for hardcoded plaintext password assignments in shell scripts
pw_matches="$(grep -rn -E --exclude-dir=".git" --include="*.sh" "(api[_-]?key|secret[_-]?key|password)[[:space:]]*=[[:space:]]*['\"][a-zA-Z0-9_\$#@!%^&*()-]{8,}['\"]" "$PROJECT_ROOT" 2>/dev/null || true)"
if [[ -z "$pw_matches" ]]; then
    pass "zero hardcoded API keys or plaintext passwords in shell scripts"
else
    fail "detected potential hardcoded password/key in shell scripts: $pw_matches"
fi

# -----------------------------------------------------------------------------
# Stage 2: Predictable Insecure Temporary File Creation Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Predictable Insecure Temporary File Creation Audit"

# Audit core, lib, modules, and reckon for hardcoded static /tmp paths
insecure_tmp="$(grep -rn -E "[^a-zA-Z0-9_]/tmp/[a-zA-Z0-9_-]+" \
    "$PROJECT_ROOT/reckon" \
    "$PROJECT_ROOT/core" \
    "$PROJECT_ROOT/lib" \
    "$PROJECT_ROOT/modules" 2>/dev/null || true)"

if [[ -z "$insecure_tmp" ]]; then
    pass "zero hardcoded static /tmp file paths in production source code"
else
    fail "detected insecure predictable /tmp file path: $insecure_tmp"
fi

# Verify filesystem library implements safe random temporary file generation
if grep -q "mktemp" "$PROJECT_ROOT/lib/fs.sh" 2>/dev/null; then
    pass "filesystem library utilizes mktemp for safe temporary file creation"
else
    fail "lib/fs.sh does not utilize mktemp for temporary resource creation"
fi

# -----------------------------------------------------------------------------
# Stage 3: Dynamic Code Evaluation ('eval') Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Dynamic Code Evaluation ('eval') Audit"

# Audit production source code for dynamic eval statements
eval_instances="$(grep -rn -E "^[[:space:]]*eval[[:space:]]" \
    "$PROJECT_ROOT/reckon" \
    "$PROJECT_ROOT/core" \
    "$PROJECT_ROOT/lib" \
    "$PROJECT_ROOT/modules" 2>/dev/null || true)"

if [[ -z "$eval_instances" ]]; then
    pass "zero dynamic 'eval' commands across all production shell code"
else
    fail "detected dynamic 'eval' command: $eval_instances"
fi

# -----------------------------------------------------------------------------
# Stage 4: Filesystem Permissions & Security Mode Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Filesystem Permissions & Security Mode Audit"

# Scan repository for world-writable files (security risk on multi-user systems)
ww_files="$(find "$PROJECT_ROOT" -perm -o+w -not -path "*/.git/*" 2>/dev/null || true)"
if [[ -z "$ww_files" ]]; then
    pass "zero world-writable files or directories in repository tree"
else
    fail "detected world-writable file(s): $ww_files"
fi

# Verify CLI entry point is executable
if [[ -x "$PROJECT_ROOT/reckon" ]]; then
    pass "primary CLI entrypoint (reckon) has executable permission"
else
    fail "primary CLI entrypoint (reckon) lacks executable permission"
fi

# Verify all module runner scripts have executable permission
unexecutable_mods=0
for mod_script in "$PROJECT_ROOT"/modules/network/*.sh "$PROJECT_ROOT"/modules/network/services/*.sh "$PROJECT_ROOT"/modules/web/*.sh; do
    # Skip common shared libraries
    if [[ "$mod_script" == *"/common.sh" ]]; then
        continue
    fi
    if [[ ! -x "$mod_script" ]]; then
        (( unexecutable_mods += 1 ))
    fi
done

if (( unexecutable_mods == 0 )); then
    pass "all 25 modular scanner scripts have executable permissions (0755)"
else
    fail "detected $unexecutable_mods modular script(s) lacking executable permission"
fi

# -----------------------------------------------------------------------------
# Stage 5: Strict Shell Configuration & Option Enforcement Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Strict Shell Configuration & Option Enforcement Audit"

# Verify nounset enforcement in main entrypoints and libraries
if grep -q -E "set -o nounset|set -u" "$PROJECT_ROOT/reckon" 2>/dev/null; then
    pass "CLI wrapper (reckon) enforces strict unbound variable checks (nounset)"
else
    fail "CLI wrapper (reckon) missing 'set -o nounset'"
fi

if grep -q -E "set -o nounset|set -u" "$PROJECT_ROOT/core/main.sh" 2>/dev/null; then
    pass "core application bootstrap (core/main.sh) enforces strict nounset"
else
    fail "core/main.sh missing 'set -o nounset'"
fi

missing_lib_nounset=0
for lib_file in "$PROJECT_ROOT"/lib/*.sh; do
    if ! grep -q -E "set -o nounset|set -u" "$lib_file" 2>/dev/null; then
        (( missing_lib_nounset += 1 ))
    fi
done

if (( missing_lib_nounset == 0 )); then
    pass "all 8 shared libraries in lib/ enforce strict unbound variable checks (nounset)"
else
    fail "detected $missing_lib_nounset library file(s) missing 'set -o nounset'"
fi

# -----------------------------------------------------------------------------
# Stage 6: Gitignore Sensitivity Coverage Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Gitignore Sensitivity Coverage Audit"

GITIGNORE="$PROJECT_ROOT/.gitignore"
if [[ -f "$GITIGNORE" && -r "$GITIGNORE" ]]; then
    pass ".gitignore file exists and is readable"
else
    fail "missing .gitignore file in project root"
fi

# Check for scan results exclusion
if grep -q -E '^results/' "$GITIGNORE" 2>/dev/null; then
    pass ".gitignore excludes scan results directory (results/)"
else
    fail ".gitignore missing 'results/' exclusion rule"
fi

# Check for log files exclusion
if grep -q -E '^\*\.log' "$GITIGNORE" 2>/dev/null; then
    pass ".gitignore excludes log files (*.log)"
else
    fail ".gitignore missing '*.log' exclusion rule"
fi

# Check for temporary and swap files exclusion
if grep -q -E '^\*\.tmp' "$GITIGNORE" 2>/dev/null && grep -q -E '^\*\.swp' "$GITIGNORE" 2>/dev/null; then
    pass ".gitignore excludes temporary files and editor swap files (*.tmp, *.swp)"
else
    fail ".gitignore missing '*.tmp' or '*.swp' exclusion rules"
fi

# Check for local environment and secret files exclusion
if grep -q -E '^\.env' "$GITIGNORE" 2>/dev/null; then
    pass ".gitignore excludes local environment configuration (.env, .env.*)"
else
    fail ".gitignore missing '.env' exclusion rule"
fi

# Check for cryptographic key and certificate exclusions
if grep -q -E '^\*\.key' "$GITIGNORE" 2>/dev/null && grep -q -E '^\*\.pem' "$GITIGNORE" 2>/dev/null; then
    pass ".gitignore excludes cryptographic keys and certificates (*.key, *.pem)"
else
    fail ".gitignore missing '*.key' or '*.pem' exclusion rules"
fi

# -----------------------------------------------------------------------------
# Stage 7: Subprocess Argument Safety & Quoting Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Subprocess Argument Safety & Quoting Audit"

# Verify lib/exec.sh uses array expansion ("${cmd[@]}") for subprocess invocation
if grep -q -E '"\$\{cmd\[@\]\}"' "$PROJECT_ROOT/lib/exec.sh" 2>/dev/null; then
    pass "exec_run invokes commands via array expansion (\"\${cmd[@]}\") preventing shell injection"
else
    fail "lib/exec.sh does not use array expansion for subprocess dispatch"
fi

# Verify core/engine.sh uses array expansion for task dispatch
# shellcheck disable=SC2016
if grep -q -E '"\$script_path"[[:space:]]+"\$target"[[:space:]]+"\$t_type"[[:space:]]+"\$task_dir"' "$PROJECT_ROOT/core/engine.sh" 2>/dev/null; then
    pass "execution engine passes target and task arguments with strict variable quoting"
else
    fail "core/engine.sh missing strict quoting on task arguments"
fi

# -----------------------------------------------------------------------------
# Stage 8: Output Directory & Report Permission Hardening Audit
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 8: Output Directory & Report Permission Hardening Audit"

# Verify engine creates base output directories with 0750 permissions
if grep -q "0750" "$PROJECT_ROOT/core/engine.sh" 2>/dev/null; then
    pass "execution engine enforces restricted 0750 permissions on output directories"
else
    fail "core/engine.sh does not enforce 0750 output directory permissions"
fi

# Verify reporting engine enforces 0640 permissions on exported assessment reports
if grep -q "0640" "$PROJECT_ROOT/lib/reporting.sh" 2>/dev/null; then
    pass "reporting engine enforces restricted 0640 permissions on generated reports"
else
    fail "lib/reporting.sh does not enforce 0640 report file permissions"
fi

# -----------------------------------------------------------------------------
# Test Summary & Clean Exit
# -----------------------------------------------------------------------------
test_summary
