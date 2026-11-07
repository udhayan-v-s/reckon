#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Execution engine core unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=core/engine.sh
if ! source "$PROJECT_ROOT/core/engine.sh"; then
    printf 'Error: Unable to load execution engine core component.\n' >&2
    exit 1
fi

# shellcheck source=core/cli.sh
if ! source "$PROJECT_ROOT/core/cli.sh"; then
    printf 'Error: Unable to load CLI component.\n' >&2
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

    printf '%s\n' "Execution engine unit tests completed."
}

printf '%s\n' "RECKON - Execution Engine Unit Tests"
printf '%s\n' "--------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Inventory & Canonical Sequences
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Inventory & Canonical Sequences"

# Test 1: Idempotent re-sourcing guard
if source "$PROJECT_ROOT/core/engine.sh"; then
    pass "Idempotent re-sourcing causes no errors or conflicts"
else
    fail "Re-sourcing core/engine.sh failed"
fi

# Test 2: Canonical counts
total_count=0
while IFS= read -r mod; do
    [[ -n "$mod" ]] && ((total_count += 1))
done < <(engine_get_all_modules)

if (( total_count == 25 )); then
    pass "engine_get_all_modules returns exactly 25 canonical modules"
else
    fail "engine_get_all_modules returned $total_count modules (expected 25)"
fi

# Test 3: Network module count
net_count=0
while IFS= read -r mod; do
    [[ -n "$mod" ]] && ((net_count += 1))
done < <(engine_get_network_modules)

if (( net_count == 11 )); then
    pass "engine_get_network_modules returns exactly 11 network modules"
else
    fail "engine_get_network_modules returned $net_count modules (expected 11)"
fi

# Test 4: Web module count
web_count=0
while IFS= read -r mod; do
    [[ -n "$mod" ]] && ((web_count += 1))
done < <(engine_get_web_modules)

if (( web_count == 14 )); then
    pass "engine_get_web_modules returns exactly 14 web modules"
else
    fail "engine_get_web_modules returned $web_count modules (expected 14)"
fi

# Test 5: Concordance with CLI canonical module list
cli_diff=false
while IFS= read -r cli_mod; do
    if ! engine_is_valid_module "$cli_mod"; then
        cli_diff=true
        break
    fi
done < <(_cli_valid_modules)

if [[ "$cli_diff" == false ]]; then
    pass "All CLI valid modules match engine canonical registry"
else
    fail "Mismatch between CLI module list and engine canonical registry"
fi

# -----------------------------------------------------------------------------
# UT-02: Module Validation & Categorization
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Module Validation & Categorization"

# Test 6: engine_is_valid_module
if engine_is_valid_module "host" && engine_is_valid_module "subdomain" && engine_is_valid_module "tls"; then
    pass "engine_is_valid_module identifies valid modules"
else
    fail "engine_is_valid_module failed on valid modules"
fi

# Test 7: engine_is_valid_module rejects invalid/empty identifiers
if ! engine_is_valid_module "invalid_xyz" && ! engine_is_valid_module ""; then
    pass "engine_is_valid_module rejects invalid and empty identifiers"
else
    fail "engine_is_valid_module accepted invalid identifier"
fi

# Test 8: engine_get_module_category for network modules
all_net_valid=true
while IFS= read -r mod; do
    cat="$(engine_get_module_category "$mod")"
    if [[ "$cat" != "network" ]]; then
        all_net_valid=false
    fi
done < <(engine_get_network_modules)

if [[ "$all_net_valid" == true ]]; then
    pass "engine_get_module_category returns 'network' for all 11 network modules"
else
    fail "engine_get_module_category miscategorized a network module"
fi

# Test 9: engine_get_module_category for web modules
all_web_valid=true
while IFS= read -r mod; do
    cat="$(engine_get_module_category "$mod")"
    if [[ "$cat" != "web" ]]; then
        all_web_valid=false
    fi
done < <(engine_get_web_modules)

if [[ "$all_web_valid" == true ]]; then
    pass "engine_get_module_category returns 'web' for all 14 web modules"
else
    fail "engine_get_module_category miscategorized a web module"
fi

# Test 10: engine_get_module_category rejects invalid module
if ! engine_get_module_category "nonexistent_module" >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"Invalid module identifier"* ]]; then
        pass "engine_get_module_category rejects invalid module and populates ENGINE_ERROR"
    else
        fail "engine_get_module_category did not set expected ENGINE_ERROR: $ENGINE_ERROR"
    fi
else
    fail "engine_get_module_category accepted invalid module"
fi

# -----------------------------------------------------------------------------
# UT-03: Human-Readable Metadata & Descriptions
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: Human-Readable Metadata & Descriptions"

# Test 11: Display names for all 25 modules
all_names_valid=true
while IFS= read -r mod; do
    name="$(engine_get_module_name "$mod")"
    if [[ -z "$name" || "$name" == "$mod" ]]; then
        all_names_valid=false
    fi
done < <(engine_get_all_modules)

if [[ "$all_names_valid" == true ]]; then
    pass "engine_get_module_name returns descriptive display titles for all 25 modules"
else
    fail "engine_get_module_name failed to return friendly name for a module"
fi

# Test 12: Functional summaries for all 25 modules
all_desc_valid=true
while IFS= read -r mod; do
    desc="$(engine_get_module_desc "$mod")"
    if [[ -z "$desc" || "$desc" == *"Reconnaissance module"* ]]; then
        all_desc_valid=false
    fi
done < <(engine_get_all_modules)

if [[ "$all_desc_valid" == true ]]; then
    pass "engine_get_module_desc returns specific summaries for all 25 modules"
else
    fail "engine_get_module_desc returned missing or generic description"
fi

# Test 13: Fallback display for unknown module
unknown_name="$(engine_get_module_name "custom_unknown_123")"
if [[ "$unknown_name" == "custom_unknown_123" ]]; then
    pass "engine_get_module_name falls back to raw identifier for unknown module"
else
    fail "engine_get_module_name fallback mismatch: $unknown_name"
fi

# -----------------------------------------------------------------------------
# UT-04: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Target Type Compatibility Rules"

# Test 14: All 25 modules resolve non-empty target types
all_targets_resolved=true
while IFS= read -r mod; do
    types=()
    while IFS= read -r t; do
        [[ -n "$t" ]] && types+=("$t")
    done < <(engine_get_module_target_types "$mod")

    if (( ${#types[@]} == 0 )); then
        all_targets_resolved=false
    fi
done < <(engine_get_all_modules)

if [[ "$all_targets_resolved" == true ]]; then
    pass "All 25 modules define compatible target type sets"
else
    fail "One or more modules failed to define target types"
fi

# Test 15: Host discovery target compatibility (supports CIDR, range, IP, names)
if engine_is_module_compatible "host" "ipv4" && \
   engine_is_module_compatible "host" "ipv4_cidr" && \
   engine_is_module_compatible "host" "ipv4_range" && \
   engine_is_module_compatible "host" "domain"; then
    pass "Host discovery correctly accepts CIDR, ranges, single IPs, and domains"
else
    fail "Host discovery target compatibility rules failed"
fi

# Test 16: DNS reconnaissance target compatibility
if engine_is_module_compatible "dns" "domain" && \
   engine_is_module_compatible "dns" "hostname" && \
   ! engine_is_module_compatible "dns" "ipv4" && \
   ! engine_is_module_compatible "dns" "url_http"; then
    pass "DNS reconnaissance requires domain/hostname and rejects raw IPv4/URLs"
else
    fail "DNS reconnaissance compatibility rules failed"
fi

# Test 17: Subdomain enumeration requires domain
if engine_is_module_compatible "subdomain" "domain" && \
   ! engine_is_module_compatible "subdomain" "ipv4" && \
   ! engine_is_module_compatible "subdomain" "url_http"; then
    pass "Subdomain enumeration accepts domain and rejects raw IPv4 or URLs"
else
    fail "Subdomain enumeration compatibility rules failed"
fi

# Test 18: Web crawling and endpoint discovery
if engine_is_module_compatible "crawl" "url_http" && \
   engine_is_module_compatible "crawl" "url_https" && \
   engine_is_module_compatible "crawl" "domain" && \
   ! engine_is_module_compatible "crawl" "ipv4_cidr"; then
    pass "Web crawling accepts HTTP/HTTPS URLs and domains but rejects CIDR blocks"
else
    fail "Web crawling compatibility rules failed"
fi

# Test 19: Port scanning requires single host/IP
if engine_is_module_compatible "port" "ipv4" && \
   engine_is_module_compatible "port" "hostname" && \
   ! engine_is_module_compatible "port" "ipv4_cidr"; then
    pass "Port scanning accepts single hosts/IPs but rejects multi-host CIDRs"
else
    fail "Port scanning compatibility rules failed"
fi

# Test 20: Empty argument handling
if ! engine_is_module_compatible "" "ipv4" && ! engine_is_module_compatible "port" ""; then
    pass "engine_is_module_compatible returns non-zero on empty inputs"
else
    fail "engine_is_module_compatible accepted empty input"
fi

# -----------------------------------------------------------------------------
# UT-05: State Initialization & Counters
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: State Initialization & Counters"

# Test 21: engine_init resets state
ENGINE_TOTAL_TASKS=10
ENGINE_COMPLETED_TASKS=5
ENGINE_FAILED_TASKS=2
ENGINE_SKIPPED_TASKS=2
ENGINE_TIMEOUT_TASKS=1
ENGINE_ERROR="stale error"

engine_init

if (( ENGINE_TOTAL_TASKS == 0 && \
      ENGINE_COMPLETED_TASKS == 0 && \
      ENGINE_FAILED_TASKS == 0 && \
      ENGINE_SKIPPED_TASKS == 0 && \
      ENGINE_TIMEOUT_TASKS == 0 )) && \
   [[ -z "$ENGINE_ERROR" ]]; then
    pass "engine_init resets all task counters and error message"
else
    fail "engine_init failed to reset state"
fi

# -----------------------------------------------------------------------------
# UT-06: Module Resolution (engine_resolve_modules)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Module Resolution (engine_resolve_modules)"

# Test 22: Network mode resolves 11 network modules
engine_init
if engine_resolve_modules "true" "false" "" ""; then
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 11 )) && \
       [[ "${ENGINE_RESOLVED_MODULES[0]}" == "host" && "${ENGINE_RESOLVED_MODULES[10]}" == "telnet" ]]; then
        pass "engine_resolve_modules resolves all 11 network modules in order"
    else
        fail "engine_resolve_modules network mode resolved unexpected modules: ${ENGINE_RESOLVED_MODULES[*]}"
    fi
else
    fail "engine_resolve_modules failed on network mode"
fi

# Test 23: Web mode resolves 14 web modules
engine_init
if engine_resolve_modules "false" "true" "" ""; then
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 14 )) && \
       [[ "${ENGINE_RESOLVED_MODULES[0]}" == "http-probe" && "${ENGINE_RESOLVED_MODULES[13]}" == "historical-urls" ]]; then
        pass "engine_resolve_modules resolves all 14 web modules in order"
    else
        fail "engine_resolve_modules web mode resolved unexpected modules: ${ENGINE_RESOLVED_MODULES[*]}"
    fi
else
    fail "engine_resolve_modules failed on web mode"
fi

# Test 24: Combined network and web resolves all 25 modules
engine_init
if engine_resolve_modules "true" "true" "" ""; then
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 25 )); then
        pass "engine_resolve_modules resolves all 25 modules when both modes active"
    else
        fail "engine_resolve_modules combined mode count mismatch: ${#ENGINE_RESOLVED_MODULES[@]}"
    fi
else
    fail "engine_resolve_modules failed on combined mode"
fi

# Test 25: Explicit modules selection
engine_init
if engine_resolve_modules "false" "false" "host,dns,subdomain" ""; then
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 3 )) && \
       [[ "${ENGINE_RESOLVED_MODULES[0]}" == "host" && "${ENGINE_RESOLVED_MODULES[1]}" == "dns" && "${ENGINE_RESOLVED_MODULES[2]}" == "subdomain" ]]; then
        pass "engine_resolve_modules resolves explicit module selection in order"
    else
        fail "engine_resolve_modules explicit selection mismatch: ${ENGINE_RESOLVED_MODULES[*]}"
    fi
else
    fail "engine_resolve_modules failed on explicit selection"
fi

# Test 26: Exclusion filter pruning
engine_init
if engine_resolve_modules "true" "false" "" "port,telnet"; then
    contains_excluded=false
    for m in "${ENGINE_RESOLVED_MODULES[@]}"; do
        if [[ "$m" == "port" || "$m" == "telnet" ]]; then
            contains_excluded=true
            break
        fi
    done
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 9 )) && [[ "$contains_excluded" == false ]]; then
        pass "engine_resolve_modules correctly prunes excluded modules"
    else
        fail "engine_resolve_modules exclusion filter failed: ${ENGINE_RESOLVED_MODULES[*]}"
    fi
else
    fail "engine_resolve_modules failed with exclusions"
fi

# Test 27: Deduplication of candidate modules
engine_init
if engine_resolve_modules "false" "false" "host,dns,host,dns" ""; then
    if (( ${#ENGINE_RESOLVED_MODULES[@]} == 2 )); then
        pass "engine_resolve_modules deduplicates repeated module selections"
    else
        fail "engine_resolve_modules failed to deduplicate: ${ENGINE_RESOLVED_MODULES[*]}"
    fi
else
    fail "engine_resolve_modules failed on duplicate modules"
fi

# Test 28: Rejecting invalid module name
engine_init
if ! engine_resolve_modules "false" "false" "host,invalid_module_xyz" "" >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"Invalid module identifier"* ]]; then
        pass "engine_resolve_modules rejects invalid module identifier and records ENGINE_ERROR"
    else
        fail "engine_resolve_modules unexpected error: $ENGINE_ERROR"
    fi
else
    fail "engine_resolve_modules accepted invalid module identifier"
fi

# Test 29: Failing when all candidate modules are excluded
engine_init
if ! engine_resolve_modules "false" "false" "dns" "dns" >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"No modules remaining"* ]]; then
        pass "engine_resolve_modules fails when all modules are excluded"
    else
        fail "engine_resolve_modules unexpected error on full exclusion: $ENGINE_ERROR"
    fi
else
    fail "engine_resolve_modules succeeded when all modules excluded"
fi

# Test 30: Failing when no scan mode or modules are specified
engine_init
if ! engine_resolve_modules "false" "false" "" "" >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"No scan mode"* ]]; then
        pass "engine_resolve_modules fails with clear error when no mode/module specified"
    else
        fail "engine_resolve_modules unexpected error: $ENGINE_ERROR"
    fi
else
    fail "engine_resolve_modules accepted empty scan mode"
fi

# -----------------------------------------------------------------------------
# UT-07: Scan Planning & Execution Graph (engine_plan_scan)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Scan Planning & Execution Graph (engine_plan_scan)"

# Test 31: Planning against single IPv4 target
TARGET_VALUE=("192.0.2.10")
TARGET_TYPE=("ipv4")
engine_init
engine_resolve_modules "true" "false" "" ""

if engine_plan_scan; then
    # In network mode, 'dns' is incompatible with raw ipv4, while other 10 network modules are compatible
    if (( ENGINE_TOTAL_TASKS == 10 )) && (( ENGINE_SKIPPED_TASKS == 1 )); then
        pass "engine_plan_scan schedules compatible modules for IPv4 target and skips 'dns'"
    else
        fail "engine_plan_scan IPv4 task count mismatch: total=$ENGINE_TOTAL_TASKS, skipped=$ENGINE_SKIPPED_TASKS"
    fi
else
    fail "engine_plan_scan failed for IPv4 target"
fi

# Test 32: Planning against domain target
TARGET_VALUE=("example.com")
TARGET_TYPE=("domain")
engine_init
engine_resolve_modules "true" "false" "" ""

if engine_plan_scan; then
    # In network mode, domain target is compatible with all 11 network modules
    if (( ENGINE_TOTAL_TASKS == 11 )) && (( ENGINE_SKIPPED_TASKS == 0 )); then
        pass "engine_plan_scan schedules all 11 network modules for domain target"
    else
        fail "engine_plan_scan domain task count mismatch: total=$ENGINE_TOTAL_TASKS, skipped=$ENGINE_SKIPPED_TASKS"
    fi
else
    fail "engine_plan_scan failed for domain target"
fi

# Test 33: Planning against CIDR block
TARGET_VALUE=("192.168.1.0/24")
TARGET_TYPE=("ipv4_cidr")
engine_init
engine_resolve_modules "true" "false" "" ""

if engine_plan_scan; then
    # CIDR block is only compatible with 'host' discovery in network mode; other 10 are skipped
    if (( ENGINE_TOTAL_TASKS == 1 )) && [[ "${ENGINE_PLAN_MODULES[0]}" == "host" ]] && (( ENGINE_SKIPPED_TASKS == 10 )); then
        pass "engine_plan_scan schedules only multi-host discovery for CIDR blocks"
    else
        fail "engine_plan_scan CIDR task count mismatch: total=$ENGINE_TOTAL_TASKS, skipped=$ENGINE_SKIPPED_TASKS"
    fi
else
    fail "engine_plan_scan failed for CIDR target"
fi

# Test 34: Planning against HTTP URL in web mode
TARGET_VALUE=("http://example.com")
TARGET_TYPE=("url_http")
engine_init
engine_resolve_modules "false" "true" "" ""

if engine_plan_scan; then
    # url_http is compatible with 11 web modules; 3 are skipped: subdomain (needs domain), tls (needs url_https/domain), historical-urls (needs domain/hostname)
    if (( ENGINE_TOTAL_TASKS == 11 )) && (( ENGINE_SKIPPED_TASKS == 3 )); then
        pass "engine_plan_scan schedules web modules compatible with HTTP URL and skips subdomain/tls/historical-urls"
    else
        fail "engine_plan_scan HTTP URL task count mismatch: total=$ENGINE_TOTAL_TASKS, skipped=$ENGINE_SKIPPED_TASKS"
    fi
else
    fail "engine_plan_scan failed for HTTP URL target"
fi

# Test 35: Planning against multiple mixed targets
TARGET_VALUE=("192.0.2.1" "example.com")
TARGET_TYPE=("ipv4" "domain")
engine_init
engine_resolve_modules "false" "false" "host,dns" ""

if engine_plan_scan; then
    # Target 1 (ipv4): host compatible (1), dns skipped (1)
    # Target 2 (domain): host compatible (1), dns compatible (1)
    # Total tasks: 3, Total skipped: 1
    if (( ENGINE_TOTAL_TASKS == 3 )) && (( ENGINE_SKIPPED_TASKS == 1 )); then
        pass "engine_plan_scan schedules execution graph across multiple mixed targets"
    else
        fail "engine_plan_scan mixed targets count mismatch: total=$ENGINE_TOTAL_TASKS, skipped=$ENGINE_SKIPPED_TASKS"
    fi
else
    fail "engine_plan_scan failed on mixed targets"
fi

# Test 36: Failing when no targets are available
TARGET_VALUE=()
TARGET_TYPE=()
engine_init
engine_resolve_modules "true" "false" "" ""

if ! engine_plan_scan >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"No valid targets available"* ]]; then
        pass "engine_plan_scan fails with clear error when TARGET_VALUE is empty"
    else
        fail "engine_plan_scan unexpected error on empty targets: $ENGINE_ERROR"
    fi
else
    fail "engine_plan_scan succeeded with empty targets"
fi

# Test 37: Failing when targets are incompatible with all selected modules
TARGET_VALUE=("192.0.2.1")
TARGET_TYPE=("ipv4")
engine_init
# 'subdomain' only accepts domain
engine_resolve_modules "false" "false" "subdomain" ""

if ! engine_plan_scan >/dev/null 2>&1; then
    if [[ "$ENGINE_ERROR" == *"No compatible modules could be scheduled"* ]]; then
        pass "engine_plan_scan fails with clear error when all target/module pairs are incompatible"
    else
        fail "engine_plan_scan unexpected error: $ENGINE_ERROR"
    fi
else
    fail "engine_plan_scan succeeded despite full incompatibility"
fi

# -----------------------------------------------------------------------------
# UT-08: Plan Formatting & Summary (engine_format_plan)
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-08: Plan Formatting & Summary (engine_format_plan)"

# Test 38: Formatted plan output structure
TARGET_VALUE=("example.com")
TARGET_TYPE=("domain")
engine_init
engine_resolve_modules "false" "false" "host,dns" ""
engine_plan_scan

formatted_plan="$(engine_format_plan)"
if [[ "$formatted_plan" == *"Execution Plan (2 tasks scheduled across 1 target)"* && \
      "$formatted_plan" == *"Target: example.com"* && \
      "$formatted_plan" == *"Module: host"* && \
      "$formatted_plan" == *"Module: dns"* ]]; then
    pass "engine_format_plan renders structured task list with target, type, and module metadata"
else
    fail "engine_format_plan output missing expected elements: $formatted_plan"
fi

# Test 39: Formatting empty plan
engine_init
empty_plan="$(engine_format_plan)"
if [[ "$empty_plan" == *"No tasks scheduled"* ]]; then
    pass "engine_format_plan outputs notice when plan is empty"
else
    fail "engine_format_plan failed on empty plan: $empty_plan"
fi

test_summary
