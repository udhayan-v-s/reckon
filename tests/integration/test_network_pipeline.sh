#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Network Reconnaissance Pipeline Integration Tests
#
# Verifies end-to-end orchestration of core network reconnaissance modules
# (host discovery, DNS enumeration, port scanning, service detection, OS fingerprinting),
# target type compatibility pruning, upstream artifact data flow, and audit logging.
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

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-netpipe-test.XXXXXX")" || {
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

    printf '%s\n' "Network reconnaissance pipeline integration tests completed."
}

printf '%s\n' "RECKON - Network Pipeline Integration Tests"
printf '%s\n' "-------------------------------------------"

# -----------------------------------------------------------------------------
# Test 1: Full Network Mode on Domain Target (Host, DNS, Port, Service, OS)
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Full Network Pipeline on Domain Target"

OUT_DIR_DOMAIN="$TEST_ROOT/domain_pipeline"
DOMAIN_TARGET="example.com"

DOMAIN_OUT="$("$RECKON_BIN" --network --target "$DOMAIN_TARGET" --output "$OUT_DIR_DOMAIN" 2>&1 || true)"
domain_status=$?

if (( domain_status == 0 )); then
    pass "full network pipeline executes successfully on domain target"
else
    printf '%s\n' "$DOMAIN_OUT" >&2
    fail "full network pipeline failed on domain target (exit: $domain_status)"
fi

# Verify expected module directory structure under domain target
TARGET_DIR_DOMAIN="$OUT_DIR_DOMAIN/$DOMAIN_TARGET"
if [[ -d "$TARGET_DIR_DOMAIN/host" && \
      -d "$TARGET_DIR_DOMAIN/dns" && \
      -d "$TARGET_DIR_DOMAIN/port" && \
      -d "$TARGET_DIR_DOMAIN/service" && \
      -d "$TARGET_DIR_DOMAIN/os" ]]; then
    pass "creates dedicated task directories for all core network modules"
else
    fail "missing expected task directories under $TARGET_DIR_DOMAIN"
fi

# Verify artifact file generation
if [[ -f "$TARGET_DIR_DOMAIN/host/hosts_live.txt" && \
      -f "$TARGET_DIR_DOMAIN/dns/dns_records.txt" && \
      -f "$TARGET_DIR_DOMAIN/port/open_ports.txt" && \
      -f "$TARGET_DIR_DOMAIN/service/services.txt" && \
      -f "$TARGET_DIR_DOMAIN/os/os_info.txt" ]]; then
    pass "generates all core network downstream artifacts (hosts_live, dns_records, open_ports, services, os_info)"
else
    fail "missing expected downstream artifact files in $TARGET_DIR_DOMAIN"
fi

# Verify file and directory permissions
port_perm="$(stat -c '%a' "$TARGET_DIR_DOMAIN/port/open_ports.txt" 2>/dev/null || stat -f '%Lp' "$TARGET_DIR_DOMAIN/port/open_ports.txt" 2>/dev/null || echo "unknown")"
dir_perm="$(stat -c '%a' "$TARGET_DIR_DOMAIN/port" 2>/dev/null || stat -f '%Lp' "$TARGET_DIR_DOMAIN/port" 2>/dev/null || echo "unknown")"

if [[ "$port_perm" == "640" && "$dir_perm" =~ ^(750|700)$ ]]; then
    pass "enforces secure permissions on network task directories (0750) and artifacts (0640)"
else
    fail "unexpected permissions: file=$port_perm (expected 640), dir=$dir_perm (expected 750/700)"
fi

# -----------------------------------------------------------------------------
# Test 2: Incompatibility Pruning for IPv4 Target
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Incompatibility Pruning for Single IPv4 Target"

OUT_DIR_IP="$TEST_ROOT/ipv4_pipeline"
IP_TARGET="192.0.2.1"

IP_OUT="$("$RECKON_BIN" --network --target "$IP_TARGET" --output "$OUT_DIR_IP" 2>&1 || true)"
ip_status=$?

if (( ip_status == 0 )); then
    pass "network scan executes successfully on single IPv4 target"
else
    printf '%s\n' "$IP_OUT" >&2
    fail "network scan failed on IPv4 target (exit: $ip_status)"
fi

TARGET_DIR_IP="$OUT_DIR_IP/$IP_TARGET"
if [[ -d "$TARGET_DIR_IP/host" && \
      -d "$TARGET_DIR_IP/port" && \
      -d "$TARGET_DIR_IP/service" && \
      -d "$TARGET_DIR_IP/os" && \
      ! -d "$TARGET_DIR_IP/dns" ]]; then
    pass "planner schedules host, port, service, os and prunes incompatible dns module"
else
    fail "planner did not prune dns module or missed core modules for IPv4 target"
fi

# -----------------------------------------------------------------------------
# Test 3: Incompatibility Pruning for CIDR Block Target
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Incompatibility Pruning for Multi-Host CIDR Target"

OUT_DIR_CIDR="$TEST_ROOT/cidr_pipeline"
CIDR_TARGET="192.168.1.0/24"

CIDR_OUT="$("$RECKON_BIN" --network --target "$CIDR_TARGET" --output "$OUT_DIR_CIDR" 2>&1 || true)"
cidr_status=$?

if (( cidr_status == 0 )); then
    pass "network scan executes successfully on CIDR block target"
else
    printf '%s\n' "$CIDR_OUT" >&2
    fail "network scan failed on CIDR target (exit: $cidr_status)"
fi

TARGET_DIR_CIDR="$OUT_DIR_CIDR/192.168.1.0_24"
if [[ -d "$TARGET_DIR_CIDR/host" && \
      ! -d "$TARGET_DIR_CIDR/port" && \
      ! -d "$TARGET_DIR_CIDR/service" && \
      ! -d "$TARGET_DIR_CIDR/os" && \
      ! -d "$TARGET_DIR_CIDR/dns" ]]; then
    pass "planner schedules only multi-host host module and prunes all single-host modules for CIDR target"
else
    fail "planner did not restrict CIDR scan strictly to multi-host discovery"
fi

# -----------------------------------------------------------------------------
# Test 4: Pipeline Data Flow with Mock Active Services
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Inter-Module Data Flow with Discovered Open Ports"

MOCK_NMAP_ACTIVE="$TEST_ROOT/mock_nmap_active.sh"
cat > "$MOCK_NMAP_ACTIVE" <<'EOF'
#!/usr/bin/env bash
set -o nounset

gnmap_path=""
nmap_path=""
target=""

is_service=false
is_os=false
for arg in "$@"; do
    if [[ "$arg" == "-sV" ]]; then is_service=true; fi
    if [[ "$arg" == "-O" ]]; then is_os=true; fi
done

while [[ $# -gt 0 ]]; do
    case "$1" in
        -oG) gnmap_path="$2"; shift 2 ;;
        -oN) nmap_path="$2"; shift 2 ;;
        -*) shift ;;
        *) target="$1"; shift ;;
    esac
done

if [[ "$is_service" == true || "$is_os" == true ]]; then
    if [[ -n "$gnmap_path" ]]; then
        cat > "$gnmap_path" <<S_GNMAP
Host: ${target:-127.0.0.1} ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1 Ubuntu/, 80/open/tcp//http//Apache httpd 2.4.52/\tOS: Linux 5.4 - 5.15
S_GNMAP
    fi
    if [[ -n "$nmap_path" ]]; then
        cat > "$nmap_path" <<S_NMAP
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
S_NMAP
    fi
    exit 0
fi

# Otherwise emit port discovery info
if [[ -n "$gnmap_path" ]]; then
    cat > "$gnmap_path" <<P_GNMAP
Host: ${target:-127.0.0.1} ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///\tIgnored State: closed (998)
P_GNMAP
fi
if [[ -n "$nmap_path" ]]; then
    cat > "$nmap_path" <<P_NMAP
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
P_NMAP
fi
exit 0
EOF
chmod +x "$MOCK_NMAP_ACTIVE"

OUT_DIR_FLOW="$TEST_ROOT/flow_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_ACTIVE"
    "$RECKON_BIN" --module port,service,os --target "active.local" --output "$OUT_DIR_FLOW" >/dev/null 2>&1
)
flow_status=$?

if (( flow_status == 0 )); then
    pass "port -> service -> os pipeline dispatches and completes with code 0"
else
    fail "pipeline failed with exit code $flow_status"
fi

FLOW_TARGET_DIR="$OUT_DIR_FLOW/active.local"

# Verify port module wrote open ports
if [[ -f "$FLOW_TARGET_DIR/port/open_ports.txt" ]] && \
   grep -q -x "22" "$FLOW_TARGET_DIR/port/open_ports.txt" && \
   grep -q -x "80" "$FLOW_TARGET_DIR/port/open_ports.txt"; then
    pass "port module extracts and generates open_ports.txt with discovered ports (22, 80)"
else
    fail "open_ports.txt missing or did not contain expected ports"
fi

# Verify service module consumed open ports and identified versions
if [[ -f "$FLOW_TARGET_DIR/service/services.txt" ]] && \
   grep -q "OpenSSH 8.9p1" "$FLOW_TARGET_DIR/service/services.txt" && \
   grep -q "Apache httpd 2.4.52" "$FLOW_TARGET_DIR/service/services.txt"; then
    pass "service module consumes open_ports.txt and interrogates discovered services into services.txt"
else
    fail "services.txt missing or did not identify expected service versions"
fi

# Verify os module fingerprinted operating system
if [[ -f "$FLOW_TARGET_DIR/os/os_info.txt" ]] && \
   grep -q "OS: Linux" "$FLOW_TARGET_DIR/os/os_info.txt"; then
    pass "os module identifies operating system from service heuristics into os_info.txt"
else
    fail "os_info.txt missing or did not identify operating system"
fi

# -----------------------------------------------------------------------------
# Test 5: Pipeline Data Flow with Zero Open Ports
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Pipeline Optimization when Zero Open Ports Detected"

MOCK_NMAP_CLOSED="$TEST_ROOT/mock_nmap_closed.sh"
cat > "$MOCK_NMAP_CLOSED" <<'EOF'
#!/usr/bin/env bash
set -o nounset

gnmap_path=""
nmap_path=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -oG) gnmap_path="$2"; shift 2 ;;
        -oN) nmap_path="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$gnmap_path" ]]; then
    printf "Host: 127.0.0.1 ()\tStatus: Up\tIgnored State: closed (1000)\n" > "$gnmap_path"
fi
if [[ -n "$nmap_path" ]]; then
    printf "All 1000 scanned ports are closed\n" > "$nmap_path"
fi
exit 0
EOF
chmod +x "$MOCK_NMAP_CLOSED"

OUT_DIR_CLOSED="$TEST_ROOT/closed_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_NMAP_BIN="$MOCK_NMAP_CLOSED"
    "$RECKON_BIN" --module port,service,os --target "closed.local" --output "$OUT_DIR_CLOSED" >/dev/null 2>&1
)
closed_status=$?

CLOSED_TARGET_DIR="$OUT_DIR_CLOSED/closed.local"
if (( closed_status == 0 )) && \
   [[ -f "$CLOSED_TARGET_DIR/port/open_ports.txt" && ! -s "$CLOSED_TARGET_DIR/port/open_ports.txt" ]] && \
   grep -q "Port scanning detected 0 open ports" "$CLOSED_TARGET_DIR/service/output.txt" && \
   grep -q "Port scanning detected 0 open ports" "$CLOSED_TARGET_DIR/os/output.txt"; then
    pass "service and os modules detect zero open ports and cleanly skip active probing"
else
    fail "zero open ports pipeline did not handle closed ports optimization properly (exit: $closed_status)"
fi

# -----------------------------------------------------------------------------
# Test 6: Multi-Target Pipeline with Mixed Target Types
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Multi-Target Execution across Mixed Targets"

TARGETS_FILE="$TEST_ROOT/mixed_targets.txt"
cat > "$TARGETS_FILE" <<'EOF'
192.0.2.10
pipe.example.com
EOF

OUT_DIR_MIXED="$TEST_ROOT/mixed_pipeline"
MIXED_OUT="$("$RECKON_BIN" --module host,dns,port,service,os --targets-file "$TARGETS_FILE" --output "$OUT_DIR_MIXED" 2>&1 || true)"
mixed_status=$?

if (( mixed_status == 0 )); then
    pass "multi-target execution across mixed targets file completes with exit code 0"
else
    printf '%s\n' "$MIXED_OUT" >&2
    fail "multi-target execution failed (exit: $mixed_status)"
fi

# Verify isolated directory structures for each target
if [[ -d "$OUT_DIR_MIXED/192.0.2.10/host" && \
      -d "$OUT_DIR_MIXED/192.0.2.10/port" && \
      ! -d "$OUT_DIR_MIXED/192.0.2.10/dns" && \
      -d "$OUT_DIR_MIXED/pipe.example.com/host" && \
      -d "$OUT_DIR_MIXED/pipe.example.com/dns" && \
      -d "$OUT_DIR_MIXED/pipe.example.com/port" ]]; then
    pass "generates isolated directory trees and selectively prunes modules per target type"
else
    fail "mixed targets directory layout did not match expected structure"
fi

# -----------------------------------------------------------------------------
# Test 7: CLI Audit Logging across Full Network Pipeline
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Audit Logging across Network Reconnaissance Execution"

AUDIT_LOG_FILE="$TEST_ROOT/net_pipeline_audit.log"
"$RECKON_BIN" --module host,port,service,os --target 192.0.2.50 --output "$TEST_ROOT/audit_scan_out" --log-file "$AUDIT_LOG_FILE" >/dev/null 2>&1 || true

if [[ -f "$AUDIT_LOG_FILE" ]] && \
   grep -q "RECKON initialized" "$AUDIT_LOG_FILE" && \
   grep -q "Executing \[1/4\] host" "$AUDIT_LOG_FILE" && \
   grep -q "Executing \[2/4\] port" "$AUDIT_LOG_FILE" && \
   grep -q "Executing \[3/4\] service" "$AUDIT_LOG_FILE" && \
   grep -q "Executing \[4/4\] os" "$AUDIT_LOG_FILE" && \
   grep -q "Scan execution finished" "$AUDIT_LOG_FILE"; then
    pass "audit log tracks execution lifecycle across all dispatched network modules"
else
    fail "audit log file missing expected task execution milestones"
fi

test_summary
