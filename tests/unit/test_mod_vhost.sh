#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Virtual Host Enumeration Module Unit Tests (test_mod_vhost.sh)
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=modules/web/vhost.sh
if ! source "$PROJECT_ROOT/modules/web/vhost.sh"; then
    printf 'Error: Unable to load modules/web/vhost.sh component.\n' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-mod-vhost-test.XXXXXX")" || {
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

    printf '%s\n' "Web virtual host enumeration module unit tests completed."
}

printf '%s\n' "RECKON - Web Virtual Host Enumeration Module Unit Tests"
printf '%s\n' "-------------------------------------------------------"

# -----------------------------------------------------------------------------
# UT-01: Module Contract & Argument Handling
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-01: Module Contract & Argument Handling"

# Test 1: Reject insufficient arguments
if module_vhost_run "example.com" "domain" 2>/dev/null; then
    fail "module_vhost_run accepted fewer than 3 arguments"
else
    pass "module_vhost_run rejects insufficient arguments (< 3)"
fi

# Test 2: Reject empty target
if module_vhost_run "" "domain" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_vhost_run accepted empty target"
else
    pass "module_vhost_run rejects empty target"
fi

# Test 3: Reject empty target type
if module_vhost_run "example.com" "" "$TEST_ROOT/t1" 2>/dev/null; then
    fail "module_vhost_run accepted empty target type"
else
    pass "module_vhost_run rejects empty target type"
fi

# Test 4: Reject empty task directory
if module_vhost_run "example.com" "domain" "" 2>/dev/null; then
    fail "module_vhost_run accepted empty task directory"
else
    pass "module_vhost_run rejects empty task directory"
fi

# -----------------------------------------------------------------------------
# UT-02: Target Type Compatibility Rules
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-02: Target Type Compatibility Rules"

mock_empty="$TEST_ROOT/bin/mock_empty"
mkdir -p "$TEST_ROOT/bin"
cat <<'EOF' > "$mock_empty"
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$mock_empty"

# Test 1: Supported domain target returns 0
task_compat_dom="$TEST_ROOT/targets/dom_test/vhost"
if VHOST_FFUF_BIN="$mock_empty" VHOST_CURL_BIN="$mock_empty" \
   module_vhost_run "corp.local" "domain" "$task_compat_dom"; then
    pass "module_vhost_run accepts valid domain target"
else
    fail "module_vhost_run failed for valid domain target"
fi

# Test 2: Supported URL target returns 0
task_compat_url="$TEST_ROOT/targets/url_test/vhost"
if VHOST_FFUF_BIN="$mock_empty" VHOST_CURL_BIN="$mock_empty" \
   module_vhost_run "http://corp.local" "url_http" "$task_compat_url"; then
    pass "module_vhost_run accepts valid URL target"
else
    fail "module_vhost_run failed for valid URL target"
fi

# Test 3: Unsupported CIDR target cleanly skipped with 0
task_compat_cidr="$TEST_ROOT/targets/cidr_test/vhost"
if VHOST_FFUF_BIN="$mock_empty" VHOST_CURL_BIN="$mock_empty" \
   module_vhost_run "192.168.1.0/24" "ipv4_cidr" "$task_compat_cidr"; then
    if [[ -f "${task_compat_cidr}/output.txt" ]] && grep -q "SKIPPED" "${task_compat_cidr}/output.txt"; then
        pass "module_vhost_run skips multi-host CIDR block with execution notice"
    else
        fail "module_vhost_run did not generate skip notice for CIDR target"
    fi
else
    fail "module_vhost_run returned non-zero for incompatible CIDR target"
fi

# -----------------------------------------------------------------------------
# UT-03: FFUF Primary Engine Virtual Host Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-03: FFUF Primary Engine Virtual Host Fuzzing"

mock_ffuf="$TEST_ROOT/bin/mock_ffuf_vhost"
cat <<'EOF' > "$mock_ffuf"
#!/usr/bin/env bash
out_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    cat <<'JSON_EOF' > "$out_file"
{
  "results": [
    {
      "input": {"FUZZ": "dev.corp.local"},
      "status": 200,
      "length": 1420,
      "redirectlocation": "",
      "url": "http://corp.local"
    },
    {
      "input": {"FUZZ": "api.corp.local"},
      "status": 200,
      "length": 890,
      "redirectlocation": "",
      "url": "http://corp.local"
    },
    {
      "input": {"FUZZ": "admin.corp.local"},
      "status": 403,
      "length": 340,
      "redirectlocation": "",
      "url": "http://corp.local"
    }
  ]
}
JSON_EOF
fi
exit 0
EOF
chmod +x "$mock_ffuf"

task_dir_ffuf="$TEST_ROOT/targets/ffuf_vhost_test/vhost"
VHOST_FFUF_BIN="$mock_ffuf" \
VHOST_CURL_BIN="$mock_empty" \
module_vhost_run "corp.local" "domain" "$task_dir_ffuf"

if [[ -f "${task_dir_ffuf}/vhosts.txt" ]] && \
   grep -q -E "^dev\.corp\.local"$'\t'"200" "${task_dir_ffuf}/vhosts.txt" && \
   grep -q -E "^api\.corp\.local"$'\t'"200" "${task_dir_ffuf}/vhosts.txt" && \
   grep -q -E "^admin\.corp\.local"$'\t'"403" "${task_dir_ffuf}/vhosts.txt"; then
    pass "FFUF engine extracts and writes discovered virtual hosts into vhosts.txt"
else
    fail "FFUF engine failed to write expected virtual hosts into vhosts.txt"
fi

if [[ -f "${task_dir_ffuf}/output.txt" ]] && \
   grep -q "Virtual Hosts Discovered.*3" "${task_dir_ffuf}/output.txt" && \
   grep -q "dev.corp.local (Status: 200, Size: 1420)" "${task_dir_ffuf}/output.txt"; then
    pass "Formats comprehensive summary report with discovered virtual hosts"
else
    fail "Formatted output report mismatch in $task_dir_ffuf"
fi

# -----------------------------------------------------------------------------
# UT-04: Native Curl Fallback Host Header Fuzzing
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-04: Native Curl Fallback Host Header Fuzzing"

mock_curl_vh="$TEST_ROOT/bin/mock_curl_vhost"
cat <<'EOF' > "$mock_curl_vh"
#!/usr/bin/env bash
head_dest=""
host_hdr=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        -H)
            if [[ "$2" =~ ^Host:[[:space:]]*(.*) ]]; then
                host_hdr="${BASH_REMATCH[1]}"
            fi
            shift 2
            ;;
        *) shift ;;
    esac
done

if [[ "$host_hdr" =~ reckon-baseline ]]; then
    printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 150\r\n\r\n' > "$head_dest"
    exit 0
elif [[ "$host_hdr" =~ ^internal\.fallback\.corp ]]; then
    printf 'HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n' > "$head_dest"
    exit 0
elif [[ "$host_hdr" =~ ^portal\.fallback\.corp ]]; then
    printf 'HTTP/1.1 302 Found\r\nLocation: https://portal.fallback.corp/login\r\nContent-Length: 0\r\n\r\n' > "$head_dest"
    exit 0
fi

printf 'HTTP/1.1 404 Not Found\r\nContent-Length: 150\r\n\r\n' > "$head_dest"
exit 0
EOF
chmod +x "$mock_curl_vh"

task_dir_curl="$TEST_ROOT/targets/curl_vh_test/vhost"
VHOST_FFUF_BIN="none" \
VHOST_CURL_BIN="$mock_curl_vh" \
module_vhost_run "fallback.corp" "domain" "$task_dir_curl"

if [[ -f "${task_dir_curl}/vhosts.txt" ]] && \
   grep -q "internal.fallback.corp" "${task_dir_curl}/vhosts.txt" && \
   grep -q "portal.fallback.corp" "${task_dir_curl}/vhosts.txt"; then
    pass "Fallback heuristics discover virtual hosts using differential curl inspection"
else
    fail "Fallback heuristics failed to detect virtual hosts"
fi

# -----------------------------------------------------------------------------
# UT-05: Wordlist Selection & Candidate Preparation
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-05: Wordlist Selection & Candidate Preparation"

custom_wl="$TEST_ROOT/custom_vhost_wordlist.txt"
printf 'dev\napi\nmail.custom.org\n' > "$custom_wl"

task_dir_wl="$TEST_ROOT/targets/wl_test/vhost"
CONFIG_EFFECTIVE_WORDLIST="$custom_wl" \
VHOST_FFUF_BIN="$mock_empty" \
VHOST_CURL_BIN="$mock_empty" \
module_vhost_run "custom.org" "domain" "$task_dir_wl"

if [[ -f "${task_dir_wl}/output.txt" ]] && \
   grep -q "Wordlist.*custom_vhost_wordlist.txt" "${task_dir_wl}/output.txt" && \
   grep -q "Candidates Count.*3" "${task_dir_wl}/output.txt"; then
    pass "Honors explicitly configured wordlist and counts expanded candidates"
else
    fail "Custom wordlist was not applied correctly in $task_dir_wl"
fi

# -----------------------------------------------------------------------------
# UT-06: Inactive / No Virtual Hosts Discovered
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-06: Inactive / No Virtual Hosts Discovered"

task_dir_empty="$TEST_ROOT/targets/empty_test/vhost"
VHOST_FFUF_BIN="$mock_empty" \
VHOST_CURL_BIN="$mock_empty" \
module_vhost_run "empty.org" "domain" "$task_dir_empty"

if [[ -f "${task_dir_empty}/vhosts.txt" ]] && [[ ! -s "${task_dir_empty}/vhosts.txt" ]] && \
   grep -q "No virtual hosts discovered" "${task_dir_empty}/output.txt"; then
    pass "Handles empty virtual host discovery results cleanly with exit code 0"
else
    fail "Clean empty virtual host discovery state not handled properly"
fi

# -----------------------------------------------------------------------------
# UT-07: Artifact Permission Enforcement
# -----------------------------------------------------------------------------
printf '\n%s\n' "UT-07: Artifact Permission Enforcement"

dir_perm="$(stat -c '%a' "$task_dir_ffuf" 2>/dev/null || stat -f '%p' "$task_dir_ffuf" 2>/dev/null)"
vhost_perm="$(stat -c '%a' "${task_dir_ffuf}/vhosts.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/vhosts.txt" 2>/dev/null)"
out_perm="$(stat -c '%a' "${task_dir_ffuf}/output.txt" 2>/dev/null || stat -f '%p' "${task_dir_ffuf}/output.txt" 2>/dev/null)"

dir_perm="${dir_perm: -3}"
vhost_perm="${vhost_perm: -3}"
out_perm="${out_perm: -3}"

if [[ "$dir_perm" == "750" && "$vhost_perm" == "640" && "$out_perm" == "640" ]]; then
    pass "Enforces 0750 directory and 0640 permissions on all vhost artifacts"
else
    fail "Permission enforcement failed: dir=$dir_perm, vhosts=$vhost_perm, output=$out_perm"
fi

test_summary
