#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Target processing unit tests
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

# shellcheck source=core/targets.sh
if ! source "$PROJECT_ROOT/core/targets.sh"; then
    printf 'Error: Unable to load target processing component.\n' >&2
    exit 1
fi

# Create an isolated temporary test directory.
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-targets-test.XXXXXX")" || {
    printf 'Error: Unable to create temporary test directory.\n' >&2
    exit 1
}
readonly TEST_ROOT

PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
    rm -rf -- "$TEST_ROOT"
}

trap cleanup EXIT

pass() { printf '[PASS] %s\n' "$1"; ((PASS_COUNT += 1)); }
fail() { printf '[FAIL] %s\n' "$1" >&2; ((FAIL_COUNT += 1)); }

test_summary() {
    printf '%s\n' "--------------------------------------"
    printf 'Tests passed: %s\n' "$PASS_COUNT"
    printf 'Tests failed: %s\n' "$FAIL_COUNT"

    if (( FAIL_COUNT > 0 )); then
        exit 1
    fi

    printf '%s\n' "Target processing unit tests completed."
}

printf '%s\n' "RECKON - Target Processing Unit Tests"
printf '%s\n' "--------------------------------------"

# UT-01: IPv4 validation.
test_ipv4() {
    printf '\n%s\n' "UT-01: IPv4 Validation"

    target_init

    if target_validate "192.0.2.10" "both"; then
        if [[ "$TARGET_VALIDATED_VALUE" == "192.0.2.10" &&
              "$TARGET_VALIDATED_TYPE" == "ipv4" &&
              "$TARGET_VALIDATED_MODE" == "both" ]]; then
            pass "Valid IPv4 accepted"
        else
            fail "Valid IPv4 accepted (state: type=$TARGET_VALIDATED_TYPE mode=$TARGET_VALIDATED_MODE)"
        fi
    else
        fail "Valid IPv4 accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "192.0.2.010" "both"; then
        fail "Leading-zero IPv4 rejected"
    elif [[ "$TARGET_ERROR" == *"leading zeros"* ]]; then
        pass "Leading-zero IPv4 rejected"
    else
        fail "Leading-zero IPv4 rejected (error: $TARGET_ERROR)"
    fi

    if target_validate "192.0.2.256" "both"; then
        fail "Out-of-range IPv4 rejected"
    elif [[ "$TARGET_ERROR" == *"out of range"* ]]; then
        pass "Out-of-range IPv4 rejected"
    else
        fail "Out-of-range IPv4 rejected (error: $TARGET_ERROR)"
    fi

    if target_validate "2001:db8::1" "both"; then
        fail "IPv6 rejected"
    elif [[ "$TARGET_ERROR" == *"IPv6"* ]]; then
        pass "IPv6 rejected"
    else
        fail "IPv6 rejected (error: $TARGET_ERROR)"
    fi
}

# UT-02: CIDR validation.
test_cidr() {
    printf '\n%s\n' "UT-02: CIDR Validation"

    if target_validate "192.0.2.0/24" "network"; then
        if [[ "$TARGET_VALIDATED_TYPE" == "ipv4_cidr" &&
              "$TARGET_VALIDATED_MODE" == "network" ]]; then
            pass "Valid CIDR accepted (network mode)"
        else
            fail "Valid CIDR accepted (type=$TARGET_VALIDATED_TYPE mode=$TARGET_VALIDATED_MODE)"
        fi
    else
        fail "Valid CIDR accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "192.0.2.0/24" "web"; then
        fail "CIDR rejected in web mode"
    elif [[ "$TARGET_ERROR" == *"incompatible with web"* ]]; then
        pass "CIDR rejected in web mode"
    else
        fail "CIDR rejected in web mode (error: $TARGET_ERROR)"
    fi

    if target_validate "192.0.2.0/33" "network"; then
        fail "CIDR prefix >32 rejected"
    elif [[ "$TARGET_ERROR" == *"prefix out of range"* ]]; then
        pass "CIDR prefix >32 rejected"
    else
        fail "CIDR prefix >32 rejected (error: $TARGET_ERROR)"
    fi
}

# UT-03: Range validation.
test_range() {
    printf '\n%s\n' "UT-03: Range Validation"

    if target_validate "192.0.2.1-192.0.2.10" "network"; then
        if [[ "$TARGET_VALIDATED_TYPE" == "ipv4_range" ]]; then
            pass "Valid range accepted"
        else
            fail "Valid range accepted (type=$TARGET_VALIDATED_TYPE)"
        fi
    else
        fail "Valid range accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "192.0.2.1-10" "network"; then
        fail "Short-form range rejected"
    else
        pass "Short-form range rejected"
    fi

    if target_validate "192.0.2.1-192.0.2.10" "web"; then
        fail "Range rejected in web mode"
    elif [[ "$TARGET_ERROR" == *"incompatible with web"* ]]; then
        pass "Range rejected in web mode"
    else
        fail "Range rejected in web mode (error: $TARGET_ERROR)"
    fi
}

# UT-04: Hostname / domain validation.
test_name() {
    printf '\n%s\n' "UT-04: Hostname and Domain Validation"

    if target_validate "example.com" "both"; then
        if [[ "$TARGET_VALIDATED_TYPE" == "domain" &&
              "$TARGET_VALIDATED_MODE" == "both" ]]; then
            pass "Domain accepted"
        else
            fail "Domain accepted (type=$TARGET_VALIDATED_TYPE)"
        fi
    else
        fail "Domain accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "EXAMPLE.com" "both"; then
        if [[ "$TARGET_VALIDATED_VALUE" == "example.com" ]]; then
            pass "Domain normalized to lowercase"
        else
            fail "Domain normalized to lowercase (got: $TARGET_VALIDATED_VALUE)"
        fi
    else
        fail "Domain normalized to lowercase (error: $TARGET_ERROR)"
    fi

    if target_validate "localhost" "both"; then
        if [[ "$TARGET_VALIDATED_TYPE" == "hostname" ]]; then
            pass "Hostname without dots accepted"
        else
            fail "Hostname without dots accepted (type=$TARGET_VALIDATED_TYPE)"
        fi
    else
        fail "Hostname without dots accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "example.com." "both"; then
        fail "Trailing-dot domain rejected"
    elif [[ "$TARGET_ERROR" == *"trailing dot"* ]]; then
        pass "Trailing-dot domain rejected"
    else
        fail "Trailing-dot domain rejected (error: $TARGET_ERROR)"
    fi

    if target_validate "-example.com" "both"; then
        fail "Leading-hyphen label rejected"
    else
        pass "Leading-hyphen label rejected"
    fi
}

# UT-05: URL validation.
test_url() {
    printf '\n%s\n' "UT-05: URL Validation"

    if target_validate "http://example.com/path" "web"; then
        if [[ "$TARGET_VALIDATED_TYPE" == "url_http" &&
              "$TARGET_VALIDATED_VALUE" == "http://example.com/path" ]]; then
            pass "HTTP URL accepted"
        else
            fail "HTTP URL accepted (value=$TARGET_VALIDATED_VALUE type=$TARGET_VALIDATED_TYPE)"
        fi
    else
        fail "HTTP URL accepted (error: $TARGET_ERROR)"
    fi

    if target_validate "https://Example.com/Path" "web"; then
        if [[ "$TARGET_VALIDATED_VALUE" == "https://example.com/Path" &&
              "$TARGET_VALIDATED_TYPE" == "url_https" ]]; then
            pass "HTTPS URL host lowercased, path preserved"
        else
            fail "HTTPS URL host lowercased, path preserved (value=$TARGET_VALIDATED_VALUE)"
        fi
    else
        fail "HTTPS URL host lowercased (error: $TARGET_ERROR)"
    fi

    if target_validate "https://example.com:8443/api" "web"; then
        if [[ "$TARGET_VALIDATED_VALUE" == "https://example.com:8443/api" ]]; then
            pass "URL with port preserved"
        else
            fail "URL with port preserved (value=$TARGET_VALIDATED_VALUE)"
        fi
    else
        fail "URL with port preserved (error: $TARGET_ERROR)"
    fi

    if target_validate "https://example.com/page#frag" "web"; then
        fail "URL with fragment rejected"
    elif [[ "$TARGET_ERROR" == *"fragment"* ]]; then
        pass "URL with fragment rejected"
    else
        fail "URL with fragment rejected (error: $TARGET_ERROR)"
    fi

    if target_validate "http://example.com:99999/" "web"; then
        fail "URL with port >65535 rejected"
    elif [[ "$TARGET_ERROR" == *"port out of range"* ]]; then
        pass "URL with port >65535 rejected"
    else
        fail "URL with port >65535 rejected (error: $TARGET_ERROR)"
    fi

    if target_validate "example.com:443" "web"; then
        fail "Bare host:port rejected"
    else
        pass "Bare host:port rejected"
    fi
}

# UT-06: Mode compatibility.
test_modes() {
    printf '\n%s\n' "UT-06: Mode Compatibility"

    if target_validate "http://example.com" "network"; then
        fail "URL rejected in network mode"
    elif [[ "$TARGET_ERROR" == *"incompatible with network"* ]]; then
        pass "URL rejected in network mode"
    else
        fail "URL rejected in network mode (error: $TARGET_ERROR)"
    fi

    if target_validate "example.com" "network"; then
        pass "Domain accepted in network mode"
    else
        fail "Domain accepted in network mode (error: $TARGET_ERROR)"
    fi

    if target_validate "example.com" "web"; then
        pass "Domain accepted in web mode"
    else
        fail "Domain accepted in web mode (error: $TARGET_ERROR)"
    fi
}

# UT-07: Targets-file processing.
test_target_process_file() {
    printf '\n%s\n' "UT-07: Targets File Processing"

    local tdir="$TEST_ROOT/targets"
    mkdir -p "$tdir"

    local f_valid="$tdir/valid.txt"
    local f_mixed="$tdir/mixed.txt"
    local f_empty="$tdir/empty.txt"
    local f_only_comments="$tdir/comments.txt"
    local f_dups="$tdir/dups.txt"
    local f_unreadable="$tdir/unreadable.txt"
    local f_inline="$tdir/inline.txt"

    # Valid multi-line file.
    cat > "$f_valid" <<'EOF'
# Primary targets
192.0.2.10
192.0.2.20
example.com
EOF

    # Mixed valid/invalid/comments/blanks.
    cat > "$f_mixed" <<'EOF'
# header

192.0.2.10
invalid_target_!@#
example.com

192.0.2.0/24
2001:db8::1
EOF

    # Empty file.
    : > "$f_empty"

    # Only comments/blanks.
    cat > "$f_only_comments" <<'EOF'
# comment
# another comment

EOF

    # Duplicate after normalization.
    cat > "$f_dups" <<'EOF'
EXAMPLE.com
example.com
Example.COM
192.0.2.10
192.0.2.10
EOF

    # Unreadable.
    printf '%s\n' '192.0.2.1' > "$f_unreadable"
    chmod 000 "$f_unreadable"

    # Inline comment — rejected as invalid line.
    cat > "$f_inline" <<'EOF'
192.0.2.10 # comment
EOF

    # Test 1: valid multi-line file accepted.
    target_init
    if target_process_file "$f_valid" "network"; then
        if [[ ${#TARGET_VALUE[@]} -eq 3 &&
              "${TARGET_VALUE[0]}" == "192.0.2.10" &&
              "${TARGET_VALUE[1]}" == "192.0.2.20" &&
              "${TARGET_VALUE[2]}" == "example.com" ]]; then
            pass "Valid multi-line targets file accepted"
        else
            fail "Valid multi-line targets file (values: ${TARGET_VALUE[*]})"
        fi
    else
        fail "Valid multi-line targets file (error: $TARGET_ERROR)"
    fi

    # Test 2: mixed file — invalid lines skipped, warnings recorded.
    target_init
    if target_process_file "$f_mixed" "network"; then
        if [[ ${#TARGET_VALUE[@]} -eq 3 ]] &&
           [[ ${#TARGET_WARNINGS[@]} -ge 2 ]]; then
            pass "Mixed targets file: valid kept, invalid warned"
        else
            fail "Mixed targets file (values=${#TARGET_VALUE[@]} warnings=${#TARGET_WARNINGS[@]})"
        fi
    else
        fail "Mixed targets file (error: $TARGET_ERROR)"
    fi

    # Test 3: empty file rejected.
    target_init
    if target_process_file "$f_empty" "network"; then
        fail "Empty targets file rejected"
    elif [[ "$TARGET_ERROR" == *"no usable targets"* ]]; then
        pass "Empty targets file rejected"
    else
        fail "Empty targets file rejected (error: $TARGET_ERROR)"
    fi

    # Test 4: only comments — rejected.
    target_init
    if target_process_file "$f_only_comments" "network"; then
        fail "Comment-only targets file rejected"
    elif [[ "$TARGET_ERROR" == *"no usable targets"* ]]; then
        pass "Comment-only targets file rejected"
    else
        fail "Comment-only targets file rejected (error: $TARGET_ERROR)"
    fi

    # Test 5: duplicates collapse.
    target_init
    if target_process_file "$f_dups" "network"; then
        if [[ ${#TARGET_VALUE[@]} -eq 2 &&
              "${TARGET_VALUE[0]}" == "example.com" &&
              "${TARGET_VALUE[1]}" == "192.0.2.10" ]]; then
            pass "Duplicates collapsed after normalization"
        else
            fail "Duplicates collapsed (values: ${TARGET_VALUE[*]})"
        fi
    else
        fail "Duplicates collapsed (error: $TARGET_ERROR)"
    fi

    # Test 6: unreadable file rejected.
    target_init
    if target_process_file "$f_unreadable" "network"; then
        fail "Unreadable targets file rejected"
    elif [[ "$TARGET_ERROR" == *"not readable"* ]]; then
        pass "Unreadable targets file rejected"
    else
        fail "Unreadable targets file rejected (error: $TARGET_ERROR)"
    fi
    chmod 600 "$f_unreadable"

    # Test 7: missing file rejected.
    target_init
    if target_process_file "$tdir/nonexistent.txt" "network"; then
        fail "Missing targets file rejected"
    elif [[ "$TARGET_ERROR" == *"does not exist"* ]]; then
        pass "Missing targets file rejected"
    else
        fail "Missing targets file rejected (error: $TARGET_ERROR)"
    fi

    # Test 8: inline comment not stripped (line fails validation).
    target_init
    if target_process_file "$f_inline" "network"; then
        fail "Inline comment rejected"
    elif [[ "$TARGET_ERROR" == *"no usable targets"* ]]; then
        pass "Inline comment not stripped (line invalid)"
    else
        fail "Inline comment not stripped (error: $TARGET_ERROR)"
    fi
}

test_ipv4
test_cidr
test_range
test_name
test_url
test_modes
test_target_process_file

test_summary