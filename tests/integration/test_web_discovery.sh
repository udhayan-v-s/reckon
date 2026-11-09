#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Discovery Pipeline Integration Tests (tests/integration/test_web_discovery.sh)
#
# Verifies end-to-end orchestration of all M9 web discovery & fingerprinting modules:
#   - HTTP Probing: http-probe
#   - Subdomain Discovery & DNS Validation: subdomain
#   - Technology Fingerprinting: technology
#   - CMS Platform Detection: cms
#   - Web Application Firewall Detection: waf
#
# Validates inter-module data flow (live_web.txt -> technology/cms/waf), target type
# compatibility pruning, heterogeneous multi-target batch execution, centralized audit
# logging, and secure file permission enforcement across all generated artifacts.
#

set -o nounset

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
readonly SCRIPT_DIR

PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)" || exit 1
readonly PROJECT_ROOT

RECKON_BIN="$PROJECT_ROOT/reckon"
readonly RECKON_BIN

if [[ ! -f "$RECKON_BIN" || ! -x "$RECKON_BIN" ]]; then
    printf 'Error: RECKON entry point missing or not executable at %s\n' "$RECKON_BIN" >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-webpipe-test.XXXXXX")" || {
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

    printf '%s\n' "Web discovery pipeline integration tests completed."
}

printf '%s\n' "RECKON - Web Discovery Pipeline Integration Tests"
printf '%s\n' "------------------------------------------------"

# -----------------------------------------------------------------------------
# Setup Shared Mock Infrastructure
# -----------------------------------------------------------------------------
MOCK_BIN_DIR="$TEST_ROOT/mock_bin"
mkdir -p "$MOCK_BIN_DIR"

# 1. Mock httpx
MOCK_HTTPX="$MOCK_BIN_DIR/mock_httpx.sh"
cat > "$MOCK_HTTPX" <<'EOF'
#!/usr/bin/env bash
set -o nounset
list_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l) list_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r host || [[ -n "$host" ]]; do
        if [[ "$host" =~ :8080 ]]; then
            printf '%s [200] [Corp Admin Console] [nginx/1.22.0] [512]\n' "$host"
        elif [[ "$host" =~ :8443 ]]; then
            printf '%s [200] [Secure Gateway] [Caddy/2.6.4] [1024]\n' "$host"
        elif [[ "$host" =~ ^https:// ]]; then
            printf '%s [200] [Enterprise Portal] [Apache/2.4.52] [2048]\n' "$host"
        elif [[ "$host" =~ ^http:// ]]; then
            printf '%s [301] [Moved Permanently] [Apache/2.4.52] [128]\n' "$host"
        fi
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$MOCK_HTTPX"

# 2. Mock subfinder
MOCK_SUBFINDER="$MOCK_BIN_DIR/mock_subfinder.sh"
cat > "$MOCK_SUBFINDER" <<'EOF'
#!/usr/bin/env bash
set -o nounset
domain=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) domain="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$domain" ]]; then
    printf 'api.%s\n' "$domain"
    printf 'vpn.%s\n' "$domain"
    printf 'mail.%s\n' "$domain"
    printf 'www.%s\n' "$domain"
fi
exit 0
EOF
chmod +x "$MOCK_SUBFINDER"

# 3. Mock dnsx
MOCK_DNSX="$MOCK_BIN_DIR/mock_dnsx.sh"
cat > "$MOCK_DNSX" <<'EOF'
#!/usr/bin/env bash
set -o nounset
list_file=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -l) list_file="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -f "${list_file:-}" ]]; then
    while IFS= read -r sub || [[ -n "$sub" ]]; do
        case "$sub" in
            api.*) printf '%s [10.20.1.50]\n' "$sub" ;;
            vpn.*) printf '%s [10.20.1.51]\n' "$sub" ;;
            mail.*) printf '%s [10.20.1.25]\n' "$sub" ;;
            www.*) printf '%s [10.20.1.80]\n' "$sub" ;;
            *) printf '%s [10.20.1.100]\n' "$sub" ;;
        esac
    done < "$list_file"
fi
exit 0
EOF
chmod +x "$MOCK_DNSX"

# 4. Mock whatweb
MOCK_WHATWEB="$MOCK_BIN_DIR/mock_whatweb.sh"
cat > "$MOCK_WHATWEB" <<'EOF'
#!/usr/bin/env bash
set -o nounset
out_file=""
targets=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-brief=*) out_file="${1#*=}"; shift ;;
        -*) shift ;;
        *) targets+=("$1"); shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    for t in "${targets[@]}"; do
        printf '%s [200 OK] Apache[2.4.52], Country[US], HTTPServer[Ubuntu Linux][Apache/2.4.52], PHP[8.1.2], Title[Enterprise Portal], WordPress[6.4.1], jQuery[3.6.0]\n' "$t" >> "$out_file"
    done
fi
exit 0
EOF
chmod +x "$MOCK_WHATWEB"

# 5. Mock wafw00f
MOCK_WAFW00F="$MOCK_BIN_DIR/mock_wafw00f.sh"
cat > "$MOCK_WAFW00F" <<'EOF'
#!/usr/bin/env bash
set -o nounset
target="${*: -1}"
printf 'Checking %s\n' "$target"
printf '[+] The site %s is behind Cloudflare (Cloudflare Inc.) WAF.\n' "$target"
exit 0
EOF
chmod +x "$MOCK_WAFW00F"

# 6. Mock curl
MOCK_CURL="$MOCK_BIN_DIR/mock_curl.sh"
cat > "$MOCK_CURL" <<'EOF'
#!/usr/bin/env bash
set -o nounset
head_dest=""
body_dest=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        -o) body_dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$head_dest" ]]; then
    cat <<'HEAD_EOF' > "$head_dest"
HTTP/1.1 200 OK
Server: cloudflare
cf-ray: 8e123456789-IAD
Content-Type: text/html
HEAD_EOF
fi

if [[ -n "$body_dest" ]]; then
    cat <<'BODY_EOF' > "$body_dest"
<html><head><title>Enterprise Portal</title><meta name="generator" content="WordPress 6.4.1" /></head><body>Enterprise Site</body></html>
BODY_EOF
fi
exit 0
EOF
chmod +x "$MOCK_CURL"

# -----------------------------------------------------------------------------
# Stage 1: Full M9 Web Discovery Pipeline Execution on Domain Target
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Full M9 Web Discovery Pipeline Execution on Domain Target"

OUT_DIR_STAGE1="$TEST_ROOT/full_web_discovery"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
    "$RECKON_BIN" --module http-probe,subdomain,technology,cms,waf \
                  --target "enterprise.corp" \
                  --output "$OUT_DIR_STAGE1" >/dev/null 2>&1
)
s1_exit=$?

if (( s1_exit == 0 )); then
    pass "M9 web discovery pipeline executes successfully on domain target with exit code 0"
else
    fail "M9 web discovery pipeline failed with exit code $s1_exit"
fi

TARGET_STAGE1_DIR="$OUT_DIR_STAGE1/enterprise.corp"
if [[ -d "$TARGET_STAGE1_DIR/http-probe" && \
      -d "$TARGET_STAGE1_DIR/subdomain" && \
      -d "$TARGET_STAGE1_DIR/technology" && \
      -d "$TARGET_STAGE1_DIR/cms" && \
      -d "$TARGET_STAGE1_DIR/waf" ]]; then
    pass "creates dedicated task directories for all 5 M9 web discovery modules"
else
    fail "missing task directory for M9 web discovery modules in $TARGET_STAGE1_DIR"
fi

# Verify every module generated output.txt with COMPLETED status
all_completed=true
for mod in http-probe subdomain technology cms waf; do
    mod_out="$TARGET_STAGE1_DIR/$mod/output.txt"
    if [[ ! -f "$mod_out" ]] || ! grep -q "Status: COMPLETED" "$mod_out"; then
        all_completed=false
        break
    fi
done

if [[ "$all_completed" == true ]]; then
    pass "every M9 web discovery module generated output.txt and logged COMPLETED status"
else
    fail "one or more M9 web discovery modules failed to log COMPLETED status"
fi

# -----------------------------------------------------------------------------
# Stage 2: Inter-Module Data Flow & Downstream Artifact Propagation
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Inter-Module Data Flow & Downstream Artifact Propagation"

# 1. http-probe artifacts
if [[ -f "$TARGET_STAGE1_DIR/http-probe/live_web.txt" && \
      -s "$TARGET_STAGE1_DIR/http-probe/live_web.txt" && \
      -f "$TARGET_STAGE1_DIR/http-probe/probed_urls.txt" && \
      -s "$TARGET_STAGE1_DIR/http-probe/probed_urls.txt" ]]; then
    pass "http-probe module produces live_web.txt and detailed probed_urls.txt"
else
    fail "http-probe failed to generate live_web.txt or probed_urls.txt"
fi

# 2. subdomain artifacts
if [[ -f "$TARGET_STAGE1_DIR/subdomain/subdomains.txt" && \
      -s "$TARGET_STAGE1_DIR/subdomain/subdomains.txt" && \
      -f "$TARGET_STAGE1_DIR/subdomain/resolved_subdomains.txt" && \
      -s "$TARGET_STAGE1_DIR/subdomain/resolved_subdomains.txt" ]]; then
    if grep -q "api.enterprise.corp" "$TARGET_STAGE1_DIR/subdomain/subdomains.txt" && \
       grep -q "api.enterprise.corp.*10.20.1.50" "$TARGET_STAGE1_DIR/subdomain/resolved_subdomains.txt"; then
        pass "subdomain module generates subdomains.txt and validated resolved_subdomains.txt"
    else
        fail "subdomain artifacts content verification failed"
    fi
else
    fail "subdomain module failed to generate subdomains.txt or resolved_subdomains.txt"
fi

# 3. technology artifacts
if [[ -f "$TARGET_STAGE1_DIR/technology/technologies.txt" && \
      -s "$TARGET_STAGE1_DIR/technology/technologies.txt" ]]; then
    if grep -q "Apache" "$TARGET_STAGE1_DIR/technology/technologies.txt" && \
       grep -q "PHP" "$TARGET_STAGE1_DIR/technology/technologies.txt" && \
       grep -q "jQuery" "$TARGET_STAGE1_DIR/technology/technologies.txt"; then
        pass "technology module extracts tech stack (Apache, PHP, jQuery) into technologies.txt"
    else
        fail "technology.txt content verification failed"
    fi
else
    fail "technology module failed to generate technologies.txt"
fi

# 4. cms artifacts
if [[ -f "$TARGET_STAGE1_DIR/cms/cms_detected.txt" && \
      -s "$TARGET_STAGE1_DIR/cms/cms_detected.txt" ]]; then
    if grep -q "WordPress" "$TARGET_STAGE1_DIR/cms/cms_detected.txt"; then
        pass "cms module identifies platform and records findings in cms_detected.txt"
    else
        fail "cms_detected.txt did not identify WordPress"
    fi
else
    fail "cms module failed to generate cms_detected.txt"
fi

# 5. waf artifacts
if [[ -f "$TARGET_STAGE1_DIR/waf/waf_detected.txt" && \
      -s "$TARGET_STAGE1_DIR/waf/waf_detected.txt" ]]; then
    if grep -q "Cloudflare" "$TARGET_STAGE1_DIR/waf/waf_detected.txt"; then
        pass "waf module identifies firewall protection and records findings in waf_detected.txt"
    else
        fail "waf_detected.txt did not identify Cloudflare"
    fi
else
    fail "waf module failed to generate waf_detected.txt"
fi

# -----------------------------------------------------------------------------
# Stage 3: Target Compatibility Pruning across URL Targets
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Target Compatibility Pruning across URL Targets"

OUT_DIR_STAGE3="$TEST_ROOT/url_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
    "$RECKON_BIN" --module http-probe,subdomain,technology,cms,waf \
                  --target "https://portal.enterprise.corp:8443/app/login" \
                  --output "$OUT_DIR_STAGE3" >/dev/null 2>&1
)
s3_exit=$?

if (( s3_exit == 0 )); then
    pass "URL pipeline execution succeeds with exit code 0"
else
    fail "URL pipeline execution failed with exit code $s3_exit"
fi

# Sanitized directory check
URL_TARGET_DIR="$OUT_DIR_STAGE3/https_portal.enterprise.corp_8443_app_login"
if [[ -d "$URL_TARGET_DIR/http-probe" && \
      -d "$URL_TARGET_DIR/technology" && \
      -d "$URL_TARGET_DIR/cms" && \
      -d "$URL_TARGET_DIR/waf" ]]; then
    pass "dispatches web modules (http-probe, technology, cms, waf) across custom port URL"
else
    fail "missing expected task directories for URL target in $URL_TARGET_DIR"
fi

# Verify subdomain module was cleanly pruned or skipped for URL target
if [[ ! -d "$URL_TARGET_DIR/subdomain" ]] || \
   grep -q "Status: SKIPPED" "$URL_TARGET_DIR/subdomain/output.txt"; then
    pass "prunes or gracefully skips incompatible subdomain module for URL target"
else
    fail "subdomain module was not pruned/skipped for URL target"
fi

# -----------------------------------------------------------------------------
# Stage 4: Single IPv4 Target Compatibility & Subdomain Pruning
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: Single IPv4 Target Compatibility & Subdomain Pruning"

OUT_DIR_STAGE4="$TEST_ROOT/ipv4_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
    "$RECKON_BIN" --module http-probe,subdomain,technology,cms,waf \
                  --target "192.168.10.50" \
                  --output "$OUT_DIR_STAGE4" >/dev/null 2>&1
)
s4_exit=$?

if (( s4_exit == 0 )); then
    pass "IPv4 pipeline execution succeeds with exit code 0"
else
    fail "IPv4 pipeline execution failed with exit code $s4_exit"
fi

IP_TARGET_DIR="$OUT_DIR_STAGE4/192.168.10.50"
if [[ -d "$IP_TARGET_DIR/http-probe" && \
      -d "$IP_TARGET_DIR/technology" && \
      -d "$IP_TARGET_DIR/cms" && \
      -d "$IP_TARGET_DIR/waf" ]]; then
    pass "schedules compatible web modules for single IPv4 target"
else
    fail "missing expected task directories for IPv4 target in $IP_TARGET_DIR"
fi

if [[ ! -d "$IP_TARGET_DIR/subdomain" ]] || \
   grep -q "Status: SKIPPED" "$IP_TARGET_DIR/subdomain/output.txt"; then
    pass "selectively prunes domain-only subdomain module for IPv4 target"
else
    fail "subdomain module was not pruned/skipped for IPv4 target"
fi

# -----------------------------------------------------------------------------
# Stage 5: Multi-Target File Execution with Heterogeneous Target Types
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Multi-Target File Execution with Heterogeneous Target Types"

TARGETS_FILE="$TEST_ROOT/batch_targets.txt"
cat <<'EOF' > "$TARGETS_FILE"
# Mixed target types for web discovery pipeline
company.local
10.20.30.40
https://api.gateway.local/v1
EOF

OUT_DIR_STAGE5="$TEST_ROOT/batch_web_pipeline"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
    "$RECKON_BIN" --module http-probe,subdomain,technology,cms,waf \
                  --targets-file "$TARGETS_FILE" \
                  --output "$OUT_DIR_STAGE5" >/dev/null 2>&1
)
s5_exit=$?

if (( s5_exit == 0 )); then
    pass "multi-target batch scan across mixed target types completes with exit code 0"
else
    fail "multi-target batch scan failed with exit code $s5_exit"
fi

if [[ -d "$OUT_DIR_STAGE5/company.local" && \
      -d "$OUT_DIR_STAGE5/10.20.30.40" && \
      -d "$OUT_DIR_STAGE5/https_api.gateway.local_v1" ]]; then
    pass "generates isolated directory trees for domain, IP, and URL targets in batch mode"
else
    fail "missing directory tree for one or more batch targets in $OUT_DIR_STAGE5"
fi

# -----------------------------------------------------------------------------
# Stage 6: Centralized Audit Logging Verification
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Centralized Audit Logging Verification"

LOG_FILE="$TEST_ROOT/audit_web.log"
(
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
    # shellcheck disable=SC2030,SC2031
    export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
    "$RECKON_BIN" --module http-probe,subdomain,technology,cms,waf \
                  --target "logbox.corp" \
                  --log-file "$LOG_FILE" \
                  --output "$TEST_ROOT/logbox_out" >/dev/null 2>&1
)

if [[ -f "$LOG_FILE" ]] && \
   grep -q "http-probe" "$LOG_FILE" && \
   grep -q "subdomain" "$LOG_FILE" && \
   grep -q "technology" "$LOG_FILE" && \
   grep -q "cms" "$LOG_FILE" && \
   grep -q "waf" "$LOG_FILE" && \
   grep -q "Scan execution finished" "$LOG_FILE"; then
    pass "audit log comprehensively records dispatch and completion for M9 web modules"
else
    fail "audit log missing expected module execution entries"
fi

# -----------------------------------------------------------------------------
# Stage 7: Secure Permission Verification across Generated Artifacts
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 7: Secure Permission Verification across Generated Artifacts"

perms_pass=true
while IFS= read -r -d '' dir; do
    d_perm="$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%p' "$dir" 2>/dev/null)"
    if [[ ! "$d_perm" =~ 750$ ]]; then
        perms_pass=false
        break
    fi
done < <(find "$TARGET_STAGE1_DIR" -mindepth 1 -maxdepth 1 -type d -print0)

while IFS= read -r -d '' file; do
    f_perm="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%p' "$file" 2>/dev/null)"
    if [[ ! "$f_perm" =~ 640$ ]]; then
        perms_pass=false
        break
    fi
done < <(find "$TARGET_STAGE1_DIR" -type f -name "*.txt" -print0)

if [[ "$perms_pass" == true ]]; then
    pass "enforces 0750 directory and 0640 file permissions across all web task directories"
else
    fail "permission check failed for one or more web directories or artifacts"
fi

test_summary
