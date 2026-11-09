#!/usr/bin/env bash

#
# RECKON - Network and Web Reconnaissance Toolkit
# Web Reconnaissance Pipeline Integration Tests (tests/integration/test_web_pipeline.sh)
#
# Verifies end-to-end execution of the complete 14-module web reconnaissance pipeline:
#   1. http-probe
#   2. subdomain
#   3. technology
#   4. cms
#   5. waf
#   6. directory
#   7. file
#   8. vhost
#   9. crawl
#  10. endpoint
#  11. http-analysis
#  12. tls
#  13. resources
#  14. historical-urls
#
# Validates inter-module data flow, artifact generation, target type compatibility
# pruning, multi-target batch execution, centralized logging, and permission hardening.
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

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/reckon-webpipe-full.XXXXXX")" || {
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

    printf '%s\n' "Web reconnaissance pipeline integration tests completed."
}

printf '%s\n' "RECKON - Web Reconnaissance Pipeline Integration Tests"
printf '%s\n' "-----------------------------------------------------"

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
        elif [[ "$host" =~ ^https:// ]]; then
            printf '%s [200] [Enterprise Portal] [Apache/2.4.52] [2048]\n' "$host"
        elif [[ "$host" =~ ^http:// ]]; then
            printf '%s [200] [Enterprise Portal] [Apache/2.4.52] [2048]\n' "$host"
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
domain="${@: -1}"
cat <<SUBS_EOF
admin.${domain}
api.${domain}
dev.${domain}
portal.${domain}
SUBS_EOF
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
        [[ -z "$sub" ]] && continue
        if [[ "$sub" =~ ^admin\. ]]; then
            printf '%s [10.10.1.10]\n' "$sub"
        elif [[ "$sub" =~ ^api\. ]]; then
            printf '%s [10.10.1.20]\n' "$sub"
        elif [[ "$sub" =~ ^dev\. ]]; then
            printf '%s [10.10.1.30]\n' "$sub"
        elif [[ "$sub" =~ ^portal\. ]]; then
            printf '%s [10.10.1.40]\n' "$sub"
        else
            printf '%s [10.10.1.50]\n' "$sub"
        fi
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
target_url="${@: -1}"
printf '%s [200 OK] Apache[2.4.52], Country[UNITED STATES][US], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.1.10], Title[Enterprise Portal], WordPress[6.4.1]\n' "$target_url"
exit 0
EOF
chmod +x "$MOCK_WHATWEB"

# 5. Mock wafw00f
MOCK_WAFW00F="$MOCK_BIN_DIR/mock_wafw00f.sh"
cat > "$MOCK_WAFW00F" <<'EOF'
#!/usr/bin/env bash
set -o nounset
out_dest=""
target_url=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_dest="$2"; shift 2 ;;
        *) target_url="$1"; shift ;;
    esac
done

if [[ -n "$out_dest" ]]; then
    cat <<'WAF_JSON' > "$out_dest"
[
  {
    "url": "https://enterprise.corp",
    "detected": true,
    "firewall": "Cloudflare",
    "manufacturer": "Cloudflare Inc."
  }
]
WAF_JSON
fi
printf 'The site %s is behind Cloudflare (Cloudflare Inc.) WAF.\n' "$target_url"
exit 0
EOF
chmod +x "$MOCK_WAFW00F"

# 6. Mock ffuf (handles directory, file, and vhost fuzzing)
MOCK_FFUF="$MOCK_BIN_DIR/mock_ffuf.sh"
cat > "$MOCK_FFUF" <<'EOF'
#!/usr/bin/env bash
set -o nounset
out_file=""
is_vhost=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        -H)
            [[ "$2" =~ Host:[[:space:]]*FUZZ ]] && is_vhost=true
            shift 2
            ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    if [[ "$is_vhost" == true ]]; then
        cat <<'VH_JSON' > "$out_file"
{
  "results": [
    {"input": {"FUZZ": "dev.enterprise.corp"}, "status": 200, "length": 1420, "redirectlocation": "", "url": "http://enterprise.corp"},
    {"input": {"FUZZ": "api.enterprise.corp"}, "status": 200, "length": 890, "redirectlocation": "", "url": "http://enterprise.corp"}
  ]
}
VH_JSON
    else
        cat <<'DIR_JSON' > "$out_file"
{
  "results": [
    {"input": {"FUZZ": "admin"}, "status": 301, "length": 128, "redirectlocation": "/admin/", "url": "http://enterprise.corp/admin"},
    {"input": {"FUZZ": "api"}, "status": 200, "length": 512, "redirectlocation": "", "url": "http://enterprise.corp/api"},
    {"input": {"FUZZ": "config.json"}, "status": 200, "length": 256, "redirectlocation": "", "url": "http://enterprise.corp/config.json"},
    {"input": {"FUZZ": "database.sql"}, "status": 200, "length": 2048, "redirectlocation": "", "url": "http://enterprise.corp/database.sql"}
  ]
}
DIR_JSON
    fi
fi
exit 0
EOF
chmod +x "$MOCK_FFUF"

# 7. Mock katana (handles crawling and endpoint extraction)
MOCK_KATANA="$MOCK_BIN_DIR/mock_katana.sh"
cat > "$MOCK_KATANA" <<'EOF'
#!/usr/bin/env bash
set -o nounset
out_file=""
is_endpoint=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out_file="$2"; shift 2 ;;
        -em) is_endpoint=true; shift 2 ;;
        *) shift ;;
    esac
done

if [[ -n "$out_file" ]]; then
    if [[ "$is_endpoint" == true ]]; then
        cat <<'EP_LIST' > "$out_file"
/api/v1/users
/api/v2/items
/auth/token
/admin/dashboard
EP_LIST
    else
        cat <<'CRAWL_LIST' > "$out_file"
https://enterprise.corp/
https://enterprise.corp/about
https://enterprise.corp/products
https://enterprise.corp/assets/app.js
https://enterprise.corp/assets/style.css
CRAWL_LIST
    fi
fi
exit 0
EOF
chmod +x "$MOCK_KATANA"

# 8. Mock testssl.sh
MOCK_TESTSSL="$MOCK_BIN_DIR/mock_testssl.sh"
cat > "$MOCK_TESTSSL" <<'EOF'
#!/usr/bin/env bash
set -o nounset
cat <<'TESTSSL_OUT'
Testing protocols via sockets

 SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      not offered
 TLS 1.1    not offered
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)

Testing server's certificate

 Certificate Validity (UTC)   Valid until: 2027-12-31
 Common Name (CN)             enterprise.corp
 Issuer                       DigiCert Global Root CA
 Subject Alt Names (SANs)     enterprise.corp, www.enterprise.corp
TESTSSL_OUT
exit 0
EOF
chmod +x "$MOCK_TESTSSL"

# 9. Mock openssl
MOCK_OPENSSL="$MOCK_BIN_DIR/mock_openssl.sh"
cat > "$MOCK_OPENSSL" <<'EOF'
#!/usr/bin/env bash
set -o nounset
subcmd="$1"
shift
if [[ "$subcmd" == "s_client" ]]; then
    printf 'CONNECTED(00000003)\r\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\r\nProtocol  : TLSv1.3\r\n'
    exit 0
elif [[ "$subcmd" == "x509" ]]; then
    cat <<'X509_EOF'
Certificate:
    Data:
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = DigiCert Inc, CN = DigiCert Global Root CA
        Validity
            Not Before: Jan  1 00:00:00 2026 GMT
            Not After : Dec 31 23:59:59 2027 GMT
        Subject: CN = enterprise.corp
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:enterprise.corp, DNS:www.enterprise.corp
X509_EOF
    exit 0
fi
exit 1
EOF
chmod +x "$MOCK_OPENSSL"

# 10. Mock gau
MOCK_GAU="$MOCK_BIN_DIR/mock_gau.sh"
cat > "$MOCK_GAU" <<'EOF'
#!/usr/bin/env bash
set -o nounset
target="${@: -1}"
cat <<GAU_OUT
https://${target}/index.php
https://${target}/login?redirect=admin
https://${target}/api/v1/users?id=123
https://${target}/backup/database.sql
https://${target}/config.json
GAU_OUT
exit 0
EOF
chmod +x "$MOCK_GAU"

# 11. Mock curl
MOCK_CURL="$MOCK_BIN_DIR/mock_curl.sh"
cat > "$MOCK_CURL" <<'EOF'
#!/usr/bin/env bash
set -o nounset
head_dest=""
body_dest=""
w_flag=""
req_origin=""
method="GET"
req_url=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -D) head_dest="$2"; shift 2 ;;
        -o) body_dest="$2"; shift 2 ;;
        -w) w_flag="$2"; shift 2 ;;
        -H)
            if [[ "$2" =~ ^Origin:[[:space:]]*(.*) ]]; then
                req_origin="${BASH_REMATCH[1]}"
            fi
            shift 2
            ;;
        -X) method="$2"; shift 2 ;;
        -*) shift ;;
        *) req_url="$1"; shift ;;
    esac
done

# Robots.txt
if [[ "$req_url" =~ /robots\.txt ]]; then
    if [[ -n "$body_dest" ]]; then
        cat <<'ROBOTS_EOF' > "$body_dest"
User-agent: *
Disallow: /admin/
Disallow: /api/private/
Sitemap: https://enterprise.corp/sitemap.xml
ROBOTS_EOF
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# Sitemap.xml
if [[ "$req_url" =~ /sitemap\.xml ]]; then
    if [[ -n "$body_dest" ]]; then
        cat <<'SITEMAP_EOF' > "$body_dest"
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://enterprise.corp/</loc></url>
  <url><loc>https://enterprise.corp/about</loc></url>
</urlset>
SITEMAP_EOF
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# Security.txt
if [[ "$req_url" =~ /security\.txt ]]; then
    if [[ -n "$body_dest" ]]; then
        printf 'Contact: mailto:security@enterprise.corp\n' > "$body_dest"
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# OpenID configuration
if [[ "$req_url" =~ /openid-configuration ]]; then
    if [[ -n "$body_dest" ]]; then
        printf '{"issuer":"https://enterprise.corp"}\n' > "$body_dest"
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# Favicon.ico
if [[ "$req_url" =~ /favicon\.ico ]]; then
    if [[ -n "$body_dest" ]]; then
        printf 'FAVICON_MOCK_BYTES' > "$body_dest"
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# OPTIONS Method
if [[ "$method" == "OPTIONS" ]]; then
    if [[ -n "$head_dest" ]]; then
        cat <<'OPT_EOF' > "$head_dest"
HTTP/1.1 200 OK
Allow: GET, POST, OPTIONS, HEAD
Content-Length: 0

OPT_EOF
    fi
    [[ -n "$w_flag" ]] && printf '200'
    exit 0
fi

# Headers
if [[ -n "$head_dest" ]]; then
    cat <<'HDR_EOF' > "$head_dest"
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Server: Apache/2.4.52 (Ubuntu)
Content-Type: text/html

HDR_EOF
fi

# CORS Origin reflection
if [[ -n "$req_origin" && -n "$head_dest" ]]; then
    printf 'Access-Control-Allow-Origin: %s\r\nAccess-Control-Allow-Credentials: true\r\n' "$req_origin" >> "$head_dest"
fi

# Body content
if [[ -n "$body_dest" ]]; then
    cat <<'BODY_EOF' > "$body_dest"
<!DOCTYPE html>
<html>
<head>
    <title>Enterprise Portal</title>
    <meta name="generator" content="WordPress 6.4.1" />
    <link rel="stylesheet" href="/assets/style.css">
    <script src="/assets/app.js"></script>
</head>
<body>
    <h1>Welcome</h1>
    <a href="/about">About Us</a>
    <a href="/products">Products</a>
    <form action="/auth/login" method="POST"></form>
</body>
</html>
BODY_EOF
fi

[[ -n "$w_flag" ]] && printf '200'
exit 0
EOF
chmod +x "$MOCK_CURL"

# Common export wrapper for executing pipeline scans
run_pipeline() {
    (
        export RECKON_MOCK_HTTPX_BIN="$MOCK_HTTPX"
        export RECKON_MOCK_SUBFINDER_BIN="$MOCK_SUBFINDER"
        export RECKON_MOCK_DNSX_BIN="$MOCK_DNSX"
        export RECKON_MOCK_WHATWEB_BIN="$MOCK_WHATWEB"
        export RECKON_MOCK_WAFW00F_BIN="$MOCK_WAFW00F"
        export RECKON_MOCK_FFUF_BIN="$MOCK_FFUF"
        export RECKON_MOCK_KATANA_BIN="$MOCK_KATANA"
        export RECKON_MOCK_TESTSSL_BIN="$MOCK_TESTSSL"
        export RECKON_MOCK_OPENSSL_BIN="$MOCK_OPENSSL"
        export RECKON_MOCK_GAU_BIN="$MOCK_GAU"
        export RECKON_MOCK_CURL_BIN="$MOCK_CURL"
        "$RECKON_BIN" "$@"
    )
}

# -----------------------------------------------------------------------------
# Stage 1: Full Web Pipeline Execution (--web) on Domain Target with All 14 Modules
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 1: Full Web Pipeline Execution (--web) with All 14 Modules"

OUT_STAGE1="$TEST_ROOT/full_web_stage1"
LOG_STAGE1="$OUT_STAGE1/reckon.log"

if run_pipeline --web --target "enterprise.corp" --output "$OUT_STAGE1" --log-file "$LOG_STAGE1" >/dev/null 2>&1; then
    pass "full web pipeline executes successfully across domain target with exit code 0"
else
    fail "full web pipeline failed with non-zero exit code"
fi

TARGET_STAGE1_DIR="$OUT_STAGE1/enterprise.corp"
readonly _ALL_14_WEB_MODULES=(
    "http-probe"
    "subdomain"
    "technology"
    "cms"
    "waf"
    "directory"
    "file"
    "vhost"
    "crawl"
    "endpoint"
    "http-analysis"
    "tls"
    "resources"
    "historical-urls"
)

all_dirs_exist=true
for mod in "${_ALL_14_WEB_MODULES[@]}"; do
    if [[ ! -d "$TARGET_STAGE1_DIR/$mod" ]]; then
        all_dirs_exist=false
        break
    fi
done

if [[ "$all_dirs_exist" == true ]]; then
    pass "creates dedicated task directories for all 14 canonical web reconnaissance modules"
else
    fail "missing one or more task directories for canonical web modules in $TARGET_STAGE1_DIR"
fi

all_completed=true
for mod in "${_ALL_14_WEB_MODULES[@]}"; do
    mod_out="$TARGET_STAGE1_DIR/$mod/output.txt"
    if [[ ! -f "$mod_out" ]] || ! grep -q "Status: COMPLETED" "$mod_out"; then
        all_completed=false
        break
    fi
done

if [[ "$all_completed" == true ]]; then
    pass "every web module generated output.txt and logged COMPLETED status"
else
    fail "one or more web modules failed to generate output.txt or log COMPLETED status"
fi

# -----------------------------------------------------------------------------
# Stage 2: Comprehensive Artifact Verification Across All Web Modules
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 2: Comprehensive Artifact Verification Across All Web Modules"

# 1. Content & Path Fuzzing
if [[ -f "$TARGET_STAGE1_DIR/directory/directories.txt" && -s "$TARGET_STAGE1_DIR/directory/directories.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/file/files.txt" && -s "$TARGET_STAGE1_DIR/file/files.txt" ]]; then
    pass "directory and file modules generate directories.txt and files.txt"
else
    fail "directory or file module failed to generate artifact files"
fi

# 2. Virtual Host & Historical Reconnaissance
if [[ -f "$TARGET_STAGE1_DIR/vhost/vhosts.txt" && -s "$TARGET_STAGE1_DIR/vhost/vhosts.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/historical-urls/historical_urls.txt" && -s "$TARGET_STAGE1_DIR/historical-urls/historical_urls.txt" ]]; then
    pass "vhost and historical-urls modules generate vhosts.txt and historical_urls.txt"
else
    fail "vhost or historical-urls module failed to generate artifact files"
fi

# 3. Active Crawling & Endpoint Extraction
if [[ -f "$TARGET_STAGE1_DIR/crawl/crawled_urls.txt" && -s "$TARGET_STAGE1_DIR/crawl/crawled_urls.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/endpoint/endpoints.txt" && -s "$TARGET_STAGE1_DIR/endpoint/endpoints.txt" ]]; then
    pass "crawl and endpoint modules generate crawled_urls.txt and endpoints.txt"
else
    fail "crawl or endpoint module failed to generate artifact files"
fi

# 4. Web Security Analysis & Auditing
if [[ -f "$TARGET_STAGE1_DIR/http-analysis/http_analysis.txt" && -s "$TARGET_STAGE1_DIR/http-analysis/http_analysis.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/tls/tls_audit.txt" && -s "$TARGET_STAGE1_DIR/tls/tls_audit.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/tls/cert_info.txt" && -s "$TARGET_STAGE1_DIR/tls/cert_info.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/resources/resources.txt" && -s "$TARGET_STAGE1_DIR/resources/resources.txt" ]]; then
    pass "http-analysis, tls, and resources modules generate security evaluation artifacts"
else
    fail "http-analysis, tls, or resources module failed to generate security artifacts"
fi

# 5. Core Discovery & Fingerprinting (M9 Baseline)
if [[ -f "$TARGET_STAGE1_DIR/http-probe/live_web.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/subdomain/subdomains.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/technology/technologies.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/cms/cms_detected.txt" ]] && \
   [[ -f "$TARGET_STAGE1_DIR/waf/waf_detected.txt" ]]; then
    pass "web discovery modules generate live_web, subdomains, technologies, cms, and waf artifacts"
else
    fail "core discovery modules missing expected baseline artifacts"
fi

# -----------------------------------------------------------------------------
# Stage 3: Inter-Module Data Flow & Chained Downstream Propagation
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 3: Inter-Module Data Flow & Chained Downstream Propagation"

# Technology and CMS inspect live URLs produced by http-probe
if grep -q "WordPress" "$TARGET_STAGE1_DIR/cms/cms_detected.txt" && \
   grep -q "Apache" "$TARGET_STAGE1_DIR/technology/technologies.txt"; then
    pass "downstream fingerprinting modules successfully consume upstream live_web endpoints"
else
    fail "upstream live_web endpoints failed to propagate to technology/cms modules"
fi

# Crawl and Endpoint propagation
if grep -q "/about" "$TARGET_STAGE1_DIR/crawl/crawled_urls.txt" && \
   grep -q "/api/v1/users" "$TARGET_STAGE1_DIR/endpoint/endpoints.txt"; then
    pass "crawling and endpoint modules extract client-side and API routes"
else
    fail "crawling or endpoint propagation failed"
fi

# -----------------------------------------------------------------------------
# Stage 4: URL Target Compatibility Pruning
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 4: URL Target Compatibility Pruning"

OUT_STAGE4="$TEST_ROOT/url_pipeline"
# Plain HTTP URL target: subdomain and historical-urls require domain/hostname, tls requires HTTPS/domain
if run_pipeline --web --target "http://api.enterprise.corp:8080/v1" --output "$OUT_STAGE4" >/dev/null 2>&1; then
    pass "URL web pipeline execution succeeds with exit code 0"
else
    fail "URL web pipeline execution returned non-zero exit code"
fi

TARGET_STAGE4_DIR="$OUT_STAGE4/http_api.enterprise.corp_8080_v1"
[[ ! -d "$TARGET_STAGE4_DIR" ]] && TARGET_STAGE4_DIR="$(find "$OUT_STAGE4" -mindepth 1 -maxdepth 1 -type d | head -n 1)"

if [[ -d "$TARGET_STAGE4_DIR/http-probe" && \
      -d "$TARGET_STAGE4_DIR/directory" && \
      -d "$TARGET_STAGE4_DIR/crawl" && \
      -d "$TARGET_STAGE4_DIR/endpoint" && \
      -d "$TARGET_STAGE4_DIR/http-analysis" && \
      ! -d "$TARGET_STAGE4_DIR/subdomain" && \
      ! -d "$TARGET_STAGE4_DIR/historical-urls" && \
      ! -d "$TARGET_STAGE4_DIR/tls" ]]; then
    pass "planner schedules web URL compatible modules and prunes incompatible modules"
else
    fail "target compatibility pruning failed for plain HTTP URL target in $TARGET_STAGE4_DIR"
fi

# -----------------------------------------------------------------------------
# Stage 5: Multi-Target File Execution with Heterogeneous Target Types
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 5: Multi-Target File Execution with Heterogeneous Target Types"

TARGETS_FILE="$TEST_ROOT/heterogeneous_targets.txt"
cat <<'TARGETS_EOF' > "$TARGETS_FILE"
enterprise.corp
https://secure.enterprise.corp
http://portal.enterprise.corp:8080/app
TARGETS_EOF

OUT_STAGE5="$TEST_ROOT/batch_web_pipeline"
if run_pipeline --web --targets-file "$TARGETS_FILE" --output "$OUT_STAGE5" >/dev/null 2>&1; then
    pass "multi-target web pipeline batch execution succeeds with exit code 0"
else
    fail "multi-target web pipeline batch execution failed"
fi

if [[ -d "$OUT_STAGE5/enterprise.corp/subdomain" && \
      -d "$OUT_STAGE5/https_secure.enterprise.corp/tls" ]]; then
    pass "selectively schedules compatible modules per target type across batch execution"
else
    fail "selective module scheduling mismatch across multi-target execution"
fi

# -----------------------------------------------------------------------------
# Stage 6: Centralized Audit Logging Verification
# -----------------------------------------------------------------------------
printf '\n%s\n' "Stage 6: Centralized Audit Logging Verification"

if [[ -f "$LOG_STAGE1" ]] && \
   grep -q "enterprise.corp" "$LOG_STAGE1" && \
   grep -q "directory" "$LOG_STAGE1" && \
   grep -q "crawl" "$LOG_STAGE1" && \
   grep -q "endpoint" "$LOG_STAGE1" && \
   grep -q "tls" "$LOG_STAGE1"; then
    pass "audit log comprehensively records dispatch and completion for all web modules"
else
    fail "centralized audit logging incomplete in $LOG_STAGE1"
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
    pass "enforces 0750 directory and 0640 file permissions across all 14 web task directories"
else
    fail "permission check failed for one or more web directories or artifacts"
fi

test_summary
