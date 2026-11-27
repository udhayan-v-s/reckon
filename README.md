# RECKON

**A modular, automated network and web reconnaissance toolkit built entirely in Bash.**

RECKON orchestrates standard security tools into a streamlined, automated workflow. It scans network hosts and web applications, detects services and vulnerabilities, normalizes findings into unified JSON, and exports structured reports (Markdown, Text, JSON) with automatic historical scan tracking.

---

## Features

- **Automated Multi-Phase Recon:** Seamlessly orchestrates network scanning, service interrogation, and web application enumeration.
- **Intelligent Target Handling:** Accepts IPv4 addresses, CIDR ranges, hostnames, domain names, URLs (`http://` / `https://`), or target files.
- **25 Dedicated Modules:** Modular architecture allowing full scans or targeted module execution.
- **Multi-Format Reporting:** Generates clean **Markdown (`report.md`)**, **Plain Text (`report.txt`)**, and schema-validated **JSON (`results.json`)**.
- **Offline Web Visualizer (`report.html`):** Standalone, zero-dependency browser viewer for inspecting `results.json`, `report.md`, and `report.txt` with search, sorting, view toggles, demo mode, and executive PDF export.
- **Historical Scan Tracking:** Every scan run is preserved in its own timestamped subfolder with a `latest` link—subsequent scans never overwrite prior results.
- **Graceful Fallbacks:** Built-in tool fallback engines (e.g., curl-based fuzzing and fingerprinting if specialized tools like `ffuf` or `whatweb` are missing).
- **Zero Configuration Required:** Ready to run out of the box with sensible defaults and support for custom wordlists, thread controls, and JSON config files.

---

## Reconnaissance Modules

### Network Reconnaissance (11 Modules)
- `host` — Host discovery & ICMP sweeps (`fping`, `nmap`, ping)
- `dns` — Forward, reverse, and record queries (`dig`, `dnsx`)
- `port` — Port scanning with customizable port ranges (`nmap`, `nc`)
- `service` — Service version detection & banner grabbing (`nmap -sV`)
- `os` — Operating system fingerprinting (`nmap -O`)
- `ssh` — SSH configuration, key exchange, and auth methods (`ssh-audit`, `ssh-keyscan`)
- `ftp` — Anonymous login testing, banner inspection, and TLS checks
- `http` — HTTP web server enumeration and banner interrogation
- `https` — HTTPS service inspection and SSL protocol verification
- `smb` — SMB share enumeration, guest access, and dialect detection (`smbclient`, `enum4linux-ng`)
- `telnet` — Telnet service identification and cleartext authentication warnings

### Web Reconnaissance (14 Modules)
- `http-probe` — HTTP live host detection, status codes, and title extraction (`httpx`, `curl`)
- `technology` — Web stack & framework fingerprinting (`whatweb`, `curl`)
- `cms` — Content Management System identification (WordPress, Joomla, Drupal)
- `waf` — Web Application Firewall detection (`wafw00f`)
- `directory` — Directory discovery fuzzing (`ffuf`, `curl`)
- `file` — Sensitive file & credential discovery (`.htpasswd`, `.env`, backups)
- `vhost` — Virtual host fuzzing with Host header manipulation (`ffuf`)
- `crawl` — Web link crawling and endpoint spidering (`katana`, regex)
- `endpoint` — API and route extraction (REST, GraphQL)
- `http-analysis` — Security header audit, CORS policy testing, and HTTP method permissions
- `tls` — Certificate inspection, SANs, and cipher evaluation (`openssl`, `testssl.sh`)
- `resources` — Standard metadata discovery (`robots.txt`, `sitemap.xml`, `.well-known`)
- `subdomain` — Passive & active subdomain resolution (`subfinder`, `dnsx`)
- `historical-urls` — Wayback Machine and archive URL discovery (`gau`)

---

## Installation & Prerequisites

RECKON is portable and requires **Bash (>= 4.4)** and standard Linux tools.

1. **Clone the repository:**
   ```bash
   git clone https://github.com/udhayan-v-s/reckon.git
   cd reckon
   chmod +x reckon
   ```

2. **Verify dependencies:**
   ```bash
   ./reckon --check-deps
   ```
   
---

## Usage

```bash
reckon -t <TARGET> [OPTIONS]
reckon -T <TARGETS_FILE> [OPTIONS]
```

### Common Examples

1. **Network Reconnaissance on a Host:**
   ```bash
   ./reckon -t 192.168.1.10 -n
   ```

2. **Web Reconnaissance against a URL:**
   ```bash
   ./reckon -t http://10.10.10.50 -w
   ```

3. **Full Combined Recon (Network + Web):**
   ```bash
   ./reckon -t example.com --mode all
   ```

4. **Web Scan with Custom File Extensions & Wordlist:**
   ```bash
   ./reckon -t http://example.com -w -e php,html,txt,bak --wordlist /usr/share/wordlists/dirb/common.txt
   ```

5. **Scanning Custom Ports or All Ports:**
   ```bash
   ./reckon -t 192.168.1.50 -n -p 21,22,80,443,8080
   ./reckon -t 192.168.1.50 -n -p-
   ```

6. **Running Specific Modules Only:**
   ```bash
   ./reckon -t 192.168.1.1 -M host,port,service,http-analysis
   ```

7. **Full Scan Excluding Noisy Modules:**
   ```bash
   ./reckon -t example.com --mode all -x smb,telnet,waf
   ```

8. **Multi-Target File Scan:**
   ```bash
   ./reckon -T targets.txt --mode all -o scans/
   ```

9. **Dry-Run (Simulate Execution Plan):**
   ```bash
   ./reckon -t 192.168.1.1 --mode all --dry-run
   ```

---

## Results & Directory Structure

Results are organized by target under `results/<target>/`. Each scan run is preserved in a timestamped folder:

```text
results/
└── 10.48.158.113/
    ├── 2026-11-18_22-49-32/           # Historical Scan Run 1
    │   ├── report.md
    │   ├── report.txt
    │   └── results.json
    ├── 2026-11-18_23-15-29/           # Historical Scan Run 2
    │   ├── report.md
    │   ├── report.txt
    │   └── results.json
    ├── latest -> 2026-11-18_23-15-29/ # Symlink to newest run
    ├── report.md                      # Direct access to latest report
    ├── report.txt
    └── results.json
```

---

## Web Report Visualizer (`report.html`)

RECKON includes a standalone, **100% offline** web visualizer (`report.html` in the repository root) with zero external CDN or network dependencies.

### Quick Workflow

1. **Open the viewer** directly in your browser:
   ```bash
   xdg-open report.html
   # Or open file:///path/to/reckon/report.html in Firefox / Chrome
   ```
2. **Load a scan report** by dragging and dropping any output file (`results.json`, `report.md`, or `report.txt`) onto the upload zone, or click **Browse Files**.
   - Want to preview the UI without running a scan? Click **Demo Mode** / **Load Sample Report**.

### Supported Formats & Views

| File Format | Visualizer Mode | Capabilities |
| :--- | :--- | :--- |
| `results.json` | **Interactive Dashboard** | Executive KPI cards, multi-target switcher tabs, open ports & services, OS/DNS records, technologies/WAF/CMS, directories & files, security headers, CORS evaluation, HTTP methods, global search, quick filters, and column sorting |
| `report.md` | **Rendered Markdown** | Clean typography, formatted tables, and syntax-styled code blocks |
| `report.txt` | **Raw ASCII Log Viewer** | Monospace line-numbered log view with live line search and match highlighting |

### Additional Controls

- **View Mode Toggle:** Switch between `Dashboard`, `Markdown`, and `Raw Text` views for the loaded file.
- **Export PDF:** Click **Export PDF** (or press `Ctrl+P`) to generate a clean, light-themed A4 executive PDF report with automatic pagination and zebra-striped tables.

---

## Testing

Run the unified test suite (unit, integration, web viewer, and security audit):

```bash
./tests/run_tests.sh
```

Or run the web viewer validation suite individually:

```bash
./tests/run_tests.sh tests/unit/test_web_viewer.sh
```

---

## Configuration File (Optional)

You can specify default scan settings via a JSON configuration file (`--config config.json`):

```json
{
  "general": {
    "output_dir": "results",
    "threads": 20,
    "timeout": 300,
    "rate_limit": 10
  },
  "scanning": {
    "profile": "default",
    "ports": "top-100",
    "wordlist": "/usr/share/wordlists/dirb/common.txt"
  },
  "reporting": {
    "formats": ["JSON", "MD", "TXT"]
  }
}
```

---

## Responsible Use

RECKON is designed for authorized security assessments, penetration testing, bug bounty testing within scope, and educational research. Always obtain written authorization before scanning target networks or systems.

---

## License

This project is licensed under the [MIT License](LICENSE).
