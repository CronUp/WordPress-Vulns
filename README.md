# WordPress-Vulns - WordPress Dual Critical Vulnerability Scanner

A non-invasive passive scanner that detects **two critical WordPress vulnerabilities** in a single run, with multi-threaded support for bulk scanning.

| CVE | Severity | Affected | Fixed in | Type |
|-----|----------|----------|----------|------|
| Click2Shell | High -> Critical (chain) | WordPress < 7.1.1 | 7.1.1 | Theme Preview Injection -> RCE |
| **CVE-2026-87902** | **CVSS 9.2 Critical** | WordPress < 7.1.2 (>= 4.7) | 7.1.2 | Path Traversal -> LFI (no auth) |

---

## How it works

### Click2Shell (WordPress < 7.1.1)
A crafted `/wp-admin/theme-install.php?theme=<value>` URL installs an attacker-selected theme from the WordPress.org catalog **without the administrator pressing Install/Activate** (selector injection in `wp-admin/js/theme.js`). Chained with pre-activation AJAX flaws in the `mobile-repair-zone` theme (2.5.4) and 40+ others, the inactive theme's PHP is loaded via the Customizer and executes attacker PHP. Core fix: `$.escapeSelector()` (WordPress 7.1.1).

### CVE-2026-87902 (WordPress < 7.1.2)
A double-encoded path traversal in `get_page_template()` / `locate_template()` allows including arbitrary PHP files outside the theme directory - **no authentication required**.

**Payload:**
```
GET /?page_id=2&pagename=templates%252F%252E%252E%252F%252E%252E%252F%252E%252E%252Findex HTTP/1.1
```
`%252F%252E%252E%252F` -> first decode -> `%2F%2E%2E%2F` -> WordPress decode -> `/../`

**Detection (passive, no exploitation):** three-request behavioral comparison per candidate page ID:
1. **Baseline** - `/?page_id=N` - real page, confirms content exists
2. **Control** - traversal targeting a nonexistent file (should not match test)
3. **Test** - traversal targeting `wp-content/index.php` (empty PHP stub)

A behavioral signal (HTTP status difference or significant content-length drop) confirms the traversal is reachable. A negative behavioral result does **not** clear a site - WAFs, CDN caches, and theme configurations can silently absorb the payload without the vulnerability being patched.

---

## Installation

```bash
git clone https://github.com/CronUp/WordPress-Vulns
cd WordPress-Vulns
pip install -r requirements.txt

# Optional: Chrome TLS fingerprint impersonation (reduces Cloudflare blocks)
pip install curl_cffi
```

Requires Python 3.8+.

---

## Usage

```
python wordpress-vulns.py [-h] [-t TARGET | -l LIST]
                          [--threads N] [--timeout N] [--delay N]
                          [--insecure] [--no-impersonate]
                          [--no-chain] [--no-pathtrav]
                          [--prefer-https] [--no-color]
                          [--json FILE] [--csv FILE] [--html FILE]
                          [--poc TARGET] [--poc-out FILE]
                          [--poc-delay MS] [--poc-theme SLUG]
```

### Examples

```bash
# Scan a single target
python wordpress-vulns.py -t https://example.com

# Scan a list of targets and export all formats
python wordpress-vulns.py -l targets.txt --html report.html --json out.json --csv out.csv

# High-concurrency bulk scan
python wordpress-vulns.py -l targets.txt --threads 50 --timeout 15

# Skip CVE-2026-87902 behavioral check (version-only, faster)
python wordpress-vulns.py -l targets.txt --no-pathtrav

# Generate Click2Shell PoC HTML (requires authenticated admin to open)
python wordpress-vulns.py --poc https://example.com --poc-out poc.html
```

### Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Single target URL or domain |
| `-l`, `--list` | File with one target per line |
| `--threads N` | Concurrent workers (default: 15) |
| `--timeout N` | HTTP timeout in seconds (default: 20) |
| `--delay N` | Per-request courtesy delay in seconds |
| `--insecure` | Ignore TLS certificate errors |
| `--no-impersonate` | Disable Chrome browser impersonation |
| `--no-chain` | Skip `mobile-repair-zone` theme detection |
| `--no-pathtrav` | Skip CVE-2026-87902 behavioral check |
| `--prefer-https` | Prefer HTTPS when same host has both schemes |
| `--no-color` | Disable ANSI colors |
| `--json FILE` | Export results as JSON |
| `--csv FILE` | Export results as CSV |
| `--html FILE` | Export self-contained, sortable HTML report |
| `--poc TARGET` | Generate Click2Shell PoC HTML |
| `--poc-out FILE` | PoC output path (default: `click2shell_poc.html`) |
| `--poc-delay MS` | Stage-2 delay in milliseconds (default: 60000) |

---

## Output columns

| Column | Description |
|--------|-------------|
| TARGET | Target URL |
| WP | WordPress detected |
| VERSION | Detected WordPress version and source |
| CLICK2SHELL | Exposure to Click2Shell (version-based) |
| CVE-2026-87902 | Exposure to path traversal (version-based + behavioral) |
| MRZ | `mobile-repair-zone` chain theme installed |
| SETUP | `wp-admin/install.php` publicly reachable |
| SOURCE | Endpoint that revealed the version |

### Status labels

#### CLICK2SHELL

| Label | Meaning |
|-------|---------|
| `VULNERABLE` | Version < 7.1.1 |
| `patched` | Version >= 7.1.1 |
| `UNKNOWN` | WordPress confirmed but version not detected |

#### CVE-2026-87902

| Label | Meaning |
|-------|---------|
| `VULNERABLE` | Version < 7.1.2 (version-based), OR behavioral check confirmed path traversal |
| `patched` | Version >= 7.1.2 |
| `UNKNOWN` | WordPress confirmed, version not detected, behavioral check inconclusive |

> **Note:** A negative behavioral result does **not** produce `patched` for versions below 7.1.2. WAFs, CDN caches, and theme configurations can produce a clean-looking behavioral response even on a vulnerable site. Version >= 7.1.2 is the only reliable confirmation of the fix.

---

## Risk summary

| Version range | Click2Shell | CVE-2026-87902 |
|---------------|-------------|----------------|
| < 7.1.1 | **VULNERABLE** (RCE chain) | **VULNERABLE** |
| 7.1.0 - 7.1.1 | patched | **VULNERABLE** |
| >= 7.1.2 | patched | patched |

- If `mobile-repair-zone` is installed on a Click2Shell-vulnerable site, the full RCE chain is available locally. Its absence does **not** mean the site is safe - WordPress can download the theme automatically.
- CVE-2026-87902 requires no authentication and affects all branches back to WordPress 4.7.

---

## Remediation

| Vulnerability | Action |
|---------------|--------|
| Click2Shell | Update to WordPress **>= 7.1.1** |
| CVE-2026-87902 | Update to WordPress **>= 7.1.2** (backports available for branches >= 4.7) |

---

## Legal notice

This tool is intended for **authorized security testing only**. You are solely responsible for ensuring you have explicit written permission to scan any target. The authors accept no liability for unauthorized use.

---

## Author

**CronUp Cybersecurity** - [https://github.com/CronUp](https://github.com/CronUp)

Research references:
- [Click2Shell - pwn.ai, Sep 2026](https://pwn.ai)
- [CVE-2026-87902 - Hadrian, 2026](https://hadrian.io/vulnerability-alerts/cve-2026-87902-working-poc-wordpress-critical-path-traversal)

License: MIT

