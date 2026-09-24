# Wordpress Vulns - WordPress Dual Critical Vulnerability Checker

A non-invasive passive scanner that detects **two critical WordPress vulnerabilities** in a single run.

| CVE | Severity | Affected | Fixed in | Type |
|-----|----------|----------|----------|------|
| Click2Shell | High → Critical (chain) | WordPress < 7.1.1 | 7.1.1 | Theme Preview Injection → RCE |
| **CVE-2026-87902** | **CVSS 9.2 Critical** | WordPress < 7.1.2 (≥ 4.7) | 7.1.2 | Path Traversal → LFI (no auth) |

---

## How it works

### Click2Shell (WordPress < 7.1.1)
A crafted `/wp-admin/theme-install.php?theme=<value>` URL installs an attacker-selected theme from the WordPress.org catalog **without the administrator pressing Install/Activate** (selector injection in `wp-admin/js/theme.js`). Chained with pre-activation AJAX flaws in the `mobile-repair-zone` theme (2.5.4) and 40+ others, the inactive theme's PHP is loaded via the Customizer and executes attacker PHP. Core fix: [changeset 63664](https://core.trac.wordpress.org/changeset/63664) (`$.escapeSelector()`).

### CVE-2026-87902 (WordPress < 7.1.2)
A double-encoded path traversal in `get_page_template()` / `locate_template()` allows including arbitrary PHP files outside the theme directory — **no authentication required**.

**Payload:**
```
GET /?page_id=2&pagename=templates%252F%252E%252E%252F%252E%252E%252F%252E%252E%252Findex HTTP/1.1
```
`%252F%252E%252E%252F` → after first decode → `%2F%2E%2E%2F` → after WordPress decode → `/../`

**Detection method (passive, no exploitation):** three-request behavioral comparison:
1. **Baseline** — normal page request (200, has content)
2. **Control** — traversal targeting a guaranteed-nonexistent file (not a minimal 200)
3. **Test** — traversal targeting `wp-content/index.php` (empty stub file)

**Positive indicator:** test returns empty HTTP 200 while control does not → confirms the traversal resolves and includes files.

---

## Installation

```bash
git clone https://github.com/CronUp/click2shell-plusWo

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

# Skip CVE-2026-87902 behavioral check (faster, version-only)
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
| `--html FILE` | Export HTML report (self-contained, sortable) |
| `--poc TARGET` | Generate Click2Shell PoC HTML |
| `--poc-out FILE` | PoC output path (default: `click2shell_poc.html`) |
| `--poc-delay MS` | Stage-2 delay in milliseconds (default: 60000) |

---

## Output columns

| Column | Description |
|--------|-------------|
| TARGET | Target URL |
| WP | WordPress detected? |
| VERSION | Detected WordPress version |
| CLICK2SHELL | Vulnerable to Click2Shell (< 7.1.1)? |
| CVE-2026-87902 | Vulnerable to path traversal (< 7.1.2)? Confirmed by behavioral check |
| MRZ | `mobile-repair-zone` chain theme installed? |
| SETUP | `wp-admin/install.php` publicly accessible? |
| SOURCE | Where the version was found |

**VULNERABLE** = confirmed exposure. **patched** = version confirmed ≥ fixed baseline. **UNKNOWN** = WordPress detected but version could not be determined.

---

## Risk summary

- **WordPress < 7.1.1**: vulnerable to Click2Shell. If `mobile-repair-zone` is also installed, the full RCE chain is ready locally. Absence of the theme does NOT mean safe — WordPress downloads it from the catalog automatically.
- **WordPress 7.1.0 – 7.1.1**: Click2Shell is patched, but CVE-2026-87902 path traversal/LFI is still present (no auth required, CVSS 9.2).
- **WordPress ≥ 7.1.2**: both vulnerabilities patched.

---

## Remediation

| Vulnerability | Fix |
|---------------|-----|
| Click2Shell | Update to WordPress **7.1.1** or later |
| CVE-2026-87902 | Update to WordPress **7.1.2** or later (backport available for branches ≥ 4.7) |

---

## Legal notice

This tool is intended for **authorized security testing only**. You are solely responsible for ensuring you have explicit permission to scan any target. The authors accept no liability for unauthorized use.

---

## Author

**CronUp Cybersecurity** — [https://github.com/CronUp](https://github.com/CronUp)

Research references:
- [Click2Shell — pwn.ai, Sep 2026](https://pwn.ai)
- [CVE-2026-87902 — Hadrian, 2026](https://hadrian.io/vulnerability-alerts/cve-2026-87902-working-poc-wordpress-critical-path-traversal)

License: MIT
