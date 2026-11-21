#!/usr/bin/env python3
"""vuln_sweep.py - Makus-VULN vulnerability discovery runner.

Drives the probe paths and payloads that were extracted from the existing
FULL JD arsenal (catalog.json / wordlists/) against one target, and writes
real artifacts: evidence/, reports/<target>.md, summary.json.

Modes:
  --list                     show the arsenal catalog
  --target URL               sweep a target
  --target URL --offline     print the plan, send nothing
  --script REL --target URL  re-target one existing arsenal script (temp copy)
  --self-test                boot hackd/vulnshop.py locally and sweep it
  --rebuild                  regenerate the catalog from FULL JD first

Stdlib only. Every request has a hard timeout; the whole sweep has a budget.
"""

import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "catalog.json"
BUILDER = ROOT / "scripts" / "build_catalog.py"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36"

SECRET_RE = re.compile(
    r"(?i)(APP_KEY|DB_PASSWORD|DB_USER|AWS_ACCESS_KEY|SECRET_KEY|BEGIN [A-Z ]*PRIVATE KEY|"
    r"ref: refs/heads|password\s*[=:]\s*['\"]?[^\s'\"]{4,}|api[_-]?key\s*[=:])"
)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.env|\.git|config|backup|\.bak|\.sql|phpinfo|swagger|appsettings|web\.config|credentials|\.aws|DS_Store)"
)
SQL_ERROR_RE = re.compile(
    r"(?i)(sql syntax|mysql|sqlite|ora-\d{5}|pg::|you have an error|warning:.*(mysql|mysqli)|"
    r"unclosed quotation|unterminated|pdoexception|syntax error|exception.*sql)"
)
SQL_PAYLOAD_RE = re.compile(r"(?i)(union\s+select|or\s+1=1|'\s*or|sleep\(|benchmark\(|'\s*--)")
XSS_PAYLOAD_RE = re.compile(r"(?i)(<script|<svg|<img|onerror|onload)")
SECURITY_HEADERS = {
    "X-Frame-Options": ("low", "Clickjacking: no frame-ancestors policy."),
    "Content-Security-Policy": ("medium", "No CSP: inline/reflected script is unconstrained."),
    "Strict-Transport-Security": ("low", "No HSTS: downgrade/SSL-strip surface."),
    "X-Content-Type-Options": ("low", "MIME sniffing allowed."),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def log(msg):
    print(msg, flush=True)


def http(url, timeout=6, method="GET", data=None, headers=None, limit=120000):
    """One request. Returns (status, headers dict, body text, error)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, dict(r.headers), r.read(limit).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(limit).decode("utf-8", "replace"), None
    except Exception as e:
        return 0, {}, "", "%s: %s" % (type(e).__name__, str(e)[:160])


def load_catalog(rebuild=False):
    if rebuild or not CATALOG.is_file():
        log("[*] rebuilding catalog from the arsenal")
        subprocess.run([sys.executable, str(BUILDER)], check=True)
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def load_lists():
    paths = [p.strip() for p in (ROOT / "wordlists" / "paths.txt").read_text(encoding="utf-8").splitlines() if p.strip()]
    payloads = [p.strip() for p in (ROOT / "wordlists" / "payloads.txt").read_text(encoding="utf-8").splitlines() if p.strip()]
    pure = sorted({p for p in paths if "?" not in p and "%" not in p and "FUZZ" not in p and "\\" not in p and len(p) <= 100})
    injectable = sorted({p for p in paths if ("?" in p or "%" in p) and len(p) <= 160})
    sql = sorted({p for p in payloads if SQL_PAYLOAD_RE.search(p) and "[" not in p and len(p) < 90})
    xss = sorted({p for p in payloads if XSS_PAYLOAD_RE.search(p) and "[" not in p and len(p) < 90})
    return {"paths": paths, "pure": pure, "injectable": injectable, "sql": sql, "xss": xss}


class Sweep:
    def __init__(self, target, lists, timeout, budget, workers, offline):
        self.target = target.rstrip("/")
        self.host = urllib.parse.urlparse(self.target).hostname or "target"
        self.lists = lists
        self.timeout = timeout
        self.budget = budget
        self.workers = workers
        self.offline = offline
        self.started = time.time()
        self.findings = []
        self.checked = 0
        self.skipped = []
        self.seen = set()

    def elapsed(self):
        return time.time() - self.started

    def over(self, fraction=1.0):
        return self.elapsed() > self.budget * fraction

    def add(self, name, severity, url, detail, evidence, remediation):
        key = (name, url)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append({
            "name": name, "severity": severity, "url": url,
            "detail": detail, "evidence": evidence[:900], "remediation": remediation,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })

    def get(self, url, **kw):
        if self.offline or self.over():
            return None
        self.checked += 1
        return http(url, timeout=self.timeout, **kw)

    def check_headers(self):
        r = self.get(self.target + "/")
        if not r:
            return
        status, hdrs, _, err = r
        if err:
            self.skipped.append("security headers: %s" % err)
            return
        low = {k.lower(): v for k, v in hdrs.items()}
        missing = [k for k in SECURITY_HEADERS if k.lower() not in low]
        if missing:
            for k in missing:
                sev, why = SECURITY_HEADERS[k]
                self.add("missing-security-header:" + k, sev, self.target + "/", why,
                         "Response headers: " + ", ".join("%s=%s" % (a, b) for a, b in list(hdrs.items())[:14]),
                         "Set %s on all responses." % k)
        if low.get("server") or low.get("x-powered-by"):
            self.add("tech-fingerprint", "info", self.target + "/",
                     "Server/stack disclosed in response headers (check_headers.py pattern).",
                     "Server=%s | X-Powered-By=%s" % (low.get("server", "-"), low.get("x-powered-by", "-")),
                     "Suppress version banners; verify the disclosed stack for known CVEs.")

    def check_paths(self):
        """Exposed-file / endpoint surface. Uses paths extracted from the arsenal."""
        paths = self.lists["pure"]
        if self.offline:
            return
        cap = min(len(paths), 250)

        def probe(p):
            url = self.target + p
            self.checked += 1
            return p, http(url, timeout=self.timeout)

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures = [ex.submit(probe, p) for p in paths[:cap]]
            for fut in as_completed(futures):
                if self.over(0.62):
                    self.skipped.append("exposed-path sweep: budget reached after %d/%d paths" % (self.checked, cap))
                    for f in futures:
                        f.cancel()
                    break
                try:
                    p, (status, hdrs, body, err) = fut.result()
                except Exception:
                    continue
                if err or status == 0 or status >= 400:
                    continue
                sensitive = bool(SENSITIVE_PATH_RE.search(p))
                secret = bool(SECRET_RE.search(body[:4000]))
                if sensitive and secret:
                    sev, name = "critical", "exposed-secret"
                    detail = "Publicly readable sensitive file with credential-like content."
                elif sensitive:
                    sev, name = "medium", "exposed-sensitive-path"
                    detail = "Sensitive path is reachable without auth (content not credential-like)."
                elif p.rstrip("/") in {"/admin", "/Admin", "/api", "/api/", "/swagger/index.html", "/healthcheck"}:
                    sev, name = "medium", "admin-or-api-surface"
                    detail = "Administrative/API surface reachable; verify authorization."
                else:
                    continue
                self.add(name, sev, self.target + p, detail,
                         "HTTP %d | len=%d | %s" % (status, len(body), body[:350].replace("\n", " ")),
                         "Block or authenticate this path; rotate any exposed secret.")

    def check_injection_paths(self):
        """Replay the arsenal's own query-string probes (check_product_sqli.py style)."""
        for p in self.lists["injectable"][:12]:
            if self.over(0.72):
                self.skipped.append("injection path replay: budget")
                return
            r = self.get(self.target + p)
            if not r:
                continue
            status, _, body, err = r
            if err:
                continue
            if SQL_ERROR_RE.search(body[:6000]):
                self.add("sql-error-disclosure", "high", self.target + p,
                         "Injected query triggered a database error in the response.",
                         body[:400].replace("\n", " "),
                         "Use parameterized queries; disable verbose DB errors.")

    def check_sqli(self):
        payloads = self.lists["sql"][:8]
        if not payloads:
            payloads = ["1' OR 1=1--", "1 UNION SELECT 1,2,3--"]
        for param in ("id", "q"):
            for pl in payloads[:5]:
                if self.over(0.8):
                    self.skipped.append("sqli probes: budget")
                    return
                url = self.target + "/?" + urllib.parse.urlencode({param: pl})
                r = self.get(url)
                if not r:
                    continue
                status, _, body, err = r
                if err:
                    continue
                if SQL_ERROR_RE.search(body[:6000]):
                    self.add("sqli-indicator", "high", url,
                             "SQL error indicator in response after payload (check_product_sqli.py pattern).",
                             body[:400].replace("\n", " "),
                             "Parameterized queries; generic error pages.")

    def check_xss(self):
        marker = "mksvuln<svg onload=1>"
        url = self.target + "/search?" + urllib.parse.urlencode({"q": marker})
        r = self.get(url)
        if not r:
            return
        status, _, body, err = r
        if err:
            return
        if marker in body or "<svg onload=1>" in body:
            self.add("reflected-xss", "medium", url,
                     "Unescaped reflection of the injected marker in the response body.",
                     body[:400].replace("\n", " "),
                     "Context-aware output encoding + CSP.")

    def check_idor(self):
        seen_bodies = []
        for uid in (1, 2, 3):
            if self.over(0.88):
                return
            url = self.target + "/api/users/%d" % uid
            r = self.get(url)
            if not r:
                continue
            status, _, body, err = r
            if err or status != 200:
                continue
            if re.search(r"(?i)(role|email|token|password)", body):
                seen_bodies.append((uid, body[:300]))
        if len(seen_bodies) >= 2:
            self.add("idor-user-records", "high", self.target + "/api/users/<id>",
                     "Sequential object IDs return different user records without an auth challenge.",
                     " | ".join("id=%d: %s" % (i, b) for i, b in seen_bodies),
                     "Enforce per-object authorization; use opaque IDs.")

    def check_js_and_forms(self):
        r = self.get(self.target + "/")
        if not r:
            return
        status, _, body, err = r
        if err:
            return
        js = re.findall(r"<script[^>]*src=[\"']([^\"']*)[\"']", body, re.I)
        api = re.findall(r"[\"']([^\"']*(?:api|auth|login|graphql)[^\"']*)[\"']", body, re.I)
        if js or api:
            self.add("client-side-endpoints", "info", self.target + "/",
                     "JS bundles and API-like strings discovered (check_js_endpoints.py pattern).",
                     "scripts=%s | api=%s" % (js[:8], api[:8]),
                     "Review these endpoints for auth gaps before publishing.")
        for p in ("/login", "/login.php"):
            if self.over(0.92):
                return
            rr = self.get(self.target + p)
            if not rr:
                continue
            st, _, hb, er = rr
            if er or st != 200:
                continue
            forms = re.findall(r"<form[^>]*>", hb, re.I)
            inputs = re.findall(r"<input[^>]*>", hb, re.I)
            if forms:
                csrf = bool(re.search(r"(?i)(csrf|_token|authenticity)", hb))
                self.add("login-form-surface", "low" if csrf else "medium", self.target + p,
                         "Login form reachable; CSRF token %s." % ("present" if csrf else "NOT found"),
                         "forms=%s | inputs=%s" % (forms[:4], inputs[:8]),
                         "Add CSRF tokens, rate limiting and lockout.")
            break

    def check_redirect_and_cors(self):
        for param in ("redirect", "url", "next", "goto"):
            if self.over(0.96):
                return
            url = self.target + "/?" + urllib.parse.urlencode({param: "//evil.example"})
            r = self.get(url)
            if not r:
                continue
            status, hdrs, _, err = r
            loc = hdrs.get("Location", "") or hdrs.get("location", "")
            if "evil.example" in loc:
                self.add("open-redirect", "medium", url,
                         "User-controlled redirect target is reflected in Location.",
                         "HTTP %d | Location=%s" % (status, loc),
                         "Allowlist redirect destinations.")
        r = self.get(self.target + "/", headers={"Origin": "https://evil.example"})
        if r:
            _, hdrs, _, err = r
            low = {k.lower(): v for k, v in hdrs.items()}
            acao = low.get("access-control-allow-origin", "")
            if acao and (acao.strip() == "*" or "evil.example" in acao):
                self.add("cors-misconfiguration", "medium", self.target + "/",
                         "Cross-origin reads permitted from an arbitrary origin.",
                         "ACAO=%s | ACAC=%s" % (acao, low.get("access-control-allow-credentials", "-")),
                         "Restrict ACAO to trusted origins; avoid wildcard with credentials.")

    def run(self):
        checks = [
            ("security headers", self.check_headers),
            ("exposed paths / endpoint surface", self.check_paths),
            ("arsenal query probes", self.check_injection_paths),
            ("SQLi indicators", self.check_sqli),
            ("reflected XSS", self.check_xss),
            ("IDOR", self.check_idor),
            ("JS / login forms", self.check_js_and_forms),
            ("open redirect / CORS", self.check_redirect_and_cors),
        ]
        if self.offline:
            log("[offline] plan for %s (no requests sent)" % self.target)
            log("  wordlists: %d pure paths, %d injection paths, %d SQL payloads, %d XSS payloads" %
                (len(self.lists["pure"]), len(self.lists["injectable"]), len(self.lists["sql"]), len(self.lists["xss"])))
            for name, _ in checks:
                log("  - %s" % name)
            return
        for name, fn in checks:
            if self.over():
                self.skipped.append("%s: total budget exhausted" % name)
                continue
            t0 = time.time()
            fn()
            log("  [+] %-34s %5.1fs  findings=%d" % (name, time.time() - t0, len(self.findings)))
        return


def write_artifacts(sweep, out_dir, extra=None):
    host = re.sub(r"[^A-Za-z0-9._-]", "_", sweep.host)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = Path(out_dir).resolve()
    ev = base / "evidence" / ("%s-%s" % (host, stamp))
    rep = base / "reports"
    ev.mkdir(parents=True, exist_ok=True)
    rep.mkdir(parents=True, exist_ok=True)
    for i, f in enumerate(sweep.findings, 1):
        slug = re.sub(r"[^A-Za-z0-9_-]", "_", f["name"])[:60]
        fname = "%02d_%s.txt" % (i, slug)
        f["evidence_file"] = str(ev / fname)
        (ev / fname).write_text(
            "name: %s\nseverity: %s\nurl: %s\ndetail: %s\nremediation: %s\n\n--- evidence ---\n%s\n" %
            (f["name"], f["severity"], f["url"], f["detail"], f["remediation"], f["evidence"]), encoding="utf-8")
    counts = {}
    for f in sweep.findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = {
        "skill": "makus-vuln", "target": sweep.target, "generated_at": sweep.findings[0]["at"] if sweep.findings else datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round(sweep.elapsed(), 2), "requests": sweep.checked,
        "wordlists": {k: len(v) for k, v in sweep.lists.items()},
        "severity_counts": counts, "skipped": sweep.skipped,
        "extra_evidence": extra or [], "findings": sweep.findings,
    }
    summary_path = base / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = [
        "# Makus-VULN - %s" % sweep.target,
        "",
        "- Generated: %s" % summary["generated_at"],
        "- Duration: %ss | requests: %d | findings: %d" % (summary["duration_seconds"], sweep.checked, len(sweep.findings)),
        "- Arsenal paths: %d | injection probes: %d | SQL payloads: %d | XSS payloads: %d" %
        (len(sweep.lists["pure"]), len(sweep.lists["injectable"]), len(sweep.lists["sql"]), len(sweep.lists["xss"])),
        "",
        "## Severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for sev in sorted(counts, key=lambda x: SEVERITY_ORDER.get(x, 9)):
        lines.append("| %s | %d |" % (sev.upper(), counts[sev]))
    lines += ["", "## Findings", ""]
    if not sweep.findings:
        lines.append("No findings. Checks executed: headers, %d paths, injection replay, SQLi, XSS, IDOR, JS/forms, redirect/CORS." % len(sweep.lists["pure"]))
    for f in sorted(sweep.findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
        lines += [
            "### [%s] %s" % (f["severity"].upper(), f["name"]),
            "",
            "- URL: `%s`" % f["url"],
            "- Detail: %s" % f["detail"],
            "- Fix: %s" % f["remediation"],
            "- Evidence: `%s`" % f.get("evidence_file", str(ev)),
            "",
            "```",
            f["evidence"][:300],
            "```",
            "",
        ]
    if sweep.skipped:
        lines += ["## Skipped / budget", ""] + ["- %s" % s for s in sweep.skipped] + [""]
    lines += ["## Artifacts", "", "- `evidence/%s/`" % ev.name, "- `reports/%s.md`" % host, "- `summary.json`", ""]
    report_path = rep / ("%s.md" % host)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return summary_path, report_path, ev


def run_arsenal_script(rel, target, catalog, timeout, out_dir):
    root = Path(catalog["arsenal_root"])
    src = (root / rel).resolve()
    if not src.is_file() or not str(src).startswith(str(root.resolve())):
        raise SystemExit("[FAIL] not an arsenal script: %s" % rel)
    if src.suffix.lower() not in {".py", ".ps1"}:
        raise SystemExit("[FAIL] only .py / .ps1 scripts are supported")
    host = urllib.parse.urlparse(target).hostname or target
    text = src.read_text(encoding="utf-8", errors="replace")
    rendered = re.sub(r"(https?://)[A-Za-z0-9._\-]+", lambda m: m.group(1) + host, text)
    rendered = re.sub(r"(\b(?:HOST|IP|BASE|TARGET)\s*=\s*[\"'])[^\"']+([\"'])",
                      lambda m: m.group(1) + host + m.group(2), rendered)
    if "urllib" in text:
        rendered = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", host, rendered)
    tmp = Path(tempfile.mkdtemp(prefix="mks-vuln-")) / src.name
    tmp.write_text(rendered, encoding="utf-8")
    if src.suffix.lower() == ".py":
        cmd = [sys.executable, str(tmp)]
    else:
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(tmp), "-Base", target]
    log("[*] re-targeted arsenal script: %s -> %s (original untouched)" % (rel, host))
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(src.parent))
        output, rc = (p.stdout or "") + "\n--- stderr ---\n" + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired as e:
        output, rc = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout"
    ev = Path(out_dir).resolve() / "evidence"
    ev.mkdir(parents=True, exist_ok=True)
    dest = ev / ("arsenal_%s.txt" % re.sub(r"[^A-Za-z0-9_-]", "_", rel))
    dest.write_text("script: %s\ntarget: %s\nrc: %s\n\n%s\n" % (rel, target, rc, output[:20000]), encoding="utf-8")
    log("[OK] arsenal output -> %s (rc=%s, %d bytes)" % (dest, rc, len(output)))
    return str(dest)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def start_self_test(catalog):
    """Boot the bundled vulnerable shop on a free localhost port. Returns (url, proc)."""
    root = Path(catalog["arsenal_root"])
    src = root / "hackd" / "vulnshop.py"
    if not src.is_file():
        raise SystemExit("[FAIL] local target missing: %s" % src)
    port = free_port()
    text = src.read_text(encoding="utf-8", errors="replace").replace("8099", str(port))
    tmp = Path(tempfile.mkdtemp(prefix="mks-vuln-selftest-")) / "vulnshop.py"
    tmp.write_text(text, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(tmp)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_port(port):
            raise SystemExit("[FAIL] local vulnshop did not start on %d" % port)
        log("[*] local vulnshop listening on 127.0.0.1:%d (no external traffic)" % port)
        return "http://127.0.0.1:%d" % port, proc
    except Exception:
        proc.terminate()
        raise


def main():
    ap = argparse.ArgumentParser(description="Makus-VULN - drive the FULL JD probe arsenal at one target")
    ap.add_argument("--target", help="base URL of the target, e.g. http://127.0.0.1:8099")
    ap.add_argument("--list", action="store_true", help="show the generated arsenal catalog and exit")
    ap.add_argument("--offline", action="store_true", help="print the plan only, send no requests")
    ap.add_argument("--self-test", action="store_true", help="boot hackd/vulnshop.py locally and sweep it")
    ap.add_argument("--script", help="re-target one existing arsenal script (relative path) and attach its output")
    ap.add_argument("--rebuild", action="store_true", help="regenerate catalog.json from FULL JD first")
    ap.add_argument("--out", default=".", help="artifact root (evidence/, reports/, summary.json)")
    ap.add_argument("--timeout", type=float, default=6, help="per-request timeout in seconds")
    ap.add_argument("--budget", type=float, default=90, help="total sweep budget in seconds")
    ap.add_argument("--workers", type=int, default=12, help="parallel path probes")
    args = ap.parse_args()

    catalog = load_catalog(args.rebuild)
    if args.list:
        print(json.dumps({
            "arsenal": catalog["arsenal_root"],
            "generated_at": catalog["generated_at"],
            "scripts": catalog["files_scanned"],
            "categories": catalog["categories"],
            "wordlists": catalog["wordlists"],
            "parameterized": catalog["parameterized_scripts"],
        }, indent=2, ensure_ascii=False))
        return 0
    if not args.target and not args.self_test:
        ap.error("need --target, --list or --self-test")

    lists = load_lists()
    proc = None
    if args.self_test:
        args.target, proc = start_self_test(catalog)
    extra = []
    if args.script and not args.offline:
        extra.append(run_arsenal_script(args.script, args.target, catalog,
                                        max(15, args.timeout * 5), args.out))
    sweep = Sweep(args.target, lists, args.timeout, args.budget, args.workers, args.offline)
    log("[M] Makus-VULN | target=%s | paths=%d | inject=%d | budget=%ss | offline=%s" %
        (sweep.target, len(lists["pure"]), len(lists["injectable"]), args.budget, args.offline))
    try:
        sweep.run()
        if args.offline:
            return 0
        summary_path, report_path, ev = write_artifacts(sweep, args.out, extra)
        counts = {}
        for f in sweep.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        log("[OK] %d findings in %.1fs (%d requests)" % (len(sweep.findings), sweep.elapsed(), sweep.checked))
        log("     %s" % (", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 9))) or "none"))
        log("     report : %s" % report_path)
        log("     summary: %s" % summary_path)
        log("     evidence: %s" % ev)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
