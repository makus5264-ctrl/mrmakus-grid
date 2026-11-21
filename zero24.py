# zero24.py — [M] 24/7 autonomous zero-day hunter (MAKUS KERNEL)
# Wraps Makus-AUTOPWN in a persistent, resumable, evidence-backed loop.
# Usage:
#   python zero24.py --once --self-test        # one verified cycle, local lab
#   python zero24.py --interval 900            # forever, 15 min between cycles
#   python zero24.py --targets targets.txt --out ./zero24-out

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
ENGINE = os.environ.get("ZERO24_ENGINE") or os.path.join(
    HOME, ".config", "opencode", "skills", "makus-autopwn", "scripts", "auto_pwn.py")
DEFAULT_TARGETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "zero24-targets.txt")


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def stamp():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def run_engine(target, out, args, self_test=False):
    cmd = [sys.executable, ENGINE]
    if self_test:
        cmd.append("--self-test")
    else:
        cmd += ["--target", target]
    cmd += ["--out", out, "--rounds", str(args.rounds), "--budget", str(args.budget),
            "--discovery-budget", str(args.discovery_budget), "--workers", str(args.workers),
            "--planner", args.planner, "--planner-timeout", str(args.planner_timeout)]
    if args.planner == "gateway":
        cmd += ["--gateway", args.gateway, "--model", args.model]
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=args.budget + 120, env=env)
        return r.returncode, (r.stdout or b"").decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        return 124, ((e.stdout or b"").decode("utf-8", "replace") + "\n[zero24] engine timeout")


def read_summary(out):
    p = os.path.join(out, "summary.json")
    if not os.path.isfile(p):
        return {}
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return {}


def count_verified(s):
    res = s.get("verified") or s.get("results") or s.get("verdicts") or []
    if isinstance(res, dict):
        return sum(1 for v in res.values() if v is True or (isinstance(v, dict) and v.get("verified")))
    n = 0
    for v in res:
        if isinstance(v, dict) and (v.get("verified") or v.get("verdict") == "verified"):
            n += 1
    return n


def load_targets(path, explicit):
    if explicit:
        return [t.strip() for t in explicit if t.strip()]
    if os.path.isfile(path):
        return [ln.strip() for ln in open(path, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
    return ["http://127.0.0.1:18787", "http://127.0.0.1:8787", "http://127.0.0.1:8800"]


def render_report(state, cycles):
    lines = [
        "[M] ZERO24 // AUTONOMOUS 0-DAY HUNTER",
        "generated: " + utcnow(),
        "cycles=%d  targets=%d  verified_total=%d" % (
            cycles, len({c.get("target") for c in state}), sum(c.get("verified", 0) for c in state)),
        "",
        "%-22s %-10s %-8s %-6s %s" % ("TIME", "TARGET", "VERIFY", "RC", "OUT"),
    ]
    for c in state[-20:]:
        lines.append("%-22s %-10s %-8s %-6s %s" % (
            c.get("time", "")[:19], c.get("target", "?"), c.get("verified", 0), c.get("rc", "?"), c.get("out", "")))
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(prog="zero24.py", description="[M] 24/7 autonomous 0-day hunter")
    ap.add_argument("--target", action="append", default=[], help="repeatable; overrides targets file")
    ap.add_argument("--targets", default=DEFAULT_TARGETS)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "zero24-out"))
    ap.add_argument("--once", action="store_true", help="run one cycle then exit")
    ap.add_argument("--self-test", action="store_true", help="use auto_pwn self-test target")
    ap.add_argument("--interval", type=float, default=900.0, help="seconds between full cycles")
    ap.add_argument("--rounds", type=int, default=25)
    ap.add_argument("--budget", type=int, default=3600)
    ap.add_argument("--discovery-budget", type=int, default=60)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--planner", choices=["rank", "gateway"], default="rank")
    ap.add_argument("--gateway", default="http://127.0.0.1:28124/v1/chat/completions")
    ap.add_argument("--model", default="big-pickle")
    ap.add_argument("--planner-timeout", type=int, default=60)
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    except Exception:
        pass
    if not os.path.isfile(ENGINE):
        print("[zero24] ENGINE MISSING:", ENGINE)
        return 2

    os.makedirs(a.out, exist_ok=True)
    state_path = os.path.join(a.out, "state.jsonl")
    report_path = os.path.join(a.out, "reports", "zero24.md")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    state = []
    if os.path.isfile(state_path):
        for ln in open(state_path, encoding="utf-8"):
            try:
                state.append(json.loads(ln))
            except Exception:
                pass

    targets = load_targets(a.targets, a.target)
    if a.self_test:
        targets = ["<self-test>"]
    print("[zero24] engine=OK targets=%d interval=%.0fs mode=%s" %
          (len(targets), a.interval, "once" if a.once else "24/7"))

    cycle = 0
    while True:
        cycle += 1
        for target in targets:
            run_id = stamp() + "-" + ("selftest" if a.self_test else target.split("//")[-1].replace("/", "_").replace(":", "-")[:28])
            out = os.path.join(a.out, "runs", run_id)
            os.makedirs(out, exist_ok=True)
            t0 = time.time()
            rc, log = run_engine(target, out, a, self_test=a.self_test)
            summ = read_summary(out)
            verified = count_verified(summ)
            rec = {"time": utcnow(), "target": target, "rc": rc, "verified": verified,
                   "seconds": round(time.time() - t0, 1), "out": out,
                   "summary_keys": sorted(summ.keys())[:12]}
            state.append(rec)
            with open(state_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(render_report(state, cycle))
            tail = "\n".join(log.strip().splitlines()[-6:])
            print("[zero24] cycle=%d %s rc=%d verified=%d %.1fs\n%s" %
                  (cycle, target, rc, verified, rec["seconds"], tail))
        if a.once:
            break
        print("[zero24] cycle %d done, sleeping %.0fs" % (cycle, a.interval))
        time.sleep(max(1.0, a.interval))


if __name__ == "__main__":
    sys.exit(main())
