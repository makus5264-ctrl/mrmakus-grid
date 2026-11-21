# vps_agent.py — [M] VPS autonomous hunter agent (MAKUS KERNEL)
# Runs zero24 cycles forever, self-heals on crash, exposes token-auth control API.
# Control: X-Zero24-Token header. Bind local; reach it over WireGuard/Tailscale.
# Usage: python vps_agent.py --token SECRET --port 9099

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ZERO24 = os.path.join(HERE, "zero24.py")
STATE = os.path.join(HERE, "vps-agent-state.json")
REPORT = os.path.join(HERE, "zero24-out", "reports", "zero24.md")


def load_state():
    try:
        return json.load(open(STATE, encoding="utf-8"))
    except Exception:
        return {"run": False, "cycles": 0, "targets": [], "verified_total": 0,
                "last_error": "", "last_cycle": "", "history": []}


def save_state(s):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=2, ensure_ascii=False)


class Agent:
    def __init__(self, token, interval, relay=None):
        self.token, self.interval, self.relay = token, interval, relay.rstrip("/") if relay else None
        self.s = load_state()
        self.proc = None
        self.lock = threading.Lock()
        self.stop = False

    def supervisor(self):
        while not self.stop:
            with self.lock:
                alive = self.proc is not None and self.proc.poll() is None
                if self.s["run"] and not alive:
                    if self.proc is not None and self.proc.returncode not in (0, None):
                        self.s["last_error"] = "engine rc=" + str(self.proc.returncode)
                        save_state(self.s)
                    cmd = [sys.executable, ZERO24, "--once"]
                    if self.s["targets"]:
                        for t in self.s["targets"]:
                            cmd += ["--target", t]
                    else:
                        cmd += ["--self-test"]
                    try:
                        self.proc = subprocess.Popen(cmd, cwd=HERE,
                                                     stdout=subprocess.DEVNULL,
                                                     stderr=subprocess.STDOUT)
                        self.s["last_cycle"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                    except Exception as e:
                        self.s["last_error"] = str(e)[:200]
                    save_state(self.s)
                if not self.s["run"] and alive:
                    try:
                        self.proc.terminate()
                    except Exception:
                        pass
            time.sleep(2)
            if self.s["run"] and self.proc is not None and self.proc.poll() is not None:
                self.s["cycles"] += 1
                try:
                    zstate = os.path.join(HERE, "zero24-out", "state.jsonl")
                    if os.path.isfile(zstate):
                        total = 0
                        for ln in open(zstate, encoding="utf-8"):
                            try:
                                rec = json.loads(ln)
                                total += int(rec.get("verified", 0) or 0)
                            except Exception:
                                pass
                        self.s["verified_total"] = total
                except Exception:
                    pass
                save_state(self.s)
                time.sleep(max(1, self.interval))

    def control(self, action, value=None):
        with self.lock:
            if action == "start":
                self.s["run"] = True
            elif action == "stop":
                self.s["run"] = False
            elif action == "add_target":
                if value and value not in self.s["targets"]:
                    self.s["targets"].append(value)
            elif action == "remove_target":
                if value in self.s["targets"]:
                    self.s["targets"].remove(value)
            elif action == "exec":
                try:
                    r = subprocess.run(value, shell=True, cwd=HERE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, timeout=120)
                    return {"ok": r.returncode == 0, "rc": r.returncode,
                            "output": (r.stdout or b"").decode("utf-8", "replace")[-4000:]}
                except Exception as e:
                    return {"ok": False, "error": str(e)[:300]}
            save_state(self.s)
        return {"ok": True, "run": self.s["run"], "targets": self.s["targets"]}

    def relay_loop(self):
        """Cloud Shell mode: agent calls out to a relay; no inbound port needed."""
        import urllib.error
        import urllib.request
        hdr = {"X-Zero24-Token": self.token, "Content-Type": "application/json"}
        last_status = 0
        while not self.stop:
            try:
                r = urllib.request.urlopen(urllib.request.Request(self.relay + "/command", headers=hdr), timeout=10)
                job = json.loads(r.read().decode("utf-8", "replace") or "null")
            except Exception:
                job = None
            if isinstance(job, dict) and job.get("cmd"):
                result = self.control(job["cmd"], job.get("value"))
                try:
                    urllib.request.urlopen(urllib.request.Request(
                        self.relay + "/result", data=json.dumps(result).encode(), headers=hdr,
                        method="POST"), timeout=10)
                except Exception:
                    pass
            if time.time() - last_status > 10:
                s = dict(self.s)
                s["pid"] = self.proc.pid if self.proc else None
                s["alive"] = bool(self.proc and self.proc.poll() is None)
                s["health"] = "OK" if not s["last_error"] else "DEGRADED"
                try:
                    urllib.request.urlopen(urllib.request.Request(
                        self.relay + "/status", data=json.dumps(s).encode(), headers=hdr,
                        method="POST"), timeout=10)
                except Exception:
                    pass
                last_status = time.time()
            time.sleep(3)

    def report(self):
        try:
            return open(REPORT, encoding="utf-8").read()[:12000]
        except Exception:
            return "(no report yet)"


def make_handler(agent):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _auth(self):
            return self.headers.get("X-Zero24-Token") == agent.token

        def do_GET(self):
            if not self._auth():
                return self._json({"error": "unauthorized"}, 401)
            p = urlparse(self.path).path
            if p == "/status":
                s = dict(agent.s)
                s["pid"] = agent.proc.pid if agent.proc else None
                s["alive"] = bool(agent.proc and agent.proc.poll() is None)
                s["health"] = "OK" if not s["last_error"] else "DEGRADED"
                return self._json(s)
            if p == "/report":
                data = agent.report().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._auth():
                return self._json({"error": "unauthorized"}, 401)
            n = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else "{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
            return self._json(agent.control(body.get("cmd", ""), body.get("value")))
    return H


def main():
    ap = argparse.ArgumentParser(prog="vps_agent.py")
    ap.add_argument("--token", default=os.environ.get("ZERO24_TOKEN", "makus-local-token"))
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--interval", type=float, default=900.0)
    ap.add_argument("--relay", default=os.environ.get("ZERO24_RELAY"), help="outbound relay URL (Cloud Shell mode, no inbound port)")
    a = ap.parse_args()
    agent = Agent(a.token, a.interval, relay=a.relay)
    threading.Thread(target=agent.supervisor, daemon=True).start()
    if agent.relay:
        threading.Thread(target=agent.relay_loop, daemon=True).start()
        print("[vps-agent] relay mode -> %s" % agent.relay)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        agent.stop = True
        return
    srv = ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(agent))
    print("[vps-agent] listening :%d token=%s..." % (a.port, a.token[:4]))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop = True


if __name__ == "__main__":
    main()
