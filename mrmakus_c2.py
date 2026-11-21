# mrmakus_c2.py — [M] Main-machine controller for the VPS hunter agent
# Usage: python mrmakus_c2.py status | start | stop | once | add <url> | rm <url> | report | exec <cmd>

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

DEFAULT = os.environ.get("ZERO24_AGENT", "http://127.0.0.1:9099")
TOKEN = os.environ.get("ZERO24_TOKEN", "makus-local-token")
RELAY = None


def req(path, body=None):
    if RELAY:
        if path == "/status":
            url, data, method = RELAY + "/status", None, "GET"
        elif path == "/control":
            url, data, method = RELAY + "/enqueue", json.dumps(body or {}).encode(), "POST"
        else:
            url, data, method = RELAY + path, json.dumps(body or {}).encode() if body else None, "POST" if body else "GET"
    else:
        url = DEFAULT + path
        data = json.dumps(body).encode() if body is not None else None
        method = "POST" if data else "GET"
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"X-Zero24-Token": TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")
    except Exception as e:
        return json.dumps({"error": str(e)})


def main():
    global DEFAULT, TOKEN, RELAY
    ap = argparse.ArgumentParser(prog="mrmakus_c2.py", description="[M] VPS hunter controller")
    ap.add_argument("cmd", choices=["status", "start", "stop", "once", "add", "rm", "report", "exec"])
    ap.add_argument("value", nargs="*")
    ap.add_argument("--agent", default=DEFAULT)
    ap.add_argument("--token", default=TOKEN)
    ap.add_argument("--relay", default=os.environ.get("ZERO24_RELAY"), help="outbound relay URL")
    a = ap.parse_args()
    DEFAULT, TOKEN = a.agent.rstrip("/"), a.token
    RELAY = a.relay.rstrip("/") if a.relay else None

    if a.cmd == "status":
        print(req("/status"))
    elif a.cmd == "report":
        print(req("/report"))
    elif a.cmd == "once":
        print(req("/control", {"cmd": "add_target", "value": None}) if False else "")
        print(req("/control", {"cmd": "start"}))
        print("[c2] once mode: agent supervisor will run one cycle; use 'stop' after it finishes")
    elif a.cmd == "add":
        print(req("/control", {"cmd": "add_target", "value": " ".join(a.value)}))
    elif a.cmd == "rm":
        print(req("/control", {"cmd": "remove_target", "value": " ".join(a.value)}))
    elif a.cmd in ("start", "stop"):
        print(req("/control", {"cmd": a.cmd}))
    elif a.cmd == "exec":
        print(req("/control", {"cmd": "exec", "value": " ".join(a.value)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
