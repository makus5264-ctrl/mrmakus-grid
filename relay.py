# relay.py — [M] outbound-command relay for Cloud Shell / NAT execution nodes
# The agent calls OUT to this relay, so no inbound port is needed on the node.
# Usage: python relay.py --port 9100 --token SECRET

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

QUEUE = []
STATUS = {"state": "no agent"}
RESULT = []
LOCK = threading.Lock()


def make_handler(token):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, obj, code=200):
            b = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _auth(self):
            return self.headers.get("X-Zero24-Token") == token

        def do_GET(self):
            if not self._auth():
                return self._json({"error": "unauthorized"}, 401)
            if self.path == "/command":
                with LOCK:
                    job = QUEUE.pop(0) if QUEUE else None
                return self._json(job or {})
            if self.path == "/status":
                return self._json(STATUS)
            if self.path == "/result":
                return self._json(RESULT[-10:])
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
            global STATUS
            if self.path == "/enqueue":
                with LOCK:
                    QUEUE.append(body)
                return self._json({"queued": True, "depth": len(QUEUE)})
            if self.path == "/status":
                STATUS = dict(body)
                STATUS["seen_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                return self._json({"ok": True})
            if self.path == "/result":
                RESULT.append(body)
                return self._json({"ok": True})
            self._json({"error": "not found"}, 404)
    return H


def main():
    ap = argparse.ArgumentParser(prog="relay.py")
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--token", default="makus-local-token")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("0.0.0.0", a.port), make_handler(a.token))
    print("[relay] listening :%d" % a.port)
    srv.serve_forever()


if __name__ == "__main__":
    main()
