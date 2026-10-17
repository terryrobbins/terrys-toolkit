#!/usr/bin/env python3
"""Terry's Toolkit — zero-dependency web server (Python stdlib only).

    python3 server.py

Serves the web UI and a small JSON API that drives nmap. Binds to 0.0.0.0 by
default so other devices on your network (phone, laptop) can reach it at
http://<this-box-ip>:8777 . Scans are restricted to the authorized scope in
config.json, and the API requires the access token if one is set.
"""
import json
import mimetypes
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "web")

DEFAULT_CFG = {
    "bind_host": "0.0.0.0",
    "bind_port": 8777,
    "nmap_path": "nmap",
    "authorized_scopes": ["0.0.0.0/0"],  # set per mission from the UI
    "excluded": [],
    "access_token": "",          # empty = no token (LAN-only, trusted net)
    "max_concurrent_scans": 2,
    "scan_timeout_sec": 900,
}


def load_cfg():
    cfg = dict(DEFAULT_CFG)
    # config.json = shareable defaults (committed). config.local.json = secrets
    # like access_token (git-ignored), overlaid on top and never pushed.
    for name in ("config.json", "config.local.json"):
        path = os.path.join(HERE, name)
        if os.path.exists(path):
            try:
                cfg.update(json.load(open(path)))
            except Exception as e:  # noqa
                print(f"[warn] bad {name} ({e}); ignoring it")
    return cfg


CFG = load_cfg()


def save_cfg():
    """Persist the editable keys back to config.json so mission scope survives restarts."""
    path = os.path.join(HERE, "config.json")
    try:
        disk = json.load(open(path)) if os.path.exists(path) else {}
    except Exception:
        disk = {}
    disk.update({"authorized_scopes": CFG["authorized_scopes"], "excluded": CFG["excluded"]})
    tmp = path + ".tmp"
    json.dump(disk, open(tmp, "w"), indent=2)
    os.replace(tmp, path)


def valid_cidrs(items):
    """Return cleaned list of valid CIDR/IP strings, or raise ValueError."""
    import ipaddress
    out = []
    for raw in items:
        raw = raw.strip()
        if not raw:
            continue
        ipaddress.ip_network(raw, strict=False)  # raises on bad input
        out.append(raw)
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "TerrysToolkit"

    # ---- helpers ----
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        token = CFG.get("access_token", "")
        if not token:
            return True
        sent = self.headers.get("X-Access-Token", "")
        return secrets.compare_digest(sent, token)

    def _serve_static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        full = os.path.normpath(os.path.join(WEB, path.lstrip("/")))
        if not full.startswith(WEB) or not os.path.isfile(full):
            self.send_error(404)
            return
        ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
        data = open(full, "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ---- routes ----
    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/api/config":
            scopes = CFG["authorized_scopes"]
            return self._json(200, {
                "authorized_scopes": scopes,
                "excluded": CFG["excluded"],
                "auth_required": bool(CFG.get("access_token")),
                "wide_open": any(s.strip() in ("0.0.0.0/0", "::/0") for s in scopes),
            })
        if p.startswith("/api/scan/"):
            if not self._authed():
                return self._json(401, {"error": "bad or missing access token"})
            job = scanner.get_job(p.rsplit("/", 1)[-1])
            if not job:
                return self._json(404, {"error": "no such scan"})
            return self._json(200, job)
        return self._serve_static(p)

    def do_POST(self):
        p = urlparse(self.path).path
        if p not in ("/api/scan", "/api/scope"):
            return self.send_error(404)
        if not self._authed():
            return self._json(401, {"error": "bad or missing access token"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid request body"})

        if p == "/api/scope":
            try:
                scopes = valid_cidrs(body.get("scopes") or [])
                excluded = valid_cidrs(body.get("excluded") or [])
            except ValueError as e:
                return self._json(400, {"error": f"invalid CIDR: {e}"})
            if not scopes:
                return self._json(400, {"error": "scope cannot be empty"})
            CFG["authorized_scopes"], CFG["excluded"] = scopes, excluded
            try:
                save_cfg()
            except Exception as e:  # noqa
                return self._json(500, {"error": f"could not save: {e}"})
            return self._json(200, {"authorized_scopes": scopes, "excluded": excluded,
                                    "wide_open": any(s in ("0.0.0.0/0", "::/0") for s in scopes)})
        target = (body.get("target") or "").strip()
        opts = body.get("options") or {}
        if not target:
            return self._json(400, {"error": "no target given"})
        try:
            job = scanner.start_scan(target, opts, CFG)
        except scanner.ScopeError as e:
            return self._json(400, {"error": str(e)})
        return self._json(200, {"id": job["id"], "command": job["command"]})

    def log_message(self, fmt, *args):  # quieter logs
        print("%s - %s" % (self.address_string(), fmt % args))


def main():
    host, port = CFG["bind_host"], int(CFG["bind_port"])
    srv = ThreadingHTTPServer((host, port), Handler)
    tok = "ON" if CFG.get("access_token") else "OFF (open on LAN)"
    print(f"""
  Terry's Toolkit  ->  http://{host}:{port}
  reach it from another device at:  http://<this-box-ip>:{port}
  authorized scope : {', '.join(CFG['authorized_scopes']) or '(none!)'}
  access token     : {tok}
  (Ctrl-C to stop)
""")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
