"""Terry's Toolkit — scan engine: scope guard, nmap command builder, job runner."""
import ipaddress
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ET

# ---------------------------------------------------------------- scope guard
class ScopeError(Exception):
    pass

_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")  # IP, CIDR, or hostname chars only


def _nets(items):
    out = []
    for i in items:
        try:
            out.append(ipaddress.ip_network(i, strict=False))
        except ValueError:
            pass
    return out


def _resolve(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        try:
            return ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return None


def check_scope(target, authorized, excluded):
    """Return (ok, reason). Enforces that target is inside an authorized range
    and not in an excluded one. target may be an IP, a CIDR, or a hostname."""
    target = (target or "").strip()
    if not target or not _TARGET_RE.match(target):
        return False, "target contains invalid characters"
    allow, excl = _nets(authorized), _nets(excluded)
    if not allow:
        return False, "no authorized scope configured (edit config.json)"
    # CIDR / range target
    try:
        net = ipaddress.ip_network(target, strict=False)
        if any(net.overlaps(e) for e in excl):
            return False, f"{target} overlaps an excluded range"
        if any(net.version == a.version and net.subnet_of(a) for a in allow):
            return True, "in scope"
        return False, f"{target} is outside the authorized scope"
    except ValueError:
        pass
    # single IP or hostname
    ip = _resolve(target)
    if ip is None:
        return False, f"could not resolve '{target}'"
    if any(ip in e for e in excl):
        return False, f"{ip} is in an excluded range"
    if any(ip in a for a in allow):
        return True, "in scope"
    return False, f"{ip} is outside the authorized scope"


# ---------------------------------------------------------- command builder
_PORTS_RE = re.compile(r"^[0-9,\-]+$")

# A fixed allow-list of options → nmap flags. Nothing the client sends is passed
# to the shell; we only ever emit flags from this map, so there's no injection.
def build_command(target, opts, nmap_path="nmap"):
    o = opts or {}
    cmd = [nmap_path, "-v"]

    scan = o.get("scan", "connect")
    cmd += {"ping": ["-sn"], "connect": ["-sT"], "syn": ["-sS"]}.get(scan, ["-sT"])
    if o.get("Pn"):
        cmd.append("-Pn")

    if scan != "ping":
        ports = (o.get("ports") or "top1000")
        if ports == "fast":
            cmd.append("-F")
        elif ports == "top100":
            cmd += ["--top-ports", "100"]
        elif ports == "all":
            cmd.append("-p-")
        elif ports == "top1000":
            pass  # nmap default
        elif _PORTS_RE.match(ports):
            cmd += ["-p", ports]
        # service / os / scripts
        if o.get("sV"):
            cmd.append("-sV")
        if o.get("O"):
            cmd.append("-O")
        if o.get("sC"):
            cmd.append("-sC")
        if o.get("A"):
            cmd.append("-A")
        if o.get("vuln"):
            cmd += ["--script", "vuln"]

    timing = str(o.get("timing", 4))
    if timing in list("012345"):
        cmd.append(f"-T{timing}")

    xmlf = tempfile.NamedTemporaryFile(prefix="ttk-", suffix=".xml", delete=False)
    xmlf.close()
    cmd += ["-oX", xmlf.name, "--"]
    # split target on whitespace so a subnet + a couple hosts can be given
    cmd += [t for t in target.split() if t]
    return cmd, xmlf.name


# ------------------------------------------------------------- XML parsing
def parse_xml(path):
    hosts = []
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return hosts
    for h in root.findall("host"):
        if (h.find("status") is not None) and h.find("status").get("state") == "down":
            continue
        addr = ""
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
        names = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        ports = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            svc = p.find("service")
            scripts = [{"id": s.get("id"), "output": s.get("output", "")}
                       for s in p.findall("script")]
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "state": st.get("state") if st is not None else "",
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "scripts": scripts,
            })
        osmatch = ""
        om = h.find("os/osmatch")
        if om is not None:
            osmatch = om.get("name", "")
        hosts.append({"ip": addr, "hostnames": names, "os": osmatch,
                      "ports": sorted(ports, key=lambda x: x["port"])})
    return hosts


# --------------------------------------------------------------- job runner
JOBS = {}
_LOCK = threading.Lock()


def active_count():
    with _LOCK:
        return sum(1 for j in JOBS.values() if j["status"] == "running")


def start_scan(target, opts, cfg):
    ok, reason = check_scope(target, cfg.get("authorized_scopes", []), cfg.get("excluded", []))
    if not ok:
        raise ScopeError(reason)
    if active_count() >= cfg.get("max_concurrent_scans", 2):
        raise ScopeError("too many scans already running — wait for one to finish")
    cmd, xmlpath = build_command(target, opts, cfg.get("nmap_path", "nmap"))
    jid = uuid.uuid4().hex[:12]
    job = {"id": jid, "target": target, "command": " ".join(cmd),
           "status": "running", "log": [], "hosts": [],
           "started": time.time(), "finished": None}
    with _LOCK:
        JOBS[jid] = job
    t = threading.Thread(target=_run, args=(job, cmd, xmlpath, cfg), daemon=True)
    t.start()
    return job


def _run(job, cmd, xmlpath, cfg):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1)
        start = time.time()
        for line in p.stdout:
            job["log"].append(line.rstrip("\n"))
            if len(job["log"]) > 2000:
                job["log"] = job["log"][-2000:]
            if time.time() - start > cfg.get("scan_timeout_sec", 900):
                p.kill()
                job["log"].append("[timeout] scan exceeded limit, killed")
                break
        p.wait()
        job["hosts"] = parse_xml(xmlpath)
        job["status"] = "done" if p.returncode == 0 else "error"
    except FileNotFoundError:
        job["status"] = "error"
        job["log"].append("[error] nmap not found — is it installed and on PATH?")
    except Exception as e:  # noqa
        job["status"] = "error"
        job["log"].append(f"[error] {e}")
    finally:
        job["finished"] = time.time()
        try:
            os.unlink(xmlpath)
        except OSError:
            pass


def get_job(jid):
    with _LOCK:
        return JOBS.get(jid)
