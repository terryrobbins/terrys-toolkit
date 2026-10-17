"use strict";
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

const state = {
  tab: "scan",
  scan: "connect", ports: "top1000", portsCustom: "",
  sV: false, O: false, sC: false, Pn: false, A: false, timing: "4",
  vports: "top100", vportsCustom: "",
};
let authRequired = false;
let polling = null;
let etaTimer = null, etaRemaining = null;

// ---- scope + auth ----
function renderScope(c) {
  $("#scope-input").value = (c.authorized_scopes || []).join(", ");
  $("#exclude-input").value = (c.excluded || []).join(", ");
  const open = !!c.wide_open, st = $("#scope-state");
  $("#scopebar").classList.toggle("open", open);
  $("#notice").classList.toggle("open", open);
  st.classList.remove("open", "set"); st.classList.add(open ? "open" : "set");
  if (open) {
    st.textContent = "⚠ WIDE OPEN (0.0.0.0/0) — every target allowed. Set your mission's authorized CIDRs before scanning.";
    $("#notice").textContent = "⚠ Scope is wide open — this will scan anything you type. Only hit what you're authorized to.";
  } else {
    st.textContent = "✓ scoped — targets outside the list are refused";
    $("#notice").textContent = "⚠ Authorized use only. Targets outside the mission scope are refused.";
  }
}
function loadConfig() {
  fetch("api/config").then(r => r.json()).then(c => {
    renderScope(c);
    authRequired = !!c.auth_required;
    if (authRequired) {
      $("#tokwrap").hidden = false;
      const s = sessionStorage.getItem("ttk_token"); if (s) $("#token").value = s;
    }
  }).catch(() => { $("#scope-state").textContent = "server unreachable"; });
}
loadConfig();

const splitList = s => (s || "").split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
$("#scope-apply").onclick = async () => {
  const st = $("#scope-state"); st.className = "scope-state"; st.textContent = "saving…";
  try {
    const r = await fetch("api/scope", {
      method: "POST", headers: headers(),
      body: JSON.stringify({ scopes: splitList($("#scope-input").value),
                             excluded: splitList($("#exclude-input").value) }),
    });
    const d = await r.json();
    if (!r.ok) { st.textContent = "✖ " + d.error; return; }
    renderScope(d);
  } catch (e) { st.textContent = "✖ " + e; }
};

// ---- tabs ----
$$(".tab").forEach(t => t.onclick = () => {
  $$(".tab").forEach(x => x.classList.toggle("active", x === t));
  state.tab = t.dataset.tab;
  $("#panel-scan").hidden = state.tab !== "scan";
  $("#panel-vuln").hidden = state.tab !== "vuln";
  preview();
});

// ---- segmented buttons ----
$$(".seg").forEach(seg => {
  const opt = seg.dataset.opt;
  $$("button", seg).forEach(b => b.onclick = () => {
    $$("button", seg).forEach(x => x.classList.toggle("on", x === b));
    state[opt] = b.dataset.val;
    if (opt === "ports") $("#customports").hidden = b.dataset.val !== "custom";
    if (opt === "vports") $("#vcustomports").hidden = b.dataset.val !== "custom";
    preview();
  });
});
$("#ports-custom").oninput = e => { state.portsCustom = e.target.value; preview(); };
$("#vports-custom").oninput = e => { state.vportsCustom = e.target.value; preview(); };

// ---- switches ----
$$(".sw input").forEach(c => c.onchange = () => { state[c.dataset.opt] = c.checked; preview(); });
$("#target").oninput = preview;

// ---- build options the backend understands ----
function buildOptions() {
  if (state.tab === "vuln") {
    const p = state.vports === "custom" ? (state.vportsCustom || "top100") : state.vports;
    return { scan: "connect", sV: true, vuln: true, ports: p, timing: "4" };
  }
  const p = state.ports === "custom" ? (state.portsCustom || "top1000") : state.ports;
  return {
    scan: state.scan, ports: p, timing: state.timing,
    sV: state.sV, O: state.O, sC: state.sC, Pn: state.Pn, A: state.A,
  };
}

// ---- mirror the server's command builder, for the live preview ----
function previewCmd(target, o) {
  const c = ["nmap", "-v"];
  c.push({ ping: "-sn", connect: "-sT", syn: "-sS" }[o.scan] || "-sT");
  if (o.Pn) c.push("-Pn");
  if (o.scan !== "ping") {
    const p = o.ports || "top1000";
    if (p === "fast") c.push("-F");
    else if (p === "top100") c.push("--top-ports 100");
    else if (p === "all") c.push("-p-");
    else if (p !== "top1000" && /^[0-9,\-]+$/.test(p)) c.push("-p " + p);
    if (o.sV) c.push("-sV");
    if (o.O) c.push("-O");
    if (o.sC) c.push("-sC");
    if (o.A) c.push("-A");
    if (o.vuln) c.push("--script vuln");
  }
  if ("012345".includes(String(o.timing))) c.push("-T" + o.timing);
  c.push(target || "<target>");
  return c.join(" ");
}
function preview() {
  $("#cmdpreview").textContent = previewCmd($("#target").value.trim(), buildOptions());
}
preview();

// ---- run ----
$("#run").onclick = run;
$("#target").addEventListener("keydown", e => { if (e.key === "Enter") run(); });

function headers() {
  const h = { "Content-Type": "application/json" };
  if (authRequired) {
    const t = $("#token").value.trim();
    sessionStorage.setItem("ttk_token", t);
    h["X-Access-Token"] = t;
  }
  return h;
}
function setStatus(s, cls) { const el = $("#status"); el.textContent = s; el.className = "status " + cls; }

// ---- progress + countdown ----
function fmtEta(s) {
  s = Math.max(0, Math.round(s));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), ss = s % 60, p = n => String(n).padStart(2, "0");
  return h ? `${h}:${p(m)}:${p(ss)}` : `${m}:${p(ss)}`;
}
function showProgress(p) {
  $("#progress").hidden = false;
  if (p && p.percent != null) {
    $("#progbar").style.width = p.percent + "%";
    $("#progpct").textContent = Math.round(p.percent) + "%";
  }
  if (p && p.remaining_sec != null) {
    etaRemaining = p.remaining_sec;
    $("#countdown").textContent = etaRemaining > 0 ? fmtEta(etaRemaining) + " left" : "finishing…";
  }
}
function startEtaTick() {
  stopEtaTick();
  etaTimer = setInterval(() => {
    if (etaRemaining == null) return;
    etaRemaining = Math.max(0, etaRemaining - 1);
    $("#countdown").textContent = etaRemaining > 0 ? fmtEta(etaRemaining) + " left" : "finishing…";
  }, 1000);
}
function stopEtaTick() { if (etaTimer) { clearInterval(etaTimer); etaTimer = null; } }

async function run() {
  const target = $("#target").value.trim();
  if (!target) { $("#target").focus(); return; }
  if (polling) clearInterval(polling);
  $("#run").disabled = true;
  $("#console").textContent = "";
  $("#results").innerHTML = "";
  $("#progress").hidden = true;
  $("#progbar").style.width = "0%"; $("#progpct").textContent = "0%";
  etaRemaining = null; $("#countdown").textContent = "estimating…";
  setStatus("launching…", "running");
  try {
    const r = await fetch("api/scan", {
      method: "POST", headers: headers(),
      body: JSON.stringify({ target, options: buildOptions() }),
    });
    const d = await r.json();
    if (!r.ok) { setStatus("refused", "error"); $("#console").textContent = "✖ " + d.error; $("#run").disabled = false; return; }
    poll(d.id);
  } catch (e) {
    setStatus("error", "error"); $("#console").textContent = "✖ " + e; $("#run").disabled = false;
  }
}

function poll(id) {
  setStatus("running", "running");
  $("#progress").hidden = false;
  startEtaTick();
  const con = $("#console");
  polling = setInterval(async () => {
    let j;
    try { j = await (await fetch("api/scan/" + id, { headers: headers() })).json(); }
    catch { return; }
    con.textContent = (j.log || []).join("\n");
    con.scrollTop = con.scrollHeight;
    if (j.progress) showProgress(j.progress);
    if (j.status !== "running") {
      clearInterval(polling); polling = null;
      stopEtaTick();
      showProgress({ percent: 100 });
      $("#countdown").textContent = j.status === "done" ? "complete" : "stopped";
      $("#run").disabled = false;
      setStatus(j.status, j.status === "done" ? "done" : "error");
      render(j.hosts || []);
    }
  }, 1200);
}

// ---- render results ----
function render(hosts) {
  const box = $("#results");
  if (!hosts.length) { box.innerHTML = '<div class="card empty">no live hosts / open ports found</div>'; return; }
  box.innerHTML = "";
  for (const h of hosts) {
    const el = document.createElement("div");
    el.className = "host";
    const name = h.hostnames && h.hostnames.length ? ` (${h.hostnames.join(", ")})` : "";
    const meta = [h.os ? "OS: " + h.os : "", `${h.ports.length} port${h.ports.length === 1 ? "" : "s"}`]
      .filter(Boolean).join("  ·  ");
    let rows = h.ports.map(p => {
      const svc = [p.product, p.version].filter(Boolean).join(" ");
      const vulns = (p.scripts || []).filter(s => /vuln|cve/i.test(s.id) || /VULNERABLE|CVE-/.test(s.output));
      const vhtml = vulns.map(s => `<div class="vulnhit">${esc(s.id)}\n${esc(s.output.trim())}</div>`).join("");
      return `<tr><td class="port">${p.port}/${p.proto}</td>
        <td class="st-${p.state}">${p.state}</td>
        <td>${esc(p.service)}</td><td>${esc(svc)}${vhtml}</td></tr>`;
    }).join("");
    if (!rows) rows = `<tr><td colspan="4" class="empty">host up, no open ports in range</td></tr>`;
    el.innerHTML = `<h3>${esc(h.ip)}${esc(name)}</h3><div class="meta">${esc(meta)}</div>
      <table><thead><tr><th>PORT</th><th>STATE</th><th>SERVICE</th><th>DETAIL</th></tr></thead><tbody>${rows}</tbody></table>`;
    box.appendChild(el);
  }
}
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m])); }
