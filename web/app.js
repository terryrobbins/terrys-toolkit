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

// ---- init: scope + auth ----
fetch("api/config").then(r => r.json()).then(c => {
  $("#scope").textContent = (c.authorized_scopes || []).join("  ·  ") || "(none configured!)";
  if (c.excluded && c.excluded.length)
    $("#scope").textContent += "   ✕ " + c.excluded.join(", ");
  authRequired = !!c.auth_required;
  if (authRequired) {
    $("#tokwrap").hidden = false;
    const saved = sessionStorage.getItem("ttk_token");
    if (saved) $("#token").value = saved;
  }
}).catch(() => { $("#scope").textContent = "server unreachable"; });

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

async function run() {
  const target = $("#target").value.trim();
  if (!target) { $("#target").focus(); return; }
  if (polling) clearInterval(polling);
  $("#run").disabled = true;
  $("#console").textContent = "";
  $("#results").innerHTML = "";
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
  const con = $("#console");
  polling = setInterval(async () => {
    let j;
    try { j = await (await fetch("api/scan/" + id, { headers: headers() })).json(); }
    catch { return; }
    con.textContent = (j.log || []).join("\n");
    con.scrollTop = con.scrollHeight;
    if (j.status !== "running") {
      clearInterval(polling); polling = null;
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
