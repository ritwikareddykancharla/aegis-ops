/* AegisOps Blueprint UI Controller — Stateless browser memory + URL hash (zero web storage) */
(() => {
  const root = document.documentElement;
  const state = {
    data: null,
    selectedNodeId: "checkout-svc",
  };

  /* Theme toggle without web storage */
  const themeBtn = document.querySelector(".theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const next = root.dataset.theme === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      history.replaceState(null, "", `#theme=${next}`);
    });
  }

  /* Reading progress bar */
  function updateReadingProgress() {
    const body = document.querySelector(".post-body");
    const fill = document.getElementById("side-bar-fill");
    const pct = document.getElementById("side-pct");
    if (!body || !fill || !pct) return;
    const r = body.getBoundingClientRect();
    const p = Math.min(1, Math.max(0, (window.innerHeight * 0.45 - r.top) / Math.max(r.height, 1)));
    fill.style.transform = `scaleX(${p})`;
    pct.textContent = `${Math.round(p * 100)}%`;
  }
  window.addEventListener("scroll", updateReadingProgress, { passive: true });

  async function api(path, method = "GET", body = null) {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (body !== null) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderMd(md) {
    let h = esc(md);
    h = h.replace(/`([^`]+)`/g, "<code>$1</code>");
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    h = h.replace(/^### (.*)$/gm, "<strong style='display:block;margin:6px 0;font-family:var(--display);color:var(--ink);'>$1</strong>");
    h = h.replace(/^- (.*)$/gm, "<div style='margin:4px 0;'>&bull; $1</div>");
    h = h.replace(/\n\n/g, "<br>");
    return h;
  }

  function statusColors(st) {
    if (st === "CRITICAL") return { fill: "var(--signal-soft)", stroke: "var(--bad)", dot: "var(--bad)", txt: "var(--bad)" };
    if (st === "AMBER") return { fill: "var(--paper)", stroke: "var(--warn)", dot: "var(--warn)", txt: "var(--warn)" };
    return { fill: "var(--card)", stroke: "var(--ok)", dot: "var(--ok)", txt: "var(--ok)" };
  }

  function renderTopology(topo) {
    const svg = document.getElementById("topology-svg");
    const map = {};
    topo.nodes.forEach((n) => (map[n.id] = n));
    const W = 166;
    const H = 64;

    const edges = topo.edges
      .map((e) => {
        const a = map[e.from];
        const b = map[e.to];
        if (!a || !b) return "";
        const x1 = a.x + W / 2;
        const y1 = a.y + H / 2;
        const x2 = b.x + W / 2;
        const y2 = b.y + H / 2;
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2 - 6;
        const hot = a.status === "CRITICAL" || b.status === "CRITICAL";
        return `
          <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${hot ? "var(--bad)" : "var(--cobalt)"}" stroke-width="${hot ? 2.4 : 1.5}" ${hot ? 'stroke-dasharray="5,4"' : ""} />
          <text x="${mx}" y="${my}" text-anchor="middle" font-size="9" font-family="var(--mono)" fill="var(--soft)">${esc(e.protocol)}</text>
        `;
      })
      .join("");

    const nodes = topo.nodes
      .map((n) => {
        const c = statusColors(n.status);
        const sel = n.id === state.selectedNodeId;
        return `
          <g class="topo-node" data-id="${n.id}" style="cursor:pointer;">
            <rect x="${n.x}" y="${n.y}" width="${W}" height="${H}" fill="${c.fill}" stroke="${sel ? "var(--ink)" : c.stroke}" stroke-width="${sel ? 3 : 1.8}" />
            <rect x="${n.x + 10}" y="${n.y + 12}" width="8" height="8" fill="${c.dot}" />
            <text x="${n.x + 24}" y="${n.y + 20}" font-size="11.5" font-weight="800" font-family="var(--display)" fill="var(--ink)">${esc(n.label)}</text>
            <text x="${n.x + 10}" y="${n.y + 37}" font-size="9.5" font-family="var(--mono)" fill="var(--soft)">${esc(n.tier)}</text>
            <text x="${n.x + 10}" y="${n.y + 53}" font-size="9.5" font-weight="500" font-family="var(--mono)" fill="${c.txt}">${esc(n.metric)}</text>
          </g>
        `;
      })
      .join("");

    svg.innerHTML = edges + nodes;
    svg.querySelectorAll(".topo-node").forEach((g) => {
      g.addEventListener("click", () => {
        state.selectedNodeId = g.dataset.id;
        renderAll();
      });
    });

    const s = map[state.selectedNodeId] || topo.nodes[0];
    document.getElementById("selected-node-bar").innerHTML = `
      <span>Selected: <strong>${esc(s.label)}</strong> (${esc(s.tier)})</span>
      <span>State: <strong>${s.status}</strong> &middot; ${esc(s.metric)} (${s.latency_ms} ms)</span>
    `;
  }

  function renderMetrics(ms) {
    const svg = document.getElementById("metrics-svg");
    document.getElementById("deploy-marker-badge").textContent = ms.deploy_label;
    const vals = ms.p99_latency_ms;
    const labels = ms.timestamps;
    const maxV = Math.max(...vals, 500) * 1.12;
    const padL = 42, padR = 14, padT = 18, padB = 26;
    const plotW = 420 - padL - padR;
    const plotH = 185 - padT - padB;

    const pts = vals.map((v, i) => ({
      x: padL + (i / Math.max(vals.length - 1, 1)) * plotW,
      y: padT + plotH - (v / maxV) * plotH,
      v,
      label: labels[i],
    }));

    const poly = pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
    const mPt = pts[ms.deploy_marker_idx] || pts[2];

    svg.innerHTML = `
      <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="var(--rule)" />
      <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" stroke="var(--rule)" />
      <line x1="${mPt.x}" y1="${padT}" x2="${mPt.x}" y2="${padT + plotH}" stroke="var(--signal)" stroke-dasharray="4,4" stroke-width="1.6" />
      <text x="${mPt.x + 5}" y="${padT + 11}" font-size="9" font-family="var(--mono)" fill="var(--signal)">${esc(ms.deploy_label)}</text>
      <polyline fill="none" stroke="var(--cobalt)" stroke-width="2.6" points="${poly}" />
      ${pts
        .map(
          (p, i) => `
        <rect x="${p.x - 3}" y="${p.y - 3}" width="6" height="6" fill="${p.v > 400 ? "var(--bad)" : "var(--ok)"}" />
        ${i % 2 === 0 || i === pts.length - 1 ? `<text x="${p.x}" y="${padT + plotH + 16}" text-anchor="middle" font-size="8.5" font-family="var(--mono)" fill="var(--soft)">${esc(p.label)}</text>` : ""}
      `
        )
        .join("")}
      <text x="${padL + 4}" y="${padT + 11}" font-size="9" font-family="var(--mono)" fill="var(--soft)">Peak ${Math.max(...vals)} ms</text>
    `;
  }

  function renderWaterfall(wf) {
    document.getElementById("trace-id-label").textContent = wf.trace_id;
    const total = Math.max(wf.total_ms, 1);
    document.getElementById("waterfall-list").innerHTML = wf.spans
      .map((sp) => {
        const left = Math.min(92, (sp.start_ms / total) * 100);
        const width = Math.max(4, Math.min(100 - left, (sp.dur_ms / total) * 100));
        const col =
          sp.status.includes("CRITICAL") || sp.status.includes("ERROR")
            ? "var(--bad)"
            : sp.status === "WARN"
            ? "var(--signal)"
            : "var(--ok)";
        return `
        <div class="wf-span">
          <div class="wf-span-h"><span><strong>${esc(sp.service)}</strong> &middot; ${esc(sp.op)}</span><strong>${sp.dur_ms}ms</strong></div>
          <div class="wf-track"><div class="wf-fill" style="left:${left}%;width:${width}%;background:${col};"></div></div>
        </div>`;
      })
      .join("");
  }

  function renderAll() {
    const d = state.data;
    if (!d) return;
    const inc = d.incident;

    const pill = document.getElementById("header-incident-pill");
    if (d.remediated) {
      pill.textContent = "RESOLVED · ALL 6 SERVICES HEALTHY";
      pill.className = "st-tag ok";
    } else {
      pill.textContent = `${inc.severity} ACTIVE · ${inc.root_node.toUpperCase()}`;
      pill.className = "st-tag bad";
    }

    document.getElementById("stat-inc-name").textContent = inc.short_label.replace(/^\d+\.\s*/, "");
    document.getElementById("stat-inc-meta").textContent = `${inc.region} · Suspect: ${inc.suspect_change}`;
    document.getElementById("stat-safety-gate").textContent = d.remediated ? "APPROVED & EXECUTED" : "HUMAN TOKEN REQUIRED";

    renderTopology(d.topology);
    renderMetrics(d.metrics_series);
    renderWaterfall(d.trace_waterfall);

    document.getElementById("mcp-steps-grid").innerHTML = d.mcp_timeline
      .map(
        (m) => `
      <div class="mcp-box">
        <div class="mcp-top"><span>0${m.step} <code>${esc(m.tool)}</code></span><span style="color:var(--ok);">${m.mode} &middot; ${m.latency_ms}ms</span></div>
        <div style="font:400 9.5px var(--mono);color:var(--soft);">MCP: ${esc(m.server)}</div>
        <p>${esc(m.finding)}</p>
      </div>`
      )
      .join("");

    const remCard = document.getElementById("remediation-card");
    remCard.classList.toggle("healed", d.remediated);
    document.getElementById("rem-action-title").textContent = `${inc.runbook_id}: ${inc.remediation_title}`;
    document.getElementById("rem-cli-box").textContent = `$ ${inc.remediation_cli}`;

    document.getElementById("rca-engine-badge").textContent = d.rca.engine;
    document.getElementById("rca-meta-bar").innerHTML = `<span>Latency: ${d.rca.latency_ms} ms</span><span>Runbook: ${esc(inc.runbook_id)}</span>`;
    document.getElementById("rca-markdown-box").innerHTML = renderMd(d.rca.rca_markdown);

    const rub = d.rubric_evaluation;
    const dims = [
      ["Factuality (Trace + Metric Citations)", rub.dimensions.factuality],
      ["Completeness (Causal Chain + Runbook)", rub.dimensions.completeness],
      ["Actionability (Rollback Precision)", rub.dimensions.actionability],
      ["Safety Gate (0 Unapproved Mutations)", rub.dimensions.safety_gate],
    ];
    document.getElementById("rubric-bars").innerHTML = dims
      .map(
        ([lbl, sc]) => `
      <div class="rubric-row">
        <div class="rubric-lbl"><span>${lbl}</span><strong>${Math.round(sc * 100)}%</strong></div>
        <div class="rubric-track"><div class="rubric-fill" style="width:${Math.round(sc * 100)}%"></div></div>
      </div>`
      )
      .join("");

    const auditEl = document.getElementById("audit-log-list");
    if (!d.safety_audit_log || d.safety_audit_log.length === 0) {
      auditEl.innerHTML = `<div style="font:400 10.5px var(--mono);color:var(--soft);">No mutating MCP calls attempted yet. Try Guided Workflow #4 or #5.</div>`;
    } else {
      auditEl.innerHTML = d.safety_audit_log
        .map(
          (a) => `
        <div class="audit-entry ${a.decision.includes("BLOCKED") ? "blocked" : "approved"}">
          <div style="display:flex;justify-content:space-between;font-weight:500;color:var(--ink);">
            <span>${esc(a.decision)}</span><span>${esc(a.timestamp)}</span>
          </div>
          <div style="color:var(--body);margin-top:3px;">${esc(a.detail)}</div>
        </div>`
        )
        .join("");
    }
  }

  async function selectIncident(incId, node) {
    state.selectedNodeId = node;
    document.getElementById("rca-markdown-box").innerHTML =
      `Executing 4 ordered read-only MCP tools &amp; generating written RCA via <code>us.amazon.nova-lite-v1:0</code>...`;
    const res = await api("/api/investigate", "POST", { incident_id: incId, run_bedrock: true });
    state.data = res;
    document.getElementById("rem-feedback-banner").classList.add("hidden");
    renderAll();
  }

  async function attemptRemediation(approved) {
    const res = await api("/api/remediate", "POST", { approved });
    state.data = res.state;
    const msg = document.getElementById("rem-feedback-banner");
    msg.classList.remove("hidden", "blocked", "approved");
    if (res.blocked) {
      msg.classList.add("blocked");
      msg.textContent = "SAFETY_GATE_VIOLATION: Mutating rollback rejected (100% blocked without human SRE token).";
    } else {
      msg.classList.add("approved");
      msg.textContent = `APPROVED (${res.approval_token}): Rollback executed; all 6 topology services verified HEALTHY.`;
    }
    renderAll();
  }

  function bind() {
    document.getElementById("wf-inc1").addEventListener("click", () => selectIncident("inc_checkout_pool", "checkout-svc"));
    document.getElementById("wf-inc2").addEventListener("click", () => selectIncident("inc_ddb_hot_partition", "dynamodb-orders"));
    document.getElementById("wf-inc3").addEventListener("click", () => selectIncident("inc_dc_chiller_drift", "rack-pdu-ctrl"));
    document.getElementById("wf-test-block").addEventListener("click", () => attemptRemediation(false));
    document.getElementById("wf-approve-fix").addEventListener("click", () => attemptRemediation(true));

    document.getElementById("btn-approve-rollback").addEventListener("click", () => attemptRemediation(true));
    document.getElementById("btn-unapproved-attempt").addEventListener("click", () => attemptRemediation(false));
    document.getElementById("regen-bedrock-btn").addEventListener("click", () => {
      if (state.data) selectIncident(state.data.active_incident_id, state.selectedNodeId);
    });

    document.getElementById("reset-demo-btn").addEventListener("click", async () => {
      state.data = await api("/api/reset", "POST", {});
      document.getElementById("rem-feedback-banner").classList.add("hidden");
      renderAll();
    });

    const drawer = document.getElementById("custom-drawer");
    document.getElementById("toggle-custom-btn").addEventListener("click", () => drawer.classList.toggle("hidden"));
    drawer.addEventListener("submit", async (e) => {
      e.preventDefault();
      drawer.classList.add("hidden");
      const svc = document.getElementById("custom-service").value;
      state.selectedNodeId = svc;
      state.data = await api("/api/incidents/custom", "POST", {
        service_id: svc,
        error_signature: document.getElementById("custom-sig").value,
        metric_symptom: document.getElementById("custom-sym").value,
      });
      renderAll();
    });
  }

  async function init() {
    bind();
    state.data = await api("/api/state");
    renderAll();
    updateReadingProgress();
  }

  init();
})();
