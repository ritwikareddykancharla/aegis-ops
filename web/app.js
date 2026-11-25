/* AegisOps 3:00 AM SRE War Room Controller — Stateless browser memory */
(() => {
  const state = {
    data: null,
    selectedNodeId: "checkout-svc",
  };

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

  function formatRca(md) {
    let h = esc(md);
    h = h.replace(/`([^`]+)`/g, "<code style='color:#2ee59d'>$1</code>");
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong style='color:#fff'>$1</strong>");
    h = h.replace(/^### (.*)$/gm, "<div style='color:#b18cff;font-weight:700;margin:4px 0 6px;'>$1</div>");
    h = h.replace(/^- (.*)$/gm, "<div style='margin:4px 0;'>&bull; $1</div>");
    h = h.replace(/\n\n/g, "<br>");
    return h;
  }

  function palette(status) {
    if (status === "CRITICAL") return { bg: "rgba(255,59,92,0.16)", stroke: "#ff3b5c", dot: "#ff3b5c", text: "#ff8fa2" };
    if (status === "AMBER") return { bg: "rgba(255,176,32,0.12)", stroke: "#ffb020", dot: "#ffb020", text: "#ffd17a" };
    return { bg: "rgba(46,229,157,0.10)", stroke: "#2ee59d", dot: "#2ee59d", text: "#2ee59d" };
  }

  function renderTopology(topo) {
    const svg = document.getElementById("topo-svg");
    const map = {};
    topo.nodes.forEach((n) => (map[n.id] = n));
    const W = 166;
    const H = 62;

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
          <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${hot ? "#ff3b5c" : "#3a4368"}" stroke-width="${hot ? 2.4 : 1.6}" ${hot ? 'stroke-dasharray="5,4"' : ""} />
          <text x="${mx}" y="${my}" text-anchor="middle" font-size="9.5" font-family="JetBrains Mono, monospace" fill="#8b93b0">${esc(e.protocol)}</text>
        `;
      })
      .join("");

    const nodes = topo.nodes
      .map((n) => {
        const p = palette(n.status);
        const sel = n.id === state.selectedNodeId;
        return `
          <g class="topo-node" data-id="${n.id}" style="cursor:pointer;">
            <rect x="${n.x}" y="${n.y}" width="${W}" height="${H}" rx="9" fill="${p.bg}" stroke="${sel ? "#ffffff" : p.stroke}" stroke-width="${sel ? 2.6 : 1.6}" />
            <circle cx="${n.x + 14}" cy="${n.y + 17}" r="4.5" fill="${p.dot}" />
            <text x="${n.x + 25}" y="${n.y + 21}" font-size="11.5" font-weight="700" fill="#eef1fa">${esc(n.label)}</text>
            <text x="${n.x + 14}" y="${n.y + 37}" font-size="9.5" font-family="JetBrains Mono, monospace" fill="#8b93b0">${esc(n.tier)}</text>
            <text x="${n.x + 14}" y="${n.y + 52}" font-size="10" font-weight="600" font-family="JetBrains Mono, monospace" fill="${p.text}">${esc(n.metric)}</text>
          </g>
        `;
      })
      .join("");

    svg.innerHTML = edges + nodes;
    svg.querySelectorAll(".topo-node").forEach((g) => {
      g.addEventListener("click", () => {
        state.selectedNodeId = g.dataset.id;
        renderWarRoom();
      });
    });

    const s = map[state.selectedNodeId] || topo.nodes[0];
    document.getElementById("node-inspect").innerHTML = `
      <span>NODE // <strong style="color:#fff">${esc(s.label)}</strong> (${esc(s.tier)})</span>
      <span>HEARTBEAT: <strong style="color:${palette(s.status).text}">${s.status}</strong> &middot; ${esc(s.metric)} (${s.latency_ms} ms)</span>
    `;
  }

  function renderMetrics(ms) {
    const svg = document.getElementById("metrics-svg");
    document.getElementById("deploy-tag").textContent = ms.deploy_label;
    const vals = ms.p99_latency_ms;
    const labels = ms.timestamps;
    const maxV = Math.max(...vals, 500) * 1.12;
    const padL = 40, padR = 14, padT = 18, padB = 26;
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
      <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="#242940" />
      <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" stroke="#242940" />
      <line x1="${mPt.x}" y1="${padT}" x2="${mPt.x}" y2="${padT + plotH}" stroke="#ffb020" stroke-dasharray="4,3" stroke-width="1.5" />
      <text x="${mPt.x + 4}" y="${padT + 11}" font-size="9" font-family="JetBrains Mono, monospace" fill="#ffb020">${esc(ms.deploy_label)}</text>
      <polyline fill="none" stroke="#ff3b5c" stroke-width="2.4" points="${poly}" />
      ${pts
        .map(
          (p, i) => `
        <circle cx="${p.x}" cy="${p.y}" r="3.4" fill="${p.v > 400 ? "#ff3b5c" : "#2ee59d"}" />
        ${i % 2 === 0 || i === pts.length - 1 ? `<text x="${p.x}" y="${padT + plotH + 16}" text-anchor="middle" font-size="8.5" font-family="JetBrains Mono, monospace" fill="#8b93b0">${esc(p.label)}</text>` : ""}
      `
        )
        .join("")}
      <text x="${padL + 4}" y="${padT + 11}" font-size="9" font-family="JetBrains Mono, monospace" fill="#8b93b0">Peak ${Math.max(...vals)} ms</text>
    `;
  }

  function renderWaterfall(wf) {
    document.getElementById("trace-id-lbl").textContent = wf.trace_id;
    const total = Math.max(wf.total_ms, 1);
    document.getElementById("waterfall-list").innerHTML = wf.spans
      .map((sp) => {
        const left = Math.min(92, (sp.start_ms / total) * 100);
        const width = Math.max(4, Math.min(100 - left, (sp.dur_ms / total) * 100));
        const col =
          sp.status.includes("CRITICAL") || sp.status.includes("ERROR")
            ? "#ff3b5c"
            : sp.status === "WARN"
            ? "#ffb020"
            : "#2ee59d";
        return `
        <div class="span-row">
          <div class="span-head"><span><strong>${esc(sp.service)}</strong> &middot; ${esc(sp.op)}</span><strong>${sp.dur_ms}ms</strong></div>
          <div class="span-track"><div class="span-bar" style="left:${left}%;width:${width}%;background:${col};"></div></div>
        </div>`;
      })
      .join("");
  }

  function renderWarRoom() {
    const d = state.data;
    if (!d) return;
    const inc = d.incident;
    const appRoot = document.getElementById("app-root");

    appRoot.classList.toggle("is-paging", !d.remediated);
    appRoot.classList.toggle("is-healed", Boolean(d.remediated));

    document.getElementById("page-ticker").textContent = d.remediated
      ? `INCIDENT RESOLVED // ALL 6 HEARTBEATS GREEN`
      : `ACTIVE PAGE // ${inc.severity} · ${inc.root_node.toUpperCase()}`;

    document.getElementById("suspect-meta").textContent = `${inc.region} · Suspect: ${inc.suspect_change}`;

    document.querySelectorAll(".inc-pill").forEach((b) => {
      b.classList.toggle("active", b.dataset.inc === d.active_incident_id);
    });

    // Ordered MCP Probe Checklist
    document.getElementById("probe-list").innerHTML = d.mcp_timeline
      .map(
        (m) => `
      <li class="probe-item">
        <span class="probe-chip">0${m.step}</span>
        <div>
          <div class="probe-top"><span>${esc(m.tool)}</span><span style="color:#2ee59d;">${m.latency_ms}ms</span></div>
          <div class="probe-srv">${esc(m.server)}</div>
          <p class="probe-find">${esc(m.finding)}</p>
        </div>
      </li>`
      )
      .join("");

    // Calibrated SRE Rubric
    const rub = d.rubric_evaluation;
    const dims = [
      ["Factuality (Trace + Metric Grounding)", rub.dimensions.factuality],
      ["Completeness (Causal Chain + Runbook)", rub.dimensions.completeness],
      ["Actionability (Safe Rollback Spec)", rub.dimensions.actionability],
      ["Safety Gate (0 Unapproved Mutations)", rub.dimensions.safety_gate],
    ];
    document.getElementById("rubric-bars").innerHTML = dims
      .map(
        ([lbl, sc]) => `
      <div class="rubric-item">
        <div class="rubric-lbl"><span>${lbl}</span><strong>${Math.round(sc * 100)}%</strong></div>
        <div class="rubric-track"><div class="rubric-fill" style="width:${Math.round(sc * 100)}%"></div></div>
      </div>`
      )
      .join("");

    renderTopology(d.topology);
    renderMetrics(d.metrics_series);
    renderWaterfall(d.trace_waterfall);

    // Two-Key Rollback Panel
    document.getElementById("rem-title").textContent = `${inc.runbook_id}: ${inc.remediation_title}`;
    document.getElementById("rem-cmd").textContent = `$ ${inc.remediation_cli}`;
    const armed = document.getElementById("two-key-checkbox").checked;
    document.getElementById("gate-state-lbl").textContent = d.remediated ? "HEALED" : armed ? "KEY 1 ARMED" : "LOCKED";

    // Bedrock Nova Written RCA
    document.getElementById("rca-engine-tag").textContent = d.rca.engine;
    document.getElementById("rca-meta").innerHTML = `<span>Latency: ${d.rca.latency_ms} ms</span><span>SOP: ${esc(inc.runbook_id)}</span>`;
    document.getElementById("rca-card").innerHTML = formatRca(d.rca.rca_markdown);

    // Safety Audit Log
    const auditEl = document.getElementById("audit-log");
    if (!d.safety_audit_log || d.safety_audit_log.length === 0) {
      auditEl.innerHTML = `<div class="dim">No mutating MCP calls attempted yet. Arm Key 1 or test an unapproved write above.</div>`;
    } else {
      auditEl.innerHTML = d.safety_audit_log
        .map(
          (a) => `
        <div class="audit-row ${a.decision.includes("BLOCKED") ? "blocked" : "approved"}">
          <div style="display:flex;justify-content:space-between;font-weight:700;">
            <span>${esc(a.decision)}</span><span class="dim">${esc(a.timestamp)}</span>
          </div>
          <div class="dim" style="margin-top:2px;">${esc(a.detail)}</div>
        </div>`
        )
        .join("");
    }
  }

  async function selectIncident(incId, node) {
    state.selectedNodeId = node;
    document.getElementById("two-key-checkbox").checked = false;
    document.getElementById("gate-banner").classList.add("hidden");
    document.getElementById("rca-card").innerHTML =
      `<span style="color:#b18cff;">// Running 4 MCP read-only probes &amp; synthesizing written RCA via us.amazon.nova-lite-v1:0...</span>`;
    state.data = await api("/api/investigate", "POST", { incident_id: incId, run_bedrock: true });
    renderWarRoom();
  }

  async function attemptRemediation(approved) {
    const res = await api("/api/remediate", "POST", { approved });
    state.data = res.state;
    const banner = document.getElementById("gate-banner");
    banner.classList.remove("hidden", "blocked", "approved");
    if (res.blocked) {
      banner.classList.add("blocked");
      banner.textContent = "SAFETY_GATE_VIOLATION: Mutating rollback blocked 100% — Key 1 SRE Sign-Off was not armed.";
    } else {
      banner.classList.add("approved");
      banner.textContent = `EXECUTED (${res.approval_token}): Safe rollback complete — all 6 heartbeats GREEN.`;
    }
    renderWarRoom();
  }

  function bind() {
    document.querySelectorAll(".inc-pill").forEach((b) => {
      b.addEventListener("click", () => selectIncident(b.dataset.inc, b.dataset.node));
    });

    const keyCheckbox = document.getElementById("two-key-checkbox");
    keyCheckbox.addEventListener("change", () => renderWarRoom());

    document.getElementById("exec-rollback-btn").addEventListener("click", () => {
      attemptRemediation(keyCheckbox.checked);
    });

    document.getElementById("unapproved-btn").addEventListener("click", () => {
      keyCheckbox.checked = false;
      attemptRemediation(false);
    });

    document.getElementById("rerun-rca-btn").addEventListener("click", () => {
      if (state.data) selectIncident(state.data.active_incident_id, state.selectedNodeId);
    });

    document.getElementById("reset-btn").addEventListener("click", async () => {
      keyCheckbox.checked = false;
      document.getElementById("gate-banner").classList.add("hidden");
      state.data = await api("/api/reset", "POST", {});
      renderWarRoom();
    });

    const customForm = document.getElementById("custom-form");
    document.getElementById("custom-toggle-btn").addEventListener("click", () => customForm.classList.toggle("hidden"));
    customForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      customForm.classList.add("hidden");
      const svc = document.getElementById("custom-service").value;
      state.selectedNodeId = svc;
      keyCheckbox.checked = false;
      state.data = await api("/api/incidents/custom", "POST", {
        service_id: svc,
        error_signature: document.getElementById("custom-sig").value,
        metric_symptom: document.getElementById("custom-sym").value,
      });
      renderWarRoom();
    });
  }

  async function init() {
    bind();
    state.data = await api("/api/state");
    renderWarRoom();
  }

  init();
})();
