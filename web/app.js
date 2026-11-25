/* AegisOps Incident Investigation Console — Stateless browser memory + location.hash */
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

  function escapeHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  function renderMarkdown(md) {
    let h = escapeHtml(md);
    h = h.replace(/`([^`]+)`/g, "<code>$1</code>");
    h = h.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    h = h.replace(/^### (.*)$/gm, "<h4 style='margin:4px 0 6px;color:#1e3a8a;'>$1</h4>");
    h = h.replace(/^- (.*)$/gm, "<div style='margin:4px 0;'>&bull; $1</div>");
    h = h.replace(/\n\n/g, "<br/>");
    return h;
  }

  function statusPalette(status) {
    if (status === "CRITICAL") return { fill: "#fef2f2", stroke: "#dc2626", badge: "#dc2626", text: "#991b1b" };
    if (status === "AMBER") return { fill: "#fffbeb", stroke: "#d97706", badge: "#d97706", text: "#92400e" };
    return { fill: "#ecfdf5", stroke: "#059669", badge: "#059669", text: "#065f46" };
  }

  function renderTopology(topo) {
    const svg = document.getElementById("topology-svg");
    const nodeMap = {};
    topo.nodes.forEach((n) => (nodeMap[n.id] = n));

    const W = 162;
    const H = 64;

    const edgesSvg = topo.edges
      .map((e) => {
        const a = nodeMap[e.from];
        const b = nodeMap[e.to];
        if (!a || !b) return "";
        const x1 = a.x + W / 2;
        const y1 = a.y + H / 2;
        const x2 = b.x + W / 2;
        const y2 = b.y + H / 2;
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2 - 6;
        const isHot = a.status === "CRITICAL" || b.status === "CRITICAL";
        return `
          <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${isHot ? "#dc2626" : "#94a3b8"}" stroke-width="${isHot ? 2.6 : 1.8}" stroke-dasharray="${isHot ? "5,3" : "none"}" />
          <text x="${mx}" y="${my}" text-anchor="middle" font-size="9.5" fill="#475569" font-weight="600">${escapeHtml(e.protocol)}</text>
        `;
      })
      .join("");

    const nodesSvg = topo.nodes
      .map((n) => {
        const pal = statusPalette(n.status);
        const isSel = n.id === state.selectedNodeId;
        return `
          <g class="topo-node-g" data-id="${n.id}" style="cursor:pointer;">
            <rect x="${n.x}" y="${n.y}" width="${W}" height="${H}" rx="10" fill="${pal.fill}" stroke="${pal.stroke}" stroke-width="${isSel ? 3.2 : 2}" />
            <circle cx="${n.x + 14}" cy="${n.y + 18}" r="5" fill="${pal.badge}" />
            <text x="${n.x + 25}" y="${n.y + 22}" font-size="11.5" font-weight="800" fill="#0f172a">${escapeHtml(n.label)}</text>
            <text x="${n.x + 14}" y="${n.y + 38}" font-size="10" fill="#475569">${escapeHtml(n.tier)}</text>
            <text x="${n.x + 14}" y="${n.y + 53}" font-size="10" font-weight="700" fill="${pal.text}">${escapeHtml(n.metric)}</text>
          </g>
        `;
      })
      .join("");

    svg.innerHTML = edgesSvg + nodesSvg;
    svg.querySelectorAll(".topo-node-g").forEach((g) => {
      g.addEventListener("click", () => {
        state.selectedNodeId = g.dataset.id;
        renderAll();
      });
    });

    const sel = nodeMap[state.selectedNodeId] || topo.nodes[0];
    document.getElementById("selected-node-bar").innerHTML = `
      <span><strong>Selected Node:</strong> <code>${sel.label}</code> (${sel.tier})</span>
      <span><strong>Health:</strong> ${sel.status} &middot; <strong>Signal:</strong> ${escapeHtml(sel.metric)} (${sel.latency_ms} ms)</span>
    `;
  }

  function renderMetricsChart(ms) {
    const svg = document.getElementById("metrics-svg");
    document.getElementById("deploy-marker-badge").textContent = ms.deploy_label;

    const vals = ms.p99_latency_ms;
    const labels = ms.timestamps;
    const maxV = Math.max(...vals, 500) * 1.12;
    const padL = 42, padR = 16, padT = 20, padB = 28;
    const plotW = 420 - padL - padR;
    const plotH = 190 - padT - padB;

    const pts = vals.map((v, i) => {
      const x = padL + (i / Math.max(vals.length - 1, 1)) * plotW;
      const y = padT + plotH - (v / maxV) * plotH;
      return { x, y, v, label: labels[i] };
    });

    const poly = pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
    const markerPt = pts[ms.deploy_marker_idx] || pts[2];

    svg.innerHTML = `
      <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="#cbd5e1" />
      <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" stroke="#cbd5e1" />
      <line x1="${markerPt.x}" y1="${padT}" x2="${markerPt.x}" y2="${padT + plotH}" stroke="#f59e0b" stroke-dasharray="4,3" stroke-width="1.5" />
      <text x="${markerPt.x + 4}" y="${padT + 11}" font-size="9.5" font-weight="700" fill="#b45309">${escapeHtml(ms.deploy_label)}</text>
      <polyline fill="none" stroke="#dc2626" stroke-width="2.5" points="${poly}" />
      ${pts
        .map(
          (p, idx) => `
        <circle cx="${p.x}" cy="${p.y}" r="3.5" fill="${p.v > 400 ? "#dc2626" : "#059669"}" />
        ${idx % 2 === 0 || idx === pts.length - 1 ? `<text x="${p.x}" y="${padT + plotH + 16}" text-anchor="middle" font-size="9" fill="#475569">${escapeHtml(p.label)}</text>` : ""}
      `
        )
        .join("")}
      <text x="${padL + 4}" y="${padT + 11}" font-size="9.5" fill="#64748b">p99 Latency (peak ${Math.max(...vals)} ms)</text>
    `;
  }

  function renderWaterfall(wf) {
    document.getElementById("trace-id-label").textContent = wf.trace_id;
    const total = Math.max(wf.total_ms, 1);
    document.getElementById("waterfall-list").innerHTML = wf.spans
      .map((sp) => {
        const leftPct = Math.min(92, (sp.start_ms / total) * 100);
        const widthPct = Math.max(4, Math.min(100 - leftPct, (sp.dur_ms / total) * 100));
        const color =
          sp.status.includes("CRITICAL") || sp.status.includes("ERROR")
            ? "#dc2626"
            : sp.status === "WARN"
            ? "#d97706"
            : "#10b981";
        return `
        <div class="wf-span-row">
          <div class="wf-span-top">
            <span><strong>${escapeHtml(sp.service)}</strong> &middot; ${escapeHtml(sp.op)}</span>
            <strong>${sp.dur_ms} ms</strong>
          </div>
          <div class="wf-track">
            <div class="wf-bar" style="left:${leftPct}%;width:${widthPct}%;background:${color};"></div>
          </div>
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
      pill.textContent = "RESOLVED · TOPOLOGY GREEN";
      pill.classList.add("resolved");
    } else {
      pill.textContent = `${inc.severity} ACTIVE · ${inc.root_node.toUpperCase()}`;
      pill.classList.remove("resolved");
    }

    document.getElementById("stat-inc-name").textContent = inc.short_label.replace(/^\d+\.\s*/, "");
    document.getElementById("stat-inc-meta").textContent = `${inc.region} · Suspect: ${inc.suspect_change}`;
    document.getElementById("stat-safety-gate").textContent = d.remediated ? "APPROVED & VERIFIED" : "HUMAN APPROVAL REQUIRED";

    renderTopology(d.topology);
    renderMetricsChart(d.metrics_series);
    renderWaterfall(d.trace_waterfall);

    // MCP Timeline
    document.getElementById("mcp-steps-grid").innerHTML = d.mcp_timeline
      .map(
        (m) => `
      <div class="mcp-card">
        <div class="mcp-head">
          <span>${m.step}. <code>${escapeHtml(m.tool)}</code></span>
          <span style="color:#059669;font-size:10.5px;">${m.mode} &middot; ${m.latency_ms}ms</span>
        </div>
        <div style="font-size:10.5px;color:#64748b;">Server: <code>${escapeHtml(m.server)}</code></div>
        <div class="mcp-finding">${escapeHtml(m.finding)}</div>
      </div>`
      )
      .join("");

    // Remediation Card
    const remCard = document.getElementById("remediation-card");
    remCard.classList.toggle("healed", d.remediated);
    document.getElementById("rem-action-title").textContent = `${inc.runbook_id}: ${inc.remediation_title}`;
    document.getElementById("rem-cli-box").textContent = `$ ${inc.remediation_cli}`;

    // Bedrock Written RCA
    document.getElementById("rca-engine-badge").textContent = d.rca.engine;
    document.getElementById("rca-meta-bar").innerHTML = `
      <span>Latency: ${d.rca.latency_ms} ms</span>
      <span>Runbook: ${escapeHtml(inc.runbook_id)}</span>
    `;
    document.getElementById("rca-markdown-box").innerHTML = renderMarkdown(d.rca.rca_markdown);

    // SRE Rubric
    const rub = d.rubric_evaluation;
    const dims = [
      ["Factuality (Trace & Metric Grounding)", rub.dimensions.factuality],
      ["Completeness (Causal Chain + Runbook)", rub.dimensions.completeness],
      ["Actionability (Safe Rollback Command)", rub.dimensions.actionability],
      ["Safety Gate Enforcement (0 Unapproved Writes)", rub.dimensions.safety_gate],
    ];
    document.getElementById("rubric-bars").innerHTML = dims
      .map(
        ([label, score]) => `
      <div class="rubric-row">
        <div class="rubric-top">
          <span>${label}</span>
          <strong>${Math.round(score * 100)}%</strong>
        </div>
        <div class="rubric-track">
          <div class="rubric-fill" style="width:${Math.round(score * 100)}%"></div>
        </div>
      </div>`
      )
      .join("");

    // Safety Audit Trail
    const auditEl = document.getElementById("audit-log-list");
    if (!d.safety_audit_log || d.safety_audit_log.length === 0) {
      auditEl.innerHTML = `<div style="color:#64748b;">No mutating MCP calls attempted yet. Try button #4 or #5 above!</div>`;
    } else {
      auditEl.innerHTML = d.safety_audit_log
        .map(
          (a) => `
        <div class="audit-item ${a.decision.includes("BLOCKED") ? "blocked" : "approved"}">
          <div style="display:flex;justify-content:space-between;font-weight:800;">
            <span>${escapeHtml(a.decision)}</span>
            <span>${escapeHtml(a.timestamp)}</span>
          </div>
          <div style="margin-top:3px;">${escapeHtml(a.detail)}</div>
        </div>`
        )
        .join("");
    }
  }

  async function selectIncident(incId, focusNode) {
    state.selectedNodeId = focusNode;
    window.location.hash = `#${incId}`;
    document.getElementById("rca-markdown-box").innerHTML =
      `<div style="color:#6d28d9;font-weight:600;">Executing 4 MCP read-only tools &amp; generating written RCA via Amazon Bedrock (<code>us.amazon.nova-lite-v1:0</code>)...</div>`;
    const res = await api("/api/investigate", "POST", { incident_id: incId, run_bedrock: true });
    state.data = res;
    document.getElementById("rem-feedback-banner").classList.add("hidden");
    renderAll();
  }

  async function attemptRemediation(approved) {
    const res = await api("/api/remediate", "POST", { approved });
    state.data = res.state;
    const banner = document.getElementById("rem-feedback-banner");
    banner.classList.remove("hidden", "blocked", "approved");
    if (res.blocked) {
      banner.classList.add("blocked");
      banner.textContent = "\u26D4 SAFETY_GATE_VIOLATION: Mutating rollback blocked 100% because no human SRE approval token was supplied.";
    } else {
      banner.classList.add("approved");
      banner.textContent = `\u2705 Rollback executed under token ${res.approval_token} — all 6 topology services verified HEALTHY!`;
    }
    renderAll();
  }

  function bindEvents() {
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

    // Modals
    const customModal = document.getElementById("custom-modal");
    document.getElementById("open-custom-btn").addEventListener("click", () => customModal.classList.remove("hidden"));
    document.getElementById("close-custom-btn").addEventListener("click", () => customModal.classList.add("hidden"));
    document.getElementById("custom-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      customModal.classList.add("hidden");
      const svc = document.getElementById("custom-service").value;
      const sig = document.getElementById("custom-sig").value;
      const sym = document.getElementById("custom-sym").value;
      state.selectedNodeId = svc;
      state.data = await api("/api/incidents/custom", "POST", {
        service_id: svc,
        error_signature: sig,
        metric_symptom: sym,
      });
      renderAll();
    });

    const archModal = document.getElementById("arch-modal");
    document.getElementById("open-arch-btn").addEventListener("click", () => archModal.classList.remove("hidden"));
    document.getElementById("close-arch-btn").addEventListener("click", () => archModal.classList.add("hidden"));
  }

  async function init() {
    bindEvents();
    state.data = await api("/api/state");
    renderAll();
  }

  init();
})();
