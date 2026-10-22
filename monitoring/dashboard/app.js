// ==============================================================================
// REDOPS // SECURITY OPERATIONS & CONTROL CENTER - FRONTEND ENGINE v6.0
// ==============================================================================

const API_BASE = window.location.origin;
// Token được backend inject vào <meta name="api-token"> khi serve index.html.
const API_TOKEN_META = document.querySelector('meta[name="api-token"]');
const API_AUTH_TOKEN = (API_TOKEN_META && API_TOKEN_META.content ? API_TOKEN_META.content : "").trim();

function getAuthHeaders() {
  return {
    "Content-Type": "application/json",
    "X-API-Token": API_AUTH_TOKEN
  };
}

async function authFetch(url, options = {}) {
  const opts = { ...options, headers: { ...(options.headers || {}), "X-API-Token": API_AUTH_TOKEN } };
  return fetch(url, opts);
}

// State management
let currentTab = "tab-overview";
let trafficChartInstance = null;
let networkTopologyInstance = null;
let visNodesDataSet = null;
let visEdgesDataSet = null;
let chartLabels = [];
let chartRxData = [];
let chartTxData = [];
const MAX_CHART_POINTS = 25;
let isC2Listening = false;
let isC2Connected = false;
let serverLocalIp = "127.0.0.1";
let serverGatewayIp = "";
let currentClientIp = "VICTIM";
let cachedFindings = [];
let cachedC2Sessions = [];
let currentC2Session = "";

// -----------------------------------------------------------------------------
// TOAST NOTIFICATION SYSTEM (Thay thế hoàn toàn alert)
// -----------------------------------------------------------------------------
function showToast(message, type = "info") {
  const container = document.getElementById("toastContainer");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  const icons = {
    success: "✅",
    error: "❌",
    warn: "⚠️",
    info: "ℹ️"
  };

  toast.innerHTML = `
    <span class="toast-icon">${icons[type] || "ℹ️"}</span>
    <span class="toast-msg">${message}</span>
  `;

  container.appendChild(toast);
  setTimeout(() => toast.classList.add("show"), 10);

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 350);
  }, 3500);
}

// -----------------------------------------------------------------------------
// INITIALIZATION
// -----------------------------------------------------------------------------
document.addEventListener("DOMContentLoaded", () => {
  initNavigation();
  initTrafficChart();
  initTopologyNetwork();
  
  // Start polling workers
  pollTelemetry();
  pollLogs();
  pollTopology();
  pollC2Status();
  pollJobs();
  pollFindings();

  setInterval(pollTelemetry, 1000);
  setInterval(pollLogs, 1500);
  setInterval(pollTopology, 5000);
  setInterval(pollC2Status, 2000);
  setInterval(pollJobs, 3000);
  setInterval(pollFindings, 4000);
});

// -----------------------------------------------------------------------------
// 1. NAVIGATION & TAB SWITCHING
// -----------------------------------------------------------------------------
function initNavigation() {
  const navButtons = document.querySelectorAll(".nav-btn");
  navButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetTab = btn.getAttribute("data-tab");
      if (targetTab) {
        switchTab(targetTab);
      }
    });
  });
}

function switchTab(tabId) {
  currentTab = tabId;
  
  document.querySelectorAll(".nav-btn").forEach(btn => {
    if (btn.getAttribute("data-tab") === tabId) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });

  document.querySelectorAll(".tab-pane").forEach(pane => {
    if (pane.id === tabId) {
      pane.classList.add("active");
    } else {
      pane.classList.remove("active");
    }
  });

  if (tabId === "tab-overview" && trafficChartInstance) {
    trafficChartInstance.resize();
  }
  if (tabId === "tab-topology") {
    setTimeout(refreshTopologyView, 150);
  }
}

// -----------------------------------------------------------------------------
// 2. REAL-TIME TELEMETRY & CHART.JS
// -----------------------------------------------------------------------------
function initTrafficChart() {
  const ctx = document.getElementById("trafficChart");
  if (!ctx || typeof Chart === "undefined") return;

  for (let i = 0; i < MAX_CHART_POINTS; i++) {
    chartLabels.push("");
    chartRxData.push(0);
    chartTxData.push(0);
  }

  trafficChartInstance = new Chart(ctx, {
    type: "line",
    data: {
      labels: chartLabels,
      datasets: [
        {
          label: "Inbound (RX MB/s)",
          data: chartRxData,
          borderColor: "#00f0ff",
          backgroundColor: "rgba(0, 240, 255, 0.12)",
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 0
        },
        {
          label: "Outbound (TX MB/s)",
          data: chartTxData,
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59, 130, 246, 0.08)",
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 0
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      scales: {
        x: {
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: { display: false }
        },
        y: {
          grid: { color: "rgba(255, 255, 255, 0.05)" },
          ticks: {
            color: "#94a3b8",
            font: { family: "'Consolas', monospace", size: 10 }
          },
          beginAtZero: true
        }
      },
      plugins: {
        legend: {
          position: "top",
          labels: {
            color: "#e2e8f0",
            font: { family: "'Segoe UI', sans-serif", size: 12 }
          }
        }
      }
    }
  });
}

async function pollTelemetry() {
  try {
    const res = await authFetch(`${API_BASE}/api/telemetry`);
    if (!res.ok) throw new Error("Offline");
    const data = await res.json();

    serverLocalIp = data.local_ip || "127.0.0.1";
    serverGatewayIp = data.gateway_ip || serverGatewayIp;
    setText("ipBadge", `IP: ${serverLocalIp}`);
    const mitmGw = document.getElementById("mitmGateway");
    if (mitmGw && !mitmGw.value && serverGatewayIp && serverGatewayIp !== "Unknown") mitmGw.value = serverGatewayIp;
    const arpGw = document.getElementById("arpKillGateway");
    if (arpGw && !arpGw.value && serverGatewayIp && serverGatewayIp !== "Unknown") arpGw.value = serverGatewayIp;
    setText("clock", data.timestamp || "00:00:00");
    setText("topPps", `${data.pps || 0} pps`);
    setText("topBandwidth", `${((data.rx_mb || 0) + (data.tx_mb || 0)).toFixed(2)} MB/s`);
    setText("topSys", `${data.cpu || 0}% / ${data.ram || 0}%`);
    setText("connStatus", `ONLINE: 8080 (${data.local_ip})`);

    const activeMods = data.active_modules || [];
    const activePill = document.getElementById("activeModBadge");
    const defconPill = document.getElementById("defconBadge");
    if (activePill) {
      if (activeMods.length > 0) {
        activePill.className = "pill pill-red";
        activePill.innerText = `RUNNING: ${activeMods.join(", ").toUpperCase()}`;
        if (defconPill) {
          defconPill.className = "pill pill-defcon pill-defcon-alert";
          defconPill.innerHTML = '<span class="dot-pulse"></span> DEFCON 1 // ENGAGED';
        }
      } else {
        activePill.className = "pill pill-yellow";
        activePill.innerText = "IDLE (READY)";
        if (defconPill) {
          defconPill.className = "pill pill-defcon";
          defconPill.innerHTML = '<span class="dot-pulse"></span> DEFCON 4 // NOMINAL';
        }
      }
    }

    setText("cardPps", data.pps || 0);
    setText("cardRx", data.rx_mb !== undefined ? data.rx_mb.toFixed(2) : "0.0");
    setText("cardTx", data.tx_mb !== undefined ? data.tx_mb.toFixed(2) : "0.0");

    const barPps = document.getElementById("barPps");
    if (barPps) barPps.style.width = `${Math.min(100, Math.max(5, (data.pps / 2000) * 100))}%`;

    const barRx = document.getElementById("barRx");
    if (barRx) barRx.style.width = `${Math.min(100, Math.max(5, (data.rx_mb / 20) * 100))}%`;

    const barTx = document.getElementById("barTx");
    if (barTx) barTx.style.width = `${Math.min(100, Math.max(5, (data.tx_mb / 20) * 100))}%`;

    if (trafficChartInstance) {
      chartRxData.push(data.rx_mb || 0);
      chartTxData.push(data.tx_mb || 0);
      chartLabels.push(data.timestamp || "");

      if (chartRxData.length > MAX_CHART_POINTS) {
        chartRxData.shift();
        chartTxData.shift();
        chartLabels.shift();
      }
      trafficChartInstance.update();
    }
  } catch (err) {}
}

// -----------------------------------------------------------------------------
// 3. TOPOLOGY & DEVICE RECON MANAGEMENT
// -----------------------------------------------------------------------------
let cachedTopologyNodes = [];

function initTopologyNetwork() {
  const container = document.getElementById("topologyNetwork");
  if (!container || typeof vis === "undefined") return;

  visNodesDataSet = new vis.DataSet([]);
  visEdgesDataSet = new vis.DataSet([]);

  const data = { nodes: visNodesDataSet, edges: visEdgesDataSet };
  const options = {
    autoResize: true,
    nodes: {
      shape: "dot",
      size: 24,
      font: { color: "#ffffff", face: "Consolas", size: 12 },
      borderWidth: 2,
      shadow: true
    },
    edges: {
      width: 1.5,
      color: { color: "rgba(56, 189, 248, 0.4)", highlight: "#00f0ff" },
      smooth: { type: "continuous" }
    },
    physics: {
      stabilization: { iterations: 120 },
      barnesHut: {
        gravitationalConstant: -12000,
        centralGravity: 0.15,
        springLength: 140,
        springConstant: 0.04,
        damping: 0.09,
        avoidOverlap: 0.3
      }
    },
    interaction: { hover: true, tooltipDelay: 100 }
  };

  networkTopologyInstance = new vis.Network(container, data, options);

  networkTopologyInstance.on("click", params => {
    if (params.nodes.length > 0) {
      const selectedId = params.nodes[0];
      selectTargetIp(selectedId);
    }
  });
}

function refreshTopologyView() {
  if (networkTopologyInstance) {
    networkTopologyInstance.setSize("100%", "560px");
    networkTopologyInstance.redraw();
    networkTopologyInstance.fit();
  }
}

function toggleReconView(viewMode) {
  const tableView = document.getElementById("reconTableView");
  const mapView = document.getElementById("reconMapView");
  const btnTable = document.getElementById("btnViewTable");
  const btnMap = document.getElementById("btnViewMap");

  if (viewMode === "table") {
    if (tableView) tableView.style.display = "block";
    if (mapView) mapView.style.display = "none";
    if (btnTable) btnTable.classList.add("active");
    if (btnMap) btnMap.classList.remove("active");
  } else {
    if (tableView) tableView.style.display = "none";
    if (mapView) mapView.style.display = "block";
    if (btnTable) btnTable.classList.remove("active");
    if (btnMap) btnMap.classList.add("active");
    setTimeout(refreshTopologyView, 120);
  }
}

function filterDeviceTable() {
  renderDeviceTable(cachedTopologyNodes);
}

function renderDeviceTable(nodes) {
  const tableBody = document.getElementById("deviceTableBody");
  if (!tableBody) return;

  if (!nodes || nodes.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#94a3b8; padding: 25px;">Chưa phát hiện thiết bị. Nhấn "Bắt Đầu Quét LAN" để dò tìm.</td></tr>`;
    return;
  }

  const query = (document.getElementById("deviceSearchInput")?.value || "").toLowerCase().trim();
  const filtered = query
    ? nodes.filter(n => {
        const ip = `${n.ip || n.id || ""} ${(Array.isArray(n.ipv6_addresses) ? n.ipv6_addresses.join(" ") : "")}`.toLowerCase();
        const mac = (n.mac || "").toLowerCase();
        const vendor = (n.vendor || "").toLowerCase();
        const host = (n.hostname || n.label || "").toLowerCase();
        const ports = String(n.ports || "").toLowerCase();
        return ip.includes(query) || mac.includes(query) || vendor.includes(query) || host.includes(query) || ports.includes(query);
      })
    : nodes;

  if (filtered.length === 0) {
    tableBody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#94a3b8; padding: 20px;">Không tìm thấy thiết bị nào khớp với từ khóa "${escapeHtml(query)}".</td></tr>`;
    return;
  }

  let html = "";
  filtered.forEach(n => {
    const ip = n.ip || n.id;
    const mac = n.mac || "Unknown";
    const vendor = n.vendor || "Unknown";
    const host = n.hostname || n.label || "N/A";
    const ports = n.ports && String(n.ports).trim() !== "None" ? n.ports : "";
    const v6list = Array.isArray(n.ipv6_addresses) ? n.ipv6_addresses : [];
    const v6shown = v6list.slice(0, 2).map(v => escapeHtml(v)).join(", ");
    const v6extra = v6list.length > 2 ? ` +${v6list.length - 2}` : "";
    const ipv6Html = v6shown
      ? `<div style="font-size:10px; color:#a78bfa; margin-top:3px; word-break:break-all;"><span style="color:#94a3b8;">IPv6:</span> ${v6shown}${v6extra}</div>`
      : "";
    const isGw = n.group === "gateway";
    const isSelf = n.group === "attacker";

    let badgeClass = "badge-ip";
    let roleText = "";
    if (isGw) {
      badgeClass = "badge-gw";
      roleText = " (GW)";
    } else if (isSelf) {
      badgeClass = "badge-self";
      roleText = " (THIS)";
    }

    let portsHtml = "";
    if (ports) {
      portsHtml = `<div style="font-size:11px; color:#38bdf8; margin-top:3px;"><span style="color:#94a3b8;">Cổng:</span> ${escapeHtml(ports)}</div>`;
    }

    html += `
      <tr>
        <td><span class="${badgeClass}">${ip}${roleText}</span>${ipv6Html}</td>
        <td><span class="mac-pill">${mac}</span></td>
        <td style="color:#e2e8f0; font-weight:500;">${escapeHtml(vendor)}</td>
        <td style="color:#ffffff;">${escapeHtml(host)}${portsHtml}</td>
        <td style="text-align:center;">
          <button class="btn btn-sm btn-cyan" onclick="selectTargetIp('${ip}')">🎯 Chọn</button>
        </td>
      </tr>
    `;
  });
  tableBody.innerHTML = html;
}

async function pollTopology() {
  try {
    const res = await authFetch(`${API_BASE}/api/topology`);
    if (!res.ok) return;
    const data = await res.json();
    const nodes = data.nodes || [];
    const links = data.links || [];

    cachedTopologyNodes = nodes;
    setText("topoDeviceCount", `${nodes.length} THIẾT BỊ`);

    // Update Vis Nodes & Edges
    if (visNodesDataSet && visEdgesDataSet && nodes.length > 0) {
      const newVisNodes = nodes.map(n => {
        let color = "#3b82f6";
        if (n.group === "gateway") color = "#00f0ff";
        else if (n.group === "attacker") color = "#ff2a5f";
        else if (n.type === "mobile") color = "#10b981";
        else if (n.type === "server") color = "#f59e0b";

        return {
          id: n.id || n.ip,
          label: `${n.hostname || n.vendor || n.ip}\n(${n.ip})`,
          color: { background: color, border: "#ffffff" }
        };
      });

      const newVisEdges = links.map(l => ({
        from: l.source,
        to: l.target
      }));

      visNodesDataSet.clear();
      visNodesDataSet.add(newVisNodes);
      visEdgesDataSet.clear();
      visEdgesDataSet.add(newVisEdges);
    }

    renderDeviceTable(cachedTopologyNodes);
  } catch (err) {}
}

function selectTargetIp(ip) {
  if (!ip) return;
  const isV6 = String(ip).includes(":");
  const l4Target = document.getElementById("l4Target");
  if (l4Target) l4Target.value = ip;

  const shareTarget = document.getElementById("shareHunterTarget");
  if (shareTarget) shareTarget.value = ip;

  // MITM/ARP hien chi ho tro IPv4; khong ghi IPv6 vao form de tranh job fail.
  const mitmTarget = document.getElementById("mitmTarget");
  if (mitmTarget) mitmTarget.value = isV6 ? "" : ip;

  const arpKillTarget = document.getElementById("arpKillTarget");
  if (arpKillTarget) arpKillTarget.value = isV6 ? "" : ip;

  showToast(isV6 ? `Đã chọn IPv6 ${ip} cho L4 Stress / Share Hunter` : `Đã chọn mục tiêu: ${ip} cho L4 Stress, Share Hunter & MITM`, "success");
}

// -----------------------------------------------------------------------------
// 4. ACTION CONTROLS (SCAN, L4, MITM, DEFENSE)
// -----------------------------------------------------------------------------
async function triggerScan() {
  const subnet = document.getElementById("scanSubnet")?.value.trim() || "AUTO";
  const mode = document.getElementById("scanMode")?.value || "2";
  const note = document.getElementById("scanNote")?.value.trim() || "";

  await postAction("scan", { subnet, mode, note });
  showToast(`Bắt đầu quét mạng LAN [Subnet: ${subnet}]`, "info");
}

async function startL4Stress() {
  const target = document.getElementById("l4Target")?.value.trim() || "ALL";
  const port = document.getElementById("l4Port")?.value.trim() || "80";
  const mode = document.getElementById("l4Mode")?.value || "BOTH";
  const threads = document.getElementById("l4Threads")?.value || "500";
  const duration = document.getElementById("l4Duration")?.value || "30";
  const note = document.getElementById("l4Note")?.value.trim() || "";

  await postAction("stress", { target, port, mode, threads, duration, note });
  showToast(`Kích hoạt L4 Flood [${mode}] -> ${target}:${port} (${threads} luồng)`, "warn");
}

async function startMitm() {
  const target = document.getElementById("mitmTarget")?.value.trim() || "ALL";
  const gateway = document.getElementById("mitmGateway")?.value.trim() || serverGatewayIp || "";
  const dnsSpoofer = (document.getElementById("mitmDns")?.value === "yes");
  const note = document.getElementById("mitmNote")?.value.trim() || "";

  await postAction("mitm", { target, gateway, dns_spoofer: dnsSpoofer, note });
  showToast(`Đã bật MITM Sniffer -> Mục tiêu: ${target} ${dnsSpoofer ? "[DNS SPOOFER: BẬT]" : ""}`, "warn");
}

async function startArpKill() {
  const target = document.getElementById("arpKillTarget")?.value.trim() || "ALL";
  const gateway = document.getElementById("arpKillGateway")?.value.trim() || serverGatewayIp || "";
  const note = document.getElementById("arpKillNote")?.value.trim() || "";

  await postAction("arp_kill", { target, gateway, note });
  showToast(`Kích hoạt DoS Cô Lập Mạng (Kill Net) -> ${target}`, "error");
}

async function triggerHardening() {
  const note = document.getElementById("defenseNote")?.value.trim() || "";
  await postAction("hardening", { note });
  showToast("Đang kích hoạt Windows Hardening & tường lửa...", "success");
}

async function startShareHunter() {
  const target = document.getElementById("shareHunterTarget")?.value.trim() || "ALL";
  const mode = document.getElementById("shareHunterMode")?.value || "quick";
  const note = document.getElementById("shareHunterNote")?.value.trim() || "";
  await postAction("share_hunter", { target, deep: mode === "deep", note });
  showToast(`Share Hunter -> ${target}${mode === "deep" ? " (deep audit)" : ""}`, "info");
}

async function stopModule(moduleName) {
  try {
    showToast(`Đang yêu cầu dừng ${moduleName}; chờ module phục hồi trạng thái mạng...`, "warn");
    const res = await authFetch(`${API_BASE}/api/action/stop`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ module: moduleName })
    });
    const data = await res.json();
    const results = data.results || [];
    if (results.length === 0) {
      showToast(`Không có tiến trình nào đang chạy cho: ${moduleName}`, "info");
    } else {
      const forced = results.filter(r => r.forced).length;
      showToast(
        forced ? `Đã dừng ${results.length} module, ${forced} bị kill sau timeout` : `Đã dừng sạch ${results.length} module`,
        forced ? "warn" : "success"
      );
    }
    pollJobs();
  } catch (err) {
    showToast(`Lỗi khi dừng module: ${err}`, "error");
  }
}

async function postAction(action, payload) {
  try {
    const res = await authFetch(`${API_BASE}/api/action/start`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ action, ...payload })
    });
    const data = await res.json();
    if (data.status === "error" || data.status === "busy") {
      showToast(data.message || "Action bị từ chối", "warn");
    }
    pollJobs();
    return data;
  } catch (err) {
    showToast(`Lỗi gửi lệnh: ${err}`, "error");
  }
}

// -----------------------------------------------------------------------------
// 5. C2 REMOTE REVERSE SHELL CONTROLLER (Port 4444)
// -----------------------------------------------------------------------------
async function pollC2Status() {
  try {
    const res = await authFetch(`${API_BASE}/api/c2/status`);
    if (!res.ok) return;
    const data = await res.json();

    isC2Listening = data.listening;
    isC2Connected = data.connected;
    cachedC2Sessions = data.sessions || [];
    currentC2Session = data.active_session || "";
    renderC2SessionSelect();

    // Cập nhật State Banner
    const stateEl = document.getElementById("c2ListenerState");
    const targetEl = document.getElementById("c2TargetHost");
    const toggleBtn = document.getElementById("btnToggleC2");
    const c2Badge = document.getElementById("c2ConnBadge");
    const cardC2 = document.getElementById("cardC2Status");
    const cardC2Sub = document.getElementById("cardC2Sub");

    if (isC2Listening) {
      if (isC2Connected) {
        currentClientIp = data.client_ip || "VICTIM";
        const isSelf = (data.client_ip === "127.0.0.1" || data.client_ip === serverLocalIp);
        if (isSelf) {
          stateEl.innerHTML = `<span class="dot dot-yellow"></span> KẾT NỐI (MÁY CỤC BỘ / LOCALHOST)`;
          targetEl.innerHTML = `<span style="color:var(--yellow); font-weight:bold;">${data.client_ip}:${data.client_port}</span> <span class="badge" style="background:var(--yellow); color:#000;">⚠️ LOCALHOST (MÁY HIỆN TẠI)</span>`;
        } else {
          stateEl.innerHTML = `<span class="dot dot-green"></span> KẾT NỐI (ACTIVE)`;
          targetEl.innerHTML = `<span style="color:var(--cyan); font-weight:bold;">${data.client_ip}:${data.client_port}</span> <span class="badge badge-success">ONLINE</span>`;
        }
        if (c2Badge) { c2Badge.innerText = isSelf ? "LOCAL" : "ONLINE"; c2Badge.style.background = isSelf ? "var(--yellow)" : "var(--green)"; }
        if (cardC2) cardC2.innerText = isSelf ? "LOCAL" : "ONLINE";
        if (cardC2Sub) cardC2Sub.innerText = data.client_ip;

        const promptEl = document.getElementById("c2PromptLabel");
        if (promptEl) promptEl.innerText = isSelf ? `C2@LOCAL-HOST>` : `C2@${data.client_ip}>`;
        const termTitle = document.getElementById("c2TermTitle");
        if (termTitle) {
          termTitle.innerText = isSelf 
            ? `⚠️ [CỤC BỘ / LOCALHOST] ${data.client_ip} (Lệnh sẽ thực thi trên máy của bạn)`
            : `victim@${data.client_ip}: ~ (Remote Execution Console)`;
        }
      } else {
        currentClientIp = "VICTIM";
        stateEl.innerHTML = `<span class="dot dot-yellow"></span> ĐANG LẮNG NGHE (PORT ${data.port})`;
        targetEl.innerHTML = `<span style="color:var(--text-dim);">Chờ agent trên máy mục tiêu kết nối...</span>`;
        if (c2Badge) { c2Badge.innerText = "LISTEN"; c2Badge.style.background = "var(--yellow)"; }
        if (cardC2) cardC2.innerText = "LISTEN";
        if (cardC2Sub) cardC2Sub.innerText = "Chờ kết nối";
        const promptEl = document.getElementById("c2PromptLabel");
        if (promptEl) promptEl.innerText = "C2@VICTIM>";
        const termTitle = document.getElementById("c2TermTitle");
        if (termTitle) termTitle.innerText = "victim@remote-shell: ~ (Remote Execution Console)";
      }
      if (toggleBtn) {
        toggleBtn.innerText = "⏹ Dừng C2 Listener";
        toggleBtn.className = "btn btn-danger";
      }
    } else {
      currentClientIp = "VICTIM";
      stateEl.innerHTML = `<span class="dot dot-red"></span> ĐANG DỪNG`;
      targetEl.innerText = "Chưa có kết nối nào";
      if (toggleBtn) {
        toggleBtn.innerText = "▶ Bật C2 Listener (Port 4444)";
        toggleBtn.className = "btn btn-primary";
      }
      if (c2Badge) { c2Badge.innerText = "OFF"; c2Badge.style.background = "var(--red)"; }
      if (cardC2) cardC2.innerText = "OFF";
      if (cardC2Sub) cardC2Sub.innerText = "Port 4444";
      const promptEl = document.getElementById("c2PromptLabel");
      if (promptEl) promptEl.innerText = "C2@VICTIM>";
      const termTitle = document.getElementById("c2TermTitle");
      if (termTitle) termTitle.innerText = "victim@remote-shell: ~ (Remote Execution Console)";
    }
  } catch (err) {}
}

async function toggleC2Listener() {
  const action = isC2Listening ? "stop" : "start";
  try {
    const res = await fetch(`${API_BASE}/api/c2/action`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ action })
    });
    const d = await res.json();
    showToast(d.message || "Thao tác C2 hoàn tất", d.status === "ok" ? "success" : "error");
    pollC2Status();
  } catch (err) {
    showToast(`Lỗi: ${err}`, "error");
  }
}

async function submitC2Command(e) {
  if (e) e.preventDefault();
  const input = document.getElementById("c2Input");
  if (!input) return;
  const cmd = input.value.trim();
  if (!cmd) return;

  const promptEl = document.getElementById("c2PromptLabel");
  const promptText = promptEl ? promptEl.innerText : "C2@VICTIM>";
  appendC2Line(`<div class="c2-term-cmd"><span class="prompt">${escapeHtml(promptText)}</span> ${escapeHtml(cmd)}</div>`);
  input.value = "";

  if (!isC2Connected) {
    appendC2Line(`<div class="c2-term-err">[-] Lỗi: Chưa có máy mục tiêu nào kết nối tới C2 Port 4444! Hãy khởi chạy agent trên máy mục tiêu trước.</div>`);
    return;
  }

  const pendingId = `cmdPending_${Date.now()}`;
  appendC2Line(`<div class="c2-term-system" id="${pendingId}">[...] Đang gửi lệnh mã hóa AES-GCM tới mục tiêu...</div>`);

  try {
    const res = await authFetch(`${API_BASE}/api/c2/exec`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ command: cmd, session_id: currentC2Session || undefined })
    });
    const d = await res.json();
    if (d.status !== "ok" || !d.job_id) {
      const pending = document.getElementById(pendingId);
      if (pending) pending.remove();
      appendC2Line(`<div class="c2-term-err">[-] ${escapeHtml(d.output || d.message || "Lỗi thực thi")}</div>`);
      return;
    }
    await pollC2Job(d.job_id, pendingId);
  } catch (err) {
    const pending = document.getElementById(pendingId);
    if (pending) pending.remove();
    appendC2Line(`<div class="c2-term-err">[-] Lỗi truyền tin: ${err}</div>`);
  }
}

async function pollC2Job(jobId, pendingId, startedAt = Date.now()) {
  const pending = document.getElementById(pendingId);
  const MAX_WAIT = 120000;
  while (Date.now() - startedAt < MAX_WAIT) {
    try {
      const res = await authFetch(`${API_BASE}/api/c2/job?id=${encodeURIComponent(jobId)}`);
      if (res.ok) {
        const job = await res.json();
        if (job.status !== "RUNNING") {
          if (pending) pending.remove();
          if (job.status === "COMPLETED") {
            appendC2Line(`<div class="c2-term-output">${escapeHtml(job.output)}</div>`);
          } else {
            appendC2Line(`<div class="c2-term-err">[-] ${escapeHtml(job.error || "Lỗi thực thi")}</div>`);
          }
          return;
        }
        if (pending) {
          const secs = Math.round((Date.now() - startedAt) / 1000);
          pending.textContent = `[...] Agent đang thực thi (${secs}s)...`;
        }
      }
    } catch (err) {}
    await new Promise(r => setTimeout(r, 700));
  }
  if (pending) pending.remove();
  appendC2Line(`<div class="c2-term-err">[-] Quá 120s không có kết quả. Kiểm tra agent hoặc hủy lệnh.</div>`);
}

function renderC2SessionSelect() {
  const select = document.getElementById("c2SessionSelect");
  if (!select) return;
  if (cachedC2Sessions.length === 0) {
    select.innerHTML = `<option value="">Chưa có agent</option>`;
    return;
  }
  select.innerHTML = cachedC2Sessions.map(s => {
    const label = s.hostname ? `${s.id} · ${s.hostname} (${s.client_ip})` : `${s.id} · ${s.client_ip}:${s.client_port}`;
    return `<option value="${s.id}" ${s.id === currentC2Session ? "selected" : ""}>${escapeHtml(label)} [${s.proto}]</option>`;
  }).join("");
}

async function selectC2Session(sessionId) {
  if (!sessionId) return;
  try {
    const res = await authFetch(`${API_BASE}/api/c2/action`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ action: "select", session_id: sessionId })
    });
    const d = await res.json();
    currentC2Session = sessionId;
    showToast(d.message || `Đã chọn ${sessionId}`, d.status === "ok" ? "success" : "error");
  } catch (err) {
    showToast(`Lỗi chọn session: ${err}`, "error");
  }
}

async function closeC2Session() {
  if (!currentC2Session) {
    showToast("Chưa có session nào để đóng", "warn");
    return;
  }
  try {
    const res = await authFetch(`${API_BASE}/api/c2/action`, {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ action: "close-session", session_id: currentC2Session })
    });
    const d = await res.json();
    showToast(d.message || "Đã đóng session", d.status === "ok" ? "success" : "error");
    pollC2Status();
  } catch (err) {
    showToast(`Lỗi đóng session: ${err}`, "error");
  }
}

function sendQuickCommand(cmd) {
  const input = document.getElementById("c2Input");
  if (input) {
    input.value = cmd;
    submitC2Command();
  }
}

function appendC2Line(html) {
  const screen = document.getElementById("c2TerminalScreen");
  if (!screen) return;
  screen.insertAdjacentHTML("beforeend", html);
  screen.scrollTop = screen.scrollHeight;
}

function clearC2Terminal() {
  const screen = document.getElementById("c2TerminalScreen");
  if (screen) {
    screen.innerHTML = `<div class="c2-term-line c2-term-system">[*] Màn hình điều khiển C2 đã được làm sạch.</div>`;
  }
}

// -----------------------------------------------------------------------------
// 6. LIVE CONSOLE & STREAMING LOGS ROUTING
// -----------------------------------------------------------------------------
let lastLogSignature = "";
async function pollLogs() {
  try {
    const res = await authFetch(`${API_BASE}/api/logs`);
    if (!res.ok) return;
    const logs = await res.json();
    if (!Array.isArray(logs) || logs.length === 0) return;

    const latest = logs[logs.length - 1];
    const currentSig = `${logs.length}_${latest.time}_${latest.msg}`;
    if (currentSig === lastLogSignature) return;
    lastLogSignature = currentSig;

    // 1. Render Main Console
    const term = document.getElementById("terminalOutput");
    if (term) {
      let html = "";
      logs.forEach(l => {
        let colorClass = "log-info";
        if (l.type === "succ") colorClass = "log-succ";
        else if (l.type === "warn") colorClass = "log-warn";
        else if (l.type === "err") colorClass = "log-err";
        else if (l.type === "cyan") colorClass = "log-cyan";
        html += `<div class="log-line ${colorClass}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
      });
      term.innerHTML = html;
      term.scrollTop = term.scrollHeight;
    }

    // 2. Route MITM in-tab logs
    const mitmTerm = document.getElementById("mitmTerminalOutput");
    if (mitmTerm) {
      const mitmLogs = logs.filter(l => l.msg.includes("[MITM]") || l.msg.toLowerCase().includes("mitm"));
      if (mitmLogs.length > 0) {
        let html = "";
        mitmLogs.slice(-30).forEach(l => {
          let c = l.type === "err" ? "log-err" : (l.type === "succ" ? "log-succ" : (l.type === "cyan" ? "log-cyan" : "log-warn"));
          html += `<div class="log-line ${c}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
        });
        mitmTerm.innerHTML = html;
        mitmTerm.scrollTop = mitmTerm.scrollHeight;
      }
    }

    // 3. Route L4 Stress in-tab logs
    const l4Term = document.getElementById("l4TerminalOutput");
    if (l4Term) {
      const l4Logs = logs.filter(l => l.msg.includes("[L4-STRESS]") || l.msg.toLowerCase().includes("flooder") || l.msg.toLowerCase().includes("l4"));
      if (l4Logs.length > 0) {
        let html = "";
        l4Logs.slice(-30).forEach(l => {
          let c = l.type === "err" ? "log-err" : (l.type === "succ" ? "log-succ" : "log-warn");
          html += `<div class="log-line ${c}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
        });
        l4Term.innerHTML = html;
        l4Term.scrollTop = l4Term.scrollHeight;
      }
    }

    // 4. Route Scan in-tab logs
    const scanTerm = document.getElementById("scanTerminalOutput");
    if (scanTerm) {
      const scanLogs = logs.filter(l => l.msg.includes("[SCAN]") || l.msg.toLowerCase().includes("quét"));
      if (scanLogs.length > 0) {
        let html = "";
        scanLogs.slice(-30).forEach(l => {
          let c = l.type === "succ" ? "log-succ" : (l.type === "err" ? "log-err" : "log-cyan");
          html += `<div class="log-line ${c}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
        });
        scanTerm.innerHTML = html;
        scanTerm.scrollTop = scanTerm.scrollHeight;
      }
    }

    // 5. Route Defense in-tab logs
    const defTerm = document.getElementById("defenseTerminalOutput");
    if (defTerm) {
      const defLogs = logs.filter(l => l.msg.includes("[DEFENSE]") || l.msg.toLowerCase().includes("bảo vệ") || l.msg.toLowerCase().includes("hardening") || l.msg.toLowerCase().includes("la chan"));
      if (defLogs.length > 0) {
        let html = "";
        defLogs.slice(-30).forEach(l => {
          let c = l.type === "succ" ? "log-succ" : (l.type === "err" ? "log-err" : "log-cyan");
          html += `<div class="log-line ${c}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
        });
        defTerm.innerHTML = html;
        defTerm.scrollTop = defTerm.scrollHeight;
      }
    }

    // 6. Route Share Hunter in-tab logs
    const shTerm = document.getElementById("shareHunterTerminalOutput");
    if (shTerm) {
      const shLogs = logs.filter(l => l.msg.includes("[SHARE-HUNTER]") || l.module === "Share Hunter");
      if (shLogs.length > 0) {
        let html = "";
        shLogs.slice(-30).forEach(l => {
          let c = l.type === "err" ? "log-err" : (l.type === "succ" ? "log-succ" : (l.type === "cyan" ? "log-cyan" : "log-warn"));
          html += `<div class="log-line ${c}">[${l.time}] ${escapeHtml(l.msg)}</div>`;
        });
        shTerm.innerHTML = html;
        shTerm.scrollTop = shTerm.scrollHeight;
      }
    }
  } catch (err) {}
}

function clearLogs() {
  const term = document.getElementById("terminalOutput");
  if (term) term.innerHTML = `<div class="log-line log-info">[${new Date().toLocaleTimeString()}] Console đã được làm sạch.</div>`;
}

// -----------------------------------------------------------------------------
// 7. MODULE JOBS (job control theo từng module)
// -----------------------------------------------------------------------------
async function pollJobs() {
  try {
    const res = await authFetch(`${API_BASE}/api/jobs`);
    if (!res.ok) return;
    const data = await res.json();
    renderJobs(data.jobs || []);
  } catch (err) {}
}

function formatDuration(job) {
  const started = job.started_at ? job.started_at * 1000 : null;
  if (!started) return "-";
  const end = job.ended_at ? job.ended_at * 1000 : Date.now();
  const secs = Math.max(0, Math.round((end - started) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}

function jobStatusClass(status) {
  const s = String(status || "").toUpperCase();
  if (s === "RUNNING" || s === "STARTING") return "pill-red";
  if (s === "STOPPING") return "pill-yellow";
  if (s === "COMPLETED") return "pill-green";
  if (s === "FAILED") return "pill-red";
  return "pill-cyan";
}

function renderJobs(jobs) {
  const body = document.getElementById("jobsTableBody");
  if (!body) return;

  const active = jobs.filter(j => ["RUNNING", "STARTING", "STOPPING"].includes(String(j.status).toUpperCase()));
  const badge = document.getElementById("jobsBadge");
  if (badge) badge.innerText = String(active.length);

  if (jobs.length === 0) {
    body.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#94a3b8; padding: 28px;">Chưa có job nào.</td></tr>`;
    return;
  }

  body.innerHTML = jobs.map(j => {
    const status = String(j.status || "?").toUpperCase();
    const stoppable = ["RUNNING", "STARTING", "STOPPING"].includes(status);
    const stopBtn = stoppable
      ? `<button class="btn btn-sm btn-secondary" onclick="stopModule('${escapeHtml(j.module)}')">⏹ Dừng</button>`
      : `<span style="color:#64748b;">—</span>`;
    const exitVal = j.exit_code === null || j.exit_code === undefined ? "-" : j.exit_code;
    return `
      <tr>
        <td><span class="badge-ip">${escapeHtml(j.job_id || "-")}</span></td>
        <td>${escapeHtml(j.label || j.module || "-")}</td>
        <td><span class="pill ${jobStatusClass(status)}" style="font-size:10px;">${status}</span></td>
        <td>${escapeHtml(j.target || "None")}</td>
        <td>${j.pid || "-"}</td>
        <td>${exitVal}</td>
        <td>${formatDuration(j)}</td>
        <td style="text-align:center;">${stopBtn}</td>
      </tr>`;
  }).join("");
}

// -----------------------------------------------------------------------------
// 8. FINDINGS (bảng kết quả có cấu trúc)
// -----------------------------------------------------------------------------
async function pollFindings() {
  try {
    const res = await authFetch(`${API_BASE}/api/findings`);
    if (!res.ok) return;
    const data = await res.json();
    cachedFindings = Array.isArray(data) ? data : [];
    const badge = document.getElementById("findingsBadge");
    if (badge) badge.innerText = String(cachedFindings.length);
    renderFindings();
  } catch (err) {}
}

function findingSeverityRank(sev) {
  const s = String(sev || "info").toLowerCase();
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s] !== undefined
    ? { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[s]
    : 5;
}

function renderFindings() {
  const body = document.getElementById("findingsTableBody");
  if (!body) return;

  const query = (document.getElementById("findingSearch")?.value || "").toLowerCase().trim();
  const sevFilter = (document.getElementById("findingSeverity")?.value || "").toLowerCase();

  const rows = cachedFindings.filter(f => {
    const sev = String(f.severity || "info").toLowerCase();
    if (sevFilter && sev !== sevFilter) return false;
    if (!query) return true;
    return [f.title, f.target, f.module, f.details].join(" ").toLowerCase().includes(query);
  });

  const countEl = document.getElementById("findingCount");
  if (countEl) countEl.innerText = `${rows.length} FINDING`;

  if (rows.length === 0) {
    body.innerHTML = `<tr><td colspan="5" style="text-align:center; color:#94a3b8; padding: 28px;">Không có finding nào khớp bộ lọc.</td></tr>`;
    return;
  }

  const sevClass = sev => {
    const s = String(sev).toLowerCase();
    if (s === "critical" || s === "high" || s === "crit") return "pill-red";
    if (s === "medium" || s === "med") return "pill-yellow";
    if (s === "low") return "pill-cyan";
    return "pill-green";
  };

  body.innerHTML = rows.slice().sort((a, b) => findingSeverityRank(a.severity) - findingSeverityRank(b.severity)).map(f => `
    <tr>
      <td>${escapeHtml(f.time || "-")}</td>
      <td><span class="pill ${sevClass(f.severity)}" style="font-size:10px;">${escapeHtml(String(f.severity || "info").toUpperCase())}</span></td>
      <td>${escapeHtml(f.module || "-")}</td>
      <td>${escapeHtml(f.target || "-")}</td>
      <td>
        <strong>${escapeHtml(f.title || "Finding")}</strong>
        ${f.details ? `<div style="font-size:11px; color:#94a3b8; margin-top:4px;">${escapeHtml(f.details)}</div>` : ""}
      </td>
    </tr>`).join("");
}

function exportFindings(format) {
  if (!cachedFindings.length) {
    showToast("Chưa có finding để export", "warn");
    return;
  }
  let content = "";
  let mime = "application/json";
  let filename = `findings_${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`;

  if (format === "csv") {
    const esc = v => `"${String(v === undefined || v === null ? "" : v).replace(/"/g, '""')}"`;
    const headers = ["time", "module", "target", "severity", "title", "details"];
    content = [headers.join(",")]
      .concat(cachedFindings.map(f => headers.map(h => esc(f[h])).join(",")))
      .join("\r\n");
    mime = "text/csv";
    filename += ".csv";
  } else {
    content = JSON.stringify(cachedFindings, null, 2);
    filename += ".json";
  }

  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast(`Đã export ${cachedFindings.length} finding (${format.toUpperCase()})`, "success");
}

// -----------------------------------------------------------------------------
// UTILITIES
// -----------------------------------------------------------------------------
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.innerText = val;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#033;");
}
