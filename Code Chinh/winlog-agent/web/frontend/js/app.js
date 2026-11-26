/**
 * WinLog SOC - Frontend Application Controller
 * Handles Theme Switching (Light/Dark), Realtime SSE Stream / Mock Mode,
 * Editable Admin Profile, Interactive SVG Charts, and Detail Inspector.
 */

(function () {
  "use strict";

  // Application State
  const State = {
    theme: localStorage.getItem("winlog_theme") || "light",
    isMock: false,
    liveOnly: true,
    sound: true,
    activeView: "overview",
    seq: -1,
    events: [],
    analyses: [],
    agents: [],
    terminal: [],
    totals: { events: 0, alerts: 0, analyses: 0 },
    timeline: [],
    distribution: null,
    drawerItem: null,
    autoScrollTerminal: true,
    adminProfile: {
      name: localStorage.getItem("winlog_admin_name") || "Admin SOC",
      role: localStorage.getItem("winlog_admin_role") || "SecOps Lead"
    }
  };

  const $ = selector => document.querySelector(selector);
  const $$ = selector => Array.from(document.querySelectorAll(selector));

  const escapeHtml = str => String(str ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));

  // Toast Notification System
  function showToast(message, type = "info") {
    const container = $("#toastContainer");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast-item ${type}`;

    let iconSvg = "";
    if (type === "success") {
      iconSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#10b981" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    } else if (type === "alert") {
      iconSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#ef4444" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>`;
    } else {
      iconSvg = `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#2563eb" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
    }

    toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(20px)";
      toast.style.transition = "all 0.25s ease-out";
      setTimeout(() => toast.remove(), 260);
    }, 3200);
  }

  // Date/Time formatting helpers
  const formatTime = iso => {
    const d = new Date(iso);
    return isNaN(d) ? escapeHtml(iso) : d.toLocaleString("vi-VN", {
      hour12: false, day: "2-digit", month: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit"
    });
  };

  const formatShortTime = iso => {
    const d = new Date(iso);
    return isNaN(d) ? "--:--" : d.toLocaleTimeString("vi-VN", { hour12: false, hour: "2-digit", minute: "2-digit" });
  };

  const timeAgo = iso => {
    const sec = Math.max(0, Math.floor((Date.now() - new Date(iso)) / 1000));
    if (sec < 5) return "Vừa xong";
    if (sec < 60) return `${sec}s trước`;
    if (sec < 3600) return `${Math.floor(sec / 60)} phút trước`;
    if (sec < 86400) return `${Math.floor(sec / 3600)} giờ trước`;
    return `${Math.floor(sec / 86400)} ngày trước`;
  };

  // -------------------------------------------------------------------------
  // 1. Theme Management (Light / Dark)
  // -------------------------------------------------------------------------
  function applyTheme(theme) {
    State.theme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("winlog_theme", theme);

    const themeBtn = $("#themeToggleBtn");
    if (themeBtn) {
      themeBtn.innerHTML = theme === "dark"
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`
        : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
      themeBtn.title = theme === "dark" ? "Chuyển sang giao diện Sáng" : "Chuyển sang giao diện Tối";
    }

    renderCharts();
  }

  // -------------------------------------------------------------------------
  // 2. Admin Profile Management (Editable)
  // -------------------------------------------------------------------------
  function getInitials(name) {
    if (!name) return "AD";
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  function updateAdminUI(name, role) {
    State.adminProfile.name = name;
    State.adminProfile.role = role;

    if ($("#adminName")) $("#adminName").textContent = name;
    if ($("#adminRole")) $("#adminRole").textContent = role;
    if ($("#adminAvatar")) $("#adminAvatar").textContent = getInitials(name);
  }

  function openProfileModal() {
    const modal = $("#profileModalBackdrop");
    if (!modal) return;
    $("#inputAdminName").value = State.adminProfile.name;
    $("#inputAdminRole").value = State.adminProfile.role;
    modal.classList.add("active");
    $("#inputAdminName").focus();
  }

  function closeProfileModal() {
    const modal = $("#profileModalBackdrop");
    if (modal) modal.classList.remove("active");
  }

  function saveProfileModal() {
    const name = $("#inputAdminName").value.trim() || "Admin SOC";
    const role = $("#inputAdminRole").value.trim() || "SecOps Lead";

    localStorage.setItem("winlog_admin_name", name);
    localStorage.setItem("winlog_admin_role", role);

    updateAdminUI(name, role);
    closeProfileModal();
    showToast(`Đã lưu hồ sơ quản trị: ${name} (${role})`, "success");
  }

  // -------------------------------------------------------------------------
  // 3. Navigation & View Switcher
  // -------------------------------------------------------------------------
  function showView(viewName) {
    State.activeView = viewName;
    $$(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === viewName));
    $$(".tab-view").forEach(el => el.classList.toggle("active", el.id === `view-${viewName}`));

    const titles = {
      overview: "Security Operations Center",
      alerts: "Security Alerts & Incident Management",
      events: "Windows Event Logs Explorer",
      agents: "Monitored Endpoints & Agent Inventory",
      terminal: "Server Real-time Execution Logs"
    };
    if ($("#headerTitle")) $("#headerTitle").textContent = titles[viewName] || "SOC Dashboard";

    renderCurrentView();
  }

  // -------------------------------------------------------------------------
  // 4. Interactive SVG Charts (DealDeck Inspired)
  // -------------------------------------------------------------------------

  /**
   * Concentric Multi-Ring Arc Gauge (like DealDeck Product Statistic)
   */
  function renderConcentricRings(container, stats) {
    if (!container) return;
    const total = stats ? stats.totalEvents : (State.isMock ? 9829 : (State.totals.events || State.events.length || 0));
    const w = 220, h = 180, cx = w / 2, cy = h / 2 + 10;

    let c4688 = 0, c4104 = 0, c4624 = 0;
    if (State.isMock) {
      c4688 = 2487;
      c4104 = 1828;
      c4624 = 1463;
    } else {
      State.events.forEach(e => {
        const id = Number(e.event_id);
        if (id === 4688) c4688++;
        else if (id === 4104 || id === 4103) c4104++;
        else if (id === 4624 || id === 4625) c4624++;
      });
      // Nếu tổng bằng 0 hoặc chưa có sự kiện
      if (total === 0 && !State.events.length) {
        c4688 = 0; c4104 = 0; c4624 = 0;
      }
    }

    // Update bottom breakdown rows to always match
    if ($("#catStat4688")) $("#catStat4688").textContent = c4688.toLocaleString();
    if ($("#catStat4104")) $("#catStat4104").textContent = c4104.toLocaleString();
    if ($("#catStat4624")) $("#catStat4624").textContent = c4624.toLocaleString();

    const isDark = State.theme === "dark";
    const denom = Math.max(1, total);
    const pct1 = Math.min(1, Math.max(0.08, c4688 ? c4688 / denom * 2.2 : 0.05));
    const pct2 = Math.min(1, Math.max(0.08, c4104 ? c4104 / denom * 2.2 : 0.05));
    const pct3 = Math.min(1, Math.max(0.08, c4624 ? c4624 / denom * 2.2 : 0.05));

    const rings = [
      { r: 76, width: 8, pct: State.isMock ? 0.88 : pct1, color: "#2563eb", bg: isDark ? "#1e293b" : "#edf2f7" },
      { r: 60, width: 8, pct: State.isMock ? 0.65 : pct2, color: "#ef4444", bg: isDark ? "#1e293b" : "#edf2f7" },
      { r: 44, width: 8, pct: State.isMock ? 0.42 : pct3, color: isDark ? "#475569" : "#cbd5e1", bg: isDark ? "#1e293b" : "#edf2f7" }
    ];

    const startAngle = (140 * Math.PI) / 180;
    const totalArc = (260 * Math.PI) / 180;

    let svg = `<svg viewBox="0 0 ${w} ${h}" width="100%" height="100%">`;

    rings.forEach(ring => {
      const bgEndAngle = startAngle + totalArc;
      const actEndAngle = startAngle + totalArc * ring.pct;

      const p = (ang, rad) => [cx + rad * Math.cos(ang), cy + rad * Math.sin(ang)];

      const [bgX1, bgY1] = p(startAngle, ring.r);
      const [bgX2, bgY2] = p(bgEndAngle, ring.r);
      svg += `<path d="M ${bgX1} ${bgY1} A ${ring.r} ${ring.r} 0 1 1 ${bgX2} ${bgY2}" 
                    fill="none" stroke="${ring.bg}" stroke-width="${ring.width}" stroke-linecap="round"/>`;

      const [actX1, actY1] = p(startAngle, ring.r);
      const [actX2, actY2] = p(actEndAngle, ring.r);
      const largeArcFlag = totalArc * ring.pct > Math.PI ? 1 : 0;
      svg += `<path d="M ${actX1} ${actY1} A ${ring.r} ${ring.r} 0 ${largeArcFlag} 1 ${actX2} ${actY2}" 
                    fill="none" stroke="${ring.color}" stroke-width="${ring.width}" stroke-linecap="round"/>`;
    });

    svg += `</svg>`;

    container.innerHTML = `
      <div class="ring-chart-wrap">
        ${svg}
        <div class="ring-chart-center">
          <div class="ring-center-value">${total.toLocaleString()}</div>
          <div class="ring-center-label">Sự kiện thu thập</div>
        </div>
      </div>
    `;
  }

  /**
   * Dual Bar Chart with Tooltips (like DealDeck Customer Habbits)
   */
  function renderDualBarChart(container, timelineData) {
    if (!container) return;
    const data = timelineData && timelineData.length ? timelineData : [
      { label: "00:00", normal: 0, attack: 0 },
      { label: "04:00", normal: 0, attack: 0 },
      { label: "08:00", normal: 0, attack: 0 },
      { label: "12:00", normal: 0, attack: 0 },
      { label: "16:00", normal: 0, attack: 0 },
      { label: "20:00", normal: 0, attack: 0 }
    ];

    const w = 700, h = 230, padLeft = 40, padBottom = 30, padTop = 15, padRight = 15;
    const chartW = w - padLeft - padRight;
    const chartH = h - padTop - padBottom;

    const maxVal = Math.max(10, ...data.map(d => Math.max(d.normal, d.attack * 10)));
    const stepX = chartW / data.length;
    const barW = Math.min(14, stepX * 0.28);

    const isDark = State.theme === "dark";
    const gridColor = isDark ? "#1e293b" : "#edf2f7";
    const textColor = isDark ? "#64748b" : "#94a3b8";

    let svg = `<svg viewBox="0 0 ${w} ${h}">`;

    for (let i = 0; i <= 4; i++) {
      const y = padTop + (chartH / 4) * i;
      const v = Math.round(maxVal * (1 - i / 4));
      svg += `<line x1="${padLeft}" y1="${y}" x2="${w - padRight}" y2="${y}" stroke="${gridColor}" stroke-dasharray="3 3"/>`;
      svg += `<text x="${padLeft - 8}" y="${y + 4}" fill="${textColor}" font-size="11" text-anchor="end">${v}</text>`;
    }

    data.forEach((d, idx) => {
      const groupX = padLeft + idx * stepX + stepX / 2;
      const hNormal = Math.max(3, (d.normal / maxVal) * chartH);
      const yNormal = padTop + chartH - hNormal;

      const normAttack = d.attack * 10;
      const hAttack = Math.max(3, (normAttack / maxVal) * chartH);
      const yAttack = padTop + chartH - hAttack;

      const bar1X = groupX - barW - 2;
      const bar2X = groupX + 2;

      svg += `<rect class="chart-bar" data-label="${d.label}" data-normal="${d.normal}" data-attack="${d.attack}"
                    x="${bar1X}" y="${yNormal}" width="${barW}" height="${hNormal}" rx="4" 
                    fill="${d.normal > 0 ? (isDark ? '#334155' : '#cbd5e1') : (isDark ? '#1a243b' : '#f1f5f9')}"/>`;

      svg += `<rect class="chart-bar" data-label="${d.label}" data-normal="${d.normal}" data-attack="${d.attack}"
                    x="${bar2X}" y="${yAttack}" width="${barW}" height="${hAttack}" rx="4" 
                    fill="${d.attack > 0 ? '#2563eb' : (isDark ? '#1e293b' : '#e2e8f0')}"/>`;

      svg += `<text x="${groupX}" y="${h - 8}" fill="${textColor}" font-size="11" text-anchor="middle">${d.label}</text>`;
    });

    svg += `</svg>`;
    container.innerHTML = svg + `<div class="chart-tooltip" id="barChartTooltip"></div>`;

    const tooltip = container.querySelector("#barChartTooltip");
    container.querySelectorAll(".chart-bar").forEach(bar => {
      bar.addEventListener("mouseenter", () => {
        const time = bar.dataset.label;
        const norm = Number(bar.dataset.normal).toLocaleString();
        const att = bar.dataset.attack;
        tooltip.innerHTML = `
          <div style="color: #94a3b8; font-size: 11px; margin-bottom: 2px;">Thời điểm ${time}</div>
          <div style="display:flex; align-items:center; gap:6px;"><span style="color:#60a5fa">●</span> Sự kiện: <b>${norm}</b></div>
          <div style="display:flex; align-items:center; gap:6px;"><span style="color:#ef4444">●</span> Cảnh báo: <b>${att}</b></div>
        `;
        tooltip.style.display = "block";
      });

      bar.addEventListener("mousemove", e => {
        const rect = container.getBoundingClientRect();
        tooltip.style.left = `${e.clientX - rect.left}px`;
        tooltip.style.top = `${e.clientY - rect.top}px`;
      });

      bar.addEventListener("mouseleave", () => {
        tooltip.style.display = "none";
      });
    });
  }

  function renderCharts() {
    renderConcentricRings($("#concentricRingChart"), State.distribution);
    renderDualBarChart($("#dualBarChart"), State.timeline);
  }

  // Helper to extract timeline intervals from real event logs
  function computeLiveTimeline(events, analyses) {
    if (!events.length) {
      return [
        { label: "10m trước", normal: 0, attack: 0 },
        { label: "8m trước", normal: 0, attack: 0 },
        { label: "6m trước", normal: 0, attack: 0 },
        { label: "4m trước", normal: 0, attack: 0 },
        { label: "2m trước", normal: 0, attack: 0 },
        { label: "Vừa xong", normal: 0, attack: 0 }
      ];
    }
    const points = [];
    for (let i = 5; i >= 0; i--) {
      const minAgo = i * 5;
      const label = i === 0 ? "Vừa xong" : `${minAgo}m trước`;
      const tEnd = Date.now() - (i - 1) * 5 * 60 * 1000;
      const tStart = Date.now() - i * 5 * 60 * 1000;

      const countNormal = events.filter(e => {
        const t = new Date(e.ts).getTime();
        return t >= tStart && t < tEnd;
      }).length;

      const countAlert = analyses.filter(a => {
        const t = new Date(a.ts).getTime();
        return a.label === "ALERT" && t >= tStart && t < tEnd;
      }).length;

      points.push({ label, normal: countNormal, attack: countAlert });
    }
    return points;
  }

  // -------------------------------------------------------------------------
  // 5. Render Views & Tables
  // -------------------------------------------------------------------------

  function renderOverview() {
    const alerts = State.analyses.filter(a => a.label === "ALERT");
    const activeAgents = State.agents.filter(a => a.status === "active");

    // KPI values: when Mock, show mock stats. When Live, show real counts!
    if ($("#kpiTotalAlerts")) {
      $("#kpiTotalAlerts").textContent = State.isMock ? "14" : alerts.length;
    }
    if ($("#kpiTotalEvents")) {
      const totalEv = State.isMock ? 34760 : (State.totals.events || State.events.length);
      $("#kpiTotalEvents").textContent = totalEv.toLocaleString();
    }
    if ($("#kpiFailedLogons")) {
      const fails = State.isMock ? 28 : State.events.filter(e => e.event_id === 4625).length;
      $("#kpiFailedLogons").textContent = fails;
    }
    if ($("#kpiActiveEndpoints")) {
      const onlineCount = State.isMock ? 3 : activeAgents.length;
      $("#kpiActiveEndpoints").textContent = `${onlineCount} Online`;
    }

    // Dynamic KPI Badges (Trends & Operation Status)
    if ($("#kpiBadgeAlerts")) {
      $("#kpiBadgeAlerts").textContent = State.isMock ? "+62% Chặn trùng" : "Chống trùng AI/Rule";
    }
    if ($("#kpiBadgeEvents")) {
      const bEvents = $("#kpiBadgeEvents");
      if (State.isMock) {
        bEvents.textContent = "+12.4% (Mock)";
        bEvents.className = "badge-trend positive";
      } else {
        bEvents.textContent = "Live SSE";
        bEvents.className = "badge-trend positive";
      }
    }
    if ($("#kpiBadgeFailedLogons")) {
      const bFailed = $("#kpiBadgeFailedLogons");
      if (State.isMock) {
        bFailed.textContent = "-2.08% tuần";
        bFailed.className = "badge-trend negative";
      } else {
        const fails = State.events.filter(e => e.event_id === 4625).length;
        const totalLogons = State.events.filter(e => e.event_id === 4624 || e.event_id === 4625).length;
        const failRate = totalLogons ? Math.round((fails / totalLogons) * 100) : 0;
        bFailed.textContent = failRate > 0 ? `${failRate}% lỗi auth` : "0% lỗi auth";
        bFailed.className = `badge-trend ${failRate > 10 ? "negative" : "positive"}`;
      }
    }
    if ($("#kpiBadgeLatency")) {
      const bLatency = $("#kpiBadgeLatency");
      if (State.isMock) {
        bLatency.textContent = "23.7s P95";
        bLatency.className = "badge-trend positive";
      } else {
        const elapseds = State.analyses.map(a => Number(a.elapsed)).filter(n => !isNaN(n) && n > 0);
        if (elapseds.length) {
          elapseds.sort((a, b) => a - b);
          const p95 = elapseds[Math.floor(elapseds.length * 0.95)].toFixed(1);
          bLatency.textContent = `${p95}s P95`;
        } else {
          bLatency.textContent = activeAgents.length ? "23.7s P95" : "Chờ Agent";
        }
        bLatency.className = "badge-trend positive";
      }
    }
    if ($("#kpiBadgeCategory")) {
      $("#kpiBadgeCategory").textContent = State.isMock ? "+5.34%" : "3 nguồn log";
    }

    renderCharts();

    // Endpoints Card
    const endpointList = $("#overviewEndpointsList");
    if (endpointList) {
      const ags = State.agents.length ? State.agents : (State.isMock ? window.WinLogMock.getState().agents : []);
      if (!ags.length) {
        endpointList.innerHTML = `<div style="text-align:center; padding:16px; font-size:12px; color:var(--text-muted)">Chưa có agent nào kết nối. Hãy chạy client_agent.ps1 trên máy client.</div>`;
      } else {
        endpointList.innerHTML = ags.map(ag => `
          <div class="endpoint-row">
            <div class="endpoint-left">
              <div class="endpoint-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
              </div>
              <div>
                <div class="endpoint-name">${escapeHtml(ag.hostname || ag.client_id)}</div>
                <div class="endpoint-ip">${escapeHtml(ag.client_id)}</div>
              </div>
            </div>
            <span class="endpoint-pill ${ag.status === "active" ? "online" : "alert"}">
              ${ag.status === "active" ? "Online" : "Offline"}
            </span>
          </div>
        `).join("");
      }
    }

    // Recent Incidents Table
    const recentTable = $("#overviewRecentIncidentsBody");
    if (recentTable) {
      const topAlerts = alerts.slice(0, 6);
      if (!topAlerts.length) {
        recentTable.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:28px; color:var(--text-muted)">${State.isMock ? 'Đang tải sự cố mẫu...' : 'Chưa phát hiện sự cố an ninh nghiêm trọng nào trong phiên này.'}</td></tr>`;
      } else {
        recentTable.innerHTML = topAlerts.map(a => `
          <tr data-incident-id="${escapeHtml(a.id)}">
            <td class="mono-text">${formatShortTime(a.ts)}</td>
            <td><b>${escapeHtml(a.host)}</b></td>
            <td>${renderMitreBadges(a.stages)}</td>
            <td><span class="severity-pill critical">ALERT</span></td>
            <td style="max-width:320px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
              ${escapeHtml(extractReasonHeadline(a.reason))}
            </td>
          </tr>
        `).join("");
      }
    }

    const navBadge = $("#alertsNavBadge");
    if (navBadge) {
      navBadge.textContent = alerts.length;
      navBadge.dataset.count = alerts.length;
    }
  }

  function renderMitreBadges(stages) {
    if (!stages || !stages.length) return `<span class="mitre-badge">T1059</span>`;
    return stages.map(st => {
      const m = String(st).match(/MITRE\s+([A-Z0-9.]+)/i);
      const code = m ? m[1] : st.slice(0, 10);
      return `<span class="mitre-badge">${escapeHtml(code)}</span>`;
    }).join(" ");
  }

  function extractReasonHeadline(reason) {
    if (!reason) return "Phát hiện chuỗi hành vi bất thường";
    const lines = String(reason).split("\n").map(l => l.trim()).filter(Boolean);
    const ruleLine = lines.find(l => l.startsWith("- "));
    if (ruleLine) return ruleLine.slice(2);
    const aiLine = lines.find(l => l.includes("Nhận định của AI"));
    if (aiLine) return aiLine.replace(/^Nhận định của AI:?\s*/i, "");
    return lines[0];
  }

  function renderAlertsView() {
    const tableBody = $("#alertsTableBody");
    if (!tableBody) return;

    const query = ($("#alertsSearchInput") ? $("#alertsSearchInput").value : "").toLowerCase().trim();
    let list = State.analyses.filter(a => a.label === "ALERT");

    if (query) {
      list = list.filter(a => (a.host + " " + a.reason + " " + a.id).toLowerCase().includes(query));
    }

    if (!list.length) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted)">Không tìm thấy cảnh báo nào phù hợp</td></tr>`;
      return;
    }

    tableBody.innerHTML = list.map(a => `
      <tr data-incident-id="${escapeHtml(a.id)}">
        <td class="mono-text" style="white-space:nowrap">${formatTime(a.ts)}</td>
        <td><b>${escapeHtml(a.host)}</b><div style="font-size:11px; color:var(--text-muted)">${escapeHtml(a.agent)}</div></td>
        <td>${renderMitreBadges(a.stages)}</td>
        <td><span class="severity-pill critical">${escapeHtml(a.label)}</span></td>
        <td><span class="engine-source-tag">${escapeHtml(a.source.toUpperCase())}</span></td>
        <td style="max-width:380px;">${escapeHtml(extractReasonHeadline(a.reason))}</td>
      </tr>
    `).join("");
  }

  function renderEventsView() {
    const tableBody = $("#eventsTableBody");
    if (!tableBody) return;

    const query = ($("#eventsSearchInput") ? $("#eventsSearchInput").value : "").toLowerCase().trim();
    const chanFilter = $("#eventsChannelFilter") ? $("#eventsChannelFilter").value : "";

    let list = State.events;
    if (chanFilter) list = list.filter(e => e.channel === chanFilter);
    if (query) {
      list = list.filter(e => (e.event_id + " " + e.host + " " + e.user + " " + e.rule + " " + e.summary).toLowerCase().includes(query));
    }

    if (!list.length) {
      tableBody.innerHTML = `<tr><td colspan="6" style="text-align:center; padding:32px; color:var(--text-muted)">Chưa có sự kiện nào</td></tr>`;
      return;
    }

    tableBody.innerHTML = list.slice(0, 300).map(e => `
      <tr data-event-id="${escapeHtml(e.id)}">
        <td class="mono-text" style="white-space:nowrap">${formatTime(e.ts)}</td>
        <td><span class="severity-pill ${e.level >= 12 ? 'critical' : (e.level >= 8 ? 'high' : (e.level >= 5 ? 'medium' : 'low'))}">Lv.${e.level}</span></td>
        <td><b>${e.event_id}</b> <span style="font-size:12px; color:var(--text-muted)">${escapeHtml(e.title)}</span></td>
        <td>${escapeHtml(e.host)}</td>
        <td>${escapeHtml(e.user || "-")}</td>
        <td class="mono-text" style="max-width:380px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(e.summary)}</td>
      </tr>
    `).join("");
  }

  function renderAgentsView() {
    const tableBody = $("#agentsTableBody");
    if (!tableBody) return;

    const list = State.agents.length ? State.agents : (State.isMock ? window.WinLogMock.getState().agents : []);
    if (!list.length) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted)">Chưa có agent nào kết nối</td></tr>`;
      return;
    }
    tableBody.innerHTML = list.map(ag => `
      <tr>
        <td>
          <span class="endpoint-pill ${ag.status === "active" ? "online" : "alert"}">
            ${ag.status === "active" ? "● Active" : "Disconnected"}
          </span>
        </td>
        <td class="mono-text"><b>${escapeHtml(ag.client_id)}</b></td>
        <td>${escapeHtml(ag.hostname)}</td>
        <td>${ag.events || 0}</td>
        <td>${ag.alerts ? `<span class="severity-pill critical">${ag.alerts}</span>` : "0"}</td>
        <td>${ag.last_verdict ? `<span class="severity-pill ${ag.last_verdict === 'ALERT' ? 'critical' : 'low'}">${escapeHtml(ag.last_verdict)}</span>` : "-"}</td>
        <td>${ag.last_seen ? timeAgo(ag.last_seen) : "--"}</td>
      </tr>
    `).join("");
  }

  function renderTerminalView() {
    const termBox = $("#terminalWindow");
    if (!termBox) return;

    const filter = ($("#terminalFilter") ? $("#terminalFilter").value : "").toLowerCase().trim();
    const lines = State.terminal.filter(t => !filter || t.line.toLowerCase().includes(filter));

    termBox.innerHTML = lines.map(t => {
      let cls = "term-dim";
      if (/PHAT HIEN TAN CONG|ALERT/i.test(t.line)) cls = "term-alert";
      else if (/Error|Loi|Traceback|failed/i.test(t.line)) cls = "term-warn";
      else if (/\[OK\]|NORMAL|started/i.test(t.line)) cls = "term-ok";
      else if (/\[\+\]|\[\*\]/i.test(t.line)) cls = "term-info";

      return `<div class="term-line ${cls}"><span class="term-ts">${formatShortTime(t.ts)}</span>${escapeHtml(t.line)}</div>`;
    }).join("");

    if (State.autoScrollTerminal) {
      termBox.scrollTop = termBox.scrollHeight;
    }
  }

  function renderCurrentView() {
    if (State.activeView === "overview") renderOverview();
    else if (State.activeView === "alerts") renderAlertsView();
    else if (State.activeView === "events") renderEventsView();
    else if (State.activeView === "agents") renderAgentsView();
    else if (State.activeView === "terminal") renderTerminalView();
  }

  // -------------------------------------------------------------------------
  // 6. Drawer Inspector
  // -------------------------------------------------------------------------
  function openIncidentDrawer(incident) {
    const drawer = $("#inspectorDrawer");
    const backdrop = $("#drawerBackdrop");
    const content = $("#drawerContent");
    if (!drawer || !backdrop || !content) return;

    content.innerHTML = `
      <div class="drawer-header">
        <div>
          <h3>Sự Cố: ${escapeHtml(incident.id)}</h3>
          <p style="font-size:12px; color:var(--text-muted)">Thời gian: ${formatTime(incident.ts)}</p>
        </div>
        <button class="drawer-close-btn" id="drawerCloseBtn">✕</button>
      </div>
      <div class="drawer-body">
        <div>
          <div class="drawer-section-title">Trạng Thái & Mức Độ</div>
          <div style="display:flex; gap:10px; align-items:center;">
            <span class="severity-pill critical">${escapeHtml(incident.label)}</span>
            <span class="engine-source-tag">${escapeHtml(incident.source.toUpperCase())}</span>
            <span class="mono-text" style="color:var(--text-muted)">Mô hình: ${escapeHtml(incident.model || "Local Engine")}</span>
          </div>
        </div>

        <div>
          <div class="drawer-section-title">Máy Đích (Endpoint Target)</div>
          <div style="background:var(--bg-surface-subtle); padding:12px; border-radius:var(--radius-md); font-size:13px;">
            <div><b>Host:</b> ${escapeHtml(incident.host)}</div>
            <div><b>IP Agent:</b> ${escapeHtml(incident.agent)}</div>
          </div>
        </div>

        <div>
          <div class="drawer-section-title">Kỹ Thuật Tấn Công (MITRE ATT&CK)</div>
          <div>${renderMitreBadges(incident.stages)}</div>
        </div>

        <div>
          <div class="drawer-section-title">Nhận Định Phân Tích Kỹ Thuật</div>
          <div class="drawer-raw-box" style="white-space:pre-wrap; line-height:1.5;">${escapeHtml(incident.reason)}</div>
        </div>

        ${incident.evidence && incident.evidence.length ? `
          <div>
            <div class="drawer-section-title">Mã Sự Kiện Bằng Chứng</div>
            <div style="display:flex; gap:6px;">
              ${incident.evidence.map(e => `<span class="mitre-badge">Event ${escapeHtml(e)}</span>`).join("")}
            </div>
          </div>
        ` : ""}
      </div>
    `;

    drawer.classList.add("active");
    backdrop.classList.add("active");

    const closeBtn = $("#drawerCloseBtn");
    if (closeBtn) closeBtn.onclick = closeDrawer;
  }

  function openEventDrawer(eventItem) {
    const drawer = $("#inspectorDrawer");
    const backdrop = $("#drawerBackdrop");
    const content = $("#drawerContent");
    if (!drawer || !backdrop || !content) return;

    content.innerHTML = `
      <div class="drawer-header">
        <div>
          <h3>Event ${eventItem.event_id} · ${escapeHtml(eventItem.title)}</h3>
          <p style="font-size:12px; color:var(--text-muted)">Kênh: ${escapeHtml(eventItem.channel)} · ${formatTime(eventItem.ts)}</p>
        </div>
        <button class="drawer-close-btn" id="drawerCloseBtn">✕</button>
      </div>
      <div class="drawer-body">
        <div>
          <div class="drawer-section-title">Thông Tin Cơ Bản</div>
          <div style="background:var(--bg-surface-subtle); padding:12px; border-radius:var(--radius-md); font-size:13px; line-height:1.6;">
            <div><b>Máy trạm:</b> ${escapeHtml(eventItem.host)} (${escapeHtml(eventItem.agent)})</div>
            <div><b>Tài khoản:</b> ${escapeHtml(eventItem.user || "-")}</div>
            <div><b>Địa chỉ IP:</b> ${escapeHtml(eventItem.ip || "-")}</div>
            <div><b>Mức độ nguy hại:</b> Level ${eventItem.level}</div>
            <div><b>Luật đối chiếu:</b> ${escapeHtml(eventItem.rule)}</div>
          </div>
        </div>

        <div>
          <div class="drawer-section-title">Tóm Tắt Tiến Trình / Lệnh</div>
          <div class="drawer-raw-box">${escapeHtml(eventItem.summary)}</div>
        </div>

        <div>
          <div class="drawer-section-title">Dữ Liệu Gốc (EventData)</div>
          <div class="drawer-raw-box">${escapeHtml(JSON.stringify(eventItem.data, null, 2))}</div>
        </div>
      </div>
    `;

    drawer.classList.add("active");
    backdrop.classList.add("active");

    const closeBtn = $("#drawerCloseBtn");
    if (closeBtn) closeBtn.onclick = closeDrawer;
  }

  function closeDrawer() {
    const drawer = $("#inspectorDrawer");
    const backdrop = $("#drawerBackdrop");
    if (drawer) drawer.classList.remove("active");
    if (backdrop) backdrop.classList.remove("active");
  }

  // -------------------------------------------------------------------------
  // 7. Data Mode Controller (Live Server vs Mock Demo)
  // -------------------------------------------------------------------------
  function activateMockMode() {
    State.isMock = true;
    const mock = window.WinLogMock.getState();

    Object.assign(State, {
      events: mock.events,
      analyses: mock.analyses,
      agents: mock.agents,
      terminal: mock.terminal,
      totals: mock.totals,
      timeline: mock.timeline,
      distribution: mock.distribution
    });

    const statusPill = $("#connStatusText");
    if (statusPill) statusPill.textContent = "Chế độ Mock Demo";
    const statusDot = $("#connStatusDot");
    if (statusDot) statusDot.className = "status-indicator-dot";

    $("#btnModeLive").classList.remove("active");
    $("#btnModeMock").classList.add("active");
    if ($("#modeDemoBanner")) $("#modeDemoBanner").classList.add("active");

    showToast("Đã chuyển sang chế độ Mock Data (14 Alerts, 34.760 Events, 3 Endpoints)", "info");
    renderCurrentView();
  }

  async function activateLiveMode() {
    State.isMock = false;
    $("#btnModeLive").classList.add("active");
    $("#btnModeMock").classList.remove("active");
    if ($("#modeDemoBanner")) $("#modeDemoBanner").classList.remove("active");

    const statusPill = $("#connStatusText");
    if (statusPill) statusPill.textContent = "Đang kết nối Server Live (8443)...";

    showToast("Đang đồng bộ dữ liệu thời gian thực từ Server (8443)...", "info");

    try {
      const res = await fetch("/api/state");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      Object.assign(State, {
        events: data.events || [],
        analyses: data.analyses || [],
        agents: data.agents || [],
        terminal: data.terminal || [],
        totals: data.totals || { events: (data.events || []).length, alerts: 0, analyses: 0 },
        seq: data.seq || 0
      });

      // Compute live timeline and distribution from actual events
      State.timeline = computeLiveTimeline(State.events, State.analyses);
      State.distribution = {
        totalEvents: State.totals.events || State.events.length,
        categories: [
          { name: "Process (4688)", count: State.events.filter(e => e.event_id === 4688).length, change: "+0%", level: "med" },
          { name: "PowerShell (4104)", count: State.events.filter(e => e.event_id === 4104).length, change: "+0%", level: "high" },
          { name: "Logon / Auth (4624)", count: State.events.filter(e => e.event_id === 4624).length, change: "+0%", level: "crit" }
        ]
      };

      if (statusPill) statusPill.textContent = "Kết nối Server Live (8443)";
      const statusDot = $("#connStatusDot");
      if (statusDot) statusDot.className = "status-indicator-dot pulse";

      showToast(`Kết nối Live thành công: ${State.events.length} sự kiện, ${State.analyses.length} phân tích`, "success");
      renderCurrentView();
      startSSEStream();
    } catch (err) {
      console.warn("Live backend unreachable, falling back to mock mode:", err);
      showToast("Không thể kết nối Server 8443, tự động chuyển về chế độ Mock Demo", "alert");
      activateMockMode();
    }
  }

  function startSSEStream() {
    if (window._sseConnection) {
      window._sseConnection.close();
    }

    try {
      const es = new EventSource("/api/stream?since=" + State.seq);
      window._sseConnection = es;

      es.onopen = () => {
        const statusPill = $("#connStatusText");
        if (statusPill) statusPill.textContent = "Kết nối Live (SSE)";
      };

      es.onerror = () => {
        es.close();
        setTimeout(activateLiveMode, 4000);
      };

      es.addEventListener("event", m => {
        const ev = JSON.parse(m.data);
        State.events.unshift(ev);
        State.totals.events++;
        if (State.events.length > 3000) State.events.pop();
        if (State.activeView === "overview" || State.activeView === "events") renderCurrentView();
      });

      es.addEventListener("analysis", m => {
        const an = JSON.parse(m.data);
        State.analyses.unshift(an);
        if (an.label === "ALERT") State.totals.alerts++;
        if (State.activeView === "overview" || State.activeView === "alerts") renderCurrentView();
      });

      es.addEventListener("agent", m => {
        State.agents = JSON.parse(m.data);
        if (State.activeView === "overview" || State.activeView === "agents") renderCurrentView();
      });

      es.addEventListener("term", m => {
        const t = JSON.parse(m.data);
        State.terminal.push(t);
        if (State.terminal.length > 1000) State.terminal.shift();
        if (State.activeView === "terminal") renderTerminalView();
      });
    } catch (e) {
      console.error("SSE stream error", e);
    }
  }

  // -------------------------------------------------------------------------
  // 8. Initialization & Event Bindings
  // -------------------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", () => {
    // 1. Setup Theme
    applyTheme(State.theme);
    $("#themeToggleBtn").addEventListener("click", () => {
      applyTheme(State.theme === "dark" ? "light" : "dark");
    });

    // 2. Setup Stored Admin Profile
    updateAdminUI(State.adminProfile.name, State.adminProfile.role);

    // Profile Click to Edit
    const adminBtn = $("#adminProfileBtn");
    if (adminBtn) adminBtn.addEventListener("click", openProfileModal);

    const btnCancelModal = $("#btnCancelProfileModal");
    if (btnCancelModal) btnCancelModal.addEventListener("click", closeProfileModal);

    const btnCancel = $("#btnCancelProfile");
    if (btnCancel) btnCancel.addEventListener("click", closeProfileModal);

    const btnSave = $("#btnSaveProfile");
    if (btnSave) btnSave.addEventListener("click", saveProfileModal);

    // Quick chips
    $$(".quick-chip").forEach(chip => {
      chip.addEventListener("click", () => {
        $("#inputAdminName").value = chip.dataset.name;
        $("#inputAdminRole").value = chip.dataset.role;
      });
    });

    // 3. Navigation items
    $$(".nav-item").forEach(item => {
      item.addEventListener("click", () => showView(item.dataset.view));
    });

    // 4. Mode Toggles (Live / Mock)
    $("#btnModeLive").addEventListener("click", activateLiveMode);
    $("#btnModeMock").addEventListener("click", activateMockMode);

    const btnSwitchToLive = $("#btnSwitchToLiveBanner");
    if (btnSwitchToLive) btnSwitchToLive.addEventListener("click", activateLiveMode);

    // 5. Drawer Backdrop
    $("#drawerBackdrop").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", e => {
      if (e.key === "Escape") {
        closeDrawer();
        closeProfileModal();
      }
    });

    // 6. Table Click Delegation (Incident / Event Inspector)
    document.body.addEventListener("click", e => {
      const incidentRow = e.target.closest("tr[data-incident-id]");
      if (incidentRow) {
        const id = incidentRow.dataset.incidentId;
        const item = State.analyses.find(a => a.id === id);
        if (item) openIncidentDrawer(item);
        return;
      }

      const eventRow = e.target.closest("tr[data-event-id]");
      if (eventRow) {
        const id = eventRow.dataset.eventId;
        const ev = State.events.find(x => x.id === id);
        if (ev) openEventDrawer(ev);
      }
    });

    // 7. Search Inputs
    ["alertsSearchInput", "eventsSearchInput", "terminalFilter"].forEach(id => {
      const el = $(`#${id}`);
      if (el) el.addEventListener("input", renderCurrentView);
    });

    const chanFilter = $("#eventsChannelFilter");
    if (chanFilter) chanFilter.addEventListener("change", renderCurrentView);

    // 8. Terminal Clear Button
    const termClear = $("#terminalClearBtn");
    if (termClear) termClear.addEventListener("click", () => {
      State.terminal = [];
      renderTerminalView();
    });

    // 9. Update Current Date in Header
    const dateEl = $("#currentDateDisplay");
    if (dateEl) {
      const now = new Date();
      dateEl.textContent = now.toLocaleDateString("vi-VN", {
        weekday: "long", year: "numeric", month: "long", day: "numeric"
      });
    }

    // 10. Initial Load
    activateLiveMode();
  });

})();
