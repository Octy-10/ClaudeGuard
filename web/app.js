(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const state = {
    data: null,
    expandedIds: new Map(),
    confirmResolver: null,
    pending: new Set(),
    scanError: "",
    primaryIssue: "",
    activeView: "overview",
    purityRunning: false,
    mascotFlash: null,
    mascotFlashTimer: null,
    mascotIdleTimer: null,
    mascotAsleep: false,
    mascotEggIndex: 0,
  };

  const MASCOT_EGGS = [
    { key: "dance", label: "开心转圈中" },
    { key: "coffee", label: "喝杯咖啡歇歇" },
    { key: "cool", label: "墨镜警戒模式" },
    { key: "wizard", label: "魔法护盾加持" },
    { key: "crown", label: "全绿守护王者" },
  ];
  const MASCOT_IDLE_MS = 90000;

  const statusTitles = { green: "防护正常", yellow: "有待处理的警告", red: "检测到防护异常" };
  const CHECK_LEVELS = { FAIL: "异常", WARN: "警告", UNKNOWN: "未知", PASS: "通过" };
  const PROBE_PATH = "clash-probe-listener";
  const TUN_PATH = "system-tun";
  const protectionSwitches = ["swKillswitch", "swDns", "swWebrtc", "swIpv6"];
  const apiControls = {
    run_doctor: ["btnDoctor"],
    enable_all_protection: ["btnEnableAll", ...protectionSwitches],
    toggle_killswitch: ["swKillswitch", "btnEnableAll"],
    toggle_dns_lock: ["swDns", "btnEnableAll"],
    toggle_webrtc: ["swWebrtc", "btnEnableAll"],
    toggle_ipv6: ["swIpv6", "btnEnableAll"],
    toggle_ip_monitor: ["btnLockIp"],
    align_timezone: ["btnAlignTz", "btnRestoreTz"],
    restore_timezone: ["btnAlignTz", "btnRestoreTz"],
    kill_claude_app: ["btnKillClaude"],
    launch_claude_app: ["btnLaunchClaude", "btnKillClaude"],
    toggle_alert_sound: ["swAlertSound"],
    toggle_auto_kill_claude: ["swAutoKill"],
    toggle_autostart: ["swAutostart"],
    run_rescue: ["btnRescue", "btnEnableAll", "btnAlignTz", "btnRestoreTz", ...protectionSwitches],
    get_override_script: ["btnOverride", "btnConfigureProbe"],
    open_author_page: ["btnOpenDouyin"],
    check_update: ["btnCheckUpdate"],
    install_update: ["btnInstallUpdate"],
    open_release_page: ["btnOpenRelease"],
  };
  const controlledIds = new Set(Object.values(apiControls).flat());

  /* ------------------------------------------------------------------
   * 通用反馈
   * ------------------------------------------------------------------ */
  function toast(message, kind = "info") {
    if (!message) return;
    const el = document.createElement("div");
    el.className = `toast ${kind}`;
    el.textContent = message;
    const stack = $("toastStack");
    const host = document.querySelector("dialog[open]") || document.body;
    if (stack.parentElement !== host) {
      stack.replaceChildren();
      host.appendChild(stack);
    }
    if (stack.children.length >= 2) stack.firstElementChild.remove();
    stack.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity .2s ease";
      setTimeout(() => el.remove(), 220);
    }, 3200);
  }

  function updatePendingControls() {
    const pendingIds = new Set([...state.pending].flatMap(method => apiControls[method] || []));
    const monitoring = Boolean(state.data?.config?.monitored_probe_ip);
    for (const id of controlledIds) {
      const el = $(id);
      if (!el) continue;
      const busy = pendingIds.has(id);
      el.disabled = busy || (id === "btnLockIp" && (!state.data?.config || (!monitoring && !state.data?.report?.exit_info?.ip)))
        || (id === "btnLaunchClaude" && !state.data?.report?.states?.firewall_active);
      const sw = el.closest?.(".switch");
      if (sw) {
        sw.classList.toggle("is-loading", busy);
        sw.setAttribute("aria-busy", String(busy));
      }
    }
    const saving = state.pending.has("toggle_ip_monitor");
    $("btnLockIp").setAttribute("aria-busy", String(saving));
    setText("btnLockIpLabel", saving ? "正在保存…" : monitoring ? "停止监控" : "开始监控");
  }

  function escapeHtml(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /* ------------------------------------------------------------------
   * 悬浮解说
   * ------------------------------------------------------------------ */
  function initTooltips() {
    const tip = $("tooltip");
    let current = null;

    function place() {
      if (!current) return;
      const anchor = current.getBoundingClientRect();
      const box = tip.getBoundingClientRect();
      const gap = 9;
      let side = "top";
      let top = anchor.top - box.height - gap;
      if (top < 8) {
        side = "bottom";
        top = anchor.bottom + gap;
      }
      const left = Math.max(10, Math.min(
        anchor.left + anchor.width / 2 - box.width / 2,
        window.innerWidth - box.width - 10
      ));
      tip.style.top = `${Math.round(top)}px`;
      tip.style.left = `${Math.round(left)}px`;
      tip.dataset.side = side;
      const arrow = Math.max(12, Math.min(box.width - 12, anchor.left + anchor.width / 2 - left));
      tip.style.setProperty("--arrow-x", `${Math.round(arrow)}px`);
    }

    function show(el) {
      const text = el.dataset.tip;
      if (!text || current === el) return;
      hide();
      current = el;
      el.classList.add("is-open");
      tip.textContent = text;
      tip.classList.add("is-on");
      tip.setAttribute("aria-hidden", "false");
      place();
    }

    function hide() {
      if (!current) return;
      current.classList.remove("is-open");
      current = null;
      tip.classList.remove("is-on");
      tip.setAttribute("aria-hidden", "true");
    }

    document.addEventListener("pointerover", (event) => {
      const el = event.target.closest?.(".help");
      if (el) show(el);
    });
    document.addEventListener("pointerout", (event) => {
      const el = event.target.closest?.(".help");
      if (el && el === current) hide();
    });
    document.addEventListener("focusin", (event) => {
      const el = event.target.closest?.(".help");
      if (el) show(el);
    });
    document.addEventListener("focusout", (event) => {
      if (event.target.closest?.(".help") === current) hide();
    });
    document.addEventListener("click", (event) => {
      const el = event.target.closest?.(".help");
      if (!el) {
        hide();
        return;
      }
      event.preventDefault();
      if (current === el) hide();
      else show(el);
    });
    document.addEventListener("scroll", hide, true);
    window.addEventListener("resize", hide);
    window.addEventListener("blur", hide);
  }

  /* ------------------------------------------------------------------
   * 进度环与数字滚动
   * ------------------------------------------------------------------ */
  function setRing(bar, ratio) {
    if (!bar) return;
    const radius = bar.r.baseVal.value;
    const circumference = 2 * Math.PI * radius;
    const clamped = Math.max(0, Math.min(1, Number(ratio) || 0));
    bar.style.strokeDasharray = `${circumference} ${circumference}`;
    const target = circumference * (1 - clamped);
    if (!bar.dataset.ready) {
      bar.style.strokeDashoffset = String(circumference);
      bar.dataset.ready = "1";
      requestAnimationFrame(() => requestAnimationFrame(() => {
        bar.style.strokeDashoffset = String(target);
      }));
    } else {
      bar.style.strokeDashoffset = String(target);
    }
  }

  function setNumber(el, value, suffix = "") {
    if (!el) return;
    const next = value === null || value === undefined ? "--" : String(Math.round(value));
    if (el.dataset.target === next) return;
    el.dataset.target = next;
    if (next === "--") {
      el.textContent = "--";
      return;
    }
    const from = Number(el.textContent);
    const start = Number.isFinite(from) ? from : 0;
    const to = Number(next);
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      el.textContent = next + suffix;
      return;
    }
    const began = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - began) / 720);
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = Math.round(start + (to - start) * eased) + suffix;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  /* ------------------------------------------------------------------
   * 模态框
   * ------------------------------------------------------------------ */
  function showConfirm(title, body, confirmText = "确认执行") {
    $("confirmTitle").textContent = title;
    $("confirmBody").textContent = body;
    $("btnConfirmOk").textContent = confirmText;
    $("confirmModal").showModal();
    $("btnConfirmCancel").focus();
    return new Promise((resolve) => {
      state.confirmResolver = resolve;
    });
  }

  function closeConfirm(result) {
    $("confirmModal").close();
    if (state.confirmResolver) {
      const fn = state.confirmResolver;
      state.confirmResolver = null;
      fn(result);
    }
  }

  /* ------------------------------------------------------------------
   * 主渲染
   * ------------------------------------------------------------------ */
  function summarizeChecks(items) {
    const counts = { FAIL: 0, WARN: 0, UNKNOWN: 0, PASS: 0 };
    for (const item of items) {
      if (Object.hasOwn(counts, item.level)) counts[item.level]++;
    }
    const issue = ["FAIL", "WARN", "UNKNOWN"]
      .map(level => items.find(item => item.level === level)).find(Boolean);
    const totals = Object.keys(counts)
      .filter(level => counts[level])
      .map(level => [level, counts[level] + " 项" + CHECK_LEVELS[level]]);
    return { issue, totals };
  }

  function setText(id, value) {
    const node = $(id);
    if (node.textContent !== value) node.textContent = value;
  }

  function renderOverviewStatus() {
    const report = state.data?.report;
    const { issue, totals } = summarizeChecks(report?.items || []);
    const scanning = state.pending.has("run_doctor");
    const showDiagnosis = Boolean(issue && !scanning && !state.scanError);
    state.primaryIssue = issue?.id || "";
    document.body.dataset.status = report?.overall || "loading";
    document.body.dataset.scan = scanning ? "checking" : state.scanError ? "error" : "idle";
    const glyph = scanning ? "#i-pulse" : report?.overall === "green" ? "#i-guard" : "#i-shield-plain";
    $("heroGlyph")?.setAttribute("href", glyph);
    syncMascot();

    let title = "等待首次巡检";
    const isMac = state.data?.platform === "macos";
    let description = isMac ? "巡检完成后会显示网络状态。" : "巡检完成后会显示防护状态。";
    if (report) {
      title = issue?.level === "UNKNOWN" ? "部分状态待核实" : statusTitles[report.overall] || statusTitles.yellow;
      if (isMac && report.overall === "red") title = "检测到网络异常";
      description = issue?.summary || (totals.length ? "所有检查项均已通过。" : "暂无可显示的检查结果。");
    }
    if (scanning) {
      title = "正在巡检";
      description = report ? "下方显示上次结果。" : "正在获取首次巡检结果。";
    } else if (state.scanError) {
      title = "本次巡检失败";
      description = state.scanError;
    }
    setText("heroTitle", title);
    setText("checkSummary", description);

    $("btnViewIssue").hidden = !showDiagnosis;
    const button = $("btnDoctor");
    button.classList.toggle("is-spinning", scanning);
    button.classList.toggle("btn-secondary", showDiagnosis);
    button.classList.toggle("btn-primary", !showDiagnosis);
    button.setAttribute("aria-busy", String(scanning));
    setText("btnDoctorLabel", scanning ? "巡检中…" : state.scanError ? "重试自检" : showDiagnosis ? "重新巡检" : "立即自检");

    $("heroFooter").hidden = !report;
    $("overviewTotals").replaceChildren(...totals.map(([level, label]) => {
      const chip = document.createElement("span");
      chip.className = "check-total";
      chip.dataset.level = level;
      chip.textContent = label;
      return chip;
    }));
    setText("scanMeta", report ? (
      scanning || state.scanError ? "上次结果 " + report.checked_at : "本次耗时 " + (report.elapsed_ms || 0) + " ms"
    ) : "");
    setText("checkedMeta", report ? "上次巡检 " + report.checked_at : "等待首次巡检");
    $("checkedMeta").title = report ? "巡检耗时 " + (report.elapsed_ms || 0) + " ms" : "";
    return totals;
  }

  function render(payload) {
    if (!payload) return;
    state.data = payload;
    const cfg = payload.config || {};
    const isMac = payload.platform === "macos";
    const canProtect = !isMac || payload.mac_installed;
    document.body.dataset.platform = payload.platform || "windows";
    document.body.dataset.macInstalled = String(Boolean(payload.mac_installed));
    $("macProtectionNote").hidden = canProtect;
    $("protectionControls").hidden = !canProtect;
    $("btnEnableAll").hidden = !canProtect;
    $("btnRescue").hidden = !canProtect;
    $("btnLaunchClaude").hidden = !isMac || !canProtect;
    setText("killswitchLabel", isMac ? "Claude Desktop 断网锁" : "防火墙断网锁");
    if (isMac) $("killswitchHelp").dataset.tip = "启用网络扩展后，通过 Guard 启动 Claude Desktop。该应用的外部连接使用 Guard-Claude 本机代理。";
    setText("scriptModalTitle", isMac ? "Clash 本机代理与出口检测脚本" : "Clash 全局分流覆写脚本（可选）");
    setText("scriptStepTwo", isMac ? "切到规则模式，为 Guard-Probe 和 Guard-Claude 分别选择节点。" : "脚本会选择订阅的 AI 或主代理组，并添加 Claude 相关分流规则。");
    setText("scriptStepThree", isMac ? "回到 Guard 启用断网锁，按系统提示批准网络扩展，然后点击「受保护地启动」。" : "在 Clash Verge 中按需开启 TUN，再回到 Claude Guard 点击「立即自检」。");
    renderLockState(cfg);
    updatePendingControls();
    const totals = renderOverviewStatus();

    const ver = `v${payload.version || "1.0.0"}`;
    $("versionTag").textContent = `${ver} · 十月Archive`;
    if ($("aboutVersion")) $("aboutVersion").textContent = `${ver} · 本地透明网络环境防护工具`;
    const priv = $("privPill");
    priv.textContent = isMac ? (canProtect ? "macOS · 按次授权" : "macOS · 只读诊断") : payload.is_admin ? "管理员模式" : "只读模式 · 以管理员重启";
    priv.disabled = isMac || payload.is_admin;
    priv.title = isMac ? "查看网络和出口状态" : payload.is_admin ? "当前可修改系统配置" : "修改系统配置需要管理员权限";

    renderLogs(payload.logs || []);
    renderUpdateState(payload.update, payload.update_progress);

    const report = payload.report;
    if (payload.purity) renderPurityView(payload.purity);

    const ex = report?.exit_info || {};
    const exitFlag = $("exitFlag");
    const flagMarkup = ex.ip && window.renderCountryFlag ? window.renderCountryFlag(ex.country_code) : "";
    if (exitFlag) {
      exitFlag.hidden = !flagMarkup;
      exitFlag.innerHTML = flagMarkup;
      exitFlag.title = [ex.country_code, ex.country].filter(Boolean).join(" ");
    }
    $("exitIp").textContent = ex.ip || "未验证";
    $("exitPath").textContent = ex.path === PROBE_PATH
      ? "Clash 回环体检 · Guard-Probe"
      : ex.path === TUN_PATH
        ? "通用 TUN 通道"
        : "未验证";
    const exitNote = $("exitNote");
    if (exitNote) {
      exitNote.textContent = ex.path === PROBE_PATH
        ? "通过 Clash Guard-Probe 回环通道核验"
        : isMac ? "需要核实 Clash Guard-Probe 回环入口" : "通过当前活跃 TUN 通道实时核验";
    }
    const cfgProbeBtn = $("btnConfigureProbe");
    if (cfgProbeBtn) {
      cfgProbeBtn.hidden = !(payload.clash_dir_exists && !ex.ip && (isMac || !report?.tun_up));
    }
    const networkKind = ex.is_proxy === true ? "代理库" : ex.is_hosting === true ? "机房段" :
      ex.is_hosting === false ? "非机房" : "";
    const networkProperty = ex.ip ? [ex.asn, networkKind].filter(Boolean).join(" · ") : "";
    $("exitAsnTag").textContent = networkProperty;
    $("exitAsnRow").hidden = !networkProperty;
    $("exitLoc").textContent = ex.ip
      ? [ex.country_code, ex.country, ex.city].filter(Boolean).join(" · ")
      : ex.error || (report ? "暂无可用的出口结果" : "");
    $("exitIsp").textContent = ex.isp || "—";
    $("exitTz").textContent = ex.timezone || "—";
    const tunCheck = report?.items?.find(item => item.id === "tun");
    const tunKnown = Boolean(tunCheck && tunCheck.level !== "UNKNOWN");
    const tunOnline = Boolean(report?.tun_up);
    $("tunState").dataset.level = !tunKnown || (isMac && tunOnline) ? "unknown" : tunOnline ? "online" : "offline";
    $("tunState").textContent = !tunKnown ? "TUN 待确认" : tunOnline ? (isMac ? "经 utun · 归属待确认" : "TUN 在线") : "TUN 未就绪";

    const st = report?.states || {};
    const firewallRules = st.firewall_rule_count || 0;
    const firewallKnown = Boolean(report && st.firewall_known !== false);
    const firewallPartial = Boolean(firewallRules && !st.firewall_active);
    updateControlTile("killswitch", "swKillswitch", Boolean(st.firewall_active),
      st.firewall_active ? (isMac ? "网络扩展已启用" : `已验证 · ${firewallRules} 条拦截规则`) :
        !firewallKnown ? "状态未知" : firewallPartial ? "规则覆盖不完整 · 开启可自动补全" : "未开启防直连规则"
    );
    document.querySelector('[data-ctrl="killswitch"]')?.classList.toggle("is-warn", firewallPartial);
    updateControlTile("dns", "swDns", Boolean(st.dns_locked),
      st.dns_locked ? "已锁定 · " + (st.dns_summary || "1.1.1.1, 8.8.8.8") : st.dns_summary || "待确认"
    );
    updateControlTile("webrtc", "swWebrtc", Boolean(st.webrtc_ok),
      st.webrtc_ok ? "浏览器策略已核对" : report ? "浏览器策略待核对" : "待确认"
    );
    updateControlTile("ipv6", "swIpv6", Boolean(st.ipv6_physical_disabled),
      st.ipv6_physical_disabled
        ? (st.ipv6_leaked_ip ? "物理已关 · 代理仍透出 IPv6" : "全部物理网卡已禁用")
        : st.ipv6_physical_disabled === false ? "存在物理网卡开启 IPv6" : "物理网卡状态未知"
    );

    const tzTile = document.querySelector('[data-ctrl="timezone"]');
    if (tzTile) tzTile.classList.toggle("is-active", Boolean(st.timezone_matched));
    $("ctrlTzSub").textContent = st.timezone_current
      ? (st.timezone_matched ? `已一致 · ${st.timezone_current}` : `本机 ${st.timezone_current}`)
      : "未知";

    const claudeCount = Number(st.claude_proc_count || 0);
    const claudeTile = document.querySelector('[data-ctrl="claude_proc"]');
    if (claudeTile) claudeTile.classList.toggle("is-active", claudeCount === 0);
    const processCheck = report?.items?.find(item => item.id === "processes");
    $("ctrlClaudeSub").textContent = claudeCount > 0 ? `运行中：${claudeCount} 个进程` : report && processCheck?.level !== "UNKNOWN" ? "未运行" : "待确认";

    // 实时守护
    const fastSec = Number(cfg.fast_watch_interval_sec || 3);
    const fullSec = Number(cfg.poll_interval_sec || 60);
    if (isMac) $("watchHelp").dataset.tip = "窗口最小化后继续巡检。菜单栏显示巡检状态，开启提示音后可听到异常提示。";
    $("watchMeta").textContent = `${fastSec} 秒本地快检 · ${fullSec} 秒出口巡检`;
    const intervalEl = $("interval");
    if (intervalEl) intervalEl.textContent = `${fastSec}s 本地快检 · ${fullSec}s 出口巡检`;
    updateGuardianTile("alert_sound", "swAlertSound", cfg.alert_sound !== false);
    updateGuardianTile("auto_kill", "swAutoKill", Boolean(cfg.auto_kill_claude_on_critical));
    updateGuardianTile("autostart", "swAutostart", Boolean(payload.autostart_enabled));

    renderChecks(report?.items || [], totals);
  }

  function renderLockState(cfg) {
    const locked = Boolean(cfg.monitored_probe_ip);
    setText("lockChip", locked ? `监控 IP ${cfg.monitored_probe_ip}` : "未开启");
    $("lockStrip").setAttribute("data-monitoring", String(locked));
  }

  function updateGuardianTile(ctrlKey, switchId, active) {
    const tile = document.querySelector(`[data-ctrl="${ctrlKey}"]`);
    if (tile) tile.classList.toggle("is-active", active);
    const sw = $(switchId);
    if (sw) sw.checked = active;
  }

  function updateControlTile(ctrlKey, switchId, active, subtitle) {
    updateGuardianTile(ctrlKey, switchId, active);
    const subMap = {
      killswitch: "ctrlKillswitchSub",
      dns: "ctrlDnsSub",
      webrtc: "ctrlWebrtcSub",
      ipv6: "ctrlIpv6Sub",
    };
    const subNode = $(subMap[ctrlKey]);
    if (subNode) subNode.textContent = subtitle;
  }

  function renderChecks(items, totals) {
    $("diagnosticTotals").textContent = totals.map(([, label]) => label).join(" · ");
    const container = $("checkList");
    const focusedId = container.contains(document.activeElement)
      ? document.activeElement.closest(".check-item")?.dataset.checkId
      : null;
    container.innerHTML = items.length ? "" : '<p class="empty">等待巡检结果</p>';

    const ordered = Object.keys(CHECK_LEVELS).flatMap(level => items.filter(item => item.level === level));
    for (const item of ordered) {
      const hasDetail = Boolean(item.detail);
      const isExpanded = state.expandedIds.get(item.id) ?? (item.level === "FAIL" && hasDetail);
      const el = document.createElement("div");
      el.dataset.checkId = item.id;
      el.className = `check-item${hasDetail ? " has-detail" : ""}${isExpanded ? " expanded" : ""}`;
      el.innerHTML = `
        <${hasDetail ? 'button type="button"' : "div"} class="check-row" ${hasDetail ? `aria-expanded="${isExpanded}"` : ""}>
          <span class="level-pill level-${escapeHtml(item.level)}">${CHECK_LEVELS[item.level] || escapeHtml(item.level)}</span>
          <span class="check-name">${escapeHtml(item.name)}</span>
          <span class="check-summary" title="${escapeHtml(item.summary)}">${escapeHtml(item.summary)}</span>
          ${hasDetail ? `<svg class="check-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>` : `<span></span>`}
        </${hasDetail ? "button" : "div"}>
        ${hasDetail ? `<div class="check-detail">${escapeHtml(item.detail)}</div>` : ""}
      `;
      if (hasDetail) {
        el.querySelector("button").addEventListener("click", (event) => {
          const next = !el.classList.contains("expanded");
          el.classList.toggle("expanded", next);
          event.currentTarget.setAttribute("aria-expanded", String(next));
          state.expandedIds.set(item.id, next);
        });
      }
      container.appendChild(el);
      if (hasDetail && el.dataset.checkId === focusedId) el.querySelector("button").focus({ preventScroll: true });
    }
  }

  /* ------------------------------------------------------------------
   * IP 体检
   * ------------------------------------------------------------------ */
  function renderPurityView(p) {
    if (!p) return;
    const purityMeta = $("purityMeta");
    const purityFlag = p.ip && window.renderCountryFlag ? window.renderCountryFlag(p.country_code) : "";
    const locText = [p.country_code, p.country, p.city].filter(Boolean).join(" ");
    const ipText = `出口 IP ${p.ip || "—"}${locText ? " · " + locText : ""}`;
    if (purityFlag) {
      purityMeta.innerHTML = `<span class="country-flag is-sm" aria-hidden="true">${purityFlag}</span><span>${escapeHtml(ipText)}</span>`;
    } else {
      purityMeta.textContent = ipText;
    }
    $("purityAsnFooter").textContent = [p.asn, p.as_org].filter(Boolean).join(" · ") || "ASN 信息未知";
    $("purityCheckedAt").textContent = `耗时 ${p.elapsed_ms} ms · ${p.checked_at}`;
    $("purityCheckedAtInline").textContent = `检测于 ${p.checked_at}`;

    $("purityGrade").className = `grade-badge ${p.risk_level || ""}`;
    $("purityGrade").textContent = p.grade || "—";
    $("purityVerdictTitle").textContent = p.verdict_title || "";
    $("purityVerdictDetail").textContent = p.verdict_detail || "";

    const score = p.fraud_score !== null && p.fraud_score !== undefined ? Number(p.fraud_score) : null;
    const purity = score !== null ? Math.max(0, 100 - score) : null;
    $("purityScoreNum").textContent = score !== null ? `${score} / 100` : "未获取";
    setNumber($("purityScoreRing"), purity);
    setRing($("purityRingBar"), purity === null ? 0 : purity / 100);
    $("purityRing").dataset.level = p.risk_level || "unknown";

    const resCard = p.is_residential === true && p.is_hosting !== true
      ? { cls: "pass", val: "原生住宅家宽", sub: "IPPure 标记为住宅网络" }
      : (p.is_residential === false || p.is_hosting === true
        ? { cls: "warn", val: "机房 / 数据中心", sub: "Hosting / IDC 网段" }
        : { cls: "", val: "待确认", sub: "暂无明确住宅标记" });

    const nativeCard = p.is_broadcast === false
      ? { cls: "pass", val: "原生 IP", sub: "注册地与落地点一致" }
      : (p.is_broadcast === true
        ? { cls: "warn", val: "广播 IP", sub: "跨区广播网段" }
        : { cls: "", val: "未知", sub: "IPPure 未返回" });

    const proxyCard = p.is_proxy === true
      ? { cls: "fail", val: "命中代理库", sub: "数据源标记该 IP 为代理" }
      : (p.is_proxy === false
        ? { cls: "pass", val: "未命中代理库", sub: "数据源无代理标记" }
        : { cls: "", val: "未知", sub: "当前数据源无该属性" });

    const exitChannel = state.data?.report?.exit_info?.path === PROBE_PATH ? "Guard-Probe" : "通用 TUN";
    const cards = [
      { k: "网络类型", ...resCard },
      { k: "IP 归属属性", ...nativeCard },
      { k: "匿名 / 代理库", ...proxyCard },
      { k: "探测通道", cls: "pass", val: exitChannel, sub: "已同步当前节点出口结果" },
    ];
    $("purityAttrGrid").innerHTML = cards
      .map(
        (c) => `
          <div class="attr-card ${c.cls}">
            <div class="attr-k">${escapeHtml(c.k)}</div>
            <div class="attr-v">${escapeHtml(c.val)}</div>
            <div class="attr-sub">${escapeHtml(c.sub)}</div>
          </div>`
      )
      .join("");

    $("puritySignals").innerHTML = (p.signals || [])
      .map(
        (s) => `
          <div class="signal-row">
            <span class="signal-label">${escapeHtml(s.label)}</span>
            <span class="signal-val ${escapeHtml(s.level)}">${escapeHtml(s.value)}</span>
            <span class="signal-note">${escapeHtml(s.note)}</span>
          </div>`
      )
      .join("");

    const errBox = $("purityErrors");
    if (p.errors && p.errors.length > 0) {
      errBox.textContent = "部分数据源异常：" + p.errors.join("；");
      errBox.classList.remove("hidden");
    } else {
      errBox.classList.add("hidden");
    }
  }

  function resetPurityView(message) {
    $("purityMeta").textContent = message || "当前无法体检";
    $("purityGrade").className = "grade-badge";
    $("purityGrade").textContent = "—";
    $("purityVerdictTitle").textContent = "未获得本次体检结果";
    $("purityVerdictDetail").textContent = "";
    $("purityAsnFooter").textContent = "";
    $("purityCheckedAt").textContent = "";
    $("purityCheckedAtInline").textContent = "";
    $("purityScoreNum").textContent = "未知";
    $("purityScoreRing").textContent = "--";
    $("purityScoreRing").dataset.target = "--";
    $("purityRing").dataset.level = "unknown";
    setRing($("purityRingBar"), 0);
    $("purityAttrGrid").replaceChildren();
    $("puritySignals").replaceChildren();
    $("purityErrors").classList.add("hidden");
  }

  function resolveMascotState() {
    const report = state.data?.report;
    const overall = report?.overall || "";

    // 1. 正在执行的即时任务优先级最高（逐项区分语义，避免误显示「执行配置中」）
    if (state.purityRunning) return { key: "searching", label: "联网体检中" };
    if (state.pending.has("run_doctor")) return { key: "scanning", label: "巡检扫描中" };
    if (state.pending.has("check_update")) return { key: "searching", label: "检查更新中" };
    if (state.pending.has("install_update")) return { key: "working", label: "下载更新中" };
    if (state.pending.has("run_rescue")) return { key: "working", label: "紧急恢复中" };
    if (state.pending.has("kill_claude_app")) return { key: "working", label: "关闭客户端中" };
    if (state.pending.has("get_override_script")) return { key: "reading", label: "读取脚本中" };
    if (state.pending.has("elevate")) return { key: "working", label: "提权重启中" };
    if (state.pending.has("quit_app")) return { key: "idle", label: "准备退出中" };

    const SILENT_ACTIONS = new Set(["open_author_page", "open_release_page", "open_clash_dir"]);
    if ([...state.pending].some((m) => !SILENT_ACTIONS.has(m))) {
      return { key: "working", label: "执行配置中" };
    }

    // 2. 高危红灯异常绝不被页面态或闲置打盹掩盖（仅允许用户主动点击彩蛋临时覆盖）
    if (state.mascotFlash && (state.mascotFlash.priority || (overall !== "red" && !state.scanError))) {
      return state.mascotFlash;
    }
    if (state.scanError || overall === "red") return { key: "error", label: "检测到异常" };

    // 3. 当前弹窗或子页面语境
    if ($("scriptModal")?.open || $("updateModal")?.open) return { key: "reading", label: "查看详情中" };
    if (state.activeView === "diagnostics") return { key: "testing", label: "逐项核查中" };
    if (state.activeView === "purity") return { key: "searching", label: "准备 IP 体检" };
    if (state.activeView === "audit") return { key: "reading", label: "翻阅日志中" };

    // 4. 长时间无操作且无告警时自动打盹
    if (state.mascotAsleep && overall !== "yellow") return { key: "asleep", label: "安稳打盹中" };

    // 5. 常驻防护状态
    if (overall === "yellow") return { key: "warn", label: "存在提醒项" };
    if (overall === "green") return { key: "done", label: "防护状态正常" };
    return { key: "idle", label: "待命守护中" };
  }

  function syncMascot() {
    const next = resolveMascotState();
    const img = $("mascotImg");
    if (img && img.dataset.state !== next.key) {
      img.dataset.state = next.key;
      img.src = "mascot/" + next.key + ".svg";
    }
    const caption = $("mascotCaption");
    if (caption && caption.textContent !== next.label) {
      caption.textContent = next.label;
      const bubble = $("mascotBubble");
      if (bubble) {
        bubble.classList.remove("is-pop");
        void bubble.offsetWidth;
        bubble.classList.add("is-pop");
      }
    }
  }

  function flashMascot(key, label, durationMs = 3600, priority = false) {
    clearTimeout(state.mascotFlashTimer);
    state.mascotAsleep = false;
    state.mascotFlash = { key, label, priority };
    syncMascot();
    state.mascotFlashTimer = setTimeout(() => {
      state.mascotFlash = null;
      syncMascot();
    }, durationMs);
  }

  function resetMascotIdleTimer() {
    clearTimeout(state.mascotIdleTimer);
    if (state.mascotAsleep) {
      state.mascotAsleep = false;
      syncMascot();
    }
    state.mascotIdleTimer = setTimeout(() => {
      state.mascotAsleep = true;
      syncMascot();
    }, MASCOT_IDLE_MS);
  }

  function switchView(id) {
    state.activeView = id;
    for (const view of document.querySelectorAll(".view")) view.hidden = view.id !== id;
    for (const item of document.querySelectorAll("nav [data-view]")) {
      if (item.dataset.view === id) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    }
    const main = document.querySelector("main");
    main.scrollTop = 0;
    main.focus({ preventScroll: true });
    syncMascot();
  }

  function openPrimaryIssue() {
    switchView("diagnostics");
    const item = $("checkList").querySelector('[data-check-id="' + CSS.escape(state.primaryIssue) + '"]');
    if (!item) return;
    const row = item.querySelector(".check-row");
    if (row.matches("button")) {
      state.expandedIds.set(state.primaryIssue, true);
      item.classList.add("expanded");
      row.setAttribute("aria-expanded", "true");
      row.focus({ preventScroll: true });
    } else {
      item.tabIndex = -1;
      item.focus({ preventScroll: true });
    }
    item.scrollIntoView({ block: "nearest" });
  }

  async function runPurityCheck() {
    if (!window.pywebview || !window.pywebview.api) {
      toast("桌面桥接尚未就绪，请稍候重试", "error");
      return;
    }
    const btn = $("btnRunPurity");
    const lbl = $("btnRunPurityLabel");
    if (btn.disabled) return;
    btn.disabled = true;
    state.purityRunning = true;
    syncMascot();
    btn.classList.add("is-spinning");
    if (lbl) lbl.textContent = "检测中…";

    const purityView = $("purity");
    if (purityView) purityView.classList.add("is-loading");
    $("purityRing").dataset.level = "loading";
    $("purityScoreRing").textContent = "…";
    $("purityScoreRing").dataset.target = "--";
    $("purityGrade").className = "grade-badge";
    $("purityGrade").textContent = "…";
    $("purityVerdictTitle").textContent = "正在检测当前出口纯净度…";
    $("purityVerdictDetail").textContent = "正在并发查询 IPPure 风险评分与出口归属地，请稍候…";
    $("purityMeta").textContent = "正在连接检测数据源…";
    $("purityAsnFooter").textContent = "";
    $("purityCheckedAt").textContent = "";
    $("purityCheckedAtInline").textContent = "实时检测中…";
    $("purityScoreNum").textContent = "检测中…";
    $("purityErrors").classList.add("hidden");
    $("purityAttrGrid").innerHTML = Array.from({ length: 4 }, () => `
      <div class="attr-card is-skeleton" aria-hidden="true">
        <div class="skel-line w-45"></div>
        <div class="skel-line w-70 lg"></div>
        <div class="skel-line w-85"></div>
      </div>`).join("");
    $("puritySignals").innerHTML = `
      <div class="purity-loading" role="status" aria-live="polite">
        <span class="purity-spinner" aria-hidden="true"></span>
        <span>正在通过当前通道实时请求 IPPure 与出口地理数据库…</span>
      </div>`;

    try {
      const res = await window.pywebview.api.check_ip_purity();
      if (res && typeof res === "object") {
        render(res);
        if (!res.purity) resetPurityView(res.message);
        if (res.message) toast(res.message, res.ok === false ? "error" : "ok");
        flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "体检未通过" : "体检已完成", 3200);
      }
    } catch (err) {
      resetPurityView("体检请求异常，请重试");
      flashMascot("error", "体检出错啦", 3200);
      toast(`纯净度体检失败：${err}`, "error");
    } finally {
      if (purityView) purityView.classList.remove("is-loading");
      state.purityRunning = false;
      btn.disabled = false;
      btn.classList.remove("is-spinning");
      if (lbl) lbl.textContent = "重新体检";
      syncMascot();
    }
  }

  function renderUpdateState(update, progress) {
    const avail = Boolean(update?.available);
    const rawLatest = String(update?.latest_version || "").replace(/^v/i, "");
    const verLabel = rawLatest ? `v${rawLatest}` : "";

    const badgeBtn = $("btnUpdateBadge");
    if (badgeBtn) {
      badgeBtn.hidden = !avail;
      setText("updateBadgeLabel", verLabel ? `新版 ${verLabel}` : "新版");
    }
    const menuDot = $("toolMenuDot");
    if (menuDot) menuDot.hidden = !avail;
    const menuBadge = $("menuUpdateBadge");
    if (menuBadge) {
      menuBadge.hidden = !avail;
      menuBadge.textContent = verLabel || "NEW";
    }

    const curVer = String(update?.current_version || state.data?.version || "—").replace(/^v/i, "");
    setText("updateCurrentVer", `v${curVer}`);
    setText("updateLatestVer", avail && verLabel ? verLabel : "已是最新");
    setText("updateTitle", avail && verLabel ? `发现新版本 ${verLabel}` : "版本更新检查");
    setText("updateNotes", update?.notes || (avail ? "包含稳定性优化与防泄漏保护更新。" : "当前已是最新版本。"));

    const sha = String(update?.sha256 || "");
    const shaNode = $("updateSha");
    if (shaNode) {
      shaNode.textContent = sha ? `${sha.slice(0, 16)}…${sha.slice(-8)}` : "—";
      shaNode.title = sha;
    }

    const wrap = $("updateProgressWrap");
    const active = Boolean(progress && progress.stage);
    if (wrap) wrap.hidden = !active;
    if (active) {
      const pct = Math.max(0, Math.min(100, Number(progress.percent || 0)));
      const bar = $("updateProgressBar");
      if (bar) bar.style.width = `${pct}%`;
      setText("updateProgressPct", `${pct}%`);
      const stageLabels = {
        downloading: progress.total > 0
          ? `正在下载 (${(progress.downloaded / 1048576).toFixed(1)} / ${(progress.total / 1048576).toFixed(1)} MB)…`
          : "正在下载更新包…",
        verifying: "正在校验 SHA-256 完整性…",
        restarting: "校验通过，正在覆盖并自动重启…",
      };
      setText("updateProgressText", stageLabels[progress.stage] || "正在处理更新…");
    }

    const installBtn = $("btnInstallUpdate");
    if (installBtn) {
      const busy = state.pending.has("install_update") || active;
      const canSelf = Boolean(update?.can_self_update);
      installBtn.disabled = !avail || !canSelf || busy;
      installBtn.textContent = busy
        ? "更新中…"
        : avail && !canSelf
          ? "源码模式请手动下载"
          : state.data?.platform === "macos" ? "下载签名安装包" : "一键更新并重启";
    }
  }

  function renderLogs(logs) {
    const list = $("logList");
    list.innerHTML = logs
      .map(
        (entry) => `
          <div class="log-entry">
            <span class="log-time">${escapeHtml(entry.time)}</span>
            <span class="log-dot ${escapeHtml(entry.level)}"></span>
            <span class="log-msg">${escapeHtml(entry.message)}</span>
          </div>`
      )
      .join("") || '<p class="empty">等待首条记录</p>';
  }

  function renderApiState(payload) {
    try {
      render(payload);
    } catch (err) {
      console.error("无法渲染桌面状态", err);
      toast("界面刷新失败，可退出 Claude Guard 后重新打开。", "error");
    }
  }

  async function callApi(method, ...args) {
    if (!window.pywebview || !window.pywebview.api) {
      toast("桌面桥接尚未就绪，请稍候重试", "error");
      return null;
    }
    if (state.pending.has(method)) return null;
    state.pending.add(method);
    updatePendingControls();
    if (method === "run_doctor") {
      state.scanError = "";
      renderOverviewStatus();
    } else {
      syncMascot();
    }
    try {
      let res;
      try {
        res = await window.pywebview.api[method](...args);
      } catch (err) {
        if (method === "run_doctor") state.scanError = String(err?.message || err);
        else if (state.data) renderApiState(state.data);
        flashMascot("error", "执行失败", 3000);
        toast("调用失败：" + (err?.message || err), "error");
        return null;
      }
      if (method === "run_doctor" && (!res || res.ok === false || !res.report)) {
        state.scanError = res?.message || "未收到巡检结果，请重试。";
      }
      if (res && res.message && (method !== "get_override_script" || !res.ok)) {
        toast(res.message, res.ok === false ? "error" : "ok");
      }
      const SKIP_FLASH = new Set([
        "run_doctor", "get_override_script", "open_author_page",
        "open_release_page", "open_clash_dir", "elevate", "quit_app",
      ]);
      if (res && !SKIP_FLASH.has(method)) {
        if (method === "check_update") {
          if (res.ok === false) flashMascot("error", "检查更新失败", 2800);
          else if (res.update?.available) flashMascot("done", "发现新版本", 3000);
          else flashMascot("done", "已是最新版", 2600);
        } else if (method === "install_update") {
          flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "更新未完成" : state.data?.platform === "macos" ? "已打开下载" : "即将重启更新", 2800);
        } else if (method === "toggle_webrtc" && state.data?.platform === "macos") {
          flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "无法打开配置" : "请在系统设置确认", 2800);
        } else if (method === "run_rescue") {
          flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "恢复未完成" : "已恢复默认", 2800);
        } else if (method === "kill_claude_app") {
          flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "未完成关闭" : "已安全关闭", 2800);
        } else {
          flashMascot(res.ok === false ? "error" : "done", res.ok === false ? "配置未完成" : "配置已生效", 2800);
        }
      }
      if (res && typeof res === "object" && "report" in res) renderApiState(res);
      return res;
    } finally {
      state.pending.delete(method);
      updatePendingControls();
      if (method === "run_doctor") renderOverviewStatus();
      else syncMascot();
    }
  }

  // 接收后端后台看门狗或托盘触发的实时状态推送
  window.__onGuardPush = (payload) => {
    if (payload && ("report" in payload || "config" in payload)) renderApiState(payload);
    if (payload?.tray_action && payload.message) {
      toast(payload.message, payload.ok === false ? "error" : "ok");
    }
    if (payload?.open_update_modal) {
      renderUpdateState(state.data?.update, state.data?.update_progress);
      const modal = $("updateModal");
      if (modal && !modal.open) modal.showModal();
    }
  };

  async function showOverrideScript() {
    const res = await callApi("get_override_script");
    if (!res?.ok) return;
    setText("scriptPath", res.path);
    setText("scriptCode", res.content);
    $("scriptModal").showModal();
    syncMascot();
  }

  function bindEvents() {
    document.querySelectorAll("[data-view]").forEach((button) => {
      button.addEventListener("click", () => switchView(button.dataset.view));
    });
    $("btnRunPurity").addEventListener("click", () => runPurityCheck());
    $("btnDoctor").addEventListener("click", () => callApi("run_doctor"));
    $("btnViewIssue").addEventListener("click", openPrimaryIssue);
    $("btnEnableAll").addEventListener("click", () => callApi("enable_all_protection"));
    $("btnLockIp").addEventListener("click", () => callApi("toggle_ip_monitor", !state.data.config.monitored_probe_ip));
    $("btnAlignTz").addEventListener("click", () => callApi("align_timezone"));
    $("btnRestoreTz").addEventListener("click", () => callApi("restore_timezone"));

    $("privPill").addEventListener("click", () => {
      if (state.data && !state.data.is_admin) callApi("elevate");
    });

    $("swKillswitch").addEventListener("change", async (ev) => {
      const target = ev.target.checked;
      if (!target) {
        const confirmed = await showConfirm(
          "关闭防火墙断网锁？",
          "关闭 Kill Switch 后，若 Clash Verge TUN 意外崩溃或关闭，Claude 可能会通过物理网卡直接暴露真实 IP。\n\n确定关闭防直连规则吗？",
          "确认关闭"
        );
        if (!confirmed) {
          ev.target.checked = true;
          return;
        }
      }
      await callApi("toggle_killswitch", target);
    });

    $("swDns").addEventListener("change", (ev) => callApi("toggle_dns_lock", ev.target.checked));
    $("swWebrtc").addEventListener("change", (ev) => callApi("toggle_webrtc", ev.target.checked));
    $("swIpv6").addEventListener("change", (ev) => callApi("toggle_ipv6", ev.target.checked));
    $("btnKillClaude").addEventListener("click", () => callApi("kill_claude_app"));
    $("btnLaunchClaude").addEventListener("click", () => callApi("launch_claude_app"));
    $("swAlertSound").addEventListener("change", (ev) => callApi("toggle_alert_sound", ev.target.checked));
    $("swAutoKill").addEventListener("change", (ev) => callApi("toggle_auto_kill_claude", ev.target.checked));
    $("swAutostart").addEventListener("change", (ev) => callApi("toggle_autostart", ev.target.checked));

    const mascotCard = $("railMascot");
    const hopMascot = () => {
      if (!mascotCard) return;
      mascotCard.classList.remove("is-hop");
      void mascotCard.offsetWidth;
      mascotCard.classList.add("is-hop");
      const egg = MASCOT_EGGS[state.mascotEggIndex % MASCOT_EGGS.length];
      state.mascotEggIndex += 1;
      flashMascot(egg.key, egg.label, 4200, true);
    };
    mascotCard?.addEventListener("click", hopMascot);
    mascotCard?.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        hopMascot();
      }
    });
    for (const evt of ["pointerdown", "keydown", "wheel"]) {
      window.addEventListener(evt, resetMascotIdleTimer, { passive: true });
    }

    $("btnRescue").addEventListener("click", async () => {
      const confirmed = await showConfirm(
        "执行紧急网络恢复 (Rescue)",
        state.data?.platform === "macos"
          ? "将按备份恢复 DNS、IPv6 和时区，并移除本应用的过滤配置。若已安装 WebRTC 描述文件，请在系统设置中移除它。"
          : "将删除 Claude Guard 的断网锁规则，并按备份恢复 DNS、WebRTC、IPv6 和时区。\n\n未完成的恢复项目会保留备份，可在日志中查看详情。",
        "立即恢复"
      );
      if (confirmed) await callApi("run_rescue");
    });

    $("btnOverride").addEventListener("click", showOverrideScript);
    $("btnConfigureProbe").addEventListener("click", showOverrideScript);
    $("btnUpdateBadge")?.addEventListener("click", () => {
      renderUpdateState(state.data?.update, state.data?.update_progress);
      $("updateModal")?.showModal();
    });
    $("btnCheckUpdate")?.addEventListener("click", async () => {
      const menu = $("toolMenu");
      if (menu) menu.open = false;
      const res = await callApi("check_update");
      if (res?.update?.available) $("updateModal")?.showModal();
    });
    $("btnInstallUpdate")?.addEventListener("click", () => callApi("install_update"));
    $("btnOpenRelease")?.addEventListener("click", () => callApi("open_release_page"));
    $("btnAbout")?.addEventListener("click", () => {
      const menu = $("toolMenu");
      if (menu) menu.open = false;
      $("aboutModal")?.showModal();
    });

    async function copyText(text, hostDialog) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.cssText = "position:fixed;opacity:0;pointer-events:none";
        (hostDialog || document.body).appendChild(ta);
        ta.select();
        try {
          return Boolean(document.execCommand("copy"));
        } catch {
          return false;
        } finally {
          ta.remove();
        }
      }
    }

    $("btnOpenDouyin")?.addEventListener("click", () => callApi("open_author_page"));

    $("btnCopyScript").addEventListener("click", async () => {
      const script = $("scriptCode").textContent;
      if (!script) return;
      const copied = await copyText(script, $("scriptModal"));
      $("btnCopyScript").focus();
      if (!copied) {
        $("scriptCode").closest("details").open = true;
        toast("无法访问剪贴板，请在脚本预览中手动复制。", "error");
        return;
      }
      toast("已复制脚本，可到 Clash Verge 粘贴并应用。", "ok");
    });

    $("btnOpenClashDir").addEventListener("click", () => callApi("open_clash_dir"));

    $("btnQuit").addEventListener("click", async () => {
      const confirmed = await showConfirm(
        "彻底退出 Claude Guard？",
        "退出后托盘状态灯与 60 秒后台漂移监控将停止（已写入的防火墙规则仍保持生效，除非执行 Rescue）。",
        "退出程序"
      );
      if (confirmed) await callApi("quit_app");
    });

    $("btnConfirmCancel").addEventListener("click", () => closeConfirm(false));
    $("btnConfirmOk").addEventListener("click", () => closeConfirm(true));

    document.querySelectorAll("[data-close-modal]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-close-modal");
        if (id === "confirmModal") closeConfirm(false);
        else $(id).close();
      });
    });

    for (const dialog of document.querySelectorAll("dialog")) {
      dialog.addEventListener("close", () => {
        if (dialog.contains($("toastStack"))) document.body.appendChild($("toastStack"));
        syncMascot();
      });
    }
    $("confirmModal").addEventListener("cancel", (event) => {
      event.preventDefault();
      closeConfirm(false);
    });
  }

  async function bootstrap() {
    try {
      renderApiState(await window.pywebview.api.get_initial_state());
    } catch {
      // The first scan can still populate the window if the initial state request fails.
    }
    await callApi("run_doctor");
  }

  bindEvents();
  initTooltips();
  flashMascot("greeting", "你好，开始守护", 3800);
  resetMascotIdleTimer();
  if (window.pywebview && window.pywebview.api) {
    bootstrap();
  } else {
    window.addEventListener("pywebviewready", bootstrap, { once: true });
  }
})();
