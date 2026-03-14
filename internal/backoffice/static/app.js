// Juno Bridge Backoffice — vanilla JS controller
// No build step required. Periodically fetches JSON APIs and updates DOM.
(function () {
  "use strict";

  // --- Helpers ---
  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

  function escapeHTML(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function fmtAddr(hex) {
    if (!hex || hex.length < 12) return escapeHTML(hex) || "-";
    var safe = escapeHTML(hex);
    return '<span class="addr" title="' + safe + '" onclick="navigator.clipboard.writeText(\'' + safe + '\')" style="cursor:pointer">' +
      safe.slice(0, 6) + "\u2026" + safe.slice(-4) + '</span>';
  }

  function fmtETH(wei) {
    if (wei === undefined || wei === null) return "-";
    var n = typeof wei === "string" ? parseFloat(wei) : wei;
    if (isNaN(n)) return "-";
    return (n / 1e18).toFixed(4) + " ETH";
  }

  function fmtTime(ts) {
    if (!ts) return "-";
    var d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString();
  }

  function badge(severity) {
    var cls = { critical: "badge-crit", warning: "badge-warn", ok: "badge-ok", info: "badge-info" };
    var safe = escapeHTML(severity);
    return '<span class="badge ' + (cls[severity] || "badge-info") + '">' + safe + "</span>";
  }

  function dot(ok) { return '<span class="dot ' + (ok ? "dot-ok" : "dot-err") + '"></span>'; }

  function stateBadge(state) {
    if (!state) return badge("info");
    var s = String(state);
    if (s === "finalized") return '<span class="badge badge-ok">' + escapeHTML(s) + "</span>";
    if (s === "rejected") return '<span class="badge badge-crit">' + escapeHTML(s) + "</span>";
    if (s === "unknown") return '<span class="badge badge-info">' + escapeHTML(s) + "</span>";
    return '<span class="badge badge-warn">' + escapeHTML(s) + "</span>";
  }

  function setHTML(id, html) {
    var el = document.getElementById(id);
    if (el) el.innerHTML = html;
  }

  function setText(id, txt) {
    var el = document.getElementById(id);
    if (el) el.textContent = txt;
  }

  function show(id) { var el = document.getElementById(id); if (el) el.classList.remove("hidden"); }
  function hide(id) { var el = document.getElementById(id); if (el) el.classList.add("hidden"); }

  // Auth token is read from a meta tag or localStorage. The backoffice API
  // requires Bearer auth on all non-healthz endpoints.
  function authHeaders() {
    var token = localStorage.getItem("bo_token") || "";
    if (!token) {
      var meta = document.querySelector('meta[name="bo-token"]');
      if (meta) token = meta.getAttribute("content") || "";
    }
    var h = { "Accept": "application/json" };
    if (token) h["Authorization"] = "Bearer " + token;
    return h;
  }

  function apiFetch(path, cb) {
    fetch("/api" + path, { headers: authHeaders() })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(cb)
      .catch(function (e) { console.error("API error " + path, e); });
  }

  function apiPost(path, body, cb) {
    fetch("/api" + path, {
      method: "POST",
      headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
      body: body ? JSON.stringify(body) : undefined,
    })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(cb)
      .catch(function (e) { console.error("API POST error " + path, e); });
  }

  function apiPut(path, body, cb) {
    fetch("/api" + path, {
      method: "PUT",
      headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
      body: JSON.stringify(body || {}),
    })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(cb)
      .catch(function (e) { console.error("API PUT error " + path, e); });
  }

  // --- Tab navigation ---
  function initTabs() {
    $$(".tab").forEach(function (a) {
      a.addEventListener("click", function (e) {
        e.preventDefault();
        $$(".tab").forEach(function (t) { t.classList.remove("active"); });
        a.classList.add("active");
        $$(".tab-content").forEach(function (s) { s.classList.remove("active"); });
        var target = a.getAttribute("data-tab");
        var sec = document.getElementById(target);
        if (sec) sec.classList.add("active");
      });
    });
  }

  function initSubTabs() {
    $$(".sub-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var group = btn.closest(".sub-tabs");
        group.querySelectorAll(".sub-tab").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
        var parent = group.parentElement;
        parent.querySelectorAll(".sub-content").forEach(function (c) { c.classList.remove("active"); });
        var target = btn.getAttribute("data-sub");
        var el = parent.querySelector('[data-sub-id="' + target + '"]');
        if (el) el.classList.add("active");
      });
    });
  }

  // --- Overview ---
  function refreshOverview() {
    apiFetch("/analytics/overview", function (d) {
      setText("stat-total-deposits", d.totalDeposits || 0);
      setText("stat-total-withdrawals", d.totalWithdrawals || 0);
      setText("stat-deposits-today", d.depositsToday || 0);
      setText("stat-withdrawals-today", d.withdrawalsToday || 0);
      setText("stat-wjuno-supply", d.activeWjunoSupply || "0");
    });

    // Operator status
    apiFetch("/ops/operators/status", function (resp) {
      var ops = (resp && resp.operators) || [];
      var html = "";
      ops.forEach(function (op) {
        html += '<div>' + dot(op.online) + ' <span class="mono">' + fmtAddr(op.address) + '</span> ' +
          escapeHTML(op.endpoint) + ' (' + escapeHTML(op.latencyMs) + 'ms)</div>';
      });
      setHTML("operator-status-grid", html || '<span class="loading">No operators configured</span>');
    });

    // Service health
    apiFetch("/ops/services/health", function (resp) {
      var html = "";
      var services = (resp && resp.data) || [];
      services.forEach(function (svc) {
        html += '<div class="svc-row">' + dot(svc.healthy) +
          '<strong>' + escapeHTML(svc.label || svc.url) + '</strong>' +
          ' <span class="mono dim">' + escapeHTML(svc.url) + '</span>' +
          (svc.healthy ? ' <span class="dim">(' + svc.latencyMs + 'ms)</span>' :
           ' <span class="badge-crit">' + escapeHTML(svc.error || 'down') + '</span>') +
          '</div>';
      });
      setHTML("svc-health-grid", html || '<span class="loading">No services reported</span>');
    });

    // Active alerts count for overview
    apiFetch("/alerts/count", function (resp) {
      var ac = (resp && resp.data && resp.data.count) || 0;
      setText("overview-alert-count", ac);
      if (ac > 0) { show("overview-alert-box"); } else { hide("overview-alert-box"); }
    });
  }

  // --- DLQ ---
  var dlqFilter = { acknowledged: "false" };
  function refreshDLQ(kind) {
    kind = kind || "proofs";
    var qs = "?acknowledged=" + dlqFilter.acknowledged;
    apiFetch("/dlq/" + kind + qs, function (resp) {
      var items = (resp && resp.data) || [];
      var rows = items.map(function (r) {
        var id = r.jobId || r.batchId || r.id || "";
        return "<tr>" +
          '<td class="mono">' + fmtAddr(id) + "</td>" +
          "<td>" + escapeHTML(r.errorCode || "-") + "</td>" +
          "<td>" + escapeHTML(r.failureStage || r.pipeline || "-") + "</td>" +
          "<td>" + escapeHTML(r.attemptCount || 0) + "</td>" +
          "<td>" + escapeHTML(fmtTime(r.createdAt)) + "</td>" +
          "<td>" + (r.acknowledged ? badge("ok") : badge("warning")) + "</td>" +
          "<td>" + (r.acknowledged ? "" : '<button class="small" onclick="ackDLQ(\'' + escapeHTML(kind) + "','" + escapeHTML(id) + "')\">" + "Ack</button>") + "</td>" +
          "</tr>";
      }).join("");
      setHTML("dlq-tbody-" + kind, rows || '<tr><td colspan="7" class="loading">No records</td></tr>');
    });
  }

  window.ackDLQ = function (kind, id) {
    apiPost("/dlq/" + kind + "/" + encodeURIComponent(id) + "/acknowledge", null, function () { refreshDLQ(kind); });
  };

  // --- Funds ---
  function refreshFunds() {
    apiFetch("/funds", function (d) {
      // Operator gas
      var ops = (d.operators || []).map(function (o) {
        var st = o.belowThreshold ? badge("crit") : badge("ok");
        return "<tr>" +
          '<td class="mono">' + fmtAddr(o.address) + copyBtn(o.address) + "</td>" +
          "<td>" + escapeHTML(o.balanceEth || fmtETH(o.balanceWei)) + "</td>" +
          "<td>" + st + "</td></tr>";
      }).join("");
      setHTML("funds-ops-tbody", ops || '<tr><td colspan="3" class="loading">-</td></tr>');
      // Prover
      if (d.prover) {
        setText("prover-addr", fmtAddr(d.prover.address));
        if (d.prover.error) {
          setText("prover-balance", "Error: " + d.prover.error);
        } else if (d.prover.network === "succinct") {
          setText("prover-balance", (d.prover.creditsFormatted || d.prover.creditsRaw || "0") + " credits");
        } else {
          setText("prover-balance", d.prover.balanceEth || fmtETH(d.prover.balanceWei));
        }
      }
      // Bridge escrow
      if (d.bridge) {
        setText("escrow-wjuno", d.bridge.wjunoBalanceFormatted || d.bridge.wjunoBalanceRaw || "0");
      }
      // MPC wallet
      if (d.mpcWallet && !d.mpcWallet.error) {
        setText("mpc-balance", d.mpcWallet.total || "0");
      }
    });
  }

  // --- Settings ---
  function showSettingsStatus(kind, message) {
    var el = document.getElementById("settings-status");
    if (!el) return;
    el.classList.remove("hidden");
    el.style.borderColor = kind === "error" ? "var(--crit)" : "var(--ok)";
    el.innerHTML = '<strong>' + escapeHTML(kind === "error" ? "Error" : "Updated") + ':</strong> ' + escapeHTML(message);
  }

  function refreshSettings() {
    apiFetch("/settings/runtime", function (resp) {
      var d = (resp && resp.data) || {};
      setText("settings-min-deposit", d.minDepositAmount || "-");
      setText("settings-min-deposit-admin", d.minDepositAdmin || "-");
      setText("settings-deposit-conf", d.depositMinConfirmations || "-");
      setText("settings-withdraw-planner-conf", d.withdrawPlannerMinConfirmations || "-");
      setText("settings-withdraw-batch-conf", d.withdrawBatchConfirmations || "-");

      var depositInput = document.getElementById("settings-input-deposit-conf");
      var plannerInput = document.getElementById("settings-input-withdraw-planner-conf");
      var batchInput = document.getElementById("settings-input-withdraw-batch-conf");
      var minDepositInput = document.getElementById("settings-input-min-deposit");
      if (depositInput && document.activeElement !== depositInput) depositInput.value = d.depositMinConfirmations || "";
      if (plannerInput && document.activeElement !== plannerInput) plannerInput.value = d.withdrawPlannerMinConfirmations || "";
      if (batchInput && document.activeElement !== batchInput) batchInput.value = d.withdrawBatchConfirmations || "";
      if (minDepositInput && document.activeElement !== minDepositInput) minDepositInput.value = d.minDepositAmount || "";

      var audit = (resp && resp.audit) || [];
      var rows = audit.map(function (entry) {
        return "<tr>" +
          "<td>" + escapeHTML(fmtTime(entry.updatedAt)) + "</td>" +
          "<td>" + escapeHTML(entry.settingKey || "-") + "</td>" +
          "<td>" + escapeHTML(entry.oldValue || "-") + "</td>" +
          "<td>" + escapeHTML(entry.newValue || "-") + "</td>" +
          '<td class="mono">' + (entry.txHash ? fmtAddr(entry.txHash) : "-") + "</td>" +
          "<td>" + escapeHTML(entry.updatedBy || "-") + "</td></tr>";
      }).join("");
      setHTML("settings-audit-tbody", rows || '<tr><td colspan="6" class="loading">No settings changes yet</td></tr>');
    });
  }

  function copyBtn(addr) {
    var safe = escapeHTML(addr);
    return ' <button class="copy-btn" onclick="copyAddr(\'' + safe + '\')" title="Copy address">copy</button>';
  }

  window.copyAddr = function (addr) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(addr);
    }
  };

  // --- Analytics ---
  function refreshAnalytics() {
    apiFetch("/analytics/overview", function (d) {
      setText("vol-deposit-total", d.totalDepositVolume || "0");
      setText("vol-withdraw-total", d.totalWithdrawalVolume || "0");
    });

    apiFetch("/analytics/bridges-over-time", function (resp) {
      var days = (resp && resp.data) || [];
      var maxVal = 1;
      days.forEach(function (r) {
        var total = (r.depositCount || 0) + (r.withdrawalCount || 0);
        if (total > maxVal) maxVal = total;
      });
      var html = days.map(function (r) {
        var total = (r.depositCount || 0) + (r.withdrawalCount || 0);
        var pct = Math.round((total / maxVal) * 100);
        return '<div class="bar-row"><span class="label">' + escapeHTML(r.date) + '</span>' +
          '<div class="bar" style="width:' + pct + '%"></div>' +
          '<span class="bar-val">' + escapeHTML(total) + '</span></div>';
      }).join("");
      setHTML("daily-chart", html || '<span class="loading">No data</span>');
    });

    apiFetch("/analytics/operator-revenue", function (resp) {
      var items = (resp && resp.data) || [];
      var rows = items.map(function (r) {
        return "<tr>" +
          '<td class="mono">' + fmtAddr(r.operatorAddress) + "</td>" +
          '<td class="mono">' + fmtAddr(r.feeRecipient) + "</td>" +
          "<td>" + escapeHTML(r.accumulatedFeesFormatted || r.accumulatedFees || "0") + "</td>" +
          "<td>" + escapeHTML(r.claimedFeesFormatted || r.claimedFees || "0") + "</td>" +
          "<td>" + escapeHTML(r.pendingFeesFormatted || r.pendingFees || "0") + "</td></tr>";
      }).join("");
      setHTML("revenue-tbody", rows || '<tr><td colspan="5" class="loading">-</td></tr>');
    });
  }

  // --- Alerts ---
  function refreshAlerts() {
    apiFetch("/alerts/active", function (resp) {
      var items = (resp && resp.data) || [];
      var count = items.length;
      setText("alert-badge", count);
      if (count > 0) { show("alert-badge"); } else { hide("alert-badge"); }
      var rows = items.map(function (a) {
        return "<tr>" +
          "<td>" + badge(a.severity) + "</td>" +
          "<td>" + escapeHTML(a.title || "") + "</td>" +
          "<td>" + escapeHTML(a.detail || "") + "</td>" +
          "<td>" + escapeHTML(fmtTime(a.fired_at)) + "</td>" +
          "<td>" + (a.acknowledged_at ? "Yes" : '<button class="small" onclick="ackAlert(\'' + escapeHTML(a.id) + '\')">Ack</button>') + "</td></tr>";
      }).join("");
      setHTML("alerts-active-tbody", rows || '<tr><td colspan="5" class="loading">No active alerts</td></tr>');
    });

    apiFetch("/alerts/history?limit=50", function (resp) {
      var items = (resp && resp.data) || [];
      var rows = items.map(function (a) {
        return "<tr>" +
          "<td>" + badge(a.severity) + "</td>" +
          "<td>" + escapeHTML(a.title || "") + "</td>" +
          "<td>" + escapeHTML(fmtTime(a.fired_at)) + "</td>" +
          "<td>" + escapeHTML(fmtTime(a.resolved_at)) + "</td></tr>";
      }).join("");
      setHTML("alerts-history-tbody", rows || '<tr><td colspan="4" class="loading">-</td></tr>');
    });
  }

  window.ackAlert = function (id) {
    apiPost("/alerts/" + id + "/acknowledge", { by: "ui" }, function () { refreshAlerts(); });
  };

  // --- Ops ---
  function refreshOps() {
    apiFetch("/ops/deposits/recent?limit=20", function (resp) {
      var items = (resp && resp.data) || [];
      var rows = items.map(function (r) {
        return "<tr>" +
          '<td class="mono">' + fmtAddr(r.depositId) + "</td>" +
          "<td>" + stateBadge(r.state) + "</td>" +
          '<td class="mono">' + fmtAddr(r.baseRecipient) + "</td>" +
          "<td>" + escapeHTML(r.amount || "-") + "</td>" +
          '<td class="mono">' + (r.txHash ? fmtAddr(r.txHash) : "-") + "</td>" +
          "<td>" + escapeHTML(r.rejectionReason || "-") + "</td>" +
          "<td>" + escapeHTML(fmtTime(r.createdAt)) + "</td>" +
          "<td>" + escapeHTML(r.junoHeight || "-") + "</td></tr>";
      }).join("");
      setHTML("ops-deposits-tbody", rows || '<tr><td colspan="8" class="loading">-</td></tr>');
    });

    apiFetch("/ops/withdrawals/recent?limit=20", function (resp) {
      var items = (resp && resp.data) || [];
      var rows = items.map(function (r) {
        return "<tr>" +
          '<td class="mono">' + fmtAddr(r.withdrawalId) + "</td>" +
          "<td>" + stateBadge(r.state) + "</td>" +
          '<td class="mono">' + fmtAddr(r.requester) + "</td>" +
          "<td>" + escapeHTML(r.amount || "-") + "</td>" +
          '<td class="mono">' + (r.junoTxId ? fmtAddr(r.junoTxId) : "-") + "</td>" +
          '<td class="mono">' + (r.baseTxHash ? fmtAddr(r.baseTxHash) : "-") + "</td>" +
          "<td>" + escapeHTML(fmtTime(r.createdAt)) + "</td></tr>";
      }).join("");
      setHTML("ops-withdrawals-tbody", rows || '<tr><td colspan="7" class="loading">-</td></tr>');
    });

    apiFetch("/ops/batches/stuck", function (resp) {
      var all = (resp && resp.stuckDeposits || []).map(function (r) {
        return { id: r.depositId, kind: "deposit", state: r.state, age: r.stuckFor };
      }).concat((resp && resp.stuckWithdrawals || []).map(function (r) {
        return { id: r.batchId, kind: "withdrawal", state: r.state, age: r.stuckFor };
      }));
      var rows = all.map(function (r) {
        return "<tr>" +
          '<td class="mono">' + fmtAddr(r.id) + "</td>" +
          "<td>" + escapeHTML(r.kind || "-") + "</td>" +
          "<td>" + stateBadge(r.state) + "</td>" +
          "<td>" + escapeHTML(r.age || "-") + "</td></tr>";
      }).join("");
      setHTML("ops-stuck-tbody", rows || '<tr><td colspan="4" class="loading">None</td></tr>');
    });
  }

  // --- Polling ---
  function startPolling() {
    // Stagger initial requests to avoid rate-limit burst.
    refreshOverview();
    setTimeout(refreshDLQ, 500, "proofs");
    setTimeout(refreshFunds, 1000);
    setTimeout(refreshSettings, 1250);
    setTimeout(refreshAnalytics, 1500);
    setTimeout(refreshAlerts, 2000);
    setTimeout(refreshOps, 2500);

    setInterval(refreshOverview, 10000);
    setInterval(function () { refreshDLQ(); }, 15000);
    setInterval(refreshFunds, 30000);
    setInterval(refreshSettings, 30000);
    setInterval(refreshAnalytics, 30000);
    setInterval(refreshAlerts, 30000);
    setInterval(refreshOps, 15000);
  }

  // --- Login ---
  function hasToken() {
    return !!localStorage.getItem("bo_token");
  }

  function showLogin() {
    var overlay = document.getElementById("login-overlay");
    if (overlay) overlay.classList.remove("hidden");
  }

  function hideLogin() {
    var overlay = document.getElementById("login-overlay");
    if (overlay) overlay.classList.add("hidden");
  }

  function initLogin() {
    var form = document.getElementById("login-form");
    if (!form) return;
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var token = document.getElementById("login-token").value.trim();
      if (!token) return;
      // Validate the token against a known API endpoint.
      fetch("/api/analytics/overview", { headers: { "Accept": "application/json", "Authorization": "Bearer " + token } })
        .then(function (r) {
          if (!r.ok) throw new Error(r.status);
          localStorage.setItem("bo_token", token);
          hideLogin();
          startPolling();
        })
        .catch(function () {
          var err = document.getElementById("login-error");
          if (err) err.classList.remove("hidden");
        });
    });
  }

  // --- Init ---
  document.addEventListener("DOMContentLoaded", function () {
    initTabs();
    initSubTabs();
    initLogin();

    if (hasToken()) {
      hideLogin();
      startPolling();
    } else {
      showLogin();
    }

    // DLQ filter controls
    var sel = document.getElementById("dlq-ack-filter");
    if (sel) sel.addEventListener("change", function () {
      dlqFilter.acknowledged = sel.value;
      var activeSub = $(".sub-tab.active");
      refreshDLQ(activeSub ? activeSub.getAttribute("data-sub") : "proofs");
    });

    // DLQ sub-tab change triggers refresh
    $$(".sub-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var kind = btn.getAttribute("data-sub");
        if (kind) refreshDLQ(kind);
      });
    });

    var runtimeForm = document.getElementById("settings-runtime-form");
    if (runtimeForm) {
      runtimeForm.addEventListener("submit", function (e) {
        e.preventDefault();
        apiPut("/settings/runtime", {
          depositMinConfirmations: parseInt(document.getElementById("settings-input-deposit-conf").value, 10),
          withdrawPlannerMinConfirmations: parseInt(document.getElementById("settings-input-withdraw-planner-conf").value, 10),
          withdrawBatchConfirmations: parseInt(document.getElementById("settings-input-withdraw-batch-conf").value, 10),
          updatedBy: document.getElementById("settings-input-updated-by").value.trim() || "backoffice",
        }, function () {
          showSettingsStatus("ok", "Runtime confirmation settings updated.");
          refreshSettings();
        });
      });
    }

    var minDepositForm = document.getElementById("settings-min-deposit-form");
    if (minDepositForm) {
      minDepositForm.addEventListener("submit", function (e) {
        e.preventDefault();
        apiPost("/settings/min-deposit", {
          minDepositAmount: document.getElementById("settings-input-min-deposit").value.trim(),
          updatedBy: document.getElementById("settings-input-min-deposit-updated-by").value.trim() || "backoffice",
        }, function (resp) {
          var txHash = resp && resp.data ? resp.data.txHash : "";
          showSettingsStatus("ok", txHash ? "Min deposit update mined in " + txHash : "Min deposit updated.");
          refreshSettings();
        });
      });
    }
  });
})();
