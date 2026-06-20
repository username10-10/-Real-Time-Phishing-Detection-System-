let warningShown = false;

function formatScore(score) {
  const n = Number(score);

  if (!Number.isFinite(n)) {
    return "N/A";
  }

  return n <= 1 ? (n * 100).toFixed(1) + "%" : n.toFixed(1) + "%";
}

function friendlyReason(reason) {
  const map = {
    medium_confidence: "Suspicious indicators were detected.",
    model_disagreement: "The detection models are not fully confident.",
    high_confidence: "High-confidence phishing indicators were detected.",
    user_blocklist_override: "You marked this domain as phishing."
  };

  return map[reason] || "This website may contain suspicious URL patterns.";
}

function shouldShowWarning(data) {
  const action = data.action || "";
  const score = Number(data.final_score ?? data.score ?? 0);
  const warnThreshold = Number(data.policy?.warn ?? 0.70);

  // Do not show popup for safe results.
  if (action === "safe") {
    return false;
  }

  // Do not show popup for known safe explanation reasons.
  if (
    data.reason === "low_risk" ||
    data.reason === "model_disagreement_low_risk" ||
    data.reason === "user_allowlist_override" ||
    data.reason === "local_dev_bypass"
  ) {
    return false;
  }

  // Show warning if backend action is warn.
  // But protect against accidental low-score warning.
  if (action === "warn") {
    return score >= warnThreshold;
  }

  // Block page is usually handled by background.js / blocked.html.
  // But if block message reaches content.js, warning popup is not needed.
  if (action === "block") {
    return false;
  }

  // Fallback: only show if score is above warn threshold.
  return score >= warnThreshold;
}

function showWarningCard(data) {
  if (warningShown) return;

  if (!shouldShowWarning(data || {})) {
    return;
  }

  warningShown = true;

  const score = data.final_score ?? data.score ?? "N/A";
  const typePred = data.type_pred || data.type || "suspicious";
  const reason = friendlyReason(data.reason);

  const oldBanner = document.getElementById("phishing-warning-banner");
  if (oldBanner) oldBanner.remove();

  const oldCard = document.getElementById("phishing-detector-warning-card");
  if (oldCard) oldCard.remove();

  const oldStyle = document.getElementById("phishing-detector-warning-style");
  if (oldStyle) oldStyle.remove();

  const style = document.createElement("style");
  style.id = "phishing-detector-warning-style";
  style.textContent = `
    #phishing-detector-warning-card {
      position: fixed;
      right: 20px;
      bottom: 20px;
      z-index: 2147483647;
      width: 370px;
      max-width: calc(100vw - 40px);
      background: #fff7ed;
      border: 1px solid #fdba74;
      border-radius: 18px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.25);
      font-family: Arial, sans-serif;
      color: #1f2937;
      overflow: hidden;
    }

    #phishing-detector-warning-card .pd-header {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 16px;
      background: #ffedd5;
      border-bottom: 1px solid #fed7aa;
    }

    #phishing-detector-warning-card .pd-icon {
      width: 42px;
      height: 42px;
      border-radius: 14px;
      background: #fb923c;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      flex-shrink: 0;
    }

    #phishing-detector-warning-card .pd-title {
      font-size: 16px;
      font-weight: 800;
      color: #9a3412;
      margin-bottom: 3px;
    }

    #phishing-detector-warning-card .pd-subtitle {
      font-size: 12px;
      color: #7c2d12;
      line-height: 1.4;
    }

    #phishing-detector-warning-card .pd-body {
      padding: 16px;
    }

    #phishing-detector-warning-card .pd-text {
      font-size: 13px;
      line-height: 1.5;
      color: #374151;
      margin-bottom: 12px;
    }

    #phishing-detector-warning-card .pd-info {
      background: #ffffff;
      border: 1px solid #fed7aa;
      border-radius: 14px;
      padding: 12px;
      font-size: 12px;
      color: #374151;
      line-height: 1.5;
    }

    #phishing-detector-warning-card .pd-info div {
      margin-bottom: 5px;
    }

    #phishing-detector-warning-card .pd-info div:last-child {
      margin-bottom: 0;
    }

    #phishing-detector-warning-card .pd-advice {
      margin-top: 12px;
      font-size: 12px;
      line-height: 1.5;
      color: #7c2d12;
      font-weight: 600;
    }

    #phishing-detector-warning-card .pd-actions {
      display: flex;
      gap: 8px;
      margin-top: 14px;
    }

    #phishing-detector-warning-card button {
      border: none;
      border-radius: 12px;
      padding: 10px 12px;
      font-size: 13px;
      font-weight: 800;
      cursor: pointer;
      font-family: Arial, sans-serif;
    }

    #phishing-detector-warning-card #pd-understand {
      flex: 1;
      background: #f97316;
      color: white;
    }

    #phishing-detector-warning-card #pd-understand:hover {
      background: #ea580c;
    }

    #phishing-detector-warning-card #pd-hide {
      background: #e5e7eb;
      color: #111827;
    }

    #phishing-detector-warning-card #pd-hide:hover {
      background: #d1d5db;
    }
  `;

  const card = document.createElement("div");
  card.id = "phishing-detector-warning-card";
  card.innerHTML = `
    <div class="pd-header">
      <div class="pd-icon">⚠️</div>
      <div>
        <div class="pd-title">Be careful with this website</div>
        <div class="pd-subtitle">This page is not blocked, but it looks suspicious.</div>
      </div>
    </div>

    <div class="pd-body">
      <div class="pd-text">
        You can continue viewing this site, but avoid entering sensitive information unless you trust it.
      </div>

      <div class="pd-info">
        <div><b>Type:</b> ${typePred}</div>
        <div><b>Risk score:</b> ${formatScore(score)}</div>
        <div><b>Reason:</b> ${reason}</div>
      </div>

      <div class="pd-advice">
        Do not enter passwords, OTP, banking details, or personal information on suspicious pages.
      </div>

      <div class="pd-actions">
        <button id="pd-understand">I understand</button>
        <button id="pd-hide">Hide</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(style);
  document.documentElement.appendChild(card);

  document.getElementById("pd-understand").addEventListener("click", () => {
    card.remove();
    style.remove();
    warningShown = false;
  });

  document.getElementById("pd-hide").addEventListener("click", () => {
    card.remove();
    style.remove();
    warningShown = false;
  });
}

chrome.runtime.onMessage.addListener((msg) => {
  if (location.hostname === "console.firebase.google.com") return;

  if (msg.type === "PHISH_WARN") {
    showWarningCard(msg.payload || {});
  }
});