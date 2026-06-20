const API_BASE = "http://127.0.0.1:8000";
let idToken = null;
const xaiCache = new Map();

console.log("[SOC] app.js loaded ✅", window.location.href);

function el(id) {
  return document.getElementById(id);
}

function setStatus(msg) {
  const s = el("status");
  if (s) s.textContent = msg;
}

function setUserUI(label, sub) {
  const u1 = el("userLine");
  const u2 = el("userSub");
  const av = el("avatar");

  if (u1) u1.textContent = label;
  if (u2) u2.textContent = sub;

  const letter = (label || "?").trim().charAt(0).toUpperCase() || "?";
  if (av) av.textContent = letter;
}

function captureTokenSession() {
  const u = new URL(window.location.href);
  const token = u.searchParams.get("token");

  if (token) {
    sessionStorage.setItem("idToken", token);
    u.searchParams.delete("token");
    history.replaceState({}, "", u.toString());
    console.log("[SOC] token captured ✅", token.slice(0, 25) + "...");
  }

  return sessionStorage.getItem("idToken");
}

async function authedFetch(path, opts = {}) {
  if (!idToken) {
    throw new Error("Missing token session. Open dashboard from extension.");
  }

  const headers = { ...(opts.headers || {}) };
  headers["Authorization"] = "Bearer " + idToken;

  if (opts.body && !headers["Content-Type"]) {
    headers["Content-Type"] = "application/json";
  }

  return fetch(API_BASE + path, { ...opts, headers });
}

async function safeJson(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

function tsToString(ts) {
  try {
    return new Date(ts * 1000).toLocaleString();
  } catch {
    return String(ts);
  }
}

function updateKpis(items) {
  const total = items.length;
  const blocked = items.filter((x) => x.action === "block").length;
  const warned = items.filter((x) => x.action === "warn").length;
  const safe = items.filter((x) => x.action === "safe").length;

  if (el("kpiTotal")) el("kpiTotal").textContent = total;
  if (el("kpiBlocked")) el("kpiBlocked").textContent = blocked;
  if (el("kpiWarned")) el("kpiWarned").textContent = warned;
  if (el("kpiSafe")) el("kpiSafe").textContent = safe;
  if (el("kpiLast")) el("kpiLast").textContent = "Last refresh: " + new Date().toLocaleString();
}

function scorePct(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return "-";
  const pct = Math.max(0, Math.min(100, n * 100));
  return pct.toFixed(1) + "%";
}

function reasonLabel(reason, action) {
  const r = String(reason || "").trim();

  const map = {
    user_allowlist_override: "Allowed due to user safe-list override",
    user_blocklist_override: "Blocked due to user phishing-list override",
    high_confidence: "High-risk phishing indicators detected",
    medium_confidence: "Moderate risk detected based on URL pattern",
    low_risk: "Low risk based on final score",
    model_disagreement_low_risk: "Low risk, but model confidence differed",
    local_dev_bypass: "Local or development site bypassed",
    no_models_loaded: "Detection unavailable because models are not loaded",
    model_disagreement: "Model uncertainty detected; caution warning issued"
  };

  if (map[r]) return map[r];

  if (!r) {
    if (action === "block") return "Blocked by detection policy";
    if (action === "warn") return "Warning issued by detection policy";
    return "Allowed by detection policy";
  }

  return r.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function actionBadge(action) {
  if (action === "block") return `<span class="badge block">block</span>`;
  if (action === "warn") return `<span class="badge warn">warn</span>`;
  return `<span class="badge safe">safe</span>`;
}

function setRowSeverityClass(tr, action) {
  tr.classList.remove("sev-safe", "sev-warn", "sev-block");
  if (action === "block") tr.classList.add("sev-block");
  else if (action === "warn") tr.classList.add("sev-warn");
  else tr.classList.add("sev-safe");
}

function shortDomain(d) {
  if (!d) return "";
  if (d.length <= 52) return d;
  return d.slice(0, 42) + "…" + d.slice(-8);
}

/* -------------------------
   GENERAL USER-FRIENDLY XAI
------------------------- */

function xaiPatternTitle(feature) {
  const map = {
    has_https: "HTTPS connection pattern",
    suspicious_word_count: "Risk-related words detected",
    tld_length: "Website ending pattern",
    nb_com: "Repeated domain-like text",
    nb_www: "Repeated 'www' pattern",
    num_dots: "Complex domain structure",
    num_special_chars: "Special characters in the address",
    url_length: "Long website address",
    count_slashes: "Complex page path",
    host_entropy: "Unusual domain pattern",
    nb_hyphens: "Hyphenated domain pattern",
    brand_impersonation: "Possible brand imitation",
    digit_ratio: "Large proportion of digits",
    num_subdomains: "Multiple domain sections",
    path_length: "Long page path",
    num_digits: "Number-heavy address",
    nb_underscore: "Underscore usage",
    count_at: "'@' symbol detected",
    count_double_slash: "Unusual slash pattern",
    count_percent: "Encoded characters detected",
    host_length: "Domain length pattern"
  };

  return map[feature] || "Other URL pattern";
}

function xaiPatternExplanation(feature, shapValue) {
  const isRisk = Number(shapValue) > 0;

  const map = {
    has_https: isRisk
      ? "The website uses HTTPS, but HTTPS only protects the connection. It does not guarantee that the website is legitimate."
      : "The HTTPS connection reduced the system’s concern for this URL.",

    suspicious_word_count: isRisk
      ? "The URL contains words that are often found in suspicious links, such as login, verify, account, or secure."
      : "No strong phishing-style wording was found in the URL.",

    tld_length: isRisk
      ? "The website ending has a pattern that the system considers less common."
      : "The website ending reduced the risk score in this case.",

    nb_com: isRisk
      ? "Repeated domain-like text can make a link appear more trustworthy than it really is."
      : "The domain-like text pattern reduced the system’s concern.",

    nb_www: isRisk
      ? "A repeated 'www' pattern can make the URL structure look unusual."
      : "The 'www' pattern did not increase concern for this URL.",

    num_dots: isRisk
      ? "Many dots can create a more complex address that is harder for users to verify."
      : "The number of dots reduced the system’s concern in this case.",

    num_special_chars: isRisk
      ? "Special characters may make the URL harder to read or may hide its true structure."
      : "The special-character pattern reduced the risk score in this case.",

    url_length: isRisk
      ? "A very long URL can make it harder for users to identify the real website destination."
      : "The website address length reduced the system’s concern.",

    count_slashes: isRisk
      ? "A complex page path may make the address harder to understand at a glance."
      : "The page path structure reduced the risk score.",

    host_entropy: isRisk
      ? "The domain pattern looks less natural or more random than ordinary trusted website names."
      : "The domain pattern reduced the system’s concern.",

    nb_hyphens: isRisk
      ? "Multiple hyphens can appear in imitation-style or suspicious-looking website names."
      : "The hyphen pattern reduced the risk score in this case.",

    brand_impersonation: isRisk
      ? "The URL may contain wording that resembles a trusted company or service."
      : "The URL did not strongly resemble a known brand pattern.",

    digit_ratio: isRisk
      ? "A high amount of digits can make a URL look generated or less typical."
      : "The digit pattern reduced the system’s concern.",

    num_subdomains: isRisk
      ? "Several domain sections can make a website address harder to verify."
      : "The domain section structure reduced the risk score.",

    path_length: isRisk
      ? "A long page path may hide the true purpose of the webpage."
      : "The page path length reduced the system’s concern.",

    num_digits: isRisk
      ? "Many numbers in the address can sometimes appear in generated or suspicious links."
      : "The number pattern reduced the risk score.",

    nb_underscore: isRisk
      ? "Underscores are less common in normal web addresses and may appear unusual."
      : "The underscore pattern reduced concern in this case.",

    count_at: isRisk
      ? "The '@' symbol can be used in URLs to mislead users about the real website destination."
      : "The '@' symbol pattern did not increase concern in this URL.",

    count_double_slash: isRisk
      ? "An unusual slash pattern can make the structure of the URL less normal."
      : "The slash pattern reduced the system’s concern.",

    count_percent: isRisk
      ? "Encoded characters can make parts of the URL harder to read and verify."
      : "The encoded-character pattern reduced concern in this case.",

    host_length: isRisk
      ? "The domain length influenced the system to view the URL as more unusual."
      : "The domain length reduced the system’s concern."
  };

  return map[feature] || (
    isRisk
      ? "This URL pattern increased the system’s risk score."
      : "This URL pattern reduced the system’s risk score."
  );
}

function xaiImpactLabel(shapValue) {
  const v = Number(shapValue);

  if (v > 0.08) {
    return `<span class="impact impact-high">High Risk Factor</span>`;
  }

  if (v > 0.02) {
    return `<span class="impact impact-medium">Medium Risk Factor</span>`;
  }

  if (v > 0) {
    return `<span class="impact impact-low">Low Risk Factor</span>`;
  }

  if (v < -0.08) {
    return `<span class="impact impact-safe-strong">Strong Safety Factor</span>`;
  }

  if (v < -0.02) {
    return `<span class="impact impact-safe">Safety Factor</span>`;
  }

  if (v < 0) {
    return `<span class="impact impact-safe-light">Minor Safety Factor</span>`;
  }

  return `<span class="impact impact-neutral">Neutral</span>`;
}

function buildGeneralUserSummary(rows) {
  const riskRows = rows
    .filter((r) => Number(r.shap) > 0)
    .sort((a, b) => Number(b.shap) - Number(a.shap));

  const safeRows = rows
    .filter((r) => Number(r.shap) < 0)
    .sort((a, b) => Number(a.shap) - Number(b.shap));

  const topRisk = riskRows.slice(0, 3);
  const topSafe = safeRows.slice(0, 2);

  return `
    <div class="xai-summary-box">
      <div class="xai-summary-title">Why the system gave this result</div>

      <div class="xai-summary-text">
        The system reviewed the URL structure and identified patterns that either increased or reduced the risk score.
      </div>

      <div class="xai-points">
        <div>
          <b>Main signs that increased risk:</b>
          <ul>
            ${
              topRisk.length
                ? topRisk
                    .map((item) => `<li>${xaiPatternTitle(item.feature)}</li>`)
                    .join("")
                : "<li>No strong risk factors were identified.</li>"
            }
          </ul>
        </div>

        <div>
          <b>Main signs that reduced risk:</b>
          <ul>
            ${
              topSafe.length
                ? topSafe
                    .map((item) => `<li>${xaiPatternTitle(item.feature)}</li>`)
                    .join("")
                : "<li>No strong safety factors were identified.</li>"
            }
          </ul>
        </div>
      </div>

      <div class="xai-summary-note">
        This explanation helps users understand the system’s decision, but it is not absolute proof that a website is safe or harmful.
      </div>
    </div>
  `;
}

function renderGeneralUserXaiRows(rows, tbody) {
  if (!tbody) return;

  tbody.innerHTML = "";

  const topRows = rows
    .filter((r) => Number(r.shap) !== 0)
    .sort((a, b) => Math.abs(Number(b.shap)) - Math.abs(Number(a.shap)))
    .slice(0, 12);

  if (!topRows.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3">No major URL patterns strongly influenced this result.</td>
      </tr>
    `;
    return;
  }

  for (const row of topRows) {
    const shapNum = Number(row.shap);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${xaiPatternTitle(row.feature)}</td>
      <td>${xaiImpactLabel(shapNum)}</td>
      <td>${xaiPatternExplanation(row.feature, shapNum)}</td>
    `;

    tbody.appendChild(tr);
  }
}

/* -------------------------
   HISTORY
------------------------- */

async function refreshHistory() {
  const body = el("histBody");
  if (!body) return;

  body.innerHTML = "";

  if (!idToken) {
    setUserUI("Not logged in", "Open dashboard from extension");
    setStatus("No token session found. Use Extension → Open Dashboard.");
    return;
  }

  setStatus("Loading history...");

  try {
    const res = await authedFetch("/history?limit=200");
    const data = await safeJson(res);

    if (!res.ok) {
      if (res.status === 401) {
        setStatus("Session expired. Please open dashboard again from extension.");
        setUserUI("Not logged in", "Token expired");
        return;
      }

      setStatus("History failed (" + res.status + "): " + JSON.stringify(data));
      return;
    }

    const items = data.items || [];
    updateKpis(items);

    if (!items.length) {
      setStatus("Logged in. No incidents found yet.");
      return;
    }

    for (const item of items) {
      const tr = document.createElement("tr");
      setRowSeverityClass(tr, item.action);

      const domainText = shortDomain(item.domain || "");
      const fullUrl = item.url || "";
      const friendlyReason = reasonLabel(item.reason, item.action);
      const scoreText = scorePct(item.final_score);

      tr.innerHTML = `
        <td>${tsToString(item.timestamp)}</td>
        <td title="${(item.domain || "").replace(/"/g, "&quot;")}">${domainText}</td>
        <td>${actionBadge(item.action)}</td>
        <td class="mono">${scoreText}</td>
        <td title="${String(item.reason || "")}">${friendlyReason}</td>
        <td><button class="btn btn-ghost xaiBtn">Explain</button></td>
      `;

      tr.querySelector(".xaiBtn").onclick = async () => loadXai(fullUrl);
      body.appendChild(tr);
    }

    setStatus("History loaded.");
  } catch (e) {
    setStatus("History error: " + (e?.message || String(e)));
  }
}

/* -------------------------
   LISTS
------------------------- */

async function loadLists() {
  const safeList = el("safeList");
  const phishList = el("phishList");

  if (safeList) safeList.innerHTML = "";
  if (phishList) phishList.innerHTML = "";

  if (!idToken) {
    setStatus("No token session.");
    return;
  }

  setStatus("Loading lists...");

  try {
    const res = await authedFetch("/lists");
    const data = await safeJson(res);

    if (!res.ok) {
      if (res.status === 401) {
        setStatus("Session expired. Please open dashboard again from extension.");
        setUserUI("Not logged in", "Token expired");
        return;
      }

      setStatus("Lists failed (" + res.status + "): " + JSON.stringify(data));
      return;
    }

    for (const d of data.safe || []) {
      const li = document.createElement("li");
      li.textContent = d;
      if (safeList) safeList.appendChild(li);
    }

    for (const d of data.phishing || []) {
      const li = document.createElement("li");
      li.textContent = d;
      if (phishList) phishList.appendChild(li);
    }

    setStatus("Lists loaded.");
  } catch (e) {
    setStatus("Lists error: " + (e?.message || String(e)));
  }
}

/* -------------------------
   XAI
------------------------- */

async function loadXai(url) {
  const xaiUrl = el("xaiUrl");
  const xaiSummary = el("xaiSummary");
  const xaiTips = el("xaiTips");
  const tbody = el("xaiBody");

  if (xaiUrl) xaiUrl.textContent = "Analysed URL: " + (url || "");
  if (xaiSummary) xaiSummary.innerHTML = "";
  if (xaiTips) xaiTips.textContent = "";
  if (tbody) tbody.innerHTML = "";

  if (!idToken) {
    setStatus("No token session.");
    return;
  }

  setStatus("Loading explanation...");

  // Load instantly from dashboard cache if URL was already explained
  if (xaiCache.has(url)) {
    const cachedRows = xaiCache.get(url);

    if (xaiSummary) {
      xaiSummary.innerHTML = buildGeneralUserSummary(cachedRows);
    }

    renderGeneralUserXaiRows(cachedRows, tbody);

    if (xaiTips) {
      xaiTips.textContent =
        "Loaded from dashboard cache. This explanation was previously generated for the same URL.";
    }

    setStatus("XAI loaded from cache.");
    return;
  }

  try {
    const res = await authedFetch("/xai", {
      method: "POST",
      body: JSON.stringify({ url })
    });

    const data = await safeJson(res);

    if (!res.ok) {
      if (res.status === 401) {
        setStatus("Session expired. Please open dashboard again from extension.");
        setUserUI("Not logged in", "Token expired");
        return;
      }

      setStatus("XAI failed (" + res.status + "): " + JSON.stringify(data));

      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="3">Explanation error: ${JSON.stringify(data)}</td></tr>`;
      }

      return;
    }

    const rows = data.top || [];
    xaiCache.set(url, rows);

    if (!rows.length) {
      setStatus("Explanation loaded, but no details were returned.");
      if (tbody) {
        tbody.innerHTML = `<tr><td colspan="3">No explanation details were returned.</td></tr>`;
      }
      return;
    }

    if (xaiSummary) {
      xaiSummary.innerHTML = buildGeneralUserSummary(rows);
    }

    renderGeneralUserXaiRows(rows, tbody);

    if (xaiTips) {
      xaiTips.textContent =
        "This section highlights the main URL patterns that influenced the final risk score.";
    }

    setStatus("XAI loaded.");
  } catch (e) {
    setStatus("XAI error: " + (e?.message || String(e)));

    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="3">XAI exception: ${(e?.message || String(e))}</td></tr>`;
    }
  }
}

/* -------------------------
   BUTTONS
------------------------- */

const btnRefresh = el("btnRefresh");
const btnLoadLists = el("btnLoadLists");

if (btnRefresh) btnRefresh.onclick = refreshHistory;
if (btnLoadLists) btnLoadLists.onclick = loadLists;

/* -------------------------
   INIT
------------------------- */

window.addEventListener("DOMContentLoaded", async () => {
  idToken = captureTokenSession();

  if (!idToken) {
    setUserUI("Not logged in", "Open dashboard from extension");
    setStatus("No token session found. Use Extension → Open Dashboard.");
    return;
  }

  setUserUI("Logged in", "Token session active");
  setStatus("Token session detected. Loading data...");

  await refreshHistory();
});