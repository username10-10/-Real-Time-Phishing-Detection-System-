const API_BASE = "http://127.0.0.1:8000";

// ================= TOKEN =================
async function getToken() {
  const { firebaseIdToken } = await chrome.storage.local.get(["firebaseIdToken"]);
  return firebaseIdToken || null;
}

// ================= URL HELPERS =================
function isHttpUrl(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

function normalizeHost(host) {
  return (host || "").toLowerCase().replace(/^www\./, "");
}

function hostFromUrl(url) {
  try {
    return normalizeHost(new URL(url).hostname);
  } catch {
    return "";
  }
}

// ================= SAVE LAST SCAN =================
async function saveLastScan(result, url) {
  await chrome.storage.local.set({
    lastScanResult: {
      url: result.url || url,
      domain: result.domain || hostFromUrl(url),
      action: result.action || "unknown",
      final_score: result.final_score ?? 0,
      reason: result.reason || "",
      type_pred: result.type_pred || "",
      time: new Date().toLocaleString()
    }
  });
}

// ================= LIST CACHE =================
const LISTS_CACHE_TTL_MS = 5 * 60 * 1000;

async function getCachedLists() {
  const { cachedLists, cachedListsAt } = await chrome.storage.local.get([
    "cachedLists",
    "cachedListsAt"
  ]);

  return {
    lists: cachedLists || null,
    at: cachedListsAt || 0
  };
}

async function setCachedLists(lists) {
  await chrome.storage.local.set({
    cachedLists: lists,
    cachedListsAt: Date.now()
  });
}

async function fetchListsFromBackend(token) {
  if (!token) return null;

  try {
    const res = await fetch(`${API_BASE}/lists`, {
      headers: { Authorization: "Bearer " + token }
    });

    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

async function getLists(token) {
  if (!token) return null;

  const { lists, at } = await getCachedLists();

  if (lists && Date.now() - at < LISTS_CACHE_TTL_MS) {
    return lists;
  }

  const fresh = await fetchListsFromBackend(token);

  if (fresh) {
    await setCachedLists(fresh);
    return fresh;
  }

  return lists || null;
}

function isDomainInList(host, list) {
  if (!host || !Array.isArray(list)) return false;

  const cleanHost = normalizeHost(host);
  return list.map(normalizeHost).includes(cleanHost);
}

// ================= PREDICT =================
async function predictUrl(url, token) {
  const headers = { "Content-Type": "application/json" };

  if (token) headers["Authorization"] = "Bearer " + token;

  const res = await fetch(`${API_BASE}/predict`, {
    method: "POST",
    headers,
    body: JSON.stringify({ url })
  });

  return await res.json();
}

// ================= BLOCK =================
function redirectToBlocked(tabId, url, score, typePred) {
  const blockedUrl =
    chrome.runtime.getURL("blocked.html") +
    `?url=${encodeURIComponent(url)}` +
    `&score=${encodeURIComponent(score ?? "")}` +
    `&type=${encodeURIComponent(typePred ?? "")}`;

  chrome.tabs.update(tabId, { url: blockedUrl });
}

// ================= WARNING STORE =================
async function savePendingWarning(tabId, result) {
  await chrome.storage.local.set({
    pendingWarn: {
      tabId,
      result,
      createdAt: Date.now()
    }
  });
}

// ================= MAIN DETECTION =================
async function handleNavigation(details) {
  if (details.frameId !== 0) return;
  if (!details.url || !isHttpUrl(details.url)) return;
  if (details.url.startsWith("chrome-extension://")) return;

  const url = details.url;
  const host = hostFromUrl(url);

  try {
    const token = await getToken();
    const lists = await getLists(token);

    // ✅ SAFE LIST
    if (isDomainInList(host, lists?.safe)) {
      await saveLastScan({
        url,
        domain: host,
        action: "safe",
        final_score: 0,
        reason: "user_allowlist_override",
        type_pred: "benign"
      }, url);
      return;
    }

    // ❌ PHISHING LIST
    if (isDomainInList(host, lists?.phishing)) {
      await saveLastScan({
        url,
        domain: host,
        action: "block",
        final_score: 1,
        reason: "user_blocklist_override",
        type_pred: "phishing"
      }, url);

      redirectToBlocked(details.tabId, url, 1, "phishing");
      return;
    }

    // 🤖 MODEL
    const result = await predictUrl(url, token);
    if (!result) return;

    await saveLastScan(result, url);

    // 🚫 BLOCK
    if (result.action === "block") {
      redirectToBlocked(
        details.tabId,
        result.effective_url || result.url || url,
        result.final_score,
        result.type_pred
      );
      return;
    }

    // ⚠️ WARN (delay until page loads)
    if (result.action === "warn") {
      await savePendingWarning(details.tabId, result);
      return;
    }

  } catch (e) {
    console.error("[Phishing Detector] Error:", e);
  }
}

// ================= LISTENERS =================

// 🚀 REAL-TIME SCAN (IMPORTANT)
chrome.webNavigation.onBeforeNavigate.addListener(handleNavigation);

// ⚠️ SHOW WARNING AFTER LOAD
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  const { pendingWarn } = await chrome.storage.local.get(["pendingWarn"]);
  if (!pendingWarn) return;

  if (pendingWarn.tabId !== details.tabId) return;

  // expire after 30 sec
  if (Date.now() - pendingWarn.createdAt > 30000) {
    await chrome.storage.local.remove(["pendingWarn"]);
    return;
  }

  try {
    await chrome.tabs.sendMessage(details.tabId, {
      type: "PHISH_WARN",
      payload: pendingWarn.result
    });

    await chrome.storage.local.remove(["pendingWarn"]);
  } catch (e) {
    console.warn("Warning send failed:", e);
  }
});