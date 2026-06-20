document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);

  const blockedUrl = params.get("url") || "";
  const typePred = params.get("type") || "phishing";
  const rawScore = params.get("score");

  function formatScore(score) {
    const n = Number(score);

    if (!Number.isFinite(n)) {
      return "N/A";
    }

    if (n <= 1) {
      return (n * 100).toFixed(1) + "%";
    }

    return n.toFixed(1) + "%";
  }

  const urlEl = document.getElementById("u");
  const typeEl = document.getElementById("t");
  const scoreEl = document.getElementById("s");

  if (urlEl) {
    urlEl.textContent = blockedUrl || "Unknown URL";
  }

  if (typeEl) {
    typeEl.textContent = typePred || "Unknown";
  }

  if (scoreEl) {
    scoreEl.textContent = formatScore(rawScore);
  }

  const backBtn = document.getElementById("back");
  const closeBtn = document.getElementById("closeTab");
  const copyBtn = document.getElementById("copyUrl");

  if (backBtn) {
    backBtn.addEventListener("click", () => {
      history.back();
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      window.close();
    });
  }

  if (copyBtn) {
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(blockedUrl);
        copyBtn.textContent = "Copied";
      } catch (e) {
        copyBtn.textContent = "Copy failed";
      }
    });
  }
});