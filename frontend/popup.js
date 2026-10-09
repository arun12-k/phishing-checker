document.addEventListener("DOMContentLoaded", () => {
  const toggleBtn = document.getElementById("toggleBtn");
  const totalEl = document.getElementById("total");
  const safeEl = document.getElementById("safe");
  const suspiciousEl = document.getElementById("suspicious");
  const highlightNav = document.getElementById("highlightNav");
  const highlightLong = document.getElementById("highlightLong");
  const highlightLogin = document.getElementById("highlightLogin");

  chrome.storage.local.get(["enabled", "options"], (result) => {
    updateButton(Boolean(result.enabled));
    const opts = result.options || {};
    highlightNav.checked = opts.highlightNav ?? true;
    highlightLong.checked = opts.highlightLong ?? true;
    highlightLogin.checked = opts.highlightLogin ?? true;
  });

  toggleBtn.addEventListener("click", () => {
    chrome.storage.local.get(["enabled"], (result) => {
      const enabled = !result.enabled;
      chrome.storage.local.set({ enabled }, () => {
        updateButton(enabled);
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]?.id) chrome.tabs.sendMessage(tabs[0].id, { type: "rescan" });
        });
      });
    });
  });

  [highlightNav, highlightLong, highlightLogin].forEach((option) => {
    option.addEventListener("change", () => {
      chrome.storage.local.set({ options: {
        highlightNav: highlightNav.checked,
        highlightLong: highlightLong.checked,
        highlightLogin: highlightLogin.checked,
      }});
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) chrome.tabs.sendMessage(tabs[0].id, { type: "rescan" });
      });
    });
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type !== "stats") return;
    totalEl.textContent = message.total;
    safeEl.textContent = message.safe;
    suspiciousEl.textContent = message.suspicious;
  });

  function updateButton(enabled) {
    toggleBtn.textContent = enabled ? "Disable Scanning" : "Enable Scanning";
    toggleBtn.className = enabled ? "enabled" : "disabled";
  }

  document.getElementById("clearCacheBtn").addEventListener("click", () => {
    chrome.storage.local.remove("suspicious_cache", () => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]?.id) chrome.tabs.sendMessage(tabs[0].id, { type: "rescan" });
      });
    });
  });

  document.getElementById("checkUrlBtn").addEventListener("click", async () => {
    const input = document.getElementById("manualUrl");
    const resultEl = document.getElementById("manualResult");
    const url = input.value.trim();
    if (!url) {
      resultEl.style.color = "#b45309";
      resultEl.textContent = "Enter a URL to check.";
      return;
    }
    resultEl.style.color = "#475569";
    resultEl.textContent = "Checking…";
    try {
      const result = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: "manualCheck", url }, (value) => {
          if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
          else resolve(value);
        });
      });
      if (!result || result.label === "unknown") throw new Error(result?.error || "The analysis service is unavailable.");
      const color = result.label === "phishing" ? "#b91c1c" : result.label === "suspicious" ? "#b45309" : "#15803d";
      const details = Array.isArray(result.indicators) && result.indicators.length
        ? ` Reasons: ${result.indicators.join("; ")}.`
        : "";
      resultEl.style.color = color;
      resultEl.textContent = `${result.label.toUpperCase()} · Risk ${Math.round(result.score * 100)}%.${details}`;
    } catch (error) {
      resultEl.style.color = "#b91c1c";
      resultEl.textContent = error.message || "Unable to reach the Java analysis service.";
    }
  });
});
