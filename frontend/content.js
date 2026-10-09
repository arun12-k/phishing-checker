const API = "http://127.0.0.1:8080/predict";
const inMemoryCache = new Map();
let storedSuspicious = new Set();

function loadStoredCache() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["suspicious_cache"], (res) => {
      const arr = res.suspicious_cache || [];
      storedSuspicious = new Set(arr);
      resolve();
    });
  });
}

function saveToStoredCache(url) {
  if (storedSuspicious.has(url)) return Promise.resolve();
  storedSuspicious.add(url);
  const arr = Array.from(storedSuspicious);
  return new Promise((resolve) => {
    chrome.storage.local.set({ suspicious_cache: arr }, () => resolve());
  });
}

function extractFeaturesFromUrl(url) {
  try {
    const u = url.toLowerCase();
    return {
      NumDots: (u.match(/\./g) || []).length,
      SubdomainLevel: u.split(".").length - 2,
      PathLevel: u.split("/").length - 3,
      UrlLength: u.length,
      NumDash: (u.match(/-/g) || []).length,
      NumDashInHostname: (new URL(url).hostname.match(/-/g) || []).length,
      AtSymbol: u.includes("@") ? 1 : 0,
      NumNumericChars: (u.match(/\d/g) || []).length,
      NoHttps: u.startsWith("https://") ? 0 : 1,
      IpAddress: /\d+\.\d+\.\d+\.\d+/.test(u) ? 1 : 0,
    };
  } catch (e) {
    // invalid URL
    return null;
  }
}

function heuristicFlag(url) {
  try {
    const u = url.toLowerCase();
    const hostname = new URL(url).hostname;
    const suspiciousWords = [
      "login",
      "signin",
      "verify",
      "secure",
      "update",
      "confirm",
      "account",
      "otp",
      "password",
      "bank",
      "wallet",
      "unlock",
      "auth",
      "subscription",
      "recovery",
    ];

    const hasKeyword = suspiciousWords.some((w) => u.includes(w));
    const isIp = /\b\d{1,3}(\.\d{1,3}){3}\b/.test(hostname);
    const isLong = u.length > 80;
    const noHttps = !u.startsWith("https://");
    const puny = hostname.startsWith("xn--") || /xn--/.test(hostname);
    const atSign = u.includes("@");

    let score = 0;
    if (hasKeyword) score += 0.4;
    if (isIp) score += 0.25;
    if (isLong) score += 0.15;
    if (noHttps) score += 0.1;
    if (puny) score += 0.2;
    if (atSign) score += 0.2;

    if (score > 1) score = 1;

    return {
      label:
        score >= 0.7 ? "phishing" : score >= 0.3 ? "suspicious" : "legitimate",
      score,
    };
  } catch (e) {
    return { label: "unknown", score: 0 };
  }
}

async function checkUrl(url) {
  const heur = heuristicFlag(url);
  if (heur.score >= 0.6) {
    inMemoryCache.set(url, heur);
    if (heur.label === "phishing") saveToStoredCache(url);
    return heur;
  }

  if (inMemoryCache.has(url)) return inMemoryCache.get(url);

  if (storedSuspicious.has(url)) {
    const result = { label: "phishing", score: 1 };
    inMemoryCache.set(url, result);
    return result;
  }

  const features = extractFeaturesFromUrl(url);
  if (!features) {
    const res = { label: "unknown", score: 0 };
    inMemoryCache.set(url, res);
    return res;
  }

  try {
    const res = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    const data = await res.json();
    inMemoryCache.set(url, data);

    if (data.label === "phishing") {
      await saveToStoredCache(url);
    }
    return data;
  } catch (err) {
    const unknown = { label: "unknown", score: 0, error: "Java API unavailable" };
    inMemoryCache.set(url, unknown);
    return unknown;
  }
}

function blockNavigationIfSuspicious(anchorEl, url) {
  anchorEl.title = anchorEl.title || "";
  anchorEl.title += `\nChecked by Phishing Checker`;

  anchorEl.addEventListener(
    "click",
    (e) => {
      const href = anchorEl.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopPropagation();
        alert(`🚨 Blocked potential phishing link!\n${href}`);
      }
    },
    true
  );

  anchorEl.addEventListener(
    "auxclick",
    (e) => {
      const href = anchorEl.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopPropagation();
        alert(`🚨 Blocked potential phishing link!\n${href}`);
      }
    },
    true
  );
}

function injectBlockerScript() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("inject.js");
  (document.head || document.documentElement).appendChild(script);
}

function exposeBlockedUrlsToPage() {
  const arr = Array.from(storedSuspicious);
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("setBlockedUrls.js");
  script.dataset.urls = JSON.stringify(arr);
  (document.head || document.documentElement).appendChild(script);
}

async function scanLinks() {
  await loadStoredCache();
  exposeBlockedUrlsToPage();

  const links = Array.from(document.querySelectorAll("a[href]"));
  let total = 0,
    safe = 0,
    suspicious = 0;

  document.addEventListener(
    "click",
    (e) => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      const href = a.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        alert("🚨 Blocked potential phishing link!\\n" + href);
      }
    },
    true
  );

  document.addEventListener(
    "auxclick",
    (e) => {
      const a = e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      const href = a.href;
      if (storedSuspicious.has(href)) {
        e.preventDefault();
        e.stopImmediatePropagation();
        alert("🚨 Blocked potential phishing link!\\n" + href);
      }
    },
    true
  );

  injectBlockerScript();

  for (const link of links) {
    total++;
    const href = link.href;
    const result = await checkUrl(href);
    link.title = `Status: ${result.label}\nScore: ${
      result.score?.toFixed?.(2) ?? result.score
    }`;

    if (result.label === "phishing") {
      link.classList.add("phishing-warning");
      suspicious++;
      saveToStoredCache(href)
        .then(() => {
          exposeBlockedUrlsToPage();
        })
        .catch(() => {});
    } else {
      link.classList.add("phishing-safe");
      safe++;
    }
  }

  chrome.runtime.sendMessage({ type: "stats", total, safe, suspicious });
}

scanLinks();
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "rescan") scanLinks();
});
