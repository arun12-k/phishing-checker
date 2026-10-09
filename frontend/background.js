const API = "http://127.0.0.1:8080/predict";

chrome.runtime.onInstalled.addListener(() => {
  console.info("Phishing Link Checker installed");
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== "manualCheck") return false;
  checkUrl(message.url)
    .then(sendResponse)
    .catch((error) => sendResponse({ label: "unknown", score: 0, error: error.message }));
  return true;
});

async function checkUrl(value) {
  const url = String(value || "").trim();
  if (!url) return { label: "unknown", score: 0, error: "Enter a URL." };
  const response = await fetch(API, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(8000),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.message || `Analysis failed (${response.status}).`);
  }
  return response.json();
}
