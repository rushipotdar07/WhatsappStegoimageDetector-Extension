const scanned = new Set();

chrome.runtime.onMessage.addListener(async (msg) => {
  if (msg?.cmd !== "scan-image" || !msg.srcUrl) return;

  if (scanned.has(msg.srcUrl)) {
    showBanner("Already scanned this image.", "yellow");
    return;
  }
  scanned.add(msg.srcUrl);

  try {
    // fetch in page context so blob: URLs work
    const resp = await fetch(msg.srcUrl);
    const ab = await resp.arrayBuffer();
    const mime = resp.headers.get("content-type") || "image/png";
    const file = new File([ab], "wa-image", { type: mime });

    const result = await analyzeArrayBuffer(ab, "wa-image", ab.byteLength, file);

    if (result.level === "alert") {
      showBanner("⚠️ Suspicious: " + result.summary, "red");
    } else if (result.level === "warn") {
      showBanner("⚠️ Warning: " + result.summary, "yellow");
    } else {
      showBanner("✅ Safe: " + (result.message || "No hidden/appended data detected."), "green");
    }
  } catch (e) {
    console.error("Scan error:", e);
    showBanner("Scan failed (blob revoked or CORS). Reopen image and try again.", "red");
  }
});

function showBanner(text, tone) {
  const colors = { red: "#4b1115", yellow: "#4b3610", green: "#0e3f29" };
  const el = document.createElement("div");
  el.textContent = text;
  el.style.cssText = `
    position: fixed; top: 10px; left: 50%; transform: translateX(-50%);
    max-width: 90vw; padding: 10px 14px; border-radius: 8px;
    color: #fff; background: ${colors[tone] || "#222"};
    font: 600 13px/1.3 system-ui, -apple-system, Segoe UI, Roboto, Arial;
    z-index: 999999; box-shadow: 0 6px 20px rgba(0,0,0,.4);
  `;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

