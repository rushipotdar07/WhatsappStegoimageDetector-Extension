document.getElementById("scan").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      alert("🔍 Scanning all visible images for hidden data...");
    },
  });
});
