chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "scan-image",
    title: "Scan image for hidden data",
    contexts: ["image"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "scan-image" && tab?.id) {
    // Send the image URL to the content script in this tab
    chrome.tabs.sendMessage(tab.id, { cmd: "scan-image", srcUrl: info.srcUrl });
  }
});
