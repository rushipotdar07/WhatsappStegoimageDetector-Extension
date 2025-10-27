// scanner.js — scans a single image buffer; optional File for LSB
async function analyzeArrayBuffer(ab, fileName = "unknown", fileSize = 0, file = null) {
    const view = new Uint8Array(ab);
    const isPNG = view[0] === 0x89 && view[1] === 0x50 && view[2] === 0x4E && view[3] === 0x47;
    const isJPG = view[0] === 0xFF && view[1] === 0xD8 && view[2] === 0xFF;

    // 1) appended data after EOF
    const eofIndex = findEOF(view, isJPG, isPNG);
    let tail = new Uint8Array(0);
    if (eofIndex > 0 && eofIndex < view.length) tail = view.slice(eofIndex);
    const tailInfo = analyzeTail(tail);

    // 2) LSB (canvas) — only if we have a File and it’s PNG/JPEG
    let lsbScore = 0, lsbSummary = "No LSB check.";
    if (file && (isPNG || isJPG)) {
        try {
            const dataUrl = await readDataURL(file);
            const img = await loadImage(dataUrl);
            const { score, summary } = lsbBlockChi2(img); // stronger block chi2
            lsbScore = score;
            lsbSummary = summary;
        } catch { }
    }

    // combine
    const combined = Math.min(100, Math.round(tailInfo.score * 0.6 + lsbScore * 0.4));
    const ALERT = 40; // sensitive but not crazy
    const WARN = 25;

    let level = "safe";
    if (combined >= ALERT) level = "alert";
    else if (combined >= WARN) level = "warn";

    const message = level === "alert"
        ? "Hidden or appended data likely present."
        : level === "warn"
            ? "Possible hidden data indicators."
            : "Image looks clean — no hidden or appended data detected.";

    return {
        suspicious: level === "alert",
        level, score: combined,
        fileName, fileSize,
        summary: `${tailInfo.summary} | ${lsbSummary}`,
        message
    };
}

// ---------- EOF / tail ----------
function findEOF(v, isJPG, isPNG) {
    if (isJPG) { for (let i = v.length - 2; i >= 0; i--) if (v[i] === 0xFF && v[i + 1] === 0xD9) return i + 2; }
    if (isPNG) { for (let i = v.length - 12; i >= 0; i--) if (v[i + 4] === 0x49 && v[i + 5] === 0x45 && v[i + 6] === 0x4E && v[i + 7] === 0x44) return i + 12; }
    return -1;
}

function analyzeTail(tail) {
    if (tail.length === 0) return { score: 0, summary: "No extra data after EOF." };
    const printable = printableFraction(tail);
    const entropy = shannonEntropy(tail);
    const sig = findNonImageSig(tail);
    let score = 0;
    if (tail.length > 64) score += 20;
    if (printable > 0.25) score += 25;
    if (entropy > 6.2) score += 25;
    if (sig) score += 35;
    return {
        score: Math.min(100, score),
        summary: `Tail=${tail.length}B, printable=${(printable * 100).toFixed(1)}%, entropy=${entropy.toFixed(2)}, ${sig ? ("sig=" + sig) : "no sig"}`
    };
}

function findNonImageSig(data) {
    const sigs = [
        [0x50, 0x4B, 0x03, 0x04, "ZIP/APK"],
        [0x52, 0x61, 0x72, 0x21, "RAR"],
        [0x25, 0x50, 0x44, 0x46, "PDF"],
        [0x4D, 0x5A, "EXE/MZ"],
        [0x7F, 0x45, 0x4C, 0x46, "ELF"]
    ];
    for (let i = 0; i < data.length - 8; i++) {
        for (const s of sigs) {
            let ok = true; for (let j = 0; j < s.length - 1; j++) { if (data[i + j] !== s[j]) { ok = false; break; } }
            if (ok) return s[s.length - 1];
        }
    }
    return null;
}

// ---------- LSB: block-based chi-square (detects subtle embeds in real photos) ----------
function lsbBlockChi2(img) {
    const maxPixels = 800 * 800;
    const scale = Math.min(1, Math.sqrt(maxPixels / (img.width * img.height)));
    const w = Math.max(1, Math.floor(img.width * scale));
    const h = Math.max(1, Math.floor(img.height * scale));

    const c = document.createElement("canvas");
    c.width = w; c.height = h;
    const x = c.getContext("2d");
    x.drawImage(img, 0, 0, w, h);
    const d = x.getImageData(0, 0, w, h).data;

    const BS = 24; // block size
    let chi2sum = 0, blocks = 0;

    for (let by = 0; by < h; by += BS) {
        for (let bx = 0; bx < w; bx += BS) {
            let c0 = 0, c1 = 0;
            for (let y = by; y < Math.min(by + BS, h); y++) {
                for (let x1 = bx; x1 < Math.min(bx + BS, w); x1++) {
                    const idx = (y * w + x1) * 4;
                    c0 += ((d[idx] & 1) === 0) + ((d[idx + 1] & 1) === 0) + ((d[idx + 2] & 1) === 0);
                    c1 += ((d[idx] & 1) === 1) + ((d[idx + 1] & 1) === 1) + ((d[idx + 2] & 1) === 1);
                }
            }
            const tot = c0 + c1; if (tot < 50) continue;
            const exp = tot / 2;
            const chi2 = ((c0 - exp) ** 2 / exp) + ((c1 - exp) ** 2 / exp);
            chi2sum += chi2; blocks++;
        }
    }
    const chi2avg = blocks ? chi2sum / blocks : 0;
    // Map avg chi2 close to 0 (too even) OR extremely high (too odd) as suspicious
    // Convert to 0..100 score with a soft window; tuned for photos
    let score = 0;
    if (chi2avg < 0.8) score = Math.min(100, Math.round((0.8 - chi2avg) * 120)); // too even
    if (chi2avg > 3.5) score = Math.max(score, Math.min(100, Math.round((chi2avg - 3.5) * 15))); // too odd
    return { score, summary: `LSB χ²(avg)=${chi2avg.toFixed(2)} score=${score}` };
}

function printableFraction(data) { let c = 0; for (const b of data) if (b >= 32 && b <= 126) c++; return data.length ? c / data.length : 0; }
function shannonEntropy(bytes) { const f = new Array(256).fill(0); for (const b of bytes) f[b]++; let H = 0, n = bytes.length || 1; for (const c of f) if (c) { const p = c / n; H -= p * Math.log2(p); } return H; }
function readDataURL(file) { return new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(file); }); }
function loadImage(url) { return new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url; }); }

if (typeof window !== "undefined") { window.analyzeArrayBuffer = analyzeArrayBuffer; }
