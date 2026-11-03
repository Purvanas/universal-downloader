const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { Readable, Transform } = require("stream");
const { pipeline } = require("stream/promises");
const youtubeDlExec = require("youtube-dl-exec");
const cheerio = require("cheerio");
const { isPrivateIP, safeFetch, validateRemoteUrl } = require("./lib/network-security");
const { MAX_PREVIEW_BYTES, createPreviewByteLimit, previewContentType, previewLengthAllowed } = require("./lib/preview");
const { createSafeProxy } = require("./lib/safe-proxy");

const app = express();
function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}
const PORT = positiveInteger(process.env.PORT, 3600);
const HOST = process.env.HOST || "127.0.0.1";
const DOWNLOADS_DIR = process.env.DOWNLOADS_DIR ? path.resolve(process.env.DOWNLOADS_DIR) : path.join(__dirname, "downloads");
const GALLERY_DL = process.env.GALLERY_DL || "gallery-dl";
const YTDLP_BIN = process.env.YTDLP_BIN || "";
const youtubedl = YTDLP_BIN ? youtubeDlExec.create(YTDLP_BIN) : youtubeDlExec;
const COOKIE_FILE = process.env.COOKIE_FILE ? path.resolve(process.env.COOKIE_FILE) : path.join(__dirname, "cookies.txt");
const CONVERTER_ORIGIN = process.env.CONVERTER_ORIGIN || "https://convert.purvanas.fr";
const ERRORS_TOKEN = process.env.ERRORS_TOKEN || "";
const MAX_ACTIVE_JOBS = positiveInteger(process.env.MAX_ACTIVE_JOBS, 3);
const MAX_DOWNLOAD_BYTES = positiveInteger(process.env.MAX_DOWNLOAD_BYTES, 500 * 1024 * 1024);
const networkRelay = createSafeProxy();
let relayUrlPromise = null;

function getRelayUrl() {
  if (!relayUrlPromise) relayUrlPromise = networkRelay.listen();
  return relayUrlPromise;
}

function extractorSpawnOptions(proxyUrl) {
  return {
    env: {
      ...process.env,
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      http_proxy: proxyUrl,
      https_proxy: proxyUrl,
      FTP_PROXY: proxyUrl,
      ftp_proxy: proxyUrl,
      ALL_PROXY: proxyUrl,
      all_proxy: proxyUrl,
      NO_PROXY: "",
      no_proxy: "",
    },
  };
}

function secureYtDlpOptions(options, proxyUrl) {
  return {
    ...options,
    ignoreConfig: true,
    proxy: proxyUrl,
    // Keep every media transfer inside yt-dlp's proxy-aware HTTP stack. FFmpeg
    // remains available for local merge/transcode post-processing only.
    downloader: "native",
  };
}

if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
// ===== INPUT VALIDATION =====
const ALLOWED_AUDIO_FORMATS = new Set(['mp3', 'm4a', 'opus', 'wav', 'flac', 'aac']);
const ALLOWED_VIDEO_QUALITIES = new Set(['best', '144', '240', '360', '480', '720', '1080', '1440', '2160', '4320']);
const ALLOWED_FORMATS = new Set(['video', 'audio', 'image', 'direct']);
const MAX_URL_LENGTH = 2048;
const PREVIEW_TTL_MS = 15 * 60 * 1000;
const MAX_PREVIEW_TARGETS = 1_000;
const previewTargets = new Map();

function sanitizeUrl(raw) {
  if (typeof raw !== 'string') return null;
  const url = raw.trim();
  if (url.length === 0 || url.length > MAX_URL_LENGTH) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  if (/[\x00-\x1f\x7f`]/.test(url)) return null;
  return url;
}

function safeDecodeComponent(value, fallback = "media") {
  const raw = typeof value === "string" && value ? value : fallback;
  try { return decodeURIComponent(raw); } catch { return raw; }
}

function previewPath(rawUrl) {
  if (typeof rawUrl !== "string") return null;
  if (/^\/api\/preview\/[a-f0-9]{64}$/.test(rawUrl)) return rawUrl;
  const sanitized = sanitizeUrl(rawUrl);
  if (!sanitized) return null;
  let parsed;
  try { parsed = new URL(sanitized); } catch { return null; }
  if (parsed.username || parsed.password) return null;
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  if (port !== 80 && port !== 443) return null;

  const now = Date.now();
  for (const [token, target] of previewTargets) {
    if (target.expiresAt <= now) previewTargets.delete(token);
  }
  const token = crypto.createHash("sha256").update(parsed.href).digest("hex");
  previewTargets.delete(token);
  previewTargets.set(token, { url: parsed.href, expiresAt: now + PREVIEW_TTL_MS });
  while (previewTargets.size > MAX_PREVIEW_TARGETS) previewTargets.delete(previewTargets.keys().next().value);
  return `/api/preview/${token}`;
}

function shortText(value, maxLength = 500) {
  return typeof value === "string" ? value.substring(0, maxLength) : "";
}

function sanitizeActivityLog(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(-30).map(entry => {
    const action = shortText(entry?.a, 40).replace(/[^a-z0-9-]/gi, "");
    const detail = ["analyze", "scan"].includes(action)
      ? ""
      : shortText(entry?.d, 200).replace(/(?:https?:\/\/|www\.)\S+/gi, "[url]");
    return { t: shortText(entry?.t, 8), a: action, d: detail };
  });
}

function loggableUrl(value) {
  try {
    const parsed = new URL(String(value));
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    return parsed.href.substring(0, MAX_URL_LENGTH);
  } catch {
    return "invalid-url";
  }
}

async function readTextLimited(response, maxBytes) {
  const declared = Number.parseInt(response.headers.get("content-length") || "0", 10);
  if (Number.isFinite(declared) && declared > maxBytes) throw new Error("Page trop grande");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maxBytes) throw new Error("Page trop grande");
      chunks.push(chunk);
    }
  } catch (error) {
    try { await reader.cancel(); } catch {}
    throw error;
  }
  return Buffer.concat(chunks, total).toString("utf8");
}



// ===== SECURITY =====
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const requestWindows = new Map();
const previewRequestWindows = new Map();
app.use("/api", (req, res, next) => {
  // Preview tokens can fan out for a playlist; their creation is already
  // bounded by the rate-limited analysis routes and the in-memory registry.
  const now = Date.now();
  const key = req.ip;
  if (req.path.startsWith("/preview/")) {
    const currentPreview = previewRequestWindows.get(key);
    const previewEntry = !currentPreview || now - currentPreview.startedAt > 15 * 60 * 1000
      ? { startedAt: now, count: 1 }
      : { ...currentPreview, count: currentPreview.count + 1 };
    previewRequestWindows.set(key, previewEntry);
    if (previewEntry.count > 600) return res.status(429).end();
    return next();
  }
  const current = requestWindows.get(key);
  const entry = !current || now - current.startedAt > 15 * 60 * 1000 ? { startedAt: now, count: 1 } : { ...current, count: current.count + 1 };
  requestWindows.set(key, entry);
  if (entry.count > 180) return res.status(429).json({ error: "Trop de requetes, reessayez plus tard" });
  next();
});

app.get("/api/preview/:token", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  const token = typeof req.params.token === "string" ? req.params.token : "";
  const target = /^[a-f0-9]{64}$/.test(token) ? previewTargets.get(token) : null;
  if (!target || target.expiresAt <= Date.now()) {
    if (target) previewTargets.delete(token);
    return res.status(404).end();
  }
  target.expiresAt = Date.now() + PREVIEW_TTL_MS;

  try {
    const response = await safeFetch(target.url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; UniversalDownloaderPreview/1.0)",
        Accept: "image/jpeg,image/png,image/webp,image/gif",
        "Accept-Encoding": "identity",
      },
      signal: AbortSignal.timeout(10_000),
    });
    const contentType = previewContentType(response.headers.get("content-type"));
    if (!response.ok || !response.body || !contentType || !previewLengthAllowed(response.headers.get("content-length"))) {
      try { await response.body?.cancel(); } catch {}
      return res.status(415).end();
    }
    res.setHeader("Content-Type", contentType);
    await pipeline(Readable.fromWeb(response.body), createPreviewByteLimit(MAX_PREVIEW_BYTES), res);
  } catch {
    if (res.headersSent) return res.destroy();
    return res.status(422).end();
  }
});
setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [key, value] of requestWindows) if (value.startedAt < cutoff) requestWindows.delete(key);
  for (const [key, value] of previewRequestWindows) if (value.startedAt < cutoff) previewRequestWindows.delete(key);
}, 15 * 60 * 1000).unref();

// ===== IN-MEMORY STATE =====
const jobs = new Map(); // id -> { status, percent, speed, eta, filePath, fileName, error }
let activeAnalyses = 0;
let pendingDownloads = 0;

function cookieOptions() {
  return fs.existsSync(COOKIE_FILE) ? { cookies: COOKIE_FILE } : {};
}

function activeJobCount() {
  return [...jobs.values()].filter(job => ["starting", "downloading", "processing"].includes(job.status)).length;
}

function activeWorkCount() {
  return activeAnalyses + pendingDownloads + activeJobCount();
}

function terminateProcess(proc, graceMs = 2_000) {
  if (!proc || proc.exitCode !== null) return;
  try { proc.kill("SIGTERM"); } catch {}
  const forceTimer = setTimeout(() => {
    if (proc.exitCode === null) try { proc.kill("SIGKILL"); } catch {}
  }, graceMs);
  forceTimer.unref();
  proc.once("close", () => clearTimeout(forceTimer));
}

function requireAdmin(req, res, next) {
  if (!ERRORS_TOKEN) return res.status(404).json({ error: "Not found" });
  const provided = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const expected = Buffer.from(ERRORS_TOKEN);
  const candidate = Buffer.from(provided);
  if (candidate.length !== expected.length || !crypto.timingSafeEqual(candidate, expected)) return res.status(403).json({ error: "Forbidden" });
  next();
}

async function runYtDlpJson(url, options, { timeoutMs = 45_000, maxOutputBytes = 10 * 1024 * 1024 } = {}) {
  const proxyUrl = await getRelayUrl();
  return new Promise((resolve, reject) => {
    const proc = youtubedl.exec(url, secureYtDlpOptions(options, proxyUrl), extractorSpawnOptions(proxyUrl));
    let stdout = "";
    let stderr = "";
    let failure = null;
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback(value);
    };
    const timer = setTimeout(() => {
      failure = new Error("Analyse trop longue");
      terminateProcess(proc);
    }, timeoutMs);
    timer.unref();

    proc.stdout.on("data", chunk => {
      if (failure) return;
      stdout += chunk.toString();
      if (Buffer.byteLength(stdout) > maxOutputBytes && !failure) {
        failure = new Error("Reponse de l'extracteur trop volumineuse");
        terminateProcess(proc);
      }
    });
    proc.stderr.on("data", chunk => { stderr = (stderr + chunk.toString()).slice(-16_384); });
    proc.on("error", error => finish(reject, error));
    proc.on("close", code => {
      if (failure) return finish(reject, failure);
      if (code !== 0) {
        const error = new Error("Echec de l'extracteur");
        error.stderr = stderr;
        return finish(reject, error);
      }
      try { finish(resolve, JSON.parse(stdout)); }
      catch { finish(reject, new Error("Reponse invalide de l'extracteur")); }
    });
  });
}

// ===== ANALYZE URL =====
app.post("/api/analyze", async (req, res) => {
  let { url } = req.body || {};
  url = sanitizeUrl(url);
  if (!url) return res.status(400).json({ error: "URL invalide" });

  // SSRF protection
  const ssrfCheck = await validateRemoteUrl(url);
  if (!ssrfCheck.safe) {
    return res.status(403).json({ error: ssrfCheck.reason });
  }

  // Early detection for direct CDN image/video URLs (e.g. preview.redd.it, i.redd.it)
  // yt-dlp cannot handle these because Reddit redirects them to www.reddit.com/media?url=...
  const directCdnInfo = buildDirectCdnInfo(url);
  if (directCdnInfo) return res.json(directCdnInfo);

  if (activeWorkCount() >= MAX_ACTIVE_JOBS) {
    return res.status(429).json({ error: "Le serveur traite deja trop de demandes" });
  }
  activeAnalyses++;

  try {
    const info = await runYtDlpJson(url, {
      dumpSingleJson: true,
      ...cookieOptions(),
      jsRuntimes: "node",
      noWarnings: true,
      preferFreeFormats: true,
      socketTimeout: 20,
      retries: 1,
    });

    // ===== PLAYLIST / CAROUSEL DETECTION =====
    // Instagram carousels, multi-media Twitter posts, etc. return entries[]
    if (info.entries && Array.isArray(info.entries) && info.entries.length > 1) {
      const source = detectSource(url, info.extractor || info.extractor_key || "");
      const IMG = new Set(["jpg","jpeg","png","webp","gif","avif"]);
      const items = info.entries.map((entry, idx) => {
        const hasV = entry.formats?.some(f => f.vcodec && f.vcodec !== "none") ?? false;
        const hasA = entry.formats?.some(f => f.acodec && f.acodec !== "none") ?? false;
        const isImg = !hasV && (!hasA || IMG.has((entry.ext || "").toLowerCase()));
        const qs = new Set();
        if (entry.formats) for (const f of entry.formats) if (f.height) qs.add(f.height);
        return {
          index: idx + 1, // 1-based for yt-dlp --playlist-items
          title: entry.title || entry.fulltitle || `Media ${idx + 1}`,
          thumbnail: previewPath(entry.thumbnail || (isImg ? (entry.url || null) : null)),
          duration: isImg ? null : (entry.duration || null),
          type: isImg ? "image" : "video",
          hasVideo: hasV,
          hasAudio: hasA,
          qualities: [...qs].sort((a, b) => b - a),
        };
      });
      return res.json({
        type: "playlist",
        source,
        title: info.title || "Plusieurs medias",
        uploader: info.uploader || info.channel || null,
        count: items.length,
        items,
      });
    }

    // Extract available qualities from formats
    const qualities = new Set();
    if (info.formats) {
      for (const f of info.formats) {
        if (f.height) qualities.add(f.height);
      }
    }

    const sortedQualities = [...qualities].sort((a, b) => b - a);
    const source = detectSource(url, info.extractor || info.extractor_key || "");

    // Detect if yt-dlp returned image content (Instagram photos, etc.)
    // If no video track AND no audio track → it's image content (photo post)
    const IMAGE_EXTS = new Set(["jpg", "jpeg", "png", "webp", "gif", "avif"]);
    const hasVideoTrack = info.formats?.some(f => f.vcodec && f.vcodec !== "none") ?? false;
    const hasAudioTrack = info.formats?.some(f => f.acodec && f.acodec !== "none") ?? false;
    const isImageContent = !hasVideoTrack && (
      !hasAudioTrack ||
      IMAGE_EXTS.has((info.ext || "").toLowerCase()) ||
      (info.formats?.length > 0 && info.formats.every(f => IMAGE_EXTS.has((f.ext || "").toLowerCase())))
    );

    return res.json({
      title: info.title || info.fulltitle || "Sans titre",
      thumbnail: previewPath(info.thumbnail),
      duration: isImageContent ? null : (info.duration || null),
      uploader: info.uploader || info.channel || null,
      type: isImageContent ? "image" : "video",
      source,
      qualities: isImageContent ? [] : (sortedQualities.length > 0 ? sortedQualities : [1080, 720, 480, 360]),
      hasVideo: hasVideoTrack,
      hasAudio: hasAudioTrack,
    });
  } catch (ytErr) {
    // yt-dlp failed — try fxtwitter for Twitter/X
    if (isTwitterUrl(url)) {
      try {
        const fxInfo = await fxtwitterInfo(url);
        if (fxInfo) return res.json(fxInfo);
      } catch {}
    }
    // Try gallery-dl (handles Instagram images/carousels with cookies)
    try {
      const gdlInfo = await galleryDlInfo(url);
      if (gdlInfo) {
        // Multi-item carousel → return playlist as-is
        if (gdlInfo.type === "playlist") return res.json(gdlInfo);
        // Single item → return single-media response with directUrls so download uses direct fetch
        return res.json({
          title: gdlInfo.title || "Media",
          thumbnail: previewPath(gdlInfo.url),
          duration: null,
          uploader: gdlInfo.uploader || null,
          type: gdlInfo.type || "image",
          source: detectSource(url, ""),
          qualities: [],
          hasVideo: gdlInfo.type === "video",
          hasAudio: gdlInfo.type === "video",
          directUrls: { best: gdlInfo.url },
        });
      }
    } catch {}
    // Try direct media URL (images, videos, audio)
    try {
      const directInfo = await tryDirectMedia(url);
      if (directInfo) return res.json(directInfo);
    } catch {}

    // ===== UNIVERSAL FALLBACK: scan the page for any media =====
    // This makes the tool work on ANY site — even unknown small ones.
    try {
      const scanInfo = await scanPage(url);
      if (scanInfo && scanInfo.items && scanInfo.items.length > 0) {
        // Single item → return as single-media response for the classic preview UI
        if (scanInfo.items.length === 1) {
          const only = scanInfo.items[0];
          return res.json({
            title: scanInfo.title || only.title,
            thumbnail: previewPath(only.thumbnail),
            duration: null,
            uploader: null,
            type: only.type,
            source: detectSource(url, "") || "other",
            qualities: [],
            hasVideo: only.type === "video",
            hasAudio: only.type === "video" || only.type === "audio",
            directUrls: only.directUrls,
          });
        }
        // Multi-item → playlist (reuses grid UI)
        return res.json(scanInfo);
      }
    } catch {}

    // All methods exhausted
    const detail = ytErr.stderr ? ytErr.stderr.substring(0, 500) : ytErr.message;
    logError("analyze", url, detail);
    return res.status(422).json({ error: "Impossible d'analyser cette URL." });
  } finally {
    activeAnalyses--;
  }
});

// ===== SCAN PAGE =====
// Fetch a page and extract all downloadable media (images, videos, audio).
// Works with static HTML; third-party JavaScript is never executed by this service.
app.post("/api/scan", async (req, res) => {
  const url = sanitizeUrl(req.body?.url);
  if (!url) return res.status(400).json({ error: "URL invalide" });

  const ssrfCheck = await validateRemoteUrl(url);
  if (!ssrfCheck.safe) return res.status(403).json({ error: ssrfCheck.reason });
  if (activeWorkCount() >= MAX_ACTIVE_JOBS) {
    return res.status(429).json({ error: "Le serveur traite deja trop de demandes" });
  }
  activeAnalyses++;

  try {
    const pageInfo = await scanPage(url);
    return res.json(pageInfo);
  } catch (err) {
    logError("scan", url, err.message || String(err));
    return res.status(422).json({ error: "Impossible d'analyser cette page: " + (err.message || "erreur inconnue").substring(0, 150) });
  } finally {
    activeAnalyses--;
  }
});

async function scanPage(url) {
  // Fetch HTML with a realistic user agent
  const resp = await safeFetch(url, {
    signal: AbortSignal.timeout(15000),
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.5",
    },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} sur la page`);

  const ct = (resp.headers.get("content-type") || "").toLowerCase();
  if (!ct.includes("text/html") && !ct.includes("xml")) {
    throw new Error("La reponse n'est pas du HTML");
  }

  const html = await readTextLimited(resp, 10 * 1024 * 1024);

  const $ = cheerio.load(html);
  const base = new URL(url);
  const finalBase = new URL(resp.url || url);
  const pageTitle = ($("title").first().text() || "").trim().substring(0, 200) ||
                    ($('meta[property="og:title"]').attr("content") || "").substring(0, 200) ||
                    base.hostname;

  const foundUrls = new Map(); // normalized url -> { type, raw, thumbnail, width, height }
  const MEDIA_EXT = /\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|mp4|webm|mov|m4v|mp3|wav|m4a|ogg|flac|aac|opus|pdf|zip|m3u8|mpd)(\?|$|#)/i;
  const IMAGE_EXT = /\.(jpg|jpeg|png|gif|webp|avif|svg|bmp)(\?|$|#)/i;
  const VIDEO_EXT = /\.(mp4|webm|mov|m4v|m3u8|mpd)(\?|$|#)/i;
  const AUDIO_EXT = /\.(mp3|wav|m4a|ogg|flac|aac|opus)(\?|$|#)/i;

  function resolveUrl(u) {
    if (!u) return null;
    u = u.trim();
    if (!u || u.startsWith("data:") || u.startsWith("javascript:") || u.startsWith("blob:")) return null;
    try {
      const parsed = new URL(u, finalBase);
      const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
      if (!["http:", "https:"].includes(parsed.protocol) || hostname === "localhost" || hostname.endsWith(".localhost") || isPrivateIP(hostname)) return null;
      return parsed.href;
    } catch { return null; }
  }

  function classify(u) {
    if (VIDEO_EXT.test(u)) return "video";
    if (AUDIO_EXT.test(u)) return "audio";
    if (IMAGE_EXT.test(u)) return "image";
    return null;
  }

  function addCandidate(rawUrl, kind, opts) {
    if (foundUrls.size >= 500) return;
    const resolved = resolveUrl(rawUrl);
    if (!resolved) return;
    // Skip tiny tracking pixels, favicons by heuristic
    if (/favicon/i.test(resolved)) return;
    // Skip extreme small data URIs already filtered by resolve
    const existing = foundUrls.get(resolved);
    const entry = {
      type: kind || classify(resolved) || "other",
      thumbnail: (opts && opts.thumbnail) || null,
      width: (opts && opts.width) || null,
      height: (opts && opts.height) || null,
    };
    if (!existing) foundUrls.set(resolved, entry);
    else {
      // Prefer better type classification
      if (existing.type === "other" && entry.type !== "other") existing.type = entry.type;
      if (!existing.thumbnail && entry.thumbnail) existing.thumbnail = entry.thumbnail;
    }
  }

  // 1. <img src>, data-src, data-lazy-src, srcset
  $("img").each(function() {
    const el = $(this);
    const candidates = [
      el.attr("src"),
      el.attr("data-src"),
      el.attr("data-lazy-src"),
      el.attr("data-original"),
      el.attr("data-hd"),
      el.attr("data-full"),
    ];
    for (const c of candidates) if (c) addCandidate(c, "image");
    // srcset: pick the widest
    const srcset = el.attr("srcset") || el.attr("data-srcset");
    if (srcset) {
      const parts = srcset.split(",").map(s => s.trim().split(/\s+/));
      if (parts.length > 0) {
        // Pick the last (usually largest) and first for fallback
        const last = parts[parts.length - 1][0];
        if (last) addCandidate(last, "image");
      }
    }
  });

  // 2. <picture><source srcset>
  $("picture source").each(function() {
    const srcset = $(this).attr("srcset");
    if (srcset) {
      const parts = srcset.split(",").map(s => s.trim().split(/\s+/));
      const last = parts[parts.length - 1]?.[0];
      if (last) addCandidate(last, "image");
    }
  });

  // 3. <video src>, <video><source src>, poster
  $("video").each(function() {
    const el = $(this);
    const src = el.attr("src");
    if (src) addCandidate(src, "video", { thumbnail: resolveUrl(el.attr("poster")) });
    const poster = el.attr("poster");
    el.find("source").each(function() {
      const s = $(this).attr("src");
      if (s) addCandidate(s, "video", { thumbnail: resolveUrl(poster) });
    });
  });

  // 4. <audio src>, <audio><source src>
  $("audio").each(function() {
    const el = $(this);
    const src = el.attr("src");
    if (src) addCandidate(src, "audio");
    el.find("source").each(function() {
      const s = $(this).attr("src");
      if (s) addCandidate(s, "audio");
    });
  });

  // 5. <a href> pointing to media files
  $("a[href]").each(function() {
    const href = $(this).attr("href");
    if (href && MEDIA_EXT.test(href)) addCandidate(href);
  });

  // 6. Meta tags: og:image, og:video, twitter:image, twitter:player:stream
  $('meta[property="og:image"], meta[name="og:image"], meta[property="og:image:url"], meta[property="og:image:secure_url"]').each(function() {
    const c = $(this).attr("content");
    if (c) addCandidate(c, "image");
  });
  $('meta[property="og:video"], meta[property="og:video:url"], meta[property="og:video:secure_url"], meta[name="twitter:player:stream"]').each(function() {
    const c = $(this).attr("content");
    if (c) addCandidate(c, "video");
  });

  // 7. Background images in <style> attributes (inline)
  $("[style*='background']").each(function() {
    const style = $(this).attr("style") || "";
    const match = style.match(/url\(['"]?([^'")]+)['"]?\)/);
    if (match) addCandidate(match[1], "image");
  });

  // 8. JSON-LD schema.org image/video
  $('script[type="application/ld+json"]').each(function() {
    try {
      const json = JSON.parse($(this).text());
      const walk = (obj) => {
        if (!obj) return;
        if (Array.isArray(obj)) return obj.forEach(walk);
        if (typeof obj === "object") {
          for (const [k, v] of Object.entries(obj)) {
            if ((k === "image" || k === "contentUrl" || k === "url" || k === "thumbnailUrl") && typeof v === "string" && MEDIA_EXT.test(v)) {
              addCandidate(v);
            } else if (typeof v === "object") walk(v);
          }
        }
      };
      walk(json);
    } catch {}
  });

  // Build items list — prioritize videos/audio over images, cap at 200
  const MAX_SCAN_RESULTS = 200;
  const allItems = [];
  let idx = 0;
  for (const [u, info] of foundUrls) {
    if (info.type === "other") continue;
    allItems.push({
      index: ++idx,
      title: safeDecodeComponent(new URL(u).pathname.split("/").pop()).substring(0, 80) || `Media ${idx}`,
      thumbnail: previewPath(info.type === "image" ? u : info.thumbnail),
      duration: null,
      type: info.type,
      hasVideo: info.type === "video",
      hasAudio: info.type === "video" || info.type === "audio",
      qualities: [],
      directUrls: { best: u },
    });
  }
  // Sort: videos first, then audio, then images
  const typeOrder = { video: 0, audio: 1, image: 2 };
  allItems.sort((a, b) => (typeOrder[a.type] ?? 3) - (typeOrder[b.type] ?? 3));
  const truncated = allItems.length > MAX_SCAN_RESULTS;
  const items = allItems.slice(0, MAX_SCAN_RESULTS).map((it, i) => ({ ...it, index: i + 1 }));

  // Also try yt-dlp on the page itself in the background (YouTube embed, etc.)
  // Skipped here for speed; client can do a regular analyze if needed.

  if (items.length === 0) {
    throw new Error("Aucun media trouve sur cette page");
  }

  return {
    type: "playlist",
    source: "scan",
    title: pageTitle,
    uploader: null,
    count: items.length,
    totalFound: allItems.length,
    truncated,
    items,
    scannedUrl: url,
  };
}

// ===== START DOWNLOAD =====
app.post("/api/download", async (req, res) => {
  const body = req.body || {};
  const { format, quality, audioFormat, title, playlistIndex } = body;
  const url = sanitizeUrl(body.url);
  if (!url) return res.status(400).json({ error: "URL invalide" });
  if (format && !ALLOWED_FORMATS.has(format)) return res.status(400).json({ error: "Format invalide" });
  if (quality && !ALLOWED_VIDEO_QUALITIES.has(String(quality))) return res.status(400).json({ error: "Qualite invalide" });
  if (audioFormat && !ALLOWED_AUDIO_FORMATS.has(audioFormat)) return res.status(400).json({ error: "Format audio invalide" });
  if (format === "direct" && !sanitizeUrl(body.directUrl)) return res.status(400).json({ error: "URL directe invalide" });
  if (activeWorkCount() >= MAX_ACTIVE_JOBS) return res.status(429).json({ error: "Le serveur traite deja trop de telechargements" });

  // Validate playlistIndex (must be integer in [1, 50])
  let playlistIdx = null;
  if (playlistIndex !== undefined && playlistIndex !== null) {
    const n = parseInt(playlistIndex, 10);
    if (!Number.isInteger(n) || n < 1 || n > 50) {
      return res.status(400).json({ error: "Index de playlist invalide" });
    }
    playlistIdx = n;
  }

  pendingDownloads++;
  try {
    // SSRF protection
    const ssrfCheck = await validateRemoteUrl(url);
    if (!ssrfCheck.safe) {
      return res.status(403).json({ error: ssrfCheck.reason });
    }

    // Also validate directUrl if provided (fxtwitter direct downloads)
    if (body.directUrl) {
      const directCheck = await validateRemoteUrl(body.directUrl);
      if (!directCheck.safe) {
        return res.status(403).json({ error: directCheck.reason });
      }
    }

    const id = crypto.randomUUID();
    const safeTitle = typeof title === "string" ? title.substring(0, 300) : null;
    jobs.set(id, { status: "starting", percent: 0, speed: null, eta: null, filePath: null, fileName: null, error: null, title: safeTitle, createdAt: Date.now(), process: null, abortController: null });

    try {
      if (format === "image") {
        await startImageDownload(id, url, playlistIdx);
      } else if (format === "audio") {
        await startAudioDownload(id, url, audioFormat || "mp3", playlistIdx);
      } else if (format === "direct") {
        // Direct MP4 URL (e.g. from fxtwitter)
        startDirectDownload(id, url, body.directUrl);
      } else {
        await startVideoDownload(id, url, quality || "best", playlistIdx);
      }
    } catch (error) {
      cleanupJob(id);
      throw error;
    }

    res.json({ downloadId: id });
  } finally {
    pendingDownloads--;
  }
});

// ===== DOWNLOAD PROGRESS (SSE) =====
app.get("/api/progress/:id", (req, res) => {
  const { id } = req.params;
  const job = jobs.get(id);
  if (!job) return res.status(404).json({ error: "Job introuvable" });

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });

  const interval = setInterval(() => {
    const j = jobs.get(id);
    if (!j) {
      clearInterval(interval);
      res.write(`data: ${JSON.stringify({ status: "error", error: "Job disparu" })}\n\n`);
      res.end();
      return;
    }
    res.write(`data: ${JSON.stringify({ status: j.status, percent: j.percent, speed: j.speed, eta: j.eta, error: j.error })}\n\n`);
    if (j.status === "done" || j.status === "error") {
      clearInterval(interval);
      setTimeout(() => res.end(), 100);
    }
  }, 500);

  req.on("close", () => clearInterval(interval));
});

// ===== SERVE FILE =====
app.get("/api/file/:id", (req, res) => {
  const { id } = req.params;
  const job = jobs.get(id);
  if (!job || !job.filePath) return res.status(404).json({ error: "Fichier introuvable" });
  if (!fs.existsSync(job.filePath)) return res.status(404).json({ error: "Fichier expire" });

  res.setHeader("Access-Control-Allow-Origin", CONVERTER_ORIGIN);
  res.download(job.filePath, job.fileName);
});

// ===== CLEANUP A JOB =====
app.delete("/api/job/:id", (req, res) => {
  cleanupJob(req.params.id);
  res.json({ ok: true });
});

app.post("/api/job/:id/cleanup", (req, res) => {
  cleanupJob(req.params.id);
  res.json({ ok: true });
});

function cleanupJob(id) {
  const job = jobs.get(id);
  if (job?.process) {
    terminateProcess(job.process);
  }
  if (job?.abortController) job.abortController.abort();
  if (job && job.filePath) {
    try { fs.unlinkSync(job.filePath); } catch {}
  }
  jobs.delete(id);
}

// ===== DOWNLOAD FUNCTIONS =====

async function startVideoDownload(id, url, quality, playlistIdx) {
  const proxyUrl = await getRelayUrl();
  const outputTemplate = path.join(DOWNLOADS_DIR, `${id}.%(ext)s`);
  const formatStr = quality === "best"
    ? "bv+ba/b"
    : `bv[height<=${quality}]+ba/b[height<=${quality}]`;

  const opts = {
    format: formatStr,
    output: outputTemplate,
    mergeOutputFormat: "mp4",
    ...cookieOptions(),
    jsRuntimes: "node",
    noWarnings: true,
    socketTimeout: 30,
    retries: 3,
    fragmentRetries: 3,
    maxFilesize: MAX_DOWNLOAD_BYTES,
  };
  if (playlistIdx) opts.playlistItems = String(playlistIdx);
  const proc = youtubedl.exec(url, secureYtDlpOptions(opts, proxyUrl), extractorSpawnOptions(proxyUrl));
  jobs.get(id).process = proc;
  trackProgress(id, proc);
}

async function startAudioDownload(id, url, audioFormat, playlistIdx) {
  const proxyUrl = await getRelayUrl();
  const outputTemplate = path.join(DOWNLOADS_DIR, `${id}.%(ext)s`);

  const opts = {
    extractAudio: true,
    audioFormat: audioFormat,
    audioQuality: 0,
    ...cookieOptions(),
    jsRuntimes: "node",
    output: outputTemplate,
    noWarnings: true,
    socketTimeout: 30,
    retries: 3,
    fragmentRetries: 3,
    maxFilesize: MAX_DOWNLOAD_BYTES,
  };
  if (playlistIdx) opts.playlistItems = String(playlistIdx);
  const proc = youtubedl.exec(url, secureYtDlpOptions(opts, proxyUrl), extractorSpawnOptions(proxyUrl));
  jobs.get(id).process = proc;
  trackProgress(id, proc);
}

async function startImageDownload(id, url, playlistIdx) {
  const job = jobs.get(id);
  job.status = "downloading";
  const proxyUrl = await getRelayUrl();

  // When a playlist index is specified, try yt-dlp first (it handles Instagram carousels natively)
  // Fall back to gallery-dl for single images.
  if (playlistIdx) {
    const outputTemplate = path.join(DOWNLOADS_DIR, `${id}.%(ext)s`);
    const proc = youtubedl.exec(url, secureYtDlpOptions({
      output: outputTemplate,
      ...cookieOptions(),
      jsRuntimes: "node",
      noWarnings: true,
      playlistItems: String(playlistIdx),
      socketTimeout: 30,
      retries: 3,
      maxFilesize: MAX_DOWNLOAD_BYTES,
    }, proxyUrl), extractorSpawnOptions(proxyUrl));
    job.process = proc;
    trackProgress(id, proc);
    return;
  }

  const galleryArgs = [
    "--config-ignore",
    "--proxy", proxyUrl,
    "--dest", DOWNLOADS_DIR,
    "--filename", `${id}.{extension}`,
    "--option", "directory=[]",  // Prevent gallery-dl from creating extractor sub-dirs
    "--filesize-max", String(MAX_DOWNLOAD_BYTES),
    "--no-mtime",
    url,
  ];
  if (fs.existsSync(COOKIE_FILE)) galleryArgs.unshift("--cookies", COOKIE_FILE);
  const proc = spawn(GALLERY_DL, galleryArgs, extractorSpawnOptions(proxyUrl));
  job.process = proc;

  let stderr = "";
  proc.stderr.on("data", (d) => { stderr = (stderr + d.toString()).slice(-16_384); });

  const timeout = setTimeout(() => {
    if (!["done", "error"].includes(job.status)) {
      terminateProcess(proc);
      job.status = "error";
      job.error = "Timeout gallery-dl";
    }
  }, 5 * 60 * 1000);
  timeout.unref();
  const sizeMonitor = monitorJobOutput(id, proc);

  proc.on("error", (err) => {
    clearInterval(sizeMonitor);
    job.status = "error";
    job.error = "gallery-dl introuvable: " + err.message;
      logError("gallery-dl", url, job.error);
  });

  proc.on("close", (code) => {
    clearTimeout(timeout);
    clearInterval(sizeMonitor);
    if (job.status === "error") return; // already handled by 'error' event
    if (code === 0) {
      // gallery-dl may create sub-dirs (e.g. downloads/instagram/user/ID.jpg) — search recursively
      const filePaths = findFilesRecursive(DOWNLOADS_DIR, id);
      if (totalFileSize(filePaths) > MAX_DOWNLOAD_BYTES) {
        for (const filePath of filePaths) try { fs.unlinkSync(filePath); } catch {}
        job.status = "error";
        job.error = "Fichier trop volumineux";
        return;
      }
      if (filePaths.length > 0) {
        const srcPath = filePaths[0];
        const ext = path.extname(srcPath);
        // Move file to DOWNLOADS_DIR root so the cleanup interval can manage it
        const destPath = path.join(DOWNLOADS_DIR, id + ext);
        if (srcPath !== destPath) {
          try { fs.renameSync(srcPath, destPath); } catch { /* keep original path */ }
        }
        const finalPath = fs.existsSync(destPath) ? destPath : srcPath;
        job.filePath = finalPath;
        job.fileName = buildDownloadFilename(job.title || "download", ext, id);
        job.status = "done";
        job.percent = 100;
      } else {
        job.status = "error";
        job.error = "Fichier non trouve apres telechargement";
        logError("download", url, job.error);
      }
    } else {
      job.status = "error";
      job.error = "Echec du telechargement de l'image";
      logError("gallery-dl", url, stderr.substring(0, 500) || job.error);
    }
  });
}

function trackProgress(id, proc) {
  const job = jobs.get(id);
  job.status = "downloading";

  // yt-dlp writes progress lines to stderr (not stdout) when piped
  const parseProgressLine = (line) => {
    // Parse yt-dlp progress: [download]  45.2% of ~150.00MiB at 5.50MiB/s ETA 00:15
    const match = line.match(/(\d+\.?\d*)%\s+of\s+~?([\d.]+\w+)\s+at\s+([\d.]+\w+\/s)\s+ETA\s+([\d:]+)/);
    if (match) {
      job.percent = parseFloat(match[1]);
      job.speed = match[3];
      job.eta = match[4];
    }
    if (line.includes("[Merger]") || line.includes("[ExtractAudio]")) {
      job.status = "processing";
      job.percent = 99;
    }
  };

  proc.stdout.on("data", (data) => { parseProgressLine(data.toString()); });

  let stderr = "";
  proc.stderr.on("data", (d) => {
    const chunk = d.toString();
    stderr = (stderr + chunk).slice(-16_384);
    // yt-dlp sends progress to stderr — parse it here too
    for (const line of chunk.split("\n")) {
      parseProgressLine(line);
    }
  });

  // Server-side kill timer: abort any job stuck for more than 5 minutes
  const MAX_JOB_MS = 5 * 60 * 1000;
  const killTimer = setTimeout(() => {
    const j = jobs.get(id);
    if (j && ["downloading", "starting", "processing"].includes(j.status)) {
      terminateProcess(proc);
      j.status = "error";
      j.error = "Timeout: le telechargement a depasse la duree maximale de 5 minutes.";
      logError("download-timeout", "unknown", j.error);
    }
  }, MAX_JOB_MS);
  killTimer.unref();
  const sizeMonitor = monitorJobOutput(id, proc);

  proc.on("error", error => {
    clearTimeout(killTimer);
    clearInterval(sizeMonitor);
    job.status = "error";
    job.error = `Impossible de lancer l'extracteur: ${error.message}`.substring(0, 200);
    logError("download-process", "unknown", job.error);
  });

  proc.on("close", (code) => {
    clearTimeout(killTimer);
    clearInterval(sizeMonitor);
    job.process = null;
    if (code === 0) {
      const files = fs.readdirSync(DOWNLOADS_DIR).filter(f => f.startsWith(id));
      if (files.length > 0) {
        const final = files.find(f => !f.includes(".part") && !f.includes(".temp")) || files[0];
        const finalPath = path.join(DOWNLOADS_DIR, final);
        if (totalFileSize(files.map(file => path.join(DOWNLOADS_DIR, file))) > MAX_DOWNLOAD_BYTES) {
          for (const file of files) try { fs.unlinkSync(path.join(DOWNLOADS_DIR, file)); } catch {}
          job.status = "error";
          job.error = "Fichier trop volumineux";
          return;
        }
        job.filePath = finalPath;
        const ext = path.extname(final);
        // Use title from analyze step if available, with a unique suffix for browser downloads.
        job.fileName = buildDownloadFilename(job.title || path.basename(final, ext) || "download", ext, id);
        job.status = "done";
        job.percent = 100;
      } else {
        job.status = "error";
        job.error = "Fichier non trouve apres telechargement";
        logError("download", "unknown", job.error);
      }
    } else if (job.status !== "error") {
      // Only overwrite if not already set by the kill timer
      job.status = "error";
      job.error = "Echec du telechargement";
      logError("download", "unknown", stderr.substring(0, 500) || job.error);
    }
  });
}

function sanitizeFilename(name) {
  return name.replace(/[<>:"/\\|?*]/g, "").replace(/\s+/g, " ").trim().substring(0, 200);
}

function buildDownloadFilename(title, ext, id) {
  const cleanExt = ext && ext.startsWith(".") ? ext : `.${ext || "bin"}`;
  const suffix = [
    new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14),
    crypto.createHash("sha1").update(String(id)).digest("hex").slice(0, 8),
  ].join("-");
  const maxBaseLength = Math.max(1, 200 - suffix.length - cleanExt.length - 1);
  const base = sanitizeFilename(title || "download").substring(0, maxBaseLength) || "download";
  return `${base}-${suffix}${cleanExt}`;
}

// Recursive search for files starting with a given prefix (gallery-dl creates sub-dirs)
function findFilesRecursive(baseDir, prefix) {
  const results = [];
  function search(dir) {
    try {
      for (const item of fs.readdirSync(dir)) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        if (stat.isDirectory()) {
          search(fullPath);
        } else if (item.startsWith(prefix)) {
          results.push(fullPath);
        }
      }
    } catch {}
  }
  search(baseDir);
  return results;
}

function totalFileSize(filePaths) {
  let total = 0;
  for (const filePath of filePaths) {
    try { total += fs.statSync(filePath).size; } catch {}
  }
  return total;
}

function monitorJobOutput(id, proc) {
  const interval = setInterval(() => {
    const job = jobs.get(id);
    if (!job || ["done", "error"].includes(job.status)) return;
    const total = totalFileSize(findFilesRecursive(DOWNLOADS_DIR, id));
    if (total > MAX_DOWNLOAD_BYTES) {
      job.status = "error";
      job.error = "Fichier trop volumineux";
      terminateProcess(proc);
    }
  }, 500);
  interval.unref();
  return interval;
}

// ===== FXTWITTER FALLBACK =====
function isTwitterUrl(url) {
  const u = url.toLowerCase();
  return u.includes("twitter.com") || u.includes("x.com");
}

function extractTweetId(url) {
  const match = url.match(/status\/(\d+)/);
  return match ? match[1] : null;
}

function buildFxVideoItem(video, tweet) {
  const qualities = (video.formats || [])
    .filter(f => f.container === "mp4")
    .map(f => {
      const match = f.url.match(/\/(\d+)x(\d+)\//);
      return match ? parseInt(match[2]) : null;
    })
    .filter(Boolean)
    .sort((a, b) => b - a);
  const directUrls = {};
  for (const f of (video.formats || []).filter(f => f.container === "mp4")) {
    const m = f.url.match(/\/(\d+)x(\d+)\//);
    if (m) directUrls[parseInt(m[2])] = f.url;
  }
  directUrls["best"] = video.url;
  return {
    title: tweet.text ? tweet.text.substring(0, 100) : "Twitter video",
    thumbnail: previewPath(video.thumbnail_url),
    duration: video.duration || null,
    uploader: tweet.author ? tweet.author.name : null,
    type: "video",
    source: "twitter",
    qualities: qualities.length > 0 ? qualities : [720, 360],
    hasVideo: true,
    hasAudio: true,
    directUrls,
  };
}

function buildFxImageItem(image, tweet) {
  return {
    title: tweet.text ? tweet.text.substring(0, 100) : "Twitter image",
    thumbnail: previewPath(image.url),
    duration: null,
    uploader: tweet.author ? tweet.author.name : null,
    type: "image",
    source: "twitter",
    qualities: [],
    hasVideo: false,
    hasAudio: false,
    directUrls: { best: image.url },
  };
}

async function fxtwitterInfo(url) {
  const tweetId = extractTweetId(url);
  if (!tweetId) return null;

  const resp = await safeFetch(`https://api.fxtwitter.com/i/status/${tweetId}`, {
    signal: AbortSignal.timeout(10000),
  });
  if (!resp.ok) return null;
  const data = JSON.parse(await readTextLimited(resp, 5 * 1024 * 1024));
  if (!data.tweet) return null;

  const tweet = data.tweet;
  const media = tweet.media || {};
  const videos = media.videos || [];
  const images = (media.all || []).filter(m => m.type === "photo");
  const totalMedia = videos.length + images.length;

  // Multi-media tweet: return playlist with ALL items
  if (totalMedia > 1) {
    const items = [];
    // Preserve original order using media.all if available
    if (Array.isArray(media.all) && media.all.length === totalMedia) {
      for (const m of media.all) {
        if (m.type === "video" || m.type === "gif") {
          items.push({
            ...buildFxVideoItem(m, tweet),
            title: (tweet.text ? tweet.text.substring(0, 60) : "Video") + ` (${items.length + 1})`,
          });
        } else if (m.type === "photo") {
          items.push({
            ...buildFxImageItem(m, tweet),
            title: (tweet.text ? tweet.text.substring(0, 60) : "Image") + ` (${items.length + 1})`,
          });
        }
      }
    } else {
      for (const v of videos) items.push({ ...buildFxVideoItem(v, tweet), title: `Video (${items.length + 1})` });
      for (const i of images) items.push({ ...buildFxImageItem(i, tweet), title: `Image (${items.length + 1})` });
    }
    return {
      type: "playlist",
      source: "twitter",
      title: tweet.text ? tweet.text.substring(0, 100) : "Tweet multi-medias",
      uploader: tweet.author ? tweet.author.name : null,
      count: items.length,
      items: items.map((it, idx) => ({ ...it, index: idx + 1 })),
    };
  }

  if (videos.length > 0) return buildFxVideoItem(videos[0], tweet);
  if (images.length > 0) return buildFxImageItem(images[0], tweet);

  return null;
}

function startDirectDownload(id, originalUrl, directUrl) {
  const job = jobs.get(id);
  job.status = "downloading";

  // Extract extension from the URL path (not query string) to avoid false matches
  const urlPathExt = new URL(directUrl).pathname.match(/\.(mp4|webm|jpg|jpeg|png|webp|gif)$/i)?.[1] || "";
  let filePath = null;

  (async () => {
    const controller = new AbortController();
    job.abortController = controller;
    try {
      const response = await safeFetch(directUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          "Accept": "image/*, video/*, */*",
        },
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(120000)]),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }

      const contentType = (response.headers.get("content-type") || "").split(";")[0].toLowerCase();
      const contentTypeExtensions = {
        "video/mp4": "mp4", "video/webm": "webm",
        "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
      };
      const fileExt = urlPathExt.toLowerCase().replace("jpeg", "jpg") || contentTypeExtensions[contentType] || "mp4";
      filePath = path.join(DOWNLOADS_DIR, `${id}.${fileExt}`);

      const totalBytes = parseInt(response.headers.get("content-length") || "0", 10);
      if (totalBytes > MAX_DOWNLOAD_BYTES) throw new Error("Fichier trop volumineux");
      if (!response.body) throw new Error("Reponse vide");
      let downloaded = 0;
      const progress = new Transform({
        transform(chunk, encoding, callback) {
          downloaded += chunk.length;
          if (downloaded > MAX_DOWNLOAD_BYTES) return callback(new Error("Fichier trop volumineux"));
          if (totalBytes > 0) job.percent = Math.min(99, Math.round((downloaded / totalBytes) * 100));
          callback(null, chunk);
        },
      });
      await pipeline(Readable.fromWeb(response.body), progress, fs.createWriteStream(filePath, { flags: "wx", mode: 0o600 }));

      job.filePath = filePath;
      const title = job.title || "download";
      job.fileName = buildDownloadFilename(title, fileExt, id);
      job.status = "done";
      job.percent = 100;
    } catch (err) {
      job.status = "error";
      job.error = err.message;
      if (filePath) {
        try { fs.unlinkSync(filePath); } catch {}
      }
      logError("direct-dl", originalUrl, job.error);
    } finally {
      job.abortController = null;
    }
  })();
}

// ===== GALLERY-DL INFO =====
// Returns either a single-item info (backward-compatible) or a playlist object.
// Uses authenticated cookies for Instagram/Twitter etc.
async function galleryDlInfo(url) {
  const proxyUrl = await getRelayUrl();
  return new Promise((resolve, reject) => {
    const args = [
      "--config-ignore",
      "--proxy", proxyUrl,
      "--dump-json",
      url,
    ];
    if (fs.existsSync(COOKIE_FILE)) args.unshift("--cookies", COOKIE_FILE);
    const proc = spawn(GALLERY_DL, args, extractorSpawnOptions(proxyUrl));
    let stdout = "";
    let stderr = "";
    let outputTooLarge = false;
    const timeout = setTimeout(() => {
      terminateProcess(proc);
      reject(new Error("gallery-dl timeout"));
    }, 20000);

    proc.stdout.on("data", (d) => {
      if (outputTooLarge) return;
      stdout += d.toString();
      if (Buffer.byteLength(stdout) > 10 * 1024 * 1024) {
        outputTooLarge = true;
        terminateProcess(proc);
      }
    });
    proc.stderr.on("data", (d) => { stderr = (stderr + d.toString()).slice(-16_384); });

    proc.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });

    proc.on("close", (code) => {
      clearTimeout(timeout);
      if (outputTooLarge) return reject(new Error("Reponse gallery-dl trop volumineuse"));
      if (code !== 0 || !stdout.trim()) {
        return reject(new Error(stderr.substring(0, 200) || "gallery-dl exit code " + code));
      }
      try {
        const parsed = JSON.parse(stdout.trim());
        // gallery-dl output: array of [type, url, metadata]
        // type 2 = directory/context, type 3 = media URL
        const mediaItems = Array.isArray(parsed) ? parsed.filter(e => Array.isArray(e) && e[0] === 3) : [];
        if (mediaItems.length === 0) {
          // Fallback to old single-object format
          if (parsed && !Array.isArray(parsed)) return resolve(parsed);
          return resolve(null);
        }

        if (mediaItems.length === 1) {
          const [, mediaUrl, meta] = mediaItems[0];
          const ext = (meta.extension || "").toLowerCase();
          const isVideo = ["mp4", "webm", "mov"].includes(ext) || !!meta.video_url;
          return resolve({
            url: mediaUrl,
            title: meta.description?.substring(0, 100) || meta.filename || "Image",
            uploader: meta.fullname || meta.username || null,
            type: isVideo ? "video" : "image",
            extension: ext,
          });
        }

        // Multi-item carousel → playlist
        const items = mediaItems.map(([, mediaUrl, meta], idx) => {
          const ext = (meta.extension || "").toLowerCase();
          const isVideo = ["mp4", "webm", "mov"].includes(ext) || !!meta.video_url;
          const finalUrl = meta.video_url || mediaUrl;
          return {
            index: idx + 1,
            title: meta.description?.substring(0, 60) || `Media ${idx + 1}`,
            thumbnail: previewPath(isVideo ? meta.display_url : finalUrl),
            duration: null,
            type: isVideo ? "video" : "image",
            hasVideo: isVideo,
            hasAudio: isVideo,
            qualities: [],
            directUrls: { best: finalUrl },
          };
        });
        const first = mediaItems[0][2];
        resolve({
          type: "playlist",
          source: first.category || "gallery",
          title: first.description?.substring(0, 100) || first.fullname || "Multi-media post",
          uploader: first.fullname || first.username || null,
          count: items.length,
          items,
        });
      } catch (err) {
        reject(new Error("gallery-dl JSON parse: " + err.message));
      }
    });
  });
}

// ===== HELPERS =====

function detectSource(url, extractor) {
  const u = url.toLowerCase();
  const e = extractor.toLowerCase();
  if (u.includes("youtube.com") || u.includes("youtu.be") || e.includes("youtube")) return "youtube";
  if (u.includes("instagram.com") || e.includes("instagram")) return "instagram";
  if (u.includes("twitter.com") || u.includes("x.com") || e.includes("twitter")) return "twitter";
  if (u.includes("tiktok.com") || e.includes("tiktok")) return "tiktok";
  if (u.includes("reddit.com") || e.includes("reddit")) return "reddit";
  if (u.includes("twitch.tv") || e.includes("twitch")) return "twitch";
  if (u.includes("soundcloud.com") || e.includes("soundcloud")) return "soundcloud";
  if (u.includes("vimeo.com") || e.includes("vimeo")) return "vimeo";
  if (u.includes("facebook.com") || u.includes("fb.watch") || e.includes("facebook")) return "facebook";
  if (u.includes("dailymotion.com") || e.includes("dailymotion")) return "dailymotion";
  if (u.includes("pinterest") || e.includes("pinterest")) return "pinterest";
  return "other";
}

// ===== CLEANUP OLD FILES =====
setInterval(() => {
  const now = Date.now();
  const TEN_MINUTES = 10 * 60 * 1000;
  const visit = directory => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(entryPath);
        try { fs.rmdirSync(entryPath); } catch {}
      } else if (now - fs.statSync(entryPath).mtimeMs > TEN_MINUTES) {
        fs.unlinkSync(entryPath);
      }
    }
  };
  try { visit(DOWNLOADS_DIR); } catch {}
  for (const [id, job] of jobs) {
    if (["done", "error"].includes(job.status) && now - job.createdAt > TEN_MINUTES) cleanupJob(id);
  }
}, 60 * 1000).unref();

// ===== ERROR LOGGING =====
const ERRORS_FILE = path.join(__dirname, "errors.json");
let errorLogs = [];
if (fs.existsSync(ERRORS_FILE)) {
  try { errorLogs = JSON.parse(fs.readFileSync(ERRORS_FILE, "utf-8")); } catch {}
}

function logError(type, url, error, extra) {
  const entry = {
    time: new Date().toISOString(),
    type,
    url: loggableUrl(url),
    error: typeof error === "string" ? error.substring(0, 500) : String(error).substring(0, 500),
    ...extra,
  };
  errorLogs.push(entry);
  if (errorLogs.length > 500) errorLogs = errorLogs.slice(-500);
  try { fs.writeFileSync(ERRORS_FILE, JSON.stringify(errorLogs, null, 2), { mode: 0o600 }); } catch {}
  console.log(`[ERROR-LOG] ${type} ${entry.url} — ${entry.error.substring(0, 100)}`);
}

// User bug report
app.post("/api/report-bug", (req, res) => {
  const { url, error, userAgent, comment, activityLog } = req.body || {};
  logError("user-report", shortText(url, MAX_URL_LENGTH), shortText(error) || "No error message", {
    comment: shortText(comment),
    activityLog: sanitizeActivityLog(activityLog),
    userAgent: shortText(userAgent, 300) || req.headers["user-agent"],
    ip: req.ip,
  });
  res.json({ ok: true });
});

// View errors (for admin)
app.get("/api/errors", requireAdmin, (req, res) => {
  res.json(errorLogs.slice(-100).reverse());
});

// ===== DIRECT CDN URL DETECTION =====
// Handles direct image/video CDN URLs that yt-dlp cannot process
// (e.g. preview.redd.it redirects to www.reddit.com/media?url=... which yt-dlp doesn't support)
const DIRECT_CDN_HOSTS = ["preview.redd.it", "i.redd.it", "i.imgur.com", "pbs.twimg.com"];
const MEDIA_EXTENSIONS = ["jpg", "jpeg", "png", "gif", "webp", "mp4", "webm"];

function buildDirectCdnInfo(url) {
  try {
    const parsed = new URL(url);
    if (!DIRECT_CDN_HOSTS.includes(parsed.hostname)) return null;
    const ext = parsed.pathname.split(".").pop()?.toLowerCase();
    if (!MEDIA_EXTENSIONS.includes(ext)) return null;
    const videoExts = ["mp4", "webm"];
    const type = videoExts.includes(ext) ? "video" : "image";
    const filename = safeDecodeComponent(parsed.pathname.split("/").pop());
    const source = detectSource(url, "");
    return {
      title: filename,
      thumbnail: previewPath(type === "image" ? url : null),
      duration: null,
      uploader: null,
      type,
      source,
      qualities: [],
      hasVideo: type === "video",
      hasAudio: type === "video",
      directUrls: { best: url },
      ext: ext.replace("jpeg", "jpg"),
    };
  } catch { return null; }
}

// ===== DIRECT MEDIA DETECTION =====
async function tryDirectMedia(url) {
  try {
    const resp = await safeFetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(8000),
      headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
    });
    if (!resp.ok) return null;
    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    const size = parseInt(resp.headers.get("content-length") || "0", 10);
    if (ct.startsWith("image/") || ct.startsWith("video/") || ct.startsWith("audio/")) {
      const ext = ct.split("/")[1].split(";")[0].replace("jpeg", "jpg").replace("mpeg", "mp3");
      let type = "image";
      if (ct.startsWith("video/")) type = "video";
      if (ct.startsWith("audio/")) type = "audio";
      // Extract a title from the URL
      const urlPath = new URL(url).pathname;
      const filename = safeDecodeComponent(urlPath.split("/").pop());
      return {
        title: filename,
        thumbnail: previewPath(type === "image" ? url : null),
        duration: null,
        uploader: null,
        type,
        source: "other",
        qualities: [],
        hasVideo: type === "video",
        hasAudio: type === "audio",
        directUrls: { best: url },
        ext,
        size,
      };
    }
    return null;
  } catch { return null; }
}

// ===== START =====
// These must remain after every API route.
app.use((req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, req, res, next) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: "Erreur interne du serveur" });
});

async function start() {
  const proxyUrl = await getRelayUrl();
  const server = app.listen(PORT, HOST, () => {
    console.log(`Universal Downloader running on http://${HOST}:${PORT}`);
    console.log(`Downloads dir: ${DOWNLOADS_DIR}`);
    console.log(`gallery-dl: ${GALLERY_DL}`);
    console.log(`network relay: ${proxyUrl}`);
  });
  server.once("close", () => { networkRelay.close().catch(() => {}); });
  return server;
}

if (require.main === module) {
  start().catch(error => {
    console.error("[START]", error.message);
    process.exitCode = 1;
  });
}

module.exports = { app, start };
