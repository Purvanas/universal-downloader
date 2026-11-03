const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { spawn } = require("child_process");
const { Readable, Transform } = require("stream");
const { pipeline } = require("stream/promises");
const youtubedl = require("youtube-dl-exec");
const cheerio = require("cheerio");
const { isPrivateIP, safeFetch, validateRemoteUrl } = require("./lib/network-security");
// Puppeteer loaded lazily — expensive at startup
let puppeteerLib = null;
function getPuppeteer() {
  if (!puppeteerLib) puppeteerLib = require("puppeteer");
  return puppeteerLib;
}

const app = express();
function positiveInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}
const PORT = positiveInteger(process.env.PORT, 3600);
const HOST = process.env.HOST || "127.0.0.1";
const DOWNLOADS_DIR = process.env.DOWNLOADS_DIR ? path.resolve(process.env.DOWNLOADS_DIR) : path.join(__dirname, "downloads");
const GALLERY_DL = process.env.GALLERY_DL || "gallery-dl";
const COOKIE_FILE = process.env.COOKIE_FILE ? path.resolve(process.env.COOKIE_FILE) : path.join(__dirname, "cookies.txt");
const CONVERTER_ORIGIN = process.env.CONVERTER_ORIGIN || "https://convert.purvanas.fr";
const ERRORS_TOKEN = process.env.ERRORS_TOKEN || "";
const MAX_ACTIVE_JOBS = positiveInteger(process.env.MAX_ACTIVE_JOBS, 3);
const MAX_DOWNLOAD_BYTES = positiveInteger(process.env.MAX_DOWNLOAD_BYTES, 500 * 1024 * 1024);
const ENABLE_DEEP_SCAN = process.env.ENABLE_DEEP_SCAN === "true";

if (!fs.existsSync(DOWNLOADS_DIR)) fs.mkdirSync(DOWNLOADS_DIR, { recursive: true });
// ===== INPUT VALIDATION =====
const ALLOWED_AUDIO_FORMATS = new Set(['mp3', 'm4a', 'opus', 'wav', 'flac', 'aac']);
const ALLOWED_VIDEO_QUALITIES = new Set(['best', '144', '240', '360', '480', '720', '1080', '1440', '2160', '4320']);
const ALLOWED_FORMATS = new Set(['video', 'audio', 'image', 'direct']);
const MAX_URL_LENGTH = 2048;

function sanitizeUrl(raw) {
  if (typeof raw !== 'string') return null;
  const url = raw.trim();
  if (url.length === 0 || url.length > MAX_URL_LENGTH) return null;
  if (!/^https?:\/\//i.test(url)) return null;
  if (/[\x00-\x1f\x7f`]/.test(url)) return null;
  return url;
}

function shortText(value, maxLength = 500) {
  return typeof value === "string" ? value.substring(0, maxLength) : "";
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
    return shortText(value, 200) || "unknown";
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
app.use("/api", (req, res, next) => {
  const now = Date.now();
  const key = req.ip;
  const current = requestWindows.get(key);
  const entry = !current || now - current.startedAt > 15 * 60 * 1000 ? { startedAt: now, count: 1 } : { ...current, count: current.count + 1 };
  requestWindows.set(key, entry);
  if (entry.count > 180) return res.status(429).json({ error: "Trop de requetes, reessayez plus tard" });
  next();
});
setInterval(() => {
  const cutoff = Date.now() - 15 * 60 * 1000;
  for (const [key, value] of requestWindows) if (value.startedAt < cutoff) requestWindows.delete(key);
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

app.get("/api/capabilities", (req, res) => {
  res.json({ deepScan: ENABLE_DEEP_SCAN });
});

function runYtDlpJson(url, options, { timeoutMs = 45_000, maxOutputBytes = 10 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const proc = youtubedl.exec(url, options);
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
        try { proc.kill("SIGTERM"); } catch {}
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
          thumbnail: entry.thumbnail || (isImg ? (entry.url || null) : null),
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
      thumbnail: info.thumbnail || null,
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
          thumbnail: gdlInfo.url || null,
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
            thumbnail: only.thumbnail,
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

    // ===== LAST RESORT: deep scan with headless browser =====
    // Handles JS-rendered sites. ~15-20s but worth it for unknown sites.
    if (ENABLE_DEEP_SCAN) try {
      const deepInfo = await deepScanPage(url);
      if (deepInfo && deepInfo.items && deepInfo.items.length > 0) {
        if (deepInfo.items.length === 1) {
          const only = deepInfo.items[0];
          return res.json({
            title: deepInfo.title || only.title,
            thumbnail: only.thumbnail,
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
        return res.json(deepInfo);
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
// Works with static HTML — for JS-rendered pages, the /scan-deep fallback is needed.
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
      title: decodeURIComponent(new URL(u).pathname.split("/").pop() || "media").substring(0, 80) || `Media ${idx}`,
      thumbnail: info.type === "image" ? u : (info.thumbnail || null),
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

// ===== DEEP SCAN (Puppeteer) =====
// Launches a headless Chrome, intercepts all network requests, captures media URLs.
// Used as fallback when /api/scan finds nothing (JS-rendered pages, blob: sources).
let _browser = null;
let _browserIdleTimer = null;
const BROWSER_IDLE_MS = 5 * 60 * 1000; // close browser after 5min idle
const DEEP_SCAN_TIMEOUT_MS = 20000;

async function getBrowser() {
  if (_browser && _browser.isConnected()) {
    resetBrowserIdleTimer();
    return _browser;
  }
  const puppeteer = getPuppeteer();
  _browser = await puppeteer.launch({
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--no-zygote",
      "--disable-background-networking",
      "--disable-sync",
      "--disable-default-apps",
      "--disable-extensions",
      "--mute-audio",
    ],
  });
  resetBrowserIdleTimer();
  return _browser;
}

function resetBrowserIdleTimer() {
  if (_browserIdleTimer) clearTimeout(_browserIdleTimer);
  _browserIdleTimer = setTimeout(async () => {
    if (_browser) {
      try { await _browser.close(); } catch {}
      _browser = null;
    }
  }, BROWSER_IDLE_MS);
}

app.post("/api/scan-deep", async (req, res) => {
  if (!ENABLE_DEEP_SCAN) return res.status(404).json({ error: "Scan profond desactive" });
  const url = sanitizeUrl(req.body?.url);
  if (!url) return res.status(400).json({ error: "URL invalide" });

  const ssrfCheck = await validateRemoteUrl(url);
  if (!ssrfCheck.safe) return res.status(403).json({ error: ssrfCheck.reason });
  if (activeWorkCount() >= MAX_ACTIVE_JOBS) {
    return res.status(429).json({ error: "Le serveur traite deja trop de demandes" });
  }
  activeAnalyses++;

  try {
    const result = await deepScanPage(url);
    return res.json(result);
  } catch (err) {
    logError("scan-deep", url, err.message || String(err));
    return res.status(422).json({ error: "Echec du scan profond: " + (err.message || "erreur inconnue").substring(0, 150) });
  } finally {
    activeAnalyses--;
  }
});

async function deepScanPage(url) {
  const browser = await getBrowser();
  const context = await browser.createBrowserContext({}); // isolated context per scan
  const page = await context.newPage();

  // Collect media URLs via network interception
  const foundUrls = new Map();
  const MEDIA_EXT = /\.(jpg|jpeg|png|gif|webp|avif|svg|bmp|mp4|webm|mov|m4v|mp3|wav|m4a|ogg|flac|aac|opus|m3u8|mpd|ts)(\?|$|#)/i;
  const MEDIA_MIME = /^(image|video|audio)\//;

  function classify(u, contentType) {
    const ct = (contentType || "").toLowerCase();
    if (ct.startsWith("video/") || /\.(mp4|webm|mov|m4v|m3u8|mpd|ts)(\?|$|#)/i.test(u)) return "video";
    if (ct.startsWith("audio/") || /\.(mp3|wav|m4a|ogg|flac|aac|opus)(\?|$|#)/i.test(u)) return "audio";
    if (ct.startsWith("image/") || /\.(jpg|jpeg|png|gif|webp|avif|svg|bmp)(\?|$|#)/i.test(u)) return "image";
    return null;
  }

  function add(u, type) {
    if (!u || u.startsWith("data:") || u.startsWith("blob:")) return;
    if (foundUrls.size >= 500) return;
    if (foundUrls.has(u)) return;
    foundUrls.set(u, { type });
  }

  try {
    await page.setUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
    await page.setViewport({ width: 1280, height: 800 });
    await page.setRequestInterception(true);
    page.on("request", async request => {
      try {
        const requestUrl = request.url();
        if (!/^https?:/i.test(requestUrl)) return request.continue();
        const validation = await validateRemoteUrl(requestUrl);
        if (!validation.safe) return request.abort("blockedbyclient");
        const type = classify(requestUrl, null);
        if (type && MEDIA_EXT.test(requestUrl)) add(requestUrl, type);
        return request.continue();
      } catch {
        try { return request.abort("blockedbyclient"); } catch {}
      }
    });

    // Intercept responses — this catches blob URLs because the blob is CREATED from a real URL first
    page.on("response", (resp) => {
      try {
        const rurl = resp.url();
        const ct = resp.headers()["content-type"] || "";
        const type = classify(rurl, ct);
        if (type && MEDIA_MIME.test(ct)) add(rurl, type);
        else if (type && MEDIA_EXT.test(rurl)) add(rurl, type);
      } catch {}
    });

    // Navigate with timeout
    await page.goto(url, { waitUntil: "networkidle2", timeout: DEEP_SCAN_TIMEOUT_MS }).catch(err => {
      // networkidle may timeout on pages with long-polling — fall back to domcontentloaded
      if (!err.message.includes("timeout")) throw err;
    });

    // Scroll to trigger lazy-loaded media
    await page.evaluate(() => {
      return new Promise(resolve => {
        let total = 0;
        const step = () => {
          window.scrollBy(0, 300);
          total += 300;
          if (total < document.body.scrollHeight && total < 10000) {
            setTimeout(step, 80);
          } else {
            resolve();
          }
        };
        step();
      });
    }).catch(() => {});

    // Wait a bit more for straggler resources
    await new Promise(r => setTimeout(r, 1500));

    // Also pull current DOM via cheerio for <img src> etc.
    const html = await page.content();
    const pageTitle = (await page.title() || "").substring(0, 200);
    const finalUrl = page.url();

    try {
      const $ = cheerio.load(html);
      const base = new URL(finalUrl);
      const resolveUrl = (u) => {
        if (!u) return null;
        u = u.trim();
        if (!u || u.startsWith("data:") || u.startsWith("blob:") || u.startsWith("javascript:")) return null;
        try { return new URL(u, base).href; } catch { return null; }
      };
      $("img[src], img[data-src]").each(function() {
        const src = $(this).attr("src") || $(this).attr("data-src");
        const resolved = resolveUrl(src);
        if (resolved) {
          const type = classify(resolved, null);
          if (type) add(resolved, type);
        }
      });
      $("video[src], video source[src]").each(function() {
        const src = $(this).attr("src");
        const resolved = resolveUrl(src);
        if (resolved) add(resolved, "video");
      });
    } catch {}

    // Build items
    const MAX_RESULTS = 200;
    const allItems = [];
    let idx = 0;
    for (const [u, info] of foundUrls) {
      if (/favicon/i.test(u) || /logo/i.test(u)) continue; // basic noise filter
      allItems.push({
        index: ++idx,
        title: decodeURIComponent(new URL(u).pathname.split("/").pop() || "media").substring(0, 80) || `Media ${idx}`,
        thumbnail: info.type === "image" ? u : null,
        duration: null,
        type: info.type,
        hasVideo: info.type === "video",
        hasAudio: info.type === "video" || info.type === "audio",
        qualities: [],
        directUrls: { best: u },
      });
    }
    const typeOrder = { video: 0, audio: 1, image: 2 };
    allItems.sort((a, b) => (typeOrder[a.type] ?? 3) - (typeOrder[b.type] ?? 3));
    const truncated = allItems.length > MAX_RESULTS;
    const items = allItems.slice(0, MAX_RESULTS).map((it, i) => ({ ...it, index: i + 1 }));

    if (items.length === 0) throw new Error("Aucun media detecte (meme apres execution JS)");

    return {
      type: "playlist",
      source: "scan-deep",
      title: pageTitle || new URL(finalUrl).hostname,
      uploader: null,
      count: items.length,
      totalFound: allItems.length,
      truncated,
      items,
      scannedUrl: finalUrl,
      deep: true,
    };
  } finally {
    try { await page.close(); } catch {}
    try { await context.close(); } catch {}
    resetBrowserIdleTimer();
  }
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
        startImageDownload(id, url, playlistIdx);
      } else if (format === "audio") {
        startAudioDownload(id, url, audioFormat || "mp3", playlistIdx);
      } else if (format === "direct") {
        // Direct MP4 URL (e.g. from fxtwitter)
        startDirectDownload(id, url, body.directUrl);
      } else {
        startVideoDownload(id, url, quality || "best", playlistIdx);
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

function startVideoDownload(id, url, quality, playlistIdx) {
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
  const proc = youtubedl.exec(url, opts);
  jobs.get(id).process = proc;
  trackProgress(id, proc);
}

function startAudioDownload(id, url, audioFormat, playlistIdx) {
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
  const proc = youtubedl.exec(url, opts);
  jobs.get(id).process = proc;
  trackProgress(id, proc);
}

function startImageDownload(id, url, playlistIdx) {
  const job = jobs.get(id);
  job.status = "downloading";

  // When a playlist index is specified, try yt-dlp first (it handles Instagram carousels natively)
  // Fall back to gallery-dl for single images.
  if (playlistIdx) {
    const outputTemplate = path.join(DOWNLOADS_DIR, `${id}.%(ext)s`);
    const proc = youtubedl.exec(url, {
      output: outputTemplate,
      ...cookieOptions(),
      jsRuntimes: "node",
      noWarnings: true,
      playlistItems: String(playlistIdx),
      socketTimeout: 30,
      retries: 3,
      maxFilesize: MAX_DOWNLOAD_BYTES,
    });
    job.process = proc;
    trackProgress(id, proc);
    return;
  }

  const galleryArgs = [
    "--dest", DOWNLOADS_DIR,
    "--filename", `${id}.{extension}`,
    "--option", "directory=[]",  // Prevent gallery-dl from creating extractor sub-dirs
    "--filesize-max", String(MAX_DOWNLOAD_BYTES),
    "--no-mtime",
    url,
  ];
  if (fs.existsSync(COOKIE_FILE)) galleryArgs.unshift("--cookies", COOKIE_FILE);
  const proc = spawn(GALLERY_DL, galleryArgs);
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
    thumbnail: video.thumbnail_url || null,
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
    thumbnail: image.url || null,
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

  const resp = await fetch(`https://api.fxtwitter.com/i/status/${tweetId}`, {
    signal: AbortSignal.timeout(10000),
  });
  if (!resp.ok) return null;
  const data = await resp.json();
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
  const fileExt = urlPathExt.toLowerCase().replace("jpeg", "jpg") || "mp4";
  const filePath = path.join(DOWNLOADS_DIR, `${id}.${fileExt}`);

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
      try { fs.unlinkSync(filePath); } catch {}
      logError("direct-dl", originalUrl, job.error);
    } finally {
      job.abortController = null;
    }
  })();
}

// ===== GALLERY-DL INFO =====
// Returns either a single-item info (backward-compatible) or a playlist object.
// Uses authenticated cookies for Instagram/Twitter etc.
function galleryDlInfo(url) {
  return new Promise((resolve, reject) => {
    const args = [
      "--dump-json",
      url,
    ];
    if (fs.existsSync(COOKIE_FILE)) args.unshift("--cookies", COOKIE_FILE);
    const proc = spawn(GALLERY_DL, args);
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
            thumbnail: isVideo ? (meta.display_url || null) : finalUrl,
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
  const { url, error, userAgent, comment } = req.body || {};
  logError("user-report", shortText(url, MAX_URL_LENGTH), shortText(error) || "No error message", {
    comment: shortText(comment),
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
    const filename = decodeURIComponent(parsed.pathname.split("/").pop() || "media");
    const source = detectSource(url, "");
    return {
      title: filename,
      thumbnail: type === "image" ? url : null,
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
      const filename = decodeURIComponent(urlPath.split("/").pop() || "media");
      return {
        title: filename,
        thumbnail: type === "image" ? url : null,
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

app.listen(PORT, HOST, () => {
  console.log(`Universal Downloader running on http://${HOST}:${PORT}`);
  console.log(`Downloads dir: ${DOWNLOADS_DIR}`);
  console.log(`gallery-dl: ${GALLERY_DL}`);
  console.log(`deep scan: ${ENABLE_DEEP_SCAN ? "enabled" : "disabled"}`);
});
