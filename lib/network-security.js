"use strict";

const dns = require("node:dns");
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { Readable } = require("node:stream");
const { promisify } = require("node:util");

const defaultLookup = promisify(dns.lookup);
const ALLOWED_PORTS = new Set([80, 443]);

function expandIPv6(address) {
  let normalized = address.split("%")[0];
  const dotted = normalized.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const octets = dotted[1].split(".").map(Number);
    if (octets.length !== 4 || octets.some(value => value < 0 || value > 255)) return null;
    normalized = normalized.slice(0, -dotted[1].length) +
      `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return null;
  const pieces = [...left, ...Array(missing).fill("0"), ...right];
  const values = pieces.map(piece => Number.parseInt(piece, 16));
  if (values.length !== 8 || values.some(value => !Number.isInteger(value) || value < 0 || value > 0xffff)) return null;
  return values;
}

function isPrivateIP(input) {
  const address = String(input || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIP(mapped[1]);

  if (net.isIP(address) === 4) {
    const [a, b, c] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 192 && b === 31 && c === 196) ||
      (a === 192 && b === 52 && c === 193) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 175 && c === 48) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224;
  }

  if (net.isIP(address) === 6) {
    const hextets = expandIPv6(address);
    if (!hextets) return true;
    const [first, second, third] = hextets;
    const mappedV4 = hextets.slice(0, 5).every(value => value === 0) && hextets[5] === 0xffff;
    if (mappedV4) {
      const ipv4 = `${hextets[6] >> 8}.${hextets[6] & 255}.${hextets[7] >> 8}.${hextets[7] & 255}`;
      return isPrivateIP(ipv4);
    }
    const nat64WellKnown = first === 0x0064 && second === 0xff9b && hextets.slice(2, 6).every(value => value === 0);
    const nat64Local = first === 0x0064 && second === 0xff9b && third === 0x0001;
    return first === 0 || nat64WellKnown || nat64Local ||
      (first & 0xfe00) === 0xfc00 ||
      (first & 0xffc0) === 0xfe80 ||
      (first & 0xff00) === 0xff00 ||
      first === 0x2002 ||
      (first === 0x0100 && hextets.slice(1, 4).every(value => value === 0)) ||
      (first === 0x2001 && (second <= 0x01ff || second === 0x0db8)) ||
      (first === 0x3fff && (second & 0xf000) === 0) ||
      first === 0x5f00;
  }

  return false;
}

async function resolvePublicHost(hostname, { lookup = defaultLookup } = {}) {
  const normalized = String(hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  if (!normalized || normalized === "localhost" || normalized.endsWith(".localhost")) {
    throw new Error("Acces aux adresses internes interdit");
  }
  let answers;
  try {
    answers = net.isIP(normalized)
      ? [{ address: normalized, family: net.isIP(normalized) }]
      : await lookup(normalized, { all: true, verbatim: true });
  } catch {
    throw new Error("Nom de domaine introuvable");
  }
  const list = (Array.isArray(answers) ? answers : [answers]).map(answer => {
    const address = typeof answer === "string" ? answer : answer?.address;
    return { address, family: Number(answer?.family) || net.isIP(address) };
  });
  if (!list.length || list.some(answer => !net.isIP(answer.address) || isPrivateIP(answer.address))) {
    throw new Error("Acces aux adresses internes interdit");
  }
  return list;
}

async function validateRemoteUrl(rawUrl, { lookup = defaultLookup } = {}) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return { safe: false, reason: "URL invalide" }; }
  if (!["http:", "https:"].includes(parsed.protocol)) return { safe: false, reason: "Protocole interdit" };
  if (parsed.username || parsed.password) return { safe: false, reason: "Identifiants interdits dans l'URL" };
  const port = Number(parsed.port || (parsed.protocol === "https:" ? 443 : 80));
  if (!ALLOWED_PORTS.has(port)) return { safe: false, reason: "Port distant interdit" };
  try {
    const addresses = await resolvePublicHost(parsed.hostname, { lookup });
    return { safe: true, url: parsed.href, hostname: parsed.hostname, port, addresses };
  } catch (error) {
    return { safe: false, reason: error.message };
  }
}

function pinnedLookup(destination) {
  return (hostname, options, callback) => {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    if (options?.all) return callback(null, [destination]);
    callback(null, destination.address, destination.family || net.isIP(destination.address));
  };
}

async function pinnedFetch(validation, options = {}, { requestImpl } = {}) {
  const parsed = new URL(validation.url);
  const destination = validation.addresses[0];
  const transport = parsed.protocol === "https:" ? https : http;
  const request = requestImpl || transport.request;
  return new Promise((resolve, reject) => {
    const signal = options.signal;
    const headers = { ...(options.headers || {}), host: parsed.host };
    const req = request({
      protocol: parsed.protocol,
      hostname: destination.address,
      port: validation.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || "GET",
      headers,
      servername: parsed.hostname.replace(/^\[|\]$/g, ""),
      lookup: pinnedLookup(destination),
    }, response => {
      const noBody = (options.method || "GET").toUpperCase() === "HEAD" || [204, 304].includes(response.statusCode);
      const body = noBody ? null : Readable.toWeb(response);
      const result = new Response(body, {
        status: response.statusCode,
        statusText: response.statusMessage,
        headers: response.headers,
      });
      Object.defineProperty(result, "url", { value: validation.url });
      resolve(result);
    });
    const abort = () => req.destroy(signal.reason instanceof Error ? signal.reason : new Error("Requete annulee"));
    if (signal) {
      if (signal.aborted) abort();
      else signal.addEventListener("abort", abort, { once: true });
      req.once("close", () => signal.removeEventListener("abort", abort));
    }
    req.once("error", reject);
    if (options.body == null) req.end();
    else if (typeof options.body?.pipe === "function") options.body.pipe(req);
    else req.end(options.body);
  });
}

async function safeFetch(rawUrl, options = {}, { fetchImpl, maxRedirects = 5, lookup, requestImpl } = {}) {
  let current = rawUrl;
  for (let redirects = 0; redirects <= maxRedirects; redirects++) {
    const validation = await validateRemoteUrl(current, { lookup });
    if (!validation.safe) throw new Error(validation.reason);
    const response = fetchImpl
      ? await fetchImpl(validation.url, { ...options, redirect: "manual" }, validation)
      : await pinnedFetch(validation, options, { requestImpl });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("location");
    if (!location) throw new Error("Redirection sans destination");
    try { await response.body?.cancel(); } catch {}
    current = new URL(location, validation.url).href;
  }
  throw new Error("Trop de redirections");
}

module.exports = { isPrivateIP, pinnedFetch, pinnedLookup, resolvePublicHost, safeFetch, validateRemoteUrl };
