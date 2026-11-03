const dns = require("dns");
const net = require("net");
const { promisify } = require("util");

const defaultLookup = promisify(dns.lookup);

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
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224;
  }

  if (net.isIP(address) === 6) {
    const hextets = expandIPv6(address);
    if (!hextets) return true;
    const [first, second] = hextets;
    const mappedV4 = hextets.slice(0, 5).every(value => value === 0) && hextets[5] === 0xffff;
    if (mappedV4) {
      const ipv4 = `${hextets[6] >> 8}.${hextets[6] & 255}.${hextets[7] >> 8}.${hextets[7] & 255}`;
      return isPrivateIP(ipv4);
    }
    return first === 0 ||
      (first & 0xfe00) === 0xfc00 ||
      (first & 0xffc0) === 0xfe80 ||
      (first & 0xff00) === 0xff00 ||
      (first === 0x0100 && hextets.slice(1, 4).every(value => value === 0)) ||
      (first === 0x2001 && [0x0000, 0x0002, 0x0db8].includes(second)) ||
      (first === 0x2001 && ((second & 0xfff0) === 0x0010 || (second & 0xfff0) === 0x0020));
  }

  return false;
}

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

async function validateRemoteUrl(rawUrl, { lookup = defaultLookup } = {}) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return { safe: false, reason: "URL invalide" }; }
  if (!['http:', 'https:'].includes(parsed.protocol)) return { safe: false, reason: "Protocole interdit" };
  if (parsed.username || parsed.password) return { safe: false, reason: "Identifiants interdits dans l'URL" };
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!hostname || hostname === "localhost" || hostname.endsWith(".localhost")) {
    return { safe: false, reason: "Acces aux adresses internes interdit" };
  }

  try {
    const answers = net.isIP(hostname) ? [{ address: hostname }] : await lookup(hostname, { all: true, verbatim: true });
    const list = Array.isArray(answers) ? answers : [answers];
    if (list.length === 0 || list.some(answer => isPrivateIP(answer.address))) {
      return { safe: false, reason: "Acces aux adresses internes interdit" };
    }
  } catch {
    return { safe: false, reason: "Nom de domaine introuvable" };
  }
  return { safe: true, url: parsed.href };
}

async function safeFetch(rawUrl, options = {}, { fetchImpl = fetch, maxRedirects = 5, lookup } = {}) {
  let current = rawUrl;
  for (let redirects = 0; redirects <= maxRedirects; redirects++) {
    const validation = await validateRemoteUrl(current, { lookup });
    if (!validation.safe) throw new Error(validation.reason);
    const response = await fetchImpl(validation.url, { ...options, redirect: "manual" });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location = response.headers.get("location");
    if (!location) throw new Error("Redirection sans destination");
    try { await response.body?.cancel(); } catch {}
    current = new URL(location, validation.url).href;
  }
  throw new Error("Trop de redirections");
}

module.exports = { isPrivateIP, safeFetch, validateRemoteUrl };
