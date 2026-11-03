"use strict";

const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const { pinnedLookup, validateRemoteUrl } = require("./network-security");

function publicError(res, status, message) {
  if (res.headersSent) return res.destroy();
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", connection: "close" });
  res.end(message);
}

function socketError(socket, status, message) {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

function sanitizedHeaders(headers, host) {
  const result = { ...headers, host };
  delete result["proxy-authorization"];
  delete result["proxy-connection"];
  delete result.connection;
  delete result.upgrade;
  return result;
}

function connectTarget(authority) {
  if (typeof authority !== "string" || authority.length > 1024 || /[\s/@]/.test(authority)) return null;
  const bracketed = authority.match(/^\[([^\]]+)\]:(80|443)$/);
  const named = authority.match(/^([^:]+):(80|443)$/);
  const match = bracketed || named;
  if (!match) return null;
  const hostname = match[1];
  const port = Number(match[2]);
  try { new URL(`http://${bracketed ? `[${hostname}]` : hostname}/`); } catch { return null; }
  const host = bracketed ? `[${hostname}]` : hostname;
  return { hostname, port, url: `${port === 443 ? "https" : "http"}://${host}:${port}/` };
}

function createSafeProxy({ lookup, connect = net.connect, httpRequest = http.request, httpsRequest = https.request } = {}) {
  const server = http.createServer(async (req, res) => {
    try {
      if (typeof req.url !== "string" || req.url.length > 8192 || !/^https?:\/\//i.test(req.url)) {
        return publicError(res, 400, "Proxy request must use an absolute HTTP(S) URL");
      }
      const validation = await validateRemoteUrl(req.url, { lookup });
      if (!validation.safe) return publicError(res, 403, validation.reason);
      const parsed = new URL(validation.url);
      const destination = validation.addresses[0];
      const requestImpl = parsed.protocol === "https:" ? httpsRequest : httpRequest;
      const upstream = requestImpl({
        protocol: parsed.protocol,
        hostname: destination.address,
        port: validation.port,
        path: `${parsed.pathname}${parsed.search}`,
        method: req.method,
        headers: sanitizedHeaders(req.headers, parsed.host),
        servername: parsed.hostname.replace(/^\[|\]$/g, ""),
        lookup: pinnedLookup(destination),
      }, upstreamResponse => {
        const headers = { ...upstreamResponse.headers };
        delete headers.connection;
        delete headers["proxy-connection"];
        res.writeHead(upstreamResponse.statusCode || 502, headers);
        upstreamResponse.pipe(res);
      });
      upstream.once("error", () => publicError(res, 502, "Upstream connection failed"));
      req.once("aborted", () => upstream.destroy());
      req.pipe(upstream);
    } catch {
      publicError(res, 502, "Proxy request failed");
    }
  });

  server.on("connect", async (req, clientSocket, head) => {
    const target = connectTarget(req.url);
    if (!target) return socketError(clientSocket, 403, "Forbidden");
    const validation = await validateRemoteUrl(target.url, { lookup });
    if (!validation.safe) return socketError(clientSocket, 403, "Forbidden");
    const destination = validation.addresses[0];
    let upstream;
    let established = false;
    try {
      upstream = connect({ host: destination.address, port: target.port, family: destination.family }, () => {
        if (clientSocket.destroyed) return upstream.destroy();
        established = true;
        clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head?.length) upstream.write(head);
        upstream.pipe(clientSocket);
        clientSocket.pipe(upstream);
      });
    } catch {
      return socketError(clientSocket, 502, "Bad Gateway");
    }
    upstream.once("error", () => established ? clientSocket.destroy() : socketError(clientSocket, 502, "Bad Gateway"));
    clientSocket.once("error", () => upstream.destroy());
    clientSocket.once("close", () => upstream.destroy());
  });
  server.on("clientError", (error, socket) => socketError(socket, 400, "Bad Request"));
  server.maxHeadersCount = 100;

  let ready = null;
  return {
    server,
    listen() {
      if (ready) return ready;
      ready = new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
          server.removeListener("error", reject);
          const address = server.address();
          resolve(`http://127.0.0.1:${address.port}`);
        });
      });
      return ready;
    },
    close() {
      if (!server.listening) return Promise.resolve();
      return new Promise(resolve => server.close(resolve));
    },
  };
}

module.exports = { connectTarget, createSafeProxy };
