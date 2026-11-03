"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const net = require("node:net");
const { PassThrough, Readable } = require("node:stream");
const test = require("node:test");
const { createSafeProxy } = require("../lib/safe-proxy");

function proxyRequest(proxyUrl, target) {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const request = http.request({
      hostname: proxy.hostname,
      port: proxy.port,
      path: target,
      method: "GET",
      headers: { host: new URL(target).host },
    }, response => {
      const chunks = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    request.once("error", reject);
    request.end();
  });
}

function connectRequest(proxyUrl, authority) {
  const proxy = new URL(proxyUrl);
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.hostname, port: proxy.port });
    let response = "";
    socket.once("error", reject);
    socket.on("data", chunk => {
      response += chunk.toString();
      if (response.includes("\r\n\r\n")) {
        socket.destroy();
        resolve(response);
      }
    });
    socket.once("connect", () => socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`));
  });
}

test("le relais revalide et epingle chaque destination HTTP", async (t) => {
  const upstreamCalls = [];
  const relay = createSafeProxy({
    lookup: async hostname => [{ address: hostname === "public.test" ? "8.8.8.8" : "127.0.0.1", family: 4 }],
    httpRequest(options, onResponse) {
      upstreamCalls.push(options);
      const request = new PassThrough();
      request.once("finish", () => {
        const response = Readable.from(["proxied"]);
        response.statusCode = 200;
        response.headers = { "content-type": "text/plain" };
        onResponse(response);
      });
      return request;
    },
  });
  const proxyUrl = await relay.listen();
  t.after(() => relay.close());

  const allowed = await proxyRequest(proxyUrl, "http://public.test/media");
  assert.deepEqual(allowed, { status: 200, body: "proxied" });
  assert.equal(upstreamCalls[0].hostname, "8.8.8.8");
  assert.equal(upstreamCalls[0].headers.host, "public.test");

  const blocked = await proxyRequest(proxyUrl, "http://private.test/secret");
  assert.equal(blocked.status, 403);
  assert.equal(upstreamCalls.length, 1);
});

test("CONNECT ouvre le socket vers l'adresse epinglee", async (t) => {
  const connections = [];
  const relay = createSafeProxy({
    lookup: async hostname => [{ address: hostname === "public.test" ? "8.8.4.4" : "127.0.0.1", family: 4 }],
    connect(options, onConnect) {
      connections.push(options);
      const socket = new PassThrough();
      process.nextTick(onConnect);
      return socket;
    },
  });
  const proxyUrl = await relay.listen();
  t.after(() => relay.close());

  const allowed = await connectRequest(proxyUrl, "public.test:443");
  assert.match(allowed, /^HTTP\/1\.1 200/);
  assert.deepEqual(connections[0], { host: "8.8.4.4", port: 443, family: 4 });

  const blocked = await connectRequest(proxyUrl, "private.test:443");
  assert.match(blocked, /^HTTP\/1\.1 403/);
  assert.equal(connections.length, 1);
});
