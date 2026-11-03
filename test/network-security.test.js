const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { Readable } = require("node:stream");
const test = require("node:test");
const { isPrivateIP, safeFetch, validateRemoteUrl } = require("../lib/network-security");
const { connectTarget } = require("../lib/safe-proxy");

test("bloque les plages internes IPv4 et IPv6", () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "100.100.0.1", "192.168.1.2", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "2001:db8::1", "64:ff9b::7f00:1", "64:ff9b:1::1"]) {
    assert.equal(isPrivateIP(address), true, address);
  }
  assert.equal(isPrivateIP("1.1.1.1"), false);
  assert.equal(isPrivateIP("2001:4860:4860::8888"), false);
});

test("refuse les ports autres que 80 et 443", async () => {
  const lookup = async () => [{ address: "8.8.8.8", family: 4 }];
  assert.equal((await validateRemoteUrl("https://example.test:8443/file", { lookup })).safe, false);
  assert.equal((await validateRemoteUrl("https://example.test/file", { lookup })).safe, true);
  assert.equal(connectTarget("example.test:22"), null);
  assert.deepEqual(connectTarget("example.test:443"), {
    hostname: "example.test",
    port: 443,
    url: "https://example.test:443/",
  });
});

test("contrôle toutes les adresses renvoyées par le DNS", async () => {
  const result = await validateRemoteUrl("https://example.test/video", {
    lookup: async () => [{ address: "8.8.8.8" }, { address: "127.0.0.1" }],
  });
  assert.equal(result.safe, false);
});

test("refuse une redirection vers le réseau local", async () => {
  const calls = [];
  const response = await safeFetch("https://public.test/file", {}, {
    lookup: async hostname => [{ address: hostname === "public.test" ? "8.8.8.8" : "127.0.0.1" }],
    fetchImpl: async url => {
      calls.push(url);
      return { status: 302, headers: new Headers({ location: "http://internal.test/private" }) };
    },
  }).catch(error => error);
  assert.match(response.message, /internes/);
  assert.equal(calls.length, 1);
});

test("epingle la connexion Node sur l'adresse DNS validee", async () => {
  let requestOptions;
  const requestImpl = (options, onResponse) => {
    requestOptions = options;
    const request = new EventEmitter();
    request.end = () => {
      const response = Readable.from(["ok"]);
      response.statusCode = 200;
      response.statusMessage = "OK";
      response.headers = { "content-type": "text/plain" };
      onResponse(response);
    };
    request.destroy = error => request.emit("error", error);
    return request;
  };
  const response = await safeFetch("https://public.test/file", {}, {
    lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    requestImpl,
  });
  assert.equal(await response.text(), "ok");
  assert.equal(requestOptions.hostname, "8.8.8.8");
  assert.equal(requestOptions.servername, "public.test");
  assert.equal(requestOptions.headers.host, "public.test");
});
