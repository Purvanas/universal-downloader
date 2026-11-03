const assert = require("node:assert/strict");
const test = require("node:test");
const { isPrivateIP, safeFetch, validateRemoteUrl } = require("../lib/network-security");

test("bloque les plages internes IPv4 et IPv6", () => {
  for (const address of ["127.0.0.1", "10.1.2.3", "100.100.0.1", "192.168.1.2", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "2001:db8::1"]) {
    assert.equal(isPrivateIP(address), true, address);
  }
  assert.equal(isPrivateIP("1.1.1.1"), false);
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
