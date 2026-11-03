"use strict";

const assert = require("node:assert/strict");
const { Writable } = require("node:stream");
const { pipeline } = require("node:stream/promises");
const test = require("node:test");
const { createPreviewByteLimit, previewContentType, previewLengthAllowed } = require("../lib/preview");

test("n'autorise que les formats d'image raster attendus", () => {
  assert.equal(previewContentType("image/jpeg; charset=binary"), "image/jpeg");
  assert.equal(previewContentType("image/webp"), "image/webp");
  assert.equal(previewContentType("image/svg+xml"), null);
  assert.equal(previewContentType("text/html"), null);
});

test("refuse une taille declaree ou diffusee superieure a la limite", async () => {
  assert.equal(previewLengthAllowed("4", 4), true);
  assert.equal(previewLengthAllowed("5", 4), false);
  assert.equal(previewLengthAllowed("invalid", 4), false);

  const sink = new Writable({ write(chunk, encoding, callback) { callback(); } });
  await assert.rejects(
    pipeline(
      async function* () { yield Buffer.from("123"); yield Buffer.from("45"); }(),
      createPreviewByteLimit(4),
      sink,
    ),
    /trop volumineux/,
  );
});
