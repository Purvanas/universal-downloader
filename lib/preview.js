"use strict";

const { Transform } = require("node:stream");

const MAX_PREVIEW_BYTES = 3 * 1024 * 1024;
const PREVIEW_CONTENT_TYPES = new Map([
  ["image/jpeg", "image/jpeg"],
  ["image/jpg", "image/jpeg"],
  ["image/png", "image/png"],
  ["image/webp", "image/webp"],
  ["image/gif", "image/gif"],
]);

function previewContentType(value) {
  return PREVIEW_CONTENT_TYPES.get(String(value || "").split(";", 1)[0].trim().toLowerCase()) || null;
}

function previewLengthAllowed(value, maxBytes = MAX_PREVIEW_BYTES) {
  if (value == null || value === "") return true;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 && parsed <= maxBytes;
}

function createPreviewByteLimit(maxBytes = MAX_PREVIEW_BYTES) {
  let total = 0;
  return new Transform({
    transform(chunk, encoding, callback) {
      total += chunk.length;
      if (total > maxBytes) return callback(new Error("Apercu trop volumineux"));
      callback(null, chunk);
    },
  });
}

module.exports = { MAX_PREVIEW_BYTES, createPreviewByteLimit, previewContentType, previewLengthAllowed };
