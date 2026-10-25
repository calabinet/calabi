import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileErrorKey, fileJobErrorKey } from "./fileErrors.ts";

test("legacy errors become safe localized summaries in both supported languages", () => {
  const cases = [
    ["cancelled locally; awaiting peer cancellation: file transfer is no longer authorized", "authorization"],
    ['Post "https://100.64.0.26:17401/file/v1/offers": dial tcp 100.64.0.18:0->100.64.0.26:17401: i/o timeout', "connection"],
    ['open \\\\.\\pipe\\Calabi.FileControl.v1.7400: Access is denied.', "authorization"],
    ["source changed since preparation", "source"],
    ["cannot persist cancellation acknowledgment: disk full", "storage"],
    ["process restarted; resume to continue", "restarted"],
    ["context canceled", "interrupted"],
    ["unexpected exception with /private/local/path", "generic"],
  ];
  for (const [raw, key] of cases) {
    assert.equal(fileErrorKey(raw), key);
    for (const language of ["en", "zh-CN"]) {
      const locale = JSON.parse(readFileSync(new URL(`../i18n/locales/${language}.json`, import.meta.url), "utf8"));
      const message = locale.files.errors[key];
      assert.ok(message && !message.includes(raw));
      assert.doesNotMatch(message, /https:|\/private|context canceled|\?\?\?/);
      if (language === "zh-CN") assert.match(message, /[\u4e00-\u9fff]/);
    }
  }
});

test("cancellation synchronization is a status, while interrupted work has a localized error", () => {
  const legacy = "cancelled locally; awaiting peer cancellation: file transfer is no longer authorized";
  assert.equal(fileJobErrorKey({ state: "cancelled", cancel_pending: true, error: legacy }), undefined);
  assert.equal(fileJobErrorKey({ state: "cancelled", error: legacy }), undefined);
  assert.equal(fileJobErrorKey({ state: "completed", error: "old error" }), undefined);
  assert.equal(fileJobErrorKey({ state: "paused", error: "dial tcp: i/o timeout" }), "connection");
});
