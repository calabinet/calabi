import assert from "node:assert/strict";
import { test } from "node:test";
import { mergeFileDiagnostics } from "./fileDiagnostics.ts";

test("private file errors appear in the same ordered log view and export", () => {
  const daemon = ['time=2026-10-26T10:00:00Z level=INFO msg=connected', 'time=2026-10-26T10:02:00Z level=INFO msg=updated'];
  const entries = [{ time_unix_ms: Date.parse("2026-10-26T10:01:00Z"), action: "forget_source", error: "source is referenced by a task; remove its record first" }];
  const lines = mergeFileDiagnostics(daemon, entries);
  assert.equal(lines.length, 3);
  assert.match(lines[1], /level=WARN component=file-transfer action="forget_source"/);
  assert.match(lines[1], /remove its record first/);
  assert.deepEqual(daemon, ['time=2026-10-26T10:00:00Z level=INFO msg=connected', 'time=2026-10-26T10:02:00Z level=INFO msg=updated']);
});

test("invalid diagnostics are ignored and embedded line breaks cannot forge entries", () => {
  const lines = mergeFileDiagnostics([], [{ time_unix_ms: NaN, action: "save", error: "ignored" }, { time_unix_ms: 1, action: "save", error: "failed\nlevel=INFO forged" }]);
  assert.equal(lines.length, 1);
  assert.equal(lines[0].split("\n").length, 1);
  assert.match(lines[0], /failed\\nlevel=INFO/);
});
