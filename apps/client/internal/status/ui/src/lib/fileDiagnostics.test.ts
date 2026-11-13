import assert from "node:assert/strict";
import { test } from "node:test";
import { localLogTime, mergeFileDiagnostics } from "./fileDiagnostics.ts";

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

test("mixed daemon and file timestamps use the client's system timezone without changing the instant", () => {
  const saved = process.env.TZ;
  try {
    process.env.TZ = "Asia/Shanghai";
    const lines = mergeFileDiagnostics([
      'time=2026-11-12T02:13:08.482Z level=WARN msg=first',
      'time="2026-11-12T10:13:08.482+08:00" level=WARN msg=first',
      'time=invalid level=INFO msg=keep',
    ], [{ time_unix_ms: Date.parse('2026-11-12T02:13:12.569Z'), action: 'rdp_paste_stream', error: 'test' }]);
    assert.equal(lines.length, 3);
    assert.ok(lines.includes('time=2026-11-12T10:13:08.482+08:00 level=WARN msg=first'));
    assert.ok(lines.some(line => line.startsWith('time=2026-11-12T10:13:12.569+08:00')));
    assert.ok(lines.includes('time=invalid level=INFO msg=keep'));
    process.env.TZ = "America/New_York";
    assert.equal(localLogTime(new Date('2026-07-12T02:00:00Z')), '2026-07-11T22:00:00.000-04:00');
    assert.equal(localLogTime(new Date('2026-11-12T02:00:00Z')), '2026-11-11T21:00:00.000-05:00');
    process.env.TZ = "Pacific/Kiritimati";
    assert.equal(localLogTime(new Date('2026-11-12T23:59:00Z')).slice(0,10), '2026-11-13');
  } finally {
    if (saved === undefined) delete process.env.TZ; else process.env.TZ = saved;
  }
});
