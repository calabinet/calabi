// Run with: node --test src/lib/usageDays.test.ts   (node >= 22 strips the types)
//
// The zone is set before anything reads the clock: the bug these tests pin
// only shows west of Greenwich, and the machines that build this are not there.
process.env.TZ = "America/Los_Angeles";

import { test } from "node:test";
import assert from "node:assert/strict";
import { dayLabel, dayTime, oldestFirst } from "./usageDays.ts";

// What the daemon connected to a self-hosted server answers /v1/usage/daily
// with (localweb.handleUsageDaily): its own meter's days, bare local dates,
// oldest first.
const standalone = [
  { ts: "2026-10-04", bytes_total: 1 },
  { ts: "2026-10-05", bytes_total: 2 },
  { ts: "2026-10-06", bytes_total: 3 },
];

// What bff-console answers through the platform daemon: ISO timestamps at the
// viewer's midnight, newest first.
const platform = [
  { ts: "2026-10-06T00:00:00-07:00", bytes_total: 3 },
  { ts: "2026-10-05T00:00:00-07:00", bytes_total: 2 },
  { ts: "2026-10-04T00:00:00-07:00", bytes_total: 1 },
];

test("the zone under test is west of Greenwich", () => {
  // Without this the label test below passes on any machine for no reason.
  assert.equal(new Date("2026-10-04").getDate(), 3, "TZ did not take effect");
});

test("a bare date is that day in the viewer's calendar", () => {
  assert.equal(dayLabel("2026-10-04"), "10/4");
  assert.equal(dayLabel("2026-01-01"), "1/1");
  assert.equal(new Date(dayTime("2026-10-04")).getHours(), 0);
});

test("an ISO timestamp keeps its own moment", () => {
  assert.equal(dayLabel("2026-10-04T00:00:00-07:00"), "10/4");
  assert.equal(dayTime("2026-10-04T07:00:00Z"), Date.UTC(2026, 9, 4, 7));
});

test("a ts that is not a date is shown as it came", () => {
  assert.equal(dayLabel("soon"), "soon");
});

test("the self-hosted daemon's oldest-first days are left in order", () => {
  assert.deepEqual(oldestFirst(standalone).map((b) => b.ts), ["2026-10-04", "2026-10-05", "2026-10-06"]);
});

test("the platform's newest-first days are reversed", () => {
  assert.deepEqual(oldestFirst(platform).map((b) => b.bytes_total), [1, 2, 3]);
});

test("both daemons end up drawing today on the right", () => {
  const last = <T,>(a: T[]) => a[a.length - 1];
  assert.equal(dayLabel(last(oldestFirst(standalone)).ts), "10/6");
  assert.equal(dayLabel(last(oldestFirst(platform)).ts), "10/6");
});

test("the input is not reordered in place", () => {
  const copy = [...platform];
  oldestFirst(platform);
  assert.deepEqual(platform, copy);
});

test("short and unreadable lists fall back to the reversal the chart always did", () => {
  assert.deepEqual(oldestFirst([]), []);
  assert.deepEqual(oldestFirst([{ ts: "2026-10-04" }]), [{ ts: "2026-10-04" }]);
  assert.deepEqual(oldestFirst([{ ts: "a" }, { ts: "b" }]).map((b) => b.ts), ["b", "a"]);
});
