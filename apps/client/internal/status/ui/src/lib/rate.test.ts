// Run with: node --test src/lib/rate.test.ts   (node >= 22 strips the types)
import { test } from "node:test";
import assert from "node:assert/strict";
import { counterSetRate, sampleOf, type CounterSample } from "./rate.ts";

const sample = (at: number, totals: Record<string, number>): CounterSample => ({
  at,
  totals: new Map(Object.entries(totals)),
});

// THE HEADLINE BUG, with the numbers that produced it.
//
// Overview polls two sources on independent timers — the daemon snapshot every
// 2s and the mesh status every 5s — and used to add their byte counters into one
// running total, then divide that total's delta by the time since the total last
// changed. The schedules drift against each other, so the mesh response lands a
// few tens of milliseconds after a snapshot response twice a minute. When it
// does, five seconds of mesh bytes get divided by the gap between two unrelated
// HTTP responses.
//
// This test runs that exact schedule against real numbers (a 15 Mbit/s mesh
// transfer plus a 2 Mbit/s tunnel) and asserts both halves: measuring each
// source against its own clock lands on the truth, and the old shared-clock
// arithmetic overstates it by more than 100x.
test("interleaved pollers do not inflate the rate", () => {
  const TUNNEL_BPS = 250_000; // 2 Mbit/s
  const MESH_BPS = 1_875_000; // 15 Mbit/s
  const TRUTH = TUNNEL_BPS + MESH_BPS;

  const tunnelAt = (t: number) => ({ tun1: Math.round((TUNNEL_BPS * t) / 1000) });
  const meshAt = (t: number) => ({ peerA: Math.round((MESH_BPS * t) / 1000) });

  // snapshot every 2s from 0; mesh every 5s from 1040ms, so it lands 40ms after
  // a snapshot whenever the two schedules coincide (every 10s).
  const events: { at: number; src: "tunnel" | "mesh" }[] = [];
  for (let t = 0; t <= 18_000; t += 2_000) events.push({ at: t, src: "tunnel" });
  for (let t = 1_040; t <= 18_000; t += 5_000) events.push({ at: t, src: "mesh" });
  events.sort((a, b) => a.at - b.at);

  // --- the fix: one baseline per source, and we sum RATES ---
  const prev: Record<string, CounterSample | null> = { tunnel: null, mesh: null };
  const rate: Record<string, number> = { tunnel: 0, mesh: 0 };
  const seen: Record<string, number> = { tunnel: 0, mesh: 0 };
  const perSourceTotals: number[] = [];

  // --- the old code: one baseline for the summed counter ---
  let naivePrev: { at: number; total: number } | null = null;
  const naiveTotals: number[] = [];
  let lastTunnel = 0;
  let lastMesh = 0;

  for (const ev of events) {
    const totals: Record<string, number> =
      ev.src === "tunnel" ? tunnelAt(ev.at) : meshAt(ev.at);
    const next = sample(ev.at, totals);
    const before = prev[ev.src];
    prev[ev.src] = next;
    seen[ev.src]++;
    if (before) rate[ev.src] = counterSetRate(before, next);
    // A source needs TWO samples before it has a rate at all. Until then it
    // contributes 0, so the first seconds after a page load under-report — the
    // benign direction, and self-correcting. Only assert once both have settled.
    if (seen.tunnel >= 2 && seen.mesh >= 2) perSourceTotals.push(rate.tunnel + rate.mesh);

    if (ev.src === "tunnel") lastTunnel = totals.tun1;
    else lastMesh = totals.peerA;

    const summed = lastTunnel + lastMesh;
    if (naivePrev) {
      const dt = (ev.at - naivePrev.at) / 1000;
      if (dt > 0) naiveTotals.push(Math.max(0, (summed - naivePrev.total) / dt));
    }
    naivePrev = { at: ev.at, total: summed };
  }

  // Every settled sample from the fixed path is the real rate.
  assert.ok(perSourceTotals.length >= 5, `only ${perSourceTotals.length} settled samples`);
  for (const got of perSourceTotals) {
    assert.ok(
      Math.abs(got - TRUTH) / TRUTH < 0.01,
      `per-source rate ${Math.round(got)} B/s is not within 1% of ${TRUTH} B/s`,
    );
  }

  // The old path spikes past 100x the real rate on the coinciding samples.
  const worst = Math.max(...naiveTotals);
  assert.ok(
    worst > TRUTH * 100,
    `expected the shared-clock arithmetic to blow past 100x ${TRUTH} B/s, saw ${Math.round(worst)} B/s`,
  );
});

// The same coincidence with a tighter gap is what put GB/s on the screen. Two
// fetches against 127.0.0.1 landing 5ms apart is ordinary, not a freak event,
// and the chart formats anything over 1024^3 as GB/s.
test("a few milliseconds of poll coincidence reads as GB/s", () => {
  const MESH_BPS = 1_875_000; // 15 Mbit/s — five seconds of it is 9.4 MB
  const fiveSeconds = MESH_BPS * 5;
  const naive = fiveSeconds / 0.005;
  assert.ok(
    naive > 1024 ** 3,
    `expected > 1 GB/s from a 5ms denominator, got ${Math.round(naive)} B/s`,
  );
});

// A peer or tunnel joining the list brings its whole lifetime counter with it.
// Charging that to the interval it appeared in is how one mesh reconnect used to
// bill the chart for every byte the peer had ever moved.
test("a newcomer's history is not this interval's traffic", () => {
  const prev = sample(0, { peerA: 1_000 });
  const next = sample(1_000, { peerA: 2_000, peerB: 10_000_000_000 });
  assert.equal(counterSetRate(prev, next), 1_000); // peerA's 1000 bytes in 1s, and nothing else
});

// Counters restart at zero on a daemon or mesh reconnect. Clamping the SUM (what
// the old code did) let a growing member mask a reset one; clamping per member
// costs the reset member one sample and leaves the rest of the total intact.
test("a counter reset costs one member's sample, not the total", () => {
  const prev = sample(0, { steady: 5_000, resets: 900_000 });
  const next = sample(1_000, { steady: 8_000, resets: 100 });
  assert.equal(counterSetRate(prev, next), 3_000); // steady's delta only
});

// Idle has to read as zero. Sampling on value-change meant an idle link recorded
// no sample at all and the chart held its last rate on screen indefinitely,
// which is the one reading a throughput chart must never give.
test("no movement is zero, not the previous value", () => {
  const prev = sample(0, { tun1: 4_242 });
  const next = sample(2_000, { tun1: 4_242 });
  assert.equal(counterSetRate(prev, next), 0);
});

// Two reads of the same instant carry no rate information. Returning Infinity
// (or NaN, from 0/0) would render as an axis that swallows every real sample.
test("a non-positive interval yields zero, not Infinity or NaN", () => {
  assert.equal(counterSetRate(sample(1_000, { a: 0 }), sample(1_000, { a: 500 })), 0);
  assert.equal(counterSetRate(sample(2_000, { a: 0 }), sample(1_000, { a: 500 })), 0);
});

test("sampleOf sums both directions and does not drop a duplicated id", () => {
  const got = sampleOf(
    7,
    [
      { id: "t1", in: 10, out: 5 },
      { id: "t1", in: 1, out: 1 },
      { id: "t2", in: 100, out: 0 },
    ],
    (x) => x.id,
    (x) => x.in + x.out,
  );
  assert.equal(got.at, 7);
  assert.equal(got.totals.get("t1"), 17);
  assert.equal(got.totals.get("t2"), 100);
});
