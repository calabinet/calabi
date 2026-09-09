// rate.ts — bytes/second from a set of cumulative per-member counters.
//
// This is arithmetic that used to be inlined in the Overview chart, where it got
// three things wrong at once and reported instantaneous rates of several GB/s on
// a home uplink that cannot do 20 Mbit/s. It lives here, pure and tested,
// because a throughput number that looks plausible is acted on: the GB/s spikes
// were read as "we burst at connection start and trip the ISP's shaper", which
// sent a real investigation after a chart artifact.
//
// What went wrong, and what each rule below is holding shut:
//
//  1. THE WRONG CLOCK. Overview summed two independently-polled sources — the
//     daemon snapshot at 2s and the mesh status at 5s — into one number and
//     divided that sum's delta by the time since the sum last CHANGED. The two
//     pollers drift, so the 5s mesh response regularly landed a few tens of
//     milliseconds after a 2s snapshot response: five seconds of mesh bytes
//     divided by 0.04s is a 125x overstatement. At a true 15 Mbit/s that prints
//     as ~1.9 GB/s. Hence: each source measures against the last time THAT
//     source was sampled, and the caller sums RATES, never counters.
//
//  2. MEMBERSHIP CHANGES CHARGED AS TRAFFIC. Both sources are sums over a list
//     — tunnels, mesh peers — whose membership moves. A peer appearing carried
//     its entire lifetime counter into a single interval's delta, so one mesh
//     reconnect billed the chart for every byte that peer had ever moved. Hence:
//     only members present in BOTH samples contribute.
//
//  3. A RESET LOOKED LIKE NEGATIVE TRAFFIC. Counters restart at 0 on a daemon
//     or mesh reconnect. Clamping the SUM at zero (what the old code did) let a
//     growing member hide a reset one, and vice versa. Hence: the clamp is
//     per-member, so a reset costs that member one sample instead of distorting
//     the total in either direction.
//
// Not solved here, deliberately: when a member is dropped mid-interval its
// in-interval bytes are lost. Attributing them would need a departure timestamp
// the daemon does not send, and undercounting a vanished tunnel is the harmless
// direction.

/** A set of cumulative counters read at one instant. */
export interface CounterSample {
  /** Milliseconds (Date.now / react-query's dataUpdatedAt). */
  at: number;
  /** Stable member id -> cumulative bytes. Ids must survive across polls. */
  totals: Map<string, number>;
}

/** Build a sample from a list, summing the byte fields of each member. */
export function sampleOf<T>(
  at: number,
  items: readonly T[] | undefined,
  id: (item: T) => string,
  bytes: (item: T) => number,
): CounterSample {
  const totals = new Map<string, number>();
  for (const item of items ?? []) {
    // Sum rather than assign: a duplicated id would otherwise silently drop one
    // of the rows instead of counting it.
    totals.set(id(item), (totals.get(id(item)) ?? 0) + bytes(item));
  }
  return { at, totals };
}

/**
 * Bytes per second between two samples of the same counter set.
 *
 * Returns 0 rather than Infinity or NaN when the interval is not positive: two
 * reads of the same instant carry no rate information, and a chart is better
 * off plotting nothing than plotting a number no traffic produced.
 */
export function counterSetRate(prev: CounterSample, next: CounterSample): number {
  const dt = (next.at - prev.at) / 1000;
  if (!(dt > 0)) return 0; // also catches NaN

  let delta = 0;
  for (const [id, now] of next.totals) {
    const before = prev.totals.get(id);
    if (before === undefined) continue; // newcomer: its history is not this interval's traffic
    if (now > before) delta += now - before; // a counter that fell was reset, not run backwards
  }
  return delta / dt;
}
