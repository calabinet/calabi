// usageDays.ts — reading the day buckets of /v1/usage/daily.
//
// Two different daemons answer that path, in two shapes:
//
//   - the platform daemon proxies bff-console: `ts` is an ISO timestamp and the
//     buckets come NEWEST first (i=0 = today);
//   - the daemon connected to a self-hosted server answers from its own meter
//     (localweb.handleUsageDaily over usageMeter.DailyBytes): `ts` is a bare
//     LOCAL date, "2026-06-14", and the buckets come OLDEST first.
//
// The chart was written against the first and met the second: it reversed
// whatever it was given, so a self-hosted console drew its week backwards with
// today on the left, and it read the bare date as UTC midnight, so west of
// Greenwich every bar was labelled with the day before.

// dayTime reads a bucket ts as a moment; NaN when it is neither form. A bare
// date is built from its parts so that it is midnight HERE — new Date() would
// take "2026-06-14" for midnight UTC, which is still the 13th in the Americas.
export function dayTime(ts: string): number {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ts);
  return (m ? new Date(+m[1], +m[2] - 1, +m[3]) : new Date(ts)).getTime();
}

// dayLabel is the chart's short "M/D" tick, in the viewer's calendar. On a ts
// that does not parse it shows the raw string.
export function dayLabel(ts: string): string {
  const d = new Date(dayTime(ts));
  if (Number.isNaN(d.getTime())) return ts;
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

// oldestFirst puts buckets in the order a bar chart reads, left to right. It
// looks at the timestamps rather than at which daemon answered: only a list
// that is plainly ascending already is left alone, and anything else — the
// platform's newest-first list, or one whose ends do not parse — is reversed,
// which is what the chart did to every list before.
export function oldestFirst<T extends { ts: string }>(buckets: T[]): T[] {
  const ascending =
    buckets.length > 1 && dayTime(buckets[0].ts) < dayTime(buckets[buckets.length - 1].ts);
  return ascending ? buckets : [...buckets].reverse();
}
