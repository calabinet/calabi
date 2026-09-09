// use-counter-rate.ts — a react-query-polled counter set, as bytes/second.
//
// One of these per POLLED SOURCE. The arithmetic lives in lib/rate.ts (with the
// tests); what this adds is the part that has to be a hook: holding the previous
// sample across renders, and — the reason the old chart read GB/s — sampling on
// the FETCH rather than on the value.
//
// Sampling on the value meant two things went wrong that this shape fixes:
//
//   * Two sources summed into one number were measured against whichever of them
//     changed the number last. A 5s poller landing milliseconds after a 2s
//     poller had five seconds of bytes divided by that gap. Each source now
//     carries its own baseline and its own clock, and callers add RATES.
//
//   * An idle link changes no value, so no sample was recorded and the chart
//     held its last rate on screen forever. `dataUpdatedAt` advances on every
//     successful fetch whether the bytes moved or not, so idle now plots 0.
//
// `at` is returned alongside the rate so a caller can tell a live 0 from a
// source that stopped answering — see freshRate below.
import { useEffect, useRef, useState } from "react";
import { counterSetRate, sampleOf, type CounterSample } from "../lib/rate";

export interface Measured {
  /** Bytes per second over the last interval of THIS source. */
  rate: number;
  /** When the rate was measured (ms); 0 until a second poll has landed. */
  at: number;
}

export function useCounterRate<T>(
  items: readonly T[] | undefined,
  updatedAt: number | undefined,
  id: (item: T) => string,
  bytes: (item: T) => number,
): Measured {
  const [measured, setMeasured] = useState<Measured>({ rate: 0, at: 0 });
  const prev = useRef<CounterSample | null>(null);

  // Keyed on updatedAt alone: it is the fetch identity. `items` is a fresh array
  // on every render, so depending on it would resample on unrelated re-renders
  // with a near-zero interval — the exact bug this file exists to remove.
  useEffect(() => {
    if (!updatedAt) return; // no successful fetch yet
    const next = sampleOf(updatedAt, items, id, bytes);
    const before = prev.current;
    prev.current = next;
    if (!before) return; // first sample is a baseline, not a rate
    setMeasured({ rate: counterSetRate(before, next), at: updatedAt });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [updatedAt]);

  return measured;
}

/**
 * A source's rate, or 0 if its last measurement is older than maxAgeMs.
 *
 * A query that starts failing keeps its last data and stops advancing
 * dataUpdatedAt, which would otherwise leave a dead source contributing a stale
 * non-zero rate to the total indefinitely. Evaluated at render time — the 2s
 * snapshot poll re-renders the page often enough that no extra timer is needed.
 */
export function freshRate(m: Measured, maxAgeMs: number, now: number = Date.now()): number {
  if (m.at <= 0) return 0;
  return now - m.at <= maxAgeMs ? m.rate : 0;
}
