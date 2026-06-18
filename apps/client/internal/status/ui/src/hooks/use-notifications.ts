// use-notifications.ts — minimal browser-notification helper for the
// daemon UI. M7-S5 task #44.
//
// What we notify on (callers fire these):
//
//   - quota threshold crossing (80% → 100%)
//   - daemon state regression (connected → reconnecting / fatal)
//   - tunnel health flip (ok → down, 3 consecutive failures)
//
// Permission flow: we DON'T prompt on first load (that pattern triggers
// permission fatigue and most users click "Block" by reflex). Instead a
// small banner on the Overview page asks once; the user has to click to
// trigger requestPermission().
//
// State management is intentionally tiny — a useState in App.tsx would
// also work, but this hook keeps the API surface obvious.
import { useEffect, useRef } from "react";

const NOTIFY_DEDUP_MS = 60_000;
const lastSeen = new Map<string, number>();

export type NotifyPermission = "default" | "granted" | "denied" | "unsupported";

export function notificationPermission(): NotifyPermission {
  if (typeof Notification === "undefined") return "unsupported";
  return Notification.permission as NotifyPermission;
}

export async function requestNotificationPermission(): Promise<NotifyPermission> {
  if (typeof Notification === "undefined") return "unsupported";
  if (Notification.permission === "granted") return "granted";
  if (Notification.permission === "denied") return "denied";
  const got = await Notification.requestPermission();
  return got as NotifyPermission;
}

// notify fires a desktop notification, deduped by `key` over a 60s
// window. Silent on permission != granted (no-op so callers don't need
// branching).
export function notify(key: string, title: string, body: string) {
  if (typeof Notification === "undefined" || Notification.permission !== "granted") {
    return;
  }
  const now = Date.now();
  const prev = lastSeen.get(key) ?? 0;
  if (now - prev < NOTIFY_DEDUP_MS) return;
  lastSeen.set(key, now);
  try {
    new Notification(title, { body, tag: key });
  } catch {
    // Some browsers throw on too-frequent notifications; swallow.
  }
}

// useTransitionNotify watches a value over time and fires `notify`
// when the value changes from `from` to `to`. Useful for "connected
// → reconnecting" style alerts.
export function useTransitionNotify<T>(
  value: T | undefined,
  from: T,
  to: T,
  key: string,
  title: string,
  body: string,
) {
  const prev = useRef<T | undefined>(value);
  useEffect(() => {
    if (prev.current === from && value === to) {
      notify(key, title, body);
    }
    prev.current = value;
  }, [value, from, to, key, title, body]);
}
