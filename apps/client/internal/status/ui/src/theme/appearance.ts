import { useSyncExternalStore } from "react";

export type AppearanceMode = "system" | "light" | "dark";
const KEY = "calabi.client.theme";
const valid = (value: unknown): value is AppearanceMode => value === "system" || value === "light" || value === "dark";
const media = window.matchMedia("(prefers-color-scheme: light)");
let mode: AppearanceMode = "system";
try { const saved = localStorage.getItem(KEY); if (valid(saved)) mode = saved; } catch { /* blocked storage: session preference still works */ }
const listeners = new Set<() => void>();
const snapshot = () => `${mode}:${media.matches ? "light" : "dark"}`;
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
function publish() { listeners.forEach(listener => listener()); }
media.addEventListener("change", publish);
window.addEventListener("storage", event => {
  if (event.key === KEY || event.key === null) { mode = valid(event.newValue) ? event.newValue : "system"; publish(); }
});
export function setAppearanceMode(value: AppearanceMode) {
  if (!valid(value)) return;
  mode = value;
  try { localStorage.setItem(KEY, value); } catch { /* session only */ }
  publish();
}
export function useAppearance() {
  useSyncExternalStore(subscribe, snapshot);
  return { mode, scheme: (mode === "system" ? (media.matches ? "light" : "dark") : mode) as "light" | "dark", setMode: setAppearanceMode };
}
