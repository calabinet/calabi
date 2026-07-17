// plan.ts — translates plan codes into the user-visible display name the
// SPA shows wherever a plan badge appears (topbar, Settings, future
// upgrade prompts).
//
// Codes mirror apps/quota-svc/internal/store/store.go::seedPlans — keep
// the i18n `plan.*` keys in lockstep when new plan rows are added there.
// Labels live in src/i18n/locales/{en,zh-CN}.json under `plan.*`; unknown
// codes fall back to a Title-Cased version of the code so we don't render
// an empty cell if the server emits a value the SPA hasn't shipped a label
// for yet.
//
// planLabel reads i18n.t directly (not a hook): every call site renders
// inside a component that already subscribes to i18n via useTranslation,
// so the whole subtree re-renders on a language toggle and the label
// updates with it. Editing labels still requires npm build + go build to
// re-bake the embedded dist into calabi.exe.
import i18n from "../i18n";

export function planLabel(code?: string): string {
  if (!code) return "—";
  return i18n.t(`plan.${code}`, {
    defaultValue: code.charAt(0).toUpperCase() + code.slice(1),
  });
}

// planTagColor picks an antd Tag color that escalates with tier. Free
// is neutral, basic/pro are progressively richer blues, business is
// gold-ish, enterprise is purple (matches the catalog page on the marketing
// site so users associate the colors with the same tier elsewhere).
export function planTagColor(code?: string): string {
  switch (code) {
    case "free":
      return "default";
    case "basic":
      return "blue";
    case "pro":
      return "geekblue";
    case "business":
      return "gold";
    case "enterprise":
      return "purple";
    default:
      return "blue";
  }
}
