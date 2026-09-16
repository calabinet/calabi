// plan.ts — translates plan codes into the user-visible display name the
// SPA shows wherever a plan badge appears.
//
// One caller left, the sidebar footer. The Settings page used to print the
// plan too and no longer does: the plan NAME is an account fact that belongs
// in the web console — on a machine-local page it tells you nothing you can
// act on. planTagColor went with it (2026-09-16); `git show` if the tier
// colors are wanted again.
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
