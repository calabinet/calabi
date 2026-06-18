// i18n/languages.ts — single source of truth for the UI's supported locales.
//
// The order here is the order the language switcher renders. Each entry's
// `label` is the language's OWN endonym (shown the same regardless of the
// active UI language), and `code` is the exact i18next/localStorage code.
// index.ts (resources + supportedLngs), AntdConfig.tsx (antd + dayjs locale
// maps) and Layout.tsx (the switcher menu) all derive from this list, so
// adding a language is a one-line change plus its locale JSON.
export const LANGS = [
  { code: "de", label: "Deutsch" },
  { code: "en", label: "English" },
  { code: "es", label: "Español" },
  { code: "fr", label: "Français" },
  { code: "it", label: "Italiano" },
  { code: "pt", label: "Português" },
  { code: "ko", label: "한국어" },
  { code: "ja", label: "日本語" },
  { code: "zh-CN", label: "简体中文" },
  { code: "zh-TW", label: "繁體中文" },
] as const;

export type LangCode = (typeof LANGS)[number]["code"];

const CODES = LANGS.map((l) => l.code) as readonly LangCode[];

// resolveLang maps whatever i18next reports as the active language down to one
// of our exact supported codes. The detector + switcher always set exact codes,
// but a base code (e.g. "zh") or an unknown value degrades to English — never a
// raw key path. zh is disambiguated to Simplified as the historical default.
export function resolveLang(raw: string | undefined): LangCode {
  if (!raw) return "en";
  if ((CODES as readonly string[]).includes(raw)) return raw as LangCode;
  if (raw === "zh" || raw.startsWith("zh-Hans") || raw.startsWith("zh-CN"))
    return "zh-CN";
  if (raw.startsWith("zh-Hant") || raw.startsWith("zh-TW")) return "zh-TW";
  const base = raw.split("-")[0];
  if ((CODES as readonly string[]).includes(base)) return base as LangCode;
  return "en";
}
