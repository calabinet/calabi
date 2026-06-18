// i18n/index.ts — i18next bootstrap for the daemon UI SPA.
//
// Default locale is ENGLISH (the product launches overseas first). The
// detector reads localStorage ONLY (key "calabi_lang") — there is NO
// navigator sniffing, so a brand-new visitor always lands in English and
// only sees 中文 after they explicitly toggle it. fallbackLng "en" means a
// missing zh key degrades to English copy, never to a raw key path.
//
// Resources are bundled (static import) rather than fetched — the SPA is
// go:embed'd into calabi.exe, so an async http-backend would be wrong here.
//
// NOTE: editing any locale JSON or string requires `npm run build` THEN
// `go build` to re-bake the embedded dist into calabi.exe — npm alone does
// not touch the running daemon binary.
import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { LANGS } from "./languages";
import de from "./locales/de.json";
import en from "./locales/en.json";
import es from "./locales/es.json";
import fr from "./locales/fr.json";
import it from "./locales/it.json";
import pt from "./locales/pt.json";
import ko from "./locales/ko.json";
import ja from "./locales/ja.json";
import zhCN from "./locales/zh-CN.json";
import zhTW from "./locales/zh-TW.json";

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      de: { translation: de },
      en: { translation: en },
      es: { translation: es },
      fr: { translation: fr },
      it: { translation: it },
      pt: { translation: pt },
      ko: { translation: ko },
      ja: { translation: ja },
      "zh-CN": { translation: zhCN },
      "zh-TW": { translation: zhTW },
    },
    fallbackLng: "en",
    supportedLngs: LANGS.map((l) => l.code),
    // NOTE: do NOT set nonExplicitSupportedLngs — it resolves a regional code
    // (e.g. "zh-CN") down to its base ("zh") for resource lookup, and since our
    // Chinese resources live under the exact keys "zh-CN"/"zh-TW", every key
    // would miss and fall back to English (switching to 中文 would show no
    // change). The switcher always sets exact codes, so we don't need it.
    load: "currentOnly",
    interpolation: { escapeValue: false }, // React already escapes
    detection: {
      order: ["localStorage"],
      lookupLocalStorage: "calabi_lang",
      caches: ["localStorage"],
    },
  });

// Keep <html lang> in lockstep with the active language (one source of
// truth; the switcher just calls changeLanguage and this fires).
i18n.on("languageChanged", (lng) => {
  document.documentElement.lang = lng;
});
document.documentElement.lang = i18n.language || "en";

export default i18n;
