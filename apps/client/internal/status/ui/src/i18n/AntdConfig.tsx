// AntdConfig.tsx — wraps the app in antd's ConfigProvider with a locale
// that tracks the active i18n language (was hardcoded zhCN in main.tsx).
//
// Reads i18n.language via useTranslation so the whole antd subtree
// re-renders on a language toggle, swapping antd's built-in component
// strings (pagination, date pickers, empty states) AND the dayjs global
// locale. The brand theme tokens that used to live in main.tsx live here.
import { useTranslation } from "react-i18next";
import { ConfigProvider, theme } from "antd";
import deDE from "antd/locale/de_DE";
import enUS from "antd/locale/en_US";
import esES from "antd/locale/es_ES";
import frFR from "antd/locale/fr_FR";
import itIT from "antd/locale/it_IT";
import ptBR from "antd/locale/pt_BR";
import koKR from "antd/locale/ko_KR";
import jaJP from "antd/locale/ja_JP";
import zhCN from "antd/locale/zh_CN";
import zhTW from "antd/locale/zh_TW";
import dayjs from "dayjs";
// dayjs locale side-effect imports register each locale string below; "en" is
// dayjs's built-in default and needs no import.
import "dayjs/locale/de";
import "dayjs/locale/es";
import "dayjs/locale/fr";
import "dayjs/locale/it";
import "dayjs/locale/pt-br";
import "dayjs/locale/ko";
import "dayjs/locale/ja";
import "dayjs/locale/zh-cn";
import "dayjs/locale/zh-tw";
import { resolveLang, type LangCode } from "./languages";

const antdLocales = {
  de: deDE,
  en: enUS,
  es: esES,
  fr: frFR,
  it: itIT,
  pt: ptBR,
  ko: koKR,
  ja: jaJP,
  "zh-CN": zhCN,
  "zh-TW": zhTW,
} as const;
const dayjsLocales: Record<LangCode, string> = {
  de: "de",
  en: "en",
  es: "es",
  fr: "fr",
  it: "it",
  pt: "pt-br",
  ko: "ko",
  ja: "ja",
  "zh-CN": "zh-cn",
  "zh-TW": "zh-tw",
};

export default function AntdConfig({ children }: { children: React.ReactNode }) {
  const { i18n } = useTranslation();
  const lng: LangCode = resolveLang(i18n.language);

  // dayjs is a global singleton — set it on every render where lng changed.
  dayjs.locale(dayjsLocales[lng]);

  return (
    <ConfigProvider
      locale={antdLocales[lng]}
      theme={{
        // Dark "tech" theme matching the marketing site (web/www): near-black
        // deep-space navy surface, electric indigo primary, cyan link accent.
        algorithm: theme.darkAlgorithm,
        token: {
          // Brand indigo (brand-500, brighter than the #2742f0 wordmark so it
          // pops on dark) drives buttons / active states; cyan is the link /
          // accent half of the indigo→cyan gradient language.
          colorPrimary: "#3a5cff",
          colorInfo: "#3a5cff",
          colorLink: "#22d3ee",
          colorLinkHover: "#67e8f9",
          // Navy-tinted neutral base — derives all the dark greys with a blue
          // cast so cards/inputs read as the same "ink" family as the site.
          colorBgBase: "#05070f",
          borderRadius: 8,
          fontFamily:
            '-apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif',
        },
        components: {
          Layout: {
            bodyBg: "#05070f",
            headerBg: "#0b1022",
            siderBg: "#0b1022",
          },
          Menu: {
            itemBg: "transparent",
            itemSelectedBg: "rgba(58,92,255,0.16)",
            itemSelectedColor: "#8eaaff",
          },
        },
      }}
    >
      {children}
    </ConfigProvider>
  );
}
