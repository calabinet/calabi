import { theme, type ThemeConfig } from "antd";

// Default palettes from web/console/src/i18n/AntdConfig.tsx. No console cookie:
// a local daemon / desktop profile remembers its own appearance preference.
export function appearanceTokens(dark: boolean): ThemeConfig {
  const canvas = dark ? "#0b0f1a" : "#eceef4";
  const sheet = dark ? "#111624" : "#ffffff";
  const ink = dark ? "#e7eaf3" : "#161a2b";
  const primary = dark ? "#4d6bff" : "#2742f0";
  return {
    algorithm: dark ? theme.darkAlgorithm : theme.defaultAlgorithm,
    token: {
      colorPrimary: primary, colorInfo: primary,
      colorLink: dark ? "#8ea2ff" : "#2742f0",
      colorSuccess: dark ? "#34c38f" : "#12a36f",
      colorWarning: dark ? "#f0a53a" : "#e08a14",
      colorError: dark ? "#ff6b62" : "#e5483e",
      colorText: ink, colorTextSecondary: dark ? "#a9b0c4" : "#5d6278",
      colorTextTertiary: dark ? "#7b839c" : "#8a8fa3",
      colorTextQuaternary: dark ? "#586079" : "#b3b7c6",
      colorBgBase: sheet, colorBgLayout: canvas, colorBgContainer: sheet,
      colorBgElevated: dark ? "#1a2133" : "#ffffff",
      colorBorder: dark ? "#2b3347" : "#dfe2ea",
      colorBorderSecondary: dark ? "#1f2637" : "#eceef3",
      colorFillAlter: dark ? "#151b2b" : "#f7f8fb", borderRadius: 8,
      fontFamily: '-apple-system, BlinkMacSystemFont, "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif',
    },
    components: {
      Layout: { bodyBg: canvas, siderBg: canvas, headerBg: sheet, lightSiderBg: canvas },
      Menu: { itemBg: "transparent", itemSelectedBg: dark ? "#161c2c" : "#ffffff", itemSelectedColor: dark ? "#9db0ff" : primary },
      Modal: { contentBg: sheet, headerBg: sheet, footerBg: sheet },
    },
  };
}
