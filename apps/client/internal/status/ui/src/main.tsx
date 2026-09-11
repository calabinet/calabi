// main.tsx — entry point for the calabi daemon UI SPA.
//
// What gets wired here:
//   - i18n (react-i18next) — imported for its init side-effect FIRST, so
//     the language is resolved before the first render. English is the
//     default; the user picks from 10 languages in the top-bar Language
//     menu (see i18n/index.ts + i18n/languages.ts; the menu is built in
//     components/Layout.tsx).
//   - React Query client (5s default stale time — most of our data
//     changes slowly; live data has its own refetchInterval).
//   - React Router with HashRouter, NOT BrowserRouter. Reason: we
//     might be mounted under /ui/ (back-compat) AND served from /
//     in the same binary. Hash routing means the SPA's internal URLs
//     never collide with server-side routes regardless of mount point.
//   - AntdConfig — antd ConfigProvider whose locale/theme tracks the
//     active i18n language (replaces the old hardcoded zhCN ConfigProvider).
import React from "react";
import ReactDOM from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { HashRouter } from "react-router-dom";

import i18n from "./i18n";
import AntdConfig from "./i18n/AntdConfig";
import App from "./App";
import { isConsoleLocked } from "./api/client";
import { CONSOLE_STATE_KEY } from "./components/ConsoleLockGate";
import "./styles/global.css";

// A visitor from another machine whose unlock lapsed (12 h, or the daemon
// restarted) gets 401 console_locked from whatever the page asks next — a
// poll, a save. Any such answer sends the page back to the unlock form, rather
// than leaving each view to show its own error until something else notices.
const relockOnLockedAnswer = (e: unknown) => {
  if (isConsoleLocked(e)) {
    void queryClient.invalidateQueries({ queryKey: CONSOLE_STATE_KEY });
  }
};

const queryClient = new QueryClient({
  queryCache: new QueryCache({ onError: relockOnLockedAnswer }),
  mutationCache: new MutationCache({ onError: relockOnLockedAnswer }),
  defaultOptions: {
    queries: {
      staleTime: 5_000,
      gcTime: 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <I18nextProvider i18n={i18n}>
      <AntdConfig>
        <QueryClientProvider client={queryClient}>
          <HashRouter>
            <App />
          </HashRouter>
        </QueryClientProvider>
      </AntdConfig>
    </I18nextProvider>
  </React.StrictMode>,
);
