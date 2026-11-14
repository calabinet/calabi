import { useEffect } from "react";

type DesktopWindow = Window & { __TAURI_INTERNALS__?: { invoke(command: string, args: unknown): Promise<unknown> } };

export function setLoginWindow(compact: boolean) {
  return (window as DesktopWindow).__TAURI_INTERNALS__?.invoke("desktop_set_login_window", { compact })
    .catch(() => { /* Browsers and older desktop shells keep their current size. */ });
}

export function useLoginWindow(active: boolean) {
  useEffect(() => {
    if (active) void setLoginWindow(true);
  }, [active]);
}
