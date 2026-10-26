import { useQuery } from "@tanstack/react-query";
import i18n from "../i18n";
type NativeWindow = Window & { __TAURI_INTERNALS__?: { invoke<T>(command: string, args: unknown): Promise<T> }; __CALABI_FILE_WEB__?: boolean; __CALABI_FILE_WEB_BASE__?: string };
export const hasBrowserFiles = () => (window as NativeWindow).__CALABI_FILE_WEB__ === true;
export const hasNativeFiles = () => !!(window as NativeWindow).__TAURI_INTERNALS__ || hasBrowserFiles();
export async function fileWebRequest<T>(path: string, body?: unknown): Promise<T> {
  const base = (window as NativeWindow).__CALABI_FILE_WEB_BASE__ || "";
  const response = await fetch(`${base}/file-web/${path}`, { credentials: "same-origin", ...(body !== undefined ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "File browser unavailable");
  return value as T;
}
export async function fileAction<T = FileSnapshot>(action: Record<string, unknown>): Promise<T> {
  if (hasBrowserFiles()) return fileWebRequest<T>("action", action);
  const native = (window as NativeWindow).__TAURI_INTERNALS__;
  if (!native) throw new Error("File transfers require the desktop app");
  const result = await native.invoke<T & { error?: string }>("files_action", { action }).catch((err: unknown) => {
    throw err instanceof Error ? err : new Error(String(err));
  });
  if (result.error) throw new Error(result.error);
  return result;
}
export function useFileSupport() {
  return useQuery({ queryKey: ["files-support", i18n.language], queryFn: async () => {
    if (!hasNativeFiles()) {
      try { const response = await fetch("/file-service/available", { credentials: "same-origin" }); if (!response.ok) return false; return (await response.json()).supported === true; } catch { return false; }
    }
    return (await fileAction<{ supported: boolean }>({ action: "supported", locale: i18n.language })).supported;
  }, staleTime: 5000, retry: false, refetchInterval: query => query.state.data === true ? false : 5000 });
}
export async function revokeUserFiles() {
  if (!hasNativeFiles()) return;
  try { await fileAction({ action: "revoke" }); } catch { /* older shells have no file agent */ }
}
export type FileTransfer = { created_unix_ms?: number; pause_supported?: boolean; stop_reason?: string; id: string; batch: string; batch_count: number; name: string; state: string; size: number; offset: number; rate_bps?: number; remaining_seconds?: number };
export type FileSource = { id: string; name: string; size: number; created_unix_ms?: number };
export type FileJob = { created_unix_ms?: number; stop_reason?: string; cancel_pending?: boolean; sources?: string[]; id: string; peer_ip: string; state: string; error?: string; rate_bps?: number; remaining_seconds?: number; progress: { preparation?: { phase: "hashing" | "connecting"; name: string; index: number; count: number; bytes: number; size: number }; index: number; count: number; transfer: FileTransfer } };
export type FilePeer = { name: string; grant: { peer: { IP: string; Fingerprint: string }; device_key: string; receiving: boolean }; expires_unix: number };
export type FileReceived = { ip: string; device_key: string; transfer: FileTransfer };
export type FileSnapshot = { available: boolean; preparing: boolean; preparation_error?: string; unavailable_reason?: string; receiving: boolean; peers: FilePeer[]; sources: FileSource[]; jobs: FileJob[]; received: FileReceived[]; service?: { managed: boolean; directory: string; receiving_requested: boolean; auto_save: boolean; error?: string; saved?: Record<string, string> }; identity?: { exists: boolean; fingerprint?: string; expires_unix?: number; needs_renewal: boolean; error?: string } };
