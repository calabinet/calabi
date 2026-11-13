type NativeWindow = Window & { __TAURI_INTERNALS__?: { invoke<T>(command: string, args?: unknown): Promise<T> } };
export type SshInfo = { name: string; host: string; account: string; port: number; native_clipboard?: boolean };
export type SshFileEntry = { name: string; kind: "directory" | "file" | "other"; size: number | null };
export type SshDirectory = { path: string; entries: SshFileEntry[]; partial: boolean };
export type SshTransferFile = {
  name: string; done: number; total: number | null;
  state: "pending" | "transferring" | "completed" | "skipped" | "cancelled" | "failed";
};
export type SshTransferProgress = { files: SshTransferFile[]; current: number | null };
export type SshFileProgress = { transfer: SshTransferProgress };
export type SshFileBatch = {
  count: number; completed: number; skipped: number; error: string | null; failed_file: string | null;
  transfer: SshTransferProgress;
};
export type SshDeleteResult = { deleted: number; remaining: number; failures: { name: string; error: string }[] };
type Confirmation = { title: string; message: string; replace: string; cancel: string; skip?: string };
type SshFileAction =
  | { kind: "list"; path?: string }
  | { kind: "upload"; dir: string; confirm: Confirmation; detailed: true }
  | { kind: "download"; paths: string[]; confirm: Confirmation; detailed: true }
  | { kind: "delete"; dir: string; names: string[]; confirm: Confirmation }
  | { kind: "progress" | "cancel" };
export type SshRequest =
  | { op: "info" }
  | { op: "start" | "resize"; rows: number; cols: number }
  | { op: "input"; data: string }
  | { op: "clipboard_read" }
  | { op: "clipboard_write"; text: string }
  | { op: "files"; action: SshFileAction };

function invoke<T>(command: string, args?: unknown): Promise<T> {
  const native = (window as NativeWindow).__TAURI_INTERNALS__;
  return native ? native.invoke<T>(command, args) : Promise.reject(new Error("SSH requires Calabi Desktop"));
}

export type RemoteSession = { id: string; name: string; protocol: "ssh" | "rdp" };
export type RemoteWorkspace = {
  active: string | null;
  fullscreen: boolean;
  sessions: RemoteSession[];
  nativeRdp?: boolean;
  rdpCompare?: boolean;
  frameWait?: boolean;
  canMinimize?: boolean;
};
type WorkspaceRequest =
  | { op: "snapshot" | "minimize" }
  | { op: "select" | "close"; id: string }
  | { op: "rdp_input"; id: string; kind: number; a: number; b: number; delta: number }
  | { op: "rdp_canvas_stats"; id: string; width: number; height: number; elapsed_ms: number; received: number; submitted: number; max_gap_ms: number }
  | { op: "fullscreen"; enabled?: boolean };

export const remoteWorkspace = <T = void>(request: WorkspaceRequest) => invoke<T>("remote_workspace", { request });
export const remoteFrame = (id: string, revision: number, cursorRevision?: number, thumbnail?: boolean, waitForUpdate?: boolean) =>
  invoke<ArrayBuffer | number[]>("remote_frame", { id, revision, cursorRevision, thumbnail, waitForUpdate });
export const sshSession = <T = void>(sessionId: string, request: SshRequest) => invoke<T>("ssh_session", { sessionId, request });
export const sshRead = (sessionId: string) => invoke<ArrayBuffer | number[]>("ssh_read", { sessionId });
export const sshFiles = <T = void>(sessionId: string, action: SshFileAction) => sshSession<T>(sessionId, { op: "files", action });

export function sshFileErrorKey(error: unknown) {
  switch (error instanceof Error ? error.message : String(error)) {
    case "sftpCancelled": return "sshFiles.cancelled";
    case "sftpUnavailable": return "sshFiles.unavailable";
    case "sftpConnect": return "sshFiles.connectFailed";
    case "sftpDisconnected": return "sshFiles.disconnected";
    case "sftpInterrupted": return "sshFiles.interrupted";
    case "sftpPermission": return "sshFiles.permission";
    case "sftpMissing": return "sshFiles.missing";
    case "sftpChanged": return "sshFiles.changed";
    case "sftpSourceChanged": return "sshFiles.sourceChanged";
    case "sftpDestinationChanged": return "sshFiles.destinationChanged";
    case "sftpLocal": return "sshFiles.localError";
    case "sftpLocalRead": return "sshFiles.localRead";
    case "sftpLocalWrite": return "sshFiles.localWrite";
    case "sftpLocalSpace": return "sshFiles.localSpace";
    case "sftpLocalBusy": return "sshFiles.localBusy";
    case "sftpLocalCommit": return "sshFiles.localCommit";
    case "sftpRemoteList": return "sshFiles.remoteList";
    case "sftpRemoteRead": return "sshFiles.remoteRead";
    case "sftpRemoteWrite": return "sshFiles.remoteWrite";
    case "sftpRemoteWriteDenied": return "sshFiles.remoteWriteDenied";
    case "sftpRemoteSpace": return "sshFiles.remoteSpace";
    case "sftpRemoteCommit": return "sshFiles.remoteCommit";
    case "sftpCommitUnknown": return "sshFiles.commitUnknown";
    case "sftpDeleteFailed": return "sshFiles.deleteFailed";
    case "sftpDeleteUnknown": return "sshFiles.deleteUnknown";
    case "sftpTimeout": return "sshFiles.timeout";
    case "sftpUnsupported": return "sshFiles.unsupported";
    case "sftpNotFile": return "sshFiles.notFile";
    case "sftpInvalidPath": return "sshFiles.invalidPath";
    case "sftpBusy": return "sshFiles.busy";
    default: {
      const key = sshErrorKey(error);
      return key === "ssh.failed" ? "sshFiles.failed" : key;
    }
  }
}

export function sshErrorKey(error: unknown) {
  switch (error instanceof Error ? error.message : String(error)) {
    case "sshClientMissing": return "ssh.clientMissing";
    case "sshNativeUnavailable": return "ssh.failed";
    case "sshTargetUnavailable": return "ssh.targetUnavailable";
    case "sshTargetChanged": return "ssh.targetChanged";
    case "sshInvalidLogin": return "ssh.invalidLogin";
    case "sshInvalidPassword": return "ssh.invalidPassword";
    case "sshAuthFailed": return "ssh.authFailed";
    case "sshHostKeyChanged": return "ssh.hostKeyChanged";
    case "sshHostKeyRejected": return "ssh.hostKeyRejected";
    case "sshLoginTimeout": return "ssh.loginTimeout";
    case "sshCredentialFailed": return "ssh.credentialFailed";
    case "sshCredentialMissing": return "ssh.credentialMissing";
    case "sshHistoryFailed": return "ssh.historyFailed";
    default: return "ssh.failed";
  }
}
