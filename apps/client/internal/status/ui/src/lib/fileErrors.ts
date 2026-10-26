// Raw agent errors remain available to diagnostics, never as user-facing copy.
// Match established errors from older agents too, including nested HTTP errors.
export function fileErrorKey(error: string): string {
  const text = error.toLowerCase();
  if (/source is referenced by a task/.test(text)) return "sourceInUse";
  // A changed receipt is stale metadata, not a moved local source file.
  if (/request changed/.test(text)) return "stale";
  if (/cannot save received file/.test(text)) {
    if (/checksum|sha256|hash mismatch|verification failed/.test(text)) return "integrity";
    if (/no space|disk full|not enough space/.test(text)) return "storage";
    return "storageWrite";
  }
  if (/no longer authorized|not authorized|permission denied|access is denied|http (401|403)/.test(text)) return "authorization";
  if (/certificate|x509|identity changed|file key/.test(text)) return "identity";
  if (/file-control|filecontrol|file agent|live file metadata|desktop app|desktop file|daemon unavailable|private inbox/.test(text)) return "agent";
  if (/source.*(changed|unavailable|missing)|no such file|cannot find the file|file.*(changed|unavailable)|size changed/.test(text)) return "source";
  if (/checksum|sha256|hash mismatch|verification failed/.test(text)) return "integrity";
  if (/no space|disk full|not enough space/.test(text)) return "storage";
  if (/persist|read-only|read only|cannot (save|write)|i\/o error/.test(text)) return "storageWrite";
  if (/timeout|timed out|deadline exceeded|offline|not receiving|connection|dial tcp|network|reconnect|eof|http 5\d\d/.test(text)) return "connection";
  if (/limit exceeded|too many|up to 32|another batch|quota/.test(text)) return "limit";
  if (/process restarted/.test(text)) return "restarted";
  if (/unknown task|unknown source|unknown transfer|task cannot be resumed|http (404|410)/.test(text)) return "stale";
  if (/context canceled|context cancelled/.test(text)) return "interrupted";
  return "generic";
}

export function fileJobErrorKey(job?: { state: string; cancel_pending?: boolean; error?: string }): string | undefined {
  if (!job?.error || job.cancel_pending || job.state === "cancelled" || job.state === "completed") return undefined;
  return fileErrorKey(job.error);
}
