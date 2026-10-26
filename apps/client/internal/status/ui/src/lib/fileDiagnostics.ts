export type FileDiagnostic = { time_unix_ms: number; action: string; error: string };

// File-agent diagnostics arrive through the private desktop bridge, never HTTP.
export function mergeFileDiagnostics(daemon: string[], entries: FileDiagnostic[]): string[] {
  const extra = entries.filter(row => Number.isFinite(row.time_unix_ms) && row.time_unix_ms > 0 && row.time_unix_ms < 8.64e15 && typeof row.action === "string" && typeof row.error === "string")
    .map(row => `time=${new Date(row.time_unix_ms).toISOString()} level=WARN component=file-transfer action=${JSON.stringify(row.action)} error=${JSON.stringify(row.error)}`);
  const timestamp = (line: string) => {
    const match = line.match(/(?:^|\s)time=(?:"([^"]+)"|([^\s]+))/);
    return match ? Date.parse(match[1] || match[2]) || 0 : 0;
  };
  return [...new Set([...daemon, ...extra])].sort((a, b) => timestamp(a) - timestamp(b));
}
