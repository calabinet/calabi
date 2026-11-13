export type FileDiagnostic = { time_unix_ms: number; action: string; level?: string; error: string };

// Use the client's OS timezone at the event instant, including historical DST.
export function localLogTime(date: Date): string {
  const pad = (value: number, digits = 2) => String(value).padStart(digits, "0");
  const offset = -date.getTimezoneOffset();
  return `${pad(date.getFullYear(), 4)}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}${offset < 0 ? "-" : "+"}${pad(Math.floor(Math.abs(offset) / 60))}:${pad(Math.abs(offset) % 60)}`;
}

function localLogLine(line: string): string {
  return line.replace(/^time=(?:"([^"]+)"|(\S+))/, (original, quoted: string, plain: string) => {
    const timestamp = quoted || plain;
    // A timezone is required: do not guess the origin of ambiguous timestamps.
    if (!/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(timestamp)) return original;
    const date = new Date(timestamp);
    return Number.isFinite(date.getTime()) ? `time=${localLogTime(date)}` : original;
  });
}

// File-agent diagnostics arrive through the private desktop bridge, never HTTP.
export function mergeFileDiagnostics(daemon: string[], entries: FileDiagnostic[]): string[] {
  const extra = entries.filter(row => Number.isFinite(row.time_unix_ms) && row.time_unix_ms > 0 && row.time_unix_ms < 8.64e15 && typeof row.action === "string" && typeof row.error === "string")
    .map(row => `time=${localLogTime(new Date(row.time_unix_ms))} level=${row.level === "INFO" ? "INFO" : "WARN"} component=file-transfer action=${JSON.stringify(row.action)} error=${JSON.stringify(row.error)}`);
  const timestamp = (line: string) => {
    const match = line.match(/(?:^|\s)time=(?:"([^"]+)"|([^\s]+))/);
    return match ? Date.parse(match[1] || match[2]) || 0 : 0;
  };
  return [...new Set([...daemon.map(localLogLine), ...extra])].sort((a, b) => timestamp(a) - timestamp(b));
}
