import type { FileJob, FileReceived, FileSnapshot, FileSource } from "../api/files";

// A job's progress is only the current file. Its ordered source IDs retain the
// whole batch, including completed files no longer represented by progress.
export function fileJobSummary(job: FileJob, sources: FileSource[]) {
  const ordered = (job.sources || []).map(id => sources.find(source => source.id === id));
  const current = job.progress.transfer;
  if (!ordered.length || ordered.some(source => !source)) {
    return { files: [{ id: current.id || job.id, name: current.name, size: current.size || 0 }], size: current.size || 0, offset: current.offset || 0 };
  }
  const files = ordered as FileSource[];
  const size = files.reduce((total, file) => total + file.size, 0);
  // BatchSender completes each file before advancing its index. A terminal
  // completion means all receipts were verified, including zero-byte files.
  const index = Math.max(0, Math.min(job.progress.index, files.length - 1));
  const offset = job.state === "completed" ? size : files.reduce((total, file, i) => total + (i < index ? file.size : i === index ? Math.min(file.size, Math.max(0, current.offset || 0)) : 0), 0);
  return { files, size, offset };
}

export type FileFilter = "all" | "active" | "waiting" | "completed";
export type FileRecord = { key: string; direction: "outgoing"; job: FileJob } | { key: string; direction: "incoming"; received: FileReceived };
export type FileRequest = { key: string; rows: FileReceived[]; waiting: FileReceived[]; complete: boolean };

export function fileJobState(job: FileJob): string {
  if (job.state === "cancelled" && job.stop_reason) return job.stop_reason;
  if (job.cancel_pending) return "cancelPending";
  if (job.state === "paused" && job.error) return "interrupted";
  if (job.state !== "sending") return job.state;
  if (job.progress.preparation) return job.progress.preparation.phase;
  const state = job.progress.transfer?.state;
  if (state === "paused") return "receiver_paused";
  return ["waiting", "verifying", "committing", "preparing"].includes(state) ? state : "sending";
}

export const fileRecordTime = (row: FileRecord) => (row.direction === "outgoing" ? row.job.created_unix_ms : row.received.transfer.created_unix_ms) || 0;

// Immutable creation times keep progress updates from shuffling task rows.
export function fileRecords(data: Pick<FileSnapshot, "jobs" | "received">): FileRecord[] {
  return [
    ...data.jobs.map(job => ({ key: `out/${job.id}`, direction: "outgoing" as const, job })),
    ...data.received.filter(row => row.transfer.state !== "waiting").map(received => ({ key: `in/${received.device_key}/${received.transfer.id}`, direction: "incoming" as const, received })),
  ].sort((a, b) => fileRecordTime(b) - fileRecordTime(a) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

export function fileRecordMatches(row: FileRecord, filter: FileFilter): boolean {
  if (filter === "all") return true;
  const state = row.direction === "outgoing" ? row.job.state : row.received.transfer.state;
  if (filter === "completed") return state === "completed";
  if (filter === "waiting") return false;
  return row.direction === "outgoing"
    ? !!row.job.cancel_pending || state === "sending" || state === "paused"
    : ["accepted", "receiving", "paused", "waiting_sender", "verifying", "committing"].includes(state);
}

export function fileRequests(rows: FileReceived[]): FileRequest[] {
  const groups = new Map<string, FileReceived[]>();
  for (const row of rows) {
    const key = `${row.device_key}/${row.transfer.batch || row.transfer.id}`;
    const group = groups.get(key) || [];
    group.push(row);
    groups.set(key, group);
  }
  return [...groups].flatMap(([key, rows]) => {
    const waiting = rows.filter(row => row.transfer.state === "waiting");
    if (!waiting.length) return [];
    return [{ key, rows, waiting, complete: rows.length >= Math.max(...rows.map(row => row.transfer.batch_count || 1)) }];
  }).sort((a, b) => Math.max(...b.rows.map(row => row.transfer.created_unix_ms || 0)) - Math.max(...a.rows.map(row => row.transfer.created_unix_ms || 0)) || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}
