import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { sshFileErrorKey, sshFiles, type SshFileBatch, type SshTransferFile, type SshTransferProgress } from "../api/ssh";

type Props = {
  sessionId: string;
  direction: "upload" | "download";
  progress?: SshTransferProgress;
  batch?: SshFileBatch;
  error?: string;
  size: (bytes: number) => string;
  onClose: () => void;
};

function percent(done: number, total: number, complete: boolean) {
  return total ? Math.min(100, Math.floor(100 * done / total)) : complete ? 100 : 0;
}

export default function SshTransferPanel({ sessionId, direction, progress, batch, error, size, onClose }: Props) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const listId = useId();
  const bodyId = useId();
  const titleId = useId();
  const snapshot = batch?.transfer ?? progress;
  const files = snapshot?.files ?? [];
  const current = snapshot?.current == null ? undefined : files[snapshot.current];
  const reason = error ?? (batch?.error ? sshFileErrorKey(batch.error) : undefined);
  const cancelled = reason === "sshFiles.cancelled";
  const active = !batch && !error;
  const completed = batch?.completed ?? files.filter(file => file.state === "completed").length;
  const skipped = batch?.skipped ?? files.filter(file => file.state === "skipped").length;
  const count = batch?.count ?? files.length;
  const done = files.reduce((sum, file) => sum + file.done, 0);
  const total = files.every(file => file.total !== null)
    ? files.reduce((sum, file) => sum + (file.total ?? 0), 0) : null;
  const percentage = total === null || !files.length ? undefined : percent(done, total, completed === count);
  const heading = reason ? cancelled ? "sshFiles.cancelled" : "sshTransfer.failed"
    : active ? cancelling ? "sshTransfer.cancelling" : direction === "upload" ? "sshTransfer.uploading" : "sshTransfer.downloading"
    : skipped ? "sshTransfer.finishedWithSkips" : "sshFiles.completed";

  function rowState(file: SshTransferFile) {
    return file.state === "pending" && !active ? "untouched" : file.state;
  }
  function fileProgress(file: SshTransferFile) {
    if (file.total === null) return file.done ? size(file.done) : undefined;
    if (file.state === "pending" || file.state === "skipped") return size(file.total);
    return size(file.done) + " / " + size(file.total) + " · " +
      percent(file.done, file.total, file.state === "completed") + "%";
  }
  async function cancel() {
    setCancelling(true);
    try { await sshFiles(sessionId, { kind: "cancel" }); } catch { setCancelling(false); }
  }

  return <footer className={"ssh-transfer" + (collapsed ? " ssh-transfer-compact" : "")}
    aria-labelledby={titleId} data-state={cancelled ? "cancelled" : reason ? "failed" : active ? "active" : "finished"}>
    <div className="ssh-transfer-header">
      {!collapsed && <div className="ssh-transfer-kicker">CALABI <span>/</span> {t("sshTransfer.title")}</div>}
      <h3 id={titleId} aria-live="polite">{t(heading)}</h3>
    </div>
    <div id={bodyId} className="ssh-transfer-body" hidden={collapsed}>
      {count > 0 ? <>
        <div className="ssh-transfer-summary">
          {t("sshTransfer.total", {
            bytes: size(done) + " / " + (total === null || !files.length ? "—" : size(total)),
            completed, total: count, percent: percentage === undefined ? "" : " · " + percentage + "%",
          })}
          {skipped > 0 && " · " + t("sshTransfer.skippedCount", { count: skipped })}
        </div>
        <progress aria-label={t("sshTransfer.progressLabel")} max={100} value={active ? percentage : percentage ?? 0} />
      </> : active && <div className="ssh-transfer-summary">{t("sshFiles.preparing")}</div>}
      {current && <div className="ssh-transfer-current">
        <div className="ssh-transfer-name" title={current.name} dir="auto">{current.name}</div>
        <div className="ssh-transfer-detail" data-state={rowState(current)}>
          {[t("sshTransfer.states." + rowState(current)), fileProgress(current)].filter(Boolean).join(" · ")}
        </div>
      </div>}
      {!current && batch?.failed_file && <div className="ssh-transfer-name" title={batch.failed_file} dir="auto">{batch.failed_file}</div>}
      {reason && !cancelled && <div className="ssh-transfer-error" role="alert">{t(reason)}</div>}
      {files.length > 1 && <>
        <button type="button" className="ssh-transfer-toggle" aria-expanded={expanded} aria-controls={listId}
          onClick={() => setExpanded(value => !value)}>
          {t(expanded ? "sshTransfer.hideFiles" : "sshTransfer.showFiles")} <span aria-hidden="true">{expanded ? "▴" : "▾"}</span>
        </button>
        <ul className="ssh-transfer-files" id={listId} hidden={!expanded}>
          {expanded && files.map((file, index) => <li key={index}>
            <div className="ssh-transfer-file-heading">
              <div className="ssh-transfer-name" title={file.name} dir="auto">{file.name}</div>
              <div className="ssh-transfer-detail" data-state={rowState(file)}>{t("sshTransfer.states." + rowState(file))}</div>
            </div>
            <div className="ssh-transfer-detail">{fileProgress(file)}</div>
          </li>)}
        </ul>
      </>}
    </div>
    <div className="ssh-transfer-actions">
      <button type="button" className="ssh-transfer-toggle" aria-expanded={!collapsed} aria-controls={bodyId}
        onClick={() => setCollapsed(value => !value)}>{t(collapsed ? "sshTransfer.expand" : "sshTransfer.collapse")}</button>
      <button type="button" className="ssh-transfer-action" disabled={active && cancelling}
        onClick={active ? () => { void cancel(); } : onClose}>{t(active ? "files.cancel" : "sshTransfer.close")}</button>
    </div>
  </footer>;
}
