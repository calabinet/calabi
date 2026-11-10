import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Checkbox, Input, Spin } from "antd";
import { useTranslation } from "react-i18next";
import { sshFileErrorKey, sshFiles, type SshDeleteResult, type SshDirectory, type SshFileBatch, type SshFileProgress, type SshTransferProgress } from "../api/ssh";
import MeshGlyph, { fileGlyph } from "./MeshGlyph";
import SshTransferPanel from "./SshTransferPanel";

type Transfer = { id: number; direction: "upload" | "download"; batch?: SshFileBatch; error?: string };

export default function SshFilePanel({ sessionId, open, connected, onClose }: { sessionId: string; open: boolean; connected: boolean; onClose: () => void }) {
  const { t, i18n } = useTranslation();
  const [directory, setDirectory] = useState<SshDirectory>();
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState<"list" | "upload" | "download" | "delete">();
  const [progress, setProgress] = useState<SshTransferProgress>();
  const [transfer, setTransfer] = useState<Transfer>();
  const [browseError, setBrowseError] = useState<string>();
  const [deletion, setDeletion] = useState<SshDeleteResult>();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const listViewport = useRef<HTMLDivElement>(null);
  const pending = useRef(false);
  const nextTransfer = useRef(0);
  const initialized = useRef(false);
  const bytes = useMemo(() => new Intl.NumberFormat(i18n.language, { maximumFractionDigits: 1 }), [i18n.language]);
  const size = (n: number) => {
    const index = n >= 1024 ** 3 ? 3 : n >= 1024 ** 2 ? 2 : n >= 1024 ? 1 : 0;
    return bytes.format(n / 1024 ** index) + " " + ["B", "KiB", "MiB", "GiB"][index];
  };

  const load = useCallback(async (target?: string) => {
    const result = await sshFiles<SshDirectory>(sessionId, { kind: "list", path: target });
    setDirectory(result);
    setPath(result.path);
    setSelected(new Set());
  }, [sessionId]);

  const run = useCallback(async (kind: NonNullable<typeof busy>, work: () => Promise<void>) => {
    if (pending.current) return;
    pending.current = true;
    setBusy(kind);
    setBrowseError(undefined);
    setDeletion(undefined);
    const direction = kind === "upload" || kind === "download" ? kind : undefined;
    const id = direction ? ++nextTransfer.current : 0;
    if (direction) {
      setProgress(undefined);
      setTransfer({ id, direction });
    }
    try { await work(); } catch (error) {
      const key = sshFileErrorKey(error);
      if (direction) {
        // Once a batch starts, its cancellation is returned with the batch result.
        setTransfer(key === "sshFiles.cancelled" ? undefined : { id, direction, error: key });
      } else if (key !== "sshFiles.cancelled") {
        setBrowseError(key);
      }
    } finally {
      pending.current = false;
      setBusy(undefined);
    }
  }, []);

  const browse = useCallback((target?: string) => { void run("list", () => load(target)); }, [load, run]);
  useEffect(() => {
    if (!open || !connected || initialized.current) return;
    const initial = window.setTimeout(() => { initialized.current = true; browse(); }, 0);
    return () => window.clearTimeout(initial);
  }, [browse, connected, open]);

  const transferring = !!transfer && !transfer.batch && !transfer.error;
  useEffect(() => {
    if (!transferring) return;
    let current = true;
    let timer: number;
    async function poll() {
      try {
        const value = await sshFiles<SshFileProgress | null>(sessionId, { kind: "progress" });
        if (current && value?.transfer) setProgress(value.transfer);
      } catch { /* Keep the last snapshot until the transfer returns its result. */ }
      if (current) timer = window.setTimeout(poll, 250);
    }
    void poll();
    return () => { current = false; window.clearTimeout(timer); };
  }, [sessionId, transferring]);

  const entries = useMemo(() => [...(directory?.entries || [])].sort((a, b) =>
    Number(b.kind === "directory") - Number(a.kind === "directory") ||
    a.name.localeCompare(b.name, i18n.language, { numeric: true })), [directory, i18n.language]);
  const selectedNames = entries.filter(entry => entry.kind === "file" && selected.has(entry.name)).map(entry => entry.name);

  const confirm = {
    title: t("sshFiles.overwrite"), message: t("sshFiles.overwriteMessage"),
    replace: t("sshFiles.replace"), cancel: t("files.cancel"), skip: t("sshFiles.skipFile"),
  };
  function report(batch: SshFileBatch) {
    setTransfer(current => current && { ...current, batch });
  }

  function upload() {
    if (!directory) return;
    const dir = directory.path;
    void run("upload", async () => {
      const batch = await sshFiles<SshFileBatch>(sessionId, { kind: "upload", dir, confirm, detailed: true });
      report(batch);
      if (batch.completed) await load(dir).catch(() => {});
    });
  }

  function download(names: string[]) {
    if (!directory || !names.length) return;
    const parent = directory.path.replace(/\/$/, "");
    const paths = names.map(name => `${parent}/${name}`);
    void run("download", async () => {
      report(await sshFiles<SshFileBatch>(sessionId, { kind: "download", paths, confirm, detailed: true }));
    });
  }

  function toggleFile(name: string, checked: boolean) {
    setSelected(previous => {
      const next = new Set(previous);
      if (checked) next.add(name);
      else next.delete(name);
      return next;
    });
  }

  function deleteSelected() {
    if (!directory || !selectedNames.length) return;
    const dir = directory.path;
    const confirm = {
      title: t("sshFiles.deleteSelected"),
      message: t("sshFiles.deleteConfirm", { count: selectedNames.length }),
      replace: t("common.delete"),
      cancel: t("common.cancel"),
    };
    void run("delete", async () => {
      const result = await sshFiles<SshDeleteResult>(sessionId, { kind: "delete", dir, names: selectedNames, confirm });
      setDeletion(result);
      listViewport.current?.scrollTo(0, 0);
      await load(dir).catch(error => setBrowseError(sshFileErrorKey(error)));
    });
  }

  const unavailable = !!busy || !connected;
  const showTransfer = transfer && (transfer.batch || transfer.error || !!progress?.files.length);
  const message = browseError ?? (!connected && !busy && !transfer ? "sshFiles.disconnected" : undefined);
  const parent = directory?.path.substring(0, directory.path.lastIndexOf("/")) || "/";

  return <aside id={sessionId + "-files"} className="ssh-files-panel" hidden={!open} aria-label={t("sshFiles.title")}>
    <header className="ssh-files-header">
      <div><h2>{t("sshFiles.title")}</h2><span>SFTP</span></div>
      <Button type="text" size="small" icon={<MeshGlyph name="close" />} aria-label={t("sshFiles.close")} onClick={onClose} />
    </header>
    <form className="ssh-files-path" onSubmit={event => { event.preventDefault(); if (path && !unavailable) browse(path); }}>
      <Button size="small" aria-label={t("sshFiles.parent")} title={t("sshFiles.parent")}
        disabled={unavailable || !directory || directory.path === "/"} onClick={() => browse(parent)}>↑</Button>
      <Input size="small" value={path} aria-label={t("sshFiles.path")} placeholder="/" disabled={unavailable || !directory}
        spellCheck={false} onChange={event => setPath(event.target.value)} />
    </form>
    <div className="ssh-files-tools">
      <Button size="small" disabled={unavailable} onClick={() => browse(directory?.path)}>{t("sshFiles.refresh")}</Button>
      <Button size="small" type="primary" icon={<MeshGlyph name="upload" />}
        disabled={unavailable || !directory} onClick={upload}>{t("sshFiles.upload")}</Button>
      <Button size="small" disabled={unavailable || !selectedNames.length} onClick={() => download(selectedNames)}>
        {selectedNames.length ? t("sshFiles.downloadSelectedCount", { count: selectedNames.length }) : t("sshFiles.downloadSelected")}
      </Button>
      <Button size="small" danger icon={<MeshGlyph name="trash" />} disabled={unavailable || !selectedNames.length}
        loading={busy === "delete"} onClick={deleteSelected}>{t("sshFiles.deleteSelected")}</Button>
    </div>
    {message && <div className="ssh-files-feedback ssh-files-failure" role="alert">{t(message)}</div>}
    <div className="ssh-files-list" ref={listViewport} aria-busy={busy === "list"}>
      {deletion && <div className={"ssh-files-feedback" + (deletion.failures.length ? " ssh-files-failure" : "")}
        role={deletion.failures.length ? "alert" : "status"}>
        <div>{t("sshFiles.deleteResult", { deleted: deletion.deleted, failed: deletion.failures.length })}</div>
        {!!deletion.remaining && <div>{t("sshFiles.deleteRemaining", { count: deletion.remaining })}</div>}
        {!!deletion.failures.length && <ul className="ssh-files-delete-errors">
          {deletion.failures.map(({ name, error }) => <li key={name}><bdi>{name}</bdi> · {t(sshFileErrorKey(error))}</li>)}
        </ul>}
      </div>}
      {busy === "list" && <div className="ssh-files-empty"><Spin size="small" /></div>}
      {!busy && directory && !entries.length && <div className="ssh-files-empty">{t("sshFiles.empty")}</div>}
      {busy !== "list" && !!entries.length && <ul>{entries.map(entry => <li key={entry.name} className="ssh-files-row">
        <span className="ssh-files-check">{entry.kind === "file" && <Checkbox aria-label={entry.name}
          checked={selected.has(entry.name)} disabled={unavailable}
          onChange={event => toggleFile(entry.name, event.target.checked)} />}</span>
        {entry.kind === "directory"
          ? <button type="button" className="ssh-files-name ssh-files-directory" disabled={unavailable}
              title={entry.name} onClick={() => browse(directory!.path.replace(/\/$/, "") + "/" + entry.name)}>
              <MeshGlyph name="folder" /><span>{entry.name}</span>
            </button>
          : <span className="ssh-files-name" title={entry.name}><MeshGlyph name={fileGlyph(entry.name)} /><span>{entry.name}</span></span>}
        {entry.kind === "file" && <>
          <span className="ssh-files-size">{entry.size === null ? "" : size(entry.size)}</span>
          <Button size="small" type="text" disabled={unavailable} onClick={() => download([entry.name])}>{t("sshFiles.download")}</Button>
        </>}
      </li>)}</ul>}
      {directory?.partial && <div className="ssh-files-empty">{t("sshFiles.partial")}</div>}
    </div>
    {showTransfer && <SshTransferPanel key={transfer.id} sessionId={sessionId} direction={transfer.direction} progress={progress}
      batch={transfer.batch} error={transfer.error} size={size} onClose={() => setTransfer(undefined)} />}
  </aside>;
}
