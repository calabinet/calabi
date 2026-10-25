import { useEffect, useRef, useState } from "react";
import { Alert, Button, Empty, Spin } from "antd";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import MeshGlyph from "../components/MeshGlyph";
import { fileErrorKey } from "../lib/fileErrors";
import "../styles/file-receipt.css";

type Request = { stamp: string; peer: string; names: string[]; bytes: number };
type Bridge = Window & { __TAURI_INTERNALS__?: { invoke<T>(command: string, args: unknown): Promise<T> } };
async function receipt<T>(action: string, args = {}): Promise<T> {
  const native = (window as Bridge).__TAURI_INTERNALS__;
  if (!native) throw new Error("Open this window from Calabi Desktop");
  try { return await native.invoke<T>("file_receipt_action", { action, ...args }); }
  catch (error) { throw new Error(String(error instanceof Error ? error.message : error)); }
}
const bytes = (n: number) => n >= 2 ** 30 ? `${(n / 2 ** 30).toFixed(2)} GiB` : n >= 2 ** 20 ? `${(n / 2 ** 20).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`;

// Only the native receipt command is used here. This route has no console API
// or account credentials and is useful only in the dedicated native window.
export default function FileReceipt() {
  const { i18n, t } = useTranslation();
  const zh = i18n.language.startsWith("zh");
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const query = useQuery({ queryKey: ["file-receipts"], queryFn: () => receipt<{ requests: Request[] }>("snapshot"), refetchInterval: 1000, retry: false });
  const panel = useRef<HTMLElement>(null);
  const header = useRef<HTMLElement>(null);
  const content = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (query.isPending || !header.current || !content.current) return;
    let lastHeight = 0;
    const resize = () => {
      // Measure natural content, not the flex list's viewport, so clamping the
      // native window does not cause a resize feedback loop for long batches.
      const padding = getComputedStyle(panel.current!);
      const height = Math.ceil(header.current!.getBoundingClientRect().height + content.current!.getBoundingClientRect().height + parseFloat(padding.paddingTop) + parseFloat(padding.paddingBottom)) + 2;
      if (height === lastHeight) return;
      lastHeight = height;
      void receipt("resize", { height, viewportHeight: window.innerHeight }).catch(() => { /* Older shells keep their fixed size. */ });
    };
    const observer = new ResizeObserver(resize);
    observer.observe(header.current);
    observer.observe(content.current);
    resize();
    return () => observer.disconnect();
  }, [query.isPending]);
  const decide = async (request: Request, accept: boolean) => {
    setBusy(true); setError("");
    try {
      await receipt("decide", { stamp: request.stamp, accept });
      // Remove immediately; an older poll response must not re-enable buttons.
      await qc.cancelQueries({ queryKey: ["file-receipts"] });
      qc.setQueryData<{ requests: Request[] }>(["file-receipts"], data => ({ requests: (data?.requests || []).filter(r => r.stamp !== request.stamp) }));
      await query.refetch();
    } catch (e) { setError((e as Error).message); await query.refetch(); }
    finally { setBusy(false); }
  };
  return <main ref={panel} className="file-receipt">
    <header ref={header}><span className="file-receipt-mark"><MeshGlyph name="inbox" /></span><div><strong>{zh ? "收到文件" : "Incoming files"}</strong><small>Calabi · {zh ? "文件传送" : "File transfers"}</small></div></header>
    <section className="file-receipt-list" aria-live="polite">
      <div ref={content}>
      {(error || query.error) && <Alert type="error" showIcon message={t(`files.errors.${fileErrorKey(error || query.error?.message || "")}`)} />}
      {query.isPending && <Spin />}
      {!query.isPending && !query.error && !query.data?.requests.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={zh ? "没有待确认的文件" : "No pending files"} />}
      {!query.error && query.data?.requests.map(request => <article key={request.stamp}>
        <div className="file-receipt-request-heading">
          <div className="file-receipt-sender"><div className="file-receipt-peer" title={request.peer}>{request.peer}</div>
          <div className="file-receipt-meta">{request.names.length} {zh ? "个文件" : "file(s)"} · {bytes(request.bytes)}</div></div>
        <div className="file-receipt-actions">
          <Button disabled={busy} onClick={() => void decide(request, false)}>{zh ? "拒绝" : "Reject"}</Button>
          <Button type="primary" disabled={busy} onClick={() => void decide(request, true)}>{zh ? "接收" : "Accept"}</Button>
        </div>
        </div>
        <ul>{request.names.map((name, index) => <li key={index} title={name}>{name}</li>)}</ul>
      </article>)}
      </div>
    </section>
  </main>;
}
