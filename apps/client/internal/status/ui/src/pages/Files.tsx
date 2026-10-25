import { useEffect, useRef, useState } from "react";
import { Alert, Button, Drawer, Input, Modal, Progress, Segmented, Select, Space, Spin, Switch, Table, Tooltip, Typography, message } from "antd";
import MeshGlyph, { deviceGlyph, fileGlyph } from "../components/MeshGlyph";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { fileAction, fileWebRequest, hasBrowserFiles, useFileSupport, type FileSource } from "../api/files";
import { api } from "../api/client";
import { fileTargets } from "../lib/fileTargets";
import { fileRecords, fileRecordMatches, fileRequests, fileJobState, type FileFilter, type FileRecord } from "../lib/fileRecords";
import { fileErrorKey, fileJobErrorKey } from "../lib/fileErrors";
import "../styles/files.css";

const bytes = (n: number) => n >= 2 ** 30 ? `${(n / 2 ** 30).toFixed(2)} GiB` : n >= 2 ** 20 ? `${(n / 2 ** 20).toFixed(1)} MiB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${n} B`;
const percent = (offset: number, size: number) => size > 0 ? Math.min(100, Math.floor(offset * 100 / size)) : 100;

export default function Files() {
  const { t } = useTranslation();
  const errorText = (error: string) => t(`files.errors.${fileErrorKey(error)}`);
  const qc = useQueryClient();
  const support = useFileSupport();
  const [params] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const deviceKey = params.get("device") || "";
  const hint = location.state?.fileTarget as { key: string; name: string; ip: string } | undefined;
  const [peer, setPeer] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [composing, setComposing] = useState(!!deviceKey);
  const [settings, setSettings] = useState(false);
  const [filter, setFilter] = useState<FileFilter>("all");
  const [direction, setDirection] = useState("all");
  const [catalog, setCatalog] = useState<{directory: string; files: {name: string; size: number}[]} | null>(null);
  const [serverSelection, setServerSelection] = useState<string[]>([]);
  const [serverSave, setServerSave] = useState<{id: string; name: string} | null>(null);
  const center = useRef<HTMLDivElement>(null);
  const [compact, setCompact] = useState(false);
  useEffect(() => {
    const element = center.current;
    if (!element) return;
    const update = () => setCompact(element.clientWidth < 660);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const reviewRequest = params.get("review");
  useEffect(() => { if (reviewRequest === "1") { setFilter("waiting"); setDirection("incoming"); } }, [reviewRequest]);
  const pickBefore = useRef<Set<string> | null>(null);
  const mesh = useQuery({ queryKey: ["mesh"], queryFn: () => hasBrowserFiles() ? fileWebRequest<Awaited<ReturnType<typeof api.mesh>>>("mesh") : api.mesh(), enabled: support.data === true, refetchInterval: 3000, retry: false });
  const query = useQuery({ queryKey: ["user-files"], queryFn: () => fileAction({ action: "snapshot" }), enabled: support.data === true, refetchInterval: 1000, retry: false });
  const data = query.data;
  const mutation = useMutation({ mutationFn: (action: Record<string, unknown>) => fileAction(action), onSuccess: snapshot => qc.setQueryData(["user-files"], snapshot), onError: (err: Error) => message.error(errorText(err.message)) });
  const busy = mutation.isPending;
  const run = (action: string, args: Record<string, unknown> = {}) => mutation.mutate({ action, ...args });
  const state = (s: string) => t(`files.states.${s}`, { defaultValue: s });
  const remove = (action: string, id: string) => Modal.confirm({ title: t("files.remove"), content: t("files.removeConfirm"), onOk: () => mutation.mutateAsync({ action, id }).then(() => undefined) });
  const maintain = (operation: "renew" | "reset") => Modal.confirm({ title: t(`files.identity${operation === "renew" ? "Renew" : "Reset"}`), content: t("files.identityConfirm"), onOk: () => mutation.mutateAsync({ action: `identity_${operation}`, confirmed: true }).then(() => undefined) });
  const targets = fileTargets(mesh.data?.up ? mesh.data.peers || [] : [], data?.peers || []);
  const target = targets.find(p => p.key === (deviceKey || peer));
  const targetLabel = target || (hint?.key === deviceKey ? hint : undefined);
  const targetDevice = mesh.data?.peers?.find(p => p.public_key === (deviceKey || peer));
  const targetStatus = target?.status || "notReady";
  const requests = fileRequests(data?.received || []);
  const records = fileRecords(data || { jobs: [], received: [] });
  const directionRecords = records.filter(row => direction === "all" || row.direction === direction);
  const visible = directionRecords.filter(row => fileRecordMatches(row, filter));
  const directionBadge = (outgoing: boolean) => <span className={`files-direction ${outgoing ? "outgoing" : "incoming"}`}><MeshGlyph name={outgoing ? "upload" : "inbox"} />{t(outgoing ? "files.outgoing" : "files.incoming")}</span>;
  const selectedFiles = (data?.sources || []).filter(source => selected.includes(source.id));
  const selectedBytes = selectedFiles.reduce((sum, source) => sum + source.size, 0);
  const peerName = (ip: string, key?: string) => targets.find(target => key ? target.key === key : target.ip === ip)?.name || ip;

  useEffect(() => {
    if (location.pathname !== "/mesh/files") { setComposing(false); setSettings(false); }
    else if (deviceKey) setComposing(true);
  }, [deviceKey, location.key, location.pathname]);

  useEffect(() => {
    if (!data) return;
    setSelected(previous => previous.filter(id => data.sources.some(source => source.id === id)));
    if (pickBefore.current && !data.preparing) {
      const before = pickBefore.current;
      setSelected(previous => [...new Set([...previous, ...data.sources.filter(source => !before.has(source.id)).map(source => source.id)])]);
      pickBefore.current = null;
    }
  }, [data]);

  const closeComposer = () => {
    setComposing(false);
  };
  const chooseFiles = async () => {
    if (hasBrowserFiles()) {
      try { setCatalog(await fileWebRequest("catalog")); setServerSelection([]); } catch { message.error(t("files.web.directoryError")); }
      return;
    }
    pickBefore.current = new Set(data?.sources.map(source => source.id) || []);
    const snapshot = await mutation.mutateAsync({ action: "pick" }).catch(() => null);
    if (!snapshot) { pickBefore.current = null; return; }
    if (!snapshot.preparing && pickBefore.current) {
      const before = pickBefore.current;
      setSelected(previous => [...new Set([...previous, ...snapshot.sources.filter(source => !before.has(source.id)).map(source => source.id)])]);
      pickBefore.current = null;
    }
  };
  const send = async () => {
    if (!data?.available || !target || target.status !== "ready" || !selectedFiles.length || data.preparing) return;
    const sent = await mutation.mutateAsync({ action: "send", peer: target.ip, ids: selectedFiles.map(source => source.id) }).catch(() => null);
    if (sent) { setSelected([]); setDirection("outgoing"); setFilter("active"); closeComposer(); }
  };

  const task = (row: FileRecord) => {
    const outgoing = row.direction === "outgoing";
    const job = row.direction === "outgoing" ? row.job : undefined;
    const incoming = row.direction === "incoming" ? row.received : undefined;
    const transfer = job?.progress.transfer || incoming!.transfer;
    const taskError = fileJobErrorKey(job);
    const preparation = job?.state === "sending" ? job.progress.preparation : undefined;
    const status = job ? fileJobState(job) : transfer.state === "cancelled" && transfer.stop_reason ? transfer.stop_reason : transfer.state;
    const ip = job?.peer_ip || incoming!.ip;
    const label = peerName(ip, incoming?.device_key);
    const name = transfer.name || (job && data?.sources.find(source => source.id === job.sources?.[0])?.name) || t("files.unnamed");
    const count = job?.progress.count || transfer.batch_count || 1;
    const active = fileRecordMatches(row, "active");
    const rate = job ? status === "sending" ? job.rate_bps : 0 : status === "receiving" ? transfer.rate_bps : 0;
    const remaining = job?.remaining_seconds || transfer.remaining_seconds || 0;
    const progress = preparation?.phase === "hashing" ? percent(preparation.bytes, preparation.size) : percent(transfer.offset, transfer.size);
    const showProgress = !!preparation && preparation.phase === "hashing" || active && job?.state !== "cancelled" && status !== "connecting" && status !== "waiting";
    return { key: row.key, direction: directionBadge(outgoing), file: <div className="files-task-file">
      <span className="files-file-icon"><MeshGlyph name={fileGlyph(name)} /></span><div className="files-task-description">
        <Typography.Text className="files-task-name">{name}</Typography.Text>
        <div className="files-task-context">{directionBadge(outgoing)}<span className="files-task-peer">{t(outgoing ? "files.toPeer" : "files.fromPeer", { device: label })}</span>{label !== ip && <span className="files-peer-ip">{ip}</span>}</div>
        {count > 1 && <Typography.Text type="secondary" className="files-secondary">{job ? t("files.batchPosition", { index: Math.min(job.progress.index + 1, count), count }) : t("files.batchCount", { count })}</Typography.Text>}
      </div></div>, progress: <div className="files-task-progress">
        <div className="files-progress-meta"><Typography.Text type={taskError || status === "failed" ? "warning" : "secondary"}>{state(status)}</Typography.Text>{showProgress && <span>{progress}%</span>}</div>
        {showProgress && <Progress size="small" strokeWidth={4} showInfo={false} percent={progress} />}
        {preparation?.phase === "hashing" && <Typography.Text type="secondary" className="files-secondary">{t("files.hashProgress", { name: preparation.name, current: bytes(preparation.bytes), total: bytes(preparation.size), index: preparation.index + 1, count: preparation.count })}</Typography.Text>}
        <Typography.Text type="secondary" className="files-secondary">{job && preparation ? t("files.transferred") : ""} {bytes(transfer.offset || 0)} / {bytes(transfer.size || 0)}</Typography.Text>
        {(status === "sending" || status === "receiving") && <Typography.Text type="secondary" className="files-secondary">{rate ? t("files.rateEta", { rate: bytes(rate), seconds: remaining }) : t("files.measuringRate")}</Typography.Text>}
        {taskError && <Typography.Text type="danger" className="files-task-error">{t(`files.errors.${taskError}`)}</Typography.Text>}
        {job?.cancel_pending && job.stop_reason && <Typography.Text type="secondary" className="files-secondary">{state("cancelPending")}</Typography.Text>}
      </div>, actions: <Space size={4} wrap className="files-task-actions">
        {job ? <>
          {job.state === "sending" && <Tooltip title={t("files.pause")}><Button type="text" aria-label={t("files.pause")} icon={<MeshGlyph name="pause" />} disabled={busy} onClick={() => run("pause", { id: job.id })} /></Tooltip>}
          {job.state === "paused" && <Tooltip title={t(job.error ? "files.retry" : "files.resume")}><Button type="text" aria-label={t(job.error ? "files.retry" : "files.resume")} icon={<MeshGlyph name="play" />} disabled={busy} onClick={() => run("resume", { id: job.id, peer: job.peer_ip })} /></Tooltip>}
          {["paused", "sending"].includes(job.state) ? <Tooltip title={t("files.cancel")}><Button type="text" aria-label={t("files.cancel")} icon={<MeshGlyph name="close" />} disabled={busy} onClick={() => run("cancel", { id: job.id })} /></Tooltip> : <Tooltip title={t("files.remove")}><Button type="text" aria-label={t("files.remove")} icon={<MeshGlyph name="trash" />} disabled={busy} onClick={() => remove("forget_job", job.id)} /></Tooltip>}
        </> : <>
          {transfer.state === "completed" && <Button type="link" disabled={busy} onClick={() => hasBrowserFiles() ? setServerSave({id:transfer.id,name:transfer.name}) : run("save", { id: transfer.id })}>{t("files.save")}</Button>}
          {["accepted", "receiving", "waiting_sender"].includes(transfer.state) && <Tooltip title={t(transfer.pause_supported ? "files.pause" : "files.updateSender")}><Button type="text" aria-label={t("files.pause")} icon={<MeshGlyph name="pause" />} disabled={busy || !transfer.pause_supported} onClick={() => run("pause_receive", { id: transfer.id })} /></Tooltip>}
          {transfer.state === "paused" && <Tooltip title={t("files.resume")}><Button type="text" aria-label={t("files.resume")} icon={<MeshGlyph name="play" />} disabled={busy} onClick={() => run("resume_receive", { id: transfer.id })} /></Tooltip>}
          {["accepted", "receiving", "paused", "waiting_sender"].includes(transfer.state) && <Button type="text" aria-label={t("files.cancel")} icon={<MeshGlyph name="close" />} disabled={busy} onClick={() => run("cancel_receive", { id: transfer.id })} />}
          {["completed", "cancelled", "failed"].includes(transfer.state) && <Button type="text" aria-label={t("files.remove")} icon={<MeshGlyph name="trash" />} disabled={busy} onClick={() => remove("forget_receive", transfer.id)} />}
        </>}
      </Space> };
  };

  const waitingRows = requests.map(request => {
    const first = request.waiting[0];
    const total = request.waiting.reduce((sum, row) => sum + row.transfer.size, 0);
    return {
      key: `request/${request.key}`,
      file: <div className="files-task-file"><span className="files-file-icon"><MeshGlyph name="inbox" /></span><div className="files-task-description">
        {request.waiting.map(row => <Typography.Text key={row.transfer.id} className="files-task-name">{row.transfer.name}</Typography.Text>)}
        <div className="files-task-context">{directionBadge(false)}<span className="files-task-peer">{t("files.fromPeer", { device: peerName(first.ip, first.device_key) })}</span>{peerName(first.ip, first.device_key) !== first.ip && <span className="files-peer-ip">{first.ip}</span>}</div>
      </div></div>,
      progress: <div className="files-task-progress"><Typography.Text type="secondary">{state("waiting")}</Typography.Text><Typography.Text className="files-secondary">{t("files.batchCount", { count: request.waiting.length })} · {bytes(total)}</Typography.Text>{!request.complete && <span className="files-secondary">{t("files.waitingBatch")}</span>}</div>,
      actions: <Space wrap className="files-task-actions"><Button size="small" type="text" disabled={busy} onClick={() => run("decide", { ids: request.waiting.map(row => row.transfer.id), accept: false })}>{t("files.decline")}</Button><Button size="small" type="primary" disabled={busy || !request.complete} onClick={() => Modal.confirm({ title: t("files.accept"), content: <ul>{request.waiting.map(row => <li key={row.transfer.id}>{row.transfer.name} · {bytes(row.transfer.size)}</li>)}</ul>, onOk: () => mutation.mutateAsync({ action: "decide", ids: request.waiting.map(row => row.transfer.id), accept: true }).then(() => undefined) })}>{t("files.acceptShort")}</Button></Space>,
    };
  });
  const rows = [...(direction !== "outgoing" && (filter === "all" || filter === "waiting") ? waitingRows.map(row => ({ ...row, direction: directionBadge(false) })) : []), ...(filter === "waiting" ? [] : visible.map(task))];

  return <div ref={center} className={`files-center${compact ? " files-center-compact" : ""}`}>
    <Modal title={t("files.web.choose")} open={!!catalog} onCancel={() => setCatalog(null)} okText={t("files.choose")} confirmLoading={busy} okButtonProps={{ disabled: !serverSelection.length }} onOk={async () => { const previous=new Set(data?.sources.map(s=>s.id)||[]); const snapshot=await mutation.mutateAsync({action:"web_stage",names:serverSelection}).catch(()=>null); if(snapshot){setSelected(old=>[...new Set([...old,...snapshot.sources.filter(s=>!previous.has(s.id)).map(s=>s.id)])]);setCatalog(null);} }}>
      <Typography.Paragraph type="secondary">{catalog?.directory}</Typography.Paragraph>
      <Table size="small" rowKey="name" pagination={{pageSize:8}} dataSource={catalog?.files || []} rowSelection={{selectedRowKeys:serverSelection,onChange:keys=>setServerSelection(keys.map(String)),getCheckboxProps:row=>({disabled:serverSelection.length>=32&&!serverSelection.includes(row.name)})}} columns={[{title:t("files.name"),dataIndex:"name",render:(name:string)=><span style={{overflowWrap:"anywhere"}}>{name}</span>},{title:t("files.size"),dataIndex:"size",width:100,render:bytes}]} />
      <Typography.Text type="secondary">{t("files.web.directoryHint")}</Typography.Text>
    </Modal>
    <Modal title={t("files.web.save")} open={!!serverSave} onCancel={()=>setServerSave(null)} confirmLoading={busy} okButtonProps={{disabled:!serverSave?.name.trim()}} onOk={async()=>{if(serverSave && await mutation.mutateAsync({action:"web_save",id:serverSave.id,name:serverSave.name}).catch(()=>null)){setServerSave(null);message.success(t("files.web.saved"));}}}>
      <Typography.Paragraph>{t("files.web.saveHint")}</Typography.Paragraph>
      <Input aria-label={t("files.web.filename")} value={serverSave?.name||""} onChange={e=>setServerSave(old=>old?{...old,name:e.target.value}:null)} />
    </Modal>
    <div className="files-toolbar"><Segmented aria-label={t("files.direction")} value={direction} onChange={value => setDirection(String(value))} options={[{ value: "all", label: t("files.filters.all") }, { value: "incoming", label: t("files.incoming"), icon: <MeshGlyph name="inbox" /> }, { value: "outgoing", label: t("files.outgoing"), icon: <MeshGlyph name="upload" /> }]} /><Space wrap size="middle">
      <Space size={7}><Switch size="small" aria-label={t("files.receiving")} checked={data?.receiving || false} disabled={!data?.available || busy} loading={busy} onChange={enabled => run("receiving", { enabled })} /><Typography.Text type="secondary">{t("files.receivingShort")}</Typography.Text></Space>
      <Tooltip title={t("files.settings")}><Button type="text" icon={<MeshGlyph name="settings" />} aria-label={t("files.settings")} onClick={() => setSettings(true)} /></Tooltip>
      <Button type="primary" icon={<MeshGlyph name="plus" />} disabled={!data?.available} onClick={() => setComposing(true)}>{t("files.send")}</Button>
    </Space></div>
    {support.isPending && <Spin />}
    {support.data === false && <Alert type="info" message={t("files.unavailable")} />}
    {support.error && <Alert type="warning" message={t("files.bridgeUnavailable")} description={errorText(support.error.message)} action={<Button onClick={() => support.refetch()}>{t("files.retry")}</Button>} />}
    {query.isPending && support.data === true && <Spin />}
    {query.error && <Alert type="error" message={errorText(query.error.message)} action={<Button onClick={() => query.refetch()}>{t("files.retry")}</Button>} />}
    {data?.unavailable_reason && <Alert type="warning" message={errorText(data.unavailable_reason)} />}
    {mesh.error && <Alert type="warning" message={t("files.devicesError")} action={<Button onClick={() => mesh.refetch()}>{t("files.retry")}</Button>} />}
    {(data?.identity?.error || data?.identity?.needs_renewal) && <Alert type="warning" message={data.identity.error ? errorText(data.identity.error) : t("files.identityDue")} action={<Button onClick={() => setSettings(true)}>{t("files.settings")}</Button>} />}
    {data && <>
      <Segmented aria-label={t("files.filterLabel")} value={filter} onChange={value => setFilter(value as FileFilter)} options={(["all", "active", "waiting", "completed"] as FileFilter[]).map(value => ({ value, label: <span>{t(`files.filters.${value}`)} <span className="files-filter-count">{value === "waiting" ? (direction === "outgoing" ? 0 : requests.length) : directionRecords.filter(row => fileRecordMatches(row, value)).length + (value === "all" && direction !== "outgoing" ? requests.length : 0)}</span></span> }))} />
      <Table className="files-records" tableLayout="fixed" size="middle" rowKey="key" dataSource={rows} pagination={{ pageSize: 20, showSizeChanger: false }} locale={{ emptyText: filter === "waiting" ? t("files.emptyRequests") : t("files.emptyRecords") }} columns={[
        { title: t("files.fileAndDevice"), dataIndex: "file", key: "file", className: "files-record-file" },
        { title: t("files.transferProgress"), dataIndex: "progress", key: "progress", width: "35%", className: "files-record-progress" },
        { title: t("files.actions"), dataIndex: "actions", key: "actions", width: 160, className: "files-record-actions", align: "right" },
      ]} />
    </>}

    <Drawer rootClassName="files-send-drawer" title={t("files.send")} open={composing} onClose={closeComposer} afterOpenChange={open => { if (!open && deviceKey) navigate("/mesh/files", { replace: true, state: null }); }} width={440} closeIcon={<MeshGlyph name="close" />} footer={<><div className="files-compose-footer"><Typography.Text type="secondary">{t("files.selectionTotal", { count: selectedFiles.length, size: bytes(selectedBytes) })}</Typography.Text><Button type="primary" icon={<MeshGlyph name="send" />} loading={busy} disabled={!data?.available || data.preparing || !selectedFiles.length || targetStatus !== "ready"} onClick={send}>{t("files.sendCount", { count: selectedFiles.length })}</Button></div><Typography.Text className="files-fine">{t("files.confirmHint")}</Typography.Text></>}>
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        {!deviceKey && <div><Typography.Text className="files-field-label">{t("files.device")}</Typography.Text><Select aria-label={t("files.device")} style={{ width: "100%" }} value={peer || undefined} loading={mesh.isLoading} placeholder={t("files.device")} onChange={setPeer} notFoundContent={t("files.noDevices")} options={targets.map(p => ({ value: p.key, label: `${p.name || p.ip || p.key}${p.ip ? ` · ${p.ip}` : ""}${p.status === "ready" ? "" : ` · ${t(`files.targetStatus.${p.status}`)}`}` }))} /></div>}
        {(deviceKey || peer) && <div><Typography.Text className="files-field-label">{t("files.targetLabel")}</Typography.Text><div className="files-send-target"><span className="files-file-icon"><MeshGlyph name={deviceGlyph(targetDevice?.os)} /></span><div className="files-target-name"><Typography.Text strong>{targetLabel?.name || targetLabel?.ip || deviceKey || peer}</Typography.Text>{targetLabel?.ip && <Typography.Text className="files-secondary files-peer-ip">{targetLabel.ip}</Typography.Text>}</div><span className={`files-ready ${targetStatus === "ready" ? "" : "files-not-ready"}`}>{t(targetStatus === "ready" ? "files.peerReady" : `files.targetStatus.${targetStatus}`)}</span></div></div>}
        {(deviceKey || peer) && targetStatus !== "ready" && <Alert type="info" message={t(`files.targetStatus.${targetStatus}`)} description={t(targetStatus === "receivingOff" ? "files.enablePeerReception" : "files.preparePeer")} />}
        <div className="files-picker"><MeshGlyph name="upload" /><Typography.Text>{t("files.selectHint")}</Typography.Text><Button icon={<MeshGlyph name="plus" />} loading={busy || data?.preparing} disabled={!data?.available} onClick={chooseFiles}>{t("files.choose")}</Button><Typography.Text type="secondary">{t("files.maxBatch")}</Typography.Text></div>
        {data?.preparing && <Button onClick={() => run("cancel_preparing")}>{t("files.cancelPreparation")}</Button>}
        {data?.preparation_error && <Alert type="error" message={errorText(data.preparation_error)} />}
        {!!data?.sources.length && <Table<FileSource> className="files-source-table" tableLayout="fixed" size="middle" rowKey="id" pagination={false} dataSource={data.sources} rowSelection={{ columnWidth: 32, selectedRowKeys: selected, onChange: keys => setSelected(keys.map(String)) }} columns={[
          { title: t("files.name"), dataIndex: "name", render: (name, source) => <span className="files-source-file"><MeshGlyph name={fileGlyph(name)} /><span className="files-source-description"><span className="files-source-name">{name}</span><span className="files-source-size">{bytes(source.size)}</span></span></span> },
          { title: t("files.actions"), key: "actions", width: 48, align: "right", render: (_, source) => <Tooltip title={t("files.remove")}><Button type="text" aria-label={t("files.removeFile", { name: source.name })} icon={<MeshGlyph name="close" />} disabled={busy || data.preparing} onClick={() => remove("forget_source", source.id)} /></Tooltip> },
        ]} />}

      </Space>
    </Drawer>
    <Drawer title={t("files.settings")} open={settings} onClose={() => setSettings(false)} width={400}>
      <Typography.Paragraph type="secondary">{t("files.hint")}</Typography.Paragraph>
      <Typography.Title level={5}>{t("files.identity")}</Typography.Title>
      {data?.identity ? <Space direction="vertical" size="middle">
        {!!data.identity.expires_unix && <Typography.Text>{t("files.identityExpires", { date: new Date(data.identity.expires_unix * 1000).toLocaleString() })}</Typography.Text>}
        {data.identity.error && <Alert type="error" message={errorText(data.identity.error)} />}
        {data.identity.needs_renewal && !data.identity.error && <Alert type="warning" message={t("files.identityDue")} />}
        {!hasBrowserFiles() && <Space wrap><Button disabled={busy || !data.identity.fingerprint} onClick={() => maintain("renew")}>{t("files.identityRenew")}</Button><Button danger disabled={busy || !data.identity.exists} onClick={() => maintain("reset")}>{t("files.identityReset")}</Button></Space>}
      </Space> : <Typography.Text type="secondary">{t("files.identityUnavailable")}</Typography.Text>}
    </Drawer>
  </div>;
}
