import { useEffect, useRef, useState } from "react";
import { Alert, Button, Drawer, Input, Modal, Space, Typography, Select, Tooltip, message } from "antd";
import { useLocation } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { FileWebContext, fileWebRequest } from "../api/files";
import { FileTransfers } from "./Files";
import { LANGS } from "../i18n/languages";

type Session = { id: string; label?: string; created?: string; last_active?: string; expires: string; current?: boolean };

function browserLabel(agent: string | undefined, fallback: string) {
  const text = agent || "";
  const browser = [/Edg(?:e|A|iOS)?\//, /(?:OPR|Opera)\//, /(?:Firefox|FxiOS)\//, /(?:Chrome|CriOS)\//, /Safari\//].findIndex(pattern => pattern.test(text));
  const name = ["Microsoft Edge", "Opera", "Firefox", "Chrome", "Safari"][browser] || fallback;
  const os = /Android/.test(text) ? "Android" : /iPhone|iPad|iPod/.test(text) ? "iOS" : /Windows/.test(text) ? "Windows" : /Macintosh|Mac OS/.test(text) ? "macOS" : /Linux/.test(text) ? "Linux" : "";
  return os ? `${name} · ${os}` : name;
}
function sessionTime(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
}

export default function FileBrowser({ embedded = false }: { embedded?: boolean }) {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const location = useLocation();
  const base = embedded ? "/file-service" : undefined;
  const [session, setSession] = useState<Session | null>(null);
  const [pair, setPair] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const availability = useQuery({ queryKey: ["file-service-available"], enabled: embedded, queryFn: async () => { try { const r = await fetch("/file-service/available", { credentials: "same-origin" }); return r.ok && (await r.json()).supported === true; } catch { return false; } }, retry: false, refetchInterval: 5000 });
  const unavailable = embedded && availability.data === false;
  const [sessions, setSessions] = useState<Session[]>([]);
  const [drawer, setDrawer] = useState(false);
  const attempted = useRef<string | null>(null);
  const connecting = useRef(false);
  const epoch = useRef(0);
  const request = <T,>(path: string, body?: unknown) => fileWebRequest<T>(path, body, base, session?.id);
  const clear = () => {
    epoch.current++; Modal.destroyAll();
    setSession(null); setSessions([]); setDrawer(false); setPair("");
    const prior = session?.id;
    const predicate = (q: { queryKey: readonly unknown[] }) => (String(q.queryKey[0]).startsWith("file-web-") && q.queryKey[1] === prior) || (q.queryKey[0] === "files-support" && q.queryKey[2] === prior);
    void qc.cancelQueries({ predicate }).then(() => qc.removeQueries({ predicate }));
  };
  const enter = async (value: string) => {
    if (connecting.current) return;
    connecting.current = true; setBusy(true); setError(false);
    const attempt = ++epoch.current;
    try {
      let secret = value.trim();
      if (!/^[a-f0-9]{64}$/.test(secret)) {
        try { secret = new URLSearchParams(new URL(secret).hash.split("?")[1] || "").get("pair") || ""; } catch { secret = ""; }
      }
      const result = await request<Session>("session", { pair: secret });
      if (attempt === epoch.current) { setPair(""); setSession(result); }
    } catch { setError(true); } finally { connecting.current = false; setBusy(false); }
  };
  useEffect(() => {
    const expired = (event: Event) => {
      const detail = (event as CustomEvent<{ base: string; scope?: string }>).detail;
      const own = base ?? (window as Window & { __CALABI_FILE_WEB_BASE__?: string }).__CALABI_FILE_WEB_BASE__ ?? "";
      if (detail.base === own && detail.scope === session?.id) clear();
    };
    window.addEventListener("calabi-file-auth-expired", expired);
    return () => window.removeEventListener("calabi-file-auth-expired", expired);
  }, [base, session?.id]);
  useEffect(() => {
    const link = location.pathname + location.search;
    if (attempted.current === link) return;
    attempted.current = link;
    const params = new URLSearchParams(window.location.hash.split("?")[1] || "");
    const secret = params.get("pair");
    const legacy = params.has("key");
    params.delete("pair"); params.delete("key");
    const route = window.location.hash.split("?")[0] || "#/mesh/files";
    window.history.replaceState(null, "", `${window.location.pathname}${route}${params.size ? `?${params}` : ""}`);
    if (secret) { void enter(secret); }
    else { const attempt = epoch.current; void request<Session>("ping").then(value => { if (attempt === epoch.current) setSession(value); }).catch(() => { if (legacy) setError(true); }); }
  }, [location.pathname, location.search]);
  const loadSessions = async () => { const attempt = epoch.current; try { const values = await request<Session[]>("sessions"); if (attempt === epoch.current) { setSessions([...values].sort((a, b) => Number(!!b.current) - Number(!!a.current) || (b.created || "").localeCompare(a.created || "") || a.id.localeCompare(b.id))); setDrawer(true); } } catch { message.error(t("files.web.loginError")); } };
  const revoke = (item?: Session) => Modal.confirm({
    title: t(item ? "files.web.revokeSession" : "files.web.revokeAll"),
    content: t(item ? "files.web.removeConfirm" : "files.web.removeAllConfirm"),
    onOk: async () => {
      await request("sessions/revoke", item ? { id: item.id } : { all: true });
      if (!item || item.current) clear(); else await loadSessions();
    },
  });
  return <main style={embedded ? { width: "100%" } : { maxWidth: 1200, margin: "0 auto", padding: 24 }}>
    <Space style={{ width: "100%", justifyContent: "space-between", marginBottom: 16 }}>
      {!embedded && <Typography.Title level={3}>{t("files.web.title")}</Typography.Title>}
      <Space wrap>
        {!embedded && <Select aria-label="Language" value={i18n.language} options={LANGS.map(l => ({ value: l.code, label: l.label }))} onChange={value => { void i18n.changeLanguage(value); }} />}
        {session && <><Button onClick={() => { void loadSessions(); }}>{t("files.web.sessions")}</Button><Tooltip title={t("files.web.logoutHint")}><Button onClick={async () => { try { await request("logout", {}); clear(); } catch { message.error(t("files.web.loginError")); } }}>{t("files.web.logout")}</Button></Tooltip></>}
      </Space>
    </Space>
    {session ? <FileWebContext.Provider value={{ base: base ?? (window as Window & { __CALABI_FILE_WEB_BASE__?: string }).__CALABI_FILE_WEB_BASE__ ?? "", session: session.id }}><FileTransfers /></FileWebContext.Provider> : <Space direction="vertical" size={16} style={{ maxWidth: 560, width: "100%" }}>
      <Typography.Title level={5} style={{ margin: 0 }}>{t("files.web.pairTitle")}</Typography.Title>
      <Typography.Text>{t("files.web.loginHint")}</Typography.Text>
      <Typography.Text type="secondary">{t("files.service.keyHint")}</Typography.Text>
      <Typography.Text code copyable>calabi mesh files service web-url</Typography.Text>
      {unavailable && <Alert type="warning" message={t("files.service.unavailable")} />}
      {error && <Alert type="error" message={t("files.web.loginError")} />}
      <Input.Password aria-label={t("files.web.key")} placeholder={t("files.web.key")} autoComplete="off" value={pair} onChange={e => setPair(e.target.value)} onPressEnter={() => { void enter(pair); }} />
      <Button type="primary" loading={busy} disabled={!pair || unavailable} onClick={() => { void enter(pair); }}>{t("files.web.enter")}</Button>
    </Space>}
    <Drawer title={t("files.web.sessions")} open={drawer} onClose={() => setDrawer(false)}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Typography.Paragraph>{t("files.web.sessionsHint")}</Typography.Paragraph>
        <Typography.Text type="secondary">{t("files.web.accessLifetime")}</Typography.Text>
        {sessions.map(item => <Space direction="vertical" key={item.id} style={{ marginBottom: 16, width: "100%" }}>
          <Typography.Text strong>{browserLabel(item.label, t("files.web.unknownBrowser"))}{item.current ? ` · ${t("files.web.currentSession")}` : ""}</Typography.Text>
          <Typography.Text type="secondary">{t("files.web.authorizedAt")}: {sessionTime(item.created)}</Typography.Text>
          <Typography.Text type="secondary">{t("files.web.lastActive")}: {sessionTime(item.last_active)}</Typography.Text>
          {!item.current && <Button danger onClick={() => revoke(item)}>{t("files.web.revokeSession")}</Button>}
        </Space>)}
        <Button danger onClick={() => revoke()}>{t("files.web.revokeAll")}</Button>
      </Space>
    </Drawer>
  </main>;
}
