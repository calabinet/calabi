import { useEffect, useState } from "react";
import { Alert, Button, Input, Space, Typography, Select, message } from "antd";
import { useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { fileWebRequest } from "../api/files";
import Files from "./Files";
import { LANGS } from "../i18n/languages";

export default function FileBrowser() {
  const { t, i18n } = useTranslation();
  const qc = useQueryClient();
  const [ready, setReady] = useState(false);
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const enter = async (secret: string) => {
    setBusy(true); setError(false);
    try {
      if (!/^[a-f0-9]{64}$/.test(secret.trim())) {
        try { secret = new URLSearchParams(new URL(secret.trim()).hash.split("?")[1] || "").get("key") || secret; } catch { /* treat as an access key */ }
      }
      await fileWebRequest("session", { key: secret });
      setKey(""); setReady(true);
    } catch { setError(true); } finally { setBusy(false); }
  };
  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.split("?")[1] || "");
    const secret = params.get("key");
    if (secret) {
      window.history.replaceState(null, "", `${window.location.pathname}#/mesh/files`);
      void enter(secret);
    } else { void fileWebRequest("ping").then(() => setReady(true)).catch(() => {}); }
  }, []);
  return <main style={{ maxWidth: 1200, margin: "0 auto", padding: 24, height: "100%", overflowY: "auto" }}>
    <Space style={{ width: "100%", justifyContent: "space-between", marginBottom: 24 }}>
      <Typography.Title level={3} style={{ margin: 0 }}>{t("files.web.title")}</Typography.Title>
      <Space><Select aria-label="Language" value={i18n.language} options={LANGS.map(l => ({value:l.code,label:l.label}))} onChange={value => { void i18n.changeLanguage(value); }} />{ready && <Button onClick={async () => { try { await fileWebRequest("logout", {}); qc.clear(); setReady(false); } catch { message.error(t("files.web.loginError")); } }}>{t("files.web.logout")}</Button>}</Space>
    </Space>
    {ready ? <Files /> : <Space direction="vertical" size={16} style={{ maxWidth: 460, width: "100%" }}>
      <Typography.Text type="secondary">{t("files.web.loginHint")}</Typography.Text>
      <Typography.Text type="secondary">{t("files.service.keyHint")}</Typography.Text>
      {error && <Alert type="error" message={t("files.web.loginError")} />}
      <Input.Password aria-label={t("files.web.key")} placeholder={t("files.web.key")} autoComplete="off" value={key} onChange={e => setKey(e.target.value)} onPressEnter={() => { void enter(key); }} />
      <Button type="primary" loading={busy} disabled={!key} onClick={() => { void enter(key); }}>{t("files.web.enter")}</Button>
    </Space>}
  </main>;
}
