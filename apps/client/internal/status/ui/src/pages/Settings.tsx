// Settings.tsx — account info, service controls, config import/export.
//
// We can't directly install/uninstall the Windows Service from the
// browser (no command execution), so this page shows the recipes
// (with copy-able commands) plus the things we CAN do: log out
// (clear creds via bff-console), export current tunnel config,
// import a JSON config doc.
import {
  CopyOutlined,
  DownloadOutlined,
  ImportOutlined,
  LogoutOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Modal,
  Space,
  Typography,
  Upload,
  message,
} from "antd";
import type { UploadFile } from "antd";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { api } from "../api/client";
import { UpdatePanel, useUpdateInfo } from "../components/UpdateNotice";
import type { AccountMe, Healthz } from "../api/types";
import { useLogout } from "../hooks/use-logout";
import { useServiceMode } from "../hooks/use-service-mode";
import { useTranslation } from "react-i18next";

const { Title, Text, Paragraph } = Typography;

export default function Settings() {
  const { t } = useTranslation();
  const [importOpen, setImportOpen] = useState(false);
  const [importResult, setImportResult] = useState<any>(null);
  const [importFile, setImportFile] = useState<UploadFile | null>(null);

  // Same shared query the panel itself reads, so the card and its contents can
  // never disagree about whether there is anything to show.
  const { data: updateInfo } = useUpdateInfo();
  const hasUpdates = !!updateInfo;
  const { data: health } = useQuery<Healthz>({
    queryKey: ["healthz"],
    queryFn: api.healthz,
  });

  const logout = useLogout();
  // Signing out only exists for a daemon a person logged into. An agent runs on
  // the API key its service was installed with and the daemon refuses the call;
  // standalone has no account at all. Same rule as the account menu in Layout.
  const { agentMode } = useServiceMode();
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });
  const standalone = me?.plan?.code === "standalone";

  async function doExport() {
    try {
      const txt = await api.exportConfig();
      const blob = new Blob([txt], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `calabi-config-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      message.success(t("common.downloaded"));
    } catch (e: any) {
      message.error(e.message || t("settings.exportFailed"));
    }
  }

  async function doImport(dryRun: boolean) {
    if (!importFile) {
      message.warning(t("settings.pickJsonFirst"));
      return;
    }
    try {
      const text = await (importFile as any).originFileObj.text();
      const doc = JSON.parse(text);
      const r = await api.importConfig(doc, dryRun);
      setImportResult(r);
      // Report honestly: "ok" = actually-created (real) / would-create (dry-run);
      // skipped = already existed. When nothing was new, don't claim success.
      const items: any[] = r.items ?? [];
      const skipped = items.filter((it) => it.skipped).length;
      const ok = items.filter((it) => !it.skipped && !it.error).length;
      if (ok === 0 && skipped > 0) {
        message.info(t("settings.allSkipped", { n: skipped }));
      } else {
        message.success(
          dryRun
            ? t("settings.dryRunDone", { total: ok })
            : t("settings.importDone", { total: ok }),
        );
      }
    } catch (e: any) {
      message.error(e.message || t("settings.importFailed"));
    }
  }

  function copy(text: string) {
    navigator.clipboard
      .writeText(text)
      .then(() => message.success(t("common.copied")));
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Title level={4} style={{ margin: 0 }}>
        {t("nav.settings")}
      </Title>

      <Card title={t("settings.daemonCard")} size="small">
        <Space direction="vertical" size={4} style={{ width: "100%" }}>
          <div>
            <Text type="secondary">{t("settings.clientVersion")}</Text>{" "}
            <code>{health?.version || "—"}</code>
          </div>
          <div>
            <Text type="secondary">{t("settings.uptime")}</Text>{" "}
            <code>{health ? `${health.uptime_seconds}s` : "—"}</code>
          </div>
          <div>
            <Text type="secondary">{t("settings.lastStateChange")}</Text>{" "}
            <code>{health?.since || "—"}</code>
          </div>
          <Paragraph type="secondary" style={{ marginTop: 12, marginBottom: 4 }}>
            {t("settings.serviceHint")}
          </Paragraph>
          {[
            "calabi daemon install",
            "calabi daemon start",
            "calabi daemon status",
            "calabi daemon stop",
            "calabi daemon uninstall",
          ].map((cmd) => (
            <div key={cmd}>
              <code style={{ fontSize: 12 }}>{cmd}</code>{" "}
              <Button
                size="small"
                type="link"
                icon={<CopyOutlined />}
                onClick={() => copy(cmd)}
              />
            </div>
          ))}
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("settings.serviceNote")}
          </Text>
        </Space>
      </Card>

      {/* Its own card: the update settings are a policy with four controls, and
          buried under the daemon's version/uptime lines they read as more status.
          Renders nothing at all when this daemon has no update agent (a dev
          build, updates disabled, or a client older than /v1/update) — so the
          card only appears where it means something. */}
      {hasUpdates && (
        <Card title={t("update.status")} size="small">
          <UpdatePanel />
        </Card>
      )}

      <Card title={t("settings.configCard")} size="small">
        <Space direction="vertical" size={8} style={{ width: "100%" }}>
          <Text type="secondary">{t("settings.configHint")}</Text>
          <Space>
            <Button icon={<DownloadOutlined />} onClick={doExport}>
              {t("settings.exportBtn")}
            </Button>
            <Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)}>
              {t("settings.importBtn")}
            </Button>
          </Space>
        </Space>
      </Card>

      {agentMode ? (
        <Card title={t("settings.identityCard")} size="small">
          <Text type="secondary">{t("settings.agentIdentityHint")}</Text>
        </Card>
      ) : (
        !standalone && (
          <Card title={t("settings.logoutCard")} size="small">
            <Space direction="vertical" size={8} style={{ width: "100%" }}>
              <Text type="secondary">{t("settings.logoutHint")}</Text>
              <Button
                danger
                icon={<LogoutOutlined />}
                loading={logout.isPending}
                onClick={() => logout.mutate()}
              >
                {t("topbar.logout")}
              </Button>
            </Space>
          </Card>
        )
      )}

      <Modal
        title={t("settings.importModalTitle")}
        open={importOpen}
        onCancel={() => {
          setImportOpen(false);
          setImportResult(null);
          setImportFile(null);
        }}
        footer={null}
        width={620}
      >
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <Upload.Dragger
            accept=".json"
            maxCount={1}
            beforeUpload={(f) => {
              // f is an RcFile (a File): name/size/type are prototype getters,
              // so `{...f}` drops them and the list item shows only the paperclip
              // icon with no filename. Build the UploadFile explicitly so the
              // name renders next to the icon.
              setImportFile({
                uid: f.uid,
                name: f.name,
                size: f.size,
                type: f.type,
                status: "done",
                originFileObj: f as any,
              });
              return false; // don't auto-upload
            }}
            onRemove={() => setImportFile(null)}
            fileList={importFile ? [importFile] : []}
          >
            <p>
              <ImportOutlined style={{ fontSize: 28, color: "#5e7fff" }} />
            </p>
            <p>{t("settings.dragHint")}</p>
            <p style={{ color: "#999", fontSize: 12 }}>
              {t("settings.formatHint")}
            </p>
          </Upload.Dragger>

          <Space>
            <Button onClick={() => doImport(true)}>{t("settings.dryRunBtn")}</Button>
            <Button type="primary" onClick={() => doImport(false)}>
              {t("settings.execImportBtn")}
            </Button>
          </Space>

          {importResult && (
            <Alert
              type={importResult.dry_run ? "info" : "success"}
              message={
                <span>
                  {t("settings.resultMsg", {
                    action: importResult.dry_run
                      ? t("settings.dryRunWord")
                      : t("settings.importWord"),
                    total: importResult.total,
                  })}
                  {importResult.skipped > 0 && (
                    <span style={{ marginLeft: 8, color: "#8c8c8c" }}>
                      · {t("settings.skippedSummary", { n: importResult.skipped })}
                    </span>
                  )}
                </span>
              }
              description={
                <div style={{ maxHeight: 200, overflow: "auto" }}>
                  {importResult.items.map((it: any, i: number) => (
                    <div key={i} style={{ fontSize: 12 }}>
                      {it.skipped ? "⏭️" : it.error ? "❌" : "✅"}{" "}
                      {it.name || t("settings.noName")}{" "}
                      {it.skipped && (
                        <span style={{ color: "#8c8c8c" }}>
                          {t("settings.alreadyExists")}
                        </span>
                      )}
                      {it.error && <span style={{ color: "#ff4d4f" }}>{it.error}</span>}
                    </div>
                  ))}
                </div>
              }
            />
          )}
        </Space>
      </Modal>
    </Space>
  );
}
