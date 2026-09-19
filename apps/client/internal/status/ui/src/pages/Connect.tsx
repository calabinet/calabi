// Connect.tsx — join this computer to a self-hosted server instead of
// calabi.net (docs/runbook/self-hosted-sign-in-plan.md §6.2), from the sign-in
// page's secondary entry, or from a self-hosted console to change servers.
//
// One thing to give: an invite link from `calabi-coord invite`, or the
// coordinator's address and a key. Joining the coordinator is the sign-in — it
// then names the edge for tunnels and signs this computer's way in
// (docs/runbook/self-hosted-server-plan.md). The daemon joins before saving
// anything; a certificate this computer does not already trust comes back with
// its fingerprint for a person to compare with what the server prints. Then the
// daemon starts again as the local one on the same address, and the page
// follows it.
import { ArrowLeftOutlined, LinkOutlined, LoadingOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Collapse,
  Descriptions,
  Form,
  Input,
  Modal,
  Space,
  Spin,
  Typography,
} from "antd";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { SelfHostedJoin, SelfHostedStatus } from "../api/types";
import Logo from "../components/Logo";
import { Fingerprint, waitForModeThenGo } from "../components/SelfHosted";

const { Title, Text, Paragraph } = Typography;

interface ConnectForm {
  meshServer?: string;
  meshKey?: string;
  meshPin?: string;
  meshPlaintext?: boolean;
}

// The coordinator's certificate, waiting for a person to compare it.
interface Unconfirmed {
  pin: string;
  subject?: string;
  issuer?: string;
  not_after?: string;
}

const isLink = (s?: string) => (s ?? "").trim().toLowerCase().startsWith("calabi://");

export default function Connect() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [form] = Form.useForm<ConnectForm>();
  const meshServer = Form.useWatch("meshServer", form);
  const meshPlaintext = Form.useWatch("meshPlaintext", form);
  const [busy, setBusy] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unconfirmed, setUnconfirmed] = useState<Unconfirmed | null>(null);
  // The fingerprint a person confirmed on this page.
  const [confirmed, setConfirmed] = useState<string | undefined>();

  const { data: st, isLoading } = useQuery<SelfHostedStatus>({
    queryKey: ["selfhosted"],
    queryFn: api.selfHosted,
    retry: false,
  });
  const selfHosted = st?.mode === "self_hosted";
  const blocked =
    st?.mode === "platform" && st.can_join === false
      ? st.reason === "agent"
        ? t("selfHosted.cannotJoinAgent")
        : t("selfHosted.cannotJoinForced")
      : selfHosted && st?.managed === false
        ? t("selfHosted.notManaged", { path: st.config_path })
        : null;

  function body(v: ConnectForm, pin: string | undefined, replace: boolean): SelfHostedJoin | null {
    const ms = (v.meshServer ?? "").trim();
    if (!ms) return null;
    // A pin a person confirmed goes with a link too: an invite that carries no
    // fingerprint takes it.
    const out: SelfHostedJoin = {
      mesh: isLink(ms)
        ? { link: ms, pin }
        : {
            server: ms,
            key: (v.meshKey ?? "").trim(),
            pin: pin || (v.meshPin ?? "").trim() || undefined,
            plaintext: !!v.meshPlaintext,
          },
    };
    if (replace) out.replace = true;
    return out;
  }

  function errorText(code: string | undefined, detail: string): string {
    const known = ["bad_link", "bad_input", "key_refused", "pin_mismatch", "no_tls", "disabled", "full"];
    if (code && known.includes(code)) return t(`selfHosted.err.${code}`);
    if (code === "unreachable") return t("selfHosted.err.unreachable", { detail });
    return t("selfHosted.err.generic", { detail });
  }

  async function submit(pin = confirmed, replace = false) {
    setError(null);
    const req = body(form.getFieldsValue(), pin, replace);
    if (!req) {
      setError(t("selfHosted.needOne"));
      return;
    }
    setBusy(true);
    try {
      await api.joinSelfHosted(req);
      setSwitching(true);
      void waitForModeThenGo("self_hosted", "/overview");
    } catch (e) {
      const b = (e as ApiError).body ?? {};
      switch (b.code) {
        case "untrusted":
          setUnconfirmed({ pin: b.pin, subject: b.subject, issuer: b.issuer, not_after: b.not_after });
          break;
        case "signed_in":
          Modal.confirm({
            title: t("selfHosted.signedInTitle"),
            content: t("selfHosted.signedInBody", { email: b.email || "calabi.net" }),
            okText: t("selfHosted.signedInOk"),
            onOk: async () => {
              await api.logout();
              await submit(pin, replace);
            },
          });
          break;
        case "joined":
          Modal.confirm({
            title: t("selfHosted.joinedTitle"),
            content: t("selfHosted.joinedBody", { server: b.server }),
            okText: t("selfHosted.joinedOk"),
            onOk: () => submit(pin, true),
          });
          break;
        default:
          setError(errorText(b.code, (e as Error).message));
      }
    } finally {
      setBusy(false);
    }
  }

  if (switching) {
    return (
      <Centered>
        <Space direction="vertical" align="center" size="middle">
          <Spin indicator={<LoadingOutlined style={{ fontSize: 28 }} spin />} />
          <Text>{t("selfHosted.switching")}</Text>
        </Space>
      </Centered>
    );
  }

  return (
    <Centered>
      <Card style={{ width: 520, borderRadius: 12 }} styles={{ body: { padding: 28 } }}>
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ margin: "0 auto 12px", lineHeight: 0 }}>
              <Logo size={40} />
            </div>
            <Title level={4} style={{ margin: 0 }}>
              {t("selfHosted.title")}
            </Title>
            <Text type="secondary" style={{ fontSize: 13 }}>
              {t("selfHosted.subtitle")}
            </Text>
          </div>

          {blocked && <Alert type="warning" showIcon message={blocked} />}
          {error && <Alert type="error" showIcon message={error} />}

          <Form form={form} layout="vertical" requiredMark={false} disabled={!!blocked || isLoading} onFinish={() => submit()}>
            {selfHosted && st?.mesh && (
              <Paragraph type="secondary" style={{ fontSize: 12 }}>
                {t("selfHosted.current", { server: st.mesh.server })}
              </Paragraph>
            )}
            <Form.Item name="meshServer" label={t("selfHosted.meshServer")} extra={t("selfHosted.meshHint")}>
              <Input prefix={<LinkOutlined style={{ color: "#94a3b8" }} />} placeholder={t("selfHosted.meshServerPlaceholder")} autoFocus />
            </Form.Item>
            {!isLink(meshServer) && (meshServer ?? "").trim() !== "" && (
              <>
                <Form.Item name="meshKey" label={t("selfHosted.meshKey")} rules={[{ required: true, message: t("selfHosted.meshKeyRequired") }]}>
                  <Input.Password autoComplete="off" />
                </Form.Item>
                <Collapse
                  size="small"
                  ghost
                  items={[
                    {
                      key: "adv",
                      label: t("selfHosted.advanced"),
                      children: (
                        <>
                          <Form.Item name="meshPin" label={t("selfHosted.fingerprint")} extra={t("selfHosted.fingerprintHint")}>
                            <Input placeholder="sha256:…" disabled={!!meshPlaintext} />
                          </Form.Item>
                          <Form.Item name="meshPlaintext" valuePropName="checked" style={{ marginBottom: 0 }}>
                            <Checkbox>{t("selfHosted.plaintext")}</Checkbox>
                          </Form.Item>
                          {meshPlaintext && <Alert type="warning" showIcon message={t("selfHosted.plaintextWarn")} />}
                        </>
                      ),
                    },
                  ]}
                />
              </>
            )}

            <Form.Item style={{ marginBottom: 0, marginTop: 16 }}>
              <Button type="primary" htmlType="submit" block size="large" loading={busy}>
                {t("selfHosted.submit")}
              </Button>
            </Form.Item>
          </Form>

          <div style={{ textAlign: "center" }}>
            <Button type="link" icon={<ArrowLeftOutlined />} onClick={() => navigate(selfHosted ? "/settings" : "/login")}>
              {t("selfHosted.back")}
            </Button>
          </div>
        </Space>
      </Card>

      <Modal
        open={!!unconfirmed}
        title={t("selfHosted.confirmTitle")}
        okText={t("selfHosted.confirmOk")}
        onCancel={() => setUnconfirmed(null)}
        onOk={() => {
          if (!unconfirmed) return;
          setConfirmed(unconfirmed.pin);
          setUnconfirmed(null);
          void submit(unconfirmed.pin);
        }}
      >
        {unconfirmed && (
          <Space direction="vertical" size={8} style={{ width: "100%" }}>
            <Text>{t("selfHosted.confirmBody")}</Text>
            <Fingerprint pin={unconfirmed.pin} />
            <Text type="secondary" style={{ fontSize: 12 }}>
              {t("selfHosted.confirmCmdMesh")}
            </Text>
            {(unconfirmed.subject || unconfirmed.not_after) && (
              <Descriptions size="small" column={1}>
                {unconfirmed.subject && <Descriptions.Item label={t("selfHosted.certSubject")}>{unconfirmed.subject}</Descriptions.Item>}
                {unconfirmed.not_after && <Descriptions.Item label={t("selfHosted.certExpires")}>{unconfirmed.not_after.slice(0, 10)}</Descriptions.Item>}
              </Descriptions>
            )}
          </Space>
        )}
      </Modal>
    </Centered>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 16,
        background:
          "radial-gradient(ellipse at top, rgba(58,92,255,0.18), transparent 60%), linear-gradient(135deg, #0b1022 0%, #05070f 100%)",
      }}
    >
      {children}
    </div>
  );
}
