// ConsoleLockGate.tsx — the outermost gate: a visitor from another machine sees
// the unlock form until they have entered the console's unlock secret.
//
// Why outermost, around the login route too: a locked daemon answers every other
// /v1 call with 401 console_locked, and AuthGate's usual answer to a 401 — the
// ACCOUNT login — would be the wrong door. Nobody should be signing the daemon
// into an account before proving they may drive it at all.
//
// Visitors on the daemon's own machine never see this: the daemon reports them
// as not locked. A daemon older than 1.9.0 has no /v1/console/state and no lock,
// so any error here renders the console exactly as before.
import { KeyOutlined, LoadingOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, Space, Spin, Typography } from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import Logo from "./Logo";

const { Title, Text, Paragraph } = Typography;

// Asked once, then again only when some other answer says the lock is back
// (main.tsx invalidates it on any 401 console_locked).
export const CONSOLE_STATE_KEY = ["consoleState"];

export default function ConsoleLockGate({ children }: { children: React.ReactNode }) {
  const { data, isLoading, error } = useQuery({
    queryKey: CONSOLE_STATE_KEY,
    queryFn: api.consoleState,
    retry: false,
    staleTime: Infinity,
  });

  if (isLoading) {
    return (
      <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <Spin indicator={<LoadingOutlined style={{ fontSize: 28 }} spin />} />
      </div>
    );
  }
  if (error || !data || !data.locked) {
    return <>{children}</>;
  }
  return <UnlockPage available={data.unlock_available} />;
}

function UnlockPage({ available }: { available: boolean }) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const unlock = useMutation({
    mutationFn: (v: { secret: string }) => api.consoleUnlock(v.secret),
    // Everything cached while locked is a 401. Start over: the gate re-asks,
    // finds itself unlocked, and the console mounts and fetches fresh.
    onSuccess: () => qc.resetQueries(),
  });

  let errMsg: string | null = null;
  if (unlock.error) {
    const e = unlock.error as ApiError;
    if (e.status === 429) {
      errMsg = t("consoleLock.throttled", { seconds: e.body?.retry_after_sec ?? 60 });
    } else if (e.status === 401) {
      errMsg = t("consoleLock.wrongSecret");
    } else {
      errMsg = t("consoleLock.failed");
    }
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        background:
          "radial-gradient(ellipse at top, rgba(58,92,255,0.18), transparent 60%), linear-gradient(135deg, #0b1022 0%, #05070f 100%)",
      }}
    >
      <Card
        style={{ width: 400, boxShadow: "0 4px 24px rgba(0, 0, 0, 0.08)", borderRadius: 12 }}
        bodyStyle={{ padding: 32 }}
      >
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <div style={{ textAlign: "center", marginBottom: 8 }}>
            <div style={{ margin: "0 auto 12px", lineHeight: 0 }}>
              <Logo size={48} />
            </div>
            <Title level={4} style={{ margin: 0 }}>
              {t("consoleLock.title")}
            </Title>
            <Text type="secondary" style={{ fontSize: 13 }}>
              {t("consoleLock.subtitle")}
            </Text>
          </div>

          {!available ? (
            <Alert type="warning" showIcon message={t("consoleLock.unavailable")} />
          ) : (
            <>
              {errMsg && <Alert type="error" showIcon message={errMsg} />}
              <Form layout="vertical" requiredMark={false} onFinish={(v) => unlock.mutate(v)}>
                <Form.Item
                  label={t("consoleLock.secret")}
                  name="secret"
                  rules={[{ required: true, message: t("consoleLock.secretRequired") }]}
                >
                  <Input.Password
                    prefix={<KeyOutlined style={{ color: "#94a3b8" }} />}
                    placeholder="xxxxxx-xxxxxx-xxxxxx-xxxxxx"
                    autoComplete="current-password"
                    autoFocus
                  />
                </Form.Item>
                <Form.Item style={{ marginBottom: 0 }}>
                  <Button type="primary" htmlType="submit" block loading={unlock.isPending} size="large">
                    {t("consoleLock.submit")}
                  </Button>
                </Form.Item>
              </Form>
              <Paragraph type="secondary" style={{ fontSize: 12, margin: 0 }}>
                {t("consoleLock.where")}
              </Paragraph>
            </>
          )}
        </Space>
      </Card>
    </div>
  );
}
