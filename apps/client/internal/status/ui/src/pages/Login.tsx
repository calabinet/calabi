// Login.tsx — in-window login form. M7.1 replaces the "open a terminal
// and run calabi login" instruction with a proper email/password +
// optional TOTP form.
//
// Flow:
//   1. User types email + password (+ TOTP if their account requires it)
//   2. POST /v1/auth/login → daemon proxies to bff-console + persists
//      access/refresh tokens to creds file
//   3. After 200, invalidate /v1/me + nav to /overview. The daemon's
//      reconnect loop (15s ticks) picks up the new creds and brings
//      the edge session up within ~15s.
//
// We don't ship registration / password-reset in M7.1 — those are TODO.
// Users who don't have an account today need to register via the web
// console first (https://calabi.example.com/register).
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, Space, Typography } from "antd";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import Logo from "../components/Logo";
import { useTranslation } from "react-i18next";

const { Title, Text, Paragraph } = Typography;

interface LoginForm {
  email: string;
  password: string;
  totp_code?: string;
}

export default function Login() {
  const { t } = useTranslation();
  const [form] = Form.useForm<LoginForm>();
  const [needsTotp, setNeedsTotp] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();

  const login = useMutation({
    mutationFn: (body: LoginForm) => api.login(body),
    onSuccess: async () => {
      // Why refetchQueries here, not invalidateQueries:
      //
      // The app's first render fired AuthGate's useQuery(["me"]) BEFORE
      // any token existed. That query settled into the error state
      // (401). With `retry: false` (see AuthGate) React Query keeps
      // that error in cache.
      //
      // If we only invalidateQueries() and navigate, AuthGate re-mounts
      // at /overview and reads the CACHED 401 error before the silent
      // background refetch finishes — so AuthGate bounces back to
      // /login. The refetch then completes and writes good data to the
      // cache, which is why the SECOND login click works: AuthGate now
      // reads the cached success and stays on /overview.
      //
      // refetchQueries actively re-runs the query and waits for it to
      // settle. By the time navigate fires, the cache holds the
      // post-login /me payload (or a fresh error). AuthGate sees the
      // final state on its first render — no bounce.
      await qc.refetchQueries({ queryKey: ["me"] });
      // Other authed queries can be invalidated lazily — they only
      // mount once we're on /overview, and a stale cached error on
      // them is non-fatal (the pages show their own loading state).
      await qc.invalidateQueries();
      navigate("/overview", { replace: true });
    },
    onError: (e: any) => {
      const msg = (e as ApiError)?.message || t("login.failed");
      if (msg.toLowerCase().includes("totp")) {
        setNeedsTotp(true);
      }
    },
  });

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
        style={{
          width: 380,
          boxShadow: "0 4px 24px rgba(0, 0, 0, 0.08)",
          borderRadius: 12,
        }}
        bodyStyle={{ padding: 32 }}
      >
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <div style={{ textAlign: "center", marginBottom: 8 }}>
            <div style={{ margin: "0 auto 12px", lineHeight: 0 }}>
              <Logo size={48} />
            </div>
            <Title level={4} style={{ margin: 0 }}>
              {t("login.title")}
            </Title>
            <Text type="secondary" style={{ fontSize: 13 }}>
              {t("login.subtitle")}
            </Text>
          </div>

          {login.error && (
            <Alert
              type="error"
              showIcon
              message={(login.error as Error).message || t("login.failed")}
            />
          )}

          <Form
            form={form}
            layout="vertical"
            onFinish={(v) => login.mutate(v)}
            requiredMark={false}
          >
            <Form.Item
              label={t("login.email")}
              name="email"
              rules={[{ required: true, message: t("login.emailRequired") }]}
            >
              <Input
                prefix={<UserOutlined style={{ color: "#94a3b8" }} />}
                placeholder="me@example.com"
                autoComplete="email"
                autoFocus
              />
            </Form.Item>

            <Form.Item
              label={t("login.password")}
              name="password"
              rules={[{ required: true, message: t("login.passwordRequired") }]}
            >
              <Input.Password
                prefix={<LockOutlined style={{ color: "#94a3b8" }} />}
                placeholder="••••••••"
                autoComplete="current-password"
              />
            </Form.Item>

            {needsTotp && (
              <Form.Item
                label={t("login.totp")}
                name="totp_code"
                rules={[{ required: true, message: t("login.totpRequired") }]}
              >
                <Input
                  placeholder="123456"
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                />
              </Form.Item>
            )}

            <Form.Item style={{ marginBottom: 0 }}>
              <Button
                type="primary"
                htmlType="submit"
                block
                loading={login.isPending}
                size="large"
              >
                {t("login.submit")}
              </Button>
            </Form.Item>
          </Form>

          <Paragraph
            type="secondary"
            style={{ fontSize: 12, margin: 0, textAlign: "center" }}
          >
            {t("login.registerPre")}
            <a
              href="https://calabi.example.com/register"
              target="_blank"
              rel="noopener noreferrer"
            >
              {t("login.consoleLink")}
            </a>
            {t("login.registerPost")}
          </Paragraph>
        </Space>
      </Card>
    </div>
  );
}
