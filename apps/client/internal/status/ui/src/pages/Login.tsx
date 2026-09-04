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
// We don't ship registration / password-reset here — those live in the web
// console. The link below is built from the console origin the daemon reports
// (/v1/service-mode → console_web), NOT a hardcoded host, so self-hosted
// deployments point at their own console.
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, Space, Typography } from "antd";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";
import Logo from "../components/Logo";
import { useServiceMode } from "../hooks/use-service-mode";
import { useTranslation } from "react-i18next";

const { Title, Text, Paragraph } = Typography;

interface LoginForm {
  email: string;
  password: string;
  totp_code?: string;
}

// classifyLoginError maps a raw login failure — usually a passed-through gRPC
// status string like "rpc error: code = Unauthenticated desc = totp required"
// (the daemon forwards bff-console's error body verbatim) — to friendly,
// translated copy plus the right severity.
//
// "totp required" is NOT a failure: it's the server asking for the second
// factor on a first attempt that omitted it. Showing the raw string in a red
// alert reads like something went wrong, so we surface it as a calm info
// banner instead. Genuine failures (wrong code, wrong password) stay red.
// Anything unrecognised gets the gRPC "…desc = " envelope stripped as a last
// resort so we never dump the raw wire error on the user.
function classifyLoginError(
  raw: string,
  t: (key: string) => string,
): { severity: "info" | "error"; message: string } {
  const m = raw.toLowerCase();
  if (m.includes("totp required")) {
    return { severity: "info", message: t("login.totpPrompt") };
  }
  if (m.includes("invalid totp")) {
    return { severity: "error", message: t("login.totpInvalid") };
  }
  if (m.includes("invalid credentials")) {
    return { severity: "error", message: t("login.badCredentials") };
  }
  const desc = raw.replace(/^rpc error:.*desc\s*=\s*/i, "").trim();
  return { severity: "error", message: desc || t("login.failed") };
}

export default function Login() {
  const { t } = useTranslation();
  const [form] = Form.useForm<LoginForm>();
  const [needsTotp, setNeedsTotp] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();
  // Agent mode pins one identity and the daemon 403s login — there's nothing to
  // sign into here, and /v1/me already authed us. Bounce to the console.
  const { agentMode, consoleWebUrl } = useServiceMode();

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

  if (agentMode) {
    return <Navigate to="/overview" replace />;
  }

  const errInfo = login.error
    ? classifyLoginError((login.error as Error).message || "", t)
    : null;

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

          {errInfo && (
            <Alert type={errInfo.severity} showIcon message={errInfo.message} />
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

          {/* Registration lives in the web console, not here. The URL comes from
              the daemon (/v1/service-mode → console_web), baked at build time and
              overridable via $CALABI_CONSOLE_WEB, so self-hosted deployments link
              to their own console. When the daemon supplies nothing (older build,
              or deliberately unset) we drop the link entirely — this used to be a
              hardcoded https://calabi.example.com/register placeholder that went
              nowhere. ?mode=register lands on the console's register tab. */}
          {consoleWebUrl && (
            <Paragraph
              type="secondary"
              style={{ fontSize: 12, margin: 0, textAlign: "center" }}
            >
              {t("login.registerPre")}
              <a
                href={`${consoleWebUrl}/login?mode=register`}
                target="_blank"
                rel="noopener noreferrer"
              >
                {t("login.consoleLink")}
              </a>
              {t("login.registerPost")}
            </Paragraph>
          )}
        </Space>
      </Card>
    </div>
  );
}
