// AuthGate.tsx — route protection wrapping the main Layout.
//
// Strategy: probe /v1/me. If it 200s, we're authed → render children
// (the Layout + page). If it 401s, we're not → redirect to /login.
// Any other error (503 daemon down, network blip) renders a friendly
// loading state rather than punting to login — bouncing back and forth
// on an infra blip would be a worse UX than waiting.
//
// We use React Query so this probe is shared with the topbar / Overview
// page (they all useQuery on ["me"]), avoiding a second roundtrip.
import { LoadingOutlined } from "@ant-design/icons";
import { Spin } from "antd";
import { useQuery } from "@tanstack/react-query";
import { Navigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { AccountMe } from "../api/types";

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const { data, isLoading, error } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
    // Refetch every minute so a remote-side logout (admin revoked the
    // session) drops the user back to the login screen within ~60s.
    refetchInterval: 60_000,
  });

  if (isLoading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Spin indicator={<LoadingOutlined style={{ fontSize: 28 }} spin />} />
      </div>
    );
  }

  if (error) {
    const status = (error as ApiError)?.status;
    // 401 = no/bad token → login screen. We don't bounce other errors to
    // login (an infra blip shouldn't log the user out) — instead we show a
    // diagnosis keyed off WHAT the status code actually means here. The SPA is
    // served by the local daemon at :7400, and /v1/me is reverse-proxied by the
    // daemon to bff-console (the control plane). So:
    //   - no status (socket refused)  → the daemon itself is unreachable/down
    //   - 502 Bad Gateway             → daemon is UP but can't reach the server
    //   - 503 Service Unavailable     → daemon is UP but still initializing
    //                                   (local token / backend URL not ready yet)
    // The old copy always blamed the daemon, which is wrong for 502/503 — the
    // daemon clearly answered, so "restart the daemon" sends users the wrong way.
    if (status === 401) {
      return <Navigate to="/login" replace />;
    }
    let primary = t("authGate.connecting");
    let hint = t("authGate.hint");
    if (status === 502 || status === 504) {
      primary = t("authGate.serverUnreachable");
      hint = t("authGate.serverUnreachableHint");
    } else if (status === 503) {
      primary = t("authGate.daemonStarting");
      hint = t("authGate.daemonStartingHint");
    }
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 12,
          color: "#94a3b8",
          fontSize: 14,
        }}
      >
        <Spin indicator={<LoadingOutlined style={{ fontSize: 28 }} spin />} />
        <div>
          {primary} ({status ? `HTTP ${status}` : t("authGate.networkError")})
        </div>
        <div style={{ fontSize: 12, maxWidth: 420, textAlign: "center" }}>{hint}</div>
      </div>
    );
  }

  if (!data) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}
