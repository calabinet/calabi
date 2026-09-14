// addr.tsx — how a tunnel's addresses are rendered, in one place.
//
// These four were private to the Tunnels page while it was the only screen that
// showed an address. The create flow's last step shows the same public address
// the list does — it is the answer to "did that work" — and a second copy of
// `edgeHttpURL` would be a second place to get the edge's advertised ports
// wrong. So they moved here rather than being duplicated.

import { Space, Tooltip, Typography } from "antd";
import { useTranslation } from "react-i18next";

const { Text } = Typography;

const ipv4Re = /^\d{1,3}(\.\d{1,3}){3}$/;

// truncateDomain hides the registered/apex domain (the last two labels,
// e.g. "xuxulaka.com") behind "…" so the 公网 column stays narrow:
//   "u000001.edge-hz.xuxulaka.com" → "u000001.edge-hz…"
// The full value is still copyable + shown in the tooltip. Domains with
// ≤ 2 labels and raw IPs are returned unchanged (nothing meaningful to
// hide).
export function truncateDomain(domain: string): string {
  if (ipv4Re.test(domain)) return domain;
  const parts = domain.split(".");
  if (parts.length <= 2) return domain;
  return parts.slice(0, parts.length - 2).join(".") + ".…";
}

// edgeHttpURL builds a directly-usable URL for an HTTP tunnel from the edge's
// advertised listener ports (AUTH_RESP) — prefers HTTPS, omits standard ports
// (80/443). Returns null when no port is advertised (a platform edge fronted by
// a load balancer on 80/443), so the caller falls back to the bare domain.
export function edgeHttpURL(
  domain: string,
  snap?: { http_port?: number; https_port?: number },
): { full: string; display: string } | null {
  const httpsP = snap?.https_port ?? 0;
  const httpP = snap?.http_port ?? 0;
  let scheme: string;
  let port: number;
  if (httpsP) {
    scheme = "https";
    port = httpsP;
  } else if (httpP) {
    scheme = "http";
    port = httpP;
  } else {
    return null;
  }
  const std = (scheme === "https" && port === 443) || (scheme === "http" && port === 80);
  const suffix = std ? "" : `:${port}`;
  return {
    full: `${scheme}://${domain}${suffix}`,
    display: `${scheme}://${truncateDomain(domain)}${suffix}`,
  };
}

// localAddrURL prefixes the local upstream address with the scheme implied by
// the tunnel TYPE — an http/https tunnel speaks that protocol to the local
// service, so the Local line mirrors the Public line's `http(s)://`. Unlike the
// public URL (which depends on the edge's advertised ports) this is derived
// purely from the type, so it applies on both editions. tcp/udp/sni carry no
// URL scheme → the bare host:port is returned unchanged.
export function localAddrURL(type: string, localAddr: string): string {
  if (!localAddr) return localAddr;
  if (type === "http") return `http://${localAddr}`;
  if (type === "https") return `https://${localAddr}`;
  return localAddr;
}

// portTunnelHost picks the host half of a tcp/udp tunnel's public endpoint,
// hostname-first:
//   1. snap.server_addr — the FQDN the daemon dialed (e.g. edge01-va.calabi.net),
//      preferred so the address is stable across an edge IP change
//   2. snap.server_ip   — resolved edge IP
//   3. snap.base_domain — the edge's HTTPListener.BaseDomain, last resort
// "" when the daemon has told us none of the three, which the caller renders as
// a bare `:port` rather than inventing a host.
export function portTunnelHost(snap?: {
  server_addr?: string;
  server_ip?: string;
  base_domain?: string;
}): string {
  return (
    (snap?.server_addr ?? "").split(":")[0] ||
    snap?.server_ip ||
    snap?.base_domain ||
    ""
  );
}

// CopyableAddr renders the truncated `display` as monospace text with a
// tooltip carrying the full value, plus an antd copy icon that copies
// the FULL value (not the truncated display). Used by the 公网 column.
export function CopyableAddr({ full, display }: { full: string; display: string }) {
  const { t } = useTranslation();
  return (
    <Space size={2}>
      <Tooltip title={full}>
        <code style={{ fontSize: 12 }}>{display}</code>
      </Tooltip>
      <Text copyable={{ text: full, tooltips: [t("common.copy"), t("common.copied")] }} />
    </Space>
  );
}
