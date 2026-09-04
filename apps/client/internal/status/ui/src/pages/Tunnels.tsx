// Tunnels.tsx — full CRUD over the tunnel list. Delete is hard-delete
// via DELETE /v1/tunnels/{id}. Create launches the wizard modal.
//
// The table joins two data sources:
//   - /v1/tunnels (bff-console): canonical persisted rows
//   - /tunnels (local daemon): live runtime state (bytes, connections)
// We merge on tunnel_id so the user sees both static config + live
// counters in one row.
import {
  CodeOutlined,
  DeleteOutlined,
  EditOutlined,
  ImportOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Badge,
  Button,
  Divider,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import type { BadgeProps } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type {
  AccountMe,
  EdgeList,
  EdgeListItem,
  ProbeHealth,
  RemoteTunnel,
  Snapshot,
  TunnelInfo,
  TunnelList,
} from "../api/types";
import InspectorDrawer from "../components/InspectorDrawer";
import TunnelWizard from "../components/TunnelWizard";
import { notify } from "../hooks/use-notifications";
import { useServiceMode } from "../hooks/use-service-mode";
import { effectiveState, type EffectiveState } from "../lib/tunnelState";
import { useTranslation } from "react-i18next";

const { Title, Text } = Typography;

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${u[i]}`;
}

const ipv4Re = /^\d{1,3}(\.\d{1,3}){3}$/;

// truncateDomain hides the registered/apex domain (the last two labels,
// e.g. "xuxulaka.com") behind "…" so the 公网 column stays narrow:
//   "u000001.edge-hz.xuxulaka.com" → "u000001.edge-hz…"
// The full value is still copyable + shown in the tooltip. Domains with
// ≤ 2 labels and raw IPs are returned unchanged (nothing meaningful to
// hide).
function truncateDomain(domain: string): string {
  if (ipv4Re.test(domain)) return domain;
  const parts = domain.split(".");
  if (parts.length <= 2) return domain;
  return parts.slice(0, parts.length - 2).join(".") + ".…";
}

// edgeHttpURL builds a directly-usable URL for an HTTP tunnel from the edge's
// advertised listener ports (AUTH_RESP) — prefers HTTPS, omits standard ports
// (80/443). Returns null when no port is advertised (a platform edge fronted by
// a load balancer on 80/443), so the caller falls back to the bare domain.
function edgeHttpURL(
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
function localAddrURL(type: string, localAddr: string): string {
  if (!localAddr) return localAddr;
  if (type === "http") return `http://${localAddr}`;
  if (type === "https") return `https://${localAddr}`;
  return localAddr;
}

// CopyableAddr renders the truncated `display` as monospace text with a
// tooltip carrying the full value, plus an antd copy icon that copies
// the FULL value (not the truncated display). Used by the 公网 column.
function CopyableAddr({ full, display }: { full: string; display: string }) {
  const { t } = useTranslation();
  return (
    <Space size={2}>
      <Tooltip title={full}>
        <code style={{ fontSize: 12 }}>{display}</code>
      </Tooltip>
      <Text
        copyable={{ text: full, tooltips: [t("common.copy"), t("common.copied")] }}
      />
    </Space>
  );
}

// STATE_BADGE maps the UNIFIED effective-state vocabulary → an antd Badge dot
// color. Identical to the cloud console (web/console Tunnels.tsx) so :7400 and
// the web console show the same color for the same state. Labels live in i18n
// under `tunnels.state.*` (also shared with the cloud console).
const STATE_BADGE: Record<EffectiveState, BadgeProps["status"]> = {
  active: "success",
  offline: "default",
  pending: "warning",
  mismatch: "warning",
  error: "error",
  disabled: "default",
  admin_disabled: "error",
};

// StatusDot renders a colored status dot followed by a short inline label
// (运行中 / 离线 / 异常 …) so the state is readable at a glance, with the longer
// description (probe latency, why-offline, cross-region detail) in a hover
// tooltip. label omitted → dot only (back-compat). cursor:help hints the hover.
function StatusDot({
  status,
  tip,
  label,
}: {
  status: BadgeProps["status"];
  tip: ReactNode;
  label?: ReactNode;
}) {
  return (
    <Tooltip title={tip}>
      <span style={{ cursor: "help", display: "inline-flex", alignItems: "center" }}>
        <Badge status={status} text={label} />
      </span>
    </Tooltip>
  );
}

// Tunnel state labels live in i18n under `tunnels.state.*` — the SAME keys the
// cloud console uses, so the two consoles speak one vocabulary (active / offline
// / pending / mismatch / error / disabled / admin_disabled). The raw tunnel-svc
// Status enum ("enabled" etc.) is no longer surfaced directly; it's collapsed
// into the effective state by lib/tunnelState.ts + the daemon's local refinement.

interface Row extends RemoteTunnel {
  bytes_in?: number;
  bytes_out?: number;
  connections?: number;
  live?: boolean;
  proxy_id?: string;
  health?: ProbeHealth;
}

export default function Tunnels() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  // Agent mode: pinned API-key identity. A MANAGEMENT key (tunnel.write) keeps a
  // fully writable console — create / edit / security / delete all work against
  // the agent's org. A READ-ONLY key greys those writes (reads + inspect stay
  // live) and shows a read-only banner. canManage folds both axes; readOnlyAgent
  // is the "agent without write" case that wants the explanatory banner.
  const { agentMode, canManage } = useServiceMode();
  const readOnlyAgent = agentMode && !canManage;
  const [wizardOpen, setWizardOpen] = useState(false);
  const [drawerProxy, setDrawerProxy] = useState<{ id: string; name?: string } | null>(null);
  const [secRow, setSecRow] = useState<RemoteTunnel | null>(null);
  const [editRow, setEditRow] = useState<RemoteTunnel | null>(null);
  const [takeoverRow, setTakeoverRow] = useState<RemoteTunnel | null>(null);
  const [searchParams, setSearchParams] = useSearchParams();
  const prefillPort = searchParams.get("prefill_port");
  // Arriving from the Services page's "发布到公网": the query carries the service
  // name, the local address to forward to, and its proto so the wizard opens
  // pre-filled and records config_json.origin on create.
  const publishService = searchParams.get("publish_service") || undefined;
  const publishAddr = searchParams.get("publish_addr") || undefined;
  const publishProto = searchParams.get("publish_proto") || undefined;
  const publish =
    publishService && publishAddr
      ? { serviceName: publishService, localAddr: publishAddr, proto: publishProto || "tcp" }
      : undefined;

  // If we arrived via /tunnels?prefill_port=N (from the port-scanner
  // page) or ?publish_service=... (from Services), auto-open the wizard with
  // the values baked in. Clean the query so a refresh doesn't re-trigger.
  useEffect(() => {
    if (prefillPort || publishService) {
      setWizardOpen(true);
    }
  }, [prefillPort, publishService]);

  const { data: list, isLoading } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
    refetchInterval: 8_000,
  });
  // This daemon's own device. The list now includes tunnels bound to OTHER
  // clients in the org; a row whose client_id differs runs elsewhere, so we
  // explain that in the status tooltip (and offer takeover) instead of a bare
  // "offline" with no reason.
  const myDeviceId = list?.my_device_id ?? 0;
  const isOffMachine = (r: Row) =>
    !!r.client_id && myDeviceId > 0 && r.client_id !== myDeviceId;
  // Pull plan info so we can pre-disable "新建隧道" once the cap is hit
  // — server-side tunnel-svc enforces the same limit, but blocking the
  // UI first means the user gets immediate feedback instead of filling
  // out the wizard only to eat a 429 on submit.
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });
  const planMax = me?.plan?.max_tunnels;
  // IP access control is a paid feature (ip_policy). Gate the editor; the
  // server re-gates on save so this is purely UX.
  const { ipPolicyEnabled, basicAuthEnabled, rateLimitEnabled, headerRewriteEnabled, oauthEnabled } = useMemo(() => {
    try {
      const f = JSON.parse(me?.plan?.features_json || "{}");
      return {
        ipPolicyEnabled: !!f.ip_policy,
        basicAuthEnabled: !!f.basic_auth,
        rateLimitEnabled: !!f.rate_limit,
        headerRewriteEnabled: !!f.header_rewrite,
        oauthEnabled: !!f.oauth,
      };
    } catch {
      return { ipPolicyEnabled: false, basicAuthEnabled: false, rateLimitEnabled: false, headerRewriteEnabled: false, oauthEnabled: false };
    }
  }, [me]);
  // Standalone (the local supervisor console): a disabled advanced feature means
  // "this edition doesn't have it" — there's no plan to upgrade — so the editor
  // hides those sections rather than showing the managed "upgrade" prompt.
  const standalone = me?.plan?.code === "standalone";
  // M11.19.1: tunnelCount must reflect the Org-wide count to line up
  // with the plan cap — plan.max_tunnels is enforced against ALL
  // members' tunnels at tunnel-svc.CreateTunnel admit. items.length is
  // already filtered to "本机" by the daemon's handleListMyTunnels, so
  // we use team_total when the daemon provides it, falling back to
  // items.length for older daemon builds.
  const tunnelCount =
    list?.team_total ?? list?.items?.length ?? 0;
  // Cap-detection: max_tunnels > 0 means a real cap (the seed plans use
  // -1 for "unlimited" but the BFF normalizes that to undefined). Both
  // the page-level Alert below and the "新建隧道" button's disabled
  // state read this. tunnel-svc admit-checks the same number server-
  // side, so the UI is purely UX — a wizard you can't submit is worse
  // than no wizard, hence the disable + visible banner.
  const capped =
    typeof planMax === "number" && planMax > 0 && tunnelCount >= planMax;
  const { data: snap } = useQuery<Snapshot>({
    queryKey: ["snapshot"],
    queryFn: api.snapshot,
    refetchInterval: 2_000,
  });
  const { data: health } = useQuery<{ items: ProbeHealth[]; enabled: boolean }>({
    queryKey: ["probe-health"],
    queryFn: api.probeHealth,
    refetchInterval: 10_000,
  });
  const healthByProxy = useMemo(() => {
    const m = new Map<string, ProbeHealth>();
    (health?.items ?? []).forEach((h) => m.set(h.proxy_id, h));
    return m;
  }, [health]);

  // Pull the edge directory so the 「Edge」 column can show region +
  // healthy state instead of bare edge_node_id integers. retry:false
  // because /v1/edges 401s on a still-bootstrapping daemon (no creds
  // yet) and a retry loop only writes more noise to the daemon log —
  // when the row renders we just fall back to the raw id.
  const { data: edgeList } = useQuery<EdgeList>({
    queryKey: ["edges"],
    queryFn: api.edges,
    refetchInterval: 30_000,
    retry: false,
  });
  const edgeById = useMemo(() => {
    const m = new Map<number, EdgeListItem>();
    (edgeList?.items ?? []).forEach((e) => m.set(e.edge_node_id, e));
    return m;
  }, [edgeList]);
  // edgeById is still used by the status column's edge-down check (an edge that
  // dropped out of the directory means a tunnel pinned to it is offline). The
  // old region-comparison logic moved to the shared effectiveState() "mismatch"
  // state (driven by server-provided client_edge_node_id), so currentEdgeID /
  // currentRegion are no longer derived here.

  // M7-S5: fire a desktop notification on the 3rd consecutive bad
  // health check (≈90s of brokenness) so the user knows the local
  // upstream actually died, not just blipped.
  useEffect(() => {
    (health?.items ?? []).forEach((h) => {
      if (h.consecutive_bad === 3) {
        notify(
          "health:" + h.proxy_id,
          "Tunnel upstream unreachable",
          `${h.proxy_id}: ${h.error || "no response"}`,
        );
      }
    });
  }, [health]);

  const del = useMutation({
    mutationFn: (id: number) => api.deleteTunnel(id),
    onSuccess: () => {
      message.success(t("tunnels.deleted"));
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      qc.invalidateQueries({ queryKey: ["snapshot"] });
    },
    onError: (e: any) => {
      message.error(e.message || t("tunnels.deleteFailed"));
    },
  });

  // Merge live counters from snap into the remote list rows.
  const liveByTunnelID = new Map<number, TunnelInfo>();
  (snap?.tunnels ?? []).forEach((t) => {
    if (t.tunnel_id) liveByTunnelID.set(t.tunnel_id, t);
  });

  const rows: Row[] = (list?.items ?? []).map((r) => {
    const live = liveByTunnelID.get(r.id);
    const pid = live?.proxy_id;
    // live.pending = true means UpsertPending wrote a placeholder entry
    // during catch-up CONFIG_PUSH but the daemon never managed to
    // OnProxyOpened the proxy (typical cause: M12 zone-edge check
    // rejected the claim because this tunnel's domain belongs to a
    // different edge than the one we're dialled to). Treating that as
    // "live" gives the user a false-positive "运行中" badge plus health
    // probes against a tunnel the local edge isn't actually serving.
    const isLive = !!live && !live.pending;
    return {
      ...r,
      bytes_in: live?.bytes_in,
      bytes_out: live?.bytes_out,
      connections: live?.connections,
      live: isLive,
      proxy_id: isLive ? pid : undefined,
      health: isLive && pid ? healthByProxy.get(pid) : undefined,
    };
  });

  // Region scoping: the local console lists only tunnels whose bound edge sits
  // in the SAME region this daemon is currently anchored to. A tunnel pinned to
  // an edge in another region has a public address this client can't serve from
  // here (per-edge wildcard DNS + edge-allocated ports), so showing it would be
  // misleading — the cloud console is where you see every region at once.
  //
  // We hide a row ONLY when we can POSITIVELY place its edge in a DIFFERENT
  // region. Everything ambiguous degrades OPEN (kept): unknown own region,
  // unbound/pending rows (no edge yet), and rows whose edge isn't in the
  // directory — so a directory blip or a fresh boot never empties the list.
  const currentRegion =
    snap?.preferred_region ||
    (snap?.edge_node_id ? edgeById.get(snap.edge_node_id)?.region : undefined) ||
    "";
  const inCurrentRegion = (r: Row): boolean => {
    if (!currentRegion) return true; // own region unknown → don't filter
    if (!r.edge_node_id) return true; // unbound / pending → belongs here
    const e = edgeById.get(r.edge_node_id);
    if (!e || !e.region) return true; // edge not in directory → degrade open
    return e.region === currentRegion;
  };
  const visibleRows = rows.filter(inCurrentRegion);
  const hiddenByRegion = rows.length - visibleRows.length;

  const columns: ColumnsType<Row> = [
    {
      title: t("tunnels.colStatus"),
      dataIndex: "status",
      width: 120,
      // Unified state vocabulary: we start from the SAME effectiveState() the
      // cloud console uses, then layer the daemon's local signals on top — its
      // own edge session being down, the per-tunnel health probe, and the edge
      // directory. The LABEL/COLOR always come from the shared `tunnels.state.*`
      // set, so :7400 and the web console never disagree (the old code leaked
      // the raw "已启用"/enabled status here, which says nothing about online).
      render: (_s, row) => {
        // Base state from the shared collapse (server-authoritative signals).
        let st = effectiveState(row);
        let tip: ReactNode = t(`tunnels.state.${st}`);

        // Does THIS daemon own/serve the row? (unbound or bound to us)
        const mine = !row.client_id || row.client_id === myDeviceId;

        // (1) This daemon's edge session is down → anything IT would be serving
        // is offline right now, regardless of stale server presence (the
        // "掉线了还显示在线" report). Doesn't touch tunnels served by OTHER
        // clients — those stay on their server-derived state.
        if (
          snap &&
          !snap.connected &&
          mine &&
          (st === "active" || st === "pending" || st === "mismatch")
        ) {
          return (
            <StatusDot
              status={STATE_BADGE.offline}
              label={t("tunnels.state.offline")}
              tip={t("tunnels.offlineNotConnectedTip")}
            />
          );
        }

        // (2) The owning edge dropped out of the directory (node down). Server
        // presence lags, so trust the directory — but never override a row we're
        // actively serving (it's on a healthy edge by definition).
        const edgeDirLoaded = (edgeList?.items?.length ?? 0) > 0;
        const rowEdge = row.edge_node_id ? edgeById.get(row.edge_node_id) : undefined;
        const edgeDown =
          edgeDirLoaded &&
          !!row.edge_node_id &&
          (!rowEdge || rowEdge.healthy === false);
        if (edgeDown && !row.live && (st === "active" || st === "mismatch")) {
          return (
            <StatusDot
              status={STATE_BADGE.offline}
              label={t("tunnels.state.offline")}
              tip={t("tunnels.edgeDownTip", { id: row.edge_node_id })}
            />
          );
        }

        // (3) We're actively serving this tunnel — the local upstream probe is
        // the freshest truth. A failing probe means the upstream is down even
        // though the server still says active; a passing one carries latency.
        if (row.live) {
          const h = row.health;
          if (h && !h.healthy) {
            return (
              <StatusDot
                status={STATE_BADGE.error}
                label={t("tunnels.state.error")}
                tip={t("tunnels.probeFailTip", {
                  err: h.error || t("common.unknown"),
                  n: h.consecutive_bad,
                })}
              />
            );
          }
          return (
            <StatusDot
              status={STATE_BADGE.active}
              label={t("tunnels.state.active")}
              tip={
                h && h.healthy
                  ? t("tunnels.probeOkTip", { ms: h.latency_ms, n: h.consecutive_good })
                  : health?.enabled === false
                    ? t("tunnels.onlineTip")
                    : t("tunnels.probing")
              }
            />
          );
        }

        // (4) Not served locally — trust the shared state, but enrich the
        // tooltip so a bare "离线"/"在线" always says WHY (esp. for rows that
        // run on another client in the org).
        if (st === "active") {
          tip = isOffMachine(row)
            ? t("tunnels.onlineOtherClientTip")
            : t("tunnels.serverOnlineTip");
        } else if (st === "offline") {
          tip = isOffMachine(row)
            ? t("tunnels.heldByOtherClientTip")
            : t("tunnels.state.offline");
        } else if (st === "mismatch") {
          tip = t("tunnels.mismatchTip", {
            clientEdge: row.client_edge_node_id ?? "?",
            boundEdge: row.edge_node_id ?? "?",
          });
        } else if (st === "pending") {
          tip = t("tunnels.pendingTip");
        }
        return (
          <StatusDot status={STATE_BADGE[st]} label={t(`tunnels.state.${st}`)} tip={tip} />
        );
      },
    },
    {
      title: t("tunnels.colName"),
      dataIndex: "name",
      width: 160,
      render: (n) => <Text strong>{n}</Text>,
    },
    {
      title: t("tunnels.colType"),
      dataIndex: "type",
      width: 80,
      render: (ty) => <Tag>{(ty || "").toUpperCase()}</Tag>,
    },
    {
      // Merged 公网 + 本地 into one "地址" column: public address on top,
      // local address below, each with a small gray label so the two are
      // unambiguous. Keeps the table narrower and reads as one logical
      // "this maps <public> → <local>" unit.
      title: t("tunnels.colAddress"),
      width: 280,
      render: (_v, r) => {
        // 公网 line — TCP/UDP host render priority (hostname-first; IP fallback):
        //   1. snap.server_addr — the FQDN the daemon dialed (edge public host,
        //      e.g. edge01-va.calabi.net) — preferred so the public addr is a
        //      stable hostname, not a bare IP that changes when the edge moves.
        //   2. snap.server_ip   — resolved edge IP (fallback when no hostname)
        //   3. snap.base_domain — edge's HTTPListener.BaseDomain (last resort)
        //   4. `:port` bare      — really last resort
        // (Was IP-first pre-2026-06; flipped per operator request — a prod edge
        //  advertises an FQDN public.addr, and a hostname survives IP changes.)
        // remote_port==0 + tcp/udp = created but never Claimed → 等待分配.
        const pub = (() => {
          if (r.domain) {
            // The edge terminates TLS for http/https tunnels, so default the
            // public URL to https:// (secure). A self-hosted edge listens on
            // non-standard ports (e.g. :8443) advertised via snap → show the
            // exact scheme+port; a managed/platform edge is on standard 443
            // (LB) → bare https://domain. SNI passthrough keeps its own scheme
            // (handled below), so this only applies to http/https.
            if (r.type === "http" || r.type === "https") {
              const u =
                me?.plan?.code === "standalone"
                  ? edgeHttpURL(r.domain, snap)
                  : null;
              const full = u ? u.full : `https://${r.domain}`;
              const display = u
                ? u.display
                : `https://${truncateDomain(r.domain)}`;
              return <CopyableAddr full={full} display={display} />;
            }
            return <CopyableAddr full={r.domain} display={truncateDomain(r.domain)} />;
          }
          if (r.remote_port && r.remote_port > 0) {
            const host =
              (snap?.server_addr ?? "").split(":")[0] ||
              snap?.server_ip ||
              snap?.base_domain;
            const full = host ? `${host}:${r.remote_port}` : `:${r.remote_port}`;
            const display = host
              ? `${truncateDomain(host)}:${r.remote_port}`
              : `:${r.remote_port}`;
            return <CopyableAddr full={full} display={display} />;
          }
          if (r.type === "tcp" || r.type === "udp") {
            return (
              <Text type="warning" style={{ fontSize: 12 }}>
                {t("tunnels.awaitingPort")}
              </Text>
            );
          }
          return <code style={{ fontSize: 12 }}>—</code>;
        })();
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 11, color: "#9ca3af", width: 42, flexShrink: 0, display: "inline-block", whiteSpace: "nowrap" }}>
                {t("tunnels.public")}
              </span>
              {pub}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ fontSize: 11, color: "#9ca3af", width: 42, flexShrink: 0, display: "inline-block", whiteSpace: "nowrap" }}>
                {t("tunnels.local")}
              </span>
              {r.local_addr ? (
                r.type === "http" || r.type === "https" ? (
                  <CopyableAddr
                    full={localAddrURL(r.type, r.local_addr)}
                    display={localAddrURL(r.type, r.local_addr)}
                  />
                ) : (
                  <code style={{ fontSize: 12 }}>{r.local_addr}</code>
                )
              ) : (
                <code style={{ fontSize: 12 }}>—</code>
              )}
            </div>
          </div>
        );
      },
    },
    // 「Edge」列已删除 — 顶栏的地域 chip 已显示当前区域,逐隧道再标一次区域
    // 冗余;真正要紧的「跨地域不可达」信号仍保留在 Status 列(crossRegion
    // badge)。edgeById / currentRegion / edgeList 仍被 Status 列用于
    // edge-down + 跨区域判定,故保留。
    // 「连接」列(基于 snap.tunnels[].connections,session-scoped,daemon
    // 重启清零)被删掉了 -- 累计连接数在多日运行场景下意义不大,且和
    // 「请求」抽屉里的逐条连接日志重复。需要查看连接明细的话点最右侧
    // 「请求」按钮看 InspectorDrawer。
    {
      title: t("tunnels.colTraffic"),
      width: 140,
      render: (_v, r) => {
        if (r.bytes_in === undefined) return "—";
        // 下行(↓)、上行(↑) 各占一行,与「地址」列的两行布局一致。
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span>
              <Text type="secondary" style={{ fontSize: 11 }}>↓</Text> {fmtBytes(r.bytes_in || 0)}
            </span>
            <span>
              <Text type="secondary" style={{ fontSize: 11 }}>↑</Text> {fmtBytes(r.bytes_out || 0)}
            </span>
          </div>
        );
      },
    },
    {
      title: t("common.actions"),
      width: 210,
      render: (_v, r) => (
        <Space size={4}>
          {r.proxy_id && (
            <Tooltip title={t("tunnels.inspectTip")}>
              <Button
                size="small"
                icon={<CodeOutlined />}
                onClick={() => setDrawerProxy({ id: r.proxy_id!, name: r.name })}
              />
            </Tooltip>
          )}
          {isOffMachine(r) && canManage && r.created_by_me && (() => {
            // The public address is bound to the tunnel's edge: an http/https
            // subdomain is DNS-pinned to its issuing edge, and a tcp/udp port is
            // allocated by that edge. So taking the tunnel over to a client on a
            // DIFFERENT edge/region changes (or breaks) the public address — for
            // a subdomain the new edge can't even serve it (the tunnel ends up
            // stuck). Grey out takeover whenever this daemon's current edge
            // differs from the tunnel's, regardless of type.
            const crossEdge =
              !!r.edge_node_id &&
              !!snap?.edge_node_id &&
              r.edge_node_id !== snap.edge_node_id;
            return (
              <Tooltip
                title={crossEdge ? t("tunnels.takeover.crossEdgeTip") : t("tunnels.takeover.tip")}
              >
                <Button
                  size="small"
                  icon={<ImportOutlined />}
                  disabled={crossEdge}
                  onClick={() => setTakeoverRow(r)}
                >
                  {t("tunnels.takeover.btn")}
                </Button>
              </Tooltip>
            );
          })()}
          <Tooltip title={canManage ? t("tunnels.edit.title") : t("serviceMode.tunnelsReadonly")}>
            <Button
              size="small"
              icon={<EditOutlined />}
              disabled={!canManage}
              onClick={() => setEditRow(r)}
            />
          </Tooltip>
          <Tooltip title={canManage ? t("tunnels.security.title") : t("serviceMode.tunnelsReadonly")}>
            <Button
              size="small"
              icon={<SafetyCertificateOutlined />}
              disabled={!canManage}
              onClick={() => setSecRow(r)}
            />
          </Tooltip>
          {!canManage ? (
            <Tooltip title={t("serviceMode.tunnelsReadonly")}>
              <Button danger size="small" icon={<DeleteOutlined />} disabled />
            </Tooltip>
          ) : (
            <Popconfirm
              title={t("tunnels.deleteConfirmTitle")}
              description={t("tunnels.deleteConfirmDesc")}
              okText={t("common.delete")}
              okButtonProps={{ danger: true }}
              cancelText={t("common.cancel")}
              onConfirm={() => del.mutate(r.id)}
            >
              <Button danger size="small" icon={<DeleteOutlined />} />
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ];

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Title level={4} style={{ margin: 0 }}>
          {t("nav.tunnels")}
        </Title>
        <Space>
          <Tooltip title={t("tunnels.refresh")}>
            <Button
              icon={<ReloadOutlined />}
              onClick={() => {
                qc.invalidateQueries({ queryKey: ["tunnels"] });
                qc.invalidateQueries({ queryKey: ["snapshot"] });
              }}
            />
          </Tooltip>
          <Tooltip
            title={
              !canManage
                ? t("serviceMode.tunnelsReadonly")
                : capped
                  ? t("tunnels.cappedTooltip", { count: tunnelCount, max: planMax })
                  : ""
            }
          >
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setWizardOpen(true)}
              disabled={capped || !canManage}
            >
              {t("tunnels.newTunnel")}
            </Button>
          </Tooltip>
        </Space>
      </div>

      {readOnlyAgent ? (
        <Alert
          showIcon
          type="info"
          message={t("serviceMode.agentBannerTitle")}
          description={t("serviceMode.agentBannerDesc")}
        />
      ) : (
        agentMode && (
          <Alert
            showIcon
            type="success"
            message={t("serviceMode.agentManageBannerTitle")}
            description={t("serviceMode.agentManageBannerDesc")}
          />
        )
      )}

      {snap?.edge_switch && (
        <Alert
          showIcon
          closable
          type="warning"
          message={t("tunnels.edgeSwitchMsg", {
            current: snap.edge_switch.current_edge_node_id,
            previous: snap.edge_switch.previous_edge_node_id,
          })}
          description={
            <span>
              {t("tunnels.edgeSwitchDesc1")}
              <Text strong>{t("tunnels.edgeSwitchAnotherRegion")}</Text>
              {t("tunnels.edgeSwitchDesc2")}
              <Text strong>{t("tunnels.edgeSwitchDeleteRebuild")}</Text>
              {t("tunnels.edgeSwitchDesc3")}
            </span>
          }
          onClose={() => {
            api
              .dismissEdgeSwitch()
              .catch((e) => message.error(e?.message || t("tunnels.dismissFailed")))
              .finally(() => {
                qc.invalidateQueries({ queryKey: ["snapshot"] });
              });
          }}
        />
      )}

      {capped && (
        <Alert
          showIcon
          type="warning"
          message={t("tunnels.cappedAlertMsg", { count: tunnelCount, max: planMax })}
          description={t("tunnels.cappedAlertDesc")}
        />
      )}

      {hiddenByRegion > 0 && (
        <Alert
          showIcon
          type="info"
          message={t("tunnels.regionFilteredMsg", { count: hiddenByRegion })}
          description={t("tunnels.regionFilteredDesc")}
        />
      )}

      <Table<Row>
        rowKey="id"
        size="middle"
        loading={isLoading}
        dataSource={visibleRows}
        columns={columns}
        pagination={{ pageSize: 20, showSizeChanger: false }}
        locale={{ emptyText: t("tunnels.emptyText") }}
      />

      <TunnelWizard
        open={wizardOpen}
        onClose={() => {
          setWizardOpen(false);
          // Drop the prefill / publish query so a re-open isn't pre-filled again.
          if (prefillPort || publishService) {
            const next = new URLSearchParams(searchParams);
            next.delete("prefill_port");
            next.delete("publish_service");
            next.delete("publish_addr");
            next.delete("publish_proto");
            setSearchParams(next, { replace: true });
          }
        }}
        prefillPort={prefillPort ? Number(prefillPort) : undefined}
        publish={publish}
      />

      <InspectorDrawer
        open={!!drawerProxy}
        onClose={() => setDrawerProxy(null)}
        proxyID={drawerProxy?.id ?? null}
        tunnelName={drawerProxy?.name}
      />

      <SecurityDrawer
        tunnel={secRow}
        standalone={standalone}
        ipPolicyEnabled={ipPolicyEnabled}
        basicAuthEnabled={basicAuthEnabled}
        rateLimitEnabled={rateLimitEnabled}
        headerRewriteEnabled={headerRewriteEnabled}
        oauthEnabled={oauthEnabled}
        onClose={() => setSecRow(null)}
      />

      <EditTunnelModal
        tunnel={editRow}
        offMachine={editRow ? isOffMachine(editRow) : false}
        onClose={() => setEditRow(null)}
      />

      <TakeoverModal tunnel={takeoverRow} onClose={() => setTakeoverRow(null)} />
    </Space>
  );
}

// localAddrIssue mirrors the wizard's client-side local_addr check (see
// TunnelWizard.tsx for the full rationale): "format" = not a bare port or
// host:port, "public" = a public IPv4 literal (open-relay risk), "" = ok or a
// hostname/IPv6 the daemon resolves authoritatively.
function localAddrIssue(addr: string): "" | "format" | "public" {
  const v = (addr || "").trim();
  if (!v) return "";
  if (/^\d+$/.test(v)) return "";
  let host: string;
  let port: string;
  if (v.startsWith("[")) {
    const end = v.indexOf("]:");
    if (end < 0) return "format";
    host = v.slice(1, end);
    port = v.slice(end + 2);
  } else {
    const c = v.lastIndexOf(":");
    if (c <= 0 || c === v.length - 1) return "format";
    host = v.slice(0, c);
    port = v.slice(c + 1);
  }
  if (!/^\d+$/.test(port)) return "format";
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1];
    const b = +m[2];
    const local =
      a === 0 ||
      a === 127 ||
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254);
    if (!local) return "public";
  }
  return "";
}

// EditTunnelModal edits a tunnel's name + local upstream. The public endpoint
// (type / domain / port) is intentionally read-only — it's shown for context
// but changing it would re-allocate the public address (delete + recreate).
function EditTunnelModal({
  tunnel,
  offMachine,
  onClose,
}: {
  tunnel: RemoteTunnel | null;
  // offMachine = this tunnel runs on ANOTHER client (you created it, but a
  // different machine serves it). Name + security apply remotely just fine, but
  // local_addr names an upstream on THAT machine — so we annotate the field
  // instead of silently letting the user point it at the wrong host.
  offMachine: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [form] = Form.useForm<{ name: string; local_addr: string }>();

  useEffect(() => {
    if (tunnel) {
      form.setFieldsValue({
        name: tunnel.name,
        local_addr: tunnel.local_addr ?? "",
      });
    }
  }, [tunnel, form]);

  const save = useMutation({
    mutationFn: (v: { name: string; local_addr: string }) =>
      api.updateTunnel(tunnel!.id, {
        name: v.name.trim(),
        local_addr: v.local_addr.trim(),
      }),
    onSuccess: () => {
      message.success(t("tunnels.edit.saved"));
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      qc.invalidateQueries({ queryKey: ["snapshot"] });
      onClose();
    },
    onError: (e: any) => message.error(e?.message || t("tunnels.edit.failed")),
  });

  return (
    <Modal
      open={!!tunnel}
      title={tunnel ? t("tunnels.edit.titleNamed", { name: tunnel.name }) : t("tunnels.edit.title")}
      onCancel={onClose}
      okText={t("tunnels.edit.save")}
      cancelText={t("common.cancel")}
      confirmLoading={save.isPending}
      onOk={() => form.submit()}
      destroyOnClose
    >
      {offMachine && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={t("tunnels.edit.offMachineTitle")}
          description={t("tunnels.edit.offMachineDesc")}
        />
      )}
      <Form layout="vertical" form={form} onFinish={(v) => save.mutate(v)}>
        <Form.Item label={t("tunnels.colType")}>
          <Tag>{(tunnel?.type || "").toUpperCase()}</Tag>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {t("tunnels.edit.endpointFixed")}
          </Typography.Text>
        </Form.Item>
        <Form.Item
          label={t("wizard.nameLabel")}
          name="name"
          rules={[{ required: true, message: t("wizard.nameRequired") }]}
        >
          <Input placeholder={t("wizard.namePlaceholder")} maxLength={64} showCount />
        </Form.Item>
        <Form.Item
          label={t("wizard.localAddrLabel")}
          name="local_addr"
          tooltip={t("wizard.localAddrTip")}
          extra={
            offMachine ? (
              <Typography.Text type="warning" style={{ fontSize: 12 }}>
                {t("tunnels.edit.offMachineLocalHint")}
              </Typography.Text>
            ) : undefined
          }
          rules={[
            { required: true, message: t("wizard.localAddrFormat") },
            {
              validator: (_, value) => {
                const r = localAddrIssue(value);
                if (r === "public")
                  return Promise.reject(new Error(t("wizard.localAddrPublic")));
                if (r === "format")
                  return Promise.reject(new Error(t("wizard.localAddrFormat")));
                return Promise.resolve();
              },
            },
          ]}
        >
          <Input placeholder="127.0.0.1:8080" />
        </Form.Item>
      </Form>
    </Modal>
  );
}

// TakeoverModal re-binds a tunnel that runs on ANOTHER client to this machine.
// The public endpoint is unchanged; the other client stops serving it and this
// daemon claims it on its own edge. Because the upstream service usually lives
// somewhere different on a new machine, the modal lets the user set the local
// address (defaulting to the tunnel's current one) and spells out the caveats.
function TakeoverModal({
  tunnel,
  onClose,
}: {
  tunnel: RemoteTunnel | null;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const [form] = Form.useForm<{ local_addr: string }>();

  useEffect(() => {
    if (tunnel) form.setFieldsValue({ local_addr: tunnel.local_addr ?? "" });
  }, [tunnel, form]);

  const run = useMutation({
    mutationFn: (v: { local_addr: string }) =>
      api.takeoverTunnel(tunnel!.id, v.local_addr.trim()),
    onSuccess: () => {
      message.success(t("tunnels.takeover.done"));
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      qc.invalidateQueries({ queryKey: ["snapshot"] });
      onClose();
    },
    onError: (e: any) => message.error(e?.message || t("tunnels.takeover.failed")),
  });

  return (
    <Modal
      open={!!tunnel}
      title={tunnel ? t("tunnels.takeover.titleNamed", { name: tunnel.name }) : t("tunnels.takeover.btn")}
      onCancel={onClose}
      okText={t("tunnels.takeover.confirm")}
      cancelText={t("common.cancel")}
      confirmLoading={run.isPending}
      onOk={() => form.submit()}
      destroyOnClose
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message={t("tunnels.takeover.warnTitle")}
        description={
          <ul style={{ margin: 0, paddingInlineStart: 18 }}>
            <li>{t("tunnels.takeover.warnLocal")}</li>
            <li>{t("tunnels.takeover.warnOther")}</li>
            <li>{t("tunnels.takeover.warnGap")}</li>
          </ul>
        }
      />
      <Form layout="vertical" form={form} onFinish={(v) => run.mutate(v)}>
        <Form.Item
          label={t("wizard.localAddrLabel")}
          name="local_addr"
          tooltip={t("tunnels.takeover.localTip")}
          rules={[
            { required: true, message: t("wizard.localAddrFormat") },
            {
              validator: (_, value) => {
                const r = localAddrIssue(value);
                if (r === "public")
                  return Promise.reject(new Error(t("wizard.localAddrPublic")));
                if (r === "format")
                  return Promise.reject(new Error(t("wizard.localAddrFormat")));
                return Promise.resolve();
              },
            },
          ]}
        >
          <Input placeholder="127.0.0.1:8080" />
        </Form.Item>
      </Form>
    </Modal>
  );
}

// ---- IP access-control policy editor (config_json security.ip) -------------
// Mirrors apps/calabi-edge/internal/policy + the bff-console validate/gate. The
// edge enforces the policy server-authoritatively; this modal edits the tunnel
// row's config_json via POST /v1/tunnels/{id}/security (proxied by the daemon).
function splitLines(s: string): string[] {
  return s.split("\n").map((x) => x.trim()).filter(Boolean);
}
function parseSecurityIP(cfg?: string): { allow: string[]; deny: string[] } {
  if (!cfg) return { allow: [], deny: [] };
  try {
    const o = JSON.parse(cfg);
    const ip = o?.security?.ip ?? {};
    return {
      allow: Array.isArray(ip.allow) ? ip.allow : [],
      deny: Array.isArray(ip.deny) ? ip.deny : [],
    };
  } catch {
    return { allow: [], deny: [] };
  }
}
type BasicUser = { user: string; password: string; hash: string };

function parseSecurityBasicAuth(cfg?: string): { user: string; hash: string }[] {
  if (!cfg) return [];
  try {
    const users = JSON.parse(cfg)?.security?.basic_auth?.users;
    if (!Array.isArray(users)) return [];
    return users
      .filter((u: any) => u && typeof u.user === "string")
      .map((u: any) => ({ user: u.user, hash: typeof u.hash === "string" ? u.hash : "" }));
  } catch {
    return [];
  }
}

function parseSecurityRateLimit(cfg?: string): number {
  if (!cfg) return 0;
  try {
    const v = JSON.parse(cfg)?.security?.rate_limit?.per_minute;
    return typeof v === "number" && v > 0 ? v : 0;
  } catch {
    return 0;
  }
}

type OAuthCfg = { provider: string; client_id: string; client_secret: string; allow_emails: string[]; allow_domains: string[] };
function parseSecurityOAuth(cfg?: string): OAuthCfg {
  const empty: OAuthCfg = { provider: "", client_id: "", client_secret: "", allow_emails: [], allow_domains: [] };
  if (!cfg) return empty;
  try {
    const o = JSON.parse(cfg)?.security?.oauth;
    if (!o || typeof o !== "object") return empty;
    return {
      provider: typeof o.provider === "string" ? o.provider : "",
      client_id: typeof o.client_id === "string" ? o.client_id : "",
      client_secret: typeof o.client_secret === "string" ? o.client_secret : "",
      allow_emails: Array.isArray(o.allow_emails) ? o.allow_emails.filter((x: any) => typeof x === "string") : [],
      allow_domains: Array.isArray(o.allow_domains) ? o.allow_domains.filter((x: any) => typeof x === "string") : [],
    };
  } catch {
    return empty;
  }
}

type HeaderKV = { name: string; value: string };
function parseSecurityRequestHeaders(cfg?: string): { set: HeaderKV[]; remove: string[] } {
  if (!cfg) return { set: [], remove: [] };
  try {
    const rh = JSON.parse(cfg)?.security?.request_headers ?? {};
    const setObj = rh.set && typeof rh.set === "object" ? rh.set : {};
    const set = Object.keys(setObj).map((name) => ({ name, value: String(setObj[name] ?? "") }));
    const remove = Array.isArray(rh.remove) ? rh.remove.filter((x: any) => typeof x === "string") : [];
    return { set, remove };
  } catch {
    return { set: [], remove: [] };
  }
}

// buildSecurityConfig preserves any non-security keys and rewrites the
// security.ip + security.basic_auth + security.rate_limit blocks. Empty inputs
// clear the respective block (and the security block if all go empty). A typed
// password is sent as cleartext (server bcrypts it); an untouched user keeps
// its existing hash.
function buildSecurityConfig(
  cfg: string | undefined,
  allow: string[],
  deny: string[],
  basicUsers: BasicUser[],
  ratePerMinute: number,
  reqHeaderSet: HeaderKV[],
  reqHeaderRemove: string[],
  oauth: OAuthCfg,
): string {
  let o: Record<string, any> = {};
  if (cfg) {
    try {
      o = JSON.parse(cfg) || {};
    } catch {
      o = {};
    }
  }
  const sec: Record<string, any> = o.security || {};
  if (allow.length === 0 && deny.length === 0) {
    delete sec.ip;
  } else {
    sec.ip = {};
    if (allow.length) sec.ip.allow = allow;
    if (deny.length) sec.ip.deny = deny;
  }
  const users = basicUsers
    .map((u) => ({ user: u.user.trim(), password: u.password, hash: u.hash }))
    .filter((u) => u.user)
    .map((u) => (u.password ? { user: u.user, password: u.password } : { user: u.user, hash: u.hash }))
    .filter((u: any) => u.password || u.hash);
  if (users.length === 0) {
    delete sec.basic_auth;
  } else {
    sec.basic_auth = { users };
  }
  if (ratePerMinute > 0) {
    sec.rate_limit = { per_minute: ratePerMinute };
  } else {
    delete sec.rate_limit;
  }
  const setObj: Record<string, string> = {};
  for (const h of reqHeaderSet) {
    const n = h.name.trim();
    if (n) setObj[n] = h.value;
  }
  const removeList = reqHeaderRemove.map((s) => s.trim()).filter(Boolean);
  if (Object.keys(setObj).length === 0 && removeList.length === 0) {
    delete sec.request_headers;
  } else {
    sec.request_headers = {};
    if (Object.keys(setObj).length) sec.request_headers.set = setObj;
    if (removeList.length) sec.request_headers.remove = removeList;
  }
  if (oauth.provider) {
    const oa: Record<string, any> = {
      provider: oauth.provider,
      client_id: oauth.client_id.trim(),
      client_secret: oauth.client_secret,
    };
    const emails = oauth.allow_emails.map((s) => s.trim()).filter(Boolean);
    const domains = oauth.allow_domains.map((s) => s.trim()).filter(Boolean);
    if (emails.length) oa.allow_emails = emails;
    if (domains.length) oa.allow_domains = domains;
    sec.oauth = oa;
  } else {
    delete sec.oauth;
  }
  if (Object.keys(sec).length === 0) {
    delete o.security;
  } else {
    o.security = sec;
  }
  return JSON.stringify(o);
}

function SecurityDrawer({
  tunnel,
  standalone,
  ipPolicyEnabled,
  basicAuthEnabled,
  rateLimitEnabled,
  headerRewriteEnabled,
  oauthEnabled,
  onClose,
}: {
  tunnel: RemoteTunnel | null;
  standalone: boolean;
  ipPolicyEnabled: boolean;
  basicAuthEnabled: boolean;
  rateLimitEnabled: boolean;
  headerRewriteEnabled: boolean;
  oauthEnabled: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const initIP = useMemo(() => parseSecurityIP(tunnel?.config_json), [tunnel?.config_json, tunnel?.id]);
  const initBA = useMemo(() => parseSecurityBasicAuth(tunnel?.config_json), [tunnel?.config_json, tunnel?.id]);
  const initRate = useMemo(() => parseSecurityRateLimit(tunnel?.config_json), [tunnel?.config_json, tunnel?.id]);
  const initRH = useMemo(() => parseSecurityRequestHeaders(tunnel?.config_json), [tunnel?.config_json, tunnel?.id]);
  const initOA = useMemo(() => parseSecurityOAuth(tunnel?.config_json), [tunnel?.config_json, tunnel?.id]);
  const [allow, setAllow] = useState("");
  const [deny, setDeny] = useState("");
  const [users, setUsers] = useState<BasicUser[]>([]);
  const [rate, setRate] = useState<number | null>(null);
  const [hdrSet, setHdrSet] = useState<HeaderKV[]>([]);
  const [hdrRemove, setHdrRemove] = useState("");
  const [oaProvider, setOaProvider] = useState("");
  const [oaClientId, setOaClientId] = useState("");
  const [oaSecret, setOaSecret] = useState("");
  const [oaEmails, setOaEmails] = useState("");
  const [oaDomains, setOaDomains] = useState("");
  useEffect(() => {
    setAllow(initIP.allow.join("\n"));
    setDeny(initIP.deny.join("\n"));
    setUsers(initBA.map((u) => ({ ...u, password: "" })));
    setRate(initRate || null);
    setHdrSet(initRH.set);
    setHdrRemove(initRH.remove.join("\n"));
    setOaProvider(initOA.provider);
    setOaClientId(initOA.client_id);
    setOaSecret("");
    setOaEmails(initOA.allow_emails.join("\n"));
    setOaDomains(initOA.allow_domains.join("\n"));
  }, [initIP, initBA, initRate, initRH, initOA]);

  const patchUser = (i: number, patch: Partial<BasicUser>) =>
    setUsers((us) => us.map((u, j) => (j === i ? { ...u, ...patch } : u)));
  const patchHdr = (i: number, patch: Partial<HeaderKV>) =>
    setHdrSet((hs) => hs.map((h, j) => (j === i ? { ...h, ...patch } : h)));

  const save = useMutation({
    mutationFn: () => {
      const cfg = buildSecurityConfig(
        tunnel?.config_json,
        splitLines(allow),
        splitLines(deny),
        users,
        rate || 0,
        hdrSet,
        splitLines(hdrRemove),
        {
          provider: oaProvider,
          client_id: oaClientId,
          client_secret: oaSecret.trim() || initOA.client_secret,
          allow_emails: splitLines(oaEmails),
          allow_domains: splitLines(oaDomains),
        },
      );
      return api.setTunnelSecurity(tunnel!.id, cfg);
    },
    onSuccess: () => {
      message.success(t("tunnels.security.saved"));
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      onClose();
    },
    onError: (e: any) => message.error(e?.message || t("tunnels.security.failed")),
  });

  // Roll every plan-locked feature into ONE notice instead of repeating an
  // upgrade box under each section. The user is a paying customer, so the copy
  // says "higher-tier plan", never "paid feature". Standalone has no plan to
  // upgrade — there the unavailable sections are simply hidden, no notice.
  const lockedFeatures = standalone
    ? []
    : ([
        !ipPolicyEnabled && t("tunnels.ipPolicy.title"),
        !basicAuthEnabled && t("tunnels.basicAuth.title"),
        !rateLimitEnabled && t("tunnels.rateLimit.title"),
        !headerRewriteEnabled && t("tunnels.headers.title"),
        !oauthEnabled && t("tunnels.oauth.title"),
      ].filter(Boolean) as string[]);

  return (
    <Drawer
      open={!!tunnel}
      title={tunnel ? t("tunnels.security.titleNamed", { name: tunnel.name }) : t("tunnels.security.title")}
      onClose={onClose}
      width={520}
      destroyOnClose
      footer={
        <div style={{ textAlign: "right" }}>
          <Space>
            <Button onClick={onClose}>{t("common.cancel")}</Button>
            <Button
              type="primary"
              loading={save.isPending}
              disabled={!ipPolicyEnabled && !basicAuthEnabled}
              onClick={() => save.mutate()}
            >
              {t("tunnels.security.save")}
            </Button>
          </Space>
        </div>
      }
    >
      {lockedFeatures.length > 0 && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message={t("tunnels.security.lockedNotice", { features: lockedFeatures.join("、") })}
        />
      )}

      {ipPolicyEnabled && (
        <>
          <Typography.Title level={5} style={{ marginTop: 0 }}>{t("tunnels.ipPolicy.title")}</Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            {t("tunnels.ipPolicy.hint")}
          </Typography.Paragraph>
          <Space direction="vertical" style={{ width: "100%" }} size="small">
            <div>
              <div style={{ fontSize: 12, color: "#8c8c8c", marginBottom: 4 }}>{t("tunnels.ipPolicy.allow")}</div>
              <Input.TextArea value={allow} onChange={(e) => setAllow(e.target.value)} rows={3} placeholder={"203.0.113.0/24\n198.51.100.7"} />
            </div>
            <div>
              <div style={{ fontSize: 12, color: "#8c8c8c", marginBottom: 4 }}>{t("tunnels.ipPolicy.deny")}</div>
              <Input.TextArea value={deny} onChange={(e) => setDeny(e.target.value)} rows={2} placeholder={"192.0.2.0/24"} />
            </div>
          </Space>
        </>
      )}

      {basicAuthEnabled && (
        <>
          <Divider />
          <Typography.Title level={5} style={{ marginTop: 0 }}>{t("tunnels.basicAuth.title")}</Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            {t("tunnels.basicAuth.hint")}
          </Typography.Paragraph>
          <Space direction="vertical" style={{ width: "100%" }} size="small">
          {users.map((u, i) => (
            <Space key={i} style={{ width: "100%" }} align="start">
              <Input
                style={{ width: 130 }}
                placeholder={t("tunnels.basicAuth.user")}
                value={u.user}
                onChange={(e) => patchUser(i, { user: e.target.value })}
              />
              <Input.Password
                style={{ width: 170 }}
                placeholder={u.hash ? t("tunnels.basicAuth.passwordKeep") : t("tunnels.basicAuth.password")}
                value={u.password}
                onChange={(e) => patchUser(i, { password: e.target.value })}
              />
              <Button danger onClick={() => setUsers((us) => us.filter((_, j) => j !== i))}>
                {t("common.delete")}
              </Button>
            </Space>
          ))}
          <Button onClick={() => setUsers((us) => [...us, { user: "", password: "", hash: "" }])}>
            + {t("tunnels.basicAuth.addUser")}
          </Button>
          </Space>
        </>
      )}

      {rateLimitEnabled && (
        <>
          <Divider />
          <Typography.Title level={5} style={{ marginTop: 0 }}>{t("tunnels.rateLimit.title")}</Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            {t("tunnels.rateLimit.hint")}
          </Typography.Paragraph>
          <Space>
            <InputNumber
              min={0}
              style={{ width: 150 }}
              value={rate}
              onChange={(v) => setRate(typeof v === "number" ? v : null)}
              placeholder={t("tunnels.rateLimit.placeholder")}
            />
            <span style={{ fontSize: 12, color: "#8c8c8c" }}>{t("tunnels.rateLimit.unit")}</span>
          </Space>
        </>
      )}

      {headerRewriteEnabled && (
        <>
          <Divider />
          <Typography.Title level={5} style={{ marginTop: 0 }}>{t("tunnels.headers.title")}</Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            {t("tunnels.headers.hint")}
          </Typography.Paragraph>
          <Space direction="vertical" style={{ width: "100%" }} size="small">
              <div style={{ fontSize: 12, color: "#8c8c8c" }}>{t("tunnels.headers.set")}</div>
              {hdrSet.map((h, i) => (
                <Space key={i} style={{ width: "100%" }} align="start">
                  <Input
                    style={{ width: 130 }}
                    placeholder={t("tunnels.headers.name")}
                    value={h.name}
                    onChange={(e) => patchHdr(i, { name: e.target.value })}
                  />
                  <Input
                    style={{ width: 170 }}
                    placeholder={t("tunnels.headers.value")}
                    value={h.value}
                    onChange={(e) => patchHdr(i, { value: e.target.value })}
                  />
                  <Button danger onClick={() => setHdrSet((hs) => hs.filter((_, j) => j !== i))}>
                    {t("common.delete")}
                  </Button>
                </Space>
              ))}
              <Button onClick={() => setHdrSet((hs) => [...hs, { name: "", value: "" }])}>
                + {t("tunnels.headers.addHeader")}
              </Button>
              <div style={{ fontSize: 12, color: "#8c8c8c", marginTop: 8 }}>{t("tunnels.headers.remove")}</div>
              <Input.TextArea
                value={hdrRemove}
                onChange={(e) => setHdrRemove(e.target.value)}
                rows={2}
                placeholder={"X-Powered-By\nCookie"}
              />
          </Space>
        </>
      )}

      {oauthEnabled && (
        <>
      <Divider />
      <Typography.Title level={5} style={{ marginTop: 0 }}>{t("tunnels.oauth.title")}</Typography.Title>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        {t("tunnels.oauth.hint")}
      </Typography.Paragraph>
        <Space direction="vertical" style={{ width: "100%" }} size="small">
          <Select
            style={{ width: 200 }}
            value={oaProvider || undefined}
            onChange={(v) => setOaProvider(v ?? "")}
            allowClear
            placeholder={t("tunnels.oauth.providerPlaceholder")}
            options={[
              { value: "google", label: "Google" },
              { value: "github", label: "GitHub" },
            ]}
          />
          {oaProvider && (
            <>
              <Alert
                type="info"
                message={t("tunnels.oauth.callbackHint")}
                description={
                  <Typography.Text code copyable>
                    {`https://${tunnel?.domain || "<your-domain>"}/__calabi/oauth/callback`}
                  </Typography.Text>
                }
              />
              <Input placeholder="Client ID" value={oaClientId} onChange={(e) => setOaClientId(e.target.value)} />
              <Input.Password
                placeholder={initOA.client_secret ? t("tunnels.oauth.secretKeep") : "Client Secret"}
                value={oaSecret}
                onChange={(e) => setOaSecret(e.target.value)}
              />
              <div style={{ fontSize: 12, color: "#8c8c8c" }}>{t("tunnels.oauth.allowEmails")}</div>
              <Input.TextArea value={oaEmails} onChange={(e) => setOaEmails(e.target.value)} rows={2} placeholder={"alice@acme.com"} />
              <div style={{ fontSize: 12, color: "#8c8c8c" }}>{t("tunnels.oauth.allowDomains")}</div>
              <Input.TextArea value={oaDomains} onChange={(e) => setOaDomains(e.target.value)} rows={2} placeholder={"acme.com"} />
            </>
          )}
        </Space>
        </>
      )}

      <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: "12px 0 0" }}>
        {t("tunnels.ipPolicy.applyNote")}
      </Typography.Paragraph>
    </Drawer>
  );
}
