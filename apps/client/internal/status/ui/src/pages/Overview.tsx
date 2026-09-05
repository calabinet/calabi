// Overview.tsx — landing page. Shows online status, edge identity,
// month-to-date traffic with quota progress, and the live throughput
// chart. Polls /tunnels every 2s for fresh byte counters.
import {
  Alert,
  Card,
  Col,
  Progress,
  Row,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { api } from "../api/client";
import type {
  AccountMe,
  CurrentUsage,
  EdgeList,
  Healthz,
  MeshStatus,
  MeshUsage,
  Snapshot,
  TunnelList,
} from "../api/types";
import TrafficChart from "../components/TrafficChart";
import DailyTrafficChart from "../components/DailyTrafficChart";
import {
  notify,
  useTransitionNotify,
} from "../hooks/use-notifications";
import { useTranslation } from "react-i18next";

const { Title, Text } = Typography;

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

// fmtUptime turns a raw seconds count into the most human-y form:
//   <60s          → "刚刚启动"
//   <1h           → "Nm"
//   <24h          → "Nh Mm"
//   >=24h         → "Nd Mh"
// Keeping it Chinese-locale because the rest of the Overview labels are.
function fmtUptime(sec: number | undefined, justStarted: string): string {
  if (!sec || sec < 60) return justStarted;
  const d = Math.floor(sec / 86_400);
  const h = Math.floor((sec % 86_400) / 3_600);
  const m = Math.floor((sec % 3_600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export default function Overview() {
  const { t } = useTranslation();

  const { data: snap } = useQuery<Snapshot>({
    queryKey: ["snapshot"],
    queryFn: api.snapshot,
    refetchInterval: 2_000,
  });

  // BFF tunnel list is the authoritative count — it's the same source the
  // Tunnels page renders and the same source tunnel-svc admit-checks
  // against plan.max_tunnels. The daemon's snapshot is also a tunnel
  // list (and powers the real-time bytes/conn fields below) but it
  // accumulates pending+active rows that can drift out of sync with
  // the server when a CONFIG_PUSH close is missed (e.g., across a brief
  // daemon reconnect). Using snap.tunnels.length here gave us "9 / 5"
  // when the user actually owned 5 — confusing because the same page
  // listed 5 rows. Pull the count from BFF instead.
  const { data: tunnelList } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
    refetchInterval: 8_000,
  });

  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });

  const { data: usage } = useQuery<CurrentUsage>({
    queryKey: ["usage"],
    queryFn: api.usage,
    refetchInterval: 30_000,
    retry: false,
  });

  // /v1/usage/current?period=today gives an UNCAPPED real-time SUM over
  // [today 00:00, now) in the viewer's own timezone (api.usageToday forwards the
  // browser tz), so "今日" matches the user's wall clock in any country and keeps
  // advancing between the daily chart's per-bucket settles.
  const { data: usageTodayResp } = useQuery<CurrentUsage>({
    queryKey: ["usage-today"],
    queryFn: api.usageToday,
    refetchInterval: 30_000,
    retry: false,
  });
  // This machine's Connect (mesh) traffic, split relay vs direct by the LOCAL
  // meter — the server can't see direct traffic at all, so both halves come from
  // here. retry:false so a daemon without the endpoint just leaves them at 0.
  const { data: meshUsage } = useQuery<MeshUsage>({
    queryKey: ["usage-mesh"],
    queryFn: () => api.meshUsage(7),
    refetchInterval: 30_000,
    retry: false,
  });
  // Edge directory — used only to tell whether this daemon's egress edge is one
  // the org self-hosts (BYOI). retry:false so a plan without edges is harmless.
  const { data: edges } = useQuery<EdgeList>({
    queryKey: ["edges"],
    queryFn: api.edges,
    refetchInterval: 30_000,
    retry: false,
  });

  // Connect (mesh) state — hoisted above the traffic split because the 中继 figure
  // is scoped by the RELAY HOME (platform vs the org's own "self-…" relay), which
  // is a SEPARATE axis from the tunnel edge. Also feeds the "中继节点" block in
  // 本机信息. retry:false so a daemon without a mesh block (404) leaves it empty.
  const { data: mesh } = useQuery<MeshStatus>({
    queryKey: ["mesh"],
    queryFn: api.mesh,
    refetchInterval: 5_000,
    retry: false,
  });

  // Egress mode — is this machine's LIVE tunnel egress a self-hosted (BYOI) edge?
  // The 隧道 figure FOLLOWS the egress: platform edge → the platform (billed) slice
  // that matches the console + cap; self-hosted edge → that node's own tunnel
  // (never billed).
  const onSelfHostedEdge = !!edges?.items?.some(
    (e) => e.owned && e.edge_node_id === snap?.edge_node_id,
  );
  // The relay home is a SEPARATE axis: a node can sit on a self-hosted edge yet
  // still relay through a PLATFORM relay. This keys 中继 to the relay it's homed on.
  const relayIsSelfHosted = !!mesh?.derp_home?.startsWith("self-");

  // Two traffic categories per card (今日 / 本月): 隧道 (tunnel) + 中继 (relay).
  // 直连 (hole-punched direct) is intentionally NOT shown.
  //
  // Both figures are ORG-LEVEL from the backend, so EVERY client of the org reads
  // the SAME number — that's what finally makes an owner's login and an agent
  // agree. (In a personal org the backend hands an API-key agent the org view too,
  // so `scope` is "org" for both.) A genuinely own-scoped view — a team member's
  // agent that can't see org-wide — has no split and falls back to THIS machine's
  // local mesh meter for relay.
  const ownScope = usage?.scope === "own";
  // selfTunnel: the self-hosted tunnel slice. Org scope carries the BYOI split; an
  // own-scoped view has none (self_hosted_bytes_total is always 0), but on a
  // self-hosted edge its whole tunnel total IS self-hosted, so fall back to
  // bytes_total rather than a hard 0.
  const selfTunnel = (u?: CurrentUsage) =>
    u?.scope === "own" ? u?.bytes_total ?? 0 : u?.self_hosted_bytes_total ?? 0;
  const platformTunnel = (u?: CurrentUsage) =>
    u?.platform_bytes_total ?? u?.bytes_total ?? 0;
  // relayFor: the org's relay for the class this node is homed on — platform relay
  // (billed) or the org's OWN self-hosted relay ("self-…" regions: reported to the
  // platform, tagged, un-billed). undefined on an own-scoped view (no org relay),
  // so the caller falls back to the local per-device meter.
  const relayFor = (u?: CurrentUsage): number | undefined => {
    if (ownScope || !u) return undefined;
    return relayIsSelfHosted
      ? u.self_hosted_relay_bytes_total ?? 0
      : u.platform_relay_bytes_total ?? 0;
  };

  const todayTunnel = onSelfHostedEdge
    ? selfTunnel(usageTodayResp)
    : platformTunnel(usageTodayResp);
  const monthTunnel = onSelfHostedEdge ? selfTunnel(usage) : platformTunnel(usage);
  const todayRelay = relayFor(usageTodayResp) ?? (meshUsage?.today?.relay ?? 0);
  const monthRelay = relayFor(usage) ?? (meshUsage?.month?.relay ?? 0);
  const todayTotal = todayTunnel + todayRelay;
  const monthTotal = monthTunnel + monthRelay;

  const { data: health } = useQuery<Healthz>({
    queryKey: ["healthz"],
    queryFn: api.healthz,
    refetchInterval: 5_000,
  });

  // Billing gate for the cap bar. The cap measures only the BILLED slice —
  // platform tunnel + platform relay — so hide it whenever nothing platform is in
  // play: the egress edge is self-hosted AND the relay isn't a platform one
  // (onSelfHostedEdge is derived up top, where it also scopes the traffic cards).
  // If the self relay drops and the node falls back to a platform relay,
  // relayIsPlatform flips true and the cap reappears (those relay bytes ARE billed).
  const relayIsPlatform =
    !!mesh?.up && !!mesh?.derp_home && !mesh.derp_home.startsWith("self-");
  const limitMB = usage?.limit_mb ?? 0;
  const showCap = limitMB > 0 && (!onSelfHostedEdge || relayIsPlatform);
  // The cap is hidden specifically BECAUSE this machine is self-hosted (own edge,
  // no platform relay) — as opposed to there being no plan cap at all. In that
  // case we replace the cap bar with a note so the empty slot doesn't read as "no
  // usage" and the user understands self-hosted traffic simply isn't metered.
  const capHiddenBySelfHosting = limitMB > 0 && onSelfHostedEdge && !relayIsPlatform;
  // Whether to show the per-category split under the big number. Only meaningful
  // once Connect is enabled; a pure-tunnel machine's number already IS the tunnel.
  const meshOn = !!mesh?.enabled;

  // M7-S5 notifications.
  useTransitionNotify(
    health?.state,
    "connected",
    "reconnecting",
    "daemon-reconnecting",
    t("overview.notifReconnectingTitle"),
    t("overview.notifReconnectingBody"),
  );
  useTransitionNotify(
    health?.state,
    "connected",
    "fatal",
    "daemon-fatal",
    t("overview.notifFatalTitle"),
    t("overview.notifFatalBody"),
  );
  // Quota threshold: fire once at 80% and once at 100% (notify itself
  // dedupes inside a 60s window).
  useEffect(() => {
    const pct = usage?.percent_of_limit ?? 0;
    if (pct >= 100) {
      notify(
        "quota-100",
        t("overview.notifQuota100Title"),
        t("overview.notifQuota100Body"),
      );
    } else if (pct >= 80) {
      notify(
        "quota-80",
        t("overview.notifQuota80Title"),
        t("overview.notifQuota80Body", { pct: pct.toFixed(1) }),
      );
    }
  }, [usage]);

  // Kept around: TrafficChart still consumes totalBytes (session-scoped
  // bytes counter is the right input for "实时吞吐" — it's the only
  // sampled-per-second source we have). The Overview top cards used to
  // also surface this as "会话流量" + "累计连接" but those reset on
  // every daemon restart and meant little to the end user; we replaced
  // them with 在线时长 + 今日流量 (see UI below).
  // Tunnel session bytes (sampled ~2s) PLUS this machine's mesh peer bytes
  // (sampled 5s), so 实时吞吐 reflects Connect traffic too — otherwise a
  // mesh-only machine shows a flat 0 B/s despite active transfer. A counter
  // reset (daemon/mesh reconnect) makes the delta negative, which TrafficChart
  // clamps to 0, so a reset costs one 0 sample rather than a spurious spike.
  const tunnelBytes =
    (snap?.tunnels ?? []).reduce(
      (sum, t) => sum + (t.bytes_in || 0) + (t.bytes_out || 0),
      0,
    ) ?? 0;
  const meshPeerBytes = (mesh?.peers ?? []).reduce(
    (sum, p) => sum + (p.rx_bytes || 0) + (p.tx_bytes || 0),
    0,
  );
  const totalBytes = tunnelBytes + meshPeerBytes;
  // M11.19.1: "活跃隧道 N / M" should compare apples to apples — M is
  // plan.max_tunnels (Org-wide cap), so N has to be the Org-wide count.
  // The daemon ships team_total alongside the filtered items list so
  // we don't need a separate /v1/tunnels?scope=team round-trip.
  // Fallback to items.length for older daemon builds (M11.19 without .1)
  // so an upgrade doesn't break the page mid-rollout.
  const activeTunnels = tunnelList?.team_total ?? tunnelList?.items?.length ?? 0;
  const myTunnels = tunnelList?.my_total ?? tunnelList?.items?.length ?? 0;
  const uptimeSec = snap?.uptime_seconds ?? health?.uptime_seconds;

  const quotaPct = usage?.percent_of_limit ?? 0;
  const quotaWarn = quotaPct >= 80 && quotaPct < 100;
  const quotaErr = quotaPct >= 100;

  // Layout.tsx's Content scrolls (overflow:auto), so this page uses
  // minHeight:100% (not height:100%): on a tall window the flex column fills the
  // viewport and the bottom charts grow via flex:1; on a SHORT window (the smaller
  // desktop shell) the charts hold their min-height floor and the page scrolls
  // instead of squeezing them into a distorted sliver. height:100% would have
  // pinned the page to the viewport and let the charts collapse below usable size.
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 12,
        minHeight: "100%",
      }}
    >
      <Title level={4} style={{ margin: 0 }}>
        {t("nav.overview")}
      </Title>

      {me?.plan?.read_only && (
        <Alert
          showIcon
          type="warning"
          message={t("overview.readOnlyTitle")}
          description={t("overview.readOnlyDesc")}
        />
      )}

      {quotaErr && (
        <Alert
          showIcon
          type="error"
          message={t("overview.quotaExceededMsg", { pct: quotaPct.toFixed(1) })}
          description={t("overview.quotaExceededDesc")}
        />
      )}

      {/* Four stat cards. Each Card gets height:100% + the Col stretches
          by default (antd Row align="stretch"), so the "本月流量" card's
          Progress + quota text no longer makes that card taller than
          the others. */}
      <Row gutter={[12, 12]} align="stretch">
        <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
          <Card size="small" style={{ width: "100%" }}>
            <Statistic
              title={t("overview.activeTunnels")}
              value={activeTunnels}
              suffix={
                me?.plan?.max_tunnels && me.plan.max_tunnels > 0
                  ? `/ ${me.plan.max_tunnels}`
                  : undefined
              }
            />
            {/* M11.19.1 + M11.20.5: surface my-share when the Org has more
                tunnels than just this machine's. In a personal Org or
                a 1-member team the two numbers match and the hint is
                pure noise → hide it.
                Pulled the styling up a notch — earlier #8c8c8c/12px on a
                light card background was getting lost; the user couldn't
                tell at a glance which slice of the 10/10 belonged to
                this machine. Now it reads as a labeled pill so the
                number sits beside its meaning instead of disappearing
                into card padding. */}
            {activeTunnels !== myTunnels && (
              <div
                style={{
                  marginTop: 8,
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 6,
                  padding: "2px 10px",
                  background: "rgba(94,127,255,0.16)",
                  color: "#9bb4ff",
                  borderRadius: 10,
                  fontSize: 12,
                  fontWeight: 500,
                  lineHeight: "18px",
                }}
              >
                <span style={{ color: "#5e7fff", fontSize: 11 }}>●</span>
                {t("overview.onThisMachine", { count: myTunnels })}
              </div>
            )}
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
          <Card size="small" style={{ width: "100%" }}>
            <Statistic
              title={t("overview.uptime")}
              value={fmtUptime(uptimeSec, t("overview.justStarted"))}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
          <Card size="small" style={{ width: "100%" }}>
            <Statistic
              title={t("overview.todayTraffic")}
              value={fmtBytes(todayTotal)}
            />
            {(meshOn || todayRelay > 0) && (
              <Text type="secondary" style={{ fontSize: 11 }}>
                {t("overview.trafficBreakdown", {
                  tunnel: fmtBytes(todayTunnel),
                  relay: fmtBytes(todayRelay),
                })}
              </Text>
            )}
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
          <Card size="small" style={{ width: "100%" }}>
            {/* Big number = this month's traffic for the CURRENT egress (隧道 +
                中继). On a platform node this is the billed slice (platform 隧道 +
                platform 中继) and the cap bar below tracks it; on a self-hosted node
                it's that node's own traffic and the cap hides (see showCap) so
                self-hosted traffic never reads as metered. */}
            <Statistic
              title={t("overview.monthTraffic")}
              value={usage ? fmtBytes(monthTotal) : "—"}
              valueStyle={
                showCap && quotaErr
                  ? { color: "#ff4d4f" }
                  : showCap && quotaWarn
                    ? { color: "#faad14" }
                    : undefined
              }
            />
            {(meshOn || monthRelay > 0) && (
              <Text type="secondary" style={{ fontSize: 11 }}>
                {t("overview.trafficBreakdown", {
                  tunnel: fmtBytes(monthTunnel),
                  relay: fmtBytes(monthRelay),
                })}
              </Text>
            )}
            {showCap && (
              <Progress
                percent={Math.min(100, Math.round(quotaPct))}
                size="small"
                showInfo={false}
                status={quotaErr ? "exception" : quotaWarn ? "active" : "normal"}
                style={{ marginTop: 4 }}
              />
            )}
            {showCap && (
              <Text type="secondary" style={{ fontSize: 11 }}>
                {quotaPct.toFixed(1)}% / {limitMB} MB
              </Text>
            )}
            {/* Cap hidden because this machine runs on a self-hosted edge/relay:
                replace the bar with a green pill so the slot doesn't read as "0
                usage" and the user sees why there's no quota here. */}
            {capHiddenBySelfHosting && (
              <div
                style={{
                  marginTop: 6,
                  display: "inline-flex",
                  alignItems: "center",
                  padding: "2px 10px",
                  background: "rgba(34,197,94,0.12)",
                  color: "#86efac",
                  border: "1px solid rgba(34,197,94,0.32)",
                  borderRadius: 10,
                  fontSize: 11,
                  lineHeight: "18px",
                }}
              >
                {t("overview.selfHostedNotBilled")}
              </div>
            )}
          </Card>
        </Col>
      </Row>

      {/* Bottom row absorbs remaining vertical space. The chart grows
          to whatever's left; the info card is fixed-width and packs
          the same 6 fields in a tight 2-col grid so it stays visible
          without a scrollbar. minHeight:0 on both the wrapper and the
          flex children is needed for the chart's ResponsiveContainer
          to size itself against the flex height instead of overflowing. */}
      <Row gutter={[12, 12]} style={{ flex: 1, minHeight: 412, margin: 0 }} wrap={false}>
        <Col
          flex="auto"
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 12,
            minHeight: 0,
            paddingLeft: 0,
          }}
        >
          {/* Last-7-days daily bars (history) on top, live throughput below.
              Each takes half the remaining height. */}
          <div style={{ flex: 1, minHeight: 200, display: "flex" }}>
            <DailyTrafficChart
              days={7}
              selfHostedEdge={onSelfHostedEdge}
              selfHostedRelay={relayIsSelfHosted}
            />
          </div>
          <div style={{ flex: 1, minHeight: 200, display: "flex" }}>
            <TrafficChart totalBytes={totalBytes} />
          </div>
        </Col>
        <Col flex="320px" style={{ display: "flex", minHeight: 0, paddingRight: 0 }}>
          <Card
            title={t("overview.localInfo")}
            size="small"
            style={{ width: "100%", display: "flex", flexDirection: "column" }}
            bodyStyle={{ flex: 1, overflow: "auto", padding: 12 }}
          >
            <Row gutter={[12, 10]}>
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.clientVersion")}</Text>
                <div><code style={{ fontSize: 12 }}>{snap?.client_version || "—"}</code></div>
              </Col>
              {/* Session/caller sits under the version so the two NODE rows —
                  edge and relay — are adjacent below it (they're the pair the
                  user compares when switching egress).

                  NOT "device": client_id is who AUTHENTICATED this control
                  session (an identity session id, or "key-<prefix>" for an
                  api-key agent). Calling it a device both named the wrong thing
                  and collided with 设备 = a mesh node. This install's device
                  identity is the row below. */}
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.sessionCaller")}</Text>
                <div><code style={{ fontSize: 11 }}>{snap?.session_id || "—"}</code></div>
                <div><code style={{ fontSize: 11 }}>{snap?.client_id || "—"}</code></div>
              </Col>
              {/* The install's own identity. Worth a row of its own: an empty
                  fingerprint is the entire explanation for a mesh device that
                  shows no link to its client record, and there was previously
                  nothing on the machine that would tell you. */}
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.deviceIdentity")}</Text>
                <div>
                  <code style={{ fontSize: 11 }}>{snap?.fingerprint || t("overview.noFingerprint")}</code>
                  {!!snap?.device_id && (
                    <Text type="secondary" style={{ fontSize: 11 }}> · #{snap.device_id}</Text>
                  )}
                </div>
              </Col>
              {/* 边缘节点 (tunnel egress): the address plus a "自建" tag when the
                  daemon's LIVE egress edge is one the org self-hosts — mirrors the
                  中继节点 row's self-hosted tag so the two nodes read consistently
                  once 数据节点 is switched to 自建. */}
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.edgeNode")}</Text>
                <div>
                  <Space size={4} wrap>
                    <code style={{ fontSize: 12 }}>{snap?.server_addr || "—"}</code>
                    {onSelfHostedEdge && (
                      <Tooltip title={t("overview.edgeSelfTip")}>
                        <Tag color="green" style={{ marginInlineEnd: 0 }}>
                          {t("overview.edgeSelf")}
                        </Tag>
                      </Tooltip>
                    )}
                  </Space>
                </div>
              </Col>
              {/* 中继节点 (Connect/组网): the relay this node is homed on. relay is
                  the address; a "self-…" home region means it's the org's OWN
                  relay, so flag it — this is where switching 数据出口 to 自建
                  shows up (edge egress + relay home move together). */}
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.relayNode")}</Text>
                <div>
                  {!mesh?.enabled ? (
                    <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.meshOff")}</Text>
                  ) : mesh?.paused ? (
                    <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.meshPaused")}</Text>
                  ) : !mesh?.up ? (
                    <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.meshConnecting")}</Text>
                  ) : (
                    <Space size={4} wrap>
                      <code style={{ fontSize: 12 }}>{mesh.relay || "—"}</code>
                      {mesh.derp_home?.startsWith("self-") && (
                        <Tooltip title={t("overview.relaySelfTip")}>
                          <Tag color="green" style={{ marginInlineEnd: 0 }}>
                            {t("overview.relaySelf")}
                          </Tag>
                        </Tooltip>
                      )}
                    </Space>
                  )}
                </div>
              </Col>
              {mesh?.up && (
                <Col span={24}>
                  <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.overlayAddr")}</Text>
                  <div>
                    <code style={{ fontSize: 12 }}>{mesh.overlay || "—"}</code>
                    <Text type="secondary" style={{ fontSize: 11, marginLeft: 8 }}>
                      {t("overview.meshPeers", { count: mesh.peers?.length ?? 0 })}
                    </Text>
                  </div>
                </Col>
              )}
              {/* 账户/套餐这块以前在这里再列一次,但顶栏右侧已经显示账号、
                  顶栏左侧「本机客户端」旁边也有套餐 Tag,信息重复,
                  从本机信息卡片移除让概览更干净。 */}
            </Row>
          </Card>
        </Col>
      </Row>
    </div>
  );
}
