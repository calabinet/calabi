// Overview.tsx — landing page. Shows online status, edge identity,
// month-to-date traffic with quota progress, and the live throughput
// chart. Polls /tunnels every 2s for fresh byte counters.
import { BellOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Col,
  Progress,
  Row,
  Statistic,
  Typography,
} from "antd";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api } from "../api/client";
import type {
  AccountMe,
  CurrentUsage,
  Healthz,
  Snapshot,
  TunnelList,
} from "../api/types";
import TrafficChart from "../components/TrafficChart";
import DailyTrafficChart from "../components/DailyTrafficChart";
import {
  notify,
  notificationPermission,
  requestNotificationPermission,
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
  const [notifPerm, setNotifPerm] = useState(() => notificationPermission());

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

  // /v1/usage/current?period=today gives an UNCAPPED real-time SUM
  // over [today 00:00 local, now). The earlier attempt used
  // /v1/usage/daily?n=1 -- that's wrong: metering-svc's daily i=0 is
  // [yesterday 00:00, today 00:00), so it returned YESTERDAY's total.
  const { data: usageTodayResp } = useQuery<CurrentUsage>({
    queryKey: ["usage-today"],
    queryFn: api.usageToday,
    refetchInterval: 30_000,
    retry: false,
  });
  const todayBytes = usageTodayResp?.bytes_total ?? 0;

  const { data: health } = useQuery<Healthz>({
    queryKey: ["healthz"],
    queryFn: api.healthz,
    refetchInterval: 5_000,
  });

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
  const totalBytes = (snap?.tunnels ?? []).reduce(
    (sum, t) => sum + (t.bytes_in || 0) + (t.bytes_out || 0),
    0,
  ) ?? 0;
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

  // The Content area is fixed-height with overflow:hidden on its parent
  // (see Layout.tsx). We mirror that here: this page is a flex column
  // that fills 100% of the available height, the stat cards keep their
  // natural size, and the bottom row (chart + local info, side-by-side)
  // takes the remainder via flex:1. That way nothing overflows the
  // viewport on the default window size and we don't need a scrollbar.
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 12,
        height: "100%",
        minHeight: 0,
      }}
    >
      <Title level={4} style={{ margin: 0 }}>
        {t("nav.overview")}
      </Title>

      {me?.plan?.code !== "standalone" && notifPerm === "default" && (
        <Alert
          showIcon
          type="info"
          icon={<BellOutlined />}
          message={t("overview.enableNotifTitle")}
          description={t("overview.enableNotifDesc")}
          action={
            <Button
              size="small"
              type="primary"
              onClick={async () => {
                const r = await requestNotificationPermission();
                setNotifPerm(r);
              }}
            >
              {t("overview.enable")}
            </Button>
          }
          closable
          onClose={() => setNotifPerm("denied")}
        />
      )}

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
            <Statistic title={t("overview.todayTraffic")} value={fmtBytes(todayBytes)} />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
          <Card size="small" style={{ width: "100%" }}>
            <Statistic
              title={t("overview.monthTraffic")}
              value={usage ? fmtBytes(usage.bytes_total) : "—"}
              valueStyle={
                quotaErr
                  ? { color: "#ff4d4f" }
                  : quotaWarn
                    ? { color: "#faad14" }
                    : undefined
              }
            />
            {usage && usage.limit_mb > 0 && (
              <Progress
                percent={Math.min(100, Math.round(quotaPct))}
                size="small"
                showInfo={false}
                status={quotaErr ? "exception" : quotaWarn ? "active" : "normal"}
                style={{ marginTop: 4 }}
              />
            )}
            {usage && usage.limit_mb > 0 && (
              <Text type="secondary" style={{ fontSize: 11 }}>
                {quotaPct.toFixed(1)}% / {usage.limit_mb} MB
              </Text>
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
      <Row gutter={[12, 12]} style={{ flex: 1, minHeight: 0, margin: 0 }} wrap={false}>
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
          <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
            <DailyTrafficChart days={7} />
          </div>
          <div style={{ flex: 1, minHeight: 0, display: "flex" }}>
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
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.edgeNode")}</Text>
                <div><code style={{ fontSize: 12 }}>{snap?.server_addr || "—"}</code></div>
              </Col>
              <Col span={24}>
                <Text type="secondary" style={{ fontSize: 12 }}>{t("overview.sessionDevice")}</Text>
                <div><code style={{ fontSize: 11 }}>{snap?.session_id || "—"}</code></div>
                <div><code style={{ fontSize: 11 }}>{snap?.client_id || "—"}</code></div>
              </Col>
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
