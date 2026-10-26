import { matchesListSearch } from "../lib/listSearch";
import { displayError } from "../api/userError";
// SelfHosted.tsx — this console connected to a self-hosted server instead of
// calabi.net:
// the coordinator it joined, a coordinator
// certificate that changed and waits for a person, the edge the coordinator
// names for its tunnels, the mesh switch, the network's tunnels and traffic as
// the coordinator keeps them, and leaving.
//
// Everything here reads GET /v1/selfhosted. The calabi.net daemon answers it
// too (mode "platform"); a daemon from before answers 404 and none of this
// renders.
import {
  CloudServerOutlined,
  DisconnectOutlined,
  ExclamationCircleOutlined,
  LinkOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import { Alert, Button, Card, Descriptions, Modal, Space, Switch, Table, Tag, Typography, message } from "antd";
import { Bar, BarChart, CartesianGrid, Tooltip as ChartTooltip, XAxis, YAxis } from "recharts";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { SelfHostedEdgeState, SelfHostedPart, SelfHostedStatus, SelfHostedTunnel, SelfHostedUsage } from "../api/types";
import { dayLabel } from "../lib/usageDays";
import { typeLabel } from "../lib/tunnelType";
import ChartFrame from "./ChartFrame";

const { Text } = Typography;

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

export function useSelfHosted(enabled = true) {
  return useQuery<SelfHostedStatus>({
    queryKey: ["selfhosted"],
    queryFn: api.selfHosted,
    retry: false,
    refetchInterval: 5_000,
    enabled,
  });
}

// serverHost is what the console calls this machine's server: the
// coordinator it joined.
export function serverHost(st?: SelfHostedStatus): string {
  return st?.mesh?.server || "";
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// waitForModeThenGo follows the daemon through a switch: it ends and starts
// again in the other mode on the same address, with a new local token. A full
// page load then starts the console over against the daemon that is there now.
export async function waitForModeThenGo(mode: SelfHostedStatus["mode"], path: string) {
  await sleep(800); // the old daemon is still answering for a moment
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    try {
      const st = await api.selfHosted();
      if (st.mode === mode) break;
    } catch {
      // between the two daemons nothing answers
    }
    await sleep(500);
  }
  // The console routes by hash (HashRouter): set it, then load the page afresh
  // — a hash change alone would keep this page's caches and local token.
  window.location.hash = "#" + path;
  window.location.reload();
}

// Fingerprint is a certificate pin, whole: a person compares it character by
// character with what the server prints, so it is never shortened.
export function Fingerprint({ pin }: { pin?: string }) {
  if (!pin) return <Text type="secondary">—</Text>;
  return (
    <Text code copyable style={{ fontSize: 12, wordBreak: "break-all" }}>
      {pin}
    </Text>
  );
}

function trustLabel(t: (k: string) => string, part?: SelfHostedPart): string {
  if (!part?.trust) return "—";
  return t(`selfHosted.trust.${part.trust}`);
}

// useLeaveSelfHosted asks, then disconnects and forgets the server; the daemon
// starts again as the calabi.net one and the page follows it to sign-in.
export function useLeaveSelfHosted() {
  const { t } = useTranslation();
  const leave = useMutation({
    mutationFn: api.leaveSelfHosted,
    onSuccess: () => {
      message.loading({ content: t("selfHosted.leaving"), key: "leave", duration: 0 });
      void waitForModeThenGo("platform", "/login");
    },
    onError: (e) => message.error((e as Error).message),
  });
  const confirm = (st?: SelfHostedStatus) =>
    Modal.confirm({
      title: t("selfHosted.leaveTitle"),
      icon: <ExclamationCircleOutlined />,
      content: (
        <Space direction="vertical" size={4}>
          <span>{t("selfHosted.leaveBody")}</span>
          {(st?.tunnels ?? 0) > 0 && <Text type="danger">{t("selfHosted.leaveTunnels", { n: st?.tunnels })}</Text>}
        </Space>
      ),
      okText: t("selfHosted.leave"),
      okButtonProps: { danger: true },
      onOk: () => leave.mutateAsync(),
    });
  return { confirm, pending: leave.isPending };
}

// CertChanged is the coordinator presenting a certificate its saved trust
// refuses. Trusting sends the pin it presents NOW; if it presents another by
// then, the daemon refuses and the person is asked to look again. The edge has
// no such step: the coordinator tells the device the edge's certificate.
function CertChanged({ part }: { part: SelfHostedPart }) {
  const { t } = useTranslation();
  const trust = useMutation({
    mutationFn: () => api.trustSelfHosted(part.cert_presented || ""),
    onSuccess: () => message.success(t("selfHosted.certTrusted")),
    onError: (e) => {
      const code = (e as ApiError).body?.code;
      message.error(code === "pin_mismatch" ? t("selfHosted.certChangedAgain") : (e as Error).message);
    },
  });
  return (
    <Alert
      type="warning"
      showIcon
      icon={<SafetyCertificateOutlined />}
      message={t("selfHosted.certTitleMesh")}
      description={
        <Space direction="vertical" size={6} style={{ width: "100%" }}>
          <span>{t("selfHosted.certBody", { server: part.server })}</span>
          <Descriptions size="small" column={1} bordered>
            <Descriptions.Item label={t("selfHosted.certWas")}>
              {part.cert_pinned ? <Fingerprint pin={part.cert_pinned} /> : <Text type="secondary">{t("selfHosted.certWasTrusted")}</Text>}
            </Descriptions.Item>
            <Descriptions.Item label={t("selfHosted.certNow")}>
              <Fingerprint pin={part.cert_presented} />
            </Descriptions.Item>
          </Descriptions>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("selfHosted.confirmCmdMesh")}
          </Text>
          <div>
            <Button type="primary" loading={trust.isPending} onClick={() => trust.mutate()}>
              {t("selfHosted.certTrust")}
            </Button>
          </div>
        </Space>
      }
    />
  );
}

// SelfHostedBanners sits above every page of a self-hosted console: a machine
// not connected to anything yet, a certificate that changed, a coordinator that
// no longer takes this device or has yet to approve it.
export function SelfHostedBanners() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: st } = useSelfHosted();
  if (!st || st.mode !== "self_hosted") return null;
  const out: JSX.Element[] = [];
  // The mesh reports why only while it runs; the edge's access says so too
  // with the mesh off.
  const refused = (s: string) => st.mesh?.state === s || st.edge?.state === s;
  if (!st.mesh && st.managed) {
    out.push(
      <Alert
        key="none"
        type="info"
        showIcon
        icon={<LinkOutlined />}
        message={t("selfHosted.notConnectedTitle")}
        description={t("selfHosted.notConnectedBody")}
        action={
          <Button type="primary" onClick={() => navigate("/connect")}>
            {t("selfHosted.entry")}
          </Button>
        }
      />,
    );
  }
  if (st.mesh?.cert_presented) out.push(<CertChanged key="mesh-cert" part={st.mesh} />);
  if (refused("needs_invite")) {
    out.push(
      <Alert
        key="invite"
        type="error"
        showIcon
        message={t("selfHosted.needsInvite")}
        action={
          st.managed ? (
            <Button onClick={() => navigate("/connect")}>{t("selfHosted.change")}</Button>
          ) : undefined
        }
      />,
    );
  }
  if (refused("disabled")) {
    out.push(<Alert key="disabled" type="error" showIcon message={t("selfHosted.disabledBanner")} />);
  }
  if (refused("awaiting_approval")) {
    out.push(<Alert key="approval" type="info" showIcon message={t("selfHosted.awaitingApprovalBanner")} />);
  }
  if (!out.length) return null;
  return (
    <Space direction="vertical" size={8} style={{ width: "100%", marginBottom: 12 }}>
      {out}
    </Space>
  );
}

// SelfHostedCard is Settings' view of the connection: the coordinator and how
// its certificate is checked, the edge it names for this device's tunnels, the
// mesh switch, and the ways to change or leave the server.
export function SelfHostedCard() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: st } = useSelfHosted();
  const leave = useLeaveSelfHosted();
  const meshSwitch = useMutation({
    mutationFn: (on: boolean) => (on ? api.meshUp() : api.meshDown()),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["selfhosted"] });
      void qc.invalidateQueries({ queryKey: ["mesh"] });
    },
    onError: (e) => message.error((e as Error).message),
  });
  if (!st || st.mode !== "self_hosted") return null;
  const mesh = st.mesh;
  const meshOn = !!mesh && mesh.state !== "paused" && mesh.state !== "off";
  const edge = st.edge;
  const edgeColor = (s?: SelfHostedEdgeState) =>
    s === "connected" ? "green" : s === "connecting" ? "blue" : s === "awaiting_approval" ? "gold" : "orange";
  return (
    <Card
      title={
        <Space>
          <CloudServerOutlined />
          {t("selfHosted.cardTitle")}
        </Space>
      }
      size="small"
    >
      <Space direction="vertical" size={12} style={{ width: "100%" }}>
        <Descriptions size="small" column={1} bordered>
          <Descriptions.Item label={t("selfHosted.coordinator")}>
            {mesh ? (
              <Space direction="vertical" size={2}>
                <Text code>{mesh.server}</Text>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {trustLabel(t, mesh)}
                </Text>
                {mesh.trust === "pin" && mesh.pins?.[0] && <Fingerprint pin={mesh.pins[0]} />}
              </Space>
            ) : (
              <Text type="secondary">{t("selfHosted.none")}</Text>
            )}
          </Descriptions.Item>
          {edge && (
            <Descriptions.Item label={t("selfHosted.tunnelsRow")}>
              <Space direction="vertical" size={2}>
                <Space size={8} wrap>
                  {edge.server && <Text code>{edge.server}</Text>}
                  <Tag color={edgeColor(edge.state)}>{t(`selfHosted.edgeState.${edge.state}`, { defaultValue: edge.state })}</Tag>
                </Space>
                {!edge.connected && edge.error && (
                  <Text type="secondary" style={{ fontSize: 12, wordBreak: "break-word" }}>
                    {displayError(edge.error, t)}
                  </Text>
                )}
              </Space>
            </Descriptions.Item>
          )}
          {mesh && (
            <Descriptions.Item label={t("selfHosted.meshRow")}>
              <Space direction="vertical" size={4}>
                <Space size={8} wrap>
                  <Switch
                    checked={meshOn}
                    loading={meshSwitch.isPending}
                    disabled={!st.managed && !meshOn}
                    onChange={(on) => meshSwitch.mutate(on)}
                  />
                  <Tag color={mesh.state === "connected" ? "green" : mesh.state === "connecting" ? "blue" : "default"}>
                    {t(`selfHosted.state.${mesh.state}`)}
                  </Tag>
                </Space>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t("selfHosted.meshSwitchHint")}
                </Text>
              </Space>
            </Descriptions.Item>
          )}
        </Descriptions>
        {!st.managed && (
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("selfHosted.notManaged", { path: st.config_path })}
          </Text>
        )}
        <Space wrap>
          {st.managed && (
            <Button icon={<LinkOutlined />} onClick={() => navigate("/connect")}>
              {t("selfHosted.change")}
            </Button>
          )}
          {st.can_leave && mesh && (
            <Button danger icon={<DisconnectOutlined />} loading={leave.pending} onClick={() => leave.confirm(st)}>
              {t("selfHosted.leave")}
            </Button>
          )}
        </Space>
      </Space>
    </Card>
  );
}

function readFailureText(t: (k: string) => string, e: unknown): string {
  const code = (e as ApiError)?.body?.code;
  if (code === "not_connected") return t("selfHosted.notConnectedRead");
  return (e as Error)?.message || "";
}

// SelfHostedTunnelsCard is every tunnel the network's daemons reported to the
// coordinator — this machine's and every other device's.
export function SelfHostedTunnelsCard({ search = "" }: { search?: string }) {
  const { t } = useTranslation();
  const { data: st } = useSelfHosted();
  const hasMesh = st?.mode === "self_hosted" && !!st.mesh;
  const { data, error, isLoading } = useQuery<{ items: SelfHostedTunnel[] }>({
    queryKey: ["selfhosted-tunnels"],
    queryFn: api.selfHostedTunnels,
    enabled: hasMesh,
    retry: false,
    refetchInterval: 15_000,
  });
  if (!hasMesh) return null;
  return (
    <Card title={t("selfHosted.meshTunnels")} size="small" extra={<Text type="secondary" style={{ fontSize: 12 }}>{t("selfHosted.meshTunnelsHint")}</Text>}>
      {error ? (
        <Alert type="info" showIcon message={readFailureText(t, error)} />
      ) : (
        <Table<SelfHostedTunnel>
          rowKey="id"
          size="small"
          loading={isLoading}
          dataSource={(data?.items ?? []).filter(row => matchesListSearch(search, row.name, row.type, row.node_name, row.public_addr))}
          pagination={false}
          locale={{ emptyText: t(search.trim() ? "listSearch.noMatches" : "selfHosted.noTunnels") }}
          columns={[
            {
              title: t("tunnels.colName"),
              key: "name",
              render: (_, r) => (
                <Space size={6}>
                  <Text strong>{r.name}</Text>
                  <Tag>{typeLabel(r.type)}</Tag>
                </Space>
              ),
            },
            {
              title: t("selfHosted.colDevice"),
              key: "device",
              render: (_, r) => (
                <Space size={6}>
                  <span
                    style={{
                      display: "inline-block",
                      width: 8,
                      height: 8,
                      borderRadius: 4,
                      background: r.node_online ? "#10b981" : "#94a3b8",
                    }}
                  />
                  {r.node_name}
                </Space>
              ),
            },
            {
              title: t("selfHosted.colAddress"),
              key: "addr",
              render: (_, r) => (r.public_addr ? <Text code copyable>{r.public_addr}</Text> : <Text type="secondary">—</Text>),
            },
            {
              title: t("tunnels.colStatus"),
              key: "status",
              render: (_, r) => (
                <Tag color={r.status === "online" ? "green" : r.status === "pending" ? "blue" : "default"}>
                  {t(`selfHosted.tunnelState.${r.status}`, { defaultValue: r.status })}
                </Tag>
              ),
            },
            {
              title: t("selfHosted.colTraffic"),
              key: "traffic",
              align: "right" as const,
              render: (_, r) => fmtBytes(r.traffic_30d),
            },
          ]}
        />
      )}
    </Card>
  );
}

// ---- the network's usage, on Overview ---------------------------------------
//
// What the coordinator keeps for the whole network: this month's traffic
// (tunnels plus relay, in this browser's calendar), each of the last seven
// days, and the devices. A self-hosted server has no limit.
//
// It is shown in one of two ways, and never as a block of its own above the
// page's bottom row — the desktop shell is 720px tall and that block is what
// made a self-hosted console open with a scrollbar every time:
//
//   "chart"  the figures, with the seven days as a real chart, in the slot
//            where a calabi.net console draws this machine's own seven days;
//   "note"   one line, when there are no figures to chart: the coordinator has
//            no database and keeps no traffic, or it could not be asked. This
//            machine's own chart then stays where it is.
//
// "none" is a console with no coordinator behind it: nothing to show.
export type NetworkUsageView = "none" | "chart" | "note";

export function useSelfHostedUsage(enabled = true) {
  const { data: st } = useSelfHosted(enabled);
  const hasMesh = enabled && st?.mode === "self_hosted" && !!st.mesh;
  const { data, error } = useQuery<SelfHostedUsage>({
    queryKey: ["selfhosted-usage"],
    queryFn: () => api.selfHostedUsage(7),
    enabled: hasMesh,
    retry: false,
    refetchInterval: 60_000,
  });
  // Still loading counts as "chart": that is where nearly every console ends
  // up, and starting anywhere else would move the page's blocks on every load.
  const view: NetworkUsageView = !hasMesh ? "none" : error || (data && !data.month) ? "note" : "chart";
  return { view, data, error };
}

function devicesText(t: (k: string) => string, data: SelfHostedUsage): string {
  return `${data.devices.used} / ${data.devices.limit > 0 ? data.devices.limit : t("selfHosted.usageUnlimited")}`;
}

// The chart card's summary column. Nothing in it wraps, so its height is the
// same in every language — it is part of the floor of Overview's bottom row.
const usageLine: React.CSSProperties = { display: "block", fontSize: 12, lineHeight: "18px" };

// SelfHostedUsageChart fills a slot of Overview's bottom row the way the other
// chart cards do: the card stretches to the slot and the chart follows the
// card (see ChartFrame).
export function SelfHostedUsageChart({ data }: { data?: SelfHostedUsage }) {
  const { t } = useTranslation();
  const month = data?.month;
  const rows = (data?.days ?? []).map((d) => ({ label: dayLabel(d.start), bytes: d.bytes }));
  return (
    <Card
      size="small"
      title={t("selfHosted.usageTitle")}
      style={{ width: "100%", display: "flex", flexDirection: "column" }}
      bodyStyle={{ padding: 12, flex: 1, minHeight: 0, display: "flex", gap: 16 }}
    >
      <div style={{ flex: "0 0 auto", minWidth: 148, whiteSpace: "nowrap" }}>
        <Text style={{ display: "block", fontSize: 24, fontWeight: 600, lineHeight: "32px" }}>
          {month ? fmtBytes(month.tunnel_bytes + month.relay_bytes) : "—"}
        </Text>
        {month && (
          <>
            <Text type="secondary" style={usageLine}>
              {t("selfHosted.usageTunnels", { v: fmtBytes(month.tunnel_bytes) })}
            </Text>
            <Text type="secondary" style={usageLine}>
              {data?.relay_not_recorded
                ? t("selfHosted.usageRelayNotRecorded")
                : t("selfHosted.usageRelay", { v: fmtBytes(month.relay_bytes) })}
            </Text>
          </>
        )}
        {data?.devices && (
          <div style={{ marginTop: 8 }}>
            <Text type="secondary" style={usageLine}>
              {t("selfHosted.usageDevices")}
            </Text>
            <Text style={{ display: "block", lineHeight: "20px" }}>{devicesText(t, data)}</Text>
          </div>
        )}
      </div>
      <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
        <Text type="secondary" style={usageLine}>
          {t("selfHosted.week")}
        </Text>
        <div style={{ flex: 1, display: "flex" }}>
          {/* 96 + the label's 18 = the summary column's 114: the card is no
              taller at its floor than the chart card it stands in for. */}
          <ChartFrame minHeight={96}>
            {/* recharts measures an axis's labels in a hidden span, at the font
                size it reads off a tick ONCE, when the axis mounts — and this
                chart mounts before its days arrive, with no tick to read. From
                then on it measured at the page's 16px what it draws at 11px:
                "667.57 MB" came out too wide for the axis and was broken in
                two, and every other tick was dropped for want of room. The key
                mounts the chart afresh when the first days arrive, so its axes
                mount with their ticks; the non-breaking space leaves a label
                nowhere to break whatever the measurement says. */}
            <BarChart key={rows.length ? "days" : "empty"} data={rows} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.08)" />
              <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#94a3b8" }} />
              <YAxis
                tickFormatter={(v: number) => fmtBytes(v).replace(" ", " ")}
                width={72}
                tick={{ fontSize: 11, fill: "#94a3b8" }}
              />
              <ChartTooltip
                cursor={{ fill: "rgba(255,255,255,0.05)" }}
                formatter={(v: number) => [fmtBytes(Number(v)), t("dailyChart.total")]}
                contentStyle={{ background: "#0b1022", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }}
                labelStyle={{ color: "#94a3b8" }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="bytes" fill="#3a5cff" radius={[3, 3, 0, 0]} maxBarSize={40} />
            </BarChart>
          </ChartFrame>
        </div>
      </div>
    </Card>
  );
}

// SelfHostedUsageNote is the one line that stands in for the chart: why there
// are no figures, and the devices when the coordinator did answer. One line in
// every language — it is cut short rather than wrapped, because Overview has
// no height to give it a second.
export function SelfHostedUsageNote({ data, error }: { data?: SelfHostedUsage; error?: unknown }) {
  const { t } = useTranslation();
  return (
    <Card size="small" bodyStyle={{ padding: "6px 12px" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, whiteSpace: "nowrap" }}>
        <Text strong>{t("selfHosted.usageTitle")}</Text>
        <Text type="secondary" style={{ flex: 1, minWidth: 0, fontSize: 12, overflow: "hidden", textOverflow: "ellipsis" }}>
          {error ? readFailureText(t, error) : data?.unavailable ? t("selfHosted.usageUnavailable") : "—"}
        </Text>
        {!error && data?.devices && (
          <span>
            <Text type="secondary" style={{ fontSize: 12, marginRight: 8 }}>
              {t("selfHosted.usageDevices")}
            </Text>
            <Text>{devicesText(t, data)}</Text>
          </span>
        )}
      </div>
    </Card>
  );
}
