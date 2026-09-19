// SelfHosted.tsx — this console connected to a self-hosted server instead of
// calabi.net (docs/runbook/self-hosted-sign-in-plan.md §6.2,
// self-hosted-server-plan.md): the coordinator it joined, a coordinator
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
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";
import type { SelfHostedEdgeState, SelfHostedPart, SelfHostedStatus, SelfHostedTunnel, SelfHostedUsage } from "../api/types";

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
                    {edge.error}
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
export function SelfHostedTunnelsCard() {
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
          dataSource={data?.items ?? []}
          pagination={false}
          locale={{ emptyText: t("selfHosted.noTunnels") }}
          columns={[
            {
              title: t("tunnels.colName"),
              key: "name",
              render: (_, r) => (
                <Space size={6}>
                  <Text strong>{r.name}</Text>
                  <Tag>{r.type.toUpperCase()}</Tag>
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

// SelfHostedUsageCard is the network's traffic this month — tunnels plus relay,
// in this browser's calendar — and its devices. A self-hosted server has no
// limit; a coordinator without a database keeps no traffic, and says so.
export function SelfHostedUsageCard() {
  const { t, i18n } = useTranslation();
  const { data: st } = useSelfHosted();
  const hasMesh = st?.mode === "self_hosted" && !!st.mesh;
  const { data, error } = useQuery<SelfHostedUsage>({
    queryKey: ["selfhosted-usage"],
    queryFn: () => api.selfHostedUsage(7),
    enabled: hasMesh,
    retry: false,
    refetchInterval: 60_000,
  });
  if (!hasMesh) return null;
  const month = data?.month;
  const max = Math.max(1, ...(data?.days ?? []).map((d) => d.bytes));
  const dayName = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString(i18n.language, { weekday: "short" });
    } catch {
      return "";
    }
  };
  return (
    <Card title={t("selfHosted.usageTitle")} size="small">
      {error ? (
        <Alert type="info" showIcon message={readFailureText(t, error)} />
      ) : (
        <div style={{ display: "flex", gap: 32, flexWrap: "wrap", alignItems: "flex-end" }}>
          <Space direction="vertical" size={2}>
            {month ? (
              <>
                <Text style={{ fontSize: 24, fontWeight: 600 }}>{fmtBytes(month.tunnel_bytes + month.relay_bytes)}</Text>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t("selfHosted.usageTunnels", { v: fmtBytes(month.tunnel_bytes) })}
                  {" · "}
                  {data?.relay_not_recorded
                    ? t("selfHosted.usageRelayNotRecorded")
                    : t("selfHosted.usageRelay", { v: fmtBytes(month.relay_bytes) })}
                </Text>
              </>
            ) : (
              <Text type="secondary">{data?.unavailable ? t("selfHosted.usageUnavailable") : "—"}</Text>
            )}
          </Space>
          {(data?.days?.length ?? 0) > 0 && (
            <Space direction="vertical" size={4}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("selfHosted.week")}
              </Text>
              <div style={{ display: "flex", gap: 6, alignItems: "flex-end", height: 56 }}>
                {data!.days.map((d, i) => (
                  <div key={d.start} title={fmtBytes(d.bytes)} style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2 }}>
                    <div
                      style={{
                        width: 18,
                        height: d.bytes ? Math.max(4, Math.round((40 * d.bytes) / max)) : 2,
                        borderRadius: 3,
                        background: d.bytes ? (i === data!.days.length - 1 ? "#5e7fff" : "rgba(94,127,255,0.45)") : "rgba(148,163,184,0.35)",
                      }}
                    />
                    <span style={{ fontSize: 10, color: "#94a3b8" }}>{dayName(d.start)}</span>
                  </div>
                ))}
              </div>
            </Space>
          )}
          {data?.devices && (
            <Space direction="vertical" size={2}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("selfHosted.usageDevices")}
              </Text>
              <Text style={{ fontSize: 16 }}>
                {data.devices.used}
                {" / "}
                {data.devices.limit > 0 ? data.devices.limit : t("selfHosted.usageUnlimited")}
              </Text>
            </Space>
          )}
        </div>
      )}
    </Card>
  );
}
