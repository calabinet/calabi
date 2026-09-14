// Mesh.tsx — Connect (WireGuard mesh) status for the local node.
//
// Read-only view over GET /v1/mesh (polled), plus a Stop control (POST
// /v1/mesh/down, local-token). Mesh runs inside the local daemon when its
// config has a `mesh:` block (see daemon_local_mesh.go); this page surfaces the
// node's overlay IP, coordinator/relay, and each peer's live WireGuard state
// (handshake age + bytes), the same data `calabi mesh status` prints.
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  Input,
  message,
  Popconfirm,
  Row,
  Space,
  Spin,
  Switch,
  Statistic,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { DeleteOutlined, PlayCircleOutlined, PlusOutlined, PoweroffOutlined } from "@ant-design/icons";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";

import { api, ApiError } from "../api/client";
import { parseRoute, formatRoute } from "../lib/cidr";
import { useSearchParams } from "react-router-dom";

import type {
  MeshAdvertise,
  MeshPeer,
  MeshStatus,
  OrgListResponse,
  Snapshot,
} from "../api/types";

const { Title, Text } = Typography;

// A direct path's round-trip. Sub-millisecond IS the interesting case — that is
// what a LAN path looks like — so it keeps a decimal that whole milliseconds
// would round away to "0 ms"; past 10ms the decimal is noise.
function fmtRtt(micros: number): string {
  const ms = micros / 1000;
  return ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`;
}

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

// fmtAgo turns a unix-seconds timestamp into a short "3s / 5m / 2h / 1d" span.
function fmtAgo(unixSec: number, never: string, ago: (d: string) => string): string {
  if (!unixSec) return never;
  const s = Math.max(0, Math.floor(Date.now() / 1000 - unixSec));
  let d: string;
  if (s < 60) d = `${s}s`;
  else if (s < 3600) d = `${Math.floor(s / 60)}m`;
  else if (s < 86400) d = `${Math.floor(s / 3600)}h`;
  else d = `${Math.floor(s / 86400)}d`;
  return ago(d);
}

// GOOS → what people call the platform. An unrecognised value is shown as-is
// rather than dropped: a new GOOS is information, and hiding it would make a
// real machine look like one that never reported.
const OS_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  darwin: "macOS",
  freebsd: "FreeBSD",
  openbsd: "OpenBSD",
  android: "Android",
  ios: "iOS",
};
function osLabel(os?: string): string {
  if (!os) return "";
  return OS_LABELS[os] ?? os;
}

function shortKey(k: string): string {
  return k.length > 16 ? k.slice(0, 16) + "…" : k;
}

export default function Mesh() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  // Peer filter. A fleet of 20 machines turns this table into scrolling, and the
  // thing you arrive knowing is the machine's NAME — so match on that first,
  // then on the address you might have pasted from somewhere, then on the key
  // for the case where you came from `wg show` or a log line.
  const [peerQuery, setPeerQuery] = useState("");

  // Owner labels. Proxied from bff-console, which is the only place that can
  // turn owner_user_id into a person (coord only ever knew the number). Fails
  // on a local daemon and for an api-key agent, and that must cost nothing but
  // the label: retry is off and the error is swallowed, so the peer table never
  // waits on it or reports it.
  const { data: orgNodes } = useQuery({
    queryKey: ["mesh-org-nodes"],
    queryFn: api.meshOrgNodes,
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  });
  const ownerByOverlay = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of orgNodes?.items ?? []) {
      if (n.overlay && n.owner_email) m.set(n.overlay, n.owner_email);
    }
    return m;
  }, [orgNodes]);

  const { data, error, isLoading } = useQuery<MeshStatus>({
    queryKey: ["mesh"],
    queryFn: api.mesh,
    refetchInterval: 3_000,
    retry: false,
    // Keep the last status visible across the 3s refetches so a poll never blanks
    // the page back to a skeleton/empty state.
    placeholderData: keepPreviousData,
  });

  // Both are already cached by the Layout (same query keys), so this costs no
  // extra fetch — it just lets the page name the org instead of an id.
  const { data: orgsResp } = useQuery<OrgListResponse>({
    queryKey: ["orgs"],
    queryFn: api.listOrgs,
    retry: false,
    staleTime: 60_000,
  });
  const { data: snap } = useQuery<Snapshot>({
    queryKey: ["snapshot"],
    queryFn: api.snapshot,
    refetchInterval: 5_000,
    retry: false,
  });
  // Same query key the settings card below uses, so it costs no extra fetch. The
  // page needs it for one thing: a machine that is refusing every inbound
  // connection looks EXACTLY like a healthy one on this page — up, addressed,
  // peers listed — and the switch that did it is three clicks away in a tab. A
  // setting whose effect is invisible from the page it breaks is a support call.
  const { data: adv } = useQuery<MeshAdvertise>({
    queryKey: ["mesh-advertise"],
    queryFn: api.meshAdvertise,
    retry: false,
  });

  // Devices this org has that this machine cannot reach. The peer table is the
  // ACL-FILTERED view, so a colleague's machine that the rules do not allow is
  // simply absent — and absent looks exactly like "does not exist". Meanwhile
  // the web console shows every device in the org to every member, so the two
  // surfaces disagree about the same machine and neither says why.
  //
  // Parked and not-yet-approved devices are excluded: they are in NOBODY's
  // netmap, so calling them blocked-by-policy would send someone to argue with
  // an admin about a rule that is not the problem.
  const unreachableCount = useMemo(() => {
    const items = orgNodes?.items ?? [];
    if (!items.length || !data?.up) return 0;
    const reachable = new Set<string>();
    for (const p of data.peers ?? []) {
      for (const ip of p.allowed_ips ?? []) reachable.add(ip.replace(/\/\d+$/, ""));
    }
    const self = data.overlay || "";
    return items.filter(
      (n) =>
        n.overlay &&
        n.overlay !== self &&
        n.approved !== false &&
        n.disabled !== true &&
        !reachable.has(n.overlay),
    ).length;
  }, [orgNodes, data?.peers, data?.overlay, data?.up]);

  const meshOrgID = data?.org_id ?? 0;
  // The org the daemon's CREDENTIAL is scoped to right now. When it disagrees
  // with the meshnet the session is in, the node is mid-switch — say so rather
  // than showing the old org's peers as if nothing happened.
  const activeOrgID = snap?.active_org_id || orgsResp?.active_org_id || 0;
  const orgNameOf = (id: number): string => {
    const o = orgsResp?.items?.find((x) => x.id === id);
    if (!o) return id ? `#${id}` : "—";
    return o.kind === "personal" ? t("mesh.orgPersonal") : o.name || `#${id}`;
  };
  const meshOrgName = orgNameOf(meshOrgID);
  const orgMismatch = meshOrgID > 0 && activeOrgID > 0 && meshOrgID !== activeOrgID;

  const stop = useMutation({
    mutationFn: api.meshDown,
    onSuccess: () => {
      message.success(t("mesh.stopped"));
      qc.invalidateQueries({ queryKey: ["mesh"] });
    },
    onError: (e) => message.error((e as Error).message),
  });

  const start = useMutation({
    mutationFn: api.meshUp,
    onSuccess: () => {
      message.success(t("mesh.started"));
      qc.invalidateQueries({ queryKey: ["mesh"] });
    },
    onError: (e) => message.error((e as Error).message),
  });

  // A 404 (older daemon, or a platform daemon that doesn't serve /v1/mesh) is
  // "unavailable"; a clean enabled:false response is "not configured".
  //
  // A 503 is NOT unavailable: the daemon does mesh and has simply not enrolled
  // yet. That used to be a 404 too, so the console told people their build had no
  // mesh support during the ordinary startup window — and because enrollment
  // polls on a 30s ticker, a first attempt that missed left the wrong message up
  // for far longer than any grace window would cover.
  const unavailable = error instanceof ApiError && error.status === 404;
  const enrolling = error instanceof ApiError && error.status === 503;

  // Startup grace window. Right after the daemon boots, /v1/mesh 404s until
  // enrollment + the datapath come up (a couple seconds). Flashing "unavailable"
  // and then swapping to the live status read as a flicker between two layouts.
  // Collapse the whole startup window — the first-load skeleton AND an early 404
  // — into ONE calm "detecting" state; only a 404 that PERSISTS past the grace
  // window hardens into the real "unavailable on this daemon" message.
  const [graceOver, setGraceOver] = useState(false);
  useEffect(() => {
    const id = setTimeout(() => setGraceOver(true), 8000);
    return () => clearTimeout(id);
  }, []);
  // Enrolling keeps the calm state for as long as it lasts — it is a definite
  // answer ("not yet"), not a guess that runs out with a timer.
  const settling = data === undefined && (isLoading || enrolling || (unavailable && !graceOver));

  // Case-insensitive substring over name, allowed prefixes and key. Filtering
  // here rather than with Table's own column filters: one box that matches
  // whatever the user happens to know beats three per-column dropdowns on a
  // table this narrow.
  const shownPeers = useMemo(() => {
    const all = data?.peers ?? [];
    const q = peerQuery.trim().toLowerCase();
    if (!q) return all;
    return all.filter(
      (p) =>
        (p.name ?? "").toLowerCase().includes(q) ||
        p.public_key.toLowerCase().includes(q) ||
        (p.allowed_ips ?? []).some((ip) => ip.toLowerCase().includes(q)) ||
        // "which machine has postgres on it" is a real way to arrive here.
        (p.services ?? []).some((sv) => sv.name.toLowerCase().includes(q)) ||
        // So is "one of kenji's machines".
        (ownerByOverlay.get((p.allowed_ips ?? [])[0]?.replace(/\/\d+$/, "") ?? "") ?? "")
          .toLowerCase()
          .includes(q),
    );
  }, [data?.peers, peerQuery, ownerByOverlay]);

  const columns = useMemo(
    () => [
      {
        // The machine's NAME, not its key. This column used to print a truncated
        // public key: correct, unique, and unreadable — nobody knows which of
        // their machines "qN3k7x…" is, and the key is not what you type to reach
        // it. The name is, and it comes from the netmap the node already holds.
        //
        // The key stays reachable in the tooltip: it is what the peer is called
        // in `wg show` and in the logs, so the one moment you need it is when
        // you are comparing this table against one of those.
        //
        // A peer with no name yet (WireGuard state read before the first netmap)
        // falls back to the short key rather than rendering blank.
        title: t("mesh.colPeer"),
        key: "peer",
        render: (_: unknown, p: MeshPeer) => {
          // Whose machine it is, when we could find out. The local part of the
          // address reads as a person and fits under the name; the full address
          // is in the tooltip. Nothing renders when unknown — an empty subline
          // is quieter than a placeholder, and "unknown owner" is not a fact
          // worth a row of its own.
          const owner = ownerByOverlay.get(
            (p.allowed_ips ?? [])[0]?.replace(/\/\d+$/, "") ?? "",
          );
          const sub = owner ? (
            <Tooltip title={owner}>
              <Text type="secondary" style={{ fontSize: 11 }}>
                {owner.split("@")[0]}
              </Text>
            </Tooltip>
          ) : null;
          return (
            <Space direction="vertical" size={0}>
              {p.name ? (
                <Tooltip title={p.public_key}>
                  <Text copyable={{ text: p.name }} style={{ fontSize: 13 }}>
                    {p.name}
                  </Text>
                </Tooltip>
              ) : (
                <Tooltip title={p.public_key}>
                  <code style={{ fontSize: 12 }}>{shortKey(p.public_key)}</code>
                </Tooltip>
              )}
              {(sub || p.os) && (
                <Space size={4}>
                  {sub}
                  {p.os && (
                    <Text type="secondary" style={{ fontSize: 11 }}>
                      {osLabel(p.os)}
                    </Text>
                  )}
                </Space>
              )}
            </Space>
          );
        },
      },
      {
        // Copyable per prefix: the overlay /32 in here is the address you paste
        // into ssh or a browser, and selecting it out of a Tag by hand is the
        // kind of friction that makes people go looking for the console instead.
        title: t("mesh.colAllowed"),
        dataIndex: "allowed_ips",
        key: "allowed",
        render: (ips: string[]) =>
          (ips || []).map((ip) => (
            <Tag key={ip}>
              <Text copyable={{ text: ip.replace(/\/\d+$/, "") }} style={{ fontSize: 12 }}>
                {ip}
              </Text>
            </Tag>
          )),
      },
      {
        // What the machine is FOR. A name tells you which box it is; this tells
        // you why you would dial it — and the port is the other half of the
        // address, so it is copyable as host:port ready to paste.
        //
        // Only confirmed services arrive here (the coordinator drops
        // unapproved declarations), so an empty cell means "declares nothing",
        // not "waiting for an admin".
        title: t("mesh.colServices"),
        key: "services",
        render: (_: unknown, p: MeshPeer) => {
          const svcs = p.services ?? [];
          if (svcs.length === 0) return <Text type="secondary">—</Text>;
          const host = (p.allowed_ips ?? [])[0]?.replace(/\/\d+$/, "") ?? "";
          return (
            <Space size={4} wrap>
              {svcs.map((sv) => (
                <Tooltip key={sv.name + sv.port} title={`${sv.proto}/${sv.port}`}>
                  <Tag style={{ marginInlineEnd: 0 }}>
                    <Text
                      copyable={host ? { text: `${host}:${sv.port}` } : false}
                      style={{ fontSize: 12 }}
                    >
                      {sv.name}
                    </Text>
                  </Tag>
                </Tooltip>
              ))}
            </Space>
          );
        },
      },
      {
        title: t("mesh.colHandshake"),
        dataIndex: "last_handshake_sec",
        key: "handshake",
        render: (s: number) => {
          const label = fmtAgo(s, t("mesh.never"), (d) => t("mesh.ago", { d }));
          const fresh = s > 0 && Date.now() / 1000 - s < 180;
          return <Tag color={fresh ? "green" : s > 0 ? "orange" : "default"}>{label}</Tag>;
        },
      },
      {
        // How this peer's traffic is actually flowing right now: straight to it
        // (hole punching succeeded) or through the relay. The endpoint is the
        // punched address — worth showing, it's the proof the path is real.
        //
        // The round-trip rides alongside the tag rather than only in the tooltip,
        // because "direct" alone is not the good news it reads as: two machines
        // on one LAN can be direct over a PUBLIC address, hairpinning out to the
        // ISP and back. That looks identical to a LAN path here and runs ~20x the
        // latency, and nobody hovers a tag that already says the reassuring word.
        title: t("mesh.colPath"),
        key: "path",
        render: (_: unknown, p: MeshPeer) => {
          const direct = p.path === "direct";
          const rtt = direct && p.rtt_micros ? fmtRtt(p.rtt_micros) : "";
          // The relay leg, shown ONLY when relayed. Prefixed with "→" and labelled
          // separately in the tooltip: it is this node to the relay, while the
          // direct figure is this node to the peer. Same column, deliberately not
          // the same presentation.
          const relayRtt = !direct && p.relay_rtt_micros ? fmtRtt(p.relay_rtt_micros) : "";
          return (
            <Tooltip
              title={
                p.endpoint ? (
                  <>
                    {p.endpoint}
                    {rtt ? (
                      <>
                        <br />
                        {t("mesh.rtt")}: {rtt}
                      </>
                    ) : null}
                    {relayRtt ? (
                      <>
                        <br />
                        {t("mesh.relayRtt")}: {relayRtt}
                        <br />
                        <span style={{ opacity: 0.75 }}>{t("mesh.relayRttHint")}</span>
                      </>
                    ) : null}
                  </>
                ) : undefined
              }
            >
              <span>
                <Tag color={direct ? "green" : "default"} style={{ marginInlineEnd: rtt || relayRtt ? 4 : undefined }}>
                  {direct ? t("mesh.pathDirect") : t("mesh.pathRelay")}
                </Tag>
                {rtt ? (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {rtt}
                  </Text>
                ) : null}
                {relayRtt ? (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    &rarr;{relayRtt}
                  </Text>
                ) : null}
              </span>
            </Tooltip>
          );
        },
      },
      {
        title: t("mesh.colTraffic"),
        key: "traffic",
        render: (_: unknown, p: MeshPeer) => (
          <Text style={{ fontSize: 12 }}>
            {fmtBytes(p.rx_bytes)} / {fmtBytes(p.tx_bytes)}
          </Text>
        ),
      },
    ],
    // ownerByOverlay belongs here: the render closes over it, so leaving it out
    // pins the columns to the empty map of the first render and the owner
    // sublines never appear — a bug with no error and no warning, found only by
    // looking at the rendered table.
    [t, ownerByOverlay],
  );

  const header = (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <Title level={4} style={{ margin: 0 }}>
        {t("mesh.title")}
      </Title>
      {/* Gated on the SAME condition the body uses. These used to disagree: the
          header read the last successful `data` while the body read `error`, so a
          daemon that started 404ing after a good fetch rendered "Stop mesh" in the
          header above "this daemon does not support mesh" in the body. */}
      {unavailable || settling ? null : data?.paused ? (
        <Button
          type="primary"
          icon={<PlayCircleOutlined />}
          loading={start.isPending}
          onClick={() => start.mutate()}
        >
          {t("mesh.start")}
        </Button>
      ) : (
        data?.enabled && (
          <Popconfirm
            title={t("mesh.stopConfirm")}
            okText={t("mesh.stop")}
            okButtonProps={{ danger: true }}
            onConfirm={() => stop.mutate()}
          >
            <Button danger icon={<PoweroffOutlined />} loading={stop.isPending}>
              {t("mesh.stop")}
            </Button>
          </Popconfirm>
        )
      )}
    </div>
  );

  let body: React.ReactNode;
  if (settling) {
    body = (
      <Card size="small">
        <div style={{ textAlign: "center", padding: "28px 0" }}>
          <Spin />
          <div style={{ marginTop: 12 }}>
            <Text type="secondary" style={{ fontSize: 13 }}>
              {t("mesh.detecting")}
            </Text>
          </div>
        </div>
      </Card>
    );
  } else if (unavailable) {
    body = (
      <Card size="small">
        <Empty description={t("mesh.unavailable")} />
      </Card>
    );
  } else if (data?.paused) {
    body = (
      <Card size="small">
        <Empty description={t("mesh.pausedDesc")}>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("mesh.pausedHint")}
          </Text>
        </Empty>
      </Card>
    );
  } else if (!data?.enabled) {
    body = (
      <Card size="small">
        <Empty description={t("mesh.notConfigured")}>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("mesh.notConfiguredHint")}
          </Text>
        </Empty>
      </Card>
    );
  } else {
    body = (
      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        {adv?.block_incoming && (
          <Alert
            type="warning"
            showIcon
            message={t("mesh.blockedBanner")}
            description={t("mesh.blockedBannerHelp")}
          />
        )}
        <Row gutter={[12, 12]} align="stretch">
          <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
            <Card size="small" style={{ width: "100%" }}>
              <Statistic
                title={t("mesh.state")}
                value={data.up ? t("mesh.stateUp") : t("mesh.stateDown")}
                valueStyle={{ color: data.up ? "#52c41a" : "#8c8c8c" }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
            <Card size="small" style={{ width: "100%" }}>
              <Statistic title={t("mesh.overlay")} value={data.overlay || "—"} />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
            <Card size="small" style={{ width: "100%" }}>
              <Statistic title={t("mesh.node")} value={data.name || "—"} />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6} style={{ display: "flex" }}>
            <Card size="small" style={{ width: "100%" }}>
              <Statistic title={t("mesh.peers")} value={data.peers?.length ?? 0} />
            </Card>
          </Col>
        </Row>

        {/* A meshnet IS an org, so which org this session enrolled into is part
            of its identity — without it the page looks identical no matter which
            org you are in, which is how a stale session went unnoticed. */}
        {orgMismatch && (
          <Alert
            type="warning"
            showIcon
            message={t("mesh.orgSwitching", { org: meshOrgName })}
          />
        )}
        <Card size="small">
          <Row gutter={[12, 8]}>
            <Col xs={24} md={8}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("mesh.org")}
              </Text>
              <div>
                <Text style={{ fontSize: 12 }}>{meshOrgName}</Text>
              </div>
            </Col>
            <Col xs={24} md={8}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("mesh.coord")}
              </Text>
              <div>
                <code style={{ fontSize: 12 }}>{data.coord || "—"}</code>
              </div>
            </Col>
            <Col xs={24} md={8}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("mesh.relay")}
              </Text>
              <div>
                <code style={{ fontSize: 12 }}>{data.relay || "—"}</code>
              </div>
            </Col>
          </Row>
        </Card>

        <Card
          title={t("mesh.peers")}
          size="small"
          extra={
            (data.peers || []).length > 5 ? (
              <Input
                allowClear
                size="small"
                style={{ width: 200 }}
                placeholder={t("mesh.peerFilter")}
                value={peerQuery}
                onChange={(e) => setPeerQuery(e.target.value)}
              />
            ) : undefined
          }
        >
          {data.up ? (
            <Table<MeshPeer>
              rowKey="public_key"
              size="small"
              pagination={false}
              columns={columns}
              dataSource={shownPeers}
              locale={{
                emptyText:
                  peerQuery && (data.peers || []).length > 0
                    ? t("mesh.peerFilterNoMatch")
                    : t("mesh.noPeers"),
              }}
            />
          ) : (
            <Empty description={t("mesh.connecting")} />
          )}
          {/* A footnote, not a warning: being unable to reach part of the org is
              the NORMAL outcome of access rules, not a fault. It is here because
              the alternative is silence — the table shows what you can reach and
              says nothing about what it left out, so "my colleague's machine is
              not in the list" reads as "it does not exist". */}
          {data.up && unreachableCount > 0 && (
            <div style={{ marginTop: 8 }}>
              <Text type="secondary" style={{ fontSize: 12 }}>
                {t("mesh.unreachableNote", { count: unreachableCount })}
              </Text>
            </div>
          )}
        </Card>
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {header}
      {body}
      <MeshAdvertiseCard />
    </div>
  );
}

// SettingRow is one capability: a title + one-line description on the left, a
// switch on the right, and (when enabled) its detail control revealed below —
// so the card stays compact and each toggle reads as a distinct choice.
function SettingRow({
  title,
  desc,
  checked,
  onChange,
  disabled,
  children,
}: {
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  children?: React.ReactNode;
}) {
  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 500 }}>{title}</div>
          <Text type="secondary" style={{ fontSize: 12 }}>
            {desc}
          </Text>
        </div>
        <Switch checked={checked} onChange={onChange} disabled={disabled} style={{ flexShrink: 0, marginTop: 2 }} />
      </div>
      {checked && children && <div style={{ marginTop: 10 }}>{children}</div>}
    </div>
  );
}

// CidrListEditor edits a list of prefixes as ROWS: type one, add it, and each
// entry gets its own delete button.
//
// It replaces a tags-in-a-box control, which made every entry a token in one
// shared field — easy to blow away the wrong one with a stray backspace, and
// nothing said a word about a malformed prefix until the whole form was saved
// and the daemon rejected it. Here a bad prefix can't even enter the list, and
// removing one can't touch its neighbours.
function CidrListEditor({
  value,
  onChange,
  placeholder,
  enforceWidth = true,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
  /** Apply the publish-side width limit. Off for the exclusion list. */
  enforceWidth?: boolean;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  const add = () => {
    const parsed = parseRoute(draft, enforceWidth);
    if (!parsed.ok) {
      // "too broad" gets its own message naming a /24 to use instead: the
      // generic "invalid" would leave the reader retyping the same thing.
      setErr(
        parsed.reason === "tooBroad"
          ? t("mesh.adv.routeTooBroad", { suggest: parsed.suggest })
          : t("mesh.adv.invalidCidr"),
      );
      return;
    }
    const norm = parsed.cidr;
    if (value.includes(norm)) {
      setErr(t("mesh.adv.dupCidr"));
      return;
    }
    onChange([...value, norm]);
    setDraft("");
    setErr("");
  };

  return (
    <div>
      <Space.Compact style={{ width: "100%", maxWidth: 420 }}>
        <Input
          value={draft}
          placeholder={placeholder}
          status={err ? "error" : undefined}
          onChange={(e) => {
            setDraft(e.target.value);
            if (err) setErr("");
          }}
          onPressEnter={(e) => {
            e.preventDefault(); // Enter here adds a row, it does not submit the card
            add();
          }}
        />
        <Button icon={<PlusOutlined />} onClick={add} disabled={!draft.trim()}>
          {t("mesh.adv.add")}
        </Button>
      </Space.Compact>
      {err && (
        <div style={{ marginTop: 4 }}>
          <Text type="danger" style={{ fontSize: 12 }}>
            {err}
          </Text>
        </div>
      )}
      <div style={{ marginTop: 8, maxWidth: 420 }}>
        {value.length === 0 ? (
          <Text type="secondary" style={{ fontSize: 12 }}>
            {t("mesh.adv.emptyList")}
          </Text>
        ) : (
          value.map((cidr) => (
            <div
              key={cidr}
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: 8,
                padding: "4px 8px",
                marginBottom: 4,
                borderRadius: 6,
                background: "rgba(255,255,255,0.04)",
              }}
            >
              <Text style={{ fontFamily: "monospace", fontSize: 13 }}>{formatRoute(cidr)}</Text>
              <Tooltip title={t("mesh.adv.remove")}>
                <Button
                  type="text"
                  size="small"
                  danger
                  icon={<DeleteOutlined />}
                  aria-label={`${t("mesh.adv.remove")} ${formatRoute(cidr)}`}
                  onClick={() => onChange(value.filter((v) => v !== cidr))}
                />
              </Tooltip>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// MeshAdvertiseCard is this node's routing settings, split into three tabs in
// the order they are usually reasoned about:
//
//   接受对端 — what this node takes FROM the mesh (off by default; an accepted
//              route lands in this machine's own routing table)
//   对外提供 — what it offers TO the mesh (subnet router / exit node)
//   本机出网 — where its own egress goes
//
// Accept comes first because it is the one that can break this machine, and the
// one whose default changed. All three save together — it is a single POST — so
// a tab with unsaved edits carries a dot, otherwise switching tabs would hide
// pending changes behind a Save button that looks idle.
//
// Hidden on daemons with no mesh controller (the GET 404s there). Forwarding is
// Linux-only; off Linux the offer tab warns that the node advertises but won't
// forward.
function MeshAdvertiseCard() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data, error } = useQuery<MeshAdvertise>({
    queryKey: ["mesh-advertise"],
    queryFn: api.meshAdvertise,
    retry: false,
  });
  // The ASSIGNED mapping, as opposed to the request above: the coordinator picks
  // the stand-in prefix, so it can only be read back from live status. Same query
  // key the page already polls, so this costs no extra fetch.
  const { data: live } = useQuery<MeshStatus>({
    queryKey: ["mesh"],
    queryFn: api.mesh,
    retry: false,
  });
  const assignedAliases = live?.subnet_aliases || [];
  // A capability of this machine, not a setting: every advertised route is
  // aliased where the host can install the rewrite. undefined = an older daemon
  // that does not report it, which must not render as "unsupported".
  const aliasSupported = data?.alias_supported;
  const refusedAliases = live?.unaliased_routes || [];
  const aliasBudget = live?.alias_budget_addrs || 0;
  const aliasUsed = live?.alias_used_addrs || 0;

  // Each switch gates its own inputs; the values persist while a switch is off
  // so toggling back doesn't lose what you typed.
  const [routesOn, setRoutesOn] = useState(false);
  const [routes, setRoutes] = useState<string[]>([]);
  const [exitNodeOn, setExitNodeOn] = useState(false);
  const [useExitOn, setUseExitOn] = useState(false);
  const [exitPeer, setExitPeer] = useState("");
  const [acceptOn, setAcceptOn] = useState(false);
  const [excludes, setExcludes] = useState<string[]>([]);
  const [blockIncoming, setBlockIncoming] = useState(false);
  useEffect(() => {
    if (!data) return;
    setRoutes(data.routes || []);
    setRoutesOn((data.routes || []).length > 0);
    setExitNodeOn(data.advertise_exit_node);
    setExitPeer(data.exit_node || "");
    setUseExitOn(!!data.exit_node);
    setAcceptOn(!!data.accept_routes);
    setExcludes(data.route_excludes || []);
    setBlockIncoming(!!data.block_incoming);
  }, [data]);

  const payload = {
    routes: routesOn ? routes : [],
    advertise_exit_node: exitNodeOn,
    exit_node: useExitOn ? exitPeer.trim() : "",
    accept_routes: acceptOn,
    // Kept even while accepting is off. The switch is a master toggle, not a
    // delete button: the exclusions are typed by hand, they are inert while the
    // switch is off, and they must come back intact when it goes on again.
    // Sending [] here meant flicking the switch off and on again silently lost
    // every exception — which is how a 192.168.1.0/24 exclusion disappeared and
    // put a LAN's traffic back out through the ISP.
    route_excludes: excludes,
    block_incoming: blockIncoming,
  };

  const save = useMutation({
    mutationFn: () => api.setMeshAdvertise(payload),
    onSuccess: () => {
      message.success(t("mesh.adv.saved"));
      qc.invalidateQueries({ queryKey: ["mesh-advertise"] });
      qc.invalidateQueries({ queryKey: ["mesh"] });
    },
    onError: (e) => message.error((e as Error).message),
  });

  if (error instanceof ApiError && error.status === 404) return null; // no mesh here
  if (!data) return null;

  const norm = (a: string[]) => [...a].sort().join(",");
  // Per-tab, so a tab holding unsaved edits can say so while you are looking at
  // another one.
  const acceptDirty =
    payload.accept_routes !== !!data.accept_routes ||
    payload.block_incoming !== !!data.block_incoming ||
    norm(payload.route_excludes) !== norm(data.route_excludes || []);
  const offerDirty =
    norm(payload.routes) !== norm(data.routes || []) ||
    payload.advertise_exit_node !== data.advertise_exit_node;
  const egressDirty = payload.exit_node !== (data.exit_node || "");
  const dirty = acceptDirty || offerDirty || egressDirty;

  // Only the "offer to the mesh" roles need OS packet forwarding (Linux-only for
  // now). Accepting routes and routing THIS node's own egress through an exit are
  // pure routing-table work, automated on Windows/macOS too, so neither is gated.
  //
  // Where forwarding is unavailable the two offer switches are locked OFF rather
  // than merely warned about: advertising without forwarding is not a degraded
  // mode, it is a blackhole — peers install a route pointing here and their
  // packets die in the tun, having also lost whatever path used to carry them.
  //
  // Locked on the SERVER's state, not the form's, so a role that is already on
  // (set by --advertise-routes, or on an older build) can still be switched OFF.
  // Otherwise this page would show a promise it cannot let anyone withdraw. The
  // API applies the same rule for real; see statusapi.newAdvertisementRefused.
  const alreadyAdvertising = (data.routes || []).length > 0 || data.advertise_exit_node;
  const routesLocked = !data.forwarding_supported && (data.routes || []).length === 0;
  const exitNodeLocked = !data.forwarding_supported && !data.advertise_exit_node;

  const label = (text: string, isDirty: boolean) => (
    <span>
      {text}
      {isDirty && (
        <Tooltip title={t("mesh.adv.unsaved")}>
          <span
            aria-label={t("mesh.adv.unsaved")}
            style={{
              display: "inline-block",
              width: 6,
              height: 6,
              borderRadius: 3,
              marginLeft: 6,
              verticalAlign: "middle",
              background: "#faad14",
            }}
          />
        </Tooltip>
      )}
    </span>
  );

  return (
    <Card title={t("mesh.adv.title")} size="small">
      <Tabs
        size="small"
        items={[
          {
            key: "accept",
            label: label(t("mesh.adv.acceptSection"), acceptDirty),
            children: (
              <Space direction="vertical" size={16} style={{ width: "100%" }}>
              {/* First, because it is the one that decides whether this machine
                  answers at all. Under the route list it would read as a detail
                  of routing, which it is not. */}
              <SettingRow
                title={t("mesh.adv.blockIncoming")}
                desc={t("mesh.adv.blockIncomingHelp")}
                checked={blockIncoming}
                onChange={setBlockIncoming}
              />
              <SettingRow
                title={t("mesh.adv.accept")}
                desc={t("mesh.adv.acceptHelp")}
                checked={acceptOn}
                onChange={setAcceptOn}
              >
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t("mesh.adv.excludes")}
                </Text>
                <div style={{ marginTop: 4 }}>
                  <CidrListEditor
                    value={excludes}
                    onChange={setExcludes}
                    placeholder="192.168.1.22"
                    enforceWidth={false}
                  />
                </div>
                <div style={{ marginTop: 6 }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("mesh.adv.excludesHelp")}
                  </Text>
                </div>
              </SettingRow>
              </Space>
            ),
          },
          {
            key: "offer",
            label: label(t("mesh.adv.offerSection"), offerDirty),
            children: (
              <Space direction="vertical" size={16} style={{ width: "100%" }}>
                {!data.forwarding_supported && (
                  <Alert
                    type="warning"
                    showIcon
                    message={t(alreadyAdvertising ? "mesh.adv.noForward" : "mesh.adv.noForwardLocked")}
                  />
                )}
                <SettingRow
                  title={t("mesh.adv.routes")}
                  desc={t("mesh.adv.routesHelp")}
                  checked={routesOn}
                  onChange={setRoutesOn}
                  disabled={routesLocked}
                >
                  <CidrListEditor
                    value={routes}
                    onChange={setRoutes}
                    placeholder="192.168.1.0/24 · 192.168.1.22"
                  />
                  {routesOn && routes.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <Text strong style={{ fontSize: 13 }}>
                        {t("mesh.adv.alias")}
                      </Text>
                      <div style={{ marginTop: 2 }}>
                        <Text type="secondary" style={{ fontSize: 12 }}>
                          {t("mesh.adv.aliasHelp")}
                        </Text>
                      </div>
                      {/* The capability warning and the assigned mapping are
                          INDEPENDENT, not an either/or. They used to be branches of
                          one ternary, so a host reported as incapable had its
                          mapping hidden — and when that report was wrong (see the
                          daemon-side tri-state in mesh/aliassupport.go) the operator
                          lost sight of a rewrite that was working. When it is right,
                          seeing "the coordinator assigned 100.96.0.0/24" next to
                          "this machine cannot install it" is the whole diagnosis. */}
                      {aliasSupported === false && (
                        <Alert
                          type="warning"
                          showIcon
                          style={{ marginTop: 8 }}
                          message={t("mesh.adv.aliasUnsupported")}
                          description={t("mesh.adv.aliasUnsupportedHelp")}
                        />
                      )}
                      {assignedAliases.length > 0 ? (
                        <div style={{ marginTop: 8 }}>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            {t("mesh.adv.aliasAssigned")}
                          </Text>
                          <div style={{ marginTop: 4 }}>
                            {assignedAliases.map((a) => (
                              <div key={a.alias} style={{ fontFamily: "monospace", fontSize: 12 }}>
                                {formatRoute(a.real)} → {formatRoute(a.alias)}
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : aliasSupported !== false && refusedAliases.length === 0 ? (
                        // "waiting for an address" is only true while one is
                        // coming. A host that cannot install the rewrite is not
                        // waiting for anything.
                        <div style={{ marginTop: 8 }}>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            {t("mesh.adv.aliasPending")}
                          </Text>
                        </div>
                      ) : null}
                      {refusedAliases.length > 0 && (
                        <Alert
                          type="warning"
                          showIcon
                          style={{ marginTop: 8 }}
                          message={t("mesh.adv.aliasRefused")}
                          description={
                            <div>
                              <div style={{ fontFamily: "monospace", fontSize: 12 }}>
                                {refusedAliases.map(formatRoute).join("  ")}
                              </div>
                              {aliasBudget > 0 && (
                                <div style={{ marginTop: 6, fontSize: 12 }}>
                                  {t("mesh.adv.aliasBudget", { used: aliasUsed, total: aliasBudget })}
                                </div>
                              )}
                            </div>
                          }
                        />
                      )}
                    </div>
                  )}
                </SettingRow>
                <SettingRow
                  title={t("mesh.adv.exitNode")}
                  desc={t("mesh.adv.exitNodeHelp")}
                  checked={exitNodeOn}
                  onChange={setExitNodeOn}
                  disabled={exitNodeLocked}
                />
              </Space>
            ),
          },
          {
            key: "egress",
            label: label(t("mesh.adv.egressSection"), egressDirty),
            children: (
              <SettingRow
                title={t("mesh.adv.useExit")}
                desc={t("mesh.adv.useExitHelp")}
                checked={useExitOn}
                onChange={setUseExitOn}
              >
                <Input
                  value={exitPeer}
                  onChange={(e) => setExitPeer(e.target.value)}
                  placeholder="node-b / 100.64.0.2"
                  allowClear
                  style={{ maxWidth: 320 }}
                />
              </SettingRow>
            ),
          },
        ]}
      />
      <div style={{ marginTop: 8 }}>
        <Button
          type="primary"
          size="small"
          loading={save.isPending}
          disabled={!dirty}
          onClick={() => save.mutate()}
        >
          {t("mesh.adv.save")}
        </Button>
      </div>
    </Card>
  );
}
