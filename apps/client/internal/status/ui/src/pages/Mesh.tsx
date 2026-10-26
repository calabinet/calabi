// Mesh.tsx — Connect (WireGuard mesh) status for the local node.
//
// Read-only view over GET /v1/mesh (polled), plus a Stop control (POST
// /v1/mesh/down, local-token). Mesh runs inside the local daemon when its
// config has a `mesh:` block (see daemon_local_mesh.go); this page surfaces the
// node's overlay IP, coordinator/relay, and each peer's live WireGuard state
// (handshake age + bytes), the same data `calabi mesh status` prints.
//
// Four tabs under one heading, each at its own URL:
//
//   设备 /mesh          — this machine's state and the peers it can reach
//   服务 /mesh/services — ports it offers to the mesh (pages/Services.tsx)
//   文件传送 /mesh/files — ordinary-user file transfer center
//   网络设置 /mesh/routing — subnets / exit device it offers, subnets it accepts
//
// 服务 and 路由 are the same question at two sizes — what this machine offers
// the mesh, one port or a whole subnet — which is why they sit side by side.
// The web console's 组网配置 uses the same 设备 / 服务 split.
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  Dropdown,
  Drawer,
  Descriptions,
  Popover,
  Input,
  message,
  Popconfirm,
  Row,
  Space,
  Spin,
  Statistic,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  DeleteOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";

import { api, ApiError } from "../api/client";
import { hasNativeFiles, fileAction, useFileSupport } from "../api/files";
import { fileTargets } from "../lib/fileTargets";
import { fileRecords, fileRecordMatches } from "../lib/fileRecords";
import ListSearch from "../components/ListSearch";
import MeshGlyph, { deviceGlyph } from "../components/MeshGlyph";
import "../styles/mesh-center.css";
import {
  exitStanding,
  formatRoute,
  parseRoute,
  routeStanding,
  type RouteReport,
  type RouteStanding,
} from "../lib/cidr";
import { matchesListSearch } from "../lib/listSearch";
import { relayOwner, relayOwnerKind } from "../lib/relayRegion";
import { peerAddresses } from "../lib/peerAddresses";
import { peerPresence } from "../lib/peerPresence";
import { useLocation, useNavigate } from "react-router-dom";
import Services from "./Services";
import Files from "./Files";

import type {
  AccountMe,
  MeshAdvertise,
  MeshOrgNode,
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
  const fileSupport = useFileSupport();
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const tab = pathname.startsWith("/mesh/services")
    ? "services"
    : pathname.startsWith("/mesh/routing")
      ? "routing"
      : pathname.startsWith("/mesh/files")
        ? "files"
        : "devices";
  // Peer filter. A fleet of 20 machines turns this table into scrolling, and the
  // thing you arrive knowing is the machine's NAME — so match on that first,
  // then on the address you might have pasted from somewhere, then on the key
  // for the case where you came from `wg show` or a log line.
  const [peerQuery, setPeerQuery] = useState("");
  const [connectionKey, setConnectionKey] = useState("");
  const files = useQuery({ queryKey: ["user-files"], queryFn: () => fileAction({ action: "snapshot" }), enabled: fileSupport.data === true && hasNativeFiles(), refetchInterval: 1000, retry: false });
  const [peerDetail, setPeerDetail] = useState<{ key: string; section: "routes" | "services" } | null>(null);
  const setPeerDetailOpen = (peer: MeshPeer, section: "routes" | "services", open: boolean) => {
    setPeerDetail((current) => open ? { key: peer.public_key, section } :
      current?.key === peer.public_key && current.section === section ? null : current);
  };
  useEffect(() => {
    if (!peerDetail) return;
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === "Escape") setPeerDetail(null); };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [peerDetail]);
  useEffect(() => { setPeerDetail(null); setConnectionKey(""); }, [pathname]);

  const { data, error, isLoading } = useQuery<MeshStatus>({
    queryKey: ["mesh"],
    queryFn: api.mesh,
    refetchInterval: 3_000,
    retry: false,
    // Keep the last status visible across the 3s refetches so a poll never blanks
    // the page back to a skeleton/empty state.
    placeholderData: keepPreviousData,
  });
  useEffect(() => {
    if (peerDetail && data && (!data.up || !data.peers?.some((peer) => peer.public_key === peerDetail.key))) {
      setPeerDetail(null);
    }
  }, [data, peerDetail]);

  useEffect(() => {
    if (connectionKey && data && (!data.up || !data.peers?.some(peer => peer.public_key === connectionKey))) setConnectionKey("");
  }, [connectionKey, data]);

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

  // The node list also carries authoritative presence. Never reuse another
  // organization's cached presence or infer offline from idle WG traffic.
  const presenceScope = snap?.active_org_id || orgsResp?.active_org_id || 0;
  const presenceEnabled = !!data?.up && !(presenceScope && data.org_id && presenceScope !== data.org_id);
  const nodesQuery = useQuery({
    queryKey: ["mesh-org-nodes", presenceScope, data?.org_id || 0],
    queryFn: api.meshOrgNodes,
    enabled: presenceEnabled,
    staleTime: 5_000,
    refetchInterval: 5_000,
    retry: false,
    throwOnError: false,
  });
  const orgNodes = presenceEnabled ? nodesQuery.data : undefined;
  const presenceCurrent = presenceEnabled && nodesQuery.isSuccess && Date.now() - nodesQuery.dataUpdatedAt < 15_000;
  const presenceOf = (peer: MeshPeer) => peerPresence(peer.allowed_ips, presenceCurrent ? orgNodes?.items : undefined);
  const ownerByOverlay = useMemo(() => {
    const m = new Map<string, string>();
    for (const n of orgNodes?.items ?? []) {
      if (n.overlay && n.owner_email) m.set(n.overlay, n.owner_email);
    }
    return m;
  }, [orgNodes]);


  // Same query key the 路由 tab's card uses, so it costs no extra fetch. The
  // 设备 tab needs it for one thing: a machine that is refusing every inbound
  // connection looks EXACTLY like a healthy one there — up, addressed, peers
  // listed — and the switch that did it is on another tab. A setting whose
  // effect is invisible from the page it breaks is a support call.
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
  // Whose relay this device is homed on, read off the region code. Only the
  // platform has two kinds to tell apart; a device signed in to a self-hosted
  // server gets the region and the address with no owner on them. (`me` is
  // already cached by the Layout under the same key.)
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });
  const standalone = me?.plan?.code === "standalone";
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
    return all.filter(p => matchesListSearch(peerQuery, p.name, p.public_key,
      ...(p.allowed_ips || []), ...(p.services || []).map(service => service.name),
      ownerByOverlay.get(peerAddresses(p.allowed_ips).overlay)));
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
          const owner = ownerByOverlay.get(peerAddresses(p.allowed_ips).overlay);
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
        title: t("mesh.peerDetails.overlay"),
        key: "overlay",
        width: 150,
        render: (_: unknown, p: MeshPeer) => {
          const { overlay } = peerAddresses(p.allowed_ips);
          return overlay ? <Text copyable={{ text: overlay }} style={{ whiteSpace: "nowrap" }}>{overlay}</Text> : <Text type="secondary">—</Text>;
        },
      },
      {
        title: t("mesh.colAllowed"),
        key: "allowed",
        width: 110,
        render: (_: unknown, p: MeshPeer) => {
          const { routes, exits } = peerAddresses(p.allowed_ips);
          const open = peerDetail?.key === p.public_key && peerDetail.section === "routes";
          return routes.length > 0 || exits.length > 0 ? <PeerDetailsPopover peer={p} section="routes" open={open}
            onOpenChange={(visible) => setPeerDetailOpen(p, "routes", visible)}>
            <Button type="link" size="small" aria-expanded={open} aria-haspopup="dialog">
              {routes.length > 0 ? t("mesh.peerDetails.routes", { count: routes.length }) : t("mesh.peerDetails.exitDevice")}
            </Button>
          </PeerDetailsPopover> : <Text type="secondary">—</Text>;
        },
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
        width: 100,
        render: (_: unknown, p: MeshPeer) => {
          const svcs = p.services ?? [];
          if (svcs.length === 0) return <Text type="secondary">—</Text>;
          const open = peerDetail?.key === p.public_key && peerDetail.section === "services";
          return <PeerDetailsPopover peer={p} section="services" open={open}
            onOpenChange={(visible) => setPeerDetailOpen(p, "services", visible)}>
            <Button type="link" size="small" aria-expanded={open} aria-haspopup="dialog">
              {t("mesh.peerDetails.services", { count: svcs.length })}
            </Button>
          </PeerDetailsPopover>;
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
          if (presenceOf(p) === "offline") return <Text type="secondary">—</Text>;
          const direct = p.path === "direct";
          const rtt = direct && p.rtt_micros ? fmtRtt(p.rtt_micros) : "";
          // The relay leg, shown ONLY when relayed. Prefixed with "→" and labelled
          // separately in the tooltip: it is this node to the relay, while the
          // direct figure is this node to the peer. Same column, deliberately not
          // the same presentation.
          const relayRtt = !direct && p.relay_rtt_micros ? fmtRtt(p.relay_rtt_micros) : "";
          // WHOSE relay carries it. A relayed peer is reached through that peer's
          // own home relay, not this device's — so with an org that runs a relay
          // next to the platform's, this column and the "home relay" card above
          // routinely name two different machines. Both used to say only "relay":
          // the card showed one address, the tooltip here another, and nothing
          // said they were different things. Unknown (an older daemon) stays a
          // bare "relay" rather than guessing an owner, and so does every relay
          // of a self-hosted server, where there is one kind only.
          const owner = direct ? null : relayOwner(p.relay_region);
          const kind = relayOwnerKind(owner, standalone);
          const ownerKind = kind ? t(kind === "self" ? "topbar.egressOwn" : "topbar.egressPlatform") : "";
          return (
            <Tooltip
              title={
                p.endpoint ? (
                  <>
                    {!direct && (
                      <>
                        {t("mesh.peerRelay")}
                        {owner ? (ownerKind ? ` · ${ownerKind} · ${owner.label}` : ` · ${owner.label}`) : ""}
                        <br />
                      </>
                    )}
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
                    {!direct && (
                      <>
                        <br />
                        <span style={{ opacity: 0.75 }}>{t("mesh.peerRelayTip")}</span>
                      </>
                    )}
                  </>
                ) : undefined
              }
            >
              <span>
                <Tag color={direct ? "green" : "default"} style={{ marginInlineEnd: rtt || relayRtt ? 4 : undefined }}>
                  {direct
                    ? t("mesh.pathDirect")
                    : kind
                      ? t(kind === "self" ? "mesh.pathRelaySelf" : "mesh.pathRelayPlatform")
                      : t("mesh.pathRelay")}
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
    [t, ownerByOverlay, standalone, peerDetail, presenceCurrent, orgNodes],
  );

  const receivers = fileTargets(data?.up ? data.peers || [] : [], files.data?.peers || []);
  const activeFiles = fileRecords(files.data || { jobs: [], received: [] }).filter(row => fileRecordMatches(row, "active"));
  const pendingFiles = files.data?.received.filter(row => row.transfer.state === "waiting").length || 0;
  const connectionPeer = data?.up ? data.peers?.find(peer => peer.public_key === connectionKey) : undefined;

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
          icon={<MeshGlyph name="play" />}
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
            <Button danger icon={<MeshGlyph name="power" />} loading={stop.isPending}>
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
        <Row className="mesh-status-cards" gutter={[12, 12]}>
          <Col xs={12} md={6}>
            <Card size="small">
              <Statistic
                title={t("mesh.state")}
                value={data.up ? t("mesh.stateUp") : t("mesh.stateDown")}
                className={data.up ? "mesh-status-up" : "mesh-status-down"}
              />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card size="small">
              <Statistic title={t("mesh.overlay")} value={data.overlay || "—"} className="mesh-status-identity" />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card size="small">
              <Statistic title={t("mesh.node")} value={data.name || "—"} className="mesh-status-identity" />
            </Card>
          </Col>
          <Col xs={12} md={6}>
            <Card size="small">
              <Statistic title={t("mesh.peers")} value={data.peers?.length || 0} />
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
        <section className="mesh-peer-section">
          <div className="mesh-peer-heading list-toolbar"><Text>{t("files.peerDevices")}</Text><ListSearch placeholder={t("listSearch.devices")} value={peerQuery} onChange={setPeerQuery} /></div>
          {data.up ? <Table<MeshPeer> size="middle" rowKey="public_key" dataSource={shownPeers} pagination={{ pageSize: 20, showSizeChanger: false }} scroll={{ x: 600 }} locale={{ emptyText: peerQuery && (data.peers || []).length > 0 ? t("mesh.peerFilterNoMatch") : t("mesh.noPeers") }} columns={[
            { title: t("mesh.colPeer"), key: "device", render: (_, peer) => <div className="mesh-device-name"><span className="files-file-icon"><MeshGlyph name={deviceGlyph(peer.os)} /></span><div><div className="mesh-device-label-row"><Text className="mesh-device-label">{peer.name || shortKey(peer.public_key)}</Text><Tooltip title={t(`mesh.presence.${presenceOf(peer)}Hint`)}><span className={`mesh-peer-presence ${presenceOf(peer)}`}>{t(`mesh.presence.${presenceOf(peer)}`)}</span></Tooltip></div><div className="mesh-device-meta"><span className="files-secondary">{[osLabel(peer.os), ownerByOverlay.get(peerAddresses(peer.allowed_ips).overlay)?.split("@")[0]].filter(Boolean).join(" · ")}</span><span className="mesh-device-capabilities">
              {peerAddresses(peer.allowed_ips).routes.length > 0 && <Tooltip title={t("mesh.peerHasSubnets")}><Button className="mesh-capability" type="text" size="small" aria-label={t("mesh.peerHasSubnets")} icon={<MeshGlyph name="network" />} onClick={() => setConnectionKey(peer.public_key)} /></Tooltip>}
              {!!peer.services?.length && <Tooltip title={t("mesh.peerHasServices")}><Button className="mesh-capability" type="text" size="small" aria-label={t("mesh.peerHasServices")} icon={<MeshGlyph name="service" />} onClick={() => setConnectionKey(peer.public_key)} /></Tooltip>}
            </span></div></div></div> },
            { title: t("mesh.peerDetails.overlay"), key: "overlay", width: 160, render: (_, peer) => <code>{peerAddresses(peer.allowed_ips).overlay || "—"}</code> },
            { title: t("files.connection"), key: "connection", width: 170, render: (_, peer) => presenceOf(peer) === "offline" ? <Text type="secondary">—</Text> : <span className={peer.path === "direct" ? "mesh-device-direct" : ""}>{peer.path === "direct" ? t("mesh.pathDirect") : t("mesh.pathRelay")}{peer.path === "direct" && peer.rtt_micros ? ` · ${fmtRtt(peer.rtt_micros)}` : peer.path !== "direct" && peer.relay_rtt_micros ? ` · ${fmtRtt(peer.relay_rtt_micros)}` : ""}</span> },
            ...columns.filter(column => column.key === "traffic").map(column => ({ ...column, width: 150 })),
            { key: "actions", width: 48, render: (_, peer) => {
              const address = peerAddresses(peer.allowed_ips).overlay;
              const receiver = receivers.find(target => target.key === peer.public_key);
              const ready = receiver?.status === "ready";
              return <Dropdown trigger={["click"]} menu={{ items: [
                ...(fileSupport.data ? [{ key: "send", icon: <MeshGlyph name="send" />, label: <Tooltip trigger={["hover", "focus"]} title={!ready ? t(`files.targetStatus.${receiver?.status || "notReady"}`) : undefined}><span tabIndex={!ready ? 0 : undefined} className="mesh-send-menu-label">{t("files.send")}</span></Tooltip>, disabled: !ready, onClick: () => navigate(`/mesh/files?device=${encodeURIComponent(peer.public_key)}`, { state: { fileTarget: { key: peer.public_key, name: peer.name || "", ip: address } } }) }] : []),
                { key: "details", icon: <MeshGlyph name="info" />, label: t("files.connectionDetails"), onClick: () => setConnectionKey(peer.public_key) },
              ] }}><Button type="text" icon={<MeshGlyph name="more" />} aria-label={t("files.deviceActions", { device: peer.name || address })} /></Dropdown>;
            } },
          ]} /> : <Empty description={t("mesh.connecting")} />}
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
        </section>
        {fileSupport.data && (activeFiles.length > 0 || pendingFiles > 0) && <div className="mesh-transfer-strip"><MeshGlyph name="transfer" /><div><Text>{activeFiles.length > 0 ? t("files.activeCount", { count: activeFiles.length }) : t("files.pendingCount", { count: pendingFiles })}</Text><span className="files-secondary">{activeFiles[0]?.direction === "outgoing" ? activeFiles[0].job.progress.transfer.name : activeFiles[0]?.received.transfer.name}</span></div><Button type="link" onClick={() => navigate("/mesh/files")}>{t("files.viewRecords")}</Button></div>}
      </div>
    );
  }

  return (
    <div className="mesh-center" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      {header}
      {fileSupport.error && tab !== "files" && <Alert type="warning" showIcon message={t("files.bridgeUnavailable")} description={fileSupport.error.message} action={<Button onClick={() => fileSupport.refetch()}>{t("files.retry")}</Button>} />}
      <Drawer rootClassName="mesh-connection-drawer" open={!!connectionPeer} onClose={() => { setPeerDetail(null); setConnectionKey(""); }} title={t("files.connectionDetails")} width={600}>
        {connectionPeer && <Space direction="vertical" size={24} style={{ width: "100%" }}>
          <span className={`mesh-peer-presence ${presenceOf(connectionPeer)}`}>{t(`mesh.presence.${presenceOf(connectionPeer)}`)}</span>
          <div className="mesh-device-name"><span className="files-file-icon"><MeshGlyph name={deviceGlyph(connectionPeer.os)} /></span><div><Text strong>{connectionPeer.name || shortKey(connectionPeer.public_key)}</Text><span className="files-secondary">{osLabel(connectionPeer.os)}</span></div></div>
          <Descriptions bordered size="small" column={1} items={[
            { key: "overlay", label: t("mesh.peerDetails.overlay"), children: <Text copyable>{peerAddresses(connectionPeer.allowed_ips).overlay || "—"}</Text> },
            { key: "key", label: t("files.deviceKey"), children: <Text copyable className="mesh-key">{connectionPeer.public_key}</Text> },
            ...columns.filter(column => ["path", "handshake", "traffic"].includes(column.key)).map(column => ({ key: column.key, label: column.title, children: column.render(("dataIndex" in column ? connectionPeer[column.dataIndex as keyof MeshPeer] : undefined) as never, connectionPeer) })),
          ]} />
          <section><Title level={5}>{t("mesh.colAllowed")}</Title><Table size="small" pagination={false} rowKey="prefix" dataSource={[...peerAddresses(connectionPeer.allowed_ips).routes, ...peerAddresses(connectionPeer.allowed_ips).exits].map(prefix => ({ prefix }))} columns={[
            { title: t("mesh.colAllowed"), dataIndex: "prefix", render: prefix => <Text code copyable>{prefix}</Text> },
            { title: t("files.routeType"), key: "kind", width: 120, render: (_, row) => <Text type="secondary">{row.prefix === "0.0.0.0/0" || row.prefix === "::/0" ? t("mesh.peerDetails.exitDevice") : t("files.subnet")}</Text> },
          ]} locale={{ emptyText: t("mesh.peerDetails.noSubnets") }} /></section>
          <section><Title level={5}>{t("mesh.colServices")}</Title><Table size="small" pagination={false} scroll={{ x: 450 }} rowKey={service => `${service.name}/${service.proto}/${service.port}`} dataSource={connectionPeer.services || []} locale={{ emptyText: t("files.noServices") }} columns={[
            { title: t("mesh.colServices"), dataIndex: "name" },
            { title: t("mesh.peerDetails.protocol"), dataIndex: "proto", width: 80 },
            { title: t("mesh.peerDetails.address"), key: "address", render: (_, service) => { const ip = peerAddresses(connectionPeer.allowed_ips).overlay; return ip ? <Text code copyable>{`${ip}:${service.port}`}</Text> : <Text type="secondary">—</Text>; } },
          ]} /></section>
        </Space>}
      </Drawer>
      {/* Panes as Tabs children, not rendered by hand off `tab`: antd keeps a
          visited pane mounted while another is shown. The 路由 card holds its
          edits in local state until Save, and they used to share a page with
          the peer list — glancing back at 设备 must not throw them away. */}
      <Tabs
        activeKey={tab}
        onChange={(k) => navigate(k === "devices" ? "/mesh" : `/mesh/${k}`)}
        tabBarStyle={{ marginBottom: 12 }}
        items={[
          { key: "devices", label: t("mesh.tabs.devices"), children: body },
          { key: "services", label: t("mesh.tabs.services"), children: <Services /> },
          ...(fileSupport.data || tab === "files" ? [{ key: "files", label: t("files.title"), children: <Files /> }] : []),
          { key: "routing", label: t("mesh.tabs.routing"), children: <MeshAdvertiseCard /> },
        ]}
      />
    </div>
  );
}

function PeerDetailsPopover({ peer, section, open, onOpenChange, children }: {
  peer: MeshPeer; section: "routes" | "services"; open: boolean;
  onOpenChange: (open: boolean) => void; children: React.ReactElement;
}) {
  const { t } = useTranslation();
  const { overlay, routes, exits } = peerAddresses(peer?.allowed_ips);
  const name = peer.name || shortKey(peer.public_key);
  const title = t(section === "routes" ? "mesh.peerDetails.routesTitle" : "mesh.peerDetails.servicesTitle", { device: name });
  return <Popover open={open} onOpenChange={onOpenChange} trigger="click" placement="bottomLeft" autoAdjustOverflow destroyOnHidden
    title={<div style={{ width: section === "routes" ? 280 : 420, maxWidth: "calc(100vw - 56px)", overflowWrap: "anywhere" }}>{title}</div>}
    content={<div role="dialog" aria-label={title} style={{ width: section === "routes" ? 280 : 420,
      maxWidth: "calc(100vw - 56px)", maxHeight: "min(320px, 50vh)", overflow: "auto" }}>
    {section === "routes" ? (
      <Space direction="vertical" size={8} style={{ width: "100%" }}>
        {routes.length === 0 ? <Text type="secondary">{t("mesh.peerDetails.noSubnets")}</Text> : routes.map((route) => <Text key={route} code copyable={{ text: route }}>{route}</Text>)}
        {exits.length > 0 && <Space direction="vertical" size={8}>
          <Text strong>{t("mesh.peerDetails.exitDevice")}</Text>
          <Space>{exits.map((exit) => <Tag key={exit}>{exit === "::/0" ? "IPv6" : "IPv4"}</Tag>)}</Space>
        </Space>}
      </Space>
    ) : (
      <Table scroll={{ x: "max-content" }} size="small" pagination={false}
        rowKey={(service) => `${service.name}/${service.proto}/${service.port}`} dataSource={peer.services || []}
        columns={[
          { title: t("mesh.colServices"), dataIndex: "name" },
          { title: t("mesh.peerDetails.protocol"), dataIndex: "proto" },
          { title: t("mesh.peerDetails.address"), render: (_: unknown, service: { name: string; proto: string; port: number }) => {
            const address = overlay ? `${overlay}:${service.port}` : "";
            return address ? <Text code copyable={{ text: address }}>{address}</Text> : <Text type="secondary">—</Text>;
          } },
        ]} />
    )}
    </div>}>
    {children}
  </Popover>;
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

// StandingTag says where one of this machine's own offers stands with the
// coordinator: published, or still waiting for an admin.
//
// The row it sits on reads the same either way — "192.168.1.0/24" is what this
// machine ASKED for, before approval and after — so a subnet nobody could reach
// yet looked exactly like one that worked.
function StandingTag({ standing, exit = false }: { standing: RouteStanding; exit?: boolean }) {
  const { t } = useTranslation();
  let color: string | undefined;
  let label: string;
  let tip: string;
  switch (standing) {
    case "published":
      color = "green";
      label = t(exit ? "mesh.adv.stateApproved" : "mesh.adv.stateLive");
      tip = t(exit ? "mesh.adv.tipExitApproved" : "mesh.adv.tipLive");
      break;
    case "pending":
      color = "orange";
      label = t("mesh.adv.statePending");
      tip = t(exit ? "mesh.adv.tipExitPending" : "mesh.adv.tipPending");
      break;
    case "unsaved":
      label = t("mesh.adv.stateUnsaved");
      tip = t("mesh.adv.tipUnsaved");
      break;
    case "offline":
      label = t("mesh.adv.stateOffline");
      tip = t("mesh.adv.tipOffline");
      break;
    default:
      label = t("mesh.adv.stateChecking");
      tip = t("mesh.adv.tipChecking");
  }
  return (
    <Tooltip title={tip}>
      <Tag color={color} style={{ margin: 0, fontSize: 11, flexShrink: 0 }}>
        {label}
      </Tag>
    </Tooltip>
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
  rowExtra,
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
  /** Apply the publish-side width limit. Off for the exclusion list. */
  enforceWidth?: boolean;
  /** Rendered on each row, before its delete button. */
  rowExtra?: (cidr: string) => React.ReactNode;
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
              <Text style={{ fontFamily: "monospace", fontSize: 13, flex: 1, minWidth: 0 }}>
                {formatRoute(cidr)}
              </Text>
              {rowExtra?.(cidr)}
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
// It is the whole of 组网 → 路由, so it no longer hides itself: on a daemon with
// no mesh controller (the GET 404s there) it says so, in the words the 设备 tab
// uses. Forwarding is Linux-only; off Linux the offer tab warns that the node
// advertises but won't forward.
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
  // Already cached by the Layout under the same key. Used for one thing: saying
  // WHERE a waiting route gets approved — a self-hosted server has no web console.
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });
  const standalone = me?.plan?.code === "standalone";
  // The org's device list, for one fact about THIS machine: whether it has been
  // let in at all. An org can auto-approve routes and still review devices, and a
  // device waiting for that review is in nobody's netmap — so a route the
  // coordinator already approved reaches no one, and "published" would be wrong.
  //
  // Same key the 设备 tab reads. Polled only while the answer is "waiting": that
  // is the one state that has to notice by itself that it ended.
  const selfPendingIn = (items?: MeshOrgNode[]) =>
    !!live?.overlay &&
    (items ?? []).some((n) => n.overlay === live.overlay && n.approved === false);
  const { data: orgNodes } = useQuery({
    queryKey: ["mesh-org-nodes"],
    queryFn: api.meshOrgNodes,
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
    refetchInterval: (q) => (selfPendingIn(q.state.data?.items) ? 5_000 : false),
  });
  const devicePending = selfPendingIn(orgNodes?.items);

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

  if (error instanceof ApiError && error.status === 404) {
    return (
      <Card size="small">
        <Empty description={t("mesh.unavailable")} />
      </Card>
    );
  }
  if (!data) {
    return (
      <Card size="small" loading={!error}>
        {error && <Empty description={(error as Error).message} />}
      </Card>
    );
  }

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

  // Where each offer stands with the coordinator. Saving is only the request:
  // on the platform a route takes effect once an admin approves it, and this
  // page reads the same before and after unless it says which is which.
  const report: RouteReport = {
    up: !!live?.up,
    netmapSeen: !!live?.netmap_seen,
    // A device that is itself waiting to be let in publishes nothing, whatever
    // the coordinator has approved for it.
    published: devicePending ? [] : live?.published_routes || [],
  };
  const standingOf = (cidr: string) => routeStanding(cidr, data.routes || [], report);
  const pendingCount = routesOn ? routes.filter((r) => standingOf(r) === "pending").length : 0;
  const anyPublished = routesOn && routes.some((r) => standingOf(r) === "published");
  const exitState = exitStanding(data.advertise_exit_node, report);
  const pendingWhere = devicePending
    ? t("mesh.adv.pendingDevice")
    : t(standalone ? "mesh.adv.pendingWhereSelfHosted" : "mesh.adv.pendingWhere");

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

  // No card title: the 路由 tab above already names it.
  return (
    <Card size="small">
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
                    rowExtra={(cidr) => <StandingTag standing={standingOf(cidr)} />}
                  />
                  {pendingCount > 0 && (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginTop: 8, maxWidth: 560 }}
                      message={t("mesh.adv.pendingTitle", { count: pendingCount })}
                      description={pendingWhere}
                    />
                  )}
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
                      ) : aliasSupported !== false &&
                        refusedAliases.length === 0 &&
                        (anyPublished || pendingCount > 0) ? (
                        // "waiting for an address" is only true while one is
                        // coming. A host that cannot install the rewrite is not
                        // waiting for anything — and neither is a route no admin
                        // has approved: the coordinator assigns nothing until
                        // then, so that line used to name the wrong party.
                        <div style={{ marginTop: 8 }}>
                          <Text type="secondary" style={{ fontSize: 12 }}>
                            {t(anyPublished ? "mesh.adv.aliasPending" : "mesh.adv.aliasAfterApproval")}
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
                >
                  <Space size={8} align="start">
                    <StandingTag standing={exitState} exit />
                    {exitState === "pending" && (
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        {pendingWhere}
                      </Text>
                    )}
                  </Space>
                </SettingRow>
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
