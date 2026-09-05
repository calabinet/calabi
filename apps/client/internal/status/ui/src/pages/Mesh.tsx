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
import { normalizeCidr } from "../lib/cidr";
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

function shortKey(k: string): string {
  return k.length > 16 ? k.slice(0, 16) + "…" : k;
}

export default function Mesh() {
  const { t } = useTranslation();
  const qc = useQueryClient();

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
  const unavailable = error instanceof ApiError && error.status === 404;

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
  const settling = data === undefined && (isLoading || (unavailable && !graceOver));

  const columns = useMemo(
    () => [
      {
        title: t("mesh.colPeer"),
        dataIndex: "public_key",
        key: "peer",
        render: (k: string) => <code style={{ fontSize: 12 }}>{shortKey(k)}</code>,
      },
      {
        title: t("mesh.colAllowed"),
        dataIndex: "allowed_ips",
        key: "allowed",
        render: (ips: string[]) => (ips || []).map((ip) => <Tag key={ip}>{ip}</Tag>),
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
                  </>
                ) : undefined
              }
            >
              <span>
                <Tag color={direct ? "green" : "default"} style={{ marginInlineEnd: rtt ? 4 : undefined }}>
                  {direct ? t("mesh.pathDirect") : t("mesh.pathRelay")}
                </Tag>
                {rtt ? (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {rtt}
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
    [t],
  );

  const header = (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <Title level={4} style={{ margin: 0 }}>
        {t("mesh.title")}
      </Title>
      {data?.paused ? (
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

        <Card title={t("mesh.peers")} size="small">
          {data.up ? (
            <Table<MeshPeer>
              rowKey="public_key"
              size="small"
              pagination={false}
              columns={columns}
              dataSource={data.peers || []}
              locale={{ emptyText: t("mesh.noPeers") }}
            />
          ) : (
            <Empty description={t("mesh.connecting")} />
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
  children,
}: {
  title: string;
  desc: string;
  checked: boolean;
  onChange: (v: boolean) => void;
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
        <Switch checked={checked} onChange={onChange} style={{ flexShrink: 0, marginTop: 2 }} />
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
}: {
  value: string[];
  onChange: (v: string[]) => void;
  placeholder: string;
}) {
  const { t } = useTranslation();
  const [draft, setDraft] = useState("");
  const [err, setErr] = useState("");

  const add = () => {
    const norm = normalizeCidr(draft);
    if (!norm) {
      setErr(t("mesh.adv.invalidCidr"));
      return;
    }
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
              <Text style={{ fontFamily: "monospace", fontSize: 13 }}>{cidr}</Text>
              <Tooltip title={t("mesh.adv.remove")}>
                <Button
                  type="text"
                  size="small"
                  danger
                  icon={<DeleteOutlined />}
                  aria-label={`${t("mesh.adv.remove")} ${cidr}`}
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

  // Each switch gates its own inputs; the values persist while a switch is off
  // so toggling back doesn't lose what you typed.
  const [routesOn, setRoutesOn] = useState(false);
  const [routes, setRoutes] = useState<string[]>([]);
  const [exitNodeOn, setExitNodeOn] = useState(false);
  const [useExitOn, setUseExitOn] = useState(false);
  const [exitPeer, setExitPeer] = useState("");
  const [acceptOn, setAcceptOn] = useState(false);
  const [excludes, setExcludes] = useState<string[]>([]);
  useEffect(() => {
    if (!data) return;
    setRoutes(data.routes || []);
    setRoutesOn((data.routes || []).length > 0);
    setExitNodeOn(data.advertise_exit_node);
    setExitPeer(data.exit_node || "");
    setUseExitOn(!!data.exit_node);
    setAcceptOn(!!data.accept_routes);
    setExcludes(data.route_excludes || []);
  }, [data]);

  const payload = {
    routes: routesOn ? routes : [],
    advertise_exit_node: exitNodeOn,
    exit_node: useExitOn ? exitPeer.trim() : "",
    accept_routes: acceptOn,
    // Exclusions only mean anything while accepting; sending them when the whole
    // switch is off would quietly keep a list the UI no longer shows.
    route_excludes: acceptOn ? excludes : [],
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
    norm(payload.route_excludes) !== norm(data.route_excludes || []);
  const offerDirty =
    norm(payload.routes) !== norm(data.routes || []) ||
    payload.advertise_exit_node !== data.advertise_exit_node;
  const egressDirty = payload.exit_node !== (data.exit_node || "");
  const dirty = acceptDirty || offerDirty || egressDirty;

  // Only the "offer to the mesh" roles need OS packet forwarding (Linux-only for
  // now). Accepting routes and routing THIS node's own egress through an exit are
  // pure routing-table work, automated on Windows/macOS too, so neither must trip
  // the no-forwarding warning.
  const forwardingRoleActive = routesOn || exitNodeOn;

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
                  <CidrListEditor value={excludes} onChange={setExcludes} placeholder="192.168.1.22/32" />
                </div>
                <div style={{ marginTop: 6 }}>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("mesh.adv.excludesHelp")}
                  </Text>
                </div>
              </SettingRow>
            ),
          },
          {
            key: "offer",
            label: label(t("mesh.adv.offerSection"), offerDirty),
            children: (
              <Space direction="vertical" size={16} style={{ width: "100%" }}>
                {forwardingRoleActive && !data.forwarding_supported && (
                  <Alert type="warning" showIcon message={t("mesh.adv.noForward")} />
                )}
                <SettingRow
                  title={t("mesh.adv.routes")}
                  desc={t("mesh.adv.routesHelp")}
                  checked={routesOn}
                  onChange={setRoutesOn}
                >
                  <CidrListEditor value={routes} onChange={setRoutes} placeholder="192.168.1.0/24" />
                </SettingRow>
                <SettingRow
                  title={t("mesh.adv.exitNode")}
                  desc={t("mesh.adv.exitNodeHelp")}
                  checked={exitNodeOn}
                  onChange={setExitNodeOn}
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
