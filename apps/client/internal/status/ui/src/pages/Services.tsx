// Services.tsx — what THIS machine offers on the mesh.
//
// A declaration is a claim, not an authorization: the coordinator records it as
// pending and an admin confirms it in the web console before any access rule
// matches. That split is why this page shows no "approved" state — the daemon
// knows what it claimed, not what was decided about it.
//
// Entries from --mesh-service / the config file are read-only here: the file
// re-declares them at every restart, so removing one would just flip back.
//
// Lives on its own menu item rather than inside Connect: what this machine
// serves is a fact about the machine, and the Tools port scanner hands off to
// it directly.
import { useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Empty,
  Input,
  Popconfirm,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";

import { api } from "../api/client";
import type { MeshServiceDecl, TunnelList } from "../api/types";

const { Title, Text } = Typography;

// isLoopbackTarget reports whether a "host:port" points at loopback (127.x /
// localhost / ::1) — where the fix for "mesh can't reach it" is "bind 0.0.0.0",
// vs a LAN/remote host the mesh doesn't route to.
function isLoopbackTarget(target: string): boolean {
  const s = (target || "").trim().toLowerCase();
  if (!s) return true;
  const host = s.startsWith("[")
    ? s.slice(1, s.indexOf("]"))
    : s.slice(0, s.lastIndexOf(":") > 0 ? s.lastIndexOf(":") : s.length);
  return host === "localhost" || host === "::1" || host.startsWith("127.");
}

// originServiceName reads config_json.origin.mesh_service — the service a tunnel
// was published from (set by the wizard). Anything malformed or shaped
// differently just means "no origin". Mirrors the console's reader so the two
// agree on what a published tunnel looks like.
function originServiceName(configJSON?: string): string {
  if (!configJSON) return "";
  try {
    const o = JSON.parse(configJSON) as { origin?: { mesh_service?: unknown } };
    return typeof o?.origin?.mesh_service === "string" ? o.origin.mesh_service : "";
  } catch {
    return "";
  }
}

export default function Services() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [name, setName] = useState("");
  const [proto, setProto] = useState("tcp");
  const [port, setPort] = useState<number | null>(null);
  const [note, setNote] = useState("");
  const [adding, setAdding] = useState(false);

  const { data, isLoading } = useQuery<{ items: MeshServiceDecl[] }>({
    queryKey: ["mesh-services"],
    queryFn: api.meshServices,
    retry: false,
    // This list stopped being static config when it started carrying the self-
    // check. Editing it also restarts the mesh session, which drops the current
    // observations — so a fetch taken right after a save shows "—" for every
    // row and stays that way until a manual reload. Polling fills it back in on
    // its own, a second or two later.
    refetchInterval: 3_000,
  });
  const items = data?.items ?? [];

  // Which services are already published as a public tunnel. All tunnels here
  // belong to this device and a service name is unique on it, so matching by
  // origin.mesh_service alone is enough. Lets the row show "已发布" and drop the
  // publish button instead of letting a second click create a duplicate tunnel.
  const { data: tunnelData } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
    retry: false,
  });
  const publishedBy = useMemo(() => {
    const m = new Map<string, string>(); // service name -> tunnel name
    for (const tn of tunnelData?.items ?? []) {
      const svc = originServiceName(tn.config_json);
      if (svc) m.set(svc, tn.name);
    }
    return m;
  }, [tunnelData]);

  // The Tools port scanner hands off here (/mesh?declare_port=5432&declare_name=postgres)
  // so there is exactly one declaration form in the app.
  useEffect(() => {
    const p = Number(searchParams.get("declare_port") || 0);
    if (!p) return;
    setAdding(true);
    setPort(p);
    setName((prev) => prev || searchParams.get("declare_name") || "");
    const next = new URLSearchParams(searchParams);
    next.delete("declare_port");
    next.delete("declare_name");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const save = useMutation({
    mutationFn: (next: MeshServiceDecl[]) => api.setMeshServices(next),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["mesh-services"] });
      void qc.invalidateQueries({ queryKey: ["mesh"] });
    },
    onError: (e) => message.error((e as Error).message),
  });

  const onAdd = () => {
    const n = name.trim().toLowerCase();
    if (!n || !port) return;
    // The coordinator's rule, checked before the request. It SKIPS a name it
    // cannot use rather than rejecting it, so a name with a space in it would
    // be accepted here and then simply never appear in the web console. The
    // daemon validates too — this is so the message lands next to the field.
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(n)) {
      message.error(t("mesh.svc.nameInvalid"));
      return;
    }
    // Keep config-sourced entries in the payload; the daemon filters them out.
    save.mutate([...items, { name: n, proto, port, note: note.trim() }], {
      onSuccess: () => {
        message.success(t("mesh.svc.declared"));
        setAdding(false);
        setName("");
        setPort(null);
        setNote("");
      },
    });
  };

  const onRemove = (target: MeshServiceDecl) => {
    save.mutate(items.filter((s) => s.name !== target.name));
  };

  // Publish a service to the public: hand off to the new-tunnel wizard (on the
  // Tunnels page) pre-filled with the service's forwarding address, so there is
  // one create-tunnel form in the app. The address is the service's target, or
  // 127.0.0.1:<port> when it declared none — the same value a tunnel's
  // local_addr carries.
  const onPublish = (s: MeshServiceDecl) => {
    const addr = s.target && s.target.trim() ? s.target.trim() : `127.0.0.1:${s.port}`;
    const q = new URLSearchParams({
      publish_service: s.name,
      publish_addr: addr,
      publish_proto: s.proto,
    });
    navigate("/tunnels?" + q.toString());
  };

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Title level={4} style={{ margin: 0 }}>
        {t("nav.services")}
      </Title>

      <Card size="small" loading={isLoading}>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message={t("mesh.svc.intro")}
        description={t("mesh.svc.introDesc")}
      />
      {items.length === 0 && !adding && (
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={t("mesh.svc.empty")} />
      )}
      {items.length > 0 && (
        <Table<MeshServiceDecl>
          rowKey="name"
          size="small"
          pagination={false}
          dataSource={items}
          style={{ marginBottom: 12 }}
          columns={[
            { title: t("mesh.svc.colName"), dataIndex: "name" },
            {
              title: t("mesh.svc.colEndpoint"),
              render: (_v: unknown, r: MeshServiceDecl) => (
                <Space direction="vertical" size={0}>
                  <code style={{ fontSize: 12 }}>
                    {r.port}/{r.proto}
                  </code>
                  {/* Only when it differs from the default — the same value on
                      two lines just looks like a bug. */}
                  {!!r.target && r.target !== `127.0.0.1:${r.port}` && (
                    <Tooltip title={t("mesh.svc.targetTip")}>
                      <Text type="secondary" style={{ fontSize: 11 }}>
                        → {r.target}
                      </Text>
                    </Tooltip>
                  )}
                </Space>
              ),
            },
            {
              // The reason this machine's console shows reachability at all: the
              // "bound to 127.0.0.1" verdict is only actionable by whoever is at
              // this machine, and making them open the web console to find out
              // is backwards.
              title: t("mesh.svc.colReach"),
              width: 120,
              render: (_v: unknown, r: MeshServiceDecl) => {
                if (!r.checked) {
                  return (
                    <Tooltip title={t("mesh.svc.reachUnknownTip")}>
                      <Text type="secondary">—</Text>
                    </Tooltip>
                  );
                }
                if (r.target_ok && r.mesh_ok) {
                  return (
                    <Tooltip title={t("mesh.svc.reachOkTip")}>
                      <Tag color="green">{t("mesh.svc.reachOk")}</Tag>
                    </Tooltip>
                  );
                }
                if (r.target_ok) {
                  // Reachable where the device dials it, not on the mesh. A
                  // loopback target = "bind 0.0.0.0"; a LAN/remote target = the
                  // app is on another host the mesh doesn't route to.
                  const loop = isLoopbackTarget(r.target || `127.0.0.1:${r.port}`);
                  return (
                    <Tooltip
                      title={
                        loop
                          ? t("mesh.svc.reachLoopbackTip")
                          : t("mesh.svc.reachRemoteTip", {
                              target: r.target || `127.0.0.1:${r.port}`,
                            })
                      }
                    >
                      <Tag color="orange">{t("mesh.svc.reachLoopback")}</Tag>
                    </Tooltip>
                  );
                }
                return (
                  <Tooltip title={t("mesh.svc.reachDownTip")}>
                    <Tag color="red">{t("mesh.svc.reachDown")}</Tag>
                  </Tooltip>
                );
              },
            },
            {
              title: t("mesh.svc.colNote"),
              dataIndex: "note",
              render: (v?: string) => v || <Text type="secondary">—</Text>,
            },
            {
              title: t("common.actions"),
              width: 200,
              render: (_v: unknown, r: MeshServiceDecl) => (
                <Space size={4}>
                  {/* Publishing to the public is creating a tunnel to the
                      service's local address; it's independent of the mesh
                      confirmation (that gates svc: rules, not a public tunnel),
                      so it's offered on every row — the person at this machine
                      is the authority for its own public endpoints. Once a
                      tunnel already points here we show "已发布" instead, so a
                      second click can't create a duplicate. */}
                  {publishedBy.has(r.name) ? (
                    <Tooltip title={t("mesh.svc.publishedTip", { name: publishedBy.get(r.name) })}>
                      <Tag color="green">{t("mesh.svc.published")}</Tag>
                    </Tooltip>
                  ) : (
                    <Button size="small" type="link" onClick={() => onPublish(r)}>
                      {t("mesh.svc.publish")}
                    </Button>
                  )}
                  {r.from_console ? (
                    <Tooltip title={t("mesh.svc.fromConsoleTip")}>
                      <Tag>{t("mesh.svc.fromConsole")}</Tag>
                    </Tooltip>
                  ) : r.from_config ? (
                    <Tooltip title={t("mesh.svc.fromConfigTip")}>
                      <Tag>{t("mesh.svc.fromConfig")}</Tag>
                    </Tooltip>
                  ) : (
                    <Popconfirm
                      title={t("mesh.svc.removeConfirm", { name: r.name })}
                      okText={t("mesh.svc.remove")}
                      cancelText={t("common.cancel")}
                      onConfirm={() => onRemove(r)}
                    >
                      <Button size="small" type="link" danger loading={save.isPending}>
                        {t("mesh.svc.remove")}
                      </Button>
                    </Popconfirm>
                  )}
                </Space>
              ),
            },
          ]}
        />
      )}
      {adding ? (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Space wrap>
            <Input
              placeholder={t("mesh.svc.namePlaceholder")}
              value={name}
              maxLength={63}
              style={{ width: 180 }}
              onChange={(e) => setName(e.target.value)}
            />
            <Select
              value={proto}
              style={{ width: 90 }}
              onChange={setProto}
              options={[
                { value: "tcp", label: "TCP" },
                { value: "udp", label: "UDP" },
              ]}
            />
            <Input
              type="number"
              placeholder={t("mesh.svc.portPlaceholder")}
              value={port ?? ""}
              style={{ width: 120 }}
              onChange={(e) => setPort(Number(e.target.value) || null)}
            />
            <Input
              placeholder={t("mesh.svc.notePlaceholder")}
              value={note}
              maxLength={200}
              style={{ width: 220 }}
              onChange={(e) => setNote(e.target.value)}
            />
          </Space>
          <Space>
            <Button
              type="primary"
              loading={save.isPending}
              disabled={!name.trim() || !port}
              onClick={onAdd}
            >
              {t("mesh.svc.declare")}
            </Button>
            <Button onClick={() => setAdding(false)}>{t("common.cancel")}</Button>
          </Space>
        </Space>
      ) : (
        <Button type="link" style={{ padding: 0 }} onClick={() => setAdding(true)}>
          {t("mesh.svc.add")}
        </Button>
      )}
      </Card>
    </Space>
  );
}
