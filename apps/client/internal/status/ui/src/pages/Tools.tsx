// Tools.tsx — diagnostics page (M7-S5). Currently hosts the port
// scanner; future probes (DNS lookup, TLS chain check, network MTU)
// would land here as additional cards.
import {
  PlusOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { Alert, Button, Card, Space, Table, Tag, Tooltip, Typography } from "antd";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { ProbePort } from "../api/types";
import { useTranslation } from "react-i18next";

const { Title, Text } = Typography;

export default function Tools() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [enabled, setEnabled] = useState(false);

  const { data, isFetching, refetch } = useQuery<{ items: ProbePort[] }>({
    queryKey: ["probe-ports"],
    queryFn: api.probePorts,
    enabled,
    refetchInterval: false,
  });

  // Declaring a mesh service reuses the Connect page's form rather than
  // duplicating one here — same shape as the tunnel hand-off below.
  function declareService(r: ProbePort) {
    const q = new URLSearchParams({ declare_port: String(r.port) });
    if (r.hint) q.set("declare_name", r.hint);
    navigate("/services?" + q.toString());
  }

  function go(port: number) {
    // Open the new-tunnel wizard pre-filled by passing through query.
    // For simplicity, just navigate; the user can paste the port into
    // the wizard. Future: deep-link to the wizard with a prefill state.
    navigate("/tunnels?prefill_port=" + port);
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      <Title level={4} style={{ margin: 0 }}>
        {t("tools.title")}
      </Title>

      <Card
        size="small"
        title={
          <span>
            <ThunderboltOutlined style={{ marginRight: 6 }} />
            {t("tools.portScanTitle")}
          </span>
        }
        extra={
          enabled ? (
            <Button
              icon={<ReloadOutlined />}
              loading={isFetching}
              onClick={() => refetch()}
            >
              {t("tools.rescan")}
            </Button>
          ) : (
            <Button type="primary" onClick={() => setEnabled(true)}>
              {t("tools.startScan")}
            </Button>
          )
        }
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message={t("tools.scanInfo")}
          description={t("tools.scanInfoDesc")}
        />
        {!enabled && <Text type="secondary">{t("tools.clickStart")}</Text>}
        {enabled && (
          <Table<ProbePort>
            rowKey="port"
            size="small"
            pagination={false}
            loading={isFetching}
            dataSource={data?.items ?? []}
            locale={{
              emptyText: isFetching
                ? t("tools.scanning")
                : t("tools.noPortsFound"),
            }}
            columns={[
              {
                title: t("tools.colPort"),
                dataIndex: "port",
                width: 100,
                render: (p) => <code style={{ fontSize: 13 }}>{p}</code>,
              },
              {
                // The bind address is the one fact that explains a "loopback
                // only" verdict at a glance — and the thing the dial scan could
                // never see. Only the enumerated scan fills it in; the dial
                // fallback leaves it blank.
                title: t("tools.colBind"),
                dataIndex: "bind_addrs",
                width: 150,
                render: (addrs?: string[]) =>
                  addrs && addrs.length ? (
                    <Space direction="vertical" size={0}>
                      {addrs.map((a) => (
                        <code key={a} style={{ fontSize: 12 }}>
                          {a}
                        </code>
                      ))}
                    </Space>
                  ) : (
                    <Text type="secondary">—</Text>
                  ),
              },
              {
                // The port scan dials LOOPBACK, so "listening" alone says
                // nothing about whether a mesh peer could reach it. This column
                // is the difference between a service others can use and one
                // only this machine can.
                title: t("tools.colMeshReach"),
                dataIndex: "mesh_reachable",
                width: 130,
                render: (_v: unknown, r: ProbePort) =>
                  !r.mesh_probed ? (
                    <Tooltip title={t("tools.meshNotProbedTip")}>
                      <Text type="secondary">—</Text>
                    </Tooltip>
                  ) : r.mesh_reachable ? (
                    <Tag color="green">{t("tools.meshReachable")}</Tag>
                  ) : (
                    <Tooltip title={t("tools.meshLoopbackOnlyTip")}>
                      <Tag color="orange">{t("tools.meshLoopbackOnly")}</Tag>
                    </Tooltip>
                  ),
              },
              {
                title: t("tools.colLatency"),
                dataIndex: "latency_ms",
                width: 100,
                render: (n) => `${n}ms`,
              },
              {
                title: t("common.actions"),
                width: 230,
                render: (_v, r) => (
                  <Space size={4}>
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() => go(r.port)}
                    >
                      {t("tools.createTunnelBtn")}
                    </Button>
                    {/* Offered even when the port is loopback-only: the operator
                        may be about to fix the binding, and the Connect form
                        repeats the warning. Hiding it would just be confusing. */}
                    <Button
                      size="small"
                      icon={<PlusOutlined />}
                      onClick={() => declareService(r)}
                    >
                      {t("tools.declareServiceBtn")}
                    </Button>
                  </Space>
                ),
              },
            ]}
          />
        )}
      </Card>
    </Space>
  );
}
