// Tools.tsx — diagnostics page (M7-S5). Currently hosts the port
// scanner; future probes (DNS lookup, TLS chain check, network MTU)
// would land here as additional cards.
import {
  PlusOutlined,
  ReloadOutlined,
  ThunderboltOutlined,
} from "@ant-design/icons";
import { Alert, Button, Card, Space, Table, Tag, Typography } from "antd";
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
                title: t("tools.colPurpose"),
                dataIndex: "hint",
                render: (h) =>
                  h ? <Tag color="blue">{h}</Tag> : <Text type="secondary">—</Text>,
              },
              {
                title: t("tools.colLatency"),
                dataIndex: "latency_ms",
                width: 100,
                render: (n) => `${n}ms`,
              },
              {
                title: t("common.actions"),
                width: 130,
                render: (_v, r) => (
                  <Button
                    size="small"
                    type="primary"
                    icon={<PlusOutlined />}
                    onClick={() => go(r.port)}
                  >
                    {t("tools.createTunnelBtn")}
                  </Button>
                ),
              },
            ]}
          />
        )}
      </Card>
    </Space>
  );
}
