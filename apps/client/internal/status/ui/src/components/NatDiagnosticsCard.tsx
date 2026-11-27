import {
  EyeInvisibleOutlined,
  EyeOutlined,
  GlobalOutlined,
  ReloadOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Space,
  Spin,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { HolePunchVerdict, NatType, NetCheckReport } from "../api/types";

const { Text } = Typography;

export function maskIpAddress(ip: string): string {
  if (!ip) return "";
  if (ip.includes(".")) {
    const parts = ip.split(".");
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.***.***`;
  }
  if (ip.includes(":")) {
    const parts = ip.split(":");
    return `${parts.slice(0, 2).join(":")}:****:****`;
  }
  return "***";
}

function natTagColor(natType: NatType | undefined): string {
  switch (natType) {
    case "open":
    case "full_cone":
      return "green";
    case "restricted_cone":
    case "port_restricted_cone":
    case "cone":
      return "blue";
    case "symmetric":
      return "orange";
    case "udp_blocked":
      return "red";
    default:
      return "default";
  }
}

function verdictAlertType(
  verdict: HolePunchVerdict | undefined,
): "success" | "info" | "warning" | "error" {
  switch (verdict) {
    case "direct":
    case "supported":
      return "success";
    case "limited":
      return "warning";
    case "blocked":
      return "error";
    default:
      return "info";
  }
}

export default function NatDiagnosticsCard() {
  const { t } = useTranslation();
  const [maskPublic, setMaskPublic] = useState(true);

  const { data, isPending, isFetching, isError, error, refetch } =
    useQuery<NetCheckReport>({
      queryKey: ["netcheck"],
      queryFn: api.netcheck,
      staleTime: 60_000,
      refetchInterval: false,
      retry: false,
    });

  const natType: NatType = data?.nat_type ?? "unknown";
  const verdict: HolePunchVerdict = data?.hole_punch ?? "unknown";
  const publicDisplay = data?.public_ip
    ? maskPublic
      ? maskIpAddress(data.public_ip)
      : data.public_ip
    : "";
  const ipv6Display = data?.ipv6
    ? maskPublic
      ? maskIpAddress(data.ipv6)
      : data.ipv6
    : "";

  const matrixRows = [
    {
      key: "nat1",
      type: t("tools.nat.types.full_cone"),
      punch: t("tools.nat.matrix.nat1Punch"),
      note: t("tools.nat.matrix.nat1Note"),
    },
    {
      key: "nat2",
      type: t("tools.nat.types.restricted_cone"),
      punch: t("tools.nat.matrix.nat2Punch"),
      note: t("tools.nat.matrix.nat2Note"),
    },
    {
      key: "nat3",
      type: t("tools.nat.types.port_restricted_cone"),
      punch: t("tools.nat.matrix.nat3Punch"),
      note: t("tools.nat.matrix.nat3Note"),
    },
    {
      key: "nat4",
      type: t("tools.nat.types.symmetric"),
      punch: t("tools.nat.matrix.nat4Punch"),
      note: t("tools.nat.matrix.nat4Note"),
    },
  ];

  return (
    <Card
      size="small"
      title={
        <span>
          <GlobalOutlined style={{ marginRight: 6 }} />
          {t("tools.nat.title")}
        </span>
      }
      extra={
        <Button
          icon={<ReloadOutlined />}
          loading={isFetching}
          onClick={() => void refetch()}
        >
          {t("tools.nat.recheck")}
        </Button>
      }
    >
      {isError && (
        <Alert
          type="error"
          showIcon
          message={t("tools.nat.error")}
          description={(error as Error)?.message}
        />
      )}

      {isPending && !isError && (
        <div style={{ padding: "16px 0", textAlign: "center" }}>
          <Spin />
          <div style={{ marginTop: 8 }}>
            <Text type="secondary">{t("tools.nat.probing")}</Text>
          </div>
        </div>
      )}

      {data && (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <Alert
            type={verdictAlertType(verdict)}
            showIcon
            message={
              <Space size={8} wrap>
                <Tag color={natTagColor(natType)} style={{ marginInlineEnd: 0 }}>
                  {t(`tools.nat.types.${natType}`)}
                </Tag>
                <Text strong>{t(`tools.nat.verdicts.${verdict}`)}</Text>
              </Space>
            }
            description={
              <Space direction="vertical" size={2} style={{ width: "100%" }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t(`tools.nat.typeDesc.${natType}`)}
                </Text>
                {data.detail === "single_stun_server" && (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("tools.nat.singleStunHint")}
                  </Text>
                )}
              </Space>
            }
          />

          <Descriptions
            bordered
            size="small"
            column={1}
            styles={{ label: { width: 150 } }}
            items={[
              {
                key: "overlay",
                label: t("tools.nat.overlayIp"),
                children: data.overlay_ip ? (
                  <Text code copyable={{ text: data.overlay_ip }}>
                    {data.overlay_ip}
                  </Text>
                ) : (
                  <Text type="secondary">{t("tools.nat.notConnected")}</Text>
                ),
              },
              {
                key: "local",
                label: t("tools.nat.localIp"),
                children: data.local_ip ? (
                  <Space size={8} wrap>
                    <Text code copyable={{ text: data.local_ip }}>
                      {data.local_ip}
                    </Text>
                    {(data.local_ips ?? [])
                      .filter((ip) => ip !== data.local_ip)
                      .slice(0, 2)
                      .map((ip) => (
                        <Text key={ip} type="secondary" code>
                          {ip}
                        </Text>
                      ))}
                  </Space>
                ) : (
                  <Text type="secondary">—</Text>
                ),
              },
              {
                key: "public",
                label: t("tools.nat.publicIp"),
                children: data.public_ip ? (
                  <Space size={8} wrap>
                    <Text code copyable={{ text: data.public_ip }}>
                      {publicDisplay}
                    </Text>
                    {!maskPublic && data.public_port ? (
                      <Text type="secondary" style={{ fontSize: 12 }}>
                        :{data.public_port}
                      </Text>
                    ) : null}
                    <Tooltip
                      title={t(
                        maskPublic
                          ? "tools.nat.showPublicIp"
                          : "tools.nat.hidePublicIp",
                      )}
                    >
                      <Button
                        type="text"
                        size="small"
                        icon={
                          maskPublic ? (
                            <EyeOutlined />
                          ) : (
                            <EyeInvisibleOutlined />
                          )
                        }
                        aria-label={t(
                          maskPublic
                            ? "tools.nat.showPublicIp"
                            : "tools.nat.hidePublicIp",
                        )}
                        onClick={() => setMaskPublic((v) => !v)}
                      />
                    </Tooltip>
                  </Space>
                ) : (
                  <Text type="secondary">—</Text>
                ),
              },
              ...(data.ipv6
                ? [
                    {
                      key: "ipv6",
                      label: t("tools.nat.ipv6"),
                      children: (
                        <Text code copyable={{ text: data.ipv6 }}>
                          {ipv6Display}
                        </Text>
                      ),
                    },
                  ]
                : []),
            ]}
          />

          <Collapse
            ghost
            size="small"
            items={[
              {
                key: "matrix",
                label: (
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("tools.nat.matrixTitle")}
                  </Text>
                ),
                children: (
                  <Table
                    size="small"
                    pagination={false}
                    rowKey="key"
                    dataSource={matrixRows}
                    columns={[
                      {
                        title: t("tools.nat.matrix.colType"),
                        dataIndex: "type",
                        width: 190,
                      },
                      {
                        title: t("tools.nat.matrix.colPunch"),
                        dataIndex: "punch",
                        width: 140,
                      },
                      {
                        title: t("tools.nat.matrix.colNote"),
                        dataIndex: "note",
                      },
                    ]}
                  />
                ),
              },
            ]}
          />
        </Space>
      )}
    </Card>
  );
}
