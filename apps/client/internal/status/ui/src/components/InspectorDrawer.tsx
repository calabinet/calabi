// InspectorDrawer.tsx — opens for one tunnel, shows:
//   - Recent connections (TCP-level)
//   - Recent HTTP captures (request/response with bodies)
//   - Replay button per HTTP capture
//
// Used by the Tunnels page when the user clicks "查看请求".
import {
  CaretRightOutlined,
  CodeOutlined,
  RetweetOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Collapse,
  Drawer,
  Empty,
  Modal,
  Space,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { ConnectionRow, HTTPCaptureRow } from "../api/types";

const { Text } = Typography;

interface Props {
  open: boolean;
  onClose: () => void;
  proxyID: string | null;
  tunnelName?: string;
}

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 2)} ${u[i]}`;
}

function statusColor(s?: number): string {
  if (!s) return "default";
  if (s < 300) return "success";
  if (s < 400) return "processing";
  if (s < 500) return "warning";
  return "error";
}

export default function InspectorDrawer({ open, onClose, proxyID, tunnelName }: Props) {
  const { t } = useTranslation();
  const [replayResult, setReplayResult] = useState<{ id: number; res: any } | null>(null);

  const { data: conns } = useQuery<{ items: ConnectionRow[] }>({
    queryKey: ["connections", proxyID],
    queryFn: () => api.inspectConnections(proxyID!),
    enabled: open && !!proxyID,
    refetchInterval: open ? 3_000 : false,
  });
  const { data: caps } = useQuery<{ items: HTTPCaptureRow[] }>({
    queryKey: ["captures", proxyID],
    queryFn: () => api.inspectCaptures(proxyID!),
    enabled: open && !!proxyID,
    refetchInterval: open ? 3_000 : false,
  });

  const replay = useMutation({
    mutationFn: (capID: number) => api.replay(proxyID!, capID),
    onSuccess: (res, capID) => {
      setReplayResult({ id: capID, res });
    },
    onError: (e: any) => message.error(e.message || t("inspector.replayFailed")),
  });

  return (
    <Drawer
      title={
        <span>
          <CodeOutlined style={{ marginRight: 6 }} />
          {t("inspector.title", { name: tunnelName || proxyID })}
        </span>
      }
      open={open}
      onClose={onClose}
      width={624}
      destroyOnClose
    >
      <Tabs
        defaultActiveKey="captures"
        items={[
          {
            key: "captures",
            // `?? []` guards against a server response of {items:null}
            // (older daemon binaries returned that for tunnels with no
            // traffic, which blew up .length and blanked the drawer).
            label: t("inspector.httpTab", { n: (caps?.items ?? []).length }),
            children: (
              <CapturesPane
                rows={caps?.items ?? []}
                onReplay={(id) => replay.mutate(id)}
                isReplaying={replay.isPending}
              />
            ),
          },
          {
            key: "conns",
            label: t("inspector.connsTab", { n: (conns?.items ?? []).length }),
            children: <ConnectionsPane rows={conns?.items ?? []} />,
          },
        ]}
      />

      <Modal
        open={!!replayResult}
        onCancel={() => setReplayResult(null)}
        onOk={() => setReplayResult(null)}
        title={t("inspector.replayResultTitle")}
        width={680}
        footer={null}
      >
        {replayResult && (
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <div>
              <Tag color={statusColor(replayResult.res.status)}>
                HTTP {replayResult.res.status}
              </Tag>
              <Text type="secondary" style={{ marginLeft: 8 }}>
                → {replayResult.res.target}
              </Text>
            </div>
            <Collapse
              defaultActiveKey={["body"]}
              items={[
                {
                  key: "body",
                  label: t("inspector.responseBody"),
                  children: (
                    <pre
                      style={{
                        background: "rgba(255,255,255,0.04)",
                        padding: 10,
                        borderRadius: 4,
                        maxHeight: 360,
                        overflow: "auto",
                        fontSize: 12,
                      }}
                    >
                      {replayResult.res.body || t("inspector.empty")}
                    </pre>
                  ),
                },
              ]}
            />
          </Space>
        )}
      </Modal>
    </Drawer>
  );
}

function CapturesPane({
  rows,
  onReplay,
  isReplaying,
}: {
  rows: HTTPCaptureRow[];
  onReplay: (id: number) => void;
  isReplaying: boolean;
}) {
  const { t } = useTranslation();
  if (rows.length === 0) {
    return (
      <Empty
        description={
          <span>
            {t("inspector.noHttp")}
            <br />
            <Text type="secondary" style={{ fontSize: 12 }}>
              {t("inspector.noHttpHint")}
            </Text>
          </span>
        }
      />
    );
  }
  return (
    <Collapse
      accordion
      ghost
      items={rows.map((r) => ({
        key: String(r.id),
        label: (
          <Space size="small">
            <Tag color={statusColor(r.response_status)}>
              {r.response_status || "—"}
            </Tag>
            <Text strong>{r.method}</Text>
            <code style={{ fontSize: 12 }}>{r.path}</code>
            {r.duration_ms !== undefined && (
              <Text type="secondary" style={{ fontSize: 11 }}>
                {r.duration_ms}ms
              </Text>
            )}
            {r.error && (
              <Tag color="error">{t("inspector.errorTag")}</Tag>
            )}
          </Space>
        ),
        extra: (
          <Tooltip title={t("inspector.replayTip")}>
            <Button
              size="small"
              icon={<RetweetOutlined />}
              loading={isReplaying}
              onClick={(e) => {
                e.stopPropagation();
                onReplay(r.id);
              }}
            >
              {t("inspector.replayBtn")}
            </Button>
          </Tooltip>
        ),
        children: <CaptureDetail row={r} />,
      }))}
    />
  );
}

function CaptureDetail({ row }: { row: HTTPCaptureRow }) {
  const { t } = useTranslation();
  return (
    <Space direction="vertical" size="small" style={{ width: "100%" }}>
      {row.error && <Alert showIcon type="warning" message={row.error} />}
      <KVTable title={t("inspector.requestHeaders")} rows={row.request_headers} />
      {row.request_body && (
        <details>
          <summary>
            <Text type="secondary">
              <CaretRightOutlined />{" "}
              {t("inspector.requestBody", { n: row.request_body.length })}
            </Text>
          </summary>
          <pre style={preStyle}>{row.request_body}</pre>
        </details>
      )}
      <KVTable title={t("inspector.responseHeaders")} rows={row.response_headers} />
      {row.response_body && (
        <details open>
          <summary>
            <Text type="secondary">
              <CaretRightOutlined />{" "}
              {t("inspector.responseBodyChars", { n: row.response_body.length })}
            </Text>
          </summary>
          <pre style={preStyle}>{row.response_body}</pre>
        </details>
      )}
    </Space>
  );
}

const preStyle: React.CSSProperties = {
  background: "#0f172a",
  color: "#d1d5db",
  padding: 10,
  borderRadius: 4,
  maxHeight: 280,
  overflow: "auto",
  fontSize: 12,
  whiteSpace: "pre-wrap",
};

function KVTable({ title, rows }: { title: string; rows?: Record<string, string> }) {
  if (!rows || Object.keys(rows).length === 0) return null;
  return (
    <div>
      <Text type="secondary" style={{ fontSize: 12 }}>
        {title}
      </Text>
      <table style={{ width: "100%", fontSize: 12, marginTop: 4 }}>
        <tbody>
          {Object.entries(rows).map(([k, v]) => (
            <tr key={k}>
              <td style={{ padding: "2px 8px", color: "#64748b", verticalAlign: "top" }}>
                {k}
              </td>
              <td style={{ padding: "2px 8px", wordBreak: "break-all" }}>
                <code style={{ fontSize: 11 }}>{v}</code>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ConnectionsPane({ rows }: { rows: ConnectionRow[] }) {
  const { t } = useTranslation();
  if (rows.length === 0) {
    return <Empty description={t("inspector.noConns")} />;
  }
  return (
    <Table<ConnectionRow>
      rowKey="id"
      size="small"
      pagination={{ pageSize: 20, showSizeChanger: false }}
      dataSource={rows}
      columns={[
        {
          title: t("inspector.colStartTime"),
          dataIndex: "started_at",
          render: (s) => (
            <Text style={{ fontSize: 12 }}>{new Date(s).toLocaleTimeString()}</Text>
          ),
          width: 100,
        },
        {
          title: t("inspector.colVisitorIp"),
          dataIndex: "visitor_ip",
          render: (v) => <code>{v || "—"}</code>,
          width: 130,
        },
        {
          title: t("inspector.colDuration"),
          dataIndex: "duration_ms",
          render: (v) => (v !== undefined ? `${v}ms` : <Tag>{t("common.inProgress")}</Tag>),
          width: 100,
        },
        {
          title: "↓ in",
          dataIndex: "bytes_in",
          render: fmtBytes,
          width: 80,
        },
        {
          title: "↑ out",
          dataIndex: "bytes_out",
          render: fmtBytes,
          width: 80,
        },
        {
          title: t("inspector.colError"),
          dataIndex: "error",
          render: (e) =>
            e ? (
              <Tooltip title={e}>
                <Tag color="error">err</Tag>
              </Tooltip>
            ) : (
              "—"
            ),
        },
      ]}
    />
  );
}
