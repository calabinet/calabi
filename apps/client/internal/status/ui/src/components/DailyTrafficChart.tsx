// DailyTrafficChart.tsx — bar chart of total transferred bytes per day for the
// last N days (default 7). Data source: /v1/usage/daily?n=N (UsageHistory).
// Works on both editions: standalone serves it from the local usage meter,
// platform proxies it to bff-console / metering-svc.
import { Card, Typography } from "antd";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { UsageHistory } from "../api/types";

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

// dayLabel turns a bucket ts into a short "M/D" tick. The standalone meter
// emits "2026-06-14"; the platform emits an ISO timestamp — new Date() parses
// both; on parse failure we show the raw string.
function dayLabel(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

export default function DailyTrafficChart({ days = 7 }: { days?: number }) {
  const { t } = useTranslation();
  const { data } = useQuery<UsageHistory>({
    queryKey: ["usage-daily", days],
    queryFn: () => api.usageDaily(days),
    refetchInterval: 60_000,
    retry: false,
  });
  // /v1/usage/daily returns buckets NEWEST-first (i=0 = today). A bar chart
  // reads left→right, so render them oldest→newest (chronological) — otherwise
  // the x-axis runs backwards (6/13 … 6/7). slice() first so we don't mutate
  // the react-query cache in place.
  const rows = (data?.buckets ?? [])
    .slice()
    .reverse()
    .map((b) => ({
      label: dayLabel(b.ts),
      bytes: b.bytes_total,
    }));
  const total = rows.reduce((s, r) => s + r.bytes, 0);

  return (
    <Card
      size="small"
      style={{ width: "100%", display: "flex", flexDirection: "column" }}
      bodyStyle={{ padding: 12, flex: 1, minHeight: 0 }}
      title={
        <span>
          {t("dailyChart.title", { n: days })}
          <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
            {t("dailyChart.total")} {fmtBytes(total)}
          </Text>
        </span>
      }
    >
      <div style={{ width: "100%", height: "100%", minHeight: 140 }}>
        <ResponsiveContainer>
          <BarChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.08)" />
            <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#94a3b8" }} />
            <YAxis tickFormatter={fmtBytes} width={64} tick={{ fontSize: 11, fill: "#94a3b8" }} />
            <Tooltip
              cursor={{ fill: "rgba(255,255,255,0.05)" }}
              formatter={(v: number) => [fmtBytes(Number(v)), t("dailyChart.tooltip")]}
              contentStyle={{ background: "#0b1022", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }}
              labelStyle={{ color: "#94a3b8" }}
              itemStyle={{ color: "#e2e8f0" }}
            />
            <Bar dataKey="bytes" fill="#3a5cff" radius={[3, 3, 0, 0]} maxBarSize={48} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
