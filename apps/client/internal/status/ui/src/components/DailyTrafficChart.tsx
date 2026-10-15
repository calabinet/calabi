// DailyTrafficChart.tsx — stacked 隧道 / 中继 bars per day for the last N days
// (default 7). Data source: /v1/usage/daily?n=N (UsageHistory), server-side.
//
// Each bucket carries BOTH classes: the platform (billed) pair and the
// self-hosted pair (BYOI tunnel + "self-" relay egress). Both are recorded — a
// customer's own edge reports usage over the same push path as a platform one —
// so this chart FOLLOWS this machine the way the 今日 / 本月 cards above it do:
// the tunnel series tracks the edge this node egresses through, the relay series
// tracks the relay it homes on. Those are independent axes (own edge + platform
// relay is a real setup), which is why the bucket breaks relay egress out.
//
// Hole-punched DIRECT traffic is in neither and never can be: it touches no
// component that could meter it. The legend says so rather than leaving a gap
// between this chart and the machine's own counters.
//
// The buckets are an ORG aggregate and every member of the org may read them
// (bff-console usage.go). They briefly did not: a plain member's /usage/daily
// was 403'd for a fortnight in September 2026 while /usage/current handed the
// same caller a narrowed figure — the card said 本月 4.44 MB (this machine's
// local mesh meter) with 近 7 天合计 10.44 GB drawn underneath it. Both sides of
// that are now the org's, so the card and this chart answer the same question.
import { Card, Typography } from "antd";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type { MeshUsageDay, UsageBucket, UsageHistory } from "../api/types";
import { dayLabel, oldestFirst } from "../lib/usageDays";
import ChartFrame from "./ChartFrame";

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

// splitBucket picks the day's tunnel + relay figures for THIS machine.
//
// The pair for a class already contains that class's relay egress, so the tunnel
// figure is pair − ownRelay: a subtraction, never a second sum, so the chart and
// the bucket can't disagree about a total. Relay is then taken from whichever
// class the node actually homes on.
//
// Degrades on an older bff-console that predates these fields: the relay split
// reads 0, everything lands in the tunnel series, and the total stays correct.
// The self-hosted pair reads 0 there too — which is exactly the old behaviour
// this chart had, so a stale server looks like it used to rather than lying.
export function splitBucket(
  b: UsageBucket,
  selfHostedEdge: boolean,
  selfHostedRelay: boolean,
): { tunnel: number; relay: number } {
  const pair = selfHostedEdge ? b.self_hosted_bytes_total ?? 0 : b.bytes_total;
  const ownRelay =
    (selfHostedEdge ? b.self_hosted_relay_bytes_out : b.relay_bytes_out) ?? 0;
  const relay =
    (selfHostedRelay ? b.self_hosted_relay_bytes_out : b.relay_bytes_out) ?? 0;
  return { tunnel: Math.max(0, pair - ownRelay), relay };
}

export default function DailyTrafficChart({
  days = 7,
  selfHostedEdge = false,
  selfHostedRelay = false,
  localRelay,
}: {
  days?: number;
  /** This machine egresses through a self-hosted (BYOI) edge — same signal the
   *  今日 / 本月 cards use, passed down so both read the same class. */
  selfHostedEdge?: boolean;
  /** This machine homes on one of the org's own relays ("self-…" region). */
  selfHostedRelay?: boolean;
  /** Connected to a self-hosted server: the buckets are this machine's own
   *  tunnel meter and carry no relay of either class, so the relay series is
   *  the machine's mesh meter instead — its days, under the same local date the
   *  buckets use for `ts`. The 今日 / 本月 cards take their relay half from the
   *  same meter, so a day's bar and the card above it agree. */
  localRelay?: MeshUsageDay[];
}) {
  const { t } = useTranslation();
  const { data } = useQuery<UsageHistory>({
    queryKey: ["usage-daily", days],
    queryFn: () => api.usageDaily(days),
    refetchInterval: 60_000,
    retry: false,
  });

  // A bar chart reads left→right, so render oldest→newest — the two daemons
  // that answer this path disagree about the order they send (lib/usageDays).
  // The endpoint always returns exactly `days` buckets (gaps zero-filled), so a
  // slice keeps the window even if it ever returns more.
  const relayByDate = new Map((localRelay ?? []).map((d) => [d.date, d.relay]));
  const rows = oldestFirst(data?.buckets ?? [])
    .slice(-days)
    .map((b) => {
      const split = splitBucket(b, selfHostedEdge, selfHostedRelay);
      return {
        label: dayLabel(b.ts),
        tunnel: split.tunnel,
        relay: localRelay ? relayByDate.get(b.ts) ?? 0 : split.relay,
      };
    });
  const total = rows.reduce((s, r) => s + r.tunnel + r.relay, 0);

  return (
    <Card
      size="small"
      style={{ width: "100%", display: "flex", flexDirection: "column" }}
      bodyStyle={{ padding: 12, flex: 1, minHeight: 0, display: "flex" }}
      title={
        <span>
          {t("dailyChart.title", { n: days })}
          <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
            {t("dailyChart.total")} {fmtBytes(total)} · {t("dailyChart.noDirect")}
          </Text>
        </span>
      }
    >
      <ChartFrame>
        <BarChart data={rows} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="rgba(255,255,255,0.08)" />
          <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#94a3b8" }} />
          <YAxis tickFormatter={fmtBytes} width={64} tick={{ fontSize: 11, fill: "#94a3b8" }} />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.05)" }}
            formatter={(v: number) => fmtBytes(Number(v))}
            contentStyle={{ background: "#0b1022", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }}
            labelStyle={{ color: "#94a3b8" }}
            itemStyle={{ color: "#e2e8f0" }}
          />
          <Legend
            verticalAlign="top"
            height={20}
            iconSize={8}
            wrapperStyle={{ fontSize: 11, color: "#94a3b8" }}
          />
          <Bar
            dataKey="tunnel"
            stackId="a"
            name={t("dailyChart.tunnel")}
            fill="#3a5cff"
            maxBarSize={40}
          />
          <Bar
            dataKey="relay"
            stackId="a"
            name={t("dailyChart.relay")}
            fill="#22c1a4"
            radius={[3, 3, 0, 0]}
            maxBarSize={40}
          />
        </BarChart>
      </ChartFrame>
    </Card>
  );
}
