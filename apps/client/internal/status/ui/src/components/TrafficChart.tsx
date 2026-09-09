// TrafficChart.tsx — rolling line chart of throughput over time.
//
// Data model: we keep the last 60 samples (one per snapshot poll at ~2s
// intervals = a 2-minute rolling window) of an ALREADY-MEASURED rate.
//
// This component used to take the cumulative byte total and do the differencing
// itself. It got the denominator wrong — see lib/rate.ts for the full account —
// and printed spikes of several GB/s on links that top out around 20 Mbit/s.
// Those spikes were read as real bursts. Measuring is now the caller's job
// (useCounterRate, one per polled source, each against its own clock); this file
// only plots.
import { useEffect, useRef, useState } from "react";
import { Card, Typography } from "antd";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useTranslation } from "react-i18next";

const { Text } = Typography;

interface Props {
  /** Bytes per second, measured by the caller. */
  rate: number;
  /**
   * Timestamp of the sample that produced `rate`, and the effect key: one point
   * is appended per distinct value. Driving the chart off the sample's identity
   * rather than the rate's VALUE is what keeps an idle link plotting real zeros
   * instead of holding its last reading on screen.
   */
  sampleAt: number;
  title?: string;
}

const MAX_POINTS = 60;

function fmtRate(bps: number): string {
  if (bps < 1024) return `${bps.toFixed(0)} B/s`;
  if (bps < 1024 * 1024) return `${(bps / 1024).toFixed(1)} KB/s`;
  if (bps < 1024 * 1024 * 1024) return `${(bps / 1024 / 1024).toFixed(1)} MB/s`;
  return `${(bps / 1024 / 1024 / 1024).toFixed(2)} GB/s`;
}

export default function TrafficChart({ rate, sampleAt, title }: Props) {
  const { t } = useTranslation();
  const displayTitle = title || t("trafficChart.title");
  const [points, setPoints] = useState<{ t: number; bps: number }[]>([]);
  const plottedRef = useRef(0);

  useEffect(() => {
    if (!sampleAt || sampleAt === plottedRef.current) return;
    plottedRef.current = sampleAt;
    const bps = Number.isFinite(rate) ? Math.max(0, rate) : 0;
    setPoints((prev) => {
      const next = [...prev, { t: sampleAt, bps }];
      return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sampleAt]);

  const peak = points.reduce((m, p) => Math.max(m, p.bps), 0);
  const current = points.length > 0 ? points[points.length - 1].bps : 0;

  // The Card stretches to fill its flex parent (the Overview bottom
   // row gives this card flex:auto height). The inner chart wrapper
   // uses height:100% so ResponsiveContainer sizes against the
   // available space instead of the old fixed 180px — that fixed
   // height was the reason the page needed a scrollbar.
  return (
    <Card
      size="small"
      style={{ width: "100%", display: "flex", flexDirection: "column" }}
      bodyStyle={{ padding: 12, flex: 1, minHeight: 0 }}
      title={
        <span>
          {displayTitle}
          <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
            {t("trafficChart.now")} {fmtRate(current)} · {t("trafficChart.peak")}{" "}
            {fmtRate(peak)}
          </Text>
        </span>
      }
    >
      <div style={{ width: "100%", height: "100%", minHeight: 160 }}>
        <ResponsiveContainer>
          <AreaChart data={points}>
            <defs>
              <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.45} />
                <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="t" hide />
            <YAxis tickFormatter={(v) => fmtRate(v)} width={70} tick={{ fontSize: 11, fill: "#94a3b8" }} />
            <Tooltip
              labelFormatter={(t) => new Date(t as number).toLocaleTimeString()}
              formatter={(v: number) => [fmtRate(v), t("trafficChart.rate")]}
              contentStyle={{ background: "#0b1022", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }}
              labelStyle={{ color: "#94a3b8" }}
              itemStyle={{ color: "#e2e8f0" }}
            />
            <Area
              type="monotone"
              dataKey="bps"
              stroke="#22d3ee"
              strokeWidth={2}
              fill="url(#trafficGradient)"
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
