// Logs.tsx — live log tail. Loads the last 200 lines on mount via
// /logs?tail=200, then opens an EventSource on /logs/stream for live
// updates. Filters happen client-side (the daemon's ring buffer is
// already small).
import { DownloadOutlined, PauseCircleOutlined, PlayCircleOutlined, ReloadOutlined } from "@ant-design/icons";
import { Button, Input, Select, Space, Tag, Typography, message } from "antd";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { useTranslation } from "react-i18next";

const { Title, Text } = Typography;

// Detect slog level inside a line — slog text handler emits e.g.
// `time=2026-05-27T16:00:00.000+08:00 level=INFO msg="..." ...`
const LEVEL_RE = /level=(DEBUG|INFO|WARN|ERROR)/;
function levelOf(line: string): "debug" | "info" | "warn" | "error" {
  const m = line.match(LEVEL_RE);
  if (!m) return "info";
  return m[1].toLowerCase() as any;
}

export default function Logs() {
  const { t } = useTranslation();
  const [lines, setLines] = useState<string[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [lvl, setLvl] = useState<"all" | "debug" | "info" | "warn" | "error">("all");
  const containerRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);
  const autoScrollRef = useRef(true);

  // Initial tail.
  useEffect(() => {
    api
      .logsTail(500)
      .then((r) => setLines(r.lines || []))
      .catch(() => {});
  }, []);

  // Live stream.
  useEffect(() => {
    if (paused) {
      esRef.current?.close();
      esRef.current = null;
      return;
    }
    const es = new EventSource("/logs/stream");
    esRef.current = es;
    es.onmessage = (ev) => {
      const line = ev.data as string;
      setLines((prev) => {
        // /logs/stream replays a small backlog on every (re)connect, which
        // overlaps the /logs?tail= history loaded on mount and repeats after an
        // EventSource auto-reconnect — so the most-recent lines would otherwise
        // appear twice. Skip a line already in the recent tail. slog lines carry
        // a millisecond timestamp, so genuinely distinct events never collide.
        if (prev.slice(-80).includes(line)) return prev;
        const next = [...prev, line];
        // Keep memory bounded — the hub is 2000 lines anyway.
        if (next.length > 5000) return next.slice(next.length - 4000);
        return next;
      });
    };
    es.onerror = () => {
      // Auto-reconnect is built into EventSource; nothing to do here.
    };
    return () => {
      es.close();
    };
  }, [paused]);

  // Auto-scroll to bottom unless the user scrolled up.
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !autoScrollRef.current) return;
    el.scrollTop = el.scrollHeight;
  }, [lines]);

  const filtered = useMemo(() => {
    const f = filter.toLowerCase();
    return lines.filter((ln) => {
      if (lvl !== "all" && levelOf(ln) !== lvl) return false;
      if (!f) return true;
      return ln.toLowerCase().includes(f);
    });
  }, [lines, filter, lvl]);

  function download() {
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `calabi-${new Date().toISOString().slice(0, 10)}.log`;
    a.click();
    URL.revokeObjectURL(url);
    message.success(t("common.downloaded"));
  }

  function onScroll() {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - (el.scrollTop + el.clientHeight) < 50;
    autoScrollRef.current = atBottom;
  }

  // Flex-column wrapper with height:100% so the log viewer fills the
  // remaining Content area (Layout pins height:100vh + overflow:hidden,
  // so 100% here resolves to "viewport minus header & padding"). The
  // header row stays at intrinsic height; .log-viewer's flex:1 swallows
  // the rest — without this, the box was a fixed 60vh and the lower
  // portion of the page was empty whitespace.
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        gap: 16,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <Title level={4} style={{ margin: 0 }}>
          {t("nav.logs")}
        </Title>
        <Space>
          <Tag color={paused ? "default" : "processing"}>
            {paused ? t("logs.paused") : t("logs.live")} ·{" "}
            {t("logs.lineCount", { filtered: filtered.length, total: lines.length })}
          </Tag>
          <Select
            size="middle"
            value={lvl}
            onChange={setLvl}
            style={{ width: 110 }}
            options={[
              { value: "all", label: t("logs.levelAll") },
              { value: "debug", label: "DEBUG" },
              { value: "info", label: "INFO" },
              { value: "warn", label: "WARN" },
              { value: "error", label: "ERROR" },
            ]}
          />
          <Input.Search
            placeholder={t("logs.filterPlaceholder")}
            allowClear
            style={{ width: 200 }}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <Button
            icon={paused ? <PlayCircleOutlined /> : <PauseCircleOutlined />}
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? t("logs.resume") : t("logs.pause")}
          </Button>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => api.logsTail(500).then((r) => setLines(r.lines || []))}
          />
          <Button icon={<DownloadOutlined />} onClick={download}>
            {t("common.download")}
          </Button>
        </Space>
      </div>

      <div ref={containerRef} className="log-viewer" onScroll={onScroll}>
        {filtered.length === 0 && (
          <Text type="secondary">{t("logs.empty")}</Text>
        )}
        {filtered.map((ln, i) => {
          const l = levelOf(ln);
          return (
            <div key={i} className={`lvl-${l}`}>
              {ln}
            </div>
          );
        })}
      </div>
    </div>
  );
}
