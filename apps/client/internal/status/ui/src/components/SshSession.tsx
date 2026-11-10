import { useEffect, useRef, useState } from "react";
import { Button, ConfigProvider, type ThemeConfig } from "antd";
import { useTranslation } from "react-i18next";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import SshFilePanel from "./SshFilePanel";
import { sshErrorKey, sshRead, sshSession, type SshInfo } from "../api/ssh";
import "@xterm/xterm/css/xterm.css";
import "./SshSession.css";

const sshPrimary = "#395ac7";
const sshTheme: ThemeConfig = {
  token: {
    colorBgContainer: "#17253a",
    colorBorder: "#384f70",
    colorText: "#e3eaf8",
    colorPrimary: sshPrimary,
  },
  components: {
    Button: { colorPrimary: sshPrimary },
    Checkbox: { colorPrimary: sshPrimary },
  },
};

export default function SshSession({ id, active, filesOpen, onCloseFiles, onPreview }: {
  id: string; active: boolean; filesOpen: boolean; onCloseFiles: () => void; onPreview: (id: string, text: string) => void;
}) {
  const { t } = useTranslation();
  const viewport = useRef<HTMLDivElement>(null);
  const reconnect = useRef<() => void>(() => {});
  const activate = useRef<() => void>(() => {});
  const selected = useRef(active);
  selected.current = active;
  const [status, setStatus] = useState<"opening" | "active" | "ended">("opening");
  const [error, setError] = useState("");
  const [filesVisited, setFilesVisited] = useState(false);
  useEffect(() => { if (filesOpen) setFilesVisited(true); }, [filesOpen]);
  useEffect(() => { if (active) activate.current(); }, [active]);

  useEffect(() => {
    const node = viewport.current;
    if (!node) return;
    const terminal = new Terminal({
      fontFamily: '"Cascadia Mono", Consolas, "Microsoft YaHei UI", monospace',
      fontSize: 15,
      lineHeight: 1.12,
      cursorBlink: true,
      scrollback: 3000,
      theme: {
        background: "#080c16",
        foreground: "#e3eaf8", cursor: "#9bb4fa", selectionBackground: "#354b78",
        black: "#172238", red: "#f58995", green: "#61dbb5", yellow: "#ffd28a",
        blue: "#8eaafa", magenta: "#d6a8fa", cyan: "#83d9ed", white: "#e3eaf8",
        brightBlack: "#7f91af", brightRed: "#ffabb3", brightGreen: "#9af1d0", brightYellow: "#ffdfa9",
        brightBlue: "#b8c9fa", brightMagenta: "#e9c8ff", brightCyan: "#b1ebf9", brightWhite: "#f6f8ff",
      },
      linkHandler: { activate: () => {} },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(node);
    terminal.parser.registerOscHandler(52, () => true);
    let disposed = false;
    let running = false;
    let acceptingInput = false;
    let nativeClipboard = false;
    let generation = 0;
    let inputQueue = Promise.resolve();
    let lastPreview = 0;
    const observer = new ResizeObserver(() => { if (selected.current) fit.fit(); });
    observer.observe(node);
    activate.current = () => {
      fit.fit();
      if (!node.closest(".remote-session")?.contains(document.activeElement)) terminal.focus();
    };
    const resize = terminal.onResize(({ rows, cols }) => {
      if (acceptingInput && selected.current) void sshSession(id, { op: "resize", rows, cols }).catch(() => {});
    });
    const input = terminal.onData(data => {
      if (!acceptingInput || !selected.current) return;
      const sentTo = generation;
      inputQueue = inputQueue.then(async () => {
        for (const chunk of data.match(/[\s\S]{1,8192}/gu) || []) {
          if (!acceptingInput || !selected.current || sentTo !== generation) return;
          await sshSession(id, { op: "input", data: chunk });
        }
      }).catch(() => { if (!disposed && acceptingInput && sentTo === generation) setError("ssh.inputFailed"); });
    });
    terminal.attachCustomKeyEventHandler(event => {
      const macShortcut = nativeClipboard && event.metaKey && !event.ctrlKey && !event.altKey;
      if (!selected.current || event.type !== "keydown" || (!macShortcut && !(event.ctrlKey && event.shiftKey))) return true;
      const key = event.key.toLowerCase();
      if (key === "c" && terminal.hasSelection()) {
        if (macShortcut) event.preventDefault();
        const text = terminal.getSelection();
        const copied = nativeClipboard ? sshSession(id, { op: "clipboard_write", text }) : navigator.clipboard.writeText(text);
        void copied.catch(() => {});
        return false;
      }
      if (key === "v" && acceptingInput) {
        if (macShortcut) event.preventDefault();
        const pastedTo = generation;
        const pasted = nativeClipboard ? sshSession<string>(id, { op: "clipboard_read" }) : navigator.clipboard.readText();
        void pasted.then(text => {
          if (acceptingInput && selected.current && pastedTo === generation) terminal.paste(text);
        }).catch(() => {});
        return false;
      }
      return true;
    });
    async function connect() {
      if (running || disposed) return;
      running = true;
      generation++;
      setStatus("opening");
      setError("");
      try {
        const details = await sshSession<SshInfo>(id, { op: "info" });
        if (disposed) return;
        nativeClipboard = details.native_clipboard === true;
        terminal.reset();
        if (selected.current) fit.fit();
        await sshSession(id, { op: "start", rows: terminal.rows, cols: terminal.cols });
        if (disposed) return;
        acceptingInput = true;
        setStatus("active");
        if (selected.current) {
          activate.current();
          void sshSession(id, { op: "resize", rows: terminal.rows, cols: terminal.cols }).catch(() => {});
        }
        while (!disposed) {
          const result = await sshRead(id);
          if (disposed) return;
          const bytes = result instanceof ArrayBuffer ? new Uint8Array(result) : Uint8Array.from(result);
          if (bytes.length === 0) break;
          await new Promise<void>(done => terminal.write(bytes, done));
          if (!disposed && Date.now() - lastPreview >= 600) {
            lastPreview = Date.now();
            const buffer = terminal.buffer.active;
            const end = buffer.baseY + buffer.cursorY;
            const lines = [];
            for (let y = Math.max(0, end - 5); y <= end; y++)
              lines.push(buffer.getLine(y)?.translateToString(true).slice(0, 72) || "");
            onPreview(id, lines.join("\n"));
          }
        }
      } catch (reason) {
        if (!disposed) setError(sshErrorKey(reason));
      } finally {
        running = false;
        acceptingInput = false;
        if (!disposed) setStatus("ended");
      }
    }
    reconnect.current = () => { void connect(); };
    // React's first development StrictMode mount is cleaned up before SSH starts.
    const initial = window.setTimeout(reconnect.current, 0);
    return () => {
      disposed = true;
      acceptingInput = false;
      window.clearTimeout(initial);
      reconnect.current = () => {};
      activate.current = () => {};
      observer.disconnect();
      resize.dispose();
      input.dispose();
      terminal.dispose();
    };
  }, [id, onPreview]);

  return <ConfigProvider theme={sshTheme}>
    <section className="ssh-window remote-session" hidden={!active}>
      {status !== "active" && <div className="ssh-error" role={error ? "alert" : "status"}>
        {t(error || `ssh.${status}`)}
        {status === "ended" && <Button size="small" onClick={() => reconnect.current()}>{t("ssh.reconnect")}</Button>}
      </div>}
      <div className="ssh-workspace">
        <div className="ssh-terminal" ref={viewport} aria-label={t("ssh.terminal")} />
        {filesVisited && <SshFilePanel sessionId={id} open={filesOpen} connected={status === "active"} onClose={onCloseFiles} />}
      </div>
    </section>
  </ConfigProvider>;
}
