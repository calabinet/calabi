import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { useTranslation } from "react-i18next";
import { remoteFrame, remoteWorkspace } from "../api/ssh";

// Mirrors probe_input_kind. Physical locations use PC set-1 scan codes.
const enum Input { Release, Text, Scan, Move, LeftDown, LeftUp, RightDown, RightUp, Wheel, HWheel, KeyDown, KeyUp, Refresh = 13 }
const leftShift = 0x2a;
const rightShift = 0x36;
const rows = [
  [0x01, "Escape Digit1 Digit2 Digit3 Digit4 Digit5 Digit6 Digit7 Digit8 Digit9 Digit0 Minus Equal Backspace"],
  [0x0f, "Tab KeyQ KeyW KeyE KeyR KeyT KeyY KeyU KeyI KeyO KeyP BracketLeft BracketRight Enter ControlLeft"],
  [0x1e, "KeyA KeyS KeyD KeyF KeyG KeyH KeyJ KeyK KeyL Semicolon Quote Backquote ShiftLeft Backslash KeyZ KeyX KeyC KeyV KeyB KeyN KeyM Comma Period Slash ShiftRight"],
  [0x37, "NumpadMultiply AltLeft Space CapsLock F1 F2 F3 F4 F5 F6 F7 F8 F9 F10 NumLock ScrollLock Numpad7 Numpad8 Numpad9 NumpadSubtract Numpad4 Numpad5 Numpad6 NumpadAdd Numpad1 Numpad2 Numpad3 Numpad0 NumpadDecimal"],
  [0x57, "F11 F12"],
] as const;
const scan = new Map<string, number>(rows.flatMap(([base, keys]) => keys.split(" ").map((key, index) => [key, base + index] as const)));
for (const [key, code] of Object.entries({
  NumpadEnter:0x11c, ControlRight:0x11d, NumpadDivide:0x135, AltRight:0x138,
  Home:0x147, ArrowUp:0x148, PageUp:0x149, ArrowLeft:0x14b, ArrowRight:0x14d,
  End:0x14f, ArrowDown:0x150, PageDown:0x151, Insert:0x152, Delete:0x153,
  MetaLeft:0x15b, MetaRight:0x15c, ContextMenu:0x15d, IntlBackslash:0x56,
})) scan.set(key, code);

function point(target: HTMLElement, width: number, height: number, x: number, y: number) {
  const box = target.getBoundingClientRect();
  const scale = Math.min(box.width / width, box.height / height);
  if (scale <= 0) return [0, 0] as const;
  const left = box.left + (box.width - scale * width) / 2;
  const top = box.top + (box.height - scale * height) / 2;
  return [
    Math.round(Math.max(0, Math.min(width - 1, (x - left) / scale))),
    Math.round(Math.max(0, Math.min(height - 1, (y - top) / scale))),
  ] as const;
}

export default function RemoteDesktop({ id, active, native, compare, frameWait, onPreview }: {
  id: string; active: boolean; native: boolean; compare: boolean; frameWait: boolean;
  onPreview: (id: string, image: string) => void;
}) {
  const { t } = useTranslation();
  const [ready, setReady] = useState(false);
  const canvas = useRef<HTMLCanvasElement>(null);
  const revision = useRef(0);
  const dimensions = useRef<[number, number]>([0, 0]);
  const cursorRevision = useRef(0);
  const pressed = useRef(new Set<number>());
  const suspendedControl = useRef(new Set<number>());
  const buttons = useRef(new Map<number, boolean>());
  const queue = useRef(Promise.resolve());
  const pending = useRef(0);
  const selected = useRef(active);
  const selection = useRef(0);
  if (selected.current !== active) {
    selected.current = active;
    selection.current++;
  }
  const mac = /Mac/.test(navigator.platform);

  useEffect(() => {
    const activeCanvas = canvas.current;
    if (!active || !activeCanvas) return;
    const target = activeCanvas;
    let stopped = false;
    let polling = false;
    let pollCursor = true;
    let hasFrame = revision.current !== 0;
    let viewEpoch = 0;
    let timer: number;
    let lastThumbnail = 0;
    let metrics: { start: number; first: number; last: number; submitted: number; maxGap: number } | undefined;
    const thumb = document.createElement("canvas");
    const cursor = document.createElement("canvas");
    const scaledCursor = document.createElement("canvas");
    let hotspot: [number, number] | undefined;
    let cursorSize = "";
    cursorRevision.current = 0;
    thumb.width = 192;
    thumb.height = 108;
    function syncCursor() {
      if (!hotspot || !hasFrame) return;
      const box = target.getBoundingClientRect();
      const [frameWidth, frameHeight] = dimensions.current;
      const scale = Math.min(box.width / frameWidth, box.height / frameHeight, 128 / cursor.width, 128 / cursor.height);
      if (scale <= 0) return;
      const width = Math.max(1, Math.round(cursor.width * scale));
      const height = Math.max(1, Math.round(cursor.height * scale));
      const size = `${width}x${height}`;
      if (size === cursorSize) return;
      scaledCursor.width = width;
      scaledCursor.height = height;
      const context = scaledCursor.getContext("2d");
      if (!context) return;
      context.drawImage(cursor, 0, 0, width, height);
      const x = Math.min(width - 1, Math.round(hotspot[0] * width / cursor.width));
      const y = Math.min(height - 1, Math.round(hotspot[1] * height / cursor.height));
      target.style.cursor = `url(${scaledCursor.toDataURL()}) ${x} ${y}, default`;
      cursorSize = size;
    }
    const resize = new ResizeObserver(syncCursor);
    resize.observe(target);
    async function poll() {
      if (stopped || document.hidden || polling) return;
      polling = true;
      const epoch = viewEpoch;
      let retryDelay = 0;
      try {
        const result = await remoteFrame(id, revision.current, pollCursor ? cursorRevision.current : undefined,
          native && Date.now() - lastThumbnail >= 700, frameWait && pollCursor);
        pollCursor = true;
        if (stopped || document.hidden || epoch !== viewEpoch) return;
        const bytes = result instanceof ArrayBuffer ? new Uint8Array(result) : Uint8Array.from(result);
        if (bytes.length >= 12) {
          const header = new DataView(bytes.buffer, bytes.byteOffset, 12);
          const width = header.getUint32(4, true), height = header.getUint32(8, true);
          if (!width && !height && bytes.length >= 20) {
            const shape = new DataView(bytes.buffer, bytes.byteOffset + 12, 8);
            const w = shape.getUint16(0, true), h = shape.getUint16(2, true);
            const x = shape.getUint16(4, true), y = shape.getUint16(6, true);
            cursorRevision.current = header.getUint32(0, true);
            pollCursor = false; // Fetch any pending frame before polling for another shape.
            if (!w && !h) {
              hotspot = undefined;
              target.style.cursor = x === 1 ? "none" : "";
            } else if (w <= 128 && h <= 128 && x < w && y < h && bytes.length === 20 + w * h * 4) {
              cursor.width = w;
              cursor.height = h;
              const rgba = new Uint8ClampedArray(bytes.buffer, bytes.byteOffset + 20, w * h * 4);
              cursor.getContext("2d")?.putImageData(new ImageData(rgba, w, h), 0, 0);
              hotspot = [x, y];
              cursorSize = "";
              syncCursor();
            }
            return;
          }
          if (width && height && native) {
            dimensions.current = [width, height];
            revision.current = header.getUint32(0, true);
            hasFrame = true;
            syncCursor();
            setReady(true);
            const w = bytes[12], h = bytes[13];
            if (w && h && bytes.length === 14 + w * h * 4) {
              lastThumbnail = Date.now();
              thumb.width = w;
              thumb.height = h;
              const rgba = new Uint8ClampedArray(bytes.buffer, bytes.byteOffset + 14, w * h * 4);
              thumb.getContext("2d")?.putImageData(new ImageData(rgba, w, h), 0, 0);
              onPreview(id, thumb.toDataURL("image/jpeg", 0.65));
            }
          } else if (width && height && bytes.length === width * height * 4 + 12) {
            const rgba = new Uint8ClampedArray(bytes.buffer, bytes.byteOffset + 12, width * height * 4);
            const words = new Uint32Array(rgba.buffer, rgba.byteOffset, width * height);
            for (let i = 0; i < words.length; i++) {
              const bgra = words[i];
              words[i] = 0xff000000 | ((bgra & 255) << 16) | (bgra & 0xff00) | ((bgra >> 16) & 255);
            }
            const image = new ImageData(rgba, width, height);
            const context = target.getContext("2d", { alpha:false });
            if (!context) return;
            dimensions.current = [width, height];
            if (target.width !== width || target.height !== height) {
              target.width = width;
              target.height = height;
              hasFrame = false;
            }
            context.putImageData(image, 0, 0);
            if (!hasFrame) {
              hasFrame = true;
              syncCursor();
            }
            revision.current = header.getUint32(0, true);
            if (compare) {
              const now = performance.now();
              metrics ??= { start: now, first: revision.current, last: now, submitted: 0, maxGap: 0 };
              metrics.submitted++;
              metrics.maxGap = Math.max(metrics.maxGap, now - metrics.last);
              metrics.last = now;
              if (now - metrics.start >= 5000) {
                void remoteWorkspace({ op: "rdp_canvas_stats", id, width, height,
                  elapsed_ms: Math.round(now - metrics.start), received: (revision.current - metrics.first) >>> 0,
                  submitted: metrics.submitted - 1, max_gap_ms: Math.round(metrics.maxGap) }).catch(() => {});
                metrics = undefined;
              }
            }
            setReady(true);
            if (Date.now() - lastThumbnail >= 700) {
              lastThumbnail = Date.now();
              const ctx = thumb.getContext("2d");
              if (ctx) {
                const scale = Math.min(thumb.width / width, thumb.height / height);
                ctx.fillStyle = "#080c16";
                ctx.fillRect(0, 0, thumb.width, thumb.height);
                ctx.drawImage(target, (thumb.width - width * scale) / 2, (thumb.height - height * scale) / 2, width * scale, height * scale);
                onPreview(id, thumb.toDataURL("image/jpeg", 0.65));
              }
            }
          }
        }
      } catch {
        // Closed helpers are removed from the workspace snapshot. Back off until it refreshes.
        retryDelay = 60;
      }
      finally {
        polling = false;
        if (!stopped && !document.hidden) {
          timer = window.setTimeout(poll, retryDelay || (!frameWait && epoch === viewEpoch && pollCursor ? 60 : 0));
        }
      }
    }
    function refreshView() {
      window.clearTimeout(timer);
      viewEpoch++;
      metrics = undefined;
      if (document.hidden) return;
      // Repaint the retained complete frame even if its revision is unchanged.
      revision.current = 0;
      send(Input.Refresh, 0);
      void poll();
    }
    canvas.current?.focus({ preventScroll:true });
    void poll();
    document.addEventListener("visibilitychange", refreshView);
    window.addEventListener("focus", refreshView);
    window.addEventListener("blur", release);
    return () => {
      stopped = true;
      resize.disconnect();
      pressed.current.clear();
      suspendedControl.current.clear();
      buttons.current.clear();
      window.clearTimeout(timer);
      document.removeEventListener("visibilitychange", refreshView);
      window.removeEventListener("focus", refreshView);
      window.removeEventListener("blur", release);
    };
  }, [active, compare, frameWait, id, mac, native, onPreview]);

  function send(kind: Input, a: number, b = 0, delta = 0) {
    if (!active || (kind === Input.Move && pending.current > 0)) return;
    const generation = selection.current;
    pending.current++;
    queue.current = queue.current.then(async () => {
      if (selected.current && selection.current === generation) {
        await remoteWorkspace({ op:"rdp_input", id, kind, a, b, delta });
      }
    }).catch(() => {}).finally(() => { pending.current--; });
  }
  function release() {
    pressed.current.clear();
    suspendedControl.current.clear();
    buttons.current.clear();
    send(Input.Release, 3);
  }
  function syncShift(held: boolean) {
    if (held) {
      if (pressed.current.has(leftShift) || pressed.current.has(rightShift)) return;
      pressed.current.add(leftShift);
      send(Input.KeyDown, leftShift);
      return;
    }
    for (const code of [leftShift, rightShift]) {
      if (pressed.current.delete(code)) send(Input.KeyUp, code);
    }
  }
  function key(event: KeyboardEvent<HTMLElement>, down: boolean) {
    const code = scan.get(event.code);
    if (code === undefined) return;
    if (!down) {
      if ((code === leftShift || code === rightShift) && !event.shiftKey) {
        event.preventDefault();
        syncShift(false);
        return;
      }
      if (suspendedControl.current.delete(code)) {
        event.preventDefault();
      } else if (pressed.current.delete(code)) {
        event.preventDefault();
        send(Input.KeyUp, code & 255, code >> 8);
      }
      return;
    }
    if (suspendedControl.current.has(code)) {
      event.preventDefault();
      return;
    }
    if (mac && event.metaKey) {
      if (["KeyC", "KeyV", "KeyX", "KeyA"].includes(event.code)) {
        event.preventDefault();
        send(Input.KeyDown, 0x1d);
        send(Input.Scan, code & 255);
        send(Input.KeyUp, 0x1d);
      }
      return;
    }
    if (mac && (event.code === "MetaLeft" || event.code === "MetaRight")) return;
    event.preventDefault();
    // IMEs may consume Shift transitions; retain the physical side when known.
    if (code !== leftShift && code !== rightShift) syncShift(event.shiftKey);
    pressed.current.add(code);
    send(Input.KeyDown, code & 255, code >> 8);
  }
  function pointer(event: PointerEvent<HTMLCanvasElement>, phase: "move" | "down" | "up") {
    if (phase === "down") {
      event.preventDefault();
      canvas.current?.focus({ preventScroll:true });
    }
    if (!ready || (phase === "down" && event.button !== 0 && event.button !== 2)) return;
    const [x, y] = point(event.currentTarget, ...dimensions.current, event.clientX, event.clientY);
    if (phase === "move") { send(Input.Move, x, y); return; }
    // A Shift press may have started outside the focused remote desktop.
    syncShift(event.shiftKey);
    if (phase === "down") {
      const secondary = event.button === 2 || (mac && event.ctrlKey);
      if (mac && secondary && event.ctrlKey) {
        // Control-click is a local gesture for an ordinary remote right-click.
        for (const code of [0x1d, 0x11d]) {
          if (!pressed.current.delete(code)) continue;
          suspendedControl.current.add(code);
          send(Input.KeyUp, code & 255, code >> 8);
        }
      }
      buttons.current.set(event.pointerId, secondary);
      event.currentTarget.setPointerCapture(event.pointerId);
      send(secondary ? Input.RightDown : Input.LeftDown, x, y);
    } else {
      const secondary = buttons.current.get(event.pointerId);
      if (secondary !== undefined) send(secondary ? Input.RightUp : Input.LeftUp, x, y);
      buttons.current.delete(event.pointerId);
      if (secondary) {
        if (event.ctrlKey) for (const code of suspendedControl.current) {
          pressed.current.add(code);
          send(Input.KeyDown, code & 255, code >> 8);
        }
        suspendedControl.current.clear();
      }
    }
  }

  return <section className="remote-session remote-desktop" hidden={!active} onContextMenu={e => e.preventDefault()}>
    {!ready && <p role="status">{t("ssh.opening")}</p>}
    {/* Physical keys go to the remote Windows IME; never compose in a local text field. */}
    <canvas ref={canvas} tabIndex={0} data-remote-keyboard
      aria-label={t("remoteWorkspace.desktop")}
      onKeyDown={e => key(e, true)} onKeyUp={e => key(e, false)}
      onBlur={release}
      onPointerMove={e => pointer(e, "move")} onPointerDown={e => pointer(e, "down")} onPointerUp={e => pointer(e, "up")}
      onPointerCancel={release} onLostPointerCapture={e => {
        if (buttons.current.has(e.pointerId)) release();
      }} onWheel={e => {
        if (!ready || e.ctrlKey) return;
        const [x, y] = point(e.currentTarget, ...dimensions.current, e.clientX, e.clientY);
        const delta = (v: number) => Math.max(-255, Math.min(255, Math.round(v * (e.deltaMode ? 40 : 1))));
        if (e.deltaY) send(Input.Wheel, x, y, delta(-e.deltaY));
        if (e.deltaX) send(Input.HWheel, x, y, delta(e.deltaX));
      }} />

  </section>;
}
