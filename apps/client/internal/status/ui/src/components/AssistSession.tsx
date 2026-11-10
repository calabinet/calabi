import { useEffect, useRef, useState } from "react";
import { Alert, Button, Input as TextBox, Space, Spin, Tag, Typography } from "antd";
import { useTranslation } from "react-i18next";
import "./AssistSession.css";
import { fileAction } from "../api/files";

type Reply = { local_split_frame?: boolean; frame_pending?: boolean; id?: string; state: string; epoch: number; text_input?: boolean; punctuation_keys?: boolean; frame?: string; frame_delta?: boolean; revision?: number; patch?: string; x?: number; y?: number };
type Input = { input: string; x: number; y: number; wheel?: number } | { input: "text"; text: string; epoch: number; seq: number };
export const nativeAssist = () => "__TAURI_INTERNALS__" in window;

function desktopPoint(canvas: HTMLCanvasElement, x: number, y: number) {
  const r = canvas.getBoundingClientRect();
  const norm = (n: number) => Math.round(Math.max(0, Math.min(1, n)) * 65535);
  return { x: norm((x-r.left)/r.width), y: norm((y-r.top)/r.height) };
}

const isPunctuation = (key: string) => /^[\p{P}\p{S}]$/u.test(key);
// DOM physical key locations mapped to Windows virtual keys for remote IME processing.
const punctuationVK: Record<string, number> = {
  Semicolon: 0xba, Equal: 0xbb, Comma: 0xbc, Minus: 0xbd, Period: 0xbe,
  Slash: 0xbf, Backquote: 0xc0, BracketLeft: 0xdb, Backslash: 0xdc,
  BracketRight: 0xdd, Quote: 0xde, IntlBackslash: 0xe2,
};

// A candidate is committed only at compositionend. Interim input stays local.
function ImeEntry({ label, commit }: { label: string; commit: (text: string) => void }) {
  const composing = useRef(false);
  return <TextBox aria-label={label} placeholder={label} autoComplete="off" spellCheck={false}
    onBlur={e => { composing.current = false; e.currentTarget.value = ""; }}
    onCompositionStart={() => { composing.current = true; }}
    onCompositionEnd={e => {
      const active = composing.current;
      composing.current = false;
      e.currentTarget.value = "";
      if (active && document.activeElement === e.currentTarget && e.data) commit(e.data);
    }}
    onInput={e => {
      const event = e.nativeEvent as InputEvent;
      if (composing.current || event.isComposing) return;
      if (event.inputType === "insertText" && isPunctuation(e.currentTarget.value)) commit(e.currentTarget.value);
      e.currentTarget.value = "";
    }}
  />;
}

export default function AssistSession({ peer, name, onClose }: { peer: string; name: string; onClose: () => void }) {
  const { t } = useTranslation();
  const [state, setState] = useState("pending");
  const [frame, setFrame] = useState(false);
  const surface = useRef<HTMLCanvasElement>(null);
  const [imeEpoch, setImeEpoch] = useState<number | null>(null);
  const [viewport, setViewport] = useState<HTMLDivElement | null>(null);
  const [area, setArea] = useState({width: 0, height: 0});
  useEffect(() => {
    const el = viewport;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => {
      const {width, height} = entry.contentRect;
      setArea({width, height});
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [viewport]);
  const [aspect, setAspect] = useState(16 / 9);
  const [fullscreen, setFullscreen] = useState(false);
  const [fullscreenError, setFullscreenError] = useState(false);
  const ownedFullscreen = useRef(false);
  const fullscreenAction = (enabled?: boolean) =>
    fileAction<{ fullscreen: boolean }>({ action: "assist_window", enabled });
  useEffect(() => {
    let mounted = true;
    const sync = () => { void fullscreenAction().then(reply => {
      if (mounted) setFullscreen(reply.fullscreen);
    }).catch(() => {}); };
    sync();
    window.addEventListener("resize", sync);
    return () => {
      mounted = false;
      window.removeEventListener("resize", sync);
      if (ownedFullscreen.current) { void fullscreenAction(false).catch(() => {}); ownedFullscreen.current = false; }
    };
  }, []);
  const toggleFullscreen = () => {
    setFullscreenError(false);
    ownedFullscreen.current = !fullscreen;
    void fullscreenAction(!fullscreen).then(reply => setFullscreen(reply.fullscreen))
      .catch(() => { setFullscreenError(true); });
  };
  const textSeq = useRef(0);
  const [attempt, setAttempt] = useState(0);
  const [failed, setFailed] = useState("");
  const [failureDetail, setFailureDetail] = useState("");
  const send = useRef<(input: Input | null) => void>(() => {});
  const remotePunctuation = useRef(false);
  const remoteKey = (e: React.KeyboardEvent) => remotePunctuation.current ? punctuationVK[e.code] : undefined;
  const commitText = (text: string) => {
    if (imeEpoch === null || text.length > 256 || /[\u0000-\u001f\u007f-\u009f]/.test(text)) return;
    send.current({input: "text", text, epoch: imeEpoch, seq: ++textSeq.current});
  };
  const usesText = (e: React.KeyboardEvent) => imeEpoch !== null && !e.ctrlKey && !e.altKey && !e.metaKey && isPunctuation(e.key);
  useEffect(() => {
    let closed = false, id = "", epoch = 0, controlling = false;
    setFailed(""); setFailureDetail(""); setState("pending");
    let pending: Input[] = [];
    let timer: ReturnType<typeof setTimeout>;
    const call = (op: string, extra = {}) => fileAction<Reply>({ action: "assist", peer, assist: { op, id, epoch, ...extra } });
    const end = () => { if (id) { void call("end").catch(() => {}); id = ""; } };
    const stop = () => { closed = true; pending = []; clearTimeout(timer); end(); };
    const apply = (reply: Reply) => {
      if (reply.state !== "control" || reply.epoch !== epoch) pending = [];
      epoch = reply.epoch; controlling = reply.state === "control";
      setState(reply.state);
      setImeEpoch(controlling && reply.text_input ? epoch : null);
      remotePunctuation.current = controlling && reply.punctuation_keys === true;

    };
    const release = () => {
      pending = [];
      if (!closed && controlling) void call("release").catch(() => {});
    };
    send.current = input => {
      if (!input) { release(); return; }
      if (closed || !controlling || ("epoch" in input && input.epoch !== epoch)) return;
      if (input.input === "move" && pending[pending.length - 1]?.input === "move") pending.pop();
      const last = pending[pending.length-1];
      if ("wheel" in input && input.wheel && last && "wheel" in last && last.input === input.input &&
          last.x === input.x && last.y === input.y && Math.sign(last.wheel || 0) === Math.sign(input.wheel)) {
        last.wheel = Math.max(-1200, Math.min(1200, (last.wheel || 0) + input.wheel));
        return;
      }
      if (pending.length >= 32) { release(); return; }
      pending.push(input);
    };
    const loop = async () => {
      try {
        const reply = await call("request", {input:"outcome-v1"});
        id = reply.id || "";
        if (closed) { end(); return; }
        if (!id) throw new Error();
        let nextFrame = 0, baseline = 0;
        const delta = reply.frame_delta === true;
        while (!closed) {
          if (!pending.length && Date.now() < nextFrame) { await new Promise(resolve => setTimeout(resolve, 20)); continue; }
          const input = Date.now() < nextFrame ? pending.shift() : undefined;
          const split = reply.local_split_frame === true && controlling && delta;
          const frameOp = split ? "frame_next" : delta ? "frame_delta" : "frame";
          const result = input ? await call("input", input) : await call(frameOp, delta ? {baseline} : {});
          if (closed) return;
          if (result.frame_pending) {
            nextFrame = Date.now() + 40;
            continue;
          }
          apply(result);
          if (result.state === "declined" || result.state === "stopped") {
            closed = true;
            pending = [];
            id = "";
            if (surface.current) surface.current.width = 0;
            setFrame(false);
            return;
          }
          if (result.frame || result.patch) {
            const image = new Image();
            image.src = result.frame ? "data:image/jpeg;base64," + result.frame : "data:image/png;base64," + result.patch;
            await image.decode();
            if (closed) return;
            const canvas = surface.current;
            const ctx = canvas?.getContext("2d");
            if (!canvas || !ctx) throw new Error("Preview canvas unavailable");
            if (result.frame) {
              canvas.width = image.naturalWidth;
              canvas.height = image.naturalHeight;
              setAspect(canvas.width / canvas.height);
            }
            ctx.drawImage(image, result.x || 0, result.y || 0);
            baseline = result.revision || 0;
            setFrame(true);
          }
          if (!input) nextFrame = Date.now() + 160;
          await new Promise(resolve => setTimeout(resolve, pending.length ? 0 : 35));
        }
      } catch (error) {
        if (!closed) {
          const detail = error instanceof Error ? error.message : String(error);
          controlling = false; pending = []; epoch = 0;
          setImeEpoch(null); setFrame(false);
          if (surface.current) surface.current.width = 0;
          if (id && detail === "target desktop transport unavailable") {
            setState("recovering");
            const until = Date.now() + 15000;
            while (!closed && Date.now() < until) {
              await new Promise(resolve => setTimeout(resolve, 500));
              if (closed) return;
              const status = await call("availability").catch(() => null);
              if (closed) return;
              if (status?.state === "available") {
                // End only the old ID. A new request needs a deliberate click and fresh consent.
                await call("end").catch(() => {});
                id = "";
                if (!closed) setState("restored");
                return;
              }
            }
            if (closed) return;
            setFailed("assist.peerUnavailable");
          } else {
            setFailed(id ? "assist.sessionInterrupted" : "assist.requestFailed");
            setFailureDetail(detail);
          }
          stop();
        }
      }
    };
    // Defer creation until the mounted modal owns the request.
    timer = setTimeout(() => void loop(), 0);
    window.addEventListener("blur", release);
    window.addEventListener("pagehide", stop);
    return () => { stop(); window.removeEventListener("blur", release); window.removeEventListener("pagehide", stop); };
  }, [peer, attempt]);
  const secondary = useRef(false);
  useEffect(() => {
    const canvas = surface.current;
    if (!canvas || state !== "control") return;
    let remainderX = 0, remainderY = 0;
    const wheel = (e: WheelEvent) => {
      e.preventDefault();
      if (e.ctrlKey) return; // WebKit can report a pinch as Ctrl+wheel.
      const unit = e.deltaMode === 1 ? 40 : e.deltaMode === 2 ? 360 : 1.2;
      const point = desktopPoint(canvas, e.clientX, e.clientY);
      remainderX += e.deltaX * unit;
      remainderY -= e.deltaY * unit;
      const dx = Math.trunc(remainderX), dy = Math.trunc(remainderY);
      remainderX -= dx; remainderY -= dy;
      const clamp = (d: number) => Math.max(-1200, Math.min(1200, d));
      if (dy) send.current({input:"wheel", ...point, wheel:clamp(dy)});
      if (dx) send.current({input:"hwheel", ...point, wheel:clamp(dx)});
    };
    canvas.addEventListener("wheel", wheel, {passive:false});
    return () => canvas.removeEventListener("wheel", wheel);
  }, [state]);
  const pointer = (e: React.PointerEvent<HTMLCanvasElement>, input: string) => {
    if (state !== "control" || (input === "move" && !(e.buttons & 3))) return;
    if (input !== "move" && e.button !== 0 && e.button !== 2) return;
    if (input === "down") {
      secondary.current = e.button === 2 || (e.button === 0 && e.ctrlKey && /Mac/.test(navigator.platform));
      e.currentTarget.focus();
      e.currentTarget.setPointerCapture(e.pointerId);
    }
    if (input !== "move" && (secondary.current || e.button === 2)) input = "right" + input;
    send.current({input, ...desktopPoint(e.currentTarget, e.clientX, e.clientY)});
  };
  const finished = state === "declined" || state === "stopped";
  return <main className={"assist-session" + (fullscreen ? " assist-fullscreen" : "")}>
    <header className="assist-toolbar" aria-label={t("assist.title")}>
      <Typography.Text strong ellipsis>{name}</Typography.Text>
      <Tag>{t("assist." + (failed ? "ended" : state))}</Tag>
      <Button onClick={e=>{toggleFullscreen(); if(e.detail) e.currentTarget.blur();}}>{t(fullscreen ? "assist.exitFullscreen" : "assist.fullscreen")}</Button>
      <Button className="assist-end" onClick={onClose}>{t(finished || failed ? "assist.closeWindow" : "assist.end")}</Button>
    </header>
      {fullscreenError && <Alert type="warning" message={t("assist.fullscreenError")} />}
      <div ref={setViewport} style={{flex:1,minHeight:0,display:"grid",placeItems:"center",background:frame?"#111":undefined}}>
      {failed ? <Alert type="warning" showIcon message={t(failed)} description={<>
          <div>{t(failureDetail.toLowerCase().includes("tls:") ? "assist.secureConnectionHint" : "assist.retryHint")}</div>
          {failureDetail && <details><summary>{t("assist.technicalDetails")}</summary><code style={{overflowWrap:"anywhere"}}>{failureDetail}</code></details>}
        </>} action={<Button onClick={()=>setAttempt(n=>n+1)}>{t("assist.requestAgain")}</Button>} /> :
        state === "restored" ? <Space direction="vertical" align="center"><Typography.Text>{t("assist.restoredHint")}</Typography.Text><Button onClick={()=>setAttempt(n=>n+1)}>{t("assist.requestAgain")}</Button></Space> : finished ?
        <Space direction="vertical" align="center"><Typography.Title level={4}>{t("assist." + state + "Message")}</Typography.Title><Button onClick={onClose}>{t("assist.closeWindow")}</Button></Space> : !frame &&
        <Space><Spin size="small"/><Typography.Text>{t(state==="recovering" ? "assist.recoveringHint" : "assist.wait")}</Typography.Text></Space>}
      <canvas hidden={!frame} ref={surface} role="img" aria-label={t("assist.preview")} tabIndex={0}
          style={{display:frame?"block":"none",width:Math.min(area.width, area.height*aspect),height:"auto",touchAction:"none"}}
          onContextMenu={e=>e.preventDefault()}
          onPointerDown={e=>pointer(e,"down")} onPointerUp={e=>pointer(e,"up")} onPointerMove={e=>pointer(e,"move")}
          onPointerCancel={()=>send.current(null)} onBlur={()=>send.current(null)}
          onKeyDown={e=>{if (state==="control" && !e.metaKey && e.key!=="Tab" && e.key!=="Escape"){
            e.preventDefault();
            const vk = remoteKey(e);
            if (vk !== undefined || (remotePunctuation.current && /^Digit[0-9]$/.test(e.code))) send.current({input:"keydown",x:vk ?? e.keyCode,y:0});
            else if (usesText(e)) commitText(e.key);
            else send.current({input:"keydown",x:e.keyCode,y:0});
          }}}
          onKeyUp={e=>{if(state==="control")send.current({input:"keyup",x:remoteKey(e) ?? e.keyCode,y:0});}} />
      </div>
      {!failed && imeEpoch !== null && <div className="assist-ime"><ImeEntry key={imeEpoch} label={t("assist.ime")} commit={commitText} /></div>}
  </main>;
}
