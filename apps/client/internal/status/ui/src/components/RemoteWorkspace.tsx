import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { remoteWorkspace, type RemoteWorkspace as WorkspaceState } from "../api/ssh";
import MeshGlyph from "./MeshGlyph";
import RemoteDesktop from "./RemoteDesktop";
import SshSession from "./SshSession";
import "./RemoteWorkspace.css";

export default function RemoteWorkspace() {
  const { t } = useTranslation();
  const [state, setState] = useState<WorkspaceState>();
  const [gallery, setGallery] = useState(false);
  const [files, setFiles] = useState<Record<string, boolean>>({});
  const [previews, setPreviews] = useState<Record<string, string>>({});
  const [error, setError] = useState(false);
  const switcher = useRef<HTMLDivElement>(null);
  const handle = useRef<HTMLButtonElement>(null);
  const hideTimer = useRef<number>();
  const restoring = useRef(false);
  const revision = useRef(0);

  const refresh = useCallback(async () => {
    const observed = revision.current;
    const snapshot = await remoteWorkspace<WorkspaceState>({ op: "snapshot" });
    if (observed === revision.current) setState(snapshot);
  }, []);
  useEffect(() => {
    let stopped = false;
    let timer: number;
    async function poll() {
      try { await refresh(); } catch { /* An empty or closed workspace has no sessions. */ }
      if (!stopped) timer = window.setTimeout(poll, 250);
    }
    void poll();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      window.clearTimeout(hideTimer.current);
    };
  }, [refresh]);

  const onPreview = useCallback((id: string, text: string) => {
    setPreviews(previous => previous[id] === text ? previous : { ...previous, [id]: text });
  }, []);
  const closeFiles = (id: string) => setFiles(previous => ({ ...previous, [id]: false }));
  const reveal = () => { window.clearTimeout(hideTimer.current); setGallery(true); };
  const dismiss = useCallback(() => {
    window.clearTimeout(hideTimer.current);
    setGallery(false);
  }, []);
  const leave = () => {
    window.clearTimeout(hideTimer.current);
    hideTimer.current = window.setTimeout(() => {
      const target = switcher.current;
      if (!target?.matches(":hover") && !target?.querySelector(":focus-visible")) dismiss();
    }, 200);
  };
  const act = useCallback(async (request: Parameters<typeof remoteWorkspace>[0]) => {
    revision.current++;
    setError(false);
    try {
      await remoteWorkspace(request);
      revision.current++;
      await refresh();
      dismiss();
      requestAnimationFrame(() => document.querySelector<HTMLElement>(
        ".remote-session:not([hidden]) :is([data-remote-keyboard], .xterm-helper-textarea)"
      )?.focus({ preventScroll: true }));
    } catch {
      setError(true);
    }
  }, [dismiss, refresh]);

  const hasSessions = !!state?.sessions.length;
  const nativeDesktop = !!state?.nativeRdp && state.sessions.some(session =>
    session.id === state.active && session.protocol === "rdp");
  useLayoutEffect(() => {
    if (!nativeDesktop) return;
    const root = document.documentElement;
    root.classList.add("remote-native-backdrop");
    return () => root.classList.remove("remote-native-backdrop");
  }, [nativeDesktop]);
  useEffect(() => {
    if (!hasSessions) return;
    function fullscreenKey(event: KeyboardEvent) {
      if (event.key !== "F11" || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
      event.preventDefault();
      event.stopPropagation();
      if (!event.repeat) void act({ op: "fullscreen" });
    }
    // Catch the local shortcut before the RDP canvas or xterm can forward it.
    window.addEventListener("keydown", fullscreenKey, true);
    return () => window.removeEventListener("keydown", fullscreenKey, true);
  }, [act, hasSessions]);

  return <main className="remote-workspace" data-fullscreen={state?.fullscreen || false}
    data-native-desktop={nativeDesktop} onKeyDownCapture={event => {
    if (event.key !== "Escape" || !gallery) return;
    event.preventDefault();
    event.stopPropagation();
    dismiss();
    if (switcher.current?.contains(document.activeElement)) {
      restoring.current = true;
      handle.current?.focus();
      restoring.current = false;
    }
  }}>
    {state?.sessions.map(session => session.protocol === "rdp" ? <RemoteDesktop key={session.id} id={session.id}
      active={session.id === state.active} native={!!state.nativeRdp} compare={!!state.rdpCompare} frameWait={!!state.frameWait}
      onPreview={onPreview} /> : <SshSession key={session.id} id={session.id}
      active={session.id === state.active} filesOpen={!!files[session.id]}
      onCloseFiles={() => closeFiles(session.id)} onPreview={onPreview} />)}
    {!!state?.sessions.length && <div className="remote-switcher" ref={switcher}
      onPointerEnter={() => window.clearTimeout(hideTimer.current)} onPointerLeave={leave}
      onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) leave(); }}>
      <button ref={handle} type="button" className="remote-edge" aria-label={t("remoteWorkspace.sessions")}
        aria-expanded={gallery} aria-controls="remote-gallery"
        onPointerEnter={event => { if (event.pointerType !== "touch") reveal(); }}
        onFocus={event => { if (!restoring.current && event.currentTarget.matches(":focus-visible")) reveal(); }}
        onClick={reveal}><span aria-hidden="true" /></button>
      <section id="remote-gallery" className="remote-gallery" hidden={!gallery} aria-label={t("remoteWorkspace.sessions")}>
        <header>
          <span>{t("remoteWorkspace.sessions")}</span>
          <button type="button" aria-keyshortcuts="F11" onClick={() => void act({ op: "fullscreen" })}>
            {t(state.fullscreen ? "assist.exitFullscreen" : "assist.fullscreen")}
          </button>
        </header>
        {error && <div className="remote-gallery-error" role="alert">{t("remoteWorkspace.failed")}</div>}
        <ul>
          {state.sessions.map(session => {
            const active = session.id === state.active;
            return <li key={session.id}>
              <button type="button" className="remote-card" aria-pressed={active}
                onClick={() => void act({ op: "select", id: session.id })}>
                <div className="remote-thumbnail" aria-hidden="true">
                  {session.protocol === "rdp"
                    ? previews[session.id] ? <img src={previews[session.id]} alt="" /> : <MeshGlyph name="monitor" />
                    : previews[session.id] ? <pre>{previews[session.id]}</pre> : <MeshGlyph name="terminal" />}
                </div>
                <span className="remote-card-label"><strong title={session.name}>{session.name}</strong><small>{session.protocol.toUpperCase()}</small></span>
              </button>
              {active && session.protocol === "ssh" && <button type="button" className="remote-files-toggle" aria-expanded={!!files[session.id]}
                onClick={() => {
                  setFiles(previous => ({ ...previous, [session.id]: !previous[session.id] }));
                  dismiss();
                }}>{t("sshFiles.title")}</button>}
              <button type="button" className="remote-close" aria-label={t("remoteWorkspace.close", { name: session.name })}
                onClick={() => { if (window.confirm(t("remoteWorkspace.close", { name: session.name }))) void act({ op: "close", id: session.id }); }}>
                <MeshGlyph name="close" />
              </button>
            </li>;
          })}
        </ul>
      </section>
    </div>}
  </main>;
}
