import type { ReactNode } from "react";

// A shared rounded outline vocabulary for mesh devices and file transfers.
const paths: Record<string, ReactNode> = {
  monitor: <><rect x="3" y="3" width="18" height="13" rx="2" /><path d="M8 21h8M12 16v5" /></>,
  laptop: <><path d="M5 16V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v11M2 16h20l-1 4H3z" /></>,
  server: <><rect x="3" y="3" width="18" height="7" rx="2" /><rect x="3" y="14" width="18" height="7" rx="2" /><path d="M7 6.5h.01M7 17.5h.01" /></>,
  phone: <><rect x="6" y="2" width="12" height="20" rx="2" /><path d="M11 18h2" /></>,
  file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6" /></>,
  text: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h6" /></>,
  archive: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M10 3v2m-2 0v2m2 0v2m-2 0v2" /><rect x="8" y="14" width="3" height="4" rx="1" /></>,
  video: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M10 12l5 3-5 3z" /></>,
  image: <><rect x="3" y="3" width="18" height="18" rx="2" /><circle cx="8" cy="8" r="1" /><path d="m21 15-5-5L5 21" /></>,
  inbox: <><path d="m4 3-3 12v5a1 1 0 0 0 1 1h20a1 1 0 0 0 1-1v-5L20 3zM1 15h6l2 3h6l2-3h6" /></>,
  upload: <><path d="M12 16V3m-5 5 5-5 5 5M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4" /></>,
  send: <><path d="m22 2-7 20-4-9L2 9zM22 2 11 13" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  close: <path d="m6 6 12 12M18 6 6 18" />,
  pause: <><path d="M8 5v14M16 5v14" /></>,
  play: <path d="m7 4 14 8-14 8z" />,
  more: <><circle cx="5" cy="12" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /></>,
  info: <><circle cx="12" cy="12" r="9" /><path d="M12 11v6M12 7h.01" /></>,
  trash: <><path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7" /></>,
  settings: <><path d="M4 6h16M4 12h16M4 18h16" /><circle cx="9" cy="6" r="2" fill="var(--mesh-surface, #0c1325)" /><circle cx="15" cy="12" r="2" fill="var(--mesh-surface, #0c1325)" /><circle cx="9" cy="18" r="2" fill="var(--mesh-surface, #0c1325)" /></>,
  power: <path d="M12 2v10M5.6 5.6a9 9 0 1 0 12.8 0" />,
  transfer: <path d="M7 3v18m-4-4 4 4 4-4M17 21V3m-4 4 4-4 4 4" />,
  network: <><rect x="8" y="2" width="8" height="6" rx="1" /><path d="M12 8v5M5 17v-4h14v4" /><rect x="2" y="17" width="6" height="5" rx="1" /><rect x="16" y="17" width="6" height="5" rx="1" /></>,
  service: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
};

export function deviceGlyph(os?: string) {
  return os === "darwin" ? "laptop" : os === "android" || os === "ios" ? "phone" : ["linux", "freebsd", "openbsd"].includes(os || "") ? "server" : "monitor";
}

export function fileGlyph(name: string) {
  const ext = name.split(".").pop()?.toLowerCase() || "";
  return /^(zip|rar|7z|gz|tar|bz2|xz)$/.test(ext) ? "archive" : /^(mp4|mov|mkv|avi|webm)$/.test(ext) ? "video" : /^(png|jpg|jpeg|gif|svg|webp|heic)$/.test(ext) ? "image" : /^(pdf|txt|md|doc|docx|csv|json)$/.test(ext) ? "text" : "file";
}

export default function MeshGlyph({ name, className = "" }: { name: string; className?: string }) {
  return <svg className={`mesh-glyph ${className}`} width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name] || paths.file}</svg>;
}
