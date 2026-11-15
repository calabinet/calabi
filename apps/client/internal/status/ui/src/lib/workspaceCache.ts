export type WorkspaceCache = {
  ids: ReadonlySet<string>;
  previews: Record<string, string>;
  files: Record<string, boolean>;
};

export const emptyWorkspaceCache = (): WorkspaceCache => ({ ids: new Set(), previews: {}, files: {} });

type Action = { type: "sessions"; ids: string[] }
  | { type: "preview"; id: string; text: string }
  | { type: "files"; id: string; open?: boolean };

export function workspaceCache(cache: WorkspaceCache, action: Action): WorkspaceCache {
  if (action.type === "sessions") {
    const ids = new Set(action.ids);
    if (ids.size === cache.ids.size && [...ids].every(id => cache.ids.has(id))) return cache;
    const retain = <T,>(values: Record<string, T>): Record<string, T> =>
      Object.fromEntries(Object.entries(values).filter(([id]) => ids.has(id)));
    return { ids, previews: retain(cache.previews), files: retain(cache.files) };
  }
  // An asynchronous final preview from an unmounted session must not restore it.
  if (!cache.ids.has(action.id)) return cache;
  if (action.type === "preview") {
    return cache.previews[action.id] === action.text ? cache
      : { ...cache, previews: { ...cache.previews, [action.id]: action.text } };
  }
  return { ...cache, files: { ...cache.files, [action.id]: action.open ?? !cache.files[action.id] } };
}
