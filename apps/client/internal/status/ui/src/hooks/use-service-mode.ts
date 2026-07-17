// useServiceMode — shared hook over GET /v1/service-mode + GET /v1/me.
//
// agentMode = the daemon runs on a pinned API-key identity (a service installed
// via `daemon install --api-key`, or CALABI_API_KEY in the env). In that case
// the daemon refuses the login portal and org switching server-side, so the SPA
// hides those affordances. Defaults to interactive (agentMode=false) while
// loading or when the endpoint is absent (older daemon).
//
// canManage = whether THIS console may create/edit/delete tunnels:
//   - interactive: always true (the logged-in human is the identity).
//   - agent: only when the pinned key carries the tunnel.write scope (a
//     "management" key). A read-only key → false, so the SPA greys writes and
//     shows a read-only banner. bff-console is the real gate (it 403s a
//     read-only key's writes); this just pre-empts the controls.
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import type { AccountMe, ServiceMode } from "../api/types";

export function useServiceMode(): {
  agentMode: boolean;
  loginEnabled: boolean;
  canManage: boolean;
  consoleWebUrl: string;
} {
  const { data } = useQuery<ServiceMode>({
    queryKey: ["service-mode"],
    queryFn: api.serviceMode,
    // Stable for the daemon's lifetime — fetch once, never refetch.
    staleTime: Infinity,
    retry: false,
  });
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    staleTime: Infinity,
    retry: false,
  });

  const agentMode = (data?.agent ?? data?.read_only) ?? false;
  const canManage = !agentMode || (me?.scopes ?? []).includes("tunnel.write");
  return {
    agentMode,
    loginEnabled: data?.login_enabled ?? true,
    canManage,
    // "" when the daemon didn't supply one (older build, or explicitly unset) —
    // callers hide the affordance rather than linking somewhere dead.
    consoleWebUrl: (data?.console_web ?? "").replace(/\/+$/, ""),
  };
}
