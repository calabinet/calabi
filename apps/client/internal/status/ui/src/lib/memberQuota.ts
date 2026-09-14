// memberQuota.ts — the caller's OWN quota, as the create flow needs it: what
// they are allowed and what they already hold.
//
// WHY IT IS READ HERE. Member quotas are enforced in tunnel-svc, at the choke
// point the console, the CLI and the edge all share. That is the right place
// for it, but it means this console learns about a refusal only after somebody
// has filled in a whole form — the error this read exists to move earlier.
//
// WHY THIS ENDPOINT AND NOT A LOCAL COUNT. The obvious cheap alternative is to
// count the rows this page already has, and it would be wrong here in a way
// that is easy to miss: the desktop list is narrowed to "created by me OR bound
// to this machine", while enforcement counts by `creator_user_id` across the
// whole org. Those differ the moment somebody runs a tunnel they did not create,
// or creates one that runs elsewhere. /v1/orgs/{id}/member-quotas is built from
// the same counting pass the quota drawer uses, and it also knows the one rule
// no client can derive: a manager is exempt from the org DEFAULT but not from a
// quota set on them by name.
//
// A plain member may read it — the server returns their own row and nobody
// else's.
import { useQuery } from "@tanstack/react-query";

import { api } from "../api/client";
import type { MemberQuotaRow } from "../api/types";

/** Dimensions with a real member-level enforcement point. Mirrors
 *  memberQuotaKeys in bff-console — a key without one would display a limit
 *  that never binds. */
export type QuotaKey = "max_tunnels" | "max_port_tunnels" | "max_mesh_nodes";

export interface MemberQuota {
  /**
   * Whether this answer can be trusted yet. NOTHING is blocked while it is
   * false: a control greyed out because a read has not landed is
   * indistinguishable to the reader from one greyed out because they are over
   * their limit.
   */
  loaded: boolean;
  exempt: boolean;
  limitOf: (key: QuotaKey) => number;
  usedOf: (key: QuotaKey) => number;
  /**
   * True only when we KNOW the caller is at or over their own limit.
   *
   * False on every uncertainty — not loaded, read failed, standalone (501), no
   * quota in this org, unlimited. The server refuses either way, so being wrong
   * here costs a refusal after submit (today's behaviour); being wrong the
   * other way tells somebody they are out of quota when they are not.
   */
  atCap: (key: QuotaKey) => boolean;
}

/**
 * @param tunnelCount  how many tunnels the page currently sees. It is part of
 *                     the query key, so react-query re-reads when it changes.
 *
 * `tunnelCount` is not decoration: what this read returns is a FUNCTION of the
 * tunnel set, so the answer goes stale the moment that set changes. Deleting a
 * tunnel at the limit left the button greyed until a page reload, because the
 * list refreshed and this did not.
 *
 * Passing the count in — rather than invalidating from each mutation — is what
 * makes that un-forgettable. Every place that changes the tunnel set already
 * has to refresh the list (or the list would be wrong), and the count moving is
 * the observable consequence. A new create/delete path added later gets this
 * for free; a list of call sites to remember would not.
 */
export function useMemberQuota(
  orgID: number,
  userID: number,
  enabled = true,
  tunnelCount = 0,
): MemberQuota {
  // userID is 0 in AGENT mode — the principal is a key, not a person — and the
  // guard below would then disable the read entirely, so nothing was ever
  // greyed: an agent-mode console offered TCP/UDP that the server refuses,
  // while the web console greyed them for the same org and the same quota.
  //
  // Callers pass `me.user.id || me.acting_user.id`; see the call sites. Kept as
  // a plain guard here rather than a second parameter because what this hook
  // needs is one id — "whose allowance does this console spend" — and for a key
  // that is the person who minted it (the server counts its tunnels against
  // them too).
  const { data, isFetched } = useQuery<MemberQuotaRow | null>({
    queryKey: ["member-quota", orgID, userID, tunnelCount],
    queryFn: () =>
      api
        .memberQuotas(orgID)
        // A manager gets every member's row back; find our own rather than
        // assuming the list has one entry.
        .then((r) => (r.items || []).find((x) => x.user_id === userID) ?? null)
        // Best-effort by design: a standalone daemon answers 501, an org that
        // never set a member quota returns no row for us, and a control-plane
        // blip lands here too. None of them should stop a tunnel being created.
        .catch(() => null),
    enabled: enabled && orgID > 0 && userID > 0,
    retry: false,
    staleTime: 60_000,
  });

  const limitOf = (key: QuotaKey) => {
    const v = data?.effective?.[key];
    return typeof v === "number" ? v : -1;
  };
  const usedOf = (key: QuotaKey) => {
    const v = data?.used?.[key];
    return typeof v === "number" ? v : 0;
  };
  return {
    loaded: isFetched,
    exempt: data?.exempt === true,
    limitOf,
    usedOf,
    atCap: (key) => {
      if (!isFetched || !data || data.exempt) return false;
      const limit = limitOf(key);
      return limit >= 0 && usedOf(key) >= limit;
    },
  };
}
