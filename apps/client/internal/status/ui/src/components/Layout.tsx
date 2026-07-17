// Layout.tsx — top bar + sidebar + content shell. Shared by every page.
//
// The healthz query polls every 5s so the top-of-screen badge stays
// honest about whether the daemon is still talking to the edge.
import {
  AppstoreOutlined,
  BarsOutlined,
  CheckOutlined,
  CloudServerOutlined,
  DownOutlined,
  ExclamationCircleOutlined,
  FileTextOutlined,
  GlobalOutlined,
  HddOutlined,
  LockOutlined,
  LogoutOutlined,
  SettingOutlined,
  TeamOutlined,
  ThunderboltOutlined,
  TranslationOutlined,
} from "@ant-design/icons";
import {
  Avatar,
  Badge,
  Dropdown,
  Layout as AntLayout,
  Menu,
  Modal,
  Space,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo } from "react";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api/client";
import Logo from "./Logo";
import type {
  AccountMe,
  EdgeAffinity,
  EdgeList,
  Healthz,
  Lifecycle,
  OrgListResponse,
  Snapshot,
  TunnelList,
} from "../api/types";
import { planLabel } from "../utils/plan";
import { useServiceMode } from "../hooks/use-service-mode";
import { useTranslation } from "react-i18next";
import { LANGS, resolveLang, type LangCode } from "../i18n/languages";

const { Sider, Header, Content } = AntLayout;
const { Text } = Typography;

const lifecycleColor: Record<Lifecycle, string> = {
  starting: "processing",
  connecting: "processing",
  connected: "success",
  reconnecting: "warning",
  stopped: "default",
  fatal: "error",
  unavailable: "error",
  unknown: "default",
};

export default function Layout() {
  const { t, i18n } = useTranslation();
  const currentLang: LangCode = resolveLang(i18n.language);
  const location = useLocation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const active = location.pathname.split("/")[1] || "overview";

  const { data: health } = useQuery<Healthz>({
    queryKey: ["healthz"],
    queryFn: api.healthz,
    refetchInterval: 5_000,
  });

  // snap + edges feed the top-bar 「edge <region>」 chip — we used to
  // print the bare IP:port from /healthz which doesn't say much to the
  // user. Joining snap.edge_node_id against the edge directory lets us
  // print "cn-chengdu" / "cn-hangzhou" instead. Both queries are cached
  // (snap 2s, edges 30s) so the extra fetches are essentially free.
  const { data: snap } = useQuery<Snapshot>({
    queryKey: ["snapshot"],
    queryFn: api.snapshot,
    refetchInterval: 5_000,
  });
  const { data: edgeList } = useQuery<EdgeList>({
    queryKey: ["edges"],
    queryFn: api.edges,
    refetchInterval: 30_000,
    retry: false,
  });
  const currentEdgeRegion = (() => {
    const eid = snap?.edge_node_id ?? 0;
    if (!eid) return "";
    const m = (edgeList?.items ?? []).find((e) => e.edge_node_id === eid);
    return m?.region || "";
  })();

  // me is already cached by AuthGate. Reuse to drive the topbar
  // user chip + logout dropdown.
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    retry: false,
  });
  // Standalone (self-hosted local daemon): no account / org / region concepts.
  // Hide the logout + region switcher; the org switcher and BYOI egress toggle
  // already hide themselves on the empty /v1/orgs + owned_total:0 stubs.
  const standalone = me?.plan?.code === "standalone";
  // Agent mode: the daemon runs on a pinned API-key identity. The daemon 403s
  // sign-in / sign-out / org-switch (IDENTITY changes), so those affordances are
  // hidden + a pinned-identity chip is shown. The region + egress (BYOI) switchers
  // are NOT identity — they're data-plane routing prefs — so an agent operator
  // CAN change them from the local console (they just pick which edge/region the
  // pinned identity connects to). canManage distinguishes a management key
  // (writable console) from a read-only key (read-only chip).
  const { agentMode, canManage } = useServiceMode();

  // M11.7 multi-Org: list the user's memberships so the topbar can
  // expose a switcher. Cached for the lifetime of the SPA — orgs
  // rarely change within a session; switchOrg invalidates this on
  // success via window.location.reload().
  const { data: orgsResp } = useQuery<OrgListResponse>({
    queryKey: ["orgs"],
    queryFn: api.listOrgs,
    enabled: !!me?.user?.id,
    retry: false,
    staleTime: 60_000,
  });
  const orgs = orgsResp?.items ?? [];
  // Source-of-truth for "which Org am I in" is the daemon snapshot's
  // active_org_id (creds.ActiveOrgID — the org the token is scoped to),
  // polled every 5s. /v1/orgs.active_org_id is cached 60s and only refreshes
  // on a full reload, so after an Org switch it could lag while the
  // (token-scoped) tunnel list already flipped — making the chip show one
  // Org and the tunnels another. Snapshot tracks the token within one poll,
  // so the chip and the list stay in lockstep even if the switch's reload is
  // skipped. orgsResp/me are only fallbacks for the pre-snapshot window.
  const activeOrgID =
    snap?.active_org_id || orgsResp?.active_org_id || me?.org?.id || 0;
  const activeOrg = orgs.find((o) => o.id === activeOrgID);

  // Show the switcher only when the user actually belongs to >1 Org —
  // for a single-Org user (the common case) the dropdown is just noise.
  // The label rule mirrors web/console's orgDisplayName(): personal Orgs
  // collapse to "个人空间" regardless of the stored name.
  const orgDisplay = (o: { name?: string; kind?: string }): string => {
    if (o.kind === "personal") return t("topbar.personalSpace");
    return o.name || t("topbar.unnamed");
  };

  const switchOrgMu = useMutation({
    mutationFn: (id: number) => api.switchOrg(id),
    onSuccess: async (_d, id) => {
      const o = orgs.find((x) => x.id === id);
      message.success(
        t("orgSwitch.switchedTo", {
          name: o ? orgDisplay(o) : t("orgSwitch.newOrg"),
        }),
      );
      // Full reload: the daemon already cancelled the in-flight edge
      // session via OnOrgSwitched, AND the new bearer is now in creds.
      // Reloading at the same URL triggers every page's queries to
      // re-fire with the new Org scope. Cleaner than threading "now
      // refetch everything" through the auth tree.
      window.location.reload();
    },
    onError: (e: any) => {
      const msg = (e as Error)?.message || t("orgSwitch.failed");
      message.error(msg);
    },
  });

  const logout = useMutation({
    mutationFn: api.logout,
    onSuccess: async () => {
      message.success(t("common.loggedOut"));
      await qc.invalidateQueries();
      navigate("/login", { replace: true });
    },
    onError: () => {
      // Even on upstream failure the local creds were cleared by the
      // handler — push the user to login anyway.
      qc.invalidateQueries();
      navigate("/login", { replace: true });
    },
  });

  // Org switcher dropdown items. Built outside JSX so the menu config
  // stays readable. Active Org gets a check mark + brand-blue highlight.
  const orgSwitcherMenu = {
    items: [
      {
        key: "_header",
        disabled: true,
        label: (
          <span style={{ color: "#8c8c8c", fontSize: 12 }}>
            {t("topbar.switchOrg")}
          </span>
        ),
      },
      { type: "divider" as const },
      ...orgs.map((o) => ({
        key: `org-${o.id}`,
        label: (
          <span
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              minWidth: 220,
              fontWeight: o.id === activeOrgID ? 600 : 400,
              color: o.id === activeOrgID ? "#5e7fff" : "inherit",
            }}
          >
            {o.id === activeOrgID ? (
              <CheckOutlined />
            ) : (
              <span style={{ width: 14 }} />
            )}
            <span style={{ flex: 1 }}>{orgDisplay(o)}</span>
            <Tag
              color={o.kind === "team" ? "blue" : "default"}
              style={{ marginRight: 0, fontSize: 11 }}
            >
              {o.kind === "team" ? t("topbar.team") : t("topbar.personal")}
            </Tag>
          </span>
        ),
        onClick: () => {
          if (o.id === activeOrgID || switchOrgMu.isPending) return;
          // M11.8: explicit confirm step. The daemon's data plane
          // is one-session-at-a-time — switching Org rebinds the
          // edge connection to the new Org and the previous Org's
          // tunnels lose their auto-claim (show as 离线 until you
          // switch back). Surface that as a Modal so the user
          // doesn't blame us when their old tunnels go dark.
          Modal.confirm({
            title: t("orgSwitch.confirmTitle", { name: orgDisplay(o) }),
            content: (
              <div>
                <p style={{ marginTop: 0 }}>
                  {t("orgSwitch.body1", { name: orgDisplay(o) })}
                </p>
                <p style={{ marginBottom: 0, color: "#8c8c8c" }}>
                  {t("orgSwitch.body2", {
                    name: activeOrg ? orgDisplay(activeOrg) : "",
                  })}
                </p>
              </div>
            ),
            okText: t("common.switch"),
            cancelText: t("common.cancel"),
            onOk: () => switchOrgMu.mutate(o.id),
          });
        },
      })),
    ],
  };

  // ---- manual region switcher --------------------------------------------
  // Cross-region auto-switch is disabled in the daemon (same-region HA
  // failover stays automatic). This top-bar dropdown is the user-driven
  // escape hatch: pick another region by hand, with an Org-switch-style
  // confirm. It doubles as the "服务器不可用，可手动切换地域" affordance —
  // when the daemon parks (lifecycle "unavailable") the chip turns red.
  const unavailable = health?.state === "unavailable";
  // The region we're anchored to: the live edge's region when connected,
  // else the daemon's persisted preferred region (survives disconnects and
  // the parked state, where there's no live edge_node_id to derive from).
  const currentRegion = currentEdgeRegion || snap?.preferred_region || "";
  // ---- BYOI data-egress affinity (derivation) ---------------------------
  // Defined here (above the region switcher) because the switcher is scoped
  // by the egress choice. Visibility is ENTITLEMENT-based: the org owns ≥1
  // self-hosted edge (edgeList.owned_total, from cert-svc — independent of
  // liveness), so a BYOI user keeps the egress control even when their edge
  // is momentarily offline. hasLiveOwnEdge tracks whether any owned edge is
  // actually UP right now (a live owned=true row); when the user prefers
  // "own" but none is live, the chip shows a "节点离线" warning so it never
  // lies about the real egress path.
  const hasLiveOwnEdge = useMemo(
    () => (edgeList?.items ?? []).some((e) => e.owned),
    [edgeList],
  );
  const hasOwnEdge = (edgeList?.owned_total ?? 0) > 0 || hasLiveOwnEdge;
  const { data: affinity } = useQuery<EdgeAffinity>({
    queryKey: ["edge-affinity"],
    queryFn: api.getEdgeAffinity,
    enabled: hasOwnEdge,
    staleTime: 30_000,
  });
  const preferPlatform = affinity?.prefer_platform ?? false;
  // User wants their own edge but none is currently live in the directory —
  // traffic is silently falling back to the platform plane. Flag it so the
  // chip shows a warning instead of a confident "出口 自建".
  const ownEdgeOffline = hasOwnEdge && !preferPlatform && !hasLiveOwnEdge;

  // True when the daemon's LIVE edge belongs to the OTHER egress class than
  // the one the dropdown is scoped to — i.e. egress=自建 but the own edge is
  // offline so the picker fell back to a PLATFORM edge (soft policy: never
  // strand the daemon). In that state currentRegion is a cross-class fallback
  // region and must NOT be injected into the scoped region list below;
  // otherwise a platform region (e.g. cn-b) shows up under "切换自建节点"
  // mislabeled as the current self-built node. Only meaningful for BYOI orgs
  // (the class split exists); eid==0 (parked, no live edge) is NOT cross-class
  // — there currentRegion is the anchored own region and should still list so
  // the user can retry it.
  const liveEdgeIsCrossClass = useMemo(() => {
    if (!hasOwnEdge) return false;
    const eid = snap?.edge_node_id ?? 0;
    if (!eid) return false;
    const live = (edgeList?.items ?? []).find((e) => e.edge_node_id === eid);
    if (!live) return false;
    return preferPlatform ? !!live.owned : !live.owned;
  }, [hasOwnEdge, snap, edgeList, preferPlatform]);

  // The region/edge switcher is SCOPED to the current egress choice: in "自建"
  // mode it lists only the org's own (BYOI) edges; in "平台" mode only platform
  // edges. Non-BYOI orgs (no own edge → no affinity toggle) see the full
  // platform set unchanged. Mirrors the picker, which routes to the matching
  // plane — so the dropdown only ever offers targets the daemon would land on.
  const edgeItemsForRegions = useMemo(() => {
    const items = edgeList?.items ?? [];
    if (!hasOwnEdge) return items; // non-BYOI: all platform, no split
    return items.filter((e) => (preferPlatform ? !e.owned : !!e.owned));
  }, [edgeList, hasOwnEdge, preferPlatform]);

  // Switchable regions — unique non-empty regions from the (affinity-scoped)
  // edge set, plus the current one (so it still lists even if its edges
  // dropped out, e.g. the region is down and that's exactly why we parked).
  const regions = useMemo(() => {
    const set = new Set<string>();
    edgeItemsForRegions.forEach((e) => {
      if (e.region) set.add(e.region);
    });
    // Surface the current region too (so a region whose edges dropped out —
    // e.g. it's down and that's why we parked — still lists for a retry), BUT
    // only when it belongs to THIS dropdown's egress class. When egress=自建
    // and the own edge is offline, the live edge is a platform fallback whose
    // region must not masquerade as a self-built node.
    if (currentRegion && !liveEdgeIsCrossClass) set.add(currentRegion);
    return Array.from(set).sort();
  }, [edgeItemsForRegions, currentRegion, liveEdgeIsCrossClass]);

  // Per-region edge health for the dropdown: how many edges are healthy out
  // of the total in each region. Drives a green/red dot + "N/M 在线" hint so
  // the user can see at a glance which region is worth switching to.
  const regionHealth = useMemo(() => {
    const m = new Map<string, { total: number; healthy: number }>();
    edgeItemsForRegions.forEach((e) => {
      if (!e.region) return;
      const cur = m.get(e.region) ?? { total: 0, healthy: 0 };
      cur.total += 1;
      if (e.healthy) cur.healthy += 1;
      m.set(e.region, cur);
    });
    return m;
  }, [edgeItemsForRegions]);

  // Per-region tunnel count for the current identity. The daemon's /v1/tunnels
  // is already scoped to the active Org and filtered to THIS user's tunnels
  // (created_by_me || bound to this device), so counting items by their bound
  // edge's region gives "我在每个地域有几条隧道" — the figure the dropdown shows
  // on the right of each row. Same edge→region join Tunnels.tsx uses.
  const { data: tunnelList } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
    refetchInterval: 30_000,
    retry: false,
    enabled: !standalone,
  });
  const edgeRegionById = useMemo(() => {
    const m = new Map<number, string>();
    (edgeList?.items ?? []).forEach((e) => {
      if (e.region) m.set(e.edge_node_id, e.region);
    });
    return m;
  }, [edgeList]);
  const regionTunnelCount = useMemo(() => {
    const m = new Map<string, number>();
    (tunnelList?.items ?? []).forEach((tn) => {
      const rg = tn.edge_node_id ? edgeRegionById.get(tn.edge_node_id) : "";
      if (!rg) return; // unbound / pending / edge not in directory → no region
      m.set(rg, (m.get(rg) ?? 0) + 1);
    });
    return m;
  }, [tunnelList, edgeRegionById]);

  const switchRegionMu = useMutation({
    mutationFn: (region: string) => api.switchRegion(region),
    onSuccess: (_d, region) => {
      message.success(t("region.switchedTo", { region }));
      // Full reload — the daemon re-anchored + kicked the session; every
      // page should re-query against the new region cleanly. Same shape as
      // the Org switcher.
      window.location.reload();
    },
    onError: (e: any) => {
      message.error((e as Error)?.message || t("region.failed"));
    },
  });

  const pickRegion = (region: string) => {
    if (switchRegionMu.isPending) return;
    const retry = region === currentRegion;
    // A same-region click only does something when we're parked (it retries
    // the current region). Otherwise it's a no-op.
    if (retry && !unavailable) return;
    Modal.confirm({
      title: retry
        ? t("region.reconnectTitle", { region })
        : t("region.switchTitle", { region }),
      content: retry ? (
        <p style={{ margin: 0 }}>{t("region.reconnectBody")}</p>
      ) : (
        <div>
          <p style={{ marginTop: 0 }}>
            {t("region.switchBody1", { region })}
          </p>
          <p style={{ marginBottom: 0, color: "#8c8c8c" }}>
            {t("region.switchBody2")}
          </p>
        </div>
      ),
      okText: retry ? t("common.reconnect") : t("common.switch"),
      cancelText: t("common.cancel"),
      onOk: () => switchRegionMu.mutate(region),
    });
  };

  // ---- BYOI data-egress affinity (mutation + menu) ----------------------
  // The derivation (hasOwnEdge / preferPlatform / ownEdgeOffline /
  // hasLiveOwnEdge) lives above, next to the region switcher it also scopes.
  const setAffinityMu = useMutation({
    mutationFn: (a: "own" | "platform") => api.setEdgeAffinity(a),
    onSuccess: (_d, a) => {
      message.success(
        a === "own"
          ? t("affinity.switchedOwn")
          : t("affinity.switchedPlatform"),
      );
      // Daemon re-anchored + kicked the session — reload like the region switch.
      window.location.reload();
    },
    onError: (e: unknown) => {
      message.error((e as Error)?.message || t("affinity.failed"));
    },
  });
  const pickAffinity = (a: "own" | "platform") => {
    if (setAffinityMu.isPending) return;
    if ((a === "platform") === preferPlatform) return; // no-op (already there)
    Modal.confirm({
      title: a === "own" ? t("affinity.toOwnTitle") : t("affinity.toPlatformTitle"),
      content: (
        <div>
          <p style={{ marginTop: 0 }}>
            {a === "own" ? t("affinity.toOwnBody") : t("affinity.toPlatformBody")}
          </p>
          <p style={{ marginBottom: 0, color: "#8c8c8c" }}>
            {t("affinity.bodyNote")}
          </p>
        </div>
      ),
      okText: t("common.switch"),
      cancelText: t("common.cancel"),
      onOk: () => setAffinityMu.mutate(a),
    });
  };
  const affinityRow = (active: boolean, label: string) => (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 8,
        minWidth: 180,
        fontWeight: active ? 600 : 400,
        color: active ? "#5e7fff" : "inherit",
      }}
    >
      {active ? <CheckOutlined /> : <span style={{ width: 14 }} />}
      <span>{label}</span>
    </span>
  );
  const affinityMenu = {
    items: [
      {
        key: "_aff_header",
        disabled: true,
        label: (
          <span style={{ color: "#8c8c8c", fontSize: 12 }}>
            {t("affinity.header")}
          </span>
        ),
      },
      { type: "divider" as const },
      {
        key: "aff-own",
        label: affinityRow(!preferPlatform, t("affinity.own")),
        onClick: () => pickAffinity("own"),
      },
      {
        key: "aff-platform",
        label: affinityRow(preferPlatform, t("affinity.platform")),
        onClick: () => pickAffinity("platform"),
      },
    ],
  };

  const regionMenu = {
    items: [
      {
        key: "_region_header",
        disabled: true,
        label: (
          <span style={{ color: "#8c8c8c", fontSize: 12 }}>
            {hasOwnEdge && !preferPlatform
              ? t("region.switchOwnNode")
              : t("region.switchRegion")}
          </span>
        ),
      },
      { type: "divider" as const },
      // Empty-state: egress=自建 but no own edge is live (and we didn't inject a
      // cross-class fallback region above) → the scoped list is empty. Show a
      // disabled placeholder instead of a bare header so the dropdown doesn't
      // look broken. The egress chip already carries the "(离线)" warning.
      ...(regions.length === 0
        ? [
            {
              key: "_region_empty",
              disabled: true,
              label: (
                <span style={{ color: "#bfbfbf", fontSize: 12 }}>
                  {t("region.noOwnNodeOnline")}
                </span>
              ),
            },
          ]
        : []),
      ...regions.map((rg) => {
        const h = regionHealth.get(rg);
        return {
          key: `region-${rg}`,
          label: (
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 8,
                minWidth: 220,
                fontWeight: rg === currentRegion ? 600 : 400,
                color: rg === currentRegion ? "#5e7fff" : "inherit",
              }}
            >
              {rg === currentRegion ? (
                <CheckOutlined />
              ) : (
                <span style={{ width: 14 }} />
              )}
              <span>{rg}</span>
              {/* The checkmark already marks the current region — no extra
                  「当前」tag needed. Spacer pushes the per-region tunnel count
                  to the far right. */}
              <span style={{ flex: 1 }} />
              {/* Right-aligned: how many of THIS identity's tunnels live in
                  this region. The dot still reflects edge reachability (green =
                  has a healthy edge, red = region down) so a region you can't
                  switch to is still visually flagged. */}
              <Badge
                status={
                  !h ? "default" : h.healthy > 0 ? "success" : "error"
                }
                text={
                  <span style={{ fontSize: 11, color: "#8c8c8c" }}>
                    {t("region.tunnelCount", {
                      count: regionTunnelCount.get(rg) ?? 0,
                    })}
                  </span>
                }
              />
            </span>
          ),
          onClick: () => pickRegion(rg),
        };
      }),
    ],
  };

  return (
    // height:100vh + overflow:hidden on the outer shell pins the sidebar
    // and topbar in place; only the inner Content scrolls. The browser-
    // window scrollbar is gone, replaced by a thin scrollbar that lives
    // inside the content area — feels more like a native desktop app
    // and stops the "this is a web page" giveaway when the page
    // (Overview, Logs) is taller than the window.
    <AntLayout style={{ height: "100vh", overflow: "hidden" }}>
      <Sider
        width={200}
        theme="dark"
        style={{ borderRight: "1px solid rgba(255,255,255,0.08)" }}
      >
        {/* Full-height flex column INSIDE the sider-children wrapper. Putting
            flex on <Sider> styles the outer <aside>, NOT the inner
            .ant-layout-sider-children div that actually wraps these children —
            so without this wrapper the account block's marginTop:auto can't
            pin it to the very bottom. */}
        <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
        {/* Brand lockup — mirrors the marketing site (web/www Header): the
            #2742f0 mark + the "calabi" wordmark with a brand-blue "b". */}
        <div
          style={{
            padding: "16px 20px",
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Logo size={28} />
          <span
            style={{
              fontSize: 20,
              fontWeight: 700,
              letterSpacing: "-0.02em",
              lineHeight: 1,
              color: "#fff",
            }}
          >
            cala<span style={{ color: "#22d3ee" }}>b</span>i
          </span>
        </div>
        <Menu
          mode="inline"
          selectedKeys={[active]}
          style={{ borderInlineEnd: "none" }}
          items={[
            {
              key: "overview",
              icon: <AppstoreOutlined />,
              label: <Link to="/overview">{t("nav.overview")}</Link>,
            },
            {
              key: "tunnels",
              icon: <BarsOutlined />,
              label: <Link to="/tunnels">{t("nav.tunnels")}</Link>,
            },
            {
              key: "logs",
              icon: <FileTextOutlined />,
              label: <Link to="/logs">{t("nav.logs")}</Link>,
            },
            {
              key: "tools",
              icon: <ThunderboltOutlined />,
              label: <Link to="/tools">{t("nav.tools")}</Link>,
            },
            {
              key: "settings",
              icon: <SettingOutlined />,
              label: <Link to="/settings">{t("nav.settings")}</Link>,
            },
          ]}
        />
        {/* Bottom of the sidebar, pinned via marginTop:auto:
            (1) parked-state prompt when the daemon gave up reconnecting
                (informational only — region switch is the top-right dropdown), and
            (2) the account / logout row — moved here from the top bar so the
                top bar stays single-line (no horizontal scroll). */}
        <div style={{ marginTop: "auto" }}>
          {unavailable && (
            <div style={{ padding: 12 }}>
              <div
                style={{
                  background: "rgba(255,77,79,0.12)",
                  border: "1px solid rgba(255,77,79,0.3)",
                  borderRadius: 8,
                  padding: "10px 12px",
                }}
              >
                <div
                  style={{
                    color: "#ff7875",
                    fontWeight: 600,
                    fontSize: 13,
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  <ExclamationCircleOutlined />
                  {t("lifecycle.unavailable")}
                </div>
                <div style={{ color: "#8c8c8c", fontSize: 12, marginTop: 6 }}>
                  {t("region.parkedNote")}
                </div>
              </div>
            </div>
          )}
          {me?.user &&
            (() => {
              // Account row (sidebar bottom): avatar + "username · Plan",
              // where username is the local-part of the email. The popup
              // (opens upward) carries the full email, a Language submenu
              // (EN / 中文 with a check on the active one), and Log out.
              const email = me.user.email || "";
              const username = (email || "user").split("@")[0] || "user";
              const planName = me.plan?.code ? planLabel(me.plan.code) : "";
              const langStyle = (k: LangCode) => ({
                display: "inline-flex" as const,
                alignItems: "center" as const,
                gap: 8,
                minWidth: 120,
                fontWeight: currentLang === k ? 600 : 400,
                color: currentLang === k ? "#5e7fff" : "inherit",
              });
              return (
                <Dropdown
                  trigger={["click"]}
                  placement="topLeft"
                  menu={{
                    items: [
                      {
                        key: "email",
                        label: (
                          <span style={{ color: "#64748b", fontSize: 12 }}>
                            {email}
                          </span>
                        ),
                        disabled: true,
                      },
                      { type: "divider" },
                      {
                        key: "language",
                        icon: <TranslationOutlined />,
                        label: t("topbar.language"),
                        children: LANGS.map((lang) => ({
                          key: `lang-${lang.code}`,
                          label: (
                            <span style={langStyle(lang.code)}>
                              {currentLang === lang.code ? (
                                <CheckOutlined />
                              ) : (
                                <span style={{ width: 14 }} />
                              )}
                              {lang.label}
                            </span>
                          ),
                          onClick: () =>
                            currentLang !== lang.code &&
                            i18n.changeLanguage(lang.code),
                        })),
                      },
                      ...(standalone || agentMode
                        ? []
                        : [
                            { type: "divider" as const },
                            {
                              key: "logout",
                              icon: <LogoutOutlined />,
                              danger: true,
                              label: t("topbar.logout"),
                              onClick: () => logout.mutate(),
                            },
                          ]),
                    ],
                  }}
                >
                  <div
                    style={{
                      cursor: "pointer",
                      borderTop: "1px solid rgba(255,255,255,0.08)",
                      padding: "10px 12px",
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                    }}
                  >
                    <Avatar
                      size="small"
                      style={{
                        backgroundColor: "#5e7fff",
                        flexShrink: 0,
                        fontSize: 12,
                      }}
                    >
                      {username.charAt(0).toUpperCase()}
                    </Avatar>
                    <Text ellipsis style={{ flex: 1, minWidth: 0, fontSize: 13 }}>
                      {username}
                      {planName && (
                        <span style={{ color: "#8c8c8c" }}>{` · ${planName}`}</span>
                      )}
                    </Text>
                    <DownOutlined style={{ fontSize: 10, color: "#94a3b8" }} />
                  </div>
                </Dropdown>
              );
            })()}
        </div>
        </div>
      </Sider>
      <AntLayout>
        <Header
          style={{
            background: "#0b1022",
            borderBottom: "1px solid rgba(255,255,255,0.08)",
            padding: "0 16px",
            display: "flex",
            alignItems: "center",
            gap: 12,
            // Single-line top bar: nowrap keeps the chips on one row (English
            // labels are ~1.5–2× wider than Chinese). overflow:hidden (not
            // overflowX:auto) — the latter makes overflow-y compute to auto,
            // which on a fixed-height Header shows a stray VERTICAL scrollbar.
            // The bar is trimmed enough to fit; a too-narrow window clips the
            // rightmost chip rather than showing any scrollbar.
            whiteSpace: "nowrap",
            overflow: "hidden",
          }}
        >
          <Space size="small" style={{ flexShrink: 0 }}>
            {/* 顶栏只放数据面相关:组织 / 在线状态 / 出口 / 地域。套餐名 + 账号 +
                语言切换都收进左侧菜单栏底部的账号菜单(「用户名 · 套餐」+ 语言 +
                退出),「本机客户端」标题已删(冗余)。 */}
            {/* M11.7 multi-Org switcher — only render when the user
                actually has more than one Org. Single-Org accounts get
                no extra chrome to wade through. */}
            {orgs.length > 1 && activeOrg && !agentMode && (
              <Dropdown
                trigger={["click"]}
                menu={orgSwitcherMenu}
                disabled={switchOrgMu.isPending}
              >
                <Space
                  size={6}
                  style={{
                    cursor: "pointer",
                    padding: "2px 10px",
                    borderRadius: 6,
                    background: "rgba(255,255,255,0.06)",
                    fontSize: 13,
                  }}
                >
                  <TeamOutlined style={{ color: "#5e7fff" }} />
                  <Text style={{ fontSize: 13, fontWeight: 500 }}>
                    {orgDisplay(activeOrg)}
                  </Text>
                  <DownOutlined style={{ fontSize: 10, color: "#94a3b8" }} />
                </Space>
              </Dropdown>
            )}
            {/* Single-Org accounts — and agent mode (no switching) — see the Org
                name read-only so they have context, but no clickable affordance. */}
            {activeOrg && (agentMode || orgs.length === 1) && (
              <Text type="secondary" style={{ fontSize: 13 }}>
                <TeamOutlined style={{ marginInlineEnd: 4 }} />
                {orgDisplay(activeOrg)}
              </Text>
            )}
            {/* Agent mode: pinned identity. A lock chip + tooltip make it obvious
                this console can't change identity. A management key still manages
                tunnels (green chip); a read-only key shows the read-only chip. */}
            {agentMode && (
              <Tooltip
                title={t(
                  canManage ? "serviceMode.agentManageTooltip" : "serviceMode.agentTooltip",
                  {
                    // An agent is an ORG credential (no human user_id), so the
                    // identity is the org it's pinned to. me.org is always set
                    // (account/me); fall back to #id if the name is blank, and
                    // only then to a logged-in email (interactive edge case).
                    identity:
                      me?.org?.name ||
                      (activeOrg ? orgDisplay(activeOrg) : "") ||
                      (me?.org?.id ? `#${me.org.id}` : "") ||
                      me?.user?.email ||
                      "",
                  },
                )}
              >
                <Tag
                  icon={<LockOutlined />}
                  color={canManage ? "success" : "default"}
                  style={{ fontSize: 12, marginInlineEnd: 0 }}
                >
                  {canManage ? t("serviceMode.agentTag") : t("serviceMode.readonlyTag")}
                </Tag>
              </Tooltip>
            )}
            {health && (
              <Badge
                status={lifecycleColor[health.state] as any}
                text={t(`lifecycle.${health.state}`)}
              />
            )}
          </Space>
          <Space size="small" style={{ flexShrink: 0, marginLeft: "auto" }}>
            {/* Region switcher — manual cross-region switch (auto-switch
                is disabled in the daemon). Stays neutral; the "服务器不可用"
                prompt lives at the bottom of the left sidebar instead, so it
                doesn't crowd the header and isn't bound to the current page. */}
            {health && hasOwnEdge && (
              <Tooltip
                title={
                  ownEdgeOffline ? t("topbar.ownEdgeOfflineTip") : undefined
                }
              >
                <Dropdown
                  trigger={["click"]}
                  menu={affinityMenu}
                  disabled={setAffinityMu.isPending}
                >
                  <Space
                    size={6}
                    style={{
                      cursor: "pointer",
                      padding: "2px 10px",
                      borderRadius: 6,
                      background: ownEdgeOffline
                        ? "rgba(245,158,11,0.15)"
                        : preferPlatform
                          ? "rgba(255,255,255,0.06)"
                          : "rgba(16,185,129,0.15)",
                      fontSize: 13,
                    }}
                  >
                    {ownEdgeOffline ? (
                      <ExclamationCircleOutlined style={{ color: "#d48806" }} />
                    ) : preferPlatform ? (
                      <CloudServerOutlined style={{ color: "#5e7fff" }} />
                    ) : (
                      <HddOutlined style={{ color: "#059669" }} />
                    )}
                    <Text style={{ fontSize: 13 }}>
                      {t("topbar.egress")}{" "}
                      {preferPlatform
                        ? t("topbar.egressPlatform")
                        : t("topbar.egressOwn")}
                      {ownEdgeOffline ? t("topbar.egressOfflineSuffix") : ""}
                    </Text>
                    <DownOutlined style={{ fontSize: 10, color: "#94a3b8" }} />
                  </Space>
                </Dropdown>
              </Tooltip>
            )}
            {health && !standalone && (regions.length > 0 || currentRegion) && (
              <Dropdown
                trigger={["click"]}
                menu={regionMenu}
                disabled={switchRegionMu.isPending}
              >
                <Space
                  size={6}
                  style={{
                    cursor: "pointer",
                    padding: "2px 10px",
                    borderRadius: 6,
                    background: "rgba(255,255,255,0.06)",
                    fontSize: 13,
                  }}
                >
                  <GlobalOutlined style={{ color: "#5e7fff" }} />
                  <Text style={{ fontSize: 13 }}>
                    edge {currentRegion || health.server_addr}
                  </Text>
                  <DownOutlined style={{ fontSize: 10, color: "#94a3b8" }} />
                </Space>
              </Dropdown>
            )}
            {health &&
              (standalone || (regions.length === 0 && !currentRegion)) && (
                <Text type="secondary" style={{ fontSize: 13 }}>
                  edge {currentRegion || health.server_addr}
                </Text>
              )}
          </Space>
        </Header>
        <Content
          className="calabi-content"
          style={{
            margin: 0,
            padding: 24,
            background: "transparent",
            overflow: "auto",
          }}
        >
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  );
}
