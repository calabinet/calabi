// TunnelNew.tsx — 新建隧道, as a page with steps.
//
// It was a modal, and the modal was the problem. Creating a tunnel is not one
// decision: it is a protocol, a local address, a public address, and — in an
// organization with a security baseline — the set of addresses allowed to reach
// it. All of that in one scrolling dialog put the security question below the
// fold, which is exactly where a required field should not be, and gave the
// whole thing the shape of an interruption rather than a task.
//
// Three steps, and the third did not exist before:
//
//  1. 基本信息 — what is being published, and where the public endpoint lands.
//     The local-service reachability probe lives here, beside the address it is
//     about.
//  2. 访问策略 — who may reach it. When the org requires protection for THIS
//     tunnel type, the step cannot be passed without an answer. It is its own
//     step precisely so a required answer is on screen by itself.
//  3. 创建完成 — what actually happened. A create returns a row that is only
//     half decided: the public domain or port is assigned by the edge that
//     claims it, which takes a second or two and sometimes longer. The old
//     modal closed on success and dropped the reader on a list row reading
//     待接入, which reads as failure. This step says 分配中 and fills the
//     values in as they arrive.
//
// Mirrors web/console's tunnels/Create.tsx, with the differences the desktop
// client actually has: client_id is always THIS machine (no picker), and the
// local service can be probed from here because the daemon is on the same host
// as the service. The egress is not offered either — the daemon is already
// connected to exactly one edge, and that is the one that will serve this
// tunnel; the choice lives in 设置 → 数据出口, as a property of the machine.
//
// The gate is still tunnel-svc's. Everything here decides what to ASK, never
// what is allowed — see apps/tunnel-svc/internal/store/baseline.go.
//
// The form stays MOUNTED across steps (bodies hidden, not unmounted) so AntD
// keeps every field registered: values, watched fields and the address preview
// behave on step 2 exactly as they did on step 1.
import {
  Alert,
  Button,
  Descriptions,
  Divider,
  Form,
  Input,
  InputNumber,
  Modal,
  Result,
  Select,
  Space,
  Steps,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import {
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api, ApiError } from "../api/client";
import { CopyableAddr, edgeHttpURL, portTunnelHost, truncateDomain } from "../lib/addr";
import { useServiceMode } from "../hooks/use-service-mode";
import { useMemberQuota } from "../lib/memberQuota";
import type {
  AccountMe,
  ClientDevicesList,
  CreateTunnelBody,
  DomainList,
  EdgeList,
  IPPolicy,
  OrgSecurity,
  ProbeCheck,
  RemoteTunnel,
  Snapshot,
  TunnelList,
} from "../api/types";

const { Title, Text } = Typography;

// PlanFeatures mirrors the gating subset of quota-svc features_json (see
// apps/bff-console/internal/handlers/tunnels.go planFeatures). tcp/udp = 专业版+;
// sni = 增强版; ip_policy / basic_auth = 基础版+.
// NOTE: custom_domain is NOT plan-gated here — 自购域名 ⟺ 自建节点, so the
// http/https domain form keys off onOwnEdge (current edge ownership), not
// features.custom_domain.
type PlanFeatures = {
  tcp: boolean;
  udp: boolean;
  sni: boolean;
  custom_domain: boolean;
  ip_policy: boolean;
  basic_auth: boolean;
};
function parseFeatures(json?: string): PlanFeatures {
  const empty = {
    tcp: false,
    udp: false,
    sni: false,
    custom_domain: false,
    ip_policy: false,
    basic_auth: false,
  };
  if (!json) return empty;
  try {
    const o = JSON.parse(json) as Partial<PlanFeatures>;
    return {
      tcp: !!o.tcp,
      udp: !!o.udp,
      sni: !!o.sni,
      custom_domain: !!o.custom_domain,
      ip_policy: !!o.ip_policy,
      basic_auth: !!o.basic_auth,
    };
  } catch {
    return empty;
  }
}

// Byte-passthrough types, which have no L7 and so can only ever be guarded by an
// address list. Mirrors store.IsBarePort in tunnel-svc, which is the one that
// decides — this copy exists so the form asks for the right thing before
// submitting, not so the client can decide anything.
function isBarePortType(tunnelType: string): boolean {
  switch ((tunnelType || "").trim().toLowerCase()) {
    case "tcp":
    case "udp":
    case "sni":
      return true;
    default:
      return false;
  }
}

// Whether an allow list actually shuts anyone out. Mirrors store.allowListCloses
// in tunnel-svc. A `0.0.0.0/0` entry admits the whole address family and makes
// the rest of the list irrelevant, so an org requiring protection refuses a
// tunnel guarded only by that.
function allowListCloses(entries: string[]): boolean {
  let closes = false;
  for (const raw of entries) {
    const e = raw.trim();
    if (!e) continue;
    const slash = e.lastIndexOf("/");
    if (slash < 0) {
      closes = true; // a bare address is as narrow as it gets
      continue;
    }
    const prefix = Number(e.slice(slash + 1));
    if (!Number.isInteger(prefix)) continue; // unparseable: the edge drops it
    if (prefix === 0) return false;
    closes = true;
  }
  return closes;
}

// Whether the protection somebody filled in satisfies a baseline, for a tunnel
// of this TYPE. Mirrors store.EffectiveProtection, and the asymmetry is the
// whole reason it is a function rather than an `||` at the call site: on a raw
// port a login counts for NOTHING, because the edge never applies one to byte
// passthrough. A form that accepted it would wave through a create the server
// then refuses.
function protectionCloses(
  tunnelType: string,
  p: { ipPolicy?: string; ipAllow?: string[]; basicAuthUsers?: number },
): boolean {
  const byIP = !!p.ipPolicy || allowListCloses(p.ipAllow || []);
  if (isBarePortType(tunnelType)) return byIP;
  return byIP || (p.basicAuthUsers || 0) > 0;
}

function splitLines(s: string): string[] {
  return (s || "")
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

// localAddrIssue validates a tunnel's local_addr client-side. Returns:
//   "format" — not a bare port or host:port (e.g. "www.google.com" — no port),
//   "public" — host is a PUBLIC IPv4 literal (open-relay risk),
//   ""       — acceptable, OR a hostname / IPv6 the browser can't judge (the
//              daemon resolves & checks it authoritatively in
//              validateLocalUpstream).
// A tunnel must forward to a local/intranet upstream (loopback, 10/8, 172.16/12,
// 192.168/16, link-local) or a LAN hostname, never an arbitrary public address.
function localAddrIssue(addr: string): "" | "format" | "public" {
  const v = (addr || "").trim();
  if (!v) return "";
  if (/^\d+$/.test(v)) return ""; // bare numeric port → loopback
  let host: string;
  let port: string;
  if (v.startsWith("[")) {
    // [ipv6]:port
    const end = v.indexOf("]:");
    if (end < 0) return "format";
    host = v.slice(1, end);
    port = v.slice(end + 2);
  } else {
    const c = v.lastIndexOf(":");
    if (c <= 0 || c === v.length - 1) return "format"; // no host or no port
    host = v.slice(0, c);
    port = v.slice(c + 1);
  }
  if (!/^\d+$/.test(port)) return "format";
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = +m[1];
    const b = +m[2];
    const local =
      a === 0 || // 0.0.0.0
      a === 127 || // loopback
      a === 10 || // 10/8
      (a === 172 && b >= 16 && b <= 31) || // 172.16/12
      (a === 192 && b === 168) || // 192.168/16
      (a === 169 && b === 254); // link-local
    if (!local) return "public";
  }
  return ""; // hostname / IPv6 — daemon resolves & checks
}

// probeMessage turns a failed check into one plain sentence.
//
// It reads `reason` — a stable code the daemon assigns (probe/reason.go) — and
// NOT the `error` text. Matching English substrings here would have been the
// obvious shortcut and would break the day Windows, Go, or a translation
// reworded anything; the daemon is the only place that can classify reliably,
// because only it holds the actual error value.
function probeMessage(t: TFunction, r: ProbeCheck): string {
  const known = ["refused", "timeout", "unreachable", "dns", "tls", "http_5xx", "invalid"];
  if (r.reason && known.includes(r.reason)) return t(`wizard.reason.${r.reason}`);
  // Unclassified: show what the daemon said rather than inventing a friendlier
  // sentence that might be wrong about the cause.
  return t("wizard.checkFail", { err: r.error || t("wizard.checkFailUnknown") });
}

// LocalCheckLine renders the reachability answer under the local-service row.
//
// It is a HINT, never a gate. "Nothing is listening on 127.0.0.1:8080" is a
// perfectly ordinary state five seconds before you start the dev server, so the
// unreachable case says so and still lets you create the tunnel — it just means
// the 502 you would otherwise have debugged from the public URL is explained
// here instead.
function LocalCheckLine({ checking, result }: { checking: boolean; result: ProbeCheck | null }) {
  const { t } = useTranslation();
  if (checking) {
    return (
      <Text type="secondary" style={{ fontSize: 12 }}>
        <LoadingOutlined /> {t("wizard.checkRunning")}
      </Text>
    );
  }
  if (!result) return null;
  if (result.healthy) {
    return (
      <Text type="success" style={{ fontSize: 12 }}>
        <CheckCircleOutlined /> {t("wizard.checkOk", { ms: result.latency_ms })}
      </Text>
    );
  }
  return (
    <span style={{ fontSize: 12 }}>
      <Text type="warning">
        <ExclamationCircleOutlined /> {probeMessage(t, result)}
      </Text>
      <br />
      <Text type="secondary">{t("wizard.checkFailHint")}</Text>
      {/* The OS sentence stays available underneath rather than being hidden:
          the friendly line is for the 95% case, and someone debugging an odd
          one still needs the real text. */}
      {result.error && (
        <>
          <br />
          <Text type="secondary" style={{ fontSize: 11 }}>
            {result.error}
          </Text>
        </>
      )}
    </span>
  );
}

// The form column. Wider than the old 560px modal, because a step has a page to
// itself and a 560px column on a full window reads as a dialog that forgot to
// open.
const COL = { maxWidth: 720, margin: "0 auto" } as const;

export default function TunnelNew() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [form] = Form.useForm<CreateTunnelBody>();
  const [modal, modalCtx] = Modal.useModal();

  // Arriving from a port scan (Tools) or from a mesh service (Services). In the
  // URL rather than in props now: the flow is a page, so it has to survive a
  // reload and be linkable — which a modal opened by a parent's state never was.
  const [searchParams] = useSearchParams();
  const prefillPort = Number(searchParams.get("prefill_port") || 0) || undefined;
  const publishService = searchParams.get("publish_service") || undefined;
  const publishAddr = searchParams.get("publish_addr") || undefined;
  const publishProto = searchParams.get("publish_proto") || undefined;
  const publish =
    publishService && publishAddr
      ? { serviceName: publishService, localAddr: publishAddr, proto: publishProto || "tcp" }
      : undefined;

  const [step, setStep] = useState(0);
  // The row this flow produced. Step 3 is not a receipt: several fields are
  // still being decided when the create returns, and saying so is the point of
  // having a step for it.
  const [created, setCreated] = useState<RemoteTunnel | null>(null);

  const { canManage } = useServiceMode();

  // Pre-fill client_id with whichever device is "online" (most often this
  // daemon itself, since it just authenticated).
  const { data: clients } = useQuery<ClientDevicesList>({
    queryKey: ["clients"],
    queryFn: api.clients,
  });
  // The Org-scoped tunnel list (NOT the daemon-local snapshot) so the count hint
  // and the cap check both read the number the quota is actually spending.
  const { data: tunnelList } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
  });
  const { data: me } = useQuery<AccountMe>({ queryKey: ["me"], queryFn: api.me, retry: false });
  // Snapshot carries the connected edge's base_domain and public host — used
  // both for the non-editable subdomain suffix and for the public address on the
  // last step.
  const { data: snap } = useQuery<Snapshot>({ queryKey: ["snapshot"], queryFn: api.snapshot });
  // Edge directory — used to tell whether the edge this daemon is CURRENTLY
  // connected to is the org's own (BYOI) node. Domain form shape follows the
  // egress: 自购域名 ⟺ 自建节点出口.
  const { data: edges } = useQuery<EdgeList>({
    queryKey: ["edges"],
    queryFn: api.edges,
    retry: false,
  });

  const features = parseFeatures(me?.plan?.features_json);
  const planCode = me?.plan?.code ?? "";
  const isPaid = planCode !== "" && planCode !== "free";
  const standalone = planCode === "standalone";
  const baseDomain = snap?.base_domain ?? "";
  const hideCommerce = me?.ui?.hide_commerce === true;

  // The org's tunnel-security baseline and its named policies.
  //
  // Both are best-effort, and that is deliberate: a standalone daemon answers
  // 501 (no org exists to hold a baseline) and a control-plane blip must not
  // stop somebody creating a tunnel. tunnel-svc enforces the rule at the choke
  // point either way, so the worst case of a failed read is the OLD behaviour —
  // a refusal after submit — not an unprotected tunnel slipping through.
  const { data: orgSec } = useQuery<OrgSecurity | null>({
    queryKey: ["org-security"],
    queryFn: () => api.orgSecurity().catch(() => null),
    retry: false,
    staleTime: 60_000,
  });
  const { data: policies } = useQuery<IPPolicy[]>({
    queryKey: ["org-ip-policies"],
    queryFn: () =>
      api
        .orgIPPolicies()
        .then((r) => r.items || [])
        .catch(() => []),
    retry: false,
    staleTime: 60_000,
  });
  // useMemo, not `policies ?? []` inline: a fresh [] every render would put a
  // new identity in the dependency arrays of the two preselect effects below
  // and re-run them on every render.
  const ipPolicies = useMemo(() => policies ?? [], [policies]);
  const defaultPolicy = orgSec?.default_ip_policy || "";

  // Is the current data egress a self-hosted (BYOI) node? True when the edge the
  // daemon is connected to (snap.edge_node_id) is tagged owned in /v1/edges.
  // 自建节点出口 → 只能用自购域名（节点不服务平台 *.calabi.net）；平台出口 →
  // 只能用平台子域名（自购域名仅自建节点可用）。
  const onOwnEdge = !!(edges?.items ?? []).find((e) => e.edge_node_id === snap?.edge_node_id)
    ?.owned;
  const { data: domains } = useQuery<DomainList>({
    queryKey: ["domains"],
    queryFn: api.domains,
    enabled: onOwnEdge,
    retry: false,
  });
  // Verified domains, FREE ones first (a domain already bound to another tunnel
  // can't be reused, so surface the pickable ones at the top); stable a→z within
  // each group. in_use comes from bff-console cross-referencing org tunnels.
  const verifiedDomains = (domains?.items ?? [])
    .filter((d) => d.status === "verified")
    .slice()
    .sort((a, b) => {
      const au = a.in_use ? 1 : 0;
      const bu = b.in_use ? 1 : 0;
      if (au !== bu) return au - bu;
      return a.name.localeCompare(b.name);
    });
  const domainHasCert = (name: string) => {
    const d = verifiedDomains.find((x) => x.name === name);
    return !!(d && (d.cert_id || d.cert_name));
  };
  // The parents this node can actually serve — which is exactly the one domain
  // it declares as base_domain, when that domain is verified.
  //
  // Not "every verified domain the org owns". base_domain is what tunnel-svc's
  // allowReclaim compares a claiming edge against, so a tunnel created here
  // under some OTHER domain would be stamped with that domain's pool and this
  // very node would be refused the claim. The tunnel would exist, look created,
  // and never be served.
  const parentDomains = verifiedDomains.filter(
    (d) => !!baseDomain && d.name.toLowerCase() === baseDomain.toLowerCase(),
  );

  // The domain is two controls on one line: an OPTIONAL prefix and the parent.
  // chosenDomain is what they add up to — the name the tunnel gets. An empty
  // prefix is a real answer: the tunnel takes the parent itself.
  const domainParent = Form.useWatch("domain_parent" as never, form) as string | undefined;
  const domainPrefix = Form.useWatch("subdomain_prefix" as never, form) as string | undefined;
  const chosenDomain = (() => {
    if (!domainParent) return "";
    const pfx = (domainPrefix || "").trim().toLowerCase();
    return pfx ? `${pfx}.${domainParent}` : domainParent;
  })();

  const typeWatch = (Form.useWatch("type", form) as string | undefined) ?? "http";
  const addrWatch = Form.useWatch("local_addr", form) as string | undefined;

  // --- local-service reachability -------------------------------------------
  //
  // Runs ONLY when asked: the 「检测」 button, or pressing create. It used to
  // probe on its own, debounced, as you typed — which meant the form dialled
  // your machine on every keystroke-pause and flashed a red cross at addresses
  // you were still in the middle of typing. The answer is worth having;
  // volunteering it isn't.
  const [checked, setChecked] = useState<ProbeCheck | null>(null);
  const [checking, setChecking] = useState(false);
  // Separate from `checking`: the submit button must show progress during the
  // pre-flight probe, but the 「检测」 button must not spin when the user pressed
  // create (and vice versa).
  const [preflight, setPreflight] = useState(false);
  // A plain effect + sequence guard rather than a mutation, because the ONLY
  // thing that matters is that a stale answer never outlives the address it was
  // about: every run bumps `seq`, and a reply for an older `seq` is dropped.
  const seq = useRef(0);
  const runCheck = async (ty: string, addr: string): Promise<ProbeCheck> => {
    const mine = ++seq.current;
    setChecking(true);
    setChecked(null);
    let res: ProbeCheck;
    try {
      res = await api.probeCheck(ty, addr);
    } catch (e) {
      res = { healthy: false, checked_at: "", latency_ms: 0, error: (e as Error).message };
    }
    if (seq.current === mine) {
      setChecked(res);
      setChecking(false);
    }
    return res;
  };
  // No probing here — only invalidation. A result describes ONE address, so the
  // moment the address changes the old answer has to go: a green tick left
  // sitting under an address it was never about is worse than no tick at all.
  useEffect(() => {
    seq.current++; // drop any answer still in flight for the previous address
    setChecked(null);
    setChecking(false);
  }, [typeWatch, addrWatch]);

  // Self-hosted (standalone): no plans, no quota, no BYOI distinction — you own
  // the edge, so every offered protocol is available without gating. SNI
  // passthrough is intentionally NOT offered (it's not a headline feature and
  // confuses self-hosters; mirrors the platform www, which dropped SNI from its
  // marketing). The edge + CLI (`calabi sni …`) still support it via YAML.
  // Declared here, not down with the other gate values: the quota hook below
  // takes it, and a const declared further down would be in its temporal dead
  // zone by then.
  const tunnelCount = tunnelList?.team_total ?? tunnelList?.items?.length ?? 0;

  // Whose allowance this console spends. In agent mode there is no logged-in
  // user (user.id == 0) and the tunnels this console creates count against the
  // person who minted the key — acting_user — so that is the quota to read.
  const quotaUserId = me?.user?.id || me?.acting_user?.id || 0;
  // The caller's own allowance. Gated HERE as well as on the list button
  // because this is a URL: bookmarked, linked from 工具 and 服务, or typed.
  const mq = useMemberQuota(me?.org?.id ?? 0, quotaUserId, canManage, tunnelCount);
  const memberCapped = mq.atCap("max_tunnels");
  // The narrower dimension. A tcp/udp tunnel spends BOTH allowances, so someone
  // with tunnels left but no port tunnels left passes the check above and is
  // still refused — the refusal this page exists to move earlier.
  const portCapped = mq.atCap("max_port_tunnels");

  const typeOptions = standalone
    ? [
        { value: "http", label: "HTTP" },
        { value: "https", label: "HTTPS" },
        { value: "tcp", label: "TCP" },
        { value: "udp", label: "UDP" },
      ]
    : // Two different reasons a protocol can be closed, and they need different
      // words. The PLAN one is about what was bought; the QUOTA one is about
      // what this person has already used, and a tcp/udp tunnel spends a second
      // allowance the web tunnels do not — so someone with tunnels left can
      // still be out of port tunnels. Saying 「需要专业版」 there would send them
      // to buy something they already have.
      (["tcp", "udp"] as const).reduce(
        (acc, ty) => {
          const allowed = ty === "tcp" ? features.tcp : features.udp;
          const up = ty.toUpperCase();
          acc.push({
            value: ty,
            label: !allowed
              ? t(ty === "tcp" ? "wizard.tcpNeedPro" : "wizard.udpNeedPro")
              : portCapped
                ? t("wizard.typePortCapped", { type: up })
                : up,
            disabled: !allowed || portCapped,
          });
          return acc;
        },
        [
          { value: "http", label: "HTTP", disabled: false },
          { value: "https", label: "HTTPS", disabled: false },
        ] as { value: string; label: string; disabled: boolean }[],
      );

  // First online client is "this device" 99% of the time — the daemon
  // auto-registers on login so the list is non-empty by the time this page
  // opens. We rank online > offline so a stale prior-machine row doesn't shadow
  // the live one.
  const defaultClientId = clients?.items?.find((c) => c.online)?.id ?? clients?.items?.[0]?.id;
  useEffect(() => {
    if (defaultClientId !== undefined) form.setFieldValue("client_id", defaultClientId);
  }, [defaultClientId, form]);

  // --- step 2 state ---------------------------------------------------------
  const [protMode, setProtMode] = useState<"none" | "policy" | "custom">("none");
  const [protPolicy, setProtPolicy] = useState("");
  const [protAllow, setProtAllow] = useState("");
  const [baUsers, setBaUsers] = useState<{ user: string; password: string }[]>([]);
  const patchBaUser = (i: number, patch: Partial<{ user: string; password: string }>) =>
    setBaUsers((us) => us.map((u, j) => (j === i ? { ...u, ...patch } : u)));
  const baReady = baUsers.filter((u) => u.user.trim() && u.password).length;
  const ipEntries = splitLines(protAllow);

  // Does the org require protection for a tunnel of THIS type? Mirrors
  // OrgBaseline.Refusal in tunnel-svc: the broad rule covers everything, the
  // raw-port rule covers tcp/udp/sni only, and either one on its own is enough.
  // Type-aware because the narrower rule exists precisely so an org can require
  // it of a database port and not of a demo link.
  const barePort = isBarePortType(typeWatch);
  const protectionRequired =
    orgSec?.require_protection === true ||
    (orgSec?.require_bare_port_protection === true && barePort);
  const barePortOnly = !!orgSec && !orgSec.require_protection && protectionRequired;
  // IP rules are a paid capability (bff-console 403s ip_policy on free plans);
  // standalone has no plan to gate against. Hidden rather than shown-and-403'd —
  // except when the org REQUIRES protection, where hiding the only control that
  // could satisfy it would leave a dead end with no explanation.
  const ipAvailable = standalone || features.ip_policy || protectionRequired;
  // Basic auth has two gates and they say different things. PROTOCOL — a raw
  // port is byte passthrough, so there is no request to challenge; hidden, with
  // a line saying why. PLAN — basic_auth is paid and the server refuses it, so
  // don't tease a field that 403s on submit.
  const basicAuthAvailable = !barePort && (standalone || features.basic_auth);


  // Where the form STARTS in a governed org — the same two rules the web
  // console's create flow uses (web/console tunnels/Create.tsx), because the
  // answer to "what will the server do with an unprotected create" is not a
  // per-console opinion.
  //
  // "暂不设置" is the initial mode and, in a governed org, also the one option
  // the select disables — so this step opened showing a value nobody is allowed
  // to pick, 创建 greyed out, and no hint which way is forward. A disabled
  // default is not a default; it is a dead end rendered as one.
  //
  // Rule 1: an org default is preselected whenever there is one, governed or
  // not. tunnel-svc applies it to any create that carries no protection
  // (server.go CreateTunnel), so showing anything else would misdescribe the
  // tunnel that is about to exist.
  useEffect(() => {
    if (!orgSec) return;
    if (defaultPolicy) {
      setProtMode("policy");
      setProtPolicy(defaultPolicy);
    } else if (protectionRequired && ipPolicies.length > 0) {
      setProtMode("policy");
      setProtPolicy(ipPolicies[0].name);
    }
  }, [orgSec, defaultPolicy, protectionRequired, ipPolicies]);

  // Rule 2: changing the type can turn the requirement ON mid-form (http → tcp
  // in an org that governs raw ports only — exactly the case in the screenshot
  // this came from). Escalate off "none" when that happens, and ONLY then: the
  // `protMode !== "none"` guard is what stops this from overwriting a policy or
  // an address list the user had already chosen. With no default and no
  // policies to offer, 手动填写 is the only route the server will accept.
  useEffect(() => {
    if (!protectionRequired || protMode !== "none") return;
    if (defaultPolicy) {
      setProtMode("policy");
      setProtPolicy(defaultPolicy);
    } else if (ipPolicies.length > 0) {
      setProtMode("policy");
      setProtPolicy(ipPolicies[0].name);
    } else {
      setProtMode("custom");
    }
  }, [protectionRequired, protMode, defaultPolicy, ipPolicies]);

  // --- create ---------------------------------------------------------------
  const create = useMutation({
    mutationFn: (body: CreateTunnelBody) => api.createTunnel(body),
    onSuccess: (row) => {
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      qc.invalidateQueries({ queryKey: ["snapshot"] });
      setCreated(row);
      setStep(2);
    },
  });

  const submit = async () => {
    let v: CreateTunnelBody;
    try {
      v = await form.validateFields();
    } catch {
      // A rule on a step-1 field failed while we are standing on step 2. AntD
      // marks the field, but the field is behind a hidden div — so go back to
      // where the user can actually see the red text.
      setStep(0);
      return;
    }
    // Prefix mode is an INPUT shape, not a wire format: join it with this node's
    // suffix and submit the finished domain, the same way the console does. The
    // platform `subdomain` field stays as it is — there the EDGE joins prefix +
    // its own base_domain at claim time.
    const withPrefix = v as typeof v & { subdomain_prefix?: string; domain_parent?: string };
    if (withPrefix.domain_parent) {
      const pfx = (withPrefix.subdomain_prefix || "").trim().toLowerCase();
      v.domain = pfx ? `${pfx}.${withPrefix.domain_parent}` : withPrefix.domain_parent;
    }
    delete withPrefix.subdomain_prefix;
    delete withPrefix.domain_parent;
    // 自购域名与子域名互斥：填了 domain 就不发 subdomain。
    if (v.domain && v.subdomain) v.subdomain = undefined;

    const cfg: Record<string, unknown> = {};
    // Link the tunnel back to the service it was published from. mesh_node is
    // THIS device's client id (the same value the console stores as the
    // Publish-side device_id), so the origin points at the right machine.
    if (publish) {
      cfg.origin = { mesh_node: v.client_id, mesh_service: publish.serviceName };
    }
    // Access protection, chosen here rather than in a drawer on a tunnel that
    // does not exist yet. Only the policy NAME goes on the wire — tunnel-svc
    // expands it into addresses, so this console can never ship a stale copy of
    // a policy somebody just edited.
    const sec: Record<string, unknown> = {};
    if (protMode === "policy" && protPolicy) {
      sec.ip = { from_policy: protPolicy };
    } else if (protMode === "custom" && ipEntries.length > 0) {
      sec.ip = { allow: ipEntries };
    }
    // Plaintext `password`, never a hash: the server bcrypts it on the way in,
    // which is what keeps this console out of the business of deciding what a
    // stored credential looks like.
    const users = baUsers
      .map((u) => ({ user: u.user.trim(), password: u.password }))
      .filter((u) => u.user && u.password);
    if (users.length > 0) sec.basic_auth = { users };
    if (Object.keys(sec).length > 0) cfg.security = sec;
    if (Object.keys(cfg).length > 0) v.config_json = JSON.stringify(cfg);

    // Check the local service HERE rather than while the user types. This is
    // the moment the answer is actually worth having, and it is still only a
    // hint: "nothing is listening yet" is an ordinary state five seconds before
    // you start the dev server, so an unreachable upstream asks instead of
    // refusing. A reachable one says nothing and gets out of the way.
    const ty = (form.getFieldValue("type") || "").trim();
    const addr = (form.getFieldValue("local_addr") || "").trim();
    if (ty && addr && localAddrIssue(addr) === "") {
      setPreflight(true);
      let res: ProbeCheck;
      try {
        res = await runCheck(ty, addr);
      } finally {
        setPreflight(false);
      }
      if (!res.healthy) {
        const go = await new Promise<boolean>((resolve) => {
          modal.confirm({
            title: t("wizard.preflightTitle"),
            content: (
              <div>
                <p style={{ marginTop: 0 }}>{probeMessage(t, res)}</p>
                <p style={{ marginBottom: 0, color: "#8c8c8c" }}>{t("wizard.preflightBody")}</p>
              </div>
            ),
            okText: t("wizard.preflightCreateAnyway"),
            cancelText: t("wizard.preflightGoStart"),
            width: 440,
            onOk: () => resolve(true),
            onCancel: () => resolve(false),
          });
        });
        if (!go) return;
      }
    }
    create.mutate(v);
  };

  // --- step 3: what actually happened ---------------------------------------
  //
  // The watch has FOUR outcomes, and a version with one — poll until claimed,
  // otherwise just stop — leaves 分配中 on screen forever, which is a lie in two
  // ways at once: it claims something is still happening, and it hides the two
  // states a reader most needs to be told about.
  //
  //   watching — the edge has not claimed it yet; keep looking
  //   claimed  — done, the address is real
  //   timeout  — still unclaimed after the bound. NOT "assigning": we stopped
  //              looking, and the likeliest reason is that this daemon is not
  //              connected to an edge
  //   missing  — the row is gone. Says so, rather than spinning on an id
  //              nothing will ever answer for. This is the state the edge's
  //              port-claim conflict used to produce silently.
  type PollState = "idle" | "watching" | "claimed" | "timeout" | "missing";
  const [pollState, setPollState] = useState<PollState>("idle");
  // Lets 「继续等待」 restart a finished watch without reloading the page.
  const [watchRound, setWatchRound] = useState(0);
  const createdID = created?.id;
  useEffect(() => {
    if (step !== 2 || !createdID) return;
    let cancelled = false;
    setPollState("watching");
    void (async () => {
      // ~24s. Long enough for a cold edge; bounded, because a claim that never
      // comes has to be REPORTED, not waited on.
      for (let i = 0; i < 16 && !cancelled; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        if (cancelled) return;
        try {
          // THE ROW, not the list. The list this SPA reads is filtered to this
          // machine's device_id, paged and time-ordered; none of that has
          // anything to do with whether this particular row exists, and every
          // bit of it can make the row absent while it exists perfectly well.
          // /v1/tunnels/{id} answers the actual question, and its 404 is a real
          // answer rather than an inference.
          const row = await api.tunnel(createdID);
          if (cancelled) return;
          setCreated(row);
          if (row.edge_node_id && row.edge_node_id > 0) {
            setPollState("claimed");
            return;
          }
        } catch (e: unknown) {
          // 404 is the one error that ENDS the watch: the row is genuinely
          // gone. Everything else is a blip — keep looking, and never raise an
          // error on top of a successful create.
          if (e instanceof ApiError && e.status === 404) {
            if (!cancelled) setPollState("missing");
            return;
          }
        }
      }
      if (!cancelled) setPollState("timeout");
    })();
    return () => {
      cancelled = true;
    };
    // createdID, not `created`: setCreated runs on every tick, and depending on
    // the OBJECT would restart this effect each time — cancelling the loop and
    // beginning a new one, so the 16-tick bound would never apply and the watch
    // would run forever. The id is what the watch is actually about.
  }, [step, createdID, watchRound]);

  // The public address, or the reason there is not one yet. Three states, and
  // conflating any two of them is how a working tunnel reads as a broken one:
  // assigned, being assigned right now, or given up on.
  const publicAddr = useMemo(() => {
    if (!created) return null;
    if (created.domain) {
      if (created.type === "http" || created.type === "https") {
        // The edge terminates TLS for http/https tunnels, so the public URL
        // defaults to https://. A self-hosted edge listens on non-standard
        // ports advertised via snap → show the exact scheme+port.
        const u = standalone ? edgeHttpURL(created.domain, snap) : null;
        return {
          kind: "ready" as const,
          full: u ? u.full : `https://${created.domain}`,
          display: u ? u.display : `https://${truncateDomain(created.domain)}`,
        };
      }
      return {
        kind: "ready" as const,
        full: created.domain,
        display: truncateDomain(created.domain),
      };
    }
    if (created.remote_port && created.remote_port > 0) {
      const host = portTunnelHost(snap);
      return {
        kind: "ready" as const,
        full: host ? `${host}:${created.remote_port}` : `:${created.remote_port}`,
        display: host ? `${truncateDomain(host)}:${created.remote_port}` : `:${created.remote_port}`,
      };
    }
    // 分配中 only while something is actually watching. After the bound, or when
    // the row is gone, saying it is being assigned is simply false.
    if (pollState === "timeout" || pollState === "missing") {
      return { kind: "stalled" as const, full: "", display: "" };
    }
    return { kind: "pending" as const, full: "", display: "" };
  }, [created, pollState, snap, standalone]);

  const claimed = !!(created?.edge_node_id && created.edge_node_id > 0);

  // --- gates ----------------------------------------------------------------
  //
  // These used to live on the list page, because the button that opened the
  // modal lived there. They belong HERE now: this is a URL, so it can be
  // bookmarked, linked from Tools or Services, or typed, and every one of those
  // paths has to meet the same answer.
  const planMax = me?.plan?.max_tunnels;
  const capped = typeof planMax === "number" && planMax > 0 && tunnelCount >= planMax;

  // TWO different questions gate step 2, and conflating them is what lets an
  // empty address list through:
  //
  //  1. Did the ORG require protection, and does what is here satisfy it? That
  //     is protectionCloses — a function rather than an `||` because on a raw
  //     port a login counts for nothing.
  //  2. Did the PERSON finish what they started? Independent of any baseline.
  //     Picking 手动填写 and typing nothing is not "a narrower rule" — an empty
  //     allow list is NO rule, which the edge reads as "let everyone in", the
  //     exact opposite of what choosing that option says.
  const baHalfFilled = baUsers.some((u) => (u.user.trim() === "") !== (u.password === ""));
  const unfinished =
    protMode === "policy" && !protPolicy
      ? t("wizard.protPickPolicyFirst")
      : protMode === "custom" && ipEntries.length === 0
        ? t("wizard.protAddrsEmpty")
        : baHalfFilled
          ? t("wizard.basicAuthIncomplete")
          : "";
  const protectionAnswered =
    !protectionRequired ||
    protectionCloses(typeWatch, {
      ipPolicy: protMode === "policy" ? protPolicy : "",
      ipAllow: protMode === "custom" ? ipEntries : [],
      basicAuthUsers: baReady,
    });
  // The button is disabled rather than the submit refused: a refusal after the
  // click would be the 412 this whole flow exists to move earlier.
  const blockReason = unfinished || (protectionAnswered ? "" : t("wizard.protNeeded"));

  const backToList = () => navigate("/tunnels");

  const next = async () => {
    try {
      await form.validateFields();
    } catch {
      return; // AntD has already marked the offending fields
    }
    setStep(1);
  };

  // `!created` is load-bearing. This guard exists to stop somebody STARTING a
  // create they cannot finish; once a tunnel exists it has nothing left to say.
  //
  // Without it the page hijacked its own result: the create succeeds, the tunnel
  // count goes up, the quota re-read comes back at the limit, and step 3 —
  // 创建完成, with the public address still arriving — is replaced by
  // 「你的隧道配额已用完」. The tunnel was made; the screen says it was refused.
  if (!created && (!canManage || capped || memberCapped)) {
    return (
      <Space direction="vertical" size="middle" style={{ width: "100%" }}>
        <Title level={4} style={{ margin: 0 }}>
          {t("tunnels.newTunnel")}
        </Title>
        <Result
          status="warning"
          title={
            !canManage
              ? t("serviceMode.tunnelsReadonly")
              : capped
                ? t("tunnels.cappedAlertMsg", { count: tunnelCount, max: planMax })
                : t("tunnels.memberCappedTitle")
          }
          subTitle={
            !canManage
              ? t("serviceMode.agentBannerDesc")
              : capped
                ? t(hideCommerce ? "tunnels.cappedAlertDescNoUpgrade" : "tunnels.cappedAlertDesc")
                : t("tunnels.memberCappedDesc", {
                    count: mq.usedOf("max_tunnels"),
                    max: mq.limitOf("max_tunnels"),
                  })
          }
          extra={
            <Button type="primary" onClick={backToList}>
              {t("wizard.backToList")}
            </Button>
          }
        />
      </Space>
    );
  }

  return (
    <Space direction="vertical" size="middle" style={{ width: "100%" }}>
      {modalCtx}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Title level={4} style={{ margin: 0 }}>
          {t("tunnels.newTunnel")}
        </Title>
        <Button onClick={backToList}>{t("wizard.backToList")}</Button>
      </div>

      <Steps
        current={step}
        style={{ ...COL, marginBottom: 8 }}
        items={[
          { title: t("wizard.step1") },
          { title: t("wizard.step2") },
          { title: t("wizard.step3") },
        ]}
      />

      {step === 2 ? (
        <div style={COL}>
          {/* The headline follows the WATCH, not just `claimed`. Reading only
              claimed left "还在准备中" standing above an alert saying the row was
              gone — two statements about the same tunnel that cannot both be
              true, and the reassuring one is on top in bigger type. The detail
              (and what to do about it) stays in the alert below. */}
          <Result
            status={
              claimed
                ? "success"
                : pollState === "missing"
                  ? "error"
                  : pollState === "timeout"
                    ? "warning"
                    : "info"
            }
            title={
              claimed
                ? t("wizard.doneTitle")
                : pollState === "missing"
                  ? t("wizard.doneMissingTitle")
                  : pollState === "timeout"
                    ? t("wizard.doneStalledTitle")
                    : t("wizard.donePendingTitle")
            }
            subTitle={
              claimed
                ? t("wizard.doneSub")
                : pollState === "missing" || pollState === "timeout"
                  ? undefined
                  : t("wizard.donePendingSub")
            }
          />
          <Descriptions bordered column={1} size="small">
            <Descriptions.Item label={t("wizard.nameLabel")}>
              {created?.name || "—"}
            </Descriptions.Item>
            <Descriptions.Item label={t("wizard.typeLabel")}>
              {(created?.type || "").toUpperCase() || "—"}
            </Descriptions.Item>
            <Descriptions.Item label={t("wizard.localServiceLabel")}>
              <code style={{ fontSize: 12 }}>{created?.local_addr || "—"}</code>
            </Descriptions.Item>
            <Descriptions.Item label={t("tunnels.public")}>
              {publicAddr?.kind === "ready" ? (
                <CopyableAddr full={publicAddr.full} display={publicAddr.display} />
              ) : (
                <Tag color={publicAddr?.kind === "pending" ? "processing" : "default"}>
                  {publicAddr?.kind === "pending"
                    ? t("wizard.stateAssigning")
                    : t("wizard.stateNotAssigned")}
                </Tag>
              )}
            </Descriptions.Item>
            <Descriptions.Item label={t("wizard.doneProtection")}>
              <Space size={6} wrap>
                {protMode === "policy" && protPolicy && <Tag color="green">{protPolicy}</Tag>}
                {protMode === "custom" && ipEntries.length > 0 && (
                  <Tag color="green">
                    {t("wizard.doneProtectionAddrs", { count: ipEntries.length })}
                  </Tag>
                )}
                {baReady > 0 && (
                  <Tag color="green">{t("wizard.doneProtectionBasic", { count: baReady })}</Tag>
                )}
                {!(protMode === "policy" && protPolicy) &&
                  !(protMode === "custom" && ipEntries.length > 0) &&
                  baReady === 0 && <Text type="secondary">{t("wizard.doneProtectionNone")}</Text>}
              </Space>
            </Descriptions.Item>
          </Descriptions>

          {!claimed && pollState === "watching" && (
            <Alert
              type="info"
              showIcon
              style={{ marginTop: 16 }}
              message={t("wizard.donePendingNote")}
            />
          )}
          {pollState === "timeout" && (
            <Alert
              type="warning"
              showIcon
              style={{ marginTop: 16 }}
              message={t("wizard.doneStalledBody")}
              action={
                <Button size="small" onClick={() => setWatchRound((n) => n + 1)}>
                  {t("wizard.doneKeepWaiting")}
                </Button>
              }
            />
          )}
          {pollState === "missing" && (
            <Alert
              type="error"
              showIcon
              style={{ marginTop: 16 }}
              // The id, because this is the one state somebody will report, and
              // "the tunnel vanished" is unactionable without it.
              message={t("wizard.doneMissingBody", { id: createdID })}
            />
          )}
        </div>
      ) : (
        <Form
          layout="vertical"
          form={form}
          style={COL}
          initialValues={{
            // udp services can only be udp tunnels; a tcp service may front an
            // http/https server, so leave the common default and let the user pick.
            type: publish ? (publish.proto === "udp" ? "udp" : "http") : "http",
            name: publish?.serviceName,
            local_addr: publish
              ? publish.localAddr
              : prefillPort
                ? `127.0.0.1:${prefillPort}`
                : "127.0.0.1:8080",
            client_id: defaultClientId,
          }}
        >
          {/* Hidden, not unmounted — see the note at the top of the file. Both
              the attribute and the inline style: `hidden` is semantic but any
              `div { display: … }` rule beats it, and an inline style cannot be
              overridden. */}
          <div hidden={step !== 0} style={{ display: step === 0 ? undefined : "none" }}>
            {publish && (
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 16 }}
                message={t("wizard.publishBanner", { name: publish.serviceName })}
                description={t("wizard.publishBannerDesc")}
              />
            )}

            <Form.Item
              label={t("wizard.nameLabel")}
              name="name"
              rules={[{ required: true, message: t("wizard.nameRequired") }]}
            >
              <Input placeholder={t("wizard.namePlaceholder")} maxLength={64} showCount />
            </Form.Item>

            {/* 类型 + 本地地址 是一件事,所以是一行。
                类型描述的是「本机服务说什么协议」,决定的只有客户端怎么拨本地上游
                (session/dial.go: http 明文 TCP、https 再包一层 TLS)。它不决定公网
                入口:edge 的 http/https 两个 listener 查的是同一张域名表
                (RegisterHTTP),入口能不能走 https 由域名和证书决定。类型单独占一行
                时,读起来就像在选入口协议。 */}
            <Form.Item
              label={t("wizard.localServiceLabel")}
              tooltip={t("wizard.localServiceTip")}
              extra={<LocalCheckLine checking={checking} result={checked} />}
              required
            >
              <Space.Compact style={{ width: "100%" }}>
                <Form.Item name="type" noStyle rules={[{ required: true }]}>
                  <Select
                    options={typeOptions}
                    aria-label={t("wizard.typeLabel")}
                    style={{ width: 120 }}
                  />
                </Form.Item>
                <Form.Item
                  name="local_addr"
                  noStyle
                  rules={[
                    { required: true, message: t("wizard.localAddrFormat") },
                    {
                      validator: (_, value) => {
                        const r = localAddrIssue(value);
                        if (r === "public")
                          return Promise.reject(new Error(t("wizard.localAddrPublic")));
                        if (r === "format")
                          return Promise.reject(new Error(t("wizard.localAddrFormat")));
                        return Promise.resolve();
                      },
                    },
                  ]}
                >
                  <Input placeholder="127.0.0.1:8080" aria-label={t("wizard.localAddrLabel")} />
                </Form.Item>
                {/* Re-check on demand: the usual sequence is "oh, it's not
                    running" → start the service → ask again, without touching
                    the address. */}
                <Button
                  loading={checking}
                  onClick={() => {
                    const ty = (form.getFieldValue("type") || "").trim();
                    const addr = (form.getFieldValue("local_addr") || "").trim();
                    if (ty && addr && localAddrIssue(addr) === "") runCheck(ty, addr);
                  }}
                >
                  {t("wizard.checkBtn")}
                </Button>
              </Space.Compact>
            </Form.Item>

            <Form.Item shouldUpdate noStyle>
              {({ getFieldValue }) => {
                const ty = getFieldValue("type") as CreateTunnelBody["type"];
                if (ty === "tcp" || ty === "udp") {
                  return (
                    <Form.Item
                      label={t("wizard.remotePortLabel")}
                      name="remote_port"
                      tooltip={t("wizard.remotePortTip")}
                    >
                      <InputNumber min={1024} max={65535} style={{ width: "100%" }} />
                    </Form.Item>
                  );
                }
                // http / https 域名形态按「当前出口」决定（自购域名 ⟺ 自建节点）：
                //   - 自建节点出口：只能填自购域名（required）。自建节点不服务平台
                //     *.calabi.net，公网地址用你自己的域名。
                //   - 平台出口：只能用平台子域名（付费版自选前缀 / 体验版随机）；
                //     自购域名仅自建节点出口可用，这里不展示。
                if (onOwnEdge) {
                  return (
                    <>
                      <Form.Item
                        label={t("wizard.customDomainLabel")}
                        required
                        tooltip={
                          snap?.server_ip
                            ? t("wizard.prefixTipNode", {
                                suffix: domainParent || baseDomain,
                                ip: snap.server_ip,
                              })
                            : t("wizard.customDomainTip")
                        }
                        extra={
                          parentDomains.length === 0
                            ? t("wizard.parentEmptyHint")
                            : chosenDomain
                              ? t("wizard.fullAddress", { addr: chosenDomain })
                              : undefined
                        }
                      >
                        <Space.Compact style={{ width: "100%" }}>
                          <Form.Item
                            name="subdomain_prefix"
                            noStyle
                            dependencies={["domain_parent"]}
                            rules={[
                              {
                                pattern: /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/,
                                message: t("wizard.subdomainPattern"),
                              },
                              // Empty means the parent itself — legal, unless
                              // the parent already carries a tunnel.
                              ({ getFieldValue: gv }) => ({
                                validator(_: unknown, value: string | undefined) {
                                  if ((value || "").trim()) return Promise.resolve();
                                  const parent = gv("domain_parent") as string | undefined;
                                  const row = parentDomains.find((d) => d.name === parent);
                                  if (!row?.in_use) return Promise.resolve();
                                  return Promise.reject(
                                    new Error(
                                      t("wizard.apexInUse", {
                                        name: parent,
                                        tunnel: row.bound_tunnel_name || "—",
                                      }),
                                    ),
                                  );
                                },
                              }),
                            ]}
                          >
                            <Input
                              style={{ width: "38%" }}
                              placeholder={t("wizard.prefixPlaceholder")}
                            />
                          </Form.Item>
                          <Form.Item
                            name="domain_parent"
                            noStyle
                            rules={[{ required: true, message: t("wizard.customDomainRequired") }]}
                          >
                            <Select
                              style={{ width: "62%" }}
                              placeholder={t("wizard.customDomainSelectPlaceholder")}
                              notFoundContent={t("wizard.parentEmptyHint")}
                              optionLabelProp="value"
                              options={parentDomains.map((d) => {
                                const hasCert = !!(d.cert_id || d.cert_name);
                                return {
                                  value: d.name,
                                  label: (
                                    <Space>
                                      <span>{d.name}</span>
                                      <Tag
                                        color={hasCert ? "green" : "orange"}
                                        style={{ marginInlineEnd: 0 }}
                                      >
                                        {hasCert
                                          ? t("wizard.domainCertReady")
                                          : t("wizard.domainNoCert")}
                                      </Tag>
                                    </Space>
                                  ),
                                };
                              })}
                            />
                          </Form.Item>
                        </Space.Compact>
                      </Form.Item>
                      {/* Exactly ONE cert line: a prefixed name gets a
                          certificate issued for it automatically once the tunnel
                          exists, the parent itself does not. Showing both said
                          opposite things. */}
                      {chosenDomain &&
                        ((domainPrefix || "").trim() ? (
                          <Alert
                            type="info"
                            showIcon
                            style={{ marginTop: -8, marginBottom: 16 }}
                            message={t("wizard.prefixCertNote")}
                          />
                        ) : !domainHasCert(chosenDomain) ? (
                          <Alert
                            type="warning"
                            showIcon
                            style={{ marginTop: -8, marginBottom: 16 }}
                            message={t("wizard.domainNoCertHint")}
                          />
                        ) : null)}
                    </>
                  );
                }
                return isPaid ? (
                  <Form.Item
                    label={t("wizard.subdomainLabel")}
                    name="subdomain"
                    tooltip={t("wizard.subdomainTip")}
                    rules={[
                      {
                        pattern: /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/,
                        message: t("wizard.subdomainPattern"),
                      },
                    ]}
                  >
                    <Input
                      placeholder="myapp"
                      addonAfter={baseDomain ? `.${baseDomain}` : undefined}
                    />
                  </Form.Item>
                ) : (
                  <Form.Item label={t("wizard.subdomainFreeLabel")}>
                    <Input
                      disabled
                      placeholder={t(
                        me?.ui?.hide_commerce
                          ? "wizard.subdomainFreePlaceholderNoUpgrade"
                          : "wizard.subdomainFreePlaceholder",
                      )}
                    />
                  </Form.Item>
                );
              }}
            </Form.Item>

            {/* client_id 通过 initialValues 静默注入,不渲染选择器。桌面客户端创建
                的隧道永远绑到本机(就是当前 daemon)——想绑别的设备只能通过 Web 控制
                台。保留隐藏的 Form.Item 让 form state 能收集到这个字段。 */}
            <Form.Item name="client_id" hidden>
              <InputNumber />
            </Form.Item>

            {/* Team-wide count (the quota dimension) plus a "其中本机 N 条" hint
                when they differ, so the user sees both "how much of my Org cap is
                used" and "how much of that is owned by this machine". For a
                personal Org / 1-member team the two collapse to one number. */}
            {(() => {
              const team = tunnelList?.team_total ?? tunnelList?.items?.length ?? 0;
              const mine = tunnelList?.my_total ?? tunnelList?.items?.length ?? 0;
              if (team === 0) return null;
              return (
                <Alert
                  type="info"
                  showIcon
                  message={
                    team === mine
                      ? t("wizard.countHint", { team })
                      : t("wizard.countHintShared", { team, mine })
                  }
                />
              );
            })()}
          </div>

          <div hidden={step !== 1} style={{ display: step === 1 ? undefined : "none" }}>
            {/* Always on screen, unlike the modal version, which had no security
                section at all. A step that renders nothing is a blank page with
                a 下一步 button, so this one says what is on offer either way. */}
            <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
              {barePortOnly
                ? t("wizard.protBarePortHelp")
                : protectionRequired
                  ? t("wizard.protRequiredHelp")
                  : t("wizard.protOptionalHelp")}
            </Typography.Paragraph>

            {ipAvailable ? (
              <Form.Item label={t("wizard.ipSection")} extra={t("wizard.ipSectionHint")}>
                <Select
                  value={protMode}
                  onChange={(v) => setProtMode(v)}
                  options={[
                    ...(ipPolicies.length > 0
                      ? [{ value: "policy", label: t("wizard.protPolicy") }]
                      : []),
                    { value: "custom", label: t("wizard.protCustom") },
                    {
                      value: "none",
                      label: protectionRequired
                        ? t("wizard.protNoneBlocked")
                        : t("wizard.protNone"),
                      disabled: protectionRequired,
                    },
                  ]}
                />
                {protMode === "policy" && (
                  <Select
                    style={{ width: "100%", marginTop: 8 }}
                    value={protPolicy || undefined}
                    onChange={setProtPolicy}
                    placeholder={t("wizard.protPickPolicy")}
                    options={ipPolicies.map((p) => ({
                      value: p.name,
                      label:
                        p.name === defaultPolicy
                          ? `${p.name} · ${t("wizard.protOrgDefault")}`
                          : p.name,
                    }))}
                  />
                )}
                {protMode === "custom" && (
                  <>
                    <Input.TextArea
                      style={{ marginTop: 8 }}
                      rows={3}
                      value={protAllow}
                      onChange={(e) => setProtAllow(e.target.value)}
                      placeholder={"203.0.113.0/24\n198.51.100.7"}
                    />
                    {/* Said here rather than left to the server's 412: a list
                        whose only entry is 0.0.0.0/0 looks like a rule and
                        admits everyone. */}
                    {ipEntries.length > 0 && !allowListCloses(ipEntries) && (
                      <div style={{ fontSize: 12, color: "#d46b08", marginTop: 4 }}>
                        {t("wizard.protOpenList")}
                      </div>
                    )}
                  </>
                )}
              </Form.Item>
            ) : (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                {t(hideCommerce ? "wizard.ipNeedPlanNoUpgrade" : "wizard.ipNeedPlan")}
              </Typography.Paragraph>
            )}

            {barePort ? (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                {t("wizard.basicAuthNotForRawPort")}
              </Typography.Paragraph>
            ) : (
              basicAuthAvailable && (
                <Form.Item label={t("wizard.basicAuthTitle")} extra={t("wizard.basicAuthHint")}>
                  <Space direction="vertical" style={{ width: "100%" }} size="small">
                    {baUsers.map((u, i) => (
                      <Space key={i} style={{ width: "100%" }} align="start">
                        <Input
                          style={{ width: 160 }}
                          placeholder={t("wizard.basicAuthUser")}
                          value={u.user}
                          onChange={(e) => patchBaUser(i, { user: e.target.value })}
                        />
                        <Input.Password
                          style={{ width: 190 }}
                          placeholder={t("wizard.basicAuthPassword")}
                          value={u.password}
                          onChange={(e) => patchBaUser(i, { password: e.target.value })}
                        />
                        <Button
                          danger
                          onClick={() => setBaUsers((us) => us.filter((_, j) => j !== i))}
                        >
                          {t("common.delete")}
                        </Button>
                      </Space>
                    ))}
                    <Button onClick={() => setBaUsers((us) => [...us, { user: "", password: "" }])}>
                      + {t("wizard.basicAuthAddUser")}
                    </Button>
                  </Space>
                </Form.Item>
              )
            )}

            {/* The one state the server cannot rescue: the requirement is on,
                the org has no default policy, and so a create that carries no
                protection has nothing to fall back to. Said here because this
                form is where somebody hits it first. */}
            {protectionRequired && !defaultPolicy && (
              <Alert
                type="warning"
                showIcon
                message={
                  barePortOnly
                    ? t("wizard.protNoDefaultWarnBarePort")
                    : t("wizard.protNoDefaultWarn")
                }
              />
            )}

            {create.error && (
              <Alert
                type="error"
                showIcon
                style={{ marginTop: 12 }}
                message={(create.error as Error).message}
              />
            )}
          </div>
        </Form>
      )}

      <Divider style={{ margin: "8px 0" }} />
      <Space style={{ ...COL, display: "flex", justifyContent: "flex-end" }}>
        {step === 0 && (
          <>
            <Button onClick={backToList}>{t("common.cancel")}</Button>
            <Button type="primary" onClick={() => void next()}>
              {t("wizard.next")}
            </Button>
          </>
        )}
        {step === 1 && (
          <>
            <Button onClick={() => setStep(0)}>{t("wizard.back")}</Button>
            <Tooltip title={blockReason}>
              <Button
                type="primary"
                loading={create.isPending || preflight}
                disabled={!!blockReason}
                onClick={() => void submit()}
              >
                {t("common.create")}
              </Button>
            </Tooltip>
          </>
        )}
        {step === 2 && (
          <>
            <Button
              onClick={() => {
                // Reset the ANSWERS, not the page. A reload would also throw
                // away the device, domain and edge lists this page just fetched,
                // and those are the same for the next tunnel.
                form.resetFields();
                setCreated(null);
                setPollState("idle");
                setProtMode("none");
                setProtPolicy("");
                setProtAllow("");
                setBaUsers([]);
                setChecked(null);
                create.reset();
                setStep(0);
              }}
            >
              {t("wizard.createAnother")}
            </Button>
            <Button type="primary" loading={pollState === "watching"} onClick={backToList}>
              {t("wizard.backToList")}
            </Button>
          </>
        )}
      </Space>
    </Space>
  );
}
