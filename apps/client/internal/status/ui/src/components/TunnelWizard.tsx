// TunnelWizard.tsx — modal form for creating a new tunnel.
//
// Fields shown to the user:
//   - type       (http / https / tcp / udp / sni)
//   - name       (human label)
//   - local_addr (host:port)
//   - domain     (optional, http/https/sni)
//   - remote_port (optional, tcp/udp)
//
// client_id is silently bound to "this device" (the daemon serving the
// current SPA). The desktop client always creates tunnels for itself,
// so the picker is gone — see the block comment below imports for the
// auto-registration trail that guarantees this device is in
// /v1/clients before the wizard ever opens.
import {
  Alert,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Tag,
} from "antd";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import type {
  AccountMe,
  ClientDevicesList,
  CreateTunnelBody,
  DomainList,
  EdgeList,
  Snapshot,
  TunnelList,
} from "../api/types";

// PlanFeatures mirrors the gating subset of quota-svc features_json (see
// apps/bff-console/internal/handlers/tunnels.go planFeatures). Drives the
// wizard's protocol gating. tcp/udp = 专业版+; sni = 增强版.
// NOTE: custom_domain is NO LONGER plan-gated here — 自购域名 ⟺ 自建节点出口,
// so the http/https domain form keys off onOwnEdge (current edge ownership),
// not features.custom_domain.
type PlanFeatures = { tcp: boolean; udp: boolean; sni: boolean; custom_domain: boolean };
function parseFeatures(json?: string): PlanFeatures {
  const empty = { tcp: false, udp: false, sni: false, custom_domain: false };
  if (!json) return empty;
  try {
    const o = JSON.parse(json) as Partial<PlanFeatures>;
    return { tcp: !!o.tcp, udp: !!o.udp, sni: !!o.sni, custom_domain: !!o.custom_domain };
  } catch {
    return empty;
  }
}

// 客户端登录后,daemon 会自动把本机注册到 identity-svc(见
// apps/client/internal/clientreg),所以本机一定在 /v1/clients 列表里。
// 桌面客户端创建隧道时,目标设备永远是「本机」(就是当前 daemon),
// 所以不再让用户从下拉里选 —— 直接拿第一个在线客户端(等价于本机)。
// 若想绑到别的设备,目前只能通过 Web 控制台,桌面端保持极简。

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

interface Props {
  open: boolean;
  onClose: () => void;
  // M7-S5: if set, the wizard initializes local_addr to 127.0.0.1:<port>.
  // Passed through by the Tunnels page when arriving from the port scanner.
  prefillPort?: number;
}

export default function TunnelWizard({ open, onClose, prefillPort }: Props) {
  const { t } = useTranslation();
  const [form] = Form.useForm<CreateTunnelBody>();
  const qc = useQueryClient();

  // Pre-fill client_id with whichever device is "online" (most often
  // this daemon itself, since it just authenticated).
  const { data: clients } = useQuery<ClientDevicesList>({
    queryKey: ["clients"],
    queryFn: api.clients,
    enabled: open,
  });
  // M11.8: pull the Org-scoped tunnel list (NOT the daemon-local
  // snapshot) so the "已有 N 条" hint matches what the user sees in
  // the table behind the modal. The previous version read
  // snap.tunnels.length, which is THIS daemon's claim count — after
  // an Org switch that's a stale or near-zero number that disagrees
  // with the list and makes the user think the page is buggy.
  const { data: tunnelList } = useQuery<TunnelList>({
    queryKey: ["tunnels"],
    queryFn: api.tunnels,
    enabled: open,
  });

  // Plan features drive protocol + domain gating (mirror of web/console
  // CreateModal). /v1/me already carries features_json; degrade to
  // all-false (most restrictive UI) until it resolves — the server
  // enforces the same rules so a race can't unlock anything.
  const { data: me } = useQuery<AccountMe>({
    queryKey: ["me"],
    queryFn: api.me,
    enabled: open,
  });
  // Snapshot carries the connected edge's base_domain — used to show the
  // real, non-editable suffix on the subdomain-prefix input (the daemon
  // knows its region base; the web console can't, so it shows a hint).
  const { data: snap } = useQuery<Snapshot>({
    queryKey: ["snapshot"],
    queryFn: api.snapshot,
    enabled: open,
  });
  // Edge directory — used to tell whether the edge this daemon is CURRENTLY
  // connected to is the org's own (BYOI) node. Domain form shape follows the
  // egress: 自购域名 ⟺ 自建节点出口.
  const { data: edges } = useQuery<EdgeList>({
    queryKey: ["edges"],
    queryFn: api.edges,
    enabled: open,
    retry: false,
  });
  const features = parseFeatures(me?.plan?.features_json);
  const planCode = me?.plan?.code ?? "";
  const isPaid = planCode !== "" && planCode !== "free";
  const baseDomain = snap?.base_domain ?? "";
  // Is the current data egress a self-hosted (BYOI) node? True when the edge
  // the daemon is connected to (snap.edge_node_id) is tagged owned in /v1/edges.
  // 自建节点出口 → 只能用自购域名（节点不服务平台 *.calabi.net）；平台出口 →
  // 只能用平台子域名（自购域名仅自建节点可用）。
  const onOwnEdge = !!(edges?.items ?? []).find(
    (e) => e.edge_node_id === snap?.edge_node_id,
  )?.owned;
  // Verified custom domains for the dropdown (BYOI egress only). The server
  // enforces verification; we list so users PICK a ready domain instead of
  // typing an unverified one and hitting a create-time rejection.
  const { data: domains } = useQuery<DomainList>({
    queryKey: ["domains"],
    queryFn: api.domains,
    enabled: open && onOwnEdge,
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
  // Watch the chosen domain so we can warn when it has no cert yet (HTTP works,
  // HTTPS lights up once a cert is issued in the console).
  const chosenDomain = Form.useWatch("domain", form);
  // Self-hosted (standalone): no plans, no quota, no BYOI distinction — you own
  // the edge, so every offered protocol is available without gating. SNI
  // passthrough is intentionally NOT offered here (it's not a headline feature
  // and confuses self-hosters; mirrors the platform www, which dropped SNI from
  // its marketing). The edge + CLI (`calabi sni …`) still support it for power
  // users who set it up via YAML.
  const standalone = planCode === "standalone";
  const typeOptions = standalone
    ? [
        { value: "http", label: "HTTP" },
        { value: "https", label: "HTTPS" },
        { value: "tcp", label: "TCP" },
        { value: "udp", label: "UDP" },
      ]
    : [
        { value: "http", label: "HTTP" },
        { value: "https", label: "HTTPS" },
        { value: "tcp", label: features.tcp ? "TCP" : t("wizard.tcpNeedPro"), disabled: !features.tcp },
        { value: "udp", label: features.udp ? "UDP" : t("wizard.udpNeedPro"), disabled: !features.udp },
        // SNI passthrough is no longer offered (dropped from the product); the
        // edge + CLI still accept it for power users via YAML, but it's hidden
        // from the wizard.
      ];

  // First online client is "this device" 99% of the time — daemon
  // auto-registers on login so the list is non-empty by the time the
  // wizard opens. We rank online > offline so a stale prior-machine
  // row doesn't shadow the live one.
  const defaultClientId =
    clients?.items?.find((c) => c.online)?.id ?? clients?.items?.[0]?.id;

  // Form mounts with initialValues snapshot — if the clients query
  // hasn't resolved yet, client_id ends up undefined. Push it into
  // the form once it arrives so submit always carries the right id.
  useEffect(() => {
    if (open && defaultClientId !== undefined) {
      form.setFieldValue("client_id", defaultClientId);
    }
  }, [open, defaultClientId, form]);

  const create = useMutation({
    mutationFn: (body: CreateTunnelBody) => api.createTunnel(body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tunnels"] });
      qc.invalidateQueries({ queryKey: ["snapshot"] });
      form.resetFields();
      onClose();
    },
  });

  return (
    <Modal
      open={open}
      title={t("tunnels.newTunnel")}
      onCancel={onClose}
      width={560}
      destroyOnClose
      footer={null}
    >
      <Form
        layout="vertical"
        form={form}
        initialValues={{
          type: "http",
          local_addr: prefillPort
            ? `127.0.0.1:${prefillPort}`
            : "127.0.0.1:8080",
          client_id: defaultClientId,
        }}
        onFinish={(v) => {
          // 自购域名与子域名互斥：填了 domain 就不发 subdomain。
          if (v.domain && v.subdomain) v.subdomain = undefined;
          create.mutate(v);
        }}
      >
        <Form.Item label={t("wizard.typeLabel")} name="type" rules={[{ required: true }]}>
          <Select options={typeOptions} />
        </Form.Item>

        <Form.Item label={t("wizard.nameLabel")} name="name" rules={[{ required: true, message: t("wizard.nameRequired") }]}>
          <Input placeholder={t("wizard.namePlaceholder")} maxLength={64} showCount />
        </Form.Item>

        <Form.Item
          label={t("wizard.localAddrLabel")}
          name="local_addr"
          tooltip={t("wizard.localAddrTip")}
          rules={[
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
          <Input placeholder="127.0.0.1:8080" />
        </Form.Item>

        <Form.Item shouldUpdate noStyle>
          {({ getFieldValue }) => {
            const ty = getFieldValue("type") as CreateTunnelBody["type"];
            if (ty === "tcp" || ty === "udp") {
              return (
                <Form.Item label={t("wizard.remotePortLabel")} name="remote_port" tooltip={t("wizard.remotePortTip")}>
                  <InputNumber min={1024} max={65535} style={{ width: "100%" }} />
                </Form.Item>
              );
            }
            // SNI is no longer offered in the wizard (type dropdown hides it),
            // so there's no SNI domain field here anymore.
            // http / https 域名形态按「当前出口」决定（自购域名 ⟺ 自建节点）：
            //   - 自建节点出口：只能填自购域名（required）。自建节点不服务平台
            //     *.calabi.net，公网地址用你自己的域名。
            //   - 平台出口：只能用平台子域名（付费版自选前缀 / 体验版随机）；
            //     自购域名仅自建节点出口可用，这里不展示。
            if (onOwnEdge) {
              const noCertChosen =
                !!chosenDomain && !domainHasCert(chosenDomain);
              return (
                <>
                  <Form.Item
                    label={t("wizard.customDomainLabel")}
                    name="domain"
                    rules={[{ required: true, message: t("wizard.customDomainRequired") }]}
                    tooltip={t("wizard.customDomainTip")}
                    extra={
                      verifiedDomains.length === 0
                        ? t("wizard.customDomainNoneHint")
                        : undefined
                    }
                  >
                    <Select
                      placeholder={t("wizard.customDomainSelectPlaceholder")}
                      notFoundContent={t("wizard.customDomainNone")}
                      optionLabelProp="value"
                      options={verifiedDomains.map((d) => {
                        const hasCert = !!(d.cert_id || d.cert_name);
                        const inUseLabel = d.bound_tunnel_name
                          ? `${t("wizard.domainInUse")} · ${d.bound_tunnel_name}`
                          : t("wizard.domainInUse");
                        return {
                          value: d.name,
                          // A domain bound to another tunnel can't be reused —
                          // disable it so the create can't fail on a conflict.
                          disabled: !!d.in_use,
                          label: (
                            <Space>
                              <span>{d.name}</span>
                              {d.in_use ? (
                                <Tag color="default" style={{ marginInlineEnd: 0 }}>
                                  {inUseLabel}
                                </Tag>
                              ) : (
                                <Tag
                                  color={hasCert ? "green" : "orange"}
                                  style={{ marginInlineEnd: 0 }}
                                >
                                  {hasCert
                                    ? t("wizard.domainCertReady")
                                    : t("wizard.domainNoCert")}
                                </Tag>
                              )}
                            </Space>
                          ),
                        };
                      })}
                    />
                  </Form.Item>
                  {noCertChosen && (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginTop: -8, marginBottom: 16 }}
                      message={t("wizard.domainNoCertHint")}
                    />
                  )}
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
                <Input disabled placeholder={t("wizard.subdomainFreePlaceholder")} />
              </Form.Item>
            );
          }}
        </Form.Item>

        {/* client_id 通过 initialValues 静默注入,不再渲染选择器 ——
            原因见文件顶部注释。保留隐藏的 Form.Item 让 form state 能
            正确收集到这个字段,onFinish 才会把它带进 createTunnel
            的 body 里。 */}
        <Form.Item name="client_id" hidden>
          <InputNumber />
        </Form.Item>

        {/* M11.19.1 — show team-wide count (the quota dimension) plus a
            "其中本机 N 条" hint when they differ, so the user sees both
            "how much of my Org cap is used" and "how much of that is
            owned by this daemon's device". For a personal Org / 1-member
            team the two collapse to one number. */}
        {(() => {
          const team = tunnelList?.team_total ?? tunnelList?.items?.length ?? 0;
          const mine = tunnelList?.my_total ?? tunnelList?.items?.length ?? 0;
          if (team === 0) return null;
          return (
            <Alert
              type="info"
              showIcon
              style={{ marginBottom: 12 }}
              message={
                team === mine
                  ? t("wizard.countHint", { team })
                  : t("wizard.countHintShared", { team, mine })
              }
            />
          );
        })()}

        {create.error && (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 12 }}
            message={(create.error as Error).message}
          />
        )}

        <Form.Item style={{ marginBottom: 0 }}>
          <Space style={{ width: "100%", justifyContent: "flex-end" }}>
            <Button onClick={onClose}>{t("common.cancel")}</Button>
            <Button type="primary" htmlType="submit" loading={create.isPending}>
              {t("common.create")}
            </Button>
          </Space>
        </Form.Item>
      </Form>
    </Modal>
  );
}
