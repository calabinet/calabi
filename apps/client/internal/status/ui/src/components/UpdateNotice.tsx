// UpdateNotice.tsx — what the console says about this client's version, and the
// machine's setting for what to do about it.
//
// Two surfaces over one query:
//   <UpdateTag/>   the 320px overview card: a signal, no controls.
//   <UpdatePanel/> Settings: the status, the buttons, and the policy.
//
// Three different facts, deliberately rendered as three different things
// (docs/runbook/client-update-policy.md §6):
//   available  — there is something newer
//   can_apply  — this machine could install it       → `reason` when false
//   hold       — it could, but the policy says not yet → `hold` when set
// A Linux box is permanently the second case and never the third; a desktop
// waiting for 3am is the third and never the second.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Radio, Select, Space, Switch, Tag, Tooltip, Typography, message } from "antd";
import { useTranslation } from "react-i18next";
import { api } from "../api/client";
import { updatePollInterval } from "../lib/updatePoll";
import type { UpdateInfo, UpdatePolicy } from "../api/types";

const { Text } = Typography;

// useUpdateInfo — one shared query. null = this daemon has no update agent (dev
// build, updates disabled, or a client older than the endpoint). Not an error:
// every caller renders nothing.
export function useUpdateInfo() {
  return useQuery<UpdateInfo | null>({
    queryKey: ["update"],
    queryFn: api.updateInfo,
    // Two intervals, not one: slow while nothing is happening, seconds while
    // something is. The spinners below are rendered from `state`, so this
    // interval IS how long a finished operation can keep spinning. See
    // lib/updatePoll.ts.
    refetchInterval: (q) => updatePollInterval(q.state.data),
    retry: false,
  });
}

// UpdateTag is the overview's signal. Deliberately not a button: the 320px card
// has no room to explain what pressing it would do on a machine that can't.
export function UpdateTag() {
  const { t } = useTranslation();
  const { data } = useUpdateInfo();
  if (!data?.available || !data.latest) return null;
  const urgent = data.critical || data.mandatory;
  return (
    <Tooltip title={data.can_apply ? t("update.tagTipApply") : t("update.tagTipManual")}>
      <Tag color={urgent ? "red" : "blue"} style={{ marginInlineStart: 6 }}>
        {t("update.newVersion", { version: data.latest })}
      </Tag>
    </Tooltip>
  );
}

// reasonKey maps the daemon's stable Reason strings to a sentence. Anything
// unrecognised falls back to the generic line rather than rendering a raw
// enum — a new reason on a newer daemon must degrade, not leak.
function reasonKey(reason?: string): string {
  switch (reason) {
    case "no-artifact":
    case "unsupported-platform":
      return "update.reasonManualPlatform";
    case "not-privileged":
      return "update.reasonNotService";
    // Installed by scoop / Homebrew / by hand: running the platform installer
    // would install something ELSE, not update this. The daemon checks this
    // before privilege, so this is the answer such a machine actually gets.
    case "managed-elsewhere":
      return "update.reasonManagedElsewhere";
    case "artifact-unsigned":
    case "artifact-foreign":
      return "update.reasonBadManifest";
    default:
      return "update.reasonGeneric";
  }
}

function holdKey(hold?: string): string | null {
  switch (hold) {
    case "notify-only":
      return "update.holdNotify";
    case "security-only":
      return "update.holdSecurity";
    case "outside-window":
      return "update.holdWindow";
    case "busy":
      return "update.holdBusy";
    // The publisher's staged rollout (U5b): the machine is ready, the release
    // has not reached it yet.
    case "rollout":
      return "update.holdRollout";
    default:
      return null;
  }
}

// modeRank orders modes loosest → strictest, as the daemon does. An unknown
// mode ranks loosest, so it can never lock anything.
function modeRank(m?: string): number {
  return m === "auto" ? 2 : m === "security" ? 1 : 0;
}

const HOURS = Array.from({ length: 24 }, (_, h) => ({
  value: h,
  label: `${String(h).padStart(2, "0")}:00`,
}));

export function UpdatePanel() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const { data } = useUpdateInfo();

  const check = useMutation({
    mutationFn: api.updateCheck,
    onSuccess: (info) => {
      qc.setQueryData(["update"], info);
      if (info.error) message.error(info.error);
      else if (info.available) message.success(t("update.newVersion", { version: info.latest }));
      else message.success(t("update.upToDate"));
    },
    onError: (e: any) => message.error(e?.message || t("update.checkFailed")),
  });

  const apply = useMutation({
    mutationFn: api.updateApply,
    onSuccess: (info) => {
      qc.setQueryData(["update"], info);
      message.success(t("update.applying"));
    },
    // The installer stops and restarts this daemon, so the request it was made
    // through can die mid-flight BY DESIGN. Reporting that as a failure would
    // tell the user the update broke at the exact moment it is working.
    onError: (e: any) => {
      if (e?.status === 409) message.warning(t(reasonKey(e?.body?.reason)));
      else message.info(t("update.applyLostConnection"));
    },
  });

  const savePolicy = useMutation({
    mutationFn: (patch: Partial<UpdatePolicy>) => api.setUpdatePolicy(patch),
    onSuccess: (info) => {
      qc.setQueryData(["update"], info);
      message.success(t("update.policySaved"));
    },
    onError: (e: any) => message.error(e?.message || t("update.policyFailed")),
  });

  if (!data) return null;
  const p = data.policy;
  const windowOn = !!p && p.window_start_hour !== p.window_end_hour;
  // What the daemon acts on: the machine's choice, tightened by the org's
  // requirement. Shown instead of the stored choice — a radio button sitting on
  // "tell me only" while the machine installs on its own would be a lie.
  const org = data.org_policy;
  const orgMin = modeRank(org?.min_mode);
  const effMode = p && orgMin > modeRank(p.mode) ? org!.min_mode! : p?.mode;
  const deferCap = org?.max_defer_days;
  const effDefer = p && deferCap !== undefined && deferCap < p.max_defer_days ? deferCap : p?.max_defer_days;
  const hold = holdKey(data.hold);
  const until = data.hold_until ? new Date(data.hold_until) : null;

  return (
    <Space direction="vertical" size={4} style={{ width: "100%" }}>
      {/* No "Updates" label here: the card this sits in is already titled that,
          and repeating it reads as two separate things. */}
      <div>
        {data.available && data.latest ? (
          <Tag color={data.critical || data.mandatory ? "red" : "blue"}>
            {t("update.newVersion", { version: data.latest })}
          </Tag>
        ) : (
          <Tag>{t("update.upToDate")}</Tag>
        )}
        {/* Mandatory wins the label: it is the stronger statement, and showing
            both would read as two separate reasons rather than one. */}
        {data.mandatory ? (
          <Tag color="red">{t("update.mandatory")}</Tag>
        ) : (
          data.critical && <Tag color="red">{t("update.critical")}</Tag>
        )}
      </div>

      {/* An unavoidable restart deserves a sentence. This is the one case where
          the setting below is not honoured, and saying so beats letting someone
          discover it from a restart. */}
      {data.mandatory && (
        <Text type="danger" style={{ fontSize: 12 }}>
          {t("update.mandatoryHint")}
        </Text>
      )}

      {/* Why it cannot be installed here at all — a fact about the machine. */}
      {data.available && !data.can_apply && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {t(reasonKey(data.reason))}
        </Text>
      )}
      {/* Why it is not being installed RIGHT NOW — a consequence of the policy.
          Never both: the first case never reaches a policy decision. */}
      {data.available && data.can_apply && hold && (
        <Text type="secondary" style={{ fontSize: 12 }}>
          {t(hold)}
          {until &&
            // A rollout ETA is hours away, not days: give the time, and say it
            // is an estimate rather than a deadline.
            (data.hold === "rollout"
              ? ` · ${t("update.holdRolloutEta", { time: until.toLocaleString() })}`
              : ` · ${t("update.holdUntil", { date: until.toLocaleDateString() })}`)}
        </Text>
      )}
      {data.error && (
        <Text type="danger" style={{ fontSize: 12 }}>
          {t("update.checkFailed")}: {data.error}
        </Text>
      )}

      <Space size={8} style={{ marginTop: 4 }}>
        <Button
          size="small"
          loading={check.isPending || data.state === "checking"}
          onClick={() => check.mutate()}
        >
          {t("update.checkNow")}
        </Button>
        {data.available && data.can_apply && (
          <Button
            size="small"
            type="primary"
            loading={apply.isPending || data.state === "updating"}
            onClick={() => apply.mutate()}
          >
            {t("update.applyNow")}
          </Button>
        )}
      </Space>

      {/* ---- the machine's setting ------------------------------------------
          Shown even where can_apply is false: the policy is stored per machine
          and stays meaningful for when that machine gains the ability to
          install (a user daemon reinstalled as a system service, or Linux once
          it can swap its own binary). */}
      {p && (
        <div style={{ marginTop: 10 }}>
          <div>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {t("update.modeLabel")}
            </Text>
          </div>
          <Radio.Group
            size="small"
            value={effMode}
            disabled={savePolicy.isPending}
            onChange={(e) => savePolicy.mutate({ mode: e.target.value })}
            style={{ marginTop: 4 }}
          >
            {/* Looser than the org allows = not offered. */}
            <Radio.Button value="auto">{t("update.modeAuto")}</Radio.Button>
            <Radio.Button value="security" disabled={orgMin > 1}>
              {t("update.modeSecurity")}
            </Radio.Button>
            <Radio.Button value="notify" disabled={orgMin > 0}>
              {t("update.modeNotify")}
            </Radio.Button>
          </Radio.Group>
          <div style={{ marginTop: 4 }}>
            <Text type="secondary" style={{ fontSize: 12 }}>
              {t(`update.mode${effMode === "auto" ? "Auto" : effMode === "security" ? "Security" : "Notify"}Hint`)}
            </Text>
          </div>
          {orgMin > 0 && (
            <div>
              <Text type="warning" style={{ fontSize: 12 }}>
                {t("update.orgMinMode", {
                  mode: t(orgMin > 1 ? "update.modeAuto" : "update.modeSecurity"),
                })}
              </Text>
            </div>
          )}

          {/* The window and the defer cap only ever bind in "auto": under
              "security" the only thing that installs is a critical release,
              which skips both, and under "notify" nothing installs at all.
              Rendering them there would be three controls that do nothing. */}
          {effMode === "auto" && (
            <>
              <div style={{ marginTop: 8 }}>
                <Switch
                  size="small"
                  checked={windowOn}
                  disabled={savePolicy.isPending}
                  onChange={(on) =>
                    savePolicy.mutate(
                      on
                        ? { window_start_hour: 3, window_end_hour: 5 }
                        : { window_start_hour: 0, window_end_hour: 0 },
                    )
                  }
                />{" "}
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t("update.windowLabel")}
                </Text>
              </div>
              {windowOn && (
                <div style={{ marginTop: 6 }}>
                  <Select
                    size="small"
                    style={{ width: 88 }}
                    value={p.window_start_hour}
                    options={HOURS}
                    disabled={savePolicy.isPending}
                    onChange={(v) => savePolicy.mutate({ window_start_hour: v })}
                  />
                  <Text type="secondary"> — </Text>
                  <Select
                    size="small"
                    style={{ width: 88 }}
                    value={p.window_end_hour}
                    options={HOURS}
                    disabled={savePolicy.isPending}
                    onChange={(v) => savePolicy.mutate({ window_end_hour: v })}
                  />{" "}
                  {/* Whose clock. A console can be open from another country;
                      the restart happens on the machine. */}
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {t("update.windowTz", { tz: data.timezone || "" })}
                  </Text>
                </div>
              )}

              <div style={{ marginTop: 8 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {t("update.deferLabel")}
                </Text>{" "}
                <Select
                  size="small"
                  style={{ width: 96 }}
                  value={effDefer}
                  disabled={savePolicy.isPending}
                  onChange={(v) => savePolicy.mutate({ max_defer_days: v })}
                  options={[0, 1, 3, 7, 14, 30].map((n) => ({
                    value: n,
                    label: n === 0 ? t("update.deferNever") : t("update.deferDays", { n }),
                    disabled: deferCap !== undefined && n > deferCap,
                  }))}
                />
              </div>
              <div style={{ marginTop: 2 }}>
                <Text type="secondary" style={{ fontSize: 12 }}>
                  {effDefer === 0 ? t("update.deferNeverHint") : t("update.deferHint")}
                </Text>
              </div>
              {deferCap !== undefined && (
                <div>
                  <Text type="warning" style={{ fontSize: 12 }}>
                    {deferCap === 0 ? t("update.orgNoDefer") : t("update.orgMaxDefer", { n: deferCap })}
                  </Text>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </Space>
  );
}
