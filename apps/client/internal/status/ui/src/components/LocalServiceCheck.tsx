import { CheckCircleOutlined, ExclamationCircleOutlined, LoadingOutlined } from "@ant-design/icons";
import { Typography } from "antd";
import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import type { ProbeCheck } from "../api/types";
import { displayError } from "../api/userError";

const { Text } = Typography;

// probeMessage turns a failed check into one plain sentence.
//
// It reads `reason` — a stable code the daemon assigns (probe/reason.go) — and
// NOT the `error` text. Matching English substrings here would have been the
// obvious shortcut and would break the day Windows, Go, or a translation
// reworded anything; the daemon is the only place that can classify reliably,
// because only it holds the actual error value.
export function probeMessage(t: TFunction, r: ProbeCheck): string {
  const known = ["refused", "timeout", "unreachable", "dns", "tls", "http_5xx", "invalid"];
  if (r.reason && known.includes(r.reason)) return t(`wizard.reason.${r.reason}`);
  // Unclassified: show what the daemon said rather than inventing a friendlier
  // sentence that might be wrong about the cause.
  return t("wizard.checkFail", { err: r.error ? displayError(r.error, t) : t("wizard.checkFailUnknown") });
}

// LocalCheckLine renders the reachability answer under the local-service row.
//
// It is a HINT, never a gate. "Nothing is listening on 127.0.0.1:8080" is a
// perfectly ordinary state five seconds before you start the dev server, so the
// unreachable case says so and still lets you create the tunnel — it just means
// the 502 you would otherwise have debugged from the public URL is explained
// here instead.
export function LocalCheckLine({ checking, result, showCreateHint = true }: {
  checking: boolean;
  result: ProbeCheck | null;
  showCreateHint?: boolean;
}) {
  const { t } = useTranslation();
  if (checking) {
    return (
      <Text role="status" type="secondary" style={{ fontSize: 12 }}>
        <LoadingOutlined /> {t("wizard.checkRunning")}
      </Text>
    );
  }
  if (!result) return null;
  if (result.healthy) {
    return (
      <Text role="status" type="success" style={{ fontSize: 12 }}>
        <CheckCircleOutlined /> {t("wizard.checkOk", { ms: result.latency_ms })}
      </Text>
    );
  }
  return (
    <span role="status" style={{ fontSize: 12 }}>
      <Text type="warning">
        <ExclamationCircleOutlined /> {probeMessage(t, result)}
      </Text>
      {showCreateHint && <><br /><Text type="secondary">{t("wizard.checkFailHint")}</Text></>}
      {/* Detailed OS diagnostics are available on demand, below the explanation. */}
      {result.error && (
        <>
          <br />
          <details><summary>{t("errorDiagnostics.details")}</summary>
            <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{result.error}</pre>
          </details>
        </>
      )}
    </span>
  );
}
