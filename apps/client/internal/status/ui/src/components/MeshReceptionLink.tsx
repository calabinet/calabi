import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
import type { FileSnapshot } from "../api/files";

export const receptionControl = {
  assist: "mesh-receive-assist",
  files: "mesh-receive-files",
};

type ReceptionState = "on" | "off" | "waiting" | "unavailable" | "blocked";

export function fileReceptionState(snapshot?: FileSnapshot, blocked?: boolean): ReceptionState {
  if (blocked) return "blocked";
  if (!snapshot) return "waiting";
  if (!snapshot.available) return "unavailable";
  if (snapshot.receiving) return "on";
  return snapshot.service?.receiving_requested ? "waiting" : "off";
}

export default function MeshReceptionLink({ kind, state }: {
  kind: keyof typeof receptionControl;
  state: ReceptionState;
}) {
  const { t } = useTranslation();
  return (
    <Link className="mesh-reception-link" to={`/mesh/routing#${receptionControl[kind]}`}>
      {t(`mesh.reception.${kind}`)} · {t(`mesh.reception.${state}`)}
    </Link>
  );
}
