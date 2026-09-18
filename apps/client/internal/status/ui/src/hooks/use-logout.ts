// useLogout — the one sign-out mutation, shared by the account menu and the
// Settings card.
//
// Only a success means anything was signed out. The daemon's handler clears the
// credentials and drops the edge + mesh sessions, then answers 200. Every
// failure happens before any of that: the daemon refusing (403 for an agent,
// 501 for standalone) or not answering at all. The machine is still signed in,
// so the page stays put and says so — sending it to /login would bounce straight
// back to the console and look like the click did nothing.
import { message } from "antd";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { api, ApiError } from "../api/client";

export function useLogout() {
  const { t } = useTranslation();
  const qc = useQueryClient();
  const navigate = useNavigate();
  return useMutation({
    mutationFn: api.logout,
    onSuccess: async () => {
      message.success(t("common.loggedOut"));
      await qc.invalidateQueries();
      navigate("/login", { replace: true });
    },
    onError: (e) => {
      message.error(
        e instanceof ApiError && e.message ? e.message : t("settings.logoutFailed"),
      );
    },
  });
}
