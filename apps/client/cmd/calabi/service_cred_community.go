// service_cred_community.go — the Community Edition only installs the LOCAL
// supervisor daemon (`daemon install --config tunnels.yaml`), which gets its
// credential from the YAML's token_env, not from a platform login. So there is
// nothing to provision at install time.

package main

func serviceInstallEnv(installArgs []string) (map[string]string, error) {
	return nil, nil
}
