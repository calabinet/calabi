//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/calabinet/calabi/apps/client/internal/creds"
)

type fileServiceConfig struct {
	Console   string `json:"console"`
	User      string `json:"user"`
	StateDir  string `json:"state_dir"`
	Directory string `json:"directory"`
	Name      string `json:"name"`
}

var fileServiceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

func fileServiceConfigPath(name string) string {
	return filepath.Join("/etc/calabi-files", name+".json")
}
func (c fileServiceConfig) port() string   { u, _ := url.Parse(c.Console); return u.Port() }
func (c fileServiceConfig) socket() string { return "/run/calabi-files-" + c.port() + "/web.sock" }
func fileServiceCommand(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
func validateFileServiceConfig(c fileServiceConfig) error {
	if !fileServiceName.MatchString(c.Name) || !fileServiceName.MatchString(c.User) {
		return errors.New("invalid file service or user name")
	}
	if c.Name != "calabi-files" && (!strings.HasPrefix(c.Name, "calabi-files-") || len(c.Name) == len("calabi-files-")) {
		return errors.New("file service name must be calabi-files or calabi-files-<daemon-name>")
	}
	if _, err := fileControlConsole(c.Console); err != nil {
		return err
	}
	u, _ := url.Parse(c.Console)
	if u.Hostname() != "127.0.0.1" {
		return errors.New("file service console must use 127.0.0.1 and an explicit port")
	}
	for _, p := range []string{c.StateDir, c.Directory} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\r\n\x00") || filepath.Clean(p) == "/" {
			return errors.New("service directories must be explicit absolute paths")
		}
	}
	private := filepath.Join(c.StateDir, ".config", "Calabi", "file-agent")
	for _, pair := range [][2]string{{private, c.Directory}, {c.Directory, private}} {
		rel, err := filepath.Rel(pair[0], pair[1])
		if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))) {
			return errors.New("file directory must be separate from the private file-service profile")
		}
	}
	return nil
}
func loadFileServiceConfig(name string) (fileServiceConfig, error) {
	var c fileServiceConfig
	if !fileServiceName.MatchString(name) {
		return c, errors.New("invalid service name")
	}
	b, err := os.ReadFile(fileServiceConfigPath(name))
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Name != name {
		return c, errors.New("file service identity mismatch")
	}
	return c, validateFileServiceConfig(c)
}
func unitQuote(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`), `%`, `%%`) + `"`
}
func fileDaemonName(name string) string {
	if name == "calabi-files" {
		return "calabi"
	}
	return strings.TrimPrefix(name, "calabi-files-")
}
func publicFileServiceDirectory(path string) error {
	return prepareFileServiceDirectory(path, true)
}
func prepareFileServiceDirectory(path string, privateToCalabi bool) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return errors.New("file-service installation directory must be root-owned and not writable by other users")
	}
	if privateToCalabi {
		return os.Chmod(path, 0755)
	}
	return nil // Never change permissions on a shared system binary directory.
}
func fileServiceUnit(c fileServiceConfig, binary string) string {
	return fmt.Sprintf("[Unit]\nDescription=Calabi file transfers (%s)\nAfter=network.target %s.service\n\n[Service]\nType=simple\nUser=%s\nUMask=0077\nEnvironment=%s\nExecStart=%s mesh files service run --service-name %s\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nRuntimeDirectory=calabi-files-%s\nRuntimeDirectoryMode=0700\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=%s %s\n\n[Install]\nWantedBy=multi-user.target\n", c.Name, fileDaemonName(c.Name), c.User, unitQuote("XDG_CONFIG_HOME="+filepath.Join(c.StateDir, ".config")), unitQuote(binary), unitQuote(c.Name), c.port(), unitQuote(c.StateDir), unitQuote(c.Directory))
}
func installFileService(c fileServiceConfig) error {
	return configureFileService(c, false)
}
func configureFileService(c fileServiceConfig, preserve bool) error {
	if os.Geteuid() != 0 {
		return errors.New("install file service as root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("systemd is required; manual mesh files remains available")
	}
	if err := validateFileServiceConfig(c); err != nil {
		return err
	}
	unit := filepath.Join("/etc/systemd/system", c.Name+".service")
	existingUnit, unitErr := os.ReadFile(unit)
	if unitErr == nil && !strings.Contains(string(existingUnit), "Description=Calabi file transfers (") {
		return errors.New("refusing to replace an unrelated file service unit")
	}
	if unitErr != nil && !errors.Is(unitErr, os.ErrNotExist) {
		return unitErr
	}
	wasEnabled, wasActive := true, true
	if preserve && unitErr == nil {
		wasEnabled = exec.Command("systemctl", "is-enabled", "--quiet", c.Name+".service").Run() == nil
		wasActive = exec.Command("systemctl", "is-active", "--quiet", c.Name+".service").Run() == nil
	}
	if existing, err := loadFileServiceConfig(c.Name); err == nil {
		if preserve {
			c = existing
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	account, err := user.Lookup(c.User)
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return err
		}
		cmd := exec.Command("useradd", "--system", "--create-home", "--home-dir", c.StateDir, "--shell", "/usr/sbin/nologin", c.User)
		if b, e := cmd.CombinedOutput(); e != nil {
			return fmt.Errorf("create file user: %s: %w", b, e)
		}
		account, err = user.Lookup(c.User)
		if err != nil {
			return err
		}
	}
	uid, e := strconv.Atoi(account.Uid)
	if e != nil || uid == 0 {
		return errors.New("file service requires a non-root account")
	}
	gid, e := strconv.Atoi(account.Gid)
	if e != nil {
		return e
	}
	for _, dir := range []string{c.StateDir, c.Directory} {
		if st, e := os.Lstat(dir); errors.Is(e, os.ErrNotExist) {
			if e = os.MkdirAll(dir, 0700); e != nil {
				return e
			}
			if e = os.Chown(dir, uid, gid); e != nil {
				return e
			}
		} else if e != nil {
			return e
		} else if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("service directory must be a real directory")
		}
	}
	// Check the actual selected user's access without changing existing ownership.
	if b, e := exec.Command("runuser", "-u", c.User, "--", "test", "-w", c.StateDir).CombinedOutput(); e != nil {
		return fmt.Errorf("state directory is not writable by file user: %s: %w", b, e)
	}
	if b, e := exec.Command("runuser", "-u", c.User, "--", "test", "-w", c.Directory).CombinedOutput(); e != nil {
		return fmt.Errorf("transfer directory is not writable by file user: %s: %w", b, e)
	}
	if err = publicFileServiceDirectory(filepath.Dir(fileServiceConfigPath(c.Name))); err != nil {
		return err
	}
	body, _ := json.MarshalIndent(c, "", "  ")
	if err = os.WriteFile(fileServiceConfigPath(c.Name), body, 0644); err != nil {
		return err
	}
	// Use the actual system bin path: a bin nested inside /usr/local/lib may
	// still match a more specific lib_t file-context rule on RHEL-family hosts.
	binary := filepath.Join("/usr/local/bin", c.Name+"-helper")
	if err = prepareFileServiceDirectory(filepath.Dir(binary), false); err != nil {
		return err
	}
	source, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	f, err := os.CreateTemp(filepath.Dir(binary), ".file-service-*.new")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0755); err != nil {
		f.Close()
		return err
	}
	_, err = io.Copy(f, in)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, binary); err != nil {
		return err
	}
	if err = labelFileServiceExecutable(binary); err != nil {
		return err
	}
	if err = os.WriteFile(unit, []byte(fileServiceUnit(c, binary)), 0644); err != nil {
		return err
	}
	if err = fileServiceCommand("daemon-reload"); err != nil {
		return err
	}
	if wasEnabled {
		if err = fileServiceCommand("enable", c.Name+".service"); err != nil {
			return err
		}
	}
	if wasActive {
		if err = fileServiceCommand("restart", c.Name+".service"); err != nil {
			return err
		}
	}
	fmt.Printf("File service %s configured (enabled=%t, running=%t); saved reception preferences are retained.\nOpen the daemon console → Mesh → File transfers.\n", c.Name, wasEnabled, wasActive)
	return nil
}

func labelFileServiceExecutable(binary string) error {
	if _, err := os.Stat("/sys/fs/selinux/enforce"); errors.Is(err, os.ErrNotExist) {
		return nil // A Debian/Ubuntu host may have tools but no active SELinux.
	}
	// Even an atomic replacement inherits its staging directory's label.
	// Restore the host policy's expected label, without installing allow rules.
	restorecon, err := exec.LookPath("restorecon")
	if err == nil {
		if output, e := exec.Command(restorecon, binary).CombinedOutput(); e != nil {
			return fmt.Errorf("restore file helper SELinux label: %w: %s", e, output)
		}
	} else if selinuxEnforcing() {
		return errors.New("SELinux is enforcing; install restorecon before configuring the file service")
	}
	if selinuxEnforcing() && !execTypesServicesMayRun[fileSELinuxType(binary)] {
		return fmt.Errorf("file helper %s has SELinux type %q after restorecon; check matchpathcon for the host file-context policy", binary, fileSELinuxType(binary))
	}
	return nil
}
func installCompanionFiles(args []string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	name := resolveServiceName(args)
	fileName := "calabi-files"
	if name != "calabi" {
		fileName += "-" + name
	}
	consoleURL := installStatusURL(args)
	if name == "calabi" && extractFlagValue(args, "status-addr") == "" && extractFlagValue(args, "status-port") == "" {
		// Existing installs may use a persisted non-default console port. Read
		// the same daemon-published address used by the service CLI's hint.
		if actual := awaitConsoleURLInAny([]string{exeDir(), creds.SystemDataDir()}, time.Now().Add(-30*time.Second), 3*time.Second); actual != "" {
			consoleURL = actual
		}
	}
	console, err := fileControlConsole(consoleURL)
	if err != nil {
		return err
	}
	c := fileServiceConfig{Console: console, User: "calabi-files", StateDir: "/var/lib/" + fileName, Directory: "/var/lib/" + fileName + "/transfers", Name: fileName}
	return configureFileService(c, true)
}
func uninstallCompanionFiles(args []string) error {
	name := "calabi-files"
	if n := resolveServiceName(args); n != "calabi" {
		name += "-" + n
	}
	return uninstallFileService(name)
}
func uninstallFileService(name string) error {
	if !fileServiceName.MatchString(name) {
		return errors.New("invalid file service name")
	}
	if _, err := os.Stat(fileServiceConfigPath(name)); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := fileServiceCommand("disable", "--now", name+".service"); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join("/etc/systemd/system", name+".service")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fileServiceCommand("daemon-reload") // user data and config intentionally retained
}
func runFileService(args []string) int {
	err := fileServiceCLI(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "file service:", err)
		return 1
	}
	return 0
}
func fileServiceCLI(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: calabi mesh files service install|uninstall|start|stop|restart|enable|disable|status|logs|web-url|reset-web-key")
	}
	fs := flag.NewFlagSet("files service", flag.ContinueOnError)
	name := fs.String("service-name", "calabi-files", "file service unit name")
	console := fs.String("console", "http://127.0.0.1:7400", "exact daemon console URL")
	owner := fs.String("user", "calabi-files", "ordinary file-service user")
	state := fs.String("state-dir", "/var/lib/calabi-files", "existing user state home (preserved on upgrade)")
	dir := fs.String("directory", "/var/lib/calabi-files/transfers", "server selection and save directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected file service arguments")
	}
	if !fileServiceName.MatchString(*name) {
		return errors.New("invalid service name")
	}
	if args[0] == "install" {
		c := fileServiceConfig{Console: *console, User: *owner, StateDir: *state, Directory: *dir, Name: *name}
		if old, err := loadFileServiceConfig(*name); err == nil {
			c = old
			// Re-running install preserves identity and paths unless the operator
			// explicitly supplies a replacement. Automatic upgrades use refresh.
			fs.Visit(func(f *flag.Flag) {
				switch f.Name {
				case "console":
					c.Console = *console
				case "user":
					c.User = *owner
				case "state-dir":
					c.StateDir = *state
				case "directory":
					c.Directory = *dir
				}
			})
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return installFileService(c)
	}
	c, err := loadFileServiceConfig(*name)
	if err != nil {
		return err
	}
	switch args[0] {
	case "reset-web-key":
		if os.Geteuid() != 0 {
			return errors.New("reset the private browser key as root")
		}
		active := exec.Command("systemctl", "is-active", "--quiet", c.Name+".service").Run() == nil
		if err := fileServiceCommand("stop", c.Name+".service"); err != nil {
			return err
		}
		// Remove only this capability, as its owner. The ordinary-user service
		// generates its replacement; root never creates private profile files.
		keyPath := filepath.Join(c.StateDir, ".config", "Calabi", "file-agent", "browser-access-key")
		if err := exec.Command("runuser", "-u", c.User, "--", "rm", "-f", "--", keyPath).Run(); err != nil {
			return fmt.Errorf("file service stopped; could not revoke browser key: %w", err)
		}
		if active {
			if err := fileServiceCommand("start", c.Name+".service"); err != nil {
				return err
			}
		}
		fmt.Println("Private browser access revoked. A new key is generated when the file service starts; use web-url to retrieve it.")
		return nil
	case "run":
		return serveManagedFiles(c)
	case "refresh":
		return configureFileService(c, true)
	case "web-url":
		if os.Geteuid() != 0 {
			account, e := user.Current()
			if e != nil || account.Username != c.User {
				return errors.New("only root or the file-service user may read its private browser key")
			}
		}
		// This command only reads: running it before the service starts must not
		// create root-owned files in the ordinary user's private profile.
		body, err := os.ReadFile(filepath.Join(c.StateDir, ".config", "Calabi", "file-agent", "browser-access-key"))
		if err != nil {
			return fmt.Errorf("private browser key unavailable; start the file service first: %w", err)
		}
		key := strings.TrimSpace(string(body))
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(key) {
			return errors.New("invalid private browser access key")
		}
		fmt.Printf("%s/file-service/#/mesh/files?key=%s\n", c.Console, key)
		return nil
	case "status":
		fmt.Printf("User: %s\nConsole: %s\nFiles: %s\n", c.User, c.Console, c.Directory)
		return fileServiceCommand("status", "--no-pager", c.Name+".service")
	case "logs":
		cmd := exec.Command("journalctl", "-u", c.Name+".service", "--no-pager", "-n", "100")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case "uninstall":
		return uninstallFileService(c.Name)
	case "start", "stop", "restart", "enable", "disable":
		return fileServiceCommand(args[0], c.Name+".service")
	default:
		return errors.New("unknown file service command")
	}
}
func serveManagedFiles(c fileServiceConfig) error {
	account, err := user.Current()
	if err != nil {
		return err
	}
	if account.Username != c.User || account.Uid == "0" {
		return errors.New("run the file service as its configured ordinary user")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	d, err := newDesktopFileAgent(ctx, c.Console)
	if err != nil {
		return err
	}
	defer d.close()
	if err = d.configureManaged(c.Directory); err != nil {
		return err
	}
	root, err := os.OpenRoot(c.Directory)
	if err != nil {
		return err
	}
	defer root.Close()
	key, err := browserKey(d.dir)
	if err != nil {
		return err
	}
	// systemd creates a private runtime directory; refuse accidental manual root paths.
	st, err := os.Lstat(filepath.Dir(c.socket()))
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("private systemd runtime directory required")
	}
	if st, err := os.Lstat(c.socket()); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("file service endpoint is not a socket")
		}
		conn, e := net.DialTimeout("unix", c.socket(), time.Second)
		if e == nil {
			conn.Close()
			return errors.New("another file service is running")
		}
		if err = os.Remove(c.socket()); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", c.socket())
	if err != nil {
		return err
	}
	defer l.Close()
	if err = os.Chmod(c.socket(), 0600); err != nil {
		return err
	}
	web := &fileBrowser{d: d, root: root, directory: c.Directory, key: key, action: d.handle, managed: true}
	srv := &http.Server{Handler: web, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stop := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stop()
	fmt.Println("File service ready; management is available in the daemon console. Private access: calabi mesh files service web-url")
	err = srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
