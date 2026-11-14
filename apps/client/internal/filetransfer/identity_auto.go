package filetransfer

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"os"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
)

// RenewalDue leaves a month to replace the certificate between transfers.
func (i *Identity) RenewalDue() bool {
	if i == nil || len(i.Certificate.Certificate) != 1 {
		return false
	}
	cert, err := x509.ParseCertificate(i.Certificate.Certificate[0])
	return err == nil && !time.Now().Before(cert.NotBefore) && !time.Now().Add(30*24*time.Hour).Before(cert.NotAfter)
}

// LoadManagedIdentity renews a valid private key without changing history or
// cancelling journals. Live agents and legacy workspaces must release their
// locks first. Damaged, missing established keys and future-dated certificates
// still require explicit recovery or a corrected system clock.
func LoadManagedIdentity(directory string) (*Identity, error) {
	id, originalErr := LoadIdentity(directory)
	if originalErr == nil && !id.RenewalDue() {
		return id, nil
	}
	fallback := func(err error) (*Identity, error) {
		if originalErr == nil {
			return id, nil
		}
		return nil, err
	}
	use, err := identityLock(directory, "file-identity-use.lock")
	if err != nil {
		return fallback(err)
	}
	defer use.Unlock()
	l, err := identityLock(directory, "file-identity.lock")
	if err != nil {
		return fallback(err)
	}
	defer l.Unlock()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return fallback(err)
	}
	defer root.Close()
	current, err := readIdentity(root)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(current.Certificate.Certificate[0])
	if time.Now().Before(cert.NotBefore) {
		return nil, errors.New("file certificate is not yet valid; check the system clock")
	}
	if err := ensureHistoryID(root, current.HistoryID()); err != nil {
		return nil, err
	}
	current.directory = directory
	if !current.RenewalDue() {
		return current, nil
	}
	locks, err := lockIdentityWorkspaces(root)
	if err != nil {
		return fallback(err)
	}
	defer func() {
		for _, held := range locks {
			held.Unlock()
		}
	}()
	next, err := identityWithKey(current.Certificate.PrivateKey.(ed25519.PrivateKey), 365*24*time.Hour)
	if err != nil {
		return fallback(err)
	}
	next.historyID, next.directory = current.HistoryID(), directory
	if err = storeIdentity(root, next); err != nil {
		return fallback(err)
	}
	return next, nil
}

// RetireForIdentityRenewal is called under the client's local operation lock.
// The HTTP gate prevents a new offer racing the final idle check. No task or
// journal is cancelled; callers close this workspace and reopen with the new pin.
func (w *Workspace) RetireForIdentityRenewal() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.stageCancel != nil || !w.Agent.maintenance.TryLock() {
		return false
	}
	defer w.Agent.maintenance.Unlock()
	cert, _ := x509.ParseCertificate(w.Agent.cfg.Identity.Certificate.Certificate[0])
	urgent := cert != nil && !time.Now().Add(meshproto.FileTransferLease).Before(cert.NotAfter)
	for _, j := range w.jobs {
		if j.cancel != nil || j.record.Job.State == "sending" || !urgent && (j.record.Job.State != "completed" && j.record.Job.State != "cancelled" && j.record.Job.State != "failed" || j.record.Job.CancelPending) {
			return false
		}
	}
	for _, row := range w.Agent.List() {
		if !urgent && row.Transfer.State != "completed" && row.Transfer.State != "cancelled" && row.Transfer.State != "failed" {
			return false
		}
	}
	w.Agent.retiring.Store(true)
	return true
}
