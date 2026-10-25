package filetransfer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	meshproto "github.com/calabinet/calabi/pkg/mesh-proto"
	"github.com/calabinet/calabi/pkg/mesh-proto/meshpb"
	"github.com/gofrs/flock"
)

type identityRecord struct {
	Certificate, Key []byte
	HistoryID        string `json:",omitempty"`
}

type IdentityStatus struct {
	Exists       bool   `json:"exists"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	ExpiresUnix  int64  `json:"expires_unix,omitempty"`
	NeedsRenewal bool   `json:"needs_renewal"`
	Error        string `json:"error,omitempty"`
}

func identityLock(directory, name string) (*flock.Flock, error) {
	l := flock.New(filepath.Join(directory, name))
	ok, err := l.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("another file agent is using this identity; close file transfers and retry")
	}
	return l, nil
}

func readIdentity(root *os.Root) (*Identity, error) {
	f, err := root.Open("file-identity.json")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var r identityRecord
	if json.NewDecoder(io.LimitReader(f, 8193)).Decode(&r) != nil {
		return nil, errors.New("file identity is corrupt; explicit reset required")
	}
	cert, err := x509.ParseCertificate(r.Certificate)
	if err != nil {
		return nil, errors.New("invalid file certificate; explicit reset required")
	}
	k, err := x509.ParsePKCS8PrivateKey(r.Key)
	if err != nil {
		return nil, errors.New("invalid file key; explicit reset required")
	}
	key, ok := k.(ed25519.PrivateKey)
	pub, pubOK := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pubOK || !key.Public().(ed25519.PublicKey).Equal(pub) {
		return nil, errors.New("file key does not match certificate; explicit reset required")
	}
	h := sha256.Sum256(cert.Raw)
	pin := hex.EncodeToString(h[:])
	if r.HistoryID == "" {
		r.HistoryID = pin
	}
	if !validID(r.HistoryID) {
		return nil, errors.New("invalid private file history identity")
	}
	return &Identity{Certificate: tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}, Fingerprint: pin, historyID: r.HistoryID}, nil
}

// The separate recovery marker lets an explicit reset retain history even if
// the certificate record is damaged. It is not a network identity or a secret.
func ensureHistoryID(root *os.Root, id string) error {
	b, err := root.ReadFile("file-history-id")
	if err == nil {
		if string(b) != id {
			return errors.New("private file history identity mismatch")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := root.OpenFile("file-history-id", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(id))
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func storeIdentity(root *os.Root, id *Identity) error {
	key, err := x509.MarshalPKCS8PrivateKey(id.Certificate.PrivateKey)
	if err != nil {
		return err
	}
	return writeRecord(root, "file-identity.json", identityRecord{Certificate: id.Certificate.Certificate[0], Key: key, HistoryID: id.HistoryID()})
}

// Existing damaged or expired keys are never silently replaced. All network
// pins still use the certificate fingerprint; only private history is stable.
func LoadIdentity(directory string) (*Identity, error) {
	l, err := identityLock(directory, "file-identity.lock")
	if err != nil {
		return nil, err
	}
	defer l.Unlock()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	id, err := readIdentity(root)
	if errors.Is(err, os.ErrNotExist) {
		id, err = newIdentity(365 * 24 * time.Hour)
		if err != nil {
			return nil, err
		}
		id.historyID = id.Fingerprint
		if _, e := root.ReadFile("file-history-id"); e == nil {
			return nil, errors.New("file identity is missing; explicit reset required")
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if err = ensureHistoryID(root, id.HistoryID()); err != nil {
			return nil, err
		}
		if err = storeIdentity(root, id); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(id.Certificate.Certificate[0])
	if time.Now().Before(cert.NotBefore) || !time.Now().Add(meshproto.FileTransferLease).Before(cert.NotAfter) {
		return nil, errors.New("file certificate is expired or not yet valid; explicitly renew or reset it")
	}
	if err = ensureHistoryID(root, id.HistoryID()); err != nil {
		return nil, err
	}
	id.directory = directory
	return id, nil
}

func ReadIdentityStatus(directory string) IdentityStatus {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return IdentityStatus{Error: "file identity is not initialized"}
	}
	defer root.Close()
	id, err := readIdentity(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if b, e := root.ReadFile("file-history-id"); e == nil && validID(string(b)) {
				return IdentityStatus{Exists: true, Error: "file identity is missing; explicit reset required"}
			}
		}
		return IdentityStatus{Exists: !errors.Is(err, os.ErrNotExist), Error: err.Error()}
	}
	cert, _ := x509.ParseCertificate(id.Certificate.Certificate[0])
	status := IdentityStatus{Exists: true, Fingerprint: id.Fingerprint, ExpiresUnix: cert.NotAfter.Unix(), NeedsRenewal: time.Now().Add(30 * 24 * time.Hour).After(cert.NotAfter)}
	if time.Now().Before(cert.NotBefore) || !time.Now().Add(meshproto.FileTransferLease).Before(cert.NotAfter) {
		status.Error = "file certificate is expired or not yet valid; explicitly renew or reset it"
	}
	return status
}

// Caller must obtain explicit local confirmation. Maintenance is exclusive
// with every agent using this stored identity, including another scope/user UI.
// It keeps completed files/sources, cancels unfinished journals and backs up the
// previous private key record before atomically publishing the replacement.
func MaintainIdentity(directory, operation string) (*Identity, error) {
	if operation != "renew" && operation != "reset" {
		return nil, errors.New("unknown identity operation")
	}
	use, err := identityLock(directory, "file-identity-use.lock")
	if err != nil {
		return nil, err
	}
	defer use.Unlock()
	l, err := identityLock(directory, "file-identity.lock")
	if err != nil {
		return nil, err
	}
	defer l.Unlock()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	old, readErr := readIdentity(root)
	var history string
	if readErr == nil {
		history = old.HistoryID()
		if err = ensureHistoryID(root, history); err != nil {
			return nil, err
		}
	} else {
		if operation == "renew" {
			return nil, errors.New("cannot renew a damaged file key; use explicit reset")
		}
		b, e := root.ReadFile("file-history-id")
		if e != nil || !validID(string(b)) {
			return nil, errors.New("cannot recover history identity; retain the private directory for manual recovery")
		}
		history = string(b)
	}
	var next *Identity
	if operation == "renew" {
		next, err = identityWithKey(old.Certificate.PrivateKey.(ed25519.PrivateKey), 365*24*time.Hour)
	} else {
		next, err = newIdentity(365 * 24 * time.Hour)
	}
	if err != nil {
		return nil, err
	}
	next.historyID = history
	next.directory = directory
	f, err := root.Open("file-identity.json")
	var previous []byte
	if err == nil {
		previous, err = io.ReadAll(io.LimitReader(f, 8193))
		f.Close()
	} else if operation == "reset" && errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if err != nil || len(previous) > 8192 {
		return nil, errors.New("invalid previous file identity size")
	}
	if len(previous) > 0 {
		backup := "file-identity.previous.json"
		if readErr != nil {
			backup = "file-identity.damaged.json"
		}
		if err = writeRecord(root, backup, struct{ Data []byte }{previous}); err != nil {
			return nil, err
		}
	}
	locks, err := lockIdentityWorkspaces(root)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, l := range locks {
			l.Unlock()
		}
	}()
	if err = cancelIdentityTasks(root); err != nil {
		return nil, err
	}
	if err = storeIdentity(root, next); err != nil {
		return nil, err
	}
	return next, nil
}

func lockIdentityWorkspaces(root *os.Root) ([]*flock.Flock, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	var locks []*flock.Flock
	for _, e := range entries {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		l, err := identityLock(filepath.Join(root.Name(), e.Name()), "workspace.lock")
		if err != nil {
			for _, held := range locks {
				held.Unlock()
			}
			return nil, err
		}
		locks = append(locks, l)
	}
	return locks, nil
}

func cancelIdentityTasks(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		w, err := root.OpenRoot(e.Name())
		if err != nil {
			return err
		}
		err = cancelWorkspaceIdentityTasks(w)
		w.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func cancelWorkspaceIdentityTasks(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasPrefix(name, "job-") && strings.HasSuffix(name, ".json") && validID(strings.TrimSuffix(strings.TrimPrefix(name, "job-"), ".json")) {
			var rec outgoingRecord
			if err := readRecord(root, name, &rec); err != nil {
				return err
			}
			if rec.Job.State != "completed" && rec.Job.State != "cancelled" {
				rec.Job.State = "cancelled"
				rec.Job.Error = "file identity changed; start a new transfer"
				rec.Job.RateBps = 0
				rec.Job.RemainingSeconds = 0
				rec.Ticket = BatchTicket{}
				if err := writeRecord(root, name, rec); err != nil {
					return err
				}
			}
		}
		if e.IsDir() && strings.HasPrefix(name, "peer-") && validID(strings.TrimPrefix(name, "peer-")) {
			pr, err := root.OpenRoot(name)
			if err != nil {
				return err
			}
			err = cancelInboxIdentityTasks(pr)
			pr.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func cancelInboxIdentityTasks(root *os.Root) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || !validID(strings.TrimSuffix(e.Name(), ".json")) {
			continue
		}
		var rec receiveRecord
		if err := readRecord(root, e.Name(), &rec); err != nil {
			return err
		}
		if rec.Transfer.State != "completed" && rec.Transfer.State != "cancelled" && rec.Transfer.State != "failed" {
			rec.Transfer.State = "cancelled"
			rec.Transfer.RateBps = 0
			rec.Transfer.RemainingSeconds = 0
			rec.Token = randomID()
			if err := writeRecord(root, e.Name(), rec); err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *Identity) Declaration(node meshproto.NodeKey, port uint16, receiving bool) (*meshpb.FileTransferInfo, error) {
	key, ok := i.Certificate.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(i.Certificate.Certificate) != 1 {
		return nil, errors.New("dedicated Ed25519 identity required")
	}
	info := &meshpb.FileTransferInfo{Version: 1, Port: uint32(port), Receiving: receiving, Certificate: append([]byte(nil), i.Certificate.Certificate[0]...), ExpiresUnix: time.Now().Add(meshproto.FileTransferLease).Unix()}
	return info, meshproto.SignFileTransfer(node, info, key)
}
