package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"

	"github.com/calabi/calabi/apps/client/internal/platform/meshenroll"
	"github.com/calabi/calabi/apps/client/internal/trust"
)

// dialCoord opens the gRPC connection to the mesh coordinator, checking its
// certificate as t says.
func dialCoord(addr string, t trust.Config) (*grpc.ClientConn, error) {
	tlsCfg, err := t.TLS(addr)
	if err != nil {
		return nil, err
	}
	return meshenroll.DialCoord(addr, tlsCfg)
}

// coordTrustSpec is what a config file or the command line says about the
// coordinator's certificate.
type coordTrustSpec struct {
	Mode   string // "" = decide; see coordTrust
	Pins   []string
	CAFile string
	// Platform: the coordinator is calabi.net's, known from the platform
	// daemon's own enrollment rather than from anything a person wrote.
	Platform bool
}

// coordTrust decides how to check the coordinator's certificate. authKey is the credential the
// node will enroll with.
//
// Stated explicitly (trust: / --trust), it is taken as stated; pins or a CA file
// without a mode mean pin or ca. Otherwise, first match wins:
//   - CALABI_INSECURE=1: plaintext, the dev-stack escape hatch it always was;
//   - calabi.net (the platform daemon's own lease, or a platform credential — a
//     tk_ key or a login token): the CA compiled into this client;
//   - CALABI_EDGE_CA_FILE: that CA, and only that CA. It used to be ADDED to the
//     compiled-in one, which made every self-hosted coordinator connection
//     trust ours as well;
//   - otherwise the system's roots, which is what a coordinator with a public
//     certificate (Let's Encrypt) needs.
func coordTrust(spec coordTrustSpec, authKey string) (trust.Config, error) {
	// Giving a fingerprint or a CA file says which trust is meant; making the
	// person also spell out the mode would only turn a forgotten --trust into
	// a connection that ignores the pin they gave.
	if strings.TrimSpace(spec.Mode) == "" {
		switch {
		case len(spec.Pins) > 0:
			spec.Mode = string(trust.Pin)
		case spec.CAFile != "":
			spec.Mode = string(trust.CA)
		}
	}
	if strings.TrimSpace(spec.Mode) != "" {
		mode, err := trust.ParseMode(spec.Mode)
		if err != nil {
			return trust.Config{}, err
		}
		return explicitCoordTrust(mode, spec)
	}
	switch {
	case os.Getenv("CALABI_INSECURE") == "1":
		return trust.Config{Mode: trust.Plaintext}, nil
	case spec.Platform || isPlatformCredential(authKey):
		return trust.Config{Mode: trust.Platform}, nil
	case os.Getenv("CALABI_EDGE_CA_FILE") != "":
		return explicitCoordTrust(trust.CA, coordTrustSpec{CAFile: os.Getenv("CALABI_EDGE_CA_FILE")})
	}
	return trust.Config{Mode: trust.System}, nil
}

func explicitCoordTrust(mode trust.Mode, spec coordTrustSpec) (trust.Config, error) {
	cfg := trust.Config{Mode: mode}
	switch mode {
	case trust.Pin:
		if len(spec.Pins) == 0 {
			return trust.Config{}, errors.New("trust pin needs the coordinator's fingerprint (pins: / --pin; the coordinator prints it with `calabi-coord fingerprint`)")
		}
		cfg.Pins = spec.Pins
	case trust.CA:
		if spec.CAFile == "" {
			return trust.Config{}, errors.New("trust ca needs the CA certificate (ca_file: / --ca-file)")
		}
		pem, err := os.ReadFile(spec.CAFile)
		if err != nil {
			return trust.Config{}, fmt.Errorf("trust ca: %w", err)
		}
		cfg.CAPEM = string(pem)
	}
	// Build it once here so a bad pin or an empty CA file is reported when the
	// config is read, not on every reconnect.
	if _, err := cfg.TLS("coordinator"); err != nil {
		return trust.Config{}, err
	}
	return cfg, nil
}

// isPlatformCredential reports whether key is one of calabi.net's: an API key
// (tk_) or a login token (a JWT). A self-hosted coordinator's keys are whatever
// its operator wrote, so this errs toward "self-hosted" for anything else.
func isPlatformCredential(key string) bool {
	return strings.HasPrefix(key, "tk_") || strings.HasPrefix(key, "eyJ")
}
