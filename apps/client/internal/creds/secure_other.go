//go:build !windows

package creds

// On unixes the 0o700 / 0o600 modes the callers already pass are honoured by
// the filesystem, so there is nothing extra to do. See secure_windows.go for
// why Windows needs an explicit DACL (audit finding ACL-1).
func secureDataDir(string) error { return nil }
