//go:build !windows && !darwin

package main

import "errors"

func pickTransferFiles(uint64) ([]string, error) {
	return nil, errors.New("native file picker is not available on this platform yet")
}
func pickTransferDestination(string, uint64) (string, error) {
	return "", errors.New("native file picker is not available on this platform yet")
}
