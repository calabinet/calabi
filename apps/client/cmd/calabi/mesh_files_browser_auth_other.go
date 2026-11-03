//go:build !linux

package main

import (
	"context"
	"errors"
)

func startBrowserAuth(context.Context, string, string, *browserAuth) (func(), error) {
	return nil, errors.New("browser file management requires Linux")
}
func standaloneBrowserURL() (string, error) {
	return "", errors.New("browser file management requires Linux")
}
