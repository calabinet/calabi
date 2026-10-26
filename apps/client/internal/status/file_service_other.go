//go:build !linux

package status

import "net/http"

func fileServiceRoutes(*http.ServeMux) {}
