//go:build !darwin

package mesh

// tunName is the mesh interface name on Linux (arbitrary) and Windows (the wintun
// adapter name). macOS overrides this — see tunname_darwin.go.
const tunName = "calabi-mesh"
