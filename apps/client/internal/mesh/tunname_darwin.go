//go:build darwin

package mesh

// tunName on macOS MUST be "utun" (or "utunN"): the darwin utun driver rejects
// any other name ("Interface name must be utun[0-9]*"). "utun" lets the kernel
// assign the next free unit; the real name comes back from tunDev.Name().
const tunName = "utun"
