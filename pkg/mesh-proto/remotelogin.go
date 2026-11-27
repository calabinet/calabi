package meshproto

// RemoteLoginService defines the platform's built-in remote login service.
// Alternate ports are recognized through confirmed declarations of this service.
func RemoteLoginService(os string) (name string, port uint16) {
	switch os {
	case "linux":
		return "ssh", 22
	case "windows":
		return "rdp", 3389
	default:
		return "", 0
	}
}
