package mobile

// CoreVersion and CoreCommit are set by the core build, independently of the app.
var CoreVersion = "dev"
var CoreCommit = "unknown"

// Version returns the version of the loaded Go library.
func Version() string { return CoreVersion }

// SourceCommit returns the public source revision of the loaded Go library.
func SourceCommit() string { return CoreCommit }
