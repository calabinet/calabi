//go:build !windows && !unix

package filetransfer

import "os"

func openLocalSource(path string) (*os.File, error) { return os.Open(path) }

func localFileIdentity(*os.File, os.FileInfo) (string, error) { return "", errLocalSource }
