//go:build !windows

package main

func verifyRDPCopyBinding(uint16, string) bool { return false }
