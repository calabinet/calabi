package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	copyChannelLock  sync.Mutex
	copyChannelOpen  = fileAgentWTS.NewProc("WTSVirtualChannelOpenEx")
	copyChannelClose = fileAgentWTS.NewProc("WTSVirtualChannelClose")
	copyChannelRead  = fileAgentWTS.NewProc("WTSVirtualChannelRead")
	copyChannelWrite = fileAgentWTS.NewProc("WTSVirtualChannelWrite")
)

// The WTS channel belongs to the Windows logon running this agent.
// The remote helper proves it holds the key presented by the mTLS peer.
func verifyRDPCopyBinding(port uint16, token string) bool {
	if port == 0 || len(token) != 64 || !copyChannelLock.TryLock() {
		return false
	}
	defer copyChannelLock.Unlock()
	var session uint32
	if windows.ProcessIdToSessionId(uint32(os.Getpid()), &session) != nil || session == 0 || !fileAgentSessionActive(session) {
		return false
	}
	name := [...]byte{'c', 'a', 'l', 'b', 'i', 'n', 'd', 0}
	channel, _, _ := copyChannelOpen.Call(uintptr(session), uintptr(unsafe.Pointer(&name[0])), 0)
	if channel == 0 {
		return false
	}
	defer copyChannelClose.Call(channel)

	var challenge [sha256.Size + 2]byte
	if _, err := rand.Read(challenge[:sha256.Size]); err != nil {
		return false
	}
	binary.BigEndian.PutUint16(challenge[sha256.Size:], port)
	var written uint32
	ok, _, _ := copyChannelWrite.Call(channel, uintptr(unsafe.Pointer(&challenge[0])), uintptr(len(challenge)), uintptr(unsafe.Pointer(&written)))
	if ok == 0 || written != uint32(len(challenge)) {
		return false
	}
	want := hmac.New(sha256.New, []byte(token))
	want.Write(challenge[:])
	var reply [sha256.Size]byte
	var chunk [1600]byte
	deadline := time.Now().Add(2 * time.Second)
	for offset := 0; offset < len(reply) && time.Now().Before(deadline); {
		var size uint32
		ok, _, err := copyChannelRead.Call(channel, 100, uintptr(unsafe.Pointer(&chunk[0])), uintptr(len(chunk)), uintptr(unsafe.Pointer(&size)))
		if ok == 0 {
			if err != windows.ERROR_IO_INCOMPLETE && err != windows.ERROR_TIMEOUT && err != windows.WAIT_TIMEOUT {
				return false
			}
			continue
		}
		if int(size) > len(reply)-offset {
			return false
		}
		offset += copy(reply[offset:], chunk[:size])
		if offset == len(reply) {
			return hmac.Equal(reply[:], want.Sum(nil))
		}
	}
	return false
}
