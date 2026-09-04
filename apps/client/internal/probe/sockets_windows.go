//go:build windows

package probe

// Windows socket enumeration via iphlpapi!GetExtendedTcpTable.
//
// We ask for the TCP_TABLE_OWNER_PID_LISTENER class (listeners only) for both
// address families and ignore the owning PID it carries. Listing the table is
// unprivileged — the elevation the package comment worries about is only needed
// to resolve another process's details, which we never do. There is no BASIC
// listener class for IPv6, so OWNER_PID is the one class that works uniformly
// for v4 and v6.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPidListener = 3 // TCP_TABLE_OWNER_PID_LISTENER
	mibTCPStateListen        = 2 // MIB_TCP_STATE_LISTEN

	// MIB_TCPROW_OWNER_PID: 6 DWORDs — state, localAddr, localPort, remoteAddr,
	// remotePort, owningPid.
	rowSizeV4 = 24
	// MIB_TCP6ROW_OWNER_PID: localAddr[16], localScopeId, localPort,
	// remoteAddr[16], remoteScopeId, remotePort, state, owningPid.
	rowSizeV6 = 56
)

// listenerSockets returns the LISTENing TCP sockets across both families. A v6
// failure is tolerated (return what v4 found); a v4 failure aborts so Scan falls
// back to dialing rather than showing a half-empty list as if it were complete.
func listenerSockets() ([]listener, error) {
	v4, err := tcpListeners(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	if v6, err := tcpListeners(windows.AF_INET6); err == nil {
		v4 = append(v4, v6...)
	}
	return v4, nil
}

func tcpListeners(af uint32) ([]listener, error) {
	// First call sizes the buffer (pTcpTable == nil).
	var size uint32
	procGetExtendedTcpTable.Call(
		0, uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), uintptr(tcpTableOwnerPidListener), 0,
	)
	if size == 0 {
		return nil, nil // nothing listening in this family
	}

	buf := make([]byte, size)
	r0, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0,
		uintptr(af), uintptr(tcpTableOwnerPidListener), 0,
	)
	if r0 != 0 {
		return nil, fmt.Errorf("probe: GetExtendedTcpTable(af=%d) failed: %d", af, r0)
	}

	n := binary.LittleEndian.Uint32(buf[:4]) // dwNumEntries; rows follow at [4:]
	rowSize, base := rowSizeV4, 4
	if af == windows.AF_INET6 {
		rowSize = rowSizeV6
	}

	out := make([]listener, 0, n)
	for i := uint32(0); i < n; i++ {
		off := base + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := buf[off : off+rowSize]
		if af == windows.AF_INET {
			if binary.LittleEndian.Uint32(row[0:4]) != mibTCPStateListen {
				continue
			}
			// dwLocalAddr is the in_addr's raw network-order bytes.
			ip := netip.AddrFrom4([4]byte{row[4], row[5], row[6], row[7]})
			out = append(out, listener{ip: ip, port: portFromField(binary.LittleEndian.Uint32(row[8:12]))})
		} else {
			// State is the 7th DWORD in the v6 row; local port the 6th byte-group.
			if binary.LittleEndian.Uint32(row[48:52]) != mibTCPStateListen {
				continue
			}
			var b [16]byte
			copy(b[:], row[0:16])
			out = append(out, listener{ip: netip.AddrFrom16(b), port: portFromField(binary.LittleEndian.Uint32(row[20:24]))})
		}
	}
	return out, nil
}

// portFromField pulls the port out of a dwLocalPort field. The port sits in the
// low two bytes in network byte order, so we swap them to host order.
func portFromField(d uint32) int {
	return int((d&0xff)<<8 | (d&0xff00)>>8)
}
