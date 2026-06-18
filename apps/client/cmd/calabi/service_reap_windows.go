//go:build windows

package main

import "golang.org/x/sys/windows/svc/mgr"

// serviceProcessPID asks the Service Control Manager for the PID of the running
// service process. Returns (0, false) if the service isn't installed, isn't
// running, or can't be queried. Used to reap an orphan that survived uninstall.
func serviceProcessPID(name string) (int, bool) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, false
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return 0, false
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.ProcessId == 0 {
		return 0, false
	}
	return int(st.ProcessId), true
}
