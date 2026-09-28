package peercred

import "syscall"

// solLocal and localPeerPID are from <sys/un.h>. The standard library has
// no wrapper for LOCAL_PEERCRED's xucred, so on macOS only the PID is read;
// socket directory permissions already limit who can connect.
const (
	solLocal     = 0
	localPeerPID = 2
)

func peer(fd int) (Cred, error) {
	pid, err := syscall.GetsockoptInt(fd, solLocal, localPeerPID)
	if err != nil {
		return Cred{-1, -1}, err
	}
	return Cred{UID: -1, PID: pid}, nil
}
