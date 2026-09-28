package peercred

import "syscall"

func peer(fd int) (Cred, error) {
	u, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return Cred{-1, -1}, err
	}
	return Cred{UID: int(u.Uid), PID: int(u.Pid)}, nil
}
