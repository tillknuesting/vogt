// Package peercred reads who is on the other end of a Unix socket. The
// kernel fills these values in; the caller cannot forge them.
package peercred

import (
	"context"
	"net"
)

// Cred identifies a socket peer. Fields the OS does not report are -1.
type Cred struct {
	UID, PID int
}

// Of returns the credentials of a Unix socket connection's peer.
func Of(c net.Conn) (Cred, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return Cred{-1, -1}, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return Cred{-1, -1}, false
	}
	var cred Cred
	var gerr error
	if err := raw.Control(func(fd uintptr) { cred, gerr = peer(int(fd)) }); err != nil || gerr != nil {
		return Cred{-1, -1}, false
	}
	return cred, true
}

type ctxKey struct{}

// NewContext stores a connection's peer credentials in ctx.
func NewContext(ctx context.Context, c net.Conn) context.Context {
	cred, _ := Of(c)
	return context.WithValue(ctx, ctxKey{}, cred)
}

// FromContext returns the peer credentials NewContext stored.
func FromContext(ctx context.Context) Cred {
	if c, ok := ctx.Value(ctxKey{}).(Cred); ok {
		return c
	}
	return Cred{-1, -1}
}
