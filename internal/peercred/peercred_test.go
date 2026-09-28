package peercred

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnProcess(t *testing.T) {
	dir, _ := os.MkdirTemp("", "pc")
	defer os.RemoveAll(dir)
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, _ := net.Dial("unix", filepath.Join(dir, "s"))
		if c != nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cred, ok := Of(c)
	if !ok || cred.PID != os.Getpid() {
		t.Fatalf("cred = %+v, ok = %v, want pid %d", cred, ok, os.Getpid())
	}
	if cred.UID != -1 && cred.UID != os.Getuid() {
		t.Fatalf("uid = %d", cred.UID)
	}
}
