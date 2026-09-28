package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

// runWebAuthn manages passkeys that approve grants from a phone or a
// security key while the Touch ID helper is away.
func runWebAuthn(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vogt webauthn enroll|list|remove ID")
	}
	c := newClient()
	switch args[0] {
	case "enroll":
		fmt.Fprintln(os.Stderr, "Approve on the helper (Touch ID)…")
		var out struct{ URL string }
		if err := c.do("POST", "/v1/admin/webauthn/enroll", nil, &out, approvalWait); err != nil {
			return err
		}
		fmt.Println("Open this page within 5 minutes and create the passkey:")
		fmt.Println(out.URL)
		return nil
	case "list":
		var l []struct{ ID, Name string }
		if err := c.do("GET", "/v1/admin/webauthn", nil, &l, 10*time.Second); err != nil {
			return err
		}
		for _, p := range l {
			fmt.Printf("%s  %s\n", p.ID, p.Name)
		}
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: vogt webauthn remove ID")
		}
		return c.do("DELETE", "/v1/admin/webauthn/"+args[1], nil, nil, 10*time.Second)
	}
	return fmt.Errorf("unknown webauthn command %q", args[0])
}
