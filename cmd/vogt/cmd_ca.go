package main

import (
	"errors"
	"os"
	"time"
)

// runCA prints the interception CA certificate. Agents that cannot change
// their base URL trust it and use HTTPS_PROXY=http://127.0.0.1:7853 with
// the broker token as the proxy password.
func runCA(args []string) error {
	if len(args) != 1 || args[0] != "export" {
		return errors.New("usage: vogt ca export > vogt-ca.pem")
	}
	var pemBytes []byte
	if err := newClient().do("GET", "/v1/admin/ca", nil, &pemBytes, 10*time.Second); err != nil {
		return err
	}
	_, err := os.Stdout.Write(pemBytes)
	return err
}
