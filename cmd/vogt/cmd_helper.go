package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vogt/internal/helperlink"
	"vogt/internal/softhelper"
)

// runHelperDev is the software approval helper. It is for tests, CI and
// Linux development: its keys sit in a file, not in hardware.
func runHelperDev(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vogt helper-dev init|keys|run [flags]")
	}
	fs := newFlags("helper-dev "+args[0], "[flags]")
	keysPath := fs.String("keys", filepath.Join(devDir(), "helper.keys"), "key file")
	run := fs.String("run", "", "the daemon's socket directory (default: system, then ~/.vogt-dev/run)")
	auto := fs.Bool("insecure-auto-approve", false, "approve everything without asking (tests only)")
	trust := fs.Bool("insecure-trust-first", false, "pin the daemon on first connection without asking (tests only)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	switch args[0] {
	case "init":
		if _, err := os.Stat(*keysPath); err == nil {
			return fmt.Errorf("%s exists; remove it to make new keys", *keysPath)
		}
		k, err := softhelper.Generate()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(*keysPath), 0o700); err != nil {
			return err
		}
		if err := k.Save(*keysPath); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Keys written. Pair them with the daemon:")
		fmt.Printf("vogt pair %s\n", base64.StdEncoding.EncodeToString(k.Public().Encode()))
		return nil
	case "keys":
		k, err := softhelper.Load(*keysPath)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k.Public().Encode()))
		return nil
	case "run":
		k, err := softhelper.Load(*keysPath)
		if err != nil {
			return err
		}
		sock := helperSocket(*run)
		var approver helperlink.Approver = &softhelper.Terminal{}
		if *auto {
			approver = &softhelper.Auto{Yes: true}
			fmt.Fprintln(os.Stderr, "WARNING: approving every request without asking")
		}
		cl := &helperlink.Client{
			Keyring: k, Approver: approver, DaemonPin: k.DaemonPin,
			TrustFirst: func(fp [32]byte) bool {
				if *trust {
					return true
				}
				fmt.Fprintf(os.Stderr, "First connection. Daemon fingerprint: %s\nDoes this match `vogt pair`? [y/N] ", fingerprintWords(fp[:]))
				tty, err := os.Open("/dev/tty")
				if err != nil {
					return false
				}
				defer tty.Close()
				line, _ := bufio.NewReader(tty).ReadString('\n')
				return strings.TrimSpace(strings.ToLower(line)) == "y"
			},
			OnPin: func(fp [32]byte) {
				k.DaemonPin = &fp
				if err := k.Save(*keysPath); err != nil {
					fmt.Fprintln(os.Stderr, "could not save the daemon pin:", err)
				}
			},
		}
		backoff := time.Second
		for {
			c, err := net.Dial("unix", sock)
			if err == nil {
				fmt.Fprintln(os.Stderr, "connected to", sock)
				backoff = time.Second
				err = cl.Serve(c)
				if errors.Is(err, helperlink.ErrWrongDaemon) {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "helper disconnected (%v); retrying in %v\n", err, backoff)
			time.Sleep(backoff)
			backoff = min(backoff*2, 30*time.Second)
		}
	}
	return fmt.Errorf("unknown helper-dev command %q", args[0])
}

func helperSocket(run string) string {
	if run != "" {
		return filepath.Join(run, "helper.sock")
	}
	sys := filepath.Join(systemRunDir, "helper.sock")
	if _, err := os.Stat(sys); err == nil {
		return sys
	}
	return filepath.Join(devDir(), "run", "helper.sock")
}
