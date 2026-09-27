// Command vogt is the Vogt broker and its CLI. Milestone M0 ships only the
// commands that exercise the crypto foundations.
package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sort"

	"vogt/internal/envelope"
	"vogt/internal/secmem"
	"vogt/internal/sig"
)

type command struct {
	summary string
	run     func(args []string) error
}

var commands = map[string]command{
	"version":  {"print the version and build info", runVersion},
	"selftest": {"check the crypto primitives on this machine", runSelftest},
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
		os.Exit(2)
	}
	cmd, ok := commands[flag.Arg(0)]
	if !ok {
		fmt.Fprintf(os.Stderr, "vogt: unknown command %q\n\n", flag.Arg(0))
		usage()
		os.Exit(2)
	}
	if err := cmd.run(flag.Args()[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vogt:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vogt <command> [arguments]\n\ncommands:")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-10s %s\n", n, commands[n].summary)
	}
}

func runVersion(args []string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return errors.New("no build info")
	}
	rev := "unknown"
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			rev = s.Value
		}
	}
	fmt.Printf("vogt %s (%s, %s)\n", info.Main.Version, rev, info.GoVersion)
	return nil
}

// runSelftest runs each primitive once, end to end.
func runSelftest(args []string) error {
	if err := secmem.DisableCoreDumps(); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	step := func(name string, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Println("ok  ", name)
		return nil
	}

	dek, err := secmem.New(envelope.DEKSize)
	if err := step("locked memory", err); err != nil {
		return err
	}
	defer dek.Destroy()
	rand.Read(dek.Bytes())

	h := envelope.Header{ID: "selftest", Tier: envelope.TierHigh, KeyVersion: 1}
	rec, err := envelope.SealRecord(dek.Bytes(), h, []byte("secret"))
	if err == nil {
		_, pt, openErr := envelope.OpenRecord(dek.Bytes(), rec, "selftest")
		if openErr == nil && string(pt) != "secret" {
			openErr = errors.New("wrong plaintext")
		}
		err = openErr
	}
	if err := step("AES-256-GCM record", err); err != nil {
		return err
	}

	for _, s := range []struct {
		name  string
		suite envelope.Suite
	}{{"HPKE MLKEM768-P256", envelope.SuiteVault}, {"HPKE X-Wing", envelope.SuiteReply}} {
		sk, err := s.suite.GenerateKey()
		if err == nil {
			var w, pt []byte
			w, err = envelope.Wrap(sk.PublicKey(), "dek", []byte(h.ID), dek.Bytes())
			if err == nil {
				pt, err = envelope.Unwrap(sk, "dek", []byte(h.ID), w)
			}
			if err == nil && !bytes.Equal(pt, dek.Bytes()) {
				err = errors.New("wrong plaintext")
			}
			clear(pt)
		}
		if err := step(s.name, err); err != nil {
			return err
		}
	}

	k, err := sig.GenerateKey()
	if err == nil {
		var s []byte
		if s, err = k.Sign("selftest", []byte("m")); err == nil {
			err = k.Public().Verify("selftest", []byte("m"), s)
		}
	}
	return step("ML-DSA-65 + ECDSA P-256 signature", err)
}
