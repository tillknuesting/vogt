package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime/debug"

	"vogt/internal/envelope"
	"vogt/internal/secmem"
	"vogt/internal/sig"
)

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
