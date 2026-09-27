package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"vogt/internal/api"
	"vogt/internal/daemon"
)

func runDaemon(args []string) error {
	fs := newFlags("daemon", "[flags]")
	dev := fs.Bool("dev", false, "run as the current user with state in ~/.vogt-dev (no isolation from agents)")
	state := fs.String("state", "", "state directory (default /var/db/vogt, or ~/.vogt-dev/state with --dev)")
	run := fs.String("run", "", "socket directory (default /var/run/vogt, or ~/.vogt-dev/run with --dev)")
	proxyAddr := fs.String("proxy", "127.0.0.1:7853", "proxy listen address (loopback only)")
	webauthnAddr := fs.String("webauthn", "", "serve the phone approval page on this loopback address, e.g. 127.0.0.1:7854")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *state == "" {
		*state = systemStateDir
		if *dev {
			*state = filepath.Join(devDir(), "state")
		}
	}
	if *run == "" {
		*run = systemRunDir
		if *dev {
			*run = filepath.Join(devDir(), "run")
		}
	}
	if !loopback(*proxyAddr) || (*webauthnAddr != "" && !loopback(*webauthnAddr)) {
		return fmt.Errorf("listen addresses must be loopback")
	}
	if !*dev && os.Geteuid() == 0 {
		return fmt.Errorf("refusing to run as root; run as the dedicated _vogt user (see `vogt install`)")
	}
	syscall.Umask(0o077)

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	d, err := daemon.New(daemon.Config{StateDir: *state, RunDir: *run, ProxyAddr: *proxyAddr, WebAuthnAddr: *webauthnAddr, Logger: log})
	if err != nil {
		return err
	}
	if err := d.Start(api.Handler(d)); err != nil {
		return err
	}
	if *dev {
		log.Warn("development mode: agents running as this user can read and change Vogt's state")
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sigs {
		if s == syscall.SIGHUP {
			if err := d.Reload(); err != nil {
				log.Error("reload failed", "err", err)
			}
			continue
		}
		log.Info("stopping", "signal", s)
		break
	}
	return d.Close()
}

func loopback(addr string) bool {
	host, _, err := splitHostPort(addr)
	return err == nil && (host == "127.0.0.1" || host == "::1" || host == "localhost")
}
