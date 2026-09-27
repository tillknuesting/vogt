package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"vogt/internal/grants"
	"vogt/internal/policy"
)

var splitHostPort = net.SplitHostPort

func runRun(args []string) error {
	fs := newFlags("run", "[--name NAME] -- command [args...]")
	name := fs.String("name", "", "session name shown on approvals (default: the command name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		fs.Usage()
		return errors.New("no command")
	}
	if *name == "" {
		*name = filepath.Base(cmdArgs[0])
	}
	c := newClient()
	var s struct{ ID, Secret string }
	if err := c.do("POST", "/v1/sessions", map[string]string{"name": *name}, &s, 10*time.Second); err != nil {
		return err
	}
	c.session = s.Secret
	defer c.do("DELETE", "/v1/sessions/self", nil, nil, 10*time.Second)

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "VOGT_SESSION="+s.Secret, "VOGT_SOCKET="+c.socket)
	fmt.Fprintf(os.Stderr, "vogt: session %s started for %s\n", s.ID[:8], *name)
	return runChild(cmd)
}

// runChild runs cmd, forwarding interrupts, and returns its exit status.
func runChild(cmd *exec.Cmd) error {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return exitError(ee.ExitCode())
	}
	return err
}

type grantFlags struct {
	ttl    *string
	reason *string
	mode   string
}

func addGrantFlags(fs interface {
	String(string, string, string) *string
}) grantFlags {
	return grantFlags{
		ttl:    fs.String("ttl", "", "how long the grant lasts, e.g. 10m (default: the policy's limit, at most 10m)"),
		reason: fs.String("reason", "", "why, shown to the human as the agent's unverified claim"),
	}
}

// requestAndWait asks for a grant and waits for the human's decision.
func requestAndWait(c *client, capability, target string, gf grantFlags, command []string) (grants.View, error) {
	var v grants.View
	if err := c.needSession(); err != nil {
		return v, err
	}
	req := map[string]any{"capability": capability, "target": target, "ttl": *gf.ttl, "reason": *gf.reason, "mode": gf.mode, "command": command}
	var created struct{ ID string }
	if err := c.do("POST", "/v1/grants", req, &created, 10*time.Second); err != nil {
		return v, err
	}
	shown := target
	if shown == "" {
		shown = "default"
	}
	fmt.Fprintf(os.Stderr, "vogt: waiting for approval of %s on %s (grant %s)\n", capability, shown, created.ID[:8])
	for {
		if err := c.do("GET", "/v1/grants/"+created.ID+"?wait=60s", nil, &v, 90*time.Second); err != nil {
			return v, err
		}
		if v.State != grants.Pending {
			break
		}
	}
	if v.State != grants.Active {
		return v, fmt.Errorf("grant %s: %s", v.State, v.EndReason)
	}
	if v.Delivery == nil {
		return v, errors.New("grant is active but its credential was already collected")
	}
	return v, nil
}

func runGrant(args []string) error {
	fs := newFlags("grant", "[flags] CAPABILITY [TARGET]")
	gf := addGrantFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		fs.Usage()
		return errors.New("need a capability and an optional target")
	}
	target := fs.Arg(1)
	gf.mode = string(policy.ModeProxy)
	v, err := requestAndWait(newClient(), fs.Arg(0), target, gf, nil)
	if err != nil {
		return err
	}
	fmt.Printf("# vogt grant %s: %s until %s\n", v.ID, v.Capability, v.NotAfter.Local().Format("15:04:05"))
	fmt.Printf("# base URL: %s\n", v.Delivery.ProxyURL)
	fmt.Printf("export VOGT_GRANT=%s\n", shellQuote(v.ID))
	fmt.Printf("export VOGT_TOKEN=%s\n", shellQuote(v.Delivery.Token))
	for _, kv := range v.Delivery.Env {
		k, val, _ := strings.Cut(kv, "=")
		fmt.Printf("export %s=%s\n", k, shellQuote(val))
	}
	return nil
}

func runExec(args []string) error {
	fs := newFlags("exec", "[flags] CAPABILITY TARGET -- command [args...]")
	gf := addGrantFlags(fs)
	direct := fs.Bool("direct", false, "hand the credential itself to the command (the agent can read it)")
	reveal := fs.Bool("reveal", false, "hand the raw static key to the command (only if the policy allows)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 3 {
		fs.Usage()
		return errors.New("need CAPABILITY TARGET -- command")
	}
	capability, target, cmdArgs := rest[0], rest[1], rest[2:]
	if cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}
	if len(cmdArgs) == 0 {
		return errors.New("no command")
	}
	gf.mode = string(policy.ModeProxy)
	if *direct {
		gf.mode = string(policy.ModeDirect)
	}
	if *reveal {
		gf.mode = string(policy.ModeReveal)
	}
	c := newClient()
	var command []string
	if gf.mode != string(policy.ModeProxy) {
		command = cmdArgs
	}
	v, err := requestAndWait(c, capability, target, gf, command)
	if err != nil {
		return err
	}
	defer c.do("DELETE", "/v1/grants/"+v.ID, nil, nil, 30*time.Second)

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if gf.mode == string(policy.ModeProxy) {
		cmd.Env = append(os.Environ(), "VOGT_GRANT="+v.ID, "VOGT_TOKEN="+v.Delivery.Token)
		cmd.Env = append(cmd.Env, v.Delivery.Env...)
	} else {
		// The credential is real: give the child as little else as possible.
		cmd.Env = scrubbedEnv()
		cmd.Env = append(cmd.Env, v.Delivery.Env...)
	}
	return runChild(cmd)
}

func scrubbedEnv() []string {
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"}
	for _, k := range []string{"HOME", "USER", "LOGNAME", "TERM", "LANG", "TMPDIR"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func runGrants(args []string) error {
	fs := newFlags("grants", "[--all]")
	all := fs.Bool("all", false, "list every session's grants")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := newClient()
	var list []grants.View
	path := "/v1/grants"
	if *all || c.session == "" {
		path = "/v1/admin/grants"
	}
	if err := c.do("GET", path, nil, &list, 10*time.Second); err != nil {
		return err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "GRANT\tSTATE\tCAPABILITY\tTARGET\tMODE\tENDS")
	for _, g := range list {
		ends := ""
		if !g.NotAfter.IsZero() {
			ends = g.NotAfter.Local().Format("15:04:05")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID[:8], g.State, g.Capability, g.Target, g.Mode, ends)
	}
	return tw.Flush()
}

func runRevoke(args []string) error {
	fs := newFlags("revoke", "GRANT-ID | --all")
	all := fs.Bool("all", false, "end every grant and bundle now (the kill switch)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	c := newClient()
	if *all {
		var out struct{ Revoked int }
		if err := c.do("POST", "/v1/admin/revoke-all", nil, &out, 60*time.Second); err != nil {
			return err
		}
		fmt.Printf("revoked %d grants\n", out.Revoked)
		return nil
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("need a grant ID or --all")
	}
	id := fs.Arg(0)
	if len(id) < 36 {
		// Accept the short IDs `vogt grants` prints.
		var list []grants.View
		if err := c.do("GET", "/v1/admin/grants", nil, &list, 10*time.Second); err != nil {
			return err
		}
		var match []string
		for _, g := range list {
			if strings.HasPrefix(g.ID, id) {
				match = append(match, g.ID)
			}
		}
		if len(match) != 1 {
			return fmt.Errorf("%q matches %d grants", id, len(match))
		}
		id = match[0]
	}
	return c.do("POST", "/v1/admin/grants/"+id+"/revoke", nil, nil, 60*time.Second)
}
