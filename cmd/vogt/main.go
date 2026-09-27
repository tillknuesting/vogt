// Command vogt is the Vogt broker and its command-line client.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
)

type command struct {
	group   string
	summary string
	run     func(args []string) error
}

var commands map[string]command

func init() {
	commands = map[string]command{
		"daemon":     {"broker", "run the broker daemon", runDaemon},
		"run":        {"agent", "run an agent in a new session: vogt run -- claude", runRun},
		"grant":      {"agent", "request a grant and print its environment", runGrant},
		"exec":       {"agent", "request a grant, run a command with it, then surrender it", runExec},
		"grants":     {"agent", "list grants (--all for every session)", runGrants},
		"revoke":     {"admin", "end a grant, or every grant with --all", runRevoke},
		"status":     {"admin", "show the daemon's state", runStatus},
		"secret":     {"admin", "add, list or remove master secrets", runSecret},
		"policy":     {"admin", "print an example policy, load one, or show the current one", runPolicy},
		"session":    {"admin", "list sessions or unlock a locked one", runSession},
		"audit":      {"admin", "verify the audit log", runAudit},
		"pair":       {"admin", "pair the daemon with an approval helper (needs root)", runPair},
		"helper-dev": {"helper", "software approval helper for tests and Linux (no hardware protection)", runHelperDev},
		"mcp":        {"agent", "serve Vogt's tools to an MCP client over stdio", runMCP},
		"install":    {"admin", "print or apply the service installation (launchd, systemd)", runInstall},
		"ca":         {"admin", "export the TLS-interception CA certificate", runCA},
		"webauthn":   {"admin", "enroll a passkey or security key for phone approvals", runWebAuthn},
		"version":    {"", "print the version", runVersion},
		"selftest":   {"", "check the crypto primitives on this machine", runSelftest},
	}
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
		var ee exitError
		if errors.As(err, &ee) {
			os.Exit(int(ee))
		}
		fmt.Fprintln(os.Stderr, "vogt:", err)
		os.Exit(1)
	}
}

// exitError carries a child process's exit code through main.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vogt <command> [arguments]")
	groups := map[string][]string{}
	for n, c := range commands {
		groups[c.group] = append(groups[c.group], n)
	}
	for _, g := range []string{"agent", "admin", "broker", "helper", ""} {
		names := groups[g]
		sort.Strings(names)
		title := map[string]string{"agent": "agents", "admin": "the human", "broker": "the broker", "helper": "the helper", "": "other"}[g]
		fmt.Fprintf(os.Stderr, "\nfor %s:\n", title)
		for _, n := range names {
			fmt.Fprintf(os.Stderr, "  %-11s %s\n", n, commands[n].summary)
		}
	}
	fmt.Fprintln(os.Stderr, "\nRun `vogt <command> -h` for a command's flags.")
}

func newFlags(name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet("vogt "+name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: vogt %s %s\n", name, usage)
		fs.PrintDefaults()
	}
	return fs
}
