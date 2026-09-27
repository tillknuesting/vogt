package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"vogt/internal/daemon"
	"vogt/internal/helperlink"
	"vogt/internal/policy"
	"vogt/internal/sig"
	"vogt/internal/vault"
)

// Admin calls that need a Touch ID tap wait up to this long.
const approvalWait = 3 * time.Minute

func runStatus(args []string) error {
	c := newClient()
	var s daemon.Status
	if err := c.do("GET", "/v1/admin/status", nil, &s, 10*time.Second); err != nil {
		return err
	}
	yes := map[bool]string{true: "yes", false: "no"}
	fmt.Printf("daemon identity   %s\n", s.Identity)
	fmt.Printf("helper paired     %s\n", yes[s.Paired])
	fmt.Printf("helper connected  %s\n", yes[s.HelperConnected])
	if s.PolicyVersion == 0 {
		fmt.Println("policy            none loaded (all requests are refused)")
	} else {
		fmt.Printf("policy            version %d\n", s.PolicyVersion)
	}
	fmt.Printf("sessions          %d\n", s.Sessions)
	fmt.Printf("active grants     %d\n", s.ActiveGrants)
	fmt.Printf("proxy             %s\n", s.ProxyURL)
	return nil
}

func runSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vogt secret add|list|rm ...")
	}
	c := newClient()
	switch args[0] {
	case "list":
		var l []vault.Meta
		if err := c.do("GET", "/v1/admin/secrets", nil, &l, 10*time.Second); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SECRET\tPROVIDER\tTIER\tVERSION\tAGE")
		for _, m := range l {
			tier := map[uint8]string{1: "high", 2: "low"}[uint8(m.Tier)]
			age := time.Since(m.Updated).Round(time.Hour)
			note := ""
			if age > 90*24*time.Hour {
				note = "  (rotate: older than 90 days)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s%s\n", m.ID, m.Provider, tier, m.KeyVersion, humanAge(age), note)
		}
		return tw.Flush()
	case "add":
		fs := newFlags("secret add", "NAME --provider P --tier high|low [--file F]")
		prov := fs.String("provider", "", "provider: static, github, aws, gcp, oauth, postgres")
		tier := fs.String("tier", "high", "high: Touch ID for every grant; low: unlocked once per login")
		file := fs.String("file", "", "read the secret from this file instead of stdin")
		name, rest := splitName(args[1:])
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if name == "" || *prov == "" {
			fs.Usage()
			return errors.New("need a name and --provider")
		}
		var secret []byte
		var err error
		if *file != "" {
			secret, err = os.ReadFile(*file)
		} else {
			if fi, _ := os.Stdin.Stat(); fi != nil && fi.Mode()&os.ModeCharDevice != 0 {
				fmt.Fprintln(os.Stderr, "Paste the secret, then press Ctrl-D:")
			}
			secret, err = io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
		}
		if err != nil {
			return err
		}
		if *prov == "static" {
			secret = []byte(strings.TrimSpace(string(secret)))
		}
		defer clear(secret)
		fmt.Fprintln(os.Stderr, "Approve on the helper (Touch ID)…")
		var m vault.Meta
		err = c.do("POST", "/v1/admin/secrets", map[string]any{"id": name, "provider": *prov, "tier": *tier, "secret": secret}, &m, approvalWait)
		if err != nil {
			return err
		}
		fmt.Printf("stored %s (version %d)\n", m.ID, m.KeyVersion)
		return nil
	case "rm":
		if len(args) != 2 {
			return errors.New("usage: vogt secret rm NAME")
		}
		fmt.Fprintln(os.Stderr, "Approve on the helper (Touch ID)…")
		return c.do("DELETE", "/v1/admin/secrets/"+args[1], nil, nil, approvalWait)
	}
	return fmt.Errorf("unknown secret command %q", args[0])
}

// splitName takes a leading positional argument before flags.
func splitName(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func humanAge(d time.Duration) string {
	if d < 48*time.Hour {
		return d.String()
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func runPolicy(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vogt policy init|load FILE|show")
	}
	c := newClient()
	switch args[0] {
	case "init":
		os.Stdout.Write(policy.Example)
		return nil
	case "show":
		var raw []byte
		if err := c.do("GET", "/v1/admin/policy", nil, &raw, 10*time.Second); err != nil {
			return err
		}
		os.Stdout.Write(raw)
		return nil
	case "load":
		if len(args) != 2 {
			return errors.New("usage: vogt policy load FILE")
		}
		raw, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		if _, err := policy.Parse(raw); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Approve on the helper (Touch ID)…")
		var out struct{ Version uint64 }
		if err := c.do("POST", "/v1/admin/policy", raw, &out, approvalWait); err != nil {
			return err
		}
		fmt.Printf("policy version %d loaded\n", out.Version)
		return nil
	}
	return fmt.Errorf("unknown policy command %q", args[0])
}

func runSession(args []string) error {
	c := newClient()
	if len(args) == 0 || args[0] == "list" {
		var l []struct {
			ID, Name string
			Created  time.Time
		}
		if err := c.do("GET", "/v1/admin/sessions", nil, &l, 10*time.Second); err != nil {
			return err
		}
		for _, s := range l {
			fmt.Printf("%s  %-20s started %s\n", s.ID, s.Name, s.Created.Local().Format("15:04"))
		}
		return nil
	}
	if args[0] == "unlock" && len(args) == 2 {
		fmt.Fprintln(os.Stderr, "Approve on the helper (Touch ID)…")
		return c.do("POST", "/v1/admin/sessions/"+args[1]+"/unlock", nil, nil, approvalWait)
	}
	return errors.New("usage: vogt session [list | unlock ID]")
}

func runAudit(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: vogt audit verify")
	}
	var out struct {
		Entries      int    `json:"entries"`
		Checkpoints  int    `json:"checkpoints"`
		UnsignedTail int    `json:"unsigned_tail"`
		OK           bool   `json:"ok"`
		Error        string `json:"error"`
	}
	if err := newClient().do("GET", "/v1/admin/audit/verify", nil, &out, time.Minute); err != nil {
		return err
	}
	if !out.OK {
		return fmt.Errorf("audit log does NOT verify: %s", out.Error)
	}
	fmt.Printf("audit log verifies: %d entries, %d signed checkpoints, %d entries since the last checkpoint\n", out.Entries, out.Checkpoints, out.UnsignedTail)
	return nil
}

// runPair writes the helper's public keys into the daemon's state. Only
// someone who can write the state directory (root, or the daemon user) can
// pair, so an agent cannot pair a helper of its own.
func runPair(args []string) error {
	fs := newFlags("pair", "[--state DIR] BUNDLE")
	state := fs.String("state", systemStateDir, "the daemon's state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("need the helper's key bundle (from the helper's `keys` command)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(fs.Arg(0)))
	if err != nil {
		return fmt.Errorf("bundle is not base64: %w", err)
	}
	keys, err := helperlink.DecodeHelperKeys(raw)
	if err != nil {
		return err
	}
	idRaw, err := os.ReadFile(filepath.Join(*state, "identity.key"))
	if err != nil {
		return fmt.Errorf("read daemon identity (start the daemon once first; pairing needs root): %w", err)
	}
	id, err := sig.ParsePrivateKey(idRaw)
	clear(idRaw)
	if err != nil {
		return err
	}
	pairing := filepath.Join(*state, "pairing.bin")
	if _, err := os.Stat(pairing); err == nil {
		fmt.Fprintln(os.Stderr, "Replacing the paired helper. Secrets sealed to the old helper can no longer be opened; add them again.")
	}
	if err := vault.WriteFileAtomic(pairing, raw, 0o600); err != nil {
		return err
	}
	hfp := keys.Fingerprint()
	dfp := helperlink.Fingerprint(id.Public().Bytes())
	fmt.Printf("helper fingerprint  %s\n", fingerprintWords(hfp[:]))
	fmt.Printf("daemon fingerprint  %s\n", fingerprintWords(dfp[:]))
	fmt.Println("Confirm the daemon fingerprint on the helper when it asks.")
	if err := newClient().do("POST", "/v1/admin/reload", nil, nil, 10*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "Could not ask the daemon to reload; restart it or send it SIGHUP:", err)
	}
	return nil
}

// fingerprintWords groups a fingerprint for reading aloud.
func fingerprintWords(b []byte) string {
	h := hex.EncodeToString(b[:12])
	var parts []string
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, " ")
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func sha256Short(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:6])
}
