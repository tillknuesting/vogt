package install

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestDarwinPlan(t *testing.T) {
	steps, err := Plan(Options{GOOS: "darwin", HumanUser: "till"})
	if err != nil {
		t.Fatal(err)
	}
	var daemon, agent []byte
	for _, s := range steps {
		switch {
		case strings.HasSuffix(s.Path, "dev.vogt.daemon.plist"):
			daemon = s.Content
		case strings.HasSuffix(s.Path, "dev.vogt.helper.plist"):
			agent = s.Content
		}
	}
	for name, b := range map[string][]byte{"daemon": daemon, "agent": agent} {
		if err := xml.Unmarshal(b, new(struct{})); err != nil {
			t.Errorf("%s plist is not XML: %v", name, err)
		}
	}
	s := string(daemon)
	for _, want := range []string{"<string>_vogt</string>", "/var/db/vogt", "<key>Core</key><integer>0</integer>"} {
		if !strings.Contains(s, want) {
			t.Errorf("daemon plist lacks %q", want)
		}
	}
}

func TestLinuxUnitIsSandboxed(t *testing.T) {
	steps, err := Plan(Options{GOOS: "linux", HumanUser: "till"})
	if err != nil {
		t.Fatal(err)
	}
	var unit string
	for _, s := range steps {
		if strings.HasSuffix(s.Path, "vogt.service") {
			unit = string(s.Content)
		}
	}
	for _, want := range []string{"User=vogt", "NoNewPrivileges=yes", "ProtectHome=yes", "LimitCORE=0", "RuntimeDirectoryMode=0750"} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit lacks %q", want)
		}
	}
}

func TestRefusesRootAsHuman(t *testing.T) {
	if _, err := Plan(Options{GOOS: "darwin", HumanUser: "root"}); err == nil {
		t.Fatal("accepted root as the human's account")
	}
}
