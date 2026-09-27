package policy

import (
	"strings"
	"testing"
	"time"
)

func TestExampleParses(t *testing.T) {
	p, err := Parse(Example)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Capabilities) == 0 || len(p.Rules) == 0 {
		t.Fatal("example is empty")
	}
	for name, c := range p.Capabilities {
		if err := p.CheckForbidden(c.Permissions); err != nil {
			t.Errorf("example capability %s: %v", name, err)
		}
	}
}

func TestDecide(t *testing.T) {
	p, _ := Parse(Example)
	if r := p.Decide("github.repo.read", "tillknuesting/vogt"); r.Decision != Allow {
		t.Errorf("read = %s", r.Decision)
	}
	if r := p.Decide("github.repo.push", "tillknuesting/vogt"); r.Decision != Ask || len(r.DenyRefs) == 0 {
		t.Errorf("push = %+v", r)
	}
	if r := p.Decide("github.repo.read", "someone/else"); r.Decision != Ask {
		t.Errorf("other owner = %s", r.Decision)
	}
	if r := p.Decide("cloud.admin", "x"); r.Decision != Deny {
		t.Errorf("admin = %s", r.Decision)
	}
	if r := p.Decide("unknown", "x"); r.Decision != Ask || time.Duration(r.MaxTTL) != 10*time.Minute {
		t.Errorf("default = %+v", r)
	}
}

func TestForbidden(t *testing.T) {
	p := &Policy{Forbidden: []string{"iam:*", "sts:AssumeRole", "github:workflows=write"}}
	for _, bad := range [][]string{{"iam:CreateUser"}, {"IAM:PassRole"}, {"*"}, {"sts:*"}, {"github:workflows=write"}} {
		if p.CheckForbidden(bad) == nil {
			t.Errorf("%v allowed", bad)
		}
	}
	if err := p.CheckForbidden([]string{"s3:GetObject", "github:contents=write"}); err != nil {
		t.Error(err)
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"aws.*", "aws.s3.read", true}, {"aws.*", "gcp.x", false},
		{"*.admin", "cloud.admin", true}, {"a*b*c", "axxbyyc", true}, {"a*b*c", "axxbyy", false},
		{"tillknuesting/*", "tillknuesting/vogt", true},
	}
	for _, c := range cases {
		if got := Match(c.p, c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func TestPermits(t *testing.T) {
	c := Capability{Allow: []ProxyRule{
		{Methods: []string{"GET"}, Path: "/api/repos/{target}/**"},
		{Methods: []string{"POST"}, Path: "/git/{target}.git/git-upload-pack"},
	}}
	cases := []struct {
		m, path string
		want    bool
	}{
		{"GET", "/api/repos/o/r/pulls", true},
		{"POST", "/api/repos/o/r/pulls", false},
		{"GET", "/api/repos/o/other/pulls", false},
		{"POST", "/git/o/r.git/git-upload-pack", true},
		{"POST", "/git/o/r.git/git-receive-pack", false},
	}
	for _, x := range cases {
		if got := c.Permits(x.m, x.path, "o/r"); got != x.want {
			t.Errorf("%s %s = %v", x.m, x.path, got)
		}
	}
	if MatchPath("/a/*/c", "/a/b/x/c") {
		t.Error("* crossed a slash")
	}
}

func TestRejects(t *testing.T) {
	bad := []string{
		`{"version":0}`,
		`{"version":1,"rules":[{"capability":"x","decision":"maybe"}]}`,
		`{"version":1,"rules":[{"capability":"x","decision":"ask","max_ttl":"2h"}]}`,
		`{"version":1,"unknown":1}`,
		`{"version":1,"capabilities":{"x":{"provider":"static","secret":"s","route":"Bad Route","display":"d"}}}`,
		`{"version":1} {"version":2}`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		} else if !strings.HasPrefix(err.Error(), "policy:") {
			t.Errorf("error lacks prefix: %v", err)
		}
	}
}
