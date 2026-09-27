package grants

import (
	"context"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"
)

func TestLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := NewStore()
		expired := make(chan *Grant, 1)
		s.OnExpire = func(g *Grant) { expired <- g }

		g := &Grant{ID: "g1", Session: "s1", TokenHash: [32]byte{7}, NotAfter: time.Now().Add(10 * time.Minute)}
		s.Add(g)
		if _, ok := s.ByToken(g.TokenHash); ok {
			t.Fatal("pending grant usable by token")
		}
		if err := s.Activate(g, &Delivery{Token: "tok"}); err != nil {
			t.Fatal(err)
		}
		if got, ok := s.ByToken(g.TokenHash); !ok || got != g {
			t.Fatal("active grant not found by token")
		}
		if v := s.View(g, true); v.Delivery == nil || v.Delivery.Token != "tok" {
			t.Fatal("first view lacks the delivery")
		}
		if v := s.View(g, true); v.Delivery != nil {
			t.Fatal("delivery handed out twice")
		}

		time.Sleep(10*time.Minute + time.Second)
		select {
		case got := <-expired:
			if got != g {
				t.Fatal("wrong grant expired")
			}
		default:
			t.Fatal("grant did not expire")
		}
		if !s.End(g, Expired, "ttl") {
			t.Fatal("End reported the grant was not active")
		}
		if _, ok := s.ByToken(g.TokenHash); ok {
			t.Fatal("expired grant still usable")
		}
	})
}

func TestDenyWakesWaiter(t *testing.T) {
	s := NewStore()
	g := &Grant{ID: "g"}
	s.Add(g)
	go s.Deny(g, "human said no")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Wait(ctx, g)
	if g.State != Denied {
		t.Fatalf("state = %s", g.State)
	}
}

func TestDigestCoversCommand(t *testing.T) {
	a := &Grant{ID: "g", Command: []string{"git", "push"}}
	b := &Grant{ID: "g", Command: []string{"sh", "-c", "env"}}
	a.ComputeDigest()
	b.ComputeDigest()
	if a.Digest == b.Digest {
		t.Fatal("digest ignores the command")
	}
}

func TestJournalRecover(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(filepath.Join(dir, "j"), filepath.Join(dir, "k"))
	if err != nil {
		t.Fatal(err)
	}
	j.Start("a", "github", []byte("ghs_secret"))
	j.Start("b", "static", nil)
	j.End("b")
	j.Start("c", "postgres", []byte("vogt_c"))

	j2, _ := OpenJournal(filepath.Join(dir, "j"), filepath.Join(dir, "k"))
	left, err := j2.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 || left[0].ID != "a" || string(left[0].Handle) != "ghs_secret" || left[1].ID != "c" {
		t.Fatalf("leftovers = %+v", left)
	}
	if left, _ := j2.Recover(); len(left) != 0 {
		t.Fatal("journal not cleared after recovery")
	}
}
