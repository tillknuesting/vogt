package session

import (
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestCreateLookupEnd(t *testing.T) {
	r := NewRegistry(Limits{})
	tok, s := r.Create("claude")
	got, err := r.Lookup(tok)
	if err != nil || got.ID != s.ID {
		t.Fatalf("Lookup = %v, %v", got, err)
	}
	if _, err := r.Lookup(tok + "x"); !errors.Is(err, ErrUnknown) {
		t.Error("malformed secret accepted")
	}
	r.End(s.ID)
	if _, err := r.Lookup(tok); !errors.Is(err, ErrUnknown) {
		t.Error("ended session still valid")
	}
}

func TestPendingLimits(t *testing.T) {
	r := NewRegistry(Limits{MaxPendingPerSession: 1, MaxPendingTotal: 2})
	_, a := r.Create("a")
	_, b := r.Create("b")
	_, c := r.Create("c")
	if err := r.BeginPending(a); err != nil {
		t.Fatal(err)
	}
	if err := r.BeginPending(a); !errors.Is(err, ErrBusy) {
		t.Errorf("second pending for a: %v", err)
	}
	if err := r.BeginPending(b); err != nil {
		t.Fatal(err)
	}
	if err := r.BeginPending(c); !errors.Is(err, ErrApproverBusy) {
		t.Errorf("third pending overall: %v", err)
	}
	r.EndPending(a, false)
	if err := r.BeginPending(c); err != nil {
		t.Errorf("after a slot freed: %v", err)
	}
	// Ending a session releases its slots.
	r.End(b.ID)
	if err := r.BeginPending(a); err != nil {
		t.Errorf("after b ended: %v", err)
	}
}

func TestLockoutAfterDenials(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r := NewRegistry(Limits{DenialsBeforeLock: 3, DenialWindow: 10 * time.Minute})
		_, s := r.Create("a")
		deny := func() {
			if err := r.BeginPending(s); err != nil {
				t.Fatal(err)
			}
			r.EndPending(s, true)
		}
		deny()
		deny()
		time.Sleep(11 * time.Minute) // the first two fall out of the window
		deny()
		deny()
		if r.Locked(s) {
			t.Fatal("locked with only two denials in the window")
		}
		deny()
		if !r.Locked(s) {
			t.Fatal("not locked after three denials in the window")
		}
		if err := r.BeginPending(s); !errors.Is(err, ErrLocked) {
			t.Fatalf("BeginPending on locked session: %v", err)
		}
		r.Unlock(s.ID)
		if err := r.BeginPending(s); err != nil {
			t.Fatal(err)
		}
	})
}
