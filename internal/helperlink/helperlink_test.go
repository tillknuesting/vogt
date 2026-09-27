package helperlink_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vogt/internal/envelope"
	"vogt/internal/helperlink"
	"vogt/internal/sig"
	"vogt/internal/softhelper"
	"vogt/internal/vault"
)

type rig struct {
	server   *helperlink.Server
	client   *helperlink.Client
	keys     *softhelper.Keys
	approver *softhelper.Auto
	identity *sig.PrivateKey
}

func setup(t *testing.T) *rig {
	t.Helper()
	identity, _ := sig.GenerateKey()
	keys, err := softhelper.Generate()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{identity: identity, keys: keys, approver: &softhelper.Auto{Yes: true}}
	r.server = helperlink.NewServer(identity, keys.Public())
	connected := make(chan bool, 4)
	r.server.OnConnect = func(ok bool) { connected <- ok }

	sock := shortSock(t)
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go r.server.Serve(l)

	fp := helperlink.Fingerprint(identity.Public().Bytes())
	r.client = &helperlink.Client{Keyring: keys, Approver: r.approver, DaemonPin: &fp}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go r.client.Serve(c)
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not connect")
	}
	return r
}

func wrapDEK(t *testing.T, k *softhelper.Keys, tier envelope.Tier, id string) (helperlink.DEKRequest, []byte) {
	dek := make([]byte, 32)
	rand.Read(dek)
	pub := k.High.PublicKey()
	if tier == envelope.TierLow {
		pub = k.Low.PublicKey()
	}
	aad := vault.WrapAAD(id, 1)
	w, err := envelope.Wrap(pub, vault.WrapPurpose, aad, dek)
	if err != nil {
		t.Fatal(err)
	}
	return helperlink.DEKRequest{Tier: tier, Wrapped: w, AAD: aad}, dek
}

func TestApprovedGrantReturnsDEKs(t *testing.T) {
	r := setup(t)
	req, dek := wrapDEK(t, r.keys, envelope.TierHigh, "github-write")
	res, err := r.server.Ask(context.Background(), helperlink.Challenge{
		Kind: helperlink.KindGrant, Display: "PUSH to github.com/o/r", DEKs: []helperlink.DEKRequest{req},
	}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Destroy()
	if !res.Approved || len(res.DEKs) != 1 || !bytes.Equal(res.DEKs[0].Bytes(), dek) {
		t.Fatalf("result = %+v", res)
	}
	if err := r.keys.Approval.Public().Verify(helperlink.PurposeApproval, res.ApprovalMessage, res.ApprovalSig); err != nil {
		t.Fatal("approval evidence does not verify:", err)
	}
	if got := r.approver.Challenges(); len(got) != 1 || got[0].Display != "PUSH to github.com/o/r" {
		t.Fatalf("helper saw %+v", got)
	}
}

func TestDenied(t *testing.T) {
	r := setup(t)
	r.approver.Yes = false
	req, _ := wrapDEK(t, r.keys, envelope.TierHigh, "x")
	res, err := r.server.Ask(context.Background(), helperlink.Challenge{Kind: helperlink.KindGrant, DEKs: []helperlink.DEKRequest{req}}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Approved || len(res.DEKs) != 0 {
		t.Fatal("denial returned approval or DEKs")
	}
}

func TestUnwrapNeedsNoTapButOnlyLowTier(t *testing.T) {
	r := setup(t)
	low, dek := wrapDEK(t, r.keys, envelope.TierLow, "read")
	res, err := r.server.Ask(context.Background(), helperlink.Challenge{Kind: helperlink.KindUnwrap, DEKs: []helperlink.DEKRequest{low}}, 5*time.Second)
	if err != nil || !res.Approved || !bytes.Equal(res.DEKs[0].Bytes(), dek) {
		t.Fatalf("unwrap: %+v %v", res, err)
	}
	if n := len(r.approver.Challenges()); n != 0 {
		t.Fatalf("unwrap asked the human %d times", n)
	}
	high, _ := wrapDEK(t, r.keys, envelope.TierHigh, "write")
	if _, err := r.server.Ask(context.Background(), helperlink.Challenge{Kind: helperlink.KindUnwrap, DEKs: []helperlink.DEKRequest{high}}, 5*time.Second); err == nil {
		t.Fatal("daemon sent a high-tier DEK without a tap")
	}
}

func TestBundleCappedByOffer(t *testing.T) {
	r := setup(t)
	r.approver.Bundle = 120
	res, err := r.server.Ask(context.Background(), helperlink.Challenge{Kind: helperlink.KindGrant, MaxBundle: 30}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.Bundle != 30*time.Minute {
		t.Fatalf("bundle = %v", res.Bundle)
	}
}

func TestWrongDaemonRejected(t *testing.T) {
	identity, _ := sig.GenerateKey()
	keys, _ := softhelper.Generate()
	server := helperlink.NewServer(identity, keys.Public())
	sock := shortSock(t)
	l, _ := net.Listen("unix", sock)
	defer l.Close()
	go server.Serve(l)

	var wrong [32]byte
	client := &helperlink.Client{Keyring: keys, Approver: &softhelper.Auto{Yes: true}, DaemonPin: &wrong}
	c, _ := net.Dial("unix", sock)
	if err := client.Serve(c); !errors.Is(err, helperlink.ErrWrongDaemon) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnpairedHelperRejected(t *testing.T) {
	identity, _ := sig.GenerateKey()
	paired, _ := softhelper.Generate()
	impostor, _ := softhelper.Generate()
	server := helperlink.NewServer(identity, paired.Public())
	sock := shortSock(t)
	l, _ := net.Listen("unix", sock)
	defer l.Close()
	go server.Serve(l)

	fp := helperlink.Fingerprint(identity.Public().Bytes())
	client := &helperlink.Client{Keyring: impostor, Approver: &softhelper.Auto{Yes: true}, DaemonPin: &fp}
	c, _ := net.Dial("unix", sock)
	go client.Serve(c)
	time.Sleep(200 * time.Millisecond)
	if server.Connected() {
		t.Fatal("server accepted a helper with unpaired keys")
	}
	if _, err := server.Ask(context.Background(), helperlink.Challenge{Kind: helperlink.KindGrant}, time.Second); !errors.Is(err, helperlink.ErrNoHelper) {
		t.Fatalf("Ask = %v", err)
	}
}

func TestRevokeAll(t *testing.T) {
	r := setup(t)
	got := make(chan struct{}, 1)
	r.server.OnRevokeAll = func() { got <- struct{}{} }
	var n [32]byte
	rand.Read(n[:])
	if err := r.client.RevokeAll(n); err != nil {
		t.Fatal(err)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("revoke-all not received")
	}
}

func TestPairingBundleRoundTrip(t *testing.T) {
	k, _ := softhelper.Generate()
	b := k.Public().Encode()
	got, err := helperlink.DecodeHelperKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Encode(), b) {
		t.Fatal("bundle changed across decode")
	}
}

func TestSoftKeysSaveLoad(t *testing.T) {
	k, _ := softhelper.Generate()
	p := filepath.Join(t.TempDir(), "keys")
	fp := [32]byte{1}
	k.DaemonPin = &fp
	if err := k.Save(p); err != nil {
		t.Fatal(err)
	}
	k2, err := softhelper.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k2.Public().Encode(), k.Public().Encode()) || *k2.DaemonPin != fp {
		t.Fatal("keys changed across save and load")
	}
}

// shortSock returns a socket path short enough for macOS's 104-byte limit.
func shortSock(t *testing.T) string {
	dir, err := os.MkdirTemp("", "hl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "h.sock")
}
