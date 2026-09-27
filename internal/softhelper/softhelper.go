// Package softhelper is a software approval helper. It speaks the same
// protocol as the Swift helper but keeps its keys in a file and asks for
// approval on a terminal, or approves automatically in tests.
//
// It exists for tests, CI and Linux development. It offers none of the
// hardware protection the Secure Enclave helper gives: anyone who can read
// its key file can approve anything.
package softhelper

import (
	"bufio"
	"crypto/hpke"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"vogt/internal/envelope"
	"vogt/internal/helperlink"
	"vogt/internal/sig"
	"vogt/internal/vault"
	"vogt/internal/wire"
)

// Keys is the helper's key set.
type Keys struct {
	Channel   *sig.PrivateKey
	Approval  *sig.PrivateKey
	High, Low hpke.PrivateKey
	DaemonPin *[32]byte
}

// Generate makes a fresh key set.
func Generate() (*Keys, error) {
	var k Keys
	var err error
	if k.Channel, err = sig.GenerateKey(); err != nil {
		return nil, err
	}
	if k.Approval, err = sig.GenerateKey(); err != nil {
		return nil, err
	}
	if k.High, err = envelope.SuiteVault.GenerateKey(); err != nil {
		return nil, err
	}
	if k.Low, err = envelope.SuiteVault.GenerateKey(); err != nil {
		return nil, err
	}
	return &k, nil
}

// Public returns the pairing bundle.
func (k *Keys) Public() *helperlink.HelperKeys {
	return &helperlink.HelperKeys{
		Channel: k.Channel.Public(), Approval: k.Approval.Public(),
		High: k.High.PublicKey(), Low: k.Low.PublicKey(),
	}
}

const labelFile = "vogt/v1/softhelper-keys"

// Save writes the keys to path with mode 0600.
func (k *Keys) Save(path string) error {
	ch, err := k.Channel.MarshalBinary()
	if err != nil {
		return err
	}
	ap, err := k.Approval.MarshalBinary()
	if err != nil {
		return err
	}
	hi, err := k.High.Bytes()
	if err != nil {
		return err
	}
	lo, err := k.Low.Bytes()
	if err != nil {
		return err
	}
	var pin []byte
	if k.DaemonPin != nil {
		pin = k.DaemonPin[:]
	}
	b := wire.NewEncoder(labelFile).PutBytes(ch).PutBytes(ap).PutBytes(hi).PutBytes(lo).PutBytes(pin).Finish()
	defer clear(b)
	return vault.WriteFileAtomic(path, b, 0o600)
}

// Load reads keys saved by Save.
func Load(path string) (*Keys, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	d := wire.NewDecoder(b, labelFile)
	ch, ap, hi, lo, pin := d.ReadBytes(), d.ReadBytes(), d.ReadBytes(), d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		return nil, err
	}
	var k Keys
	if k.Channel, err = sig.ParsePrivateKey(ch); err != nil {
		return nil, err
	}
	if k.Approval, err = sig.ParsePrivateKey(ap); err != nil {
		return nil, err
	}
	kem, _ := envelope.SuiteVault.KEM()
	if k.High, err = kem.NewPrivateKey(hi); err != nil {
		return nil, err
	}
	if k.Low, err = kem.NewPrivateKey(lo); err != nil {
		return nil, err
	}
	if len(pin) == 32 {
		var p [32]byte
		copy(p[:], pin)
		k.DaemonPin = &p
	}
	return &k, nil
}

// ChannelPublic implements helperlink.Keyring.
func (k *Keys) ChannelPublic() *sig.PublicKey { return k.Channel.Public() }

// ChannelSign implements helperlink.Keyring.
func (k *Keys) ChannelSign(purpose string, msg []byte) ([]byte, error) {
	return k.Channel.Sign(purpose, msg)
}

// ApprovalSign implements helperlink.Keyring.
func (k *Keys) ApprovalSign(purpose string, msg []byte) ([]byte, error) {
	return k.Approval.Sign(purpose, msg)
}

// UnwrapDEK implements helperlink.Keyring.
func (k *Keys) UnwrapDEK(tier envelope.Tier, wrapped, aad []byte) ([]byte, error) {
	sk := k.High
	if tier == envelope.TierLow {
		sk = k.Low
	}
	return envelope.Unwrap(sk, vault.WrapPurpose, aad, wrapped)
}

// LowUnlocked implements helperlink.Keyring. The software helper has no
// login tap, so the low tier is always unlocked.
func (k *Keys) LowUnlocked() bool { return true }

// Auto approves or denies every challenge and records what it saw.
type Auto struct {
	mu     sync.Mutex
	Yes    bool
	Bundle uint64
	Seen   []helperlink.Challenge
}

// Approve implements helperlink.Approver.
func (a *Auto) Approve(ch *helperlink.Challenge) (bool, uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Seen = append(a.Seen, *ch)
	return a.Yes, a.Bundle
}

// Challenges returns the challenges seen so far.
func (a *Auto) Challenges() []helperlink.Challenge {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]helperlink.Challenge(nil), a.Seen...)
}

// Terminal asks on the controlling terminal.
type Terminal struct{ mu sync.Mutex }

// Approve implements helperlink.Approver.
func (t *Terminal) Approve(ch *helperlink.Challenge) (bool, uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, 0
	}
	defer tty.Close()
	fmt.Fprintf(tty, "\n── Vogt approval (%s) ──\n%s\n", ch.Kind, ch.Display)
	prompt := "Approve? [y/N] "
	if ch.MaxBundle > 0 {
		prompt = fmt.Sprintf("Approve? [y/N, or b for %d minutes] ", ch.MaxBundle)
	}
	fmt.Fprint(tty, prompt)
	line, err := bufio.NewReader(tty).ReadString('\n')
	if err != nil && !errors.Is(err, os.ErrClosed) && line == "" {
		return false, 0
	}
	switch strings.TrimSpace(strings.ToLower(line)) {
	case "y", "yes":
		return true, 0
	case "b":
		if ch.MaxBundle > 0 {
			return true, ch.MaxBundle
		}
	}
	return false, 0
}
