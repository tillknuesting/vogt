package helperlink

import (
	"crypto/hpke"
	"fmt"

	"vogt/internal/envelope"
	"vogt/internal/sig"
	"vogt/internal/wire"
)

// HelperKeys are the helper's public keys, exchanged once at pairing.
type HelperKeys struct {
	Channel  *sig.PublicKey // signs every response; no tap
	Approval *sig.PublicKey // signs approvals; Touch ID on every use
	High     hpke.PublicKey // MLKEM768-P256; Touch ID on every use
	Low      hpke.PublicKey // MLKEM768-P256; unlocked once per login
}

// Encode serializes the keys as a pairing bundle.
func (k *HelperKeys) Encode() []byte {
	return wire.NewEncoder(labelHelperKeys).
		PutUint(Version).
		PutBytes(k.Channel.Bytes()).
		PutBytes(k.Approval.Bytes()).
		PutBytes(k.High.Bytes()).
		PutBytes(k.Low.Bytes()).
		Finish()
}

// Fingerprint identifies a pairing bundle to the human.
func (k *HelperKeys) Fingerprint() [32]byte { return Fingerprint(k.Encode()) }

// DecodeHelperKeys parses a pairing bundle.
func DecodeHelperKeys(b []byte) (*HelperKeys, error) {
	d := wire.NewDecoder(b, labelHelperKeys)
	v := d.ReadUint()
	ch, ap, hi, lo := d.ReadBytes(), d.ReadBytes(), d.ReadBytes(), d.ReadBytes()
	if err := d.Finish(); err != nil {
		return nil, err
	}
	if v != Version {
		return nil, fmt.Errorf("helperlink: pairing bundle version %d", v)
	}
	var k HelperKeys
	var err error
	if k.Channel, err = sig.ParsePublicKey(ch); err != nil {
		return nil, fmt.Errorf("channel key: %w", err)
	}
	if k.Approval, err = sig.ParsePublicKey(ap); err != nil {
		return nil, fmt.Errorf("approval key: %w", err)
	}
	kem, _ := envelope.SuiteVault.KEM()
	if k.High, err = kem.NewPublicKey(hi); err != nil {
		return nil, fmt.Errorf("high-tier key: %w", err)
	}
	if k.Low, err = kem.NewPublicKey(lo); err != nil {
		return nil, fmt.Errorf("low-tier key: %w", err)
	}
	return &k, nil
}
