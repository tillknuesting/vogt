// Package vault stores master secrets encrypted at rest.
//
// Each secret has its own random data key (DEK). The secret is sealed under
// the DEK as an envelope record, and the DEK is wrapped one or more times:
// always to the Secure Enclave key of the secret's tier (wrap name "se"),
// and optionally under a WebAuthn PRF key (wrap name "prf:<credential>").
// The daemon never holds an unwrapped DEK except while serving an approved
// grant, so reading the vault files alone reveals nothing.
package vault

import (
	"crypto/hpke"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"vogt/internal/envelope"
	"vogt/internal/secmem"
	"vogt/internal/wire"
)

// WrapPurpose is the HPKE purpose for DEK wraps.
const WrapPurpose = "dek"

// WrapSE names the wrap to the tier's Secure Enclave key.
const WrapSE = "se"

var ErrNotFound = errors.New("vault: no such secret")

// Meta describes a stored secret without its contents.
type Meta struct {
	ID         string        `json:"id"`
	Provider   string        `json:"provider"`
	Tier       envelope.Tier `json:"tier"`
	KeyVersion uint64        `json:"key_version"`
	Created    time.Time     `json:"created"`
	Updated    time.Time     `json:"updated"`
}

// Entry is a stored secret: its metadata, sealed record and DEK wraps.
type Entry struct {
	Meta
	Record hexBytes            `json:"record"`
	Wraps  map[string]hexBytes `json:"wraps"`
}

type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }
func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	*h = v
	return err
}

// TierKeys are the helper's Secure Enclave public keys, one per tier.
type TierKeys struct {
	High, Low hpke.PublicKey
}

// Store is a directory of encrypted secrets.
type Store struct {
	dir  string
	keys TierKeys
	now  func() time.Time
}

// Open opens or creates the vault directory.
func Open(dir string, keys TierKeys) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir, keys: keys, now: time.Now}, nil
}

// SetKeys replaces the tier keys, after pairing a new helper.
func (s *Store) SetKeys(k TierKeys) { s.keys = k }

// ValidID reports whether id is a usable secret name.
func ValidID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.", c)) {
			return false
		}
	}
	return id[0] != '.'
}

// WrapAAD is the associated data binding a DEK wrap to one secret version.
func WrapAAD(id string, keyVersion uint64) []byte {
	return wire.NewEncoder("vogt/v1/dek-aad").PutString(id).PutUint(keyVersion).Finish()
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

// Put stores secret under id, replacing any existing version. It wipes
// secret. Earlier PRF wraps are dropped, because the new DEK cannot be
// wrapped under them without the authenticator.
func (s *Store) Put(id, provider string, tier envelope.Tier, secret []byte) (Meta, error) {
	defer clear(secret)
	if !ValidID(id) {
		return Meta{}, fmt.Errorf("vault: invalid secret name %q", id)
	}
	pub := s.keys.High
	if tier == envelope.TierLow {
		pub = s.keys.Low
	} else if tier != envelope.TierHigh {
		return Meta{}, errors.New("vault: tier must be high or low")
	}
	if pub == nil {
		return Meta{}, errors.New("vault: no helper is paired")
	}
	now := s.now().UTC()
	m := Meta{ID: id, Provider: provider, Tier: tier, KeyVersion: 1, Created: now, Updated: now}
	if old, err := s.Get(id); err == nil {
		m.KeyVersion, m.Created = old.KeyVersion+1, old.Created
	}

	dek, err := secmem.New(envelope.DEKSize)
	if err != nil {
		return Meta{}, err
	}
	defer dek.Destroy()
	rand.Read(dek.Bytes())

	rec, err := envelope.SealRecord(dek.Bytes(), envelope.Header{ID: id, Tier: tier, KeyVersion: m.KeyVersion}, secret)
	if err != nil {
		return Meta{}, err
	}
	w, err := envelope.Wrap(pub, WrapPurpose, WrapAAD(id, m.KeyVersion), dek.Bytes())
	if err != nil {
		return Meta{}, err
	}
	e := &Entry{Meta: m, Record: rec, Wraps: map[string]hexBytes{WrapSE: w}}
	return m, s.write(e)
}

// Get loads an entry.
func (s *Store) Get(id string) (*Entry, error) {
	if !ValidID(id) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("vault: %s: %w", id, err)
	}
	if e.ID != id {
		return nil, fmt.Errorf("vault: %s: file holds %q", id, e.ID)
	}
	return &e, nil
}

// List returns the metadata of every secret, sorted by ID.
func (s *Store) List() ([]Meta, error) {
	names, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []Meta
	for _, n := range names {
		e, err := s.Get(strings.TrimSuffix(filepath.Base(n), ".json"))
		if err != nil {
			return nil, err
		}
		out = append(out, e.Meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Delete removes a secret.
func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return ErrNotFound
	}
	err := os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

// SetWrap adds or replaces a named DEK wrap.
func (s *Store) SetWrap(id, name string, wrapped []byte) error {
	e, err := s.Get(id)
	if err != nil {
		return err
	}
	e.Wraps[name] = wrapped
	return s.write(e)
}

// Decrypt opens an entry's record with its DEK and returns the secret in
// locked memory.
func Decrypt(e *Entry, dek []byte) (*secmem.Buffer, error) {
	h, pt, err := envelope.OpenRecord(dek, e.Record, e.ID)
	if err != nil {
		return nil, err
	}
	if h.KeyVersion != e.KeyVersion || h.Tier != e.Tier {
		clear(pt)
		return nil, envelope.ErrOpen
	}
	if len(pt) == 0 {
		return nil, errors.New("vault: empty secret")
	}
	return secmem.FromBytes(pt)
}

func (s *Store) write(e *Entry) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path(e.ID), b, 0o600)
}

// WriteFileAtomic writes data to a temporary file, syncs it and renames it
// over path, so a crash leaves either the old or the new file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
