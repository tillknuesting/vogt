package grants

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// Journal records the revoke handle of every live credential, so a daemon
// that crashed can revoke them on restart. Handles can be secrets (a GitHub
// token), so each is sealed with AES-256-GCM under a key kept next to the
// journal, both readable only by the daemon's user.
type Journal struct {
	mu   sync.Mutex
	path string
	aead cipher.AEAD
}

type journalLine struct {
	Op       string `json:"op"`
	ID       string `json:"id"`
	Provider string `json:"provider,omitempty"`
	Handle   string `json:"handle,omitempty"`
}

// Leftover is a credential that was live when the daemon stopped.
type Leftover struct {
	ID       string
	Provider string
	Handle   []byte
}

// OpenJournal opens the journal at path, creating its key at keyPath.
func OpenJournal(path, keyPath string) (*Journal, error) {
	key, err := os.ReadFile(keyPath)
	if os.IsNotExist(err) {
		key = make([]byte, 32)
		rand.Read(key)
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("grants: journal key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}
	return &Journal{path: path, aead: aead}, nil
}

func (j *Journal) append(l journalLine) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(l)
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// Start records a live credential.
func (j *Journal) Start(id, provider string, handle []byte) error {
	var h string
	if len(handle) > 0 {
		h = hex.EncodeToString(j.aead.Seal(nil, nil, handle, []byte(id)))
	}
	return j.append(journalLine{Op: "start", ID: id, Provider: provider, Handle: h})
}

// End records that a credential was revoked or expired.
func (j *Journal) End(id string) error {
	return j.append(journalLine{Op: "end", ID: id})
}

// Recover returns credentials started but never ended, then clears the
// journal. Call it once, before issuing new grants.
func (j *Journal) Recover() ([]Leftover, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.Open(j.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	live := map[string]*Leftover{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l journalLine
		if json.Unmarshal(sc.Bytes(), &l) != nil {
			continue // a torn last line after a crash
		}
		switch l.Op {
		case "start":
			lo := &Leftover{ID: l.ID, Provider: l.Provider}
			if l.Handle != "" {
				ct, err := hex.DecodeString(l.Handle)
				if err == nil {
					lo.Handle, _ = j.aead.Open(nil, nil, ct, []byte(l.ID))
				}
			}
			live[l.ID] = lo
			order = append(order, l.ID)
		case "end":
			delete(live, l.ID)
		}
	}
	f.Close()
	var out []Leftover
	for _, id := range order {
		if lo, ok := live[id]; ok {
			out = append(out, *lo)
			delete(live, id)
		}
	}
	return out, os.Remove(j.path)
}
