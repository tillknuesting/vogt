// Package audit writes Vogt's append-only, hash-chained audit log.
//
// Each line is a JSON entry. Its hash covers the previous entry's hash and
// the entry's own fields, so editing, removing or reordering an entry breaks
// the chain from that point. Every CheckpointEvery entries, and on Close, the
// log adds a checkpoint entry signed with the daemon's identity key, so a
// rebuilt chain is also detectable.
//
// Entries must never contain secrets or tokens. Callers log token hashes and
// request paths without query strings.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"vogt/internal/sig"
	"vogt/internal/wire"
)

// CheckpointEvery is the number of entries between signed checkpoints.
const CheckpointEvery = 64

const checkpointEvent = "checkpoint"

// Entry is one line of the log.
type Entry struct {
	Seq    uint64            `json:"seq"`
	Time   int64             `json:"ts"` // Unix nanoseconds
	Event  string            `json:"event"`
	Fields map[string]string `json:"fields,omitempty"`
	Prev   string            `json:"prev"`
	Hash   string            `json:"hash"`
	Sig    string            `json:"sig,omitempty"`
}

func (e *Entry) digest(prev []byte) [32]byte {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kv := make([][]byte, 0, len(keys))
	for _, k := range keys {
		kv = append(kv, wire.NewEncoder("vogt/v1/audit-field").PutString(k).PutString(e.Fields[k]).Finish())
	}
	m := wire.NewEncoder("vogt/v1/audit").
		PutBytes(prev).
		PutUint(e.Seq).
		PutUint(uint64(e.Time)).
		PutString(e.Event).
		PutList(kv).
		Finish()
	return sha256.Sum256(m)
}

// Log is an open audit log.
type Log struct {
	mu        sync.Mutex
	f         *os.File
	w         *bufio.Writer
	signer    *sig.PrivateKey
	prev      [32]byte
	seq       uint64
	sinceSign int
	now       func() time.Time
}

// Open opens or creates the log at path. It verifies the existing chain
// before appending, so it never extends a broken log.
func Open(path string, signer *sig.PrivateKey) (*Log, error) {
	l := &Log{signer: signer, now: time.Now}
	if _, err := os.Stat(path); err == nil {
		st, err := verify(path, signer.Public())
		if err != nil {
			return nil, fmt.Errorf("audit: existing log does not verify: %w", err)
		}
		l.prev, l.seq, l.sinceSign = st.head, st.seq, st.sinceSign
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	l.f, l.w = f, bufio.NewWriter(f)
	return l, nil
}

// Append adds an entry and flushes it to disk.
func (l *Log) Append(event string, fields map[string]string) error {
	if event == checkpointEvent {
		return errors.New("audit: reserved event name")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.appendLocked(event, fields, false); err != nil {
		return err
	}
	if l.sinceSign >= CheckpointEvery {
		return l.appendLocked(checkpointEvent, nil, true)
	}
	return nil
}

// Checkpoint adds a signed checkpoint now.
func (l *Log) Checkpoint() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(checkpointEvent, nil, true)
}

func (l *Log) appendLocked(event string, fields map[string]string, signed bool) error {
	if l.f == nil {
		return errors.New("audit: log closed")
	}
	e := Entry{Seq: l.seq + 1, Time: l.now().UnixNano(), Event: event, Fields: fields, Prev: hex.EncodeToString(l.prev[:])}
	h := e.digest(l.prev[:])
	e.Hash = hex.EncodeToString(h[:])
	if signed {
		s, err := l.signer.Sign("audit", h[:])
		if err != nil {
			return err
		}
		e.Sig = hex.EncodeToString(s)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := l.w.Flush(); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.prev, l.seq = h, e.Seq
	if signed {
		l.sinceSign = 0
	} else {
		l.sinceSign++
	}
	return nil
}

// Close writes a final checkpoint and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	var err error
	if l.sinceSign > 0 {
		err = l.appendLocked(checkpointEvent, nil, true)
	}
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// Result summarises a verified log.
type Result struct {
	Entries     int
	Checkpoints int
	Unsigned    int // entries after the last checkpoint
}

type state struct {
	head      [32]byte
	seq       uint64
	sinceSign int
	checks    int
	entries   int
}

// Verify checks the chain and every checkpoint signature in the log at path.
func Verify(path string, pub *sig.PublicKey) (Result, error) {
	st, err := verify(path, pub)
	return Result{Entries: st.entries, Checkpoints: st.checks, Unsigned: st.sinceSign}, err
}

func verify(path string, pub *sig.PublicKey) (state, error) {
	var st state
	f, err := os.Open(path)
	if err != nil {
		return st, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return st, fmt.Errorf("line %d: %w", st.entries+1, err)
		}
		if e.Seq != st.seq+1 {
			return st, fmt.Errorf("entry %d: sequence %d, want %d", st.entries+1, e.Seq, st.seq+1)
		}
		if e.Prev != hex.EncodeToString(st.head[:]) {
			return st, fmt.Errorf("entry %d: previous hash does not match", e.Seq)
		}
		h := e.digest(st.head[:])
		if e.Hash != hex.EncodeToString(h[:]) {
			return st, fmt.Errorf("entry %d: hash does not match its contents", e.Seq)
		}
		if e.Event == checkpointEvent {
			s, err := hex.DecodeString(e.Sig)
			if err != nil || pub.Verify("audit", h[:], s) != nil {
				return st, fmt.Errorf("entry %d: checkpoint signature is invalid", e.Seq)
			}
			st.checks++
			st.sinceSign = 0
		} else {
			if e.Sig != "" {
				return st, fmt.Errorf("entry %d: unexpected signature", e.Seq)
			}
			st.sinceSign++
		}
		st.head, st.seq = h, e.Seq
		st.entries++
	}
	return st, sc.Err()
}
