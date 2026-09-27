// Package wire is Vogt's canonical binary encoding for anything that gets
// signed or encrypted. Every value has exactly one encoding, so Go and Swift
// produce the same bytes for the same message.
//
// A message is a domain label followed by a fixed sequence of fields. Each
// field is a one-byte tag and a body:
//
//	0x01 uint:   8-byte big-endian unsigned integer
//	0x02 bytes:  4-byte big-endian length, then the bytes
//	0x03 string: same layout as bytes; the body must be valid UTF-8
//	0x04 list:   4-byte big-endian count, then that many bytes fields
//
// The label is encoded as a string field. Decoders read fields in the order
// the caller expects and fail on a wrong tag, an oversized length, invalid
// UTF-8 or trailing bytes.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	tagUint   = 0x01
	tagBytes  = 0x02
	tagString = 0x03
	tagList   = 0x04
)

// Limits on decoded sizes. They keep a hostile input from forcing large
// allocations.
const (
	MaxLen   = 16 << 20
	MaxItems = 1024
)

// ErrMalformed wraps every decoding failure.
var ErrMalformed = errors.New("wire: malformed message")

// Encoder builds a message. The zero value is not usable; call NewEncoder.
type Encoder struct {
	buf []byte
}

// NewEncoder starts a message with the given domain label.
func NewEncoder(label string) *Encoder {
	e := &Encoder{}
	return e.PutString(label)
}

// PutUint appends an unsigned integer field.
func (e *Encoder) PutUint(v uint64) *Encoder {
	e.buf = append(e.buf, tagUint)
	e.buf = binary.BigEndian.AppendUint64(e.buf, v)
	return e
}

// PutBytes appends a bytes field. It panics if b is longer than MaxLen,
// because such a message could never be decoded.
func (e *Encoder) PutBytes(b []byte) *Encoder {
	return e.putBlob(tagBytes, b)
}

// PutString appends a string field. It panics on invalid UTF-8 or a string
// longer than MaxLen.
func (e *Encoder) PutString(s string) *Encoder {
	if !utf8.ValidString(s) {
		panic("wire: invalid UTF-8 in string field")
	}
	return e.putBlob(tagString, []byte(s))
}

// PutList appends a list of bytes fields.
func (e *Encoder) PutList(items [][]byte) *Encoder {
	if len(items) > MaxItems {
		panic("wire: too many list items")
	}
	e.buf = append(e.buf, tagList)
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(len(items)))
	for _, it := range items {
		e.PutBytes(it)
	}
	return e
}

func (e *Encoder) putBlob(tag byte, b []byte) *Encoder {
	if len(b) > MaxLen {
		panic("wire: field longer than MaxLen")
	}
	e.buf = append(e.buf, tag)
	e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(len(b)))
	e.buf = append(e.buf, b...)
	return e
}

// Finish returns the encoded message.
func (e *Encoder) Finish() []byte {
	return e.buf
}

// Decoder reads a message field by field. The first error sticks: later reads
// return zero values, and Finish reports it.
type Decoder struct {
	b   []byte
	err error
}

// NewDecoder starts reading msg and checks that it carries the given label.
func NewDecoder(msg []byte, label string) *Decoder {
	d := &Decoder{b: msg}
	if got := d.ReadString(); d.err == nil && got != label {
		d.fail("label %q, want %q", got, label)
	}
	return d
}

func (d *Decoder) fail(format string, args ...any) {
	if d.err == nil {
		d.err = fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
	}
}

func (d *Decoder) tag(want byte) bool {
	if d.err != nil {
		return false
	}
	if len(d.b) < 1 {
		d.fail("truncated before tag")
		return false
	}
	if d.b[0] != want {
		d.fail("tag 0x%02x, want 0x%02x", d.b[0], want)
		return false
	}
	d.b = d.b[1:]
	return true
}

// ReadUint reads an unsigned integer field.
func (d *Decoder) ReadUint() uint64 {
	if !d.tag(tagUint) {
		return 0
	}
	if len(d.b) < 8 {
		d.fail("truncated uint")
		return 0
	}
	v := binary.BigEndian.Uint64(d.b)
	d.b = d.b[8:]
	return v
}

// ReadBytes reads a bytes field and returns a copy of its body.
func (d *Decoder) ReadBytes() []byte {
	return d.readBlob(tagBytes)
}

// ReadString reads a string field.
func (d *Decoder) ReadString() string {
	b := d.readBlob(tagString)
	if d.err != nil {
		return ""
	}
	if !utf8.Valid(b) {
		d.fail("invalid UTF-8")
		return ""
	}
	return string(b)
}

// ReadList reads a list of bytes fields.
func (d *Decoder) ReadList() [][]byte {
	if !d.tag(tagList) {
		return nil
	}
	if len(d.b) < 4 {
		d.fail("truncated list count")
		return nil
	}
	n := binary.BigEndian.Uint32(d.b)
	d.b = d.b[4:]
	if n > MaxItems {
		d.fail("list of %d items exceeds limit", n)
		return nil
	}
	items := make([][]byte, 0, n)
	for range n {
		it := d.ReadBytes()
		if d.err != nil {
			return nil
		}
		items = append(items, it)
	}
	return items
}

func (d *Decoder) readBlob(tag byte) []byte {
	if !d.tag(tag) {
		return nil
	}
	if len(d.b) < 4 {
		d.fail("truncated length")
		return nil
	}
	n := binary.BigEndian.Uint32(d.b)
	d.b = d.b[4:]
	if n > MaxLen {
		d.fail("length %d exceeds limit", n)
		return nil
	}
	if uint64(len(d.b)) < uint64(n) {
		d.fail("length %d exceeds remaining %d bytes", n, len(d.b))
		return nil
	}
	out := make([]byte, n)
	copy(out, d.b[:n])
	d.b = d.b[n:]
	return out
}

// Finish reports the first decoding error, or an error if bytes remain.
func (d *Decoder) Finish() error {
	if d.err != nil {
		return d.err
	}
	if len(d.b) != 0 {
		return fmt.Errorf("%w: %d trailing bytes", ErrMalformed, len(d.b))
	}
	return nil
}

// Err reports the first decoding error so far, without checking for
// trailing bytes.
func (d *Decoder) Err() error {
	return d.err
}
