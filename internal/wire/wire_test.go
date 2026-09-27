package wire

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	msg := NewEncoder("vogt/test").
		PutUint(42).
		PutBytes([]byte{1, 2, 3}).
		PutString("héllo").
		PutList([][]byte{{9}, {}, {7, 7}}).
		Finish()

	d := NewDecoder(msg, "vogt/test")
	if got := d.ReadUint(); got != 42 {
		t.Errorf("uint = %d", got)
	}
	if got := d.ReadBytes(); !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("bytes = %x", got)
	}
	if got := d.ReadString(); got != "héllo" {
		t.Errorf("string = %q", got)
	}
	list := d.ReadList()
	if len(list) != 3 || !bytes.Equal(list[2], []byte{7, 7}) || len(list[1]) != 0 {
		t.Errorf("list = %x", list)
	}
	if err := d.Finish(); err != nil {
		t.Fatal(err)
	}
}

// TestKnownEncoding pins the byte layout. The Swift port checks the same
// bytes, so a change here is a protocol change.
func TestKnownEncoding(t *testing.T) {
	got := hex.EncodeToString(NewEncoder("ab").PutUint(1).PutBytes([]byte{0xff}).Finish())
	want := "0300000002" + "6162" + "01" + "0000000000000001" + "0200000001" + "ff"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestRejects(t *testing.T) {
	good := NewEncoder("vogt/test").PutUint(1).Finish()
	cases := map[string]struct {
		msg   []byte
		label string
		read  func(*Decoder)
	}{
		"wrong label":    {good, "vogt/other", func(d *Decoder) { d.ReadUint() }},
		"wrong tag":      {good, "vogt/test", func(d *Decoder) { d.ReadBytes() }},
		"trailing bytes": {append(append([]byte{}, good...), 0), "vogt/test", func(d *Decoder) { d.ReadUint() }},
		"truncated":      {good[:len(good)-1], "vogt/test", func(d *Decoder) { d.ReadUint() }},
		"oversized length": {
			append(NewEncoder("x").Finish(), tagBytes, 0xff, 0xff, 0xff, 0xff),
			"x", func(d *Decoder) { d.ReadBytes() },
		},
		"length past end": {
			append(NewEncoder("x").Finish(), tagBytes, 0, 0, 0, 5, 1),
			"x", func(d *Decoder) { d.ReadBytes() },
		},
		"invalid utf8": {
			append(NewEncoder("x").Finish(), tagString, 0, 0, 0, 1, 0xff),
			"x", func(d *Decoder) { d.ReadString() },
		},
		"too many items": {
			append(NewEncoder("x").Finish(), tagList, 0, 0, 0x10, 0),
			"x", func(d *Decoder) { d.ReadList() },
		},
		"empty": {nil, "x", func(d *Decoder) {}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := NewDecoder(c.msg, c.label)
			c.read(d)
			if err := d.Finish(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestPanicsOnUnencodable(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic on invalid UTF-8")
		}
	}()
	NewEncoder("x").PutString("\xff")
}

// FuzzDecode checks that decoding never panics, and that whatever decodes
// cleanly re-encodes to the same bytes.
func FuzzDecode(f *testing.F) {
	f.Add(NewEncoder("f").PutUint(3).PutBytes([]byte("abc")).PutString("s").PutList([][]byte{{1}}).Finish())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, msg []byte) {
		d := NewDecoder(msg, "f")
		u := d.ReadUint()
		b := d.ReadBytes()
		s := d.ReadString()
		l := d.ReadList()
		if d.Finish() != nil {
			return
		}
		again := NewEncoder("f").PutUint(u).PutBytes(b).PutString(s).PutList(l).Finish()
		if !bytes.Equal(again, msg) {
			t.Fatalf("re-encoding differs:\n%x\n%x", msg, again)
		}
	})
}
