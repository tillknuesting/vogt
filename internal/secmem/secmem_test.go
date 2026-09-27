//go:build darwin || linux

package secmem

import (
	"bytes"
	"syscall"
	"testing"
)

func TestNewIsZeroedAndWritable(t *testing.T) {
	for _, n := range []int{1, 32, syscall.Getpagesize(), syscall.Getpagesize() + 1} {
		b, err := New(n)
		if err != nil {
			t.Fatal(err)
		}
		if b.Len() != n {
			t.Fatalf("len = %d, want %d", b.Len(), n)
		}
		if !bytes.Equal(b.Bytes(), make([]byte, n)) {
			t.Fatal("new buffer is not zeroed")
		}
		for i := range b.Bytes() {
			b.Bytes()[i] = 0xa5
		}
		b.Destroy()
		if b.Len() != 0 || b.Bytes() != nil {
			t.Fatal("destroyed buffer still exposes memory")
		}
		b.Destroy() // second call is a no-op
	}
}

func TestFromBytesWipesSource(t *testing.T) {
	src := []byte("correct horse battery staple")
	want := append([]byte{}, src...)
	b, err := FromBytes(src)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	if !bytes.Equal(b.Bytes(), want) {
		t.Fatal("buffer does not hold the copied bytes")
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Fatal("source was not wiped")
	}
}

func TestDataEndsAtGuardPage(t *testing.T) {
	b, err := New(10)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	if cap(b.Bytes()) != 10 {
		t.Fatalf("cap = %d; appending could run into the guard page", cap(b.Bytes()))
	}
}

func TestRejectsZeroSize(t *testing.T) {
	if _, err := New(0); err == nil {
		t.Fatal("New(0) succeeded")
	}
}
