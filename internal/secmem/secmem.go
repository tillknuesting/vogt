//go:build darwin || linux

// Package secmem holds secret bytes outside the Go heap. Each buffer lives in
// its own anonymous mapping, locked so it is never swapped to disk, with a
// no-access guard page on each side, and it is wiped when destroyed.
//
// Go strings and ordinary slices can be copied by the runtime and cannot be
// wiped reliably, so key material should stay in a Buffer for its whole life.
package secmem

import (
	"errors"
	"sync"
	"syscall"
)

// ErrDestroyed is returned when a destroyed buffer is used.
var ErrDestroyed = errors.New("secmem: buffer destroyed")

// Buffer is a fixed-size region of locked memory.
type Buffer struct {
	mu     sync.Mutex
	region []byte // the whole mapping, guard pages included
	data   []byte // the usable bytes, ending at the trailing guard page
}

// New allocates a zeroed buffer of n bytes.
func New(n int) (*Buffer, error) {
	if n <= 0 {
		return nil, errors.New("secmem: size must be positive")
	}
	page := syscall.Getpagesize()
	inner := (n + page - 1) / page * page
	region, err := syscall.Mmap(-1, 0, page+inner+page,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Buffer, error) {
		syscall.Munmap(region)
		return nil, err
	}
	if err := syscall.Mprotect(region[:page], syscall.PROT_NONE); err != nil {
		return fail(err)
	}
	if err := syscall.Mprotect(region[page+inner:], syscall.PROT_NONE); err != nil {
		return fail(err)
	}
	if err := syscall.Mlock(region[page : page+inner]); err != nil {
		return fail(err)
	}
	// Place the data at the end of the inner pages, so an overrun hits the
	// trailing guard page instead of silently reading or writing past it.
	end := page + inner
	return &Buffer{region: region, data: region[end-n : end : end]}, nil
}

// FromBytes copies src into a new buffer and wipes src.
func FromBytes(src []byte) (*Buffer, error) {
	b, err := New(len(src))
	if err != nil {
		return nil, err
	}
	copy(b.data, src)
	clear(src)
	return b, nil
}

// Bytes returns the buffer's memory. The slice is valid until Destroy; callers
// must not keep it longer or copy it into ordinary memory.
func (b *Buffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

// Len returns the buffer size, or 0 once destroyed.
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.data)
}

// Destroy wipes, unlocks and unmaps the buffer. It is safe to call twice.
func (b *Buffer) Destroy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.region == nil {
		return
	}
	page := syscall.Getpagesize()
	inner := b.region[page : len(b.region)-page]
	clear(inner)
	syscall.Munlock(inner)
	syscall.Munmap(b.region)
	b.region, b.data = nil, nil
}

// DisableCoreDumps sets the core file size limit to zero, so a crash cannot
// write secrets to disk.
func DisableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}
