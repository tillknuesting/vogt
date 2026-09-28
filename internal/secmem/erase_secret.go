//go:build goexperiment.runtimesecret && linux

package secmem

import "runtime/secret"

// Do runs f and then erases the registers, stack and new heap allocations
// it used. Linux builds with GOEXPERIMENT=runtimesecret get this; other
// builds run f as is.
func Do(f func()) { secret.Do(f) }

// Erasing reports whether Do erases temporaries in this build.
func Erasing() bool { return true }
