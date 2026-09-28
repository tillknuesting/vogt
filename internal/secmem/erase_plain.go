//go:build !(goexperiment.runtimesecret && linux)

package secmem

// Do runs f. Builds for Linux with GOEXPERIMENT=runtimesecret also erase
// the temporaries f used; this build cannot.
func Do(f func()) { f() }

// Erasing reports whether Do erases temporaries in this build.
func Erasing() bool { return false }
