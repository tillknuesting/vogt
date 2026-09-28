// Package leakcheck fails a test binary that leaks goroutines.
//
// It reads Go's goroutineleak profile, which finds goroutines blocked
// forever on channels, mutexes or other primitives that nothing reachable
// can ever unblock. Every test package calls Main from its TestMain.
package leakcheck

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"
)

var total = regexp.MustCompile(`goroutineleak profile: total (\d+)`)

// Leaks returns the number of leaked goroutines and their stacks.
func Leaks() (int, string) {
	p := pprof.Lookup("goroutineleak")
	if p == nil {
		return 0, ""
	}
	var b bytes.Buffer
	if err := p.WriteTo(&b, 1); err != nil {
		return 0, ""
	}
	m := total.FindSubmatch(b.Bytes())
	if m == nil {
		return 0, ""
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n, b.String()
}

// Main runs the tests, then fails the binary if goroutines leaked.
func Main(m *testing.M) {
	code := m.Run()
	if code == 0 {
		// Give goroutines that are winding down a moment to exit.
		var n int
		var report string
		for range 20 {
			if n, report = Leaks(); n == 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "FAIL: %d goroutines leaked\n%s", n, report)
			code = 1
		}
	}
	os.Exit(code)
}
