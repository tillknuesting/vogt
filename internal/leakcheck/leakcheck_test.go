package leakcheck

import (
	"testing"
	"time"
)

// TestDetectsLeak leaks a goroutine on purpose and checks the profile sees it.
func TestDetectsLeak(t *testing.T) {
	before, _ := Leaks()
	go func() {
		ch := make(chan int)
		<-ch // nothing else holds ch, so this never returns
	}()
	time.Sleep(50 * time.Millisecond)
	after, report := Leaks()
	if after <= before {
		t.Fatalf("leak not detected: %d before, %d after\n%s", before, after, report)
	}
}
