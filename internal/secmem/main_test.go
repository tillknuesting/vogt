package secmem

import (
	"testing"

	"vogt/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.Main(m) }
