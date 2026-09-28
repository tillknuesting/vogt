package provider

import (
	"testing"

	"vogt/internal/leakcheck"
)

func TestMain(m *testing.M) { leakcheck.Main(m) }
