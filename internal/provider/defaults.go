package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Defaults returns every built-in adapter, sharing one HTTP client.
func Defaults(client *http.Client) Registry {
	return Registry{
		"static":   Static{},
		"github":   &GitHub{Client: client},
		"aws":      &AWS{Client: client},
		"gcp":      &GCP{Client: client},
		"oauth":    &OAuth{Client: client},
		"postgres": &Postgres{},
	}
}

// Revoker is implemented by credentials that can revoke themselves while
// still live, using state a bare handle does not carry.
type Revoker interface {
	Revoke(ctx context.Context) error
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
