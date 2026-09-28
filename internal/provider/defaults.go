package provider

import (
	"context"
	"net/http"
)

// Defaults returns every built-in adapter, sharing one HTTP client.
func Defaults(client *http.Client) Registry {
	return Registry{
		"static":   Static{},
		"github":   &GitHub{Client: client},
		"oauth":    &OAuth{Client: client},
		"postgres": &Postgres{},
	}
}

// Rotator is implemented by adapters that can replace their master secret
// through the provider's API. It returns the new master secret.
type Rotator interface {
	Rotate(ctx context.Context, master []byte) ([]byte, error)
}

// Revoker is implemented by credentials that can revoke themselves while
// still live, using state a bare handle does not carry.
type Revoker interface {
	Revoke(ctx context.Context) error
}
