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
