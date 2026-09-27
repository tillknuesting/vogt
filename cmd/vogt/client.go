package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Default locations. A system install uses /var/db/vogt and /var/run/vogt;
// `vogt daemon --dev` uses ~/.vogt-dev.
const (
	systemStateDir = "/var/db/vogt"
	systemRunDir   = "/var/run/vogt"
)

func devDir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".vogt-dev")
}

// socketPath finds the API socket: $VOGT_SOCKET, the system socket, or the
// development socket.
func socketPath() string {
	if p := os.Getenv("VOGT_SOCKET"); p != "" {
		return p
	}
	sys := filepath.Join(systemRunDir, "vogt.sock")
	if _, err := os.Stat(sys); err == nil {
		return sys
	}
	return filepath.Join(devDir(), "run", "vogt.sock")
}

type client struct {
	http    *http.Client
	session string
	socket  string
}

func newClient() *client {
	sock := socketPath()
	return &client{
		socket:  sock,
		session: os.Getenv("VOGT_SESSION"),
		http: &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		}},
	}
}

type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return e.Msg }

// do calls the API. body may be nil, a []byte (sent as is) or a value
// encoded as JSON. out may be nil.
func (c *client) do(method, path string, body, out any, timeout time.Duration) error {
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		r = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return err
		}
		r = bytes.NewReader(j)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://vogt"+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.session != "" {
		req.Header.Set("Authorization", "Bearer "+c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) {
			return fmt.Errorf("cannot reach the daemon at %s; is `vogt daemon` running? (%v)", c.socket, ne.Err)
		}
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return &apiError{resp.StatusCode, e.Error}
		}
		return &apiError{resp.StatusCode, resp.Status}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if b, ok := out.(*[]byte); ok {
		*b = raw
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *client) needSession() error {
	if c.session == "" {
		return errors.New("no session: run the agent under `vogt run -- <agent>` so VOGT_SESSION is set")
	}
	return nil
}
