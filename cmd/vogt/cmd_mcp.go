package main

import (
	"os"
	"time"

	"vogt/internal/grants"
	"vogt/internal/mcp"
)

// runMCP serves Vogt's tools over stdio. Configure the agent to launch it,
// for example `vogt mcp` as a stdio MCP server, and run the agent itself
// under `vogt run` so the session secret is in the environment.
func runMCP(args []string) error {
	c := newClient()
	if err := c.needSession(); err != nil {
		return err
	}
	s := &mcp.Server{Backend: &mcpBackend{c: c}, Name: "vogt", Version: "1"}
	return s.Serve(os.Stdin, os.Stdout)
}

type mcpBackend struct{ c *client }

func (b *mcpBackend) Capabilities() ([]mcp.Capability, error) {
	var out []mcp.Capability
	err := b.c.do("GET", "/v1/capabilities", nil, &out, 10*time.Second)
	return out, err
}

func (b *mcpBackend) RequestAccess(capability, target, ttl, reason string) (mcp.Access, error) {
	gf := grantFlags{ttl: &ttl, reason: &reason, mode: "proxy"}
	v, err := requestAndWait(b.c, capability, target, gf, nil)
	if err != nil {
		return mcp.Access{}, err
	}
	return accessFrom(v), nil
}

func accessFrom(v grants.View) mcp.Access {
	return mcp.Access{
		GrantID: v.ID, ProxyURL: v.Delivery.ProxyURL, Token: v.Delivery.Token,
		Env: v.Delivery.Env, Expires: v.NotAfter.Format(time.RFC3339),
	}
}

func (b *mcpBackend) ReleaseAccess(id string) error {
	return b.c.do("DELETE", "/v1/grants/"+id, nil, nil, 30*time.Second)
}
