// Package mcp serves Vogt's tools to an MCP client over stdio.
//
// It speaks JSON-RPC 2.0 with newline-delimited messages. It handles the
// per-request model of the 2026-07-28 revision and, for clients on earlier
// revisions, the initialize handshake. Tool results carry proxy settings and
// broker tokens only: a real credential would land in the model's context
// and transcript, so direct and reveal modes are not offered here.
package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// Versions are the protocol revisions this server accepts, newest first.
var Versions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"}

// Backend performs the tool actions.
type Backend interface {
	Capabilities() ([]Capability, error)
	RequestAccess(capability, target, ttl, reason string) (Access, error)
	ReleaseAccess(grantID string) error
}

// Capability is one entry of the catalogue.
type Capability struct {
	Name    string `json:"name"`
	Display string `json:"display"`
	Target  string `json:"target,omitempty"`
}

// Access is what an approved request returns to the model.
type Access struct {
	GrantID  string   `json:"grant_id"`
	ProxyURL string   `json:"proxy_url"`
	Token    string   `json:"broker_token"`
	Env      []string `json:"env"`
	Expires  string   `json:"expires"`
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server is an MCP server.
type Server struct {
	Backend Backend
	Name    string
	Version string
	mu      sync.Mutex
}

// Serve reads requests from r and writes responses to w until r ends.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var wmu sync.Mutex
	write := func(v any) {
		b, err := json.Marshal(v)
		if err != nil {
			return
		}
		wmu.Lock()
		defer wmu.Unlock()
		w.Write(append(b, '\n'))
	}
	var wg sync.WaitGroup
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if line[0] == '[' {
			var batch []json.RawMessage
			if err := json.Unmarshal(line, &batch); err != nil {
				write(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
				continue
			}
			var out []response
			for _, m := range batch {
				if resp := s.handle(m); resp != nil {
					out = append(out, *resp)
				}
			}
			if len(out) > 0 {
				write(out)
			}
			continue
		}
		wg.Go(func() {
			if resp := s.handle(line); resp != nil {
				write(resp)
			}
		})
	}
	wg.Wait()
	return sc.Err()
}

func (s *Server) handle(raw []byte) *response {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}}
	}
	if req.ID == nil {
		return nil // a notification: nothing to answer
	}
	result, err := s.dispatch(req)
	resp := &response{JSONRPC: "2.0", ID: req.ID}
	if err != nil {
		if re, ok := errors.AsType[*rpcError](err); ok {
			resp.Error = re
		} else {
			resp.Error = &rpcError{-32603, err.Error()}
		}
		return resp
	}
	resp.Result = result
	return resp
}

func (e *rpcError) Error() string { return e.Message }

func (s *Server) dispatch(req request) (any, error) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(req.Params, &p)
		v := Versions[0]
		if slices.Contains(Versions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": s.Name, "version": s.Version},
			"instructions":    "Use request_access before calling a provider. Each request waits for the human to approve it. Send your requests to the returned proxy URL with the broker token where the API key would go.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "server/discover":
		return map[string]any{
			"supportedVersions": Versions,
			"capabilities":      map[string]any{"tools": map[string]any{}},
			"serverInfo":        map[string]string{"name": s.Name, "version": s.Version},
		}, nil
	case "tools/list":
		return map[string]any{"tools": tools()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		return s.call(p.Name, p.Arguments), nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func tools() []map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	return []map[string]any{
		{
			"name":        "list_capabilities",
			"description": "List what this agent may ask Vogt for.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		},
		{
			"name":        "request_access",
			"description": "Ask for short-lived access to a capability. Blocks until the human approves or denies. Returns a proxy URL and a broker token; the real credential never reaches you.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"capability": str("capability name from list_capabilities"),
					"target":     str("what to act on, e.g. owner/repo"),
					"ttl":        str("how long, e.g. 10m; the policy caps it"),
					"reason":     str("why; shown to the human as your unverified claim"),
				},
				"required": []string{"capability"},
			},
		},
		{
			"name":        "release_access",
			"description": "End a grant as soon as the task no longer needs it.",
			"inputSchema": map[string]any{
				"type":       "object",
				"properties": map[string]any{"grant_id": str("the grant_id from request_access")},
				"required":   []string{"grant_id"},
			},
		},
	}
}

func textResult(v any, isErr bool) map[string]any {
	var text string
	if s, ok := v.(string); ok {
		text = s
	} else {
		b, _ := json.MarshalIndent(v, "", "  ")
		text = string(b)
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": text}}, "isError": isErr}
}

func (s *Server) call(name string, args json.RawMessage) map[string]any {
	switch name {
	case "list_capabilities":
		caps, err := s.Backend.Capabilities()
		if err != nil {
			return textResult(err.Error(), true)
		}
		return textResult(caps, false)
	case "request_access":
		var a struct{ Capability, Target, TTL, Reason string }
		if err := json.Unmarshal(args, &a); err != nil || a.Capability == "" {
			return textResult("request_access needs a capability", true)
		}
		acc, err := s.Backend.RequestAccess(a.Capability, a.Target, a.TTL, a.Reason)
		if err != nil {
			return textResult(fmt.Sprintf("not granted: %v", err), true)
		}
		return textResult(acc, false)
	case "release_access":
		var a struct {
			GrantID string `json:"grant_id"`
		}
		if err := json.Unmarshal(args, &a); err != nil || a.GrantID == "" {
			return textResult("release_access needs a grant_id", true)
		}
		if err := s.Backend.ReleaseAccess(a.GrantID); err != nil {
			return textResult(err.Error(), true)
		}
		return textResult("released", false)
	}
	return textResult("unknown tool "+name, true)
}
