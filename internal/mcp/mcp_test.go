package mcp

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeBackend struct{ released []string }

func (f *fakeBackend) Capabilities() ([]Capability, error) {
	return []Capability{{Name: "github.repo.read", Display: "READ github.com/{target}"}}, nil
}

func (f *fakeBackend) RequestAccess(c, t, ttl, reason string) (Access, error) {
	if c == "denied" {
		return Access{}, errors.New("the human denied the request")
	}
	return Access{GrantID: "g1", ProxyURL: "http://127.0.0.1:7853/github", Token: "vogt_p_x"}, nil
}

func (f *fakeBackend) ReleaseAccess(id string) error {
	f.released = append(f.released, id)
	return nil
}

func run(t *testing.T, in string) []map[string]any {
	t.Helper()
	b := &fakeBackend{}
	pr, pw := io.Pipe()
	s := &Server{Backend: b, Name: "vogt", Version: "test"}
	go func() {
		s.Serve(strings.NewReader(in), pw)
		pw.Close()
	}()
	var out []map[string]any
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		var v any
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			t.Fatalf("bad output line %q", sc.Text())
		}
		switch x := v.(type) {
		case map[string]any:
			out = append(out, x)
		case []any:
			for _, e := range x {
				out = append(out, e.(map[string]any))
			}
		}
	}
	return out
}

func byID(out []map[string]any, id float64) map[string]any {
	for _, m := range out {
		if m["id"] == id {
			return m
		}
	}
	return nil
}

func TestHandshakeAndTools(t *testing.T) {
	out := run(t, strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_access","arguments":{"capability":"github.repo.read","target":"o/r"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_access","arguments":{"capability":"denied"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":6,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
	}, "\n"))
	if len(out) != 6 {
		t.Fatalf("%d responses: %v", len(out), out)
	}
	if v := byID(out, 1)["result"].(map[string]any)["protocolVersion"]; v != "2025-06-18" {
		t.Errorf("negotiated %v", v)
	}
	if tl := byID(out, 2)["result"].(map[string]any)["tools"].([]any); len(tl) != 3 {
		t.Errorf("%d tools", len(tl))
	}
	ok := byID(out, 3)["result"].(map[string]any)
	if ok["isError"] != false || !strings.Contains(ok["content"].([]any)[0].(map[string]any)["text"].(string), "vogt_p_x") {
		t.Errorf("request_access = %v", ok)
	}
	if denied := byID(out, 4)["result"].(map[string]any); denied["isError"] != true {
		t.Errorf("denied = %v", denied)
	}
	if e := byID(out, 5)["error"].(map[string]any); e["code"] != float64(-32601) {
		t.Errorf("unknown method = %v", e)
	}
	if byID(out, 6)["result"] == nil {
		t.Error("stateless ping without initialize failed")
	}
}

func TestBatchAndGarbage(t *testing.T) {
	out := run(t, `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"ping"}]`+"\n{not json\n")
	if len(out) != 3 || byID(out, 1) == nil || byID(out, 2) == nil {
		t.Fatalf("%d outputs", len(out))
	}
}
