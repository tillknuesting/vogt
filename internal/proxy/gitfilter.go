package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"vogt/internal/policy"
)

// maxCommands bounds the ref-update section of a push we are willing to read.
const maxCommands = 1 << 20

// filterPush checks the ref updates at the start of a git-receive-pack
// request against the denied refs. It leaves r.Body readable from the start,
// decompressed if the client gzipped it.
func filterPush(r *http.Request, denied []string) error {
	var body io.Reader = r.Body
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			return errors.New("git: bad gzip body")
		}
		body = zr
		r.Header.Del("Content-Encoding")
		r.ContentLength = -1
		r.Header.Del("Content-Length")
	}
	br := bufio.NewReader(body)
	var seen bytes.Buffer
	for {
		line, flush, err := readPktLine(br, &seen)
		if err != nil {
			return err
		}
		if flush {
			break
		}
		cmd := line
		if i := bytes.IndexByte(cmd, 0); i >= 0 {
			cmd = cmd[:i] // capabilities follow the first command
		}
		f := strings.Fields(string(cmd))
		if len(f) != 3 {
			return fmt.Errorf("git: malformed ref update %q", truncateStr(string(cmd), 80))
		}
		ref := f[2]
		for _, d := range denied {
			if policy.Match(d, ref) {
				return fmt.Errorf("git: pushing to %s is not allowed by policy", ref)
			}
		}
		if seen.Len() > maxCommands {
			return errors.New("git: ref update section too large")
		}
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(&seen, br), r.Body}
	return nil
}

// readPktLine reads one pkt-line, copying its raw bytes into seen.
func readPktLine(br *bufio.Reader, seen *bytes.Buffer) (payload []byte, flush bool, err error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, false, errors.New("git: truncated push")
	}
	seen.Write(hdr[:])
	n, err := strconv.ParseUint(string(hdr[:]), 16, 16)
	if err != nil {
		return nil, false, errors.New("git: bad pkt-line length")
	}
	if n == 0 {
		return nil, true, nil
	}
	if n < 4 {
		return nil, false, errors.New("git: bad pkt-line length")
	}
	payload = make([]byte, n-4)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, false, errors.New("git: truncated push")
	}
	seen.Write(payload)
	return bytes.TrimSuffix(payload, []byte("\n")), false, nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
