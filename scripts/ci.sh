#!/bin/sh
# CI gates for Vogt. Run from anywhere: scripts/ci.sh
# FUZZTIME sets how long each fuzz target runs (default 5s; 0 skips fuzzing).
set -eu
cd "$(dirname "$0")/.."
export CGO_ENABLED=0
FUZZTIME=${FUZZTIME:-5s}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

step() { printf '\n== %s\n' "$1"; }

step "standard library only"
if grep -q '^require' go.mod; then
	echo "go.mod must not require any module" >&2
	exit 1
fi
if [ "$(go list -m all)" != "vogt" ]; then
	echo "unexpected modules:" >&2
	go list -m all >&2
	exit 1
fi
nonstd=$(go list -deps -test -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... | grep -v '^vogt' || true)
if [ -n "$nonstd" ]; then
	echo "imports outside the standard library:" >&2
	echo "$nonstd" >&2
	exit 1
fi
echo ok

step "gofmt"
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
	echo "$unformatted" >&2
	exit 1
fi
echo ok

step "go vet"
go vet ./...
echo ok

step "go test"
go test -count=1 ./...

if CGO_ENABLED=1 go test -race -count=1 ./... >"$tmp/race.log" 2>&1; then
	step "go test -race"
	echo ok
else
	step "go test -race"
	cat "$tmp/race.log" >&2
	exit 1
fi

if [ "$FUZZTIME" != "0" ]; then
	step "fuzz ($FUZZTIME per target)"
	for pkg in $(go list ./...); do
		for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
			echo "$pkg $target"
			go test -run '^$' -fuzz "^$target\$" -fuzztime "$FUZZTIME" "$pkg" >"$tmp/fuzz.log" 2>&1 || {
				cat "$tmp/fuzz.log" >&2
				exit 1
			}
		done
	done
fi

step "reproducible build"
go build -trimpath -o "$tmp/a" ./cmd/vogt
go build -trimpath -o "$tmp/b" ./cmd/vogt
if ! cmp -s "$tmp/a" "$tmp/b"; then
	echo "two builds differ" >&2
	exit 1
fi
echo ok

step "selftest"
"$tmp/a" selftest
