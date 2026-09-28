# Vogt

Vogt keeps credentials away from AI agents. An agent asks Vogt for access.
You approve it with Touch ID, or with a passkey on your phone. The agent then
calls the provider through Vogt's local proxy, which adds the real key for a
few minutes. The agent never holds the key.

## How it fits together

- **Daemon** (`vogt daemon`): runs as its own OS user and owns the vault,
  the policy, the audit log and the proxy.
- **Helper** (`helper/`): a menu-bar app in your login session. It holds the
  Secure Enclave keys, shows each request and asks for Touch ID.
- **Agent side** (`vogt run`, `vogt grant`, `vogt exec`, `vogt mcp`): starts a
  session, asks for grants and points tools at the proxy.

A grant ends when the agent surrenders it, when its time runs out, when the
session ends, or when you hit the kill switch (`vogt revoke --all` or the
menu bar). The proxy stops accepting the token at once, and Vogt revokes the
upstream credential where the provider allows it.

## Providers

| Provider | How Vogt gets a credential | Modes |
| --- | --- | --- |
| Hugging Face, DeepSeek, OpenAI, Anthropic, Stripe, Slack | Stored API key, added to each proxied request | proxy |
| GitHub | GitHub App installation token for one repository, revoked when the grant ends | proxy, direct |
| Any OAuth 2.0 API | Access token from a stored refresh token | proxy |
| Postgres | A login role per grant with only the policy's privileges, dropped at the end | direct |

Hugging Face and DeepSeek have no API for creating keys on ordinary plans,
so Vogt stores one key and never lets it leave the proxy. Tools that cannot
change their base URL can use `HTTPS_PROXY` instead. Vogt then terminates TLS
with a local CA that is name-constrained to the hosts in your policy.

## Security choices

- Go code uses the standard library only: no third-party modules, no cgo.
  The helper uses Apple frameworks only.
- Secrets are sealed with AES-256-GCM. Their keys are wrapped with hybrid
  post-quantum HPKE (ML-KEM-768 + P-256) to Secure Enclave keys. High-tier
  secrets need Touch ID for every grant; low-tier ones need one tap per login.
- Approvals and the policy carry two signatures, ML-DSA-65 and ECDSA P-256,
  and both must verify.
- Every grant, approval, proxied call and revocation goes into a
  hash-chained audit log with signed checkpoints.
- Secrets in the daemon live in locked, guard-paged memory and are wiped
  after use.

## Getting started

Needs Go 1.27 or later and macOS 26 for the helper.

```sh
go build -o vogt ./cmd/vogt
./vogt install --user "$USER"          # prints the plan; add --apply with sudo
helper/build.sh                        # builds "Vogt Helper.app"
"helper/build/Vogt Helper.app/Contents/MacOS/VogtHelper" --keys
sudo vogt pair <bundle printed above>
vogt policy init > policy.json         # edit, then:
vogt policy load policy.json           # approve with Touch ID
vogt secret add deepseek --provider static --tier high < key.txt
vogt run -- claude                     # the agent runs in a session
```

Inside the session the agent runs `vogt grant deepseek.api` or
`vogt exec deepseek.api default -- ./script`, or uses the tools from
`vogt mcp`.

For development without installing anything: `vogt daemon --dev` keeps its
state in `~/.vogt-dev`, and `vogt helper-dev` is a software helper. Neither
protects you from an agent running as the same user.

## Checks

```sh
scripts/ci.sh      # stdlib-only check, gofmt, go fix, vet, tests (with a
                   # goroutine-leak check), race, fuzzing, Linux and FIPS
                   # builds, reproducible build, self-test
helper/e2e.sh      # Swift helper with real Secure Enclave keys against a
                   # dev daemon (macOS 26, local only)
```

The design spec and implementation plan are in the project's design doc.
