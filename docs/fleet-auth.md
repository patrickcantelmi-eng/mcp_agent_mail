# Fleet authentication & sender binding

*(bd `fba-restock-planner-xlhjj`; design: `svswarm/reports/mail-channel-auth-design-20260827.md`)*

Before this change the HTTP transport admitted any localhost caller with no
credential (`HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED` defaulted true), and every
identity-carrying tool argument (`sender_name`, `agent_name`, …) was a
caller-chosen string. Any local process could send fleet mail as any identity.

## Mechanism

Each HTTP request resolves to a **Principal** (`src/mcp_agent_mail/authz.py`):

| Principal | Credential | May assert identity? |
|---|---|---|
| `agent` | per-agent token bound to a name | only its bound name — mismatch → **403** |
| `unclaimed` | minted per-agent token, not yet bound | only `register_agent`, which claims it (TOFU) |
| `shared` | a fleet-wide token (`HTTP_BEARER_TOKEN` / `HTTP_BEARER_TOKENS`) | any (legacy mode) / refused (strict mode) |
| `localhost` | none (`HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED=true`) | same as `shared` |
| `jwt` | token unknown to the fleet layer while `HTTP_JWT_ENABLED=true` — deferred to (and validated/rejected by) the JWT middleware | same as `shared` |

Unknown/revoked tokens and (with localhost-unauth off) missing headers → **401**.

`authz.CALLER_IDENTITY_PARAMS` is the policy table naming, per tool, which
arguments assert the *caller's own* identity. Arguments naming other agents
(`whois.agent_name`, `send_message.to`, `request_contact.to_agent`) are
deliberately absent.

**Attestation:** every stored message carries `sender_attested` — true only
when the sending request's credential was bound to the sender identity.
Exposed in `fetch_inbox` / `search_messages` payloads and the archive `.md`
frontmatter. Authority-class consumers (review verdicts, seat GOs, relays)
should require `sender_attested: true` once their senders are on bound tokens.
Messages sent during the shared-token migration window are stamped `false` —
that is honest, not a bug.

## Configuration

| Env | Default | Meaning |
|---|---|---|
| `HTTP_BEARER_TOKEN` | unset | primary shared token (unchanged) |
| `HTTP_BEARER_TOKENS` | empty | CSV of additional accepted shared tokens (rotation dual-accept) |
| `HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED` | `true` | **set `false` in fleet deployments** |
| `MAIL_AGENT_TOKENS_PATH` | `~/.config/mcp_agent_mail/agent_tokens.json` | registry: `sha256(token) → binding` (plaintext never stored) |
| `MAIL_SENDER_BINDING` | `legacy` | `strict` refuses shared tokens for identity-asserting tools |
| `HTTP_RBAC_DEFAULT_ROLE` | `reader` | **must be `writer` in fleet deployments once localhost-unauth is off** — otherwise RBAC demotes every non-JWT caller to read-only and 403s all sends |

The auth middleware engages when any token source is configured (shared token,
registry file present, or strict mode). A bare dev checkout with none of those
keeps the historical open-localhost behavior.

## Token lifecycle

```bash
# pre-bound (conductor seats, known handles) — plaintext printed ONCE
uv run python -m mcp_agent_mail.cli tokens mint --name LilacStone --note "seat"

# launcher token: unclaimed; the lane's first register_agent binds it
uv run python -m mcp_agent_mail.cli tokens mint --note "lane launch 2026-08-27"

uv run python -m mcp_agent_mail.cli tokens list
uv run python -m mcp_agent_mail.cli tokens revoke --name LilacStone   # fails closed immediately
```

A bound token with `name` omitted at `register_agent` re-registers its own
identity (seat continuity across sessions).

## Migration (fleet)

1. **Deploy dual-accept**: `.env` gets `HTTP_ALLOW_LOCALHOST_UNAUTHENTICATED=false`,
   `HTTP_RBAC_DEFAULT_ROLE=writer`, and the *new* fleet token added via
   `HTTP_BEARER_TOKENS` while the old (burned) token stays in
   `HTTP_BEARER_TOKEN`. Restart. Live lanes keep working; anonymous callers
   stop. Revert = flip the flag back + restart.
2. **Rotate helpers**: `mcpmail.sh` copies read the token from
   `~/.config/mcp_agent_mail/fleet-token` (0600) or `$MCPMAIL_TOKEN` — no
   literals in tracked files. The old committed token is burned (public in git
   history); it keeps authenticating only until step 4.
3. **Bind identities**: mint per-agent tokens (seats first, lanes as launch
   tooling delivers per-lane headers). Sends become `sender_attested`.
4. **Tighten**: drop the burned token from the accepted set; when all senders
   are bound, set `MAIL_SENDER_BINDING=strict`.

## Honest limits (unchanged by this build)

- Same-uid bypass: any process running as the server's uid can write
  `storage.sqlite3` / the git mailbox store directly, bypassing HTTP auth
  entirely, and can read token files. Real agent-vs-agent guarantees require
  the confinement uid split (bd 7zx7b) — until then this is defense against
  accident and against *non-fleet* processes, not against a same-uid attacker.
- Charter arming stays blocked until per-lane bound tokens are live (design
  §3: the gate lifts at P2, not at deploy).
