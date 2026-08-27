"""Fleet authentication: bearer-token principals and caller-identity binding.

Addresses bd fba-restock-planner-xlhjj: the HTTP transport accepted any
localhost caller with no credential, and every identity-carrying tool argument
(``sender_name``, ``agent_name``, ...) was a caller-chosen string. This module
gives the HTTP layer a resolved :class:`Principal` per request and a single
policy table (:data:`CALLER_IDENTITY_PARAMS`) describing which tool arguments
assert the *caller's own* identity, so the middleware can refuse a credential
whose bound agent does not match what the request claims to be.

Token registry
--------------
Per-agent tokens live in a JSON registry file (``MAIL_AGENT_TOKENS_PATH``)
keyed by ``sha256(token)`` — the plaintext token is never stored server-side.
An entry with ``agent_name: null`` is *unclaimed*: it may only call
``register_agent``, and the registration claims it (trust-on-first-use), which
is how launcher-minted tokens bind to server-generated agent names.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "CALLER_IDENTITY_PARAMS",
    "Principal",
    "TokenRegistry",
    "claim_agent_token",
    "evaluate_identity_claims",
    "get_request_principal",
    "hash_token",
]


@dataclass(frozen=True)
class Principal:
    """The authenticated caller of one HTTP request.

    kind:
      - ``agent``     — per-agent token bound to ``agent_name``
      - ``unclaimed`` — minted per-agent token not yet bound to a name
      - ``shared``    — a fleet-wide shared bearer token (no agent binding)
      - ``localhost`` — no credential, admitted by allow_localhost_unauthenticated
    """

    kind: str
    agent_name: Optional[str] = None
    token_sha256: Optional[str] = None

    @property
    def is_bound(self) -> bool:
        return self.kind == "agent" and bool(self.agent_name)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def unclaimed_token_expired(
    entry: dict[str, Any], ttl_seconds: int, now: datetime
) -> bool:
    """True iff an UNCLAIMED registry entry is older than the TTL.

    An unclaimed per-agent token is a bearer credential that can claim any
    identity at its first register_agent (bd u5yak). Bounding its lifetime
    limits the window in which a minted-but-never-launched token is useful to
    anyone who reads it. ttl_seconds <= 0 disables expiry. A bound entry
    (``agent_name`` set) never expires here — its lifetime is managed by
    revocation. A missing/unparseable ``created_ts`` is treated as expired
    (fail closed): a token we cannot age is not one we should keep honoring.
    """
    if ttl_seconds <= 0:
        return False
    if entry.get("agent_name"):
        return False
    created_raw = entry.get("created_ts")
    if not isinstance(created_raw, str) or not created_raw:
        return True
    try:
        created = datetime.fromisoformat(created_raw)
    except ValueError:
        return True
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (now - created).total_seconds() > ttl_seconds


# Tool argument(s) that assert the CALLER's own identity. Arguments naming
# other agents (whois.agent_name, send_message.to, request_contact.to_agent)
# are deliberately absent — only self-assertions are bound to the credential.
CALLER_IDENTITY_PARAMS: dict[str, tuple[str, ...]] = {
    "send_message": ("sender_name",),
    "reply_message": ("sender_name",),
    "register_agent": ("name",),
    "fetch_inbox": ("agent_name",),
    "fetch_inbox_product": ("agent_name",),
    "mark_message_read": ("agent_name",),
    "acknowledge_message": ("agent_name",),
    "list_contacts": ("agent_name",),
    "set_contact_policy": ("agent_name",),
    "request_contact": ("from_agent",),
    "respond_contact": ("to_agent",),
    "file_reservation_paths": ("agent_name",),
    "release_file_reservations": ("agent_name",),
    "renew_file_reservations": ("agent_name",),
    "force_release_file_reservation": ("agent_name",),
    "macro_start_session": ("agent_name",),
    "macro_prepare_thread": ("agent_name",),
    "macro_file_reservation_cycle": ("agent_name",),
    "macro_contact_handshake": ("requester",),
    "acquire_build_slot": ("agent_name",),
    "renew_build_slot": ("agent_name",),
    "release_build_slot": ("agent_name",),
}


class TokenRegistry:
    """mtime-cached, thread-safe reader/writer for the agent-token registry.

    File format (version 1)::

        {"version": 1,
         "tokens": {"<sha256hex>": {"agent_name": "BlueLake" | null,
                                     "created_ts": "...", "claimed_ts": "..." | null,
                                     "revoked": false, "note": ""}}}
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_stat: tuple[int, int] | None = None

    @property
    def path(self) -> Path:
        return self._path

    def _load_locked(self) -> dict[str, dict[str, Any]]:
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            self._cache = {}
            self._cache_stat = None
            return self._cache
        key = (stat.st_mtime_ns, stat.st_size)
        if self._cache_stat == key:
            return self._cache
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            tokens = data.get("tokens", {})
            self._cache = tokens if isinstance(tokens, dict) else {}
        except Exception:
            # A corrupt registry must fail CLOSED for per-agent tokens (they
            # stop resolving -> 401), never open.
            self._cache = {}
        self._cache_stat = key
        return self._cache

    def lookup_sha(self, token_sha256: str) -> Optional[dict[str, Any]]:
        with self._lock:
            entry = self._load_locked().get(token_sha256)
            return dict(entry) if isinstance(entry, dict) else None

    def entries(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._load_locked().items() if isinstance(v, dict)}

    def _write_locked(self, tokens: dict[str, dict[str, Any]]) -> None:
        payload = {"version": 1, "tokens": tokens}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            self._path.parent.chmod(0o700)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(self._path)
        self._cache_stat = None

    def _mutate(self, fn) -> Any:  # type: ignore[no-untyped-def]
        """Run ``fn(tokens_dict)`` under an inter-process file lock and persist."""
        from filelock import FileLock

        lock = FileLock(str(self._path) + ".lock")
        with lock, self._lock:
            self._cache_stat = None  # force re-read under the lock
            tokens = {k: dict(v) for k, v in self._load_locked().items() if isinstance(v, dict)}
            result = fn(tokens)
            self._write_locked(tokens)
            return result

    def mint(self, agent_name: Optional[str] = None, note: str = "") -> tuple[str, str]:
        """Create a token (optionally pre-bound to ``agent_name``); return (plaintext, sha256)."""
        token = secrets.token_hex(32)
        sha = hash_token(token)
        now = datetime.now(timezone.utc).isoformat()

        def _add(tokens: dict[str, dict[str, Any]]) -> None:
            tokens[sha] = {
                "agent_name": agent_name or None,
                "created_ts": now,
                "claimed_ts": now if agent_name else None,
                "revoked": False,
                "note": note,
            }

        self._mutate(_add)
        return token, sha

    def claim(self, token_sha256: str, agent_name: str) -> None:
        """Bind an unclaimed token to ``agent_name`` (idempotent for the same name)."""

        def _claim(tokens: dict[str, dict[str, Any]]) -> None:
            entry = tokens.get(token_sha256)
            if entry is None or entry.get("revoked"):
                raise PermissionError("agent token is unknown or revoked")
            bound = entry.get("agent_name")
            if bound is None:
                entry["agent_name"] = agent_name
                entry["claimed_ts"] = datetime.now(timezone.utc).isoformat()
            elif str(bound).lower() != agent_name.lower():
                raise PermissionError(
                    f"agent token is already bound to '{bound}' and cannot claim '{agent_name}'"
                )

        self._mutate(_claim)

    def revoke(self, *, sha_prefix: Optional[str] = None, agent_name: Optional[str] = None) -> int:
        def _revoke(tokens: dict[str, dict[str, Any]]) -> int:
            count = 0
            for sha, entry in tokens.items():
                match = (sha_prefix and sha.startswith(sha_prefix)) or (
                    agent_name and str(entry.get("agent_name") or "").lower() == agent_name.lower()
                )
                if match and not entry.get("revoked"):
                    entry["revoked"] = True
                    count += 1
            return count

        return int(self._mutate(_revoke))


def evaluate_identity_claims(
    principal: Principal,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    strict: bool,
) -> Optional[str]:
    """Return a refusal reason, or None when the call is admissible.

    - bound agent token: every present caller-identity argument must equal the
      bound name (case-insensitive). Absent/None arguments are left to the tool
      layer (register_agent defaults them to the bound name).
    - unclaimed token: only register_agent among identity-asserting tools.
    - shared/localhost: unrestricted in ``legacy`` mode (migration window);
      refused for identity-asserting tools in ``strict`` mode.
    """
    params = CALLER_IDENTITY_PARAMS.get(tool_name)
    if not params:
        return None
    if principal.kind == "unclaimed":
        if tool_name == "register_agent":
            return None
        return (
            "unclaimed agent token may only call register_agent to bind its identity "
            f"(attempted '{tool_name}')"
        )
    if principal.is_bound:
        assert principal.agent_name is not None
        for param in params:
            value = arguments.get(param)
            if isinstance(value, str) and value.strip() and value.strip().lower() != principal.agent_name.lower():
                return (
                    f"identity mismatch: credential is bound to '{principal.agent_name}' "
                    f"but {tool_name}.{param} claims '{value.strip()}'"
                )
        return None
    # shared / localhost principals
    if strict:
        return (
            f"strict sender binding is enabled: shared credentials may not call the "
            f"identity-asserting tool '{tool_name}'; use a per-agent token"
        )
    return None


def get_request_principal() -> Optional[Principal]:
    """Return the Principal the HTTP middleware attached to the current request.

    Returns None outside an HTTP request context (stdio transport, tests that
    call tools directly) — callers must treat that as *unattested*, not as an
    error, so non-HTTP transports keep working.
    """
    try:
        from fastmcp.server.dependencies import get_http_request

        request = get_http_request()
    except Exception:
        return None
    if request is None:
        return None
    principal = getattr(request.state, "mail_principal", None)
    return principal if isinstance(principal, Principal) else None


def claim_agent_token(registry_path: Path, token_sha256: str, agent_name: str) -> None:
    TokenRegistry(registry_path).claim(token_sha256, agent_name)
