#!/usr/bin/env bash
# Out-of-process liveness probe for the MCP Agent Mail HTTP service.
#
# This intentionally runs outside the server process. An in-process asyncio
# task cannot observe a blocked event loop, which is the mz67v failure mode.

set -uo pipefail

readonly PROBE_ID="agent_mail_liveness"
readonly TIMEOUT_SECONDS="${MCP_AGENT_MAIL_LIVENESS_TIMEOUT_SECONDS:-5}"
readonly PROBE_URL="${MCP_AGENT_MAIL_LIVENESS_URL:-http://127.0.0.1:8765/health/liveness}"
readonly EXPECTED_BODY='{"status":"alive"}'

alarm() {
  local reason="$1"
  local request_exit="${2:-none}"
  printf '%s.alarm timestamp=%s reason=%s timeout_seconds=%s request_exit=%s target=loopback\n' \
    "$PROBE_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" "$TIMEOUT_SECONDS" "$request_exit" >&2
}

if [[ ! "$TIMEOUT_SECONDS" =~ ^([1-9]|[12][0-9]|30)$ ]]; then
  alarm "invalid_timeout"
  exit 2
fi

case "$PROBE_URL" in
  http://127.0.0.1:*/health/liveness | http://localhost:*/health/liveness | http://\[::1\]:*/health/liveness) ;;
  *)
    alarm "invalid_loopback_url"
    exit 2
    ;;
esac

curl_bin="$(command -v curl 2>/dev/null || true)"
timeout_bin="$(command -v timeout 2>/dev/null || true)"
if [[ -z "$curl_bin" ]]; then
  alarm "curl_missing"
  exit 2
fi
if [[ -z "$timeout_bin" ]]; then
  alarm "timeout_missing"
  exit 2
fi

response="$({
  "$timeout_bin" --foreground --signal KILL "${TIMEOUT_SECONDS}s" \
    "$curl_bin" \
      --silent \
      --show-error \
      --fail-with-body \
      --noproxy '*' \
      --connect-timeout "$TIMEOUT_SECONDS" \
      --max-time "$TIMEOUT_SECONDS" \
      --retry 0 \
      --header 'Accept: application/json' \
      -- "$PROBE_URL"
} 2>/dev/null)"
request_exit=$?

if [[ "$request_exit" -ne 0 ]]; then
  if [[ "$request_exit" -eq 28 || "$request_exit" -eq 124 || "$request_exit" -eq 137 ]]; then
    alarm "deadline_exceeded" "$request_exit"
  else
    alarm "request_failed" "$request_exit"
  fi
  exit 1
fi

if [[ "$response" != "$EXPECTED_BODY" ]]; then
  alarm "unexpected_response" 0
  exit 1
fi

exit 0
