from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROBE = PROJECT_ROOT / "scripts" / "probe_agent_mail_liveness.sh"
PROBE_SERVICE = PROJECT_ROOT / "deploy" / "systemd" / "mcp-agent-mail-liveness-probe.service"
PROBE_TIMER = PROJECT_ROOT / "deploy" / "systemd" / "mcp-agent-mail-liveness-probe.timer"


def _fake_curl(tmp_path: Path) -> tuple[Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True)
    args_file = tmp_path / "curl-args.txt"
    curl = fake_bin / "curl"
    curl.write_text(
        """#!/usr/bin/env bash
set -uo pipefail
printf '%s\\n' "$@" > "$PROBE_TEST_ARGS_FILE"
if [[ "${PROBE_TEST_SLEEP_SECONDS:-0}" != "0" ]]; then
  exec sleep "$PROBE_TEST_SLEEP_SECONDS"
fi
printf '%s' "$PROBE_TEST_BODY"
exit "${PROBE_TEST_EXIT:-0}"
""",
        encoding="utf-8",
    )
    curl.chmod(0o755)
    return fake_bin, args_file


def _run_probe(
    tmp_path: Path,
    *,
    body: str = '{"status":"alive"}',
    request_exit: int = 0,
    sleep_seconds: int = 0,
    timeout_seconds: int = 5,
    url: str | None = None,
    subprocess_timeout: float = 8.0,
) -> tuple[subprocess.CompletedProcess[str], list[str], float]:
    fake_bin, args_file = _fake_curl(tmp_path)
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "MCP_AGENT_MAIL_LIVENESS_TIMEOUT_SECONDS": str(timeout_seconds),
            "PROBE_TEST_ARGS_FILE": str(args_file),
            "PROBE_TEST_BODY": body,
            "PROBE_TEST_EXIT": str(request_exit),
            "PROBE_TEST_SLEEP_SECONDS": str(sleep_seconds),
        }
    )
    if url is not None:
        env["MCP_AGENT_MAIL_LIVENESS_URL"] = url
    started = time.monotonic()
    result = subprocess.run(
        [str(PROBE)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=subprocess_timeout,
    )
    elapsed = time.monotonic() - started
    args = args_file.read_text(encoding="utf-8").splitlines() if args_file.exists() else []
    return result, args, elapsed


def test_probe_accepts_only_the_expected_fast_liveness_response(tmp_path: Path) -> None:
    result, args, _elapsed = _run_probe(tmp_path)

    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
    assert args == [
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--noproxy",
        "*",
        "--connect-timeout",
        "5",
        "--max-time",
        "5",
        "--retry",
        "0",
        "--header",
        "Accept: application/json",
        "--",
        "http://127.0.0.1:8765/health/liveness",
    ]


def test_probe_deadline_is_external_and_emits_a_stable_alarm(tmp_path: Path) -> None:
    result, _args, elapsed = _run_probe(
        tmp_path,
        sleep_seconds=10,
        timeout_seconds=1,
        subprocess_timeout=4,
    )

    assert result.returncode == 1
    assert elapsed < 3
    assert "agent_mail_liveness.alarm" in result.stderr
    assert "reason=deadline_exceeded" in result.stderr
    assert "timeout_seconds=1" in result.stderr


def test_probe_rejects_wrong_payload_and_request_failures(tmp_path: Path) -> None:
    wrong_body, _args, _elapsed = _run_probe(tmp_path / "wrong-body", body='{"status":"ready"}')
    assert wrong_body.returncode == 1
    assert "reason=unexpected_response" in wrong_body.stderr

    request_failure, _args, _elapsed = _run_probe(tmp_path / "request-failure", request_exit=7)
    assert request_failure.returncode == 1
    assert "reason=request_failed" in request_failure.stderr
    assert "request_exit=7" in request_failure.stderr


def test_probe_refuses_unbounded_or_non_loopback_configuration(tmp_path: Path) -> None:
    fake_bin, args_file = _fake_curl(tmp_path)
    base_env = os.environ.copy()
    base_env.update({"PATH": f"{fake_bin}:/usr/bin:/bin", "PROBE_TEST_ARGS_FILE": str(args_file)})

    invalid_timeout_env = base_env | {"MCP_AGENT_MAIL_LIVENESS_TIMEOUT_SECONDS": "31"}
    invalid_timeout = subprocess.run(
        [str(PROBE)], check=False, capture_output=True, text=True, env=invalid_timeout_env, timeout=2
    )
    assert invalid_timeout.returncode == 2
    assert "reason=invalid_timeout" in invalid_timeout.stderr

    remote_url_env = base_env | {"MCP_AGENT_MAIL_LIVENESS_URL": "https://example.com/health/liveness"}
    remote_url = subprocess.run(
        [str(PROBE)], check=False, capture_output=True, text=True, env=remote_url_env, timeout=2
    )
    assert remote_url.returncode == 2
    assert "reason=invalid_loopback_url" in remote_url.stderr
    assert not args_file.exists()


def test_probe_rejects_userinfo_query_fragment_and_invalid_ports_before_curl(tmp_path: Path) -> None:
    invalid_urls = [
        "http://127.0.0.1:8765@evil.example:80/health/liveness",
        "http://localhost:8765@evil.example:80/health/liveness",
        "http://[::1]:8765@evil.example:80/health/liveness",
        "http://127.0.0.1:8765/health/liveness?target=evil",
        "http://localhost:8765/health/liveness#fragment",
        "http://127.0.0.1:0/health/liveness",
        "http://127.0.0.1:65536/health/liveness",
        "http://127.0.0.1:not-a-port/health/liveness",
    ]

    for index, url in enumerate(invalid_urls):
        case_dir = tmp_path / str(index)
        result, args, _elapsed = _run_probe(case_dir, url=url)
        assert result.returncode == 2, url
        assert "reason=invalid_loopback_url" in result.stderr, url
        assert args == [], url


def test_probe_accepts_only_numeric_loopback_port_boundaries(tmp_path: Path) -> None:
    valid_urls = [
        "http://127.0.0.1:1/health/liveness",
        "http://localhost:65535/health/liveness",
        "http://[::1]:8765/health/liveness",
    ]

    for index, url in enumerate(valid_urls):
        result, args, _elapsed = _run_probe(tmp_path / str(index), url=url)
        assert result.returncode == 0, url
        assert args[-1] == url


def test_systemd_timer_runs_the_out_of_process_probe_with_bounded_failure_visibility() -> None:
    service = PROBE_SERVICE.read_text(encoding="utf-8")
    timer = PROBE_TIMER.read_text(encoding="utf-8")

    assert "ExecStart=/opt/mcp-agent-mail/scripts/probe_agent_mail_liveness.sh" in service
    assert [line for line in service.splitlines() if line.startswith("User=")] == ["User=appuser"]
    assert [line for line in service.splitlines() if line.startswith("Group=")] == ["Group=appuser"]
    assert "MCP_AGENT_MAIL_LIVENESS_TIMEOUT_SECONDS=5" in service
    assert "TimeoutStartSec=35s" in service
    assert "StandardError=journal" in service
    assert "SyslogIdentifier=mcp-agent-mail-liveness-probe" in service
    assert "OnBootSec=1min" in timer
    assert "OnUnitActiveSec=1min" in timer
    assert "Persistent=true" in timer
    assert "Unit=mcp-agent-mail-liveness-probe.service" in timer


def test_service_deadline_exceeds_every_timeout_the_probe_accepts(tmp_path: Path) -> None:
    probe = PROBE.read_text(encoding="utf-8")
    service = PROBE_SERVICE.read_text(encoding="utf-8")
    accepted_max_match = re.search(r'^readonly MAX_TIMEOUT_SECONDS="([0-9]+)"$', probe, re.MULTILINE)
    service_ceiling_match = re.search(r"^TimeoutStartSec=([0-9]+)s$", service, re.MULTILINE)

    assert accepted_max_match is not None
    assert service_ceiling_match is not None
    accepted_max = int(accepted_max_match.group(1))
    service_ceiling = int(service_ceiling_match.group(1))
    assert accepted_max < service_ceiling

    accepted, _args, _elapsed = _run_probe(
        tmp_path,
        timeout_seconds=accepted_max,
    )
    assert accepted.returncode == 0
