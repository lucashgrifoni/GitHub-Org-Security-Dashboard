"""A missing advisory response must not produce a successful audit gate."""

import os
import subprocess
import sys
from pathlib import Path


def test_missing_dependency_advisory_blocks_audit(tmp_path: Path) -> None:
    guard = tmp_path / "guard"
    guard.mkdir()
    (guard / "sitecustomize.py").write_text(
        """import socket
import requests

def deny_network(*args, **kwargs):
    raise AssertionError("Network access is forbidden in this regression")

socket.socket.connect = deny_network
socket.socket.connect_ex = deny_network
socket.create_connection = deny_network
socket.getaddrinfo = deny_network

def unavailable_advisory(self, url, *args, **kwargs):
    response = requests.Response()
    response.status_code = 404
    response.url = url
    response._content = b'{}'
    return response

requests.Session.get = unavailable_advisory
""",
        encoding="utf-8",
    )
    audit_script = Path(__file__).resolve().parents[1] / "scripts" / "audit_environment.py"
    harness = """import runpy
import sys
from types import SimpleNamespace

scope = runpy.run_path(sys.argv[1])
audit_main = scope["main"]
audit_main.__globals__["distributions"] = lambda: [SimpleNamespace(
    metadata={"Name": "ghorgsec-audit-unavailable-fixture"}, version="1.0.0"
)]
raise SystemExit(audit_main())
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(guard)
    result = subprocess.run(
        [sys.executable, "-c", harness, str(audit_script)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=30,
        check=False,
    )
    output = result.stdout + result.stderr
    assert "could not be audited" in output
    assert "Traceback" not in output
    assert result.returncode != 0, "A skipped dependency must block the audit gate"
