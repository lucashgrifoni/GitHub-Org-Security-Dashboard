"""Exercise the installed wheel with local fixtures and network access denied."""

import json
import os
import socket
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import NoReturn


def deny_network(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("The installed offline CLI attempted to use the network")


def main() -> None:
    fixture = Path(sys.argv[1]).resolve()
    installed = distribution("ghorgsec")
    marker = Path(str(installed.locate_file("ghorgsec/py.typed")))
    if not marker.is_file():
        raise AssertionError("The installed wheel does not include py.typed")

    # sitecustomize is loaded in each CLI subprocess, before the package imports.
    with TemporaryDirectory() as directory:
        root = Path(directory)
        guard = root / "sitecustomize.py"
        guard.write_text(
            "import socket\n"
            "def deny(*args, **kwargs):\n"
            "    raise AssertionError('offline CLI attempted network access')\n"
            "socket.socket.connect = deny\n"
            "socket.socket.connect_ex = deny\n"
            "socket.create_connection = deny\n"
            "socket.getaddrinfo = deny\n",
            encoding="utf-8",
        )
        # Only the guard enters PYTHONPATH; the source tree is never imported.
        environment = dict(os.environ, PYTHONPATH=str(root), PYTHONIOENCODING="utf-8")
        # A canary token must not opt offline commands into authenticated reads.
        environment.update(GH_TOKEN="synthetic-token-canary", GITHUB_TOKEN="")
        entry_point = Path(sys.executable).parent / (
            "ghorgsec.exe" if os.name == "nt" else "ghorgsec"
        )

        def invoke(*arguments: str, module: bool = False) -> subprocess.CompletedProcess[bytes]:
            command = [sys.executable, "-m", "ghorgsec"] if module else [str(entry_point)]
            return subprocess.run(
                [*command, *arguments],
                cwd=root,
                env=environment,
                capture_output=True,
                timeout=30,
                check=False,
            )

        guard_probe = subprocess.run(
            [sys.executable, "-c", "import socket; socket.create_connection(('127.0.0.1', 1))"],
            cwd=root,
            env=environment,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert guard_probe.returncode != 0
        assert b"offline CLI attempted network access" in guard_probe.stderr
        help_result = invoke("--help")
        assert help_result.returncode == 0 and b"report" in help_result.stdout

        for format_name in ("md", "json"):
            arguments = ("report", "--fixture", str(fixture), "--format", format_name)
            stdout = invoke(*arguments)
            target = root / f"report with spaces.{format_name}"
            written = invoke(*arguments, "--output", str(target))
            assert stdout.returncode == written.returncode == 0, (stdout.stderr, written.stderr)
            assert stdout.stdout == target.read_bytes()
            if format_name == "json":
                assert json.loads(stdout.stdout)["collection_mode"] == "fixture_json"
            else:
                assert b"Repository Risk" in stdout.stdout

        stub = invoke(
            "report", "--org", "example-org", "--repo", "api", "--format", "json", module=True
        )
        assert stub.returncode == 0, stub.stderr
        data = json.loads(stub.stdout)
        assert data["repositories"][0]["risk"]["rating"] == "not_assessed"
        assert data["repositories"][0]["risk"]["assessment_status"] == "not_assessed"

        invalid = root / "invalid.json"
        invalid.write_text("{not JSON}", encoding="utf-8")
        result = invoke("report", "--fixture", str(invalid))
        assert result.returncode == 2 and b"Error:" in result.stderr
        conflict = invoke("report", "--fixture", str(fixture), "--org", "another-org")
        assert conflict.returncode == 2

        live_conflict = invoke("report", "--live", "--fixture", str(fixture))
        assert live_conflict.returncode == 2 and b"Error:" in live_conflict.stderr
        assert b"offline CLI attempted network access" not in live_conflict.stderr
        environment["GH_TOKEN"] = ""
        missing_token = invoke("report", "--live", "--user", "example")
        assert missing_token.returncode == 2 and b"token" in missing_token.stderr
        assert b"offline CLI attempted network access" not in missing_token.stderr

        large = root / "large snapshot.json"
        payload = {
            "organization": "example-org",
            "generated_at": "2026-10-05T12:00:00Z",
            "repositories": [
                {
                    "name": f"repo-{index}",
                    "controls": dict.fromkeys(
                        (
                            "branch_protection",
                            "secret_scanning",
                            "code_scanning",
                            "dependabot_alerts",
                        ),
                        "not_collected",
                    ),
                }
                for index in range(1000)
            ],
        }
        large.write_text(json.dumps(payload), encoding="utf-8")
        large_report = invoke("report", "--fixture", str(large), "--format", "json")
        repeated = invoke("report", "--fixture", str(large), "--format", "json")
        assert large_report.returncode == repeated.returncode == 0
        assert large_report.stdout == repeated.stdout
        assert json.loads(large_report.stdout)["summary"]["total_repositories"] == 1000

    socket.create_connection = deny_network
    from ghorgsec import RealCollectionDisabledError, collect_org_security_snapshot

    try:
        collect_org_security_snapshot("example-org", allow_network=True)
    except RealCollectionDisabledError:
        pass
    else:
        raise AssertionError("The installed collector accepted real network collection")

    print(f"Installed wheel smoke: PASS | version={installed.version} | network=denied")


if __name__ == "__main__":
    main()
