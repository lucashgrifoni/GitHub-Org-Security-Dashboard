"""Audit installed dependencies without re-resolving their complete version inventory."""

import subprocess
import sys
from importlib.metadata import distributions
from pathlib import Path
from tempfile import TemporaryDirectory


def main() -> int:
    # ghorgsec is built locally and reviewed as source, not fetched from PyPI.
    requirements = sorted(
        f"{package.metadata['Name']}=={package.version}"
        for package in distributions()
        if package.metadata["Name"].lower() != "ghorgsec"
    )
    print(f"Auditing {len(requirements)} installed dependencies; ghorgsec is reviewed as source.",
          flush=True)
    with TemporaryDirectory() as directory:
        pins = Path(directory) / "installed-requirements.txt"
        pins.write_text("\n".join(requirements) + "\n", encoding="utf-8", newline="\n")
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip_audit",
                    "--strict",
                    "--requirement",
                    str(pins),
                    "--no-deps",
                    "--disable-pip",
                    "--cache-dir",
                    str(Path(directory) / "cache"),
                    "--progress-spinner",
                    "off",
                    "--timeout",
                    "10",
                ],
                check=False,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            print("Dependency audit timed out; no clean result was established.", file=sys.stderr)
            return 2
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
