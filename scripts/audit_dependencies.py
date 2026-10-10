"""Run pip-audit and explicitly audit official CPU Torch's upstream version.

PyPI does not publish +cpu local-version wheels; never silently treat that skip as audited.
"""

import json
import os
import subprocess  # nosec B404
import sys
import tempfile
from importlib.metadata import distribution
from importlib.metadata import version as installed_version
from pathlib import Path
from urllib.parse import unquote, urlsplit

from packaging.version import Version


def run_audit(args: list[str], output: Path, cache: Path) -> dict:
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "--progress-spinner",
        "off",
        "--format",
        "json",
        "--output",
        str(output),
        "--cache-dir",
        str(cache),
        *args,
    ]
    # Fixed executable/module and argument list; no shell or user-supplied executable.
    result = subprocess.run(command, check=False)  # nosec B603
    if result.returncode not in {0, 1} or not output.exists():
        raise RuntimeError("pip-audit did not complete")
    data = json.loads(output.read_text())
    if any(d.get("vulns") for d in data["dependencies"]):
        raise RuntimeError("Known dependency vulnerabilities found; inspect pip-audit output")
    return data


def main() -> None:
    cache = Path(os.getenv("CTIG_AUDIT_CACHE", ".cache/pip-audit"))
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ctig-audit-") as temp:
        root = Path(temp)
        data = run_audit(["--skip-editable"], root / "installed.json", cache)
        skipped = [d for d in data["dependencies"] if d.get("skip_reason")]
        normalized = []
        project_exclusions = []
        for dependency in skipped:
            if dependency["name"] == "defensive-ctig":
                direct = json.loads(
                    distribution("defensive-ctig").read_text("direct_url.json") or "{}"
                )
                url = urlsplit(direct.get("url", ""))
                if (
                    url.scheme == "file"
                    and direct.get("dir_info", {}).get("editable")
                    and Path(unquote(url.path)).resolve() == Path.cwd().resolve()
                ):
                    project_exclusions.append(
                        "defensive-ctig: verified editable current project; source checked by Bandit/tests"
                    )
                    continue
            version_text = installed_version(dependency["name"])
            if dependency["name"] != "torch" or not version_text.endswith("+cpu"):
                raise RuntimeError(f"Unaudited dependency: {dependency['name']}")
            version = Version(version_text).base_version
            req = root / "torch.txt"
            req.write_text("torch==" + version + "\n")
            base = run_audit(
                ["-r", str(req), "--no-deps", "--disable-pip"], root / "torch.json", cache
            )
            if any(d.get("skip_reason") for d in base["dependencies"]):
                raise RuntimeError("Upstream PyTorch version could not be audited")
            normalized.append(
                {
                    "package": "torch",
                    "installed": version_text,
                    "audited_upstream": version,
                    "caveat": "Known advisories for upstream release; local CPU artifact is downloaded from the official verified CPU index.",
                }
            )
        summary = {
            "status": "passed",
            "installed_dependencies": len(data["dependencies"]),
            "known_vulnerabilities": 0,
            "own_project_exclusions": project_exclusions,
            "normalized_cpu_versions": normalized,
            "unexpected_skips": 0,
        }
        report = Path("reports/local/dependency-audit.json")
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
