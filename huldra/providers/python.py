"""Python Provider."""

import json
import subprocess
from typing import List

from huldra.core.types import Vulnerability
from huldra.providers.base import Provider


class PythonPipAudit(Provider):
    """Provider for Python vulnerabilities."""

    def audit(self) -> List[Vulnerability]:
        """Audit Python vulnerabilities."""
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json"],
                capture_output=True,
                text=True,
                check=False,
            )

            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            vulnerabilities = []

            if "dependencies" in data:
                for dep in data["dependencies"]:
                    if "vulns" in dep:
                        for vuln in dep["vulns"]:
                            vulnerabilities.append(
                                Vulnerability(
                                    id=vuln.get("id", "UNKNOWN"),
                                    package=dep.get("name", "UNKNOWN"),
                                    current_version=dep.get(
                                        "version", "UNKNOWN"
                                    ),
                                    fixed_version=vuln.get(
                                        "fix_versions", [None]
                                    )[0],
                                    description=vuln.get("description", ""),
                                )
                            )
            return vulnerabilities

        except FileNotFoundError:
            return []
        except json.JSONDecodeError:
            return []

    def apply_fix(self, command: str) -> bool:
        """Apply a fix to a vulnerability."""
        try:
            subprocess.run(command, shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
