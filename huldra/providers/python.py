import json
import subprocess
from typing import List

from huldra.core.types import Vulnerability
from huldra.providers.base import Provider


class PythonPipAudit(Provider):
    def audit(self) -> List[Vulnerability]:
        try:
            # Run pip-audit and get JSON output
            result = subprocess.run(
                ["pip-audit", "--format=json"],
                capture_output=True,
                text=True,
                check=False,  # pip-audit returns non-zero exit code if vulns found
            )

            if not result.stdout:
                return []

            data = json.loads(result.stdout)
            vulnerabilities = []

            # Parse pip-audit JSON output (simplified for scaffolding)
            if "dependencies" in data:
                for dep in data["dependencies"]:
                    if "vulns" in dep:
                        for vuln in dep["vulns"]:
                            vulnerabilities.append(
                                Vulnerability(
                                    id=vuln.get("id", "UNKNOWN"),
                                    package=dep.get("name", "UNKNOWN"),
                                    current_version=dep.get("version", "UNKNOWN"),
                                    fixed_version=vuln.get("fix_versions", [None])[0],
                                    description=vuln.get("description", ""),
                                )
                            )
            return vulnerabilities

        except FileNotFoundError:
            print("Error: pip-audit not found. Please install it.")
            return []
        except json.JSONDecodeError:
            print("Error: Failed to parse pip-audit output.")
            return []

    def apply_fix(self, command: str) -> bool:
        try:
            subprocess.run(command, shell=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
