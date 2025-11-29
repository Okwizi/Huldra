"""Python Provider."""

import json
import subprocess
from typing import List

from huldra.core.types import Vulnerability
from huldra.providers.base import Provider


class PythonPipAudit(Provider):
    """Provider for Python vulnerabilities."""

    def audit(self) -> List[Vulnerability] | list:
        """Audit Python vulnerabilities.

        The format of the json from `pip-audit` as of version `2.9.0` is:
        {
            "dependencies": [
                {
                    "name": "dependency_name",
                    "version": "dependency_version",
                    "vulns": [
                        {
                            "id": "vulnerability_id",
                            "fix_versions": [
                                "fixed_version_1",
                                "fixed_version_2"
                            ],
                            "aliases": ["alias_1", "alias_2"],
                            "description": "vulnerability_description",
                        }
                    ],
                }
                ### LIST OF DEPENDENCIES CONTINUES ###
            ]
            ### END OF JSON ###
        }

        Definition of key values:
        - dependencies: A list of dependencies in the current project.
        - name: The name of the dependency.
        - version: The version of the dependency currently installed.
        - vulns: A list of vulnerabilities found within the dependency.
        - id: The vulnerability identifier,
            usually in the format of `PYSEC-YYYY-NNN`.
        - fix_versions: A list of fixed versions of the dependency.
        - aliases: A list of aliases for the vulnerability,
            usually in the format of `CVE-YYYY-NNNNN`.
        - description: The vulnerability description.

        If the tool does not find any vulnerabilities,
        it will not interact with the LLM and return an empty list.

        If vulnerabilities are found, the tool will interact with the LLM
        and return a list of vulnerabilities of type `Vulnerability`."""
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json"],
                capture_output=True,
                text=True,
                check=False,
            )

            if result.stderr == "No known vulnerabilities found\n":
                # when no vulnerabilities are found
                return []

            data = json.loads(result.stdout)
            vulnerabilities = []

            for dependency in data["dependencies"]:
                if len(dependency["vulns"]) == 0:
                    # even though we handled a case where no vulnerabilities
                    # are found, we still need to handle a case where
                    # some dependencies have no vulnerabilities here..
                    continue
                for vulnerability in dependency["vulns"]:
                    vulnerabilities.append(
                        Vulnerability(
                            id=vulnerability.get("id"),
                            package=dependency.get("name"),
                            current_version=dependency.get("version"),
                            fixed_versions=vulnerability.get(
                                "fix_versions", [None]
                            ),
                            aliases=vulnerability.get("aliases", [None]),
                            description=vulnerability.get("description"),
                        )
                    )
            return vulnerabilities

        except json.JSONDecodeError as e:
            # when stdout is not valid json
            raise ValueError("Invalid JSON from pip-audit") from e

    def apply_fix(self, command: str) -> bool:
        """Apply a fix to a vulnerability."""
        try:
            subprocess.run(command, shell=True, check=True)
            return True
        except subprocess.CalledProcessError as e:
            raise ValueError("Failed to apply fix") from e
