"""The LLM Orchestrator."""

import json
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import List

import tomlkit
from tensorzero import TensorZeroGateway

from huldra.core.types import FixRecommendation, Vulnerability


class Orchestrator(ABC):
    """Orchestrator abstract class."""

    @abstractmethod
    def generate_fix(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[FixRecommendation]:
        """Analyze vulnerabilities and generate fix recommendations."""
        pass


class TensorZeroOrchestrator(Orchestrator):
    """TensorZero orchestrator class."""

    def __init__(self, endpoint: str = "http://localhost:3000") -> None:
        """Initialize TensorZero orchestrator."""
        self.endpoint = endpoint
        self.client = TensorZeroGateway.build_http(gateway_url=self.endpoint)

    def generate_fix(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[FixRecommendation]:
        """Generate fix recommendations."""
        if not vulnerabilities:
            return []

        # Read pyproject.toml
        try:
            with open("pyproject.toml", "r", encoding="utf-8") as f:
                toml_doc = tomlkit.load(f)
            project_section = toml_doc.get("project", {})
            deps = project_section.get("dependencies", [])
            opt_deps = project_section.get("optional-dependencies", {})
            deps_json = json.dumps(
                {
                    "dependencies": deps,
                    "optional-dependencies": opt_deps,
                },
                indent=2,
            )
        except Exception as e:
            logging.error(f"Failed to extract pyproject deps: {e}")
            return []

        # Gather uv pip tree
        try:
            tree_output = subprocess.run(
                ["uv", "pip", "tree"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout
        except Exception:
            tree_output = "No tree available."

        vuln_lines: list[str] = []
        for v in vulnerabilities:
            fixed = v.fixed_versions[0] if v.fixed_versions else "latest"
            vuln_lines.append(
                f"- {v.package} ({v.current_version} -> {fixed})"
            )
        vulns_str = "\n".join(vuln_lines)

        user_prompt = (
            "Here is the dependency tree to help locate sub-dependencies:\n"
            "```\n"
            f"{tree_output}\n"
            "```\n\n"
            "Here are the current dependencies arrays from pyproject.toml:\n"
            "```json\n"
            f"{deps_json}\n"
            "```\n\n"
            "Please fix the following vulnerabilities by modifying "
            "the JSON structure explicitly:\n"
            f"{vulns_str}\n\n"
            "INSTRUCTIONS:\n"
            "1. If a vulnerable package is already in the JSON, update its "
            "version constraint.\n"
            "2. If a vulnerable package is a SUB-DEPENDENCY (not currently "
            "in the JSON), you MUST ADD it to the exact same array (e.g., "
            "'dependencies', or a specific 'optional-dependencies' group) "
            "where its top-level parent resides, with a pinned version "
            "constraint (e.g. `>=20.36.1`).\n"
            "3. DO NOT lazily put sub-dependencies into the main "
            "'dependencies' array! You MUST trace the tree up to the ROOT "
            "parent, find that root in the provided JSON, and put the "
            "sub-dependency in the EXACT SAME array as that root.\n"
            "4. Output ONLY the fully modified JSON object. Do not include "
            "markdown blocks like ```json, explanations, or text outside "
            "the raw JSON content."
        )

        try:
            response = self.client.inference(
                function_name="chat",
                input={
                    "messages": [
                        {
                            "role": "user",
                            "content": user_prompt,
                        },
                    ],
                },
            )

            # Extract content from response
            output_text = ""
            if hasattr(response, "content") and response.content:
                output_text = getattr(
                    response.content[0], "text", str(response.content[0])
                )
            elif hasattr(response, "output") and response.output:
                # Ignore indexing lint for dynamic output struct
                output_block = response.output[0]  # type: ignore
                output_text = getattr(output_block, "text", str(output_block))
            else:
                output_text = str(response)

            payload = output_text.strip()
            new_deps_dict = json.loads(payload)

            # Preserve TOML formatting by injecting back updated structures
            if "dependencies" in new_deps_dict and "project" in toml_doc:
                new_deps = new_deps_dict["dependencies"]
                toml_doc["project"]["dependencies"] = new_deps  # type: ignore
            opt_deps_key = "optional-dependencies"
            if opt_deps_key in new_deps_dict and "project" in toml_doc:
                new_o_deps = new_deps_dict[opt_deps_key]
                toml_doc["project"][opt_deps_key] = new_o_deps  # type: ignore

            final_toml_payload = tomlkit.dumps(toml_doc)

            return [
                FixRecommendation(
                    package="pyproject.toml",
                    from_version="N/A",
                    to_version="N/A",
                    rationale="Aggregated JSON pyproject.toml fix",
                    payload=final_toml_payload,
                )
            ]

        except Exception as e:
            logging.error(f"Failed to generate fix: {e}")
            return []
