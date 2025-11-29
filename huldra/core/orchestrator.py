"""The LLM Orchestrator."""

from abc import ABC, abstractmethod
from typing import List

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

    def __init__(self, endpoint: str = "http://localhost:8000") -> None:
        """Initialize TensorZero orchestrator."""
        self.endpoint = endpoint
        # TODO: Initialize TensorZero client here

    def generate_fix(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[FixRecommendation]:
        """Generate fix recommendations."""
        recommendations = []
        for vuln in vulnerabilities:
            # Placeholder logic for LLM interaction
            _prompt = (
                f"Fix vulnerability {vuln.id} in {vuln.package} "
                f"version {vuln.current_version}. "
                f"Fixed in {vuln.fixed_versions}."
            )

            # Mock response
            recommendations.append(
                FixRecommendation(
                    package=vuln.package,
                    from_version=vuln.current_version,
                    # hardcoded `to_version` for now since we haven't handled
                    # cases where there's vulnerabilities with no fixed version
                    to_version="latest",
                    rationale=f"Fixes {vuln.id} based on pip-audit report.",
                    command=(
                        f"pip install {vuln.package}=={vuln.fixed_versions[0]}"
                    )
                    if vuln.fixed_versions
                    else f"pip install --upgrade {vuln.package}",
                )
            )

        return recommendations
