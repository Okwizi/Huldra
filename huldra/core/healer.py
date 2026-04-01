"""The Healer."""

from typing import List

from huldra.core.orchestrator import Orchestrator
from huldra.core.types import FixRecommendation
from huldra.providers.base import Provider


class Healer:
    """Healer class."""

    def __init__(self, provider: Provider, orchestrator: Orchestrator) -> None:
        """Initialize the healer."""
        self.provider = provider
        self.orchestrator = orchestrator

    def heal(self) -> List[FixRecommendation]:
        """Heal the vulnerabilities."""
        vulnerabilities = self.provider.audit()

        if not vulnerabilities:
            return []

        recommendations = self.orchestrator.generate_fix(vulnerabilities)

        return recommendations

    def apply_fixes(self, recommendations: List[FixRecommendation]) -> None:
        """Apply fix recommendations."""
        for rec in recommendations:
            if self.provider.apply_fix(rec.payload):
                # return nothing for now
                return
