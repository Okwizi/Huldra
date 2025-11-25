from typing import List

from huldra.core.orchestrator import Orchestrator
from huldra.core.types import FixRecommendation
from huldra.providers.base import Provider


class Healer:
    def __init__(self, provider: Provider, orchestrator: Orchestrator):
        self.provider = provider
        self.orchestrator = orchestrator

    def heal(self) -> List[FixRecommendation]:
        print("Running audit...")
        vulnerabilities = self.provider.audit()

        if not vulnerabilities:
            print("No vulnerabilities found.")
            return []

        print(
            f"Found {len(vulnerabilities)} vulnerabilities. "
            "Analyzing with Orchestrator..."
        )
        recommendations = self.orchestrator.generate_fix(vulnerabilities)

        return recommendations

    def apply_fixes(self, recommendations: List[FixRecommendation]):
        for rec in recommendations:
            print(f"Applying fix for {rec.package}: {rec.command}")
            if self.provider.apply_fix(rec.command):
                print("Success.")
            else:
                print("Failed.")
