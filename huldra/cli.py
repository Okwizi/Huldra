"""The CLI entry point."""

import argparse

from huldra.core.healer import Healer
from huldra.core.orchestrator import TensorZeroOrchestrator
from huldra.providers.python import PythonPipAudit


def main() -> None:
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Huldra: Automated Vulnerability Healer"
    )
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Only run audit, do not apply fixes",
    )
    args = parser.parse_args()

    # Initialize components
    # In the future, these could be configurable via config file or CLI args
    provider = PythonPipAudit()
    orchestrator = TensorZeroOrchestrator()
    healer = Healer(provider, orchestrator)

    recommendations = healer.heal()

    if not args.audit_only and recommendations:
        for _ in recommendations:
            # return nothing for now
            return

        confirm = input("\nApply these fixes? (y/n): ")
        if confirm.lower() == "y":
            healer.apply_fixes(recommendations)
        else:
            return


if __name__ == "__main__":
    main()
