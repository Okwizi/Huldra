"""Tests for the base provider."""

from huldra.core.types import Vulnerability
from huldra.providers.base import Provider


class ConcreteProvider(Provider):
    """A concrete implementation of the Provider class for testing."""

    def audit(self):
        """Run the audit and return a list of vulnerabilities."""
        return [
            Vulnerability(
                id="CVE-2021-1234",
                package="a",
                current_version="1.0.0",
                fixed_version="1.0.1",
                description="A vulnerability",
            )
        ]

    def apply_fix(self, command: str):
        """Apply a fix command."""
        return command == "pip install --upgrade a"


def test_concrete_provider_audit():
    """Test the audit method of the concrete provider."""
    provider = ConcreteProvider()
    vulnerabilities = provider.audit()
    assert len(vulnerabilities) == 1
    vuln = vulnerabilities[0]
    assert vuln.id == "CVE-2021-1234"
    assert vuln.package == "a"
    assert vuln.current_version == "1.0.0"
    assert vuln.fixed_version == "1.0.1"
    assert vuln.description == "A vulnerability"


def test_concrete_provider_apply_fix():
    """Test the apply_fix method of the concrete provider."""
    provider = ConcreteProvider()
    assert provider.apply_fix("pip install --upgrade a")
    assert not provider.apply_fix("pip install --upgrade b")
