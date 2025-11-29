"""Tests for the Orchestrator core component."""

from huldra.core.orchestrator import TensorZeroOrchestrator
from huldra.core.types import Vulnerability


def test_tensorzero_orchestrator_init():
    """Test the TensorZeroOrchestrator class initialization."""
    orchestrator = TensorZeroOrchestrator()
    assert orchestrator.endpoint == "http://localhost:8000"


def test_tensorzero_orchestrator_init_with_endpoint():
    """Test the TensorZeroOrchestrator initialization with custom endpoint."""
    orchestrator = TensorZeroOrchestrator(endpoint="http://test.com")
    assert orchestrator.endpoint == "http://test.com"


def test_tensorzero_orchestrator_generate_fix():
    """Test the generate_fix method."""
    orchestrator = TensorZeroOrchestrator()
    vulnerabilities = [
        Vulnerability(
            id="CVE-2021-1234",
            package="a",
            current_version="1.0.0",
            fixed_versions=["1.0.1"],
            aliases=["CVE-2021-1234"],
            description="A vulnerability",
        )
    ]
    recommendations = orchestrator.generate_fix(vulnerabilities)
    assert len(recommendations) == 1
    rec = recommendations[0]
    assert rec.package == "a"
    assert rec.from_version == "1.0.0"
    assert rec.to_version == "latest"
    assert "CVE-2021-1234" in rec.rationale
    assert rec.command == "pip install a==1.0.1"


def test_tensorzero_orchestrator_generate_fix_no_fixed_version():
    """Test the generate_fix method when no fixed version is available."""
    orchestrator = TensorZeroOrchestrator()
    vulnerabilities = [
        Vulnerability(
            id="CVE-2021-1234",
            package="a",
            current_version="1.0.0",
            fixed_versions=[],
            aliases=["CVE-2021-1234"],
            description="A vulnerability",
        )
    ]
    recommendations = orchestrator.generate_fix(vulnerabilities)
    assert len(recommendations) == 1
    rec = recommendations[0]
    assert rec.package == "a"
    assert rec.from_version == "1.0.0"
    assert rec.to_version == "latest"
    assert "CVE-2021-1234" in rec.rationale
    assert rec.command == "pip install --upgrade a"
