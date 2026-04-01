"""Tests for the Orchestrator core component."""

from unittest.mock import MagicMock, mock_open, patch

from huldra.core.orchestrator import TensorZeroOrchestrator
from huldra.core.types import Vulnerability


def test_tensorzero_orchestrator_init():
    """Test the TensorZeroOrchestrator class initialization."""
    orchestrator = TensorZeroOrchestrator()
    assert orchestrator.endpoint == "http://localhost:3000"


def test_tensorzero_orchestrator_init_with_endpoint():
    """Test the TensorZeroOrchestrator initialization with custom endpoint."""
    orchestrator = TensorZeroOrchestrator(endpoint="http://test.com")
    assert orchestrator.endpoint == "http://test.com"


def test_tensorzero_orchestrator_generate_fix_empty():
    """Test the generate_fix method when vulnerabilities is empty."""
    orchestrator = TensorZeroOrchestrator()
    assert orchestrator.generate_fix([]) == []


@patch("builtins.open")
def test_tensorzero_orchestrator_generate_fix_read_toml_fails(mock_open_func):
    """Test generate_fix failing to extract dependencies."""
    mock_open_func.side_effect = Exception("File read error")
    orchestrator = TensorZeroOrchestrator()

    vulnerabilities = [
        Vulnerability("1", "pkg_a", "1.0.0", ["1.0.1"], [], "desc")
    ]
    assert orchestrator.generate_fix(vulnerabilities) == []


@patch("subprocess.run")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="[project]\ndependencies = []",
)
def test_tensorzero_orchestrator_generate_fix_subprocess_fails(
    mock_file, mock_run
):
    """Test tree execution fallback."""
    mock_run.side_effect = Exception("Subprocess failed")

    orchestrator = TensorZeroOrchestrator()
    orchestrator.client = MagicMock()
    mock_response = MagicMock()
    mock_response.content = [
        MagicMock(text='{"dependencies": ["pkg_a==1.0.1"]}')
    ]
    orchestrator.client.inference.return_value = mock_response

    vulnerabilities = [
        Vulnerability("1", "pkg_a", "1.0.0", ["1.0.1"], [], "desc")
    ]
    recs = orchestrator.generate_fix(vulnerabilities)
    assert len(recs) == 1
    assert recs[0].package == "pyproject.toml"
    assert "pkg_a==1.0.1" in recs[0].payload


@patch("subprocess.run")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="[project]\ndependencies = []",
)
def test_tensorzero_orchestrator_generate_fix_with_content(
    mock_file, mock_run
):
    """Test the generate_fix method with standard output.content."""
    mock_run.return_value = MagicMock(stdout="Tree output", returncode=0)

    orchestrator = TensorZeroOrchestrator()
    orchestrator.client = MagicMock()

    mock_response = MagicMock()
    del mock_response.content
    mock_response.output = [
        MagicMock(text='{"dependencies": ["pkg_a==1.0.1"]}')
    ]
    orchestrator.client.inference.return_value = mock_response

    vulnerabilities = [
        Vulnerability("1", "pkg_a", "1.0.0", ["1.0.1"], [], "desc")
    ]

    recommendations = orchestrator.generate_fix(vulnerabilities)

    assert len(recommendations) == 1
    rec = recommendations[0]
    assert rec.package == "pyproject.toml"
    assert rec.from_version == "N/A"
    assert rec.to_version == "N/A"
    assert "Aggregated JSON pyproject.toml fix" in rec.rationale
    assert "pkg_a==1.0.1" in rec.payload


@patch("subprocess.run")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="[project]\ndependencies = []",
)
def test_tensorzero_orchestrator_generate_fix_with_string_fallback(
    mock_file, mock_run
):
    """Test the generate_fix method when response is a plain string."""
    mock_run.return_value = MagicMock(stdout="Tree output", returncode=0)

    orchestrator = TensorZeroOrchestrator()
    orchestrator.client = MagicMock()

    mock_response = MagicMock()
    del mock_response.content
    del mock_response.output
    mock_response.__str__.return_value = (
        '{"optional-dependencies": {"dev": ["pkg_a"]}}'
    )

    orchestrator.client.inference.return_value = mock_response

    vulnerabilities = [Vulnerability("1", "pkg_a", "1.0.0", [], [], "desc")]

    recommendations = orchestrator.generate_fix(vulnerabilities)
    assert len(recommendations) == 1
    assert "pkg_a" in recommendations[0].payload


@patch("subprocess.run")
@patch(
    "builtins.open",
    new_callable=mock_open,
    read_data="[project]\ndependencies = []",
)
def test_tensorzero_orchestrator_generate_fix_json_error(mock_file, mock_run):
    """Test the generate_fix method when LLM outputs invalid JSON."""
    mock_run.return_value = MagicMock(stdout="Tree output", returncode=0)

    orchestrator = TensorZeroOrchestrator()
    orchestrator.client = MagicMock()

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="THIS IS NOT JSON")]
    orchestrator.client.inference.return_value = mock_response

    vulnerabilities = [
        Vulnerability("1", "pkg_a", "1.0.0", ["1.0.1"], [], "desc")
    ]

    assert orchestrator.generate_fix(vulnerabilities) == []
