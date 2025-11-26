"""Test the CLI entry point."""

from unittest.mock import patch

import pytest

from huldra.cli import main


@pytest.fixture
def mock_dependencies():
    """Mock external dependencies."""
    with (
        patch("huldra.cli.PythonPipAudit") as mock_provider,
        patch("huldra.cli.TensorZeroOrchestrator") as mock_orchestrator,
        patch("huldra.cli.Healer") as mock_healer_cls,
    ):
        mock_healer = mock_healer_cls.return_value
        yield mock_provider, mock_orchestrator, mock_healer


def test_main_audit_only(mock_dependencies):
    """Test main with --audit-only flag."""
    _, _, mock_healer = mock_dependencies

    with patch("sys.argv", ["huldra", "--audit-only"]):
        main()

    mock_healer.heal.assert_called_once()
    mock_healer.apply_fixes.assert_not_called()


def test_main_apply_fixes_yes(mock_dependencies):
    """Test main with fixes available and user confirms 'y'."""
    _, _, mock_healer = mock_dependencies
    mock_healer.heal.return_value = ["fix1", "fix2"]

    with (
        patch("sys.argv", ["huldra"]),
        patch("builtins.input", return_value="y") as mock_input,
    ):
        main()

    mock_input.assert_called_once()
    mock_healer.heal.assert_called_once()
    mock_healer.apply_fixes.assert_called_once_with(["fix1", "fix2"])


def test_main_apply_fixes_no(mock_dependencies):
    """Test main with fixes available and user confirms 'n'."""
    _, _, mock_healer = mock_dependencies
    mock_healer.heal.return_value = ["fix1", "fix2"]

    with (
        patch("sys.argv", ["huldra"]),
        patch("builtins.input", return_value="n"),
    ):
        main()

    mock_healer.heal.assert_called_once()
    mock_healer.apply_fixes.assert_not_called()


def test_main_no_recommendations(mock_dependencies):
    """Test main with no recommendations returned."""
    _, _, mock_healer = mock_dependencies
    mock_healer.heal.return_value = []

    with patch("sys.argv", ["huldra"]), patch("builtins.input") as mock_input:
        main()

    mock_healer.heal.assert_called_once()
    mock_input.assert_not_called()
    mock_healer.apply_fixes.assert_not_called()
