"""Tests for the Healer core component."""

from unittest.mock import MagicMock

from huldra.core.healer import Healer
from huldra.core.types import FixRecommendation


def test_healer_init():
    """Test the Healer class initialization."""
    provider = MagicMock()
    orchestrator = MagicMock()
    healer = Healer(provider, orchestrator)
    assert healer.provider == provider
    assert healer.orchestrator == orchestrator


def test_healer_heal_no_vulnerabilities():
    """Test the heal method when no vulnerabilities are found."""
    provider = MagicMock()
    orchestrator = MagicMock()
    provider.audit.return_value = []
    healer = Healer(provider, orchestrator)
    recommendations = healer.heal()
    assert recommendations == []
    provider.audit.assert_called_once()
    orchestrator.generate_fix.assert_not_called()


def test_healer_heal_with_vulnerabilities():
    """Test the heal method when vulnerabilities are found."""
    provider = MagicMock()
    orchestrator = MagicMock()
    vulnerabilities = [MagicMock()]
    provider.audit.return_value = vulnerabilities
    recommendations = [
        FixRecommendation(
            package="a",
            from_version="1.0.0",
            to_version="1.0.1",
            rationale="a > 1.0.1 is vulnerable",
            command="pip install --upgrade a",
        )
    ]
    orchestrator.generate_fix.return_value = recommendations
    healer = Healer(provider, orchestrator)
    result = healer.heal()
    assert result == recommendations
    provider.audit.assert_called_once()
    orchestrator.generate_fix.assert_called_once_with(vulnerabilities)


def test_healer_apply_fixes_success():
    """Test the apply_fixes method with successful application."""
    provider = MagicMock()
    orchestrator = MagicMock()
    recommendations = [
        FixRecommendation(
            package="a",
            from_version="1.0.0",
            to_version="1.0.1",
            rationale="a > 1.0.1 is vulnerable",
            command="pip install --upgrade a",
        )
    ]
    provider.apply_fix.return_value = True
    healer = Healer(provider, orchestrator)
    healer.apply_fixes(recommendations)
    provider.apply_fix.assert_called_once_with("pip install --upgrade a")


def test_healer_apply_fixes_failure():
    """Test the apply_fixes method with failed application."""
    provider = MagicMock()
    orchestrator = MagicMock()
    recommendations = [
        FixRecommendation(
            package="a",
            from_version="1.0.0",
            to_version="1.0.1",
            rationale="a > 1.0.1 is vulnerable",
            command="pip install --upgrade a",
        )
    ]
    provider.apply_fix.return_value = False
    healer = Healer(provider, orchestrator)
    healer.apply_fixes(recommendations)
    provider.apply_fix.assert_called_once_with("pip install --upgrade a")
