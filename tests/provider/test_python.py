"""Tests for the Python provider."""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from huldra.providers.python import PythonPipAudit


def test_python_pip_audit_audit_no_vulnerabilities():
    """Test the audit method when no vulnerabilities are found."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(
                {
                    "dependencies": [
                        {
                            "name": "a",
                            "version": "1.0.0",
                            "vulns": [],
                        }
                    ]
                }
            ),
            returncode=0,
        )
        provider = PythonPipAudit()
        vulnerabilities = provider.audit()
        assert vulnerabilities == []
        mock_run.assert_called_once_with(
            ["pip-audit", "--format=json"],
            capture_output=True,
            text=True,
            check=False,
        )


def test_python_pip_audit_audit_with_vulnerabilities():
    """Test the audit method when vulnerabilities are found."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(
                {
                    "dependencies": [
                        {
                            "name": "a",
                            "version": "1.0.0",
                            "vulns": [
                                {
                                    "id": "CVE-2021-1234",
                                    "fix_versions": ["1.0.1"],
                                    "aliases": ["CVE-2021-1234"],
                                    "description": "A vulnerability",
                                }
                            ],
                        }
                    ]
                }
            ),
            returncode=0,
        )
        provider = PythonPipAudit()
        vulnerabilities = provider.audit()
        assert len(vulnerabilities) == 1
        vuln = vulnerabilities[0]
        assert vuln.id == "CVE-2021-1234"
        assert vuln.package == "a"
        assert vuln.current_version == "1.0.0"
        assert vuln.fixed_versions == ["1.0.1"]
        assert vuln.aliases == ["CVE-2021-1234"]
        assert vuln.description == "A vulnerability"


def test_python_pip_audit_audit_file_not_found():
    """Test the audit method when pip-audit is not found."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = FileNotFoundError
        provider = PythonPipAudit()
        with pytest.raises(FileNotFoundError):
            provider.audit()


def test_python_pip_audit_audit_json_decode_error():
    """Test the audit method with invalid JSON output."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="invalid json", returncode=0)
        provider = PythonPipAudit()

        with pytest.raises(ValueError, match="Invalid JSON from pip-audit"):
            provider.audit()


def test_python_pip_audit_apply_fix_success():
    """Test the apply_fix method with a successful command."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        provider = PythonPipAudit()
        result = provider.apply_fix("pip install --upgrade a")
        assert result is True
        mock_run.assert_called_once_with(
            "pip install --upgrade a", shell=True, check=True
        )


def test_python_pip_audit_apply_fix_failure():
    """Test the apply_fix method with a failed command."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd")
        provider = PythonPipAudit()
        with pytest.raises(ValueError, match="Failed to apply fix"):
            provider.apply_fix("pip install --upgrade a")


def test_python_pip_audit_audit_no_stdout():
    """Test the audit method with no stdout."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        provider = PythonPipAudit()
        with pytest.raises(ValueError, match="Invalid JSON from pip-audit"):
            provider.audit()


def test_python_pip_audit_audit_no_vulnerabilities_stderr():
    """Test the audit method when stderr say there's no vulnerabilities."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout={
                "dependencies": [
                    {
                        "name": "a",
                        "version": "1.0.0",
                        "vulns": [],
                    }
                ]
            },
            stderr="No known vulnerabilities found\n",
            returncode=0,
        )
        provider = PythonPipAudit()
        vulnerabilities = provider.audit()
        assert vulnerabilities == []
        mock_run.assert_called_once_with(
            ["pip-audit", "--format=json"],
            capture_output=True,
            text=True,
            check=False,
        )
