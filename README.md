# Huldra

[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
![ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)
[![pyrefly](https://img.shields.io/endpoint?url=https://pyrefly.org/badge.json)](https://github.com/facebook/pyrefly)
[![huldra](https://img.shields.io/pypi/v/huldra.svg)](https://pypi.org/project/huldra/)
![License](https://img.shields.io/badge/license-Apache--2.0-green)
![CI](https://github.com/Okwizi/Huldra/actions/workflows/ci.yml/badge.svg)
![CodeQL](https://github.com/Okwizi/Huldra/actions/workflows/codeql.yml/badge.svg)
![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)

**Huldra** is an automated vulnerability remediation tool designed to streamline the security auditing process. It leverages existing audit tools to identify vulnerabilities in language dependencies and uses an LLM orchestrator to intelligently suggest and apply fixes.

## Features

- **Automated Auditing**: Uses `pip-audit` to scan Python dependencies for known vulnerabilities.
- **Intelligent Remediation**: Integrates with **TensorZero** (LLM Orchestrator) to analyze vulnerability reports and generate context-aware fix recommendations.
- **Auto-Fix**: Capable of automatically applying recommended fixes (e.g., upgrading packages) via the CLI.
- **Extensible Architecture**: Designed with a modular provider system to support multiple languages and audit tools in the future.

## Components

Huldra consists of three main components:

1.  **Provider**: Interfaces with language-specific audit tools (e.g., `pip-audit` for Python) to detect vulnerabilities and apply fixes.
2.  **Orchestrator**: Connects to an LLM service (currently **TensorZero**) to interpret vulnerability data and propose solutions.
3.  **Healer**: The core logic that coordinates the Provider and Orchestrator to execute the "audit -> analyze -> fix" workflow.

## Installation

Huldra requires Python 3.11 or higher.

```bash
# Clone the repository
git clone https://github.com/Okwizi/Huldra.git
cd Huldra

# Create a virtual environment and install dependencies using uv
uv venv
source .venv/bin/activate
uv pip install .
```

## Usage

Huldra provides a command-line interface (CLI) for easy interaction.

### Run an Audit and Apply Fixes

To run a full audit and interactively apply fixes:

```bash
huldra-cli
```

### Run Audit Only

To perform an audit without applying any fixes:

```bash
huldra-cli --audit-only
```

## Development

This project uses `uv` for dependency management and `tox` for testing and linting.

### Setting up the Environment

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync
```

### Running Tests

```bash
# Run tests using tox
uvx tox -e test
```

### Linting and Type Checking

```bash
# Run linting and type checking
uvx tox -e lint
```

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.
