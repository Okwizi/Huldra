"""Types for dataclasses.
This is where custom class types are defined for classes
we want to act as data stores.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class Vulnerability:
    """Vulnerability dataclass."""

    id: str
    package: str
    current_version: str
    fixed_versions: List[str]
    aliases: List[str]
    description: str


@dataclass
class FixRecommendation:
    """Fix recommendation dataclass."""

    package: str
    from_version: str
    to_version: str
    rationale: str
    command: str
