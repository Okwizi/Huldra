"""Base Abstract for all Providers."""


from abc import ABC, abstractmethod
from typing import List

from huldra.core.types import Vulnerability


class Provider(ABC):
    """Base Provider class."""
    @abstractmethod
    def audit(self) -> List[Vulnerability]:
        """
        Run the audit and return a list of vulnerabilities.
        """
        pass

    @abstractmethod
    def apply_fix(self, command: str) -> bool:
        """
        Apply a fix command.
        """
        pass
