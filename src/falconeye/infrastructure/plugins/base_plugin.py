"""Base plugin interface for language-specific analysis."""

from abc import ABC, abstractmethod
from typing import Dict, List


class LanguagePlugin(ABC):
    """
    Base class for language plugins.

    IMPORTANT: Plugins provide context and prompts for AI analysis,
    NOT pattern-based vulnerability detection rules.

    Each plugin provides:
    - Language-specific system prompts for AI
    - Vulnerability categories for context
    - Validation prompts to reduce false positives
    - Optional chunking strategies
    """

    @property
    @abstractmethod
    def language_name(self) -> str:
        """
        Language name.

        Returns:
            Language name (e.g., "python", "javascript")
        """
        pass

    @property
    @abstractmethod
    def file_extensions(self) -> List[str]:
        """
        File extensions for this language.

        Returns:
            List of file extensions (e.g., [".py", ".pyw"])
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Get language-specific system prompt for security analysis.

        This prompt guides the AI to:
        - Understand language semantics
        - Consider common vulnerability patterns (for context, not matching)
        - Perform deep reasoning about code behavior
        - Output findings in structured format

        Returns:
            System prompt string
        """
        pass

    @abstractmethod
    def get_validation_prompt(self) -> str:
        """
        Get prompt for validating findings to reduce false positives.

        The AI uses this prompt to review findings and determine
        if they are genuine vulnerabilities or false positives.

        Returns:
            Validation prompt string
        """
        pass

    @abstractmethod
    def get_vulnerability_categories(self) -> List[str]:
        """
        Get common vulnerability categories for this language.

        These categories provide context for the AI, NOT matching rules.
        They help the AI understand what types of issues to look for.

        Returns:
            List of vulnerability category names
        """
        pass

    def get_chunking_strategy(self) -> Dict[str, int]:
        """
        Get language-specific chunking parameters.

        Can be overridden for languages that need different chunking.

        Returns:
            Dictionary with 'chunk_size' and 'chunk_overlap' keys
        """
        return {
            "chunk_size": 50,
            "chunk_overlap": 10,
        }

    def get_framework_context(self) -> List[str]:
        """
        Get common frameworks/libraries for this language.

        This provides additional context for the AI about common
        security issues in popular frameworks.

        Returns:
            List of framework names
        """
        return []

    def __repr__(self) -> str:
        """String representation."""
        return f"<{self.__class__.__name__}: {self.language_name}>"