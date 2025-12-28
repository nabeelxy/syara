"""
Text cleaning utilities for preprocessing text before matching.
"""
from abc import ABC, abstractmethod
import re
import unicodedata


class TextCleaner(ABC):
    """Abstract base class for text cleaners."""

    @abstractmethod
    def clean(self, text: str) -> str:
        """
        Clean the input text.

        Args:
            text: Raw input text

        Returns:
            Cleaned text
        """
        pass


class DefaultCleaner(TextCleaner):
    """
    Default text cleaner that performs:
    - Unicode normalization (NFKC)
    - Lowercasing
    - Whitespace normalization
    """

    def clean(self, text: str) -> str:
        """Clean text with default preprocessing."""
        # Normalize unicode characters
        text = unicodedata.normalize('NFKC', text)

        # Convert to lowercase
        text = text.lower()

        # Normalize whitespace (replace multiple spaces with single space)
        text = re.sub(r'\s+', ' ', text)

        # Strip leading/trailing whitespace
        text = text.strip()

        return text


class NoOpCleaner(TextCleaner):
    """Cleaner that returns text unchanged."""

    def clean(self, text: str) -> str:
        """Return text without any cleaning."""
        return text


class AggressiveCleaner(TextCleaner):
    """
    Aggressive cleaning that removes:
    - All punctuation
    - Extra whitespace
    - Numbers
    """

    def clean(self, text: str) -> str:
        """Clean text aggressively."""
        # Normalize unicode
        text = unicodedata.normalize('NFKC', text)

        # Lowercase
        text = text.lower()

        # Remove numbers
        text = re.sub(r'\d+', '', text)

        # Remove punctuation
        text = re.sub(r'[^\w\s]', ' ', text)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)

        # Strip
        text = text.strip()

        return text
