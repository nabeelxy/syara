"""
Session-scoped cache for cleaned text to avoid redundant preprocessing.
"""
import hashlib
from typing import Dict, Optional
from syara.engine.cleaner import TextCleaner


class TextCache:
    """
    Cache for storing cleaned text during a matching session.
    The cache is cleared after each match() call to ensure session scope.
    """

    def __init__(self):
        """Initialize an empty cache."""
        self._cache: Dict[str, str] = {}

    def _generate_key(self, text: str, cleaner_name: str) -> str:
        """
        Generate a cache key from text and cleaner name.

        Args:
            text: Original text
            cleaner_name: Name of the cleaner being used

        Returns:
            Hash key for cache lookup
        """
        # Combine text and cleaner name, then hash for efficient lookup
        combined = f"{cleaner_name}:{text}"
        return hashlib.sha256(combined.encode('utf-8')).hexdigest()

    def get_cleaned_text(
        self,
        text: str,
        cleaner: TextCleaner,
        cleaner_name: str
    ) -> str:
        """
        Get cleaned text from cache or clean and cache it.

        Args:
            text: Original text to clean
            cleaner: TextCleaner instance to use
            cleaner_name: Name of the cleaner (for cache key)

        Returns:
            Cleaned text
        """
        cache_key = self._generate_key(text, cleaner_name)

        # Check cache first
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Not in cache - clean the text
        cleaned = cleaner.clean(text)

        # Store in cache
        self._cache[cache_key] = cleaned

        return cleaned

    def clear(self) -> None:
        """Clear the cache. Called at the end of each match() session."""
        self._cache.clear()

    def size(self) -> int:
        """Get the number of cached entries."""
        return len(self._cache)

    def get(self, text: str, cleaner_name: str) -> Optional[str]:
        """
        Get cached text without cleaning if not found.

        Args:
            text: Original text
            cleaner_name: Name of the cleaner

        Returns:
            Cached cleaned text or None if not found
        """
        cache_key = self._generate_key(text, cleaner_name)
        return self._cache.get(cache_key)
