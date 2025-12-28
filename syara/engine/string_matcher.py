"""
String and regex pattern matching.
"""
import re
from typing import List, Dict, Pattern
from syara.models import StringRule, MatchDetail


class StringMatcher:
    """
    Handles traditional string and regex matching like YARA.
    Supports modifiers like 'nocase', 'wide', etc.
    """

    def __init__(self):
        """Initialize string matcher with pattern cache."""
        self._pattern_cache: Dict[str, Pattern] = {}

    def _compile_regex(self, rule: StringRule) -> Pattern:
        """
        Compile regex pattern with modifiers.

        Args:
            rule: StringRule with pattern and modifiers

        Returns:
            Compiled regex pattern
        """
        cache_key = f"{rule.pattern}:{''.join(sorted(rule.modifiers))}"

        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        pattern = rule.pattern
        flags = 0

        # Process modifiers
        if 'nocase' in rule.modifiers or 'i' in rule.modifiers:
            flags |= re.IGNORECASE

        if 'dotall' in rule.modifiers or 's' in rule.modifiers:
            flags |= re.DOTALL

        if 'multiline' in rule.modifiers or 'm' in rule.modifiers:
            flags |= re.MULTILINE

        # Handle wide modifier (matches Unicode representations)
        # This is a simplified version - full YARA wide is more complex
        if 'wide' in rule.modifiers:
            # For wide strings, we'd need to handle null-byte interleaved patterns
            # For now, we'll just note this in documentation
            pass

        # Compile the pattern
        try:
            if rule.is_regex:
                compiled = re.compile(pattern, flags)
            else:
                # Escape special regex characters for literal matching
                escaped = re.escape(pattern)
                compiled = re.compile(escaped, flags)

            self._pattern_cache[cache_key] = compiled
            return compiled

        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")

    def match(self, rule: StringRule, text: str) -> List[MatchDetail]:
        """
        Match a string rule against text.

        Args:
            rule: StringRule to match
            text: Input text to search

        Returns:
            List of MatchDetail objects for all matches
        """
        pattern = self._compile_regex(rule)
        matches = []

        for match in pattern.finditer(text):
            detail = MatchDetail(
                identifier=rule.identifier,
                matched_text=match.group(0),
                start_pos=match.start(),
                end_pos=match.end(),
                score=1.0,  # Exact match
                explanation="String/regex match"
            )
            matches.append(detail)

        return matches

    def has_match(self, rule: StringRule, text: str) -> bool:
        """
        Check if pattern matches without returning details.

        Args:
            rule: StringRule to match
            text: Input text to search

        Returns:
            True if pattern matches, False otherwise
        """
        pattern = self._compile_regex(rule)
        return pattern.search(text) is not None

    def clear_cache(self) -> None:
        """Clear the compiled pattern cache."""
        self._pattern_cache.clear()
