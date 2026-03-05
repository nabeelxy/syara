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

        # 'wide' modifier is handled separately in match() — skip here

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

        Supports the 'wide' modifier (UTF-16LE null-byte interleaving):
          - 'wide'        : match only the wide (null-interleaved) form
          - 'wide ascii'  : match both the wide and the normal ASCII form
          - (default)     : match only the normal ASCII form

        Args:
            rule: StringRule to match
            text: Input text to search

        Returns:
            List of MatchDetail objects for all matches
        """
        search_wide = 'wide' in rule.modifiers
        # 'ascii' alongside 'wide' means match both forms; absent 'wide' always
        # implies normal-only matching.
        search_ascii = ('ascii' in rule.modifiers) or not search_wide

        matches: List[MatchDetail] = []

        if search_ascii:
            pattern = self._compile_regex(rule)
            for m in pattern.finditer(text):
                matches.append(MatchDetail(
                    identifier=rule.identifier,
                    matched_text=m.group(0),
                    start_pos=m.start(),
                    end_pos=m.end(),
                    score=1.0,
                    explanation="String/regex match"
                ))

        if search_wide:
            matches.extend(self._match_wide(rule, text))

        return matches

    def _match_wide(self, rule: StringRule, text: str) -> List[MatchDetail]:
        """
        Match the wide (UTF-16LE) form of the pattern against text.

        For literal strings the pattern is converted to null-byte-interleaved
        form (e.g. "hi" → 'h\\x00i\\x00') and searched directly.

        For regex patterns the text is first stripped of null bytes
        (treating it as decoded UTF-16LE) and the original regex is applied —
        a best-effort approach for regex patterns with 'wide'.
        """
        flags = 0
        if 'nocase' in rule.modifiers or 'i' in rule.modifiers:
            flags |= re.IGNORECASE

        if rule.is_regex:
            # Best-effort: match original regex against null-stripped text
            stripped = text.replace('\x00', '')
            try:
                wide_re = re.compile(rule.pattern, flags)
            except re.error:
                return []
            matches: List[MatchDetail] = []
            for m in wide_re.finditer(stripped):
                matches.append(MatchDetail(
                    identifier=rule.identifier,
                    matched_text=m.group(0),
                    start_pos=m.start(),
                    end_pos=m.end(),
                    score=1.0,
                    explanation="Wide regex match (null-stripped)"
                ))
            return matches
        else:
            # Literal: interleave each character with a null byte
            wide_str = '\x00'.join(rule.pattern) + '\x00'
            wide_re = re.compile(re.escape(wide_str), flags)
            matches = []
            for m in wide_re.finditer(text):
                matches.append(MatchDetail(
                    identifier=rule.identifier,
                    matched_text=m.group(0),
                    start_pos=m.start(),
                    end_pos=m.end(),
                    score=1.0,
                    explanation="Wide string match"
                ))
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
