"""
Field-based matching for Sigma-style key:value rules.
"""
import re
from typing import List
from syara.models import FieldRule, MatchDetail


class FieldMatcher:
    """
    Matches FieldRule against a field value string.
    For literal patterns: exact equality (with optional nocase).
    For regex patterns: re.search against field value.
    """

    def match(self, rule: FieldRule, field_value: str) -> List[MatchDetail]:
        """
        Match a FieldRule against a field value.

        Args:
            rule: FieldRule to match
            field_value: The string value of the field

        Returns:
            List of MatchDetail (empty if no match)
        """
        nocase = 'nocase' in rule.modifiers

        if rule.is_regex:
            flags = re.IGNORECASE if nocase or 'i' in rule.modifiers else 0
            try:
                m = re.search(rule.pattern, field_value, flags)
                if m:
                    return [MatchDetail(
                        identifier=rule.identifier,
                        matched_text=field_value,
                        start_pos=m.start(),
                        end_pos=m.end(),
                        score=1.0,
                    )]
            except re.error:
                pass
            return []
        else:
            # Literal exact match
            lhs = field_value.lower() if nocase else field_value
            rhs = rule.pattern.lower() if nocase else rule.pattern
            if lhs == rhs:
                return [MatchDetail(
                    identifier=rule.identifier,
                    matched_text=field_value,
                    start_pos=0,
                    end_pos=len(field_value),
                    score=1.0,
                )]
            return []
