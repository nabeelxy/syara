"""
Execution engine for compiled rules.
"""
from typing import List, Dict
import re
from syara.models import Rule, Match, MatchDetail
from syara.config import ConfigManager
from syara.cache import TextCache
from syara.engine.string_matcher import StringMatcher


class CompiledRules:
    """
    Compiled rules ready for matching.
    Executes rules in cost-optimized order: strings → similarity → classifier → llm
    """

    def __init__(self, rules: List[Rule], config_manager: ConfigManager):
        """
        Initialize compiled rules.

        Args:
            rules: List of parsed and validated rules
            config_manager: Configuration manager for loading components
        """
        self.rules = rules
        self.config_manager = config_manager
        self.string_matcher = StringMatcher()

    def match(self, text: str) -> List[Match]:
        """
        Match text against all compiled rules.

        Args:
            text: Input text to match

        Returns:
            List of Match objects for all rules
        """
        # Create a session cache for this match operation
        cache = TextCache()

        try:
            # Execute each rule
            matches = []
            for rule in self.rules:
                match = self._execute_rule(rule, text, cache)
                matches.append(match)

            return matches

        finally:
            # Always clear cache after matching session
            cache.clear()

    def _execute_rule(self, rule: Rule, text: str, cache: TextCache) -> Match:
        """
        Execute a single rule against text.

        Args:
            rule: Rule to execute
            text: Input text
            cache: Text cache for this session

        Returns:
            Match object with results
        """
        # Dictionary to track all pattern matches
        # Key: identifier (e.g., "$s1"), Value: List[MatchDetail]
        pattern_matches: Dict[str, List[MatchDetail]] = {}

        # Execute pattern matching in cost-optimized order

        # 1. String patterns (cheapest)
        for string_rule in rule.strings:
            matches = self.string_matcher.match(string_rule, text)
            if matches:
                pattern_matches[string_rule.identifier] = matches

        # 2. Similarity patterns (moderate cost)
        for sim_rule in rule.similarity:
            matches = self._execute_similarity(sim_rule, text, cache)
            if matches:
                pattern_matches[sim_rule.identifier] = matches

        # 3. Classifier patterns (higher cost)
        for cls_rule in rule.classifier:
            matches = self._execute_classifier(cls_rule, text, cache)
            if matches:
                pattern_matches[cls_rule.identifier] = matches

        # 4. LLM patterns (highest cost)
        # Only execute if needed by condition
        for llm_rule in rule.llm:
            # Check if LLM pattern is needed for condition
            if self._is_identifier_needed(llm_rule.identifier, rule.condition, pattern_matches):
                matches = self._execute_llm(llm_rule, text, cache)
                if matches:
                    pattern_matches[llm_rule.identifier] = matches

        # Evaluate condition
        matched = self._evaluate_condition(rule.condition, pattern_matches)

        return Match(
            rule_name=rule.name,
            tags=rule.tags,
            meta=rule.meta,
            matched=matched,
            matched_patterns=pattern_matches if matched else {}
        )

    def _execute_similarity(self, rule, text: str, cache: TextCache) -> List[MatchDetail]:
        """Execute similarity matching."""
        # Get components
        cleaner = self.config_manager.get_cleaner(rule.cleaner_name)
        chunker = self.config_manager.get_chunker(rule.chunker_name)
        matcher = self.config_manager.get_matcher(rule.matcher_name)

        # Clean text (with caching)
        cleaned_text = cache.get_cleaned_text(text, cleaner, rule.cleaner_name)

        # Chunk text
        chunks = chunker.chunk(cleaned_text)

        # Match chunks
        matches = matcher.match_chunks(rule, chunks)

        return matches

    def _execute_classifier(self, rule, text: str, cache: TextCache) -> List[MatchDetail]:
        """Execute classifier matching."""
        # Get components
        cleaner = self.config_manager.get_cleaner(rule.cleaner_name)
        chunker = self.config_manager.get_chunker(rule.chunker_name)
        classifier = self.config_manager.get_classifier(rule.classifier_name)

        # Clean text (with caching)
        cleaned_text = cache.get_cleaned_text(text, cleaner, rule.cleaner_name)

        # Chunk text
        chunks = chunker.chunk(cleaned_text)

        # Classify chunks
        matches = classifier.classify_chunks(rule, chunks)

        return matches

    def _execute_llm(self, rule, text: str, cache: TextCache) -> List[MatchDetail]:
        """Execute LLM evaluation."""
        # Get LLM evaluator
        llm = self.config_manager.get_llm(rule.llm_name)

        # For LLM, we typically don't chunk - evaluate the whole text
        # But we could add a chunker if needed
        matches = llm.evaluate_chunks(rule, [text])

        return matches

    def _is_identifier_needed(
        self,
        identifier: str,
        condition: str,
        current_matches: Dict[str, List[MatchDetail]]
    ) -> bool:
        """
        Determine if an identifier needs to be evaluated based on condition.

        This enables short-circuit evaluation for expensive operations.

        Args:
            identifier: Pattern identifier (e.g., "$s5")
            condition: Condition string
            current_matches: Already evaluated patterns

        Returns:
            True if identifier might be needed, False if can skip
        """
        # Simple heuristic: if identifier appears in condition, it might be needed
        # More sophisticated would parse condition as AST and evaluate lazily

        # For now, always execute (conservative approach)
        # TODO: Implement smart short-circuit evaluation
        return True

    def _evaluate_condition(
        self,
        condition: str,
        pattern_matches: Dict[str, List[MatchDetail]]
    ) -> bool:
        """
        Evaluate boolean condition.

        Args:
            condition: Condition string (e.g., "$s1 and ($s2 or $s3)")
            pattern_matches: Dictionary of pattern matches

        Returns:
            True if condition is satisfied, False otherwise
        """
        if not condition:
            return False

        # Build evaluation context
        # Replace pattern identifiers with their boolean values
        eval_expr = condition

        # Find all identifiers in condition
        identifiers = set(re.findall(r'\$\w+', condition))

        # Replace each identifier with True/False based on matches
        for identifier in identifiers:
            has_match = identifier in pattern_matches and len(pattern_matches[identifier]) > 0
            eval_expr = eval_expr.replace(identifier, str(has_match))

        # Evaluate the expression safely
        try:
            # Use Python's eval with restricted namespace for safety
            result = eval(eval_expr, {"__builtins__": {}}, {})
            return bool(result)

        except Exception as e:
            # If evaluation fails, log and return False
            print(f"Warning: Failed to evaluate condition '{condition}': {e}")
            return False

    def __repr__(self) -> str:
        """String representation of compiled rules."""
        return f"CompiledRules(rules={len(self.rules)})"

    def __len__(self) -> int:
        """Number of compiled rules."""
        return len(self.rules)
