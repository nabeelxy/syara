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
    Executes rules in cost-optimized order: strings → similarity → phash → classifier → llm
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
        Match text against all text-based rules (strings, similarity, classifier, llm).
        Note: This will NOT match phash rules which require binary file input.

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
                match = self._execute_rule(rule, text, cache, file_path=None)
                matches.append(match)

            return matches

        finally:
            # Always clear cache after matching session
            cache.clear()

    def match_file(self, file_path: str) -> List[Match]:
        """
        Match binary file against phash rules.

        Args:
            file_path: Path to binary file (image, audio, video)

        Returns:
            List of Match objects for rules containing phash patterns
        """
        # Create a session cache (not used for phash but kept for consistency)
        cache = TextCache()

        try:
            # Execute each rule that has phash patterns
            matches = []
            for rule in self.rules:
                if rule.phash:  # Only execute rules with phash patterns
                    match = self._execute_rule(rule, "", cache, file_path=file_path)
                    matches.append(match)

            return matches

        finally:
            cache.clear()

    def _execute_rule(self, rule: Rule, text: str, cache: TextCache, file_path: str = None) -> Match:
        """
        Execute a single rule against text or file.

        Args:
            rule: Rule to execute
            text: Input text (for text-based rules)
            cache: Text cache for this session
            file_path: Optional file path (for phash rules)

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

        # 3. Phash patterns (moderate-to-high cost) - only if file_path provided
        if file_path:
            for phash_rule in rule.phash:
                matches = self._execute_phash(phash_rule, file_path)
                if matches:
                    pattern_matches[phash_rule.identifier] = matches

        # 4. Classifier patterns (higher cost)
        for cls_rule in rule.classifier:
            matches = self._execute_classifier(cls_rule, text, cache)
            if matches:
                pattern_matches[cls_rule.identifier] = matches

        # 5. LLM patterns (highest cost)
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

    def _execute_phash(self, rule, file_path: str) -> List[MatchDetail]:
        """Execute phash matching on binary files."""
        # Get phash matcher
        phash_matcher = self.config_manager.get_phash_matcher(rule.phash_name)

        # Compute similarity between reference file and input file
        try:
            similarity = phash_matcher.similarity(rule.file_path, file_path)

            # Check if similarity meets threshold
            if similarity >= rule.threshold:
                return [MatchDetail(
                    identifier=rule.identifier,
                    matched_text=f"File: {file_path}",
                    score=similarity
                )]
        except Exception as e:
            # If hashing fails (file not found, wrong format, etc.), return no matches
            import warnings
            warnings.warn(f"PHash matching failed for {file_path}: {e}")

        return []

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
        Evaluate boolean condition with YARA syntax support.

        Args:
            condition: Condition string (e.g., "$s1 and ($s2 or $s3)" or "any of ($dan*)")
            pattern_matches: Dictionary of pattern matches

        Returns:
            True if condition is satisfied, False otherwise
        """
        if not condition:
            return False

        # Translate YARA syntax to Python
        eval_expr = self._translate_yara_condition(condition, pattern_matches)

        # Evaluate the expression safely
        try:
            # Use Python's eval with restricted namespace for safety
            result = eval(eval_expr, {"__builtins__": {}}, {})
            return bool(result)

        except Exception as e:
            # If evaluation fails, log and return False
            print(f"Warning: Failed to evaluate condition '{condition}': {e}")
            return False

    def _translate_yara_condition(
        self,
        condition: str,
        pattern_matches: Dict[str, List[MatchDetail]]
    ) -> str:
        """
        Translate YARA condition syntax to Python boolean expression.

        Handles:
        - Simple identifiers: $s1 -> True/False
        - Wildcards: any of ($dan*) -> (True or False or ...)
        - all of: all of ($s*) -> (True and False and ...)
        - Boolean operators: and, or, not

        Args:
            condition: YARA condition string
            pattern_matches: Dictionary of pattern matches

        Returns:
            Python boolean expression string
        """
        eval_expr = condition

        # Handle "any of" and "all of" patterns
        # Pattern: any of ($identifier*) or all of ($identifier*)
        any_of_pattern = r'any\s+of\s+\(\s*(\$\w+)\*\s*\)'
        all_of_pattern = r'all\s+of\s+\(\s*(\$\w+)\*\s*\)'

        # Replace "any of ($prefix*)" with OR of matching identifiers
        for match in re.finditer(any_of_pattern, eval_expr, re.IGNORECASE):
            prefix = match.group(1)
            # Find all identifiers that start with this prefix
            matching_ids = [id for id in pattern_matches.keys() if id.startswith(prefix)]

            if matching_ids:
                # Build OR expression
                or_parts = []
                for id in matching_ids:
                    has_match = len(pattern_matches[id]) > 0
                    or_parts.append(str(has_match))
                replacement = f"({' or '.join(or_parts)})"
            else:
                replacement = "False"

            eval_expr = eval_expr.replace(match.group(0), replacement)

        # Replace "all of ($prefix*)" with AND of matching identifiers
        for match in re.finditer(all_of_pattern, eval_expr, re.IGNORECASE):
            prefix = match.group(1)
            # Find all identifiers that start with this prefix
            matching_ids = [id for id in pattern_matches.keys() if id.startswith(prefix)]

            if matching_ids:
                # Build AND expression
                and_parts = []
                for id in matching_ids:
                    has_match = len(pattern_matches[id]) > 0
                    and_parts.append(str(has_match))
                replacement = f"({' and '.join(and_parts)})"
            else:
                replacement = "False"

            eval_expr = eval_expr.replace(match.group(0), replacement)

        # Find all remaining simple identifiers in condition
        identifiers = set(re.findall(r'\$\w+', eval_expr))

        # Replace each identifier with True/False based on matches
        # Sort by length (longest first) to avoid partial replacements
        for identifier in sorted(identifiers, key=len, reverse=True):
            has_match = identifier in pattern_matches and len(pattern_matches[identifier]) > 0
            # Replace all occurrences of this exact identifier
            # Use negative lookahead to avoid replacing $s1 when looking for $s10
            eval_expr = re.sub(re.escape(identifier) + r'(?!\w)', str(has_match), eval_expr)

        return eval_expr

    def __repr__(self) -> str:
        """String representation of compiled rules."""
        return f"CompiledRules(rules={len(self.rules)})"

    def __len__(self) -> int:
        """Number of compiled rules."""
        return len(self.rules)
