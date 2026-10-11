"""
Execution engine for compiled rules.
"""
from typing import Dict, List, Optional
import re
import warnings
from syara.models import Rule, Match, MatchDetail, DecisionRule
from syara.config import ConfigManager
from syara.cache import TextCache
from syara.engine.string_matcher import StringMatcher
from syara.engine.field_matcher import FieldMatcher
from syara.engine.decision_evaluator import build_question_spec, DecisionResult


class _BoolEval:
    """
    Recursive-descent parser/evaluator for boolean expressions
    containing True, False, and, or, not, and parentheses.
    Avoids the use of eval() for security.
    """

    def __init__(self, expr: str):
        self._tokens = self._tokenize(expr)
        self._pos = 0

    def _tokenize(self, expr: str):
        token_re = re.compile(
            r'\bTrue\b|\bFalse\b|\band\b|\bor\b|\bnot\b|[()]',
            re.IGNORECASE
        )
        return [m.group(0) for m in token_re.finditer(expr)]

    def _peek(self) -> Optional[str]:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def _consume(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def evaluate(self) -> bool:
        result = self._parse_or()
        return result

    def _parse_or(self) -> bool:
        left = self._parse_and()
        while self._peek() and self._peek().lower() == 'or':
            self._consume()
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        left = self._parse_not()
        while self._peek() and self._peek().lower() == 'and':
            self._consume()
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self) -> bool:
        if self._peek() and self._peek().lower() == 'not':
            self._consume()
            operand = self._parse_not()
            return not operand
        return self._parse_atom()

    def _parse_atom(self) -> bool:
        tok = self._peek()
        if tok is None:
            return False
        if tok == '(':
            self._consume()
            result = self._parse_or()
            if self._peek() == ')':
                self._consume()
            return result
        if tok.lower() == 'true':
            self._consume()
            return True
        if tok.lower() == 'false':
            self._consume()
            return False
        # Unknown token — skip it and return False
        self._consume()
        return False


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
        self.field_matcher = FieldMatcher()

    def match(self, text: str, fields: Dict[str, str] = None) -> List[Match]:
        """
        Match text against all text-based rules (strings, similarity, classifier, llm).
        Note: This will NOT match phash rules which require binary file input.

        Args:
            text: Input text to match
            fields: Optional dict of field name → value for Sigma-style field matching

        Returns:
            List of Match objects for all rules
        """
        # Create a session cache for this match operation
        cache = TextCache()

        try:
            # Execute each rule
            matches = []
            for rule in self.rules:
                match = self._execute_rule(rule, text, cache, file_path=None, fields=fields)
                matches.append(match)

            return matches

        finally:
            # Always clear cache after matching session
            cache.clear()

    def match_file(self, file_path: str, fields: Dict[str, str] = None) -> List[Match]:
        """
        Match binary file against phash rules.

        Args:
            file_path: Path to binary file (image, audio, video)
            fields: Optional dict of field name → value for Sigma-style field matching

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
                    match = self._execute_rule(rule, "", cache, file_path=file_path, fields=fields)
                    matches.append(match)

            return matches

        finally:
            cache.clear()

    def _execute_rule(self, rule: Rule, text: str, cache: TextCache, file_path: str = None, fields: Dict[str, str] = None) -> Match:
        """
        Execute a single rule against text or file.

        Args:
            rule: Rule to execute
            text: Input text (for text-based rules)
            cache: Text cache for this session
            file_path: Optional file path (for phash rules)
            fields: Optional dict of field name → value for field matching

        Returns:
            Match object with results
        """
        # Initialise every identifier with an empty list so that condition
        # constructs like "all of them" and "all of ($prefix*)" can correctly
        # evaluate identifiers that produced no matches (rather than silently
        # ignoring them and treating a partial match as "all").
        pattern_matches: Dict[str, List[MatchDetail]] = {}
        for string_rule in rule.strings:
            pattern_matches[string_rule.identifier] = []
        for sim_rule in rule.similarity:
            pattern_matches[sim_rule.identifier] = []
        for phash_rule in rule.phash:
            pattern_matches[phash_rule.identifier] = []
        for cls_rule in rule.classifier:
            pattern_matches[cls_rule.identifier] = []
        for llm_rule in rule.llm:
            pattern_matches[llm_rule.identifier] = []
        for field_rule in rule.fields:
            pattern_matches[field_rule.identifier] = []
        for dec_rule in rule.decision:
            pattern_matches[dec_rule.identifier] = []

        # Execute pattern matching in cost-optimized order

        # 1. String patterns (cheapest)
        for string_rule in rule.strings:
            matches = self.string_matcher.match(string_rule, text)
            if matches:
                pattern_matches[string_rule.identifier] = matches

        # 1.5. Field patterns (like string matching but against specific field values)
        if fields:
            for field_rule in rule.fields:
                field_value = fields.get(field_rule.field_name, '')
                if field_value:
                    matches = self.field_matcher.match(field_rule, field_value)
                    if matches:
                        pattern_matches[field_rule.identifier] = matches

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
            # Skip if classifier result cannot change the condition outcome
            if not self._is_identifier_needed(cls_rule.identifier, rule.condition, pattern_matches):
                continue
            matches = self._execute_classifier(cls_rule, text, cache)
            if matches:
                pattern_matches[cls_rule.identifier] = matches

        # 5. Decision patterns (structured model evaluation: JEV, Laya, Winnow, etc.)
        # Use a group-level short-circuit: check whether assuming ALL decision
        # identifiers are True would change the condition outcome.  This is
        # necessary because individual checks cannot detect AND-chains where
        # every identifier depends on the others (e.g. $d1 and $d2 and $d3).
        if rule.decision and self._any_decision_needed(rule.decision, rule.condition, pattern_matches):
            for identifier, matches in self._execute_decision_batch(
                rule.decision, text, fields, cache
            ).items():
                if matches:
                    pattern_matches[identifier] = matches

        # 6. LLM patterns (highest cost)
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

    def _any_decision_needed(
        self,
        decision_rules: List[DecisionRule],
        condition: str,
        current_matches: Dict[str, List[MatchDetail]],
    ) -> bool:
        """
        Group-level short-circuit for decision rules.

        Checks whether assuming ALL decision identifiers are True (optimistic)
        would change the condition outcome compared to the current state where
        they are all False.  If the outcome is the same either way, executing
        the decision models cannot affect the result and they are all skipped.

        This handles AND-chains (e.g. $d1 and $d2 and $d3) where individually
        each identifier appears unnecessary (the others are still False) but
        together they CAN flip the condition.
        """
        optimistic = dict(current_matches)
        for r in decision_rules:
            optimistic[r.identifier] = [MatchDetail(identifier=r.identifier, matched_text="")]

        try:
            cur = _BoolEval(
                self._translate_yara_condition(condition, current_matches)
            ).evaluate()
            opt = _BoolEval(
                self._translate_yara_condition(condition, optimistic)
            ).evaluate()
            return cur != opt
        except Exception:
            return True  # conservative: evaluate if unsure

    def _execute_decision_batch(
        self,
        rules: List[DecisionRule],
        text: str,
        fields: Dict,
        cache: TextCache,
    ) -> Dict[str, List[MatchDetail]]:
        """
        Execute one or more decision rules, batching by model for efficiency.

        All rules that share the same model_name are sent in a single
        `decide()` call (one question per rule identifier).  Each answer is
        then evaluated against the rule's answer_type, positive_label, and
        threshold to produce a list of MatchDetail objects.

        Returns:
            Dict mapping identifier -> List[MatchDetail]
        """
        results: Dict[str, List[MatchDetail]] = {r.identifier: [] for r in rules}

        # Group rules by model so we can batch into one API call per model
        by_model: Dict[str, List[DecisionRule]] = {}
        for rule in rules:
            by_model.setdefault(rule.model_name, []).append(rule)

        for model_name, model_rules in by_model.items():
            try:
                evaluator = self.config_manager.get_decision_evaluator(model_name)
            except ValueError as e:
                warnings.warn(str(e), UserWarning, stacklevel=2)
                continue

            # Build questions dict: one entry per rule (key = bare identifier)
            questions = {}
            for rule in model_rules:
                key = rule.identifier.lstrip('$')
                cleaner = self.config_manager.get_cleaner(rule.cleaner_name)
                cleaned_text = cache.get_cleaned_text(text, cleaner, rule.cleaner_name)
                questions[key] = build_question_spec(
                    rule.answer_type, rule.question, rule.positive_label
                )

            # Build state: merge cleaned text with fields if available
            # Use the first rule's cleaner for the shared text (all share the same text)
            first_rule = model_rules[0]
            cleaner = self.config_manager.get_cleaner(first_rule.cleaner_name)
            cleaned_text = cache.get_cleaned_text(text, cleaner, first_rule.cleaner_name)
            state = {"content": cleaned_text, **(fields or {})} if fields else cleaned_text

            try:
                decision_result: DecisionResult = evaluator.decide(state, questions)
            except Exception as e:
                warnings.warn(
                    f"Decision evaluator '{model_name}' failed: {e}",
                    UserWarning, stacklevel=2
                )
                continue

            # Map each answer back to its rule
            for rule in model_rules:
                key = rule.identifier.lstrip('$')
                detail = self._evaluate_decision_answer(rule, key, decision_result)
                if detail:
                    results[rule.identifier] = [detail]

        return results

    @staticmethod
    def _evaluate_decision_answer(
        rule: DecisionRule,
        answer_key: str,
        result: DecisionResult,
    ) -> Optional[MatchDetail]:
        """
        Extract and threshold a single answer from a DecisionResult.

        Returns a MatchDetail if the answer constitutes a match, else None.
        """
        if rule.answer_type == 'choice':
            answer = result.choices.get(answer_key)
            if not answer:
                return None
            chosen = answer.get('choice', '')
            confidence = float(answer.get('confidence', 0.0))
            if chosen == rule.positive_label and confidence >= rule.threshold:
                return MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chosen,
                    score=confidence,
                    explanation=f"Decision choice='{chosen}' confidence={confidence:.3f}",
                )

        elif rule.answer_type == 'noul':
            prob = result.nouls.get(answer_key)
            if prob is None:
                return None
            prob = float(prob)
            if prob >= rule.threshold:
                return MatchDetail(
                    identifier=rule.identifier,
                    matched_text=f"noul={prob:.3f}",
                    score=prob,
                    explanation=f"Decision noul={prob:.3f} >= threshold={rule.threshold}",
                )

        elif rule.answer_type == 'score':
            answer = result.scores.get(answer_key)
            if not answer:
                return None
            score_val = float(answer.get('score', 0.0))
            confidence = float(answer.get('confidence', 1.0))
            if score_val >= rule.threshold:
                return MatchDetail(
                    identifier=rule.identifier,
                    matched_text=f"score={score_val:.2f}",
                    score=score_val / 4.0,  # normalise to [0,1] assuming 0-4 scale
                    explanation=f"Decision score={score_val:.2f} >= threshold={rule.threshold}",
                )

        return None

    def _execute_llm(self, rule, text: str, cache: TextCache) -> List[MatchDetail]:
        """Execute LLM evaluation."""
        # Get components
        cleaner = self.config_manager.get_cleaner(rule.cleaner_name)
        chunker = self.config_manager.get_chunker(rule.chunker_name)
        llm = self.config_manager.get_llm(rule.llm_name)

        # Clean text (with caching) then chunk
        cleaned_text = cache.get_cleaned_text(text, cleaner, rule.cleaner_name)
        chunks = chunker.chunk(cleaned_text)

        matches = llm.evaluate_chunks(rule, chunks)

        return matches

    def _is_identifier_needed(
        self,
        identifier: str,
        condition: str,
        current_matches: Dict[str, List[MatchDetail]]
    ) -> bool:
        """
        Determine if an identifier needs to be evaluated based on condition.

        Compares the condition result with identifier absent vs present.
        If the result differs, the identifier can change the outcome and must be evaluated.
        """
        # State without this identifier (set to empty)
        matches_without = dict(current_matches)
        matches_without[identifier] = []

        # State with this identifier (optimistically set to matched)
        matches_with = dict(current_matches)
        matches_with[identifier] = [MatchDetail(identifier=identifier, matched_text="")]

        try:
            expr_without = self._translate_yara_condition(condition, matches_without)
            expr_with = self._translate_yara_condition(condition, matches_with)
            result_without = _BoolEval(expr_without).evaluate()
            result_with = _BoolEval(expr_with).evaluate()
            return result_without != result_with
        except Exception:
            return True  # conservative: evaluate if unsure

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
            result = _BoolEval(eval_expr).evaluate()
            return bool(result)
        except Exception as e:
            warnings.warn(
                f"Failed to evaluate condition '{condition}': {e}",
                UserWarning,
                stacklevel=2,
            )
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
        # Normalize whitespace: collapse newlines/tabs to single spaces so that
        # eval() can handle multi-line conditions from .syara files.
        eval_expr = re.sub(r'\s+', ' ', condition).strip()

        # Handle "any of them" / "all of them" — refers to ALL defined identifiers
        for match in re.finditer(r'any\s+of\s+them', eval_expr, re.IGNORECASE):
            all_ids = list(pattern_matches.keys())
            if all_ids:
                replacement = "(" + " or ".join(
                    str(len(pattern_matches[i]) > 0) for i in all_ids
                ) + ")"
            else:
                replacement = "False"
            eval_expr = eval_expr.replace(match.group(0), replacement)

        for match in re.finditer(r'all\s+of\s+them', eval_expr, re.IGNORECASE):
            all_ids = list(pattern_matches.keys())
            if all_ids:
                replacement = "(" + " and ".join(
                    str(len(pattern_matches[i]) > 0) for i in all_ids
                ) + ")"
            else:
                replacement = "False"
            eval_expr = eval_expr.replace(match.group(0), replacement)

        # Handle "any of" and "all of" wildcard patterns.
        # Two forms supported:
        #   any of ($prefix*)   — parens wrap the wildcard
        #   any of $prefix*     — bare wildcard (e.g. inside outer parentheses)
        any_of_pattern = r'any\s+of\s+\(\s*(\$\w+)\*\s*\)'
        any_of_bare    = r'any\s+of\s+(\$\w+)\*'
        all_of_pattern = r'all\s+of\s+\(\s*(\$\w+)\*\s*\)'
        all_of_bare    = r'all\s+of\s+(\$\w+)\*'

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

        # Replace bare "any of $prefix*" (no parens around wildcard)
        for match in re.finditer(any_of_bare, eval_expr, re.IGNORECASE):
            prefix = match.group(1)
            matching_ids = [id for id in pattern_matches.keys() if id.startswith(prefix)]
            if matching_ids:
                replacement = "(" + " or ".join(
                    str(len(pattern_matches[i]) > 0) for i in matching_ids
                ) + ")"
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

        # Replace bare "all of $prefix*" (no parens around wildcard)
        for match in re.finditer(all_of_bare, eval_expr, re.IGNORECASE):
            prefix = match.group(1)
            matching_ids = [id for id in pattern_matches.keys() if id.startswith(prefix)]
            if matching_ids:
                replacement = "(" + " and ".join(
                    str(len(pattern_matches[i]) > 0) for i in matching_ids
                ) + ")"
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

    def match_any(self, text: str, fields: Dict[str, str] = None) -> List[Match]:
        """
        Match text and return only rules that matched.

        Args:
            text: Input text to match
            fields: Optional dict of field name → value for field matching

        Returns:
            List of Match objects where matched=True
        """
        return [m for m in self.match(text, fields=fields) if m.matched]

    def matched(self, text: str, fields: Dict[str, str] = None) -> bool:
        """
        Check if any rule matches the text.

        Args:
            text: Input text to match
            fields: Optional dict of field name → value for field matching

        Returns:
            True if any rule matched, False otherwise
        """
        return any(m.matched for m in self.match(text, fields=fields))

    def __repr__(self) -> str:
        """String representation of compiled rules."""
        return f"CompiledRules(rules={len(self.rules)})"

    def __len__(self) -> int:
        """Number of compiled rules."""
        return len(self.rules)
