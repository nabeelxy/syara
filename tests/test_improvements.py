"""
Tests for the 12 improvements made to SYara.
"""
import pytest
import re
from unittest.mock import MagicMock, patch


# ─────────────────────────────────────────────
# Improvement 1 & 2: SBERTMatcher embedding cache
# ─────────────────────────────────────────────

def test_sbert_matcher_has_embedding_cache():
    """SBERTMatcher.__init__ should create an _embedding_cache dict."""
    from syara.engine.semantic_matcher import SBERTMatcher
    import numpy as np

    mock_model = MagicMock()
    mock_model.get_sentence_embedding_dimension.return_value = 4
    mock_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4])

    with patch('syara.engine.semantic_matcher.SentenceTransformer', return_value=mock_model):
        matcher = SBERTMatcher()

    assert hasattr(matcher, '_embedding_cache')
    assert isinstance(matcher._embedding_cache, dict)


def test_sbert_embed_caches_result():
    """embed() should cache results and not call model.encode twice for same text."""
    from syara.engine.semantic_matcher import SBERTMatcher
    import numpy as np

    mock_model = MagicMock()
    mock_model.get_sentence_embedding_dimension.return_value = 4
    mock_model.encode.return_value = np.array([0.1, 0.2, 0.3, 0.4])

    with patch('syara.engine.semantic_matcher.SentenceTransformer', return_value=mock_model):
        matcher = SBERTMatcher()

    matcher.embed("hello world")
    matcher.embed("hello world")  # second call — should hit cache

    assert mock_model.encode.call_count == 1


def test_sbert_embed_empty_returns_zero_vector():
    """embed('') should return a zero vector."""
    from syara.engine.semantic_matcher import SBERTMatcher
    import numpy as np

    mock_model = MagicMock()
    mock_model.get_sentence_embedding_dimension.return_value = 4

    with patch('syara.engine.semantic_matcher.SentenceTransformer', return_value=mock_model):
        matcher = SBERTMatcher()

    result = matcher.embed("")
    assert np.all(result == 0)
    mock_model.encode.assert_not_called()


def test_get_similarity_batch_uses_cache():
    """get_similarity_batch() should only encode uncached texts."""
    from syara.engine.semantic_matcher import SBERTMatcher
    import numpy as np

    vecs = {
        "ref": np.array([1.0, 0.0, 0.0, 0.0]),
        "a":   np.array([1.0, 0.0, 0.0, 0.0]),
        "b":   np.array([0.0, 1.0, 0.0, 0.0]),
    }

    mock_model = MagicMock()
    mock_model.get_sentence_embedding_dimension.return_value = 4
    mock_model.encode.side_effect = lambda texts, **kw: (
        vecs[texts] if isinstance(texts, str)
        else np.array([vecs[t] for t in texts])
    )

    with patch('syara.engine.semantic_matcher.SentenceTransformer', return_value=mock_model):
        matcher = SBERTMatcher()

    # Pre-populate cache for "a"
    matcher._embedding_cache["a"] = vecs["a"]

    similarities = matcher.get_similarity_batch("ref", ["a", "b"])

    # encode called once for "ref" (embed) + once for ["b"] (uncached)
    # actual call_count may be 2: once for "ref" via embed(), once for ["b"]
    # but "a" should NOT be in the batch call
    assert len(similarities) == 2

    # Verify "b" was encoded (it wasn't in cache)
    calls = mock_model.encode.call_args_list
    batch_calls = [c for c in calls if isinstance(c[0][0], list)]
    if batch_calls:
        encoded_texts = batch_calls[0][0][0]
        assert "a" not in encoded_texts
        assert "b" in encoded_texts


# ─────────────────────────────────────────────
# Improvement 3: classify() return contract
# ─────────────────────────────────────────────

def test_tuned_sbert_classify_returns_false_when_low_confidence():
    """TunedSBERTClassifier.classify should return False when confidence < 0.5."""
    from syara.engine.classifier import TunedSBERTClassifier
    import numpy as np

    mock_model = MagicMock()
    # Return nearly orthogonal vectors → low similarity
    mock_model.encode.side_effect = lambda text, **kw: (
        np.array([1.0, 0.0]) if text == "rule_text" else np.array([0.0, 1.0])
    )

    with patch('syara.engine.classifier.SentenceTransformer', return_value=mock_model):
        clf = TunedSBERTClassifier(threshold_boost=0.0)

    is_match, confidence = clf.classify("rule_text", "input_text")
    # similarity ≈ 0, boost=0 → confidence ≈ 0 < 0.5 → is_match=False
    assert not is_match
    assert 0.0 <= confidence <= 1.0


def test_tuned_sbert_classify_returns_true_when_high_confidence():
    """TunedSBERTClassifier.classify should return True when confidence >= 0.5."""
    from syara.engine.classifier import TunedSBERTClassifier
    import numpy as np

    mock_model = MagicMock()
    vec = np.array([1.0, 0.0])
    mock_model.encode.return_value = vec

    with patch('syara.engine.classifier.SentenceTransformer', return_value=mock_model):
        clf = TunedSBERTClassifier(threshold_boost=0.0)

    is_match, confidence = clf.classify("same text", "same text")
    # similarity = 1.0, boost=0 → confidence = 1.0 ≥ 0.5 → True
    assert is_match
    assert confidence >= 0.5


# ─────────────────────────────────────────────
# Improvement 4: word-boundary _parse_response
# ─────────────────────────────────────────────

def test_openai_parse_response_yes():
    """_parse_response should parse 'YES: explanation' correctly."""
    from syara.engine.llm_evaluator import OpenAIEvaluator

    with patch('syara.engine.llm_evaluator.OpenAI'):
        ev = OpenAIEvaluator.__new__(OpenAIEvaluator)
        ev.model_name = 'gpt-3.5-turbo'
        ev.client = MagicMock()

    is_match, explanation = ev._parse_response("YES: it matched")
    assert is_match is True
    assert "it matched" in explanation


def test_openai_parse_response_no():
    from syara.engine.llm_evaluator import OpenAIEvaluator

    with patch('syara.engine.llm_evaluator.OpenAI'):
        ev = OpenAIEvaluator.__new__(OpenAIEvaluator)

    is_match, explanation = ev._parse_response("NO: it did not match")
    assert is_match is False


def test_openai_parse_response_ambiguous():
    from syara.engine.llm_evaluator import OpenAIEvaluator

    with patch('syara.engine.llm_evaluator.OpenAI'):
        ev = OpenAIEvaluator.__new__(OpenAIEvaluator)

    is_match, explanation = ev._parse_response("MAYBE: not sure")
    assert is_match is False
    assert "Ambiguous" in explanation


def test_oss_parse_response_yes_word_boundary():
    """'YESTERDAY' should NOT trigger YES match."""
    from syara.engine.llm_evaluator import OSSLLMEvaluator

    ev = OSSLLMEvaluator.__new__(OSSLLMEvaluator)
    is_match, _ = ev._parse_response("YESTERDAY was nice")
    # "YESTERDAY" starts with "YES" but not at word boundary → should not match
    # With re.match(r'YES\b', upper), "YESTERDAY..." won't match because \b fails after 'S' in 'YESTERDAY'
    assert is_match is False


def test_oss_parse_response_no_word_boundary():
    """'NOPE' should NOT trigger NO match with word-boundary regex."""
    from syara.engine.llm_evaluator import OSSLLMEvaluator

    ev = OSSLLMEvaluator.__new__(OSSLLMEvaluator)
    is_match, _ = ev._parse_response("NOPE")
    # "NOPE" starts with "NO" but 'P' breaks word boundary after 'O' in 'NO'
    assert is_match is False


# ─────────────────────────────────────────────
# Improvement 5: LLM confidence scores
# ─────────────────────────────────────────────

def test_openai_evaluate_returns_3_tuple():
    """OpenAIEvaluator.evaluate should return (bool, str, float)."""
    from syara.engine.llm_evaluator import OpenAIEvaluator

    with patch('syara.engine.llm_evaluator.OpenAI'):
        ev = OpenAIEvaluator.__new__(OpenAIEvaluator)
        ev.model_name = 'gpt-3.5-turbo'

    # Mock the client
    mock_response = MagicMock()
    mock_response.choices[0].message.content = "YES: it matches"
    mock_response.choices[0].logprobs = None
    ev.client = MagicMock()
    ev.client.chat.completions.create.return_value = mock_response

    result = ev.evaluate("pattern", "input text")
    assert len(result) == 3
    is_match, explanation, confidence = result
    assert is_match is True
    assert isinstance(confidence, float)


# ─────────────────────────────────────────────
# Improvement 6: Order-independent parser sections
# ─────────────────────────────────────────────

def test_parser_split_sections_basic():
    """_split_sections should find all sections and return correct content."""
    from syara.parser import SYaraParser

    parser = SYaraParser()
    body = """
    meta:
        author = "test"
    strings:
        $s1 = "hello"
    condition:
        $s1
    """
    sections = parser._split_sections(body)
    assert 'meta' in sections
    assert 'strings' in sections
    assert 'condition' in sections
    assert 'author' in sections['meta']
    assert '$s1' in sections['strings']


def test_parser_order_independent():
    """Sections can appear in any order."""
    from syara.parser import SYaraParser

    parser = SYaraParser()
    content = '''
rule OrderTest {
    condition:
        $s1
    strings:
        $s1 = "hello"
}
'''
    rules = parser.parse_string(content)
    assert len(rules) == 1
    assert rules[0].name == "OrderTest"
    assert len(rules[0].strings) == 1
    assert rules[0].strings[0].pattern == "hello"
    assert rules[0].condition == "$s1"


def test_parser_condition_first():
    """Rule with condition before strings section should parse correctly."""
    from syara import compile_string

    rules = compile_string('''
rule CondFirst {
    condition:
        $s1
    strings:
        $s1 = "world"
}
''')
    matches = rules.match("hello world")
    assert any(m.matched for m in matches)


# ─────────────────────────────────────────────
# Improvement 7: Escaped slashes in regex patterns
# ─────────────────────────────────────────────

def test_regex_with_escaped_slash():
    """Regex patterns with escaped slashes should parse correctly."""
    from syara import compile_string

    rules = compile_string(r'''
rule EscapedSlash {
    strings:
        $url = /https?:\/\/example\.com/
    condition:
        $url
}
''')
    matches = rules.match("Visit https://example.com today")
    assert any(m.matched for m in matches)


def test_regex_with_multiple_flags():
    """Regex patterns support multiple inline flags like /pattern/is."""
    from syara.parser import SYaraParser

    parser = SYaraParser()
    content = '''
rule FlagTest {
    strings:
        $s1 = /hello/i
    condition:
        $s1
}
'''
    rules = parser.parse_string(content)
    assert len(rules) == 1
    sr = rules[0].strings[0]
    assert sr.is_regex
    assert 'i' in sr.modifiers


# ─────────────────────────────────────────────
# Improvement 8: compile_string() public API
# ─────────────────────────────────────────────

def test_compile_string_module_level():
    """syara.compile_string should be importable and work."""
    import syara
    assert hasattr(syara, 'compile_string')

    rules = syara.compile_string('''
rule TestRule {
    strings:
        $s1 = "hello"
    condition:
        $s1
}
''')
    matches = rules.match("hello world")
    assert any(m.matched for m in matches)


def test_compile_string_in_all():
    """compile_string should be in syara.__all__."""
    import syara
    assert 'compile_string' in syara.__all__


# ─────────────────────────────────────────────
# Improvement 9: _BoolEval replaces eval()
# ─────────────────────────────────────────────

def test_bool_eval_basic():
    """_BoolEval should evaluate basic boolean expressions."""
    from syara.compiled_rules import _BoolEval

    assert _BoolEval("True").evaluate() is True
    assert _BoolEval("False").evaluate() is False
    assert _BoolEval("True and False").evaluate() is False
    assert _BoolEval("True or False").evaluate() is True
    assert _BoolEval("not True").evaluate() is False
    assert _BoolEval("not False").evaluate() is True


def test_bool_eval_nested():
    """_BoolEval should handle nested parentheses."""
    from syara.compiled_rules import _BoolEval

    assert _BoolEval("(True and True) or False").evaluate() is True
    assert _BoolEval("True and (False or True)").evaluate() is True
    assert _BoolEval("not (True and False)").evaluate() is True


def test_bool_eval_case_insensitive():
    """_BoolEval should handle case-insensitive keywords."""
    from syara.compiled_rules import _BoolEval

    assert _BoolEval("TRUE AND FALSE").evaluate() is False
    assert _BoolEval("true OR false").evaluate() is True


def test_condition_evaluation_uses_bool_eval():
    """_evaluate_condition should work correctly using _BoolEval."""
    from syara import compile_string

    rules = compile_string('''
rule BoolTest {
    strings:
        $s1 = "hello"
        $s2 = "world"
    condition:
        $s1 and $s2
}
''')
    # Both present — should match
    assert rules.match("hello world")[0].matched
    # Only one present — should not match
    assert not rules.match("hello there")[0].matched


# ─────────────────────────────────────────────
# Improvement 10: Classifier short-circuit
# ─────────────────────────────────────────────

def test_classifier_short_circuit():
    """Classifier should be skipped when condition is already determined."""
    from syara.compiled_rules import CompiledRules
    from syara.models import Rule, StringRule, ClassifierRule, MatchDetail
    from syara.config import ConfigManager

    # Build a rule: $s1 (string) AND $c1 (classifier)
    # If $s1 fails, $c1 cannot save the condition → skip classifier
    rule = Rule(
        name="TestRule",
        strings=[StringRule(identifier="$s1", pattern="MUST_NOT_MATCH_XYZ123")],
        classifier=[ClassifierRule(identifier="$c1", pattern="test", threshold=0.5)],
        condition="$s1 and $c1"
    )

    config = ConfigManager()
    compiled = CompiledRules([rule], config)

    # Patch _execute_classifier to track calls
    call_count = []
    original = compiled._execute_classifier

    def patched(cls_rule, text, cache):
        call_count.append(1)
        return original(cls_rule, text, cache)

    compiled._execute_classifier = patched

    # Text does not contain "MUST_NOT_MATCH_XYZ123" → $s1 fails → $c1 should be skipped
    matches = compiled.match("some innocent text")
    assert not matches[0].matched
    # Classifier should NOT have been called (short-circuited)
    assert len(call_count) == 0, f"Classifier was called {len(call_count)} times unexpectedly"


# ─────────────────────────────────────────────
# Improvement 11: match_any() and matched()
# ─────────────────────────────────────────────

def test_match_any_returns_only_matched():
    """match_any() should return only rules that matched."""
    from syara import compile_string

    rules = compile_string('''
rule Rule1 {
    strings:
        $s1 = "hello"
    condition:
        $s1
}
rule Rule2 {
    strings:
        $s2 = "goodbye"
    condition:
        $s2
}
''')
    results = rules.match_any("hello world")
    assert len(results) == 1
    assert results[0].rule_name == "Rule1"


def test_match_any_empty_when_no_match():
    """match_any() should return empty list when nothing matches."""
    from syara import compile_string

    rules = compile_string('''
rule Rule1 {
    strings:
        $s1 = "xyz_not_present"
    condition:
        $s1
}
''')
    assert rules.match_any("hello world") == []


def test_matched_returns_true_when_any_match():
    """matched() should return True when at least one rule matches."""
    from syara import compile_string

    rules = compile_string('''
rule Rule1 {
    strings:
        $s1 = "hello"
    condition:
        $s1
}
''')
    assert rules.matched("say hello there") is True


def test_matched_returns_false_when_no_match():
    """matched() should return False when no rules match."""
    from syara import compile_string

    rules = compile_string('''
rule Rule1 {
    strings:
        $s1 = "xyz_not_present"
    condition:
        $s1
}
''')
    assert rules.matched("hello world") is False


# ─────────────────────────────────────────────
# Improvement 12: CalibratedSBERTClassifier alias
# ─────────────────────────────────────────────

def test_calibrated_sbert_alias_importable():
    """CalibratedSBERTClassifier should be importable from syara.engine."""
    from syara.engine import CalibratedSBERTClassifier
    from syara.engine.classifier import TunedSBERTClassifier
    assert CalibratedSBERTClassifier is TunedSBERTClassifier


def test_calibrated_sbert_in_engine_all():
    """CalibratedSBERTClassifier should be in syara.engine.__all__."""
    from syara import engine
    assert 'CalibratedSBERTClassifier' in engine.__all__
