"""
Tests for the decision: section — structured model evaluation (JEV/Laya/Winnow-style).

All tests use a MockDecisionEvaluator registered at runtime; no external model
dependencies are required.
"""
import pytest
from unittest.mock import MagicMock

import syara
from syara.compiled_rules import CompiledRules
from syara.compiler import SYaraCompiler
from syara.config import ConfigManager
from syara.engine.decision_evaluator import (
    DecisionEvaluator,
    DecisionResult,
    build_question_spec,
    _auto_criteria_choice,
    _auto_criteria_noul,
    _auto_criteria_score,
)
from syara.models import DecisionRule, Rule, StringRule, MatchDetail
from syara.parser import SYaraParser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_evaluator(result: DecisionResult) -> DecisionEvaluator:
    """Return a DecisionEvaluator that always returns `result`."""
    class _Mock(DecisionEvaluator):
        def decide(self, state, questions):
            return result
    return _Mock()


def _cfg_with(evaluator: DecisionEvaluator, name: str = "mock") -> ConfigManager:
    cfg = ConfigManager()
    cfg.register_decision_evaluator(name, evaluator)
    return cfg


def _compile_with(rule_text: str, evaluator: DecisionEvaluator, name: str = "mock") -> CompiledRules:
    cfg = _cfg_with(evaluator, name)
    return SYaraCompiler(config_manager=cfg).compile_string(rule_text)


# ---------------------------------------------------------------------------
# DecisionResult dataclass
# ---------------------------------------------------------------------------

class TestDecisionResult:
    def test_empty_result(self):
        r = DecisionResult()
        assert r.choices == {}
        assert r.nouls == {}
        assert r.scores == {}

    def test_populated_result(self):
        r = DecisionResult(
            choices={"verdict": {"choice": "malicious", "confidence": 0.9, "probabilities": {}}},
            nouls={"prob": 0.8},
            scores={"severity": {"score": 3.5, "confidence": 0.85, "probabilities": {}}},
        )
        assert r.choices["verdict"]["choice"] == "malicious"
        assert r.nouls["prob"] == 0.8
        assert r.scores["severity"]["score"] == 3.5


# ---------------------------------------------------------------------------
# build_question_spec helper
# ---------------------------------------------------------------------------

class TestBuildQuestionSpec:
    def test_choice_spec(self):
        spec = build_question_spec("choice", "Is this malicious?", positive_label="malicious")
        assert spec["type"] == "choice"
        assert spec["instructions"] == "Is this malicious?"
        assert "malicious" in spec["criteria"]

    def test_noul_spec(self):
        spec = build_question_spec("noul", "Probability of attack.")
        assert spec["type"] == "noul"
        assert "true" in spec["criteria"]
        assert "false" in spec["criteria"]

    def test_score_spec(self):
        spec = build_question_spec("score", "Rate severity 0-4.")
        assert spec["type"] == "score"
        assert isinstance(spec["criteria"], list)
        assert len(spec["criteria"]) == 5

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown decision answer_type"):
            build_question_spec("unknown", "question")


# ---------------------------------------------------------------------------
# DecisionEvaluator ABC
# ---------------------------------------------------------------------------

class TestDecisionEvaluatorABC:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            DecisionEvaluator()

    def test_concrete_subclass_works(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9}))
        result = ev.decide("some text", {"d1": {"type": "noul", "instructions": "..."}})
        assert result.nouls["d1"] == 0.9

    def test_importable_from_engine(self):
        from syara.engine import DecisionEvaluator as DE, DecisionResult as DR
        assert DE is DecisionEvaluator
        assert DR is DecisionResult

    def test_importable_from_syara(self):
        from syara import DecisionRule
        assert DecisionRule is syara.DecisionRule


# ---------------------------------------------------------------------------
# Parser: decision: section
# ---------------------------------------------------------------------------

class TestDecisionParser:
    def _parse(self, content: str):
        return SYaraParser().parse_string(content)

    def test_parse_choice_verdict(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Is this malicious?" model="jev" verdict="malicious" threshold=0.7
            condition:
                $d1
        }
        ''')
        rule = rules[0]
        assert len(rule.decision) == 1
        d = rule.decision[0]
        assert d.identifier == "$d1"
        assert d.question == "Is this malicious?"
        assert d.model_name == "jev"
        assert d.answer_type == "choice"
        assert d.positive_label == "malicious"
        assert abs(d.threshold - 0.7) < 1e-6

    def test_parse_noul(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Clickfix probability" model="laya" noul=0.6
            condition:
                $d1
        }
        ''')
        d = rules[0].decision[0]
        assert d.answer_type == "noul"
        assert abs(d.threshold - 0.6) < 1e-6

    def test_parse_score(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Rate severity" model="winnow" score=3.0
            condition:
                $d1
        }
        ''')
        d = rules[0].decision[0]
        assert d.answer_type == "score"
        assert abs(d.threshold - 3.0) < 1e-6

    def test_parse_multiple_decision_rules(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Is this malicious?" model="jev"  verdict="yes"  threshold=0.6
                $d2 = "Threat probability"  model="laya" noul=0.7
            condition:
                $d1 or $d2
        }
        ''')
        assert len(rules[0].decision) == 2

    def test_parse_with_cleaner(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Bad content?" model="jev" verdict="yes" cleaner="default_cleaning"
            condition:
                $d1
        }
        ''')
        assert rules[0].decision[0].cleaner_name == "default_cleaning"

    def test_parse_default_cleaner_noop(self):
        rules = self._parse('''
        rule r {
            decision:
                $d1 = "Bad?" model="jev" verdict="yes"
            condition:
                $d1
        }
        ''')
        assert rules[0].decision[0].cleaner_name == "no_op"

    def test_decision_before_condition_order_independent(self):
        """decision: section works before condition: (order independence)."""
        rules = self._parse('''
        rule r {
            condition:
                $d1
            decision:
                $d1 = "Bad?" model="jev" verdict="yes"
        }
        ''')
        assert len(rules[0].decision) == 1
        assert "$d1" in rules[0].condition

    def test_missing_model_skips_line(self):
        """Lines without model= are silently skipped."""
        rules = self._parse('''
        rule r {
            strings:
                $s1 = "trigger"
            decision:
                $d1 = "No model specified"
            condition:
                $s1
        }
        ''')
        assert len(rules[0].decision) == 0


# ---------------------------------------------------------------------------
# ConfigManager: decision evaluator registration
# ---------------------------------------------------------------------------

class TestConfigManagerDecision:
    def test_register_and_get_instance(self):
        ev = _make_evaluator(DecisionResult())
        cfg = ConfigManager()
        cfg.register_decision_evaluator("test-ev", ev)
        assert cfg.get_decision_evaluator("test-ev") is ev

    def test_register_string_class_path(self):
        """A dotted class-path string is instantiated on first get."""
        cfg = ConfigManager()
        # Use a built-in class that takes no args as a smoke test
        cfg.register_decision_evaluator(
            "noop-list",
            "syara.engine.cleaner.NoOpCleaner"  # wrong type, but tests instantiation
        )
        # get_decision_evaluator instantiates — just check no error
        obj = cfg.get_decision_evaluator("noop-list")
        assert obj is not None

    def test_caching(self):
        ev = _make_evaluator(DecisionResult())
        cfg = ConfigManager()
        cfg.register_decision_evaluator("cached", ev)
        assert cfg.get_decision_evaluator("cached") is cfg.get_decision_evaluator("cached")

    def test_unknown_evaluator_raises(self):
        cfg = ConfigManager()
        with pytest.raises(ValueError, match="Unknown decision evaluator"):
            cfg.get_decision_evaluator("nonexistent")

    def test_re_register_invalidates_cache(self):
        ev1 = _make_evaluator(DecisionResult(nouls={"x": 0.5}))
        ev2 = _make_evaluator(DecisionResult(nouls={"x": 0.9}))
        cfg = ConfigManager()
        cfg.register_decision_evaluator("ev", ev1)
        _ = cfg.get_decision_evaluator("ev")
        cfg.register_decision_evaluator("ev", ev2)
        assert cfg.get_decision_evaluator("ev") is ev2


# ---------------------------------------------------------------------------
# Compiler validation
# ---------------------------------------------------------------------------

class TestDecisionCompilerValidation:
    def test_compile_valid_choice_rule(self):
        ev = _make_evaluator(DecisionResult())
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Is this malicious?" model="mock" verdict="yes"
            condition:
                $d1
        }
        ''', ev)
        assert len(rules) == 1

    def test_compile_valid_noul_rule(self):
        ev = _make_evaluator(DecisionResult())
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Prob malicious?" model="mock" noul=0.6
            condition:
                $d1
        }
        ''', ev)
        assert len(rules) == 1

    def test_compile_valid_score_rule(self):
        ev = _make_evaluator(DecisionResult())
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Severity?" model="mock" score=3.0
            condition:
                $d1
        }
        ''', ev)
        assert len(rules) == 1

    def test_compile_unknown_model_raises(self):
        with pytest.raises(ValueError, match="Unknown decision evaluator"):
            SYaraCompiler().compile_string('''
            rule r {
                decision:
                    $d1 = "Bad?" model="no-such-model" verdict="yes"
                condition:
                    $d1
            }
            ''')

    def test_compile_decision_counts_as_pattern(self):
        """A rule with only decision: patterns is valid (has at least one pattern)."""
        ev = _make_evaluator(DecisionResult())
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Is this bad?" model="mock" verdict="yes"
            condition:
                $d1
        }
        ''', ev)
        assert len(rules) == 1


# ---------------------------------------------------------------------------
# End-to-end matching: choice
# ---------------------------------------------------------------------------

class TestDecisionMatchChoice:
    def _rule_text(self, verdict="malicious", threshold=0.5):
        return f'''
        rule r {{
            decision:
                $d1 = "Is this malicious?" model="mock" verdict="{verdict}" threshold={threshold}
            condition:
                $d1
        }}
        '''

    def test_choice_match_when_verdict_and_confidence_met(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "malicious", "confidence": 0.9, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        assert rules.matched("any text")

    def test_choice_no_match_wrong_verdict(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "benign", "confidence": 0.9, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        assert not rules.matched("any text")

    def test_choice_no_match_low_confidence(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "malicious", "confidence": 0.3, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(threshold=0.7), ev)
        assert not rules.matched("any text")

    def test_choice_match_detail_populated(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "malicious", "confidence": 0.88, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        matches = rules.match_any("text")
        assert matches[0].matched_patterns["$d1"][0].matched_text == "malicious"
        assert abs(matches[0].matched_patterns["$d1"][0].score - 0.88) < 1e-6

    def test_choice_match_with_yes_label(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "yes", "confidence": 0.8, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(verdict="yes"), ev)
        assert rules.matched("text")


# ---------------------------------------------------------------------------
# End-to-end matching: noul
# ---------------------------------------------------------------------------

class TestDecisionMatchNoul:
    def _rule_text(self, noul_threshold=0.6):
        return f'''
        rule r {{
            decision:
                $d1 = "Probability malicious?" model="mock" noul={noul_threshold}
            condition:
                $d1
        }}
        '''

    def test_noul_match_above_threshold(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.8}))
        rules = _compile_with(self._rule_text(), ev)
        assert rules.matched("text")

    def test_noul_no_match_below_threshold(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.4}))
        rules = _compile_with(self._rule_text(), ev)
        assert not rules.matched("text")

    def test_noul_match_exactly_at_threshold(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.6}))
        rules = _compile_with(self._rule_text(0.6), ev)
        assert rules.matched("text")

    def test_noul_score_in_match_detail(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.75}))
        rules = _compile_with(self._rule_text(), ev)
        detail = rules.match_any("text")[0].matched_patterns["$d1"][0]
        assert abs(detail.score - 0.75) < 1e-6


# ---------------------------------------------------------------------------
# End-to-end matching: score
# ---------------------------------------------------------------------------

class TestDecisionMatchScore:
    def _rule_text(self, score_threshold=3.0):
        return f'''
        rule r {{
            decision:
                $d1 = "Severity 0-4?" model="mock" score={score_threshold}
            condition:
                $d1
        }}
        '''

    def test_score_match_above_threshold(self):
        ev = _make_evaluator(DecisionResult(
            scores={"d1": {"score": 3.5, "confidence": 0.9, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        assert rules.matched("text")

    def test_score_no_match_below_threshold(self):
        ev = _make_evaluator(DecisionResult(
            scores={"d1": {"score": 2.0, "confidence": 0.9, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        assert not rules.matched("text")

    def test_score_normalised_to_0_1_in_detail(self):
        """MatchDetail.score is normalised (score / 4) for a 0-4 scale."""
        ev = _make_evaluator(DecisionResult(
            scores={"d1": {"score": 4.0, "confidence": 1.0, "probabilities": {}}}
        ))
        rules = _compile_with(self._rule_text(), ev)
        detail = rules.match_any("text")[0].matched_patterns["$d1"][0]
        assert abs(detail.score - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# Missing answer key → no match (graceful)
# ---------------------------------------------------------------------------

class TestDecisionMissingAnswer:
    def test_missing_choice_key_no_match(self):
        ev = _make_evaluator(DecisionResult(choices={}))  # no "d1" key
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Question?" model="mock" verdict="yes"
            condition:
                $d1
        }
        ''', ev)
        assert not rules.matched("text")

    def test_missing_noul_key_no_match(self):
        ev = _make_evaluator(DecisionResult(nouls={}))
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Question?" model="mock" noul=0.5
            condition:
                $d1
        }
        ''', ev)
        assert not rules.matched("text")

    def test_evaluator_exception_emits_warning_no_match(self):
        class _Broken(DecisionEvaluator):
            def decide(self, state, questions):
                raise RuntimeError("API down")

        cfg = _cfg_with(_Broken())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            decision:
                $d1 = "Question?" model="mock" verdict="yes"
            condition:
                $d1
        }
        ''')
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = rules.matched("text")
        assert result is False
        assert any("API down" in str(warning.message) for warning in w)


# ---------------------------------------------------------------------------
# Batching: multiple identifiers with same model → one decide() call
# ---------------------------------------------------------------------------

class TestDecisionBatching:
    def test_multiple_ids_same_model_batched(self):
        """All decision rules for the same model go in one decide() call."""
        call_count = [0]

        class _Counter(DecisionEvaluator):
            def decide(self, state, questions):
                call_count[0] += 1
                return DecisionResult(
                    nouls={k: 0.9 for k in questions}
                )

        cfg = _cfg_with(_Counter())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            decision:
                $d1 = "Q1?" model="mock" noul=0.5
                $d2 = "Q2?" model="mock" noul=0.5
                $d3 = "Q3?" model="mock" noul=0.5
            condition:
                $d1 and $d2 and $d3
        }
        ''')
        assert rules.matched("text")
        assert call_count[0] == 1  # batched into one call

    def test_different_models_separate_calls(self):
        call_counts = {"a": 0, "b": 0}

        def _make_counter(name):
            class _C(DecisionEvaluator):
                def decide(self, state, questions):
                    call_counts[name] += 1
                    return DecisionResult(nouls={k: 0.9 for k in questions})
            return _C()

        cfg = ConfigManager()
        cfg.register_decision_evaluator("model-a", _make_counter("a"))
        cfg.register_decision_evaluator("model-b", _make_counter("b"))

        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            decision:
                $d1 = "Q1?" model="model-a" noul=0.5
                $d2 = "Q2?" model="model-b" noul=0.5
            condition:
                $d1 and $d2
        }
        ''')
        rules.matched("text")
        assert call_counts["a"] == 1
        assert call_counts["b"] == 1


# ---------------------------------------------------------------------------
# Short-circuit: decision skipped when condition already determined
# ---------------------------------------------------------------------------

class TestDecisionShortCircuit:
    def test_decision_skipped_when_and_prefilter_fails(self):
        call_count = [0]

        class _Counter(DecisionEvaluator):
            def decide(self, state, questions):
                call_count[0] += 1
                return DecisionResult(nouls={k: 0.9 for k in questions})

        cfg = _cfg_with(_Counter())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            strings:
                $pre = "REQUIRED"
            decision:
                $d1 = "Expensive check?" model="mock" noul=0.5
            condition:
                $pre and $d1
        }
        ''')
        rules.matched("text without the required word")
        assert call_count[0] == 0  # never called

    def test_decision_called_when_needed(self):
        call_count = [0]

        class _Counter(DecisionEvaluator):
            def decide(self, state, questions):
                call_count[0] += 1
                return DecisionResult(nouls={k: 0.9 for k in questions})

        cfg = _cfg_with(_Counter())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            strings:
                $pre = "REQUIRED"
            decision:
                $d1 = "Expensive check?" model="mock" noul=0.5
            condition:
                $pre and $d1
        }
        ''')
        rules.matched("text with REQUIRED word")
        assert call_count[0] == 1


# ---------------------------------------------------------------------------
# Decision + fields state merging
# ---------------------------------------------------------------------------

class TestDecisionWithFields:
    def test_fields_merged_into_state(self):
        captured_states = []

        class _Capture(DecisionEvaluator):
            def decide(self, state, questions):
                captured_states.append(state)
                return DecisionResult(nouls={k: 0.9 for k in questions})

        cfg = _cfg_with(_Capture())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            decision:
                $d1 = "Malicious?" model="mock" noul=0.5
            condition:
                $d1
        }
        ''')
        rules.matched("some text", fields={"EventID": "4625", "process": "cmd.exe"})
        state = captured_states[0]
        assert isinstance(state, dict)
        assert state.get("EventID") == "4625"
        assert state.get("process") == "cmd.exe"

    def test_no_fields_state_is_string(self):
        captured_states = []

        class _Capture(DecisionEvaluator):
            def decide(self, state, questions):
                captured_states.append(state)
                return DecisionResult(nouls={k: 0.8 for k in questions})

        cfg = _cfg_with(_Capture())
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            decision:
                $d1 = "Malicious?" model="mock" noul=0.5
            condition:
                $d1
        }
        ''')
        rules.matched("just text")
        assert captured_states[0] == "just text"


# ---------------------------------------------------------------------------
# Decision combined with other rule types
# ---------------------------------------------------------------------------

class TestDecisionCombined:
    def test_decision_and_strings(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9}))
        rules = _compile_with('''
        rule r {
            strings:
                $s1 = "trigger" nocase
            decision:
                $d1 = "Confirm threat?" model="mock" noul=0.6
            condition:
                $s1 and $d1
        }
        ''', ev)
        assert rules.matched("TRIGGER word in text")
        assert not rules.matched("no keyword at all")

    def test_decision_or_strings(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9}))
        rules = _compile_with('''
        rule r {
            strings:
                $s1 = "specific_keyword"
            decision:
                $d1 = "Is this suspicious?" model="mock" noul=0.5
            condition:
                $s1 or $d1
        }
        ''', ev)
        # Decision alone triggers
        assert rules.matched("unrelated text")

    def test_decision_and_fields(self):
        ev = _make_evaluator(DecisionResult(
            choices={"d1": {"choice": "malicious", "confidence": 0.9, "probabilities": {}}}
        ))
        cfg = _cfg_with(ev)
        rules = SYaraCompiler(config_manager=cfg).compile_string('''
        rule r {
            fields:
                $evt = EventID = "4625"
            decision:
                $d1 = "Confirm threat?" model="mock" verdict="malicious"
            condition:
                $evt and $d1
        }
        ''')
        assert rules.matched("", fields={"EventID": "4625"})
        assert not rules.matched("", fields={"EventID": "4624"})  # wrong event

    def test_match_any_with_decision(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9}))
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Threat?" model="mock" noul=0.5
            condition:
                $d1
        }
        ''', ev)
        matched = rules.match_any("text")
        assert len(matched) == 1
        assert matched[0].rule_name == "r"

    def test_matched_with_decision(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9}))
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Threat?" model="mock" noul=0.5
            condition:
                $d1
        }
        ''', ev)
        assert rules.matched("text") is True

    def test_condition_any_of_decision_wildcards(self):
        ev = _make_evaluator(DecisionResult(nouls={"d1": 0.9, "d2": 0.9}))
        rules = _compile_with('''
        rule r {
            decision:
                $d1 = "Q1?" model="mock" noul=0.5
                $d2 = "Q2?" model="mock" noul=0.5
            condition:
                any of ($d*)
        }
        ''', ev)
        assert rules.matched("text")


# ---------------------------------------------------------------------------
# DecisionRule model
# ---------------------------------------------------------------------------

class TestDecisionRuleModel:
    def test_required_fields(self):
        d = DecisionRule(
            identifier="$d1",
            question="Is this bad?",
            model_name="jev",
            answer_type="choice",
        )
        assert d.identifier == "$d1"
        assert d.answer_type == "choice"

    def test_defaults(self):
        d = DecisionRule(
            identifier="$d1",
            question="Bad?",
            model_name="jev",
            answer_type="noul",
        )
        assert d.positive_label == "yes"
        assert d.threshold == 0.5
        assert d.cleaner_name == "no_op"
        assert d.chunker_name == "no_chunking"

    def test_in_all(self):
        assert "DecisionRule" in syara.__all__
