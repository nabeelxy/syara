"""
Tests for the fields: section feature in SYara.
"""
import pytest
from syara import compile_string, FieldRule


RULE_LITERAL = '''
rule LiteralFieldMatch {
    fields:
        $evt = EventID = "4624"
    condition:
        $evt
}
'''

RULE_NOCASE = '''
rule NocaseFieldMatch {
    fields:
        $proc = process.name = "cmd.exe" nocase
    condition:
        $proc
}
'''

RULE_REGEX = '''
rule RegexFieldMatch {
    fields:
        $ip = source.ip = /192\\.168\\.\\d+\\.\\d+/
    condition:
        $ip
}
'''

RULE_COMBINED = '''
rule CombinedFieldAndStrings {
    strings:
        $s1 = "malicious"
    fields:
        $evt = EventID = "4625"
    condition:
        $s1 and $evt
}
'''

RULE_FIELD_MISSING = '''
rule FieldNotInDict {
    fields:
        $evt = EventID = "4624"
    condition:
        $evt
}
'''

RULE_ORDER_INDEPENDENT = '''
rule OrderIndependent {
    condition:
        $evt
    fields:
        $evt = EventID = "4624"
}
'''


def test_literal_field_match():
    rules = compile_string(RULE_LITERAL)
    matches = rules.match("", fields={"EventID": "4624"})
    assert len(matches) == 1
    assert matches[0].matched


def test_literal_field_no_match():
    rules = compile_string(RULE_LITERAL)
    matches = rules.match("", fields={"EventID": "4625"})
    assert len(matches) == 1
    assert not matches[0].matched


def test_nocase_field_match():
    rules = compile_string(RULE_NOCASE)
    matches = rules.match("", fields={"process.name": "CMD.EXE"})
    assert matches[0].matched


def test_nocase_field_exact_case():
    rules = compile_string(RULE_NOCASE)
    matches = rules.match("", fields={"process.name": "cmd.exe"})
    assert matches[0].matched


def test_regex_field_match():
    rules = compile_string(RULE_REGEX)
    matches = rules.match("", fields={"source.ip": "192.168.1.100"})
    assert matches[0].matched


def test_regex_field_no_match():
    rules = compile_string(RULE_REGEX)
    matches = rules.match("", fields={"source.ip": "10.0.0.1"})
    assert not matches[0].matched


def test_field_not_in_dict():
    rules = compile_string(RULE_FIELD_MISSING)
    matches = rules.match("", fields={"OtherField": "4624"})
    assert not matches[0].matched


def test_field_no_fields_dict():
    rules = compile_string(RULE_LITERAL)
    matches = rules.match("some text")
    assert not matches[0].matched


def test_combined_fields_and_strings():
    rules = compile_string(RULE_COMBINED)
    # Both must match
    matches = rules.match("malicious", fields={"EventID": "4625"})
    assert matches[0].matched

    # Only string matches
    matches = rules.match("malicious", fields={"EventID": "9999"})
    assert not matches[0].matched

    # Only field matches
    matches = rules.match("benign", fields={"EventID": "4625"})
    assert not matches[0].matched


def test_order_independent_fields_before_condition():
    """Fields section can appear before condition section."""
    rules = compile_string(RULE_ORDER_INDEPENDENT)
    matches = rules.match("", fields={"EventID": "4624"})
    assert matches[0].matched


def test_fieldmatcher_import():
    """FieldMatcher should be importable from syara.engine."""
    from syara.engine import FieldMatcher
    fm = FieldMatcher()
    assert fm is not None


def test_fieldrule_model():
    """FieldRule should be importable from syara."""
    fr = FieldRule(identifier="$t", field_name="EventID", pattern="4624")
    assert fr.identifier == "$t"
    assert fr.field_name == "EventID"
    assert fr.pattern == "4624"
    assert not fr.is_regex
