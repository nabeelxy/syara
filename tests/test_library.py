"""
Extended library tests for syara.

Covers gaps in test_basic.py:
  - Models (ClassifierRule, LLMRule, Rule, Match, MatchDetail)
  - AggressiveCleaner, ParagraphChunker, WordChunker
  - Chunker edge cases and invalid constructors
  - StringMatcher (literal, regex, modifiers, positions, cache)
  - Parser edge cases (comments, multi-rule, regex strings, file I/O)
  - Compiler validation (empty rules, duplicates, bad identifiers, bad components)
  - CompiledRules end-to-end with string-only rules (no ML deps)
  - Condition translation (_translate_yara_condition, _evaluate_condition)
  - LLM short-circuit optimization (_is_identifier_needed)
  - ConfigManager (registration, caching, pre-instantiated objects)
  - TextCache edge cases
  - Placeholder phash matchers (AudioHashMatcher, VideoHashMatcher)
"""
import os
import tempfile
import pytest
from unittest.mock import MagicMock

import syara
from syara.models import (
    StringRule, SimilarityRule, ClassifierRule, LLMRule, PHashRule,
    Rule, Match, MatchDetail,
)
from syara.engine.cleaner import DefaultCleaner, NoOpCleaner, AggressiveCleaner
from syara.engine.chunker import (
    NoChunker, SentenceChunker, FixedSizeChunker,
    ParagraphChunker, WordChunker, TextChunker,
)
from syara.engine.string_matcher import StringMatcher
from syara.engine.phash_matcher import ImageHashMatcher, AudioHashMatcher, VideoHashMatcher
from syara.cache import TextCache
from syara.parser import SYaraParser
from syara.compiler import SYaraCompiler
from syara.config import ConfigManager
from syara.compiled_rules import CompiledRules


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compiler() -> SYaraCompiler:
    """Return a fresh compiler with default config."""
    return SYaraCompiler()


def _compile(rule_text: str) -> CompiledRules:
    """Compile a rule string (no ML deps needed for string-only rules)."""
    return _compiler().compile_string(rule_text)


def _string_only_rule(name: str = "test") -> str:
    return f"""
    rule {name} {{
        strings:
            $s1 = "hello"
        condition:
            $s1
    }}
    """


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class TestModelsComplete:
    """Tests for model fields not covered by test_basic.py."""

    def test_classifier_rule_defaults(self):
        rule = ClassifierRule(identifier="$c1", pattern="phishing", threshold=0.7)
        assert rule.cleaner_name == "default_cleaning"
        assert rule.chunker_name == "no_chunking"
        assert rule.classifier_name == "tuned-sbert"

    def test_llm_rule_defaults(self):
        rule = LLMRule(identifier="$l1", pattern="Is this malicious?")
        assert rule.llm_name == "flan-t5-large"

    def test_rule_creation_with_all_fields(self):
        sr = StringRule(identifier="$s1", pattern="test", is_regex=False)
        rule = Rule(
            name="full_rule",
            tags=["security", "test"],
            meta={"author": "alice", "version": "1.0"},
            strings=[sr],
            condition="$s1",
        )
        assert rule.name == "full_rule"
        assert "security" in rule.tags
        assert rule.meta["author"] == "alice"
        assert len(rule.strings) == 1
        assert rule.condition == "$s1"

    def test_match_str_not_matched(self):
        m = Match(rule_name="my_rule", matched=False)
        assert "my_rule" in str(m)
        assert "False" in str(m)

    def test_match_str_matched(self):
        detail = MatchDetail(identifier="$s1", matched_text="found")
        m = Match(
            rule_name="my_rule",
            matched=True,
            matched_patterns={"$s1": [detail]},
        )
        text = str(m)
        assert "my_rule" in text
        assert "True" in text

    def test_match_detail_defaults(self):
        d = MatchDetail(identifier="$x", matched_text="abc")
        assert d.start_pos == -1
        assert d.end_pos == -1
        assert d.score == 1.0
        assert d.explanation == ""

    def test_match_empty_patterns_on_creation(self):
        m = Match(rule_name="r")
        assert m.matched_patterns == {}
        assert m.tags == []
        assert m.meta == {}


# ---------------------------------------------------------------------------
# Cleaners
# ---------------------------------------------------------------------------

class TestAggressiveCleaner:
    def test_removes_numbers(self):
        c = AggressiveCleaner()
        assert "42" not in c.clean("hello 42 world")

    def test_removes_punctuation(self):
        c = AggressiveCleaner()
        result = c.clean("Hello, World!")
        assert "," not in result
        assert "!" not in result

    def test_lowercases(self):
        c = AggressiveCleaner()
        assert c.clean("UPPER") == "upper"

    def test_normalizes_whitespace(self):
        c = AggressiveCleaner()
        assert c.clean("  a   b  ") == "a b"

    def test_empty_string(self):
        c = AggressiveCleaner()
        assert c.clean("") == ""

    def test_unicode_normalization(self):
        c = AggressiveCleaner()
        # NFKC: ﬁ (ligature) → fi
        result = c.clean("\uFB01le")  # ﬁle
        assert "fi" in result or "file" in result


class TestDefaultCleanerEdgeCases:
    def test_empty_string(self):
        assert DefaultCleaner().clean("") == ""

    def test_unicode_normalization(self):
        c = DefaultCleaner()
        # NFKC normalization: ﬁ → fi
        result = c.clean("\uFB01le")
        assert result in ("file", "fi le")  # depends on normalization

    def test_only_whitespace(self):
        assert DefaultCleaner().clean("   ") == ""


# ---------------------------------------------------------------------------
# Chunkers
# ---------------------------------------------------------------------------

class TestParagraphChunker:
    def test_splits_on_double_newline(self):
        c = ParagraphChunker()
        text = "First paragraph.\n\nSecond paragraph."
        chunks = c.chunk(text)
        assert len(chunks) == 2
        assert "First" in chunks[0]
        assert "Second" in chunks[1]

    def test_single_paragraph_returns_list_of_one(self):
        c = ParagraphChunker()
        text = "Just one paragraph with no double newlines."
        chunks = c.chunk(text)
        assert chunks == [text]

    def test_empty_string_returns_empty(self):
        assert ParagraphChunker().chunk("") == []

    def test_filters_empty_paragraphs(self):
        c = ParagraphChunker()
        text = "Para one.\n\n\n\nPara two."
        chunks = c.chunk(text)
        assert all(ch.strip() for ch in chunks)


class TestWordChunker:
    def test_short_text_single_chunk(self):
        c = WordChunker(words_per_chunk=10, overlap_words=2)
        text = "just a few words"
        chunks = c.chunk(text)
        assert chunks == [text]

    def test_splits_long_text(self):
        c = WordChunker(words_per_chunk=3, overlap_words=1)
        text = "one two three four five six"
        chunks = c.chunk(text)
        assert len(chunks) > 1

    def test_overlap_means_words_repeated(self):
        c = WordChunker(words_per_chunk=3, overlap_words=1)
        text = "one two three four five"
        chunks = c.chunk(text)
        # With overlap=1, "three" should appear in both chunk 1 and chunk 2
        if len(chunks) >= 2:
            words_chunk1 = set(chunks[0].split())
            words_chunk2 = set(chunks[1].split())
            assert words_chunk1 & words_chunk2  # non-empty intersection

    def test_empty_string_returns_empty(self):
        assert WordChunker().chunk("") == []

    def test_invalid_words_per_chunk(self):
        with pytest.raises(ValueError):
            WordChunker(words_per_chunk=0)

    def test_invalid_overlap_negative(self):
        with pytest.raises(ValueError):
            WordChunker(words_per_chunk=10, overlap_words=-1)

    def test_invalid_overlap_gte_chunk(self):
        with pytest.raises(ValueError):
            WordChunker(words_per_chunk=5, overlap_words=5)


class TestChunkerEdgeCases:
    def test_nochunker_empty(self):
        assert NoChunker().chunk("") == []

    def test_sentence_chunker_empty(self):
        assert SentenceChunker().chunk("") == []

    def test_fixed_size_short_text_one_chunk(self):
        c = FixedSizeChunker(chunk_size=100, overlap=10)
        text = "short"
        assert c.chunk(text) == [text]

    def test_fixed_size_empty(self):
        assert FixedSizeChunker().chunk("") == []

    def test_fixed_size_invalid_chunk_size(self):
        with pytest.raises(ValueError):
            FixedSizeChunker(chunk_size=0)

    def test_fixed_size_invalid_overlap_negative(self):
        with pytest.raises(ValueError):
            FixedSizeChunker(chunk_size=100, overlap=-1)

    def test_fixed_size_invalid_overlap_gte_size(self):
        with pytest.raises(ValueError):
            FixedSizeChunker(chunk_size=10, overlap=10)

    def test_text_chunker_alias(self):
        """TextChunker is an alias for SentenceChunker."""
        assert TextChunker is SentenceChunker


# ---------------------------------------------------------------------------
# StringMatcher
# ---------------------------------------------------------------------------

class TestStringMatcher:
    def test_literal_match(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="hello", is_regex=False)
        results = m.match(rule, "say hello world")
        assert len(results) == 1
        assert results[0].matched_text == "hello"
        assert results[0].identifier == "$s1"

    def test_literal_no_match(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="hello", is_regex=False)
        assert m.match(rule, "nothing relevant") == []

    def test_multiple_occurrences(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="ab", is_regex=False)
        results = m.match(rule, "ab ab ab")
        assert len(results) == 3

    def test_nocase_modifier(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="hello", modifiers=["nocase"], is_regex=False)
        assert m.match(rule, "HELLO") != []
        assert m.match(rule, "Hello") != []
        assert m.match(rule, "HeLLo") != []

    def test_case_sensitive_by_default(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="hello", is_regex=False)
        assert m.match(rule, "HELLO") == []

    def test_match_positions(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="world", is_regex=False)
        text = "hello world"
        results = m.match(rule, text)
        assert len(results) == 1
        assert results[0].start_pos == 6
        assert results[0].end_pos == 11

    def test_match_score_is_one(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="x", is_regex=False)
        results = m.match(rule, "x")
        assert results[0].score == 1.0

    def test_regex_match(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern=r"\d+", is_regex=True)
        results = m.match(rule, "abc 123 def 456")
        assert len(results) == 2

    def test_regex_no_match(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern=r"\d+", is_regex=True)
        assert m.match(rule, "no digits here") == []

    def test_regex_with_i_flag(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern="hello", modifiers=["i"], is_regex=True)
        assert m.match(rule, "HELLO world") != []

    def test_dotall_modifier(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern="start.*end", modifiers=["dotall"], is_regex=True)
        assert m.match(rule, "start\nmiddle\nend") != []

    def test_multiline_modifier(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern="^line", modifiers=["multiline"], is_regex=True)
        results = m.match(rule, "line one\nline two")
        assert len(results) == 2

    def test_has_match_true(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="target", is_regex=False)
        assert m.has_match(rule, "find the target here")

    def test_has_match_false(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="target", is_regex=False)
        assert not m.has_match(rule, "nothing relevant")

    def test_invalid_regex_raises(self):
        m = StringMatcher()
        rule = StringRule(identifier="$r1", pattern="[invalid", is_regex=True)
        with pytest.raises(ValueError, match="Invalid regex"):
            m.match(rule, "test")

    def test_pattern_cache_is_used(self):
        """Same pattern compiled only once."""
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="x", is_regex=False)
        m.match(rule, "x")
        m.match(rule, "xx")
        # Cache has one entry for this pattern/modifier combination
        assert len(m._pattern_cache) == 1

    def test_clear_cache(self):
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="x", is_regex=False)
        m.match(rule, "x")
        assert len(m._pattern_cache) == 1
        m.clear_cache()
        assert len(m._pattern_cache) == 0

    def test_special_chars_in_literal_escaped(self):
        """Literal patterns with regex special chars must be escaped."""
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="a.b", is_regex=False)
        # Should only match the literal "a.b", not "axb"
        assert m.match(rule, "a.b found") != []
        assert m.match(rule, "axb found") == []

    # -- wide modifier ---------------------------------------------------

    def test_wide_literal_matches_null_interleaved(self):
        """'wide' matches null-byte-interleaved (UTF-16LE) form of literal."""
        m = StringMatcher()
        wide_text = "h\x00i\x00"
        rule = StringRule(identifier="$s1", pattern="hi", is_regex=False, modifiers=["wide"])
        results = m.match(rule, wide_text)
        assert len(results) == 1
        assert results[0].matched_text == wide_text

    def test_wide_literal_does_not_match_normal_ascii(self):
        """'wide' (without ascii) should NOT match the plain ASCII form."""
        m = StringMatcher()
        rule = StringRule(identifier="$s1", pattern="hello", is_regex=False, modifiers=["wide"])
        assert m.match(rule, "hello world") == []

    def test_wide_ascii_matches_both_forms(self):
        """'wide ascii' matches both the null-interleaved and plain ASCII forms."""
        m = StringMatcher()
        rule = StringRule(
            identifier="$s1", pattern="hi", is_regex=False, modifiers=["wide", "ascii"]
        )
        assert m.match(rule, "hi there") != []          # ASCII form
        assert m.match(rule, "h\x00i\x00 there") != []  # wide form

    def test_wide_nocase_literal(self):
        """'wide nocase' matches null-interleaved text case-insensitively."""
        m = StringMatcher()
        rule = StringRule(
            identifier="$s1", pattern="hi", is_regex=False, modifiers=["wide", "nocase"]
        )
        wide_upper = "H\x00I\x00"
        assert m.match(rule, wide_upper) != []

    def test_wide_regex_matches_null_stripped_text(self):
        """'wide' on regex matches original regex against null-stripped text."""
        m = StringMatcher()
        rule = StringRule(
            identifier="$r1", pattern=r"\d{3}", is_regex=True, modifiers=["wide"]
        )
        # Text with null bytes between digits (simulates UTF-16LE binary)
        wide_digits = "1\x002\x003\x00"
        results = m.match(rule, wide_digits)
        assert len(results) == 1
        assert results[0].matched_text == "123"


# ---------------------------------------------------------------------------
# Parser edge cases
# ---------------------------------------------------------------------------

class TestParserEdgeCases:
    def test_remove_single_line_comments(self):
        p = SYaraParser()
        content = "rule foo {\n    strings:\n        $s1 = \"test\" // this is a comment\n    condition:\n        $s1\n}"
        rules = p.parse_string(content)
        assert len(rules) == 1
        # Comment should not appear in pattern
        assert rules[0].strings[0].pattern == "test"

    def test_remove_block_comments(self):
        p = SYaraParser()
        content = "/* block comment */\nrule foo {\n    strings:\n        $s1 = \"test\"\n    condition:\n        $s1\n}"
        rules = p.parse_string(content)
        assert len(rules) == 1

    def test_parse_multi_rule_file(self):
        p = SYaraParser()
        content = """
        rule rule_one {
            strings:
                $s1 = "alpha"
            condition:
                $s1
        }
        rule rule_two {
            strings:
                $s1 = "beta"
            condition:
                $s1
        }
        """
        rules = p.parse_string(content)
        assert len(rules) == 2
        names = {r.name for r in rules}
        assert names == {"rule_one", "rule_two"}

    def test_parse_regex_string_rule(self):
        p = SYaraParser()
        content = """
        rule test {
            strings:
                $r1 = /[0-9]+/ i
            condition:
                $r1
        }
        """
        rules = p.parse_string(content)
        assert len(rules) == 1
        assert rules[0].strings[0].is_regex
        assert rules[0].strings[0].pattern == "[0-9]+"

    def test_parse_regex_with_i_flag(self):
        p = SYaraParser()
        content = """
        rule test {
            strings:
                $r1 = /hello/i
            condition:
                $r1
        }
        """
        rules = p.parse_string(content)
        assert "i" in rules[0].strings[0].modifiers

    def test_parse_rule_no_tags(self):
        p = SYaraParser()
        content = """
        rule notags {
            strings:
                $s1 = "x"
            condition:
                $s1
        }
        """
        rules = p.parse_string(content)
        assert rules[0].tags == []

    def test_parse_meta_multiple_entries(self):
        p = SYaraParser()
        content = """
        rule meta_rule {
            meta:
                author = "alice"
                version = "2.0"
                description = "a test rule"
            strings:
                $s1 = "x"
            condition:
                $s1
        }
        """
        rules = p.parse_string(content)
        meta = rules[0].meta
        assert meta["author"] == "alice"
        assert meta["version"] == "2.0"
        assert meta["description"] == "a test rule"

    def test_parse_llm_triple_quoted_pattern(self):
        p = SYaraParser()
        content = '''
        rule test_llm {
            llm:
                $l1 = """Does this text contain a
                multi-line LLM prompt?""" llm="gpt-4"
            condition:
                $l1
        }
        '''
        rules = p.parse_string(content)
        assert len(rules) == 1
        assert len(rules[0].llm) == 1
        assert rules[0].llm[0].llm_name == "gpt-4"

    def test_parse_file_not_found(self):
        p = SYaraParser()
        with pytest.raises(FileNotFoundError):
            p.parse_file("/nonexistent/path/rules.syara")

    def test_parse_file_reads_disk(self):
        p = SYaraParser()
        content = """
        rule from_file {
            strings:
                $s1 = "disk"
            condition:
                $s1
        }
        """
        with tempfile.NamedTemporaryFile(mode="w", suffix=".syara", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            rules = p.parse_file(path)
            assert len(rules) == 1
            assert rules[0].name == "from_file"
        finally:
            os.unlink(path)

    def test_parse_similarity_default_chunker(self):
        p = SYaraParser()
        content = """
        rule test {
            similarity:
                $s1 = "prompt injection" threshold=0.8
            condition:
                $s1
        }
        """
        rules = p.parse_string(content)
        sim = rules[0].similarity[0]
        assert sim.chunker_name == "no_chunking"

    def test_parse_phash_supports_phash_key(self):
        """phash section accepts 'phash' as alias for 'hasher'."""
        p = SYaraParser()
        content = """
        rule test {
            phash:
                $p1 = "ref.png" threshold=0.9 phash="imagehash"
            condition:
                $p1
        }
        """
        rules = p.parse_string(content)
        assert rules[0].phash[0].phash_name == "imagehash"


# ---------------------------------------------------------------------------
# Compiler validation
# ---------------------------------------------------------------------------

class TestCompilerValidation:
    def test_compile_string_valid(self):
        compiled = _compile(_string_only_rule())
        assert len(compiled) == 1

    def test_compile_empty_raises(self):
        with pytest.raises(ValueError, match="No rules"):
            _compile("// just a comment, no rules")

    def test_compile_duplicate_names_raises(self):
        with pytest.raises(ValueError, match="Duplicate"):
            _compile("""
            rule dup { strings: $s1 = "x" condition: $s1 }
            rule dup { strings: $s1 = "y" condition: $s1 }
            """)

    def test_compile_no_patterns_raises(self):
        with pytest.raises(ValueError, match="no patterns"):
            _compile("""
            rule empty {
                condition:
                    true
            }
            """)

    def test_compile_no_condition_raises(self):
        # A rule with no condition section produces condition="" which is falsy
        with pytest.raises(ValueError, match="no condition"):
            _compile("""
            rule nocond {
                strings:
                    $s1 = "x"
            }
            """)

    def test_compile_undefined_identifier_raises(self):
        with pytest.raises(ValueError, match="undefined identifiers"):
            _compile("""
            rule bad {
                strings:
                    $s1 = "x"
                condition:
                    $s1 and $s_undefined
            }
            """)

    def test_compile_wildcard_identifier_valid(self):
        """$prefix* in condition should match $prefix1, $prefix2, etc."""
        compiled = _compile("""
        rule wildcards {
            strings:
                $payload1 = "a"
                $payload2 = "b"
            condition:
                any of ($payload*)
        }
        """)
        assert len(compiled) == 1

    def test_compile_invalid_cleaner_raises(self):
        with pytest.raises(ValueError):
            _compile("""
            rule bad {
                similarity:
                    $s1 = "test" threshold=0.8 cleaner="nonexistent-cleaner"
                condition:
                    $s1
            }
            """)

    def test_compile_invalid_matcher_raises(self):
        with pytest.raises(ValueError):
            _compile("""
            rule bad {
                similarity:
                    $s1 = "test" threshold=0.8 matcher="nonexistent-matcher"
                condition:
                    $s1
            }
            """)

    def test_compile_invalid_classifier_raises(self):
        with pytest.raises(ValueError):
            _compile("""
            rule bad {
                classifier:
                    $c1 = "test" threshold=0.7 classifier="nonexistent-cls"
                condition:
                    $c1
            }
            """)

    def test_compile_invalid_llm_raises(self):
        with pytest.raises(ValueError):
            _compile("""
            rule bad {
                llm:
                    $l1 = "test" llm="nonexistent-llm"
                condition:
                    $l1
            }
            """)

    def test_compile_from_file(self):
        content = _string_only_rule("file_rule")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".syara", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            compiled = _compiler().compile(path)
            assert len(compiled) == 1
            assert compiled.rules[0].name == "file_rule"
        finally:
            os.unlink(path)

    def test_compile_file_not_found_raises(self):
        with pytest.raises(FileNotFoundError):
            _compiler().compile("/nonexistent/path.syara")

    def test_syara_compile_convenience_function(self):
        content = _string_only_rule("conv_rule")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".syara", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            compiled = syara.compile(path)
            assert len(compiled) == 1
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# CompiledRules — end-to-end with string-only patterns (no ML deps)
# ---------------------------------------------------------------------------

class TestCompiledRulesStringOnly:
    def test_match_hit(self):
        rules = _compile(_string_only_rule())
        matches = rules.match("say hello world")
        assert len(matches) == 1
        assert matches[0].matched
        assert matches[0].rule_name == "test"

    def test_match_miss(self):
        rules = _compile(_string_only_rule())
        matches = rules.match("nothing here")
        assert len(matches) == 1
        assert not matches[0].matched
        assert matches[0].matched_patterns == {}

    def test_matched_patterns_populated(self):
        rules = _compile(_string_only_rule())
        match = rules.match("hello world")[0]
        assert match.matched
        assert "$s1" in match.matched_patterns
        assert match.matched_patterns["$s1"][0].matched_text == "hello"

    def test_match_nocase(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "hello" nocase
            condition:
                $s1
        }
        """)
        assert rules.match("HELLO")[0].matched
        assert rules.match("Hello World")[0].matched

    def test_match_regex(self):
        rules = _compile("""
        rule test {
            strings:
                $r1 = /evil\\.com/
            condition:
                $r1
        }
        """)
        assert rules.match("download from evil.com")[0].matched
        assert not rules.match("legit.com")[0].matched

    def test_condition_and_both_present(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "foo"
                $s2 = "bar"
            condition:
                $s1 and $s2
        }
        """)
        assert rules.match("foo bar")[0].matched

    def test_condition_and_only_one(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "foo"
                $s2 = "bar"
            condition:
                $s1 and $s2
        }
        """)
        assert not rules.match("foo only")[0].matched
        assert not rules.match("bar only")[0].matched

    def test_condition_or(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "foo"
                $s2 = "bar"
            condition:
                $s1 or $s2
        }
        """)
        assert rules.match("foo only")[0].matched
        assert rules.match("bar only")[0].matched
        assert not rules.match("neither")[0].matched

    def test_condition_not(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "malicious"
                $s2 = "benign"
            condition:
                $s1 and not $s2
        }
        """)
        assert rules.match("malicious content")[0].matched
        assert not rules.match("malicious but also benign")[0].matched

    def test_condition_any_of_them(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "alpha"
                $s2 = "beta"
            condition:
                any of them
        }
        """)
        assert rules.match("alpha")[0].matched
        assert rules.match("beta")[0].matched
        assert not rules.match("gamma")[0].matched

    def test_condition_all_of_them(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "alpha"
                $s2 = "beta"
            condition:
                all of them
        }
        """)
        assert rules.match("alpha beta")[0].matched
        assert not rules.match("alpha only")[0].matched

    def test_condition_any_of_wildcard_parens(self):
        rules = _compile("""
        rule test {
            strings:
                $payload1 = "attack1"
                $payload2 = "attack2"
            condition:
                any of ($payload*)
        }
        """)
        assert rules.match("attack1")[0].matched
        assert rules.match("attack2")[0].matched
        assert not rules.match("nothing")[0].matched

    def test_condition_all_of_wildcard_parens(self):
        rules = _compile("""
        rule test {
            strings:
                $s1 = "foo"
                $s2 = "bar"
            condition:
                all of ($s*)
        }
        """)
        assert rules.match("foo bar")[0].matched
        assert not rules.match("foo only")[0].matched

    def test_multiline_condition(self):
        """Conditions spanning multiple lines should be normalized."""
        rules = _compile("""
        rule test {
            strings:
                $s1 = "foo"
                $s2 = "bar"
            condition:
                $s1
                and $s2
        }
        """)
        assert rules.match("foo bar")[0].matched
        assert not rules.match("foo only")[0].matched

    def test_multi_rule_all_evaluated(self):
        rules = _compile("""
        rule rule_a {
            strings:
                $s1 = "alpha"
            condition:
                $s1
        }
        rule rule_b {
            strings:
                $s1 = "beta"
            condition:
                $s1
        }
        """)
        matches = rules.match("alpha beta")
        assert len(matches) == 2
        assert all(m.matched for m in matches)

    def test_multi_rule_selective_match(self):
        rules = _compile("""
        rule rule_a {
            strings:
                $s1 = "alpha"
            condition:
                $s1
        }
        rule rule_b {
            strings:
                $s1 = "beta"
            condition:
                $s1
        }
        """)
        matches = rules.match("only alpha")
        matched = [m for m in matches if m.matched]
        unmatched = [m for m in matches if not m.matched]
        assert len(matched) == 1
        assert matched[0].rule_name == "rule_a"
        assert len(unmatched) == 1

    def test_repr_contains_count(self):
        rules = _compile(_string_only_rule())
        r = repr(rules)
        assert "CompiledRules" in r
        assert "1" in r

    def test_len(self):
        rules = _compile(_string_only_rule())
        assert len(rules) == 1

    def test_match_file_skips_string_only_rules(self):
        """match_file returns no matches for rules with no phash patterns."""
        rules = _compile(_string_only_rule())
        result = rules.match_file("/dev/null")
        assert result == []

    def test_tags_and_meta_propagated_to_match(self):
        rules = _compile("""
        rule tagged : security threat {
            meta:
                author = "tester"
            strings:
                $s1 = "x"
            condition:
                $s1
        }
        """)
        match = rules.match("x")[0]
        assert match.matched
        assert "security" in match.tags
        assert match.meta.get("author") == "tester"

    def test_regex_with_quantifier(self):
        """Regex quantifiers like {n} inside a rule body are parsed correctly."""
        rules = _compile("""
        rule test {
            strings:
                $r1 = /\\d{3}-\\d{4}/
            condition:
                $r1
        }
        """)
        assert rules.match("call 555-1234")[0].matched
        assert not rules.match("no phone here")[0].matched


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

class TestConditionEvaluation:
    """Tests for _evaluate_condition and _translate_yara_condition."""

    def _cr(self) -> CompiledRules:
        return _compile(_string_only_rule())

    def _d(self, identifier: str) -> MatchDetail:
        return MatchDetail(identifier=identifier, matched_text="x")

    def test_empty_condition_is_false(self):
        cr = self._cr()
        assert not cr._evaluate_condition("", {})

    def test_simple_true(self):
        cr = self._cr()
        assert cr._evaluate_condition("$s1", {"$s1": [self._d("$s1")]})

    def test_simple_false(self):
        cr = self._cr()
        assert not cr._evaluate_condition("$s1", {})

    def test_and_both_true(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": [self._d("$s2")]}
        assert cr._evaluate_condition("$s1 and $s2", pm)

    def test_and_one_false(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": []}
        assert not cr._evaluate_condition("$s1 and $s2", pm)

    def test_or_one_true(self):
        cr = self._cr()
        pm = {"$s1": [], "$s2": [self._d("$s2")]}
        assert cr._evaluate_condition("$s1 or $s2", pm)

    def test_or_both_false(self):
        cr = self._cr()
        assert not cr._evaluate_condition("$s1 or $s2", {"$s1": [], "$s2": []})

    def test_not_true(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": []}
        assert cr._evaluate_condition("$s1 and not $s2", pm)

    def test_any_of_them_one_match(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": []}
        assert cr._evaluate_condition("any of them", pm)

    def test_any_of_them_none_match(self):
        cr = self._cr()
        pm = {"$s1": [], "$s2": []}
        assert not cr._evaluate_condition("any of them", pm)

    def test_all_of_them_all_match(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": [self._d("$s2")]}
        assert cr._evaluate_condition("all of them", pm)

    def test_all_of_them_partial(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": []}
        assert not cr._evaluate_condition("all of them", pm)

    def test_any_of_wildcard_parens(self):
        cr = self._cr()
        pm = {"$p1": [self._d("$p1")], "$p2": []}
        assert cr._evaluate_condition("any of ($p*)", pm)

    def test_any_of_wildcard_bare(self):
        cr = self._cr()
        pm = {"$p1": [self._d("$p1")], "$p2": []}
        assert cr._evaluate_condition("any of $p*", pm)

    def test_all_of_wildcard_parens_all_match(self):
        cr = self._cr()
        pm = {"$p1": [self._d("$p1")], "$p2": [self._d("$p2")]}
        assert cr._evaluate_condition("all of ($p*)", pm)

    def test_all_of_wildcard_parens_partial(self):
        cr = self._cr()
        pm = {"$p1": [self._d("$p1")], "$p2": []}
        assert not cr._evaluate_condition("all of ($p*)", pm)

    def test_multiline_whitespace_normalized(self):
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s2": [self._d("$s2")]}
        # Condition with embedded newlines and tabs
        cond = "$s1\n\t\tand\n\t\t$s2"
        assert cr._evaluate_condition(cond, pm)

    def test_longer_identifier_not_partial_replaced(self):
        """$s10 should not be replaced by the result for $s1."""
        cr = self._cr()
        pm = {"$s1": [self._d("$s1")], "$s10": []}
        # $s10 is False, $s1 is True; result should be False
        assert not cr._evaluate_condition("$s1 and $s10", pm)

    def test_empty_pattern_matches_dict(self):
        """No matches at all → any simple identifier is False."""
        cr = self._cr()
        assert not cr._evaluate_condition("$s1", {})

    def test_invalid_condition_returns_false(self):
        """An unevaluable condition returns False (no exception with _BoolEval)."""
        cr = self._cr()
        # Unknown tokens are silently skipped by _BoolEval → False
        result = cr._evaluate_condition("1/0", {})
        assert result is False


# ---------------------------------------------------------------------------
# LLM short-circuit optimization
# ---------------------------------------------------------------------------

class TestLLMShortCircuit:
    """Tests for _is_identifier_needed (cost optimization)."""

    def _make_compiled_with_mock_llm(self) -> tuple:
        """Return (CompiledRules, mock_llm, rule)."""
        cfg = ConfigManager()
        mock_llm = MagicMock()
        mock_llm.evaluate_chunks.return_value = []
        cfg.config.llms["mock-llm"] = mock_llm

        rule = Rule(
            name="test",
            strings=[
                StringRule(identifier="$must_match", pattern="REQUIRED", is_regex=False),
            ],
            llm=[LLMRule(identifier="$llm_check", pattern="Is this bad?", llm_name="mock-llm")],
            condition="$must_match and $llm_check",
        )
        compiled = CompiledRules([rule], cfg)
        return compiled, mock_llm, rule

    def test_llm_skipped_when_prefilter_fails(self):
        """LLM not called when preceding required pattern already fails."""
        compiled, mock_llm, _ = self._make_compiled_with_mock_llm()
        matches = compiled.match("text without the required keyword")
        mock_llm.evaluate_chunks.assert_not_called()
        assert not matches[0].matched

    def test_llm_called_when_prefilter_passes(self):
        """LLM is called when the pre-filter pattern matches."""
        cfg = ConfigManager()
        detail = MatchDetail(identifier="$llm_check", matched_text="text")
        mock_llm = MagicMock()
        mock_llm.evaluate_chunks.return_value = [detail]
        cfg.config.llms["mock-llm"] = mock_llm

        rule = Rule(
            name="test",
            strings=[
                StringRule(identifier="$must_match", pattern="REQUIRED", is_regex=False),
            ],
            llm=[LLMRule(identifier="$llm_check", pattern="Is this bad?", llm_name="mock-llm")],
            condition="$must_match and $llm_check",
        )
        compiled = CompiledRules([rule], cfg)
        matches = compiled.match("text with REQUIRED keyword")
        mock_llm.evaluate_chunks.assert_called_once()
        assert matches[0].matched

    def test_is_identifier_needed_returns_false_when_irrelevant(self):
        """If assuming the LLM matches doesn't flip the overall condition, skip it."""
        compiled = _compile(_string_only_rule())
        d = MatchDetail(identifier="$s1", matched_text="x")
        # condition: $must and $llm; $must is False → overall is always False
        result = compiled._is_identifier_needed(
            "$llm",
            "$must and $llm",
            {"$must": []},  # $must is False
        )
        assert result is False

    def test_is_identifier_needed_returns_true_when_decisive(self):
        """If the LLM result could flip the condition, it is needed."""
        compiled = _compile(_string_only_rule())
        d = MatchDetail(identifier="$s1", matched_text="x")
        # condition: $must and $llm; $must is True → $llm determines outcome
        result = compiled._is_identifier_needed(
            "$llm",
            "$must and $llm",
            {"$must": [d]},  # $must is True
        )
        assert result is True


# ---------------------------------------------------------------------------
# LLMRule cleaner/chunker fields (TODO 6)
# ---------------------------------------------------------------------------

class TestLLMRuleCleanerChunker:
    """Tests for LLMRule cleaner_name / chunker_name fields."""

    def test_llm_rule_defaults(self):
        """LLMRule defaults to no_op cleaner and no_chunking chunker."""
        rule = LLMRule(identifier="$l1", pattern="Is this bad?")
        assert rule.cleaner_name == "no_op"
        assert rule.chunker_name == "no_chunking"

    def test_llm_rule_custom_cleaner_chunker(self):
        """LLMRule accepts custom cleaner/chunker names."""
        rule = LLMRule(
            identifier="$l1",
            pattern="Is this bad?",
            cleaner_name="aggressive",
            chunker_name="sentence_chunking",
        )
        assert rule.cleaner_name == "aggressive"
        assert rule.chunker_name == "sentence_chunking"

    def test_parser_llm_section_defaults(self):
        """Parser sets default cleaner/chunker on LLMRule when not specified."""
        from syara.parser import SYaraParser
        parser = SYaraParser()
        rules = parser.parse_string("""
        rule llm_default {
            llm:
                $l1 = "Is this spam?" llm="flan-t5-large"
            condition:
                $l1
        }
        """)
        assert rules[0].llm[0].cleaner_name == "no_op"
        assert rules[0].llm[0].chunker_name == "no_chunking"

    def test_parser_llm_section_explicit(self):
        """Parser parses explicit cleaner/chunker parameters on LLMRule."""
        from syara.parser import SYaraParser
        parser = SYaraParser()
        rules = parser.parse_string("""
        rule llm_explicit {
            llm:
                $l1 = "Is this spam?" llm="flan-t5-large" cleaner="aggressive" chunker="sentence_chunking"
            condition:
                $l1
        }
        """)
        assert rules[0].llm[0].cleaner_name == "aggressive"
        assert rules[0].llm[0].chunker_name == "sentence_chunking"

    def test_execute_llm_applies_cleaner_and_chunker(self):
        """_execute_llm cleans and chunks the text before passing to the LLM."""
        from syara.cache import TextCache
        from syara.compiled_rules import CompiledRules
        from syara.engine.cleaner import NoOpCleaner
        from syara.engine.chunker import NoChunker

        cfg = ConfigManager()

        mock_llm = MagicMock()
        mock_llm.evaluate_chunks.return_value = []
        cfg.config.llms["mock-llm"] = mock_llm

        rule = Rule(
            name="test",
            llm=[LLMRule(
                identifier="$l1",
                pattern="prompt",
                llm_name="mock-llm",
                cleaner_name="no_op",
                chunker_name="no_chunking",
            )],
            condition="$l1",
        )
        cr = CompiledRules([rule], cfg)
        cache = TextCache()
        cr._execute_llm(rule.llm[0], "some text", cache)

        # LLM must be called with a list of chunks (at least one)
        mock_llm.evaluate_chunks.assert_called_once()
        _, call_args, _ = mock_llm.evaluate_chunks.mock_calls[0]
        chunks_passed = call_args[1]
        assert isinstance(chunks_passed, list)
        assert len(chunks_passed) >= 1


# ---------------------------------------------------------------------------
# ConfigManager
# ---------------------------------------------------------------------------

class TestConfigManager:
    def test_default_config_has_core_cleaners(self):
        cfg = ConfigManager()
        assert "default_cleaning" in cfg.config.cleaners
        assert "no_op" in cfg.config.cleaners
        assert "aggressive" in cfg.config.cleaners

    def test_default_config_has_core_chunkers(self):
        cfg = ConfigManager()
        for name in ("no_chunking", "sentence_chunking", "paragraph", "fixed_size", "word"):
            assert name in cfg.config.chunkers

    def test_default_config_has_distilbert_classifier(self):
        cfg = ConfigManager()
        assert "distilbert" in cfg.config.classifiers
        assert "TunedSBERTClassifier" in cfg.config.classifiers["tuned-sbert"]
        assert "DistilBERTClassifier" in cfg.config.classifiers["distilbert"]

    def test_get_cleaner_default(self):
        cfg = ConfigManager()
        cleaner = cfg.get_cleaner("default_cleaning")
        assert isinstance(cleaner, DefaultCleaner)

    def test_get_cleaner_noop(self):
        cfg = ConfigManager()
        cleaner = cfg.get_cleaner("no_op")
        assert isinstance(cleaner, NoOpCleaner)

    def test_get_cleaner_cached(self):
        cfg = ConfigManager()
        c1 = cfg.get_cleaner("default_cleaning")
        c2 = cfg.get_cleaner("default_cleaning")
        assert c1 is c2

    def test_get_cleaner_unknown_raises(self):
        cfg = ConfigManager()
        with pytest.raises(ValueError, match="Unknown cleaner"):
            cfg.get_cleaner("nonexistent-cleaner")

    def test_get_chunker_no_chunking(self):
        cfg = ConfigManager()
        chunker = cfg.get_chunker("no_chunking")
        assert isinstance(chunker, NoChunker)

    def test_get_chunker_unknown_raises(self):
        cfg = ConfigManager()
        with pytest.raises(ValueError, match="Unknown chunker"):
            cfg.get_chunker("nonexistent-chunker")

    def test_register_cleaner_string_path(self):
        cfg = ConfigManager()
        cfg.register_cleaner("my-noop", "syara.engine.cleaner.NoOpCleaner")
        cleaner = cfg.get_cleaner("my-noop")
        assert isinstance(cleaner, NoOpCleaner)

    def test_register_cleaner_instance(self):
        cfg = ConfigManager()
        instance = AggressiveCleaner()
        cfg.config.cleaners["my-aggressive"] = instance
        result = cfg.get_cleaner("my-aggressive")
        assert result is instance

    def test_register_classifier_instance(self):
        cfg = ConfigManager()
        mock_cls = MagicMock()
        cfg.config.classifiers["mock-cls"] = mock_cls
        result = cfg.get_classifier("mock-cls")
        assert result is mock_cls

    def test_register_llm_instance(self):
        cfg = ConfigManager()
        mock_llm = MagicMock()
        cfg.config.llms["mock-llm"] = mock_llm
        result = cfg.get_llm("mock-llm")
        assert result is mock_llm

    def test_register_cleaner_invalidates_cache(self):
        cfg = ConfigManager()
        old = cfg.get_cleaner("no_op")
        cfg.register_cleaner("no_op", "syara.engine.cleaner.AggressiveCleaner")
        new = cfg.get_cleaner("no_op")
        assert isinstance(new, AggressiveCleaner)

    def test_config_from_yaml_file(self):
        """ConfigManager loads from disk when a config_path is given."""
        yaml_content = """
default_cleaner: no_op
cleaners:
  no_op: syara.engine.cleaner.NoOpCleaner
chunkers:
  no_chunking: syara.engine.chunker.NoChunker
matchers: {}
phash_matchers: {}
classifiers: {}
llms: {}
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            path = f.name
        try:
            cfg = ConfigManager(config_path=path)
            assert cfg.config.default_cleaner == "no_op"
            cleaner = cfg.get_cleaner("no_op")
            assert isinstance(cleaner, NoOpCleaner)
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# TextCache edge cases
# ---------------------------------------------------------------------------

class TestCacheEdgeCases:
    def test_cache_miss_returns_none(self):
        cache = TextCache()
        result = cache.get("uncached text", "default")
        assert result is None

    def test_different_cleaners_different_keys(self):
        cache = TextCache()
        cleaner = DefaultCleaner()
        cache.get_cleaned_text("hello", cleaner, "cleaner_a")
        cache.get_cleaned_text("hello", cleaner, "cleaner_b")
        assert cache.size() == 2

    def test_same_text_same_cleaner_cached(self):
        cache = TextCache()
        cleaner = DefaultCleaner()
        r1 = cache.get_cleaned_text("hello", cleaner, "default")
        r2 = cache.get_cleaned_text("hello", cleaner, "default")
        assert r1 == r2
        assert cache.size() == 1

    def test_multiple_entries(self):
        cache = TextCache()
        cleaner = DefaultCleaner()
        for i in range(5):
            cache.get_cleaned_text(f"text_{i}", cleaner, "default")
        assert cache.size() == 5

    def test_clear_resets_size(self):
        cache = TextCache()
        cleaner = DefaultCleaner()
        cache.get_cleaned_text("x", cleaner, "default")
        cache.clear()
        assert cache.size() == 0
        assert cache.get("x", "default") is None


# ---------------------------------------------------------------------------
# Phash matchers
# ---------------------------------------------------------------------------

def _make_wav(path: str, samples) -> None:
    """Write a minimal 16-bit mono PCM WAV file containing `samples`."""
    import wave, struct
    with wave.open(path, 'wb') as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(8000)
        data = struct.pack(f'<{len(samples)}h', *samples)
        w.writeframes(data)


class TestPlaceholderHashers:
    # -- AudioHashMatcher -------------------------------------------------

    def test_audio_hasher_identical_files(self, tmp_path):
        """Two identical WAV files produce the same hash."""
        wav_path = str(tmp_path / "test.wav")
        samples = list(range(200)) * 10  # 2000 samples with a clear gradient
        _make_wav(wav_path, samples)

        m = AudioHashMatcher()
        h1 = m.compute_hash(wav_path)
        h2 = m.compute_hash(wav_path)
        assert h1 == h2

    def test_audio_hasher_returns_int(self, tmp_path):
        """compute_hash returns an integer."""
        wav_path = str(tmp_path / "test.wav")
        _make_wav(wav_path, [100] * 200)
        m = AudioHashMatcher()
        assert isinstance(m.compute_hash(wav_path), int)

    def test_audio_hasher_different_content_different_hash(self, tmp_path):
        """Two WAV files with very different content produce different hashes."""
        wav_a = str(tmp_path / "a.wav")
        wav_b = str(tmp_path / "b.wav")
        # Ascending vs descending amplitude ramp — should produce inverted bits
        _make_wav(wav_a, list(range(65)))
        _make_wav(wav_b, list(range(64, -1, -1)))
        m = AudioHashMatcher()
        assert m.compute_hash(wav_a) != m.compute_hash(wav_b)

    def test_audio_hasher_similarity_identical(self, tmp_path):
        """similarity() returns 1.0 for identical files."""
        wav_path = str(tmp_path / "test.wav")
        _make_wav(wav_path, [1000] * 200)
        m = AudioHashMatcher()
        assert m.similarity(wav_path, wav_path) == 1.0

    def test_audio_hamming_distance_works(self):
        m = AudioHashMatcher()
        assert m.hamming_distance(0b1010, 0b1110) == 1

    # -- VideoHashMatcher -------------------------------------------------

    def test_video_hasher_identical_files(self, tmp_path):
        """Two identical binary files produce the same hash."""
        vid_path = str(tmp_path / "test.bin")
        content = bytes(range(256)) * 10
        with open(vid_path, 'wb') as f:
            f.write(content)

        m = VideoHashMatcher()
        assert m.compute_hash(vid_path) == m.compute_hash(vid_path)

    def test_video_hasher_returns_int(self, tmp_path):
        vid_path = str(tmp_path / "test.bin")
        with open(vid_path, 'wb') as f:
            f.write(b'\x00' * 200)
        m = VideoHashMatcher()
        assert isinstance(m.compute_hash(vid_path), int)

    def test_video_hasher_different_content_different_hash(self, tmp_path):
        """Different binary content produces different hashes."""
        path_a = str(tmp_path / "a.bin")
        path_b = str(tmp_path / "b.bin")
        with open(path_a, 'wb') as f:
            f.write(bytes(range(65)))           # ascending
        with open(path_b, 'wb') as f:
            f.write(bytes(range(64, -1, -1)))   # descending
        m = VideoHashMatcher()
        assert m.compute_hash(path_a) != m.compute_hash(path_b)

    def test_video_hasher_empty_file(self, tmp_path):
        """Empty file returns hash 0."""
        path = str(tmp_path / "empty.bin")
        open(path, 'wb').close()
        m = VideoHashMatcher()
        assert m.compute_hash(path) == 0

    def test_video_hasher_similarity_identical(self, tmp_path):
        """similarity() returns 1.0 for the same file."""
        path = str(tmp_path / "test.bin")
        with open(path, 'wb') as f:
            f.write(b'\xAB' * 200)
        m = VideoHashMatcher()
        assert m.similarity(path, path) == 1.0

    def test_video_hamming_distance_works(self):
        m = VideoHashMatcher()
        assert m.hamming_distance(0b0000, 0b1111) == 4

    # -- ImageHashMatcher -------------------------------------------------

    def test_image_similarity_method_delegates(self):
        """PHashMatcher.similarity() calls compute_hash + normalized_distance."""
        m = ImageHashMatcher()
        # Monkeypatch compute_hash to return known values
        m.compute_hash = lambda p: 0b0000 if p == "a" else 0b1111
        sim = m.similarity("a", "a", bits=4)
        assert sim == 1.0
        sim2 = m.similarity("a", "b", bits=4)
        assert sim2 == 0.0


# ---------------------------------------------------------------------------
# TunedSBERTClassifier.train() (TODO 3)
# ---------------------------------------------------------------------------

class TestTunedSBERTClassifierTrain:
    """Tests for TunedSBERTClassifier.train() calibration."""

    def _make_classifier(self, similarities: dict):
        """
        Build a TunedSBERTClassifier with a mocked SBERT model.

        similarities: dict mapping (rule_text, input_text) → float
        """
        from syara.engine.classifier import TunedSBERTClassifier
        import numpy as np

        clf = TunedSBERTClassifier.__new__(TunedSBERTClassifier)
        clf.model_name = "mock"
        clf.threshold_boost = 0.1  # initial value

        # Build a fake encoder: returns a 1-D unit vector whose dot product
        # with another such vector equals the pre-specified similarity.
        def encode(text, convert_to_numpy=True):
            # Encode as a 1-D vector; cosine sim will be computed externally
            key = text
            return np.array([similarities.get(key, 0.5)])

        mock_model = MagicMock()
        mock_model.encode.side_effect = encode
        clf.model = mock_model

        return clf

    def test_train_empty_examples_is_noop(self):
        """train([]) must not crash and must leave threshold_boost unchanged."""
        from syara.engine.classifier import TunedSBERTClassifier
        clf = TunedSBERTClassifier.__new__(TunedSBERTClassifier)
        clf.threshold_boost = 0.1
        clf.model = MagicMock()
        clf.train([])
        assert clf.threshold_boost == 0.1

    def test_train_adjusts_threshold_boost(self):
        """
        After training on clearly separable examples, threshold_boost should
        shift so that positive examples score >= 0.5 and negatives < 0.5.
        """
        import numpy as np
        from syara.engine.classifier import TunedSBERTClassifier

        # Positive example: similarity 0.9; Negative: similarity 0.2
        # Optimal cutpoint should be somewhere between 0.2 and 0.9.
        # After training: threshold_boost = 0.5 - cutpoint
        # So confidence = 0.9 + boost should be >= 0.5, and 0.2 + boost < 0.5.

        clf = TunedSBERTClassifier.__new__(TunedSBERTClassifier)
        clf.threshold_boost = 0.0
        clf.model_name = "mock"

        # Mock: encode returns a 2-D unit vector so cosine = 1.0 when identical.
        # We control similarity by returning vectors with known dot products.
        pos_vec = np.array([0.9, np.sqrt(1 - 0.9**2)])
        ref_vec = np.array([1.0, 0.0])
        neg_vec = np.array([0.2, np.sqrt(1 - 0.2**2)])

        call_count = [0]
        def encode(text, convert_to_numpy=True):
            c = call_count[0]
            call_count[0] += 1
            # Calls come in pairs: (rule_text, input_text)
            if c % 2 == 0:
                return ref_vec  # rule_text always → reference
            if (c // 2) == 0:
                return pos_vec  # first pair → positive input
            return neg_vec      # second pair → negative input

        mock_model = MagicMock()
        mock_model.encode.side_effect = encode
        clf.model = mock_model

        clf.train([
            ("rule", "positive_input", True),
            ("rule", "negative_input", False),
        ])

        # After training, positive_sim + boost >= 0.5 and negative_sim + boost < 0.5
        pos_sim = float(np.dot(ref_vec, pos_vec))  # ~0.9
        neg_sim = float(np.dot(ref_vec, neg_vec))  # ~0.2
        assert pos_sim + clf.threshold_boost >= 0.5
        assert neg_sim + clf.threshold_boost < 0.5

    def test_train_ignores_empty_texts(self):
        """Examples with empty rule_text or input_text are skipped."""
        from syara.engine.classifier import TunedSBERTClassifier
        clf = TunedSBERTClassifier.__new__(TunedSBERTClassifier)
        clf.threshold_boost = 0.1
        clf.model = MagicMock()
        # All examples have empty strings — train should not crash and not call encode
        clf.train([("", "input", True), ("rule", "", False)])
        clf.model.encode.assert_not_called()
        assert clf.threshold_boost == 0.1  # unchanged (no scored examples)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
