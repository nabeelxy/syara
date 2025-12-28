"""
Basic tests for SYara library.
"""
import pytest
from syara.models import StringRule, SimilarityRule, ClassifierRule, LLMRule, Rule
from syara.engine.cleaner import DefaultCleaner, NoOpCleaner
from syara.engine.chunker import NoChunker, SentenceChunker, FixedSizeChunker
from syara.cache import TextCache
from syara.parser import SYaraParser


class TestModels:
    """Test data models."""

    def test_string_rule_creation(self):
        rule = StringRule(
            identifier="$s1",
            pattern="test",
            modifiers=["nocase"],
            is_regex=False
        )
        assert rule.identifier == "$s1"
        assert rule.pattern == "test"
        assert "nocase" in rule.modifiers

    def test_similarity_rule_creation(self):
        rule = SimilarityRule(
            identifier="$s2",
            pattern="test pattern",
            threshold=0.8
        )
        assert rule.threshold == 0.8
        assert rule.matcher_name == "sbert"


class TestCleaners:
    """Test text cleaners."""

    def test_default_cleaner(self):
        cleaner = DefaultCleaner()
        text = "  Hello   WORLD  "
        cleaned = cleaner.clean(text)
        assert cleaned == "hello world"

    def test_noop_cleaner(self):
        cleaner = NoOpCleaner()
        text = "  Hello   WORLD  "
        cleaned = cleaner.clean(text)
        assert cleaned == text


class TestChunkers:
    """Test text chunkers."""

    def test_no_chunker(self):
        chunker = NoChunker()
        text = "This is a test. This is only a test."
        chunks = chunker.chunk(text)
        assert len(chunks) == 1
        assert chunks[0] == text

    def test_sentence_chunker(self):
        chunker = SentenceChunker()
        text = "First sentence. Second sentence! Third sentence?"
        chunks = chunker.chunk(text)
        assert len(chunks) >= 2  # At least 2 sentences

    def test_fixed_size_chunker(self):
        chunker = FixedSizeChunker(chunk_size=10, overlap=2)
        text = "This is a long text that needs to be chunked"
        chunks = chunker.chunk(text)
        assert len(chunks) > 1


class TestCache:
    """Test text cache."""

    def test_cache_storage_and_retrieval(self):
        cache = TextCache()
        cleaner = DefaultCleaner()

        text = "Test TEXT"
        cleaned = cache.get_cleaned_text(text, cleaner, "default")

        # Should get same result from cache
        cached = cache.get(text, "default")
        assert cached == cleaned
        assert cached == "test text"

    def test_cache_clear(self):
        cache = TextCache()
        cleaner = DefaultCleaner()

        cache.get_cleaned_text("test", cleaner, "default")
        assert cache.size() == 1

        cache.clear()
        assert cache.size() == 0


class TestParser:
    """Test rule parser."""

    def test_parse_basic_rule(self):
        rule_text = '''
        rule test_rule: tag1 tag2
        {
            meta:
                author = "tester"

            strings:
                $s1 = "test" nocase

            condition:
                $s1
        }
        '''

        parser = SYaraParser()
        rules = parser.parse_string(rule_text)

        assert len(rules) == 1
        rule = rules[0]
        assert rule.name == "test_rule"
        assert "tag1" in rule.tags
        assert "tag2" in rule.tags
        assert rule.meta["author"] == "tester"
        assert len(rule.strings) == 1
        assert rule.strings[0].identifier == "$s1"

    def test_parse_similarity_rule(self):
        rule_text = '''
        rule test_similarity
        {
            similarity:
                $s1 = "test pattern" 0.85 default_cleaning no_chunking sbert

            condition:
                $s1
        }
        '''

        parser = SYaraParser()
        rules = parser.parse_string(rule_text)

        assert len(rules) == 1
        rule = rules[0]
        assert len(rule.similarity) == 1
        sim = rule.similarity[0]
        assert sim.identifier == "$s1"
        assert sim.threshold == 0.85
        assert sim.matcher_name == "sbert"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
