"""
Basic tests for SYara library.
"""
import pytest
from syara.models import StringRule, SimilarityRule, PHashRule, ClassifierRule, LLMRule, Rule
from syara.engine.cleaner import DefaultCleaner, NoOpCleaner
from syara.engine.chunker import NoChunker, SentenceChunker, FixedSizeChunker
from syara.engine.phash_matcher import ImageHashMatcher
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

    def test_phash_rule_creation(self):
        rule = PHashRule(
            identifier="$p1",
            file_path="reference.png",
            threshold=0.9
        )
        assert rule.threshold == 0.9
        assert rule.phash_name == "imagehash"
        assert rule.file_path == "reference.png"


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


class TestPHashMatchers:
    """Test perceptual hash matchers for binary files."""

    def test_imagehash_hamming_distance(self):
        matcher = ImageHashMatcher()

        # Test known hamming distances
        hash1 = 0b1010  # Binary: 1010
        hash2 = 0b1110  # Binary: 1110 (differs in 1 bit)
        distance = matcher.hamming_distance(hash1, hash2)
        assert distance == 1

        # Test identical hashes
        hash3 = 0b11111111
        hash4 = 0b11111111
        distance2 = matcher.hamming_distance(hash3, hash4)
        assert distance2 == 0

    def test_imagehash_normalized_distance(self):
        matcher = ImageHashMatcher()

        hash1 = 0b00000000  # All zeros
        hash2 = 0b11111111  # All ones (8 bits differ)

        normalized = matcher.normalized_distance(hash1, hash2, bits=8)
        assert normalized == 1.0  # Maximum distance

        hash3 = 0b00000000
        hash4 = 0b00000000
        normalized2 = matcher.normalized_distance(hash3, hash4, bits=8)
        assert normalized2 == 0.0  # No distance

    # Note: Actual image hashing tests would require test image files
    # and the PIL (Pillow) library to be installed. These are unit tests
    # for the hash comparison logic only.


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

    def test_parse_similarity_rule_keyvalue(self):
        """Test new YARA-like key-value parameter format."""
        rule_text = '''
        rule test_similarity
        {
            similarity:
                $s1 = "test pattern" threshold=0.85 matcher="sbert" cleaner="default_cleaning" chunker="no_chunking"

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
        assert sim.cleaner_name == "default_cleaning"
        assert sim.chunker_name == "no_chunking"

    def test_parse_similarity_rule_keyvalue_minimal(self):
        """Test key-value format with minimal parameters (defaults)."""
        rule_text = '''
        rule test_similarity
        {
            similarity:
                $s1 = "test pattern" threshold=0.75

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
        assert sim.threshold == 0.75
        # Check defaults
        assert sim.matcher_name == "sbert"
        assert sim.cleaner_name == "default_cleaning"
        assert sim.chunker_name == "no_chunking"

    def test_parse_phash_rule_keyvalue(self):
        """Test new key-value phash format."""
        rule_text = '''
        rule test_phash_images
        {
            phash:
                $p1 = "reference_logo.png" threshold=0.95 hasher="imagehash"
                $p2 = "malicious_icon.png" threshold=0.90 hasher="imagehash"

            condition:
                $p1 or $p2
        }
        '''

        parser = SYaraParser()
        rules = parser.parse_string(rule_text)

        assert len(rules) == 1
        rule = rules[0]
        assert len(rule.phash) == 2

        # Check first phash rule
        phash1 = rule.phash[0]
        assert phash1.identifier == "$p1"
        assert phash1.file_path == "reference_logo.png"
        assert phash1.threshold == 0.95
        assert phash1.phash_name == "imagehash"

        # Check second phash rule
        phash2 = rule.phash[1]
        assert phash2.identifier == "$p2"
        assert phash2.file_path == "malicious_icon.png"
        assert phash2.threshold == 0.90
        assert phash2.phash_name == "imagehash"

    def test_parse_classifier_rule_keyvalue(self):
        """Test new key-value classifier format."""
        rule_text = '''
        rule test_classifier
        {
            classifier:
                $c1 = "prompt injection" threshold=0.7 classifier="deberta-prompt-injection"

            condition:
                $c1
        }
        '''

        parser = SYaraParser()
        rules = parser.parse_string(rule_text)

        assert len(rules) == 1
        rule = rules[0]
        assert len(rule.classifier) == 1

        cls = rule.classifier[0]
        assert cls.identifier == "$c1"
        assert cls.pattern == "prompt injection"
        assert cls.threshold == 0.7
        assert cls.classifier_name == "deberta-prompt-injection"

    def test_parse_llm_rule_keyvalue(self):
        """Test new key-value LLM format."""
        rule_text = '''
        rule test_llm
        {
            llm:
                $l1 = "Check if this is malicious" llm="gpt-4"

            condition:
                $l1
        }
        '''

        parser = SYaraParser()
        rules = parser.parse_string(rule_text)

        assert len(rules) == 1
        rule = rules[0]
        assert len(rule.llm) == 1

        llm = rule.llm[0]
        assert llm.identifier == "$l1"
        assert llm.pattern == "Check if this is malicious"
        assert llm.llm_name == "gpt-4"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
