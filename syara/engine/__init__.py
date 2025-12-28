"""
SYara engine components for pattern matching and evaluation.
"""
from syara.engine.cleaner import TextCleaner, DefaultCleaner, NoOpCleaner, AggressiveCleaner
from syara.engine.chunker import (
    Chunker,
    NoChunker,
    SentenceChunker,
    FixedSizeChunker,
    ParagraphChunker,
    WordChunker,
    TextChunker
)
from syara.engine.string_matcher import StringMatcher
from syara.engine.semantic_matcher import SemanticMatcher, SBERTMatcher
from syara.engine.classifier import SemanticClassifier, TunedSBERTClassifier, DistilBERTClassifier
from syara.engine.llm_evaluator import LLMEvaluator, OpenAIEvaluator, OSSLLMEvaluator

__all__ = [
    # Cleaners
    'TextCleaner',
    'DefaultCleaner',
    'NoOpCleaner',
    'AggressiveCleaner',
    # Chunkers
    'Chunker',
    'NoChunker',
    'SentenceChunker',
    'FixedSizeChunker',
    'ParagraphChunker',
    'WordChunker',
    'TextChunker',
    # Matchers
    'StringMatcher',
    'SemanticMatcher',
    'SBERTMatcher',
    # Classifiers
    'SemanticClassifier',
    'TunedSBERTClassifier',
    'DistilBERTClassifier',
    # LLM Evaluators
    'LLMEvaluator',
    'OpenAIEvaluator',
    'OSSLLMEvaluator',
]
