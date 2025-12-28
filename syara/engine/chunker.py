"""
Text chunking strategies for splitting large documents.
"""
from abc import ABC, abstractmethod
from typing import List
import re


class Chunker(ABC):
    """Abstract base class for text chunkers."""

    @abstractmethod
    def chunk(self, text: str) -> List[str]:
        """
        Split text into chunks.

        Args:
            text: Input text to chunk

        Returns:
            List of text chunks
        """
        pass


class NoChunker(Chunker):
    """
    No chunking - returns the entire text as a single chunk.
    """

    def chunk(self, text: str) -> List[str]:
        """Return text as a single chunk."""
        return [text] if text else []


class SentenceChunker(Chunker):
    """
    Split text by sentences using simple punctuation-based heuristics.
    """

    def __init__(self):
        # Pattern to split on sentence-ending punctuation
        self.sentence_pattern = re.compile(r'[.!?]+\s+')

    def chunk(self, text: str) -> List[str]:
        """Split text into sentences."""
        if not text:
            return []

        # Split on sentence boundaries
        sentences = self.sentence_pattern.split(text)

        # Filter out empty strings and strip whitespace
        chunks = [s.strip() for s in sentences if s.strip()]

        return chunks if chunks else [text]


class FixedSizeChunker(Chunker):
    """
    Split text into fixed-size chunks with optional overlap.
    """

    def __init__(self, chunk_size: int = 500, overlap: int = 50):
        """
        Initialize fixed-size chunker.

        Args:
            chunk_size: Maximum characters per chunk
            overlap: Number of characters to overlap between chunks
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if overlap < 0:
            raise ValueError("overlap cannot be negative")
        if overlap >= chunk_size:
            raise ValueError("overlap must be less than chunk_size")

        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk(self, text: str) -> List[str]:
        """Split text into fixed-size chunks with overlap."""
        if not text:
            return []

        if len(text) <= self.chunk_size:
            return [text]

        chunks = []
        start = 0

        while start < len(text):
            end = start + self.chunk_size
            chunk = text[start:end]

            if chunk.strip():
                chunks.append(chunk)

            # Move start position accounting for overlap
            start = end - self.overlap

            # Prevent infinite loop
            if self.overlap == 0 and start >= len(text):
                break

        return chunks


class ParagraphChunker(Chunker):
    """
    Split text by paragraphs (double newlines).
    """

    def chunk(self, text: str) -> List[str]:
        """Split text into paragraphs."""
        if not text:
            return []

        # Split on double newlines
        paragraphs = re.split(r'\n\s*\n', text)

        # Filter out empty strings and strip whitespace
        chunks = [p.strip() for p in paragraphs if p.strip()]

        return chunks if chunks else [text]


class WordChunker(Chunker):
    """
    Split text into chunks of approximately N words.
    """

    def __init__(self, words_per_chunk: int = 100, overlap_words: int = 10):
        """
        Initialize word-based chunker.

        Args:
            words_per_chunk: Target number of words per chunk
            overlap_words: Number of words to overlap between chunks
        """
        if words_per_chunk <= 0:
            raise ValueError("words_per_chunk must be positive")
        if overlap_words < 0:
            raise ValueError("overlap_words cannot be negative")
        if overlap_words >= words_per_chunk:
            raise ValueError("overlap_words must be less than words_per_chunk")

        self.words_per_chunk = words_per_chunk
        self.overlap_words = overlap_words

    def chunk(self, text: str) -> List[str]:
        """Split text into word-based chunks."""
        if not text:
            return []

        # Split into words
        words = text.split()

        if len(words) <= self.words_per_chunk:
            return [text]

        chunks = []
        start = 0

        while start < len(words):
            end = start + self.words_per_chunk
            chunk_words = words[start:end]
            chunk = ' '.join(chunk_words)

            if chunk.strip():
                chunks.append(chunk)

            # Move start position accounting for overlap
            start = end - self.overlap_words

        return chunks


# Alias for backward compatibility and common usage
TextChunker = SentenceChunker
