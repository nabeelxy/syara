"""
Semantic similarity matching using embeddings.
"""
from abc import ABC, abstractmethod
from typing import List, Tuple
import numpy as np
from syara.models import SimilarityRule, MatchDetail


class SemanticMatcher(ABC):
    """Abstract base class for semantic matchers."""

    @abstractmethod
    def get_similarity(self, text1: str, text2: str) -> float:
        """
        Compute similarity between two texts.

        Args:
            text1: First text
            text2: Second text

        Returns:
            Similarity score between 0.0 and 1.0
        """
        pass

    @abstractmethod
    def embed(self, text: str) -> np.ndarray:
        """
        Generate embedding for text.

        Args:
            text: Input text

        Returns:
            Embedding vector as numpy array
        """
        pass


class SBERTMatcher(SemanticMatcher):
    """
    Semantic matcher using Sentence-BERT embeddings.
    Uses cosine similarity between embeddings.
    """

    def __init__(self, model_name: str = 'all-MiniLM-L6-v2'):
        """
        Initialize SBERT matcher.

        Args:
            model_name: Name of the sentence-transformers model to use
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for SBERTMatcher. "
                "Install it with: pip install sentence-transformers"
            )

        self.model_name = model_name
        self.model = SentenceTransformer(model_name)

    def embed(self, text: str) -> np.ndarray:
        """Generate SBERT embedding for text."""
        if not text:
            # Return zero vector for empty text
            return np.zeros(self.model.get_sentence_embedding_dimension())

        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding

    def get_similarity(self, text1: str, text2: str) -> float:
        """Compute cosine similarity between two texts using SBERT."""
        if not text1 or not text2:
            return 0.0

        # Get embeddings
        emb1 = self.embed(text1)
        emb2 = self.embed(text2)

        # Compute cosine similarity
        similarity = self._cosine_similarity(emb1, emb2)

        # Ensure result is in [0, 1] range
        return max(0.0, min(1.0, similarity))

    def get_similarity_batch(self, text1: str, texts: List[str]) -> List[float]:
        """
        Compute similarity between one text and multiple texts efficiently.

        Args:
            text1: Reference text
            texts: List of texts to compare against

        Returns:
            List of similarity scores
        """
        if not text1 or not texts:
            return [0.0] * len(texts)

        # Get embedding for reference text
        emb1 = self.embed(text1)

        # Get embeddings for all comparison texts
        embeddings = self.model.encode(texts, convert_to_numpy=True)

        # Compute cosine similarities
        similarities = []
        for emb2 in embeddings:
            sim = self._cosine_similarity(emb1, emb2)
            similarities.append(max(0.0, min(1.0, sim)))

        return similarities

    @staticmethod
    def _cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        # Compute dot product
        dot_product = np.dot(vec1, vec2)

        # Compute norms
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        # Avoid division by zero
        if norm1 == 0 or norm2 == 0:
            return 0.0

        # Cosine similarity
        similarity = dot_product / (norm1 * norm2)

        return float(similarity)

    def match_chunks(
        self,
        rule: SimilarityRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """
        Match rule against multiple text chunks.

        Args:
            rule: SimilarityRule to match
            chunks: List of text chunks to check

        Returns:
            List of MatchDetail for chunks above threshold
        """
        matches = []

        # Compute similarities for all chunks
        similarities = self.get_similarity_batch(rule.pattern, chunks)

        # Find matches above threshold
        for idx, (chunk, similarity) in enumerate(zip(chunks, similarities)):
            if similarity >= rule.threshold:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,  # Chunk-based matching doesn't track positions
                    end_pos=-1,
                    score=similarity,
                    explanation=f"Semantic similarity: {similarity:.3f}"
                )
                matches.append(detail)

        return matches
