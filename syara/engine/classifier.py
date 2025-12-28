"""
Semantic classification for binary match/no-match decisions.
"""
from abc import ABC, abstractmethod
from typing import List, Tuple
import numpy as np
from syara.models import ClassifierRule, MatchDetail


class SemanticClassifier(ABC):
    """Abstract base class for semantic classifiers."""

    @abstractmethod
    def classify(self, rule_text: str, input_text: str) -> Tuple[bool, float]:
        """
        Classify whether input_text matches the intent of rule_text.

        Args:
            rule_text: Reference text from the rule
            input_text: Text to classify

        Returns:
            Tuple of (is_match, confidence_score)
        """
        pass

    def train(self, examples: List[Tuple[str, str, bool]]) -> None:
        """
        Train or fine-tune the classifier (optional).

        Args:
            examples: List of (rule_text, input_text, is_match) tuples
        """
        pass


class TunedSBERTClassifier(SemanticClassifier):
    """
    Classifier based on fine-tuned SBERT for binary classification.
    This is a simplified version - in production, you'd load a pre-trained model.
    """

    def __init__(self, model_name: str = 'all-MiniLM-L6-v2', threshold_boost: float = 0.1):
        """
        Initialize tuned SBERT classifier.

        Args:
            model_name: Base SBERT model to use
            threshold_boost: Additional threshold boost for classification
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            raise ImportError(
                "sentence-transformers is required for TunedSBERTClassifier. "
                "Install it with: pip install sentence-transformers"
            )

        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.threshold_boost = threshold_boost

        # In a real implementation, you would load weights from a fine-tuned model here
        # For now, we use the base model with adjusted scoring

    def classify(self, rule_text: str, input_text: str) -> Tuple[bool, float]:
        """
        Classify using semantic similarity with adjusted threshold.

        In a production classifier, this would use a trained binary classifier head.
        Here we use cosine similarity as a proxy.
        """
        if not rule_text or not input_text:
            return False, 0.0

        # Get embeddings
        emb1 = self.model.encode(rule_text, convert_to_numpy=True)
        emb2 = self.model.encode(input_text, convert_to_numpy=True)

        # Compute similarity
        similarity = self._cosine_similarity(emb1, emb2)

        # Apply threshold boost (simulates classifier tuning)
        # In practice, this would be replaced by actual classification logits
        confidence = max(0.0, min(1.0, similarity + self.threshold_boost))

        return True, float(confidence)

    @staticmethod
    def _cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity between two vectors."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    def classify_chunks(
        self,
        rule: ClassifierRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """
        Classify multiple text chunks.

        Args:
            rule: ClassifierRule to apply
            chunks: List of text chunks

        Returns:
            List of MatchDetail for chunks classified as matching
        """
        matches = []

        for chunk in chunks:
            is_match, confidence = self.classify(rule.pattern, chunk)

            # Check if confidence meets threshold
            if is_match and confidence >= rule.threshold:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=confidence,
                    explanation=f"Classifier confidence: {confidence:.3f}"
                )
                matches.append(detail)

        return matches

    def train(self, examples: List[Tuple[str, str, bool]]) -> None:
        """
        Placeholder for training/fine-tuning.

        In a real implementation, this would:
        1. Create a classification dataset from examples
        2. Fine-tune the SBERT model with a classification head
        3. Save the tuned weights

        Args:
            examples: List of (rule_text, input_text, is_match) tuples
        """
        # This is a placeholder - actual implementation would require:
        # - PyTorch training loop
        # - Classification loss (e.g., binary cross-entropy)
        # - Validation split
        # - Model checkpoint saving
        print(f"Training placeholder: {len(examples)} examples provided")
        print("Note: Actual training requires additional implementation")


class DistilBERTClassifier(SemanticClassifier):
    """
    Alternative classifier using DistilBERT for efficiency.
    This is a lightweight alternative to SBERT.
    """

    def __init__(self, model_name: str = 'distilbert-base-uncased'):
        """
        Initialize DistilBERT classifier.

        Args:
            model_name: HuggingFace model name
        """
        try:
            from transformers import DistilBertTokenizer, DistilBertModel
            import torch
        except ImportError:
            raise ImportError(
                "transformers and torch are required for DistilBERTClassifier. "
                "Install with: pip install transformers torch"
            )

        self.tokenizer = DistilBertTokenizer.from_pretrained(model_name)
        self.model = DistilBertModel.from_pretrained(model_name)
        self.torch = torch

    def classify(self, rule_text: str, input_text: str) -> Tuple[bool, float]:
        """Classify using DistilBERT embeddings."""
        if not rule_text or not input_text:
            return False, 0.0

        # Get embeddings
        emb1 = self._get_embedding(rule_text)
        emb2 = self._get_embedding(input_text)

        # Compute similarity
        similarity = self._cosine_similarity(emb1, emb2)

        return True, float(max(0.0, min(1.0, similarity)))

    def _get_embedding(self, text: str) -> np.ndarray:
        """Get DistilBERT embedding for text."""
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512)

        with self.torch.no_grad():
            outputs = self.model(**inputs)

        # Use mean pooling of last hidden state
        embedding = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
        return embedding

    @staticmethod
    def _cosine_similarity(vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Compute cosine similarity."""
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    def classify_chunks(
        self,
        rule: ClassifierRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """Classify multiple chunks."""
        matches = []

        for chunk in chunks:
            is_match, confidence = self.classify(rule.pattern, chunk)

            if is_match and confidence >= rule.threshold:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=confidence,
                    explanation=f"DistilBERT confidence: {confidence:.3f}"
                )
                matches.append(detail)

        return matches
