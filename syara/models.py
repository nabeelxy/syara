"""
Data models for SYara rules and matches.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class StringRule:
    """Represents a traditional string/regex matching rule."""
    identifier: str  # e.g., "$s1"
    pattern: str
    modifiers: List[str] = field(default_factory=list)  # nocase, wide, etc.
    is_regex: bool = False


@dataclass
class SimilarityRule:
    """Represents a semantic similarity matching rule."""
    identifier: str  # e.g., "$s3"
    pattern: str
    threshold: float  # 0.0 to 1.0
    cleaner_name: str = "default_cleaning"
    chunker_name: str = "no_chunking"
    matcher_name: str = "sbert"


@dataclass
class PHashRule:
    """Represents a perceptual hash matching rule for binary files (images, audio, video)."""
    identifier: str  # e.g., "$p1"
    file_path: str  # Path to reference file (image/audio/video)
    threshold: float  # 0.0 to 1.0 (Hamming distance normalized)
    phash_name: str = "imagehash"  # Type of phash: imagehash, audiohash, videohash


@dataclass
class ClassifierRule:
    """Represents a classifier-based matching rule."""
    identifier: str  # e.g., "$s4"
    pattern: str
    threshold: float  # 0.0 to 1.0
    cleaner_name: str = "default_cleaning"
    chunker_name: str = "no_chunking"
    classifier_name: str = "tuned-sbert"


@dataclass
class LLMRule:
    """Represents an LLM-based evaluation rule."""
    identifier: str  # e.g., "$s5"
    pattern: str
    llm_name: str = "flan-t5-large"
    cleaner_name: str = "no_op"
    chunker_name: str = "no_chunking"


@dataclass
class FieldRule:
    """Represents a key:value field matching rule (Sigma-style)."""
    identifier: str  # e.g., "$evt"
    field_name: str  # e.g., "EventID"
    pattern: str     # e.g., "4624" or "cmd.exe" or r"192\.168\.\d+\.\d+"
    modifiers: List[str] = field(default_factory=list)  # nocase, etc.
    is_regex: bool = False


@dataclass
class DecisionRule:
    """
    Represents a structured decision-model rule (JEV / Laya / Winnow style).

    The model receives a 'state' (text + optional fields dict) and a typed
    question, then returns a structured answer.  Three answer types are
    supported, selected by which parameter is present in the DSL:

    Choice  — model picks one label from a set; match when the selected label
               equals `positive_label` and confidence >= `threshold`.
               DSL param: verdict="malicious"

    Noul    — model returns a probability 0-1; match when value >= `threshold`.
               DSL param: noul=0.6  (the number IS the threshold)

    Score   — model returns a numeric score; match when score >= `threshold`.
               DSL param: score=3.0  (the number IS the threshold)
    """
    identifier: str        # "$d1"
    question: str          # Free-text instructions sent to the model
    model_name: str        # "jev", "laya", "winnow", or any registered name
    answer_type: str       # "choice", "noul", "score"
    positive_label: str = "yes"   # For choice: the label that counts as a match
    threshold: float = 0.5        # Confidence (choice) / probability (noul) / score threshold
    cleaner_name: str = "no_op"
    chunker_name: str = "no_chunking"


@dataclass
class MatchDetail:
    """Details of a single pattern match."""
    identifier: str
    matched_text: str
    start_pos: int = -1
    end_pos: int = -1
    score: float = 1.0  # similarity/classifier confidence
    explanation: str = ""  # for LLM matches


@dataclass
class Rule:
    """Complete rule definition."""
    name: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    strings: List[StringRule] = field(default_factory=list)
    similarity: List[SimilarityRule] = field(default_factory=list)
    phash: List[PHashRule] = field(default_factory=list)
    classifier: List[ClassifierRule] = field(default_factory=list)
    llm: List[LLMRule] = field(default_factory=list)
    fields: List[FieldRule] = field(default_factory=list)
    decision: List[DecisionRule] = field(default_factory=list)
    condition: str = ""


@dataclass
class Match:
    """Result of matching a rule against text."""
    rule_name: str
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    matched: bool = False
    matched_patterns: Dict[str, List[MatchDetail]] = field(default_factory=dict)

    def __str__(self) -> str:
        """String representation of match result."""
        if not self.matched:
            return f"Match(rule='{self.rule_name}', matched=False)"

        pattern_count = sum(len(details) for details in self.matched_patterns.values())
        return f"Match(rule='{self.rule_name}', matched=True, patterns={pattern_count})"
