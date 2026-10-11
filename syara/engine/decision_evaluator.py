"""
Decision-model evaluation for structured yes/no/score decisions.

Supports JEV (TypeSafe), Laya (convaiinnovations), Winnow (EldanRing/Winnow-E4B)
and any custom evaluator that implements the DecisionEvaluator ABC.

Question format passed to decide():
{
    "<answer_key>": {
        "type": "choice" | "noul" | "score",
        "instructions": "<question text>",
        "criteria": {  # for choice / noul
            "<label>": "<description>",
            ...
        }
        # or for score:
        "criteria": ["level0 description", "level1 description", ...]
    }
}

DecisionResult returned by decide():
    choices  — dict[key -> {choice, confidence, probabilities}]
    nouls    — dict[key -> float]
    scores   — dict[key -> {score, confidence, probabilities}]
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Union


@dataclass
class DecisionResult:
    """
    Normalised response from any decision model.

    Each dict is keyed by the question name (the answer_key passed in the
    questions dict).  Missing keys mean the model did not answer that
    question (treat as no-match).
    """
    choices: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # key → {"choice": str, "confidence": float, "probabilities": dict}

    nouls: Dict[str, float] = field(default_factory=dict)
    # key → probability (float 0-1)

    scores: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # key → {"score": float, "confidence": float, "probabilities": dict}


class DecisionEvaluator(ABC):
    """
    Abstract base class for decision-model evaluators.

    A decision evaluator wraps a structured model (JEV, Laya, Winnow, or any
    compatible system) and exposes a single `decide()` method that accepts a
    state and a questions dict and returns a `DecisionResult`.

    Implement this class to integrate a new decision model into SYara:

        class MyEvaluator(DecisionEvaluator):
            def decide(self, state, questions):
                raw = my_api_call(state, questions)
                return DecisionResult(
                    choices={"verdict": {"choice": raw["verdict"], "confidence": 0.9}},
                    nouls={"prob": raw["prob"]},
                    scores={},
                )
    """

    @abstractmethod
    def decide(
        self,
        state: Union[str, Dict[str, Any]],
        questions: Dict[str, Dict[str, Any]],
    ) -> DecisionResult:
        """
        Evaluate state against one or more typed questions.

        Args:
            state: The content to evaluate.  Can be a plain string (text) or
                   a dict merging free text with structured fields, e.g.:
                   {"content": text, "EventID": "4625", "process.name": "cmd.exe"}
            questions: Mapping from answer key → question spec.
                       Each spec has "type", "instructions", and "criteria".

        Returns:
            DecisionResult populated with whichever answer types were requested.
        """
        pass


def _auto_criteria_choice(positive_label: str) -> Dict[str, str]:
    """
    Generate minimal two-option criteria for a choice question.
    Used when the rule DSL does not specify explicit options.
    """
    negative = "no" if positive_label.lower() == "yes" else "benign"
    return {
        positive_label: f"The content matches the described pattern ({positive_label}).",
        negative: "The content does not match the described pattern.",
    }


def _auto_criteria_noul() -> Dict[str, str]:
    """Generate minimal criteria for a noul question."""
    return {
        "true":  "The described condition is present in the content.",
        "false": "The described condition is absent from the content.",
    }


def _auto_criteria_score() -> List[str]:
    """Generate a generic 0-4 severity scale for a score question."""
    return [
        "0 — Benign / no signal.",
        "1 — Low: minor indicators only.",
        "2 — Medium: plausible match, some evidence.",
        "3 — High: strong evidence, likely positive.",
        "4 — Critical: definitive match, no doubt.",
    ]


def build_question_spec(
    answer_type: str,
    instructions: str,
    positive_label: str = "yes",
) -> Dict[str, Any]:
    """
    Build a question spec dict from DecisionRule fields.

    This is the format expected by DecisionEvaluator.decide() and by Laya /
    Winnow natively.  JEV-specific evaluators convert it to Choice/Noul/Score
    objects internally.
    """
    if answer_type == "choice":
        return {
            "type": "choice",
            "instructions": instructions,
            "criteria": _auto_criteria_choice(positive_label),
        }
    elif answer_type == "noul":
        return {
            "type": "noul",
            "instructions": instructions,
            "criteria": _auto_criteria_noul(),
        }
    elif answer_type == "score":
        return {
            "type": "score",
            "instructions": instructions,
            "criteria": _auto_criteria_score(),
        }
    else:
        raise ValueError(f"Unknown decision answer_type: {answer_type!r}")
