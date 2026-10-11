"""
LLM-based evaluation for semantic rule matching.
"""
import re
import math
from abc import ABC, abstractmethod
from typing import List, Tuple
from syara.models import LLMRule, MatchDetail


class LLMEvaluator(ABC):
    """Abstract base class for LLM evaluators."""

    @abstractmethod
    def evaluate(self, rule_text: str, input_text: str) -> Tuple[bool, str]:
        """
        Evaluate whether input_text matches the semantic intent of rule_text.

        Args:
            rule_text: Reference text from the rule
            input_text: Text to evaluate

        Returns:
            Tuple of (is_match, explanation)
        """
        pass


class OpenAIEvaluator(LLMEvaluator):
    """
    LLM evaluator using OpenAI's GPT models.
    """

    def __init__(self, model_name: str = 'gpt-3.5-turbo', api_key: str = ''):
        """
        Initialize OpenAI evaluator.

        Args:
            model_name: OpenAI model to use (gpt-3.5-turbo, gpt-4, etc.)
            api_key: OpenAI API key
        """
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai is required for OpenAIEvaluator. "
                "Install it with: pip install openai"
            )

        self.model_name = model_name
        self.client = OpenAI(api_key=api_key) if api_key else OpenAI()

    def evaluate(self, rule_text: str, input_text: str) -> Tuple[bool, str]:
        """Evaluate using OpenAI LLM."""
        if not rule_text or not input_text:
            return False, "Empty input", 0.0

        prompt = self._build_prompt(rule_text, input_text)

        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a semantic matching system. Analyze if the input text matches the pattern's semantic intent."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.0,
                max_tokens=10,
                logprobs=True,
                top_logprobs=2
            )

            result = response.choices[0].message.content.strip()
            is_match, explanation = self._parse_response(result)

            # Extract confidence from logprobs if available
            confidence = 0.5
            try:
                logprob_content = response.choices[0].logprobs.content
                if logprob_content:
                    top_logprob = logprob_content[0].logprob
                    confidence = math.exp(top_logprob)
            except Exception:
                pass

            return is_match, explanation, confidence

        except Exception as e:
            return False, f"LLM evaluation error: {str(e)}", 0.0

    def _build_prompt(self, rule_text: str, input_text: str) -> str:
        """Build evaluation prompt for LLM."""
        return f"""Pattern to match: "{rule_text}"

Input text: "{input_text}"

Does the input text semantically match the pattern's intent? Respond with:
- "YES: <brief explanation>" if it matches
- "NO: <brief explanation>" if it doesn't match"""

    def _parse_response(self, response: str) -> Tuple[bool, str]:
        """Parse LLM response into match result and explanation."""
        upper = response.strip().upper()

        if re.match(r'YES\b', upper):
            explanation = response.split(":", 1)[1].strip() if ":" in response else "LLM matched"
            return True, explanation
        elif re.match(r'NO\b', upper):
            explanation = response.split(":", 1)[1].strip() if ":" in response else "LLM did not match"
            return False, explanation
        else:
            return False, f"Ambiguous LLM response: {response}"

    def evaluate_chunks(
        self,
        rule: LLMRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """
        Evaluate multiple chunks using LLM.
        """
        matches = []

        for chunk in chunks:
            result = self.evaluate(rule.pattern, chunk)
            if len(result) == 3:
                is_match, explanation, confidence = result
            else:
                is_match, explanation = result
                confidence = 1.0

            if is_match:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=confidence,
                    explanation=explanation
                )
                matches.append(detail)

        return matches


class OSSLLMEvaluator(LLMEvaluator):
    """
    LLM evaluator using open-source models via HuggingFace or custom endpoints.
    """

    def __init__(self, model_name: str = 'google/flan-t5-large', endpoint: str = ''):
        """
        Initialize OSS LLM evaluator.

        Args:
            model_name: HuggingFace model name or model identifier
            endpoint: Optional API endpoint for hosted model
        """
        self.model_name = model_name
        self.endpoint = endpoint
        self.model = None
        self.tokenizer = None

        if not endpoint:
            # Load model locally using transformers
            self._load_local_model()

    def _load_local_model(self):
        """Load model locally using transformers."""
        try:
            from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
            import torch
        except ImportError:
            raise ImportError(
                "transformers and torch are required for local OSS models. "
                "Install with: pip install transformers torch"
            )

        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_name)
        self.torch = torch

    def evaluate(self, rule_text: str, input_text: str) -> Tuple[bool, str]:
        """Evaluate using OSS LLM."""
        if not rule_text or not input_text:
            return False, "Empty input", 0.0

        prompt = self._build_prompt(rule_text, input_text)

        if self.endpoint:
            return self._evaluate_remote(prompt)
        else:
            return self._evaluate_local(prompt)

    def _build_prompt(self, rule_text: str, input_text: str) -> str:
        """Build evaluation prompt."""
        return f"""Question: Does the following text match the pattern "{rule_text}"?

Text: {input_text}

Answer YES or NO with a brief explanation:"""

    def _extract_confidence(self, prompt: str, is_yes: bool) -> float:
        """Extract confidence score using output token probabilities."""
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
            with self.torch.no_grad():
                outputs = self.model(**inputs)
            logits = outputs.logits if hasattr(outputs, 'logits') else None
            if logits is None:
                return 1.0
            yes_id = self.tokenizer.encode("YES", add_special_tokens=False)
            no_id = self.tokenizer.encode("NO", add_special_tokens=False)
            if not yes_id or not no_id:
                return 1.0
            import torch
            probs = torch.softmax(logits[0, -1, :], dim=-1)
            yes_prob = float(probs[yes_id[0]])
            no_prob = float(probs[no_id[0]])
            total = yes_prob + no_prob
            if total == 0:
                return 1.0
            return yes_prob / total if is_yes else no_prob / total
        except Exception:
            return 1.0

    def _evaluate_local(self, prompt: str) -> Tuple[bool, str]:
        """Evaluate using locally loaded model."""
        try:
            inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)

            with self.torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_length=100,
                    temperature=0.0,
                    do_sample=False
                )

            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            is_match, explanation = self._parse_response(response)
            confidence = self._extract_confidence(prompt, is_match)
            return is_match, explanation, confidence

        except Exception as e:
            return False, f"Local LLM error: {str(e)}", 0.0

    def _evaluate_remote(self, prompt: str) -> Tuple[bool, str]:
        """Evaluate using remote endpoint."""
        try:
            import requests

            response = requests.post(
                self.endpoint,
                json={"prompt": prompt, "max_tokens": 100},
                timeout=30
            )

            if response.status_code == 200:
                result = response.json().get('text', '')
                return self._parse_response(result)
            else:
                return False, f"Remote LLM error: HTTP {response.status_code}"

        except Exception as e:
            return False, f"Remote LLM error: {str(e)}"

    def _parse_response(self, response: str) -> Tuple[bool, str]:
        """Parse LLM response."""
        upper = response.strip().upper()

        if re.match(r'YES\b', upper):
            return True, response
        elif re.match(r'NO\b', upper):
            return False, response
        else:
            return False, f"Ambiguous response: {response}"

    def evaluate_chunks(
        self,
        rule: LLMRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """Evaluate multiple chunks."""
        matches = []

        for chunk in chunks:
            result = self.evaluate(rule.pattern, chunk)
            if len(result) == 3:
                is_match, explanation, confidence = result
            else:
                is_match, explanation = result
                confidence = 1.0

            if is_match:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=confidence,
                    explanation=explanation
                )
                matches.append(detail)

        return matches
