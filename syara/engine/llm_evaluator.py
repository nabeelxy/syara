"""
LLM-based evaluation for semantic rule matching.
"""
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
            return False, "Empty input"

        # Construct prompt for LLM evaluation
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
                max_tokens=100
            )

            result = response.choices[0].message.content.strip()

            # Parse response
            is_match, explanation = self._parse_response(result)

            return is_match, explanation

        except Exception as e:
            return False, f"LLM evaluation error: {str(e)}"

    def _build_prompt(self, rule_text: str, input_text: str) -> str:
        """Build evaluation prompt for LLM."""
        return f"""Pattern to match: "{rule_text}"

Input text: "{input_text}"

Does the input text semantically match the pattern's intent? Respond with:
- "YES: <brief explanation>" if it matches
- "NO: <brief explanation>" if it doesn't match"""

    def _parse_response(self, response: str) -> Tuple[bool, str]:
        """Parse LLM response into match result and explanation."""
        response = response.strip()

        if response.upper().startswith("YES"):
            # Extract explanation after "YES:"
            explanation = response.split(":", 1)[1].strip() if ":" in response else "LLM matched"
            return True, explanation
        elif response.upper().startswith("NO"):
            explanation = response.split(":", 1)[1].strip() if ":" in response else "LLM did not match"
            return False, explanation
        else:
            # Ambiguous response
            return False, f"Ambiguous LLM response: {response}"

    def evaluate_chunks(
        self,
        rule: LLMRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """
        Evaluate multiple chunks using LLM.

        Args:
            rule: LLMRule to apply
            chunks: List of text chunks

        Returns:
            List of MatchDetail for matched chunks
        """
        matches = []

        for chunk in chunks:
            is_match, explanation = self.evaluate(rule.pattern, chunk)

            if is_match:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=1.0,  # LLM matches are binary
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
            return False, "Empty input"

        prompt = self._build_prompt(rule_text, input_text)

        if self.endpoint:
            # Use remote endpoint
            return self._evaluate_remote(prompt)
        else:
            # Use local model
            return self._evaluate_local(prompt)

    def _build_prompt(self, rule_text: str, input_text: str) -> str:
        """Build evaluation prompt."""
        return f"""Question: Does the following text match the pattern "{rule_text}"?

Text: {input_text}

Answer YES or NO with a brief explanation:"""

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

            return self._parse_response(response)

        except Exception as e:
            return False, f"Local LLM error: {str(e)}"

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
        response = response.strip()

        # Check for YES/NO in response
        response_upper = response.upper()

        if "YES" in response_upper and "NO" not in response_upper:
            return True, response
        elif "NO" in response_upper:
            return False, response
        else:
            # Ambiguous - default to no match
            return False, f"Ambiguous response: {response}"

    def evaluate_chunks(
        self,
        rule: LLMRule,
        chunks: List[str]
    ) -> List[MatchDetail]:
        """Evaluate multiple chunks."""
        matches = []

        for chunk in chunks:
            is_match, explanation = self.evaluate(rule.pattern, chunk)

            if is_match:
                detail = MatchDetail(
                    identifier=rule.identifier,
                    matched_text=chunk,
                    start_pos=-1,
                    end_pos=-1,
                    score=1.0,
                    explanation=explanation
                )
                matches.append(detail)

        return matches
