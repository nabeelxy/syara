"""
Parser for .syara rule files.
"""
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from syara.models import (
    Rule,
    StringRule,
    SimilarityRule,
    PHashRule,
    ClassifierRule,
    LLMRule
)


class SYaraParser:
    """Parser for YARA-compatible .syara files."""

    def __init__(self):
        """Initialize parser."""
        self.current_line = 0

    def parse_file(self, filepath: str) -> List[Rule]:
        """
        Parse a .syara file and return list of rules.

        Args:
            filepath: Path to .syara file

        Returns:
            List of parsed Rule objects
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Rule file not found: {filepath}")

        content = path.read_text(encoding='utf-8')
        return self.parse_string(content)

    def parse_string(self, content: str) -> List[Rule]:
        """
        Parse rules from a string.

        Args:
            content: Rule file content

        Returns:
            List of parsed Rule objects
        """
        # Remove comments
        content = self._remove_comments(content)

        # Split into individual rules
        rule_blocks = self._split_rules(content)

        # Parse each rule
        rules = []
        for block in rule_blocks:
            try:
                rule = self._parse_rule_block(block)
                rules.append(rule)
            except Exception as e:
                # Include more context in error
                raise ValueError(f"Error parsing rule: {e}")

        return rules

    def _remove_comments(self, content: str) -> str:
        """Remove single-line (//) and multi-line (/* */) comments."""
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)

        # Remove single-line comments
        content = re.sub(r'//.*?$', '', content, flags=re.MULTILINE)

        return content

    def _split_rules(self, content: str) -> List[str]:
        """Split content into individual rule blocks."""
        # Pattern to match: rule <name> [: tags] { ... }
        pattern = r'rule\s+\w+(?:\s*:\s*[\w\s]+)?\s*\{[^}]*(?:\{[^}]*\}[^}]*)*\}'

        matches = re.finditer(pattern, content, re.DOTALL)

        blocks = [match.group(0) for match in matches]

        return blocks

    def _parse_rule_block(self, block: str) -> Rule:
        """Parse a single rule block."""
        # Extract rule header: rule name : tags
        header_match = re.match(r'rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{', block)

        if not header_match:
            raise ValueError(f"Invalid rule header in: {block[:100]}")

        rule_name = header_match.group(1)
        tags_str = header_match.group(2) or ''
        tags = [t.strip() for t in tags_str.split() if t.strip()]

        # Extract rule body
        body_start = block.find('{') + 1
        body_end = block.rfind('}')
        body = block[body_start:body_end]

        # Parse sections
        meta = self._parse_meta_section(body)
        strings = self._parse_strings_section(body)
        similarity = self._parse_similarity_section(body)
        phash = self._parse_phash_section(body)
        classifier = self._parse_classifier_section(body)
        llm = self._parse_llm_section(body)
        condition = self._parse_condition_section(body)

        return Rule(
            name=rule_name,
            tags=tags,
            meta=meta,
            strings=strings,
            similarity=similarity,
            phash=phash,
            classifier=classifier,
            llm=llm,
            condition=condition
        )

    def _parse_meta_section(self, body: str) -> Dict[str, str]:
        """Parse meta section."""
        meta = {}

        # Find meta section
        meta_match = re.search(r'meta:\s*(.*?)(?=\n\s*(?:strings|similarity|phash|classifier|llm|condition):|$)', body, re.DOTALL)

        if not meta_match:
            return meta

        meta_content = meta_match.group(1)

        # Parse key = "value" pairs
        for line in meta_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Match: key = "value"
            match = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
            if match:
                key, value = match.groups()
                meta[key] = value

        return meta

    def _parse_strings_section(self, body: str) -> List[StringRule]:
        """Parse strings section."""
        strings = []

        # Find strings section
        strings_match = re.search(r'strings:\s*(.*?)(?=\n\s*(?:similarity|phash|classifier|llm|condition):|$)', body, re.DOTALL)

        if not strings_match:
            return strings

        strings_content = strings_match.group(1)

        # Parse each string rule
        for line in strings_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Match: $identifier = "pattern" modifiers or $identifier = /regex/ modifiers
            # String pattern
            match = re.match(r'(\$\w+)\s*=\s*"([^"]*)"\s*(.*)', line)
            if match:
                identifier, pattern, modifiers_str = match.groups()
                modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]

                strings.append(StringRule(
                    identifier=identifier,
                    pattern=pattern,
                    modifiers=modifiers,
                    is_regex=False
                ))
                continue

            # Regex pattern
            match = re.match(r'(\$\w+)\s*=\s*/([^/]*)/(i?)\s*(.*)', line)
            if match:
                identifier, pattern, i_flag, modifiers_str = match.groups()
                modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]

                if i_flag:
                    modifiers.append('i')

                strings.append(StringRule(
                    identifier=identifier,
                    pattern=pattern,
                    modifiers=modifiers,
                    is_regex=True
                ))

        return strings

    def _parse_similarity_section(self, body: str) -> List[SimilarityRule]:
        """Parse similarity section."""
        similarity_rules = []

        # Find similarity section
        sim_match = re.search(r'similarity:\s*(.*?)(?=\n\s*(?:phash|classifier|llm|condition):|$)', body, re.DOTALL)

        if not sim_match:
            return similarity_rules

        sim_content = sim_match.group(1)

        # Parse each similarity rule
        # Format: $identifier = "pattern" threshold cleaner chunker matcher
        for line in sim_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split('"')
            if len(parts) < 3:
                continue

            # Extract identifier
            identifier = parts[0].strip().rstrip('=').strip()

            # Extract pattern
            pattern = parts[1]

            # Extract parameters
            params = parts[2].strip().split()

            threshold = float(params[0]) if params else 0.8
            cleaner_name = params[1] if len(params) > 1 else "default_cleaning"
            chunker_name = params[2] if len(params) > 2 else "no_chunking"
            matcher_name = params[3] if len(params) > 3 else "sbert"

            similarity_rules.append(SimilarityRule(
                identifier=identifier,
                pattern=pattern,
                threshold=threshold,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
                matcher_name=matcher_name
            ))

        return similarity_rules

    def _parse_phash_section(self, body: str) -> List[PHashRule]:
        """Parse phash section."""
        phash_rules = []

        # Find phash section
        phash_match = re.search(r'phash:\s*(.*?)(?=\n\s*(?:classifier|llm|condition):|$)', body, re.DOTALL)

        if not phash_match:
            return phash_rules

        phash_content = phash_match.group(1)

        # Parse each phash rule
        # Format: $identifier = "file_path" threshold phash_type
        # Example: $p1 = "reference_image.png" 0.9 imagehash
        for line in phash_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split('"')
            if len(parts) < 3:
                continue

            # Extract identifier
            identifier = parts[0].strip().rstrip('=').strip()

            # Extract file path
            file_path = parts[1]

            # Extract parameters
            params = parts[2].strip().split()

            threshold = float(params[0]) if params else 0.9
            phash_name = params[1] if len(params) > 1 else "imagehash"

            phash_rules.append(PHashRule(
                identifier=identifier,
                file_path=file_path,
                threshold=threshold,
                phash_name=phash_name
            ))

        return phash_rules

    def _parse_classifier_section(self, body: str) -> List[ClassifierRule]:
        """Parse classifier section."""
        classifier_rules = []

        # Find classifier section
        class_match = re.search(r'classifier:\s*(.*?)(?=\n\s*(?:llm|condition):|$)', body, re.DOTALL)

        if not class_match:
            return classifier_rules

        class_content = class_match.group(1)

        # Parse each classifier rule
        # Format: $identifier = "pattern" threshold cleaner chunker classifier
        for line in class_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split('"')
            if len(parts) < 3:
                continue

            # Extract identifier
            identifier = parts[0].strip().rstrip('=').strip()

            # Extract pattern
            pattern = parts[1]

            # Extract parameters
            params = parts[2].strip().split()

            threshold = float(params[0]) if params else 0.7
            cleaner_name = params[1] if len(params) > 1 else "default_cleaning"
            chunker_name = params[2] if len(params) > 2 else "no_chunking"
            classifier_name = params[3] if len(params) > 3 else "tuned-sbert"

            classifier_rules.append(ClassifierRule(
                identifier=identifier,
                pattern=pattern,
                threshold=threshold,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
                classifier_name=classifier_name
            ))

        return classifier_rules

    def _parse_llm_section(self, body: str) -> List[LLMRule]:
        """Parse LLM section."""
        llm_rules = []

        # Find LLM section
        llm_match = re.search(r'llm:\s*(.*?)(?=\n\s*condition:|$)', body, re.DOTALL)

        if not llm_match:
            return llm_rules

        llm_content = llm_match.group(1)

        # Parse each LLM rule
        # Format: $identifier = "pattern" llm_name
        for line in llm_content.split('\n'):
            line = line.strip()
            if not line:
                continue

            parts = line.split('"')
            if len(parts) < 3:
                continue

            # Extract identifier
            identifier = parts[0].strip().rstrip('=').strip()

            # Extract pattern
            pattern = parts[1]

            # Extract LLM name
            params = parts[2].strip().split()
            llm_name = params[0] if params else "gpt-oss20b"

            llm_rules.append(LLMRule(
                identifier=identifier,
                pattern=pattern,
                llm_name=llm_name
            ))

        return llm_rules

    def _parse_condition_section(self, body: str) -> str:
        """Parse condition section."""
        # Find condition section
        cond_match = re.search(r'condition:\s*(.*?)$', body, re.DOTALL)

        if not cond_match:
            return ""

        condition = cond_match.group(1).strip()

        return condition
