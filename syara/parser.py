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
    LLMRule,
    FieldRule,
    DecisionRule,
)


class SYaraParser:
    """Parser for YARA-compatible .syara files."""

    # Section header regex: keyword followed by colon, not inside strings/identifiers
    _SECTION_RE = re.compile(
        r'(?<!["\$\w])(meta|strings|similarity|phash|classifier|llm|fields|decision|condition)[ \t]*:',
        re.IGNORECASE
    )

    def __init__(self):
        """Initialize parser."""
        self.current_line = 0

    def _parse_modifiers(self, params_str: str) -> Dict[str, str]:
        """
        Parse YARA-style modifiers (key-value or key-only).

        Supports:
        - key=value (e.g., threshold=0.8, matcher="sbert")
        - key="value with spaces" (e.g., cleaner="default cleaning")
        - key only (e.g., nocase, wide)

        Args:
            params_str: String containing modifiers

        Returns:
            Dictionary of parsed modifiers
        """
        modifiers = {}

        # Pattern to match key="value" or key=value or just key
        # Handles quoted values: key="value with spaces"
        # Handles unquoted values: key=value
        # Handles boolean flags: nocase
        pattern = r'(\w+)(?:=(?:"([^"]*)"|([^\s=]+)))?'

        for match in re.finditer(pattern, params_str):
            key = match.group(1)
            quoted_value = match.group(2)  # Value in quotes
            unquoted_value = match.group(3)  # Value without quotes

            if quoted_value is not None:
                modifiers[key] = quoted_value
            elif unquoted_value is not None:
                modifiers[key] = unquoted_value
            else:
                # Boolean flag (like 'nocase')
                modifiers[key] = True

        return modifiers

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
        """Split content into individual rule blocks using brace counting.

        Handles regex patterns with {n,m} quantifiers inside rule bodies by
        skipping over string literals and regex literals when counting braces.
        """
        blocks = []
        i = 0
        n = len(content)

        # Match: rule <name> [: tags] {
        header_re = re.compile(r'\brule\s+\w+(?:\s*:\s*[\w\s]+?)?\s*\{', re.DOTALL)

        while i < n:
            m = header_re.search(content, i)
            if not m:
                break

            rule_start = m.start()
            j = m.end()   # position immediately after the opening '{'
            depth = 1     # we already consumed one '{'

            while j < n and depth > 0:
                c = content[j]

                if c == '\\':
                    # Escape sequence — skip next character
                    j += 2

                elif c == '"':
                    # String literal — triple-quoted or single-quoted
                    if content[j:j + 3] == '"""':
                        j += 3
                        while j < n:
                            if content[j] == '\\':
                                j += 2
                                continue
                            if content[j:j + 3] == '"""':
                                j += 3
                                break
                            j += 1
                    else:
                        j += 1
                        while j < n:
                            if content[j] == '\\':
                                j += 2
                                continue
                            if content[j] == '"':
                                j += 1
                                break
                            j += 1

                elif c == '/':
                    # Regex literal when immediately preceded by '=' (with optional whitespace)
                    k = j - 1
                    while k >= rule_start and content[k] in ' \t':
                        k -= 1
                    if k >= rule_start and content[k] == '=':
                        # Skip regex body to closing '/'
                        j += 1
                        while j < n:
                            if content[j] == '\\':
                                j += 2
                                continue
                            if content[j] == '/':
                                j += 1
                                break
                            j += 1
                        # Skip optional flags (e.g., 'i', 's')
                        while j < n and content[j].isalpha():
                            j += 1
                    else:
                        j += 1

                elif c == '{':
                    depth += 1
                    j += 1

                elif c == '}':
                    depth -= 1
                    j += 1

                else:
                    j += 1

            blocks.append(content[rule_start:j])
            i = j

        return blocks

    def _split_sections(self, body: str) -> Dict[str, str]:
        """
        Find all section headers in body and return a dict of section_name -> content.
        Sections can appear in any order.
        """
        sections: Dict[str, str] = {}
        # Find all matches for section headers
        matches = list(self._SECTION_RE.finditer(body))
        for idx, m in enumerate(matches):
            section_name = m.group(1).lower()
            content_start = m.end()
            # Content ends at next section header (or end of body)
            if idx + 1 < len(matches):
                content_end = matches[idx + 1].start()
            else:
                content_end = len(body)
            sections[section_name] = body[content_start:content_end]
        return sections

    def _parse_rule_block(self, block: str) -> Rule:
        """Parse a single rule block."""
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

        # Split body into sections (order-independent)
        sections = self._split_sections(body)

        # Parse each section
        meta = self._parse_meta_content(sections.get('meta', ''))
        strings = self._parse_strings_content(sections.get('strings', ''))
        similarity = self._parse_similarity_content(sections.get('similarity', ''))
        phash = self._parse_phash_content(sections.get('phash', ''))
        classifier = self._parse_classifier_content(sections.get('classifier', ''))
        llm = self._parse_llm_content(sections.get('llm', ''))
        fields = self._parse_fields_content(sections.get('fields', ''))
        decision = self._parse_decision_content(sections.get('decision', ''))
        condition = sections.get('condition', '').strip()

        return Rule(
            name=rule_name,
            tags=tags,
            meta=meta,
            strings=strings,
            similarity=similarity,
            phash=phash,
            classifier=classifier,
            llm=llm,
            fields=fields,
            decision=decision,
            condition=condition
        )

    def _parse_meta_content(self, content: str) -> Dict[str, str]:
        """Parse meta section content."""
        meta = {}
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            match = re.match(r'(\w+)\s*=\s*"([^"]*)"', line)
            if match:
                key, value = match.groups()
                meta[key] = value
        return meta

    def _parse_strings_content(self, content: str) -> List[StringRule]:
        """Parse strings section content."""
        strings = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

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

            # Regex pattern - supports escaped slashes and multi-char flags
            match = re.match(r'(\$\w+)\s*=\s*/((?:[^/\\]|\\.)+)/([is]*)\s*(.*)', line)
            if match:
                identifier, pattern, inline_flags, modifiers_str = match.groups()
                pattern = pattern.replace('\\/', '/')
                modifiers = list(inline_flags) + [tok for tok in modifiers_str.split() if tok.strip()]
                strings.append(StringRule(
                    identifier=identifier,
                    pattern=pattern,
                    modifiers=modifiers,
                    is_regex=True
                ))

        return strings

    def _parse_similarity_content(self, content: str) -> List[SimilarityRule]:
        """Parse similarity section content."""
        similarity_rules = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            match = re.match(r'(\$\w+)\s*=\s*"([^"]+)"\s*(.*)', line)
            if not match:
                continue
            identifier = match.group(1)
            pattern = match.group(2)
            params_str = match.group(3).strip()
            parsed_params = self._parse_modifiers(params_str)
            threshold = float(parsed_params.get('threshold', 0.8))
            cleaner_name = parsed_params.get('cleaner', 'default_cleaning')
            chunker_name = parsed_params.get('chunker', 'no_chunking')
            matcher_name = parsed_params.get('matcher', 'sbert')
            similarity_rules.append(SimilarityRule(
                identifier=identifier,
                pattern=pattern,
                threshold=threshold,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
                matcher_name=matcher_name
            ))
        return similarity_rules

    def _parse_phash_content(self, content: str) -> List[PHashRule]:
        """Parse phash section content."""
        phash_rules = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            match = re.match(r'(\$\w+)\s*=\s*"([^"]+)"\s*(.*)', line)
            if not match:
                continue
            identifier = match.group(1)
            file_path = match.group(2)
            params_str = match.group(3).strip()
            parsed_params = self._parse_modifiers(params_str)
            threshold = float(parsed_params.get('threshold', 0.9))
            phash_name = parsed_params.get('hasher', parsed_params.get('phash', 'imagehash'))
            phash_rules.append(PHashRule(
                identifier=identifier,
                file_path=file_path,
                threshold=threshold,
                phash_name=phash_name
            ))
        return phash_rules

    def _parse_classifier_content(self, content: str) -> List[ClassifierRule]:
        """Parse classifier section content."""
        classifier_rules = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            match = re.match(r'(\$\w+)\s*=\s*"([^"]+)"\s*(.*)', line)
            if not match:
                continue
            identifier = match.group(1)
            pattern = match.group(2)
            params_str = match.group(3).strip()
            parsed_params = self._parse_modifiers(params_str)
            threshold = float(parsed_params.get('threshold', 0.7))
            cleaner_name = parsed_params.get('cleaner', 'default_cleaning')
            chunker_name = parsed_params.get('chunker', 'no_chunking')
            classifier_name = parsed_params.get('classifier', 'tuned-sbert')
            classifier_rules.append(ClassifierRule(
                identifier=identifier,
                pattern=pattern,
                threshold=threshold,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
                classifier_name=classifier_name
            ))
        return classifier_rules

    def _parse_llm_content(self, content: str) -> List[LLMRule]:
        """Parse LLM section content."""
        llm_rules = []

        # Match triple-quoted patterns first
        triple_quote_pattern = r'(\$\w+)\s*=\s*"""(.*?)"""\s*(.*)$'
        for match in re.finditer(triple_quote_pattern, content, re.MULTILINE | re.DOTALL):
            identifier = match.group(1)
            pattern = match.group(2)
            params_str = match.group(3).strip()
            parsed_params = self._parse_modifiers(params_str)
            llm_name = parsed_params.get('llm', 'flan-t5-large')
            cleaner_name = parsed_params.get('cleaner', 'no_op')
            chunker_name = parsed_params.get('chunker', 'no_chunking')
            llm_rules.append(LLMRule(
                identifier=identifier,
                pattern=pattern,
                llm_name=llm_name,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
            ))

        # Match single-quoted patterns
        single_quote_pattern = r'(\$\w+)\s*=\s*"([^"]+)"\s*(.*)$'
        for match in re.finditer(single_quote_pattern, content, re.MULTILINE):
            identifier = match.group(1)
            if any(r.identifier == identifier for r in llm_rules):
                continue
            pattern = match.group(2)
            params_str = match.group(3).strip()
            parsed_params = self._parse_modifiers(params_str)
            llm_name = parsed_params.get('llm', 'flan-t5-large')
            cleaner_name = parsed_params.get('cleaner', 'no_op')
            chunker_name = parsed_params.get('chunker', 'no_chunking')
            llm_rules.append(LLMRule(
                identifier=identifier,
                pattern=pattern,
                llm_name=llm_name,
                cleaner_name=cleaner_name,
                chunker_name=chunker_name,
            ))

        return llm_rules

    def _parse_fields_content(self, content: str) -> List[FieldRule]:
        """Parse fields section content."""
        field_rules = []
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

            # Literal: $id = field_name = "value" [modifiers]
            match = re.match(r'(\$\w+)\s*=\s*([\w.]+)\s*=\s*"([^"]*)"\s*(.*)', line)
            if match:
                identifier, field_name, pattern, modifiers_str = match.groups()
                modifiers = [m.strip() for m in modifiers_str.split() if m.strip()]
                field_rules.append(FieldRule(
                    identifier=identifier,
                    field_name=field_name,
                    pattern=pattern,
                    modifiers=modifiers,
                    is_regex=False
                ))
                continue

            # Regex: $id = field_name = /pattern/[flags]
            match = re.match(r'(\$\w+)\s*=\s*([\w.]+)\s*=\s*/((?:[^/\\]|\\.)+)/([is]*)\s*(.*)', line)
            if match:
                identifier, field_name, pattern, inline_flags, modifiers_str = match.groups()
                pattern = pattern.replace('\\/', '/')
                modifiers = list(inline_flags) + [tok for tok in modifiers_str.split() if tok.strip()]
                field_rules.append(FieldRule(
                    identifier=identifier,
                    field_name=field_name,
                    pattern=pattern,
                    modifiers=modifiers,
                    is_regex=True
                ))

        return field_rules

    def _parse_decision_content(self, content: str) -> List[DecisionRule]:
        """
        Parse decision: section content.

        Supported DSL forms (one per line):

        Choice — match when model's selected label equals `verdict`:
            $d1 = "Is this malicious?" model="jev" verdict="malicious" threshold=0.6

        Noul — match when model's probability >= threshold:
            $d2 = "Probability this is a clickfix attack" model="laya" noul=0.7

        Score — match when model's numeric score >= threshold:
            $d3 = "Rate severity 0–4" model="jev" score=3.0

        Optional per-rule text preprocessing (rare for decision models):
            $d4 = "..." model="jev" verdict="yes" cleaner="default_cleaning"
        """
        rules: List[DecisionRule] = []

        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

            # $id = "question text" key=value ...
            m = re.match(r'(\$\w+)\s*=\s*"([^"]+)"\s*(.*)', line)
            if not m:
                continue

            identifier, question, params_str = m.group(1), m.group(2), m.group(3).strip()
            params = self._parse_modifiers(params_str)

            model_name = params.get('model', '')
            if not model_name:
                continue  # model is required

            # Determine answer type from which param is present
            if 'verdict' in params:
                answer_type = 'choice'
                positive_label = str(params['verdict'])
                threshold = float(params.get('threshold', 0.5))
            elif 'noul' in params:
                answer_type = 'noul'
                positive_label = 'yes'
                threshold = float(params['noul'])
            elif 'score' in params:
                answer_type = 'score'
                positive_label = 'yes'
                threshold = float(params['score'])
            else:
                # Default: treat as choice with verdict="yes"
                answer_type = 'choice'
                positive_label = str(params.get('verdict', 'yes'))
                threshold = float(params.get('threshold', 0.5))

            rules.append(DecisionRule(
                identifier=identifier,
                question=question,
                model_name=str(model_name),
                answer_type=answer_type,
                positive_label=positive_label,
                threshold=threshold,
                cleaner_name=str(params.get('cleaner', 'no_op')),
                chunker_name=str(params.get('chunker', 'no_chunking')),
            ))

        return rules

    def _parse_fields_section(self, body: str) -> List[FieldRule]:
        """Parse fields section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_fields_content(sections.get('fields', ''))

    def _parse_meta_section(self, body: str) -> Dict[str, str]:
        """Parse meta section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_meta_content(sections.get('meta', ''))

    def _parse_strings_section(self, body: str) -> List[StringRule]:
        """Parse strings section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_strings_content(sections.get('strings', ''))

    def _parse_similarity_section(self, body: str) -> List[SimilarityRule]:
        """Parse similarity section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_similarity_content(sections.get('similarity', ''))

    def _parse_phash_section(self, body: str) -> List[PHashRule]:
        """Parse phash section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_phash_content(sections.get('phash', ''))

    def _parse_classifier_section(self, body: str) -> List[ClassifierRule]:
        """Parse classifier section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_classifier_content(sections.get('classifier', ''))

    def _parse_llm_section(self, body: str) -> List[LLMRule]:
        """Parse LLM section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return self._parse_llm_content(sections.get('llm', ''))

    def _parse_condition_section(self, body: str) -> str:
        """Parse condition section (backward compat wrapper)."""
        sections = self._split_sections(body)
        return sections.get('condition', '').strip()
