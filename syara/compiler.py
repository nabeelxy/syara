"""
Compiler for SYara rules.
"""
from typing import List, Optional
from syara.parser import SYaraParser
from syara.models import Rule
from syara.config import ConfigManager
from syara.compiled_rules import CompiledRules


class SYaraCompiler:
    """
    Compiler for .syara rule files.
    Compiles rules into an executable format.
    """

    def __init__(self, config_path: Optional[str] = None, config_manager: Optional[ConfigManager] = None):
        """
        Initialize compiler.

        Args:
            config_path: Path to configuration YAML file
            config_manager: Pre-configured ConfigManager instance (overrides config_path if provided)
        """
        self.parser = SYaraParser()
        if config_manager is not None:
            self.config_manager = config_manager
        else:
            self.config_manager = ConfigManager(config_path)

    def compile(self, filepath: str) -> CompiledRules:
        """
        Compile a .syara rule file.

        Args:
            filepath: Path to .syara file

        Returns:
            CompiledRules object ready for matching

        Raises:
            FileNotFoundError: If rule file doesn't exist
            ValueError: If rules are invalid
        """
        # Parse rules from file
        rules = self.parser.parse_file(filepath)

        # Validate rules
        self._validate_rules(rules)

        # Create compiled rules object
        compiled = CompiledRules(rules, self.config_manager)

        return compiled

    def compile_string(self, rule_content: str) -> CompiledRules:
        """
        Compile rules from a string.

        Args:
            rule_content: Rule content as string

        Returns:
            CompiledRules object
        """
        rules = self.parser.parse_string(rule_content)
        self._validate_rules(rules)

        compiled = CompiledRules(rules, self.config_manager)
        return compiled

    def _validate_rules(self, rules: List[Rule]) -> None:
        """
        Validate parsed rules.

        Args:
            rules: List of Rule objects

        Raises:
            ValueError: If any rule is invalid
        """
        if not rules:
            raise ValueError("No rules found in file")

        # Check for duplicate rule names
        rule_names = [r.name for r in rules]
        duplicates = [name for name in rule_names if rule_names.count(name) > 1]

        if duplicates:
            raise ValueError(f"Duplicate rule names: {set(duplicates)}")

        # Validate each rule
        for rule in rules:
            self._validate_rule(rule)

    def _validate_rule(self, rule: Rule) -> None:
        """
        Validate a single rule.

        Args:
            rule: Rule to validate

        Raises:
            ValueError: If rule is invalid
        """
        # Rule must have at least one pattern
        total_patterns = (
            len(rule.strings) +
            len(rule.similarity) +
            len(rule.phash) +
            len(rule.classifier) +
            len(rule.llm)
        )

        if total_patterns == 0:
            raise ValueError(f"Rule '{rule.name}' has no patterns")

        # Rule must have a condition
        if not rule.condition:
            raise ValueError(f"Rule '{rule.name}' has no condition")

        # Validate that all identifiers in condition exist in patterns
        self._validate_condition_identifiers(rule)

        # Validate cleaner/chunker/matcher/classifier/llm names
        self._validate_component_names(rule)

    def _validate_condition_identifiers(self, rule: Rule) -> None:
        """Validate that condition references valid pattern identifiers."""
        # Collect all pattern identifiers
        identifiers = set()

        for s in rule.strings:
            identifiers.add(s.identifier)
        for s in rule.similarity:
            identifiers.add(s.identifier)
        for p in rule.phash:
            identifiers.add(p.identifier)
        for s in rule.classifier:
            identifiers.add(s.identifier)
        for s in rule.llm:
            identifiers.add(s.identifier)

        # Extract identifiers from condition (simple approach)
        # This matches $identifier patterns
        import re
        condition_identifiers = set(re.findall(r'\$\w+', rule.condition))

        # Check if all condition identifiers exist
        # Handle wildcards like $dan* by checking if any identifier starts with the prefix
        undefined = set()
        for cond_id in condition_identifiers:
            # Check if it's an exact match
            if cond_id in identifiers:
                continue

            # Check if it's a wildcard pattern (e.g., $dan used with "any of ($dan*)")
            # In YARA, you can use $var* to match all variables starting with $var
            is_wildcard_match = False
            for actual_id in identifiers:
                if actual_id.startswith(cond_id):
                    is_wildcard_match = True
                    break

            if not is_wildcard_match:
                undefined.add(cond_id)

        if undefined:
            raise ValueError(
                f"Rule '{rule.name}' condition references undefined identifiers: {undefined}"
            )

    def _validate_component_names(self, rule: Rule) -> None:
        """Validate cleaner/chunker/matcher/classifier/LLM names exist in config."""
        # Validate similarity rules
        for sim in rule.similarity:
            try:
                self.config_manager.get_cleaner(sim.cleaner_name)
                self.config_manager.get_chunker(sim.chunker_name)
                self.config_manager.get_matcher(sim.matcher_name)
            except ValueError as e:
                raise ValueError(f"Rule '{rule.name}', pattern '{sim.identifier}': {e}")

        # Validate phash rules
        for phash in rule.phash:
            try:
                self.config_manager.get_phash_matcher(phash.phash_name)
            except ValueError as e:
                raise ValueError(f"Rule '{rule.name}', pattern '{phash.identifier}': {e}")

        # Validate classifier rules
        for cls in rule.classifier:
            try:
                self.config_manager.get_cleaner(cls.cleaner_name)
                self.config_manager.get_chunker(cls.chunker_name)
                self.config_manager.get_classifier(cls.classifier_name)
            except ValueError as e:
                raise ValueError(f"Rule '{rule.name}', pattern '{cls.identifier}': {e}")

        # Validate LLM rules
        for llm in rule.llm:
            try:
                self.config_manager.get_llm(llm.llm_name)
            except ValueError as e:
                raise ValueError(f"Rule '{rule.name}', pattern '{llm.identifier}': {e}")


# Convenience function for direct compilation
def compile(filepath: str, config_path: Optional[str] = None, config_manager: Optional[ConfigManager] = None) -> CompiledRules:
    """
    Compile a .syara rule file.

    Args:
        filepath: Path to .syara file
        config_path: Optional path to configuration file
        config_manager: Optional pre-configured ConfigManager instance (overrides config_path if provided)

    Returns:
        CompiledRules object

    Example:
        >>> import syara
        >>> rules = syara.compile('rules.syara')
        >>> matches = rules.match("some text to check")

        # Or with a custom config manager
        >>> config = syara.ConfigManager()
        >>> config.config.classifiers['my-classifier'] = my_classifier_instance
        >>> rules = syara.compile('rules.syara', config_manager=config)
    """
    compiler = SYaraCompiler(config_path, config_manager)
    return compiler.compile(filepath)
