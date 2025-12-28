"""
SYara - Semantic YARA

A Python library for YARA-like rules with semantic matching capabilities.
Supports traditional string/regex patterns plus similarity matching,
classification, and LLM-based evaluation.

Example:
    >>> import syara
    >>> rules = syara.compile('rules.syara')
    >>> matches = rules.match("suspicious text here")
    >>> for match in matches:
    ...     if match.matched:
    ...         print(f"Rule {match.rule_name} matched!")
"""

__version__ = "0.1.0"
__author__ = "nabeelxy"

# Import main API
from syara.compiler import compile, SYaraCompiler
from syara.compiled_rules import CompiledRules
from syara.models import (
    Rule,
    Match,
    MatchDetail,
    StringRule,
    SimilarityRule,
    ClassifierRule,
    LLMRule,
)
from syara.config import ConfigManager, Config

# Import engine components for custom extensions
from syara import engine

__all__ = [
    # Main API
    'compile',
    'SYaraCompiler',
    'CompiledRules',
    # Models
    'Rule',
    'Match',
    'MatchDetail',
    'StringRule',
    'SimilarityRule',
    'ClassifierRule',
    'LLMRule',
    # Config
    'ConfigManager',
    'Config',
    # Engine module
    'engine',
    # Metadata
    '__version__',
    '__author__',
]
