# SYara Library Structure

## Directory Tree

```
syara/
├── __init__.py                 # Main API exports
├── models.py                   # Data models (Rule, Match, etc.)
├── cache.py                    # Text cache for session optimization
├── config.py                   # Configuration manager
├── config.yaml                 # Default configuration
├── parser.py                   # .syara file parser
├── compiler.py                 # Rule compiler
├── compiled_rules.py           # Execution engine
│
├── engine/                     # Pattern matching components
│   ├── __init__.py
│   ├── cleaner.py             # Text cleaning (DefaultCleaner, etc.)
│   ├── chunker.py             # Text chunking strategies
│   ├── string_matcher.py      # String/regex matching
│   ├── semantic_matcher.py    # SBERT semantic matching
│   ├── classifier.py          # ML classification
│   └── llm_evaluator.py       # LLM-based evaluation
│
├── examples/                   # Usage examples
│   ├── basic_usage.py
│   ├── custom_matcher.py
│   └── sample_rules.syara
│
├── tests/                      # Unit tests
│   └── test_basic.py
│
├── pyproject.toml             # Package configuration
└── README.md                  # Documentation
```

## Component Overview

### Core Components (5 files)
1. **models.py** - Data structures for rules and matches
2. **cache.py** - Session-scoped text caching
3. **config.py** - Configuration management
4. **parser.py** - YARA-compatible rule parser
5. **compiler.py** - Rule compilation and validation

### Engine Components (7 files)
1. **cleaner.py** - Text preprocessing
2. **chunker.py** - Document chunking
3. **string_matcher.py** - Traditional YARA matching
4. **semantic_matcher.py** - Semantic similarity (SBERT)
5. **classifier.py** - ML classification
6. **llm_evaluator.py** - LLM evaluation (OpenAI, OSS)
7. **compiled_rules.py** - Execution engine

### Supporting Files
- **config.yaml** - Default configuration
- **pyproject.toml** - Package metadata and dependencies
- **README.md** - Comprehensive documentation
- **examples/** - Working code examples
- **tests/** - Unit tests

## Key Features Implemented

✅ YARA-compatible syntax parser
✅ String/regex pattern matching
✅ Semantic similarity matching (SBERT)
✅ ML classification rules
✅ LLM evaluation (OpenAI + OSS)
✅ Text cleaning and chunking
✅ Session-scoped caching
✅ Cost-optimized execution (strings → similarity → classifier → LLM)
✅ Extensibility (custom matchers, classifiers, LLMs)
✅ Configuration management
✅ Comprehensive documentation
✅ Working examples
✅ Unit tests

## Total Lines of Code

Approximately 2,400+ lines across:
- 15 Python modules
- 1 YAML config
- 1 TOML package config
- 3 example files
- 1 test file
- Comprehensive README

## Installation

```bash
cd syara
pip install -e .              # Development install
pip install -e ".[all]"       # With all dependencies
```

## Quick Test

```bash
cd examples
python basic_usage.py
```
