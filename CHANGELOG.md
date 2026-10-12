# Changelog

All notable changes to SYARA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-10-11

### Added
- **`fields:` section (Sigma-style key:value matching)** — match against structured event data (logs, alerts, API payloads) with `$id = field.name = "literal"` or `$id = field.name = /regex/`. New `FieldRule` model and `FieldMatcher` engine component. Pass event data via `match(text, fields={...})`; absent fields evaluate to `False`.
- **`decision:` section (structured model evaluation)** — pluggable decision models (JEV, Laya, Winnow-E4B) returning typed `choice`/`noul`/`score` answers. New `DecisionRule` model, `DecisionEvaluator` ABC, `DecisionResult`, and `build_question_spec()` helper. Register via `ConfigManager.register_decision_evaluator()`. Identifiers sharing a model are batched into one call; the whole block is short-circuited when it cannot change the condition outcome.
- **`syara.compile_string()`** — module-level public API for compiling rules directly from a string (previously only on `SYaraCompiler`).
- **`CompiledRules.match_any()` and `.matched()`** — convenience helpers returning only matched rules, or a single boolean.
- **Per-instance SBERT embedding cache** — `SBERTMatcher` caches embeddings across `match()` calls; pattern strings are encoded only once. `get_similarity_batch()` batch-encodes only uncached chunks.
- **Calibrated LLM confidence scores** — `LLMEvaluator.evaluate()` now returns a 3-tuple `(is_match, explanation, confidence)`; OpenAI uses token logprobs, OSS models use YES/NO softmax. `MatchDetail.score` reflects the confidence.
- **`CalibratedSBERTClassifier`** — descriptive alias for `TunedSBERTClassifier`, exported from `syara.engine`.
- **Order-independent rule sections** — sections (`meta`, `strings`, `similarity`, `fields`, `decision`, etc.) may now appear in any order within a rule body.
- **2-hour CTF workshop** (`workshop/`) — five Google Colab notebooks with 8 flags covering the full library, built for [un]prompted.
- **New example scripts** — `examples/field_matching.py` and `examples/decision_model.py`.
- **Test suites** — `tests/test_improvements.py`, `tests/test_fields.py`, `tests/test_decision.py`; 287 tests total.

### Fixed
- **`eval()` removed from condition evaluation** — replaced with a `_BoolEval` recursive-descent parser for safe boolean evaluation of translated conditions.
- **`_parse_response` false positives** — LLM YES/NO parsing now uses word-boundary matching so words like "NOBODY" or "KNOWLEDGE" no longer trigger the NO branch.
- **`classify()` return contract** — `TunedSBERTClassifier`/`DistilBERTClassifier` now return `(confidence >= 0.5, confidence)` instead of always `True`.
- **Escaped slashes in regex patterns** — `/https?:\/\//` style patterns parse correctly; inline multi-flag support (`/pattern/is`).
- **Classifier short-circuit** — classifier rules are now skipped (like LLM rules) when they cannot change the condition outcome.
- **`_evaluate_remote()` return arity** — remote LLM endpoint path now returns a proper 3-tuple, consistent with the `evaluate()` contract.
- **Docs/code consistency** — corrected README test count, converted regex-bearing `compile_string` examples to raw strings (`r'''...'''`), and aligned `evaluate()` type annotations with the 3-tuple return.

### Backward Compatibility
- ✅ All existing rules and APIs continue to work — `fields:` and `decision:` are additive sections, and `match()`/`match_any()`/`matched()` accept an optional `fields=` argument.
- ✅ `evaluate_chunks()` accepts both legacy 2-tuple and new 3-tuple `evaluate()` returns.

## [0.2.4] - 2026-03-04

### Added
- **`wide` modifier fully implemented** — literal strings are searched in their UTF-16LE (null-byte-interleaved) form; regex patterns are matched against null-stripped text (best-effort). Combine with `ascii` to match both encodings simultaneously.
- **`cleaner` and `chunker` parameters for LLM rules** — LLM rules now support the same `cleaner="<name>"` and `chunker="<name>"` parameters as similarity and classifier rules (defaults: `no_op` and `no_chunking` to preserve prior behaviour).
- **`distilbert` classifier registered** — `DistilBERTClassifier` is now available as `classifier="distilbert"` in both `config.yaml` and the programmatic default config.
- **`AudioHashMatcher.compute_hash()` implemented** — uses the stdlib `wave` module to fingerprint PCM WAV files with a dHash-style 64-bit hash (no extra dependencies).
- **`VideoHashMatcher.compute_hash()` implemented** — produces a deterministic 64-bit content fingerprint by sampling raw bytes at evenly-spaced offsets (no extra dependencies).
- **`TunedSBERTClassifier.train()` implemented** — calibrates `threshold_boost` from labeled `(rule_text, input_text, is_match)` examples by finding the optimal similarity cutpoint and mapping it to a 0.5 reference threshold.
- **`examples/syara_components.py`** — new file collecting example-specific components (`HTMLTextCleaner`, `BERTPhishingClassifier`, `DeBERTaClickFixClassifier`, `GeminiLLMEvaluator`) with a `get_example_config_manager()` helper, keeping the core library dependency-free.
- **187 library tests** in `tests/test_library.py` covering all previously untested code paths.

### Fixed
- **Regex quantifiers `{n,m}` in rule bodies** — `_split_rules` in the parser was replaced with a brace-counting algorithm that correctly handles `{n,m}` quantifiers inside regex patterns, quoted strings, and triple-quoted LLM prompts.
- **`all of them` / `all of ($prefix*)` condition** — previously evaluated only identifiers that had matches, silently treating missing identifiers as vacuously true. Now all pattern identifiers are pre-seeded with empty lists before matching, so `all of them` correctly returns `False` when any pattern produced no matches.
- **Pre-instantiated objects in `get_cleaner()`, `get_chunker()`, `get_phash_matcher()`** — these three methods were missing the `isinstance(v, str)` guard that `get_matcher()`, `get_classifier()`, and `get_llm()` already had. Registering a live object instance now works correctly for all component types.
- **Condition evaluation failure** — replaced `print()` with `warnings.warn(UserWarning)` so failed condition evaluations surface through Python's standard warning mechanism instead of printing to stdout.

### Changed
- Example-specific classes (`BERTPhishingClassifier`, `DeBERTaClickFixClassifier`, `GeminiLLMEvaluator`, `HTMLTextCleaner`) moved from the core library (`syara/engine/`) to `examples/syara_components.py`. Their names are no longer registered in `syara/config.yaml` or `syara/config.py`. Use `get_example_config_manager()` in example scripts.

### Backward Compatibility
- ✅ All existing rules continue to work — new LLM `cleaner`/`chunker` parameters default to `no_op`/`no_chunking` (same as prior behaviour).
- ✅ `wide` modifier was previously a no-op; rules using it will now actively match the wide form.
- ⚠️ Rules referencing `html-text`, `sbert-finetuned-phishing`, `deberta-clickfix`, or `gemini` from the default config must now pass a `config_manager` from `get_example_config_manager()`.

## [0.2.3] - 2026-01-05

### Changed
- **Default LLM name changed from `gpt-oss20b` to `flan-t5-large`** for better clarity and consistency
- Updated all documentation, examples, and demo files to use `flan-t5-large` as the default LLM name
- `gpt-oss20b` maintained as a legacy alias for backward compatibility

### Updated Files
- Core library: `config.yaml`, `config.py`, `models.py`, `parser.py`
- Examples: `ollama_llm.py`, `sample_rules.syara`, `prompt_injection_demo.ipynb`
- Documentation: `README_OLLAMA.md`, `DEBUG_LLM_OUTPUT.md`, `OLLAMA_INTEGRATION.md`
- Main docs: `README.md`, `CHANGELOG_KEYVALUE_PARAMS.md`, `MIGRATION_GUIDE.md`

### Backward Compatibility
- ✅ **100% backward compatible** - existing rules using `llm="gpt-oss20b"` continue to work
- Legacy alias `gpt-oss20b` maps to the same `OSSLLMEvaluator` as `flan-t5-large`

## [0.2.2] - 2026-01-05

### Added
- **Ollama LLM Evaluator** - Local, private, and cost-free LLM evaluation via Ollama
- `examples/ollama_llm.py` - OllamaLLMEvaluator class extending LLMEvaluator base class
- `examples/README_OLLAMA.md` - Comprehensive guide for using Ollama with SYARA
- `examples/OLLAMA_INTEGRATION.md` - Technical documentation and architecture details
- New section in `prompt_injection_demo.ipynb` demonstrating Ollama integration
- Support for local LLM inference with 100% privacy and zero API costs

### Changed
- Default LLM changed from `gpt-oss20b` to `flan-t5-large` for clarity
- Ollama now recommended as default for `flan-t5-large` instead of cloud FLAN-T5
- Examples updated to show Ollama as primary local LLM option

### Documentation
- Added detailed Ollama setup instructions
- Model comparison table (llama3.2, mistral, phi3, etc.)
- Performance benchmarks and cost analysis
- Hybrid approach recommendations (Ollama + GPT-4)

## [0.2.1] - 2026-01-05

### Added
- Support for passing pre-configured `ConfigManager` instances to `syara.compile()`
- Support for registering pre-instantiated classifier/matcher/LLM objects in `ConfigManager`
- New `config_manager` parameter in `compile()` function and `SYaraCompiler.__init__()`
- Comprehensive documentation in `CLASSIFIER_REGISTRATION_FIX.md`

### Changed
- `ConfigManager.get_classifier()` now accepts both class path strings and instances
- `ConfigManager.get_matcher()` now accepts both class path strings and instances
- `ConfigManager.get_llm()` now accepts both class path strings and instances
- Updated `prompt_injection_demo.ipynb` to use new config_manager parameter

### Fixed
- Fixed classifier registration issue in notebooks where custom classifiers weren't recognized
- Resolved `ValueError: Unknown classifier` error when using runtime-registered classifiers

## [0.2.0] - 2026-01-05

### Added
- **YARA-like key-value parameters** for all rule types (similarity, classifier, phash, llm)
- Support for order-independent parameter specification
- Boolean modifiers support (like `nocase`, `wide` from YARA)
- Comprehensive parameter defaults for cleaner rule syntax
- New test cases for key-value parameter parsing
- Migration guide ([MIGRATION_GUIDE.md](MIGRATION_GUIDE.md))

### Changed
- **BREAKING**: Removed legacy positional parameter support
  - Old: `$s = "pattern" 0.8 default_cleaning no_chunking sbert`
  - New: `$s = "pattern" threshold=0.8 matcher="sbert"`
- Simplified parser logic for easier maintenance
- Improved parser error messages
- Updated all examples to use key-value syntax
- Updated documentation with new syntax

### Fixed
- Parser now correctly handles quoted values in parameters
- Fixed issue where classifier parameters were incorrectly parsed as cleaner names
- Improved regex pattern for parameter extraction

### Improved
- Parser coverage increased from 49% to 84%
- Code is now simpler and easier to maintain
- Better alignment with YARA's design philosophy

## [0.1.1] - 2025-12-30

### Added
- Initial DeBERTa classifier example
- Prompt injection detection demo notebook

### Fixed
- Minor bug fixes in semantic matcher

## [0.1.0] - 2025-12-28

### Added
- Initial release of SYARA
- String matching (traditional YARA-compatible)
- Semantic similarity matching using SBERT
- Classifier support with fine-tuned models
- LLM evaluation support
- Perceptual hashing for images
- Text cleaning and chunking utilities
- Configuration system
- Basic test suite

[0.2.5]: https://github.com/nabeelxy/syara/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/nabeelxy/syara/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/nabeelxy/syara/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/nabeelxy/syara/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/nabeelxy/syara/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nabeelxy/syara/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/nabeelxy/syara/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nabeelxy/syara/releases/tag/v0.1.0
