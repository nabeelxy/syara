# Changelog

All notable changes to SYARA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.2]: https://github.com/nabeelxy/syara/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/nabeelxy/syara/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/nabeelxy/syara/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/nabeelxy/syara/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nabeelxy/syara/releases/tag/v0.1.0
