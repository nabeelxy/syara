# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Activate the venv before running anything
source venv/bin/activate

# Run all tests
pytest

# Run a single test
pytest tests/test_basic.py::TestModels::test_string_rule_creation -v

# Run tests without coverage
pytest --no-cov

# Install with all optional deps (for development)
pip install -e ".[all,dev]"
```

> **Important**: Always use `source venv/bin/activate && python` — the system Python lacks the optional deps (torch, sentence-transformers, etc.). Installing `sentence-transformers` can silently upgrade `transformers` past 5.0, which breaks DeBERTa-v3-small. Re-pin `transformers<5.0` after.

## Architecture

### Pipeline

```
.syara rule file → SYaraParser → [Rule] → SYaraCompiler → CompiledRules → .match(text)
```

The public API entry point is `syara.compile(path)` (in `syara/compiler.py`), which runs parse + validate and returns a `CompiledRules` object. `CompiledRules.match(text)` and `CompiledRules.match_file(path)` are the two execution methods.

### Rule execution order (cost-optimized)

Inside `CompiledRules._execute_rule` (`compiled_rules.py`), patterns are evaluated cheapest-first with short-circuit for LLM calls:

1. String/regex (`engine/string_matcher.py`)
2. Semantic similarity via SBERT (`engine/semantic_matcher.py`)
3. Perceptual hash on binary files — only when `match_file()` is called (`engine/phash_matcher.py`)
4. Classifier (`engine/classifier.py`)
5. LLM — only called when it can still change the condition outcome (`engine/llm_evaluator.py`)

All identifiers are pre-initialised with `[]` in `pattern_matches` before any matcher runs, so `all of them` / `all of ($prefix*)` correctly treats un-matched patterns as False.

### Component registry (`syara/config.py`)

`ConfigManager` is the dependency-injection layer. It lazy-instantiates and caches engine components by name (e.g. `"sbert"`, `"tuned-sbert"`, `"gemini"`). Components can be registered as either a dotted class path string or a live instance — all `get_*` methods check `isinstance(v, str)` before calling `_instantiate_class`.

To add a new component type (e.g. a custom classifier), register it before compiling rules:

```python
config_manager = syara.ConfigManager()
config_manager.register_classifier("my-cls", "mypackage.MyClassifier")
rules = syara.SYaraCompiler(config_manager).compile("rules.syara")
```

### `.syara` DSL sections

| Section | Cost tier | Key params |
|---------|-----------|-----------|
| `strings:` | cheapest | `nocase`, regex `/pattern/i` |
| `similarity:` | moderate | `threshold`, `matcher`, `cleaner`, `chunker` |
| `phash:` | moderate | `threshold`, `hasher` |
| `classifier:` | high | `threshold`, `classifier`, `cleaner`, `chunker` |
| `llm:` | highest | `llm`, `cleaner`, `chunker` |

The `condition:` block supports YARA boolean syntax: `$id and $id2`, `any of ($prefix*)`, `all of them`, `not $id`, etc. Note the exact keyword is `condition:` — a trailing `s` silently drops the block.

### Known parser limitation

`_split_rules` in `parser.py` uses a regex (`[^}]*`) that consumes `{` from quantifiers, so `{n,m}` in string patterns truncates rule body parsing. Workaround: avoid `{n,m}` quantifiers in `.syara` regex patterns. This is tracked as an XFAIL test.

### Session cache (`syara/cache.py`)

`TextCache` (SHA-256 keyed) is created per `match()` call and cleared in a `finally` block. Cleaned text is cached so multiple patterns with the same cleaner don't re-clean.

## Key files

| File | Purpose |
|------|---------|
| `syara/compiler.py` | `compile()` public entry point, validation |
| `syara/compiled_rules.py` | `CompiledRules` — execution engine |
| `syara/parser.py` | `.syara` DSL parser |
| `syara/models.py` | Dataclasses: `Rule`, `*Rule`, `Match`, `MatchDetail` |
| `syara/config.py` | `ConfigManager` — component registry + lazy init |
| `syara/engine/` | Pluggable cleaners, chunkers, matchers, classifiers, LLMs |
| `syara/config.yaml` | Default component registry (shipped with package) |
| `tests/test_basic.py` | Unit tests for models, cleaners, chunkers, cache, parser |
| `examples/` | Working runnable examples; `sample_rules.syara` is canonical |

## Optional dependencies

Core deps are only `numpy` and `pyyaml`. All ML components are behind optional extras:

- `sbert` — similarity matching (sentence-transformers + torch)
- `classifier` — adds scikit-learn, transformers
- `llm` — adds openai, transformers
- `all` — everything above
- `dev` — pytest, black, flake8, mypy

## Recent Improvements

1. **SBERTMatcher embedding cache** (`engine/semantic_matcher.py`): Added `_embedding_cache: Dict[str, np.ndarray]` per instance. `embed()` returns cached result on repeated calls; `get_similarity_batch()` only batch-encodes uncached texts.

2. **classify() return contract** (`engine/classifier.py`): `TunedSBERTClassifier.classify` and `DistilBERTClassifier.classify` now correctly return `(confidence >= 0.5, confidence)` instead of always returning `True` as first element.

3. **Word-boundary _parse_response** (`engine/llm_evaluator.py`): Both `OpenAIEvaluator` and `OSSLLMEvaluator` use `re.match(r'YES\b', ...)` / `re.match(r'NO\b', ...)` so strings like "YESTERDAY" or "NOPE" don't false-trigger.

4. **LLM confidence scores** (`engine/llm_evaluator.py`): `evaluate()` now returns a 3-tuple `(is_match, explanation, confidence)`. OpenAI uses logprobs; OSS uses token probability of YES/NO output token. `evaluate_chunks()` updated to unpack 3-tuple and store confidence as `score`.

5. **Order-independent parser sections** (`parser.py`): Replaced regex-based section extraction with `_split_sections()` that finds all section headers via `_SECTION_RE` and slices content between them. Sections can now appear in any order in `.syara` files.

6. **Escaped slashes in regex patterns** (`parser.py`): `_parse_strings_content` regex changed from `/([^/]*)/(i?)` to `/((?:[^/\\]|\\.)+)/([is]*)` — handles `\/` inside patterns and supports multiple inline flags (e.g., `/pattern/is`).

7. **compile_string() public API** (`compiler.py`, `__init__.py`): Module-level `compile_string(rule_content, ...)` function added alongside existing `compile(filepath, ...)`. Exported in `__all__`.

8. **_BoolEval replaces eval()** (`compiled_rules.py`): Added `_BoolEval` recursive-descent parser that evaluates `True/False/and/or/not/(...)` expressions without `eval()`. Used in `_evaluate_condition` and `_is_identifier_needed`.

9. **Classifier short-circuit** (`compiled_rules.py`): Step 4 of `_execute_rule` now calls `_is_identifier_needed` before running classifier, skipping it when the condition outcome cannot change (mirrors existing LLM short-circuit).

10. **match_any() and matched() helpers** (`compiled_rules.py`): `match_any(text)` returns only matched rules; `matched(text)` returns a bool. Both are convenience wrappers over `match()`.

11. **CalibratedSBERTClassifier alias** (`engine/classifier.py`, `engine/__init__.py`): `CalibratedSBERTClassifier = TunedSBERTClassifier` alias added for clearer naming and backward compat. Exported from `syara.engine`.

12. **fields: section** (`models.py`, `parser.py`, `compiled_rules.py`, `compiler.py`, `engine/field_matcher.py`): New DSL section for Sigma-style key:value field matching. Format: `$id = field_name = "value" [nocase]` or `$id = field_name = /regex/`. `match(text, fields={"EventID": "4624"})` passes field dict to execution engine. `FieldMatcher` uses exact equality for literals and `re.search` for regexes.
