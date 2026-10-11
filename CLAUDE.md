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

The public API entry points are `syara.compile(path)` and `syara.compile_string(content)` (in `syara/compiler.py`), which run parse + validate and return a `CompiledRules` object.

### Rule execution order (cost-optimized)

Inside `CompiledRules._execute_rule` (`compiled_rules.py`), patterns run cheapest-first. Both classifiers and LLMs are short-circuited via `_is_identifier_needed` — skipped when the condition result is already determined:

1. Field matching (`engine/field_matcher.py`) — Sigma-style key:value, same cost as strings
2. String/regex (`engine/string_matcher.py`)
3. Semantic similarity via SBERT (`engine/semantic_matcher.py`)
4. Perceptual hash — only when `match_file()` is called (`engine/phash_matcher.py`)
5. Classifier — skipped if condition already determined (`engine/classifier.py`)
6. LLM — skipped if condition already determined (`engine/llm_evaluator.py`)

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
| `fields:` | cheapest | `nocase`, regex `/pattern/i` |
| `strings:` | cheapest | `nocase`, regex `/pattern/i`, `wide` |
| `similarity:` | moderate | `threshold`, `matcher`, `cleaner`, `chunker` |
| `phash:` | moderate | `threshold`, `hasher` |
| `classifier:` | high | `threshold`, `classifier`, `cleaner`, `chunker` |
| `llm:` | highest | `llm`, `cleaner`, `chunker` |

The `condition:` block supports YARA boolean syntax: `$id and $id2`, `any of ($prefix*)`, `all of them`, `not $id`, etc.

Sections can appear in any order inside a rule body (order-independent parser).

### fields: section (Sigma-style)

```
fields:
    $evt  = EventID = "4625"
    $proc = process.name = "mimikatz.exe" nocase
    $port = dest.port = /^(445|4444)$/
```

Pass a `fields` dict to `match()`:

```python
rules.match(text, fields={"EventID": "4625", "process.name": "cmd.exe"})
rules.match_any(text, fields=event)
rules.matched(text, fields=event)
```

If a field name is absent from the dict, that identifier evaluates to False.

### Condition evaluation (`_BoolEval`)

`compiled_rules.py` uses a recursive-descent parser (`_BoolEval`) to evaluate translated boolean expressions — no `eval()` is used. After `_translate_yara_condition` replaces all `$id` tokens with `True`/`False`, `_BoolEval` handles `and`, `or`, `not`, and parentheses.

### Session cache (`syara/cache.py`)

`TextCache` (SHA-256 keyed) is created per `match()` call and cleared in a `finally` block. Cleaned text is cached so multiple patterns with the same cleaner don't re-clean.

`SBERTMatcher` maintains a persistent `_embedding_cache` (dict keyed by text) across all `match()` calls. Pattern strings (which never change after compile) are encoded only once, ever.

## Key files

| File | Purpose |
|------|---------|
| `syara/compiler.py` | `compile()` and `compile_string()` public entry points, validation |
| `syara/compiled_rules.py` | `CompiledRules` — execution engine, `match_any()`, `matched()` |
| `syara/parser.py` | `.syara` DSL parser (order-independent sections, escaped regex slashes) |
| `syara/models.py` | Dataclasses: `Rule`, `*Rule`, `FieldRule`, `Match`, `MatchDetail` |
| `syara/config.py` | `ConfigManager` — component registry + lazy init |
| `syara/engine/field_matcher.py` | `FieldMatcher` — literal/regex matching against event fields |
| `syara/engine/` | Pluggable cleaners, chunkers, matchers, classifiers, LLMs |
| `syara/config.yaml` | Default component registry (shipped with package) |
| `tests/test_basic.py` | Unit tests for models, cleaners, chunkers, cache, parser |
| `tests/test_library.py` | Extended library tests |
| `tests/test_improvements.py` | Tests for all 12 improvements |
| `tests/test_fields.py` | Tests for fields: section |
| `examples/sample_rules.syara` | Canonical example rules |
| `examples/field_matching.py` | Fields / Sigma-style matching example |

## Optional dependencies

Core deps are only `numpy` and `pyyaml`. All ML components are behind optional extras:

- `sbert` — similarity matching (sentence-transformers + torch)
- `classifier` — adds scikit-learn, transformers
- `llm` — adds openai, transformers
- `all` — everything above
- `dev` — pytest, black, flake8, mypy

## Known issues

- **transformers 5.x breaks DeBERTa-v3-small**: tiktoken misidentifies the SentencePiece `.spm.model` file. Pin `transformers<5.0`.
- **`condition:` not `conditions:`**: Parser looks for exact keyword — trailing `s` silently drops the condition block.
- **`//` in regex patterns stripped**: The comment-removal pass (`//` to end-of-line) runs before the regex body parser. Use `\/` (escaped slash) inside regex patterns to avoid this; the parser unescapes `\/` to `/` after capture.
