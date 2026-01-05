"""
Configuration management for SYara.
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Type
import importlib
import os
import yaml


@dataclass
class Config:
    """Configuration data class."""
    default_cleaner: str = "default_cleaning"
    default_chunker: str = "no_chunking"
    default_matcher: str = "sbert"
    default_phash: str = "imagehash"
    default_classifier: str = "tuned-sbert"
    default_llm: str = "flan-t5-large"
    cleaners: Dict[str, str] = field(default_factory=dict)
    chunkers: Dict[str, str] = field(default_factory=dict)
    matchers: Dict[str, str] = field(default_factory=dict)
    phash_matchers: Dict[str, str] = field(default_factory=dict)
    classifiers: Dict[str, str] = field(default_factory=dict)
    llms: Dict[str, str] = field(default_factory=dict)
    api_keys: Dict[str, str] = field(default_factory=dict)
    llm_configs: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class ConfigManager:
    """Manages configuration loading and component instantiation."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to YAML config file. If None, uses default config.
        """
        self.config = self._load_config(config_path)
        self._cleaner_cache: Dict[str, Any] = {}
        self._chunker_cache: Dict[str, Any] = {}
        self._matcher_cache: Dict[str, Any] = {}
        self._phash_cache: Dict[str, Any] = {}
        self._classifier_cache: Dict[str, Any] = {}
        self._llm_cache: Dict[str, Any] = {}

    def _load_config(self, config_path: Optional[str]) -> Config:
        """Load configuration from YAML file."""
        if config_path is None:
            # Use default config from package
            config_path = Path(__file__).parent / "config.yaml"

        if not Path(config_path).exists():
            # Return default config if file doesn't exist
            return self._get_default_config()

        with open(config_path, 'r') as f:
            data = yaml.safe_load(f) or {}

        # Expand environment variables in API keys
        api_keys = data.get('api_keys', {})
        for key, value in api_keys.items():
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                api_keys[key] = os.getenv(env_var, '')

        return Config(
            default_cleaner=data.get('default_cleaner', 'default_cleaning'),
            default_chunker=data.get('default_chunker', 'no_chunking'),
            default_matcher=data.get('default_matcher', 'sbert'),
            default_phash=data.get('default_phash', 'imagehash'),
            default_classifier=data.get('default_classifier', 'tuned-sbert'),
            default_llm=data.get('default_llm', 'flan-t5-large'),
            cleaners=data.get('cleaners', {}),
            chunkers=data.get('chunkers', {}),
            matchers=data.get('matchers', {}),
            phash_matchers=data.get('phash_matchers', {}),
            classifiers=data.get('classifiers', {}),
            llms=data.get('llms', {}),
            api_keys=api_keys,
            llm_configs=data.get('llm_configs', {}),
        )

    def _get_default_config(self) -> Config:
        """Get default configuration when no config file is provided."""
        return Config(
            cleaners={
                'default_cleaning': 'syara.engine.cleaner.DefaultCleaner',
                'no_op': 'syara.engine.cleaner.NoOpCleaner',
                'aggressive': 'syara.engine.cleaner.AggressiveCleaner',
            },
            chunkers={
                'no_chunking': 'syara.engine.chunker.NoChunker',
                'text_chunking': 'syara.engine.chunker.SentenceChunker',
                'sentence_chunking': 'syara.engine.chunker.SentenceChunker',
                'fixed_size': 'syara.engine.chunker.FixedSizeChunker',
                'paragraph': 'syara.engine.chunker.ParagraphChunker',
                'word': 'syara.engine.chunker.WordChunker',
            },
            matchers={
                'sbert': 'syara.engine.semantic_matcher.SBERTMatcher',
            },
            phash_matchers={
                'imagehash': 'syara.engine.phash_matcher.ImageHashMatcher',
                'audiohash': 'syara.engine.phash_matcher.AudioHashMatcher',
                'videohash': 'syara.engine.phash_matcher.VideoHashMatcher',
            },
            classifiers={
                'tuned-sbert': 'syara.engine.classifier.TunedSBERTClassifier',
            },
            llms={
                'flan-t5-large': 'syara.engine.llm_evaluator.OSSLLMEvaluator',
                'gpt-oss20b': 'syara.engine.llm_evaluator.OSSLLMEvaluator',  # Legacy alias
                'gpt-4': 'syara.engine.llm_evaluator.OpenAIEvaluator',
                'openai': 'syara.engine.llm_evaluator.OpenAIEvaluator',
            },
        )

    def _instantiate_class(self, class_path: str, *args, **kwargs) -> Any:
        """
        Dynamically instantiate a class from a module path.

        Args:
            class_path: Full module path to class (e.g., 'syara.engine.cleaner.DefaultCleaner')
            *args: Positional arguments for class constructor
            **kwargs: Keyword arguments for class constructor

        Returns:
            Instance of the class
        """
        module_path, class_name = class_path.rsplit('.', 1)
        module = importlib.import_module(module_path)
        cls = getattr(module, class_name)
        return cls(*args, **kwargs)

    def get_cleaner(self, name: Optional[str] = None):
        """Get a text cleaner instance by name."""
        if name is None:
            name = self.config.default_cleaner

        if name in self._cleaner_cache:
            return self._cleaner_cache[name]

        class_path = self.config.cleaners.get(name)
        if class_path is None:
            raise ValueError(f"Unknown cleaner: {name}")

        instance = self._instantiate_class(class_path)
        self._cleaner_cache[name] = instance
        return instance

    def get_chunker(self, name: Optional[str] = None, **kwargs):
        """Get a chunker instance by name."""
        if name is None:
            name = self.config.default_chunker

        # For chunkers with parameters, don't cache
        if kwargs:
            class_path = self.config.chunkers.get(name)
            if class_path is None:
                raise ValueError(f"Unknown chunker: {name}")
            return self._instantiate_class(class_path, **kwargs)

        if name in self._chunker_cache:
            return self._chunker_cache[name]

        class_path = self.config.chunkers.get(name)
        if class_path is None:
            raise ValueError(f"Unknown chunker: {name}")

        instance = self._instantiate_class(class_path)
        self._chunker_cache[name] = instance
        return instance

    def get_matcher(self, name: Optional[str] = None):
        """Get a semantic matcher instance by name."""
        if name is None:
            name = self.config.default_matcher

        if name in self._matcher_cache:
            return self._matcher_cache[name]

        class_path_or_instance = self.config.matchers.get(name)
        if class_path_or_instance is None:
            raise ValueError(f"Unknown matcher: {name}")

        # Support both class paths (strings) and pre-instantiated objects
        if isinstance(class_path_or_instance, str):
            instance = self._instantiate_class(class_path_or_instance)
        else:
            instance = class_path_or_instance

        self._matcher_cache[name] = instance
        return instance

    def get_phash_matcher(self, name: Optional[str] = None):
        """Get a phash matcher instance by name."""
        if name is None:
            name = self.config.default_phash

        if name in self._phash_cache:
            return self._phash_cache[name]

        class_path = self.config.phash_matchers.get(name)
        if class_path is None:
            raise ValueError(f"Unknown phash matcher: {name}")

        instance = self._instantiate_class(class_path)
        self._phash_cache[name] = instance
        return instance

    def get_classifier(self, name: Optional[str] = None):
        """Get a classifier instance by name."""
        if name is None:
            name = self.config.default_classifier

        if name in self._classifier_cache:
            return self._classifier_cache[name]

        class_path_or_instance = self.config.classifiers.get(name)
        if class_path_or_instance is None:
            raise ValueError(f"Unknown classifier: {name}")

        # Support both class paths (strings) and pre-instantiated objects
        if isinstance(class_path_or_instance, str):
            instance = self._instantiate_class(class_path_or_instance)
        else:
            # Already an instance
            instance = class_path_or_instance

        self._classifier_cache[name] = instance
        return instance

    def get_llm(self, name: Optional[str] = None):
        """Get an LLM evaluator instance by name."""
        if name is None:
            name = self.config.default_llm

        if name in self._llm_cache:
            return self._llm_cache[name]

        class_path_or_instance = self.config.llms.get(name)
        if class_path_or_instance is None:
            raise ValueError(f"Unknown LLM: {name}")

        # Support both class paths (strings) and pre-instantiated objects
        if isinstance(class_path_or_instance, str):
            # Get LLM-specific config
            llm_config = self.config.llm_configs.get(name, {})

            # Get API key if specified
            api_key = self.config.api_keys.get('openai', '') if 'openai' in class_path_or_instance.lower() else None

            # Instantiate with config
            kwargs = {}
            if 'model' in llm_config:
                kwargs['model_name'] = llm_config['model']
            if 'endpoint' in llm_config:
                kwargs['endpoint'] = llm_config['endpoint']
            if api_key:
                kwargs['api_key'] = api_key

            instance = self._instantiate_class(class_path_or_instance, **kwargs) if kwargs else self._instantiate_class(class_path_or_instance)
        else:
            # Already an instance
            instance = class_path_or_instance

        self._llm_cache[name] = instance
        return instance

    def register_cleaner(self, name: str, class_path: str) -> None:
        """Register a custom cleaner."""
        self.config.cleaners[name] = class_path
        if name in self._cleaner_cache:
            del self._cleaner_cache[name]

    def register_chunker(self, name: str, class_path: str) -> None:
        """Register a custom chunker."""
        self.config.chunkers[name] = class_path
        if name in self._chunker_cache:
            del self._chunker_cache[name]

    def register_matcher(self, name: str, class_path: str) -> None:
        """Register a custom semantic matcher."""
        self.config.matchers[name] = class_path
        if name in self._matcher_cache:
            del self._matcher_cache[name]

    def register_classifier(self, name: str, class_path: str) -> None:
        """Register a custom classifier."""
        self.config.classifiers[name] = class_path
        if name in self._classifier_cache:
            del self._classifier_cache[name]

    def register_phash_matcher(self, name: str, class_path: str) -> None:
        """Register a custom phash matcher."""
        self.config.phash_matchers[name] = class_path
        if name in self._phash_cache:
            del self._phash_cache[name]

    def register_llm(self, name: str, class_path: str) -> None:
        """Register a custom LLM evaluator."""
        self.config.llms[name] = class_path
        if name in self._llm_cache:
            del self._llm_cache[name]
