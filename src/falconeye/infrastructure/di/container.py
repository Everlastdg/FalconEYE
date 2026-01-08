"""Dependency injection container for FalconEYE."""

from dataclasses import dataclass
from typing import Optional
from pathlib import Path

from ..config.config_loader import ConfigLoader
from ..config.config_models import FalconEyeConfig
from ..llm_providers.ollama_adapter import OllamaLLMAdapter
from ..resilience import RetryConfig, CircuitBreakerConfig
from ..vector_stores.chroma_adapter import ChromaVectorStoreAdapter
from ..persistence.chroma_metadata_repository import ChromaMetadataRepository
from ..registry.chroma_registry_adapter import ChromaIndexRegistryAdapter
from ..ast.ast_analyzer import EnhancedASTAnalyzer
from ..plugins.plugin_registry import PluginRegistry
from ..chunking import LargeFileChunker, ChunkingStrategy
from ..parallel import AnalysisWorkerPool, WorkerConfig
from ..streaming import ResultStreamer
from ...domain.services.security_analyzer import SecurityAnalyzer
from ...domain.services.context_assembler import ContextAssembler
from ...domain.services.language_detector import LanguageDetector
from ...domain.services.project_identifier import ProjectIdentifier
from ...domain.services.checksum_service import ChecksumService
from ...application.commands.index_codebase import IndexCodebaseHandler
from ...application.commands.review_file import ReviewFileHandler


@dataclass
class DIContainer:
    """
    Dependency injection container for FalconEYE.

    Assembles all components with proper dependency injection.
    This container is created once at application startup.
    """

    # Configuration
    config: FalconEyeConfig

    # Infrastructure
    llm_service: OllamaLLMAdapter
    vector_store: ChromaVectorStoreAdapter
    metadata_repo: ChromaMetadataRepository
    index_registry: ChromaIndexRegistryAdapter
    ast_analyzer: EnhancedASTAnalyzer
    plugin_registry: PluginRegistry

    # Domain Services
    security_analyzer: SecurityAnalyzer
    context_assembler: ContextAssembler
    language_detector: LanguageDetector
    project_identifier: ProjectIdentifier
    checksum_service: ChecksumService

    # New Infrastructure Components
    large_file_chunker: LargeFileChunker
    worker_pool: AnalysisWorkerPool

    # Application Handlers
    index_handler: IndexCodebaseHandler
    review_file_handler: ReviewFileHandler

    @classmethod
    def create(cls, config_path: Optional[str] = None) -> "DIContainer":
        """
        Create and wire all dependencies.

        Args:
            config_path: Optional path to configuration file

        Returns:
            DIContainer with all dependencies wired
        """
        # Load configuration
        config = ConfigLoader.load(config_path)

        # Create data directories if they don't exist
        Path(config.vector_store.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.metadata.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.index_registry.persist_directory).mkdir(parents=True, exist_ok=True)
        Path(config.output.output_directory).mkdir(parents=True, exist_ok=True)

        # Infrastructure layer - Adapters

        # Create retry config from configuration
        retry_config = RetryConfig(
            max_retries=config.llm.retry.max_retries,
            initial_delay=config.llm.retry.initial_delay,
            max_delay=config.llm.retry.max_delay,
            exponential_base=config.llm.retry.exponential_base,
            jitter=config.llm.retry.jitter,
            retryable_exceptions=(ConnectionError, TimeoutError, OSError)
        )

        # Create circuit breaker config from configuration
        circuit_breaker_config = CircuitBreakerConfig(
            failure_threshold=config.llm.circuit_breaker.failure_threshold,
            success_threshold=config.llm.circuit_breaker.success_threshold,
            timeout=config.llm.circuit_breaker.timeout,
            exclude_exceptions=(ValueError, TypeError)
        )

        llm_service = OllamaLLMAdapter(
            host=config.llm.base_url,
            chat_model=config.llm.model.analysis,
            embedding_model=config.llm.model.embedding,
            retry_config=retry_config,
            circuit_breaker_config=circuit_breaker_config,
        )

        vector_store = ChromaVectorStoreAdapter(
            persist_directory=config.vector_store.persist_directory,
            collection_prefix=config.vector_store.collection_prefix,
        )

        metadata_repo = ChromaMetadataRepository(
            persist_directory=config.metadata.persist_directory,
            collection_name=config.metadata.collection_name,
        )

        index_registry = ChromaIndexRegistryAdapter(
            persist_directory=config.index_registry.persist_directory,
            collection_name=config.index_registry.collection_name,
        )

        ast_analyzer = EnhancedASTAnalyzer()

        plugin_registry = PluginRegistry()
        plugin_registry.load_all_plugins()

        # Domain services - Business logic
        security_analyzer = SecurityAnalyzer(llm_service)
        context_assembler = ContextAssembler(vector_store, metadata_repo)
        language_detector = LanguageDetector()
        project_identifier = ProjectIdentifier()
        checksum_service = ChecksumService()

        # Large file chunker
        chunking_strategy = ChunkingStrategy(config.large_files.strategy)
        large_file_chunker = LargeFileChunker(
            max_lines_single_pass=config.large_files.max_lines_single_pass,
            chunk_size_lines=config.large_files.chunk_size_lines,
            chunk_overlap_lines=config.large_files.chunk_overlap_lines,
            strategy=chunking_strategy,
            max_file_size_mb=config.large_files.max_file_size_mb,
            ast_analyzer=ast_analyzer,
        )

        # Worker pool for parallel processing
        worker_config = WorkerConfig(
            max_workers=config.parallel.max_workers,
            llm_concurrency=config.parallel.llm_concurrency,
            timeout_per_file=config.parallel.timeout_per_file,
        )
        worker_pool = AnalysisWorkerPool(
            config=worker_config,
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
            large_file_chunker=large_file_chunker,
        )

        # Application handlers - Use cases
        index_handler = IndexCodebaseHandler(
            vector_store=vector_store,
            metadata_repo=metadata_repo,
            llm_service=llm_service,
            language_detector=language_detector,
            ast_analyzer=ast_analyzer,
            project_identifier=project_identifier,
            checksum_service=checksum_service,
            index_registry=index_registry,
        )

        review_file_handler = ReviewFileHandler(
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
        )

        return cls(
            config=config,
            llm_service=llm_service,
            vector_store=vector_store,
            metadata_repo=metadata_repo,
            index_registry=index_registry,
            ast_analyzer=ast_analyzer,
            plugin_registry=plugin_registry,
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
            language_detector=language_detector,
            project_identifier=project_identifier,
            checksum_service=checksum_service,
            large_file_chunker=large_file_chunker,
            worker_pool=worker_pool,
            index_handler=index_handler,
            review_file_handler=review_file_handler,
        )

    def get_system_prompt(self, language: str) -> str:
        """
        Get system prompt for a language.

        Args:
            language: Language name

        Returns:
            System prompt string
        """
        plugin = self.plugin_registry.get_plugin(language)
        if plugin:
            return plugin.get_system_prompt()

        # Default generic prompt if no plugin
        return """You are a security expert analyzing code for vulnerabilities.
Analyze the provided code and identify any security issues.

Output format (JSON):
{
  "reviews": [
    {
      "issue": "Brief description",
      "reasoning": "Detailed explanation",
      "mitigation": "How to fix",
      "severity": "critical|high|medium|low|info",
      "confidence": 0.9,
      "code_snippet": "Vulnerable code"
    }
  ]
}

If no issues found, return: {"reviews": []}"""

    def __repr__(self) -> str:
        """String representation."""
        return f"<DIContainer: {len(self.plugin_registry.get_supported_languages())} languages>"