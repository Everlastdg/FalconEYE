"""Integration tests for large file indexing and scanning.

Tests FalconEYE's adaptive chunking and prompt truncation for files
with 5000+ lines, ensuring proper handling of very large codebases.

These tests require a running Ollama instance with models:
- qwen3-coder:30b (for analysis)
- embeddinggemma:300m (for embeddings)
"""

import pytest
import tempfile
from pathlib import Path
from typing import List

from falconeye.domain.models.code_chunk import CodeChunk
from falconeye.domain.models.prompt import PromptContext
from falconeye.infrastructure.llm_providers.ollama_adapter import OllamaLLMAdapter
from falconeye.infrastructure.config.config_loader import ConfigLoader
from falconeye.application.commands.index_codebase import (
    IndexCodebaseCommand,
    IndexCodebaseHandler,
)
from falconeye.application.commands.review_file import (
    ReviewFileCommand,
    ReviewFileHandler,
)
from falconeye.domain.services.security_analyzer import SecurityAnalyzer
from falconeye.domain.services.context_assembler import ContextAssembler
from falconeye.domain.services.language_detector import LanguageDetector
from falconeye.domain.services.project_identifier import ProjectIdentifier
from falconeye.domain.services.checksum_service import ChecksumService
from falconeye.infrastructure.ast.ast_analyzer import EnhancedASTAnalyzer
from falconeye.infrastructure.vector_stores.chroma_adapter import ChromaVectorStoreAdapter
from falconeye.infrastructure.persistence.chroma_metadata_repository import (
    ChromaMetadataRepository,
)
from falconeye.infrastructure.registry.chroma_registry_adapter import ChromaIndexRegistryAdapter
from falconeye.infrastructure.plugins.python_plugin import PythonPlugin

from tests.conftest import (
    generate_large_python_file,
    generate_large_javascript_file,
)


@pytest.mark.integration
class TestLargeFileIndexing:
    """Test suite for large file indexing with adaptive chunking."""

    @pytest.fixture
    async def llm_service(self, mock_config, temp_dir):
        """Provide LLM service for testing."""
        # OllamaLLMAdapter is the concrete LLM service implementation
        service = OllamaLLMAdapter(
            host="http://localhost:11434",
            chat_model="qwen3-coder:30b",
            embedding_model="embeddinggemma:300m",
        )
        return service

    @pytest.fixture
    async def index_handler(self, llm_service, temp_dir, mock_config):
        """Provide index handler with all dependencies."""
        # Create temporary vector store
        vector_store_dir = temp_dir / "vector_store"
        vector_store_dir.mkdir(exist_ok=True)
        vector_store = ChromaVectorStoreAdapter(
            persist_directory=str(vector_store_dir),
            collection_prefix="test_",
        )

        # Create metadata repository
        metadata_dir = temp_dir / "metadata"
        metadata_dir.mkdir(exist_ok=True)
        metadata_repo = ChromaMetadataRepository(
            persist_directory=str(metadata_dir),
        )

        # Create index registry
        registry_dir = temp_dir / "registry"
        registry_dir.mkdir(exist_ok=True)
        index_registry = ChromaIndexRegistryAdapter(
            persist_directory=str(registry_dir),
        )

        # Create other services
        language_detector = LanguageDetector()
        ast_analyzer = EnhancedASTAnalyzer()
        project_identifier = ProjectIdentifier()
        checksum_service = ChecksumService()

        handler = IndexCodebaseHandler(
            vector_store=vector_store,
            metadata_repo=metadata_repo,
            llm_service=llm_service,
            language_detector=language_detector,
            ast_analyzer=ast_analyzer,
            project_identifier=project_identifier,
            checksum_service=checksum_service,
            index_registry=index_registry,
        )
        return handler

    @pytest.fixture
    async def review_handler(self, llm_service, temp_dir):
        """Provide review handler with dependencies."""
        # Create security analyzer
        python_plugin = PythonPlugin()
        security_analyzer = SecurityAnalyzer(
            llm_service=llm_service,
            plugin=python_plugin,
        )

        # Create context assembler (simplified for testing)
        context_assembler = ContextAssembler(
            vector_store=None,  # Will use simple context without RAG
        )

        handler = ReviewFileHandler(
            security_analyzer=security_analyzer,
            context_assembler=context_assembler,
        )
        return handler

    async def test_adaptive_chunking_5000_lines(self, index_handler, temp_dir):
        """
        Test adaptive chunking for a 5000-line file.

        Expected behavior:
        - File > 1000 lines should trigger adaptive chunking
        - Chunk size should be increased from default (50) to larger size
        - Should result in ~50-75 chunks maximum
        """
        # Create 5000-line Python file
        large_file = temp_dir / "large_module.py"
        content = generate_large_python_file(num_lines=5000, with_vulnerabilities=True)
        large_file.write_text(content)

        # Create index command
        command = IndexCodebaseCommand(
            codebase_path=temp_dir,
            language="python",
            chunk_size=50,  # Default size
            chunk_overlap=10,
            include_documents=False,
            force_reindex=True,
        )

        # Execute indexing
        codebase = await index_handler.handle(command)

        # Verify codebase was created
        assert codebase is not None
        assert len(codebase.files) == 1

        # Get project metadata to check chunks
        project_id = index_handler.project_identifier.identify_project(temp_dir)[0]
        project_meta = index_handler.index_registry.get_project(project_id)

        # Verify adaptive chunking was applied
        # For 5000 lines: adaptive_chunk_size = max(50, min(200, 5000 // 50)) = 100
        # Expected chunks: ~5000 / 100 = ~50 chunks (with overlap, slightly more)
        assert project_meta.total_chunks >= 45
        assert project_meta.total_chunks <= 75
        print(f"✓ 5000-line file chunked into {project_meta.total_chunks} chunks")

    async def test_adaptive_chunking_10000_lines(self, index_handler, temp_dir):
        """
        Test adaptive chunking for a 10,000-line file.

        Expected behavior:
        - Chunk size should scale to 200 (the maximum)
        - Should result in ~50 chunks
        """
        # Create 10,000-line Python file
        large_file = temp_dir / "very_large_module.py"
        content = generate_large_python_file(num_lines=10000, with_vulnerabilities=True)
        large_file.write_text(content)

        # Create index command
        command = IndexCodebaseCommand(
            codebase_path=temp_dir,
            language="python",
            chunk_size=50,
            chunk_overlap=10,
            include_documents=False,
            force_reindex=True,
        )

        # Execute indexing
        codebase = await index_handler.handle(command)

        # Get project metadata
        project_id = index_handler.project_identifier.identify_project(temp_dir)[0]
        project_meta = index_handler.index_registry.get_project(project_id)

        # For 10,000 lines: adaptive_chunk_size = max(50, min(200, 10000 // 50)) = 200
        # Expected chunks: ~10,000 / 200 = ~50 chunks (with overlap, slightly more)
        assert project_meta.total_chunks >= 45
        assert project_meta.total_chunks <= 75
        print(f"✓ 10,000-line file chunked into {project_meta.total_chunks} chunks")

    async def test_prompt_truncation_15000_lines(self, llm_service):
        """
        Test prompt truncation for files exceeding max_code_lines limit.

        Expected behavior:
        - Files > 10,000 lines should be truncated in prompts
        - Truncation note should be added
        - Should prevent LLM context window overflow
        """
        # Generate 15,000-line file
        content = generate_large_python_file(num_lines=15000, with_vulnerabilities=True)

        # Create prompt context
        context = PromptContext(
            file_path="very_large_file.py",
            code_snippet=content,
            language="python",
            analysis_type="review",
        )

        # Format for AI with default max_code_lines=10000
        formatted_prompt = context.format_for_ai(max_code_lines=10000)

        # Verify truncation occurred
        assert "[Truncated" in formatted_prompt
        assert "5000 lines" in formatted_prompt  # 15000 - 10000 = 5000 truncated

        # Verify first 10,000 lines are present
        lines = formatted_prompt.split('\n')
        numbered_lines = [l for l in lines if '|' in l and l.strip()[0].isdigit()]

        # Should have 10,000 numbered lines (plus headers and truncation note)
        assert len(numbered_lines) == 10000
        print(f"✓ 15,000-line file truncated to 10,000 lines in prompt")

    async def test_chunking_preserves_line_boundaries(self, index_handler, temp_dir):
        """
        Test that chunking respects line boundaries, not character counts.

        Expected behavior:
        - Chunks should split at line boundaries
        - No partial lines in chunks
        - Overlap should be in complete lines
        """
        # Create test file
        test_file = temp_dir / "test_chunking.py"
        content = generate_large_python_file(num_lines=1000, with_vulnerabilities=True)
        test_file.write_text(content)

        # Test chunking directly
        chunks = index_handler._chunk_content(
            content=content,
            file_path="test_chunking.py",
            language="python",
            chunk_size=50,
            overlap=10,
        )

        # Verify all chunks end with complete lines
        for chunk in chunks:
            # Chunk content should not split lines
            assert not chunk.content.endswith('\\')  # No line continuation artifacts

            # Verify metadata has proper line numbers
            assert chunk.metadata.start_line > 0
            assert chunk.metadata.end_line >= chunk.metadata.start_line

            # Count actual lines in chunk
            actual_lines = len(chunk.content.splitlines())
            expected_lines = chunk.metadata.end_line - chunk.metadata.start_line + 1
            assert actual_lines == expected_lines

        print(f"✓ All {len(chunks)} chunks respect line boundaries")

    async def test_large_file_multiple_languages(self, index_handler, temp_dir):
        """
        Test indexing a codebase with large files in multiple languages.

        Expected behavior:
        - Each language file should be detected and processed
        - Adaptive chunking should apply to both
        - Multi-language metadata should be tracked
        """
        # Create large Python file
        python_file = temp_dir / "large_module.py"
        python_content = generate_large_python_file(num_lines=5000, with_vulnerabilities=True)
        python_file.write_text(python_content)

        # Create large JavaScript file
        js_file = temp_dir / "large_module.js"
        js_content = generate_large_javascript_file(num_lines=5000, with_vulnerabilities=True)
        js_file.write_text(js_content)

        # Index codebase (auto-detect languages)
        command = IndexCodebaseCommand(
            codebase_path=temp_dir,
            language=None,  # Auto-detect
            chunk_size=50,
            chunk_overlap=10,
            include_documents=False,
            force_reindex=True,
        )

        codebase = await index_handler.handle(command)

        # Verify both files were indexed
        assert len(codebase.files) == 2

        # Get project metadata
        project_id = index_handler.project_identifier.identify_project(temp_dir)[0]
        project_meta = index_handler.index_registry.get_project(project_id)

        # Verify multi-language detection
        assert "python" in project_meta.languages
        assert "javascript" in project_meta.languages

        # Verify total chunks (should be ~100 total for both 5000-line files)
        assert project_meta.total_chunks >= 90
        assert project_meta.total_chunks <= 150

        print(f"✓ Multi-language codebase indexed with {project_meta.total_chunks} total chunks")

    @pytest.mark.slow
    async def test_end_to_end_large_file_review(
        self, index_handler, review_handler, llm_service, temp_dir
    ):
        """
        End-to-end test: Index and review a 5000-line file with vulnerabilities.

        This test verifies that:
        1. Large file is successfully indexed
        2. Review can process the file
        3. Security findings are detected in large files
        4. LLM context doesn't overflow

        Note: This test requires Ollama and may take several minutes.
        """
        # Create large file with known vulnerabilities
        large_file = temp_dir / "vulnerable_module.py"
        content = generate_large_python_file(num_lines=5000, with_vulnerabilities=True)
        large_file.write_text(content)

        # Step 1: Index the file
        index_command = IndexCodebaseCommand(
            codebase_path=temp_dir,
            language="python",
            chunk_size=50,
            chunk_overlap=10,
            include_documents=False,
            force_reindex=True,
        )
        codebase = await index_handler.handle(index_command)
        assert codebase is not None
        print("✓ Large file indexed successfully")

        # Step 2: Review the file
        python_plugin = PythonPlugin()
        review_command = ReviewFileCommand(
            file_path=large_file,
            language="python",
            system_prompt=python_plugin.get_system_prompt(),
            validate_findings=False,  # Skip validation for faster test
            top_k_context=5,
        )

        review = await review_handler.handle(review_command)
        assert review is not None
        print(f"✓ Large file reviewed successfully")

        # Step 3: Verify findings were detected
        # The generated file has vulnerabilities every 3 functions
        # With 5000 lines and ~10 functions per class, we expect multiple findings
        print(f"✓ Detected {len(review.findings)} security findings")

        # Verify at least some findings (LLM may not catch all, but should find some)
        assert len(review.findings) > 0, "Expected to find at least one vulnerability in large file"

        # Verify findings have proper metadata
        for finding in review.findings[:5]:  # Check first 5
            assert finding.file_path is not None
            assert finding.severity is not None
            assert finding.description is not None
            print(f"  - {finding.severity.upper()}: {finding.title[:60]}")


@pytest.mark.integration
class TestLargeFileTokenCounts:
    """Test suite for token counting and context window management."""

    @pytest.fixture
    async def llm_service(self, mock_config):
        """Provide LLM service for testing."""
        # OllamaLLMAdapter is the concrete LLM service implementation
        service = OllamaLLMAdapter(
            host="http://localhost:11434",
            chat_model="qwen3-coder:30b",
            embedding_model="embeddinggemma:300m",
        )
        return service

    async def test_token_count_estimation(self, llm_service):
        """
        Test token counting for various file sizes.

        Verifies that token estimation is reasonable and within
        expected bounds for the LLM's context window.
        """
        test_cases = [
            (1000, "Small file"),
            (5000, "Medium large file"),
            (10000, "Large file"),
        ]

        for num_lines, description in test_cases:
            content = generate_large_python_file(num_lines=num_lines)
            token_count = llm_service.count_tokens(content)

            # Rough estimate: ~4 characters per token
            # Python code with indentation: ~30-50 chars per line
            # So ~7-12 tokens per line expected
            expected_min = num_lines * 5
            expected_max = num_lines * 15

            assert expected_min <= token_count <= expected_max, \
                f"{description}: Token count {token_count} outside expected range [{expected_min}, {expected_max}]"

            print(f"✓ {description} ({num_lines} lines): ~{token_count:,} tokens")

    async def test_context_window_safety(self, llm_service):
        """
        Test that prompts stay within safe context window limits.

        Most LLMs have 128k-256k token limits. We should stay well below
        to leave room for the AI's response.
        """
        # Generate a very large file
        content = generate_large_python_file(num_lines=10000)

        # Create prompt context with truncation
        context = PromptContext(
            file_path="large_file.py",
            code_snippet=content,
            language="python",
            analysis_type="review",
        )

        # Format with truncation at 10,000 lines
        formatted = context.format_for_ai(max_code_lines=10000)

        # Count tokens in formatted prompt
        token_count = llm_service.count_tokens(formatted)

        # Should be well under 128k tokens (safe limit)
        assert token_count < 100000, \
            f"Prompt token count {token_count} too high, risks context overflow"

        print(f"✓ 10,000-line prompt uses {token_count:,} tokens (safe)")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
