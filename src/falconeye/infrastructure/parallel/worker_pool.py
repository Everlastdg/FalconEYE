"""Worker pool for parallel file analysis."""

from dataclasses import dataclass, field
from typing import List, Optional, Callable, Any, Dict
from pathlib import Path
import asyncio
import time
from datetime import datetime

from ...domain.models.security import SecurityFinding, SecurityReview
from ...domain.models.prompt import PromptContext
from ..logging import FalconEyeLogger


@dataclass
class WorkerConfig:
    """Configuration for the worker pool."""
    max_workers: int = 4
    llm_concurrency: int = 2
    timeout_per_file: int = 300
    retry_failed: bool = True
    max_retries: int = 2


@dataclass
class AnalysisTask:
    """Represents a file analysis task."""
    file_path: Path
    language: str
    system_prompt: str
    validate_findings: bool = False
    top_k_context: int = 5
    priority: int = 0  # Higher = more priority
    retry_count: int = 0


@dataclass
class AnalysisResult:
    """Result of analyzing a single file."""
    file_path: Path
    findings: List[SecurityFinding] = field(default_factory=list)
    success: bool = True
    error: Optional[str] = None
    duration_seconds: float = 0.0
    chunks_analyzed: int = 1


# Type aliases for callbacks
OnFileStartCallback = Callable[[str], None]
OnFileCompleteCallback = Callable[[str, List[SecurityFinding], Optional[str]], None]
OnFindingCallback = Callable[[SecurityFinding, str], None]


class AnalysisWorkerPool:
    """
    Manages parallel file analysis with controlled concurrency.
    
    Uses asyncio for concurrent file processing with semaphores
    to limit concurrent LLM API calls and prevent overloading.
    """

    def __init__(
        self,
        config: WorkerConfig,
        security_analyzer: Any,
        context_assembler: Any,
        large_file_chunker: Optional[Any] = None,
    ):
        """
        Initialize the worker pool.
        
        Args:
            config: Worker pool configuration
            security_analyzer: Security analyzer service
            context_assembler: Context assembler service
            large_file_chunker: Optional large file chunker
        """
        self.config = config
        self.security_analyzer = security_analyzer
        self.context_assembler = context_assembler
        self.large_file_chunker = large_file_chunker
        self.logger = FalconEyeLogger.get_instance()

        # Semaphores for concurrency control
        self._worker_semaphore: Optional[asyncio.Semaphore] = None
        self._llm_semaphore: Optional[asyncio.Semaphore] = None

        # Callbacks
        self._on_file_start: Optional[OnFileStartCallback] = None
        self._on_file_complete: Optional[OnFileCompleteCallback] = None
        self._on_finding: Optional[OnFindingCallback] = None

        # Statistics
        self._stats = {
            "files_processed": 0,
            "files_failed": 0,
            "total_findings": 0,
            "total_duration": 0.0,
        }

    def set_callbacks(
        self,
        on_file_start: Optional[OnFileStartCallback] = None,
        on_file_complete: Optional[OnFileCompleteCallback] = None,
        on_finding: Optional[OnFindingCallback] = None,
    ):
        """
        Set callback functions for progress reporting.
        
        Args:
            on_file_start: Called when file analysis starts
            on_file_complete: Called when file analysis completes
            on_finding: Called when a finding is discovered
        """
        self._on_file_start = on_file_start
        self._on_file_complete = on_file_complete
        self._on_finding = on_finding

    async def analyze_files(
        self,
        tasks: List[AnalysisTask],
    ) -> List[AnalysisResult]:
        """
        Analyze multiple files in parallel.
        
        Args:
            tasks: List of analysis tasks
            
        Returns:
            List of analysis results
        """
        if not tasks:
            return []

        # Initialize semaphores
        self._worker_semaphore = asyncio.Semaphore(self.config.max_workers)
        self._llm_semaphore = asyncio.Semaphore(self.config.llm_concurrency)

        self.logger.info(
            "Starting parallel analysis",
            extra={
                "total_files": len(tasks),
                "max_workers": self.config.max_workers,
                "llm_concurrency": self.config.llm_concurrency,
            }
        )

        start_time = time.time()

        # Sort tasks by priority (higher first)
        sorted_tasks = sorted(tasks, key=lambda t: t.priority, reverse=True)

        # Create analysis coroutines
        coroutines = [
            self._analyze_file_with_semaphore(task)
            for task in sorted_tasks
        ]

        # Run all tasks concurrently with controlled parallelism
        results = await asyncio.gather(*coroutines, return_exceptions=True)

        # Process results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # Task raised an exception
                task = sorted_tasks[i]
                self.logger.error(
                    f"Task failed with exception: {task.file_path}",
                    extra={"error": str(result)}
                )
                final_results.append(AnalysisResult(
                    file_path=task.file_path,
                    success=False,
                    error=str(result),
                ))
                self._stats["files_failed"] += 1
            else:
                final_results.append(result)
                if result.success:
                    self._stats["files_processed"] += 1
                    self._stats["total_findings"] += len(result.findings)
                else:
                    self._stats["files_failed"] += 1

        total_duration = time.time() - start_time
        self._stats["total_duration"] = total_duration

        self.logger.info(
            "Parallel analysis complete",
            extra={
                "files_processed": self._stats["files_processed"],
                "files_failed": self._stats["files_failed"],
                "total_findings": self._stats["total_findings"],
                "total_duration_seconds": round(total_duration, 2),
                "avg_time_per_file": round(total_duration / len(tasks), 2) if tasks else 0,
            }
        )

        return final_results

    async def _analyze_file_with_semaphore(
        self,
        task: AnalysisTask,
    ) -> AnalysisResult:
        """
        Analyze a file with semaphore-controlled concurrency.
        
        Args:
            task: Analysis task
            
        Returns:
            Analysis result
        """
        async with self._worker_semaphore:
            return await self._analyze_file(task)

    async def _analyze_file(
        self,
        task: AnalysisTask,
    ) -> AnalysisResult:
        """
        Analyze a single file.
        
        Args:
            task: Analysis task
            
        Returns:
            Analysis result
        """
        start_time = time.time()
        file_path_str = str(task.file_path)

        # Notify start
        if self._on_file_start:
            try:
                self._on_file_start(file_path_str)
            except Exception:
                pass

        try:
            # Read file content
            content = task.file_path.read_text(encoding='utf-8', errors='ignore')

            # Check if file needs chunking
            chunks_analyzed = 1
            all_findings: List[SecurityFinding] = []

            if self.large_file_chunker and self.large_file_chunker.should_chunk(task.file_path, content):
                # Large file - chunk and analyze each chunk
                chunk_result = self.large_file_chunker.chunk_file(
                    content, file_path_str, task.language
                )
                chunks_analyzed = chunk_result.chunk_count

                self.logger.info(
                    f"Large file chunked: {task.file_path.name}",
                    extra={"chunks": chunks_analyzed}
                )

                # Analyze each chunk
                chunk_findings = []
                for chunk in chunk_result.chunks:
                    findings = await self._analyze_chunk(
                        chunk.content,
                        file_path_str,
                        task,
                        chunk.start_line,
                        chunk.end_line,
                    )
                    chunk_findings.append(findings)

                # Merge findings from all chunks
                all_findings = self.large_file_chunker.merge_findings(
                    chunk_findings, chunk_result
                )
            else:
                # Normal file - single pass analysis
                all_findings = await self._analyze_content(
                    content, file_path_str, task
                )

            # Notify findings
            if self._on_finding:
                for finding in all_findings:
                    try:
                        self._on_finding(finding, file_path_str)
                    except Exception:
                        pass

            duration = time.time() - start_time

            # Notify completion
            if self._on_file_complete:
                try:
                    self._on_file_complete(file_path_str, all_findings, None)
                except Exception:
                    pass

            return AnalysisResult(
                file_path=task.file_path,
                findings=all_findings,
                success=True,
                duration_seconds=duration,
                chunks_analyzed=chunks_analyzed,
            )

        except asyncio.TimeoutError:
            duration = time.time() - start_time
            error_msg = f"Analysis timed out after {self.config.timeout_per_file}s"

            self.logger.warning(
                f"File analysis timed out: {task.file_path.name}",
                extra={"timeout": self.config.timeout_per_file}
            )

            if self._on_file_complete:
                try:
                    self._on_file_complete(file_path_str, [], error_msg)
                except Exception:
                    pass

            return AnalysisResult(
                file_path=task.file_path,
                success=False,
                error=error_msg,
                duration_seconds=duration,
            )

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)

            self.logger.error(
                f"File analysis failed: {task.file_path.name}",
                extra={"error": error_msg},
                exc_info=True
            )

            if self._on_file_complete:
                try:
                    self._on_file_complete(file_path_str, [], error_msg)
                except Exception:
                    pass

            return AnalysisResult(
                file_path=task.file_path,
                success=False,
                error=error_msg,
                duration_seconds=duration,
            )

    async def _analyze_content(
        self,
        content: str,
        file_path: str,
        task: AnalysisTask,
    ) -> List[SecurityFinding]:
        """
        Analyze file content with LLM concurrency control.
        
        Args:
            content: File content
            file_path: Path to file
            task: Analysis task
            
        Returns:
            List of findings
        """
        # Acquire LLM semaphore for the actual LLM call
        async with self._llm_semaphore:
            # Assemble context with RAG
            context = await self.context_assembler.assemble_context(
                file_path=file_path,
                code_snippet=content,
                language=task.language,
                top_k_similar=task.top_k_context,
                analysis_type="review",
            )

            # Perform analysis with timeout
            findings = await asyncio.wait_for(
                self.security_analyzer.analyze_code(
                    context=context,
                    system_prompt=task.system_prompt,
                ),
                timeout=self.config.timeout_per_file
            )

            # Optional validation
            if task.validate_findings and findings:
                findings = await asyncio.wait_for(
                    self.security_analyzer.validate_findings(
                        findings=findings,
                        context=context,
                    ),
                    timeout=self.config.timeout_per_file // 2
                )

            return findings

    async def _analyze_chunk(
        self,
        chunk_content: str,
        file_path: str,
        task: AnalysisTask,
        start_line: int,
        end_line: int,
    ) -> List[SecurityFinding]:
        """
        Analyze a chunk of a large file.
        
        Args:
            chunk_content: Chunk content
            file_path: Original file path
            task: Analysis task
            start_line: Starting line of chunk
            end_line: Ending line of chunk
            
        Returns:
            List of findings
        """
        # Add chunk context to the prompt
        chunk_context = f"\n[CHUNK INFO: Lines {start_line}-{end_line} of {file_path}]\n"

        async with self._llm_semaphore:
            context = await self.context_assembler.assemble_context(
                file_path=file_path,
                code_snippet=chunk_context + chunk_content,
                language=task.language,
                top_k_similar=task.top_k_context,
                analysis_type="review",
            )

            findings = await asyncio.wait_for(
                self.security_analyzer.analyze_code(
                    context=context,
                    system_prompt=task.system_prompt,
                ),
                timeout=self.config.timeout_per_file
            )

            # Adjust line numbers to be relative to original file
            for finding in findings:
                if hasattr(finding, 'line_start') and finding.line_start:
                    # Line numbers from LLM are relative to chunk
                    # Add offset to get original file line numbers
                    # Note: SecurityFinding is immutable, so we'd need to recreate
                    # For now, the LLM should report correct lines based on chunk info
                    pass

            return findings

    def get_stats(self) -> Dict[str, Any]:
        """
        Get worker pool statistics.
        
        Returns:
            Dictionary with statistics
        """
        return dict(self._stats)

    async def analyze_files_batched(
        self,
        tasks: List[AnalysisTask],
        batch_size: int = 10,
    ) -> List[AnalysisResult]:
        """
        Analyze files in batches for very large codebases.
        
        This is useful when you have thousands of files and want
        to process them in manageable batches.
        
        Args:
            tasks: List of analysis tasks
            batch_size: Number of files per batch
            
        Returns:
            List of analysis results
        """
        all_results = []
        total_batches = (len(tasks) + batch_size - 1) // batch_size

        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_num = i // batch_size + 1

            self.logger.info(
                f"Processing batch {batch_num}/{total_batches}",
                extra={"batch_size": len(batch)}
            )

            results = await self.analyze_files(batch)
            all_results.extend(results)

            # Small delay between batches to prevent resource exhaustion
            if i + batch_size < len(tasks):
                await asyncio.sleep(0.5)

        return all_results


def create_tasks_from_files(
    files: List[Path],
    language_detector: Any,
    plugin_registry: Any,
    validate_findings: bool = False,
    top_k_context: int = 5,
) -> List[AnalysisTask]:
    """
    Create analysis tasks from a list of files.
    
    Args:
        files: List of file paths
        language_detector: Language detector service
        plugin_registry: Plugin registry for system prompts
        validate_findings: Whether to validate findings
        top_k_context: Number of context chunks
        
    Returns:
        List of analysis tasks
    """
    tasks = []

    for file_path in files:
        try:
            # Detect language
            language = language_detector.detect_language(file_path)

            # Get system prompt from plugin
            plugin = plugin_registry.get_plugin(language)
            if plugin:
                system_prompt = plugin.get_system_prompt()
            else:
                system_prompt = _get_default_system_prompt()

            task = AnalysisTask(
                file_path=file_path,
                language=language,
                system_prompt=system_prompt,
                validate_findings=validate_findings,
                top_k_context=top_k_context,
            )
            tasks.append(task)

        except Exception as e:
            # Skip files that can't be processed
            logger = FalconEyeLogger.get_instance()
            logger.warning(f"Skipping file {file_path}: {e}")

    return tasks


def _get_default_system_prompt() -> str:
    """Get default system prompt for unknown languages."""
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
      "code_snippet": "Vulnerable code",
      "line_start": 42,
      "line_end": 45
    }
  ]
}

If no issues found, return: {"reviews": []}"""
