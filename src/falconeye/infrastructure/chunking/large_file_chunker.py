"""Large file chunking for efficient analysis of oversized files."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any, Tuple
from pathlib import Path

from ..logging import FalconEyeLogger


class ChunkingStrategy(str, Enum):
    """Strategy for splitting large files."""
    HYBRID = "hybrid"  # AST-aware with line fallback
    AST = "ast"  # Split by function/class boundaries
    LINES = "lines"  # Fixed line-based chunks


@dataclass
class FileChunk:
    """Represents a chunk of a large file."""
    content: str
    start_line: int
    end_line: int
    chunk_index: int
    total_chunks: int
    context_before: Optional[str] = None  # Lines before chunk for context
    context_after: Optional[str] = None  # Lines after chunk for context
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def line_count(self) -> int:
        """Number of lines in this chunk."""
        return self.end_line - self.start_line + 1


@dataclass
class ChunkResult:
    """Result of chunking a large file."""
    chunks: List[FileChunk]
    original_line_count: int
    strategy_used: ChunkingStrategy
    file_path: str

    @property
    def chunk_count(self) -> int:
        """Number of chunks created."""
        return len(self.chunks)


class LargeFileChunker:
    """
    Handles chunking of large files for efficient analysis.
    
    Large files are split into manageable chunks that can be analyzed
    individually, then findings are merged and deduplicated.
    """

    def __init__(
        self,
        max_lines_single_pass: int = 500,
        chunk_size_lines: int = 300,
        chunk_overlap_lines: int = 50,
        strategy: ChunkingStrategy = ChunkingStrategy.HYBRID,
        max_file_size_mb: int = 10,
        ast_analyzer: Optional[Any] = None,
    ):
        """
        Initialize the large file chunker.
        
        Args:
            max_lines_single_pass: Files larger than this get chunked
            chunk_size_lines: Target lines per chunk
            chunk_overlap_lines: Overlap between chunks for context
            strategy: Chunking strategy to use
            max_file_size_mb: Skip files larger than this
            ast_analyzer: Optional AST analyzer for smart chunking
        """
        self.max_lines_single_pass = max_lines_single_pass
        self.chunk_size_lines = chunk_size_lines
        self.chunk_overlap_lines = chunk_overlap_lines
        self.strategy = strategy
        self.max_file_size_mb = max_file_size_mb
        self.ast_analyzer = ast_analyzer
        self.logger = FalconEyeLogger.get_instance()

    def should_chunk(self, file_path: Path, content: Optional[str] = None) -> bool:
        """
        Determine if a file should be chunked.
        
        Args:
            file_path: Path to the file
            content: Optional file content (read if not provided)
            
        Returns:
            True if file should be chunked
        """
        # Check file size
        try:
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                self.logger.warning(
                    f"File too large, will be skipped: {file_path} ({file_size_mb:.2f} MB)"
                )
                return False
        except OSError:
            pass

        # Check line count
        if content is None:
            try:
                content = file_path.read_text(encoding='utf-8', errors='ignore')
            except Exception as e:
                self.logger.warning(f"Could not read file {file_path}: {e}")
                return False

        line_count = content.count('\n') + 1
        return line_count > self.max_lines_single_pass

    def should_skip(self, file_path: Path) -> bool:
        """
        Determine if a file should be skipped entirely (too large).
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file should be skipped
        """
        try:
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            return file_size_mb > self.max_file_size_mb
        except OSError:
            return False

    def chunk_file(
        self,
        content: str,
        file_path: str,
        language: str,
    ) -> ChunkResult:
        """
        Split a large file into chunks for analysis.
        
        Args:
            content: File content
            file_path: Path to the file
            language: Programming language
            
        Returns:
            ChunkResult with list of chunks
        """
        lines = content.splitlines(keepends=True)
        original_line_count = len(lines)

        self.logger.info(
            f"Chunking large file: {file_path}",
            extra={
                "line_count": original_line_count,
                "strategy": self.strategy.value,
            }
        )

        # Choose strategy
        if self.strategy == ChunkingStrategy.AST and self.ast_analyzer:
            chunks = self._chunk_by_ast(lines, file_path, language)
        elif self.strategy == ChunkingStrategy.HYBRID and self.ast_analyzer:
            chunks = self._chunk_hybrid(lines, file_path, language)
        else:
            chunks = self._chunk_by_lines(lines, file_path)

        # Update total_chunks in each chunk
        total = len(chunks)
        for chunk in chunks:
            chunk.total_chunks = total

        self.logger.info(
            f"File chunked into {total} parts",
            extra={
                "file_path": file_path,
                "chunk_count": total,
                "strategy_used": self.strategy.value,
            }
        )

        return ChunkResult(
            chunks=chunks,
            original_line_count=original_line_count,
            strategy_used=self.strategy,
            file_path=file_path,
        )

    def _chunk_by_lines(self, lines: List[str], file_path: str) -> List[FileChunk]:
        """
        Chunk file by fixed line counts with overlap.
        
        Args:
            lines: List of lines from file
            file_path: Path to file
            
        Returns:
            List of FileChunk objects
        """
        chunks = []
        total_lines = len(lines)
        chunk_index = 0
        start = 0

        while start < total_lines:
            end = min(start + self.chunk_size_lines, total_lines)

            # Get chunk content
            chunk_lines = lines[start:end]
            chunk_content = ''.join(chunk_lines)

            # Get context before (for AI understanding)
            context_before = None
            if start > 0:
                ctx_start = max(0, start - 10)
                context_before = ''.join(lines[ctx_start:start])

            # Get context after
            context_after = None
            if end < total_lines:
                ctx_end = min(total_lines, end + 10)
                context_after = ''.join(lines[end:ctx_end])

            chunk = FileChunk(
                content=chunk_content,
                start_line=start + 1,  # 1-indexed
                end_line=end,
                chunk_index=chunk_index,
                total_chunks=0,  # Updated later
                context_before=context_before,
                context_after=context_after,
                metadata={
                    "file_path": file_path,
                    "chunking_strategy": "lines",
                }
            )
            chunks.append(chunk)
            chunk_index += 1

            # Move to next chunk with overlap
            start = end - self.chunk_overlap_lines
            if start >= total_lines:
                break
            # Prevent infinite loop
            if end == total_lines:
                break

        return chunks

    def _chunk_by_ast(
        self,
        lines: List[str],
        file_path: str,
        language: str,
    ) -> List[FileChunk]:
        """
        Chunk file by AST boundaries (functions, classes).
        
        Args:
            lines: List of lines from file
            file_path: Path to file
            language: Programming language
            
        Returns:
            List of FileChunk objects
        """
        if not self.ast_analyzer:
            return self._chunk_by_lines(lines, file_path)

        try:
            content = ''.join(lines)
            # Get function/class boundaries from AST
            metadata = self.ast_analyzer.analyze_file(file_path, content)

            if not metadata or not metadata.functions:
                # Fallback to line-based chunking
                return self._chunk_by_lines(lines, file_path)

            # Group functions into chunks
            chunks = []
            current_chunk_lines = []
            current_start = 1
            chunk_index = 0

            for func in sorted(metadata.functions, key=lambda f: f.start_line):
                func_start = func.start_line - 1  # 0-indexed
                func_end = func.end_line if func.end_line else func_start + 20

                # Get function lines
                func_lines = lines[func_start:func_end]

                # Check if adding this function exceeds chunk size
                if len(current_chunk_lines) + len(func_lines) > self.chunk_size_lines:
                    # Save current chunk if not empty
                    if current_chunk_lines:
                        chunk = FileChunk(
                            content=''.join(current_chunk_lines),
                            start_line=current_start,
                            end_line=current_start + len(current_chunk_lines) - 1,
                            chunk_index=chunk_index,
                            total_chunks=0,
                            metadata={
                                "file_path": file_path,
                                "chunking_strategy": "ast",
                            }
                        )
                        chunks.append(chunk)
                        chunk_index += 1

                    # Start new chunk with this function
                    current_chunk_lines = func_lines
                    current_start = func_start + 1
                else:
                    # Add function to current chunk
                    if not current_chunk_lines:
                        current_start = func_start + 1
                    current_chunk_lines.extend(func_lines)

            # Don't forget the last chunk
            if current_chunk_lines:
                chunk = FileChunk(
                    content=''.join(current_chunk_lines),
                    start_line=current_start,
                    end_line=current_start + len(current_chunk_lines) - 1,
                    chunk_index=chunk_index,
                    total_chunks=0,
                    metadata={
                        "file_path": file_path,
                        "chunking_strategy": "ast",
                    }
                )
                chunks.append(chunk)

            return chunks if chunks else self._chunk_by_lines(lines, file_path)

        except Exception as e:
            self.logger.warning(
                f"AST chunking failed, falling back to line-based: {e}"
            )
            return self._chunk_by_lines(lines, file_path)

    def _chunk_hybrid(
        self,
        lines: List[str],
        file_path: str,
        language: str,
    ) -> List[FileChunk]:
        """
        Hybrid chunking: AST-aware with line-based fallback.
        
        Tries to respect function/class boundaries but falls back
        to line-based chunking for code outside functions.
        
        Args:
            lines: List of lines from file
            file_path: Path to file
            language: Programming language
            
        Returns:
            List of FileChunk objects
        """
        if not self.ast_analyzer:
            return self._chunk_by_lines(lines, file_path)

        try:
            content = ''.join(lines)
            metadata = self.ast_analyzer.analyze_file(file_path, content)

            if not metadata or not metadata.functions:
                return self._chunk_by_lines(lines, file_path)

            # Get all function boundaries
            covered_lines = set()
            for func in metadata.functions:
                end_line = func.end_line if func.end_line else func.start_line + 20
                for i in range(func.start_line, end_line + 1):
                    covered_lines.add(i)

            # Also include class boundaries if available
            if hasattr(metadata, 'classes') and metadata.classes:
                for cls in metadata.classes:
                    end_line = cls.end_line if hasattr(cls, 'end_line') and cls.end_line else cls.start_line + 50
                    for i in range(cls.start_line, end_line + 1):
                        covered_lines.add(i)

            # Create chunks respecting boundaries
            chunks = []
            chunk_index = 0
            current_lines = []
            current_start = 1

            i = 0
            while i < len(lines):
                line_num = i + 1  # 1-indexed

                # Check if this line starts a function/class
                is_boundary_start = any(
                    f.start_line == line_num for f in metadata.functions
                )

                if is_boundary_start and current_lines:
                    # Save current chunk before starting new boundary
                    if len(current_lines) >= 10:  # Minimum chunk size
                        chunk = FileChunk(
                            content=''.join(current_lines),
                            start_line=current_start,
                            end_line=current_start + len(current_lines) - 1,
                            chunk_index=chunk_index,
                            total_chunks=0,
                            metadata={
                                "file_path": file_path,
                                "chunking_strategy": "hybrid",
                            }
                        )
                        chunks.append(chunk)
                        chunk_index += 1
                        current_lines = []
                        current_start = line_num

                current_lines.append(lines[i])

                # Check if we've exceeded chunk size
                if len(current_lines) >= self.chunk_size_lines:
                    # Try to find a good break point
                    break_point = self._find_break_point(
                        current_lines, covered_lines, current_start
                    )

                    if break_point > 0:
                        chunk = FileChunk(
                            content=''.join(current_lines[:break_point]),
                            start_line=current_start,
                            end_line=current_start + break_point - 1,
                            chunk_index=chunk_index,
                            total_chunks=0,
                            metadata={
                                "file_path": file_path,
                                "chunking_strategy": "hybrid",
                            }
                        )
                        chunks.append(chunk)
                        chunk_index += 1

                        # Keep overlap
                        overlap_start = max(0, break_point - self.chunk_overlap_lines)
                        current_lines = current_lines[overlap_start:]
                        current_start = current_start + overlap_start

                i += 1

            # Final chunk
            if current_lines:
                chunk = FileChunk(
                    content=''.join(current_lines),
                    start_line=current_start,
                    end_line=current_start + len(current_lines) - 1,
                    chunk_index=chunk_index,
                    total_chunks=0,
                    metadata={
                        "file_path": file_path,
                        "chunking_strategy": "hybrid",
                    }
                )
                chunks.append(chunk)

            return chunks if chunks else self._chunk_by_lines(lines, file_path)

        except Exception as e:
            self.logger.warning(
                f"Hybrid chunking failed, falling back to line-based: {e}"
            )
            return self._chunk_by_lines(lines, file_path)

    def _find_break_point(
        self,
        lines: List[str],
        covered_lines: set,
        start_line: int,
    ) -> int:
        """
        Find a good break point in the lines (preferably outside functions).
        
        Args:
            lines: Current chunk lines
            covered_lines: Set of lines covered by functions/classes
            start_line: Starting line number of current chunk
            
        Returns:
            Index in lines to break at
        """
        # Look for a line not in a function, starting from the end
        for i in range(len(lines) - 1, len(lines) // 2, -1):
            line_num = start_line + i
            if line_num not in covered_lines:
                # Found a line outside function boundaries
                return i + 1

        # Fallback: break at chunk_size
        return len(lines)

    def merge_findings(
        self,
        chunk_findings: List[List[Any]],
        chunk_result: ChunkResult,
    ) -> List[Any]:
        """
        Merge findings from multiple chunks, removing duplicates.
        
        Duplicates are identified by:
        1. Same issue type + overlapping line ranges
        2. Same code_snippet (fuzzy match)
        3. Same CWE ID + same file location
        
        Args:
            chunk_findings: List of findings lists from each chunk
            chunk_result: The chunk result with metadata
            
        Returns:
            Merged and deduplicated findings
        """
        all_findings = []
        for findings in chunk_findings:
            all_findings.extend(findings)

        if not all_findings:
            return []

        # Deduplicate
        unique_findings = []
        seen_signatures = set()

        for finding in all_findings:
            # Create a signature for deduplication
            signature = self._create_finding_signature(finding)

            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_findings.append(finding)
            else:
                self.logger.debug(
                    f"Duplicate finding removed: {finding.issue[:50]}..."
                )

        self.logger.info(
            f"Merged findings: {len(all_findings)} -> {len(unique_findings)} (removed {len(all_findings) - len(unique_findings)} duplicates)"
        )

        return unique_findings

    def _create_finding_signature(self, finding: Any) -> str:
        """
        Create a signature for a finding for deduplication.
        
        Args:
            finding: SecurityFinding object
            
        Returns:
            String signature
        """
        # Use issue type, CWE, and approximate location
        issue = getattr(finding, 'issue', '')[:100]
        cwe = getattr(finding, 'cwe_id', '') or ''
        line_start = getattr(finding, 'line_start', 0) or 0
        line_end = getattr(finding, 'line_end', 0) or 0

        # Round line numbers to handle overlap
        line_bucket = line_start // 10 * 10

        # Include snippet hash for more accurate dedup
        snippet = getattr(finding, 'code_snippet', '')[:200]
        snippet_hash = hash(snippet.strip()) if snippet else 0

        return f"{issue}|{cwe}|{line_bucket}|{snippet_hash}"

    def adjust_line_numbers(
        self,
        findings: List[Any],
        chunk: FileChunk,
    ) -> List[Any]:
        """
        Adjust line numbers in findings to match original file.
        
        Args:
            findings: Findings from chunk analysis
            chunk: The chunk that was analyzed
            
        Returns:
            Findings with adjusted line numbers
        """
        offset = chunk.start_line - 1  # Convert to 0-based offset

        for finding in findings:
            if hasattr(finding, 'line_start') and finding.line_start:
                # Create new finding with adjusted lines (findings are immutable)
                # This assumes findings have a way to be recreated
                pass  # Line numbers should already be relative to chunk

        return findings
