"""Result streaming for incremental output during analysis."""

from dataclasses import dataclass, field
from typing import Callable, Optional, List, Any, Dict
from pathlib import Path
from datetime import datetime
import threading
import time

from ...domain.models.security import SecurityFinding, SecurityReview, Severity
from ..logging import FalconEyeLogger


# Type alias for callback function
StreamingCallback = Callable[[SecurityFinding, str], None]


@dataclass
class FileProgress:
    """Progress information for a single file."""
    file_path: str
    status: str  # pending, analyzing, completed, failed
    findings_count: int = 0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class ScanProgress:
    """Overall scan progress information."""
    total_files: int
    files_completed: int = 0
    files_failed: int = 0
    files_with_findings: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    current_file: Optional[str] = None

    @property
    def files_remaining(self) -> int:
        return self.total_files - self.files_completed - self.files_failed

    @property
    def progress_percent(self) -> float:
        if self.total_files == 0:
            return 100.0
        return ((self.files_completed + self.files_failed) / self.total_files) * 100


class ResultStreamer:
    """
    Streams security findings as they are discovered.
    
    Instead of waiting for all files to be analyzed, this class
    allows findings to be output/saved immediately after each file
    is processed.
    """

    def __init__(
        self,
        output_file: Optional[Path] = None,
        callbacks: Optional[List[StreamingCallback]] = None,
        flush_interval: int = 1,
        incremental_save: bool = True,
    ):
        """
        Initialize result streamer.
        
        Args:
            output_file: Optional file to write results to
            callbacks: Optional list of callback functions to invoke on each finding
            flush_interval: Number of files to process before flushing results
            incremental_save: Whether to save results incrementally
        """
        self.output_file = output_file
        self.callbacks = callbacks or []
        self.flush_interval = flush_interval
        self.incremental_save = incremental_save

        self._findings: List[SecurityFinding] = []
        self._file_progress: Dict[str, FileProgress] = {}
        self._scan_progress: Optional[ScanProgress] = None
        self._lock = threading.Lock()
        self._files_since_flush = 0
        self._writer: Optional[Any] = None

        self.logger = FalconEyeLogger.get_instance()

    def on_scan_start(
        self,
        target_path: str,
        total_files: int,
        output_format: str = "json",
    ):
        """
        Called when a scan starts.
        
        Args:
            target_path: Path being scanned
            total_files: Total number of files to analyze
            output_format: Output format (json, html)
        """
        with self._lock:
            self._scan_progress = ScanProgress(
                total_files=total_files,
                started_at=datetime.now(),
                findings_by_severity={
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                }
            )
            self._findings = []
            self._file_progress = {}
            self._files_since_flush = 0

            # Initialize incremental writer
            if self.output_file and self.incremental_save:
                from .incremental_writer import IncrementalJSONWriter, IncrementalHTMLWriter

                if output_format == "html":
                    self._writer = IncrementalHTMLWriter(self.output_file)
                else:
                    self._writer = IncrementalJSONWriter(self.output_file)

                self._writer.write_header({
                    "target": target_path,
                    "started_at": self._scan_progress.started_at.isoformat(),
                    "total_files": total_files,
                })

            self.logger.info(
                "Scan started with streaming enabled",
                extra={
                    "target": target_path,
                    "total_files": total_files,
                    "incremental_save": self.incremental_save,
                }
            )

    def on_file_start(self, file_path: str):
        """
        Called when analysis of a file starts.
        
        Args:
            file_path: Path to the file being analyzed
        """
        with self._lock:
            self._file_progress[file_path] = FileProgress(
                file_path=file_path,
                status="analyzing",
                started_at=datetime.now(),
            )
            if self._scan_progress:
                self._scan_progress.current_file = file_path

    def on_finding(self, finding: SecurityFinding, file_path: str):
        """
        Called when a new finding is discovered.
        
        Args:
            finding: The security finding
            file_path: Path to the file where finding was discovered
        """
        with self._lock:
            self._findings.append(finding)

            # Update progress
            if self._scan_progress:
                self._scan_progress.total_findings += 1
                severity = finding.severity.value
                self._scan_progress.findings_by_severity[severity] = \
                    self._scan_progress.findings_by_severity.get(severity, 0) + 1

            # Update file progress
            if file_path in self._file_progress:
                self._file_progress[file_path].findings_count += 1

            # Invoke callbacks
            for callback in self.callbacks:
                try:
                    callback(finding, file_path)
                except Exception as e:
                    self.logger.warning(f"Streaming callback failed: {e}")

    def on_file_complete(
        self,
        file_path: str,
        findings: List[SecurityFinding],
        error: Optional[str] = None,
    ):
        """
        Called when a file analysis is complete.
        
        Args:
            file_path: Path to the analyzed file
            findings: All findings from this file
            error: Optional error message if analysis failed
        """
        with self._lock:
            # Update file progress
            if file_path in self._file_progress:
                progress = self._file_progress[file_path]
                progress.status = "failed" if error else "completed"
                progress.completed_at = datetime.now()
                progress.findings_count = len(findings)
                progress.error = error

            # Update scan progress
            if self._scan_progress:
                if error:
                    self._scan_progress.files_failed += 1
                else:
                    self._scan_progress.files_completed += 1
                    if findings:
                        self._scan_progress.files_with_findings += 1

                self._scan_progress.current_file = None

            # Add findings (avoiding duplicates)
            for finding in findings:
                if finding not in self._findings:
                    self._findings.append(finding)
                    if self._scan_progress:
                        self._scan_progress.total_findings += 1
                        severity = finding.severity.value
                        self._scan_progress.findings_by_severity[severity] = \
                            self._scan_progress.findings_by_severity.get(severity, 0) + 1

            self._files_since_flush += 1

            # Flush if interval reached
            if self._files_since_flush >= self.flush_interval:
                self._flush()

            self.logger.info(
                f"File analysis complete: {Path(file_path).name}",
                extra={
                    "file_path": file_path,
                    "findings_count": len(findings),
                    "error": error,
                }
            )

    def _flush(self):
        """Flush buffered findings to output."""
        if not self._writer or not self._findings:
            self._files_since_flush = 0
            return

        try:
            # Write new findings since last flush
            self._writer.write_findings(self._findings)
            self._writer.update_progress(self.get_progress())
            self._files_since_flush = 0
        except Exception as e:
            self.logger.error(f"Failed to flush results: {e}")

    def on_scan_complete(self) -> SecurityReview:
        """
        Called when the entire scan is complete.
        
        Returns:
            Complete SecurityReview with all findings
        """
        with self._lock:
            # Final flush
            if self._writer:
                self._writer.write_findings(self._findings)
                self._writer.write_footer({
                    "completed_at": datetime.now().isoformat(),
                    "total_findings": len(self._findings),
                    "files_analyzed": self._scan_progress.files_completed if self._scan_progress else 0,
                    "files_failed": self._scan_progress.files_failed if self._scan_progress else 0,
                })
                self._writer.finalize()

            # Create final review
            review = SecurityReview.create(
                codebase_path=self._scan_progress.current_file if self._scan_progress else "",
                language="mixed",
            )
            for finding in self._findings:
                review.add_finding(finding)

            if self._scan_progress:
                review.files_analyzed = self._scan_progress.files_completed

            review.complete()

            self.logger.info(
                "Scan complete",
                extra={
                    "total_findings": len(self._findings),
                    "files_completed": self._scan_progress.files_completed if self._scan_progress else 0,
                    "files_failed": self._scan_progress.files_failed if self._scan_progress else 0,
                }
            )

            return review

    def get_progress(self) -> Dict[str, Any]:
        """
        Get current scan progress.
        
        Returns:
            Dictionary with progress information
        """
        with self._lock:
            if not self._scan_progress:
                return {}

            return {
                "total_files": self._scan_progress.total_files,
                "files_completed": self._scan_progress.files_completed,
                "files_failed": self._scan_progress.files_failed,
                "files_remaining": self._scan_progress.files_remaining,
                "progress_percent": round(self._scan_progress.progress_percent, 1),
                "total_findings": self._scan_progress.total_findings,
                "findings_by_severity": self._scan_progress.findings_by_severity,
                "current_file": self._scan_progress.current_file,
            }

    def get_findings(self) -> List[SecurityFinding]:
        """
        Get all findings collected so far.
        
        Returns:
            List of security findings
        """
        with self._lock:
            return list(self._findings)

    def add_callback(self, callback: StreamingCallback):
        """
        Add a callback to be invoked on each finding.
        
        Args:
            callback: Callback function
        """
        with self._lock:
            self.callbacks.append(callback)
