"""Incremental file writers for streaming results."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import threading

from ...domain.models.security import SecurityFinding
from ..logging import FalconEyeLogger


class IncrementalWriter(ABC):
    """Base class for incremental file writers."""

    def __init__(self, output_file: Path):
        """
        Initialize writer.
        
        Args:
            output_file: Path to output file
        """
        self.output_file = output_file
        self.logger = FalconEyeLogger.get_instance()
        self._lock = threading.Lock()
        self._written_finding_ids: set = set()

    @abstractmethod
    def write_header(self, scan_info: Dict[str, Any]):
        """Write the header/opening of the output file."""
        pass

    @abstractmethod
    def write_findings(self, findings: List[SecurityFinding]):
        """Write findings to the output file."""
        pass

    @abstractmethod
    def update_progress(self, progress: Dict[str, Any]):
        """Update progress information in the output file."""
        pass

    @abstractmethod
    def write_footer(self, summary: Dict[str, Any]):
        """Write the footer/closing of the output file."""
        pass

    @abstractmethod
    def finalize(self):
        """Finalize the output file."""
        pass


class IncrementalJSONWriter(IncrementalWriter):
    """
    Writes JSON output incrementally.
    
    Maintains a valid JSON structure at all times by keeping
    the file structure in memory and rewriting on each update.
    For very large scans, consider using JSON Lines format instead.
    """

    def __init__(self, output_file: Path):
        super().__init__(output_file)
        self._data = {
            "scan_info": {},
            "progress": {},
            "findings": [],
        }
        self._initialized = False

    def write_header(self, scan_info: Dict[str, Any]):
        """Write the header with scan information."""
        with self._lock:
            self._data["scan_info"] = {
                **scan_info,
                "status": "in_progress",
            }
            self._data["progress"] = {
                "files_total": scan_info.get("total_files", 0),
                "files_completed": 0,
                "files_with_findings": 0,
            }
            self._data["findings"] = []
            self._write_file()
            self._initialized = True

    def write_findings(self, findings: List[SecurityFinding]):
        """Append new findings to the output."""
        with self._lock:
            for finding in findings:
                finding_id = str(finding.id)
                if finding_id not in self._written_finding_ids:
                    self._written_finding_ids.add(finding_id)
                    self._data["findings"].append(finding.to_dict())

            self._write_file()

    def update_progress(self, progress: Dict[str, Any]):
        """Update progress information."""
        with self._lock:
            self._data["progress"] = {
                "files_total": progress.get("total_files", 0),
                "files_completed": progress.get("files_completed", 0),
                "files_failed": progress.get("files_failed", 0),
                "files_with_findings": progress.get("files_with_findings", 0),
                "progress_percent": progress.get("progress_percent", 0),
                "current_file": progress.get("current_file"),
            }
            self._write_file()

    def write_footer(self, summary: Dict[str, Any]):
        """Write the footer with summary information."""
        with self._lock:
            self._data["scan_info"]["status"] = "completed"
            self._data["scan_info"]["completed_at"] = summary.get("completed_at")
            self._data["summary"] = {
                "total_findings": summary.get("total_findings", len(self._data["findings"])),
                "files_analyzed": summary.get("files_analyzed", 0),
                "files_failed": summary.get("files_failed", 0),
                "duration_seconds": self._calculate_duration(),
            }
            self._write_file()

    def finalize(self):
        """Finalize the JSON file."""
        with self._lock:
            self._write_file()
            self.logger.info(f"JSON results finalized: {self.output_file}")

    def _write_file(self):
        """Write the current data to file."""
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self._data, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to write JSON file: {e}")

    def _calculate_duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        try:
            started = self._data["scan_info"].get("started_at")
            completed = self._data["scan_info"].get("completed_at")
            if started and completed:
                start_dt = datetime.fromisoformat(started)
                end_dt = datetime.fromisoformat(completed)
                return (end_dt - start_dt).total_seconds()
        except Exception:
            pass
        return None


class IncrementalHTMLWriter(IncrementalWriter):
    """
    Writes HTML output incrementally.
    
    Uses a template-based approach where findings are appended
    to a specific section of the HTML file.
    """

    def __init__(self, output_file: Path):
        super().__init__(output_file)
        self._scan_info: Dict[str, Any] = {}
        self._findings: List[Dict[str, Any]] = []
        self._progress: Dict[str, Any] = {}

    def write_header(self, scan_info: Dict[str, Any]):
        """Write the HTML header."""
        with self._lock:
            self._scan_info = scan_info
            self._findings = []
            self._write_html()

    def write_findings(self, findings: List[SecurityFinding]):
        """Append new findings to the HTML."""
        with self._lock:
            for finding in findings:
                finding_id = str(finding.id)
                if finding_id not in self._written_finding_ids:
                    self._written_finding_ids.add(finding_id)
                    self._findings.append(finding.to_dict())

            self._write_html()

    def update_progress(self, progress: Dict[str, Any]):
        """Update progress in the HTML."""
        with self._lock:
            self._progress = progress
            self._write_html()

    def write_footer(self, summary: Dict[str, Any]):
        """Write the HTML footer with summary."""
        with self._lock:
            self._scan_info["status"] = "completed"
            self._scan_info["completed_at"] = summary.get("completed_at")
            self._scan_info["summary"] = summary
            self._write_html()

    def finalize(self):
        """Finalize the HTML file."""
        with self._lock:
            self._write_html()
            self.logger.info(f"HTML results finalized: {self.output_file}")

    def _write_html(self):
        """Write the current data to HTML file."""
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)

            # Count findings by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for finding in self._findings:
                severity = finding.get("severity", "info")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            html_content = self._generate_html(severity_counts)

            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to write HTML file: {e}")

    def _generate_html(self, severity_counts: Dict[str, int]) -> str:
        """Generate the HTML content."""
        status = self._scan_info.get("status", "in_progress")
        status_color = "#28a745" if status == "completed" else "#ffc107"
        status_text = "Complete" if status == "completed" else "In Progress"

        findings_html = self._generate_findings_html()
        progress_percent = self._progress.get("progress_percent", 0)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
    <title>FalconEYE Security Report - Live</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%); padding: 30px; border-radius: 12px; margin-bottom: 20px; border: 1px solid #30363d; }}
        .header h1 {{ color: #58a6ff; font-size: 2em; margin-bottom: 10px; }}
        .status {{ display: inline-block; padding: 5px 15px; border-radius: 20px; background: {status_color}; color: white; font-weight: bold; }}
        .progress-bar {{ background: #21262d; border-radius: 10px; height: 20px; margin: 20px 0; overflow: hidden; }}
        .progress-fill {{ background: linear-gradient(90deg, #238636, #2ea043); height: 100%; transition: width 0.3s; width: {progress_percent}%; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #161b22; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #30363d; }}
        .stat-card.critical {{ border-left: 4px solid #f85149; }}
        .stat-card.high {{ border-left: 4px solid #db6d28; }}
        .stat-card.medium {{ border-left: 4px solid #d29922; }}
        .stat-card.low {{ border-left: 4px solid #3fb950; }}
        .stat-value {{ font-size: 2em; font-weight: bold; color: #58a6ff; }}
        .stat-label {{ color: #8b949e; font-size: 0.9em; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ background: #161b22; border-radius: 8px; padding: 20px; margin-bottom: 15px; border: 1px solid #30363d; }}
        .finding.critical {{ border-left: 4px solid #f85149; }}
        .finding.high {{ border-left: 4px solid #db6d28; }}
        .finding.medium {{ border-left: 4px solid #d29922; }}
        .finding.low {{ border-left: 4px solid #3fb950; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
        .finding-title {{ font-size: 1.1em; font-weight: bold; color: #c9d1d9; }}
        .severity-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #f85149; color: white; }}
        .severity-badge.high {{ background: #db6d28; color: white; }}
        .severity-badge.medium {{ background: #d29922; color: black; }}
        .severity-badge.low {{ background: #3fb950; color: black; }}
        .finding-file {{ color: #8b949e; font-size: 0.9em; margin-bottom: 10px; }}
        .finding-description {{ color: #c9d1d9; margin-bottom: 15px; }}
        .code-block {{ background: #0d1117; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Fira Code', monospace; font-size: 0.9em; border: 1px solid #30363d; }}
        .mitigation {{ background: #1c2128; padding: 15px; border-radius: 6px; margin-top: 10px; border-left: 3px solid #3fb950; }}
        .mitigation-title {{ color: #3fb950; font-weight: bold; margin-bottom: 5px; }}
        .live-indicator {{ display: inline-flex; align-items: center; gap: 8px; }}
        .live-dot {{ width: 10px; height: 10px; background: #3fb950; border-radius: 50%; animation: pulse 2s infinite; }}
        @keyframes pulse {{ 0%, 100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
        .no-findings {{ text-align: center; padding: 50px; color: #8b949e; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🦅 FalconEYE Security Report</h1>
            <p>Target: <strong>{self._scan_info.get('target', 'Unknown')}</strong></p>
            <p>Started: {self._scan_info.get('started_at', 'Unknown')}</p>
            <div style="margin-top: 15px;">
                <span class="status">{status_text}</span>
                {f'<span class="live-indicator" style="margin-left: 15px;"><span class="live-dot"></span> Live Updates</span>' if status != 'completed' else ''}
            </div>
        </div>

        <div class="progress-bar">
            <div class="progress-fill"></div>
        </div>
        <p style="text-align: center; color: #8b949e;">
            {self._progress.get('files_completed', 0)} / {self._progress.get('total_files', 0)} files analyzed
            ({progress_percent:.1f}%)
        </p>

        <div class="stats">
            <div class="stat-card critical">
                <div class="stat-value">{severity_counts.get('critical', 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{severity_counts.get('high', 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{severity_counts.get('medium', 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{severity_counts.get('low', 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <div class="findings">
            <h2 style="margin-bottom: 20px; color: #c9d1d9;">Findings ({len(self._findings)})</h2>
            {findings_html if findings_html else '<div class="no-findings">No findings yet...</div>'}
        </div>
    </div>
</body>
</html>"""

    def _generate_findings_html(self) -> str:
        """Generate HTML for all findings."""
        if not self._findings:
            return ""

        html_parts = []
        for finding in self._findings:
            severity = finding.get("severity", "info")
            code_snippet = finding.get("code_snippet", "").replace("<", "&lt;").replace(">", "&gt;")
            file_path = finding.get("file_path", "Unknown")
            line_start = finding.get("line_start", "?")
            line_end = finding.get("line_end", "?")

            html_parts.append(f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <span class="finding-title">{finding.get('issue', 'Unknown Issue')}</span>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-file">📁 {file_path} (lines {line_start}-{line_end})</div>
                <div class="finding-description">{finding.get('reasoning', '')}</div>
                {f'<div class="code-block"><pre>{code_snippet}</pre></div>' if code_snippet else ''}
                <div class="mitigation">
                    <div class="mitigation-title">💡 Mitigation</div>
                    {finding.get('mitigation', 'No mitigation provided')}
                </div>
            </div>
            """)

        return "\n".join(html_parts)
