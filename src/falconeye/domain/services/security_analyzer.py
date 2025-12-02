"""Security analyzer domain service."""

from typing import List
import json
import time
from ..models.security import SecurityFinding, Severity, FindingConfidence
from ..models.prompt import PromptContext
from .llm_service import LLMService
from ..exceptions import AnalysisError, InvalidSecurityFindingError
from ...infrastructure.logging import FalconEyeLogger


class SecurityAnalyzer:
    """
    Domain service for security analysis.

    This service orchestrates AI-powered security analysis.
    CRITICAL: ALL analysis is done by AI, NO pattern matching.
    """

    def __init__(self, llm_service: LLMService):
        """
        Initialize security analyzer.

        Args:
            llm_service: LLM service for AI analysis
        """
        self.llm_service = llm_service
        self.logger = FalconEyeLogger.get_instance()

    async def analyze_code(
        self,
        context: PromptContext,
        system_prompt: str,
    ) -> List[SecurityFinding]:
        """
        Analyze code for security vulnerabilities using AI.

        This method sends code to the LLM and parses security findings.
        NO pattern matching - pure AI reasoning.

        Args:
            context: Code context with metadata
            system_prompt: Instructions for the AI

        Returns:
            List of security findings identified by AI

        Raises:
            AnalysisError: If AI analysis fails
        """
        start_time = time.time()

        # Log start
        self.logger.info(
            "Starting security analysis",
            extra={
                "file_path": context.file_path,
                "language": context.language,
                "code_size": len(context.code_snippet),
            }
        )

        try:
            # Get AI analysis
            raw_response = await self.llm_service.analyze_code_security(
                context=context,
                system_prompt=system_prompt,
            )

            # Parse AI response into findings
            findings = self._parse_findings(raw_response, context.file_path)
            
            # Enhance findings with line numbers and context
            findings = self._enhance_findings_with_context(findings, context)

            # Calculate duration
            duration = time.time() - start_time

            # Group findings by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Log completion
            self.logger.info(
                "Security analysis completed",
                extra={
                    "file_path": context.file_path,
                    "findings_count": len(findings),
                    "severity_counts": severity_counts,
                    "duration_seconds": round(duration, 2),
                }
            )

            return findings

        except InvalidSecurityFindingError as e:
            duration = time.time() - start_time
            
            # Save problematic response for debugging
            debug_file = f"/tmp/falconeye_failed_response_{int(time.time())}.txt"
            try:
                with open(debug_file, 'w') as f:
                    f.write(f"File: {context.file_path}\n")
                    f.write(f"Error: {str(e)}\n")
                    f.write(f"\n{'='*80}\n")
                    f.write(f"AI Response:\n")
                    f.write(f"{'='*80}\n")
                    f.write(raw_response)
            except Exception:
                pass  # Don't fail if we can't save debug file
            
            self.logger.error(
                "Failed to parse AI response",
                extra={
                    "file_path": context.file_path,
                    "error": str(e),
                    "duration_seconds": round(duration, 2),
                    "debug_file": debug_file,
                    "hint": f"Check {debug_file} for the problematic AI response"
                },
                exc_info=True
            )
            self.logger.warning(
                f"Skipping file due to unparseable AI response. "
                f"Debug info saved to: {debug_file}"
            )
            # Return empty findings instead of crashing
            return []

        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(
                "Security analysis failed",
                extra={
                    "file_path": context.file_path,
                    "error": str(e),
                    "duration_seconds": round(duration, 2),
                },
                exc_info=True
            )
            raise AnalysisError(f"AI analysis failed: {str(e)}") from e

    async def validate_findings(
        self,
        findings: List[SecurityFinding],
        context: PromptContext,
    ) -> List[SecurityFinding]:
        """
        Use AI to validate findings and filter false positives.

        The AI re-evaluates each finding to ensure it's a genuine issue.
        NO pattern-based filtering - AI makes all decisions.

        Args:
            findings: Initial findings to validate
            context: Original code context

        Returns:
            Validated findings (false positives removed by AI)
        """
        if not findings:
            return []

        # Prepare findings for AI validation
        findings_json = json.dumps([
            {
                "issue": f.issue,
                "reasoning": f.reasoning,
                "code_snippet": f.code_snippet,
                "severity": f.severity.value,
            }
            for f in findings
        ])

        # Ask AI to validate
        validated_response = await self.llm_service.validate_findings(
            code_snippet=context.code_snippet,
            findings=findings_json,
            context=context.format_for_ai(),
        )

        # Parse validated findings
        validated = self._parse_findings(validated_response, context.file_path)
        return validated

    def _parse_findings(
        self,
        ai_response: str,
        file_path: str,
    ) -> List[SecurityFinding]:
        """
        Parse AI response into SecurityFinding objects.

        The AI returns findings in JSON format. This method just parses them.
        NO analysis or pattern matching happens here.

        Args:
            ai_response: Raw AI response (JSON)
            file_path: File being analyzed

        Returns:
            List of SecurityFinding objects

        Raises:
            InvalidSecurityFindingError: If AI response is malformed
        """
        try:
            # Try to extract JSON from response
            data = self._extract_json(ai_response)

            if not data:
                # AI found no issues
                return []

            # Handle different response formats
            # Check if data itself is a list (direct array response)
            if isinstance(data, list):
                reviews = data
            else:
                # Data is an object, extract reviews array
                reviews = data.get("reviews", [])
                if not reviews:
                    # Maybe the object itself is a single review
                    if "issue" in data:
                        reviews = [data]

            findings = []
            for review in reviews:
                try:
                    finding = SecurityFinding.create(
                        issue=review.get("issue", "Unknown issue"),
                        reasoning=review.get("reasoning", ""),
                        mitigation=review.get("mitigation", ""),
                        severity=self._parse_severity(review.get("severity", "medium")),
                        confidence=self._parse_confidence(review.get("confidence", 0.7)),
                        file_path=file_path,
                        code_snippet=review.get("code_snippet", ""),
                        line_start=review.get("line_start"),
                        line_end=review.get("line_end"),
                        cwe_id=review.get("cwe_id"),
                        tags=review.get("tags", []),
                    )
                    findings.append(finding)
                except Exception as e:
                    # Log but don't fail on single malformed finding
                    self.logger.warning(
                        "Skipping malformed finding",
                        extra={
                            "file_path": file_path,
                            "error": str(e),
                            "review_data": review,
                        }
                    )
                    continue

            return findings

        except json.JSONDecodeError as e:
            # Save problematic response to debug file
            import tempfile
            import time
            
            debug_file = tempfile.gettempdir() + f"/falconeye_failed_response_{int(time.time())}.txt"
            try:
                with open(debug_file, 'w') as f:
                    f.write(f"File: {file_path}\n")
                    f.write(f"Error: {str(e)}\n")
                    f.write(f"Response length: {len(ai_response) if ai_response else 0}\n")
                    f.write("="*80 + "\n")
                    f.write(ai_response or "(empty response)")
                self.logger.error(
                    f"Failed to parse AI response. Debug file saved to: {debug_file}"
                )
            except Exception as write_error:
                self.logger.error(f"Could not save debug file: {write_error}")
            
            raise InvalidSecurityFindingError(
                f"AI response is not valid JSON: {str(e)}. "
                f"Response length: {len(ai_response) if ai_response else 0}. "
                f"Debug file: {debug_file if 'debug_file' in locals() else 'N/A'}"
            ) from e
        except Exception as e:
            raise InvalidSecurityFindingError(
                f"Failed to parse AI findings: {str(e)}"
            ) from e

    def _extract_json(self, text: str) -> dict:
        """
        Extract JSON from AI response.

        AI might wrap JSON in markdown code blocks or include explanatory text.
        
        Args:
            text: Raw AI response text
            
        Returns:
            Parsed JSON object
            
        Raises:
            json.JSONDecodeError: If no valid JSON found
        """
        import re
        
        # Handle empty or None responses
        if not text or not text.strip():
            self.logger.warning("Received empty AI response")
            return {"reviews": []}
        
        # Try to find JSON in markdown code block
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("""`""", start)
            if end == -1:
                end = len(text)
            json_text = text[start:end].strip()
            try:
                return json.loads(json_text)
            except json.JSONDecodeError:
                # Try to fix common JSON issues
                json_text = self._fix_json(json_text)
                return json.loads(json_text)

        # Try to extract JSON object/array from text FIRST
        # (before checking code blocks, since ``` might be inside JSON strings)
        # Find the first { or [ and try to parse from there
        for start_char in ['{', '[']:
            start_idx = text.find(start_char)
            if start_idx == -1:
                continue
            
            # Try to find the matching closing bracket
            json_text = text[start_idx:]
            
            # Remove trailing non-JSON characters
            while json_text and json_text[-1] not in ('}', ']'):
                json_text = json_text[:-1].strip()
            
            if not json_text:
                continue
                
            try:
                # Try parsing directly first
                return json.loads(json_text)
            except json.JSONDecodeError:
                # Try fixing common issues
                try:
                    fixed_json = self._fix_json(json_text)
                    return json.loads(fixed_json)
                except json.JSONDecodeError:
                    # This attempt failed, try next start character
                    continue

        # Try to find JSON in code block as last resort
        # (only if JSON wasn't found at the start of the text)
        if "```" in text:
            start = text.find("```") + 3
            # Skip language identifier if present (e.g., ```json)
            newline_after_start = text.find('\n', start)
            if newline_after_start != -1 and newline_after_start - start < 20:
                start = newline_after_start + 1
            
            end = text.find("```", start)
            if end == -1:
                end = len(text)
            json_text = text[start:end].strip()
            
            if json_text:
                try:
                    return json.loads(json_text)
                except json.JSONDecodeError:
                    json_text = self._fix_json(json_text)
                    return json.loads(json_text)

        # Try parsing the whole response as last resort
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            json_text = self._fix_json(text)
            return json.loads(json_text)

    def _fix_json(self, json_text: str) -> str:
        """
        Attempt to fix common JSON formatting issues.
        
        Args:
            json_text: Potentially malformed JSON string
            
        Returns:
            Fixed JSON string
        """
        import re
        
        # Fix invalid escape sequences (e.g., \U, \u followed by invalid hex, etc.)
        # Replace invalid escapes with escaped backslashes
        def fix_escape_sequences(text: str) -> str:
            """Fix invalid escape sequences in JSON strings."""
            result = []
            i = 0
            in_string = False
            escape_count = 0
            
            while i < len(text):
                char = text[i]
                
                # Track if we're inside a string (handle escaped quotes properly)
                if char == '"':
                    # Count preceding backslashes
                    num_backslashes = 0
                    j = i - 1
                    while j >= 0 and text[j] == '\\':
                        num_backslashes += 1
                        j -= 1
                    
                    # If even number of backslashes (or zero), this quote is not escaped
                    if num_backslashes % 2 == 0:
                        in_string = not in_string
                    
                    result.append(char)
                    i += 1
                    continue
                
                # Only process escapes inside strings
                if in_string and char == '\\' and i + 1 < len(text):
                    next_char = text[i + 1]
                    
                    # Valid JSON escape sequences: " \ / b f n r t u
                    if next_char in ('"', '\\', '/', 'b', 'f', 'n', 'r', 't'):
                        result.append(char)
                        i += 1
                    elif next_char == 'u':
                        # Check if it's a valid unicode escape (4 hex digits)
                        if i + 5 < len(text) and all(c in '0123456789abcdefABCDEF' for c in text[i+2:i+6]):
                            result.append(char)
                            i += 1
                        else:
                            # Invalid unicode escape, escape the backslash
                            result.append('\\\\')
                            i += 1
                    else:
                        # Invalid escape sequence, escape the backslash
                        result.append('\\\\')
                        i += 1
                else:
                    result.append(char)
                    i += 1
            
            return ''.join(result)
        
        json_text = fix_escape_sequences(json_text)
        
        # Additional aggressive fix: replace common problematic patterns
        # Fix Windows-style paths (C:\Users\...) 
        json_text = re.sub(r'([A-Z]):\\', r'\1:\\\\', json_text)
        
        # Fix any remaining single backslashes before common characters
        # This is aggressive but necessary for AI-generated content
        json_text = re.sub(r'\\([^"\\/bfnrtu])', r'\\\\\\1', json_text)
        
        # Fix unescaped quotes within strings (common AI error)
        # This is a more aggressive approach that looks for patterns like ["key"]
        def fix_unescaped_quotes(text: str) -> str:
            """Fix unescaped quotes within JSON string values."""
            import re
            
            # Fix quotes in patterns like $var["key"] or $_GET["cmd"]
            # Use a callback to properly escape
            def escape_array_access(match):
                prefix = match.group(1)  # $var[
                key = match.group(2)      # the key
                return prefix + '\\"' + key + '\\"]'
            
            text = re.sub(r'(\$[\w_]+\[)"([^"]+)"\]', escape_array_access, text)
            
            # Also handle single quotes
            def escape_array_access_single(match):
                prefix = match.group(1)
                key = match.group(2)
                return prefix + "\\'" + key + "\\']"
            
            text = re.sub(r"(\$[\w_]+\[)'([^']+)'\]", escape_array_access_single, text)
            
            return text
        
        json_text = fix_unescaped_quotes(json_text)
        
        # Remove trailing commas before closing braces/brackets
        json_text = re.sub(r',\s*([}\]])', r'\1', json_text)
        
        # Remove any trailing content after final closing brace/bracket
        json_text = json_text.strip()
        if json_text.startswith('{'):
            # Find the last closing brace
            last_brace = json_text.rfind('}')
            if last_brace != -1:
                json_text = json_text[:last_brace + 1]
        elif json_text.startswith('['):
            # Find the last closing bracket
            last_bracket = json_text.rfind(']')
            if last_bracket != -1:
                json_text = json_text[:last_bracket + 1]
        
        return json_text

    def _enhance_findings_with_context(
        self,
        findings: List[SecurityFinding],
        context: PromptContext,
    ) -> List[SecurityFinding]:
        """
        Enhance findings with accurate line numbers and expanded code context.
        
        Args:
            findings: List of findings to enhance
            context: Original code context
            
        Returns:
            Enhanced findings with line numbers and context
        """
        from pathlib import Path
        
        enhanced_findings = []
        
        # Read the full file content
        try:
            file_path = Path(context.file_path)
            if not file_path.exists():
                return findings
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_lines = f.readlines()
        except Exception as e:
            self.logger.warning(
                f"Could not read file for context enhancement: {e}",
                extra={"file_path": context.file_path}
            )
            return findings
        
        for finding in findings:
            # Try to find the code snippet in the file and extract line numbers
            line_start, line_end = self._find_snippet_location(
                finding.code_snippet,
                file_lines
            )
            
            # If we found the location, expand the context
            if line_start is not None:
                context_snippet = self._extract_context_snippet(
                    file_lines,
                    line_start,
                    line_end or line_start,
                    context_lines=4
                )
                
                # Create enhanced finding
                enhanced_finding = SecurityFinding.create(
                    issue=finding.issue,
                    reasoning=finding.reasoning,
                    mitigation=finding.mitigation,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    file_path=finding.file_path,
                    code_snippet=context_snippet,
                    line_start=line_start,
                    line_end=line_end or line_start,
                    cwe_id=finding.cwe_id,
                    tags=finding.tags,
                )
                enhanced_findings.append(enhanced_finding)
            else:
                # Keep original finding if we couldn't locate it
                enhanced_findings.append(finding)
        
        return enhanced_findings

    def _find_snippet_location(
        self,
        snippet: str,
        file_lines: List[str],
    ) -> tuple[int | None, int | None]:
        """
        Find the line numbers where a code snippet appears in the file.
        
        Args:
            snippet: Code snippet to find
            file_lines: Lines of the file
            
        Returns:
            Tuple of (line_start, line_end) or (None, None) if not found
        """
        if not snippet or not file_lines:
            return None, None
        
        # Clean the snippet (remove line numbers if present, trim whitespace)
        snippet_lines = []
        for line in snippet.strip().splitlines():
            # Remove line numbers like "  123 | code"
            cleaned = line.strip()
            if '|' in cleaned and cleaned.split('|')[0].strip().isdigit():
                cleaned = '|'.join(cleaned.split('|')[1:]).strip()
            snippet_lines.append(cleaned)
        
        if not snippet_lines:
            return None, None
        
        # Search for the snippet in the file
        for i in range(len(file_lines)):
            # Try to match starting from this line
            match = True
            for j, snippet_line in enumerate(snippet_lines):
                if i + j >= len(file_lines):
                    match = False
                    break
                
                file_line = file_lines[i + j].strip()
                if snippet_line and snippet_line not in file_line:
                    match = False
                    break
            
            if match:
                # Found it! Return 1-indexed line numbers
                return i + 1, i + len(snippet_lines)
        
        return None, None

    def _extract_context_snippet(
        self,
        file_lines: List[str],
        line_start: int,
        line_end: int,
        context_lines: int = 4,
    ) -> str:
        """
        Extract code snippet with surrounding context lines.
        
        Args:
            file_lines: All lines from the file
            line_start: Starting line number (1-indexed)
            line_end: Ending line number (1-indexed)
            context_lines: Number of context lines before and after
            
        Returns:
            Code snippet with context and line numbers
        """
        # Convert to 0-indexed
        start_idx = max(0, line_start - 1 - context_lines)
        end_idx = min(len(file_lines), line_end + context_lines)
        
        # Extract lines with line numbers
        snippet_lines = []
        for i in range(start_idx, end_idx):
            line_num = i + 1
            line_content = file_lines[i].rstrip()
            
            # Mark the actual finding lines
            if line_start <= line_num <= line_end:
                snippet_lines.append(f"{line_num:4d} > {line_content}")
            else:
                snippet_lines.append(f"{line_num:4d} | {line_content}")
        
        return "\n".join(snippet_lines)

    def _parse_severity(self, severity: str) -> Severity:
        """Parse severity string to Severity enum."""
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        return severity_map.get(severity.lower(), Severity.MEDIUM)

    def _parse_confidence(self, confidence: float) -> FindingConfidence:
        """Parse confidence float to FindingConfidence enum."""
        if confidence >= 0.8:
            return FindingConfidence.HIGH
        elif confidence >= 0.5:
            return FindingConfidence.MEDIUM
        else:
            return FindingConfidence.LOW