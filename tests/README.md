# FalconEYE Test Suite

This directory contains the test suite for FalconEYE v2.0.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and test utilities
├── unit/                    # Unit tests (no external dependencies)
├── integration/            # Integration tests (require Ollama)
│   └── test_large_file.py  # Large file handling tests
└── fixtures/               # Test data and fixtures
```

## Running Tests

### Prerequisites

For **integration tests**, ensure you have:
1. Ollama running: `ollama serve`
2. Required models pulled:
   ```bash
   ollama pull qwen3-coder:30b
   ollama pull embeddinggemma:300m
   ```

### Run All Tests

```bash
# Run all tests (unit + integration)
pytest

# Run with verbose output
pytest -v

# Run with output from print statements
pytest -v -s
```

### Run Specific Test Types

```bash
# Unit tests only (fast, no Ollama needed)
pytest -m unit

# Integration tests only (requires Ollama)
pytest -m integration

# Run specific test file
pytest tests/integration/test_large_file.py -v

# Run specific test class
pytest tests/integration/test_large_file.py::TestLargeFileIndexing -v

# Run specific test
pytest tests/integration/test_large_file.py::TestLargeFileIndexing::test_adaptive_chunking_5000_lines -v
```

### Skip Slow Tests

Some integration tests are marked as `@pytest.mark.slow` because they take several minutes:

```bash
# Skip slow tests
pytest -m "integration and not slow"
```

## Test Coverage

### Large File Tests (`test_large_file.py`)

Tests for handling files with 5000+ lines:

#### `TestLargeFileIndexing`
- ✅ **test_adaptive_chunking_5000_lines**: Verifies adaptive chunking for 5K line files
- ✅ **test_adaptive_chunking_10000_lines**: Verifies maximum chunk size (200 lines) for 10K+ files
- ✅ **test_prompt_truncation_15000_lines**: Tests truncation at 10K line limit
- ✅ **test_chunking_preserves_line_boundaries**: Ensures chunks split at line boundaries
- ✅ **test_large_file_multiple_languages**: Tests multi-language codebase indexing
- ✅ **test_end_to_end_large_file_review**: Full workflow test (slow, requires Ollama)

#### `TestLargeFileTokenCounts`
- ✅ **test_token_count_estimation**: Validates token counting accuracy
- ✅ **test_context_window_safety**: Ensures prompts stay under context limits

## Expected Behavior

### Adaptive Chunking

FalconEYE automatically adjusts chunk sizes based on file size:

| File Size | Chunk Size | Expected Chunks |
|-----------|------------|-----------------|
| ≤1000 lines | 50 lines (default) | ~20 chunks |
| 5000 lines | ~100 lines | ~50 chunks |
| 10000+ lines | 200 lines (max) | ~50 chunks |

Formula: `chunk_size = max(default_size, min(200, total_lines // 50))`

### Prompt Truncation

For files exceeding 10,000 lines:
- First 10,000 lines are included in prompts
- Remaining lines are truncated with a note
- Prevents LLM context window overflow

### Token Limits

- Target: < 100,000 tokens per prompt (safe for 128k context)
- Average: ~7-12 tokens per line of Python code
- 10,000 lines ≈ 70k-120k tokens (within safe limits)

## Test Data Generation

Test utilities in `conftest.py` generate large files with:
- **Realistic code structure**: Classes, functions, imports
- **Known vulnerabilities**: Command injection, SQL injection, XSS
- **Configurable size**: Any number of lines
- **Multiple languages**: Python, JavaScript

Example:
```python
from tests.conftest import generate_large_python_file

# Generate 5000-line file with vulnerabilities
content = generate_large_python_file(num_lines=5000, with_vulnerabilities=True)
```

## Debugging Failed Tests

### Check Ollama Connection

```bash
# Verify Ollama is running
curl http://localhost:11434/api/tags

# Check model availability
ollama list
```

### View Test Logs

```bash
# Run with logging enabled
pytest -v -s --log-cli-level=INFO
```

### Inspect Test Artifacts

Failed LLM responses are saved to `/tmp/falconeye_failed_response_*.txt`

## Writing New Tests

### Unit Tests

Place in `tests/unit/`. No external dependencies allowed.

```python
import pytest

@pytest.mark.unit
def test_my_feature():
    # Test domain logic only
    pass
```

### Integration Tests

Place in `tests/integration/`. May use Ollama, ChromaDB, etc.

```python
import pytest

@pytest.mark.integration
async def test_with_llm(llm_service):
    # Test with real LLM
    result = await llm_service.analyze(...)
    assert result is not None
```

### Slow Tests

Mark long-running tests:

```python
@pytest.mark.slow
@pytest.mark.integration
async def test_full_codebase_scan():
    # This test takes 5+ minutes
    pass
```

## Continuous Integration

For CI environments without Ollama:

```bash
# Run only unit tests in CI
pytest -m unit
```

Or use a mock LLM provider for faster integration tests.

## Troubleshooting

### Import Errors

Ensure FalconEYE is installed in development mode:
```bash
pip install -e ".[dev]"
```

### Ollama Timeout

Increase timeout in `mock_config` fixture (conftest.py):
```python
"llm": {
    "timeout": 600,  # 10 minutes for slow operations
    ...
}
```

### ChromaDB/onnxruntime Conflicts

Use locked requirements:
```bash
pip install -r requirements.txt
```

See `DEPENDENCY_TROUBLESHOOTING.md` for details.
