"""Pytest configuration and fixtures for FalconEYE tests."""

import os
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Provide a temporary directory for test files.

    Automatically cleaned up after the test completes.
    """
    temp_path = Path(tempfile.mkdtemp(prefix="falconeye_test_"))
    try:
        yield temp_path
    finally:
        if temp_path.exists():
            shutil.rmtree(temp_path)


@pytest.fixture
def sample_python_code() -> str:
    """
    Provide sample Python code with potential security issues.

    Returns:
        String containing Python code with various security patterns
    """
    return '''
import os
import subprocess

def read_user_file(filename):
    """Potentially vulnerable file read."""
    with open(filename, 'r') as f:
        return f.read()

def execute_command(cmd):
    """Command injection vulnerability."""
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout.decode()

def sql_query(user_input):
    """SQL injection vulnerability."""
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

class UserAuth:
    """Authentication with weak password handling."""

    def __init__(self):
        self.password = "hardcoded_password"

    def check_password(self, pwd):
        return pwd == self.password
'''


@pytest.fixture
def sample_javascript_code() -> str:
    """
    Provide sample JavaScript code with potential security issues.

    Returns:
        String containing JavaScript code with various security patterns
    """
    return '''
const express = require('express');
const app = express();

// XSS vulnerability
app.get('/greet', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);
});

// Eval vulnerability
function executeCode(userCode) {
    return eval(userCode);
}

// Insecure random
function generateToken() {
    return Math.random().toString(36).substring(2);
}

module.exports = { app, executeCode, generateToken };
'''


@pytest.fixture
def mock_config() -> dict:
    """
    Provide mock configuration for testing.

    Returns:
        Dictionary with test configuration values
    """
    return {
        "llm": {
            "provider": "ollama",
            "base_url": "http://localhost:11434",
            "model": {
                "analysis": "qwen3-coder:30b",
                "embedding": "embeddinggemma:300m",
            },
            "timeout": 300,
            "max_retries": 3,
        },
        "analysis": {
            "top_k_context": 5,
            "validate_findings": True,
            "min_severity": "medium",
        },
        "chunking": {
            "default_size": 50,
            "overlap": 10,
            "max_chunk_size": 200,
        },
        "vector_store": {
            "persist_directory": None,  # Use temp directory
            "collection_prefix": "test_",
        },
        "logging": {
            "level": "INFO",
            "format": "json",
        },
    }


def generate_large_python_file(num_lines: int, with_vulnerabilities: bool = True) -> str:
    """
    Generate a large Python file for testing.

    Args:
        num_lines: Number of lines to generate
        with_vulnerabilities: Whether to include security vulnerabilities

    Returns:
        String containing generated Python code
    """
    lines = [
        '"""Large Python module for testing."""',
        'import os',
        'import sys',
        'import subprocess',
        'import hashlib',
        'from typing import Optional, List, Dict',
        '',
        '',
    ]

    # Generate classes with methods
    functions_per_class = 10
    lines_per_function = 15
    num_classes = max(1, num_lines // (functions_per_class * lines_per_function))

    for class_idx in range(num_classes):
        lines.append(f'class DataProcessor{class_idx}:')
        lines.append(f'    """Data processor class {class_idx}."""')
        lines.append('')
        lines.append('    def __init__(self):')
        lines.append(f'        self.data = []')
        lines.append(f'        self.counter = 0')
        lines.append('')

        for func_idx in range(functions_per_class):
            # Add vulnerable function periodically if requested
            if with_vulnerabilities and func_idx % 3 == 0:
                lines.extend([
                    f'    def process_user_input_{func_idx}(self, user_input: str) -> str:',
                    f'        """Process user input - Line {len(lines)}."""',
                    '        # Potential command injection vulnerability',
                    '        cmd = f"echo {user_input}"',
                    '        result = subprocess.run(cmd, shell=True, capture_output=True)',
                    '        return result.stdout.decode()',
                    '',
                ])
            elif with_vulnerabilities and func_idx % 3 == 1:
                lines.extend([
                    f'    def query_database_{func_idx}(self, table: str, condition: str) -> str:',
                    f'        """Query database - Line {len(lines)}."""',
                    '        # Potential SQL injection vulnerability',
                    f'        query = f"SELECT * FROM {{table}} WHERE {{condition}}"',
                    '        # Execute query here',
                    '        return query',
                    '',
                ])
            else:
                lines.extend([
                    f'    def safe_function_{func_idx}(self, data: List[str]) -> Dict[str, int]:',
                    f'        """Safe data processing function - Line {len(lines)}."""',
                    '        result = {}',
                    '        for item in data:',
                    f'            key = hashlib.sha256(item.encode()).hexdigest()',
                    '            result[key] = len(item)',
                    '        self.counter += 1',
                    '        return result',
                    '',
                ])

        lines.append('')

    # Pad to reach desired line count
    while len(lines) < num_lines:
        lines.append(f'# Padding line {len(lines) + 1}')

    return '\n'.join(lines[:num_lines])


def generate_large_javascript_file(num_lines: int, with_vulnerabilities: bool = True) -> str:
    """
    Generate a large JavaScript file for testing.

    Args:
        num_lines: Number of lines to generate
        with_vulnerabilities: Whether to include security vulnerabilities

    Returns:
        String containing generated JavaScript code
    """
    lines = [
        '/**',
        ' * Large JavaScript module for testing',
        ' */',
        "const express = require('express');",
        "const crypto = require('crypto');",
        '',
        '',
    ]

    # Generate classes with methods
    functions_per_class = 10
    lines_per_function = 12
    num_classes = max(1, num_lines // (functions_per_class * lines_per_function))

    for class_idx in range(num_classes):
        lines.append(f'class DataProcessor{class_idx} {{')
        lines.append('    constructor() {')
        lines.append('        this.data = [];')
        lines.append('        this.counter = 0;')
        lines.append('    }')
        lines.append('')

        for func_idx in range(functions_per_class):
            if with_vulnerabilities and func_idx % 3 == 0:
                lines.extend([
                    f'    processUserInput{func_idx}(userInput) {{',
                    f'        // XSS vulnerability - Line {len(lines)}',
                    '        return `<div>${userInput}</div>`;',
                    '    }',
                    '',
                ])
            elif with_vulnerabilities and func_idx % 3 == 1:
                lines.extend([
                    f'    executeCode{func_idx}(code) {{',
                    f'        // Code injection vulnerability - Line {len(lines)}',
                    '        return eval(code);',
                    '    }',
                    '',
                ])
            else:
                lines.extend([
                    f'    safeFunction{func_idx}(data) {{',
                    f'        // Safe function - Line {len(lines)}',
                    '        const hash = crypto.createHash("sha256");',
                    '        hash.update(data);',
                    '        this.counter++;',
                    '        return hash.digest("hex");',
                    '    }',
                    '',
                ])

        lines.append('}')
        lines.append('')

    # Pad to reach desired line count
    while len(lines) < num_lines:
        lines.append(f'// Padding line {len(lines) + 1}')

    return '\n'.join(lines[:num_lines])
