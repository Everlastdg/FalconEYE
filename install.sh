#!/bin/bash
#
# FalconEYE Installation Script
# Handles dependency conflicts and creates proper virtual environment
#

set -e  # Exit on error

echo "=========================================="
echo "FalconEYE v2.0 - Installation Script"
echo "=========================================="
echo ""

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

echo "Platform: $OS ($ARCH)"
echo ""

# Check Python version
PYTHON_CMD=""
for cmd in python3.12 python3.13 python3; do
    if command -v $cmd &> /dev/null; then
        VERSION=$($cmd --version 2>&1 | cut -d' ' -f2)
        MAJOR=$(echo $VERSION | cut -d'.' -f1)
        MINOR=$(echo $VERSION | cut -d'.' -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 12 ]; then
            PYTHON_CMD=$cmd
            echo "✓ Found Python $VERSION at $(which $cmd)"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "✗ Error: Python 3.12+ not found"
    echo "Please install Python 3.12 or later"
    exit 1
fi

echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON_CMD -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

echo ""

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

echo "✓ Virtual environment activated"
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo "✓ pip upgraded"
echo ""

# Install dependencies
echo "Installing FalconEYE dependencies..."
echo ""

# Option 1: Use locked requirements (recommended)
if [ -f "requirements.txt" ]; then
    echo "Using locked requirements.txt for reproducible installation..."
    pip install -r requirements.txt
    echo "✓ Core dependencies installed"
else
    echo "Using pyproject.toml..."
    pip install -e .
fi

echo ""

# Install optional development dependencies
read -p "Install development dependencies (pytest, ruff, black, mypy)? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Installing development dependencies..."
    pip install -e ".[dev]"
    echo "✓ Development dependencies installed"
fi

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To verify installation, run:"
echo "  falconeye info"
echo ""
echo "Note: Make sure Ollama is running with required models:"
echo "  ollama pull qwen3-coder:30b"
echo "  ollama pull embeddinggemma:300m"
echo ""
