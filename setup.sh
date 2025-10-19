#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# Zevionx CLI Setup Script
# This script helps configure the environment and install dependencies

set -e

echo "🛡️  Zevionx CLI Setup"
echo "===================="

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: Please run this script from the Zevionx-CLI directory"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
echo "🔄 Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip --quiet

# Install CLI package
echo "📥 Installing Zevionx CLI..."
pip install -e . --quiet

# Install optional dependencies
echo "🔧 Installing optional AI providers..."
read -p "Install Google Gemini support? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install google-generativeai --quiet
    echo "✅ Gemini support installed"
fi

read -p "Install OpenAI support? (y/N): " -n 1 -r  
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install openai --quiet
    echo "✅ OpenAI support installed"
fi

read -p "Install enhanced UI support (prompt_toolkit)? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install prompt_toolkit --quiet
    echo "✅ Enhanced UI support installed"
fi

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Setting up environment file..."
    cp .env.example .env
    echo "✅ Created .env file from template"
    echo "📋 Please edit .env file to add your API keys"
else
    echo "ℹ️  .env file already exists"
fi

echo
echo "🎉 Setup completed!"
echo
echo "Next steps:"
echo "1. Edit .env file to add your API keys:"
echo "   nano .env"
echo
echo "2. Activate the virtual environment:"
echo "   source .venv/bin/activate"
echo  
echo "3. Start the CLI:"
echo "   zevionx"
echo "   or"
echo "   zevionx chat -t http://localhost:8080"
echo
echo "4. Available commands:"
echo "   zevionx --help           # Show all commands"
echo "   zevionx chat            # Interactive chat mode"
echo "   zevionx menu            # Menu-based experience"
echo "   zevionx pentest \"objective\" --target https://example.com"
echo
echo "🔒 For security testing, make sure you have permission to test your targets!"
