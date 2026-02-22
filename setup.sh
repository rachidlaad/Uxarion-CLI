#!/bin/bash
# SPDX-License-Identifier: Apache-2.0

# Uxarion CLI Setup Script
# This script helps configure the environment and install dependencies

set -e

echo "🛡️  Uxarion CLI Setup"
echo "===================="

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: Please run this script from the Uxarion-CLI directory"
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
echo "📥 Installing Uxarion CLI..."
pip install -e . --quiet

# Install optional dependencies
echo "🔧 Installing optional extras..."
read -p "Install OpenAI package explicitly? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    pip install openai --quiet
    echo "✅ OpenAI package installed"
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
echo "1. Activate the virtual environment:"
echo "   source .venv/bin/activate"
echo  
echo "2. Add or replace your OpenAI key:"
echo "   uxarion --addKey"
echo
echo "3. Use one command name for all modes:"
echo "   uxarion                                   # interactive chat"
echo "   uxarion --prompt \"quick recon\" --max-commands 3"
echo "   uxarion --prompt \"quick recon\" --chat-after"
echo
echo "🔒 For security testing, make sure you have permission to test your targets!"
