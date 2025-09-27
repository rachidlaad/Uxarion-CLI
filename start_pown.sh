#!/bin/bash
# 4myPown Launcher Script
# Activates virtual environment and launches Claude Code-style interface

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activate virtual environment
source "$SCRIPT_DIR/.venv/bin/activate"

# Launch pown with Claude Code-style interface
if [ "$#" -eq 0 ]; then
    # No arguments - launch default Claude-style chat
    echo "🚀 Starting 4myPown Claude Code-style interface..."
    pown
else
    # Pass through all arguments
    pown "$@"
fi