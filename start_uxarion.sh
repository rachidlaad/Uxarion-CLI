#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Uxarion Launcher Script
# Activates virtual environment and launches Claude Code-style interface

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activate virtual environment
source "$SCRIPT_DIR/.venv/bin/activate"

# Launch uxarion with Claude Code-style interface
if [ "$#" -eq 0 ]; then
    # No arguments - launch default Claude-style chat
    echo "🚀 Starting Uxarion Claude Code-style interface..."
    uxarion
else
    # Pass through all arguments
    uxarion "$@"
fi
