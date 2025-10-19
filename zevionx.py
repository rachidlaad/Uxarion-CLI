#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Unified entrypoint for Zevionx.

Usage:
  zevionx                     -> launch interactive chat UI
  zevionx "objective" [flags] -> run single-shot agent (auto inserts --prompt)
  zevionx --prompt "obj" ...  -> identical to python zevionx_cli.py --prompt ...
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List

from importlib.machinery import SourceFileLoader


def _load_agent_module():
    loader = SourceFileLoader("zevionx_cli_main", str(Path(__file__).resolve().parent / "zevionx_cli.py"))
    return loader.load_module()  # type: ignore[deprecated-attr]


_AGENT_MODULE = _load_agent_module()
run_agent_main = getattr(_AGENT_MODULE, "main")

from zevionx_cli.ui.chat_ui import ChatUI


def _run_agent(args: List[str]) -> int:
    # Insert --prompt if the user passed a bare objective.
    if args and not any(arg in {"--prompt", "-p"} for arg in args):
        args = ["--prompt", args[0], *args[1:]]
    sys.argv = ["zevionx_cli.py", *args]
    try:
        return run_agent_main()
    except KeyboardInterrupt:
        print("\nSession interrupted by user.")
        return 130


def main() -> int:
    if len(sys.argv) == 1:
        ui = ChatUI()
        ui.run()
        return 0
    return _run_agent(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
