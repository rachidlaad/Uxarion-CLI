from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Optional, List


HOME_DIR = Path(os.path.expanduser("~"))
BASE_DIR = HOME_DIR / ".4mypown"
SESSIONS_DIR = BASE_DIR / "sessions"
TODO_PATH = BASE_DIR / "todo.json"

# Core tooling expected on Kali Linux hosts (zap handled separately)
KALI_CORE_TOOLS: List[str] = [
    "aircrack-ng",
    "amass",
    "arp-scan",
    "assetfinder",
    "beef-xss",
    "bettercap",
    "bloodhound",
    "cewl",
    "certipy",
    "crackmapexec",
    "curl",
    "dirb",
    "dirsearch",
    "dnsenum",
    "dnsrecon",
    "enum4linux",
    "enum4linux-ng",
    "evil-winrm",
    "feroxbuster",
    "ffuf",
    "fierce",
    "gobuster",
    "hash-identifier",
    "hashcat",
    "hydra",
    "httpx",
    "impacket-psexec",
    "impacket-secretsdump",
    "john",
    "kerbrute",
    "kismet",
    "ldapsearch",
    "linpeas",
    "masscan",
    "medusa",
    "metasploit-framework",
    "msfconsole",
    "naabu",
    "nbtscan",
    "netcat",
    "netdiscover",
    "nikto",
    "nmap",
    "nuclei",
    "onesixtyone",
    "openssl",
    "proxychains",
    "responder",
    "rpcclient",
    "rdesktop",
    "rustscan",
    "searchsploit",
    "setoolkit",
    "smbclient",
    "smbmap",
    "snmpwalk",
    "socat",
    "sqlmap",
    "subfinder",
    "theHarvester",
    "tmux",
    "wfuzz",
    "whatweb",
    "wafw00f",
    "wget",
    "wpscan",
    "xfreerdp",
]


def ensure_dirs() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)


def supports_emoji() -> bool:
    return os.environ.get("NO_EMOJI") not in ("1", "true", "True") and sys.platform != "win32"


def strip_md_fences(text: str) -> str:
    # Remove markdown code fences that may wrap JSON
    return re.sub(r"^```[a-zA-Z0-9]*\n|\n```$", "", text.strip())


def try_parse_json(text: str) -> Optional[Any]:
    try:
        return json.loads(strip_md_fences(text))
    except Exception:
        return None


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def read_json(path: Path) -> Optional[Any]:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


async def maybe_async(func, *args, **kwargs):
    res = func(*args, **kwargs)
    if hasattr(res, "__await__"):
        return await res
    return res
