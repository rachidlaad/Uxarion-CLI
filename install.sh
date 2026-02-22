#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="${HOME}/.local/bin"
LAUNCHER_PATH="${LOCAL_BIN}/uxarion"
VENV_DIR="${ROOT_DIR}/.venv"

echo "Uxarion Installer"
echo "-----------------"

if [[ ! -f "${ROOT_DIR}/pyproject.toml" ]]; then
  echo "Error: run this installer from the Uxarion-CLI project directory."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 is required but not found."
  exit 1
fi

used_pipx=false
if command -v pipx >/dev/null 2>&1; then
  echo "Using pipx for isolated installation..."
  pipx install --force "${ROOT_DIR}"
  used_pipx=true
else
  echo "pipx not found; using local virtual environment at ${VENV_DIR}"
  if [[ ! -d "${VENV_DIR}" ]]; then
    python3 -m venv "${VENV_DIR}"
  fi

  echo "Installing package into local virtual environment..."
  if ! "${VENV_DIR}/bin/python" -m pip install --disable-pip-version-check -e "${ROOT_DIR}"; then
    echo "Initial install failed; upgrading pip tooling and retrying..."
    "${VENV_DIR}/bin/python" -m pip install --disable-pip-version-check --upgrade pip setuptools wheel
    "${VENV_DIR}/bin/python" -m pip install --disable-pip-version-check -e "${ROOT_DIR}"
  fi

  mkdir -p "${LOCAL_BIN}"
  cat > "${LAUNCHER_PATH}" <<EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${ROOT_DIR}/uxarion.py" "\$@"
EOF
  chmod +x "${LAUNCHER_PATH}"
fi

if [[ "${used_pipx}" == "true" ]]; then
  if ! command -v uxarion >/dev/null 2>&1; then
    echo
    echo "uxarion is installed with pipx, but not found in current PATH."
    echo "Run:"
    echo "  pipx ensurepath"
    echo "Then open a new shell and retry."
  fi
elif [[ ":${PATH}:" != *":${LOCAL_BIN}:"* ]]; then
  echo
  echo "Add ${LOCAL_BIN} to PATH:"
  echo "  export PATH=\"${LOCAL_BIN}:\$PATH\""
fi

echo
echo "Installed."
echo "Next steps:"
echo "  1) uxarion --addKey"
echo "  2) uxarion"
echo "  3) Optional direct run: uxarion --prompt \"safe passive recon on https://example.com\" --max-commands 3"
echo "  4) Optional env check: uxarion --doctor"
