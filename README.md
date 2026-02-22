# Uxarion CLI

Official site: https://uxarion.com/

AI pentesting CLI assistant for authorized security testing.

> **Authorized testing only**  
> Use only on systems you own or have explicit written permission to test.

## Install (choose your user type)

### 1) Ubuntu/Kali root user (recommended for your current setup)

This is the exact flow that worked in your Ubuntu session:

```bash
apt update
apt install -y pipx
pipx ensurepath
export PATH="$PATH:/root/.local/bin"
pipx install uxarion
uxarion --doctor
```

If pipx shows this warning:
`File exists at /root/.local/bin/uxarion ... symlink missing or pointing to unexpected location`

run:

```bash
rm -f /root/.local/bin/uxarion
pipx reinstall uxarion
```

### 2) Ubuntu/Kali normal user (non-root)

```bash
sudo apt update
sudo apt install -y pipx
pipx ensurepath
pipx install uxarion
uxarion --doctor
```

If `uxarion` is not found, open a new shell or run:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

### 3) Python virtualenv user

```bash
python3 -m venv ~/.venvs/uxarion
source ~/.venvs/uxarion/bin/activate
python -m pip install -U pip
python -m pip install -U uxarion
uxarion --doctor
```

### 4) From source (developers)

```bash
git clone https://github.com/rachidlaad/Uxarion-CLI.git
cd Uxarion-CLI
./install.sh
uxarion --doctor
```

## First run

```bash
uxarion --addKey
uxarion
```

Direct one-shot run:

```bash
uxarion --prompt "safe passive recon on https://example.com" --max-commands 3
```

## Update

- pipx installs:
  `pipx upgrade uxarion`
- venv installs:
  `python -m pip install -U uxarion`

Uxarion also checks PyPI for updates at startup (cached for 24h) and prints a one-line upgrade hint.  
Disable this check with:

```bash
export UXARION_DISABLE_UPDATE_CHECK=1
```

## Common install issue (Ubuntu/Kali)

If you get:
`error: externally-managed-environment`

Do not install into system Python with plain `pip`. Use `pipx` or a virtualenv (shown above).

## License

Apache-2.0 (`LICENSE`).
