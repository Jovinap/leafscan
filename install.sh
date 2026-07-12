#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# LeafScan v2.0 — One-Line Installer
# By Leaf Security AI (JJ Groups of Company) | Created by A.P.Jovin
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Jovinap/leafscan/main/install.sh | bash
#
# ─────────────────────────────────────────────────────────────────────────────
set -e

REPO="Jovinap/leafscan"
MIN_PYTHON="3.8"
PACKAGE="leafscan"

GREEN='\033[0;32m'
BOLD='\033[1m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
RESET='\033[0m'
DIM='\033[2m'

banner() {
  echo ""
  echo -e "${GREEN}${BOLD}"
  cat << 'EOF'
  ██╗     ███████╗ █████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██║     ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║     █████╗  ███████║█████╗  ███████╗██║     ███████║██╔██╗ ██║
  ██║     ██╔══╝  ██╔══██║██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
  ███████╗███████╗██║  ██║██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
  echo -e "${RESET}"
  echo -e "  ${BOLD}LeafScan v2.0${RESET} — World's First Continuous Bug Bounty Scanner"
  echo -e "  ${DIM}By Leaf Security AI (JJ Groups of Company) · Created by A.P.Jovin${RESET}"
  echo -e "  ${DIM}https://github.com/${REPO}${RESET}"
  echo ""
}

info()    { echo -e "  ${DIM}ℹ  $*${RESET}"; }
success() { echo -e "  ${GREEN}✓  $*${RESET}"; }
warn()    { echo -e "  ${YELLOW}⚠  $*${RESET}"; }
error()   { echo -e "  ${RED}✗  $*${RESET}" >&2; exit 1; }
step()    { echo -e "\n  ${BOLD}${GREEN}→ $*${RESET}"; }

banner

# ── RESPONSIBLE USE NOTICE ─────────────────────────────────────────────────
echo -e "  ${YELLOW}${BOLD}⚠  RESPONSIBLE USE NOTICE${RESET}"
echo ""
echo -e "  LeafScan is for AUTHORIZED security testing only."
echo -e "  By installing, you agree to:"
echo -e "    1. Only scan systems you own or have explicit written permission to test."
echo -e "    2. Comply with all applicable laws (CFAA, Computer Misuse Act, etc.)."
echo -e "    3. Use reports for authorized compliance or bug bounty purposes only."
echo ""
echo -e "  ${DIM}Unauthorized scanning is illegal. See RESPONSIBLE_USE.md${RESET}"
echo ""

read -r -p "  Do you accept these terms? [y/N]: " terms_accepted
if [[ ! "$terms_accepted" =~ ^[Yy]$ ]]; then
  echo "  Installation cancelled."
  exit 0
fi

echo ""

# ── CHECK OS ───────────────────────────────────────────────────────────────
step "Checking system"

OS="$(uname -s)"
case "$OS" in
  Linux*)   info "OS: Linux" ;;
  Darwin*)  info "OS: macOS" ;;
  *)        warn "Untested OS: $OS — proceeding anyway." ;;
esac

# ── CHECK PYTHON ───────────────────────────────────────────────────────────
step "Checking Python"

PYTHON=""
for candidate in python3 python python3.12 python3.11 python3.10 python3.9 python3.8; do
  if command -v "$candidate" &>/dev/null; then
    ver=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
      PYTHON="$candidate"
      info "Found: $candidate (Python $ver)"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  error "Python ${MIN_PYTHON}+ is required. Install from https://python.org or your package manager."
fi

# ── CHECK PIP ─────────────────────────────────────────────────────────────
step "Checking pip"

if ! "$PYTHON" -m pip --version &>/dev/null; then
  warn "pip not found — attempting to install..."
  curl -sSL https://bootstrap.pypa.io/get-pip.py | "$PYTHON"
fi

PIP="$PYTHON -m pip"
info "pip: $($PIP --version)"

# ── CHECK FOR EXISTING INSTALL ────────────────────────────────────────────
step "Checking for existing installation"

if "$PYTHON" -c "import leafscan" 2>/dev/null; then
  current_ver=$("$PYTHON" -c "import leafscan; print(leafscan.__version__)" 2>/dev/null || echo "unknown")
  warn "LeafScan already installed (v${current_ver}). Upgrading..."
  UPGRADE_FLAG="--upgrade"
else
  info "Fresh installation"
  UPGRADE_FLAG=""
fi

# ── INSTALL ────────────────────────────────────────────────────────────────
step "Installing LeafScan"

info "Running: pip install ${UPGRADE_FLAG} leafscan"
if ! $PIP install $UPGRADE_FLAG leafscan 2>&1; then
  warn "PyPI install failed — trying install from GitHub..."
  $PIP install $UPGRADE_FLAG "git+https://github.com/${REPO}.git" || \
    error "Installation failed. Check your internet connection and try: pip install leafscan"
fi

# ── VERIFY ─────────────────────────────────────────────────────────────────
step "Verifying installation"

if command -v leafscan &>/dev/null; then
  installed_ver=$(leafscan --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  success "LeafScan v${installed_ver} installed successfully!"
else
  # Try to find leafscan in user bin
  user_bin="$($PYTHON -m site --user-base 2>/dev/null)/bin"
  if [ -f "$user_bin/leafscan" ]; then
    warn "leafscan installed to $user_bin — add to PATH:"
    echo ""
    echo "    export PATH=\"\$PATH:$user_bin\""
    echo ""
    echo "  Or add to ~/.bashrc / ~/.zshrc"
  else
    warn "Installation may have succeeded but 'leafscan' command not in PATH."
    info "Try: python -m leafscan --version"
  fi
fi

# ── FIRST-RUN PROMPT ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${GREEN}🌿 LeafScan is ready!${RESET}"
echo ""
echo -e "  ${BOLD}Next Steps:${RESET}"
echo -e "  ${GREEN}leafscan setup${RESET}                     Run the setup wizard"
echo -e "  ${GREEN}leafscan scan https://your-app.com${RESET}  Scan your own application"
echo -e "  ${GREEN}leafscan help${RESET}                      Full command reference"
echo -e "  ${GREEN}leafscan --version${RESET}                 Check installed version"
echo ""
echo -e "  ${DIM}Docs:   https://github.com/${REPO}/wiki${RESET}"
echo -e "  ${DIM}Issues: https://github.com/${REPO}/issues${RESET}"
echo ""

read -r -p "  Run setup wizard now? [Y/n]: " run_setup
if [[ ! "$run_setup" =~ ^[Nn]$ ]]; then
  echo ""
  leafscan setup
fi
