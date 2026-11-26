#!/bin/bash
# Double-click this file to start Netmapper. It sets everything up the first time.
cd "$(dirname "$0")" || exit 1

echo "Starting Netmapper..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is not installed. Opening the download page."
  echo "Install it, then double-click this file again."
  open "https://www.python.org/downloads/" 2>/dev/null
  read -n 1 -s -r -p "Press any key to close."
  exit 1
fi

# First run only: make a private Python environment and install what the app needs.
if [ ! -x ".venv/bin/python" ]; then
  echo "First-time setup (about a minute)..."
  python3 -m venv .venv || { echo "Could not create the environment."; read -n 1 -s -r -p "Press any key to close."; exit 1; }
fi
if [ ! -f ".venv/.installed" ]; then
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements.txt || { echo "Install failed. Check your internet and try again."; read -n 1 -s -r -p "Press any key to close."; exit 1; }
  touch .venv/.installed
fi

# Skip Streamlit's first-run email question.
mkdir -p "$HOME/.streamlit"
[ -f "$HOME/.streamlit/credentials.toml" ] || printf '[general]\nemail = ""\n' > "$HOME/.streamlit/credentials.toml"

if [ -n "$NETMAPPER_SETUP_ONLY" ]; then
  echo "Setup finished."
  exit 0
fi

echo "Opening Netmapper in your browser. Close this window to stop it."
exec .venv/bin/python -m streamlit run app.py --browser.gatherUsageStats false
