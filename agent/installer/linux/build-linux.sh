#!/usr/bin/env bash
# Build a single-file Linux binary of the Cage agent with PyInstaller. Run on the SAME distro family you will deploy
# to (glibc version matters). Produces dist/cage-agent (an ELF executable).
#
#   cd agent && ./installer/linux/build-linux.sh
#
set -euo pipefail
cd "$(dirname "$0")/../.."          # -> agent/

python3 -m venv .buildenv
# shellcheck disable=SC1091
source .buildenv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt pyinstaller

cat > _entry_linux.py <<'PY'
from cage_agent.__main__ import main
import sys
sys.exit(main())
PY

pyinstaller --onefile --name cage-agent \
    --collect-submodules cage_agent \
    --hidden-import psutil \
    _entry_linux.py

rm -f _entry_linux.py
echo
echo "Built: $(pwd)/dist/cage-agent"
echo "Next: sudo ./installer/linux/install.sh --server https://YOUR-SERVER --token XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
