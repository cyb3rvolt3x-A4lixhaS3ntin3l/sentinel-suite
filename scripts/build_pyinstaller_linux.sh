#!/usr/bin/env bash
# Build an UNSIGNED Linux one-file CLI binary via PyInstaller.
# Artifact: dist/sentinel-linux-<arch> — must be labeled UNSIGNED on Release.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ARCH="$(uname -m)"
OUT_NAME="sentinel-linux-${ARCH}"

python3 -m pip install -q 'pyinstaller>=6.0'
python3 -m pip install -q \
  -e packages/sentinel_core \
  -e packages/shadowseye \
  -e packages/gungnir \
  -e packages/sentinel_cli \
  -e packages/sentinel_suite

mkdir -p dist build/pyinstaller-linux
ENTRY="$ROOT/build/pyinstaller-linux/sentinel_entry.py"
cat > "$ENTRY" <<'PY'
from sentinel_cli.cli import main
if __name__ == "__main__":
    raise SystemExit(main())
PY

pyinstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name "$OUT_NAME" \
  --paths "$ROOT/packages/sentinel_core/src" \
  --paths "$ROOT/packages/shadowseye/src" \
  --paths "$ROOT/packages/gungnir/src" \
  --paths "$ROOT/packages/sentinel_cli/src" \
  --paths "$ROOT/packages/sentinel_suite/src" \
  --collect-submodules sentinel_cli \
  --collect-submodules shadowseye \
  --collect-submodules gungnir \
  --collect-submodules sentinel_core \
  --hidden-import bcrypt \
  --add-data "${ROOT}/ui:ui" \
  --distpath "$ROOT/dist" \
  --workpath "$ROOT/build/pyinstaller-linux/work" \
  --specpath "$ROOT/build/pyinstaller-linux" \
  "$ENTRY"

echo "UNSIGNED artifact: dist/${OUT_NAME}"
ls -lh "dist/${OUT_NAME}"
file "dist/${OUT_NAME}" || true
./dist/"$OUT_NAME" doctor | head -20
