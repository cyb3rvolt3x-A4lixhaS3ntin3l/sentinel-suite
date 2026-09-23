# Build UNSIGNED sentinel.exe on a Windows host with Python 3.10+.
# Cross-build from Linux via Wine is NOT verified in this repo — do not claim it.
# SmartScreen will warn: label Release assets UNSIGNED (no Authenticode).
#
# Usage (PowerShell, from repo root):
#   py -3 -m pip install pyinstaller
#   py -3 -m pip install -e packages/sentinel_core -e packages/shadowseye `
#        -e packages/gungnir -e packages/sentinel_cli -e packages/sentinel_suite
#   .\scripts\build_pyinstaller_windows.ps1
#
# Output: dist\sentinel-windows-x86_64.exe (UNSIGNED)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$OutName = "sentinel-windows-x86_64"
$Entry = Join-Path $Root "build\pyinstaller-windows\sentinel_entry.py"
New-Item -ItemType Directory -Force -Path (Split-Path $Entry) | Out-Null
@"
from sentinel_cli.cli import main
if __name__ == '__main__':
    raise SystemExit(main())
"@ | Set-Content -Encoding UTF8 $Entry

py -3 -m PyInstaller --noconfirm --clean --onefile --name $OutName `
  --paths packages\sentinel_core\src `
  --paths packages\shadowseye\src `
  --paths packages\gungnir\src `
  --paths packages\sentinel_cli\src `
  --collect-submodules sentinel_cli `
  --collect-submodules shadowseye `
  --collect-submodules gungnir `
  --collect-submodules sentinel_core `
  --hidden-import bcrypt `
  --add-data "ui;ui" `
  --distpath dist `
  --workpath build\pyinstaller-windows\work `
  --specpath build\pyinstaller-windows `
  $Entry

Write-Host "UNSIGNED artifact: dist\$OutName.exe"
