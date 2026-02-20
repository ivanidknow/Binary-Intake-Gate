# Сборка bin-gate.exe в корень проекта (рядом с этим скриптом).
# После сборки запускайте: .\bin-gate.exe scan ...
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

if (Test-Path build) { Remove-Item -Recurse -Force build }
# exe собираем в корень, папка dist не используется
if (Test-Path dist) { Remove-Item -Recurse -Force dist }

# --distpath . = exe в текущей папке (корень проекта)
pyinstaller --distpath . --workpath build bin-gate.spec

if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "OK: bin-gate.exe создан в $root"
