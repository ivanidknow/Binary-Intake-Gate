# Полная сборка проекта (все компоненты):
#   1. Python-пакет (wheel + установка в режиме editable для bin-gate / bin-gate-rules-sync)
#   2. bin-gate.exe — один исполняемый файл в корне (PyInstaller)
#   3. Docker-образ эмуляции bin-gate-emulation:latest (если доступен Docker)
# После сборки: .\bin-gate.exe scan ... или python -m bin_gate.cli ...
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$componentsOk = @{
    Package = $false
    Exe     = $false
    Docker  = $false
}

# ---- 1. Python-пакет (wheel в dist/ и editable install) ----
Write-Host ""
Write-Host "[1/3] Сборка Python-пакета (binary-intake-gate)..." -ForegroundColor Cyan
if (Test-Path dist) { Remove-Item -Recurse -Force dist }
$null = New-Item -ItemType Directory -Force -Path dist

# pip пишет в stderr даже при успехе — временно отключаем Stop, иначе NativeCommandError
$prevEa = $ErrorActionPreference
$ErrorActionPreference = "Continue"
pip wheel . --wheel-dir dist --no-deps 2>&1 | Out-Null
$ErrorActionPreference = $prevEa
if ($LASTEXITCODE -eq 0) {
    $componentsOk.Package = $true
    Write-Host "OK: wheel создан в dist/" -ForegroundColor Green
} else {
    Write-Host "WARN: сборка wheel не удалась; продолжаем (exe не зависит от wheel)." -ForegroundColor Yellow
}

# Установка пакета в режиме editable (pip пишет в stderr — временно Continue)
$ErrorActionPreference = "Continue"
pip install -e . --quiet 2>$null
$ErrorActionPreference = $prevEa
if ($LASTEXITCODE -eq 0) {
    Write-Host "OK: пакет установлен (editable); доступны bin-gate, bin-gate-rules-sync" -ForegroundColor Green
}

# ---- 2. bin-gate.exe (PyInstaller) ----
Write-Host ""
Write-Host "[2/3] Сборка bin-gate.exe (PyInstaller)..." -ForegroundColor Cyan
if (Test-Path build) { Remove-Item -Recurse -Force build }

# exe в корень проекта (--distpath .)
pyinstaller --distpath . --workpath build bin-gate.spec
if ($LASTEXITCODE -ne 0) {
    Write-Error "Ошибка сборки bin-gate.exe (PyInstaller exited with code $LASTEXITCODE)"
    exit $LASTEXITCODE
}
$componentsOk.Exe = $true
Write-Host "OK: bin-gate.exe создан в $root" -ForegroundColor Green

# ---- 3. Docker-образ эмуляции (опционально) ----
Write-Host ""
Write-Host "[3/3] Сборка Docker-образа эмуляции (bin-gate-emulation:latest)..." -ForegroundColor Cyan
$dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerCmd) {
    Write-Host "Пропуск: Docker не найден в PATH. Образ эмуляции не собран." -ForegroundColor Yellow
} else {
    # Тот же Python, что для pip (где установлен bin_gate); PYTHONPATH на случай другого интерпретатора
    $env:PYTHONPATH = Join-Path $root "src"
    $pythonExe = $null
    $pipExe = Get-Command pip -ErrorAction SilentlyContinue
    if ($pipExe) {
        $pipDir = Split-Path $pipExe.Source -Parent
        $pythonExe = Join-Path (Split-Path $pipDir -Parent) "python.exe"
        if (-not (Test-Path $pythonExe)) { $pythonExe = $null }
    }
    if ($pythonExe) {
        & $pythonExe -m bin_gate.cli emulation-build 2>&1
    } else {
        bin-gate emulation-build 2>&1
    }
    if ($LASTEXITCODE -eq 0) {
        $componentsOk.Docker = $true
        Write-Host "OK: Docker-образ эмуляции успешно собран." -ForegroundColor Green
    } else {
        Write-Host "WARN: сборка Docker-образа не удалась (код $LASTEXITCODE). Проверьте docker/emulation/Dockerfile и запуск Docker Desktop." -ForegroundColor Yellow
    }
}

# ---- Итог ----
Write-Host ""
Write-Host "========== Итог сборки ==========" -ForegroundColor Cyan
Write-Host "  Python package (wheel): $(if ($componentsOk.Package) { 'OK (dist/*.whl)' } else { 'пропущен/ошибка' })"
Write-Host "  bin-gate.exe:           $(if ($componentsOk.Exe) { "OK ($root\bin-gate.exe)" } else { 'ошибка' })"
Write-Host "  Docker emulation image: $(if ($componentsOk.Docker) { 'OK (bin-gate-emulation:latest)' } else { 'пропущен/ошибка' })"
Write-Host "================================" -ForegroundColor Cyan
if (-not $componentsOk.Exe) {
    exit 1
}
Write-Host ""
Write-Host "Запуск: .\bin-gate.exe scan <путь>  или  bin-gate scan <путь>" -ForegroundColor Gray
