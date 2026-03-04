# Внешние базы YARA-сигнатур

Директория `external/` заполняется загрузчиком и содержит подкаталоги:
- **Yara-Rules** — общая база малвари (Yara-Rules/rules)
- **Neo23x0** — сигнатуры Florian Roth (APT, утилиты, anti-analysis, packers)

## Первоначальная загрузка

```bash
python -m bin_gate.rules.updater --sync
```

Требуется: `git` в PATH и доступ в интернет. После установки пакета также доступна команда:

```bash
bin-gate-rules-sync --sync
```

## Кэширование

Скомпилированные правила кэшируются в `.yarc` (каталог кэша: `~/.cache/bin-gate/yara` или `%LOCALAPPDATA%\bin-gate\yara-cache`). При следующем запуске сканирования пересборка не выполняется, пока не изменится содержимое `external/`.
