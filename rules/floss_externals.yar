/*
  FLOSS externals pack — триггеры по количественным метрикам,
  переданным из bin-gate через YARA externals:
    - floss_total_cnt      (int)
    - floss_decoded_cnt    (int)
    - floss_stack_cnt      (int)
    - floss_static_cnt     (int)
    - floss_url_cnt        (int)
    - floss_ip_cnt         (int)
    - floss_cmd_cnt        (int)
    - floss_has_strings    (bool)

  Назначение:
    - быстро подсветить образцы с «богатыми» раскодированными строками
      (полезно для ранжирования/приоритизации ревью),
    - дать слабые/средние эвристики (URLs/команды),
    - отметить «stringless» кейсы (ноль строк при заметном размере).

  ВАЖНО: эти правила не ищут ничего в самом файле — они
  зависят от externals. Если FLOSS отключён/упал, значения должны
  приходить нулями (bin-gate уже передаёт дефолтные нули).
*/

/* --- Базовые «информационные» флаги --- */

rule FLOSS_Decoded_Any
{
  meta:
    author      = "bin-gate"
    category    = "floss"
    severity    = "info"
    description = "FLOSS found at least 1 decoded or stack string"
  condition:
    (floss_decoded_cnt + floss_stack_cnt) >= 1
}

rule FLOSS_Decoded_Many
{
  meta:
    author      = "bin-gate"
    category    = "floss"
    severity    = "medium"
    description = "FLOSS found lots of decoded/stack strings (>= 60)"
  condition:
    (floss_decoded_cnt + floss_stack_cnt) >= 60
}

/* --- URL/IP индикаторы --- */

rule FLOSS_URL_Any
{
  meta:
    author      = "bin-gate"
    category    = "floss/ioc"
    severity    = "info"
    description = "At least one URL discovered by FLOSS"
  condition:
    floss_url_cnt >= 1
}

rule FLOSS_URL_Many
{
  meta:
    author      = "bin-gate"
    category    = "floss/ioc"
    severity    = "medium"
    description = "Multiple URLs discovered by FLOSS (>= 5)"
  condition:
    floss_url_cnt >= 5
}

rule FLOSS_IP_Any
{
  meta:
    author      = "bin-gate"
    category    = "floss/ioc"
    severity    = "info"
    description = "At least one IPv4 discovered by FLOSS"
  condition:
    floss_ip_cnt >= 1
}

/* --- Командные/скриптовые артефакты --- */

rule FLOSS_SuspiciousCmd_Any
{
  meta:
    author      = "bin-gate"
    category    = "floss/behavior"
    severity    = "medium"
    description = "Suspicious command keywords present (PowerShell/cmd/wscript/etc.)"
  condition:
    floss_cmd_cnt >= 1
}

rule FLOSS_SuspiciousCmd_Many
{
  meta:
    author      = "bin-gate"
    category    = "floss/behavior"
    severity    = "high"
    description = "Many suspicious command keywords (>= 5)"
  condition:
    floss_cmd_cnt >= 5
}

/* --- Сводная эвристика «повышенная активность» --- */

rule FLOSS_Heuristic_HighSignal
{
  meta:
    author      = "bin-gate"
    category    = "floss/heuristic"
    severity    = "high"
    description = "High signal: many decoded/stack strings AND some suspicious commands or URLs"
  condition:
    (floss_decoded_cnt + floss_stack_cnt) >= 80 and
    (floss_cmd_cnt >= 1 or floss_url_cnt >= 3)
}

/* --- «Stringless» подсветка (мало/нет строк при ощутимом размере файла) --- */

rule FLOSS_Stringless_Heuristic
{
  meta:
    author      = "bin-gate"
    category    = "floss/heuristic"
    severity    = "medium"
    description = "No strings extracted by FLOSS on a non-tiny file (possible packing/obfuscation)"
  condition:
    (not floss_has_strings) and filesize >= 64KB
}

/* --- Мягкий суммарный триггер «обратить внимание» --- */

rule FLOSS_Attention
{
  meta:
    author      = "bin-gate"
    category    = "floss/summary"
    severity    = "medium"
    description = "Any notable FLOSS signal: decoded/stack >= 40 OR urls >= 3 OR suspicious cmd >= 2"
  condition:
    (floss_decoded_cnt + floss_stack_cnt) >= 40 or
    floss_url_cnt >= 3 or
    floss_cmd_cnt >= 2
}
