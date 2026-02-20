from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
import re
import hashlib
import time
import os

def _vt_debug_log(msg: str):
    """Пишет в vt_debug.log (общий путь через bin_gate.vt_debug)."""
    try:
        from bin_gate.vt_debug import vt_debug_log as _write
        _write(msg)
    except Exception:
        try:
            with open("vt_debug.log", "a", encoding="utf-8") as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
        except Exception:
            pass

# Устанавливаем путь к системным браузерам Playwright (важно для PyInstaller)
# Браузеры Playwright устанавливаются в %USERPROFILE%\AppData\Local\ms-playwright
if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
    default_pw_path = Path(os.environ.get("USERPROFILE", "")) / "AppData" / "Local" / "ms-playwright"
    if default_pw_path.exists():
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(default_pw_path)

from playwright.sync_api import sync_playwright

VT_UI_URL = "https://www.virustotal.com/gui/home/upload"
_SHA_URL_RE = re.compile(r"/gui/file/([0-9a-fA-F]{64})/(?:detection|details|analysis|community|behavior)?")
# Из любой ссылки VT (gui или api) достаём SHA256
_SHA_FROM_LINK_RE = re.compile(r"(?:virustotal\.com/(?:gui/file|api/v3/files)/|/file/)([0-9a-fA-F]{64})")

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def vt_upload_file_ui(
    path: Path,
    *,
    timeout_sec: int = 45,
    headless: bool = True,
    browser: str = "chromium",
) -> Tuple[Optional[str], List[str]]:
    """
    Headless UI upload → (sha256, errors).
    - поддержка browser: chromium/firefox/webkit
    - быстрые таймауты и фолбэки
    """
    errs: List[str] = []
    expected_sha = _sha256_file(path)

    engine = (browser or "chromium").strip().lower()
    if engine not in ("chromium", "firefox", "webkit"):
        engine = "chromium"

    try:
        with sync_playwright() as pw:
            btype = getattr(pw, engine)
            try:
                br = btype.launch(headless=headless)
            except Exception as e:
                err_msg = str(e)
                if "Executable doesn't exist" in err_msg or "chromium" in err_msg.lower() or "browser" in err_msg.lower():
                    return None, ["vt_ui_error:playwright_browser_not_found (run 'playwright install' to fix)"]
                return None, [f"vt_ui_error:browser_launch_failed:{err_msg[:100]}"]
            ctx = br.new_context(ignore_https_errors=True)
            page = ctx.new_page()

            # 1) /home/upload
            try:
                page.goto(VT_UI_URL, wait_until="domcontentloaded", timeout=20_000)
            except Exception as e:
                # fallback: прямая страница по известному SHA
                try:
                    page.goto(f"https://www.virustotal.com/gui/file/{expected_sha}/detection",
                              wait_until="domcontentloaded", timeout=20_000)
                    br.close()
                    return expected_sha, ["vt_ui_direct_sha"]
                except Exception as e2:
                    br.close()
                    return None, [f"vt_ui_start_fail:{e}", f"vt_ui_direct_sha_fail:{e2}"]

            # 2) cookie/consent
            try:
                page.get_by_role("button", name="Accept").first.click(timeout=5_000)
            except Exception:
                pass

            # 3) input[type=file]
            try:
                page.locator("input[type='file']").first.set_input_files(str(path), timeout=10_000)
            except Exception as e:
                br.close()
                return None, [f"vt_ui_file_input_fail:{e}"]

            # 4) ждём редирект на /gui/file/<sha>/*
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                url = page.url or ""
                m = _SHA_URL_RE.search(url)
                if m:
                    br.close()
                    return m.group(1).lower(), ["vt_ui_redirect_ok"]
                try:
                    page.wait_for_url(_SHA_URL_RE, timeout=1_000)
                except Exception:
                    pass

            # 5) финальный фолбэк — успех, не добавляем в ошибки
            try:
                page.goto(f"https://www.virustotal.com/gui/file/{expected_sha}/detection",
                          wait_until="domcontentloaded", timeout=15_000)
                br.close()
                return expected_sha, []
            except Exception as e:
                br.close()
                return None, [f"vt_ui_timeout({timeout_sec}s)", f"vt_ui_fallback_error:{e}"]

    except Exception as e:
        err_msg = str(e)
        # Упрощаем сообщения об ошибках
        if "Executable doesn't exist" in err_msg or "chromium" in err_msg.lower() or "browser" in err_msg.lower():
            return None, ["vt_ui_error:playwright_browser_not_found (run 'playwright install' to fix)"]
        elif "KeyboardInterrupt" in err_msg or "interrupted" in err_msg.lower():
            return None, ["vt_ui_error:interrupted_by_user"]
        elif "timeout" in err_msg.lower():
            return None, [f"vt_ui_error:timeout"]
        else:
            # Берем только краткое сообщение об ошибке
            short_msg = err_msg.split("\n")[0][:100] if "\n" in err_msg else err_msg[:100]
            return None, [f"vt_ui_error:{short_msg}"]


def vt_fetch_behaviour_ui(
    sha256: str,
    *,
    browser: str = "chromium",
    headless: bool = True,
    timeout_sec: int = 90,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Скрейп вкладки Behaviour на RU/EN локали.
    Возвращает ([behaviour_dict], errors) или ([], ["vt_ui_behaviour_empty"]) если ничего нет.
    """
    errs: List[str] = []
    url = f"https://www.virustotal.com/gui/file/{sha256}/behavior"
    _vt_debug_log(f"[vt_ui] behaviour fetch start sha256={sha256} url={url}")

    # Двуязычные заголовки
    H: Dict[str, List[str]] = {
        "processes": ["Processes", "Created processes", "Modules loaded",
                      "Процессы", "Созданные процессы", "Загруженные модули"],
        "commands":  ["Commands", "Command executions", "Command line",
                      "Команды", "Выполнение команд", "Командная строка"],
        "files":     ["Files", "Files written", "Files deleted", "Files read",
                      "Файлы", "Запись файлов", "Удаление файлов", "Чтение файлов"],
        "registry":  ["Registry", "Registry keys set", "Registry keys deleted", "Registry keys queried",
                      "Реестр", "Ключи реестра изменены", "Ключи реестра удалены", "Запросы к реестру"],
        "mutexes":   ["Mutexes", "Mutants", "Мьютексы"],
        "mitre":     ["MITRE", "MITRE ATT&CK"],
    }
    NET_D = ["Domains", "Домены", "Hosts contacted", "DNS lookups", "DNS-запросы"]
    NET_I = ["IPs", "IP", "Hosts contacted", "Сеть"]
    NET_U = ["URLs", "HTTP conversations", "URL", "HTTP-сессии"]

    def _extract_block_texts(page, header_variants: List[str]) -> List[str]:
        txts: List[str] = []
        for title in header_variants:
            try:
                el = page.get_by_text(title, exact=False).first
                el.wait_for(state="attached", timeout=2_000)
                parent = el.locator("xpath=ancestor::*[self::section or self::div][1]")
                candidates = parent.locator("xpath=.//li | .//tr | .//div | .//span | .//a")
                for t in candidates.all_inner_texts():
                    s = " ".join((t or "").split()).strip()
                    if s:
                        txts.append(s)
                if txts:
                    break
            except Exception:
                continue
        out, seen = [], set()

        # Заголовки/мусор, которые не должны попадать в списки
        blacklist = {
            "Behavior","Behaviour","Поведение",
            "Processes","Created processes","Modules loaded",
            "Процессы","Созданные процессы","Загруженные модули",
            "Commands","Command executions","Command line",
            "Команды","Выполнение команд","Командная строка",
            "Domains","Hosts contacted","DNS lookups","URLs","HTTP conversations",
            "Домены","Обращения к узлам","DNS-запросы","URL","HTTP-диалоги",
            "Files","Files written","Files deleted","Files read",
            "Файлы","Запись файлов","Удаление файлов","Чтение файлов",
            "Registry","Registry keys set","Registry keys deleted","Registry keys queried",
            "Реестр","Ключи реестра изменены","Ключи реестра удалены","Запросы к реестру",
            "Mutexes","Mutants","Мьютексы",
            "MITRE","MITRE ATT&CK","ATT&CK",
            "MITRE ATT&CK Tactics and Techniques", "Tactics and Techniques",
            "Show more","Показать ещё"
        }

        for s in txts:
            s = s.strip()
            if not s or len(s) <= 2:
                continue
            if s in blacklist:
                continue
            if len(s) > 400:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)

        return out[:100]

    try:
        with sync_playwright() as pw:
            engine = getattr(pw, (browser or "chromium").strip().lower(), pw.chromium)
            br = engine.launch(headless=headless)
            ctx = br.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.set_default_timeout(timeout_sec * 1000)

            try:
                page.goto(url, wait_until="domcontentloaded")
            except Exception as e:
                errs.append(f"vt_ui_goto_error:{e}")
                try: br.close()
                except Exception: pass
                return [], errs

            # дать фронту дорисоваться и подгрузить блоки
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass
            # развернуть "Show more" / "Показать ещё", чтобы подтянуть все элементы
            for btn_text in ("Show more", "Показать ещё", "Show More"):
                try:
                    btn = page.get_by_role("button", name=btn_text).first
                    if btn.is_visible(timeout=500):
                        btn.click()
                        page.wait_for_timeout(800)
                except Exception:
                    pass

            try:
                processes = _extract_block_texts(page, H["processes"])
                commands  = _extract_block_texts(page, H["commands"])
                net_domains = _extract_block_texts(page, NET_D)
                net_ips     = _extract_block_texts(page, NET_I)
                net_urls    = _extract_block_texts(page, NET_U)
                files    = _extract_block_texts(page, H["files"])
                registry = _extract_block_texts(page, H["registry"])
                mutexes  = _extract_block_texts(page, H["mutexes"])
                mitre    = _extract_block_texts(page, H["mitre"])
            except Exception as _e:
                errs.append(f"vt_ui_extract_error:{type(_e).__name__}:{_e}")
                processes = commands = net_domains = net_ips = net_urls = files = registry = mutexes = mitre = []
            # Оставляем только строки с ID техник (T1xxx, T0xxx), убираем заголовок секции
            mitre    = [m for m in mitre if m and ("T1" in m or "T0" in m)]

            _vt_debug_log(
                f"[vt_ui] sha256={sha256} extracted processes={len(processes)} commands={len(commands)} "
                f"domains={len(net_domains)} ips={len(net_ips)} urls={len(net_urls)} "
                f"files={len(files)} registry={len(registry)} mutexes={len(mutexes)} mitre={len(mitre)}"
            )

            beh: Dict[str, Any] = {
                "summary": {
                    "processes": processes,
                    "commands": commands,
                    "network": {
                        "domains": net_domains,
                        "ips":     net_ips,
                        "urls":    net_urls,
                    },
                    "files":    files,
                    "registry": registry,
                    "mutexes":  mutexes,
                    "mitre":    mitre,
                },
                "sandbox_name": "VT-UI",
                "origin": "ui-scrape",
            }

            no_data = (
                not processes and not commands
                and not (net_domains or net_ips or net_urls)
                and not files and not registry and not mutexes and not mitre
            )
            if no_data:
                _vt_debug_log(f"[vt_ui] sha256={sha256} no_data=True -> vt_ui_behaviour_empty")
                try: br.close()
                except Exception: pass
                return [], ["vt_ui_behaviour_empty"]

            _vt_debug_log(f"[vt_ui] sha256={sha256} returning 1 session (VT-UI)")
            try:
                br.close()
            except Exception:
                pass
            return [beh], errs

    except Exception as e:
        errs.append(f"vt_ui_behaviour_error:{e}")
        _vt_debug_log(f"[vt_ui] sha256={sha256} exception: {e}")
        return [], errs


def vt_fetch_details_ui(
    sha256: str,
    *,
    browser: str = "chromium",
    headless: bool = True,
    timeout_sec: int = 45,
) -> Tuple[Dict[str, Any], List[str]]:
    """
    Скрейп вкладки Details: Basic properties, Names, ELF Info.
    Возвращает ({"basic_properties": {...}, "names": [...], "elf_info": {...}}, errors).
    """
    errs: List[str] = []
    url = f"https://www.virustotal.com/gui/file/{sha256}/details"
    out: Dict[str, Any] = {"basic_properties": {}, "names": [], "elf_info": {}}

    # Заголовки секций — не считать ключами
    _section_headers = frozenset([
        "Basic properties", "Properties", "Основные свойства",
        "Names", "File names", "Имена",
        "ELF information", "ELF Info", "ELF-информация", "ELF сведения", "ELF",
    ])

    def _section_texts(page, header_variants: List[str], max_items: int = 50) -> List[str]:
        for title in header_variants:
            try:
                el = page.get_by_text(title, exact=False).first
                el.wait_for(timeout=3_000)
                # Берём более широкий контейнер: 2-й уровень вверх или следующий sibling
                parent = el.locator("xpath=ancestor::*[self::section or self::div or self::article][2]")
                try:
                    nodes = parent.locator("xpath=.//*[self::div or self::span or self::p or self::li or self::tr or self::dt or self::dd or self::td]")
                except Exception:
                    parent = el.locator("xpath=ancestor::*[self::section or self::div or self::article][1]")
                    nodes = parent.locator("xpath=.//*[self::div or self::span or self::p or self::li or self::tr or self::dt or self::dd]")
                texts = []
                for t in nodes.all_inner_texts():
                    s = " ".join((t or "").split()).strip()
                    if s and s != title and len(s) < 500 and s.lower() not in (x.lower() for x in _section_headers):
                        texts.append(s)
                if texts:
                    return texts[:max_items]
            except Exception:
                continue
        return []

    def _parse_kv(lines: List[str]) -> Dict[str, str]:
        d: Dict[str, str] = {}
        for s in lines:
            if ":" in s:
                k, _, v = s.partition(":")
                k, v = k.strip(), v.strip()
                if k and v and k.lower() not in _section_headers and k != s:
                    d[k] = v
        return d

    def _fallback_from_page(page) -> List[str]:
        """Собрать со страницы все строки вида 'Key: value' (fallback если секции пустые)."""
        try:
            body = page.locator("main").first if page.locator("main").count() > 0 else page.locator("body")
            full = body.inner_text(timeout=5_000) or ""
        except Exception:
            return []
        lines = []
        for line in full.splitlines():
            s = " ".join(line.split()).strip()
            if ":" in s and 3 <= len(s) <= 300 and s.count(":") >= 1:
                lines.append(s)
        return lines[:60]

    try:
        with sync_playwright() as pw:
            engine = getattr(pw, (browser or "chromium").strip().lower(), pw.chromium)
            br = engine.launch(headless=headless)
            ctx = br.new_context(ignore_https_errors=True)
            page = ctx.new_page()
            page.set_default_timeout(timeout_sec * 1000)
            try:
                page.goto(url, wait_until="domcontentloaded")
            except Exception as e:
                errs.append(f"vt_details_goto:{e}")
                try: br.close()
                except Exception: pass
                return out, errs
            try:
                page.wait_for_timeout(2500)
            except Exception:
                pass
            for btn in ("Show more", "Показать ещё", "Show More"):
                try:
                    b = page.get_by_role("button", name=btn).first
                    if b.is_visible(timeout=500):
                        b.click()
                        page.wait_for_timeout(600)
                except Exception:
                    pass
            fallback = _fallback_from_page(page)

            basic_lines = _section_texts(page, ["Basic properties", "Основные свойства", "Properties"], 40)
            if basic_lines:
                out["basic_properties"] = _parse_kv(basic_lines)
            if not out["basic_properties"] and fallback:
                out["basic_properties"] = _parse_kv(fallback)
            if not out["basic_properties"] and basic_lines:
                out["basic_properties"] = {"_raw": "; ".join(basic_lines[:15])}

            names_lines = _section_texts(page, ["Names", "Имена", "File names"], 30)
            if names_lines:
                skip = {"Names", "Имена", "File names", "Show more", "Показать ещё"} | _section_headers
                out["names"] = [n for n in names_lines if n not in skip and len(n) > 1 and len(n) < 300 and ":" not in n]
            if not out["names"] and fallback:
                for line in fallback:
                    if ":" in line and "name" in line.lower()[:20]:
                        k, _, v = line.partition(":")
                        if v.strip() and len(v.strip()) < 250:
                            out["names"].append(v.strip())

            elf_lines = _section_texts(page, ["ELF information", "ELF Info", "ELF-информация", "ELF сведения"], 60)
            if elf_lines:
                out["elf_info"] = _parse_kv(elf_lines)
            if not out["elf_info"] and fallback:
                elf_like = [x for x in fallback if any(z in x.lower() for z in ("elf", "entry", "class", "machine", "abi", "section", "segment"))]
                if elf_like:
                    out["elf_info"] = _parse_kv(elf_like)
            if not out["elf_info"] and elf_lines:
                out["elf_info"] = {"_raw": "; ".join(elf_lines[:20])}
            try:
                br.close()
            except Exception:
                pass
            _vt_debug_log(f"[vt_ui] details sha256={sha256} basic_keys={len(out['basic_properties'])} names={len(out['names'])} elf_keys={len(out['elf_info'])}")
    except Exception as e:
        errs.append(f"vt_details_error:{e}")
        _vt_debug_log(f"[vt_ui] details sha256={sha256} exception: {e}")
    return out, errs


def sha256_from_vt_link(link: str) -> Optional[str]:
    """
    Из ссылки VT (например https://www.virustotal.com/gui/file/SHA256/...) извлекает SHA256.
    Поддерживает gui/file/ и api/v3/files/.
    """
    if not link or not isinstance(link, str):
        return None
    m = _SHA_FROM_LINK_RE.search(link.strip())
    return m.group(1).lower() if m else None


def vt_fetch_behaviour_by_link(
    link: str,
    *,
    browser: str = "chromium",
    headless: bool = True,
    timeout_sec: int = 90,
) -> Tuple[Optional[str], List[Dict[str, Any]], List[str]]:
    """
    На вход — только ссылка на файл в VT (gui или api).
    Открывает вкладку Behaviour в браузере и парсит всё поднаготную (процессы, команды, файлы, реестр, сеть и т.д.).
    Возвращает (sha256, [behaviour_dict], errors).
    Образец структуры как в vt.py: процессы, команды, files_written, registry, network и т.д.
    """
    sha = sha256_from_vt_link(link)
    if not sha:
        return None, [], ["vt_link_invalid: no SHA256 in link"]
    beh_list, errs = vt_fetch_behaviour_ui(sha, browser=browser, headless=headless, timeout_sec=timeout_sec)
    return sha, beh_list, errs
