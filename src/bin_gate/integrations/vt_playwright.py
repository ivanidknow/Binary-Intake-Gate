from __future__ import annotations
from pathlib import Path
from typing import Optional, Tuple, List
import re

def vt_upload_file_ui(path: Path, *, browser: str = "chromium", headless: bool = True, timeout_sec: int = 180) -> Tuple[Optional[str], List[str]]:
    """
    Загружает файл через https://www.virustotal.com/gui/home/upload и возвращает sha256 из URL.
    Требует: pip install playwright; python -m playwright install chromium
    Важно: автоматизация UI может подпадать под ограничения/ToS VT — используй легально.
    """
    errs: List[str] = []
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except Exception as e:
        return None, [f"vt_ui_not_installed:{e}"]

    url = "https://www.virustotal.com/gui/home/upload"
    sha_re = re.compile(r"/gui/file/([0-9a-fA-F]{64})/")

    try:
        with sync_playwright() as p:
            b = {"chromium": p.chromium, "firefox": p.firefox, "webkit": p.webkit}.get(browser)
            if not b:
                return None, [f"vt_ui_bad_browser:{browser}"]
            br = b.launch(headless=headless)
            ctx = br.new_context()
            page = ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=30_000)

            # input[type=file]
            fp = str(path)
            page.set_input_files("input[type='file']", fp)

            # После attach VT перенаправляет на /gui/file/<sha256>/detection
            page.wait_for_url(re.compile(r".*/gui/file/[0-9a-fA-F]{64}/.*"), timeout=timeout_sec*1000)
            cur = page.url
            m = sha_re.search(cur)
            if not m:
                # иногда ссылка раскрывается в <a>; попробуем вычитать из href
                hrefs = page.locator("a").all_inner_texts()
                for h in hrefs:
                    mm = sha_re.search(h)
                    if mm:
                        sha = mm.group(1).lower()
                        br.close()
                        return sha, errs
                br.close()
                return None, ["vt_ui_no_sha_in_url"]
            sha = m.group(1).lower()
            br.close()
            return sha, errs

    except PWTimeout:
        return None, [f"vt_ui_timeout({timeout_sec}s)"]
    except Exception as e:
        return None, [f"vt_ui_error:{e}"]
