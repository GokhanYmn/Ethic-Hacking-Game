"""Terminal görünümü: renkler, kutular ve basit işaretleme (md-lite).

İşaretleme kuralları (seviye metinlerinde kullanılır):
  - Boş satır paragrafları ayırır, paragraf içi satırlar birleştirilip sarılır.
  - ``` ile çevrili bloklar kod bloğudur (sarılmaz, renklenir).
  - "- " ile başlayan satırlar madde, "1. " ile başlayanlar numaralı maddedir.
  - "# " ile başlayan satır alt başlıktır.
  - Satır içi `kod` ve **kalın** desteklenir.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import textwrap

_KODLAR = {
    "kalin": "1", "soluk": "2", "kirmizi": "31", "yesil": "32", "sari": "33",
    "mavi": "34", "mor": "35", "camgobegi": "36", "gri": "90", "beyaz": "97",
}


def renk_acik() -> bool:
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("HY_RENK") == "1":
        return True
    return sys.stdout.isatty()


def r(metin: str, *stiller: str) -> str:
    """Metni verilen stillerle renklendirir (renk kapalıysa olduğu gibi döner)."""
    if not stiller or not renk_acik():
        return metin
    kod = ";".join(_KODLAR[s] for s in stiller)
    return f"\033[{kod}m{metin}\033[0m"


def genislik() -> int:
    sutun = shutil.get_terminal_size((90, 24)).columns
    return max(50, min(100, sutun - 2))


_NBSP = "\x00"


def _satir_ici(satir: str) -> str:
    satir = re.sub(r"`([^`]+)`", lambda m: r(m.group(1), "camgobegi"), satir)
    satir = re.sub(r"\*\*([^*]+)\*\*", lambda m: r(m.group(1), "kalin"), satir)
    return satir.replace(_NBSP, " ")


def _kilitle(metin: str) -> str:
    """Kod ve kalın parçalarının satır sonunda bölünmemesi için içindeki boşlukları kilitler."""
    return re.sub(r"(`[^`]+`|\*\*[^*]+\*\*)", lambda m: m.group(0).replace(" ", _NBSP), metin)


def _sar(metin: str, gen: int, ilk: str = "", sonraki: str = "") -> list[str]:
    satirlar = textwrap.wrap(
        _kilitle(metin), width=gen, initial_indent=ilk, subsequent_indent=sonraki,
        break_long_words=False, break_on_hyphens=False,
    )
    return [_satir_ici(s) for s in satirlar] or [ilk.rstrip()]


def md(metin: str, girinti: int = 2, gen: int | None = None) -> str:
    """md-lite metnini terminal için biçimlendirir."""
    gen = gen or genislik()
    bosluk = " " * girinti
    satirlar = textwrap.dedent(metin).strip("\n").split("\n")
    cikti: list[str] = []
    paragraf: list[str] = []

    def bosalt():
        if paragraf:
            cikti.extend(_sar(" ".join(paragraf), gen, bosluk, bosluk))
            paragraf.clear()

    i = 0
    while i < len(satirlar):
        s = satirlar[i]
        yalin = s.strip()
        if yalin.startswith("```"):
            bosalt()
            i += 1
            while i < len(satirlar) and not satirlar[i].strip().startswith("```"):
                cikti.append(bosluk + r("│ ", "gri") + r(satirlar[i].rstrip(), "camgobegi"))
                i += 1
        elif not yalin:
            bosalt()
            if cikti and cikti[-1] != "":
                cikti.append("")
        elif yalin.startswith("# "):
            bosalt()
            cikti.append(bosluk + r(yalin[2:], "kalin", "sari"))
        elif re.match(r"[-•] ", yalin):
            bosalt()
            madde = yalin[2:]
            while i + 1 < len(satirlar) and satirlar[i + 1].startswith("  ") and satirlar[i + 1].strip() \
                    and not re.match(r"\s*([-•] |\d+\. |```)", satirlar[i + 1]):
                i += 1
                madde += " " + satirlar[i].strip()
            cikti.extend(_sar(madde, gen, bosluk + "• ", bosluk + "  "))
        elif re.match(r"\d+\. ", yalin):
            bosalt()
            no, madde = yalin.split(" ", 1)
            while i + 1 < len(satirlar) and satirlar[i + 1].startswith("  ") and satirlar[i + 1].strip() \
                    and not re.match(r"\s*([-•] |\d+\. |```)", satirlar[i + 1]):
                i += 1
                madde += " " + satirlar[i].strip()
            cikti.extend(_sar(madde, gen, bosluk + no + " ", bosluk + " " * (len(no) + 1)))
        else:
            paragraf.append(yalin)
        i += 1
    bosalt()
    while cikti and cikti[-1] == "":
        cikti.pop()
    return "\n".join(cikti)


KUTU_RENK = {
    "BRİFİNG": "sari",
    "İPUCU": "mavi",
    "DİKKAT": "kirmizi",
    "HACKER GÖZÜYLE": "yesil",
    "GERÇEK HAYATTA": "mor",
    "GÖREV": "camgobegi",
    "BAŞARI": "yesil",
}


def kutu(baslik: str, govde: str, renk: str | None = None) -> str:
    """Sol kenar çizgili kutu: kitabın İPUCU/DİKKAT kutularının terminal karşılığı."""
    renk = renk or KUTU_RENK.get(baslik, "camgobegi")
    cizgi = r("┃ ", renk)
    ic = md(govde, girinti=0, gen=genislik() - 4)
    satirlar = [cizgi + r(baslik, "kalin", renk)] + [cizgi + s for s in ic.split("\n")]
    return "\n".join("  " + s for s in satirlar)


def baslik_cubugu(metin: str, renk: str = "camgobegi") -> str:
    gen = genislik()
    govde = f"━━ {metin} "
    return r(govde + "━" * max(3, gen - len(govde)), "kalin", renk)


def ilerleme(oran: float, gen: int = 20) -> str:
    oran = max(0.0, min(1.0, oran))
    dolu = round(oran * gen)
    return r("▓" * dolu, "yesil") + r("░" * (gen - dolu), "gri")


def temizle() -> None:
    if sys.stdout.isatty() and os.environ.get("HY_TEMIZLEME") != "0":
        print("\033[2J\033[H", end="")


def sor(istem: str) -> str:
    """Kullanıcıdan satır okur; Ctrl+D/Ctrl+C 'q' sayılır."""
    try:
        return input(istem).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return "q"


def bekle(mesaj: str = "Devam etmek için Enter'a bas") -> bool:
    """Enter bekler. 'q' girilirse False döner."""
    return sor(r(f"\n  [{mesaj}] ", "gri")).lower() != "q"


def onay(soru: str) -> bool:
    return sor(f"  {soru} [e/h] ").lower() in ("e", "evet", "y", "yes")


def basari(metin: str) -> str:
    return r("  ✔ ", "yesil", "kalin") + r(metin, "yesil")


def hata(metin: str) -> str:
    return r("  ✘ ", "kirmizi", "kalin") + metin


def bilgi(metin: str) -> str:
    return r("  ● ", "camgobegi") + metin
