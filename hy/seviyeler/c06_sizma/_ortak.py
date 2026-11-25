"""Cilt 6 seviyelerinin ortak yardımcıları (kabuk çalıştırma, küçük dosya işlemleri)."""
from __future__ import annotations

import subprocess
from pathlib import Path


def sh(komut: str, lab: Path) -> str:
    """Test çözücüleri için: komutu lab dizininde bash ile çalıştırıp çıktısını döndürür."""
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def satirlar(yol: Path) -> list:
    """Dosyanın yorum olmayan, boş olmayan satırları (dosya yoksa boş liste)."""
    try:
        metin = yol.read_text(encoding="utf-8")
    except OSError:
        return []
    return [x for x in metin.splitlines() if x.strip() and not x.lstrip().startswith("#")]
