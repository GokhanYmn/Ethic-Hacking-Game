"""Sözlük ve komut başvurusu: hy/veri/sozluk.json ve komutlar.json üzerinde arama."""
from __future__ import annotations

import json
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

VERI = Path(__file__).resolve().parents[1] / "veri"


def _sadelestir(s: str) -> str:
    s = unicodedata.normalize("NFKD", str(s))
    s = "".join(c for c in s if not unicodedata.combining(c))
    return s.replace("ı", "i").replace("İ", "i").casefold()


@lru_cache(maxsize=2)
def _yukle(ad: str) -> list:
    yol = VERI / ad
    try:
        veri = json.loads(yol.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return veri.get("terimler") or veri.get("komutlar") or []


def terimler() -> list:
    return _yukle("sozluk.json")


def komutlar() -> list:
    return _yukle("komutlar.json")


def ara(kayitlar: list, sorgu: str, alanlar: tuple) -> list:
    q = _sadelestir(sorgu).strip()
    if not q:
        return kayitlar
    puanli = []
    for k in kayitlar:
        metin = _sadelestir(" ".join(str(k.get(a, "")) for a in alanlar))
        ad = _sadelestir(str(k.get(alanlar[0], "")))
        if q in ad.split() or ad == q:
            puan = 0           # tam/kelime eşleşmesi önce
        elif ad.startswith(q):
            puan = 1
        elif re.search(r"\b" + re.escape(q), metin):
            puan = 2
        elif q in metin:
            puan = 3
        else:
            continue
        puanli.append((puan, _sadelestir(str(k.get(alanlar[0], ""))), k))
    puanli.sort(key=lambda x: (x[0], x[1]))
    return [k for _, _, k in puanli]


def terim_ara(sorgu: str) -> list:
    return ara(terimler(), sorgu, ("terim", "tr", "aciklama"))


def komut_ara(sorgu: str) -> list:
    return ara(komutlar(), sorgu, ("ad", "kategori", "aciklama", "ornek"))
