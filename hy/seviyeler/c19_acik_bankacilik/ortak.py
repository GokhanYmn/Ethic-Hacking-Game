"""Cilt 19 ortak yardımcıları: test çözücüsü araçları ve kurgusal JWT üretimi.

Bütün kişiler, şirketler, token'lar ve imzalar kurgusaldır; imza rastgele metindir, hiçbir gerçek
anahtarla üretilmez ve hiçbir sistemde geçerli değildir.
"""
from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Secmeli


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Test çözücüsü: çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _kodla(d: dict) -> str:
    """JSON'u base64url yapar. Dolgu (`=`) ve `-`/`_` çıkmasın diye boşlukla 3'ün katına tamamlar,
    gerekirse `n` adlı zararsız bir alan ekler. Böylece lab'da `base64 -d` doğrudan çalışır."""
    for n in range(1000):
        d2 = dict(d)
        if n:
            d2["n"] = n
        ham = json.dumps(d2, ensure_ascii=False, separators=(",", ":"))
        ham += " " * (-len(ham.encode()) % 3)
        kod = _b64u(ham.encode())
        if "-" not in kod and "_" not in kod:
            return kod
    raise RuntimeError("uygun kodlama bulunamadı")


def jwt_yap(rng, baslik: dict, yuk: dict, imzali: bool = True) -> str:
    """header.payload.signature biçiminde kurgusal JWT (imza rastgele metin; `alg: none` için boş)."""
    harfler = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    imza = "".join(rng.choice(harfler) for _ in range(43)) if imzali else ""
    return f"{_kodla(baslik)}.{_kodla(yuk)}.{imza}"
