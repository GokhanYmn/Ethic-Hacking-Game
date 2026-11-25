"""Cilt 20 ortak yardımcıları: test çözücüsü araçları ve kurgusal kart verisi.

Bütün kişiler ve şirketler kurgusaldır. Kart numaraları YALNIZCA herkesçe bilinen test kartı
numaralarıdır (ödeme sağlayıcıların belgelerindeki örnekler); gerçek kart verisi yoktur.
"""
from __future__ import annotations

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


# Herkesçe bilinen 16 haneli test kartı numaraları (gerçek kimseye ait değildir)
TEST_PAN = ["4111111111111111", "5555555555554444", "4012888888881881", "5105105105105100",
            "6011111111111117", "3566002020360505"]


def maske(pan: str) -> str:
    """İlk 6 + yıldız + son 4 (PCI'da gösterim için izin verilen biçim)."""
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:]


def token(rng) -> str:
    """Kart numarasıyla ilgisiz, rakam dizisi içermeyen anlamsız token."""
    h = "0123456789abcdef"
    return "tok_" + "-".join("".join(rng.choice(h[10:] + h[:4]) for _ in range(4)) for _ in range(4))
