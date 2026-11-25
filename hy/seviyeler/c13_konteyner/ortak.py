"""Cilt 13 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

Bütün compose/Dockerfile/Kubernetes dosyaları KURGUSALDIR ve hiçbir zaman çalıştırılmaz:
görevler dosyaları okur, riskli ayarı bulur ve düzeltir. PyYAML yoktur; ayrıştırma satır tabanlıdır
(düzenli ifadelerle) ve yalnızca bu cildin kendi yazdığı sabit biçimleri tanır.
"""
from __future__ import annotations

import random
import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Secmeli


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def py(kod: str, lab: Path) -> str:
    return subprocess.run(["python3", "-c", kod], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


SIRKETLER = [
    {"kod": "pazarix", "ad": "Pazarix", "alan": "pazarix.lab", "on": "pzx",
     "servisler": ["vitrin", "siparis-api", "kuyruk-isci", "izleyici", "veritabani"]},
    {"kod": "medora", "ad": "Medora Sağlık", "alan": "medora.lab", "on": "mdr",
     "servisler": ["portal", "randevu-api", "bildirim-isci", "izleme-ajani", "veritabani"]},
    {"kod": "paramix", "ad": "Paramix", "alan": "paramix.lab", "on": "pmx",
     "servisler": ["yonetim-paneli", "odeme-api", "webhook-isci", "metrik-ajani", "veritabani"]},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "alan": "kuzgun.lab", "on": "kzg",
     "servisler": ["takip-sitesi", "rota-api", "sevkiyat-isci", "filo-ajani", "veritabani"]},
]


def sirket_sec(rng: random.Random) -> dict:
    return dict(rng.choice(SIRKETLER))


def hex_(rng: random.Random, n: int = 6) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def servis_bloklari(metin: str) -> dict:
    """compose dosyasında `services:` altındaki her servisin satırlarını {ad: blok_metni} verir."""
    bloklar: dict = {}
    ad = None
    satirlar: list = []
    icinde = False
    for ham in metin.splitlines():
        if re.match(r"^services:\s*$", ham):
            icinde = True
            continue
        if not icinde:
            continue
        if ham and not ham.startswith(" ") and not ham.startswith("#"):
            break
        m = re.match(r"^  ([\w.-]+):\s*$", ham)
        if m:
            if ad is not None:
                bloklar[ad] = "\n".join(satirlar)
            ad, satirlar = m.group(1), []
        elif ad is not None:
            satirlar.append(ham)
    if ad is not None:
        bloklar[ad] = "\n".join(satirlar)
    return bloklar
