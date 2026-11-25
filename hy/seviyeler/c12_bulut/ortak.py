"""Cilt 12 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

Bulut kaynakları tamamen kurgusaldır: hesap numaraları, kova adları, anahtarlar gerçek değildir.
Hiçbir görev internete ya da bir bulut servisine istek yapmaz; her şey lab'a yazılan dosyalardır.
"""
from __future__ import annotations

import json
import random
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
    {"kod": "pazarix", "ad": "Pazarix", "alan": "pazarix.lab", "on": "pzx", "sektor": "e-ticaret",
     "veri": "müşteri adresleri ve sipariş geçmişi"},
    {"kod": "medora", "ad": "Medora Sağlık", "alan": "medora.lab", "on": "mdr", "sektor": "hastane",
     "veri": "hasta randevuları ve tanı notları"},
    {"kod": "paramix", "ad": "Paramix", "alan": "paramix.lab", "on": "pmx", "sektor": "fintech",
     "veri": "üye işyeri ödeme kayıtları"},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "alan": "kuzgun.lab", "on": "kzg", "sektor": "lojistik",
     "veri": "alıcı adresleri ve sevkiyat kayıtları"},
    {"kod": "ferahbank", "ad": "Ferah Bank", "alan": "ferahbank.lab", "on": "fb", "sektor": "banka",
     "veri": "müşteri hesap hareketleri"},
]


def sirket_sec(rng: random.Random, kodlar=None) -> dict:
    adaylar = [s for s in SIRKETLER if not kodlar or s["kod"] in kodlar]
    return dict(rng.choice(adaylar))


def json_yaz(nesne) -> str:
    return json.dumps(nesne, indent=2, ensure_ascii=False) + "\n"


def hex_(rng: random.Random, n: int = 6) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def json_satirli(ust: dict, listeler: dict) -> str:
    """Her kaydı tek satırda yazan geçerli JSON (grep/sed ile satır satır işlenebilir)."""
    parcalar = [f'  "{k}": {json.dumps(v, ensure_ascii=False)}' for k, v in ust.items()]
    for ad, kayitlar in listeler.items():
        satirlar = ",\n".join("    " + json.dumps(k, ensure_ascii=False) for k in kayitlar)
        parcalar.append(f'  "{ad}": [\n{satirlar}\n  ]')
    return "{\n" + ",\n".join(parcalar) + "\n}\n"


def liste(x) -> list:
    return x if isinstance(x, list) else [x]
