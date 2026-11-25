"""Cilt 11 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

- `sh` / `py`      : test çözücüleri için komut çalıştırıcılar.
- `sec_doldur`     : çoktan seçmeli görevlerin test cevabını kontrolden alır.
- `hesap_adlari`   : kurgusal kullanıcı adları (ad.soyad).
- `sirket_sec`     : vaka şirketi (alan adı, NetBIOS adı, ön ek, birimler).
- `json_satirli`   : her kaydı tek satırda yazan, geçerli JSON (grep ile süzülebilir).
Hiçbir dosya çalıştırılabilir saldırı içeriği taşımaz; hepsi kurgusal düz metindir.
"""
from __future__ import annotations

import json
import random
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Secmeli
from hy.ortak import uretec as u


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def py(kod: str, lab: Path) -> str:
    return subprocess.run(["python3", "-c", kod], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


SOYADLAR = ["yilmaz", "kaya", "demir", "celik", "sahin", "arslan", "dogan", "kilic", "aydin", "ozturk",
            "polat", "korkmaz", "tekin", "aksoy", "gunes", "erdem", "bozkurt", "yavuz", "taskin", "coskun"]


def hesap_adlari(rng: random.Random, adet: int, haric=()) -> list:
    return u.benzersiz(rng, lambda r: f"{r.choice(u.ISIMLER)}.{r.choice(SOYADLAR)}", adet, set(haric))


SIRKETLER = [
    {"kod": "ferahbank", "ad": "Ferah Bank", "alan": "ferahbank.lab", "nb": "FERAH", "on": "fb",
     "ouler": ["Subeler", "GenelMudurluk", "KrediBirimi", "CagriMerkezi"]},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "alan": "kuzgun.lab", "nb": "KUZGUN", "on": "kzg",
     "ouler": ["Depolar", "Filo", "Muhasebe", "Operasyon"]},
    {"kod": "yesiltepe", "ad": "Yeşiltepe Belediyesi", "alan": "yesiltepe.lab", "nb": "YTB", "on": "ytb",
     "ouler": ["FenIsleri", "Zabita", "EvlendirmeDairesi", "BilgiIslem"]},
    {"kod": "medora", "ad": "Medora Sağlık", "alan": "medora.lab", "nb": "MEDORA", "on": "mdr",
     "ouler": ["Poliklinikler", "Laboratuvar", "Eczane", "Randevu"]},
]


def sirket_sec(rng: random.Random) -> dict:
    return dict(rng.choice(SIRKETLER))


def json_satirli(ust: dict, listeler: dict) -> str:
    """Her kayıt tek satırda olan geçerli JSON: `grep` ile satır satır süzülebilir."""
    parcalar = [f'  "{k}": {json.dumps(v, ensure_ascii=False)}' for k, v in ust.items()]
    for ad, kayitlar in listeler.items():
        satirlar = ",\n".join("    " + json.dumps(k, ensure_ascii=False) for k in kayitlar)
        parcalar.append(f'  "{ad}": [\n{satirlar}\n  ]')
    return "{\n" + ",\n".join(parcalar) + "\n}\n"
