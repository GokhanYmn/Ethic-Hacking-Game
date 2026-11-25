"""Cilt 21-23 ortak yardımcıları (bu üç cildin seviyeleri kullanır).

- `sh`          : bash ile komut çalıştırır (test çözücüleri için).
- `Dizi`        : sıralı kod listesi kontrolü (eşleme ya da sıralama). Cevap: `c a e b d`.
- `sec_doldur`  : test çözücüsü için çoktan seçmeli cevapları kontrolden alır.
- `csv_yaz`     : CSV dosyası yazar.
Hepsi kurgusal veridir; gerçek kişi, kurum ya da numara içermez.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Kontrol, Secmeli, Sonuc
from hy.ortak import uretec as u


def sh(komut: str, lab: Path, zaman: int = 60) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True,
                          timeout=zaman).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır (rehber bölüm 10)."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


def csv_yaz(yol: Path, baslik: str, satirlar: list) -> Path:
    return u.yaz(yol, baslik + "\n" + "\n".join(satirlar) + "\n")


class Dizi(Kontrol):
    """Sıralı kod listesi (eşleme / sıralama). Cevap: kodlar sırayla, örn. `c a e b d`."""

    def __init__(self, anahtar: str, sik_hatalar=None, bicim: str = "kodlar sırayla, örn. c a e b d"):
        self.anahtar = anahtar
        self.sik_hatalar = sik_hatalar
        self.bicim = bicim

    @staticmethod
    def _parcala(girdi: str) -> list:
        g = str(girdi).casefold().replace("ı", "i")
        return re.findall(r"[a-z0-9]+", g)

    def dogrula(self, girdi: str, b) -> Sonuc:
        beklenen = [str(x).casefold() for x in self.beklenen(b)]
        verilen = self._parcala(girdi)
        if not verilen:
            return Sonuc(False, "Kodları sırayla yaz, örn. `c a e b d`.")
        if verilen == beklenen:
            return Sonuc(True)
        if len(verilen) == 1 and len(beklenen) > 1 and len(verilen[0]) == len(beklenen):
            verilen = list(verilen[0])           # "caebd" biçimi de kabul
            if verilen == beklenen:
                return Sonuc(True)
        if self.sik_hatalar:
            mesaj = self.sik_hatalar(verilen, beklenen, b)
            if mesaj:
                return Sonuc(False, mesaj, yakin=True)
        if len(verilen) != len(beklenen):
            return Sonuc(False, f"{len(beklenen)} kod bekleniyor, sen {len(verilen)} tane yazdın.")
        dogru = sum(1 for a, c in zip(verilen, beklenen) if a == c)
        return Sonuc(False, f"{dogru}/{len(beklenen)} kod doğru yerde." if dogru else "", yakin=dogru > 0)

    def cevabi_goster(self, b) -> str:
        return " ".join(str(x) for x in self.beklenen(b))
