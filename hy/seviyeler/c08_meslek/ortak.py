"""Cilt 8 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

- `sh`            : bash ile komut çalıştırır (test çözücüleri için).
- `ascii_norm`    : Türkçe karakterleri sadeleştirip küçültür (karşılaştırma için).
- `sec_doldur`    : çoktan seçmeli görevlerin test cevabını kontrolün kendisinden alır.
- `Sira`          : numaralı öğeleri doğru sıraya dizdirme kontrolü.
- `alan_oku`      : "Alan: değer" biçimli bir rapor/plan dosyasını sözlüğe çevirir.
Bu cildin hiçbir seviyesi saldırı yükü ya da çalışır saldırı kodu içermez.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Kontrol, Secmeli, Sonuc

_TR = str.maketrans("ıİöÖüÜşŞçÇğĞ", "iIoOuUsScCgG")


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def ascii_norm(s: str) -> str:
    return s.translate(_TR).strip().lower()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Test çözücüsü için: çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır (rehber bölüm 10)."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


class Sira(Kontrol):
    """Numaralı öğeleri doğru sıraya dizme. Cevap: numaralar sırayla (`3 1 2 ...`)."""
    bicim = "numaralar sırayla, örn. 3 1 2"

    def __init__(self, anahtar: str, sik_hatalar=None):
        self.anahtar = anahtar
        self.sik_hatalar = sik_hatalar

    def dogrula(self, girdi: str, b) -> Sonuc:
        beklenen = [int(x) for x in self.beklenen(b)]
        verilen = [int(x) for x in re.findall(r"\d+", girdi)]
        if not verilen:
            return Sonuc(False, "Numaraları sırayla yaz, örn. `3 1 2`.")
        if verilen == beklenen:
            return Sonuc(True)
        if self.sik_hatalar:
            mesaj = self.sik_hatalar(verilen, beklenen, b)
            if mesaj:
                return Sonuc(False, mesaj, yakin=True)
        if len(verilen) != len(beklenen):
            return Sonuc(False, f"{len(beklenen)} numara bekleniyor, sen {len(verilen)} tane yazdın.")
        dogru = sum(1 for a, c in zip(verilen, beklenen) if a == c)
        return Sonuc(False, f"{dogru}/{len(beklenen)} numara doğru yerde." if dogru else "", yakin=dogru > 0)

    def cevabi_goster(self, b) -> str:
        return " ".join(str(x) for x in self.beklenen(b))


def alan_oku(metin: str, alanlar: list) -> dict:
    """`Alan: değer` satırlarını ayrıştırır. Bir alanın değeri sonraki alan başlığına kadar sürer.

    Alan adları Türkçe karakter ve büyük/küçük harf farkından bağımsız eşleşir. Dönüş: {sade_ad: metin}.
    """
    sade = {ascii_norm(a): ascii_norm(a) for a in alanlar}
    sonuc: dict = {}
    simdiki = None
    for satir in metin.splitlines():
        m = re.match(r"^\s*[#*\-]*\s*\**([A-Za-zÇĞİÖŞÜçğıöşü ]+?)\**\s*:\s*(.*)$", satir)
        if m and ascii_norm(m.group(1)) in sade:
            simdiki = ascii_norm(m.group(1))
            sonuc[simdiki] = m.group(2).strip()
        elif simdiki is not None:
            sonuc[simdiki] += " " + satir.strip()
    return {k: v.strip() for k, v in sonuc.items()}
