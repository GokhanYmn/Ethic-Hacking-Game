"""Cilt 14 ortak yardımcıları (Cilt 16 da `Esle` ve `sh` için buradan alır).

- `sh`, `sec_doldur`: test çözücüsü yardımcıları.
- `Esle`: numaralı öğeleri harfli kategorilere eşleme (cevap: `1c 2a 3d`).
- `manifest_oku`: kurgusal AndroidManifest.xml dosyasını xml.etree ile okur.
- `VAKALAR`: mobil finans/fintech uygulaması vakaları (hepsi kurgusal).
Hiçbir dosya gerçek bir uygulamadan türetilmedi; anahtarlar ve token'lar rastgele üretilmiş sahte dizgilerdir.
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from hy.motor.kontrol import Baglam, Kontrol, Secmeli, Sonuc

ANDROID = "http://schemas.android.com/apk/res/android"


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır (rehber bölüm 10)."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


class Esle(Kontrol):
    """Numaralı öğeleri harfli kategorilere eşleme. Cevap örn. `1c 2a 3d 4b`."""
    bicim = "eşleme, örn. 1c 2a 3d 4b"

    def __init__(self, anahtar: str, sik_hatalar=None):
        self.anahtar = anahtar
        self.sik_hatalar = sik_hatalar

    @staticmethod
    def _coz(girdi: str) -> dict:
        return {n: h.lower() for n, h in re.findall(r"(\d+)\s*[-:=.)]?\s*([A-Za-z])\b", girdi)}

    def dogrula(self, girdi: str, b) -> Sonuc:
        beklenen = {str(k): v for k, v in self.beklenen(b).items()}
        verilen = self._coz(girdi)
        if not verilen:
            return Sonuc(False, "Eşlemeyi `1c 2a 3d` biçiminde yaz (numara + harf).")
        if verilen == beklenen:
            return Sonuc(True)
        if len(verilen) != len(beklenen):
            return Sonuc(False, f"{len(beklenen)} öğenin hepsini eşle; sen {len(verilen)} tane yazdın.",
                         yakin=len(verilen) > 0 and bool(set(verilen) & set(beklenen)))
        dogru = sum(1 for k, v in verilen.items() if beklenen.get(k) == v)
        return Sonuc(False, f"{dogru}/{len(beklenen)} eşleme doğru." if dogru else "", yakin=dogru > 0)

    def cevabi_goster(self, b) -> str:
        return " ".join(f"{k}{v}" for k, v in sorted(self.beklenen(b).items()))


def harfli(rng, ogeler: list, kategoriler: list) -> tuple:
    """Kategorileri karıştırıp harf atar; öğeleri karıştırıp numara atar.

    ogeler: [(metin, kategori_adi)]; kategoriler: [kategori_adi]. Döndürür: (soru_metni, {no: harf}).
    """
    kat = list(kategoriler)
    rng.shuffle(kat)
    harf = {k: "abcdefgh"[i] for i, k in enumerate(kat)}
    sira = list(ogeler)
    rng.shuffle(sira)
    satirlar = [f"{i}) {m}" for i, (m, _) in enumerate(sira, 1)]
    secenek = [f"{harf[k]}) {k}" for k in kat]
    metin = "\n".join(satirlar) + "\n\nKategoriler:\n" + "\n".join(secenek)
    return metin, {str(i): harf[k] for i, (_, k) in enumerate(sira, 1)}


# ----------------------------------------------------------------------------- manifest

def manifest_oku(yol: Path) -> dict:
    """{'hata': str|None, 'uygulama': {ad: değer}, 'bilesenler': [{tur, ad, exported, izin, launcher, etkili}]}."""
    try:
        kok = ET.parse(yol).getroot()
    except (ET.ParseError, OSError) as e:
        return {"hata": f"{yol.name} okunamadı ({e}). XML bozuk olabilir.", "uygulama": {}, "bilesenler": []}
    uyg = kok.find("application")
    if uyg is None:
        return {"hata": "<application> öğesi bulunamadı.", "uygulama": {}, "bilesenler": []}
    ozn = {k.replace("{%s}" % ANDROID, ""): v for k, v in uyg.attrib.items()}
    bilesenler = []
    for e in uyg:
        if e.tag not in ("activity", "service", "receiver", "provider"):
            continue
        a = {k.replace("{%s}" % ANDROID, ""): v for k, v in e.attrib.items()}
        filtreler = e.findall("intent-filter")
        launcher = any(c.get("{%s}name" % ANDROID) == "android.intent.category.LAUNCHER"
                       for f in filtreler for c in f.findall("category"))
        ex = a.get("exported")
        etkili = (ex == "true") if ex is not None else bool(filtreler)
        bilesenler.append({"tur": e.tag, "ad": a.get("name", "").lstrip("."), "exported": ex,
                           "izin": a.get("permission"), "launcher": launcher, "etkili": etkili})
    return {"hata": None, "uygulama": ozn, "bilesenler": bilesenler}


def korunmasiz(b: dict) -> bool:
    """Dışarıya açık, izinsiz ve ana ekran girişi olmayan bileşen mi?"""
    return b["etkili"] and not b["izin"] and not b["launcher"]


VAKALAR = [
    {"kod": "ferah", "ad": "Ferah Bank", "uyg": "Ferah Mobil Şube", "paket": "lab.ferahbank.mobil",
     "api": "mobil-api.ferahbank.lab", "alan": "ferahbank.lab", "sektor": "banka", "sinif": "Havale",
     "hikaye": "Mobil şubede bir müşteri, telefonunu bir tamirciye bıraktıktan sonra hesabına yabancı bir cihazdan girildiğini bildirdi.",
     "veri": "hesap bakiyeleri ve havale geçmişi"},
    {"kod": "paramix", "ad": "Paramix", "uyg": "Paramix Cüzdan", "paket": "lab.paramix.cuzdan",
     "api": "api.paramix.lab", "alan": "paramix.lab", "sektor": "fintech", "sinif": "Odeme",
     "hikaye": "Paramix, yeni sürüm yayımlamadan önce bağımsız bir mobil güvenlik incelemesi istedi.",
     "veri": "cüzdan bakiyesi ve kayıtlı kart bilgileri"},
    {"kod": "kuzey", "ad": "Kuzey Yatırım", "uyg": "Kuzey Portföy", "paket": "lab.kuzeyyatirim.portfoy",
     "api": "mobil.kuzeyyatirim.lab", "alan": "kuzeyyatirim.lab", "sektor": "yatırım kuruluşu", "sinif": "Emir",
     "hikaye": "Kuzey Yatırım'ın hisse alım-satım uygulaması mağazada kullanıcı şikâyetleriyle gündeme geldi: 'Hesabım başkasının cihazında açık kaldı.'",
     "veri": "portföy bilgileri ve alım-satım emirleri"},
    {"kod": "pazarix", "ad": "Pazarix", "uyg": "Pazarix Alışveriş", "paket": "lab.pazarix.alisveris",
     "api": "m.pazarix.lab", "alan": "pazarix.lab", "sektor": "e-ticaret", "sinif": "Siparis",
     "hikaye": "Pazarix, uygulamasına kayıtlı kart ve adres bilgisi eklemeden önce mobil güvenlik taramasından geçmek istiyor.",
     "veri": "kayıtlı kartlar, adresler ve sipariş geçmişi"},
]


def vaka_sec(rng) -> dict:
    return dict(rng.choice(VAKALAR))


def hex_(rng, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))
