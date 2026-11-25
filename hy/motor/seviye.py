"""Seviye, görev ve eğitim adımı tanımları + seviye kayıt defteri."""
from __future__ import annotations

import importlib
import pkgutil
import random
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


@dataclass
class Adim:
    """Eğitim adımı: kısa anlatım + isteğe bağlı 'şimdi sen yaz' komutu."""
    baslik: str
    metin: str
    komut: Optional[str] = None            # oyuncunun yazması beklenen komut
    alternatifler: tuple = ()              # kabul edilen diğer yazımlar
    calistir: bool = True                  # komut lab dizininde çalıştırılsın mı
    etkilesimli: bool = False              # less/man/nano gibi ekranı ele geçiren komutlar
    sonra: str = ""                        # komut çalıştıktan sonra gösterilen açıklama


@dataclass
class Gorev:
    """Saha görevindeki tek bir soru/iş."""
    soru: str
    kontrol: Any                           # hy.motor.kontrol.Kontrol
    ipuclari: tuple                        # 3 kademe: dürtme, yöntem, neredeyse çözüm
    puan: int = 30
    baslik: str = ""


@dataclass
class Seviye:
    kimlik: str                            # örn. "c01b02"
    cilt: int
    bolum: int
    baslik: str
    brifing: str
    gorevler: list
    uret: Callable[[random.Random], dict]  # saf fonksiyon: senaryo sözlüğü üretir
    adimlar: list = field(default_factory=list)
    yaz: Optional[Callable[[Path, dict], None]] = None          # lab dosyalarını yazar
    servis: Optional[Callable[[dict, Path, Any], None]] = None  # (senaryo, lab, dur_olayi) — bloklar
    coz: Optional[Callable[[Path, dict], dict]] = None          # SADECE TEST: {görev_no: cevap}
    kapanis: str = ""                      # "Hacker Gözüyle" metni
    gercek_hayat: str = ""                 # "Gerçek Hayatta" metni
    sure_hedef_dk: int = 25                # Hızlı Müdahale rozeti için
    tamamlama_bonusu: int = 50
    olay_masasi: bool = False              # Olay Masası (antrenman) ailesi mi
    on_kosul: tuple = ()                   # açılması için bitmiş olması gereken seviye kimlikleri

    def senaryo(self, tohum: int) -> dict:
        """Tohumdan senaryo üretir.

        Senaryo sözlüğü:
          cevaplar: {anahtar: beklenen}     — kontroller buradan okur
          metin:    {ad: değer}             — metinlerdeki <<ad>> yer tutucuları
          vaka:     "Hastane randevu sistemi" (isteğe bağlı; aynı becerinin hangi hikâyeyle
                    sunulduğu — tekrar oynayınca başka vaka seçilir)
          brifing:  (isteğe bağlı) vakaya özel brifing; verilirse Seviye.brifing yerine gösterilir
        """
        s = self.uret(random.Random(f"{self.kimlik}:{tohum}"))
        s.setdefault("cevaplar", {})
        s.setdefault("metin", {})
        s["_tohum"] = tohum
        return s

    def brifing_metni(self, senaryo: dict) -> str:
        return yer_tut(senaryo.get("brifing") or self.brifing, senaryo)

    @property
    def etiket(self) -> str:
        if self.olay_masasi:
            return f"Olay Masası · {self.baslik}"
        if self.cilt == 0:
            return f"Bölüm 0 — {self.baslik}"
        return f"Cilt {self.cilt} · Bölüm {self.bolum} — {self.baslik}"


def yer_tut(metin: str, senaryo: dict) -> str:
    """Metindeki <<ad>> yer tutucularını senaryo['metin'] değerleriyle doldurur."""
    degerler = senaryo.get("metin", {})
    return re.sub(r"<<(\w+)>>", lambda m: str(degerler.get(m.group(1), m.group(0))), metin)


_KAYIT: dict = {}
YUKLEME_HATALARI: list = []   # (modül, hata) — testler boş olmasını şart koşar


def _yukle() -> None:
    import sys
    import traceback
    for paket_adi in ("hy.seviyeler", "hy.olay_masasi"):
        try:
            paket = importlib.import_module(paket_adi)
        except ModuleNotFoundError:
            continue
        for bilgi in pkgutil.walk_packages(paket.__path__, paket.__name__ + "."):
            try:
                modul = importlib.import_module(bilgi.name)
            except Exception as e:  # bozuk tek bir seviye bütün oyunu düşürmesin
                YUKLEME_HATALARI.append((bilgi.name, "".join(traceback.format_exception_only(type(e), e)).strip()))
                print(f"Uyarı: {bilgi.name} yüklenemedi, atlandı: {e}", file=sys.stderr)
                continue
            sv = getattr(modul, "SEVIYE", None)
            if isinstance(sv, Seviye):
                if sv.kimlik in _KAYIT:
                    raise RuntimeError(f"Aynı seviye kimliği iki kez tanımlı: {sv.kimlik}")
                _KAYIT[sv.kimlik] = sv


def tum_seviyeler() -> dict:
    if not _KAYIT:
        _yukle()
    return _KAYIT


def seviye_al(kimlik: str) -> Seviye:
    sv = tum_seviyeler().get(kimlik)
    if sv is None:
        raise KeyError(f"Böyle bir seviye yok: {kimlik}")
    return sv


def sirali_seviyeler(olay: bool = False) -> list:
    return sorted((s for s in tum_seviyeler().values() if s.olay_masasi == olay),
                  key=lambda s: (s.cilt, s.bolum, s.kimlik))
