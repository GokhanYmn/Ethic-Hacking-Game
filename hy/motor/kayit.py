"""Oyuncu ilerlemesi: ~/.hackeryolu/kayit.json (atomik yazım).

Kayıtta cevaplar tutulmaz; sadece senaryo tohumu tutulur, cevaplar tohumdan yeniden üretilir.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
import time
from pathlib import Path


def ev_dizini() -> Path:
    return Path(os.environ.get("HY_EV") or (Path.home() / ".hackeryolu"))


def lab_koku() -> Path:
    return Path(os.environ.get("HY_LAB_KOKU") or (Path.home() / "hackeryolu" / "lab"))


_BOS = {
    "surum": 1,
    "oyuncu": {},
    "ayarlar": {"serbest": False, "zorluk": "normal"},
    "xp": 0,
    "seviyeler": {},
    "rozetler": {},
    "istatistik": {"dogru": 0, "yanlis": 0, "ipucu": 0, "pes": 0, "olay": 0, "olay_seri": 0, "tespit": 0},
    "seri": {"son_gun": None, "gun_sayisi": 0, "en_uzun": 0, "sinav_en_iyi": 0},
}


def bos_seviye_durumu() -> dict:
    return {
        "tohum": None,       # aktif senaryonun tohumu
        "deneme": 0,         # kaçıncı oynanış (1 = ilk)
        "carpan": 1.0,       # XP çarpanı (tekrar oynanışta düşer)
        "cozulen": {},       # {"1": {"puan": 27, "ipucu": 1, "pes": false, "zaman": ...}}
        "ipucu": {},         # {"1": 2}  açılan kademe
        "yanlis": {},        # {"1": 3}
        "tamamlandi": False, # en az bir kez bitirildi mi
        "ilk_ipucusuz": None,  # ilk bitirişte hiç ipucu/pes kullanılmadı mı
        "baslangic": None,
        "bitis": None,
        "egitim": [],        # tamamlanan eğitim adımı indeksleri
        "iz": 0,             # tespit metresi (sadece Zor+); gürültüyle dolar
        "iz_uyari": False,   # SOC uyarısı bu denemede gösterildi mi
    }


class Kayit:
    def __init__(self, yol: Path | None = None):
        self.yol = yol or (ev_dizini() / "kayit.json")
        self.veri = self._oku()

    def _oku(self) -> dict:
        try:
            veri = json.loads(self.yol.read_text(encoding="utf-8"))
            if not isinstance(veri, dict):
                raise ValueError("kayıt sözlük değil")
        except FileNotFoundError:
            veri = {}
        except (ValueError, OSError):
            # Bozuk kayıt: kaybetme, kenara al ve temiz başla.
            yedek = self.yol.with_name(f"kayit.bozuk-{int(time.time())}.json")
            try:
                self.yol.replace(yedek)
            except OSError:
                pass
            veri = {}
        for anahtar, varsayilan in _BOS.items():
            if anahtar not in veri:
                veri[anahtar] = copy.deepcopy(varsayilan)
            elif isinstance(varsayilan, dict):
                for k, v in varsayilan.items():
                    veri[anahtar].setdefault(k, copy.deepcopy(v))
        for durum in veri["seviyeler"].values():
            for k, v in bos_seviye_durumu().items():
                durum.setdefault(k, v)
        return veri

    def kaydet(self) -> None:
        self.yol.parent.mkdir(parents=True, exist_ok=True)
        fd, gecici = tempfile.mkstemp(dir=self.yol.parent, prefix=".kayit-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self.veri, f, ensure_ascii=False, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(gecici, self.yol)
        except BaseException:
            try:
                os.unlink(gecici)
            except OSError:
                pass
            raise

    def seviye(self, kimlik: str) -> dict:
        return self.veri["seviyeler"].setdefault(kimlik, bos_seviye_durumu())

    def tamam_mi(self, kimlik: str) -> bool:
        return bool(self.veri["seviyeler"].get(kimlik, {}).get("tamamlandi"))

    def rozet_ver(self, kimlik: str) -> bool:
        """Rozeti verir; yeni kazanıldıysa True."""
        if kimlik in self.veri["rozetler"]:
            return False
        self.veri["rozetler"][kimlik] = time.strftime("%Y-%m-%d %H:%M")
        return True

    @property
    def serbest(self) -> bool:
        return bool(self.veri["ayarlar"].get("serbest"))

    def gun_isaretle(self) -> dict:
        """Günlük seriyi günceller. Dönen: {'yeni_gun', 'seri', 'rekor'}."""
        import datetime
        s = self.veri["seri"]
        bugun = datetime.date.today()
        son = s.get("son_gun")
        if son == bugun.isoformat():
            return {"yeni_gun": False, "seri": s["gun_sayisi"], "rekor": False}
        dun = (bugun - datetime.timedelta(days=1)).isoformat()
        s["gun_sayisi"] = s["gun_sayisi"] + 1 if son == dun else 1
        s["son_gun"] = bugun.isoformat()
        rekor = s["gun_sayisi"] > s.get("en_uzun", 0)
        if rekor:
            s["en_uzun"] = s["gun_sayisi"]
        return {"yeni_gun": True, "seri": s["gun_sayisi"], "rekor": rekor}

    def notlar_yolu(self) -> Path:
        return self.yol.parent / "notlar.md"
