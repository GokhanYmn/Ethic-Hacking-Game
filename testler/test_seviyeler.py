"""Her seviye için: 3 farklı tohumla üret, gerçekten çöz, bütün kontrollerin geçtiğini doğrula.

Çalıştırma (proje kökünde, Linux'ta):
    python3 -m unittest discover -s testler -v
Tek seviye:
    HY_TEST_SEVIYE=c01b02 python3 -m unittest testler.test_seviyeler -v
"""
from __future__ import annotations

import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hy.motor.kontrol import Baglam, Serbest  # noqa: E402
from hy.motor.seviye import tum_seviyeler, yer_tut  # noqa: E402

TOHUMLAR = (1, 2, 3)
YER_TUTUCU = re.compile(r"<<\w+>>")


def _seviyeler():
    secili = os.environ.get("HY_TEST_SEVIYE")
    hepsi = tum_seviyeler()
    if secili:
        istenen = [k for k in secili.split(",") if k]
        eksik = [k for k in istenen if k not in hepsi]
        if eksik:
            raise RuntimeError(f"HY_TEST_SEVIYE içinde bulunamayan seviye(ler): {eksik}")
        return {k: hepsi[k] for k in istenen}
    return hepsi


class _Servis:
    """Seviyenin servislerini test süresince bir iş parçacığında çalıştırır."""

    def __init__(self, sv, senaryo, lab):
        self.sv, self.senaryo, self.lab = sv, senaryo, lab
        self.dur = threading.Event()
        self.hata = None

    def __enter__(self):
        if not self.sv.servis:
            return self

        def calis():
            try:
                self.sv.servis(self.senaryo, self.lab, self.dur)
            except Exception as e:  # pragma: no cover - test raporu için
                self.hata = e

        self.t = threading.Thread(target=calis, daemon=True)
        self.t.start()
        time.sleep(0.8)
        if self.hata:
            raise self.hata
        return self

    def __exit__(self, *a):
        self.dur.set()
        if self.sv.servis:
            self.t.join(timeout=5)


class SeviyeTestleri(unittest.TestCase):
    def setUp(self):
        self.gecici = tempfile.TemporaryDirectory()
        os.environ["HY_LAB_KOKU"] = str(Path(self.gecici.name) / "lab")
        os.environ["HY_EV"] = str(Path(self.gecici.name) / "ev")

    def tearDown(self):
        from hy.motor.kabuk import _guvenli_sil, lab_koku
        kok = lab_koku()
        if kok.exists():
            for alt in kok.iterdir():
                if alt.is_dir():
                    _guvenli_sil(alt)
        self.gecici.cleanup()

    def test_yapi(self):
        from hy.motor.seviye import YUKLEME_HATALARI, tum_seviyeler
        tum_seviyeler()
        self.assertEqual(YUKLEME_HATALARI, [], "yüklenemeyen seviye modülleri var")
        for kimlik, sv in _seviyeler().items():
            with self.subTest(seviye=kimlik):
                self.assertIsNotNone(sv.coz, "her seviyenin bir test çözücüsü (coz) olmalı")
                self.assertTrue(sv.gorevler, "en az bir görev olmalı")
                for no, g in enumerate(sv.gorevler, 1):
                    self.assertEqual(len(g.ipuclari), 3, f"görev {no}: tam 3 ipucu kademesi olmalı")
                    self.assertGreater(g.puan, 0)
                self.assertTrue(sv.brifing.strip())
                self.assertTrue(sv.kapanis.strip(), "Hacker Gözüyle (kapanis) boş olmamalı")
                self.assertTrue(sv.gercek_hayat.strip(), "Gerçek Hayatta boş olmamalı")

    def test_yer_tutucular_dolu(self):
        for kimlik, sv in _seviyeler().items():
            for tohum in TOHUMLAR:
                s = sv.senaryo(tohum)
                metinler = [sv.brifing_metni(s), yer_tut(sv.kapanis, s), yer_tut(sv.gercek_hayat, s)]
                for g in sv.gorevler:
                    metinler.append(yer_tut(g.soru, s))
                    metinler += [yer_tut(i, s) for i in g.ipuclari]
                for a in sv.adimlar:
                    metinler += [yer_tut(a.metin, s), yer_tut(a.komut or "", s), yer_tut(a.sonra, s)]
                for m in metinler:
                    kalan = YER_TUTUCU.findall(m)
                    self.assertFalse(kalan, f"{kimlik} tohum {tohum}: doldurulmamış yer tutucu {kalan}")

    def test_vakalar_cesitli(self):
        """Farklı tohumlar farklı cevaplar üretmeli (ezber olmasın)."""
        for kimlik, sv in _seviyeler().items():
            with self.subTest(seviye=kimlik):
                cevaplar = [repr(sorted(sv.senaryo(t)["cevaplar"].items(), key=lambda x: x[0]))
                            for t in TOHUMLAR]
                if any(sv.senaryo(TOHUMLAR[0])["cevaplar"].values()):
                    self.assertGreater(len(set(cevaplar)), 1, "tohumlar aynı cevapları üretiyor")

    def test_coz_ve_dogrula(self):
        from hy.motor.kabuk import lab_kur
        for kimlik, sv in _seviyeler().items():
            for tohum in TOHUMLAR:
                with self.subTest(seviye=kimlik, tohum=tohum):
                    s = sv.senaryo(tohum)
                    lab = lab_kur(sv, s, zorla=True)
                    with _Servis(sv, s, lab):
                        # "Yap ve kontrol et" görevleri, oyuncu bir şey yapmadan geçmemeli
                        for no, g in enumerate(sv.gorevler, 1):
                            if g.kontrol.girdi_gerekmez:
                                once = g.kontrol.dogrula("", Baglam(s, lab, no, lab))
                                self.assertFalse(once.dogru, f"görev {no}: hiçbir şey yapılmadan geçiyor")
                        cozum = sv.coz(lab, s)
                        for no, g in enumerate(sv.gorevler, 1):
                            b = Baglam(s, lab, no, lab)
                            cevap = str(cozum.get(no, ""))
                            sonuc = g.kontrol.dogrula(cevap, b)
                            self.assertTrue(sonuc.dogru,
                                            f"görev {no} çözülemedi: cevap={cevap!r} mesaj={sonuc.mesaj!r}")
                            self.assertTrue(str(g.kontrol.cevabi_goster(b)).strip())
                            if not g.kontrol.girdi_gerekmez:
                                yanlis = g.kontrol.dogrula("kesinlikle_yanlis_cevap -987654", b)
                                self.assertFalse(yanlis.dogru, f"görev {no} yanlış cevabı kabul etti")
                                if not isinstance(g.kontrol, Serbest):
                                    bos = g.kontrol.dogrula("", b)
                                    self.assertFalse(bos.dogru, f"görev {no} boş cevabı kabul etti")


if __name__ == "__main__":
    unittest.main()
