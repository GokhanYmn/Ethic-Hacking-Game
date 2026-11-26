"""Motor testleri: kontrol türleri, kayıt, rütbe ve kabuk komutlarının uçtan uca akışı."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

from hy.motor import kontrol as k  # noqa: E402
from hy.motor.kayit import Kayit  # noqa: E402
from hy.motor.rutbe import gorev_puani, rutbe  # noqa: E402


def _b(cevaplar, tohum=7, no=1):
    return k.Baglam({"cevaplar": cevaplar, "metin": {}, "_tohum": tohum}, Path("."), no)


class KontrolTestleri(unittest.TestCase):
    def test_bayrak(self):
        b = _b({"f": "FLAG{abc_123}"})
        kt = k.Bayrak("f")
        self.assertTrue(kt.dogrula("FLAG{abc_123}", b).dogru)
        self.assertTrue(kt.dogrula("  flag{ABC_123} ", b).dogru)
        ic = kt.dogrula("abc_123", b)
        self.assertFalse(ic.dogru)
        self.assertTrue(ic.yakin)
        self.assertFalse(kt.dogrula("FLAG{baska}", b).dogru)

    def test_sayi_ve_sik_hata(self):
        b = _b({"n": 18})
        kt = k.Sayi("n", sik_hatalar=lambda g, bek, b: "başlık satırı" if int(g) == bek + 1 else None)
        self.assertTrue(kt.dogrula("18 istek", b).dogru)
        self.assertTrue(kt.dogrula("18", b).dogru)
        s = kt.dogrula("19", b)
        self.assertFalse(s.dogru)
        self.assertIn("başlık", s.mesaj)
        self.assertFalse(kt.dogrula("yok", b).dogru)

    def test_sayi_ip_icindeki_rakamlari_yok_sayar(self):
        b = _b({"n": 6})
        self.assertTrue(k.Sayi("n").dogrula("10.0.0.66 6", b).dogru)

    def test_ip(self):
        b = _b({"ip": "10.0.0.66"})
        self.assertTrue(k.IP("ip").dogrula("saldırgan 10.0.0.66", b).dogru)
        self.assertFalse(k.IP("ip").dogrula("10.0.0.6", b).dogru)

    def test_kume(self):
        b = _b({"k": ["test", "oracle"]})
        kt = k.Kume("k")
        self.assertTrue(kt.dogrula("oracle, test", b).dogru)
        s = kt.dogrula("test", b)
        self.assertFalse(s.dogru)
        self.assertIn("1 doğru", s.mesaj)
        self.assertIn("1 eksik", s.mesaj)

    def test_metin_onek_sonek_ve_turkce(self):
        b = _b({"y": "../loglar"})
        kt = k.Metin("y", on_ekleri_at=("cd ",), son_ekleri_at=("/",))
        self.assertTrue(kt.dogrula("cd ../loglar/", b).dogru)
        self.assertTrue(kt.dogrula("../LOGLAR", b).dogru)
        self.assertTrue(k.Metin(kabul=["admin"]).dogrula("ADMİN", b).dogru)
        self.assertTrue(k.Metin(kabul=["admin"]).dogrula("admın", b).dogru)

    def test_metin_sadece_ad(self):
        b = _b({"d": "ozet.txt"})
        self.assertTrue(k.Metin("d", sadece_ad=True).dogrula("raporlar/ozet.txt", b).dogru)

    def test_secmeli_karistirma_tutarli(self):
        kt = k.Secmeli([("doğru", "evet"), ("yanlış1", "hayır"), ("yanlış2", ""), ("yanlış3", "")])
        b = _b({})
        harf = kt.cevabi_goster(b)[0]
        self.assertTrue(kt.dogrula(harf, b).dogru)
        self.assertEqual(kt.cevabi_goster(b), kt.cevabi_goster(_b({})))
        yanlis = next(h for h in "abcd" if h != harf)
        self.assertFalse(kt.dogrula(yanlis, b).dogru)
        self.assertFalse(kt.dogrula("z", b).dogru)

    def test_serbest(self):
        kt = k.Serbest("örnek cevap", min_kelime=4)
        self.assertFalse(kt.dogrula("kısa", _b({})).dogru)
        self.assertTrue(kt.dogrula("bu yeterince uzun bir cevap", _b({})).dogru)

    def test_hepsi(self):
        b = _b({"ip": "10.0.0.66", "n": 6})
        kt = k.Hepsi([k.IP("ip"), k.Sayi("n")])
        self.assertTrue(kt.dogrula("10.0.0.66 6", b).dogru)
        s = kt.dogrula("10.0.0.66 7", b)
        self.assertFalse(s.dogru)
        self.assertTrue(s.yakin)


class KayitVeRutbeTestleri(unittest.TestCase):
    def test_bozuk_kayit_yedeklenir(self):
        with tempfile.TemporaryDirectory() as d:
            yol = Path(d) / "kayit.json"
            yol.write_text("{ bozuk")
            kayit = Kayit(yol)
            self.assertEqual(kayit.veri["xp"], 0)
            self.assertTrue(any(p.name.startswith("kayit.bozuk-") for p in Path(d).iterdir()))
            kayit.veri["xp"] = 42
            kayit.kaydet()
            self.assertEqual(json.loads(yol.read_text())["xp"], 42)
            self.assertFalse([p for p in Path(d).iterdir() if p.suffix == ".tmp"])

    def test_rutbe(self):
        self.assertEqual(rutbe(0)["ad"], "Sivil")
        self.assertEqual(rutbe(999)["ad"], "Sivil")
        self.assertEqual(rutbe(1000)["ad"], "Çırak")
        self.assertIsNone(rutbe(99999)["sonraki_ad"])

    def test_puan(self):
        self.assertEqual(gorev_puani(100, 0, 1.0), 100)
        self.assertEqual(gorev_puani(100, 1, 1.0), 90)
        self.assertEqual(gorev_puani(100, 3, 1.0), 50)
        self.assertEqual(gorev_puani(100, 0, 0.5), 50)


class EkOzellikTestleri(unittest.TestCase):
    def test_seri(self):
        import datetime
        with tempfile.TemporaryDirectory() as d:
            kayit = Kayit(Path(d) / "kayit.json")
            self.assertTrue(kayit.gun_isaretle()["yeni_gun"])
            self.assertEqual(kayit.veri["seri"]["gun_sayisi"], 1)
            self.assertFalse(kayit.gun_isaretle()["yeni_gun"])  # aynı gün tekrar artırmaz
            kayit.veri["seri"]["son_gun"] = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
            self.assertEqual(kayit.gun_isaretle()["seri"], 2)   # dün oynadıysa seri artar
            kayit.veri["seri"]["son_gun"] = (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
            self.assertEqual(kayit.gun_isaretle()["seri"], 1)   # ara verdiyse sıfırlanır

    def test_basvuru_arama(self):
        from hy.motor import basvuru
        self.assertTrue(basvuru.terimler())
        self.assertTrue(basvuru.komutlar())
        self.assertTrue(any(t["terim"].upper() == "IDOR" for t in basvuru.terim_ara("idor")))
        # Türkçe karakter ve büyük/küçük harf duyarsız
        self.assertEqual(basvuru.terim_ara("IDOR"), basvuru.terim_ara("idor"))
        self.assertTrue(basvuru.komut_ara("grep"))
        self.assertEqual(basvuru.terim_ara("kesinlikle_boyle_bir_terim_yok"), [])

    def test_sinav_bos_kayitta_coker_mez(self):
        from hy.motor import sinav
        with tempfile.TemporaryDirectory() as d:
            kayit = Kayit(Path(d) / "kayit.json")
            self.assertEqual(sinav.sinav_hazirla(kayit, 10), [])   # hiçbir cilt açık değil

    def test_sinav_sorulari_secmeli(self):
        """Her soru çoktan seçmeli olmalı ve senaryoyla doldurulabilmeli."""
        from hy.motor import sinav
        from hy.motor.kontrol import Baglam, Secmeli
        with tempfile.TemporaryDirectory() as d:
            kayit = Kayit(Path(d) / "kayit.json")
            # Bütün ciltleri bitmiş say
            from hy.motor.seviye import sirali_seviyeler
            for sv in sirali_seviyeler():
                kayit.seviye(sv.kimlik)["tamamlandi"] = True
            sorular = sinav.sinav_hazirla(kayit, 8)
            self.assertEqual(len(sorular), 8)
            for s in sorular:
                g = s["sv"].gorevler[s["no"] - 1]
                self.assertIsInstance(g.kontrol, Secmeli)
                b = Baglam(s["senaryo"], Path("."), s["no"])
                self.assertTrue(g.kontrol.ek_metin(b).strip())        # şıklar dolu
                self.assertTrue(str(g.kontrol.cevabi_goster(b)).strip())


class KabukAkisiTestleri(unittest.TestCase):
    """`cevap`, `ipucu`, `pes` komutlarını gerçek süreç olarak çalıştırır."""

    def setUp(self):
        self.gecici = tempfile.TemporaryDirectory()
        self.ortam = os.environ.copy()
        self.ortam.update({
            "HY_EV": str(Path(self.gecici.name) / "ev"),
            "HY_LAB_KOKU": str(Path(self.gecici.name) / "lab"),
            "HY_SEVIYE": "c01b02",
            "NO_COLOR": "1",
        })

    def tearDown(self):
        self.gecici.cleanup()

    def hy(self, *args, girdi=""):
        return subprocess.run([sys.executable, str(KOK / "hackeryolu.py"), *args], env=self.ortam,
                              input=girdi, capture_output=True, text=True, cwd=self.gecici.name)

    def kayit(self):
        return json.loads((Path(self.ortam["HY_EV"]) / "kayit.json").read_text())

    def test_akis(self):
        p = self.hy("gorev")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("Terminalde Yolunu Bulmak", p.stdout)
        tohum = self.kayit()["seviyeler"]["c01b02"]["tohum"]
        os.environ["HY_LAB_KOKU"] = self.ortam["HY_LAB_KOKU"]
        from hy.motor.kabuk import lab_kur
        from hy.motor.seviye import seviye_al
        sv = seviye_al("c01b02")
        s = sv.senaryo(tohum)
        lab = lab_kur(sv, s)
        cozum = sv.coz(lab, s)

        p = self.hy("cevap", "2", "FLAG{yanlis}")
        self.assertEqual(p.returncode, 1)
        self.assertIn("bayrak", p.stdout.lower())

        p = self.hy("ipucu", "2", girdi="e\n")
        self.assertIn("İPUCU 1/3", p.stdout)
        self.assertEqual(self.kayit()["seviyeler"]["c01b02"]["ipucu"]["2"], 1)

        p = self.hy("cevap", "2", cozum[2])
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn("+36 XP", p.stdout)   # 40 puan, 1. ipucu %10 kesinti
        self.assertIn("İlk Bayrak", p.stdout)

        p = self.hy("cevap", "2", cozum[2])
        self.assertIn("zaten", p.stdout)

        p = self.hy("pes", "7", girdi="e\n")
        self.assertIn(s["cevaplar"]["parola"], p.stdout)

        for no in (1, 3, 4, 5, 6):
            p = self.hy("cevap", str(no), str(cozum[no]))
            self.assertEqual(p.returncode, 0, f"görev {no}: {p.stdout}")
        d = self.kayit()["seviyeler"]["c01b02"]
        self.assertTrue(d["tamamlandi"])
        self.assertIn("Vaka kapandı", p.stdout)
        self.assertIn("HACKER GÖZÜYLE", p.stdout)
        self.assertFalse(d["ilk_ipucusuz"])
        self.assertGreater(self.kayit()["xp"], 100)

    def test_zor_modda_tespit_ve_avlanma(self):
        """Zor modda çok yanlış deneme tespit metresini doldurur; savunma hedefi döndürür."""
        self.hy("ayar", "zorluk", "zor")
        self.hy("gorev")                       # tohum oluştur
        tohum1 = self.kayit()["seviyeler"]["c01b02"]["tohum"]
        yakalandi = False
        for _ in range(12):
            p = self.hy("cevap", "1", "kesinlikle_yanlis")
            if "YAKALANDIN" in p.stdout:
                yakalandi = True
                break
        self.assertTrue(yakalandi, "çok yanlış denemeye rağmen tespit tetiklenmedi")
        self.assertEqual(self.kayit()["istatistik"]["tespit"], 1)
        self.assertNotEqual(self.kayit()["seviyeler"]["c01b02"]["tohum"], tohum1)  # hedef döndü

    def test_normal_modda_tespit_yok(self):
        self.hy("gorev")
        for _ in range(12):
            p = self.hy("cevap", "1", "kesinlikle_yanlis")
            self.assertNotIn("YAKALANDIN", p.stdout)
        self.assertEqual(self.kayit()["istatistik"].get("tespit", 0), 0)

    def test_kabuk_disinda_uyari(self):
        ortam = dict(self.ortam)
        ortam.pop("HY_SEVIYE")
        p = subprocess.run([sys.executable, str(KOK / "hackeryolu.py"), "cevap", "1", "x"], env=ortam,
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("görev kabuğunun içinde", p.stdout)


class YasamTestleri(unittest.TestCase):
    """Hayat Modu (Aşama 1-2) — etkileşimsiz mantık: durum, kutu, kademe, ekipman, ödül."""

    def setUp(self):
        from hy.motor import yasam
        self.y = yasam

    def test_durum_baslatma(self):
        with tempfile.TemporaryDirectory() as td:
            dur = self.y._durumu(Kayit(Path(td) / "k.json"))
            for anahtar in ("gun", "para", "itibar", "ekipman", "kutu", "sonraki_no"):
                self.assertIn(anahtar, dur)
            self.assertEqual(dur["gun"], 1)
            self.assertEqual(dur["para"], 0)

    def test_kutu_doldur_serilestirilebilir(self):
        with tempfile.TemporaryDirectory() as td:
            kayit = Kayit(Path(td) / "k.json")
            self.y._kutu_doldur(kayit)
            kutu = self.y._durumu(kayit)["kutu"]
            self.assertGreaterEqual(len([j for j in kutu if j["durum"] == "yeni"]), 1)
            for j in kutu:
                for alan in ("no", "anahtar", "zorluk", "tohum", "kurulus", "durum"):
                    self.assertIn(alan, j)
                self.assertIn(j["anahtar"], self.y.ISLER)
            json.dumps(kutu)   # kalıcılık için JSON güvenli olmalı

    def test_kademe_itibarla_yukselir(self):
        i0, k0 = self.y._kademe(0)
        iN, kN = self.y._kademe(10 ** 6)
        self.assertEqual(i0, 0)
        self.assertEqual(iN, len(self.y.KADEMELER) - 1)
        self.assertGreater(kN[4], k0[4])        # üst kademe ödül çarpanı daha yüksek

    def test_ekipman_etki(self):
        etki = self.y._ekipman_etki({"ekipman": ["pazarlikci", "menajer"]})
        self.assertGreater(etki["pay"], 0)
        self.assertGreater(etki["itibar"], 0)

    def test_odul_zorluk_ve_kademeyle_artar(self):
        with tempfile.TemporaryDirectory() as td:
            dur = self.y._durumu(Kayit(Path(td) / "k.json"))
            kolay = {"anahtar": "web", "zorluk": "kolay"}
            zor = {"anahtar": "web", "zorluk": "zor"}
            self.assertLess(self.y._odul_max(kolay, dur), self.y._odul_max(zor, dur))
            dur["itibar"] = 10 ** 6                           # üst kademe → daha çok öder
            self.assertGreater(self.y._odul_max(zor, dur),
                               self.y._odul_max(zor, {"itibar": 0, "ekipman": []}))

    def test_hikaye_omurgasi(self):
        self.assertGreaterEqual(len(self.y.HIKAYE), 5)
        self.assertEqual(self.y.HIKAYE[0][0], 1)                 # ilk an 1 işte açılır
        job = self.y._is_uret("web", "normal", 1, hikaye=True, patron="K.")
        self.assertTrue(job["hikaye"])
        self.assertEqual(job["patron"], "K.")
        with tempfile.TemporaryDirectory() as td:
            dur = self.y._durumu(Kayit(Path(td) / "k.json"))
            normal = {"anahtar": "web", "zorluk": "normal"}
            hik = {"anahtar": "web", "zorluk": "normal", "hikaye": True}
            self.assertGreater(self.y._odul_max(hik, dur), self.y._odul_max(normal, dur))

    def test_lab_gelir_kademeyle_artar(self):
        self.assertEqual(self.y._lab_gelir({"lab": 0}), 0)
        self.assertGreater(self.y._lab_gelir({"lab": 1}), 0)
        son = len(self.y.LAB_KADEMELERI) - 1
        self.assertGreater(self.y._lab_gelir({"lab": son}), self.y._lab_gelir({"lab": 1}))

    def test_tohum_deterministik(self):
        sv = self.y.ISLER["web"]["sv"]
        self.assertEqual(sv.senaryo(4242)["metin"]["musteri"],
                         sv.senaryo(4242)["metin"]["musteri"])

    def test_teaser_gercek_olay(self):
        for e in self.y.ISLER.values():
            self.assertTrue(self.y._teaser(e["sv"]))            # her ailede gerçek-hayat bağı var


if __name__ == "__main__":
    unittest.main()
