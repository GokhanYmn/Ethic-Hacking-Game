"""Uçtan uca: oyunu gerçek bir terminal (pty) üzerinden oynar.

Menü → brifing → görev kabuğu (gerçek bash) → kabukta komut → `cevap` → `ipucu` → `cik`.
Bu test, rc dosyasındaki kabuk fonksiyonlarının, istem (PS1) ve çalışma dizininin, kayıt
dosyasının bir arada çalıştığını kanıtlar.
"""
from __future__ import annotations

import json
import os
import pty
import re
import select
import sys
import tempfile
import time
import unittest
from pathlib import Path

KOK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(KOK))

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


class Terminal:
    def __init__(self, argv, ortam):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # çocuk
            os.execvpe(argv[0], argv, ortam)
        self.tampon = ""

    def oku(self, sure=0.2):
        son = time.time() + sure
        while time.time() < son:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    veri = os.read(self.fd, 4096)
                except OSError:
                    return
                if not veri:
                    return
                self.tampon += ANSI.sub("", veri.decode("utf-8", "replace"))

    def bekle(self, desen, sure=15):
        son = time.time() + sure
        while time.time() < son:
            if re.search(desen, self.tampon):
                eslesme = re.search(desen, self.tampon)
                kalan = self.tampon[eslesme.end():]
                gorulen = self.tampon[: eslesme.end()]
                self.tampon = kalan
                return gorulen
            self.oku(0.2)
        raise AssertionError(f"Beklenen çıktı gelmedi: {desen!r}\nSon çıktı:\n{self.tampon[-1500:]}")

    def yaz(self, metin):
        os.write(self.fd, metin.encode("utf-8"))

    def kapat(self):
        try:
            os.kill(self.pid, 9)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass
        os.close(self.fd)


class UctanUcaTest(unittest.TestCase):
    def setUp(self):
        self.gecici = tempfile.TemporaryDirectory()
        g = Path(self.gecici.name)
        (g / "home").mkdir()
        self.ortam = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(g / "home"),
            "TERM": "xterm",
            "LANG": "C.UTF-8",
            "NO_COLOR": "1",
            "HY_TEMIZLEME": "0",
            "HY_EV": str(g / "ev"),
            "HY_LAB_KOKU": str(g / "lab"),
            "COLUMNS": "100",
        }

    def tearDown(self):
        self.gecici.cleanup()

    def test_etik_bolumunu_kabukta_oyna(self):
        t = Terminal([sys.executable, str(KOK / "hackeryolu.py"), "oyna", "c00"], self.ortam)
        try:
            t.bekle(r"nasıl hitap edelim\?")
            t.yaz("Deneme\n")
            t.bekle(r"Devam etmek için Enter")            # açılış sahnesi
            t.yaz("\n")
            t.bekle(r"Eğitim adımlarına geçelim mi\?.*\[e/h\]")
            t.yaz("h\n")
            t.bekle(r"Saha görevine girelim mi\?.*\[e/h\]")
            t.yaz("e\n")
            t.bekle(r"Komutlar:")
            t.bekle(r"HY:c00")                              # kabuk istemi
            t.yaz("pwd\n")
            cikti = t.bekle(r"HY:c00")
            self.assertIn(str(Path(self.ortam["HY_LAB_KOKU"]) / "c00"), cikti)

            # Mektubu kabukta okuyup yasak IP'yi bul (oyuncunun yapacağı gibi)
            t.yaz("grep -A2 'KAPSAM DIŞI' yetkilendirme_mektubu.txt | grep -oE '([0-9]+\\.){3}[0-9]+'\n")
            cikti = t.bekle(r"HY:c00")
            ipler = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", cikti)
            self.assertTrue(ipler, cikti)

            t.yaz(f"cevap 3 {ipler[0]}\n")
            cikti = t.bekle(r"HY:c00")
            self.assertIn("Doğru! +20 XP", cikti)

            t.yaz("cevap 4 1\n")
            cikti = t.bekle(r"HY:c00")
            self.assertIn("Olmadı", cikti)

            t.yaz("ipucu 4\n")
            t.bekle(r"\[e/h\]")
            t.yaz("e\n")
            cikti = t.bekle(r"HY:c00")
            self.assertIn("İPUCU 1/3", cikti)

            t.yaz("cik\n")
            t.bekle(r"Seçimin:")                             # seviye menüsüne döndü
            t.yaz("q\n")
            time.sleep(0.5)
        finally:
            t.kapat()

        kayit = json.loads((Path(self.ortam["HY_EV"]) / "kayit.json").read_text())
        d = kayit["seviyeler"]["c00"]
        self.assertIn("3", d["cozulen"])
        self.assertEqual(d["ipucu"].get("4"), 1)
        self.assertEqual(d["yanlis"].get("4"), 1)
        self.assertEqual(kayit["xp"], 20)
        self.assertIn("ilk_bayrak", kayit["rozetler"])


if __name__ == "__main__":
    unittest.main()
