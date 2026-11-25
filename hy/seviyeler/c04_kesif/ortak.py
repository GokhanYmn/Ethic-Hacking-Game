"""Cilt 4 seviyeleri için ortak yardımcılar (bu klasöre özel).

- `sh`: test çözücüsünün kabuk komutu çalıştırıcısı.
- `secmeli_cevap`: çoktan seçmeli görevin doğru şıkkını verir (coz için).
- `lab_adresi`, `portlar`: servisler için rastgele 127.x adresi ve port seçimi.
- `site_sunucusu`: küçük, sabit rotalı bir web sitesi (Server / X-Powered-By başlıklı).
- `tara`, `banner_oku`: test çözücüsünün python socket ile port tarama ve banner okuması.
- `dosya_bul`: oyuncunun yazdığı dosyayı çalışma dizininde ya da lab'da bulur.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam
from hy.motor.servis import SessizIsleyici, http_sunucu


def sh(komut: str, lab: Path, zaman: int = 120) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True,
                          timeout=zaman).stdout.strip()


def secmeli_cevap(sv, s, lab, no) -> str:
    return sv.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def lab_adresi(rng) -> str:
    """127.0.0.1 dışında rastgele bir loopback adresi (127.0.0.0/8 tamamı yerel makinedir)."""
    return f"127.{rng.randint(2, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}"


def portlar(rng, adet: int, haric=(), aralik=(20000, 45000)) -> list:
    adaylar = [p for p in range(aralik[0], aralik[1] + 1) if p not in set(haric)]
    return sorted(rng.sample(adaylar, adet))


def site_sunucusu(host: str, port: int, server: str, rotalar: dict, ek_baslik: dict | None = None,
                  yok_govde: str = "<html><body><h1>404 Not Found</h1></body></html>\n"):
    """rotalar: {"/yol": (kod, govde)} ya da (kod, govde, {"Başlık": "değer"}). Olmayan yol 404."""
    ek = dict(ek_baslik or {})

    class Isleyici(SessizIsleyici):
        server_version = server
        timeout = 15

        def version_string(self):
            return self.server_version

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            yol = self.path.split("?", 1)[0].split("#", 1)[0]
            kayit = rotalar.get(yol)
            if kayit is None:
                self.yanit(404, yok_govde, basliklar=dict(ek))
                return
            kod, govde, *ozel = kayit
            bas = dict(ek)
            if ozel:
                bas.update(ozel[0])
            tur = bas.pop("Content-Type", "text/html; charset=utf-8")
            self.yanit(kod, govde, tur=tur, basliklar=bas)

    return http_sunucu(host, port, Isleyici)


_TARAMA_PY = """
import socket, sys
from concurrent.futures import ThreadPoolExecutor
ad, bas, son = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
def dene(p):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect((ad, p)); return p
    except OSError:
        return None
    finally:
        s.close()
with ThreadPoolExecutor(64) as ex:
    print(*sorted(p for p in ex.map(dene, range(bas, son + 1)) if p))
"""

_BANNER_PY = """
import socket, sys
s = socket.socket(); s.settimeout(1.0)
try:
    s.connect((sys.argv[1], int(sys.argv[2])))
    print(s.recv(300).decode('utf-8', 'replace').strip())
except OSError:
    pass
"""


def tara(adres: str, lab: Path, bas: int = 20000, son: int = 45000) -> list:
    """python socket ile (nmap'siz) bağlantı taraması; açık portların listesi."""
    c = subprocess.run(["python3", "-c", _TARAMA_PY, adres, str(bas), str(son)], cwd=lab,
                       capture_output=True, text=True, timeout=240)
    return [int(x) for x in c.stdout.split()]


def banner_oku(adres: str, port: int, lab: Path) -> str:
    c = subprocess.run(["python3", "-c", _BANNER_PY, adres, str(port)], cwd=lab,
                       capture_output=True, text=True, timeout=30)
    return c.stdout.strip()


def dosya_bul(b: Baglam, ad: str):
    adaylar = [Path(b.calisma_dizini or b.lab) / ad, Path(b.lab) / ad]
    return next((p for p in adaylar if p.is_file()), None)


def banner_metni(tur: str, urun: str, surum: str, sunucu: str) -> str:
    """Servis türüne göre gerçekçi karşılama satırı (ssh, ftp, smtp, imap, pop3)."""
    if tur == "ssh":
        return f"SSH-2.0-OpenSSH_{surum}\r\n"
    if tur == "ftp":
        if urun == "vsFTPd":
            return f"220 (vsFTPd {surum})\r\n"
        return f"220 ProFTPD {surum} Server (Debian) [::ffff:127.0.0.1]\r\n"
    if tur == "smtp":
        return f"220 {sunucu} ESMTP Exim {surum} Wed, 04 Nov 2026 03:12:44 +0300\r\n"
    if tur == "imap":
        return "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Dovecot ready.\r\n"
    if tur == "pop3":
        return "+OK Dovecot ready.\r\n"
    raise ValueError(tur)
