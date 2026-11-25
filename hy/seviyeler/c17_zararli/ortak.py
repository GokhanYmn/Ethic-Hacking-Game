"""Cilt 17 ortak yardımcıları.

Bu cildin HİÇBİR dosyası gerçek zararlı yazılım, EICAR dizgisi, çalışır betik ya da gizlenmiş çalıştırılabilir yük
içermez. "Örnekler" düz metin, geçerli ama zararsız küçük bir PNG ve gzip'lenmiş bir metindir; "yapılandırma" metni
kurgusaldır (.lab alan adı, TEST-NET IP). Sandbox raporu ve loglar düz metindir.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import struct
import zlib

from hy.motor.kontrol import Kontrol, Sonuc, norm
from hy.seviyeler.c14_mobil.ortak import hex_, sec_doldur, sh  # noqa: F401

VAKALAR = [
    {"kod": "ferah", "ad": "Ferah Bank", "alan": "ferahbank.lab", "pc": "sube-pc", "sektor": "banka",
     "hikaye": "Şube personeli, e-postayla gelen bir 'ekstre' ekini açtıktan sonra bilgisayarının yavaşladığını bildirdi.",
     "dosyalar": ["ekstre_bilgilendirme.dat", "guncelleme_araci.bin", "sube_raporu.dat", "yazici_suruculeri.bin",
                  "toplanti_ozeti.dat", "kampanya_gorseli.dat", "kasa_sayim.dat", "ekran_koruyucu.bin"]},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "alan": "kuzgun.lab", "pc": "depo-pc", "sektor": "lojistik",
     "hikaye": "Depodaki bir el terminali yöneticisinin PC'si, kimsenin kurmadığı bir 'sürücü güncelleme' dosyası içeriyor.",
     "dosyalar": ["irsaliye_taslagi.dat", "surucu_guncelleme.bin", "sevk_listesi.dat", "etiket_yazici.bin",
                  "vardiya_cizelgesi.dat", "arac_takip.dat", "depo_haritasi.dat", "tarayici_ayarlari.bin"]},
    {"kod": "medora", "ad": "Medora Sağlık", "alan": "medora.lab", "pc": "klinik-pc", "sektor": "hastane",
     "hikaye": "Radyoloji bilgisayarında bir kullanıcı, açılışta beliren tuhaf bir pencere gördüğünü söyledi.",
     "dosyalar": ["rapor_sablonu.dat", "goruntuleyici_guncelleme.bin", "randevu_listesi.dat", "cihaz_kalibrasyon.bin",
                  "nobet_cizelgesi.dat", "laboratuvar_sonuc.dat", "hasta_bilgi_formu.dat", "yedek_ayarlari.bin"]},
    {"kod": "paramix", "ad": "Paramix", "alan": "paramix.lab", "pc": "muh-pc", "sektor": "fintech",
     "hikaye": "Muhasebe çalışanının indirdiği bir 'toplu ödeme aracı' şüphe uyandırdı; ağ ekibi beklenmedik bir dış bağlantı gördü.",
     "dosyalar": ["toplu_odeme_araci.bin", "komisyon_tablosu.dat", "mutabakat_raporu.dat", "banka_eki.dat",
                  "makro_yardimcisi.bin", "fatura_listesi.dat", "kur_guncelleme.dat", "muhasebe_ayar.bin"]},
]

KURGUSAL_AILELER = ["BankaCasusu.Lab", "SahteTroya.A", "YemDropper.B", "FidyeDeneme.C", "SessizYukleyici.D",
                    "KopyaKurt.E", "GolgeAgent.F", "SahteYukleyici.G"]


def vaka_sec(rng) -> dict:
    return dict(rng.choice(VAKALAR))


def sha256(veri: bytes) -> str:
    return hashlib.sha256(veri).hexdigest()


def png_bytes(rng) -> bytes:
    """Geçerli, 1x1 piksellik zararsız bir PNG (file komutu 'PNG image data' der)."""
    def parca(tur: bytes, veri: bytes) -> bytes:
        return struct.pack(">I", len(veri)) + tur + veri + struct.pack(">I", zlib.crc32(tur + veri) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    piksel = bytes(rng.randrange(256) for _ in range(3))
    idat = zlib.compress(b"\x00" + piksel)
    metin = b"Comment\x00ZARARSIZ EGITIM ORNEGI"
    return (b"\x89PNG\r\n\x1a\n" + parca(b"IHDR", ihdr) + parca(b"tEXt", metin) + parca(b"IDAT", idat) +
            parca(b"IEND", b""))


def gzip_bytes(metin: str) -> bytes:
    tampon = io.BytesIO()
    with gzip.GzipFile(fileobj=tampon, mode="wb", mtime=0) as g:
        g.write(metin.encode("utf-8"))
    return tampon.getvalue()


GURULTU = list(range(0, 9)) + list(range(14, 32)) + list(range(128, 256))


def gurultu(rng, n: int) -> bytes:
    """Yazdırılabilir dizi oluşturmayan rastgele bayt dizisi (strings/grep çıktısını kirletmez)."""
    return bytes(rng.choice(GURULTU) for _ in range(n))


class Icerir(Kontrol):
    """Girdi, beklenen anahtar sözcüklerden birini içeriyorsa doğru (örn. `file` çıktısının tamamı yapıştırılabilir)."""

    def __init__(self, anahtarlar: list, bicim: str = "cevabın"):
        self.anahtarlar = anahtarlar
        self.bicim = bicim

    def dogrula(self, girdi: str, b) -> Sonuc:
        g = norm(girdi)
        return Sonuc(bool(g) and any(norm(a) in g for a in self.anahtarlar))

    def cevabi_goster(self, b) -> str:
        return self.anahtarlar[0]
