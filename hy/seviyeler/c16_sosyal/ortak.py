"""Cilt 16 ortak yardımcıları. Her mesaj, e-posta ve form KURGUSALDIR; alan adları .lab ile biter.

Bu cilt şablon, oltalama kiti ya da kullanılabilir bir kimlik avı metni içermez: kurgusal vakalar yalnızca
tanıma, ayrıştırma ve savunma amaçlı analiz için kısa notlar olarak verilir.
"""
from __future__ import annotations

from hy.seviyeler.c14_mobil.ortak import Esle, sec_doldur, sh  # noqa: F401
from hy.seviyeler.c07_savunma.ortak import Sira  # noqa: F401

VAKALAR = [
    {"kod": "ferah", "ad": "Ferah Bank", "alan": "ferahbank.lab", "sistem": "internet şubesi yönetim paneli",
     "yonetici": "Kaan Bey", "bt": "Bilgi İşlem", "birim": "operasyon", "sektor": "banka",
     "hikaye": "Operasyon biriminde bir çalışan şüpheli bir telefon aldığını söyledi."},
    {"kod": "paramix", "ad": "Paramix", "alan": "paramix.lab", "sistem": "üye işyeri yönetim paneli",
     "yonetici": "Ece Hanım", "bt": "BT Destek", "birim": "finans", "sektor": "fintech",
     "hikaye": "Finans ekibi son haftalarda alışılmadık sayıda 'acil' e-posta aldığını fark etti."},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "alan": "kuzgun.lab", "sistem": "depo yönetim paneli",
     "yonetici": "Serdar Bey", "bt": "IT Sorumlusu", "birim": "depo", "sektor": "lojistik",
     "hikaye": "Depo çalışanları, yöneticilerinin adıyla gelen tuhaf mesajlardan söz ediyor."},
    {"kod": "yesiltepe", "ad": "Yeşiltepe Belediyesi", "alan": "yesiltepe.lab", "sistem": "e-belediye personel portalı",
     "yonetici": "Nurcan Hanım", "bt": "Bilgi İşlem Müdürlüğü", "birim": "yazı işleri", "sektor": "belediye",
     "hikaye": "Yazı işleri personeli, 'tebligat' başlıklı garip bildirimler aldığını bildirdi."},
    {"kod": "medora", "ad": "Medora Sağlık", "alan": "medora.lab", "sistem": "hasta kayıt sistemi",
     "yonetici": "Dr. Aslı Hanım", "bt": "Bilgi İşlem", "birim": "hasta kabul", "sektor": "hastane",
     "hikaye": "Hasta kabul personeli, kendilerini BT diye tanıtan birinden arama aldı."},
]


def vaka_sec(rng) -> dict:
    return dict(rng.choice(VAKALAR))
