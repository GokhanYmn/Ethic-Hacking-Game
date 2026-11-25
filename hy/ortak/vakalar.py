"""Kurgusal müşteri vakaları: aynı beceriyi farklı sektör ve hikâyede sunmak için.

Her müşteri, log/web görevlerinde kullanılabilecek tutarlı ayrıntılar taşır: alan adı,
sunucu adı, giriş sayfası, ID parametreli sayfa, hassas yedek dosyası, yönetici adı.
Bir seviye `musteri_sec(rng)` ile vakayı seçer; tekrar oynandığında farklı müşteri gelir.

Bütün şirketler ve kişiler kurgusaldır. Alan adları `.lab` uzantılıdır.
"""
from __future__ import annotations

import random

MUSTERILER = [
    {
        "kod": "pazarix",
        "ad": "Pazarix",
        "sektor": "e-ticaret",
        "alan": "pazarix.lab",
        "sunucu": "pzx-web01",
        "kisi": "Tuncay Bey (sistem yöneticisi)",
        "giris": "/admin/login.php",
        "id_sayfa": "/urun.php?id=",
        "normal_sayfalar": ["/index.php", "/kategori.php?k=elektronik", "/sepet.php", "/kampanyalar.php", "/hakkimizda.php"],
        "yedek": "/config.php.bak",
        "yedek_icerik": "DB_USER=pzx_app\nDB_PASS={parola}\nDB_HOST=10.0.0.12\n",
        "hassas_veri": "müşteri adresleri ve sipariş geçmişi",
        "hikaye": "Kampanya haftasında sipariş sayfası yavaşladı; yönetici loglarda tuhaf istekler gördü.",
    },
    {
        "kod": "medora",
        "ad": "Medora Sağlık",
        "sektor": "hastane",
        "alan": "medora.lab",
        "sunucu": "medora-portal",
        "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
        "giris": "/hasta/giris.php",
        "id_sayfa": "/randevu.php?id=",
        "normal_sayfalar": ["/index.php", "/doktorlar.php", "/bolumler.php?b=kardiyoloji", "/iletisim.php", "/randevu-al.php"],
        "yedek": "/db_yedek.sql.gz",
        "yedek_icerik": "-- Medora hasta veritabanı yedeği\n-- kullanıcı: medora_db / parola: {parola}\n",
        "hassas_veri": "hasta randevuları ve tanı bilgileri (KVKK'da özel nitelikli veri)",
        "hikaye": "Bir hasta, randevu sayfasında başka birinin bilgilerini gördüğünü bildirdi.",
    },
    {
        "kod": "ferahbank",
        "ad": "Ferah Bank",
        "sektor": "banka",
        "alan": "ferahbank.lab",
        "sunucu": "fb-sube02",
        "kisi": "Kaan Bey (bilgi güvenliği müdürü)",
        "giris": "/sube/giris.php",
        "id_sayfa": "/hesap-ozeti.php?no=",
        "normal_sayfalar": ["/index.php", "/kredi-hesapla.php", "/doviz.php", "/subeler.php", "/sss.php"],
        "yedek": "/.env.old",
        "yedek_icerik": "APP_ENV=production\nDB_USER=fb_sube\nDB_PASSWORD={parola}\n",
        "hassas_veri": "müşteri hesap hareketleri",
        "hikaye": "Gece yarısı internet şubesinde olağandışı bir giriş alarmı düştü.",
    },
    {
        "kod": "kuzgun",
        "ad": "Kuzgun Lojistik",
        "sektor": "lojistik",
        "alan": "kuzgun.lab",
        "sunucu": "kzg-depo",
        "kisi": "Serdar Bey (IT sorumlusu)",
        "giris": "/panel/giris.php",
        "id_sayfa": "/kargo-takip.php?kod=",
        "normal_sayfalar": ["/index.php", "/sube-bul.php", "/fiyat-hesapla.php", "/kurumsal.php", "/kargo-takip.php?kod=KZ48213"],
        "yedek": "/backup.zip",
        "yedek_icerik": "depo_panel kullanıcı listesi\nadmin:{parola}\n",
        "hassas_veri": "alıcı adresleri ve telefonları",
        "hikaye": "Depo panelinde kimsenin hatırlamadığı bir sevkiyat iptali görüldü.",
    },
    {
        "kod": "yesiltepe",
        "ad": "Yeşiltepe Belediyesi",
        "sektor": "belediye",
        "alan": "yesiltepe.lab",
        "sunucu": "ytb-ebelediye",
        "kisi": "Nurcan Hanım (bilgi işlem müdürü)",
        "giris": "/e-belediye/giris.php",
        "id_sayfa": "/borc-sorgula.php?sicil=",
        "normal_sayfalar": ["/index.php", "/duyurular.php", "/ihaleler.php", "/meclis-kararlari.php", "/iletisim.php"],
        "yedek": "/eski_site.tar.gz",
        "yedek_icerik": "# eski site ayarları\n$db_kullanici = 'ytb';\n$db_parola = '{parola}';\n",
        "hassas_veri": "vatandaşların emlak ve vergi borcu bilgileri",
        "hikaye": "Belediyenin borç sorgulama sayfası birkaç dakikalığına çöktü.",
    },
    {
        "kod": "paramix",
        "ad": "Paramix",
        "sektor": "fintech",
        "alan": "paramix.lab",
        "sunucu": "pmx-api01",
        "kisi": "Ece Hanım (CTO)",
        "giris": "/merchant/login.php",
        "id_sayfa": "/odeme-detay.php?islem=",
        "normal_sayfalar": ["/index.php", "/fiyatlandirma.php", "/gelistiriciler.php", "/destek.php", "/blog.php"],
        "yedek": "/settings.php~",
        "yedek_icerik": "<?php\n$api_secret = 'pmx_live_{parola}';\n",
        "hassas_veri": "üye işyerlerinin ödeme kayıtları",
        "hikaye": "Bir üye işyeri, panelinde kendisine ait olmayan işlemler gördüğünü yazdı.",
    },
    {
        "kod": "atolye",
        "ad": "Atölye Kahve",
        "sektor": "küçük işletme",
        "alan": "atolye.lab",
        "sunucu": "atolye-web",
        "kisi": "Berk (kafenin sahibi, siteyi kendisi yönetiyor)",
        "giris": "/wp-login.php",
        "id_sayfa": "/menu.php?urun=",
        "normal_sayfalar": ["/index.php", "/menu.php", "/subeler.php", "/iletisim.php", "/hakkimizda.php"],
        "yedek": "/wp-config.php.bak",
        "yedek_icerik": "define('DB_USER', 'atolye');\ndefine('DB_PASSWORD', '{parola}');\n",
        "hassas_veri": "sadakat kartı üyelerinin e-posta adresleri",
        "hikaye": "Sitenin ana sayfası bir sabah yabancı bir yazıyla açıldı.",
    },
]


def musteri_sec(rng: random.Random, haric: tuple = ()) -> dict:
    adaylar = [m for m in MUSTERILER if m["kod"] not in haric]
    return dict(rng.choice(adaylar))


def musteri(kod: str) -> dict:
    for m in MUSTERILER:
        if m["kod"] == kod:
            return dict(m)
    raise KeyError(kod)
