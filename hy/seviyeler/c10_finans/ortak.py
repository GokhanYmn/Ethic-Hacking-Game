"""Cilt 10 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

"Ferah Mini": oyunun kendi küçük, kurgusal bankacılık/ödeme uygulaması.
- `uygulama/mantik.py` lab'a yazılır; iş kuralları orada durur ve OYUNCU tarafından düzeltilir.
- Sunucu (`banka_servis`) her istekte mantik.py'yi yeniden okur, böylece oyuncu kodu düzeltince
  yeniden başlatmaya gerek kalmaz. Sadece 127.x adresinde dinler; gerçek para/ağ yoktur.
- Düzeltme testleri (`test_*`) uygulamayı canlı sunucuya değil, bellekteki ya da geçici bir
  veritabanına karşı çalıştırır; oyuncunun yanlışlıkla bozduğu canlı veri sonucu etkilemez.

Saldırı yükü, kabuk ya da otomatik araç yoktur: yalnızca parametre değiştirme (negatif tutar,
başka bir hesap numarası) gibi iş mantığı denemeleri ve bunların düzeltilmesi vardır.
"""
from __future__ import annotations

import json
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from hy.motor import servis as sv
from hy.motor.kontrol import Baglam, Secmeli, Sonuc
from hy.ortak import uretec as u

# ----------------------------------------------------------------------------- küçük araçlar


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Test çözücüsü: çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır (rehber bölüm 10)."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


def tl(kurus: int) -> str:
    """12345 -> '123,45' (Türkçe gösterim)."""
    isaret = "-" if kurus < 0 else ""
    k = abs(kurus)
    return f"{isaret}{k // 100},{k % 100:02d}"


SOYADLAR = ["Yılmaz", "Kaya", "Demir", "Çelik", "Şahin", "Aydın", "Öztürk", "Arslan", "Doğan", "Koç",
            "Aksoy", "Polat", "Erdem", "Güneş", "Kurt", "Özdemir", "Acar", "Tekin", "Yıldız", "Bulut"]
ADLAR = ["Ayşe", "Mehmet", "Zeynep", "Ali", "Can", "Elif", "Emre", "Deniz", "Burak", "Selin", "Murat", "Ece",
         "Kerem", "Derya", "Okan", "Gizem", "Tolga", "Büşra", "Serkan", "Melis", "Barış", "Pınar", "Hakan",
         "İrem", "Onur", "Seda", "Volkan", "Nazlı", "Uğur", "Esra"]

_TR = str.maketrans("ıİöÖüÜşŞçÇğĞ", "iIoOuUsScCgG")


def ascii_ad(s: str) -> str:
    return s.translate(_TR).lower().replace(" ", ".")


def kisi_adlari(rng, adet: int) -> list:
    return u.benzersiz(rng, lambda r: f"{r.choice(ADLAR)} {r.choice(SOYADLAR)}", adet)


def sahte_iban(rng) -> str:
    """Kurgusal IBAN (gerçek bir bankaya ait değildir)."""
    return "TR" + "".join(rng.choice("0123456789") for _ in range(24))


# ----------------------------------------------------------------------------- vakalar

VAKALAR = {
    "ferah": {
        "ad": "Ferah Bank — internet şubesi", "musteri": "Ferah Bank", "alan": "sube.ferahbank.lab",
        "terim": "vadesiz hesap", "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)",
        "sahne": "Ferah Bank, internet şubesinin yeni sürümünü yayına almadan önce iş mantığı testi istiyor.",
    },
    "paramix": {
        "ad": "Paramix — dijital cüzdan", "musteri": "Paramix", "alan": "api.paramix.lab",
        "terim": "cüzdan", "kisi": "Ece Hanım (CTO)",
        "sahne": "Paramix, cüzdan API'sinin kullanıma açılmasından önce kendi ekibinin kodunu sana inceletiyor.",
    },
    "pazarix": {
        "ad": "Pazarix — ödeme altyapısı", "musteri": "Pazarix", "alan": "odeme.pazarix.lab",
        "terim": "satıcı hesabı", "kisi": "Tuncay Bey (sistem yöneticisi)",
        "sahne": "Pazarix'in ödeme modülünde bir satıcı, hesabında açıklayamadığı bir hareket gördü.",
    },
    "kuzgun": {
        "ad": "Kuzgun Lojistik — tahsilat sistemi", "musteri": "Kuzgun Lojistik", "alan": "tahsilat.kuzgun.lab",
        "terim": "cari hesap", "kisi": "Serdar Bey (IT sorumlusu)",
        "sahne": "Kuzgun Lojistik, bayilerinden tahsilat yaptığı yeni sistemi denetime sokmak istiyor.",
    },
    "medora": {
        "ad": "Medora Sağlık — fatura ödeme modülü", "musteri": "Medora Sağlık", "alan": "fatura.medora.lab",
        "terim": "hasta cari hesabı", "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
        "sahne": "Medora, hastaların faturalarını internetten ödediği modülün güvenlik değerlendirmesini istedi.",
    },
}


def vaka_sec(rng, kodlar) -> tuple:
    kod = rng.choice(list(kodlar))
    return kod, VAKALAR[kod]


def taban(rng, kod: str, musteri_sayisi: int = 6) -> dict:
    """Vakaya göre uygulama senaryosu: adres, port, müşteriler (0. = oyuncunun test hesabı)."""
    v = VAKALAR[kod]
    host = f"127.{rng.randint(10, 200)}.{rng.randint(0, 250)}.{rng.randint(2, 250)}"
    port = rng.randint(20000, 45000)
    adlar = kisi_adlari(rng, musteri_sayisi)
    hesap0 = rng.randint(2000, 8000)
    ms = []
    for i, ad in enumerate(adlar):
        ms.append({
            "id": i + 1, "ad": ad, "rol": "musteri",
            "telefon": f"05{rng.randint(30, 59)} {rng.randint(100, 999)} {rng.randint(10, 99)} {rng.randint(10, 99)}",
            "eposta": ascii_ad(ad) + "@" + v["alan"].split(".", 1)[1],
            "islem_limiti_kurus": rng.choice([500000, 750000, 1000000]),
            "hesap_id": hesap0 + i, "iban": sahte_iban(rng),
            "bakiye_kurus": rng.randrange(250000, 4000000, 25),
            "token": "tk_" + "".join(rng.choice("0123456789abcdef") for _ in range(12)),
        })
    ben = ms[0]
    return {
        "vaka": v["ad"], "kod": kod, "v": v, "host": host, "port": port, "musteriler": ms,
        "kuponlar": [], "bekleyen": [],
        "metin": {
            "musteri": v["musteri"], "adres": f"{host}:{port}", "ben": ben["ad"], "token": ben["token"],
            "hesap_id": ben["hesap_id"], "terim": v["terim"], "kisi": v["kisi"], "sahne": v["sahne"],
        },
    }


# ----------------------------------------------------------------------------- veritabanı

SEMA = """
CREATE TABLE musteriler(id INTEGER PRIMARY KEY, ad TEXT, rol TEXT, telefon TEXT, eposta TEXT,
                        islem_limiti_kurus INTEGER);
CREATE TABLE hesaplar(id INTEGER PRIMARY KEY, musteri_id INTEGER, iban TEXT, bakiye_kurus INTEGER);
CREATE TABLE oturumlar(token TEXT PRIMARY KEY, musteri_id INTEGER);
CREATE TABLE islemler(id INTEGER PRIMARY KEY AUTOINCREMENT, zaman TEXT, kimden INTEGER, kime INTEGER,
                      tutar_kurus INTEGER, komisyon_kurus INTEGER DEFAULT 0, durum TEXT DEFAULT 'tamam');
CREATE TABLE kuponlar(kod TEXT PRIMARY KEY, indirim_kurus INTEGER, kullanildi INTEGER DEFAULT 0);
CREATE TABLE bekleyen(id INTEGER PRIMARY KEY AUTOINCREMENT, kimden INTEGER, kime INTEGER, tutar_kurus INTEGER,
                      otp TEXT, durum TEXT DEFAULT 'bekliyor');
"""


def db_doldur(db, s: dict) -> None:
    db.executescript(SEMA)
    for m in s["musteriler"]:
        db.execute("INSERT INTO musteriler VALUES (?,?,?,?,?,?)",
                   (m["id"], m["ad"], m["rol"], m["telefon"], m["eposta"], m["islem_limiti_kurus"]))
        db.execute("INSERT INTO hesaplar VALUES (?,?,?,?)", (m["hesap_id"], m["id"], m["iban"], m["bakiye_kurus"]))
        db.execute("INSERT INTO oturumlar VALUES (?,?)", (m["token"], m["id"]))
    for k in s.get("kuponlar", []):
        db.execute("INSERT INTO kuponlar(kod, indirim_kurus) VALUES (?,?)", (k["kod"], k["indirim_kurus"]))
    for b in s.get("bekleyen", []):
        db.execute("INSERT INTO bekleyen(id, kimden, kime, tutar_kurus, otp, durum) VALUES (?,?,?,?,?,?)",
                   (b["id"], b["kimden"], b["kime"], b["tutar_kurus"], b["otp"], b.get("durum", "bekliyor")))
    db.commit()


def db_yaz(yol: Path, s: dict) -> None:
    yol.parent.mkdir(parents=True, exist_ok=True)
    if yol.exists():
        yol.unlink()
    db = sqlite3.connect(str(yol))
    db_doldur(db, s)
    db.close()


def bellek_db(s: dict):
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db_doldur(db, s)
    return db


def kullanici_al(db, musteri_id: int):
    r = db.execute("SELECT m.id, m.ad, m.rol, m.islem_limiti_kurus, h.id AS hesap_id FROM musteriler m "
                   "JOIN hesaplar h ON h.musteri_id = m.id WHERE m.id = ?", (musteri_id,)).fetchone()
    return dict(r) if r else None


def bakiye(db, hesap_id: int) -> int:
    return db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (hesap_id,)).fetchone()[0]


SORGU_ARACI = '''"""Salt okunur veritabanı sorgu aracı: python3 uygulama/sorgu.py "SELECT * FROM hesaplar" """
import sqlite3
import sys
from pathlib import Path

yol = Path(__file__).with_name("banka.db")
db = sqlite3.connect(f"file:{yol}?mode=ro", uri=True)
db.row_factory = sqlite3.Row
if len(sys.argv) < 2:
    print("Kullanım: python3 uygulama/sorgu.py \\"SELECT * FROM hesaplar\\"")
    print("Tablolar:", ", ".join(r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")))
    sys.exit(0)
for satir in db.execute(sys.argv[1]):
    print(" | ".join(str(satir[k]) for k in satir.keys()))
'''

MANTIK_BASLIK = '''# Ferah Mini — iş mantığı katmanı.
# Bu dosyayı düzenleyebilirsin: sunucu her istekte dosyayı yeniden okur (yeniden başlatma gerekmez).
#
# - Veritabanında para KURUŞ cinsinden tam sayıdır (125,50 TL = 12550). İstekte tutar TL olarak gelir.
# - db: sqlite3 bağlantısı (satırlar sütun adıyla okunur). Commit'i sunucu yapar.
# - istek["kullanici"]: oturumdaki müşteri {"id","ad","rol","islem_limiti_kurus","hesap_id"} ya da None.
# - istek["govde"]: gelen JSON (sözlük).  istek["parametre"]: adresteki sayılar (örn. /hesap/<id>/ozet).
# - Her uç nokta (HTTP kodu, sözlük) döndürür.

'''

# ----------------------------------------------------------------------------- uç noktaların kodu

KOD_SAGLIK = '''def hesabim(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    h = db.execute("SELECT id, iban, bakiye_kurus FROM hesaplar WHERE id = ?", (kul["hesap_id"],)).fetchone()
    return 200, {"hesap_id": h["id"], "ad": kul["ad"], "iban": h["iban"], "bakiye_kurus": h["bakiye_kurus"],
                 "bakiye_tl": h["bakiye_kurus"] / 100}

'''

KOMISYON_HATALI = '''def komisyon_kurus(tutar_kurus):
    """Havale komisyonu %1,25. Kural belgesi: en yakın kuruşa yuvarla, yarımlar yukarı."""
    return int(tutar_kurus * 0.0125)

'''

KOMISYON_DOGRU = '''def komisyon_kurus(tutar_kurus):
    """Havale komisyonu %1,25. Kural belgesi: en yakın kuruşa yuvarla, yarımlar yukarı."""
    return (tutar_kurus * 125 + 5000) // 10000

'''

TRANSFER_ACIK = '''def transfer(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    kimden = kul["hesap_id"]
    kime = int(g["kime"])
    tutar = int(round(float(g["tutar"]) * 100))          # TL -> kuruş
    if not db.execute("SELECT 1 FROM hesaplar WHERE id = ?", (kime,)).fetchone():
        return 404, {"hata": "alıcı hesap yok"}
    bakiye = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (kimden,)).fetchone()[0]
    if tutar > bakiye:
        return 400, {"hata": "yetersiz bakiye"}
    kom = komisyon_kurus(tutar)
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus - ? - ? WHERE id = ?", (tutar, kom, kimden))
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?", (tutar, kime))
    db.execute("INSERT INTO islemler(zaman, kimden, kime, tutar_kurus, komisyon_kurus) VALUES (?,?,?,?,?)",
               (datetime.now().isoformat(timespec="seconds"), kimden, kime, tutar, kom))
    yeni = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (kimden,)).fetchone()[0]
    return 200, {"durum": "tamam", "tutar_kurus": tutar, "komisyon_kurus": kom, "yeni_bakiye_kurus": yeni}

'''

TRANSFER_GUVENLI = '''def transfer(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    kimden = kul["hesap_id"]
    try:
        kime = int(g["kime"])
        tutar = int(round(float(g["tutar"]) * 100))      # TL -> kuruş
    except (KeyError, TypeError, ValueError, OverflowError):
        return 400, {"hata": "kime ve tutar geçerli sayılar olmalı"}
    if tutar <= 0:
        return 400, {"hata": "tutar sıfırdan büyük olmalı"}
    if not db.execute("SELECT 1 FROM hesaplar WHERE id = ?", (kime,)).fetchone():
        return 404, {"hata": "alıcı hesap yok"}
    kom = komisyon_kurus(tutar)
    bakiye = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (kimden,)).fetchone()[0]
    if tutar + kom > bakiye:
        return 400, {"hata": "yetersiz bakiye"}
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus - ? - ? WHERE id = ?", (tutar, kom, kimden))
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?", (tutar, kime))
    db.execute("INSERT INTO islemler(zaman, kimden, kime, tutar_kurus, komisyon_kurus) VALUES (?,?,?,?,?)",
               (datetime.now().isoformat(timespec="seconds"), kimden, kime, tutar, kom))
    yeni = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (kimden,)).fetchone()[0]
    return 200, {"durum": "tamam", "tutar_kurus": tutar, "komisyon_kurus": kom, "yeni_bakiye_kurus": yeni}

'''

KUPON_ACIK = '''def kupon_kullan(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    kod = str(istek["govde"].get("kod", ""))
    k = db.execute("SELECT kod, indirim_kurus, kullanildi FROM kuponlar WHERE kod = ?", (kod,)).fetchone()
    if not k:
        return 404, {"hata": "geçersiz kupon"}
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?",
               (k["indirim_kurus"], kul["hesap_id"]))
    db.execute("UPDATE kuponlar SET kullanildi = kullanildi + 1 WHERE kod = ?", (kod,))
    return 200, {"durum": "kupon uygulandi", "eklenen_kurus": k["indirim_kurus"]}

'''

KUPON_GUVENLI = '''def kupon_kullan(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    kod = str(istek["govde"].get("kod", ""))
    k = db.execute("SELECT kod, indirim_kurus FROM kuponlar WHERE kod = ?", (kod,)).fetchone()
    if not k:
        return 404, {"hata": "geçersiz kupon"}
    # Kontrol ve işaretleme TEK SQL ifadesinde: aynı anda gelen iki istekten yalnızca biri satırı değiştirebilir.
    islendi = db.execute("UPDATE kuponlar SET kullanildi = 1 WHERE kod = ? AND kullanildi = 0", (kod,))
    if islendi.rowcount == 0:
        return 409, {"hata": "kupon daha önce kullanılmış"}
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?",
               (k["indirim_kurus"], kul["hesap_id"]))
    return 200, {"durum": "kupon uygulandi", "eklenen_kurus": k["indirim_kurus"]}

'''

# Sadece ardışık tekrarı kapatan ama yarışa açık ara sürüm (testin mesajı için örnek; coz kullanmaz)

OZET_ACIK = '''def hesap_ozet(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    hid = int(istek["parametre"][0])
    h = db.execute("SELECT h.id, h.musteri_id, h.iban, h.bakiye_kurus, m.ad FROM hesaplar h "
                   "JOIN musteriler m ON m.id = h.musteri_id WHERE h.id = ?", (hid,)).fetchone()
    if not h:
        return 404, {"hata": "hesap yok"}
    son = db.execute("SELECT id, zaman, kimden, kime, tutar_kurus FROM islemler "
                     "WHERE kimden = ? OR kime = ? ORDER BY id DESC LIMIT 5", (hid, hid)).fetchall()
    return 200, {"hesap_id": h["id"], "sahip": h["ad"], "iban": h["iban"], "bakiye_kurus": h["bakiye_kurus"],
                 "son_islemler": [dict(x) for x in son]}

'''

OZET_GUVENLI = OZET_ACIK.replace('''    if not h:
        return 404, {"hata": "hesap yok"}
''', '''    if not h:
        return 404, {"hata": "hesap yok"}
    if h["musteri_id"] != kul["id"]:
        return 403, {"hata": "bu hesap size ait değil"}
''')

PROFIL_ACIK = '''def profil_guncelle(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    # Profil modelinin bütün sütunları isteğe açık: gelen alan neyse olduğu gibi yazılıyor.
    for alan in ("telefon", "eposta", "rol", "islem_limiti_kurus"):
        if alan in g:
            db.execute(f"UPDATE musteriler SET {alan} = ? WHERE id = ?", (g[alan], kul["id"]))
    m = db.execute("SELECT telefon, eposta, rol, islem_limiti_kurus FROM musteriler WHERE id = ?",
                   (kul["id"],)).fetchone()
    return 200, {"durum": "guncellendi", "profil": dict(m)}

'''

PROFIL_GUVENLI = '''def profil_guncelle(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    IZINLI = ("telefon", "eposta")                      # allow-list: yalnızca bunlar değişebilir
    if any(alan not in IZINLI for alan in g):
        return 400, {"hata": "değiştirilemez alan gönderildi"}
    for alan in IZINLI:
        if alan in g:
            db.execute(f"UPDATE musteriler SET {alan} = ? WHERE id = ?", (g[alan], kul["id"]))
    m = db.execute("SELECT telefon, eposta, rol, islem_limiti_kurus FROM musteriler WHERE id = ?",
                   (kul["id"],)).fetchone()
    return 200, {"durum": "guncellendi", "profil": dict(m)}

'''

BASLAT_ACIK = '''import secrets


def transfer_baslat(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    try:
        kime = int(g["kime"])
        tutar = int(round(float(g["tutar"]) * 100))
    except (KeyError, TypeError, ValueError, OverflowError):
        return 400, {"hata": "kime ve tutar geçerli sayılar olmalı"}
    if tutar <= 0:
        return 400, {"hata": "tutar sıfırdan büyük olmalı"}
    if not db.execute("SELECT 1 FROM hesaplar WHERE id = ?", (kime,)).fetchone():
        return 404, {"hata": "alıcı hesap yok"}
    otp = "%06d" % secrets.randbelow(1000000)
    cur = db.execute("INSERT INTO bekleyen(kimden, kime, tutar_kurus, otp) VALUES (?,?,?,?)",
                     (kul["hesap_id"], kime, tutar, otp))
    sms_gonder(f"Ferah Mini onay kodunuz {otp} (işlem #{cur.lastrowid}, {tutar / 100:.2f} TL)")
    return 200, {"durum": "onay_bekliyor", "id": cur.lastrowid}

'''

BASLAT_GUVENLI = BASLAT_ACIK.replace('''    if not db.execute("SELECT 1 FROM hesaplar WHERE id = ?", (kime,)).fetchone():
        return 404, {"hata": "alıcı hesap yok"}
    otp''', '''    if tutar > kul["islem_limiti_kurus"]:
        return 403, {"hata": "işlem limitini aşıyor"}
    if not db.execute("SELECT 1 FROM hesaplar WHERE id = ?", (kime,)).fetchone():
        return 404, {"hata": "alıcı hesap yok"}
    otp''')

ONAYLA_ACIK = '''def transfer_onayla(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    b = db.execute("SELECT id, kimden, kime, tutar_kurus, otp, durum FROM bekleyen WHERE id = ?",
                   (g.get("id"),)).fetchone()
    if not b:
        return 404, {"hata": "bekleyen işlem yok"}
    # Mobil uygulama kodu kendisi doğruladıysa "dogrulandi": true gönderiyor; sunucu buna güveniyor.
    if not g.get("dogrulandi"):
        if str(g.get("otp")) != b["otp"]:
            return 403, {"hata": "onay kodu yanlış"}
    bak = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (b["kimden"],)).fetchone()[0]
    if b["tutar_kurus"] > bak:
        return 400, {"hata": "yetersiz bakiye"}
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus - ? WHERE id = ?", (b["tutar_kurus"], b["kimden"]))
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?", (b["tutar_kurus"], b["kime"]))
    db.execute("UPDATE bekleyen SET durum = 'tamam' WHERE id = ?", (b["id"],))
    return 200, {"durum": "tamam", "tutar_kurus": b["tutar_kurus"]}

'''

ONAYLA_GUVENLI = '''def transfer_onayla(db, istek):
    kul = istek["kullanici"]
    if not kul:
        return 401, {"hata": "oturum gerekli"}
    g = istek["govde"]
    b = db.execute("SELECT id, kimden, kime, tutar_kurus, otp, durum FROM bekleyen WHERE id = ?",
                   (g.get("id"),)).fetchone()
    if not b or b["kimden"] != kul["hesap_id"]:
        return 404, {"hata": "bekleyen işlem yok"}
    if b["durum"] != "bekliyor":
        return 409, {"hata": "işlem zaten sonuçlanmış"}
    if str(g.get("otp")) != b["otp"]:                  # kodu SUNUCU karşılaştırır; istemci beyanına güvenilmez
        return 403, {"hata": "onay kodu yanlış"}
    bak = db.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (b["kimden"],)).fetchone()[0]
    if b["tutar_kurus"] > bak:
        return 400, {"hata": "yetersiz bakiye"}
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus - ? WHERE id = ?", (b["tutar_kurus"], b["kimden"]))
    db.execute("UPDATE hesaplar SET bakiye_kurus = bakiye_kurus + ? WHERE id = ?", (b["tutar_kurus"], b["kime"]))
    db.execute("UPDATE bekleyen SET durum = 'tamam' WHERE id = ?", (b["id"],))
    return 200, {"durum": "tamam", "tutar_kurus": b["tutar_kurus"]}

'''

# fonksiyon adı -> güvenli kaynak (test çözücüsü ve b08 kullanır)
GUVENLI = {
    "komisyon_kurus": KOMISYON_DOGRU, "transfer": TRANSFER_GUVENLI, "kupon_kullan": KUPON_GUVENLI,
    "hesap_ozet": OZET_GUVENLI, "profil_guncelle": PROFIL_GUVENLI, "transfer_baslat": BASLAT_GUVENLI,
    "transfer_onayla": ONAYLA_GUVENLI,
}


def fonksiyon_degistir(kaynak: str, ad: str, yeni: str) -> str:
    """Kaynaktaki üst düzey `def ad(...)` bloğunu `yeni` ile değiştirir (yoksa sona ekler)."""
    desen = re.compile(rf"^def {re.escape(ad)}\(.*?(?=^(?:def |import |from |class )|\Z)", re.S | re.M)
    if desen.search(kaynak):
        return desen.sub(lambda m: yeni.rstrip("\n") + "\n\n\n", kaynak, count=1)
    return kaynak.rstrip("\n") + "\n\n\n" + yeni


def duzelt(lab: Path, *adlar: str) -> None:
    """TEST ÇÖZÜCÜSÜ: oyuncunun yapacağı düzeltmeyi (güvenli sürümü yazmak) uygular."""
    yol = lab / "uygulama" / "mantik.py"
    k = yol.read_text(encoding="utf-8")
    for ad in adlar:
        yeni = GUVENLI[ad].replace("import secrets" + chr(10) * 3, "", 1)
        k = fonksiyon_degistir(k, ad, yeni)
    yol.write_text(k, encoding="utf-8")


# ----------------------------------------------------------------------------- sunucu

_LOG_KILIDI = threading.Lock()

ROTALAR = [
    ("GET", r"^/saglik$", "saglik"),
    ("GET", r"^/hesabim$", "hesabim"),
    ("POST", r"^/transfer$", "transfer"),
    ("GET", r"^/hesap/(\d+)/ozet$", "hesap_ozet"),
    ("POST", r"^/kupon/kullan$", "kupon_kullan"),
    ("POST", r"^/profil/guncelle$", "profil_guncelle"),
    ("POST", r"^/transfer/baslat$", "transfer_baslat"),
    ("POST", r"^/transfer/onayla$", "transfer_onayla"),
]


def mantik_yukle(lab: Path, sms=None) -> dict:
    """lab/uygulama/mantik.py dosyasını taze bir ad alanına yükler (her istekte yeniden)."""
    yol = lab / "uygulama" / "mantik.py"
    kod = compile(yol.read_text(encoding="utf-8"), str(yol), "exec")

    def sms_gonder(metin: str) -> None:
        if sms is not None:
            sms.append(metin)
            return
        with _LOG_KILIDI, open(lab / "uygulama" / "sms.log", "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} SMS: {metin}\n")

    ns = {"__name__": "mantik", "datetime": datetime, "sms_gonder": sms_gonder}
    exec(kod, ns)
    return ns


def log_satiri(t: datetime, kullanici: str, yontem: str, yol: str, govde, kod: int) -> str:
    g = json.dumps(govde, ensure_ascii=False, separators=(",", ":")) if govde else "-"
    return f"{t:%Y-%m-%dT%H:%M:%S}.{t.microsecond // 1000:03d} {kullanici} {yontem} {yol} {g} {kod}"


def _isleyici(lab: Path):
    db_yolu = lab / "uygulama" / "banka.db"
    log_yolu = lab / "uygulama" / "erisim.log"

    class Isleyici(sv.SessizIsleyici):
        server_version = "FerahMini/1.0"

        def _yurut(self, yontem: str) -> None:
            url = urlparse(self.path)
            uzunluk = int(self.headers.get("Content-Length") or 0)
            ham = self.rfile.read(uzunluk) if uzunluk else b""
            govde, kod, cevap, kul_ad = {}, 404, {"hata": "böyle bir uç nokta yok"}, "-"
            try:
                if ham:
                    govde = json.loads(ham.decode("utf-8"))
                    if not isinstance(govde, dict):
                        raise ValueError("gövde bir JSON nesnesi olmalı")
            except ValueError as e:
                kod, cevap = 400, {"hata": f"geçersiz JSON: {e}"}
                govde = {}
                self._bitir(yontem, url.path, ham.decode("utf-8", "replace")[:80], kod, cevap, kul_ad)
                return
            if yontem == "GET" and url.path == "/saglik":
                self._bitir(yontem, url.path, None, 200, {"durum": "ayakta"}, kul_ad)
                return
            db = None
            try:
                ns = mantik_yukle(lab)
                db = sqlite3.connect(str(db_yolu), timeout=10)
                db.row_factory = sqlite3.Row
                token = self.headers.get("X-Oturum", "")
                satir = db.execute("SELECT m.id, m.ad, m.rol, m.islem_limiti_kurus, h.id AS hesap_id FROM oturumlar o "
                                   "JOIN musteriler m ON m.id = o.musteri_id JOIN hesaplar h ON h.musteri_id = m.id "
                                   "WHERE o.token = ?", (token,)).fetchone()
                kul = dict(satir) if satir else None
                kul_ad = ascii_ad(kul["ad"]) if kul else "-"
                for m, desen, ad in ROTALAR:
                    eslesme = re.match(desen, url.path)
                    if m == yontem and eslesme and ad in ns:
                        istek = {"yontem": yontem, "yol": url.path, "sorgu": {k: v[0] for k, v in parse_qs(url.query).items()},
                                 "govde": govde, "kullanici": kul, "parametre": eslesme.groups()}
                        sonuc = ns[ad](db, istek)
                        kod, cevap = sonuc if isinstance(sonuc, tuple) else (200, sonuc)
                        break
                if kod < 500:
                    db.commit()
                else:
                    db.rollback()
            except Exception as e:  # oyuncunun kodu hata verirse sunucu düşmesin, hatayı göstersin
                kod = 500
                cevap = {"hata": f"uygulama/mantik.py çalışırken hata verdi: {type(e).__name__}: {e}",
                         "satir": traceback.format_exc().strip().splitlines()[-3:-1]}
                if db:
                    db.rollback()
            finally:
                if db:
                    db.close()
            self._bitir(yontem, url.path, govde, kod, cevap, kul_ad)

        def _bitir(self, yontem, yol, govde, kod, cevap, kul_ad):
            with _LOG_KILIDI, open(log_yolu, "a", encoding="utf-8") as f:
                f.write(log_satiri(datetime.now(), kul_ad, yontem, yol, govde, kod) + "\n")
            self.yanit(kod, json.dumps(cevap, ensure_ascii=False) + "\n", "application/json; charset=utf-8")

        def do_GET(self):
            self._yurut("GET")

        def do_POST(self):
            self._yurut("POST")

    return Isleyici


def banka_servis(s: dict, lab: Path, dur) -> None:
    sv.calistir([sv.http_sunucu(s["host"], s["port"], _isleyici(lab))], dur)


def uygulama_yaz(lab: Path, s: dict, mantik_kodu: str, sms_baslangic: list | None = None) -> None:
    """Lab'a uygulama/ klasörünü yazar: mantik.py, banka.db, sorgu.py, boş erişim logu."""
    u.yaz(lab / "uygulama" / "mantik.py", MANTIK_BASLIK + mantik_kodu)
    u.yaz(lab / "uygulama" / "sorgu.py", SORGU_ARACI)
    u.yaz(lab / "uygulama" / "erisim.log", "")
    u.yaz(lab / "uygulama" / "sms.log", "".join(sms_baslangic or []))
    db_yaz(lab / "uygulama" / "banka.db", s)


# ----------------------------------------------------------------------------- test çözücüsü için curl

def curl(s: dict, lab: Path, yontem: str, yol: str, govde: dict | None = None, token: str | None = None):
    """Gerçek curl ile uygulamaya istek atar; (yanıt metni, JSON ya da None) döner."""
    token = token or s["musteriler"][0]["token"]
    komut = f"curl -s -X {yontem} -H 'X-Oturum: {token}'"
    if govde is not None:
        komut += " -H 'Content-Type: application/json' -d '" + json.dumps(govde) + "'"
    komut += f" http://{s['host']}:{s['port']}{yol}"
    metin = sh(komut, lab)
    try:
        return metin, json.loads(metin)
    except ValueError:
        return metin, None


def db_oku(lab: Path, sql: str, parametre=()) -> list:
    db = sqlite3.connect(f"file:{lab / 'uygulama' / 'banka.db'}?mode=ro", uri=True, timeout=10)
    try:
        return db.execute(sql, parametre).fetchall()
    finally:
        db.close()


# ----------------------------------------------------------------------------- düzeltme testleri

def _istek(kul, govde=None, parametre=()):
    return {"yontem": "POST", "yol": "", "sorgu": {}, "govde": govde or {}, "kullanici": kul, "parametre": parametre}


def cagir(ns: dict, ad: str, db, kul, govde=None, parametre=()):
    """Uç nokta fonksiyonunu çağırır; (kod, sözlük) döner. Kodun fırlattığı hatayı 500 olarak yakalar."""
    if ad not in ns:
        raise KeyError(f"mantik.py içinde `{ad}` fonksiyonu yok (silmiş olabilir misin?)")
    try:
        sonuc = ns[ad](db, _istek(kul, govde, parametre))
    except Exception as e:  # noqa: BLE001
        return 500, {"hata": f"{type(e).__name__}: {e}"}
    return sonuc if isinstance(sonuc, tuple) else (200, sonuc)


def durum_testi(test):
    """`test(ns, s) -> Sonuc` fonksiyonunu Durum için sarar: mantik.py'yi yükler, hataları anlatır."""
    def f(b: Baglam) -> Sonuc:
        try:
            ns = mantik_yukle(b.lab)
        except SyntaxError as e:
            return Sonuc(False, f"`uygulama/mantik.py` yazım hatası: satır {e.lineno}: {e.msg}. Girintilere dikkat et.")
        except Exception as e:  # noqa: BLE001
            return Sonuc(False, f"`uygulama/mantik.py` yüklenemedi: {type(e).__name__}: {e}")
        try:
            return test(ns, b.senaryo)
        except KeyError as e:
            return Sonuc(False, str(e).strip("'\""))
        except Exception as e:  # noqa: BLE001
            return Sonuc(False, f"Testi çalıştırırken kodun hata verdi: {type(e).__name__}: {e}")
    return f


def _durum(db, s):
    return {m["hesap_id"]: bakiye(db, m["hesap_id"]) for m in s["musteriler"]}


def test_negatif(ns, s) -> Sonuc:
    db = bellek_db(s)
    a, b = s["musteriler"][0], s["musteriler"][1]
    kul = kullanici_al(db, a["id"])
    once = _durum(db, s)
    for ad, tutar in (("negatif", -50), ("negatif (küçük)", -0.01), ("sıfır", 0)):
        kod, cevap = cagir(ns, "transfer", db, kul, {"kime": b["hesap_id"], "tutar": tutar})
        if kod != 400 or _durum(db, s) != once:
            return Sonuc(False, f"{ad} tutarlı transfer hâlâ reddedilmiyor ya da bakiyeler değişti "
                                f"(yanıt {kod}: {cevap}). Sıfır ve negatif tutar 400 ile reddedilmeli.", yakin=True)
    for ad, tutar in (("metin", "abc"), ("boş", None)):
        kod, cevap = cagir(ns, "transfer", db, kul, {"kime": b["hesap_id"], "tutar": tutar})
        if kod != 400:
            return Sonuc(False, f"Geçersiz ({ad}) tutar 400 ile reddedilmeli; yanıt {kod}: {cevap}. "
                                "Sunucu hata fırlatıp çökmemeli.", yakin=True)
    kod, cevap = cagir(ns, "transfer", db, kul, {"kime": b["hesap_id"], "tutar": 25.5})
    if kod != 200 or bakiye(db, b["hesap_id"]) != once[b["hesap_id"]] + 2550:
        return Sonuc(False, f"Normal bir transfer artık çalışmıyor: yanıt {kod}: {cevap}. Düzeltme gerçek işlemleri bozmamalı.")
    return Sonuc(True, "Negatif, sıfır ve geçersiz tutarlar reddediliyor; normal transfer çalışıyor.")


def test_komisyon(ns, s) -> Sonuc:
    if "komisyon_kurus" not in ns:
        return Sonuc(False, "mantik.py içinde `komisyon_kurus` fonksiyonu yok.")
    f = ns["komisyon_kurus"]
    for tutar in (100, 1000, 1040, 2999, 3000, 7777, 12345, 100000, 160, 40, 56, 43, 99999, 250050, 1234567):
        beklenen = (tutar * 125 + 5000) // 10000
        try:
            sonuc = f(tutar)
        except Exception as e:  # noqa: BLE001
            return Sonuc(False, f"komisyon_kurus({tutar}) hata verdi: {e}")
        if sonuc != beklenen:
            return Sonuc(False, f"komisyon_kurus({tutar}) = {sonuc} döndü, kural belgesine göre {beklenen} olmalı "
                                "(%1,25, en yakın kuruşa, yarımlar yukarı). Kesme (int) ya da float yuvarlama "
                                "yerine tam sayı aritmetiği dene.", yakin=abs(sonuc - beklenen) <= 1)
        if not isinstance(sonuc, int):
            return Sonuc(False, f"komisyon_kurus tam sayı (int) döndürmeli, `{type(sonuc).__name__}` döndürdü.")
    return Sonuc(True, "Komisyon her tutarda kurala uygun, tam sayı aritmetiğiyle hesaplanıyor.")


class _Gecikmeli:
    """sqlite bağlantısını sarar: her SELECT'ten sonra bekler (iki isteğin aynı anda araya girmesini simüle eder)."""

    def __init__(self, baglanti, bekleme: float):
        self._c, self._b = baglanti, bekleme

    def execute(self, sql, *a):
        r = self._c.execute(sql, *a)
        if sql.lstrip().upper().startswith("SELECT"):
            time.sleep(self._b)
        return r

    def __getattr__(self, ad):
        return getattr(self._c, ad)


def test_kupon_tekrar(ns, s) -> Sonuc:
    db = bellek_db(s)
    kupon = s["kuponlar"][0]
    a = s["musteriler"][0]
    kul = kullanici_al(db, a["id"])
    once = bakiye(db, a["hesap_id"])
    k1, c1 = cagir(ns, "kupon_kullan", db, kul, {"kod": kupon["kod"]})
    db.commit()
    if k1 != 200 or bakiye(db, a["hesap_id"]) != once + kupon["indirim_kurus"]:
        return Sonuc(False, f"İlk kupon kullanımı artık çalışmıyor (yanıt {k1}: {c1}); bakiye tam kupon tutarı kadar artmalı.")
    k2, c2 = cagir(ns, "kupon_kullan", db, kul, {"kod": kupon["kod"]})
    db.commit()
    if bakiye(db, a["hesap_id"]) != once + kupon["indirim_kurus"] or k2 < 400:
        return Sonuc(False, f"Aynı kupon ikinci kez kabul ediliyor (yanıt {k2}). Kullanılmış kupon reddedilmeli "
                            "(4xx) ve bakiye ikinci kez artmamalı.", yakin=True)
    k3, c3 = cagir(ns, "kupon_kullan", db, kul, {"kod": "YOKBOYLEKOD"})
    if k3 != 404:
        return Sonuc(False, f"Var olmayan kupon 404 vermeli; yanıt {k3}.")
    return Sonuc(True, "Kupon bir kez geçerli; ikinci kullanım reddediliyor.")


def test_kupon_yaris(ns, s) -> Sonuc:
    kupon = s["kuponlar"][1]
    a = s["musteriler"][0]
    with tempfile.TemporaryDirectory() as d:
        yol = Path(d) / "yaris.db"
        db_yaz(yol, s)
        sonuclar = []
        bariyer = threading.Barrier(2)

        def istek():
            c = sqlite3.connect(str(yol), timeout=10)
            c.row_factory = sqlite3.Row
            sar = _Gecikmeli(c, 0.25)
            kul = kullanici_al(c, a["id"])
            bariyer.wait()
            try:
                kod, _ = cagir(ns, "kupon_kullan", sar, kul, {"kod": kupon["kod"]})
                c.commit()
                sonuclar.append(kod)
            except Exception as e:  # noqa: BLE001
                sonuclar.append(f"hata:{e}")
            finally:
                c.close()

        ts = [threading.Thread(target=istek) for _ in range(2)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        c = sqlite3.connect(str(yol))
        son = c.execute("SELECT bakiye_kurus FROM hesaplar WHERE id = ?", (a["hesap_id"],)).fetchone()[0]
        c.close()
    artis = son - a["bakiye_kurus"]
    if artis > kupon["indirim_kurus"]:
        return Sonuc(False, f"Aynı anda gelen iki istek kuponu {artis // kupon['indirim_kurus']} kez bozdurdu. "
                            "Kontrol (SELECT) ile işaretleme (UPDATE) ayrı adımlar olduğu için ikisi de "
                            "\"kullanılmamış\" gördü. Kontrolü ve işaretlemeyi tek bir UPDATE içinde yap "
                            "(`WHERE ... AND kullanildi = 0`) ve etkilenen satır sayısına (`rowcount`) bak.", yakin=True)
    if artis != kupon["indirim_kurus"]:
        return Sonuc(False, f"Kupon eşzamanlı istekte bir kez bile uygulanamadı (yanıtlar: {sonuclar}).")
    return Sonuc(True, "İki eşzamanlı istekte kupon yalnızca bir kez bozduruldu: işlem atomik.")


def test_bola(ns, s) -> Sonuc:
    db = bellek_db(s)
    a, b = s["musteriler"][0], s["musteriler"][1]
    kul = kullanici_al(db, a["id"])
    kod, cevap = cagir(ns, "hesap_ozet", db, kul, parametre=(str(a["hesap_id"]),))
    if kod != 200 or cevap.get("bakiye_kurus") != a["bakiye_kurus"]:
        return Sonuc(False, f"Kendi hesabının özeti artık görünmüyor (yanıt {kod}). Düzeltme sahibini engellememeli.")
    kod, cevap = cagir(ns, "hesap_ozet", db, kul, parametre=(str(b["hesap_id"]),))
    if kod not in (403, 404) or "bakiye_kurus" in cevap or "iban" in cevap:
        return Sonuc(False, f"Başka birinin hesabının özeti hâlâ dönüyor (yanıt {kod}). Hesabın isteği yapana ait "
                            "olup olmadığını sunucuda kontrol et; değilse 403 dön.", yakin=True)
    return Sonuc(True, "Hesap özeti yalnızca hesabın sahibine gösteriliyor.")


def test_kutle(ns, s) -> Sonuc:
    db = bellek_db(s)
    a = s["musteriler"][0]
    kul = kullanici_al(db, a["id"])
    kod, cevap = cagir(ns, "profil_guncelle", db, kul, {"telefon": "0500 000 00 00", "rol": "personel",
                                                         "islem_limiti_kurus": 999999999})
    m = db.execute("SELECT rol, islem_limiti_kurus FROM musteriler WHERE id = ?", (a["id"],)).fetchone()
    if m["rol"] != "musteri" or m["islem_limiti_kurus"] != a["islem_limiti_kurus"]:
        return Sonuc(False, "İstekle gelen `rol` ya da `islem_limiti_kurus` hâlâ kaydediliyor. Kullanıcı yalnızca "
                            "izin verilen alanları (telefon, eposta) değiştirebilmeli: allow-list kullan.", yakin=True)
    kod, cevap = cagir(ns, "profil_guncelle", db, kul, {"telefon": "0555 111 22 33"})
    t = db.execute("SELECT telefon FROM musteriler WHERE id = ?", (a["id"],)).fetchone()[0]
    if kod != 200 or t != "0555 111 22 33":
        return Sonuc(False, f"İzin verilen alan (telefon) artık güncellenemiyor (yanıt {kod}: {cevap}).")
    return Sonuc(True, "Yalnızca telefon ve e-posta değişebiliyor; rol ve limit istekle değiştirilemiyor.")


def baslat_dene(ns, s, db, kul, kime_hesap, tutar_tl):
    sms: list = []
    ns["sms_gonder"] = sms.append
    kod, cevap = cagir(ns, "transfer_baslat", db, kul, {"kime": kime_hesap, "tutar": tutar_tl})
    return kod, cevap, sms


def test_limit(ns, s) -> Sonuc:
    db = bellek_db(s)
    a, b = s["musteriler"][0], s["musteriler"][1]
    kul = kullanici_al(db, a["id"])
    limit = a["islem_limiti_kurus"]
    kod, cevap, sms = baslat_dene(ns, s, db, kul, b["hesap_id"], (limit + 100) / 100)
    if kod < 400 or db.execute("SELECT COUNT(*) FROM bekleyen WHERE tutar_kurus > ?", (limit,)).fetchone()[0]:
        return Sonuc(False, f"Limitin üstünde bir işlem başlatılabiliyor (yanıt {kod}). Limit kontrolü istemcide değil "
                            "SUNUCUDA yapılmalı: tutar `kul[\"islem_limiti_kurus\"]` değerini aşarsa 403 dön.", yakin=True)
    kod, cevap, sms = baslat_dene(ns, s, db, kul, b["hesap_id"], limit / 100)
    if kod != 200:
        return Sonuc(False, f"Limit tutarına eşit işlem de reddedilmiş (yanıt {kod}: {cevap}). Limitin kendisi serbest, "
                            "yalnızca aşan reddedilmeli.")
    return Sonuc(True, "İşlem limiti sunucuda uygulanıyor; limit altı işlem başlayabiliyor.")


def test_otp(ns, s) -> Sonuc:
    db = bellek_db(s)
    a, b, c = s["musteriler"][0], s["musteriler"][1], s["musteriler"][2]
    kul, kul_c = kullanici_al(db, a["id"]), kullanici_al(db, c["id"])
    kod, cevap, sms = baslat_dene(ns, s, db, kul, b["hesap_id"], 10)
    if kod != 200:
        return Sonuc(False, f"İşlem başlatma çalışmıyor (yanıt {kod}: {cevap}).")
    bid = cevap["id"]
    otp = db.execute("SELECT otp FROM bekleyen WHERE id = ?", (bid,)).fetchone()[0]
    once = _durum(db, s)
    for ad, govde in (("`dogrulandi: true` beyanıyla", {"id": bid, "dogrulandi": True}),
                      ("yanlış kodla", {"id": bid, "otp": "000000" if otp != "000000" else "111111"}),
                      ("kodsuz", {"id": bid})):
        k, cv = cagir(ns, "transfer_onayla", db, kul, govde)
        if k < 400 or _durum(db, s) != once:
            return Sonuc(False, f"İşlem {ad} onaylanabildi (yanıt {k}). Onay kodunu sunucu, bekleyen kayıttaki kodla "
                                "karşılaştırmalı; istemcinin beyanına güvenmemeli.", yakin=True)
    k, cv = cagir(ns, "transfer_onayla", db, kul_c, {"id": bid, "otp": otp})
    if k < 400 or _durum(db, s) != once:
        return Sonuc(False, "Başka bir müşteri, doğru kodu bilse bile bu işlemi onaylayabildi. Onay yalnızca "
                            "bekleyen işlemin sahibine açık olmalı.", yakin=True)
    k, cv = cagir(ns, "transfer_onayla", db, kul, {"id": bid, "otp": otp})
    if k != 200 or bakiye(db, b["hesap_id"]) != once[b["hesap_id"]] + 1000:
        return Sonuc(False, f"Doğru kodla onay artık çalışmıyor (yanıt {k}: {cv}).")
    k, cv = cagir(ns, "transfer_onayla", db, kul, {"id": bid, "otp": otp})
    if k < 400 or bakiye(db, b["hesap_id"]) != once[b["hesap_id"]] + 1000:
        return Sonuc(False, "Aynı işlem ikinci kez onaylanabildi (para iki kez gitti). Sonuçlanmış işlem tekrar "
                            "onaylanamamalı.", yakin=True)
    return Sonuc(True, "Onay kodu sunucuda doğrulanıyor; yanlış/kodsuz/başkasının/tekrar onaylar reddediliyor.")
