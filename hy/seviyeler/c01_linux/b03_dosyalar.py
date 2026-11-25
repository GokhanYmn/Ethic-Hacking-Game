"""Cilt 1 · Bölüm 3 — Dosyalarla Çalışmak.

Beceri: dosya okumak (head/tail), oluşturmak/kopyalamak/taşımak (mkdir, cp, mv), joker
karakterler (*, ?, [...]), dosyanın gerçek türü (file) ve find ile dosya avı (-name, -iname,
-type, -mtime). Kapanış bulgusu: web kökünde unutulmuş .bak yedeğindeki parola.

Vakalar: farklı müşterilerin taşınacak eski sunucu kopyaları; klasör adları, yedek dosya
adlandırması, gizli not, sahte resim dosyasının türü ve çeyrek raporları her vakada değişir.
"""
from __future__ import annotations

import gzip
import io
import os
import re
import subprocess
import time
import zipfile
from pathlib import Path

from hy.motor.kontrol import Bayrak, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye, yer_tut
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

DUZENLER = [
    # (web kökü, yedek klasörü, rapor klasörü, log klasörü, görsel klasörü)
    ("site_kopyasi", "yedekler", "raporlar", "loglar", "gorseller"),
    ("www", "backup", "aylik_raporlar", "kayitlar", "resimler"),
    ("public_html", "arsiv_yedek", "rapor_arsivi", "log", "medya"),
    ("web_kok", "snapshotlar", "raporlar_eski", "gunlukler", "fotograflar"),
]
YEDEK_ADLARI = [("yedek_", ".tar"), ("dump_", ".sql"), ("snap_", ".tar.gz"), ("arsiv_", ".zip")]
WEB_DALLARI = ["admin", "css", "js", "img/urunler", "img/banner", "uploads/2025", "uploads/2026", "includes",
               "vendor/lib", "eski/tema/v1", "api/v2", "cache", "lang/tr", "tema/parcalar"]
BAK_DOSYALARI = [("config.php.bak", "define"), ("ayarlar.inc.php.bak", "php"), ("db_baglanti.env.bak", "env"),
                 ("settings.yml.bak", "yaml")]
BAK_ICERIK = {
    "define": "<?php\ndefine('DB_HOST', '10.0.0.12');\ndefine('DB_USER', '{kod}_app');\ndefine('DB_PASSWORD', '{parola}');\n",
    "php": "<?php\n$db_sunucu = 'localhost';\n$db_kullanici = '{kod}';\n$db_parola = '{parola}';\n",
    "env": "DB_HOST=10.0.0.12\nDB_USER={kod}_app\nDB_PASS={parola}\n",
    "yaml": "veritabani:\n  sunucu: 10.0.0.12\n  kullanici: {kod}_app\n  parola: {parola}\n",
}
NOT_ADLARI = ["gizli_not.txt", "sifre_hatirlatma.txt", "unutma.txt", "yonetici_notu.txt"]
FOTOLAR = ["vitrin.jpg", "logo_buyuk.jpg", "ekip.jpg", "magaza_on.jpg", "kampanya.jpg", "urun_01.jpg",
           "urun_02.jpg", "afis.jpg", "sertifika.jpg", "etkinlik.jpg"]
SAHTE_TURLER = ["zip", "gzip", "pdf", "betik"]
CEYREKLER = {1: ("1. çeyrek", "Ocak-Mart", "0[1-3]"), 2: ("2. çeyrek", "Nisan-Haziran", "0[4-6]"),
             3: ("3. çeyrek", "Temmuz-Eylül", "0[7-9]"), 4: ("4. çeyrek", "Ekim-Aralık", "1[0-2]")}
CALISMA_ADLARI = ["calisma", "inceleme", "analiz_masasi", "vaka_dosyasi"]


class _Durum(Durum):
    """Çözüm metnindeki <<yer tutucuları>> da dolduran Durum."""

    def cevabi_goster(self, b):
        return yer_tut(self.cozum, b.senaryo)


def _karisik_harf(rng, ad: str) -> str:
    while True:
        sonuc = "".join(ch.upper() if ch.isalpha() and rng.random() < 0.5 else ch for ch in ad)
        if sonuc != ad and sonuc != ad.upper():
            return sonuc


def uret(rng):
    m = musteri_sec(rng)
    web, yedek_k, rapor_k, log_k, foto_k = rng.choice(DUZENLER)
    # Web ağacı: seçilen dallar + bütün ara klasörleri
    dallar = rng.sample(WEB_DALLARI, rng.randint(5, 9))
    dizinler = set()
    for d in dallar:
        parca = d.split("/")
        for i in range(1, len(parca) + 1):
            dizinler.add("/".join(parca[:i]))
    dizinler = sorted(dizinler)
    derin = [d for d in dizinler if "/" in d] or dizinler
    bak_ad, bak_tur = rng.choice(BAK_DOSYALARI)
    bak_yer = rng.choice(derin)
    not_ad = rng.choice(NOT_ADLARI)
    not_yer = rng.choice([d for d in dizinler if d != bak_yer])
    # Yedekler: tek ve iki haneli numaralar, eski/yeni karışık
    onek, uzanti = rng.choice(YEDEK_ADLARI)
    while True:
        numaralar = sorted(rng.sample(range(1, 25), rng.randint(10, 14)))
        tek = sum(1 for n in numaralar if n < 10)
        if 3 <= tek <= len(numaralar) - 3:
            break
    yedekler = {}
    for n in numaralar:
        yedekler[f"{onek}{n}{uzanti}"] = rng.choice([rng.randint(45, 400), rng.uniform(0.05, 2.0)])
    for n in rng.sample(numaralar, 2):
        yedekler[f"{onek}{n}{uzanti}.md5"] = yedekler[f"{onek}{n}{uzanti}"]
    yedekler[f"{onek}eski{uzanti}"] = rng.randint(200, 500)
    for ad in sorted(yedekler):                    # hem eski hem yeni en az 3'er dosya olsun
        eski = sum(1 for g in yedekler.values() if g > 30)
        if eski < 3 and yedekler[ad] <= 30:
            yedekler[ad] = rng.randint(45, 400)
        elif eski > len(yedekler) - 3 and yedekler[ad] > 30:
            yedekler[ad] = rng.uniform(0.05, 2.0)
    eski = sum(1 for g in yedekler.values() if g > 30)
    yil = rng.choice([2024, 2025])
    ceyrek = rng.randint(1, 4)
    ceyrek_adi, aylar, desen = CEYREKLER[ceyrek]
    ceyrek_k = f"{m['kod']}_{yil}_q{ceyrek}"
    ay_listesi = [int(desen[0] + c) for c in "0123456789" if re.fullmatch(desen, desen[0] + c)]
    fotolar = rng.sample(FOTOLAR, rng.randint(5, 7))
    sahte = rng.choice(fotolar)
    calisma_k = rng.choice(CALISMA_ADLARI)
    yeni_ad = rng.choice(["analiz.log", "inceleme.log", "kopya_access.log", f"{m['kod']}_access.log"])
    parola = u.parola(rng)
    web_log = loglar.web_logu(rng, m, saldirilar=(), mesru_kisi=(2, 4))
    return {
        "vaka": f"{m['ad']} — taşınacak sunucunun dosya envanteri ({m['sunucu']})",
        "musteri": m,
        "duzen": (web, yedek_k, rapor_k, log_k, foto_k),
        "dizinler": dizinler, "bak": (bak_ad, bak_tur, bak_yer), "not": (not_ad, not_yer, _karisik_harf(rng, not_ad)),
        "yedekler": yedekler, "yedek_adi": (onek, uzanti),
        "ceyrek": (yil, ceyrek, ceyrek_k, desen, ay_listesi),
        "fotolar": fotolar, "sahte": (sahte, rng.choice(SAHTE_TURLER)),
        "calisma": (calisma_k, yeni_ad),
        "access_log": loglar.metin(web_log),
        "metin": {
            "musteri": m["ad"], "sunucu": m["sunucu"], "kisi": m["kisi"], "web": web, "yedek_k": yedek_k,
            "rapor_k": rapor_k, "log_k": log_k, "foto_k": foto_k, "not_ad": not_ad,
            "onek": onek, "uzanti": uzanti, "yil": yil, "onceki_yil": yil - 1, "ceyrek_adi": ceyrek_adi,
            "aylar": aylar, "ceyrek_k": ceyrek_k, "desen": desen, "calisma_k": calisma_k, "yeni_ad": yeni_ad,
        },
        "cevaplar": {
            "bayrak": u.bayrak(rng, rng.choice(["kayip_dosya", "sakli_bahce", "unutulan_not", "kor_nokta"])),
            "parola": parola,
            "dizin_sayi": len(dizinler),
            "eski_sayi": eski,
            "soru_sayi": tek,
            "sahte": sahte,
        },
    }


def _jpeg(rng_baytlari: bytes) -> bytes:
    return (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            + rng_baytlari + b"\xff\xd9")


def _sahte_icerik(tur: str, m: dict) -> bytes:
    if tur == "zip":
        tampon = io.BytesIO()
        with zipfile.ZipFile(tampon, "w") as z:
            z.writestr("musteri_listesi.csv", f"ad,eposta\nornek,ornek@{m['alan']}\n")
        return tampon.getvalue()
    if tur == "gzip":
        return gzip.compress(f"-- {m['kod']} veritabanı dökümü\n".encode(), mtime=0)
    if tur == "pdf":
        return b"%PDF-1.4\n% Kalkan test belgesi\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n"
    return f"#!/bin/bash\n# {m['kod']} bakım betiği\necho \"bakim tamam\"\n".encode()


def yaz(lab: Path, s: dict) -> None:
    web, yedek_k, rapor_k, log_k, foto_k = s["duzen"]
    m = s["musteri"]
    c = s["cevaplar"]
    simdi = time.time()
    u.yaz(lab / "OKUBENI.txt", f"{m['ad']} — {m['sunucu']} sunucusunun taşınma öncesi kopyası.\n"
                               "Selin'den not: Neyin nerede olduğunu bilmeden hiçbir şeyi silme.\n")
    for d in s["dizinler"]:
        (lab / web / d).mkdir(parents=True, exist_ok=True)
    u.yaz(lab / web / "index.php", "<?php include 'includes/ust.php'; ?>\n")
    u.yaz(lab / web / "iletisim.php", "<?php // iletişim formu ?>\n")
    u.yaz(lab / web / ".htaccess", "Options -Indexes\n")
    for d in s["dizinler"][::2]:
        u.yaz(lab / web / d / "index.html", "<!-- boş -->\n")
    bak_ad, bak_tur, bak_yer = s["bak"]
    u.yaz(lab / web / bak_yer / bak_ad, BAK_ICERIK[bak_tur].format(kod=m["kod"], parola=c["parola"]))
    u.yaz(lab / web / bak_yer / bak_ad.replace(".bak", ""), "# güncel ayarlar ortam değişkenlerinden okunuyor\n")
    u.yaz(lab / web / s["dizinler"][0] / "index.php.old", "<?php echo 'eski sürüm'; ?>\n")
    not_ad, not_yer, not_gercek = s["not"]
    u.yaz(lab / web / not_yer / not_gercek,
          f"Eski yöneticinin notu: sunucu taşınırken unutma!\nKurtarma kodu: {c['bayrak']}\n")
    # Yedekler: mtime'lar şimdiye göre geriye kaydırılır
    for ad, gun_once in s["yedekler"].items():
        yol = u.yaz(lab / yedek_k / ad, f"{ad} yedek arşivi (laboratuvar kopyası)\n")
        t = simdi - gun_once * 86400
        os.utime(yol, (t, t))
    # Raporlar: iki yıl, her ay bir rapor
    yil = s["ceyrek"][0]
    for y in (yil - 1, yil):
        for ay in range(1, 13):
            u.yaz(lab / rapor_k / f"rapor_{y}-{ay:02d}.pdf", f"{m['ad']} aylık güvenlik raporu {y}-{ay:02d}\n")
    u.yaz(lab / rapor_k / "rapor_sablonu.docx", "şablon\n")
    u.yaz(lab / log_k / "access.log", s["access_log"])
    # Görseller: biri resim değil
    sahte, tur = s["sahte"]
    for i, ad in enumerate(s["fotolar"]):
        yol = lab / foto_k / ad
        yol.parent.mkdir(parents=True, exist_ok=True)
        if ad == sahte:
            yol.write_bytes(_sahte_icerik(tur, m))
        else:
            yol.write_bytes(_jpeg(bytes((i * 37 + k * 11) % 256 for k in range(200 + i * 30))))


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: bölümün find/joker/cp/mv/file komutlarıyla çözer."""
    from hy.motor.kontrol import Baglam
    v = s["metin"]
    bayrak = _sh(f"cat \"$(find . -iname '{v['not_ad']}')\" | grep -o 'FLAG{{[^}}]*}}'", lab)
    satir = _sh(f"cat $(find {v['web']} -name '*.bak') | grep -iE 'pass|parola'", lab)
    parola = re.split(r"[=:,]", satir)[-1].strip(" '\";)")
    dizin = _sh(f"find {v['web']} -mindepth 1 -type d | wc -l", lab)
    eski = _sh(f"find {v['yedek_k']} -type f -mtime +30 | wc -l", lab)
    soru = _sh(f"ls {v['yedek_k']}/{v['onek']}?{v['uzanti']} | wc -l", lab)
    _sh(f"mkdir {v['ceyrek_k']} && cp {v['rapor_k']}/rapor_{v['yil']}-{v['desen']}.pdf {v['ceyrek_k']}/", lab)
    _sh(f"mkdir {v['calisma_k']} && cp {v['log_k']}/access.log {v['calisma_k']}/ && "
        f"mv {v['calisma_k']}/access.log {v['calisma_k']}/{v['yeni_ad']}", lab)
    sahte = _sh(f"file {v['foto_k']}/*.jpg | grep -v 'JPEG image' | cut -d: -f1", lab)
    secmeli = SEVIYE.gorevler[8].kontrol.cevabi_goster(Baglam(s, lab, 9))[0]
    return {1: bayrak, 2: parola, 3: dizin, 4: eski, 5: soru, 6: "", 7: "", 8: sahte, 9: secmeli}


# ---------------------------------------------------------------- kontrol yardımcıları

def _ceyrek_kontrol(b) -> Sonuc:
    s, lab = b.senaryo, b.lab
    yil, _, ceyrek_k, _, aylar = s["ceyrek"]
    rapor_k = s["duzen"][2]
    hedef = lab / ceyrek_k
    if not hedef.is_dir():
        return Sonuc(False, f"Lab'ın kökünde `{ceyrek_k}` klasörü yok. Önce `mkdir {ceyrek_k}` ile oluştur "
                            "(lab'a dönmek için `lab`).")
    beklenen = {f"rapor_{yil}-{a:02d}.pdf" for a in aylar}
    var = {p.name for p in hedef.iterdir()}
    eksik_kaynak = [a for a in beklenen if not (lab / rapor_k / a).exists()]
    if eksik_kaynak:
        return Sonuc(False, f"`{rapor_k}` klasöründen {len(eksik_kaynak)} rapor eksilmiş: kopyalaman gerekiyordu, "
                            "taşımışsın (`mv`). Lab'ı `sifirla` ile tazeleyip `cp` ile dene.", yakin=True)
    fazla = sorted(var - beklenen)
    eksik = sorted(beklenen - var)
    if fazla:
        baska_yil = [f for f in fazla if f.startswith(f"rapor_{yil - 1}")]
        if baska_yil:
            return Sonuc(False, f"Fazladan {yil - 1} raporları da gelmiş ({len(baska_yil)} dosya). Desende yılı "
                                f"sabit yaz: `rapor_{yil}-...`. Fazlaları `rm` ile sil.", yakin=True)
        return Sonuc(False, "Klasörde fazladan dosyalar var: " + ", ".join(fazla[:4])
                     + ". Sadece istenen üç ayın raporu olmalı; fazlaları `rm` ile sil.", yakin=True)
    if eksik:
        return Sonuc(False, "Eksik raporlar var: " + ", ".join(eksik) + ". Köşeli parantez `[...]` ile üç ayı "
                            "birden seçebilirsin.", yakin=True)
    return Sonuc(True, f"Üç rapor `{ceyrek_k}` içinde, asılları da yerinde. `[...]` joker karakteri tam olarak "
                       "bunun için var.")


def _calisma_kontrol(b) -> Sonuc:
    s, lab = b.senaryo, b.lab
    calisma_k, yeni_ad = s["calisma"]
    log_k = s["duzen"][3]
    kaynak = lab / log_k / "access.log"
    klasor = lab / calisma_k
    if not kaynak.exists():
        return Sonuc(False, f"Orijinal `{log_k}/access.log` yerinde değil: taşımak değil, kopyalamak gerekiyordu. "
                            "`sifirla` ile lab'ı tazeleyip tekrar dene.", yakin=True)
    if not klasor.is_dir():
        return Sonuc(False, f"Lab'ın kökünde `{calisma_k}` klasörü yok. `mkdir {calisma_k}` ile başla.")
    hedef = klasor / yeni_ad
    if not hedef.exists():
        if (klasor / "access.log").exists():
            return Sonuc(False, f"Kopya yerinde ama adı hâlâ `access.log`. `mv` ile adını `{yeni_ad}` yap.", yakin=True)
        return Sonuc(False, f"`{calisma_k}/{yeni_ad}` bulunamadı. Önce `cp`, sonra `mv` ile yeniden adlandır.")
    if hedef.read_bytes() != kaynak.read_bytes():
        return Sonuc(False, f"`{yeni_ad}` var ama içeriği `access.log` ile aynı değil. Elle mi oluşturdun? `cp` kullan.",
                     yakin=True)
    return Sonuc(True, "Kopya hazır, orijinal yerinde. Analizi hep kopya üzerinde yapmak, kanıtı korumanın ilk kuralıdır.")


def _eski_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    toplam = len(b.senaryo["yedekler"])
    if n == toplam - beklenen:
        return "İşaret ters: `-mtime -30` '30 günden yeni', `-mtime +30` '30 günden eski' demektir."
    if n == toplam:
        return "Bu klasördeki bütün dosyalar. `find`'a bir zaman koşulu ekle."
    if n == toplam + 1 or n == beklenen + 1:
        return "Klasörün kendisini de saymış olabilirsin; `-type f` ekle."
    return None


def _soru_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    onek, uzanti = b.senaryo["yedek_adi"]
    hepsi = sum(1 for ad in b.senaryo["yedekler"] if ad.startswith(onek) and ad.endswith(uzanti))
    if n == hepsi:
        return "`*` kullanmış olabilirsin: o 'herhangi bir şey' demek. `?` ise tam olarak tek karakter eşler."
    if n == len(b.senaryo["yedekler"]):
        return "Klasördeki bütün dosyaları saydın. Sadece desene uyanları say."
    return None


def _dizin_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "`find` başlangıç klasörünün kendisini de listeler. Soruda o hariç tutuluyor."
    return None


def _parola_hata(g, beklenen, b):
    if g.startswith(("db_pass", "db_password", "$db_parola", "parola", "define")):
        return "Satırın tamamını değil, sadece parolanın kendisini yaz (eşittir ya da tırnak sonrası)."
    return None


ADIMLAR = [
    Adim("Okumak: head ve tail", """
`cat` dosyanın tamamını basar; büyük dosyalarda boğulursun. Kısımlarını okumak için:

- `head dosya` ilk 10 satır, `head -n 3 dosya` ilk 3 satır
- `tail dosya` son 10 satır, `tail -f dosya` dosyayı **canlı** izler (yeni satır geldikçe basar)
- `less dosya` sayfa sayfa okur: `q` çıkış, `/kelime` arama
""", komut="head -n 3 <<log_k>>/access.log", sonra="""
`tail -f` savunmacının en iyi arkadaşıdır: bir saldırıyı canlı izlerken log dosyasını böyle
takip edersin (Ctrl+C ile çıkılır).
"""),
    Adim("Oluşturmak: mkdir ve touch", """
`touch dosya` boş bir dosya oluşturur (varsa sadece tarihini günceller). `mkdir klasor` bir
klasör açar; `mkdir -p a/b/c` iç içe klasörleri tek seferde oluşturur. Üçünü birlikte dene:
""", komut="mkdir -p deneme/a/b && touch deneme/a/b/not.txt && ls -R deneme"),
    Adim("Kopyalamak, taşımak, yeniden adlandırmak", """
- `cp kaynak hedef` kopyalar; `cp -r klasor/ yedek/` klasörü içiyle kopyalar.
- `mv eski yeni` yeniden adlandırır; `mv dosya klasor/` taşır. Linux'ta ikisi aynı komuttur.
""", komut="cp OKUBENI.txt deneme/ && mv deneme/OKUBENI.txt deneme/kopya.txt && ls deneme"),
    Adim("Silmek: geri dönüşü yok", """
`rm dosya` siler, `rm -r klasor` klasörü içiyle siler, `rmdir` sadece boş klasörü siler.
**Linux'ta çöp kutusu yoktur.** `rm -rf`'deki `-f` "sorma, zorla" demektir; yanlış klasörde
çalışan bir `rm -rf` günlerin emeğini saniyede götürür. Emin değilsen önce `ls` ile neyi
sileceğine bak.
""", komut="rm -r deneme && ls"),
    Adim("Joker karakterler", """
Joker karakterler birden çok dosyayı tek seferde seçer:

- `*` herhangi bir şey (hiç dahil): `*.log` bütün log dosyaları
- `?` **tam olarak tek** karakter: `yedek_?.tar` → `yedek_1.tar` ... `yedek_9.tar` (ama `yedek_10.tar` değil)
- `[...]` parantezdeki karakterlerden biri: `yedek_[2-4].tar` → 2, 3 ve 4

<<onceki_yil>> yılının bütün raporlarını yıldızla listele:
""", komut="ls <<rapor_k>>/rapor_<<onceki_yil>>-*"),
    Adim("Dosyanın gerçek türü: file", """
Linux dosya uzantısına güvenmez, dosyanın içine bakar; sen de güvenme. `file` dosyanın
başındaki **sihirli baytlara** (her dosya türünün imzası) bakarak gerçek türü söyler.
""", komut="file OKUBENI.txt /bin/ls", sonra="""
**Hacker gözüyle:** CTF'lerde ve gerçek olaylarda adı `resim.jpg` olan ama aslında bir arşiv
ya da program olan dosyalarla sık karşılaşırsın. Zararlı yazılımlar da kendilerini masum
uzantılarla gizler.
"""),
    Adim("find: hacker'ın dedektifi", """
`find` dosya sisteminde neredeyse her ölçüte göre arar. Kalıbı: `find NEREDE KOŞUL`.

- `-name "*.log"` adına göre, `-iname "okubeni*"` büyük-küçük harf duyarsız
- `-type d` sadece klasörler, `-type f` sadece dosyalar
- `-size +1k` 1 KB'tan büyükler
""", komut="find . -name \"*.log\""),
    Adim("find: zamana göre ve -exec", """
- `-mtime -1` son 1 günde değişenler, `-mtime +30` 30 günden eski olanlar
- `-exec ls -l {} \\;` bulduğu her dosyada komut çalıştırır (`{}` dosyanın yerine geçer)
- `find / -name "*.bak" 2>/dev/null` bütün sistemde arar; `2>/dev/null` erişim izni olmayan
  klasörlerin hata mesajlarını gizler (Bölüm 4'te açacağız)

Son bir günde değişen log dosyalarını bul:
""", komut="find . -mtime -1 -name \"*.log\"", sonra="""
**Hacker gözüyle:** Gerçek keşifte en sık aranan şeyler: yedek ve yapılandırma dosyaları
(`*.bak`, `*.old`, `*.conf`, `*.env`), SSH anahtarları (`id_rsa`), veritabanı dosyaları
(`*.sqlite`, `*.db`) ve yakın zamanda değişen dosyalar. Savunmacı aynı `-mtime` aramasını
"saldırgan son 24 saatte neye dokundu?" sorusu için kullanır.
"""),
]

GOREVLER = [
    Gorev("Eski yönetici `<<not_ad>>` adında bir not bırakmış ama adını nasıl yazdığını kimse "
          "hatırlamıyor (büyük-küçük harfler karışık olabilir); lab'ın neresinde olduğu da belli "
          "değil. Bul ve içindeki kurtarma kodunu (bayrak) gönder.",
          Bayrak("bayrak"),
          ("Nerede olduğunu bilmediğin bir dosyayı aramanın aracı `find`. Harf sorunu için de bir seçeneği var.",
           "`-name` büyük-küçük harfe duyarlıdır; `-iname` değildir. Lab'ın kökünden (`.`) ara.",
           "`find . -iname \"<<not_ad>>\"` ile yolu bul, sonra o yolu `cat` ile oku."),
          puan=30, baslik="Kayıp not"),
    Gorev("`<<web>>` klasörünün derinliklerinde adı `.bak` ile biten bir yedek var. Bul ve içindeki "
          "**veritabanı parolasını** yaz.",
          Metin("parola", bicim="parola", sik_hatalar=_parola_hata),
          ("Uzantıya göre arama yapacaksın.",
           "`find <<web>> -name \"*.bak\"` dosyanın yolunu verir.",
           "Bulduğun yolu `cat` ile oku; parola `PASS`, `PASSWORD` ya da `parola` geçen satırda."),
          puan=35, baslik="Unutulan yedek"),
    Gorev("`<<web>>` klasörünün içinde (kendisi hariç, alt klasörler dahil) kaç klasör var?",
          Sayi("dizin_sayi", sik_hatalar=_dizin_hata),
          ("Sadece klasörleri listeleyen bir `find` koşulu var.",
           "`find <<web>> -type d` hepsini listeler; ilk satır `<<web>>`'in kendisi.",
           "`find <<web>> -type d | wc -l` ve çıkan sayıdan 1 çıkar (ya da `-mindepth 1` ekle)."),
          puan=25, baslik="Klasör sayımı"),
    Gorev("`<<yedek_k>>` klasöründe **30 günden eski** kaç dosya var?",
          Sayi("eski_sayi", sik_hatalar=_eski_hata),
          ("`ls -l` tarihleri gösterir ama saymak zor. `find`'ın zaman koşulunu hatırla.",
           "`-mtime +30` 30 günden eski demek. Sadece dosyaları say: `-type f`.",
           "`find <<yedek_k>> -type f -mtime +30 | wc -l`"),
          puan=30, baslik="Eski yedekler"),
    Gorev("`ls <<yedek_k>>/<<onek>>?<<uzanti>>` komutu kaç dosya listeler?",
          Sayi("soru_sayi", sik_hatalar=_soru_hata),
          ("`?` joker karakterinin tam olarak kaç karakter eşlediğini düşün.",
           "`?` tek bir karakterdir: tek haneli numaralar eşleşir, iki haneliler ve `.md5` uzantılılar eşleşmez.",
           "Komutu çalıştır ve satırları say: `ls <<yedek_k>>/<<onek>>?<<uzanti>> | wc -l`"),
          puan=25, baslik="Soru işareti"),
    Gorev("<<kisi>> sadece <<yil>> yılının **<<ceyrek_adi>>** raporlarını (<<aylar>>) istiyor. Lab'ın "
          "kökünde `<<ceyrek_k>>` adlı bir klasör oluştur ve bu üç raporu oraya **kopyala** "
          "(asılları `<<rapor_k>>` içinde kalsın). Bitince `cevap 6` yaz.",
          _Durum(_ceyrek_kontrol, "mkdir <<ceyrek_k>> && cp <<rapor_k>>/rapor_<<yil>>-<<desen>>.pdf <<ceyrek_k>>/"),
          ("Önce klasörü oluştur, sonra üç dosyayı tek komutla seç. Hangi joker karakter 'şu karakterlerden biri' demek?",
           "`mkdir <<ceyrek_k>>`, ardından `cp` ile `[...]` jokerini kullan. Yılı desende sabit yaz.",
           "`cp <<rapor_k>>/rapor_<<yil>>-<<desen>>.pdf <<ceyrek_k>>/` (köşeli parantez aralığı aylara karşılık geliyor)."),
          puan=35, baslik="Çeyrek raporları"),
    Gorev("Lab'ın kökünde `<<calisma_k>>` adında bir klasör oluştur, `<<log_k>>/access.log` dosyasını "
          "oraya **kopyala** ve kopyanın adını `<<yeni_ad>>` yap. Bitince `cevap 7` yaz.",
          _Durum(_calisma_kontrol, "mkdir <<calisma_k>> && cp <<log_k>>/access.log <<calisma_k>>/ && "
                                   "mv <<calisma_k>>/access.log <<calisma_k>>/<<yeni_ad>>"),
          ("Üç ayrı iş var: klasör oluşturmak, kopyalamak, yeniden adlandırmak.",
           "`mkdir`, `cp` ve `mv`. Linux'ta yeniden adlandırma da `mv` ile yapılır.",
           "`mkdir <<calisma_k>>`, `cp <<log_k>>/access.log <<calisma_k>>/`, sonra `mv <<calisma_k>>/access.log <<calisma_k>>/<<yeni_ad>>`"),
          puan=30, baslik="Çalışma kopyası"),
    Gorev("`<<foto_k>>` klasöründeki `.jpg` dosyalarından biri aslında resim değil. Hangisi?",
          Metin("sahte", sadece_ad=True, bicim="dosya adı"),
          ("Uzantıya güvenme; dosyanın içine bakan bir komut var.",
           "`file <<foto_k>>/*.jpg` her dosyanın gerçek türünü yazar.",
           "Çıktıda 'JPEG image data' yazmayan satıra bak: `file <<foto_k>>/*.jpg | grep -v JPEG`"),
          puan=30, baslik="Kılık değiştirmiş dosya"),
    Gorev("Bulduğun `.bak` dosyası canlı sunucuda da web kökünde duruyor olsaydı, neden tehlikeli olurdu?",
          Secmeli([
              ("Sunucu .php'yi çalıştırıp çıktısını verir ama .bak'ı düz metin olarak indirtir",
               "Doğru. `config.php` istenince sunucu kodu çalıştırır, parolayı göstermez. `config.php.bak` ise "
               "tanınmayan bir uzantı olduğu için olduğu gibi indirilir; içindeki parola herkesin olur."),
              ("Yedek dosyaları diskte çok yer kaplar ve zamanla sunucuyu yavaşlatıp çökertir",
               "Küçük bir metin dosyası diski doldurmaz. Asıl sorun içindeki bilginin herkese açık olması."),
              ("Tarayıcılar .bak dosyasını açarken içindeki kodu ziyaretçinin bilgisayarında çalıştırır",
               "Tarayıcı .bak dosyasını çalıştırmaz, indirir. Tehlike ziyaretçiye değil, sitenin sırlarına."),
              ("Sunucu .bak dosyalarını sadece yöneticiye gösterir, o yüzden aslında bir risk yoktur",
               "Web sunucusu dosyayı isteyen herkese verir; yönetici ayrımı yapmaz. Nikto gibi tarayıcılar tam olarak bunları arar."),
          ]),
          ("Web sunucusu `.php` ile biten bir dosyayı istendiğinde ne yapar? Peki tanımadığı bir uzantıyı?",
           "`.php` çalıştırılır, çıktısı gönderilir. `.bak` ise sunucunun bildiği bir tür değil.",
           "Tanınmayan uzantı düz dosya olarak indirilir: içindeki parola okunur."),
          puan=20, baslik="Neden tehlikeli"),
]


SEVIYE = Seviye(
    kimlik="c01b03",
    cilt=1,
    bolum=3,
    baslik="Dosyalarla Çalışmak",
    brifing="""
**<<musteri>>** sunucusu **<<sunucu>>**'yu yeni bir veri merkezine taşıyor. <<kisi>>, taşımadan
önce eski sunucuda ne var ne yok bilmek istiyor: hangi yedekler eski, hangi raporlar nerede,
unutulmuş bir şey var mı?

Selin kopyayı laboratuvarına koydu: "Keşfin büyük kısmı dosya avıdır. `find` senin
dedektifin. Bir de dikkat: analizini hep **kopya** üzerinde yap, asıllarına dokunma."

Mert ekliyor: "Web klasörüne iyi bak. Taşınan her sunucuda birinin unuttuğu bir `.bak`
çıkar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bir sisteme girdiğinde ilk sorulardan biri "burada ilginç ne var?" sorusudur ve cevabı
`find` verir: `*.bak`, `*.old`, `*.env`, `id_rsa`, son günlerde değişen dosyalar. Saldırgan
bunları parola ve anahtar için arar; savunmacı aynı aramayı "saldırgan neye dokundu?" diye
yapar. Ders iki yönlü: web kökünde yedek bırakılmaz, uzantıya güvenilmez (`file`) ve analiz
her zaman kanıtın **kopyası** üzerinde yapılır.
""",
    gercek_hayat="""
- **Unutulan yedek ve yapılandırma dosyaları:** Sızma testi raporlarında web kökünde kalmış
  `.bak`, `.old`, `.zip` yedekleri ve erişilebilir `.git` klasörleri çok sık görülen
  bulgulardır. Nikto gibi tarayıcılar bu dosya adlarını özellikle dener; açık bir `.git`
  klasöründen sitenin kaynak kodunun tamamı geri çıkarılabilir.
- **GitLab, 2017:** GitLab.com'da bir mühendis, yoğun bir gecede `rm -rf` komutunu yanlış
  sunucuda çalıştırarak üretim veritabanının verilerini sildi; birkaç yedekleme yönteminin
  de çalışmadığı ortaya çıktı ve saatlerce veri kaybedildi. Şirket olayı herkese açık
  biçimde raporladı. "Linux'ta çöp kutusu yok" uyarısının en bilinen örneklerinden biri.
""",
    sure_hedef_dk=30,
)
