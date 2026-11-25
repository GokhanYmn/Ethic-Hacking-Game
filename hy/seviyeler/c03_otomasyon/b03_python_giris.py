"""Cilt 3 · Bölüm 3 — Python'a Hacker Girişi.

Beceri: sys.argv ve kullanım mesajı, int() + try/except, sözlük (dict) ile eşleme ve sayma,
dosyayı satır satır okuma, strip() ve boş satırlar, split() ile alan seçmek.

Oyuncu üç küçük Python betiği yazar: hedef.py (argüman + doğrulama), servis.py (port ->
servis sözlüğü) ve say.py (bir log/veri dosyasındaki anahtarları sayan araç). Vakaya göre
veri dosyası değişir: web erişim logu (durum kodu), güvenlik duvarı logu (hedef port),
uygulama logu (log seviyesi) ya da CSV sorgu kaydı (sorgu sonucu). Oyun say.py'yi hem lab
dosyasında hem de her seferinde yeniden üretilen bir dosyada çalıştırıp sayımları karşılaştırır.
"""
from __future__ import annotations

import os
import random
import re
import subprocess
import tempfile
from collections import Counter
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Metin, Sayi, Secmeli, Sonuc, norm
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

# Ek B'deki sık kullanılan portlar tablosu
PORTLAR = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB",
           3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt"}


# ---------------------------------------------------------------- vaka veri üreteçleri

def _pazarix_satir(rng, anahtar, t, m):
    kod = int(anahtar)
    yollar = {200: m["normal_sayfalar"] + ["/sepet.php", "/urun.php?id=" + str(rng.randint(100, 999))],
              304: ["/css/site.css", "/js/sepet.js", "/img/logo.png"],
              301: ["/kampanya", "/indirim", "/blog"], 302: ["/sepet.php?adim=odeme", "/giris"],
              404: ["/wp-login.php", "/eski-kampanya.php", "/favicon.ico", "/.env", "/phpmyadmin/"],
              403: ["/admin/", "/.git/config", "/yedek/"], 500: ["/odeme/onay.php", "/api/stok"]}
    yol = rng.choice(yollar.get(kod, ["/odeme/onay.php", "/api/kargo-durum", "/sepet.php?adim=odeme"]))
    metod = "POST" if "odeme" in yol and rng.random() < 0.5 else "GET"
    boyut = rng.randint(180, 25000) if kod in (200, 500) else rng.randint(0, 600)
    ua = rng.choice(u.TARAYICI_UA)
    return u.apache_satiri(u.dis_ip(rng) if rng.random() < 0.3 else u.ic_ip(rng, "10.0.12"), t, metod, yol,
                           kod, boyut, ua)


def _kuzgun_satir(rng, anahtar, t, m):
    return (f"{u.syslog_zamani(t)} kzg-fw kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"MAC=52:54:00:{rng.randint(16, 255):02x}:{rng.randint(16, 255):02x}:3c:00:16:3e "
            f"SRC={u.dis_ip(rng)} DST=10.30.8.{rng.randint(2, 60)} LEN={rng.choice([40, 44, 52, 60])} TOS=0x00 "
            f"PREC=0x00 TTL={rng.randint(40, 250)} ID={rng.randint(1000, 65000)} DF PROTO=TCP "
            f"SPT={rng.randint(1025, 65000)} DPT={anahtar} WINDOW={rng.choice([1024, 29200, 64240])} RES=0x00 "
            "SYN URGP=0")


def _medora_satir(rng, anahtar, t, m):
    mesajlar = {
        "INFO": ["randevu olusturuldu id={n}", "hasta girisi basarili hasta={n}", "doktor takvimi guncellendi"],
        "WARN": ["yavas sorgu sure={n}ms", "oturum suresi doldu hasta={n}", "tekrarlanan randevu istegi"],
        "ERROR": ["veritabani baglantisi koptu", "sms servisi yanit vermedi", "randevu kaydi yazilamadi id={n}"],
        "DEBUG": ["onbellek isabeti anahtar=takvim_{n}", "istek basliklari okundu", "sorgu planı hazir"],
    }
    mesaj = rng.choice(mesajlar.get(anahtar, ["randevu id={n} baska hastanin oturumunda goruntulendi"]))
    return f"{t:%Y-%m-%d %H:%M:%S} [{anahtar}] randevu-api: {mesaj.format(n=rng.randint(10000, 99999))}"


def _yesiltepe_satir(rng, anahtar, t, m):
    return (f"{t:%Y-%m-%d %H:%M:%S};sicil={rng.randint(100000, 999999)};sonuc={anahtar};"
            f"ip={u.ic_ip(rng, '192.168.40') if rng.random() < 0.2 else u.dis_ip(rng)}")


VAKALAR = [
    {
        "kod": "pazarix", "dosya": "erisim.log", "uret": _pazarix_satir, "anahtar_ad": "HTTP durum kodu",
        "anahtarlar": {"200": 60, "304": 12, "301": 4, "302": 5, "404": 9, "403": 3, "500": 2},
        "nadir": ["405", "429", "502", "503"],
        "ayiklama": "Durum kodu satırın 9. alanıdır: `satir.split()[8]`",
        "ornek_ifade": "satir.split()[8]", "ayikla_kod": "satir.split()[8]", "on_ekler": (),
        "olay": "Kampanya haftasında sipariş sayfası yavaşladı. Tuncay Bey hangi durum kodundan kaç tane "
                "olduğunu her saat soruyor ve ekip bunu Excel'de elle sayıyor.",
    },
    {
        "kod": "kuzgun", "dosya": "fw_drop.log", "uret": _kuzgun_satir, "anahtar_ad": "hedef port (DPT)",
        "anahtarlar": {"22": 30, "23": 14, "445": 12, "3389": 10, "80": 8, "443": 6, "3306": 5, "8080": 7},
        "nadir": ["5900", "6379", "9200", "27017"],
        "ayiklama": "Hedef port 21. alandır (`satir.split()[20]`) ve `DPT=22` biçimindedir; `DPT=` kısmını at",
        "ornek_ifade": "satir.split()[20]", "ayikla_kod": "satir.split()[20][4:]", "on_ekler": ("dpt=",),
        "olay": "Depo güvenlik duvarı gece boyunca binlerce bağlantıyı engelliyor. Serdar Bey hangi "
                "portlara en çok saldırıldığını görmek istiyor ama logu elle okumak imkânsız.",
    },
    {
        "kod": "medora", "dosya": "randevu_api.log", "uret": _medora_satir, "anahtar_ad": "log seviyesi",
        "anahtarlar": {"INFO": 55, "WARN": 15, "ERROR": 8, "DEBUG": 22},
        "nadir": ["CRITICAL", "FATAL", "ALERT"],
        "ayiklama": "Log seviyesi 3. alandır ve köşeli parantez içindedir: `[ERROR]` → `ERROR`",
        "ornek_ifade": "satir.split()[2]", "ayikla_kod": 'satir.split()[2].strip("[]")', "on_ekler": (),
        "olay": "Bir hasta, randevu sayfasında başka birinin bilgilerini gördüğünü bildirdi. Dr. Aslı Hanım "
                "randevu servisinin logunda hangi seviyeden kaç kayıt olduğunu ve sıra dışı bir kayıt olup "
                "olmadığını soruyor.",
    },
    {
        "kod": "yesiltepe", "dosya": "borc_sorgu.csv", "uret": _yesiltepe_satir, "anahtar_ad": "sorgu sonucu",
        "anahtarlar": {"BASARILI": 50, "BULUNAMADI": 18, "HATALI_SICIL": 12, "ZAMAN_ASIMI": 9},
        "nadir": ["YETKISIZ", "SISTEM_HATASI", "COKLU_KAYIT"],
        "ayiklama": "Alanlar `;` ile ayrılır, sonuç 3. alandır: `sonuc=BASARILI` → `BASARILI`",
        "ornek_ifade": 'satir.strip().split(";")[2]', "ayikla_kod": 'satir.split(";")[2].split("=")[1]',
        "on_ekler": ("sonuc=",),
        "olay": "Borç sorgulama sayfası geçen hafta çöktü. Nurcan Hanım o haftanın sorgu kaydında hangi "
                "sonuçtan kaç tane olduğunu ve tuhaf bir sonuç olup olmadığını öğrenmek istiyor.",
    },
]


def _vaka(kod: str) -> dict:
    return next(v for v in VAKALAR if v["kod"] == kod)


def _dagilim(rng, v: dict, toplam: int, nadir: str) -> Counter:
    agirlik = {k: w * rng.uniform(0.6, 1.4) for k, w in v["anahtarlar"].items()}
    tw = sum(agirlik.values())
    sayim = Counter({k: max(2, int(toplam * w / tw)) for k, w in agirlik.items()})
    sayim[nadir] = 1
    return sayim


def _satirlar(rng, v: dict, sayim: Counter, m: dict, bos: int = 2) -> list:
    anahtarlar = [k for k, n in sayim.items() for _ in range(n)]
    rng.shuffle(anahtarlar)
    t = u.gun(rng) + timedelta(hours=rng.randint(0, 6))
    satirlar = []
    for k in anahtarlar:
        t += timedelta(seconds=rng.randint(1, 40))
        satirlar.append(v["uret"](rng, k, t, m))
    for _ in range(bos):   # boş satırlar: strip() ve atlama dersi
        satirlar.insert(rng.randint(5, len(satirlar) - 5), "")
    return satirlar


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    nadir = rng.choice(v["nadir"])
    sayim = _dagilim(rng, v, rng.randint(1500, 2400), nadir)
    ortalar = sorted(v["anahtarlar"], key=lambda k: sayim[k])[1:-1]
    sorulan = rng.choice(ortalar)
    ip = u.ic_ip(rng)
    return {
        "vaka": f"{m['ad']} — {v['dosya']} içinde {v['anahtar_ad']} sayımı",
        "musteri": m,
        "kod": v["kod"],
        "sayim": dict(sayim),
        "veri_tohum": rng.randint(1, 10**9),
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "dosya": v["dosya"],
            "anahtar_ad": v["anahtar_ad"], "ayiklama": v["ayiklama"], "ornek_ifade": v["ornek_ifade"],
            "ayikla_kod": v["ayikla_kod"], "sorulan": sorulan, "alan": m["alan"], "ip": ip,
        },
        "cevaplar": {
            "sorulan_sayi": sayim[sorulan],
            "nadir": nadir,
        },
    }


ILK_PY = '''#!/usr/bin/env python3
import sys

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <hedef>")
    sys.exit(1)

hedef = sys.argv[1]
print(f"[*] Hedef: {hedef}")
print(f"[*] sys.argv tamamı: {sys.argv}")
print(f"[*] Argüman sayısı (betik adı hariç): {len(sys.argv) - 1}")
'''

KELIME_SAY_PY = '''#!/usr/bin/env python3
# kelime_say.py — bir dosyadaki kelimeleri sözlükle sayar
import sys

sayac = {}
with open(sys.argv[1], encoding="utf-8") as f:
    for satir in f:
        satir = satir.strip()          # sondaki görünmez \\n karakterini at
        if not satir:                  # boş satırı atla
            continue
        sayac[satir] = sayac.get(satir, 0) + 1

for kelime, adet in sayac.items():
    print(kelime, adet)
'''

SAYIYA_CEVIR_PY = '''#!/usr/bin/env python3
# sayiya_cevir.py — her argümanı sayıya çevirmeyi dener, çökmeden devam eder
import sys

for arg in sys.argv[1:]:
    try:
        port = int(arg)
        print(f"[+] {port} geçerli bir sayı")
    except ValueError:
        print(f"[-] '{arg}' sayı değil, atlıyorum")
'''

HEDEF_PY = '''#!/usr/bin/env python3
import sys

if len(sys.argv) < 3:
    print(f"Kullanım: {sys.argv[0]} <ip> <port>")
    sys.exit(1)

ip = sys.argv[1]
try:
    port = int(sys.argv[2])
except ValueError:
    print(f"Hata: port bir sayı olmalı, '{sys.argv[2]}' değil.")
    sys.exit(1)

print(f"IP: {ip}, Port: {port}")
'''

SERVIS_PY = '''#!/usr/bin/env python3
import sys

servisler = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
             445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt"}

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <port>")
    sys.exit(1)

try:
    port = int(sys.argv[1])
except ValueError:
    print("Hata: port bir sayı olmalı.")
    sys.exit(1)

print(f"{port}: {servisler.get(port, 'bilinmeyen servis')}")
'''

SAY_PY = '''#!/usr/bin/env python3
import sys

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <dosya>")
    sys.exit(1)

try:
    f = open(sys.argv[1], encoding="utf-8")
except FileNotFoundError:
    print(f"Hata: {sys.argv[1]} bulunamadı.")
    sys.exit(1)

sayac = {}
with f:
    for satir in f:
        satir = satir.strip()
        if not satir:
            continue
        anahtar = <<AYIKLA>>
        sayac[anahtar] = sayac.get(anahtar, 0) + 1

for anahtar, adet in sorted(sayac.items(), key=lambda x: -x[1]):
    print(anahtar, adet)
'''


def yaz(lab: Path, s: dict) -> None:
    v = _vaka(s["kod"])
    rng = random.Random(s["veri_tohum"])
    satirlar = _satirlar(rng, v, Counter(s["sayim"]), s["musteri"])
    u.yaz(lab / v["dosya"], "\n".join(satirlar) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['dosya']}\n\n"
          f"Sayılacak anahtar: {v['anahtar_ad']}\n"
          f"{v['ayiklama'].replace('`', '')}\n"
          "Dikkat: dosyada boş satırlar var.\n\n"
          "Kendi betiklerini lab'ın köküne yaz: hedef.py, servis.py, say.py\n"
          "Çalıştırmak için: python3 say.py " + v["dosya"] + "\n")
    u.yaz(lab / "ornekler" / "ilk.py", ILK_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "kelime_say.py", KELIME_SAY_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "sayiya_cevir.py", SAYIYA_CEVIR_PY, mod=0o755)
    kelimeler = ["admin", "root", "admin", "test", "", "root", "admin", "guest", "test", "admin"]
    u.yaz(lab / "ornekler" / "kullanicilar.txt", "\n".join(kelimeler) + "\n")


# ---------------------------------------------------------------- denetimler

def _yakin(mesaj: str) -> Sonuc:
    return Sonuc(False, mesaj, yakin=True)


def _hedef_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    for args in ((), ("10.0.0.5",)):
        hata = bt.kullanim_denetle(calistir, *args)
        if hata:
            return _yakin(hata)
    c = calistir("10.0.0.5", "abc")
    nasil = calistir.goster("10.0.0.5", "abc")
    if "Traceback" in c.stderr:
        return _yakin(f"`{nasil}` çalıştırınca betiğin çöktü (Traceback). Port sayı değilse `int()` ValueError "
                      "fırlatır; `try: ... except ValueError:` ile yakala, bir hata mesajı yaz ve `sys.exit(1)`.")
    cokme = calistir.cokme(c)
    if c.zaman_asimi or c.hata:
        return Sonuc(False, cokme or "Betik çalışmadı.")
    if c.kod == 0:
        return _yakin(f"`{nasil}` hatasız (0 koduyla) bitti; ama \"abc\" bir port değil. Sayıya çevrilemezse hata "
                      "mesajı yazıp `sys.exit(1)` ile çık." + bt.ozet(c))
    ip = b.senaryo["metin"]["ip"]
    port = random.randint(1, 65535)
    c = calistir(ip, port)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{calistir.goster(ip, port)}` çalışırken: {cokme}")
    cikti = norm(c.stdout)
    if not re.search(r"ip:\s*" + re.escape(ip) + r"\b", cikti) or not re.search(rf"port:\s*{port}\b", cikti):
        return Sonuc(False, f"`{calistir.goster(ip, port)}` çalıştırınca `IP: {ip}, Port: {port}` satırını "
                     "bekliyordum." + bt.ozet(c))
    if c.kod != 0:
        return _yakin(f"Doğru satırı yazdın ama çıkış kodu {c.kod}; başarılı çalışma 0 ile bitmeli.")
    return Sonuc(True, "hedef.py hem eksik argümanı hem sayı olmayan portu çökmeden yakalıyor. `try/except`, ağ "
                       "araçlarında hayat kurtarır: binlerce hedeften biri hata verince araç durmamalı.")


def _servis_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return _yakin(hata)
    rng = random.Random()
    denenecek = rng.sample(sorted(PORTLAR), 4) + [rng.choice([7, 111, 1234, 5432, 6667, 9999])]
    for port in denenecek:
        c = calistir(port)
        nasil = calistir.goster(port)
        cokme = calistir.cokme(c)
        if cokme:
            if "KeyError" in c.stderr:
                return _yakin(f"`{nasil}` çalıştırınca KeyError ile çöktü: sözlükte olmayan anahtara `[]` ile "
                              "erişilince Python hata fırlatır. `servisler.get(port, 'bilinmeyen servis')` kullan.")
            return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
        cikti = norm(c.stdout)
        if port in PORTLAR:
            ad = PORTLAR[port]
            istenen = norm(ad.split("-")[0])
            if istenen not in cikti:
                if "bilinmeyen" in cikti:
                    return _yakin(f"`{nasil}` için \"{ad}\" bekliyordum ama \"bilinmeyen\" dedin. Sözlük anahtarları "
                                  "sayı mı? `sys.argv` her zaman metin (str) verir; `int()` ile çevirmeden "
                                  "`servisler[\"22\"]` ile `servisler[22]` farklı anahtarlardır.")
                return Sonuc(False, f"`{nasil}` için \"{ad}\" bekliyordum (Ek B'deki port tablosu)." + bt.ozet(c))
        elif "bilinmeyen" not in cikti:
            return _yakin(f"`{nasil}`: {port} tabloda yok; \"bilinmeyen servis\" yazmalıydın." + bt.ozet(c))
    return Sonuc(True, "servis.py çalışıyor. Bir sonraki bölümde port tarayıcın bu sözlüğü kullanacak: açık "
                       "bulduğu portun yanına servis adını yazacak.")


def _anahtar_norm(k: str, on_ekler: tuple) -> str:
    k = norm(k).strip("[]")
    for on in on_ekler:
        if k.startswith(on):
            k = k[len(on):]
    return k


def _sayimlar(c: bt.Cikti, on_ekler: tuple, ters: bool = False) -> dict:
    sonuc = {}
    for satir in c.stdout.splitlines():
        parca = [p for p in re.split(r"[\s:,|]+", satir.strip()) if p]
        if len(parca) != 2:
            continue
        a, b = parca
        if ters:
            a, b = b, a
        if b.isdigit():
            anahtar, adet = a, int(b)
        elif a.isdigit():
            anahtar, adet = b, int(a)
        else:
            continue
        sonuc[_anahtar_norm(anahtar, on_ekler)] = adet
    return sonuc


def _say_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    v = _vaka(s["kod"])
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return _yakin(hata)
    olmayan = str(Path(tempfile.gettempdir()) / f"hy_yok_{random.randint(1000, 9999)}.log")
    c = calistir(olmayan)
    if "Traceback" in c.stderr:
        return _yakin("Olmayan bir dosya verdiğimde betiğin çöktü (FileNotFoundError). Dosyayı açmayı `try: ... "
                      "except FileNotFoundError:` içine al; hata mesajı yazıp `sys.exit(1)` ile çık.")
    if c.kod == 0:
        return _yakin("Olmayan bir dosya verdiğimde betiğin 0 koduyla (başarı) bitti. Hata mesajı yazıp "
                      "`sys.exit(1)` ile çık." + bt.ozet(c))
    rng = random.Random()
    nadir = rng.choice(v["nadir"])
    sayim = _dagilim(rng, v, rng.randint(150, 400), nadir)
    fd, ad = tempfile.mkstemp(prefix="hy_say_", suffix=Path(v["dosya"]).suffix)
    os.close(fd)
    gecici = Path(ad)
    try:
        gecici.write_text("\n".join(_satirlar(rng, v, sayim, s["musteri"], bos=3)) + "\n", encoding="utf-8")
        lab_dosya = Path(b.lab) / v["dosya"]
        if not lab_dosya.is_file():
            return Sonuc(False, f"{lab_dosya} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
        for dosya, beklenen_ham in ((lab_dosya, Counter(s["sayim"])), (gecici, sayim)):
            beklenen = {_anahtar_norm(k, v["on_ekler"]): n for k, n in beklenen_ham.items()}
            c = calistir(str(dosya))
            nasil = calistir.goster(dosya.name if dosya == lab_dosya else dosya)
            cokme = calistir.cokme(c)
            if cokme:
                if "IndexError" in c.stderr:
                    cokme += ("\n    Dosyada BOŞ satırlar var: boş satırı `split()` edince liste boş kalır. "
                              "`satir = satir.strip()` ve `if not satir: continue` ekle.")
                return Sonuc(False, f"`{nasil}` çalışırken: {cokme}", yakin="IndexError" in c.stderr)
            bulunan = _sayimlar(c, v["on_ekler"])
            if bulunan == beklenen:
                continue
            if not bulunan:
                return _yakin(f"`{nasil}` çıktısında `anahtar sayı` biçiminde satır bulamadım. Her anahtarı ayrı "
                              f"satıra yaz: `print(anahtar, adet)`." + bt.ozet(c))
            if "" in bulunan or any(k.endswith("\\n") for k in bulunan):
                return _yakin("Boş bir anahtar ya da sonunda satır sonu olan anahtar sayılmış. Satırı `strip()` et, "
                              "boş satırları atla.")
            if _sayimlar(c, v["on_ekler"], ters=True) == beklenen:
                return _yakin("Sayımların doğru ama sıra ters: her satırda ÖNCE anahtar, SONRA sayı olmalı "
                              "(`print(anahtar, adet)`). Anahtarın kendisi de sayı olduğu için sıra önemli.")
            eksik = [k for k in beklenen if k not in bulunan]
            yanlis = [k for k in beklenen if k in bulunan and bulunan[k] != beklenen[k]]
            fazla = [k for k in bulunan if k not in beklenen]
            parcalar = []
            if yanlis:
                k = yanlis[0]
                parcalar.append(f"`{k}` için {bulunan[k]} dedin, {beklenen[k]} olmalı")
            if eksik:
                parcalar.append(f"{len(eksik)} anahtar hiç yok (örn. `{eksik[0]}`)")
            if fazla:
                parcalar.append(f"beklenmeyen anahtar(lar) var: {', '.join(fazla[:3])} ({v['ayiklama']})")
            ek = ""
            if dosya == gecici and _sayimlar(c, v["on_ekler"]) == {
                    _anahtar_norm(k, v["on_ekler"]): n for k, n in s["sayim"].items()}:
                ek = " Farklı bir dosyada laboratuvarın sonuçlarını verdin: değerleri sabit yazmış olabilir misin?"
            return _yakin(f"`{nasil}` sayımları tutmuyor: " + "; ".join(parcalar) + "." + ek + bt.ozet(c, 8))
    finally:
        gecici.unlink(missing_ok=True)
    return Sonuc(True, "say.py hem laboratuvar dosyasında hem de senin hiç görmediğin yeni bir dosyada doğru "
                       "saydı. Cilt 1'de `cut | sort | uniq -c` ile elle yaptığın işi artık bir program yapıyor.")


def _sorulan_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    s = b.senaryo
    v = _vaka(s["kod"])
    sorulan = s["metin"]["sorulan"]
    try:
        metin = (Path(b.lab) / v["dosya"]).read_text(encoding="utf-8")
    except OSError:
        return None
    if n == sum(1 for satir in metin.splitlines() if sorulan in satir) and n != beklenen:
        return (f"Bu, içinde \"{sorulan}\" geçen SATIR sayısı; değer satırın başka yerlerinde de (boyut, port, "
                "sicil...) geçebiliyor. Sadece anahtar alanına bakan aracınla say.")
    return None


def _argv_hata(g, beklenen, b):
    if g.replace(" ", "") in ("len(sys.argv)", "len(argv)"):
        return "`sys.argv[0]` betiğin adıdır; `$#` onu saymaz. Bir şey çıkarman gerekiyor."
    if "sys.argv[0]" in g:
        return "`sys.argv[0]`, Bash'teki `$0`'ın karşılığıdır (betiğin adı)."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    v = _vaka(s["kod"])
    bt.betik_yaz(lab / "hedef.py", HEDEF_PY)
    bt.betik_yaz(lab / "servis.py", SERVIS_PY)
    bt.betik_yaz(lab / "say.py", SAY_PY.replace("<<AYIKLA>>", v["ayikla_kod"]))
    cikti = subprocess.run(["python3", "say.py", v["dosya"]], cwd=lab, capture_output=True, text=True).stdout
    sayim = {}
    for satir in cikti.splitlines():
        k, n = satir.split()
        sayim[k] = int(n)
    sorulan = s["metin"]["sorulan"]
    nadir = [k for k, n in sayim.items() if n == 1][0]
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (7, 8)}
    return {1: "", 2: "", 3: "", 4: sayim[sorulan], 5: nadir, 6: "len(sys.argv) - 1", **secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Neden Python?", """
Bash kısa işler için harika; ama veri işleme, sayma, ağ programlama gibi işlerde Python çok
daha rahattır. Güvenlik dünyasının fiili dili Python'dır: sqlmap, Impacket, Volatility gibi
araçlar Python'la yazılmıştır. İlk örneğe bak:
""", komut="cat ornekler/ilk.py", sonra="""
Bash'teki `$1` burada `sys.argv[1]`, `$0` ise `sys.argv[0]`. `len(sys.argv)` betik adı
**dahil** eleman sayısıdır; bu yüzden Bash'teki `$#`'in karşılığı `len(sys.argv) - 1`.
`f"...{degisken}..."` (f-string) değişkeni metne gömer. `sys.exit(1)` Bash'teki `exit 1`.
"""),
    Adim("Çalıştır ve sys.argv'yi gör", """
Python betiğini `python3 betik.py` diye çalıştırabilirsin (çalıştırma izni gerekmez).
Shebang (`#!/usr/bin/env python3`) ve `chmod +x` ile `./betik.py` de olur.
""", komut="python3 ornekler/ilk.py <<alan>>"),
    Adim("Sözlük: anahtar → değer", """
**Sözlük** (dict), bir anahtardan değere eşleme yapar: port → servis adı gibi. `[]` ile
olmayan bir anahtara erişirsen program `KeyError` ile çöker; `.get(anahtar, varsayilan)`
ise çökmeden varsayılanı döndürür:
""", komut="""python3 -c 's = {22: "SSH", 80: "HTTP"}; print(s[22], s.get(8080, "yok"))'""",
         sonra="""
Dikkat: `sys.argv`'den gelen her şey **metindir** (`"22"`). Sözlüğün anahtarı sayıysa
(`22`) önce `int()` ile çevirmelisin; `"22"` ile `22` farklı anahtarlardır.
"""),
    Adim("Dosya okumak ve görünmez karakter", """
`with open(dosya) as f:` dosyayı açar, `for satir in f:` satır satır okur. Ama her satırın
sonunda görünmeyen bir **satır sonu** (`\\n`) vardır. `repr()` onu görünür kılar:
""", komut="""python3 -c 'print(repr(open("<<dosya>>").readline()))'""", sonra="""
Sondaki `\\n`'i gördün. `satir.strip()` baştaki ve sondaki boşlukları ve satır sonlarını
temizler. Dosya okurken neredeyse her zaman gerekir; yoksa `"ERROR"` ile `"ERROR\\n"` iki
ayrı anahtar olur.
"""),
    Adim("split ile alan seçmek", """
`satir.split()` satırı boşluklardan böler ve bir **liste** döndürür; `[8]` gibi bir indeksle
istediğin alanı alırsın (sayma 0'dan başlar). `split(";")` ise noktalı virgülden böler.
Bu vakada: <<ayiklama>>. İlk satırda dene:
""", komut="""python3 -c 'satir = open("<<dosya>>").readline(); print(<<ornek_ifade>>)'""", sonra="""
Aradığın anahtarı satırdan böyle ayıklayacaksın. Boş bir satırı `split()` edersen liste
boş kalır ve `[8]` `IndexError` verir; boş satırları atlaman gerekecek.
"""),
    Adim("Sözlükle saymak", """
Bir şeyin kaç kez geçtiğini saymanın klasik kalıbı:
`sayac[anahtar] = sayac.get(anahtar, 0) + 1`. Örnek betik bir dosyadaki kullanıcı
adlarını sayıyor (içini sonra `cat ornekler/kelime_say.py` ile oku):
""", komut="python3 ornekler/kelime_say.py ornekler/kullanicilar.txt", sonra="""
`strip()`, boş satırı atlama ve `get(..., 0) + 1`: say.py'nin bütün iskeleti bu. Senin
farkın, satırın tamamını değil `split()` ile seçtiğin alanı saymak olacak.
"""),
    Adim("try/except: çökme, devam et", """
Ağ ve dosya işleri sık sık hata verir: dosya yok, bağlantı reddedildi, sayı beklerken metin
geldi. `try/except` bu hatayı yakalar; program çökmek yerine düzgün davranır:
""", komut="python3 ornekler/sayiya_cevir.py 80 abc 443", sonra="""
"abc" `int()`'e verilince `ValueError` fırladı, `except` yakaladı ve döngü devam etti.
Binlerce port ya da satır işleyen bir araçta tek bir hata yüzünden durmak istemezsin.
Olmayan dosya için `except FileNotFoundError:` kullanılır.

**Hacker gözüyle:** Python'ın güvenlikteki gücü kütüphanelerindedir: `socket` ile ham ağ
bağlantısı, `urllib`/`requests` ile HTTP, `re` ile desen arama. Sonraki bölümlerde
hepsini kullanacaksın.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`hedef.py` yaz: iki argüman (IP ve port) alıp `IP: <ip>, Port: <port>` yazsın. Argüman eksikse "
          "kullanım mesajı + `sys.exit(1)`. Port sayı değilse (örn. `abc`) **çökmeden** bir hata mesajı yazıp "
          "`sys.exit(1)` ile çıksın. Dene: `python3 hedef.py <<ip>> 22`",
          bt.BetikKontrol("hedef.py", _hedef_denetle, "Örnek `hedef.py`:\n\n```\n" + HEDEF_PY.rstrip() + "\n```"),
          ("Üç parça: argüman sayısı kontrolü, sayıya çevirme denemesi, yazdırma.",
           "`if len(sys.argv) < 3:` ile başla. `int(sys.argv[2])`'yi `try/except ValueError` içine al.",
           "İskelet:\n\n```\nimport sys\nif len(sys.argv) < 3:\n    print(...)\n    sys.exit(1)\ntry:\n    "
           "port = int(...)\nexcept ValueError:\n    ...\nprint(f\"IP: {...}, Port: {...}\")\n```"),
          puan=35, baslik="Argüman ve doğrulama"),
    Gorev("`servis.py` yaz: bir port numarası alıp hangi servise ait olduğunu yazsın. Sözlükte Ek B'deki on "
          "port olsun: 21 FTP, 22 SSH, 25 SMTP, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB, 3306 MySQL, 3389 RDP, "
          "8080 HTTP-alt. Tabloda olmayan port için `bilinmeyen servis` yazsın. Argümansızsa kullanım mesajı + "
          "`sys.exit(1)`.",
          bt.BetikKontrol("servis.py", _servis_denetle, "Örnek `servis.py`:\n\n```\n" + SERVIS_PY.rstrip() + "\n```"),
          ("Port → ad eşlemesi tam bir sözlük işi.",
           "Anahtarları sayı olan bir sözlük kur; argümanı `int()` ile çevir; `.get(port, 'bilinmeyen servis')`.",
           "İskelet:\n\n```\nservisler = {21: \"FTP\", 22: \"SSH\", ...}\nport = int(sys.argv[1])\n"
           "print(port, servisler.get(port, ...))\n```"),
          puan=35, baslik="Port sözlüğü"),
    Gorev("<<kisi>> için asıl araç: `say.py` yaz. Bir dosya yolunu argüman alsın, dosyayı satır satır okuyup "
          "her satırdaki **<<anahtar_ad>>** değerini saysın ve her anahtarı ayrı satırda `anahtar sayı` "
          "biçiminde yazsın (örn. `<<sorulan>> 37`). <<ayiklama>>. Boş satırları atla. Argümansızsa kullanım "
          "mesajı, dosya yoksa çökmeden hata mesajı; ikisinde de `sys.exit(1)`. Dene: `python3 say.py <<dosya>>`",
          bt.BetikKontrol("say.py", _say_denetle,
                          "Örnek `say.py` (bu vaka için):\n\n```\n" + SAY_PY.replace("<<AYIKLA>>", "<<ayikla_kod>>").rstrip()
                          + "\n```"),
          ("Eğitimdeki `kelime_say.py` neredeyse hazır; satırın tamamı yerine tek bir alanı saymalısın.",
           "Döngüde: `satir = satir.strip()`, boşsa `continue`, anahtarı ayıkla (<<ayiklama>>), "
           "`sayac[anahtar] = sayac.get(anahtar, 0) + 1`. Sonda `for anahtar, adet in sayac.items(): print(anahtar, adet)`.",
           "İskelet:\n\n```\nimport sys\nif len(sys.argv) < 2: ...\ntry:\n    f = open(sys.argv[1])\nexcept "
           "FileNotFoundError: ...\nsayac = {}\nfor satir in f:\n    satir = satir.strip()\n    if not satir:\n"
           "        continue\n    anahtar = ...\n    sayac[anahtar] = ...\nfor anahtar, adet in sayac.items():\n"
           "    print(anahtar, adet)\n```"),
          puan=60, baslik="Sayım aracı"),
    Gorev("Aracını laboratuvar dosyasında çalıştır: `<<dosya>>` içinde <<anahtar_ad>> değeri **<<sorulan>>** olan "
          "kaç kayıt var?",
          Sayi("sorulan_sayi", sik_hatalar=_sorulan_hata),
          ("say.py'nin çıktısında cevap hazır.",
           "`python3 say.py <<dosya>>` çıktısında <<sorulan>> satırına bak.",
           "`python3 say.py <<dosya>> | grep -w <<sorulan>>`"),
          puan=25, baslik="Kaç tane?"),
    Gorev("Sıra dışı olan çoğu zaman ilginç olandır: `<<dosya>>` içinde **yalnızca bir kez** geçen <<anahtar_ad>> "
          "değeri hangisi?",
          Metin("nadir", on_ekleri_at=("dpt=", "sonuc=", "["), son_ekleri_at=("]", " 1"),
                bicim="anahtar değeri"),
          ("Aracının çıktısında sayısı 1 olan satırı ara.",
           "Çıktıyı sayıya göre sırala: `python3 say.py <<dosya>> | sort -k2 -n | head -3`",
           "En küçük sayılı satır; sayısı 1 olan anahtarı yaz."),
          puan=30, baslik="Tek kayıt"),
    Gorev("Bash'teki `$#` (argüman sayısı) Python'da nasıl yazılır?",
          Metin(kabul=["len(sys.argv) - 1", "len(sys.argv)-1", "len(sys.argv[1:])"], sik_hatalar=_argv_hata,
                bicim="Python ifadesi"),
          ("`sys.argv` bir liste; listenin uzunluğu `len()` ile alınır.",
           "`sys.argv[0]` betiğin adıdır; `$#` onu saymaz.",
           "`len(sys.argv)` eksi bir şey."),
          puan=20, baslik="$# karşılığı"),
    Gorev("Port tarayan bir araçta `try/except` neden bu kadar önemlidir?",
          Secmeli([
              ("Ağ hataları sık olur; yakalanmazsa araç ilk hatada durur",
               "Doğru. Binlerce port denerken birinin zaman aşımına uğraması ya da reddedilmesi normaldir; araç devam "
               "etmeli."),
              ("`try` bloğundaki kod paralel çalışır, böylece tarama belirgin biçimde hızlanır",
               "`try` paralellik sağlamaz; sadece hatayı yakalar. Paralellik için iş parçacığı ya da `&` gerekir."),
              ("`except` yazılmazsa Python betiği hiç çalıştırmaz, söz dizimi hatası verir",
               "`try/except` isteğe bağlıdır; yazmazsan betik çalışır ama ilk hatada çöker."),
              ("Hedef sistemdeki loglara bağlantı denemelerinin iz düşmesini engeller",
               "Hata yakalamak hedef taraftaki kayıtları etkilemez; bağlantı denemesi yine loglanabilir."),
          ]),
          ("Ağ işlemleri ne sıklıkla başarısız olur?",
           "Bir hata yakalanmadığında Python ne yapar?",
           "Yakalanmayan hata programı durdurur; tarama yarıda kalır."),
          puan=20, baslik="Neden try"),
    Gorev("Bir stajyer say.py'de satırı `strip()` etmeden sözlüğe anahtar yapmış. Sonuç ne olur?",
          Secmeli([
              ("Anahtar sonda `\\n` taşır; aynı değer iki kez sayılabilir",
               "Doğru. Son satırda `\\n` yoksa `ERROR` ile `ERROR\\n` farklı anahtar olur; boş satırlar da `\\n` "
               "anahtarıyla sayılır."),
              ("Python satırları otomatik temizlediği için hiçbir fark olmaz",
               "Python satır sonunu otomatik atmaz; `for satir in f` satırı `\\n` ile birlikte verir."),
              ("Dosya açılamaz ve program FileNotFoundError ile durur",
               "`strip()` dosya açmayla ilgili değildir; dosya yine açılır."),
              ("Sözlük sadece ilk satırı tutar, geri kalan satırlar kaybolur",
               "Sözlük bütün anahtarları tutar; sorun anahtarların yanlış biçimde olması."),
          ]),
          ("Eğitimde `repr()` ile satır sonunda ne gördün?",
           "Görünmez bir karakter anahtarın parçası olursa iki \"aynı\" anahtar eşit olur mu?",
           "`\"ERROR\" == \"ERROR\\n\"` yanlıştır."),
          puan=20, baslik="strip()"),
]


SEVIYE = Seviye(
    kimlik="c03b03",
    cilt=3,
    bolum=3,
    baslik="Python'a Hacker Girişi",
    brifing="""
Mert ekranına bir Python dosyası açmış: "Bash'le bir yere kadar. Sayma, sözlük, ağ...
Ciddi araçlar Python'la yazılır."

Selin araya giriyor: "**<<musteri>>**'den <<kisi>> yazdı. <<olay>> Elimizde
laboratuvara kopyalanmış `<<dosya>>` var. Senden üç şey istiyorum: argüman alan ve girdiyi
doğrulayan küçük bir araç, port numarasını servis adına çeviren bir sözlük, bir de dosyadaki
**<<anahtar_ad>>** değerlerini sayan bir sayım aracı."

Mert ekliyor: "Oyun senin aracını görmediğin dosyalarla da deneyecek. Boş satırlara dikkat;
ilk Python araçlarının yarısı orada çöker."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bu bölümde yazdığın üç küçük araç, büyük güvenlik araçlarının yapı taşlarıdır: argümanı
doğrulayan bir giriş, bilgiyi eşleyen bir sözlük ve veriyi sayan bir döngü. Saldırgan bu
yapı taşlarıyla tarama sonuçlarını ve sızan verileri hızla süzer; savunmacı da aynılarıyla
binlerce satırlık logda tek bir sıra dışı kaydı yakalar. Bu vakadaki "yalnızca bir kez
geçen" kayıt gibi. İki taraf için de ders aynı: girdiye güvenme, hatayı yakala, veriyi say.
""",
    gercek_hayat="""
- **Güvenlik araçlarının dili:** sqlmap (SQL enjeksiyonu), Impacket (Windows ağ protokolleri)
  ve Volatility (bellek adli analizi) gibi yaygın açık kaynak güvenlik araçları Python ile
  yazılmıştır. Python okuyabilmek, bu araçların ne yaptığını ve neden hata verdiğini
  anlamanı sağlar.
- **Girdi doğrulamanın önemi:** OWASP'ın en yaygın web açıkları listelerinde enjeksiyon
  türü açıklar yıllardır üst sıralardadır; hepsinin kökü doğrulanmayan girdidir. `hedef.py`'de
  portu `int()` ile doğrulaman, aynı alışkanlığın en küçük örneği.
- **Sayarak anomali bulmak:** Pek çok olay müdahale raporunda saldırı izi, binlerce normal
  kaydın arasında birkaç kez görülen sıra dışı bir değerle (beklenmeyen bir port, bir hata
  kodu, garip bir kullanıcı adı) fark edilir. "Değerleri say, en nadirine bak" en eski ve
  en etkili tehdit avı yöntemlerindendir.
""",
    sure_hedef_dk=45,
)
