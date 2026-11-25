"""Cilt 3 · Bölüm 5 — HTTP Otomasyonu: Gizli Dizin Bulucu.

Beceri: kelime listesiyle dizin keşfi (gobuster/ffuf'un çekirdeği), urllib ile HTTP isteği
ve HTTPError'dan durum kodunu almak (requests'te `status_code`), 200/301/403/404'ün anlamı,
yönlendirmenin otomatik takip edilmesi ve Location başlığı, rstrip("/") ve boş satırlar,
robots.txt'nin kelime listesinin kaçırdığını göstermesi, bulguları dosyaya yazmak.

Laboratuvar: 127.0.0.1 üzerinde rastgele portta, SessizIsleyici'den türeyen bir web sunucusu.
Gizli yollar 200/301/403 döndürür, gerisi 404. Oyunun kontrolü, oyuncunun aracını hem bu
sunucuda hem de kontrol anında açılan, farklı gizli yollara sahip geçici bir sunucuda çalıştırır.
"""
from __future__ import annotations

import contextlib
import json
import os
import random
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlsplit

from hy.motor.kontrol import Baglam, Bayrak, Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import SessizIsleyici, calistir
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c03_otomasyon.ortak import http_sunucu

KELIMELER = """
admin administrator login giris panel yonetim yonetici kullanici uye hesap profil
backup backups yedek yedekler old eski arsiv archive bak tmp temp test testler dev
staging beta demo deneme ornek config conf settings ayarlar setup install kurulum
api v1 v2 rest graphql docs dokuman belgeler dosyalar files download indir upload
uploads images img resimler css js static assets media video fonts vendor lib inc
includes cgi-bin scripts logs log rapor raporlar istatistik stats status health
metrics debug console shell editor phpmyadmin pma mysql db database sql dump data
veri private gizli secret hidden internal ic portal intranet mail webmail smtp ftp
server-status server-info .git .svn .env .htaccess .htpasswd .DS_Store web.config
robots.txt sitemap.xml crossdomain.xml humans.txt security.txt favicon.ico
index.php index.html default.aspx home anasayfa iletisim hakkimizda blog haber
haberler duyuru duyurular destek yardim sss kampanya kampanyalar indirim sepet odeme
siparis siparisler urun urunler kategori arama magaza fatura musteri musteriler
doktorlar randevu hasta bolumler sube subeler doviz kredi ihaleler meclis menu
wp-admin wp-login.php wp-content wp-includes xmlrpc.php info.php phpinfo.php
test.php config.php config.php.bak backup.zip backup.sql db.sql site.tar.gz
""".split()

VAKALAR = [
    {
        "kod": "pazarix", "sunucu_yazilimi": "nginx/1.18.0",
        "yonlendir": "admin", "yasak": ".git", "acik": ["api", "kampanyalar", "magaza"],
        "robots": ["siparis-raporlari-2026", "gizli-kampanya-taslak"],
        "olay": "Pazarix kampanya öncesi yeni bir site yayına aldı. Tuncay Bey, eski sitenin bıraktığı "
                "\"unutulmuş\" sayfa ve dosyalar olup olmadığını merak ediyor.",
    },
    {
        "kod": "medora", "sunucu_yazilimi": "Apache/2.4.41 (Ubuntu)",
        "yonlendir": "hasta", "yasak": "server-status", "acik": ["doktorlar", "randevu", "api"],
        "robots": ["pacs-eski", "test-hasta-verisi"],
        "olay": "Bir hasta, randevu sayfasında başka birinin bilgilerini gördüğünü bildirdi. Dr. Aslı Hanım "
                "hasta portalında bilinmeyen, bağlantısı verilmemiş sayfalar olup olmadığını öğrenmek istiyor.",
    },
    {
        "kod": "ferahbank", "sunucu_yazilimi": "Apache/2.4.58",
        "yonlendir": "sube", "yasak": ".htpasswd", "acik": ["doviz", "kredi", "api"],
        "robots": ["test-ortami", "eski-mobil-api"],
        "olay": "Ferah Bank'ın internet şubesinde gece yarısı olağandışı bir giriş alarmı düştü. Kaan Bey "
                "sitede herkese açık kalmış bir yönetim ya da test sayfası olup olmadığını soruyor.",
    },
    {
        "kod": "yesiltepe", "sunucu_yazilimi": "nginx/1.24.0",
        "yonlendir": "e-belediye", "yasak": "arsiv", "acik": ["duyurular", "ihaleler", "meclis"],
        "robots": ["meclis-taslak", "personel-listesi"],
        "olay": "Belediyenin sitesi yeni bir firmaya devredildi. Nurcan Hanım, eski firmanın sunucuda "
                "unuttuğu yedek ya da yönetim sayfası olup olmadığını öğrenmek istiyor.",
    },
    {
        "kod": "atolye", "sunucu_yazilimi": "Apache/2.4.52 (Ubuntu)",
        "yonlendir": "wp-admin", "yasak": ".htaccess", "acik": ["menu", "subeler", "iletisim"],
        "robots": ["sadakat-listesi", "kasa-raporlari"],
        "olay": "Atölye Kahve'nin sitesi bir sabah yabancı bir yazıyla açıldı. Berk, saldırganın hangi "
                "gizli sayfadan girmiş olabileceğini bulmamızı istiyor.",
    },
]

EKSTRA_200 = ["test", "dev", "eski", "beta", "uploads", "docs"]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    parola = u.parola(rng)
    sizinti = m["yedek"].lstrip("/")
    acik = rng.sample(v["acik"], 2) + rng.sample(EKSTRA_200, 1)
    robots = rng.choice(v["robots"])
    yonlendir_hedef = m["giris"]
    return {
        "vaka": f"{m['ad']} — {m['alan']} gizli yol keşfi",
        "musteri": m,
        "v": v,
        "port": port,
        "acik": acik,
        "sizinti": sizinti,
        "robots": robots,
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "port": port, "alan": m["alan"],
            "url": f"http://127.0.0.1:{port}",
        },
        "cevaplar": {
            "yasak": v["yasak"],
            "konum": [yonlendir_hedef, yonlendir_hedef.lstrip("/"), f"http://127.0.0.1:{port}{yonlendir_hedef}"],
            "parola": parola,
            "bayrak": u.bayrak(rng, "robotlara_bak"),
        },
    }


def yollar(s: dict) -> dict:
    """Sunucunun yol tablosu: 'yol' (baştaki/sondaki / olmadan) -> (kod, başlıklar, gövde, tür)."""
    v = s["v"]
    m = s["musteri"]
    c = s["cevaplar"]
    konum = c["konum"][0]
    html = "text/html; charset=utf-8"
    t = {
        "": (200, {}, f"<html><head><title>{m['ad']}</title></head><body><h1>{m['ad']}</h1>"
                      "<p>Hoş geldiniz.</p></body></html>\n", html),
        "robots.txt": (200, {}, f"User-agent: *\nDisallow: /{s['robots']}/\nDisallow: /{v['yasak']}\n",
                       "text/plain; charset=utf-8"),
        v["yonlendir"]: (301, {"Location": konum}, "", html),
        konum.strip("/"): (200, {}, f"<html><body><h1>{m['ad']} — Yönetici Girişi</h1><form method=post>"
                                         "<input name=kullanici><input name=parola type=password></form>"
                                         "</body></html>\n", html),
        v["yasak"]: (403, {}, "<html><body><h1>403 Forbidden</h1></body></html>\n", html),
        s["sizinti"]: (200, {}, m["yedek_icerik"].format(parola=c["parola"]), "application/octet-stream"),
        s["robots"]: (200, {}, f"<html><body><h1>Dahili</h1><p>Bu sayfa arama motorlarından gizlendi.</p>"
                                f"<!-- erisim kodu: {c['bayrak']} --></body></html>\n", html),
        "eski-anasayfa": (301, {"Location": "/"}, "", html),
    }
    for ad in s["acik"]:
        if ad == "api":
            t[ad] = (200, {}, json.dumps({"servis": f"{m['kod']}-api", "surum": "1.4.2", "durum": "ok"}) + "\n",
                     "application/json")
        else:
            t[ad] = (200, {}, f"<html><body><h1>{ad}</h1></body></html>\n", html)
    return t


def isleyici_uret(tablo: dict, sunucu_yazilimi: str):
    class Isleyici(SessizIsleyici):
        server_version = sunucu_yazilimi

        def do_GET(self):
            yol = self.path.split("?", 1)[0].split("#", 1)[0].strip("/")
            if yol in tablo:
                kod, basliklar, govde, tur = tablo[yol]
                self.yanit(kod, govde, tur=tur, basliklar=basliklar)
            else:
                self.yanit(404, "<html><body><h1>404 Not Found</h1></body></html>\n")

        do_HEAD = do_GET

    return Isleyici


def servis(s: dict, lab: Path, dur) -> None:
    sunucu = http_sunucu("127.0.0.1", s["port"], isleyici_uret(yollar(s), s["v"]["sunucu_yazilimi"]))
    calistir([sunucu], dur)


def kelime_listesi(s: dict, rng: random.Random) -> list:
    v = s["v"]
    zorunlu = [v["yonlendir"], v["yasak"], s["sizinti"], "robots.txt"] + s["acik"]
    liste = list(dict.fromkeys(KELIMELER + zorunlu))
    rng.shuffle(liste)
    for _ in range(3):                    # boş satırlar: strip() dersi
        liste.insert(rng.randint(3, len(liste) - 3), "")
    return liste


TEK_ISTEK_PY = '''#!/usr/bin/env python3
# tek_istek.py — tek bir URL'ye GET isteği gönderip durum kodunu yazar (sadece standart kütüphane)
import sys
import urllib.error
import urllib.request

url = sys.argv[1]
try:
    with urllib.request.urlopen(url, timeout=3) as r:      # 3 sn zaman aşımı
        print("Durum kodu:", r.status)
        print("Server    :", r.headers.get("Server"))
        print("Son URL   :", r.url)                         # yönlendirme varsa takip edilmiş hali
except urllib.error.HTTPError as e:                          # 4xx/5xx burada yakalanır
    print("Durum kodu:", e.code, "(HTTPError)")
except urllib.error.URLError as e:                           # sunucuya hiç ulaşılamadı
    print("Bağlanılamadı:", e.reason)
'''

DIZIN_BULUCU_PY = '''#!/usr/bin/env python3
import sys
import urllib.error
import urllib.request

if len(sys.argv) < 3:
    print(f"Kullanım: {sys.argv[0]} <url> <kelime_listesi>")
    print(f"Örnek:   {sys.argv[0]} http://127.0.0.1:8000 kelimeler.txt")
    sys.exit(1)

url = sys.argv[1].rstrip("/")
try:
    with open(sys.argv[2], encoding="utf-8") as f:
        kelimeler = [k.strip() for k in f if k.strip()]
except FileNotFoundError:
    print(f"Hata: {sys.argv[2]} bulunamadı.")
    sys.exit(1)

print(f"[*] {url} üzerinde {len(kelimeler)} yol deneniyor...")
for kelime in kelimeler:
    hedef = f"{url}/{kelime}"
    try:
        with urllib.request.urlopen(hedef, timeout=3) as r:
            kod = r.status
    except urllib.error.HTTPError as e:
        kod = e.code
    except (urllib.error.URLError, OSError):
        continue
    if kod != 404:
        print(f"[+] {kod}  {hedef}")
print("[*] Bitti.")
'''


def yaz(lab: Path, s: dict) -> None:
    rng = random.Random(f"{s['port']}-{s['robots']}")
    u.yaz(lab / "kelimeler.txt", "\n".join(kelime_listesi(s, rng)) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {s['musteri']['alan']} (laboratuvar kopyası)\n\n"
          f"Site adresi   : http://127.0.0.1:{s['port']}\n"
          "Kelime listesi: kelimeler.txt (SecLists'in çok küçük bir kardeşi; boş satırlar var)\n\n"
          "Kendi aracını lab'ın köküne yaz: dizin_bulucu.py\n"
          f"Kullanım      : python3 dizin_bulucu.py http://127.0.0.1:{s['port']} kelimeler.txt\n\n"
          "Not: Kali'de requests kuruludur; ama urllib her Python'da vardır. İkisi de olur.\n")
    u.yaz(lab / "ornekler" / "tek_istek.py", TEK_ISTEK_PY, mod=0o755)


# ---------------------------------------------------------------- çıktı ayrıştırma

HTTP_KODLARI = {200, 201, 202, 204, 301, 302, 303, 307, 308, 400, 401, 403, 404, 405, 500, 502, 503}


def bulgular(metin: str) -> dict:
    """Araç çıktısından {yol: kod|None}. Yol baştaki/sondaki / olmadan; kök = ''."""
    sonuc = {}
    for satir in metin.splitlines():
        url = re.search(r"https?://[^\s\"'<>]+", satir)
        if url:
            yol = urlsplit(url.group(0)).path.strip("/")
            kalan = satir.replace(url.group(0), " ")
        else:
            parca = re.search(r"(?<!\S)/(\S*)", satir)
            if not parca:
                continue
            yol = parca.group(1).strip("/")
            kalan = satir.replace(parca.group(0), " ")
        if not yol and not satir.lstrip().startswith("[+]"):
            continue                      # "[*] http://... üzerinde N yol deneniyor" gibi başlık satırları
        kodlar = [int(k) for k in re.findall(r"(?<![\d.])([1-5]\d\d)(?![\d.])", kalan) if int(k) in HTTP_KODLARI]
        sonuc[yol] = kodlar[0] if kodlar else None
    return sonuc


def _karsilastir(bulunan: dict, tablo: dict, kelimeler: list) -> tuple:
    """(eksik, fazla, yanlis_404) — 301'ler için yönlendirme hedefi de kabul edilir."""
    beklenen = {k: tablo[k][0] for k in kelimeler if k in tablo}
    takma = {}
    for k, (kod, basliklar, _, _) in tablo.items():
        if kod in (301, 302) and k in beklenen:
            takma[basliklar["Location"].strip("/")] = k
    gorulen = set()
    fazla = []
    for yol, kod in bulunan.items():
        asil = yol if yol in beklenen else takma.get(yol)
        if asil is None:
            fazla.append(yol)
        else:
            gorulen.add(asil)
    eksik = [k for k in beklenen if k not in gorulen]
    yanlis_404 = [y for y in fazla if bulunan[y] == 404]
    return eksik, fazla, yanlis_404, beklenen


def _sonucu_yorumla(nasil: str, c: bt.Cikti, bulunan: dict, tablo: dict, kelimeler: list) -> Sonuc | None:
    eksik, fazla, yanlis_404, beklenen = _karsilastir(bulunan, tablo, kelimeler)
    if not eksik and not fazla:
        return None
    if not bulunan:
        return Sonuc(False, f"`{nasil}` hiçbir yol yazmadı. Bulduğun her yolu `[+] KOD URL` biçiminde yaz "
                     "(örn. `[+] 200  http://127.0.0.1:8000/admin`)." + bt.ozet(c))
    if "" in fazla:
        return Sonuc(False, f"`{nasil}` kök dizini (`/`) de \"buldu\": kelime listesindeki BOŞ satırları istek olarak "
                     "göndermişsin. `[k.strip() for k in f if k.strip()]` ile boş satırları at.", yakin=True)
    if yanlis_404 or len(fazla) > 10:
        return Sonuc(False, f"`{nasil}` var olmayan yolları da yazıyor ({len(fazla)} fazla). Sadece durum kodu 404 "
                     "OLMAYANLARI yazmalısın." + bt.ozet(c), yakin=True)
    yasaklar = [k for k in eksik if beklenen[k] in (401, 403)]
    if yasaklar and len(yasaklar) == len(eksik):
        return Sonuc(False, f"`{nasil}` 403 dönen yolu (`/{yasaklar[0]}`) kaçırdı. urllib 4xx cevaplarında "
                     "`HTTPError` fırlatır; `except urllib.error.HTTPError as e:` ile yakalayıp `e.code`'u kullan. "
                     "403 \"var ama yasak\" demektir ve genellikle EN ilginç bulgudur.", yakin=True)
    mesaj = f"`{nasil}` {len(beklenen)} yol bulmalıydı"
    if eksik:
        mesaj += f"; {len(eksik)} tanesini kaçırdı (örn. `/{eksik[0]}`)"
    if fazla:
        mesaj += f"; {len(fazla)} fazladan yol yazdı (örn. `/{fazla[0]}`)"
    return Sonuc(False, mesaj + "." + bt.ozet(c, 8), yakin=True)


@contextlib.contextmanager
def _gecici_site():
    """Kontrol anında farklı gizli yollara sahip geçici bir site ve kelime listesi açar."""
    rng = random.Random()
    havuz = [k for k in KELIMELER if k not in ("robots.txt",)]
    secilen = rng.sample(havuz, 5)
    yonlendir_hedef = "/" + rng.choice(["giris", "yonetim", "panel"]) + "/oturum.php"
    tablo = {
        "": (200, {}, "ana sayfa\n", "text/html"),
        secilen[0]: (200, {}, "a\n", "text/html"),
        secilen[1]: (200, {}, "b\n", "text/html"),
        secilen[2]: (403, {}, "yasak\n", "text/html"),
        secilen[3]: (301, {"Location": yonlendir_hedef}, "", "text/html"),
        yonlendir_hedef.strip("/"): (200, {}, "giris\n", "text/html"),
    }
    liste = rng.sample(havuz, 25)
    for k in secilen[:4]:
        if k not in liste:
            liste.append(k)
    rng.shuffle(liste)
    liste.insert(5, "")
    sunucu = None
    for _ in range(6):
        port = rng.randint(20000, 45000)
        with contextlib.suppress(OSError):
            sunucu = http_sunucu("127.0.0.1", port, isleyici_uret(tablo, "Apache/2.4.41"))
            break
    if sunucu is None:
        raise RuntimeError("Geçici web sunucusu açılamadı")
    threading.Thread(target=sunucu.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
    fd, ad = tempfile.mkstemp(prefix="hy_kelimeler_", suffix=".txt")
    os.close(fd)
    Path(ad).write_text("\n".join(liste) + "\n", encoding="utf-8")
    try:
        yield f"http://127.0.0.1:{port}", Path(ad), tablo, [k for k in liste if k]
    finally:
        sunucu.shutdown()
        sunucu.server_close()
        Path(ad).unlink(missing_ok=True)


def _bulucu_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    url = f"http://127.0.0.1:{s['port']}"
    for args in ((), (url,)):
        hata = bt.kullanim_denetle(calistir, *args)
        if hata:
            return Sonuc(False, hata, yakin=True)
    lab_liste = Path(b.lab) / "kelimeler.txt"
    if not lab_liste.is_file():
        return Sonuc(False, "kelimeler.txt yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    lab_tablo = yollar(s)
    with _gecici_site() as (g_url, g_liste, g_tablo, g_kelimeler):
        denemeler = [
            (url + "/", lab_liste, lab_tablo, [k.strip() for k in lab_liste.read_text(encoding="utf-8").split("\n")
                                               if k.strip()]),
            (g_url, g_liste, g_tablo, g_kelimeler),
        ]
        lab_sonucu = None
        for hedef, liste, tablo, kelimeler in denemeler:
            c = calistir(hedef, str(liste), zaman_asimi=60)
            nasil = calistir.goster(hedef, liste.name if liste == lab_liste else liste)
            cokme = calistir.cokme(c)
            if cokme:
                return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
            bulunan = bulgular(c.stdout)
            if "//" in c.stdout.replace("://", ""):
                return Sonuc(False, f"`{nasil}` çıktısında çift eğik çizgili URL'ler var (`...//admin`). Adresi "
                             "sonunda `/` ile verdim; `sys.argv[1].rstrip(\"/\")` ile sondaki eğik çizgiyi at.",
                             yakin=True)
            if lab_sonucu is not None and bulunan == lab_sonucu and bulunan:
                return Sonuc(False, "Farklı bir sitede laboratuvarın sonuçlarını verdin. URL ve kelime listesini "
                             "`sys.argv`'den aldığından emin ol.", yakin=True)
            sonuc = _sonucu_yorumla(nasil, c, bulunan, tablo, kelimeler)
            if sonuc:
                return sonuc
            lab_sonucu = bulunan
    return Sonuc(True, "dizin_bulucu.py hem laboratuvar sitesinde hem de senin hiç görmediğin bir sitede bütün "
                       "gizli yolları buldu; 403'ü kaçırmadı, 404'leri yazmadı. gobuster'ın çekirdeği bu.")


def _bulgular_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    adaylar = [Path(b.calisma_dizini or b.lab) / "bulgular.txt", Path(b.lab) / "bulgular.txt"]
    yol = next((p for p in adaylar if p.is_file()), None)
    if yol is None:
        return Sonuc(False, "`bulgular.txt` bulunamadı (lab'da ya da bulunduğun klasörde). Aracının çıktısını "
                     "`>` ile bu dosyaya yönlendir ya da betiğin içinde dosyaya yaz.")
    lab_liste = Path(b.lab) / "kelimeler.txt"
    kelimeler = [k.strip() for k in lab_liste.read_text(encoding="utf-8").split("\n") if k.strip()]
    bulunan = bulgular(yol.read_text(encoding="utf-8", errors="replace"))
    eksik, fazla, yanlis_404, beklenen = _karsilastir(bulunan, yollar(s), kelimeler)
    if not bulunan:
        return Sonuc(False, "bulgular.txt'de `KOD URL` biçiminde hiç bulgu satırı yok.")
    if eksik:
        return Sonuc(False, f"bulgular.txt'de {len(eksik)} yol eksik (örn. `/{eksik[0]}`).", yakin=True)
    if fazla:
        return Sonuc(False, f"bulgular.txt'de kelime listesiyle bulunmayan ya da 404 dönen {len(fazla)} yol var "
                     f"(örn. `/{fazla[0]}`).", yakin=True)
    kodsuz = [y for y, k in bulunan.items() if k is None and y]
    if kodsuz:
        return Sonuc(False, f"Bazı satırlarda durum kodu yok (örn. `/{kodsuz[0]}`). Her yolun yanına kodunu yaz.",
                     yakin=True)
    return Sonuc(True, f"bulgular.txt hazır: {len(beklenen)} yol, kodlarıyla. Rapora eklenecek kanıt bu.")


def _konum_hata(g, beklenen, b):
    if g.strip("/") == b.senaryo["v"]["yonlendir"].lower():
        return "Bu, yönlendiren yolun kendisi. Soru, yönlendirmenin GİTTİĞİ adresi soruyor: `Location` başlığına bak."
    return None


def _yasak_hata(g, beklenen, b):
    g = g.strip("/")
    if g == "robots.txt":
        return "robots.txt herkese açık (200). 403 dönen yolu arıyorsun."
    if g == b.senaryo["robots"].lower():
        return "Bu yol robots.txt'de geçiyor ama 403 değil. Aracının çıktısında 403 kodlu satıra bak."
    return None


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=120).stdout


def coz(lab: Path, s: dict) -> dict:
    url = s["metin"]["url"]
    bt.betik_yaz(lab / "dizin_bulucu.py", DIZIN_BULUCU_PY)
    cikti = _sh(f"python3 dizin_bulucu.py {url} kelimeler.txt | tee bulgular.txt", lab)
    bulunan = bulgular(cikti)
    yasak = next(y for y, k in bulunan.items() if k == 403)
    konum = ""
    for yol in bulunan:
        kod_konum = _sh(f"curl -s -o /dev/null -w '%{{http_code}} %{{redirect_url}}' {url}/{yol}", lab).split()
        if kod_konum and kod_konum[0] == "301" and len(kod_konum) > 1 and urlsplit(kod_konum[1]).path != "/":
            konum = urlsplit(kod_konum[1]).path
    parola = ""
    for yol in bulunan:
        icerik = _sh(f"curl -s {url}/{yol}", lab)
        m = re.search(r"(?:PASS(?:WORD)?=|parola: |admin:|\$db_parola = '|DB_PASSWORD', ')([^'\s]+)", icerik)
        if m:
            parola = m.group(1)
    gizli = re.search(r"Disallow: /([^/\s]+)/", _sh(f"curl -s {url}/robots.txt", lab)).group(1)
    bayrak = re.search(r"FLAG\{[^}]+\}", _sh(f"curl -s {url}/{gizli}/", lab)).group(0)
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (7, 8)}
    return {1: "", 2: yasak, 3: konum, 4: parola, 5: bayrak, 6: "", **secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Bağlantısı verilmemiş sayfalar", """
Web testlerinin en sık işlerinden biri, sitede **bağlantısı verilmemiş** ama erişilebilir
sayfaları bulmaktır: `/admin`, `/yedek`, unutulmuş bir `config.php.bak`... Bunun yolu bir
**kelime listesi** (wordlist) almak, her kelimeyi adresin sonuna eklemek ve cevabın 404
(yok) olup olmadığına bakmaktır. Laboratuvardaki listeye bak:
""", komut="head -12 kelimeler.txt", sonra="""
Gerçek işte SecLists gibi on binlerce kelimelik listeler kullanılır; bizimki küçük bir
kardeşi. Listede **boş satırlar** da var; aracın onları atlamalı.
"""),
    Adim("Durum kodları", """
Cilt 2, Bölüm 5'i hatırla: **200** bulundu, **301/302** başka yere yönlendiriyor, **403**
"var ama yasak" (çoğu zaman en ilginç bulgu), **404** yok. curl ile olmayan bir sayfayı
iste ve sadece kodu yazdır:
""", komut='curl -s -o /dev/null -w "%{http_code}\\n" <<url>>/olmayan-sayfa', sonra="""
`-o /dev/null` gövdeyi çöpe atar, `-w "%{http_code}"` sadece kodu yazar. Aracın bu işi
yüzlerce kelime için yapacak.
"""),
    Adim("Python'da HTTP: urllib", """
Kitap `requests` kütüphanesini kullanır (Kali'de kurulu gelir): `requests.get(url).status_code`.
Ama `urllib.request` her Python'da vardır ve sana ek bir paket gerektirmez. Örneği oku:
""", komut="cat ornekler/tek_istek.py", sonra="""
En önemli fark: `urllib` 4xx ve 5xx cevaplarında **istisna fırlatır** (`HTTPError`). Durum
kodunu `except urllib.error.HTTPError as e:` içinde `e.code` ile alırsın. Bunu unutan
araç 403'leri sessizce kaçırır. `requests` ise istisna fırlatmaz; kodu `r.status_code`'da
verir.
"""),
    Adim("Bir istek gönder", """
Ana sayfayı iste:
""", komut="python3 ornekler/tek_istek.py <<url>>/", sonra="""
200 ve `Server` başlığı geldi. Şimdi aynı komutu olmayan bir yolla kendin dene
(`<<url>>/yok`); `HTTPError` dalının çalıştığını göreceksin.
"""),
    Adim("Yönlendirme ve Location", """
301 cevabı bir `Location` başlığıyla "şuraya git" der. `urllib` ve `requests` yönlendirmeyi
**otomatik takip eder**; sonuçta son sayfanın kodunu (genellikle 200) görürsün. Asıl
301'i ve gittiği yeri görmek için `curl -I` (sadece başlıklar) kullan:
""", komut="curl -s -I <<url>>/eski-anasayfa", sonra="""
`HTTP/1.0 301` ve `Location: /` gördün. requests'te yönlendirmeyi takip etmemek için
`allow_redirects=False` verilir. Görevlerden biri bir yönlendirmenin nereye gittiğini
soracak.
"""),
    Adim("Çift eğik çizgi ve rstrip", """
Kullanıcı adresi sonunda eğik çizgiyle verirse (`http://site/`) ve sen `f"{url}/{kelime}"`
yazarsan `http://site//admin` olur. Bazı sunucular bunu farklı yorumlar. Çözüm:
`url = sys.argv[1].rstrip("/")`. Dene:
""", komut="""python3 -c 'print("http://site/".rstrip("/") + "/admin")'""", sonra="""
**Hacker gözüyle:** Bu araç gobuster, ffuf ve dirb'in çekirdeğidir: kelime listesi + durum
kodu filtresi. Ama hedefe yüzlerce istek gönderir; **gürültülüdür ve iz bırakır.** Yalnızca
test etme iznin olan sistemlerde çalıştır. İzinsiz bir siteye dizin taraması yapmak
Bölüm 0'daki TCK 243 kapsamına girebilir.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`dizin_bulucu.py` yaz: `python3 dizin_bulucu.py <url> <kelime_listesi>` listedeki her kelimeyi adresin "
          "sonuna ekleyip istek göndersin ve cevabı **404 olmayan** her yolu `[+] KOD URL` biçiminde yazsın (örn. "
          "`[+] 403  <<url>>/gizli`). Boş satırları atla, adresin sonundaki `/`'yi temizle. Argüman eksikse "
          "kullanım mesajı + `sys.exit(1)`. Dene: `python3 dizin_bulucu.py <<url>> kelimeler.txt`",
          bt.BetikKontrol("dizin_bulucu.py", _bulucu_denetle,
                          "Örnek `dizin_bulucu.py` (sadece standart kütüphane):\n\n```\n" + DIZIN_BULUCU_PY.rstrip()
                          + "\n```", zaman_asimi=60),
          ("`ornekler/tek_istek.py` tek bir istek için hazır; onu bir kelime döngüsüne koy.",
           "Listeyi `[k.strip() for k in f if k.strip()]` ile oku. Her kelime için `urlopen`; `HTTPError`'da kod "
           "`e.code`. Kod 404 değilse yazdır.",
           "İskelet:\n\n```\nurl = sys.argv[1].rstrip(\"/\")\nfor kelime in kelimeler:\n    hedef = f\"{url}/{kelime}\"\n"
           "    try:\n        with urllib.request.urlopen(hedef, timeout=3) as r:\n            kod = r.status\n"
           "    except urllib.error.HTTPError as e:\n        kod = ...\n    if kod != 404:\n        print(...)\n```"),
          puan=60, baslik="Dizin bulucu"),
    Gorev("Aracının bulduğu yollardan biri \"var ama yasak\" (403). Hangisi?",
          Metin("yasak", sadece_ad=True, sik_hatalar=_yasak_hata, bicim="yol (örn. /gizli)"),
          ("Aracının çıktısında durum koduna bak.",
           "`python3 dizin_bulucu.py <<url>> kelimeler.txt | grep 403`",
           "403'lü satırdaki yolu yaz."),
          puan=25, baslik="Yasak bölge"),
    Gorev("Bulunan yollardan biri kalıcı olarak (301) bir **giriş sayfasına** yönlendiriyor. Yönlendirmenin gittiği "
          "adres (yol) nedir?",
          Metin("konum", on_ekleri_at=("location:",), sik_hatalar=_konum_hata, bicim="yol (örn. /a/b.php)"),
          ("Aracın yönlendirmeyi otomatik takip ettiği için 301'i göremeyebilirsin.",
           "Bulduğun yolları `curl -s -I <<url>>/YOL` ile tek tek iste; `301` ve `Location:` satırına bak.",
           "`for y in $(python3 dizin_bulucu.py <<url>> kelimeler.txt | grep -oE '[^/ ]+$'); do echo \"== $y\"; "
           "curl -s -I <<url>>/$y | grep -iE '^HTTP|^location'; done`"),
          puan=30, baslik="Yönlendirme"),
    Gorev("Bulunan dosyalardan biri unutulmuş bir yedek ve içinde bir parola var. Parola ne?",
          Metin("parola", bicim="parola"),
          ("Adı `.bak`, `.old`, `.sql`, `.zip`, `~` gibi biten ya da yedek olduğu belli olan yola bak.",
           "`curl -s <<url>>/DOSYA` ile içeriği oku.",
           "Dosyada `PASS`, `PASSWORD`, `parola` ya da `kullanıcı:parola` biçiminde bir satır var."),
          puan=35, baslik="Unutulan yedek"),
    Gorev("Kelime listesi her şeyi bulamaz. Site, arama motorlarından gizlemek istediği bir yolu kendisi ilan ediyor; "
          "orada bir erişim kodu (bayrak) var. Bul.",
          Bayrak("bayrak"),
          ("Arama motorlarına \"buraya bakma\" diyen dosyayı aracın zaten buldu.",
           "`curl -s <<url>>/robots.txt` ve `Disallow:` satırları. Kelime listende olmayan yola git.",
           "`curl -s <<url>>/YOL/` (YOL robots.txt'deki Disallow değeri); bayrak HTML yorumunun içinde."),
          puan=35, baslik="robots.txt"),
    Gorev("Bulduğun her yolu durum koduyla birlikte lab'da `bulgular.txt` dosyasına yaz (her satırda bir bulgu, "
          "`KOD URL`). Hazır olunca `cevap 6`.",
          Durum(_bulgular_denetle, "```\npython3 dizin_bulucu.py <<url>> kelimeler.txt > bulgular.txt\n```"),
          ("Aracın zaten bu biçimde yazıyor; çıktıyı bir dosyaya koyman yeter.",
           "Kabuğun `>` yönlendirmesi ya da Python'da `open(\"bulgular.txt\", \"a\")` ile `write`.",
           "`python3 dizin_bulucu.py <<url>> kelimeler.txt > bulgular.txt`"),
          puan=25, baslik="Kanıt dosyası"),
    Gorev("Kitaptaki araçta `url = sys.argv[1].rstrip(\"/\")` satırı ne işe yarar?",
          Secmeli([
              ("Sondaki `/`'yi atar; `site//admin` gibi çift eğik çizgiyi önler",
               "Doğru. Kullanıcı adresi `http://site/` diye verirse `f\"{url}/{kelime}\"` çift eğik çizgi üretir."),
              ("Adresin başındaki `http://` kısmını temizleyip alan adını bırakır",
               "`rstrip` sadece SAĞ uçtan (sondan) karakter atar; baştaki `http://` olduğu gibi kalır."),
              ("URL'deki bütün eğik çizgileri silip tek kelimelik bir ad üretir",
               "`rstrip` sadece sondaki karakterlere dokunur; ortadaki eğik çizgiler kalır."),
              ("Adresi küçük harfe çevirip sunucunun büyük harf hatasını önler",
               "Küçük harfe çevirmek `lower()` ile yapılır; `rstrip(\"/\")` sadece sondaki eğik çizgiyi atar."),
          ]),
          ("`rstrip` adındaki `r` neyi anlatıyor olabilir?",
           "Eğitimdeki `\"http://site/\".rstrip(\"/\")` denemesini hatırla.",
           "Sağdan (sondan) eğik çizgiyi atar; aksi halde kelimeyi eklerken iki eğik çizgi yan yana gelir."),
          puan=20, baslik="rstrip"),
    Gorev("Arkadaşın, bu aracı \"sadece meraktan\" sevdiği bir alışveriş sitesinde çalıştırmak istiyor. Ne dersin?",
          Secmeli([
              ("Yazılı izin yoksa yapma; iz bırakır ve TCK 243'e girebilir",
               "Doğru. Dizin taraması hedefte açıkça loglanır ve izinsiz yapıldığında yetkisiz erişim girişimi "
               "sayılabilir."),
              ("Sadece GET isteği gönderdiği için hiçbir yasal sorunu yoktur",
               "İsteğin türü değil, iznin olup olmadığı belirleyicidir. Saldırı amaçlı keşif GET ile de yapılır."),
              ("robots.txt'de yasak olmayan yolları taradığı sürece serbesttir",
               "robots.txt arama motorları için bir rica dosyasıdır; sana test izni vermez."),
              ("Gece yaparsa kimse fark etmez, sabah sonuçları site sahibine bildirir",
               "Zamanlama yetkisiz testi meşru yapmaz; iyi niyet de izin yerine geçmez."),
          ]),
          ("Bölüm 0'ı hatırla: etik hacker ile suçluyu ne ayırır?",
           "Bu araç hedefte iz bırakır mı?",
           "Yazılı izin olmadan herhangi bir sisteme tarama yapılmaz."),
          puan=20, baslik="İzin"),
]


SEVIYE = Seviye(
    kimlik="c03b05",
    cilt=3,
    bolum=5,
    baslik="HTTP Otomasyonu: Gizli Dizin Bulucu",
    brifing="""
Mert ekranında kayan yüzlerce satırı gösteriyor: "gobuster. Ama bu hafta onu değil, onun
çekirdeğini yazacaksın."

Selin dosyayı uzatıyor: "**<<musteri>>** (<<alan>>). <<olay>> Sitenin laboratuvar kopyası
`<<url>>` adresinde, küçük bir kelime listesi de lab'ında. Bağlantısı verilmemiş her yolu
bul: açık olanları, yasak olanları, bir yere yönlenenleri."

Deniz monitörünü çeviriyor: "Bu tür taramalar benim ekranımda yüzlerce 404 olarak görünür.
İzinli olduğun için sorun yok; ama ne kadar gürültü yaptığını unutma."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Kelime listesi artı durum kodu filtresi: gobuster ve ffuf'un özü bu kadar. Saldırgan bu
yöntemle unutulmuş yedekleri, test sayfalarını ve yönetim panellerini bulur; bu vakada bir
yedek dosyası doğrudan parola sızdırdı. Ama kelime listesi sadece içindekini bulur;
robots.txt gibi sitenin kendi ipuçlarına bakmayan, eksik kalır. Savunma tarafı için ders
iki katlı: canlı sunucuda yedek ve test dosyası bırakma, gizlemek istediğin yolu robots.txt'de
ilan etme; ve loglarında kısa sürede yüzlerce 404 üreten bir IP gördüğünde bunun bir dizin
taraması olduğunu bil.
""",
    gercek_hayat="""
- **SecLists:** Daniel Miessler ve Jason Haddix'in başlattığı SecLists projesi, dizin, dosya,
  kullanıcı adı ve parola keşfi için toplanmış kelime listelerinin en yaygın kullanılan
  açık kaynak koleksiyonudur; Kali'de `seclists` paketiyle gelir.
- **Açıkta kalan .git klasörleri:** Güvenlik araştırmacıları, yanlışlıkla web kökünde
  bırakılmış `.git` klasörlerinden sitenin bütün kaynak kodunun ve içindeki parolaların
  indirilebildiğini defalarca raporladı. Kelime listelerinin hemen hepsinde `.git` bu
  yüzden bulunur.
- **robots.txt bir güvenlik önlemi değildir:** robots.txt standardı (RFC 9309) kendisinin
  bir erişim kontrolü olmadığını açıkça belirtir; dosya herkese açıktır. İçine yazılan
  "gizli" yollar, saldırgana nereye bakacağını söyler.
""",
    sure_hedef_dk=45,
)
