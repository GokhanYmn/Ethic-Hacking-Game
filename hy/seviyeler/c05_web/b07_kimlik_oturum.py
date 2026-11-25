"""Cilt 5 · Bölüm 7 — Kimlik Doğrulama ve Oturum Açıkları.

Beceri: giriş loglarından deneme-yanılma (brute-force) saldırısını tespit etmek, kullanıcı sayımı
(enumeration), tahmin edilebilir oturum çerezi, MFA kavramı ve üç düzeltme: rastgele oturum kimliği,
hız sınırlama (rate limiting), tek tip hata mesajı.

Laboratuvar: küçük bir giriş uygulaması (lab/uygulama.py) + kurgusal bir giriş günlüğü
(giris_kayit.log) + aday kullanıcı listesi. Oturum kimliği kullanıcı adının MD5 özetinden üretiliyor;
giriş hız sınırsız; iki farklı hata mesajı var. Üç düzeltme ayrı ayrı sınanır.
"""
from __future__ import annotations

import hashlib
import random
import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Durum, IP, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c05_web import ortak as o

VAKALAR = [
    {"kod": "pazarix", "giris": "/giris", "profil": "/hesabim", "bicim": "A", "etiket": "müşteri hesabı",
     "olay": "Pazarix'in müşteri hesabı sayfasında gece yarısı bir yönetici hesabı için yüzlerce başarısız giriş görüldü. "
             "Tuncay Bey, saldırının nasıl yapıldığını, neden engellenemediğini ve oturum çerezinin güvenli olup olmadığını soruyor."},
    {"kod": "medora", "giris": "/hasta/giris", "profil": "/hasta/ozet", "bicim": "B", "etiket": "hasta portalı",
     "olay": "Medora Sağlık'ın hasta portalında bir personel hesabı sabaha karşı ele geçirildi. Dr. Aslı Hanım, "
             "giriş günlüğünden saldırganı bulmamızı ve uygulamanın bu saldırıya neden açık olduğunu öğrenmek istiyor."},
    {"kod": "ferahbank", "giris": "/sube/giris", "profil": "/sube/hesap", "bicim": "C", "etiket": "internet şubesi",
     "olay": "Ferah Bank'ın internet şubesi için bir alarm üretildi: tek bir kaynaktan çok sayıda giriş denemesi. "
             "Kaan Bey, günlükleri inceleyip girişin neden hız sınırsız olduğunu ve oturumun nasıl yönetildiğini sormak istiyor."},
    {"kod": "paramix", "giris": "/merchant/giris", "profil": "/merchant/panel", "bicim": "B", "etiket": "üye işyeri paneli",
     "olay": "Paramix'in üye işyeri panelinde yönetici hesabı için olağandışı giriş denemeleri var. Ece Hanım, saldırganın IP'sini "
             "ve panelin giriş mantığındaki zayıflıkları bir rapor için istiyor."},
]

SEMA = """
CREATE TABLE kullanicilar (id INTEGER PRIMARY KEY, ad TEXT, parola TEXT, rol TEXT, notu TEXT);
CREATE TABLE oturumlar (sid TEXT PRIMARY KEY, kullanici_id INTEGER);
"""

KAYNAK = '''# uygulama.py — @@AD@@ giriş ve oturum (laboratuvar kopyası)
@@ICE_AKTAR@@
@@MODUL_DURUMU@@
FORM = ("<form method='post' action='@@GIRIS@@'><input name='kullanici'> "
        "<input name='parola' type='password'> <button>Giriş</button></form>")


def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def isle(istek, db):
    if istek.path == "@@GIRIS@@":
        if istek.method != "POST":
            return 200, {}, sayfa("Giriş", FORM)
        ad = istek.form.get("kullanici", "")
        parola = istek.form.get("parola", "")
@@LIMIT_KONTROL@@        k = db.execute("SELECT id, ad, parola FROM kullanicilar WHERE ad = ?", (ad,)).fetchone()
@@HATA_DALI@@@@OTURUM@@
        return 302, {"Location": "@@PROFIL@@", "Set-Cookie": "oturum=" + sid + "; Path=/; HttpOnly"}, ""
    if istek.path == "@@PROFIL@@":
        sid = istek.cerez.get("oturum", "")
        kul = None
        if sid:
            kul = db.execute("SELECT k.ad, k.rol, k.notu FROM oturumlar o JOIN kullanicilar k "
                             "ON k.id = o.kullanici_id WHERE o.sid = ?", (sid,)).fetchone()
        if kul is None:
            return 302, {"Location": "@@GIRIS@@"}, ""
        notu = "<p>Yönetici notu: %s</p>" % kul["notu"] if kul["rol"] == "yonetici" else ""
        return 200, {}, sayfa("Profil", "<p>Merhaba %s (%s)</p>%s" % (kul["ad"], kul["rol"], notu))
    return 404, {}, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''


_limit_kontrol = o.giris_limit_kontrol
_hata_dali = o.giris_hata_dali


OTURUM_ACIK = '''        sid = hashlib.md5(k["ad"].encode()).hexdigest()
        db.execute("INSERT OR REPLACE INTO oturumlar VALUES (?, ?)", (sid, k["id"]))
'''
OTURUM_GUVENLI = '''        sid = secrets.token_hex(16)
        db.execute("INSERT INTO oturumlar VALUES (?, ?)", (sid, k["id"]))
'''


def kaynak(s: dict, token: bool = False, limit: bool = False, tekil: bool = False) -> str:
    v = s["v"]
    ice = ["import secrets" if token else "import hashlib"] + (["import time"] if limit else [])
    govde = (KAYNAK.replace("@@LIMIT_KONTROL@@", _limit_kontrol() if limit else "")
             .replace("@@HATA_DALI@@@@OTURUM@@", _hata_dali(tekil, limit) + (OTURUM_GUVENLI if token else OTURUM_ACIK)))
    return o.kaynak_doldur(govde, {
        "AD": s["musteri"]["ad"], "GIRIS": v["giris"], "PROFIL": v["profil"],
        "ICE_AKTAR": "\n".join(ice), "MODUL_DURUMU": "DENEMELER = {}   # ip -> başarısız deneme zamanları\n" if limit else "",
    })


def kaynak_guvenli(s: dict) -> str:
    return kaynak(s, token=True, limit=True, tekil=True)


# ---------------------------------------------------------------- günlük üretimi

def _satir(bicim: str, t, sonuc_ok: bool, ad: str, ip: str, giris: str, ua: str) -> str:
    z = t.strftime("%Y-%m-%d %H:%M:%S")
    if bicim == "A":
        return f"{z} LOGIN {'OK' if sonuc_ok else 'FAIL'} user={ad} ip={ip}"
    if bicim == "B":
        return f"{z} [auth] kullanici={ad} istemci={ip} sonuc={'basarili' if sonuc_ok else 'basarisiz'}"
    return f'{ip} - {ad} [{u.apache_zamani(t)}] "POST {giris} HTTP/1.1" {302 if sonuc_ok else 401} 512'


def gunluk_uret(rng: random.Random, s: dict) -> tuple:
    """(satırlar, saldırgan_ip, hedef_hesap, başarısız_sayısı)."""
    v = s["v"]
    gercek = [k["ad"] for k in s["kullanicilar"]]
    t0 = u.gun(rng) + timedelta(hours=rng.randint(8, 10))
    olaylar = []
    # gündüz: meşru kullanıcılar (iç IP'ler), arada hatalı parola denemeleri
    ic_ipler = {ad: u.ic_ip(rng) for ad in gercek}
    for t in u.zamanlar(rng, t0, rng.randint(26, 36), 40, 900):
        ad = rng.choice(gercek)
        ok = rng.random() > 0.12
        olaylar.append((t, ok, ad, ic_ipler[ad]))
    # gürültü: başka bir dış IP birkaç başarısız deneme yapıp bırakıyor
    gurultu_ip = u.dis_ip(rng)
    for t in u.zamanlar(rng, t0 + timedelta(hours=2), rng.randint(2, 4), 30, 200):
        olaylar.append((t, False, rng.choice(gercek), gurultu_ip))
    # gece: saldırgan, tek hesaba art arda deneme, sonunda başarı
    saldirgan = u.dis_ip(rng)
    while saldirgan == gurultu_ip:
        saldirgan = u.dis_ip(rng)
    hedef = s["admin"]["ad"]
    basarisiz = rng.randint(42, 88)
    tg = t0 + timedelta(hours=14, minutes=rng.randint(0, 50))
    for t in u.zamanlar(rng, tg, basarisiz + 1, 1, 3):
        olaylar.append((t, False, hedef, saldirgan))
    son = max(olaylar, key=lambda x: x[0])
    olaylar.remove(son)
    olaylar.append((son[0], True, hedef, saldirgan))
    olaylar.sort(key=lambda x: x[0])
    ua = "python-requests/2.31.0"
    satirlar = [_satir(v["bicim"], t, ok, ad, ip, v["giris"], ua) for t, ok, ad, ip in olaylar]
    return satirlar, saldirgan, hedef, basarisiz


# ---------------------------------------------------------------- senaryo

def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    adlar = u.isimler(rng, 8)
    admin = {"ad": "yonetici_" + rng.choice(["deniz", "kaya", "toprak", "yildiz"]), "parola": u.parola(rng),
             "rol": "yonetici", "notu": u.bayrak(rng, "tahmin_edilen_oturum")}
    kullanicilar = [
        {"ad": adlar[0], "parola": u.parola(rng), "rol": "kullanici", "notu": ""},     # oyuncu
        {"ad": adlar[1], "parola": u.parola(rng), "rol": "kullanici", "notu": ""},
        {"ad": adlar[2], "parola": u.parola(rng), "rol": "kullanici", "notu": ""},
        admin,
    ]
    sahte = adlar[3:7]
    adaylar = [k["ad"] for k in kullanicilar] + sahte
    rng.shuffle(adaylar)
    s = {"vaka": f"{m['ad']} — {v['etiket']} girişi", "musteri": m, "v": v, "port": port,
         "kullanicilar": kullanicilar, "admin": admin, "adaylar": adaylar}
    s["gunluk_tohum"] = rng.randint(1, 10**9)
    satirlar, saldirgan, hedef, sayi = gunluk_uret(random.Random(s["gunluk_tohum"]), s)
    s.update({"saldirgan": saldirgan, "hedef": hedef, "basarisiz": sayi, "gunluk": satirlar})
    s["metin"] = {
        "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}", "giris": v["giris"],
        "profil": v["profil"], "demo_k": kullanicilar[0]["ad"], "demo_p": kullanicilar[0]["parola"],
        "admin_adi": admin["ad"],
    }
    s["cevaplar"] = {
        "saldirgan": saldirgan, "basarisiz": sayi, "hesap": hedef,
        "gercek": [k["ad"] for k in kullanicilar], "bayrak": admin["notu"],
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    tablo = [(i + 1, k["ad"], k["parola"], k["rol"], k["notu"]) for i, k in enumerate(s["kullanicilar"])]
    admin_id = len(tablo)
    oturum = [(hashlib.md5(s["admin"]["ad"].encode()).hexdigest(), admin_id)]   # yöneticinin açık duran eski oturumu
    o.db_olustur(lab / "uygulama.db", SEMA, {"kullanicilar": tablo, "oturumlar": oturum})
    u.yaz(lab / "uygulama.py", kaynak(s))
    u.yaz(lab / "giris_kayit.log", "\n".join(s["gunluk"]) + "\n")
    u.yaz(lab / "adaylar.txt", "\n".join(s["adaylar"]) + "\n")
    t = s["kullanicilar"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['etiket']} laboratuvar kopyası (veriler kurgusal)\n\n"
          f"Adres        : http://127.0.0.1:{s['port']}\n"
          f"Giriş        : POST {v['giris']} (alanlar: kullanici, parola); profil: {v['profil']}\n"
          f"Test hesabın : {t['ad']}  /  {t['parola']}\n\n"
          "giris_kayit.log  uygulamanın giriş günlüğü (bir günlük)\n"
          "adaylar.txt      bir sızma testi ekibinin denediği kullanıcı adı adayları (hepsi gerçek değil)\n"
          "uygulama.py      kaynak; 6., 7. ve 8. görevlerde düzeltilecek (sunucu dosyayı kendisi yeniden yükler)\n")


def servis(s: dict, lab: Path, dur) -> None:
    o.servis_calis(s["port"], lab, dur)


# ---------------------------------------------------------------- kontroller

def _sifir_ips():
    return iter(f"203.0.113.{i}" for i in range(100, 250))


def _token_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    a, c = s["kullanicilar"][0], s["kullanicilar"][1]

    def f(d):
        ips = _sifir_ips()
        belirtecler = {}
        for tekrar in range(2):
            for k in (a, c):
                y, cerez = d.giris(v["giris"], {"kullanici": k["ad"], "parola": k["parola"]}, ip=next(ips))
                hata = o.cokme_sonucu(y, "giriş")
                if hata:
                    return hata
                t = cerez.get("oturum", "")
                if y.kod not in (200, 302) or not t:
                    return Sonuc(False, f"`{k['ad']}` ile giriş artık `oturum` çerezi vermiyor (durum {y.kod}); düzeltme girişi bozmuş.", yakin=True)
                belirtecler[(k["ad"], tekrar)] = t
        t1 = belirtecler[(a["ad"], 0)]
        if len(t1) < 16:
            return Sonuc(False, f"Oturum kimliği (`{t1}`) çok kısa; rastgele ve en az 16 karakter (128 bit) olmalı.", yakin=True)
        if t1 == hashlib.md5(a["ad"].encode()).hexdigest() or a["ad"] in t1 or re.fullmatch(r"\d+", t1):
            return Sonuc(False, "Oturum kimliği hâlâ kullanıcı adından türetiliyor (ya da düz bir sayı). `md5(kullanıcı_adı)` gibi "
                                "bir değer, adı bilen herkesin hesaplayabileceği bir değerdir. Rastgele üret: `secrets.token_hex(16)`.", yakin=True)
        if belirtecler[(a["ad"], 0)] == belirtecler[(a["ad"], 1)]:
            return Sonuc(False, "Aynı kullanıcı iki kez giriş yapınca aynı oturum kimliğini alıyor. Her girişte yeni, rastgele "
                                "bir kimlik üretilmeli.", yakin=True)
        if len(set(belirtecler.values())) != 4:
            return Sonuc(False, "İki kullanıcının oturum kimlikleri çakışıyor.", yakin=True)
        p = d.get(v["profil"], cerez={"oturum": t1})
        if p.kod != 200 or a["ad"] not in p.govde:
            return Sonuc(False, "Yeni oturum kimliğiyle profil sayfası açılmıyor; kimlik veritabanına yazılmalı ve profil onu okuyabilmeli.", yakin=True)
        sahte = d.get(v["profil"], cerez={"oturum": hashlib.md5(c["ad"].encode()).hexdigest()})
        if sahte.kod == 200:
            return Sonuc(False, "Kullanıcı adından hesaplanan eski tip çerez hâlâ bir oturum açıyor.", yakin=True)
        return Sonuc(True, "Oturum kimlikleri artık `secrets.token_hex(16)` ile rastgele, her girişte yeni ve tahmin edilemez. "
                           "Kullanıcı adını bilmek oturumu hesaplamaya yetmiyor.")

    return o.deneme_calistir(b, f)


def _limit_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    a, c = s["kullanicilar"][0], s["kullanicilar"][1]
    hedef = s["admin"]

    def f(d):
        y, _ = d.giris(v["giris"], {"kullanici": a["ad"], "parola": "yanlis1"}, ip="203.0.113.201")
        y, cerez = d.giris(v["giris"], {"kullanici": a["ad"], "parola": "yanlis2"}, ip="203.0.113.201")
        y, cerez = d.giris(v["giris"], {"kullanici": a["ad"], "parola": a["parola"]}, ip="203.0.113.201")
        hata = o.cokme_sonucu(y, "iki hatadan sonra doğru parola")
        if hata:
            return hata
        if y.kod not in (200, 302):
            return Sonuc(False, f"İki yanlış denemeden sonra doğru parolayla bile giriş engelleniyor (durum {y.kod}). Sınır çok sıkı: "
                                "meşru kullanıcılar da yanlış yazabilir (örneğin 5 başarısız denemeden sonra engelle).", yakin=True)
        durumlar = []
        for i in range(12):
            y, _ = d.giris(v["giris"], {"kullanici": hedef["ad"], "parola": f"deneme{i}"}, ip="203.0.113.202")
            hata = o.cokme_sonucu(y, f"{i + 1}. başarısız deneme")
            if hata:
                return hata
            durumlar.append(y.kod)
        if any(k in (200, 302) for k in durumlar):
            return Sonuc(False, "Yanlış parola ile giriş başarılı görünüyor; uygulamanın parola denetimi bozulmuş.", yakin=True)
        engel = next((i for i, k in enumerate(durumlar) if k in (423, 429, 403)), None)
        if engel is None:
            return Sonuc(False, f"12 başarısız denemenin hiçbirinde engel yok (durumlar: {sorted(set(durumlar))}). Aynı IP'den arka arkaya "
                                "başarısız girişi sayıp sınırı aşınca 429 (Too Many Requests) dönmelisin.", yakin=True)
        if engel < 2:
            return Sonuc(False, f"Engel çok erken başlıyor ({engel + 1}. denemede). Meşru kullanıcı birkaç kez yanlış yazabilir; "
                                "sınırı en az 3-5 deneme olarak ayarla.", yakin=True)
        y, _ = d.giris(v["giris"], {"kullanici": c["ad"], "parola": c["parola"]}, ip="203.0.113.203")
        if y.kod not in (200, 302):
            return Sonuc(False, f"Başka bir IP'den, başka bir kullanıcının doğru girişi de engelleniyor (durum {y.kod}). "
                                "Engel saldırganı hedeflemeli, herkesi değil.", yakin=True)
        return Sonuc(True, f"Giriş hız sınırlı: {engel + 1}. başarısız denemeden sonra {durumlar[engel]} dönüyor, meşru "
                           "kullanıcılar etkilenmiyor. Saniyede yüzlerce deneme artık imkânsız; saldırı saatlerden yıllara uzar.")

    return o.deneme_calistir(b, f)


def _mesaj_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    a = s["kullanicilar"][0]

    def f(d):
        y1, _ = d.giris(v["giris"], {"kullanici": a["ad"], "parola": "kesinlikle_yanlis"}, ip="203.0.113.211")
        y2, _ = d.giris(v["giris"], {"kullanici": "boyle_biri_yok", "parola": "kesinlikle_yanlis"}, ip="203.0.113.212")
        for y, ne in ((y1, "var olan kullanıcı"), (y2, "olmayan kullanıcı")):
            hata = o.cokme_sonucu(y, ne)
            if hata:
                return hata
        if y1.kod != y2.kod or y1.govde != y2.govde:
            return Sonuc(False, "Var olan ve olmayan kullanıcı için cevaplar hâlâ farklı (durum ya da metin). Saldırgan farkı "
                                "okuyup hangi kullanıcıların gerçek olduğunu öğrenir. İki durumda da aynı genel mesajı ver: "
                                "\"Kullanıcı adı veya parola hatalı.\"", yakin=True)
        if y1.kod != 401:
            return Sonuc(False, f"Hatalı girişte 401 bekliyordum, {y1.kod} geldi.", yakin=True)
        y, cerez = d.giris(v["giris"], {"kullanici": a["ad"], "parola": a["parola"]}, ip="203.0.113.213")
        if y.kod not in (200, 302) or not cerez.get("oturum"):
            return Sonuc(False, "Doğru bilgilerle giriş bozulmuş.", yakin=True)
        return Sonuc(True, "Hatalı girişte artık tek tip mesaj dönüyor: hangi kullanıcıların var olduğu sızmıyor.")

    return o.deneme_calistir(b, f)


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    for satir in s["gunluk"]:
        if g in satir and g != beklenen:
            return "Bu IP günlükte birkaç başarısız deneme yapmış ama başka biri çok daha fazlasını yapmış. IP'lere göre say."
    return None


def _sayi_hata(g, beklenen, b):
    if g == str(int(beklenen) + 1):
        return "Saldırganın son denemesi BAŞARILI: başarısızları sayarken onu dahil etme."
    if g == str(int(beklenen) - 1):
        return "Bir başarısız denemeyi atladın; filtrenin tam olduğundan emin ol."
    return None


def _hesap_hata(g, beklenen, b):
    if g == b.senaryo["kullanicilar"][0]["ad"]:
        return "Bu senin test hesabın. Saldırganın IP'sinin BAŞARILI girdiği hesabı ara."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, v = s["metin"]["url"], s["v"]
    o.hazir_bekle(url + v["giris"])
    ip_satiri = o.sh("grep -E 'FAIL|basarisiz| 401 ' giris_kayit.log | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | "
                     "sort | uniq -c | sort -nr | head -1", lab).split()
    sayi, ip = int(ip_satiri[0]), ip_satiri[1]
    basarili = o.sh(f"grep -F {ip} giris_kayit.log | grep -E 'OK|sonuc=basarili| 302 '", lab)
    hesap = re.search(r"user=(\w+)|kullanici=(\w+)|- (\w+) \[", basarili)
    hesap = next(g for g in hesap.groups() if g)
    gercek = []
    for ad in o.sh("cat adaylar.txt", lab).split():
        cevap = o.sh(f"curl -s -d 'kullanici={ad}&parola=yanlis_parola' {url}{v['giris']}", lab)
        if "Parola hatalı" in cevap:
            gercek.append(ad)
    s_ad = next(ad for ad in gercek if ad.startswith("yonetici_"))
    ozet = o.sh(f"printf %s {s_ad} | md5sum | cut -d' ' -f1", lab).strip()
    profil = o.sh(f"curl -s -b oturum={ozet} {url}{v['profil']}", lab)
    bayrak = re.search(r"FLAG\{[^}]+\}", profil).group(0)
    (lab / "uygulama.py").write_text(kaynak_guvenli(s), encoding="utf-8")
    secmeli = SEVIYE.gorevler[8].kontrol.cevabi_goster(Baglam(s, lab, 9))[0]
    return {1: ip, 2: str(sayi), 3: hesap, 4: " ".join(gercek), 5: bayrak, 6: "", 7: "", 8: "", 9: secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Giriş sistemi: ön kapı", """
Giriş sistemleri bir uygulamanın **ön kapısıdır** ve sık sık zayıftır. Üç temel zayıflık bu bölümün konusu:

- **Brute-force koruması yok:** sınırsız parola denemesi (Cilt 1 ve 3'te logda gördüğün saldırı).
- **Kullanıcı sayımı** (enumeration): "kullanıcı yok" ile "parola yanlış" mesajları farklıysa hangi hesapların gerçek olduğu sızar.
- **Zayıf oturum kimliği:** tahmin edilebilen çerez, parolayı hiç bilmeden oturum açtırır.

Önce günlüğe bak; uygulama her girişi kaydediyor:
""", komut="head -6 giris_kayit.log", sonra="""
Her satır bir giriş denemesi: zaman, sonuç (başarılı/başarısız), kullanıcı adı ve IP adresi.
Cilt 3'teki log avcısını hatırla: sorunun cevabı bu satırlarda saklı.
"""),
    Adim("Günlükte kim çok konuşuyor?", """
Bir saldırı tek bir IP'den gelen **çok sayıda** istek olarak görünür. Cilt 1'deki boru hattı alışkanlığı:
IP adreslerini ayıkla, say, çoktan aza sırala:
""", komut="grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' giris_kayit.log | sort | uniq -c | sort -nr | head -3",
         sonra="""
Bu IP'ler **tüm** kayıtlara göre sıralı. Görevde yalnızca **başarısız** girişleri sayacaksın; satırları
önce `grep` ile süzeceksin. Bir IP'nin kısa sürede onlarca başarısız denemeyi aynı hesaba yapması
brute-force'un imzasıdır; günlükteki saniye aralıklarına dikkat et: insan bu hızda yazamaz.
"""),
    Adim("Kullanıcı sayımı: var olan kullanıcı", """
Şimdi uygulamanın kendisine bak. Önce **gerçek** bir kullanıcı adıyla, yanlış parola dene:
""", komut="curl -s -d 'kullanici=<<demo_k>>&parola=yanlis' <<url>><<giris>>", sonra="""
Cevap "Parola hatalı". Uygulama sana "bu kullanıcı var, ama parola yanlış" dedi.
"""),
    Adim("Kullanıcı sayımı: olmayan kullanıcı", """
Şimdi hiç var olmayan bir ad dene:
""", komut="curl -s -d 'kullanici=boyle_biri_yok&parola=yanlis' <<url>><<giris>>", sonra="""
Bu kez "Kullanıcı bulunamadı". İki mesajın farkı, saldırgana **hangi kullanıcı adlarının gerçek olduğunu**
söyler: bir kelime listesiyle (adaylar.txt) hızla geçerli hesapları listeleyebilir. Doğru tasarım iki
durumda da aynı mesajı verir: "Kullanıcı adı veya parola hatalı."
"""),
    Adim("Oturum çerezine bak", """
Giriş yap ve çerezi yakala:
""", komut="curl -si -d 'kullanici=<<demo_k>>&parola=<<demo_p>>' <<url>><<giris>> | grep -i set-cookie", sonra="""
`oturum=` ardından 32 karakterlik rastgele görünen bir değer. Peki gerçekten rastgele mi? Bir sonraki adımda bu
değerle kullanıcı adının arasında bir ilişki var mı diye bakacağız.
"""),
    Adim("Çerez neden tahmin edilebilir?", """
Kullanıcı adının MD5 özetini (hash) hesapla ve çerezle karşılaştır. `printf %s` satır sonu eklemez; `md5sum` özeti çıkarır:
""", komut="printf %s <<demo_k>> | md5sum", sonra="""
Çerezin aynısı! Oturum kimliği **rastgele değil, kullanıcı adından hesaplanıyor**. Kullanıcı adını bilen herkes
çerezi hesaplayabilir; parolaya gerek kalmaz. Bu, oturum çalma (session hijacking) için eksiksiz bir
tarif. (MD5 bir hash'tir, rastgelelik kaynağı değil.) Doğru çözüm: her girişte **kriptografik olarak rastgele**
bir kimlik üretmek (`secrets.token_hex(16)`, 128 bit).
"""),
    Adim("Savunma özeti", """
Üç düzeltmeyi `uygulama.py` içinde yapacaksın:

1. **Rastgele oturum kimliği:** `secrets.token_hex(16)`; her girişte yenisi.
2. **Hız sınırlama (rate limiting):** aynı IP'den 5 başarısız denemeden sonra 429 (Too Many Requests).
3. **Tek tip hata mesajı:** "Kullanıcı adı veya parola hatalı."

Ek olarak **MFA** (çok faktörlü doğrulama): parolaya ek ikinci bir faktör (telefondaki kod, uygulama onayı)
ister; çalınmış bir parola tek başına işe yaramaz. Kodu görmek için:
""", komut="grep -n 'md5\\|Parola hatalı\\|bulunamadı' uygulama.py", sonra="""
Bu satırlar düzeltmen gereken yerler. Kitabın dediği gibi: zayıf parola + brute-force koruması yokluğu +
kullanıcı sayımı birleşince saldırgan önce geçerli kullanıcıları listeler, sonra zayıf parolaları dener
ve içeri girer. Güvenlik katmanlıdır; tek bir önlem yetmez.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`giris_kayit.log` içinde en çok **başarısız** giriş denemesi yapan IP adresi hangisi? (Saldırganın IP'si.)",
          IP("saldirgan", sik_hatalar=_ip_hata),
          ("Başarısız satırları süz, sonra IP'lere göre say.",
           "`grep -E 'FAIL|basarisiz| 401 ' giris_kayit.log | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | sort | uniq -c | sort -nr | head`",
           "Çıktıdaki en üstteki satırın IP'si (sayıdan sonraki sütun)."),
          puan=30, baslik="Saldırganın IP'si"),
    Gorev("Bu IP kaç **başarısız** giriş denemesi yaptı? (Son, başarılı girişi sayma.)",
          Sayi("basarisiz", sik_hatalar=_sayi_hata),
          ("Aynı süzgeç, yalnızca sayıya bak.",
           "Önceki komutun sayı sütunu zaten bunu veriyor; `grep -F IP giris_kayit.log | grep -cE 'FAIL|basarisiz| 401 '` de olur.",
           "`grep -F <IP> giris_kayit.log | grep -cE 'FAIL|basarisiz| 401 '`"),
          puan=25, baslik="Kaç deneme"),
    Gorev("Aynı IP'nin **başarılı** girdiği hesap hangisi? (Saldırganın ele geçirdiği hesap.)",
          Metin("hesap", sik_hatalar=_hesap_hata, bicim="kullanıcı adı"),
          ("Başarılı satır, saldırganın son satırıdır.",
           "`grep -F IP giris_kayit.log | tail -1`",
           "Son satırdaki kullanıcı adı alanı."),
          puan=25, baslik="Ele geçirilen hesap"),
    Gorev("`adaylar.txt` içindeki adaylardan hangileri **gerçek** kullanıcı? Uygulamanın verdiği iki farklı hata mesajından "
          "yararlan (yanlış parolayla dene; \"Parola hatalı\" diyenler gerçektir).",
          Kume("gercek", bicim="gerçek kullanıcı adları, boşlukla ayrılmış"),
          ("Aday listesini tek tek uygulamaya sormalısın.",
           "`for a in $(cat adaylar.txt); do echo -n \"$a: \"; curl -s -d \"kullanici=$a&parola=yanlis\" <<url>><<giris>> | grep -o 'Parola hatalı\\|bulunamadı'; done`",
           "\"Parola hatalı\" yazanlar gerçek, \"Kullanıcı bulunamadı\" yazanlar sahte."),
          puan=30, baslik="Kullanıcı sayımı"),
    Gorev("Oturum kimliği kullanıcı adından hesaplanıyor. Gerçek kullanıcılar arasındaki **yönetici** (`yonetici_...`) hesabı "
          "için çerezi, parolasını bilmeden hesapla (`oturum=` değeri) ve `<<profil>>` sayfasındaki yönetici notunda bayrağı bul. "
          "(Yönetici sistemde açık bir oturuma sahip.)",
          Bayrak("bayrak"),
          ("Çerezin nasıl üretildiğini 6. adımda gördün.",
           "`printf %s KULLANICI_ADI | md5sum | cut -d' ' -f1` ile çerezi hesapla; `curl -s -b oturum=DEĞER <<url>><<profil>>`.",
           "`curl -s -b oturum=$(printf %s <yönetici_adı> | md5sum | cut -d' ' -f1) <<url>><<profil>> | grep -o 'FLAG{[^}]*}'`"),
          puan=35, baslik="Tahmin edilen oturum"),
    Gorev("Oturum kimliğini **rastgele** ve her girişte yeni üret (`secrets.token_hex(16)` ve `INSERT`). `uygulama.py`'de "
          "`hashlib.md5(...)` kullanılan yeri düzelt, gerekirse `import secrets` ekle. Kaydet ve `cevap 6` yaz.",
          Durum(_token_denetle, "```\nimport secrets\n...\nsid = secrets.token_hex(16)\ndb.execute(\"INSERT INTO oturumlar VALUES (?, ?)\", (sid, k[\"id\"]))\n```"),
          ("Çerez değerini üreten satırı bul; adından hesaplanmamalı.",
           "`secrets` modülü kriptografik rastgele üretir. `secrets.token_hex(16)` 32 karakterlik bir dizge verir.",
           "`sid = secrets.token_hex(16)` ve `db.execute(\"INSERT INTO oturumlar VALUES (?, ?)\", (sid, k[\"id\"]))`; `import hashlib` yerine `import secrets`."),
          puan=40, baslik="Rastgele oturum"),
    Gorev("Giriş için **hız sınırlama** ekle: aynı IP'den 5 başarısız denemeden sonra giriş 429 dönsün (en azından ilk 2 hatalı "
          "denemede engel olmamalı, başka IP'ler etkilenmemeli). `uygulama.py`'de bir sözlükte (`DENEMELER`) IP başına "
          "başarısız deneme zamanlarını tut. Kaydet ve `cevap 7` yaz.",
          Durum(_limit_denetle, "```\nDENEMELER = {}\n...\nsimdi = time.time()\nDENEMELER[istek.ip] = [t for t in DENEMELER.get(istek.ip, []) if simdi - t < 300]\n"
                "if len(DENEMELER[istek.ip]) >= 5:\n    return 429, {...}, sayfa(...)\n...\n# başarısız her denemede:\nDENEMELER.setdefault(istek.ip, []).append(time.time())\n```"),
          ("Sınır, başarısız denemelerin sayısına bağlı; sayacı bir yerde tutmalısın.",
           "Modül düzeyinde `DENEMELER = {}` tanımla; giriş başında IP'nin son 5 dakikadaki başarısız sayısına bak; eşiği geçtiyse `return 429, ...`; her başarısız denemede kaydet.",
           "Başarısız dallarına `DENEMELER.setdefault(istek.ip, []).append(time.time())`; kontrol: `len(...) >= 5` ise `return 429, {\"Retry-After\": \"300\"}, sayfa(...)`."),
          puan=50, baslik="Hız sınırlama"),
    Gorev("Kullanıcı sayımını kapat: kullanıcı adı yanlış da olsa parola yanlış da olsa **aynı** durum kodu ve **aynı** mesajı "
          "dön (örn. \"Kullanıcı adı veya parola hatalı.\"). Kaydet ve `cevap 8` yaz.",
          Durum(_mesaj_denetle, "```\nif k is None or k[\"parola\"] != parola:\n    return 401, {}, sayfa(\"Giriş\", \"<p>Kullanıcı adı veya parola hatalı.</p>\" + FORM)\n```"),
          ("Şu an iki ayrı `if` ve iki ayrı mesaj var.",
           "İki koşulu tek `if`te birleştir (`k is None or ...`) ve tek bir mesaj ver.",
           "`if k is None or k[\"parola\"] != parola:` sonra tek `return 401, ...` genel mesajla."),
          puan=30, baslik="Tek tip mesaj"),
    Gorev("Saldırgan yöneticinin parolasını (zayıf bir parola) başarıyla tahmin etti. Hangi ek önlem, çalınmış ya da tahmin edilmiş "
          "tek başına bir parolayı büyük ölçüde değersiz kılar?",
          Secmeli([
              ("Çok faktörlü doğrulama (MFA): parolaya ek ikinci bir faktör (telefondaki kod) ister",
               "Doğru. Saldırganın parolası olsa bile ikinci faktörü olmadığı için giriş yapamaz."),
              ("Parolayı her ay değiştirmeye zorlamak, çünkü yeni parola eskisinin yerini alır",
               "Zorunlu sık değişim çoğu zaman zayıf, öngörülebilir parolalar üretir; çalınan parolayı tek başına değersiz kılmaz."),
              ("Giriş sayfasının rengini ve adresini sık sık değiştirmek",
               "Görünümü değiştirmek saldırganı durdurmaz; parola doğruysa giriş yapılır."),
              ("Parolaları büyük harfle yazmayı zorunlu kılmak, çünkü büyük harfler deneme sayısını azaltır",
               "Karakter kuralları tek başına yetersizdir; asıl çözüm ikinci bir kanıt istemektir."),
          ]),
          ("Parola dışında bir şey istenebilir mi: \"bildiğin\", \"sahip olduğun\", \"olduğun\"?",
           "Bölüm metnindeki son alıştırmaya bak.",
           "Çok faktörlü doğrulama."),
          puan=20, baslik="MFA"),
]


SEVIYE = Seviye(
    kimlik="c05b07",
    cilt=5,
    bolum=7,
    baslik="Kimlik Doğrulama ve Oturum Açıkları",
    brifing="""
Deniz bir günlük dosyasını ekranına çekiyor: "Sabaha karşı tek bir kaynaktan arka arkaya
başarısız girişler, sonra bir başarılı giriş. Klasik."

"**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>` adresinde, giriş günlüğü
`giris_kayit.log` içinde. Test hesabın `OKUBENI.txt` dosyasında."

Selin üç soru bırakıyor: "Saldırganı günlükten bul. Uygulamanın saldırıya neden açık olduğunu üç yönden
çıkar: kullanıcı sayımı, tahmin edilebilir oturum, hız sınırı yok. Sonra üçünü de kodda kapat. Bu, kitabın
zincirinin ilk halkası: küçük açıklar birleşince ön kapı açılır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Kimlik doğrulama açıkları zincirin ilk halkasıdır. Kullanıcı sayımı saldırgana hangi hesapların var
olduğunu söyler, hız sınırı olmayan giriş ona sınırsız deneme hakkı verir, tahmin edilebilir oturum kimliği ise
parola gerekmeden içeri sokar. Tek başına küçük görünen bu üçü birleşince tam erişim olur. Savunma katmanlıdır:
tek tip hata mesajı, hız sınırlama (ve gerekirse hesap kilitleme/CAPTCHA), her girişte yeni kriptografik rastgele
oturum kimliği ve en önemlisi çok faktörlü doğrulama. Tespit tarafında, Cilt 3'te yazdığın log avcısı tam olarak
bu günlükte işe yarar: aynı IP'den kısa sürede çok sayıda başarısız giriş, alarm üretmesi gereken bir imzadır.
""",
    gercek_hayat="""
- **Uber 2022:** Bir saldırgan, bir çalışanın parolasını edindikten sonra çok faktörlü doğrulama onay istekleriyle
  çalışanı bunalttı (MFA yorgunluğu) ve sosyal mühendislikle onayı aldı. Ders: MFA tek başına değil, onay
  isteklerinin sınırlandırılması ve kullanıcı eğitimiyle birlikte düşünülmeli. Tespit: bir kullanıcının kısa sürede
  çok sayıda MFA isteği alması anormal bir imzadır.
- **Parola doldurma (credential stuffing):** Başka sitelerden sızan kullanıcı adı/parola çiftleri otomatik olarak
  denenir; pek çok kuruluşta başarılı girişlerin önemli kısmı bu yolla olur. Hız sınırlama, MFA, sızan parolaların
  engellenmesi ve anormal giriş izleme (yeni cihaz, olağandışı konum) bu saldırıyı zorlaştırır.
- **Oturum yönetimi temelleri:** Oturum kimlikleri sunucu tarafında kriptografik rastgele üretilmeli, girişten sonra
  yenilenmeli, `HttpOnly` ve `Secure` çerezle taşınmalı, çıkışta sunucuda geçersiz kılınmalıdır. Pek çok sızma
  testi raporunda tahmin edilebilir ya da yenilenmeyen oturum kimliği, kullanıcı sayımı ve hız sınırı eksikliği
  yan yana yer alır.
""",
    sure_hedef_dk=45,
)
