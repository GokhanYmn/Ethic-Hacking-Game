"""Cilt 5 · Bölüm 4 — Injection: SQL Enjeksiyonu.

Beceri: SQLi'nin tespiti (tek tırnakla hata, mantıksal koşulla davranış farkı), kitabın klasik
`' OR '1'='1` örneğinin neden çalıştığı (AND/OR öncelik sırası), etkisi (görünmemesi gereken kayıtlar),
düzeltme (parametreli sorgu) ve düzeltmenin doğrulanması.

Laboratuvar: küçük bir katalog + personel girişi uygulaması (lab/uygulama.py, sqlite). İki sorgu,
girdiyi metne yapıştırarak kuruluyor. Oyuncu açığı elle sınar (UNION/sqlmap yok, veri dökümü yok),
sonra iki sorguyu parametreli yapar. Kontrol, girdinin SQL metnine karışıp karışmadığına bakar.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c05_web import ortak as o

VAKALAR = [
    {"kod": "pazarix", "tablo": "urunler", "ara": "/kategori", "param": "k", "etiket": "ürün",
     "katalog": {"elektronik": [("Kablosuz kulaklık", "899 TL"), ("Akıllı saat", "1499 TL"), ("Powerbank 20.000 mAh", "649 TL")],
                 "ev": [("Hava fritözü", "2199 TL"), ("Robot süpürge", "7499 TL")],
                 "spor": [("Yoga matı", "349 TL"), ("Koşu bandı", "11990 TL"), ("Dambıl seti", "799 TL")]},
     "gizli": [("Tedarikçi maliyet listesi (dahili)", "gizli"), ("Personel indirim kodları (dahili)", "gizli"),
               ("Satıştan kalkan ürün (taslak)", "taslak")],
     "olay": "Pazarix'in kategori sayfası kampanya haftasında anlamsız hatalar verdi ve loglarda tek tırnaklı "
             "istekler görüldü. Tuncay Bey, sayfanın veritabanı sorgusunu nasıl kurduğunu incelememizi istiyor."},
    {"kod": "medora", "tablo": "doktorlar", "ara": "/bolum", "param": "ad", "etiket": "doktor",
     "katalog": {"kardiyoloji": [("Dr. Ayşe K.", "poliklinik 3"), ("Dr. Murat T.", "poliklinik 4")],
                 "ortopedi": [("Dr. Selin B.", "poliklinik 7"), ("Dr. Kerem A.", "poliklinik 8"), ("Dr. Elif Y.", "poliklinik 9")],
                 "dahiliye": [("Dr. Okan D.", "poliklinik 1"), ("Dr. Derya S.", "poliklinik 2"), ("Dr. Hakan Ç.", "poliklinik 5")]},
     "gizli": [("Acil nöbet çizelgesi (dahili)", "gizli"), ("Dr. Gizem P. (ayrılan personel)", "arşiv"),
               ("Yönetim kurulu randevuları (dahili)", "gizli")],
     "olay": "Medora Sağlık'ın bölüm sayfası, bir hasta yakını tarafından adrese eklenen garip karakterler yüzünden "
             "hata verdi. Dr. Aslı Hanım, sayfanın girdiyi nasıl işlediğini öğrenmek istiyor."},
    {"kod": "ferahbank", "tablo": "kampanyalar", "ara": "/kampanyalar", "param": "tur", "etiket": "kampanya",
     "katalog": {"kredi": [("İhtiyaç kredisi 0,99", "36 ay"), ("Konut kredisi", "120 ay")],
                 "kart": [("Market kartı iadesi", "%5"), ("Seyahat puanları", "2x"), ("Yakıt indirimi", "%3")],
                 "mevduat": [("Vadeli hesap", "%48"), ("Altın hesabı", "gram"), ("Döviz hesabı", "EUR")]},
     "gizli": [("Personel kredisi (dahili)", "gizli"), ("VIP müşteri oranları (dahili)", "gizli"),
               ("Yayından kalkan kampanya", "arşiv")],
     "olay": "Ferah Bank'ın kampanya sayfasında gece yarısı olağandışı hatalar vardı. Kaan Bey, sayfanın veritabanına "
             "nasıl sorduğunu ve gizli kampanyaların sızıp sızmadığını soruyor."},
    {"kod": "yesiltepe", "tablo": "ihaleler", "ara": "/ihaleler", "param": "durum", "etiket": "ihale",
     "katalog": {"acik": [("Çöp toplama aracı alımı", "ihale 12"), ("Park aydınlatma yenileme", "ihale 14")],
                 "sonuclandi": [("Yol asfaltlama 2025", "ihale 07"), ("Okul bakım onarım", "ihale 09"), ("Su sayacı alımı", "ihale 10")],
                 "planlanan": [("Kültür merkezi yapımı", "ihale 21"), ("Bisiklet yolu", "ihale 22"), ("Spor salonu", "ihale 23")]},
     "gizli": [("Teklif değerlendirme notları (dahili)", "gizli"), ("Personel atama listesi (dahili)", "gizli"),
               ("İptal edilen ihale (taslak)", "taslak")],
     "olay": "Yeşiltepe Belediyesi'nin ihale listesi, bir vatandaşın adres satırına yazdığı denemeden sonra hata "
             "gösterdi. Nurcan Hanım, sayfanın sorgusunu kontrol etmemizi istiyor."},
]

SEMA = """
CREATE TABLE @@TABLO@@ (id INTEGER PRIMARY KEY, ad TEXT, kategori TEXT, ek TEXT, yayinda INTEGER);
CREATE TABLE kullanicilar (id INTEGER PRIMARY KEY, ad TEXT, parola TEXT);
"""

KAYNAK = '''# uygulama.py — @@AD@@ katalog ve personel girişi (laboratuvar kopyası)
def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def isle(istek, db):
    if istek.path == "/":
        n = db.execute("SELECT COUNT(*) AS n FROM @@TABLO@@ WHERE yayinda = 1").fetchone()["n"]
        return 200, {}, sayfa("@@AD@@", "<p>Katalogda yayında %d kayıt var.</p><p>Kategoriler: @@LINKLER@@</p>"
                              "<p><a href='/giris'>Personel girişi</a></p>" % n)
    if istek.path == "@@ARA@@":
        deger = istek.sorgu.get("@@PARAM@@", "")
@@ARA_SORGUSU@@
        li = "".join("<li>%s — %s</li>" % (s["ad"], s["ek"]) for s in satirlar)
        return 200, {}, sayfa("@@ETIKET@@ listesi", "<ul>%s</ul><p>Sonuç sayısı: %d</p>" % (li, len(satirlar)))
    if istek.path == "/giris":
        if istek.method != "POST":
            return 200, {}, sayfa("Personel girişi", "<form method='post'><input name='kullanici'> "
                                  "<input name='parola' type='password'> <button>Giriş</button></form>")
        ad = istek.form.get("kullanici", "")
        parola = istek.form.get("parola", "")
@@GIRIS_SORGUSU@@
        if k is None:
            return 401, {}, sayfa("Personel girişi", "<p>Kullanıcı adı ya da parola hatalı.</p>")
        return 200, {}, sayfa("Panel", "<p>Hoş geldin, %s</p>" % k["ad"])
    return 404, {}, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''

ARA_ACIK = '''        sorgu = "SELECT ad, ek FROM @@TABLO@@ WHERE yayinda = 1 AND kategori = '" + deger + "' ORDER BY ad"
        satirlar = db.execute(sorgu).fetchall()'''
ARA_GUVENLI = '''        satirlar = db.execute("SELECT ad, ek FROM @@TABLO@@ WHERE yayinda = 1 AND kategori = ? ORDER BY ad",
                              (deger,)).fetchall()'''
GIRIS_ACIK = '''        sorgu = "SELECT ad FROM kullanicilar WHERE ad = '" + ad + "' AND parola = '" + parola + "'"
        k = db.execute(sorgu).fetchone()'''
GIRIS_GUVENLI = '''        k = db.execute("SELECT ad FROM kullanicilar WHERE ad = ? AND parola = ?", (ad, parola)).fetchone()'''


def kaynak(s: dict, guvenli: bool = False) -> str:
    v = s["v"]
    govde = KAYNAK.replace("@@ARA_SORGUSU@@", ARA_GUVENLI if guvenli else ARA_ACIK)
    govde = govde.replace("@@GIRIS_SORGUSU@@", GIRIS_GUVENLI if guvenli else GIRIS_ACIK)
    linkler = " ".join(f"<a href='{v['ara']}?{v['param']}={k}'>{k}</a>" for k in v["katalog"])
    return o.kaynak_doldur(govde, {"AD": s["musteri"]["ad"], "TABLO": v["tablo"], "ARA": v["ara"],
                                   "PARAM": v["param"], "ETIKET": v["etiket"].capitalize(), "LINKLER": linkler})


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    kat = rng.choice([k for k, r in v["katalog"].items() if len(r) >= 2])
    gorunen = sum(len(r) for r in v["katalog"].values())
    toplam = gorunen + len(v["gizli"])
    adlar = u.isimler(rng, 3)
    kullanicilar = [(adlar[0] + "_yonetici", u.parola(rng)), (adlar[1], u.parola(rng)), (adlar[2], u.parola(rng))]
    return {
        "vaka": f"{m['ad']} — {v['etiket']} sayfası sorgusu",
        "musteri": m, "v": v, "port": port, "kat": kat, "kullanicilar": kullanicilar,
        "gorunen": gorunen, "toplam": toplam,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}", "ara": v["ara"],
            "param": v["param"], "kat": kat, "etiket": v["etiket"],
            "test_k": kullanicilar[1][0], "test_p": kullanicilar[1][1],
        },
        "cevaplar": {
            "hata_kodu": 500,
            "normal": len(v["katalog"][kat]),
            "tumu": toplam,
            "gizli": toplam - gorunen,
            "motor": ["sqlite", "sqlite3"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    satirlar, i = [], 1
    for k, r in v["katalog"].items():
        for ad, ek in r:
            satirlar.append((i, ad, k, ek, 1))
            i += 1
    for ad, ek in v["gizli"]:
        satirlar.append((i, ad, "dahili", ek, 0))
        i += 1
    o.db_olustur(lab / "uygulama.db", o.kaynak_doldur(SEMA, {"TABLO": v["tablo"]}), {
        v["tablo"]: satirlar,
        "kullanicilar": [(n + 1, a, p) for n, (a, p) in enumerate(s["kullanicilar"])],
    })
    u.yaz(lab / "uygulama.py", kaynak(s))
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['etiket']} sayfası laboratuvar kopyası\n\n"
          f"Adres        : http://127.0.0.1:{s['port']}\n"
          f"Liste sayfası: {v['ara']}?{v['param']}={s['kat']}\n"
          f"Giriş        : POST /giris (alanlar: kullanici, parola)\n"
          f"Test hesabın : {s['kullanicilar'][1][0]}  /  {s['kullanicilar'][1][1]}\n\n"
          "Bu bölümde sqlmap kullanmıyoruz: açığı elle bulacak, kanıtını okuyacak ve kodda kapatacaksın.\n"
          "uygulama.py 7. görevde düzeltilecek; sunucu dosyayı kaydedince kendisi yeniden yükler.\n")


def servis(s: dict, lab: Path, dur) -> None:
    o.servis_calis(s["port"], lab, dur)


# ---------------------------------------------------------------- kontroller

def _sayi(govde: str):
    m = re.search(r"Sonuç sayısı: (\d+)", govde)
    return int(m.group(1)) if m else None


def _duzeltme_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    k, p = s["kullanicilar"][1]
    ham = "x' OR '1'='1"
    klasik = "' OR '1'='1"

    def f(d):
        y = d.get(v["ara"], sorgu={v["param"]: s["kat"]})
        hata = o.cokme_sonucu(y, "normal liste")
        if hata:
            return hata
        if y.kod != 200 or _sayi(y.govde) != s["cevaplar"]["normal"]:
            return Sonuc(False, f"Normal arama bozuldu: `{v['param']}={s['kat']}` için {s['cevaplar']['normal']} sonuç "
                                f"bekliyordum (durum {y.kod}, sayı {_sayi(y.govde)}).", yakin=True)
        for deger, ne in ((ham, "mantıksal koşullu"), ("'", "tek tırnaklı"), ("O'Neil", "kesme işaretli bir")):
            y = d.get(v["ara"], sorgu={v["param"]: deger})
            hata = o.cokme_sonucu(y, f"{ne} arama")
            if hata:
                return hata
            if y.kod != 200 or _sayi(y.govde) != 0:
                return Sonuc(False, f"`{deger}` değeri hâlâ sorgunun mantığını değiştiriyor: {_sayi(y.govde)} sonuç geldi "
                                    "(0 bekleniyor; böyle bir kategori yok). Girdi sorguya yapıştırılmamalı.", yakin=True)
            if any(deger in sql or (deger != "'" and "OR '1'='1" in sql) for sql, _ in y.sql):
                return Sonuc(False, f"Sonuç doğru ama `{deger}` hâlâ SQL metninin içine yapıştırılıyor. Kesme işaretlerini "
                                    "kaçırmak ya da filtrelemek yerine parametreli sorgu kullan: SQL'de `?`, değer ayrı bir demette.",
                             yakin=True)
        y, _ = d.giris("/giris", {"kullanici": k, "parola": p})
        if y.kod != 200 or k not in y.govde:
            return Sonuc(False, "Doğru kullanıcı adı ve parolayla giriş artık çalışmıyor; düzeltme girişi bozmuş.", yakin=True)
        for form, ne in (({"kullanici": klasik, "parola": klasik}, "iki"), ({"kullanici": k, "parola": ham}, "parola")):
            y, _ = d.giris("/giris", form)
            hata = o.cokme_sonucu(y, "mantıksal koşullu giriş")
            if hata:
                return hata
            if y.kod == 200:
                return Sonuc(False, f"Giriş formunun {ne} alanına mantıksal koşul yazınca hâlâ içeri giriliyor. "
                                    "Giriş sorgusunu da parametreli yap.", yakin=True)
            if any("OR '1'='1" in sql for sql, _ in y.sql):
                return Sonuc(False, "Giriş reddediliyor ama girdi hâlâ SQL metninin içine karışıyor. "
                                    "Parametreli sorgu kullan (`?`).", yakin=True)
        return Sonuc(True, "Hem arama hem giriş sorgusu parametreli: girdi artık yalnızca veri. Tek tırnak, kesme "
                           "işareti ve mantıksal koşul sorgunun yapısını değiştiremiyor; normal kullanım sağlam.")

    return o.deneme_calistir(b, f)


def _tumu_hata(g, beklenen, b):
    s = b.senaryo
    if g == str(s["cevaplar"]["gizli"]):
        return "Bu, görünmemesi gereken kayıtların sayısı (sonraki görevin cevabı). Burada koşul tümünü doğru yapınca gelen TOPLAM satır soruluyor."
    if g == str(s["cevaplar"]["normal"]):
        return "Bu, normal aramanın sonucu. Mantıksal koşul eklenince sayı değişmeli: `' OR '1'='1` ile dene."
    return None


def _gizli_hata(g, beklenen, b):
    s = b.senaryo
    if g == str(s["cevaplar"]["tumu"]):
        return "Bu toplam sayı. Ana sayfada \"yayında N kayıt\" yazıyor; toplamdan yayındakileri çıkar."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, v = s["metin"]["url"], s["v"]
    o.hazir_bekle(url + "/")

    def al(param_deger: str):
        return o.sh(f"curl -s -G --data-urlencode \"{v['param']}={param_deger}\" {url}{v['ara']}", lab)

    kod = o.sh(f"curl -s -o /dev/null -w '%{{http_code}}' -G --data-urlencode \"{v['param']}='\" {url}{v['ara']}", lab).strip()
    hata_sayfasi = al("'")
    motor = re.search(r"(sqlite3?)\.", hata_sayfasi).group(1)
    normal = _sayi(al(s["kat"]))
    tumu = _sayi(al("x' OR '1'='1"))
    yayinda = int(re.search(r"yayında (\d+) kayıt", o.sh(f"curl -s {url}/", lab)).group(1))
    (lab / "uygulama.py").write_text(kaynak(s, guvenli=True), encoding="utf-8")
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (6, 8)}
    return {1: kod, 2: motor, 3: str(normal), 4: str(tumu), 5: str(tumu - yayinda), 6: secmeli[6], 7: "", 8: secmeli[8]}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Enjeksiyon: girdi komuta dönüşür", """
**Enjeksiyon**, kullanıcı girdisinin bir komutun parçası olarak çalıştırılmasıdır. En klasik ve
en yıkıcı örneği **SQL enjeksiyonu** (SQLi): girdinin bir veritabanı sorgusuna karışması.
Uygulamanın sorgularını görelim; hepsi `SELECT` ile başlıyor:
""", komut="grep -n 'SELECT' uygulama.py", sonra="""
İki sorguda `" + deger + "` ve `" + ad + "` gibi parçalar var: sunucu, kullanıcıdan gelen metni
**doğrudan sorgu metnine yapıştırıyor**. Sorgu ile veri iç içe; işte açık bu.
"""),
    Adim("Normal kullanım", """
Önce uygulamanın normal çalışmasına bak: bir kategori iste. Sayfa "Sonuç sayısı" yazıyor:
""", komut="curl -s '<<url>><<ara>>?<<param>>=<<kat>>'", sonra="""
Sorgu şuna dönüştü: `... WHERE yayinda = 1 AND kategori = '<<kat>>' ORDER BY ad`. Tırnaklar
değerin sınırı; `yayinda = 1` ise sadece yayındaki kayıtları göstermesini sağlıyor.
"""),
    Adim("Tespit: tek tırnak", """
SQLi tespitinin klasik ilk adımı: değere bir **tek tırnak** ekle ve uygulamanın bozulup
bozulmadığına bak. Tırnak değerin sınırını kapatıyorsa sorgunun sözdizimi bozulur:
""", komut="""curl -s -G --data-urlencode "<<param>>='" <<url>><<ara>>""", sonra="""
**500** hatası ve ekranda sorgunun kendisi! Hata mesajı, sorgu parçası ve hangi veritabanı motoru
olduğu görünüyor. Cilt 1'deki log analizini hatırla: tek tırnaklı isteklerin 500 üretmesi
SQLi'nin işaretiydi. Savunma notu: bu kadar ayrıntıyı kullanıcıya göstermek de başlı başına bir bulgudur.
"""),
    Adim("Tespit: davranış farkı (doğru koşul)", """
Hata görmek tek kanıt değildir. İkinci yöntem: sorguya **her zaman doğru** bir koşul ekleyip
sonucun değişmediğini, **her zaman yanlış** bir koşulla ise değiştiğini göstermek.
Önce doğru koşul (`'1'='1`), sonuç normal sonuçla aynı olmalı:
""", komut="""curl -s -G --data-urlencode "<<param>>=<<kat>>' AND '1'='1" <<url>><<ara>>""", sonra="""
Aynı sonuç. Girdi sorguya karıştı ve ek koşul sessizce çalıştı.
"""),
    Adim("Tespit: davranış farkı (yanlış koşul)", """
Şimdi her zaman **yanlış** bir koşul (`'1'='2`):
""", komut="""curl -s -G --data-urlencode "<<param>>=<<kat>>' AND '1'='2" <<url>><<ara>>""", sonra="""
Sonuç sayısı 0'a düştü. İki isteğin farkı, girdinin sorguyu etkilediğinin **kanıtıdır**; bir
kayıt bile okumadan ve kimseye zarar vermeden. Gerçek testlerde de bu kanıt rapora yazılır.
"""),
    Adim("Etki: görünmemesi gereken kayıtlar", """
Şimdi bir adım ileri: koşulu **her satır için doğru** yapalım. Kategori sorgusu şöyle kuruluyor:

```
WHERE yayinda = 1 AND kategori = 'GIRDI'
```

Değer olarak `x' OR '1'='1` verilirse sorgu şuna döner: `WHERE yayinda = 1 AND kategori = 'x' OR '1'='1'`.
SQL'de **AND, OR'dan önce işlenir**: ifade `(yayinda = 1 AND kategori = 'x') OR '1'='1'` olur.
`'1'='1'` her zaman doğru olduğundan OR'un bir kolu doğrudur ve bütün koşul her satır için doğru çıkar;
`yayinda = 1` süzgeci **devre dışı** kalır:
""", komut="""curl -s -G --data-urlencode "<<param>>=x' OR '1'='1" <<url>><<ara>>""", sonra="""
Görünmemesi gereken (yayında olmayan, dahili) kayıtlar da listelendi. Bu, SQLi'nin **etkisi**:
uygulama sana göstermek istemediğini gösterdi. Bunun için tek bir veri satırı çalmana gerek kalmadı;
yalnızca koşulun mantığını değiştirdin.
"""),
    Adim("Kitabın klasiği: giriş formu", """
Kitap, giriş sorgusu `WHERE ad = 'GIRDI' AND parola = 'GIRDI2'` için aynı fikri `' OR '1'='1` ile gösterir.
İki alana da bunu yazarsan sorgu şu olur:

```
WHERE ad = '' OR '1'='1' AND parola = '' OR '1'='1'
```

AND önce işlenir, ama ifadede iki `OR '1'='1'` var: OR'un bir kolu her zaman doğru olduğundan bütün koşul
doğrudur ve sorgu bir kullanıcı döndürür; parola denetimi anlamsız kalır. (Bazı örnekler bunun yerine
sorgunun kalanını yok sayan bir yorum işareti kullanır; mantık aynıdır: girdi sorgunun yapısını değiştirir.)
Laboratuvardaki girişte dene:
""", komut="""curl -s --data-urlencode "kullanici=' OR '1'='1" --data-urlencode "parola=' OR '1'='1" <<url>>/giris""",
         sonra="""
Parolayı bilmeden "Hoş geldin" yazan bir sayfa: sorgunun döndürdüğü ilk kullanıcı olarak içeri girdin.
Gerçek işte bunu sqlmap gibi araçlar otomatikleştirir; yalnızca izinli hedeflerde kullanılır.
"""),
    Adim("Savunma: parametreli sorgu", """
SQLi'nin çözümü basit ve bilinir: **parametreli sorgu** (prepared statement). Sorgu metni sabit
kalır, değer ayrı bir yoldan gider; böylece girdi ne olursa olsun "veri" kalır, "komut" olamaz:

```
db.execute("SELECT ad, ek FROM ... WHERE yayinda = 1 AND kategori = ?", (deger,))
```

Python'un `sqlite3` modülünde `?` yer tutucudur, değerler bir demet (tuple) olarak ikinci argümandır.
**"Tehlikeli karakterleri filtrelemek" doğru çözüm değildir:** farklı kodlamalarla sürekli atlatılır.
""", komut="grep -n 'db.execute' uygulama.py", sonra="""
Düzeltmen gereken yerler bunlar: kategori sorgusu ve giriş sorgusu. Görevde ikisini de
parametreli yapacaksın; kontrol, girdinin SQL metnine karışıp karışmadığına bakacak.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Liste sayfasının `<<param>>` parametresine tek bir tırnak (`'`) gönder. Sunucu hangi durum kodunu veriyor?",
          Sayi("hata_kodu"),
          ("Tırnak, sorgudaki değerin sınırını bozar.",
           "`curl -s -o /dev/null -w \"%{http_code}\\n\" -G --data-urlencode \"<<param>>='\" <<url>><<ara>>`",
           "Cevap sunucu hatasıdır (5xx sınıfı); sayıyı komutun çıktısından oku."),
          puan=20, baslik="Tek tırnak"),
    Gorev("Aynı hata sayfasındaki ayrıntıya göre arka plandaki **veritabanı motoru** hangisi?",
          Metin(None, kabul=["sqlite", "sqlite3"], bicim="motor adı"),
          ("Hata sayfası mesajın hangi modülden geldiğini de gösterir.",
           "Tek tırnaklı isteğin cevabını oku: `curl -s -G --data-urlencode \"<<param>>='\" <<url>><<ara>>`",
           "`....OperationalError` önündeki modül adı motoru söyler."),
          puan=20, baslik="Hangi veritabanı"),
    Gorev("Normal arama: `<<ara>>?<<param>>=<<kat>>` sayfası kaç sonuç gösteriyor?",
          Sayi("normal"),
          ("Sayfanın altında bir sayı yazıyor.",
           "`curl -s '<<url>><<ara>>?<<param>>=<<kat>>'` ve \"Sonuç sayısı\" satırı.",
           "Satırdaki sayıyı yaz (listede kaç `li` varsa o)."),
          puan=15, baslik="Normal sonuç"),
    Gorev("Değere `x' OR '1'='1` göndererek koşulu her satır için doğru yap (kitabın klasik örneği). Sayfa kaç sonuç "
          "gösteriyor?",
          Sayi("tumu", sik_hatalar=_tumu_hata),
          ("Koşul her satır için doğruysa tablo hakkında ne söyleyebilirsin?",
           "`curl -s -G --data-urlencode \"<<param>>=x' OR '1'='1\" <<url>><<ara>>`",
           "\"Sonuç sayısı\" satırındaki sayı, tablodaki **tüm** kayıtların sayısıdır."),
          puan=30, baslik="Her zaman doğru"),
    Gorev("Az önceki sonuçta, normalde **görünmemesi gereken** (yayında olmayan) kaç kayıt da listelendi? "
          "İpucu: ana sayfa kaç kaydın yayında olduğunu söylüyor.",
          Sayi("gizli", sik_hatalar=_gizli_hata),
          ("Toplamı biliyorsun; yayındakileri bulursan farkı alırsın.",
           "`curl -s <<url>>/` ana sayfasında \"yayında N kayıt\" yazıyor.",
           "Tümü - yayında = görünmemesi gereken kayıt sayısı."),
          puan=30, baslik="Sızan kayıtlar"),
    Gorev("Kitabın örneğindeki `' OR '1'='1` girdisi (kullanıcı adı ve parola alanlarına yazılınca) neden parolayı bilmeden "
          "**giriş sağlar**?",
          Secmeli([
              ("`'1'='1'` her zaman doğrudur; OR'un bir kolu doğruysa bütün koşul doğrudur ve parola denetimi anlamını yitirir",
               "Doğru. Girdi sorgunun yapısına karışıp mantığını değiştirdi: tırnak sınırı kapattı, OR yeni bir koşul ekledi."),
              ("Veritabanı boş bir kullanıcı adını \"herkes\" olarak yorumladığı için tüm hesapları listeler",
               "SQL boş dizgeyi herkes saymaz; koşulun doğru çıkmasının sebebi eklenen OR ifadesidir."),
              ("Tek tırnak veritabanı bağlantısını kapattığı için kontrol atlanır ve yönetici girişi açılır",
               "Tırnak bağlantıyı kapatmaz; sorgunun metin sınırını bozar ve girdinin sorguya karışmasını sağlar."),
              ("Parolalar zaten düz metin olduğu için `'1'='1'` ifadesi gerçek parola gibi kabul edilir",
               "Parolanın nasıl saklandığı bu açığın nedeni değil; bütün koşulun mantığı OR yüzünden değişir."),
          ]),
          ("OR'un iki yanından biri doğruysa sonuç ne olur?",
           "Giriş adımındaki sorguyu yazıya dök: `ad = '' OR '1'='1' AND parola = '' OR '1'='1'`.",
           "`'1'='1'` her zaman doğru; OR yüzünden bütün ifade doğru çıkar."),
          puan=25, baslik="Neden çalışıyor"),
    Gorev("`uygulama.py` içindeki **iki** sorguyu (kategori listesi ve giriş) parametreli sorguya çevir. Kaydet ve `cevap 7` yaz. "
          "Normal arama ve giriş çalışmaya devam etmeli; tek tırnak, kesme işareti (`O'Neil`) ve mantıksal koşul artık "
          "sorgunun yapısını değiştirememeli.",
          Durum(_duzeltme_denetle,
                "```\nsatirlar = db.execute(\"SELECT ad, ek FROM ... WHERE yayinda = 1 AND kategori = ? ORDER BY ad\", (deger,)).fetchall()\n"
                "k = db.execute(\"SELECT ad FROM kullanicilar WHERE ad = ? AND parola = ?\", (ad, parola)).fetchone()\n```"),
          ("Sorgu metnine girdiyi `+` ile eklemek yerine, değerin yerine bir yer tutucu koyabilirsin.",
           "`sqlite3`'te yer tutucu `?`'dir ve değerler `db.execute(sorgu, (deger,))` biçiminde ikinci argümandır.",
           "`db.execute(\"... kategori = ? ORDER BY ad\", (deger,))` ve `db.execute(\"... ad = ? AND parola = ?\", (ad, parola))`; `+ deger +` parçalarını sil."),
          puan=50, baslik="Parametreli sorgu"),
    Gorev("SQLi'ye karşı \"tehlikeli karakterleri (örn. tek tırnak) silmek\" yerine neden parametreli sorgu kullanılır?",
          Secmeli([
              ("Filtreler farklı kodlamalarla atlatılır; parametreli sorgu girdiyi yapısal olarak \"veri\" tutar",
               "Doğru. Parametreli sorguda girdi hiçbir zaman sorgunun yapısına karışmaz; çözüm kök nedene iner."),
              ("Tek tırnak zararsız bir karakter olduğu için filtrelemek bir fayda sağlamaz",
               "Tek tırnak tehlikeli olabilir; asıl mesele, listeyi kimin tamamlayabileceği ve kodlamalarla atlatılabilmesi."),
              ("Parametreli sorgular veritabanını hızlandırdığı için güvenlik amacı ikincil kalır",
               "Hız ana neden değil; önemli olan girdiyle komutun yapısal olarak ayrılmasıdır."),
              ("Filtreleme yalnızca arama kutularında çalışır, giriş formlarında uygulanamaz",
               "Filtreleme her girdide uygulanabilir; sorun, güvenilir bir koruma olmaması."),
          ]),
          ("Bu bölümün uyarısı: filtreleme sürekli atlatılır.",
           "Bir filtre yazarsan her olası kodlamayı kapsadığını nasıl garanti edersin?",
           "Çözüm girdiyi temizlemek değil, sorgudan **ayırmaktır**."),
          puan=20, baslik="Neden filtre değil"),
]


SEVIYE = Seviye(
    kimlik="c05b04",
    cilt=5,
    bolum=4,
    baslik="Injection: SQL Enjeksiyonu",
    brifing="""
Selin, bir müşteri bildirimini ekrana yansıtıyor: "Sayfa tuhaf bir hata verdi ve loglarda tek
tırnaklı istekler var." Mert homurdanıyor: "Tek bir tırnak. Genelde her şey oradan başlar."

"**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>` adresinde. Liste sayfası
`<<ara>>?<<param>>=<<kat>>`, personel girişi `/giris`. Bu bölümde sqlmap ya da veri
dökümü yok: açığı **elle kanıtlayacak**, etkisini anlayacak ve **kodda kapatacaksın**."

Deniz son uyarıyı yapıyor: "Bu denemeler sadece bu laboratuvarda. Gerçek bir siteye tek bir
tırnak bile göndermek izinsiz erişim sayılabilir."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
SQLi, girdinin komuta dönüşmesidir: bir tek tırnak sorgunun sınırını bozar, bir `OR` koşulu
mantığını değiştirir. Saldırgan açığı hata mesajından ve "doğru/yanlış koşul" farkından
anlar; sonra kayıt okur, giriş denetimini atlar, en kötüsünde veritabanının tamamını boşaltır.
Savunma tek ve nettir: **parametreli sorgu**. Sorguyu ve veriyi ayrı tut; böylece filtre
listeleriyle yarışmak zorunda kalmazsın. Ayrıca kullanıcıya SQL hatasını ve sorguyu gösterme:
hatayı kendine logla, kullanıcıya genel bir mesaj ver.
""",
    gercek_hayat="""
- **SQL enjeksiyonu on yıllardır OWASP Top 10'un üst sıralarında:** Çözümü bilinmesine rağmen,
  tek bir denetimsiz sorgu yüzünden pek çok gerçek veri sızıntısında rol oynamıştır. Kök neden
  hep aynıdır: kullanıcı girdisi sorgu metnine yapıştırılmıştır.
- **Tespit:** Web sunucusu loglarında istek adreslerinde tek tırnak, `OR 1=1`, `UNION SELECT` gibi
  kalıplar ve aynı IP'den kısa sürede gelen çok sayıda 500 hatası taranıyor işaretidir; sqlmap gibi
  araçlar varsayılan User-Agent'larını da loga bırakır. Bir WAF (web uygulaması güvenlik duvarı)
  bu kalıpları engelleyebilir ama tek başına çözüm değildir.
- **Önleme:** Parametreli sorgular (ya da güvenilir bir ORM'in parametreli çağrıları), veritabanı
  kullanıcısına yalnızca gereken izinleri vermek (uygulama hesabı tabloları silemesin) ve hata
  ayrıntısını kullanıcıya göstermemek birlikte katmanlı bir savunma kurar.
""",
    sure_hedef_dk=40,
)
