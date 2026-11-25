"""Cilt 5 · Bölüm 6 — Broken Access Control ve IDOR.

Beceri: kimliği (ID) değiştirince başkasının kaydını görmek (IDOR, yatay yetki ihlali), giriş yapmış
sıradan kullanıcının yönetici sayfasına girmesi (dikey), "menüden gizlemek yetki kontrolü değildir"
ilkesi ve sunucu tarafı yetki denetimiyle düzeltme. Bütün veriler kurgusaldır.

Laboratuvar: giriş yapan kullanıcının kendi kayıtlarını gördüğü küçük uygulama (lab/uygulama.py).
Kayıt sayfası sahibini denetlemiyor; yönetim sayfası yalnızca girişe bakıyor, role bakmıyor. Düzeltme
kontrolü; sahip/başkası/yönetici/giriş yapmamış kullanıcıların her biriyle istek gönderip yanıtı sınar.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c05_web import ortak as o

VAKALAR = [
    {"kod": "pazarix", "kayit": "/fatura", "param": "id", "etiket": "fatura", "liste": "Faturalarım",
     "olay": "Bir Pazarix müşterisi, fatura adresindeki numarayı değiştirince başka birinin faturasını gördüğünü "
             "bildirdi. Tuncay Bey bunun doğru olup olmadığını ve nasıl kapatılacağını soruyor."},
    {"kod": "medora", "kayit": "/randevu", "param": "id", "etiket": "randevu", "liste": "Randevularım",
     "olay": "Bir hasta, randevu sayfasında başka birinin bilgilerini gördüğünü bildirdi. Dr. Aslı Hanım, "
             "bunun KVKK açısından ciddi olduğunu ve acilen incelememizi istediğini söylüyor."},
    {"kod": "ferahbank", "kayit": "/hesap-ozeti", "param": "no", "etiket": "hesap özeti", "liste": "Hesap özetlerim",
     "olay": "Ferah Bank'ın mobil şubesinde bir müşteri, adresteki hesap numarasını değiştirince başka bir "
             "özet gördü. Kaan Bey bu şikâyeti ciddiye alıp laboratuvar kopyasında doğrulamamızı istiyor."},
    {"kod": "paramix", "kayit": "/odeme-detay", "param": "islem", "etiket": "ödeme kaydı", "liste": "Ödeme kayıtlarım",
     "olay": "Bir Paramix üye işyeri, panelinde kendisine ait olmayan işlemler gördüğünü yazdı. Ece Hanım "
             "bunun bir erişim kontrolü açığı olup olmadığını öğrenmek istiyor."},
]

SEMA = """
CREATE TABLE kullanicilar (id INTEGER PRIMARY KEY, ad TEXT, parola TEXT, rol TEXT);
CREATE TABLE oturumlar (sid TEXT PRIMARY KEY, kullanici_id INTEGER);
CREATE TABLE kayitlar (id INTEGER PRIMARY KEY, sahip_id INTEGER, baslik TEXT, icerik TEXT);
"""

KAYNAK = '''# uygulama.py — @@AD@@ @@ETIKET@@ uygulaması (laboratuvar kopyası)
import secrets


def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def oturumdaki_kullanici(istek, db):
    sid = istek.cerez.get("oturum", "")
    if not sid:
        return None
    return db.execute("SELECT k.id, k.ad, k.rol FROM oturumlar o JOIN kullanicilar k ON k.id = o.kullanici_id "
                      "WHERE o.sid = ?", (sid,)).fetchone()


def isle(istek, db):
    if istek.path == "/giris":
        if istek.method != "POST":
            return 200, {}, sayfa("Giriş", "<form method='post'><input name='kullanici'> "
                                  "<input name='parola' type='password'> <button>Giriş</button></form>")
        k = db.execute("SELECT id FROM kullanicilar WHERE ad = ? AND parola = ?",
                       (istek.form.get("kullanici", ""), istek.form.get("parola", ""))).fetchone()
        if k is None:
            return 401, {}, sayfa("Giriş", "<p>Bilgiler hatalı.</p>")
        sid = secrets.token_hex(16)
        db.execute("INSERT INTO oturumlar VALUES (?, ?)", (sid, k["id"]))
        return 302, {"Location": "/kayitlarim", "Set-Cookie": "oturum=" + sid + "; Path=/; HttpOnly"}, ""
    kul = oturumdaki_kullanici(istek, db)
    if kul is None:
        return 302, {"Location": "/giris"}, ""
    if istek.path == "/kayitlarim":
        satirlar = db.execute("SELECT id, baslik FROM kayitlar WHERE sahip_id = ? ORDER BY id", (kul["id"],))
        li = "".join("<li><a href='@@KAYIT@@?@@PARAM@@=%d'>%s</a></li>" % (r["id"], r["baslik"]) for r in satirlar)
        menu = " <a href='/yonetim/kullanicilar'>Yönetim</a>" if kul["rol"] == "yonetici" else ""
        return 200, {}, sayfa("@@LISTE@@", "<p>Merhaba %s.%s</p><ul>%s</ul>" % (kul["ad"], menu, li))
    if istek.path == "@@KAYIT@@":
        r = db.execute("SELECT k.id, k.sahip_id, k.baslik, k.icerik, u.ad AS sahip FROM kayitlar k "
                       "JOIN kullanicilar u ON u.id = k.sahip_id WHERE k.id = ?",
                       (istek.sorgu.get("@@PARAM@@", ""),)).fetchone()
        if r is None:
            return 404, {}, sayfa("Bulunamadı", "<p>Böyle bir kayıt yok.</p>")
@@KAYIT_YETKI@@
        return 200, {}, sayfa(r["baslik"], "<p>%s</p><p>Sahibi: %s</p>" % (r["icerik"], r["sahip"]))
    if istek.path == "/yonetim/kullanicilar":
@@YONETIM_YETKI@@
        li = "".join("<li>%s (%s)</li>" % (r["ad"], r["rol"])
                     for r in db.execute("SELECT ad, rol FROM kullanicilar ORDER BY id"))
        return 200, {}, sayfa("Kullanıcılar", "<ul>%s</ul>" % li)
    return 404, {}, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''

KAYIT_YETKI_GUVENLI = '''        if kul["rol"] != "yonetici" and r["sahip_id"] != kul["id"]:
            return 403, {}, sayfa("Yasak", "<p>Bu kayıt size ait değil.</p>")'''
YONETIM_YETKI_GUVENLI = '''        if kul["rol"] != "yonetici":
            return 403, {}, sayfa("Yasak", "<p>Bu sayfa yalnızca yöneticiler içindir.</p>")'''


def kaynak(s: dict, guvenli: bool = False, kayit_duzelt: bool | None = None, yonetim_duzelt: bool | None = None) -> str:
    v = s["v"]
    kd = guvenli if kayit_duzelt is None else kayit_duzelt
    yd = guvenli if yonetim_duzelt is None else yonetim_duzelt
    govde = (KAYNAK.replace("@@KAYIT_YETKI@@", KAYIT_YETKI_GUVENLI if kd else "")
             .replace("@@YONETIM_YETKI@@", YONETIM_YETKI_GUVENLI if yd else ""))
    return o.kaynak_doldur(govde, {"AD": s["musteri"]["ad"], "ETIKET": v["etiket"], "KAYIT": v["kayit"],
                                   "PARAM": v["param"], "LISTE": v["liste"]})


def _kayit_metni(rng, v: dict, no: int) -> tuple:
    kod = v["kod"]
    if kod == "pazarix":
        urun = rng.choice(["Kablosuz kulaklık", "Akıllı saat", "Robot süpürge", "Yoga matı", "Powerbank", "Hava fritözü"])
        return f"Fatura {no} — {urun}", f"Tutar: {rng.randint(3, 120) * 50} TL · Teslimat: {rng.choice(['Kadıköy', 'Çankaya', 'Konak', 'Nilüfer'])}"
    if kod == "medora":
        bolum = rng.choice(["Kardiyoloji", "Ortopedi", "Dahiliye", "Göz", "Nöroloji"])
        return f"Randevu {no} — {bolum}", f"Tarih: {rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.2026 · Poliklinik {rng.randint(1, 12)} · Kontrol randevusu"
    if kod == "ferahbank":
        return f"Hesap özeti {no}", f"Bakiye: {rng.randint(20, 900) * 100} TL · Son hareket: {rng.choice(['maaş yatışı', 'fatura ödemesi', 'havale', 'kart harcaması'])}"
    return f"Ödeme {no}", f"Tutar: {rng.randint(1, 80) * 25} TL · Üye işyeri: {rng.choice(['Kitapçı', 'Çiçekçi', 'Kafe', 'Tamirci'])} · Durum: tamamlandı"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    adlar = u.isimler(rng, 4)
    kullanicilar = [
        {"id": 1, "ad": adlar[0], "parola": u.parola(rng), "rol": "kullanici"},       # oyuncu
        {"id": 2, "ad": adlar[1], "parola": u.parola(rng), "rol": "kullanici"},
        {"id": 3, "ad": adlar[2], "parola": u.parola(rng), "rol": "kullanici"},
        {"id": 4, "ad": adlar[3], "parola": u.parola(rng), "rol": "kullanici"},
        {"id": 5, "ad": "yonetici_" + rng.choice(["deniz", "kaya", "toprak"]), "parola": u.parola(rng), "rol": "yonetici"},
    ]
    sahipler = [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, rng.choice([1, 2, 3, 4]), rng.choice([2, 3, 4])]
    rng.shuffle(sahipler)
    baslangic = rng.randint(1000, 4000)
    bayrak = u.bayrak(rng, "yatay_yetki")
    admin_nolari = [i for i, sh in enumerate(sahipler) if sh == 5]
    bayrak_i = rng.choice(admin_nolari)
    kayitlar = []
    for i, sahip in enumerate(sahipler):
        no = baslangic + i
        baslik, icerik = _kayit_metni(rng, v, no)
        if i == bayrak_i:
            icerik += f" · iç not: {bayrak}"
        kayitlar.append({"id": no, "sahip": sahip, "baslik": baslik, "icerik": icerik})
    benim = [k["id"] for k in kayitlar if k["sahip"] == 1]
    baskalari = [k for k in kayitlar if k["sahip"] in (2, 3, 4)]
    hedef = rng.choice(baskalari)
    sahip_ad = {k["id"]: k["ad"] for k in kullanicilar}
    return {
        "vaka": f"{m['ad']} — {v['etiket']} erişim kontrolü",
        "musteri": m, "v": v, "port": port, "kullanicilar": kullanicilar, "kayitlar": kayitlar,
        "benim": benim, "hedef": hedef["id"], "baslangic": baslangic, "bitis": baslangic + len(kayitlar) - 1,
        "bayrak_kayit": baslangic + bayrak_i,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}", "kayit": v["kayit"],
            "param": v["param"], "etiket": v["etiket"], "kullanici": kullanicilar[0]["ad"],
            "parola": kullanicilar[0]["parola"], "hedef_id": hedef["id"], "ilk": baslangic, "son": baslangic + len(kayitlar) - 1,
            "benim_ilk": benim[0],
        },
        "cevaplar": {
            "benim": benim,
            "sahip": sahip_ad[hedef["sahip"]],
            "bayrak": bayrak,
            "kullanici_sayisi": len(kullanicilar),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    o.db_olustur(lab / "uygulama.db", SEMA, {
        "kullanicilar": [(k["id"], k["ad"], k["parola"], k["rol"]) for k in s["kullanicilar"]],
        "kayitlar": [(k["id"], k["sahip"], k["baslik"], k["icerik"]) for k in s["kayitlar"]],
    })
    u.yaz(lab / "uygulama.py", kaynak(s))
    t = s["kullanicilar"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['etiket']} uygulaması laboratuvar kopyası (veriler kurgusal)\n\n"
          f"Adres        : http://127.0.0.1:{s['port']}\n"
          f"Test hesabın : {t['ad']}  /  {t['parola']}   (sıradan kullanıcı, rolü: kullanici)\n"
          f"Giriş        : POST /giris (alanlar: kullanici, parola) — çerezi `curl -c cerez.txt` ile sakla\n"
          f"Bilinen yollar: /kayitlarim , {v['kayit']}?{v['param']}=NUMARA , /yonetim/kullanicilar\n"
          f"Kayıt numaraları sistem genelinde sıralıdır: {s['baslangic']} ile {s['bitis']} arası.\n\n"
          "uygulama.py 6. ve 7. görevlerde düzeltilecek; sunucu dosyayı kaydedince kendisi yeniden yükler.\n")


def servis(s: dict, lab: Path, dur) -> None:
    o.servis_calis(s["port"], lab, dur)


# ---------------------------------------------------------------- kontroller

def _kullanici(s, ad):
    return next(k for k in s["kullanicilar"] if k["ad"] == ad)


def _giris_yap(d, k):
    y, cerez = d.giris("/giris", {"kullanici": k["ad"], "parola": k["parola"]})
    return y, cerez


def _kayit_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    oyuncu, yonetici = s["kullanicilar"][0], s["kullanicilar"][-1]
    hedef = next(k for k in s["kayitlar"] if k["id"] == s["hedef"])
    benim = next(k for k in s["kayitlar"] if k["id"] == s["benim"][0])
    admin_kaydi = next(k for k in s["kayitlar"] if k["id"] == s["bayrak_kayit"])

    def f(d):
        y, c_oyuncu = _giris_yap(d, oyuncu)
        hata = o.cokme_sonucu(y, "giriş")
        if hata:
            return hata
        y, c_admin = _giris_yap(d, yonetici)
        if not c_oyuncu or not c_admin:
            return Sonuc(False, "Giriş çerez vermiyor; uygulama.py'de giriş kısmını bozmuşsun.", yakin=True)
        y = d.get(v["kayit"], sorgu={v["param"]: str(benim["id"])}, cerez=c_oyuncu)
        hata = o.cokme_sonucu(y, "kendi kaydı")
        if hata:
            return hata
        if y.kod != 200 or benim["baslik"] not in y.govde:
            return Sonuc(False, "Kullanıcı artık KENDİ kaydını bile göremiyor; sahip denetimi ters kurulmuş olabilir.", yakin=True)
        for kayit, ne in ((hedef, "başka bir kullanıcının"), (admin_kaydi, "yöneticinin")):
            y = d.get(v["kayit"], sorgu={v["param"]: str(kayit["id"])}, cerez=c_oyuncu)
            hata = o.cokme_sonucu(y, f"{ne} kaydına")
            if hata:
                return hata
            if y.kod == 200 or kayit["baslik"] in y.govde or "FLAG{" in y.govde:
                return Sonuc(False, f"Sıradan kullanıcı hâlâ {ne} kaydını ({kayit['id']}) görebiliyor (durum {y.kod}). "
                                    "Kaydı çektikten sonra sahibi ile istek yapan kullanıcıyı karşılaştır; eşleşmiyorsa 403 döndür.",
                             yakin=True)
            if y.kod not in (403, 404):
                return Sonuc(False, f"Başkasının kaydı için 403 (yasak) ya da 404 bekliyordum, {y.kod} geldi.", yakin=True)
        y = d.get(v["kayit"], sorgu={v["param"]: str(hedef["id"])}, cerez=c_admin)
        if y.kod != 200 or hedef["baslik"] not in y.govde:
            return Sonuc(False, "Yönetici artık kayıtları göremiyor. Kurala göre yönetici her kaydı görebilir.", yakin=True)
        y = d.get(v["kayit"], sorgu={v["param"]: str(hedef["id"])})
        if y.kod == 200:
            return Sonuc(False, "Giriş yapmamış biri kaydı görebiliyor; önce oturum kontrolü olmalı.", yakin=True)
        return Sonuc(True, "Kayıt sayfası artık her istekte \"bu kullanıcının bu kayda hakkı var mı?\" diye soruyor: sahibi ve "
                           "yönetici görür, başkası 403 alır. Kimliği değiştirmek artık işe yaramaz.")

    return o.deneme_calistir(b, f)


def _yonetim_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    oyuncu, yonetici = s["kullanicilar"][0], s["kullanicilar"][-1]

    def f(d):
        y, c_oyuncu = _giris_yap(d, oyuncu)
        hata = o.cokme_sonucu(y, "giriş")
        if hata:
            return hata
        y, c_admin = _giris_yap(d, yonetici)
        y = d.get("/yonetim/kullanicilar", cerez=c_oyuncu)
        hata = o.cokme_sonucu(y, "sıradan kullanıcının yönetim sayfası")
        if hata:
            return hata
        if y.kod == 200 or yonetici["ad"] in y.govde:
            return Sonuc(False, f"Sıradan kullanıcı yönetim sayfasını hâlâ görüyor (durum {y.kod}). Menüde linkin gizlenmesi "
                                "yetki kontrolü değildir: sayfanın kendisi rolü denetlemeli.", yakin=True)
        if y.kod not in (401, 403, 404):
            return Sonuc(False, f"Yetkisiz kullanıcıya 403 (ya da 401/404) bekliyordum, {y.kod} geldi.", yakin=True)
        y = d.get("/yonetim/kullanicilar", cerez=c_admin)
        if y.kod != 200 or not all(k["ad"] in y.govde for k in s["kullanicilar"]):
            return Sonuc(False, "Yönetici artık kullanıcı listesini göremiyor; kontrol yalnızca yetkisizleri engellemeli.", yakin=True)
        y = d.get("/yonetim/kullanicilar")
        if y.kod == 200:
            return Sonuc(False, "Giriş yapmamış biri yönetim sayfasını görebiliyor.", yakin=True)
        return Sonuc(True, "Yönetim sayfası artık rolü sunucuda denetliyor: yönetici görür, sıradan kullanıcı ve ziyaretçi göremez. "
                           "Dikey yetki yükseltme kapandı.")

    return o.deneme_calistir(b, f)


def _sahip_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["kullanicilar"][0]["ad"].lower():
        return "Bu senin kendi kullanıcı adın. Sayfada \"Sahibi:\" satırı, kaydın GERÇEK sahibini yazar; başkasının kaydını açtın."
    return None


def _sayi_hata(g, beklenen, b):
    if g == str(int(beklenen) - 1):
        return "Listede bir kişi daha var: yöneticileri de say."
    return None


def _kume_hata(g, beklenen, b):
    if str(b.senaryo["hedef"]) in g.split():
        return "İçinde başkasının kaydı var: sadece KENDİ kayıtların (`/kayitlarim` sayfasındaki bağlantılar) soruluyor."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, v, t = s["metin"]["url"], s["v"], s["kullanicilar"][0]
    o.hazir_bekle(url + "/giris")
    jar = "cerez.txt"
    o.sh(f"curl -s -c {jar} -d 'kullanici={t['ad']}&parola={t['parola']}' {url}/giris", lab)
    liste = o.sh(f"curl -s -b {jar} {url}/kayitlarim", lab)
    benim = " ".join(re.findall(rf"{re.escape(v['kayit'])}\?{v['param']}=(\d+)", liste))
    sayfa = o.sh(f"curl -s -b {jar} '{url}{v['kayit']}?{v['param']}={s['hedef']}'", lab)
    sahip = re.search(r"Sahibi: (\w+)", sayfa).group(1)
    tara = o.sh(f"for i in $(seq {s['baslangic']} {s['bitis']}); do curl -s -b {jar} '{url}{v['kayit']}?{v['param']}='$i; done", lab)
    bayrak = re.search(r"FLAG\{[^}]+\}", tara).group(0)
    yonetim = o.sh(f"curl -s -b {jar} {url}/yonetim/kullanicilar", lab)
    n = yonetim.count("<li>")
    (lab / "uygulama.py").write_text(kaynak(s, guvenli=True), encoding="utf-8")
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (5, 8)}
    return {1: benim, 2: sahip, 3: bayrak, 4: str(n), 5: secmeli[5], 6: "", 7: "", 8: secmeli[8]}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Erişim kontrolü: kim neye hakkı var?", """
OWASP'ın bir numaralı açığı **erişim kontrolü ihlalleridir** ve enjeksiyon kadar teknik değildir: çoğu
zaman sunucu "bu kullanıcının buna erişip erişemeyeceğini" kontrol etmeyi **unutmuştur**. Bu yüzden çok
yaygındır.

İki yön vardır: **yatay** (aynı seviyedeki başkasının verisine erişmek) ve **dikey** (normal kullanıcıyken
yönetici işlevlerine erişmek). Önce kendi hesabınla giriş yap; `-c` çerezi dosyaya yazar:
""", komut="curl -s -c cerez.txt -d 'kullanici=<<kullanici>>&parola=<<parola>>' <<url>>/giris", sonra="""
Cevap boş (sunucu seni `/kayitlarim` sayfasına yönlendirdi) ama oturum çerezin artık `cerez.txt` içinde.
"""),
    Adim("Kendi kayıtların", """
Şimdi `-b` ile çerezi gönderip kendi kayıtlarını listele:
""", komut="curl -s -b cerez.txt <<url>>/kayitlarim", sonra="""
Listedeki bağlantılar `<<kayit>>?<<param>>=NUMARA` biçiminde. Numaralar küçük, tahmin edilebilir
sayılar: bir **doğrudan nesne referansı** (direct object reference). Bu tek başına bir açık değil; ama
sunucu bu numaraya gelen isteğin sahibini denetlemiyorsa açıktır.
"""),
    Adim("Kendi kaydını aç", """
Kendi kayıtlarından birini aç ve cevabın yapısına bak (özellikle "Sahibi:" satırı):
""", komut="curl -s -b cerez.txt '<<url>><<kayit>>?<<param>>=<<benim_ilk>>'", sonra="""
Kayıt sayfası içeriği ve sahibini gösteriyor. Şimdi akla gelen soru: sunucu, bu numarayı soran kişinin
sahibi olup olmadığına bakıyor mu?
"""),
    Adim("Numarayı değiştir (IDOR)", """
Aynı isteği **başka bir numarayla** gönder (`<<hedef_id>>`). Burp'ta bunu Repeater'da, burada curl'ün
adresinde yaparsın:
""", komut="curl -s -b cerez.txt '<<url>><<kayit>>?<<param>>=<<hedef_id>>'", sonra="""
Başka birinin kaydı geldi, hem de "Sahibi:" satırında senin adın değil, başkasının adı var. İşte **IDOR**
(Insecure Direct Object Reference): özel araç, exploit, karmaşık yük yok; sadece bir sayıyı değiştirdin.
Bug bounty'de en çok bulunan açıklardan biri bu kadar basit.

**Hacker gözüyle:** Test için iki hesapla çalışmak en etkilisidir: A'nın isteğini al, B'nin numarasıyla
gönder. Burada tek hesap + sıralı numaralar yeterli.
"""),
    Adim("Dikey: yönetici sayfası", """
Sıradan kullanıcı olarak yönetim sayfasını doğrudan iste. `/kayitlarim` sayfasında "Yönetim" bağlantısı
sadece yöneticilere gösteriliyor; ama sayfanın **kendisi** korunuyor mu?
""", komut="curl -s -b cerez.txt <<url>>/yonetim/kullanicilar", sonra="""
Kullanıcı listesi geldi: normal bir kullanıcı, yönetici işlevine erişti. Bu **dikey** yetki ihlalidir.
Bağlantıyı menüden gizlemek yalnızca **görünürlüğü** etkiler; saldırgan adresi doğrudan yazar.
"""),
    Adim("Kodu oku", """
İki açık da `uygulama.py` içinde. Kayıt sayfasının ve yönetim sayfasının yetki ile ilgili satırlarına bak
(sorgu ve `kul["rol"]`):
""", komut="grep -n 'kul\\[\\|sahip' uygulama.py", sonra="""
Kayıt sayfası, kaydı çekiyor ama `kul["id"]` ile **karşılaştırmıyor**; yönetim sayfası ise `kul["rol"]`'e
hiç bakmıyor. Çözüm bu satırların eksik olması: **her istekte, her nesne için sunucu tarafı yetki kontrolü.**
İsteği yapanın kimliği her zaman oturumdan alınır, istekten değil.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Test hesabınla giriş yap (`OKUBENI.txt`). `/kayitlarim` sayfasında listelenen **kendi** kayıtlarının numaralarını yaz.",
          Kume("benim", tur="sayi", sik_hatalar=_kume_hata, bicim="kayıt numaraları, boşlukla ayrılmış"),
          ("Önce oturum çerezi almalısın.",
           "`curl -s -c cerez.txt -d 'kullanici=<<kullanici>>&parola=<<parola>>' <<url>>/giris` sonra `curl -s -b cerez.txt <<url>>/kayitlarim`",
           "Bağlantılardaki `<<param>>=` den sonra gelen sayıları yaz."),
          puan=20, baslik="Kendi kayıtların"),
    Gorev("`<<kayit>>?<<param>>=<<hedef_id>>` kaydını (sana ait değil) aç. Sayfadaki \"Sahibi:\" satırında kimin adı yazıyor?",
          Metin("sahip", sik_hatalar=_sahip_hata, bicim="kullanıcı adı"),
          ("Kayıt numarasını değiştirmek yeterli.",
           "`curl -s -b cerez.txt '<<url>><<kayit>>?<<param>>=<<hedef_id>>'`",
           "Cevabın sonundaki `Sahibi: ...` satırındaki ad."),
          puan=25, baslik="Başkasının kaydı"),
    Gorev("Kayıt numaraları <<ilk>> ile <<son>> arasında ardışık. Bu kayıtlardan birinde bir yöneticinin iç notunda bayrak "
          "(FLAG{...}) var. Bul.",
          Bayrak("bayrak"),
          ("Numaraları tek tek denemek yerine bir döngü kur.",
           "Çerezle her numarayı iste: `for i in $(seq <<ilk>> <<son>>); do curl -s -b cerez.txt \"<<url>><<kayit>>?<<param>>=$i\"; done`",
           "Çıktının sonuna `| grep -o 'FLAG{[^}]*}'` ekle."),
          puan=35, baslik="Yöneticinin notu"),
    Gorev("Sıradan kullanıcı olarak `/yonetim/kullanicilar` sayfasını açtın. Sayfa kaç kullanıcı listeliyor?",
          Sayi("kullanici_sayisi", sik_hatalar=_sayi_hata),
          ("Dikey erişim: sıradan kullanıcı yönetici sayfasında.",
           "`curl -s -b cerez.txt <<url>>/yonetim/kullanicilar` ve `<li>` etiketlerini say (`| grep -c '<li>'`).",
           "Yönetici hesapları da listede."),
          puan=20, baslik="Yönetim sayfası"),
    Gorev("Aşağıdaki iki durumu sınıflandır: (1) Ayşe, kendi faturasındaki numarayı değiştirip Ali'nin faturasını görüyor. "
          "(2) Normal kullanıcı Mehmet, adrese `/yonetim` yazıp yönetici panelini açıyor. Hangisi doğru?",
          Secmeli([
              ("1 yatay (aynı seviyede başkasının verisi), 2 dikey (düşük yetkiyle yönetici işlevi)",
               "Doğru. Yatay: aynı yetki seviyesindeki başka bir kullanıcının verisine erişim; dikey: yetki basamağını atlamak."),
              ("1 dikey, 2 yatay",
               "Ters. Ayşe ve Ali aynı seviyedeki kullanıcılar (yatay); Mehmet'in yönetici işlevine ulaşması dikey."),
              ("İkisi de yataydır, çünkü ikisi de adresteki bir değeri değiştirmekle yapılıyor",
               "Sınıflandırma, adres değişikliğine değil hangi yetki sınırının aşıldığına bakar."),
              ("İkisi de dikeydir, çünkü ikisinde de yetki kontrolü eksik",
               "Yetki eksikliği ortak neden; yön, aşılan sınırı anlatır: eşit seviye mi, üst seviye mi?"),
          ]),
          ("Ayşe ile Ali aynı yetkide mi?",
           "Yönetici işlevi bir üst basamak mı yoksa aynı basamak mı?",
           "Aynı seviye = yatay, üst seviye = dikey."),
          puan=20, baslik="Yatay mı dikey mi"),
    Gorev("Kayıt sayfasını düzelt: kaydı isteyen kullanıcı kaydın **sahibi değilse ve yönetici değilse** 403 dönmeli. "
          "Sahibi ve yönetici kaydı görmeye devam etmeli. `uygulama.py`'de kaydı çektikten hemen sonra denetle; kaydet ve `cevap 6` yaz.",
          Durum(_kayit_denetle, "```\nif kul[\"rol\"] != \"yonetici\" and r[\"sahip_id\"] != kul[\"id\"]:\n"
                "    return 403, {}, sayfa(\"Yasak\", \"<p>Bu kayıt size ait değil.</p>\")\n```"),
          ("İsteği yapan kullanıcı `kul` değişkeninde, kaydın sahibi `r[\"sahip_id\"]` içinde.",
           "`r` çekildikten sonra (404 kontrolünün altında) `kul[\"id\"]` ile `r[\"sahip_id\"]`'yi karşılaştır; eşleşmiyorsa ve rol yönetici değilse `return 403, ...`.",
           "`if kul[\"rol\"] != \"yonetici\" and r[\"sahip_id\"] != kul[\"id\"]:` sonra `return 403, {}, sayfa(\"Yasak\", ...)`."),
          puan=45, baslik="Sahip denetimi"),
    Gorev("Yönetim sayfasını düzelt: yalnızca rolü `yonetici` olanlar görsün; diğerleri 403 alsın. Kaydet ve `cevap 7` yaz.",
          Durum(_yonetim_denetle, "```\nif kul[\"rol\"] != \"yonetici\":\n    return 403, {}, sayfa(\"Yasak\", \"<p>Bu sayfa yalnızca yöneticiler içindir.</p>\")\n```"),
          ("Kullanıcının rolü `kul[\"rol\"]` içinde.",
           "`/yonetim/kullanicilar` bloğunun başında rolü denetle; yönetici değilse `return 403, ...`.",
           "`if kul[\"rol\"] != \"yonetici\":` sonra `return 403, {}, sayfa(\"Yasak\", ...)`."),
          puan=35, baslik="Rol denetimi"),
    Gorev("Geliştirici, \"Yönetim\" bağlantısını yalnızca yöneticilere gösteriyor ama `/yonetim/kullanicilar` sayfasının "
          "kendisi korumasız. Bu neden erişim kontrolü sayılmaz?",
          Secmeli([
              ("Gizlemek yalnızca görünürlüğü değiştirir; saldırgan adresi doğrudan yazabilir, kontrol sunucuda her istekte olmalı",
               "Doğru. \"Kullanıcı bu linki normalde göremez\" güvenlik değildir; her erişimde \"hakkı var mı?\" sorulmalıdır."),
              ("Bağlantı gizlenince tarayıcılar sayfayı önbelleğe aldığı için sonradan açılabilir",
               "Sorun önbellek değil; sayfanın kendisinde yetki denetimi olmaması."),
              ("Yönetici bağlantısı gizlenemez, çünkü HTML her zaman tüm bağlantıları gösterir",
               "Bağlantı gizlenebilir; ama gizleme bir güvenlik önlemi değil, yalnızca kullanım kolaylığıdır."),
              ("Adresler büyük/küçük harf duyarlı olduğu için saldırgan başka bir yazımla sayfaya girer",
               "Mesele yazım değil; hangi biçimde yazılırsa yazılsın sayfa yetkiyi denetlemiyor."),
          ]),
          ("`/kayitlarim` sayfasında bağlantıyı kim görüyor? Peki sayfayı kim açabiliyor?",
           "Bölümde geçen ilke: \"gizlilik güvenlik değildir\".",
           "Saldırgan menüye değil, adrese bakar; kontrolün sunucuda, her istekte olması gerekir."),
          puan=20, baslik="Menüden gizlemek"),
]


SEVIYE = Seviye(
    kimlik="c05b06",
    cilt=5,
    bolum=6,
    baslik="Broken Access Control ve IDOR",
    brifing="""
Selin bir şikâyet e-postasını masana kaydırıyor: "Bir kullanıcı, adresteki numarayı değiştirince
başkasının verisini görmüş. Doğruysa çok ciddi."

"**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>` adresinde. Test hesabın
`OKUBENI.txt` içinde; sıradan bir kullanıcı. Bütün veriler kurgusal. Görevin: açığı **kanıtla**, hangi türde
olduğunu belirle, sonra **sunucu tarafı yetki denetimiyle** kapat."

Mert tek cümle ekliyor: "Özel araç yok, exploit yok. Çoğu zaman sadece bir sayıyı değiştirirsin; asıl
iş, sunucunun neden sormadığını anlamak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
IDOR'un güzelliği (ve tehlikesi) basitliğidir: bir sayıyı değiştirirsin ve başkasının verisi gelir. Kök neden
her zaman aynı: sunucu "bu kullanıcının bu nesneye hakkı var mı?" diye **sormamış**. Dikey ihlalde de aynı
eksik var, bu kez rol için. Saldırgan açıkları kolayca otomatikleştirir: ardışık numaraları bir döngüyle tarar.
Savunma tarafında ders net: **her istekte, her nesne için sunucu tarafında yetki kontrolü** yap; kimliği
istekten değil oturumdan al. Rastgele ID'ler ya da menüden gizlemek yardımcı olabilir ama yetki kontrolünün
yerini tutmaz.
""",
    gercek_hayat="""
- **Bug bounty'nin en sık bulgusu:** IDOR ve erişim kontrolü hataları, hata ödül programlarında en çok bildirilen
  ve çoğu zaman ödüllendirilen açık sınıflarındandır; çünkü otomatik tarayıcıların yakalaması zordur, bir
  insanın "başka bir kullanıcının numarasını deneyeyim" demesi gerekir.
- **Ardışık kimlikler tarama kolaylığı demektir:** Araştırmacıların bildirdiğine göre 2021'de Parler'ın gönderi
  kimlikleri ardışık sayılardı ve kimlik doğrulama gerektirmeyen bir arayüzden toplu biçimde indirilebildi.
  Ardışık numara tek başına açık değildir; ama kontrol yoksa saldırganın işini otomatikleştirir.
- **Tespit ve önleme:** Tespit için, aynı oturumun kısa sürede çok sayıda farklı nesne numarası istemesi (log
  analizi) ve 403/404 dalgaları izlenir. Önleme: yetkiyi tek bir merkezi yerde (her istekte çalışan bir
  denetim katmanı) uygulamak, varsayılanı "yasak" yapmak ve testlere "iki farklı kullanıcıyla aynı isteği dene"
  senaryosunu eklemek.
""",
    sure_hedef_dk=40,
)
