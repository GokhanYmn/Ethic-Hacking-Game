"""Cilt 5 · Bölüm 1 — Web Uygulaması Nasıl Çalışır?

Beceri: istek/yanıt döngüsü, HTTP'nin durumsuzluğu, oturum çerezi, form alanları (gizli alanlar
dahil), çerez bayrakları (HttpOnly, SameSite, Secure) ve "istemciye güvenme" ilkesi. Uygulamanın
akışını yalnızca curl ile dışarıdan çıkarmak.

Laboratuvar: oyunun kendi küçük web uygulaması (lab/uygulama.py + uygulama.db) 127.0.0.1'de.
Oyuncu akışı çıkarır, sonra çerezin eksik bayraklarını uygulama kodunda düzeltir; servis dosyayı
değişince yeniden yüklediği için düzeltmeyi curl ile görebilir.
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
    {"kod": "pazarix", "alan_k": "eposta", "alan_p": "sifre", "gizli": "kanal", "cerez": "PZXSID",
     "giris": "/giris", "dogrula": "/oturum/dogrula", "hesap": "/hesabim", "no_etiket": "Müşteri No",
     "karsilama": "Kampanya haftası başladı, sepetinizi bekliyoruz.", "kimlik": "{isim}@{alan}",
     "olay": "Pazarix kampanya haftasına hazırlanıyor. Tuncay Bey, müşteri hesabı sayfasının nasıl "
             "çalıştığını dışarıdan gözlemleyip güvenli olup olmadığını sormak istiyor."},
    {"kod": "medora", "alan_k": "hasta_no", "alan_p": "parola", "gizli": "kaynak", "cerez": "medora_sid",
     "giris": "/hasta/giris", "dogrula": "/hasta/dogrula", "hesap": "/hasta/ozet", "no_etiket": "Protokol No",
     "karsilama": "Randevularınıza ve sonuçlarınıza buradan ulaşabilirsiniz.", "kimlik": "H-{n}",
     "olay": "Medora Sağlık hasta portalını yeniledi. Dr. Aslı Hanım, portalın giriş ve oturum akışını "
             "inceleyip raporlamamızı istiyor; çünkü ekranlarda hasta bilgisi dolaşıyor."},
    {"kod": "ferahbank", "alan_k": "musteri_no", "alan_p": "pin", "gizli": "cihaz", "cerez": "FBSESSION",
     "giris": "/sube/giris", "dogrula": "/sube/kontrol", "hesap": "/sube/hesap", "no_etiket": "Hesap No",
     "karsilama": "Ferah Bank internet şubesine hoş geldiniz.", "kimlik": "{n}",
     "olay": "Ferah Bank internet şubesinin yeni sürümü yayına çıkıyor. Kaan Bey, oturumun nasıl "
             "yönetildiğini ve çerezlerin yeterince korunup korunmadığını öğrenmek istiyor."},
    {"kod": "paramix", "alan_k": "eposta", "alan_p": "parola", "gizli": "ref", "cerez": "pmx_oturum",
     "giris": "/merchant/giris", "dogrula": "/merchant/dogrula", "hesap": "/merchant/panel",
     "no_etiket": "Üye İşyeri No",
     "karsilama": "Ödeme altyapınızı buradan yönetin.", "kimlik": "{isim}@{alan}",
     "olay": "Paramix, üye işyeri panelini dışarıdan bir göz incelesin istiyor. Ece Hanım, giriş "
             "formunun ve oturum çerezinin nasıl davrandığını gözlemlememizi rica etti."},
]

SEMA = """
CREATE TABLE kullanicilar (id INTEGER PRIMARY KEY, @@ALAN_K@@ TEXT, parola TEXT, ad TEXT, no TEXT, destek_notu TEXT);
CREATE TABLE oturumlar (sid TEXT PRIMARY KEY, kullanici_id INTEGER);
"""

KAYNAK = '''# uygulama.py — @@AD@@ (laboratuvar kopyası)
# Her istekte isle(istek, db) çağrılır. Dönüş: (durum_kodu, başlıklar, gövde)
import secrets

GIRIS_FORMU = """<form method="post" action="@@DOGRULA@@">
<input name="@@ALAN_K@@"> <input name="@@ALAN_P@@" type="password">
<input type="hidden" name="@@GIZLI@@" value="web"> <button>Giriş</button></form>"""


def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def oturumdaki_kullanici(istek, db):
    sid = istek.cerez.get("@@CEREZ@@", "")
    if not sid:
        return None
    return db.execute(
        "SELECT k.ad, k.no, k.destek_notu FROM oturumlar o JOIN kullanicilar k "
        "ON k.id = o.kullanici_id WHERE o.sid = ?", (sid,)).fetchone()


def isle(istek, db):
    if istek.path == "/":
        return 200, {}, sayfa("@@AD@@", "<p>@@KARSILAMA@@</p><p><a href='@@GIRIS@@'>Giriş yap</a></p>")
    if istek.path == "@@GIRIS@@":
        return 200, {}, sayfa("Giriş", GIRIS_FORMU)
    if istek.path == "@@DOGRULA@@" and istek.method == "POST":
        k = db.execute("SELECT id FROM kullanicilar WHERE @@ALAN_K@@ = ? AND parola = ?",
                       (istek.form.get("@@ALAN_K@@", ""), istek.form.get("@@ALAN_P@@", ""))).fetchone()
        if k is None:
            return 401, {}, sayfa("Giriş", "<p>Bilgiler hatalı.</p>" + GIRIS_FORMU)
        sid = secrets.token_hex(16)
        db.execute("INSERT INTO oturumlar VALUES (?, ?)", (sid, k["id"]))
        cerez = "@@CEREZ@@=" + sid + "; Path=/@@BAYRAKLAR@@"
        return 302, {"Location": "@@HESAP@@", "Set-Cookie": cerez}, ""
    if istek.path == "@@HESAP@@":
        kul = oturumdaki_kullanici(istek, db)
        if kul is None:
            return 302, {"Location": "@@GIRIS@@"}, ""
        return 200, {}, sayfa("Hesabım", "<p>Merhaba %s</p><p>@@NO_ETIKET@@: %s</p>"
                              "<!-- destek notu: %s -->" % (kul["ad"], kul["no"], kul["destek_notu"]))
    return 404, {}, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''

BAYRAKLAR_GUVENLI = "; HttpOnly; SameSite=Lax"


def kaynak(s: dict, guvenli: bool = False) -> str:
    v = s["v"]
    return o.kaynak_doldur(KAYNAK, {
        "AD": s["musteri"]["ad"], "ALAN_K": v["alan_k"], "ALAN_P": v["alan_p"], "GIZLI": v["gizli"],
        "CEREZ": v["cerez"], "GIRIS": v["giris"], "DOGRULA": v["dogrula"], "HESAP": v["hesap"],
        "NO_ETIKET": v["no_etiket"], "KARSILAMA": v["karsilama"],
        "BAYRAKLAR": BAYRAKLAR_GUVENLI if guvenli else "",
    })


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    isim = rng.choice(u.ISIMLER)
    n = rng.randint(1000000, 9999999)
    demo = {
        "ad": isim.capitalize(),
        "kimlik": v["kimlik"].format(isim=isim, n=n, alan=m["alan"]),
        "parola": u.parola(rng),
        "no": f"{rng.randint(100, 999)}-{rng.randint(10000, 99999)}",
        "bayrak": u.bayrak(rng, "oturum_cerezi"),
    }
    digerleri = []
    for ad in u.isimler(rng, 2, haric={isim}):
        digerleri.append({"ad": ad.capitalize(), "kimlik": v["kimlik"].format(isim=ad, n=rng.randint(1000000, 9999999), alan=m["alan"]),
                          "parola": u.parola(rng), "no": f"{rng.randint(100, 999)}-{rng.randint(10000, 99999)}",
                          "bayrak": u.bayrak(rng, "baska_hesap")})
    return {
        "vaka": f"{m['ad']} — {m['sektor']} uygulaması akışı",
        "musteri": m, "v": v, "port": port, "demo": demo, "digerleri": digerleri,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}",
            "yol_giris": v["giris"], "yol_dogrula": v["dogrula"], "yol_hesap": v["hesap"],
            "alan_k": v["alan_k"], "alan_p": v["alan_p"], "gizli": v["gizli"], "cerez": v["cerez"],
            "demo_k": demo["kimlik"], "demo_p": demo["parola"],
        },
        "cevaplar": {
            "action": [v["dogrula"], v["dogrula"].lstrip("/"), f"http://127.0.0.1:{port}{v['dogrula']}"],
            "alanlar": [v["alan_k"], v["alan_p"], v["gizli"]],
            "cerez": v["cerez"],
            "kod": 302,
            "bayrak": demo["bayrak"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v, d = s["v"], s["demo"]
    tablo = [(1, d["kimlik"], d["parola"], d["ad"], d["no"], d["bayrak"])]
    for i, k in enumerate(s["digerleri"], 2):
        tablo.append((i, k["kimlik"], k["parola"], k["ad"], k["no"], k["bayrak"]))
    o.db_olustur(lab / "uygulama.db", o.kaynak_doldur(SEMA, {"ALAN_K": v["alan_k"]}),
                 {"kullanicilar": tablo})
    u.yaz(lab / "uygulama.py", kaynak(s))
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — web uygulaması laboratuvar kopyası\n\n"
          f"Adres        : http://127.0.0.1:{s['port']}\n"
          f"Test hesabı  : {d['kimlik']}  /  {d['parola']}   (bu senin hesabın; başkalarınınkini arama)\n\n"
          "Önce uygulamaya DIŞARIDAN, sadece curl ile bak (kara kutu testi).\n"
          "Kaynak kodu (uygulama.py) 6. görevde düzeltmen için burada. Sunucu dosyayı kaydedince kendisi\n"
          "yeniden yükler; yeniden başlatmana gerek yok.\n")


def servis(s: dict, lab: Path, dur) -> None:
    o.servis_calis(s["port"], lab, dur)


# ---------------------------------------------------------------- kontroller

def _cerez_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v, d = s["v"], s["demo"]

    def f(dn):
        y, cerezler = dn.giris(v["dogrula"], {v["alan_k"]: d["kimlik"], v["alan_p"]: d["parola"]})
        hata = o.cokme_sonucu(y, "giriş")
        if hata:
            return hata
        if y.kod not in (200, 302) or v["cerez"] not in cerezler:
            return Sonuc(False, f"Giriş artık `{v['cerez']}` çerezini vermiyor (durum {y.kod}). Düzeltirken "
                                "oturum mantığını bozmuşsun; sadece `Set-Cookie` değerine bayrak ekle.", yakin=True)
        sc = " ".join(y.set_cerezler).lower()
        eksik = [ad for ad, anahtar in (("HttpOnly", "httponly"), ("SameSite", "samesite")) if anahtar not in sc]
        if eksik:
            return Sonuc(False, f"Çerezde hâlâ eksik bayrak var: {', '.join(eksik)}. `Set-Cookie` satırı şu an: "
                                f"`{y.set_cerezler[0]}`. Bayraklar `;` ile ayrılarak çerezin sonuna eklenir.", yakin=True)
        h = dn.get(v["hesap"], cerez=cerezler)
        if h.kod != 200 or d["ad"] not in h.govde:
            return Sonuc(False, "Çerez bayrakları tamam ama oturumla hesap sayfası artık açılmıyor. Çerezin adını "
                                "ve değerini bozmamış olmalısın.", yakin=True)
        return Sonuc(True, f"`{y.set_cerezler[0]}` artık HttpOnly ve SameSite taşıyor; oturum hâlâ çalışıyor. "
                           "Secure bayrağını ise site HTTPS'e geçince eklersin (lab HTTP olduğu için burada yok).")

    return o.deneme_calistir(b, f)


def _action_hata(g, beklenen, b):
    v = b.senaryo["v"]
    if g.strip("/") == v["giris"].strip("/"):
        return "Bu, formu GÖSTEREN sayfa. Soru formun verilerini GÖNDERDİĞİ yeri soruyor: `<form ... action=...>`."
    return None


def _cerez_hata(g, beklenen, b):
    if len(g) >= 24 or re.fullmatch(r"[0-9a-f]{16,}", g):
        return "Bu çerezin DEĞERİ gibi duruyor. Soru çerezin ADINI soruyor: `Set-Cookie: AD=değer`."
    return None


def _kod_hata(g, beklenen, b):
    if g == "200":
        return "`-L` ile yönlendirmeyi takip ettiysen giriş sayfasının (200) kodunu görmüşsündür. `-L`'siz dene: sunucunun ilk cevabı ne?"
    if g == "404":
        return "Sayfa var; sunucu seni başka bir yere gönderiyor. Başlıklara (`curl -i`) bak."
    return None


def _alanlar_hata(g, beklenen, b):
    v = b.senaryo["v"]
    if v["gizli"] not in g:
        return "Ekranda görünmeyen (type=\"hidden\") bir alan da var; form HTML'inde onu da ara."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, v, d = s["metin"]["url"], s["v"], s["demo"]
    o.hazir_bekle(url + "/")
    form = o.sh(f"curl -s {url}{v['giris']}", lab)
    action = re.search(r'action="([^"]+)"', form).group(1)
    alanlar = re.findall(r'name="([^"]+)"', form)
    baslik = o.sh(f"curl -si -d '{v['alan_k']}={d['kimlik']}&{v['alan_p']}={d['parola']}' {url}{v['dogrula']}", lab)
    cerez = re.search(r"Set-Cookie: ([^=]+)=", baslik).group(1)
    kod = o.sh(f"curl -s -o /dev/null -w '%{{http_code}}' {url}{v['hesap']}", lab).strip()
    sayfa = o.sh(f"curl -sL -c cerez.txt -d '{v['alan_k']}={d['kimlik']}&{v['alan_p']}={d['parola']}' "
                 f"{url}{v['dogrula']}", lab)
    bayrak = re.search(r"FLAG\{[^}]+\}", sayfa).group(0)
    (lab / "uygulama.py").write_text(kaynak(s, guvenli=True), encoding="utf-8")
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (7, 8)}
    return {1: action, 2: " ".join(alanlar), 3: cerez, 4: kod, 5: bayrak, 6: "", **secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("İstemci ve sunucu", """
Bir web uygulaması iki yerde çalışır. **İstemci** (tarayıcı) HTML, CSS ve JavaScript'i çalıştırır; o
senin bilgisayarındadır ve kullanıcı onun her parçasını görüp değiştirebilir. **Sunucu** asıl
mantığı ve veritabanını barındırır; kullanıcı onu doğrudan göremez.

Bu cildin tek fikri şu: **istemciden gelen her şey kullanıcının kontrolündedir.** Form alanı, çerez,
başlık, adres parametresi... hepsi değiştirilebilir. Laboratuvardaki uygulamanın ana sayfasını iste:
""", komut="curl -s <<url>>/", sonra="""
Küçük bir HTML sayfası geldi: bir karşılama ve bir "Giriş yap" bağlantısı. Tarayıcın da arka planda
tam olarak bunu yapıyor: bir **istek** gönderiyor, bir **yanıt** alıyor, sonra yanıtı çiziyor.

**Hacker gözüyle:** Tarayıcı sadece bir arayüzdür; gerçek konuşma HTTP isteği ve yanıtıdır. curl o
konuşmayı çıplak haliyle gösterir.
"""),
    Adim("Başlıklar: yanıtın künyesi", """
Gövdenin yanında yanıtın **başlıkları** da gelir: durum kodu, sunucunun adı, içerik türü... `-i`
seçeneği başlıkları da yazdırır:
""", komut="curl -i <<url>>/", sonra="""
İlk satırdaki `200` "tamam" demek. `Content-Type` içeriğin türünü, `Server` sunucunun kendini nasıl
tanıttığını gösterir. Cilt 4'te sürüm tespitini hatırla: başlıklar çoğu zaman gereğinden fazla
bilgi verir.
"""),
    Adim("Giriş formunu oku", """
Giriş sayfasını iste ve **formu** oku. Üç şeye bak: formun verileri nereye gönderiyor (`action`),
hangi alanlar var (`name=`), ve ekranda görünmeyen (`type="hidden"`) alan var mı?
""", komut="curl -s <<url>><<yol_giris>>", sonra="""
Form `<<yol_dogrula>>` adresine **POST** ediyor. İki görünür alan (`<<alan_k>>`, `<<alan_p>>`) ve bir
**gizli** alan (`<<gizli>>`) var. "Gizli" demek kullanıcı ekranda görmez demektir; görüntüle-kaynak
ya da curl ile herkes okur ve değiştirebilir.
"""),
    Adim("Giriş yap ve çerezi yakala", """
Şimdi formun yaptığını kendin yap: test hesabınla giriş verisini POST et. `-i` ile başlıklara bak:
""", komut="curl -i -d '<<alan_k>>=<<demo_k>>&<<alan_p>>=<<demo_p>>&<<gizli>>=web' <<url>><<yol_dogrula>>", sonra="""
İki önemli şey var. `302` ve bir `Location` başlığı: sunucu seni hesap sayfasına **yönlendiriyor**.
Ve bir `Set-Cookie: <<cerez>>=...` başlığı: sunucu sana bir **oturum kimliği** (session ID) veriyor.
Çerezin sonundaki bayraklara dikkat et; `HttpOnly` ya da `SameSite` var mı? Bunu 6. görevde
ele alacaksın.
"""),
    Adim("Durumsuzluk ve çerez", """
HTTP **durumsuzdur** (stateless): sunucu her isteği bağımsız görür, seni hatırlamaz. Giriş
yaptıktan sonra seni tanıması için tarayıcın çerezi **her istekte** geri gönderir. curl'e bir
çerez kavanozu (cookie jar) verelim; `-c` çerezleri dosyaya yazar, `-L` yönlendirmeyi takip eder,
curl de çereze sahip olduğu için hesap sayfasına çerezle gider:
""", komut="curl -s -L -c cerez.txt -d '<<alan_k>>=<<demo_k>>&<<alan_p>>=<<demo_p>>&<<gizli>>=web' <<url>><<yol_dogrula>>",
         sonra="""
Hesap sayfası geldi. Sayfanın içinde (HTML yorumunun içinde) bir "destek notu" var; biri
unutmuş. Şimdi çerezi çıkarsak ne göreceğiz?
"""),
    Adim("Çerez kavanozuna bak", """
Kavanozun içi düz metin:
""", komut="cat cerez.txt", sonra="""
Çerezin adı, değeri ve geçerli olduğu yol (`/`) burada. Satırın başında `#HttpOnly_` yazıyorsa
JavaScript çereze erişemiyor demektir; yazmıyorsa erişebilir. **Oturum çerezi, kullanıcı adı ve
paroladan sonra en değerli şeydir**: kim ele geçirirse parolayı bilmeden o kişi gibi davranır.
"""),
    Adim("Çerezsiz istek", """
Aynı hesap sayfasını bu kez çerez göndermeden iste. Sadece durum kodunu yazdırıyoruz:
""", komut='curl -s -o /dev/null -w "%{http_code}\\n" <<url>><<yol_hesap>>', sonra="""
Çerez yoksa sunucu seni tanımaz ve giriş sayfasına yönlendirir (302). Bu akış, her web
uygulamasının iskeletidir. Sonraki bölümlerdeki bütün açıklar bu akışın bir noktasında
sunucunun **istemciye fazla güvenmesi** olarak ortaya çıkar.

**Hacker gözüyle:** "Bu alanı JavaScript ile kontrol ediyorum" güvenlik değildir. Saldırgan
tarayıcıyı hiç kullanmadan isteği doğrudan sunucuya gönderebilir; az önce curl ile tam bunu yaptın.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Giriş formu, doldurulan verileri hangi yola (action) gönderiyor? Formu `curl` ile oku.",
          Metin("action", sadece_ad=False, on_ekleri_at=("action=",), sik_hatalar=_action_hata, bicim="yol (örn. /a/b)"),
          ("Giriş sayfasının HTML'inde `<form>` etiketine bak.",
           "`curl -s <<url>><<yol_giris>>` ve `action=` özniteliği.",
           "Çıktıdaki `<form method=\"post\" action=\"...\">` içindeki yolu yaz."),
          puan=25, baslik="Formun gittiği yer"),
    Gorev("Aynı formdaki bütün alanların adını (`name=`) yaz; ekranda görünmeyen **gizli** alan da dahil.",
          Kume("alanlar", sik_hatalar=_alanlar_hata, bicim="üç alan adı, aralarına boşluk"),
          ("Bir form yalnızca görünen kutulardan oluşmaz.",
           "`curl -s <<url>><<yol_giris>> | grep -o 'name=\"[^\"]*\"'`",
           "Üç alan var: kullanıcı, parola ve `type=\"hidden\"` olan."),
          puan=30, baslik="Gizli alan"),
    Gorev("Test hesabınla giriş yapınca sunucu bir oturum çerezi veriyor. Çerezin **adı** nedir?",
          Metin("cerez", sik_hatalar=_cerez_hata, bicim="çerez adı"),
          ("Sunucu çerezi bir yanıt başlığıyla verir.",
           "`curl -i -d '<<alan_k>>=<<demo_k>>&<<alan_p>>=<<demo_p>>&<<gizli>>=web' <<url>><<yol_dogrula>>` ve `Set-Cookie:` satırı.",
           "`Set-Cookie: AD=değer; ...` biçimindeki satırda `=` işaretinden önceki kısım."),
          puan=30, baslik="Oturum çerezi"),
    Gorev("Hesap sayfasını (`<<yol_hesap>>`) hiç çerez göndermeden istediğinde sunucu hangi durum kodunu veriyor?",
          Sayi("kod", sik_hatalar=_kod_hata),
          ("Sunucu seni tanımıyor; ne yapar?",
           "`curl -s -o /dev/null -w \"%{http_code}\\n\" <<url>><<yol_hesap>>`",
           "`-L` kullanma: yönlendirmeyi takip edersen sondaki sayfanın kodunu görürsün."),
          puan=25, baslik="Çerezsiz istek"),
    Gorev("Giriş yaptıktan sonra hesap sayfasının HTML'inin içinde unutulmuş bir bayrak (FLAG{...}) var. Bul.",
          Bayrak("bayrak"),
          ("Giriş yapmadan göremezsin; çerezle gitmen gerek.",
           "`curl -s -L -c cerez.txt -d '...' <<url>><<yol_dogrula>>` hesap sayfasını da getirir.",
           "Çıktıyı `grep FLAG` ile süz; bayrak bir HTML yorumunun (`<!-- ... -->`) içinde."),
          puan=35, baslik="Hesap sayfası"),
    Gorev("Oturum çerezi `HttpOnly` ve `SameSite` bayrakları olmadan veriliyor; bir pentest raporunda bu bulgudur. "
          "`uygulama.py` içinde `Set-Cookie` değerini düzelt (giriş çalışmaya devam etmeli), kaydet ve `cevap 6` yaz. "
          "Sunucu dosyayı kendisi yeniden yükler; `curl -i` ile bayrakları kendin de görebilirsin.",
          Durum(_cerez_denetle, "`uygulama.py` içinde cerez satırını şöyle yap:\n\n```\ncerez = \"<<cerez>>=\" + sid + \"; Path=/; HttpOnly; SameSite=Lax\"\n```"),
          ("Çerez, yanıtın `Set-Cookie` başlığında; kodda `\"Path=/\"` ile biten dizgeye bak.",
           "Bayraklar çerezin sonuna `; HttpOnly; SameSite=Lax` olarak eklenir. `nano uygulama.py` ile aç, `Path=/` geçen yeri bul.",
           "`cerez = \"<<cerez>>=\" + sid + \"; Path=/; HttpOnly; SameSite=Lax\"` (kaydet: Ctrl+O, Enter, Ctrl+X)."),
          puan=40, baslik="Çerez bayrakları"),
    Gorev("Geliştirici, giriş formunun parola alanını JavaScript ile \"en az 8 karakter\" diye denetliyor ve sunucuda hiçbir "
          "denetim yapmıyor. Bu neden güvenlik sağlamaz?",
          Secmeli([
              ("İstemci kodu saldırganın elindedir; curl ile isteği doğrudan sunucuya atıp denetimi atlar",
               "Doğru. Tarayıcıdaki kontrol sadece kullanıcıya kolaylıktır; sunucu her gelen veriyi yeniden denetlemeli."),
              ("JavaScript yalnızca eski tarayıcılarda çalıştığı için modern kullanıcılar etkilenmez",
               "JavaScript her tarayıcıda çalışır; sorun uyumluluk değil, saldırganın tarayıcıyı hiç kullanmamasıdır."),
              ("Parola uzunluğu zaten güvenlikle ilgisiz olduğundan denetlemek anlamsızdır",
               "Parola politikası önemlidir; yanlış olan, denetimin sadece istemcide yapılmasıdır."),
              ("JavaScript denetimi sunucuya fazladan yük bindirdiği için performansı düşürür",
               "Sorun performans değil; istemci denetimi atlanabildiği için sunucu tarafında karşılığı olmak zorundadır."),
          ]),
          ("Saldırgan formu bir tarayıcıda doldurmak zorunda mı?",
           "Bu bölümde giriş isteğini hangi araçla gönderdin?",
           "curl ile gönderilen istek JavaScript'e hiç uğramaz."),
          puan=20, baslik="İstemciye güvenme"),
    Gorev("HTTP \"durumsuz\" olduğuna göre, giriş yaptıktan sonra sunucu seni sonraki isteklerde nasıl tanır?",
          Secmeli([
              ("Tarayıcı oturum çerezini her istekte geri gönderir; sunucu çerezdeki kimliği kayıtla eşler",
               "Doğru. Durum sunucuda tutulur; çerez sadece o kayda işaret eden bir anahtardır."),
              ("Sunucu istemcinin IP adresini ezberler ve aynı IP'den gelene izin verir",
               "IP'ler paylaşılır ve değişir; oturum yönetimi IP'ye değil, rastgele bir oturum kimliğine dayanır."),
              ("Tarayıcı her istekte kullanıcı adı ve parolayı yeniden gönderir",
               "Bu temel kimlik doğrulamadır (Basic Auth); bu uygulama parolayı bir kez alıp oturum kimliği verir."),
              ("Bağlantı hiç kapanmadığı için sunucu aynı soketten konuşanı tanır",
               "HTTP bağlantıları kapanabilir ya da paylaşılabilir; kimliği taşıyan şey bağlantı değil, çereze koyulan oturum kimliğidir."),
          ]),
          ("Giriş isteğinin yanıtındaki `Set-Cookie` başlığını hatırla.",
           "Çerez kavanozunda (`cat cerez.txt`) ne vardı?",
           "Oturum kimliği çerezde gider, asıl bilgi sunucuda saklanır."),
          puan=20, baslik="Durumsuzluk"),
]


SEVIYE = Seviye(
    kimlik="c05b01",
    cilt=5,
    bolum=1,
    baslik="Web Uygulaması Nasıl Çalışır?",
    brifing="""
Selin, Cilt 5'in ilk dosyasını masana bırakıyor: "Bu cilt boyunca saldırı yapmayacağız;
**açığı bulacak, kanıtını okuyacak ve kodda kapatacaksın.** Ama önce bir web uygulaması
nasıl çalışır, onu görmen lazım."

"**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>` adresinde çalışıyor.
Test hesabın `OKUBENI.txt` dosyasında. Tarayıcıya hiç dokunma: sadece curl ile istek gönder,
akışı çıkar."

Mert araya giriyor: "Kural basit: sunucu, tarayıcıdan gelen **hiçbir şeye** güvenmez. Çerez de
dahil. Bu yüzden önce sunucunun sana ne verdiğine, sonra senden ne beklediğine bak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Bir web uygulaması, yanıtlar ve çerezlerle yürüyen bir diyalogdur ve saldırgan o diyaloğa
istediği gibi katılabilir: formun gizli alanını değiştirir, çerezi başka birinin çerezi yapar,
JavaScript denetimini hiç çalıştırmaz. Savunmanın ilk dersi şudur: **sunucu, istemciden gelen hiçbir
veriye güvenmez**; her şeyi kendisi yeniden denetler. İkinci ders çerezle ilgili: oturum çerezi
parola kadar değerlidir, bu yüzden `HttpOnly` (JavaScript okuyamasın), `Secure` (sadece HTTPS) ve
`SameSite` (başka sitelerden tetiklenen isteklerde gönderilmesin) bayraklarıyla korunur.
""",
    gercek_hayat="""
- **Çerez bayrakları rutin bir bulgudur:** Pek çok sızma testi raporunda "oturum çerezinde
  HttpOnly/Secure bayrağı eksik" maddesi yer alır. Bayrak eksikliği tek başına sızma değildir, ama
  başka bir açığın (örneğin XSS) etkisini büyütür. Tespit: tarayıcının geliştirici araçlarında
  Çerezler sekmesi ya da curl'ün `-i` çıktısı; önleme: çerezi üreten tek satırda bayrakları vermek.
- **Oturum çerezi çalmak, parola çalmaktan kolaydır:** Oturumu ele geçiren kişi, parolayı ve
  çoğu zaman MFA'yı hiç görmeden içeri girer. Bu yüzden sunucular oturum kimliğini rastgele üretir,
  girişten sonra yeniler ve çıkışta sunucu tarafında geçersiz kılar.
- **İstemci tarafı denetim yalnızca kolaylıktır:** HTML'deki `maxlength`, JavaScript doğrulaması ya
  da gizli alanlar kullanıcının elinde olduğu için Cilt 5 boyunca tekrar edecek kuralı hatırla:
  her denetimin bir sunucu tarafı karşılığı olmalı.
""",
    sure_hedef_dk=30,
)
