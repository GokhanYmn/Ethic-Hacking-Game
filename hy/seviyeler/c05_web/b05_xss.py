"""Cilt 5 · Bölüm 5 — XSS: Siteler Arası Betik Çalıştırma.

Beceri: girdinin kaçışsız yansıdığını **zararsız bir işaretle** (`<b>deneme</b>`) tespit etmek, reflected
ile stored farkı, HTML gövdesi ile öznitelik (attribute) bağlamı, çıktı kodlama (`html.escape`) ve
Content-Security-Policy ile düzeltme.

Laboratuvar: bir arama sayfası (reflected) ve bir yorum/defter sayfası (stored) olan küçük uygulama.
Hiçbir betik (script) yazılmaz ve çerez çalınmaz: işaret yalnızca kalın yazı etiketidir. Düzeltme
kontrolü, işaretin kaçırılarak (escaped) döndüğünü ve CSP başlığının varlığını sınar.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c05_web import ortak as o

ISARET = "<b>deneme</b>"

VAKALAR = [
    {"kod": "pazarix", "ara": "/ara", "param": "arama", "yorum": "/yorumlar", "f_isim": "isim", "f_mesaj": "yorum",
     "yorum_etiket": "Ürün yorumları", "aranan": "kablosuz kulaklık",
     "yorumlar": ["Kargo bir gün içinde geldi, teşekkürler.", "Kulaklığın ses kalitesi beklentimin üstünde.", "Paket özenli hazırlanmıştı."],
     "olay": "Pazarix'in arama sayfası ve ürün yorumları kampanya öncesi yeniden yazıldı. Tuncay Bey, "
             "müşterilerin yazdıklarının sayfaya nasıl basıldığını incelememizi istiyor."},
    {"kod": "medora", "ara": "/doktor-ara", "param": "kelime", "yorum": "/geri-bildirim", "f_isim": "ad", "f_mesaj": "mesaj",
     "yorum_etiket": "Hasta geri bildirimleri", "aranan": "kardiyoloji",
     "yorumlar": ["Randevu çok kolay alındı.", "Bekleme süresi kısaydı, ilgilendiler.", "Sonuçlar zamanında portala düştü."],
     "olay": "Medora Sağlık'ın doktor arama kutusu ve hasta geri bildirim sayfası var. Dr. Aslı Hanım, bu "
             "alanlara yazılan metinlerin başka hastaların ekranına kontrolsüz yansıyıp yansımadığını öğrenmek istiyor."},
    {"kod": "ferahbank", "ara": "/ara", "param": "s", "yorum": "/musteri-defteri", "f_isim": "ad", "f_mesaj": "gorus",
     "yorum_etiket": "Müşteri görüşleri", "aranan": "konut kredisi",
     "yorumlar": ["Şube çalışanları çok yardımcı oldu.", "Mobil uygulama hızlandı.", "Kredi başvurusu bir günde sonuçlandı."],
     "olay": "Ferah Bank'ın internet şubesindeki arama kutusu ve müşteri görüşleri sayfası bir iç denetimde "
             "işaretlendi. Kaan Bey, bunların kullanıcı girdisini güvenli yazdırıp yazdırmadığını soruyor."},
    {"kod": "atolye", "ara": "/menu-ara", "param": "terim", "yorum": "/defter", "f_isim": "isim", "f_mesaj": "mesaj",
     "yorum_etiket": "Ziyaretçi defteri", "aranan": "filtre kahve",
     "yorumlar": ["Kahveniz harika, yine geleceğiz.", "Çalışma masaları rahat.", "Tatlı seçenekleri artsın."],
     "olay": "Atölye Kahve'nin sahibi Berk, ziyaretçi defteri ve menü arama kutusunu kendi yazmıştı. Sitede "
             "bir sabah garip bir görünüm fark edince tedirgin oldu ve bize başvurdu."},
]

SEMA = """
CREATE TABLE yorumlar (id INTEGER PRIMARY KEY, isim TEXT, mesaj TEXT);
"""

KAYNAK = '''# uygulama.py — @@AD@@ arama ve yorum sayfaları (laboratuvar kopyası)
@@ICE_AKTAR@@
# Her yanıta eklenecek güvenlik başlıkları (ör. Content-Security-Policy buraya yazılır)
GUVENLIK_BASLIKLARI = @@BASLIKLAR@@


def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def isle(istek, db):
    if istek.path == "/":
        return 200, GUVENLIK_BASLIKLARI, sayfa("@@AD@@", "<form action='@@ARA@@'><input name='@@PARAM@@'> "
                                               "<button>Ara</button></form><p><a href='@@YORUM@@'>@@YORUM_ETIKET@@</a></p>")
    if istek.path == "@@ARA@@":
@@ARANAN@@
        govde = ("<form action='@@ARA@@'><input name='@@PARAM@@' value=\\"%s\\"> <button>Ara</button></form>"
                 "<p>Aradığınız: %s</p><p>Sonuç bulunamadı.</p>" % (aranan, aranan))
        return 200, GUVENLIK_BASLIKLARI, sayfa("Arama", govde)
    if istek.path == "@@YORUM@@":
        if istek.method == "POST":
            db.execute("INSERT INTO yorumlar (isim, mesaj) VALUES (?, ?)",
                       (istek.form.get("@@F_ISIM@@", ""), istek.form.get("@@F_MESAJ@@", "")))
            return 302, {"Location": "@@YORUM@@"}, ""
        li = ""
        for y in db.execute("SELECT isim, mesaj FROM yorumlar ORDER BY id"):
@@YORUM_SATIRI@@
        govde = ("<ul>%s</ul><form method='post'><input name='@@F_ISIM@@'> <input name='@@F_MESAJ@@'> "
                 "<button>Gönder</button></form>" % li)
        return 200, GUVENLIK_BASLIKLARI, sayfa("@@YORUM_ETIKET@@", govde)
    return 404, GUVENLIK_BASLIKLARI, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''

ARANAN_ACIK = '        aranan = istek.sorgu.get("@@PARAM@@", "")'
ARANAN_GUVENLI = '        aranan = html.escape(istek.sorgu.get("@@PARAM@@", ""))'
SATIR_ACIK = '            li += "<li><b>%s</b>: %s</li>" % (y["isim"], y["mesaj"])'
SATIR_GUVENLI = '            li += "<li><b>%s</b>: %s</li>" % (html.escape(y["isim"]), html.escape(y["mesaj"]))'
CSP = '''{"Content-Security-Policy": "default-src 'self'"}'''


def kaynak(s: dict, guvenli: bool = False) -> str:
    v = s["v"]
    govde = (KAYNAK.replace("@@ARANAN@@", ARANAN_GUVENLI if guvenli else ARANAN_ACIK)
             .replace("@@YORUM_SATIRI@@", SATIR_GUVENLI if guvenli else SATIR_ACIK))
    return o.kaynak_doldur(govde, {
        "AD": s["musteri"]["ad"], "ARA": v["ara"], "PARAM": v["param"], "YORUM": v["yorum"],
        "F_ISIM": v["f_isim"], "F_MESAJ": v["f_mesaj"], "YORUM_ETIKET": v["yorum_etiket"],
        "ICE_AKTAR": "import html\n" if guvenli else "", "BASLIKLAR": CSP if guvenli else "{}",
    })


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    isimler = u.isimler(rng, 3)
    return {
        "vaka": f"{m['ad']} — {v['yorum_etiket'].lower()} ve arama",
        "musteri": m, "v": v, "port": port, "isimler": isimler,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}", "ara": v["ara"],
            "param": v["param"], "yorum": v["yorum"], "f_isim": v["f_isim"], "f_mesaj": v["f_mesaj"],
            "aranan": v["aranan"], "isaret": ISARET,
        },
        "cevaplar": {
            "param": v["param"],
            "adet": 2,
            "yorum_yol": [v["yorum"], v["yorum"].lstrip("/"), f"http://127.0.0.1:{port}{v['yorum']}"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    o.db_olustur(lab / "uygulama.db", SEMA,
                 {"yorumlar": [(i + 1, ad.capitalize(), t) for i, (ad, t) in enumerate(zip(s["isimler"], v["yorumlar"]))]})
    u.yaz(lab / "uygulama.py", kaynak(s))
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — arama ve yorum sayfaları laboratuvar kopyası\n\n"
          f"Adres : http://127.0.0.1:{s['port']}\n"
          f"Sayfalar: / , {v['ara']} (arama), {v['yorum']} (yorumlar)\n\n"
          f"Bu bölümde sadece zararsız bir işaret kullanıyoruz: {ISARET}\n"
          "Betik (script) yazmak, çerez çalmak ya da başka kullanıcıları hedeflemek yok.\n"
          "uygulama.py 6. ve 7. görevlerde düzeltilecek; sunucu dosyayı kaydedince kendisi yeniden yükler.\n")


def servis(s: dict, lab: Path, dur) -> None:
    o.servis_calis(s["port"], lab, dur)


# ---------------------------------------------------------------- kontroller

def _yorum_birak_denetle(b: Baglam) -> Sonuc:
    yol = Path(b.lab) / "uygulama.db"
    try:
        n = o.db_sorgu(yol, "SELECT COUNT(*) FROM yorumlar WHERE mesaj LIKE ? OR isim LIKE ?",
                       (f"%{ISARET}%", f"%{ISARET}%"))[0][0]
    except Exception as e:
        return Sonuc(False, f"Veritabanı okunamadı: {e}")
    if n:
        return Sonuc(True, f"Yorum kaydedildi ve sayfada kalıcı: `{ISARET}` artık sunucuda duruyor. Sayfayı açan HER ziyaretçi "
                           "bunu alacak; tehlike de buradan geliyor.")
    return Sonuc(False, f"Yorum veritabanında `{ISARET}` içeren bir kayıt yok. Formu POST ile gönder: "
                        "`curl -s -d '<<f_isim>>=Deneme&<<f_mesaj>>=" + ISARET + "' <<url>><<yorum>>`", yakin=True)


def _kacis_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    kacan = "&lt;b&gt;deneme&lt;/b&gt;"

    def f(d):
        y = d.get(v["ara"], sorgu={v["param"]: v["aranan"]})
        hata = o.cokme_sonucu(y, "normal arama")
        if hata:
            return hata
        if y.kod != 200 or v["aranan"] not in y.govde:
            return Sonuc(False, "Normal arama artık aranan metni göstermiyor; düzeltme sayfayı bozmuş.", yakin=True)
        y = d.get(v["ara"], sorgu={v["param"]: ISARET})
        hata = o.cokme_sonucu(y, "işaretli arama")
        if hata:
            return hata
        if ISARET in y.govde:
            return Sonuc(False, f"Arama sayfası `{ISARET}` işaretini hâlâ olduğu gibi (etiket olarak) basıyor. "
                                f"`{v['param']}` değerini sayfaya yazmadan önce `html.escape` ile kodla (iki yerde: metin ve "
                                "kutunun `value=` özniteliği).", yakin=True)
        if kacan not in y.govde:
            return Sonuc(False, f"İşaret görünmüyor; kaçırılmış hali `{kacan}` sayfada olmalı (kullanıcı ne yazdıysa, "
                                "metin olarak görmeli).", yakin=True)
        y = d.get(v["ara"], sorgu={v["param"]: 'a"b'})
        if 'a"b' in y.govde:
            return Sonuc(False, "Çift tırnak (`\"`) kodlanmıyor. `html.escape(metin)` varsayılan olarak tırnakları da kodlar; "
                                "yoksa kutunun `value=\"...\"` özniteliğinden çıkılabilir.", yakin=True)
        d.post(v["yorum"], {v["f_isim"]: "<i>ad</i>", v["f_mesaj"]: ISARET})
        y = d.get(v["yorum"])
        hata = o.cokme_sonucu(y, "yorum listesi")
        if hata:
            return hata
        if ISARET in y.govde or "<i>ad</i>" in y.govde:
            return Sonuc(False, "Yorum sayfası saklanan (stored) girdiyi hâlâ kaçışsız basıyor. Hem `isim` hem `mesaj` "
                                "sayfaya yazılırken `html.escape` ile kodlanmalı. Bu, daha tehlikeli olan türdür: "
                                "sayfayı açan herkesi etkiler.", yakin=True)
        if kacan not in y.govde:
            return Sonuc(False, "Yorum görünmüyor; kaçırılmış hali sayfada olmalı.", yakin=True)
        return Sonuc(True, "Arama (reflected) ve yorumlar (stored) artık çıktı kodlamasıyla yazılıyor: `<` karakteri `&lt;` oldu, "
                           "tarayıcı işareti kod değil metin olarak gösterir. Doğru yerde (sayfaya yazarken) kodladın.")

    return o.deneme_calistir(b, f)


def _csp_denetle(b: Baglam) -> Sonuc:
    v = b.senaryo["v"]

    def f(d):
        for yol, sorgu in (("/", None), (v["ara"], {v["param"]: "x"}), (v["yorum"], None)):
            y = d.get(yol, sorgu=sorgu)
            hata = o.cokme_sonucu(y, yol)
            if hata:
                return hata
            if y.kod != 200:
                return Sonuc(False, f"`{yol}` artık {y.kod} döndürüyor; düzeltme sayfayı bozmuş.", yakin=True)
            csp = y.baslik("content-security-policy")
            if not csp:
                return Sonuc(False, f"`{yol}` yanıtında `Content-Security-Policy` başlığı yok. `uygulama.py`'nin başındaki "
                                    "`GUVENLIK_BASLIKLARI` sözlüğü her yanıta ekleniyor; oraya başlığı yaz.", yakin=True)
            if "default-src" not in csp and "script-src" not in csp:
                return Sonuc(False, f"CSP başlığı var (`{csp}`) ama betik kaynağını sınırlamıyor: `default-src 'self'` "
                                    "ya da `script-src 'self'` gibi bir yönerge gerekli.", yakin=True)
            if "unsafe-inline" in csp or "unsafe-eval" in csp or re.search(r"(^|[\s;])\*([\s;]|$)", csp):
                return Sonuc(False, f"`{csp}` politikası hemen her betiğe izin veriyor (`unsafe-inline`, `unsafe-eval` ya da `*`). "
                                    "Politikanın amacı satır içi/dış kaynaklı betikleri kısıtlamaktır.", yakin=True)
        return Sonuc(True, "Her yanıt artık `Content-Security-Policy` taşıyor: satır içi betikler ve başka sitelerden betik "
                           "yükleme tarayıcı tarafından engellenir. Çıktı kodlama birinci, CSP ikinci savunma hattıdır.")

    return o.deneme_calistir(b, f)


def _param_hata(g, beklenen, b):
    if g.strip("/") == b.senaryo["v"]["ara"].strip("/"):
        return "Bu, arama sayfasının yolu. Soru, değeri sayfaya yansıtan sorgu PARAMETRESİNİN adını soruyor (`?ad=değer`)."
    return None


def _adet_hata(g, beklenen, b):
    if g == "1":
        return "Bir yerde daha var: aramaya yazdığın değer hem sayfa metninde hem de başka bir yerde (arama kutusunun içinde) geri geliyor."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, v = s["metin"]["url"], s["v"]
    o.hazir_bekle(url + "/")
    form = o.sh(f"curl -s {url}/", lab)
    param = re.search(r"name='(\w+)'", form).group(1)
    sayfa = o.sh(f"curl -s -G --data-urlencode '{param}={ISARET}' {url}{v['ara']}", lab)
    adet = len(re.findall(re.escape(ISARET), sayfa))
    liste_yolu = re.search(r"href='([^']+)'", form).group(1)
    o.sh(f"curl -s -d '{v['f_isim']}=Deneme&{v['f_mesaj']}={ISARET}' {url}{liste_yolu}", lab)
    (lab / "uygulama.py").write_text(kaynak(s, guvenli=True), encoding="utf-8")
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (5, 8, 9)}
    return {1: param, 2: str(adet), 3: liste_yolu, 4: "", 5: secmeli[5], 6: "", 7: "", 8: secmeli[8], 9: secmeli[9]}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("XSS: girdi sayfaya karışırsa", """
**XSS** (Cross-Site Scripting), bir web sayfasının kullanıcı girdisini **kaçışsız** (kodlamadan) sayfaya
basması ve bu yüzden girdinin tarayıcıda *metin* yerine *kod* gibi yorumlanmasıdır. SQLi veritabanını
hedef alırken XSS, **diğer kullanıcıların tarayıcılarını** hedef alır.

Bu bölümde **hiçbir betik (script) yazmayacağız**. Açığı, zararsız bir HTML işaretiyle tespit edeceğiz:
`<b>deneme</b>` (kalın yazı). Sayfa bunu etiket olarak geri veriyorsa girdi kodlanmıyor demektir.
Uygulamanın nerede kullanıcı metni bastığına bakalım:
""", komut="grep -n 'aranan\\|isim\\|mesaj' uygulama.py", sonra="""
İki yerde kullanıcıdan gelen metin sayfaya yazılıyor: arama (`aranan`) ve yorum listesi (`isim`, `mesaj`).
İkisinde de `%s` ile **olduğu gibi** basılıyor.
"""),
    Adim("Normal arama", """
Önce sıradan bir arama yap ve cevabı oku:
""", komut="curl -s -G --data-urlencode '<<param>>=<<aranan>>' <<url>><<ara>>", sonra="""
Cevapta aradığın metin iki kere geri geliyor: bir paragrafta ve arama kutusunun içinde. Uygulama
sorgunu **yansıtıyor**; buna *reflected* (yansıyan) tür denir.
"""),
    Adim("Zararsız işaret ile tespit", """
Aynı aramaya bu kez bir HTML işareti ver. Bir tarayıcı `<b>...</b>` arasını kalın yazı olarak çizer.
Sayfa işareti **olduğu gibi** geri veriyorsa girdi metin değil kod olarak işlenmiş demektir:
""", komut="curl -s -G --data-urlencode '<<param>>=<<isaret>>' <<url>><<ara>>", sonra="""
İşaret yanıtta **olduğu gibi** durdu (iki yerde). Doğru bir uygulama `<` karakterini `&lt;` olarak
yazardı. Gerçek bir saldırgan `<b>` yerine bir betik koyardı ve o betik kurbanın tarayıcısında çalışırdı;
biz bu bölümde bunu yapmıyoruz, kanıt olarak işaret yeter.
"""),
    Adim("Savunma başlıkları var mı?", """
Yanıtın başlıklarına bak. Bir XSS'in etkisini sınırlayan `Content-Security-Policy` başlığı var mı?
""", komut="curl -s -i <<url>>/ | head -8", sonra="""
Yok. Bu başlık tarayıcıya "yalnızca şu kaynaklardan gelen betikleri çalıştır" der; XSS'in ikinci
savunma hattıdır. Birinci hat çıktı kodlamasıdır; ikisini birlikte uygulayacağız.
"""),
    Adim("Stored: işaret sunucuda kalır", """
Yansıyan türde kurbanın kötü bir bağlantıya tıklaması gerekir. **Stored** (saklanan) türde ise girdi
sunucuda saklanır ve sayfayı açan **herkese** servis edilir. Yorum formuna işaretli bir yorum bırak:
""", komut="curl -s -d '<<f_isim>>=Deneme&<<f_mesaj>>=<<isaret>>' <<url>><<yorum>>", sonra="""
Yorum kaydedildi (cevap boş: sunucu seni yorum sayfasına yönlendirdi).
"""),
    Adim("Saklanan girdiyi gör", """
Şimdi yorum sayfasını iste; işaret listede, **kaçışsız**:
""", komut="curl -s <<url>><<yorum>>", sonra="""
Bu sayfayı kim açarsa aynı işareti alır. İşaret yerine bir betik olsaydı, o betik **her ziyaretçinin**
tarayıcısında çalışırdı. Bu yüzden stored XSS en tehlikeli türdür.
"""),
    Adim("Çözüm: çıktı kodlama", """
Çözüm, kullanıcı metnini sayfaya yazarken özel karakterleri (`<`, `>`, `&`, `"`, `'`) zararsız karşılıklarına
çevirmektir: **çıktı kodlama** (output encoding). Python'da bu iş `html.escape`'indir:
""", komut="""python3 -c 'import html; print(html.escape("<b>deneme</b>"))'""", sonra="""
`<` karakteri `&lt;` oldu; tarayıcı bunu **metin olarak** gösterir, etiket olarak yorumlamaz.
Kodlamayı girdiyi aldığın yerde değil, **sayfaya yazdığın yerde** yaparsın; "doğru yerde kodlama" web
güvenliğinin temel disiplinidir. İkinci hat: sunucu `Content-Security-Policy` başlığı gönderirse, bir
açık kaçsa bile tarayıcı izinsiz betikleri çalıştırmaz. Örnek: `default-src 'self'`.

**Hacker gözüyle:** XSS ve SQLi aynı kökten gelir (denetimsiz girdi) ama farklı yöne gider: SQLi
"metni sorguya", XSS "metni sayfaya" enjekte eder.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Arama sayfası, aranan metni sayfaya geri yazıyor. Arama değerini hangi **sorgu parametresi** taşıyor?",
          Metin("param", sik_hatalar=_param_hata, bicim="parametre adı"),
          ("Ana sayfadaki arama formuna bak.",
           "`curl -s <<url>>/` ve `<input name='...'>`.",
           "`<form>` içindeki kutunun `name` değeri."),
          puan=15, baslik="Yansıyan parametre"),
    Gorev("Aramaya `<<isaret>>` gönder. Bu işaret yanıtın **kaç yerinde** olduğu gibi (etiket olarak) geri geliyor?",
          Sayi("adet", sik_hatalar=_adet_hata),
          ("Sayfanın hem yazı kısmına hem de formun içine bak.",
           "`curl -s -G --data-urlencode '<<param>>=<<isaret>>' <<url>><<ara>> | grep -o '<b>deneme</b>' | wc -l`",
           "Biri paragrafta, biri arama kutusunun `value=\"...\"` özniteliğinde: sayı ikinci."),
          puan=25, baslik="Kaç yerde yansıyor"),
    Gorev("Kullanıcıların yorumlarının saklanıp **herkese** gösterildiği sayfa (stored XSS'in yeri) hangi yol?",
          Metin("yorum_yol", bicim="yol (örn. /a)"),
          ("Ana sayfadaki bağlantılara bak.",
           "`curl -s <<url>>/` çıktısında bir yorum/defter sayfasına bağlantı var.",
           "`href='...'` içindeki yolu yaz."),
          puan=15, baslik="Saklanan yorumlar"),
    Gorev("Yorum sayfasına zararsız işareti bir yorum olarak bırak (`curl -s -d '<<f_isim>>=Deneme&<<f_mesaj>>=<<isaret>>' "
          "<<url>><<yorum>>`) ve `cevap 4` yaz. İşaretin sunucuda kalıcı olduğunu kontrol edeceğim.",
          Durum(_yorum_birak_denetle, "```\ncurl -s -d '<<f_isim>>=Deneme&<<f_mesaj>>=<<isaret>>' <<url>><<yorum>>\n```"),
          ("Yorum POST ile gönderilir; `-d` seçeneği gövdeyi verir.",
           "Alanların adları: `<<f_isim>>` ve `<<f_mesaj>>`. Adres: `<<url>><<yorum>>`.",
           "`curl -s -d '<<f_isim>>=Deneme&<<f_mesaj>>=<<isaret>>' <<url>><<yorum>>`"),
          puan=25, baslik="Stored işaret"),
    Gorev("Bir e-postadaki kötü niyetli arama bağlantısına tıklayan kişinin tarayıcısında, girdi **o anda** cevaba yansıyıp "
          "çalışıyor; ama bağlantıya tıklamayan kimse etkilenmiyor. Öte yandan bir forum yorumuna konan zararlı girdi, "
          "sayfayı açan **herkesi** etkiliyor. Hangisi daha tehlikelidir ve neden?",
          Secmeli([
              ("Stored: girdi sunucuda saklandığı için sayfayı ziyaret eden herkes ek bir tıklama olmadan etkilenir",
               "Doğru. Reflected tür kurbanın bir bağlantıya tıklamasını gerektirir; stored tür sayfayı açan herkese kendiliğinden ulaşır."),
              ("Reflected: bağlantı e-postayla yayılabildiği için her zaman daha fazla kişiyi etkiler",
               "Bağlantı yayılabilir ama her kurban ayrı tıklamalıdır; stored tür sayfayı açan herkese otomatik ulaşır."),
              ("İkisi aynı derecede tehlikelidir, çünkü ikisinde de aynı karakter kodlanmıyor",
               "Kök neden aynı olsa da etki alanı farklıdır; saklanan girdi kitlesel ve otomatik etkiler."),
              ("Hiçbiri tehlikeli değildir, çünkü tarayıcı kendisi bu tür betikleri zaten engeller",
               "Tarayıcılar sınırlı koruma sağlar ama sunucu kodlamazsa girdi kod olarak çalışabilir; koruma sunucuda başlar."),
          ]),
          ("Kurbanın bir şey yapması gerekiyor mu?",
           "Sayfa herkese aynı içeriği veriyorsa, saklanan girdi kaç kişiye ulaşır?",
           "Saklanan (stored) türde sayfayı açan her ziyaretçi etkilenir."),
          puan=20, baslik="Reflected mi stored mı"),
    Gorev("Arama sayfasını ve yorum listesini düzelt: kullanıcıdan gelen metinleri sayfaya yazmadan önce `html.escape` ile kodla "
          "(arama değeri, yorumun `isim` ve `mesaj` alanları). `uygulama.py`'nin başına `import html` eklemeyi unutma. "
          "Kaydet ve `cevap 6` yaz. Normal arama ve yorumlar çalışmaya devam etmeli.",
          Durum(_kacis_denetle, "```\nimport html\n...\naranan = html.escape(istek.sorgu.get(\"<<param>>\", \"\"))\n...\n"
                "li += \"<li><b>%s</b>: %s</li>\" % (html.escape(y[\"isim\"]), html.escape(y[\"mesaj\"]))\n```"),
          ("Kodlama, metni sayfaya yazdığın satırların hemen öncesinde yapılır.",
           "`import html` ekle; `aranan = html.escape(...)` ve yorum satırında `html.escape(y[\"isim\"])`, `html.escape(y[\"mesaj\"])` kullan.",
           "`aranan = html.escape(istek.sorgu.get(\"<<param>>\", \"\"))` ve `li += \"<li><b>%s</b>: %s</li>\" % (html.escape(y[\"isim\"]), html.escape(y[\"mesaj\"]))`."),
          puan=45, baslik="html.escape"),
    Gorev("İkinci savunma hattı: `uygulama.py`'nin başındaki `GUVENLIK_BASLIKLARI` sözlüğüne bir `Content-Security-Policy` "
          "başlığı ekle (örneğin `default-src 'self'`; `unsafe-inline` ya da `*` kullanma). Kaydet ve `cevap 7` yaz.",
          Durum(_csp_denetle, "```\nGUVENLIK_BASLIKLARI = {\"Content-Security-Policy\": \"default-src 'self'\"}\n```"),
          ("Bu sözlük her yanıtın başlıklarına eklenir.",
           "Anahtar `Content-Security-Policy`, değer bir politika dizgesi; en basit güvenli seçenek tek bir `default-src` yönergesi.",
           "`GUVENLIK_BASLIKLARI = {\"Content-Security-Policy\": \"default-src 'self'\"}`"),
          puan=35, baslik="Content-Security-Policy"),
    Gorev("Kullanıcı girdisini XSS'e karşı **nerede** kodlamak doğrudur?",
          Secmeli([
              ("Sayfaya yazdığın yerde, bağlama uygun biçimde: HTML için `html.escape`",
               "Doğru. Aynı veri farklı yerlerde (HTML, öznitelik, URL) farklı kodlama ister; en güvenlisi çıktı anında kodlamaktır."),
              ("Girdiyi aldığın anda, veritabanına yazmadan önce bir kez temizleyip sonra hep güvenmek",
               "Veri sonradan başka bir bağlamda (e-posta, rapor) kullanılabilir; ve girdiyi bozarak saklarsın. Kodlama çıktıda yapılır."),
              ("Tarayıcıda JavaScript ile kullanıcı yazarken karakterleri engellemek",
               "İstemci denetimi atlanabilir (curl ile); sunucu çıktıyı kendisi kodlamalı."),
              ("Hiçbir yerde, çünkü modern tarayıcılar zaten hepsini kendiliğinden temizler",
               "Tarayıcılar kodlanmamış HTML'yi sayfa olarak yorumlar; kodlamak sunucunun işidir."),
          ]),
          ("Aynı metin hem HTML gövdesinde hem bir `value=\"...\"` içinde yer alabilir.",
           "\"Doğru yerde kodlama\" ifadesi bölümde geçti.",
           "Çıktıyı sayfaya yazdığın an kodlarsın."),
          puan=20, baslik="Kodlama nerede"),
    Gorev("Oturum çerezi `HttpOnly` bayrağıyla verildiyse (Bölüm 1), bir XSS açığının sonucu nasıl değişir?",
          Secmeli([
              ("Betik çerezi okuyamaz; ama sayfa içinde kullanıcı adına başka işlemler yapabilir, bu yüzden XSS yine de ciddidir",
               "Doğru. HttpOnly çerez çalınmasını zorlaştırır ama XSS'in diğer etkilerini (kullanıcı adına işlem, sahte form) ortadan kaldırmaz."),
              ("XSS tamamen ortadan kalkar, çünkü HttpOnly betiklerin çalışmasını engeller",
               "HttpOnly yalnızca JavaScript'in çereze erişimini engeller; betiğin kendisi yine çalışır."),
              ("Çerez artık şifrelendiği için saldırgan oturumu hiçbir şekilde kullanamaz",
               "HttpOnly şifreleme değildir; tarayıcıya çerezi betiğe göstermemesini söyler."),
              ("HttpOnly yalnızca sunucuların kendi aralarındaki isteklerde anlamlıdır",
               "Bayrak tarayıcıya yöneliktir ve betiğin `document.cookie` ile çereze erişimini engeller."),
          ]),
          ("Bölüm 1'deki çerez bayraklarını hatırla.",
           "HttpOnly neyi engelliyor: betiğin çalışmasını mı, çereze erişimini mi?",
           "Çereze erişimi engeller; betik yine de sayfada çalışabilir."),
          puan=20, baslik="HttpOnly ve XSS"),
]


SEVIYE = Seviye(
    kimlik="c05b05",
    cilt=5,
    bolum=5,
    baslik="XSS: Siteler Arası Betik Çalıştırma",
    brifing="""
Mert bir ekran görüntüsünü gösteriyor: bir sayfada metin bir anda kalın ve büyük yazıyla
çıkmış. "Biri bir kutuya bir şey yazdı ve site onu olduğu gibi geri bastı. Mesele bu."

"**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>` adresinde. Arama sayfası
`<<ara>>`, yorum sayfası `<<yorum>>`. Açığı **zararsız işaretle** (`<<isaret>>`) kanıtlayacak,
reflected ve stored farkını göreceksin, sonra iki katmanla kapatacaksın: çıktı kodlama ve CSP."

Deniz hatırlatıyor: "Burada betik yok, çerez çalmak yok. Sadece işaretin sayfada hangi biçimde
geri geldiğine bakıyoruz. Gerçek bir sitede bunu izinsiz denemek bile sorun olur."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
XSS, "metni sayfaya" enjekte etmektir: sayfa, kullanıcı girdisini kodlamadan basarsa tarayıcı girdiyi
sayfanın kendi kodu sanır. Saldırgan bunu diğer kullanıcılar üzerinde kullanır: oturumu ele geçirmek,
kullanıcı adına işlem yapmak, sahte form göstermek. Stored türü daha tehlikelidir, çünkü sayfayı açan herkese
kendiliğinden ulaşır. Savunma iki katmanlıdır: birinci hat **çıktı kodlama** (girdiyi sayfaya yazarken kodla),
ikinci hat **Content-Security-Policy** (bir açık kaçsa bile tarayıcı izinsiz betikleri çalıştırmasın).
Modern şablon motorları kodlamayı varsayılan yapar; "güvenli değil" işaretli kaçış kapılarına dikkat.
""",
    gercek_hayat="""
- **Samy solucanı (MySpace, 2005):** Kullanıcı profillerinde saklanan (stored) bir XSS açığı, kısa
  sürede çok sayıda profile kendiliğinden yayılan bir solucana dönüştü ve siteyi geçici olarak kapattırdı.
  Stored XSS'in "sayfayı açan herkes" etkisinin klasik örneğidir.
- **Ödeme sayfalarına betik enjeksiyonu:** 2018'de British Airways, sitesindeki bir JavaScript dosyasının
  değiştirilmesiyle ödeme sayfasından kart bilgilerinin toplandığı bir saldırıya uğradı. Sayfanın hangi
  kaynaklardan betik yükleyebileceğini sınırlayan CSP ve harici betikleri doğrulayan alt kaynak bütünlüğü
  (Subresource Integrity) gibi önlemler bu sınıf saldırıların etkisini azaltır.
- **Tespit ve önleme:** Web sunucusu loglarında istek adreslerinde `<`, `%3C` ya da `script` geçen
  kalıplar işarettir; WAF'lar bunları işaretler. Kalıcı çözüm çıktı kodlama, CSP, `HttpOnly` çerezler ve
  kodlamayı varsayılan yapan çerçeveler kullanmaktır; bir kod incelemesinde "kullanıcı verisi doğrudan HTML'e
  yapıştırılıyor mu?" sorusu en etkili tarama sorusudur.
""",
    sure_hedef_dk=40,
)
