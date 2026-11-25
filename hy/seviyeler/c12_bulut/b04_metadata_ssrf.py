"""Cilt 12 · Bölüm 4 — Metadata, SSRF ve Bulut Savunması.

Beceri: kurgusal uygulama kodunda kullanıcıdan URL alıp istek yapan işlevi (SSRF zafiyeti) bulmak,
kurgusal erişim logunda 169.254.169.254 (metadata servisi) isteklerini ve saldırganı tespit etmek,
işlevi **izin listesiyle** düzeltmek. `cevap <no>` dosyanın son halini sahte bir `urlopen` ile
çalıştırıp dener; hiçbir gerçek ağ isteği yapılmaz. Oyuncuya iç adrese istek yaptırılmaz:
metadata adresi yalnızca log satırlarında ve test metinlerinde geçer.

Vakalar: e-ticaret (ürün görseli), hastane (dış sonuç bağlantısı), fintech (webhook), lojistik
(takip önizleme). Fonksiyon adı, parametre adı ve izinli alan adları her vakada farklıdır.
"""
from __future__ import annotations

import re
import urllib.parse
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, IP, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c12_bulut.ortak import hex_, py, sec_doldur, sh, sirket_sec

VAKALAR = {
    "pazarix": ("urun_gorseli_getir", "gorsel_url", "Satıcının verdiği bağlantıdaki ürün görselini getirip küçük resim üretir.", "/api/gorsel-yukle"),
    "medora": ("harici_sonuc_onizle", "sonuc_url", "Hastanın paylaştığı dış laboratuvar bağlantısının önizlemesini getirir.", "/api/sonuc-onizle"),
    "paramix": ("webhook_dogrula", "geri_cagri_url", "Üye işyerinin kaydettiği geri çağrı adresine bir test isteği atar.", "/api/webhook-test"),
    "kuzgun": ("takip_sayfasi_onizle", "takip_url", "Alıcının yapıştırdığı kargo takip bağlantısının önizlemesini getirir.", "/api/takip-onizle"),
}
SAHNE = {
    "pazarix": "Pazarix'in 'bağlantıdan ürün görseli yükle' özelliği bir araştırmacının dikkatini çekti.",
    "medora": "Medora Sağlık'ın bulut sunucusundan bir gece alışılmadık API çağrıları yapıldı.",
    "paramix": "Paramix'in bulut güvenlik uyarısı, bir sunucu rolünün tanıdık olmayan bir IP'den kullanıldığını bildirdi.",
    "kuzgun": "Kuzgun Lojistik'in takip önizleme özelliğinin logunda garip bağlantılar görüldü.",
}
META = "169.254.169.254"


def uret(rng):
    sk = sirket_sec(rng, kodlar=set(VAKALAR))
    fonk, param, doc, yol = VAKALAR[sk["kod"]]
    alan = sk["alan"]
    izinli = [f"cdn.{alan}", f"img.{alan}"]
    rol = f"{sk['on']}-uygulama-rolu-{hex_(rng, 4)}"
    saldirgan = u.dis_ip(rng)
    kullanicilar = u.benzersiz(rng, u.dis_ip, 4, {saldirgan})
    gun = u.gun(rng) + timedelta(hours=rng.randint(1, 3))
    satirlar = []

    def sat(t, ip, hedef, kod, boyut, ua):
        q = urllib.parse.quote(hedef, safe="")
        satirlar.append((t, u.apache_satiri(ip, t, "GET", f"{yol}?url={q}", kod, boyut, ua)))

    for _ in range(rng.randint(40, 60)):
        sat(gun + timedelta(seconds=rng.randint(-3000, 3000)), rng.choice(kullanicilar),
            f"https://{rng.choice(izinli)}/img/{hex_(rng, 6)}.png", 200, rng.randint(800, 60000), rng.choice(u.TARAYICI_UA))
    for _ in range(rng.randint(2, 3)):                           # iç ağ denemeleri (metadata değil)
        sat(gun + timedelta(minutes=rng.randint(1, 5)), saldirgan, rng.choice(["http://127.0.0.1:8500/", "http://10.0.0.5/admin"]),
            500, 0, "python-requests/2.31.0")
    t = gun + timedelta(minutes=rng.randint(6, 12))
    yollar = ["/latest/meta-data/", "/latest/meta-data/iam/", "/latest/meta-data/iam/security-credentials/",
              f"/latest/meta-data/iam/security-credentials/{rol}"]
    if rng.random() < 0.5:
        yollar.insert(1, "/latest/user-data")
    if rng.random() < 0.5:
        yollar.insert(0, "/latest/meta-data/hostname")
    for y in yollar:
        t += timedelta(seconds=rng.randint(2, 20))
        sat(t, saldirgan, f"http://{META}{y}", 200, rng.randint(40, 1200), "python-requests/2.31.0")
    satirlar.sort(key=lambda x: x[0])
    return {
        "vaka": f"{sk['ad']} — SSRF ve metadata logu",
        "sirket": sk, "fonk": fonk, "param": param, "doc": doc, "yol": yol, "izinli": izinli,
        "satirlar": [x[1] for x in satirlar], "saldirgan": saldirgan, "rol": rol,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "fonk": fonk, "param": param,
                  "izinli1": izinli[0], "izinli2": izinli[1], "yol": yol},
        "cevaplar": {"fonk": fonk, "meta_sayi": len(yollar), "saldirgan": saldirgan, "rol": rol},
    }


def _kod(s: dict) -> str:
    alan = s["sirket"]["alan"]
    return f'''"""Bağlantı önizleme modülü — {s['sirket']['ad']} (KURGUSAL örnek uygulama kodu)."""
import urllib.parse
import urllib.request

SEHIR_ADRESI = "https://veri.{alan}/sehirler.json"


def sehir_listesi():
    """Sabit bir adresten şehir listesini getirir (kullanıcıdan girdi almaz)."""
    return urllib.request.urlopen(SEHIR_ADRESI).read()


def kur_getir(kur_kodu):
    """Kullanıcının verdiği kur kodunu sabit bir adresin YOLUNA ekler."""
    adres = "https://kur.{alan}/api/" + urllib.parse.quote(kur_kodu)
    return urllib.request.urlopen(adres).read()


def {s['fonk']}({s['param']}):
    """{s['doc']}"""
    yanit = urllib.request.urlopen({s['param']}, timeout=3)
    return yanit.read()[:2000]
'''


def yaz(lab: Path, s: dict) -> None:
    k = lab / "bulut/ssrf"
    u.yaz(k / "uygulama/onizleme.py", _kod(s))
    u.yaz(k / "uygulama/izinli_alanlar.txt",
          f"`{s['fonk']}` işlevi YALNIZCA şu alan adlarındaki http/https adreslerini getirmelidir:\n"
          f"{s['izinli'][0]}\n{s['izinli'][1]}\n"
          "Başka her adres (iç ağ, localhost, metadata adresi, başka protokoller) reddedilmelidir.\n")
    u.yaz(k / "erisim_logu.txt", "\n".join(s["satirlar"]) + "\n")


class _Sahte:
    def read(self):
        return b"sahte-yanit"


def _calistir(kod_yolu: Path, fonk: str, adresler: list):
    """Dosyayı sahte `urlopen` ile çalıştırır; her adres için urlopen çağrıldı mı döndürür."""
    import urllib.request as ur
    cagri: list = []
    orijinal = ur.urlopen

    def sahte(*a, **k):
        cagri.append(a[0] if a else k.get("url"))
        return _Sahte()

    sonuc = {}
    ur.urlopen = sahte
    try:
        ns = {"__name__": "onizleme_test"}
        exec(compile(kod_yolu.read_text(encoding="utf-8"), str(kod_yolu), "exec"), ns)
        f = ns.get(fonk)
        if not callable(f):
            return None, f"`{fonk}` işlevi bulunamadı (silmişsin ya da adını değiştirmişsin)."
        for a in adresler:
            cagri.clear()
            try:
                f(a)
            except Exception:
                pass
            sonuc[a] = len(cagri)
    except Exception as e:
        return None, f"Dosya çalıştırılamadı: {type(e).__name__}: {e}. `python3 -m py_compile` ile sözdizimini denetle."
    finally:
        ur.urlopen = orijinal
    return sonuc, None


def _duzelt(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "bulut/ssrf/uygulama/onizleme.py"
    if not yol.is_file():
        return Sonuc(False, "`onizleme.py` yok.")
    izinli = [f"https://{s['izinli'][0]}/img/a.png", f"http://{s['izinli'][1]}/b.jpg?x=1"]
    kotu = [f"http://{META}/latest/meta-data/", "http://10.0.0.5/admin", "http://localhost:8500/",
            f"http://{s['izinli'][0]}@{META}/latest/meta-data/", f"http://{s['izinli'][0]}.kotu.lab/x",
            "file:///etc/passwd", "http://2852039166/"]
    sonuc, hata = _calistir(yol, s["fonk"], izinli + kotu)
    if hata:
        return Sonuc(False, hata)
    for a in kotu:
        if sonuc[a]:
            ipucu = {
                f"http://{META}/latest/meta-data/": "Metadata adresine hâlâ istek atılıyor: tam da Capital One 2019'daki yol.",
                f"http://{s['izinli'][0]}@{META}/latest/meta-data/": "`@` hilesi: adresin '@'den önceki kısmı kullanıcı bilgisidir, asıl sunucu '@'den sonrasıdır. Alan adını `urlparse(...).hostname` ile al, metin içinde arama.",
                f"http://{s['izinli'][0]}.kotu.lab/x": "Alan adını 'ile başlıyor mu?' diye değil, **tam eşleşme** ile izin listesinde ara; yoksa `izinli.kotu.lab` geçer.",
                "file:///etc/passwd": "Yalnızca `http` ve `https` şemalarına izin ver; `file://` gibi şemalar yerel dosyaları açar.",
            }.get(a, f"`{a}` adresine hâlâ istek atılıyor. İzin listesinde olmayan her adres reddedilmeli.")
            return Sonuc(False, ipucu, yakin=True)
    for a in izinli:
        if sonuc[a] != 1:
            return Sonuc(False, f"İzin listesindeki meşru adrese (`{a}`) istek atılmıyor: işlev iş görmüyor. Yalnızca kötü adresleri reddet.", yakin=True)
    return Sonuc(True, "İşlev yalnızca izin listesindeki alan adlarına (http/https) istek atıyor; iç ağ, metadata ve hileli adresler reddediliyor.")


def coz(lab: Path, s: dict) -> dict:
    k = "bulut/ssrf"
    fonk = sh(f"awk '/^def /{{f=$2}} /urlopen\\({s['param']}/ {{split(f,a,\"(\"); print a[1]}}' {k}/uygulama/onizleme.py", lab)
    meta = sh(f"grep -c '{META}' {k}/erisim_logu.txt", lab)
    ip = sh(f"grep '{META}' {k}/erisim_logu.txt | awk '{{print $1}}' | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    rol = sh(f"grep -oE 'security-credentials%2F[A-Za-z0-9-]+' {k}/erisim_logu.txt | head -1 | cut -d'%' -f2 | cut -c3-", lab)
    # düzeltme
    p = s["param"]
    ekle = ('    p = urllib.parse.urlparse(%s)\n    if p.scheme not in ("http", "https") or p.hostname not in IZINLI_ALANLAR:\n'
            '        raise ValueError("izin verilmeyen adres")\n') % p
    kod = ("import pathlib\nf=pathlib.Path('bulut/ssrf/uygulama/onizleme.py');t=f.read_text(encoding='utf-8')\n"
           f"t=t.replace('    yanit = urllib.request.urlopen({p}, timeout=3)', {ekle!r}+'    yanit = urllib.request.urlopen({p}, timeout=3)')\n"
           f"t=t.replace('SEHIR_ADRESI =', 'IZINLI_ALANLAR = {{\"{s['izinli'][0]}\", \"{s['izinli'][1]}\"}}\\nSEHIR_ADRESI =',1)\n"
           "f.write_text(t,encoding='utf-8')\n")
    py(kod, lab)
    return sec_doldur({1: "", 2: fonk, 3: meta, 4: ip, 5: rol, 6: "", 7: "", 8: ""}, GOREVLER, lab, s)


def _meta_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    toplam = sum(1 for x in b.senaryo["satirlar"] if "127.0.0.1" in x or "10.0.0.5" in x)
    if n == beklenen + toplam:
        return "İç ağa (127.0.0.1, 10.x) giden istekleri de saymışsın; onlar da şüpheli ama sorulan yalnızca metadata adresi (169.254.169.254)."
    return None


def _rol_hata(g, beklenen, b):
    if "security-credentials" in g:
        return "Yolun tamamını değil, sadece **rol adını** yaz (`security-credentials/` sonrası)."
    return None


ADIMLAR = [
    Adim("Metadata servisi ve SSRF", """
Her bulut sanal makinesi, kendisi hakkında bilgi (ve çoğu zaman **geçici kimlik bilgileri**) döndüren iç
bir **metadata servisi** çalıştırır. Sabit, yönlendirilemeyen bir adreste durur: `169.254.169.254`.
Sunucunun üzerindeki uygulamalar bu adrese istek atarak bulut kimliklerini alır; dışarıdan erişilemez.

**SSRF** (Server-Side Request Forgery, sunucu tarafı istek sahteciliği): uygulama, **kullanıcının
verdiği bir adrese** sunucu adına istek atıyorsa, saldırgan uygulamayı bu **iç** adrese yöneltebilir.
Sunucu isteği kendi iç ağından attığı için metadata servisi cevap verir ve kimlik bilgileri dışarı sızar.
Bu, bir web açığının (SSRF, Cilt 5) buluta özgü ve çok tehlikeli bir sonucudur.

**<<musteri>>**. <<sahne>> Bu seviyede **hiçbir iç adrese istek atmayacaksın**: yalnızca kodu ve logu
okuyacaksın. Uygulama kodunun yapısına bak:
""", komut="cat bulut/ssrf/uygulama/onizleme.py"),
    Adim("Zafiyetli işlevi bulmak", """
SSRF'in kod izi şudur: bir işlev kullanıcıdan gelen bir adresi **denetlemeden** doğrudan bir ağ
istek işlevine verir. Bu modülde üç işlev var; ağ isteği yapan çağrıları ve çağıran işlevlerin
başlıklarını birlikte gör:
""", komut="grep -n 'def \\|urlopen' bulut/ssrf/uygulama/onizleme.py", sonra="""
Üç işlev de `urlopen` çağırıyor ama **fark, adresin kimden geldiği**: biri tamamen sabit adres, biri
kullanıcı girdisini sabit adresin **yoluna** ekliyor (sunucuyu değiştiremez), biri ise **adresin
tamamını** kullanıcıdan alıyor. Üçüncüsü SSRF'e açıktır.
"""),
    Adim("Logda metadata isteklerini aramak", """
Erişim logunda saldırı izi, `url=` parametresinde metadata adresini görmektir. Adres URL kodlamasından
(`%2F` = `/`) etkilenmez çünkü noktalar kodlanmaz; doğrudan arayabilirsin:
""", komut="grep -c '169.254.169.254' bulut/ssrf/erisim_logu.txt", sonra="""
Normal bir uygulama kullanıcısı hiçbir zaman `url=` parametresine metadata adresini yazmaz. Bu adrese
tek bir istek bile bir **alarmdır**.
"""),
    Adim("Kim ve ne sordu?", """
İstekleri yapan IP, logun ilk sütunudur; sorulan yol ise `url=` parametresinde. Metadata isteklerini
okuyalım:
""", komut="grep '169.254.169.254' bulut/ssrf/erisim_logu.txt | cut -c1-200", sonra="""
Saldırganın izlediği sıra klasiktir: önce `meta-data/` dizinini gezer, sonra `iam/security-credentials/`
yoluyla sunucunun **rol adını** öğrenir, en sonunda o rolün adıyla geçici kimlik bilgilerini ister.
Rol adı yolda göründüğüne göre, hangi rolün kimlik bilgilerinin istendiğini görebilirsin.
"""),
    Adim("IMDSv2 ve izin listesi", """
İki savunma katmanı vardır:

1. **Uygulama katmanı:** kullanıcıdan alınan adres bir **izin listesine** karşı denetlenir. Yalnızca
   önceden bilinen alan adlarına, yalnızca `http/https` şemasıyla ve adresin **gerçek sunucusu**
   (`hostname`) tam eşleşmeyle izin verilir. İzin listesi, yasak listesinden güvenlidir: yasak listesine
   `169.254.169.254` yazarsın ama saldırgan onu başka gösterimlerle (ondalık sayı, DNS adı, yönlendirme)
   yazar.
2. **Altyapı katmanı:** **IMDSv2** gibi korumalı metadata sürümü. Oturum tabanlıdır: önce bir `PUT`
   isteğiyle kısa ömürlü bir belirteç alınır, sonraki isteklerde bu belirteç özel bir başlıkla gönderilir.
   Basit bir SSRF genellikle isteğin yöntemini ve başlıklarını denetleyemediği için bu korumayı
   aşamaz. Ayrıca rol, **en az yetkiyle** sınırlanmalıdır ki kimlik sızsa bile zarar küçük kalsın.

İzin verilecek alan adlarına bak:
""", komut="cat bulut/ssrf/uygulama/izinli_alanlar.txt"),
]

GOREVLER = [
    Gorev("Metadata servisi nedir ve bir SSRF açığıyla nasıl kötüye kullanılır?",
          Secmeli([
              ("Sunucu hakkında bilgi ve geçici kimlik veren iç servistir; SSRF onu tetikler",
               "Doğru. İstek sunucunun içinden geldiği için servis cevap verir ve bulut kimlik bilgileri sızabilir."),
              ("Dışarıdan herkesin eriştiği bir yedek depolama servisidir ve SSRF onu yalnızca yavaşlatır",
               "Yanlış. Metadata servisi dışarıya kapalıdır; tehlike, uygulamanın onu dışarıdan tetiklenebilmesidir."),
              ("Bir veritabanı yedeğini şifreleyen servistir ve SSRF anahtarını silmeye yarar",
               "Yanlış. Metadata servisinin yedekleme ya da şifrelemeyle ilgisi yok."),
              ("Yalnızca ağ yöneticisinin kullandığı bir ping aracıdır ve SSRF yalnızca ping'i engeller",
               "Yanlış. Bir araç değil, sunucunun kimlik ve bilgi sunan iç servisidir."),
          ], dogru=0),
          ("Adres `169.254.169.254`: dışarıdan erişilebilir mi?",
           "Uygulama kullanıcının verdiği adrese istek atıyorsa istek nereden çıkar?",
           "İç servis + uygulamanın isteği = kimlik bilgisi sızıntısı."),
          puan=20, baslik="Metadata ve SSRF"),
    Gorev("`onizleme.py` içinde **kullanıcıdan gelen adresi denetlemeden** ağ isteğine veren, yani SSRF'e açık "
          "işlevin adı nedir?",
          Metin("fonk", bicim="işlev adı"),
          ("Üç işlevden ikisi sabit adrese istek atıyor.",
           "`grep -n 'def \\|urlopen' bulut/ssrf/uygulama/onizleme.py`: hangi `urlopen` bir parametreyi **olduğu gibi** alıyor?",
           "Adresin tamamını parametreden alan işlev."),
          puan=30, baslik="Zafiyetli işlev"),
    Gorev("Erişim logunda **metadata adresine (169.254.169.254)** giden kaç istek var?",
          Sayi("meta_sayi", sik_hatalar=_meta_hata),
          ("Adresi doğrudan arayabilirsin.",
           "`grep -c` satırları sayar. İç ağa giden diğer şüpheli istekleri sayma.",
           "`grep -c '169.254.169.254' bulut/ssrf/erisim_logu.txt`"),
          puan=20, baslik="Metadata istekleri"),
    Gorev("Bu metadata isteklerini yapan **dış IP** hangisi?",
          IP("saldirgan"),
          ("Logun ilk sütunu istemci IP'sidir.",
           "Önceki görevdeki süzgeçle satırları al, ilk sütunu çek.",
           "`grep '169.254.169.254' bulut/ssrf/erisim_logu.txt | awk '{print $1}' | sort | uniq -c`"),
          puan=30, baslik="Saldırgan IP"),
    Gorev("Saldırgan **hangi rolün** kimlik bilgilerini istedi? (Sadece rol adı.)",
          Metin("rol", sik_hatalar=_rol_hata, bicim="rol adı"),
          ("Son metadata isteğinin yoluna bak.",
           "`iam/security-credentials/` yolundan **sonra** gelen kısım, rol adıdır.",
           "`grep -oE 'security-credentials%2F[A-Za-z0-9-]+' bulut/ssrf/erisim_logu.txt` ve `%2F` sonrasını al."),
          puan=30, baslik="Hedeflenen rol"),
    Gorev("`<<fonk>>` işlevini **izin listesiyle düzelt**: yalnızca `http`/`https` şemasına ve yalnızca "
          "`<<izinli1>>` ile `<<izinli2>>` alan adlarına istek atsın; başka her adres hata versin. "
          "Bitince `cevap 6`.",
          Durum(_duzelt, "IZINLI_ALANLAR + urlparse(...).hostname tam eşleşme + şema denetimi"),
          ("Denetimi `urlopen` çağrısından **önce** yap.",
           "`urllib.parse.urlparse(adres)` ile `.scheme` ve `.hostname` alanlarını al; `hostname` listede olmalı.",
           "`nano bulut/ssrf/uygulama/onizleme.py`: üstte `IZINLI_ALANLAR = {...}`; işlevde `p = urllib.parse.urlparse(<<param>>)` ve `if p.scheme not in (\"http\",\"https\") or p.hostname not in IZINLI_ALANLAR: raise ValueError(...)`."),
          puan=60, baslik="İzin listesi"),
    Gorev("IMDSv2'nin SSRF'e karşı sağladığı temel fayda nedir?",
          Secmeli([
              ("Oturum belirteci ister; basit bir SSRF çoğu zaman bunu üretemez",
               "Doğru. Düz bir GET isteği yeterli olmaz; ayrıca rol en az yetkiyle sınırlanmalıdır."),
              ("Metadata adresini internete açar ki saldırgan nereden geldiğini kolayca görebilsin",
               "Yanlış. Tersine, adres iç ağa özeldir ve dışarıya açılmaz."),
              ("Sunucunun tüm günlüklerini silerek SSRF izlerinin görünmesini engeller",
               "Yanlış. Günlük silmek savunma değildir; tespiti ortadan kaldırır."),
              ("Kimlik bilgilerini hiç üretmez; roller artık yalnızca kağıt üzerinde bulunur",
               "Yanlış. Roller çalışmaya devam eder; sadece onlara erişim zorlaştırılır."),
          ], dogru=0),
          ("IMDSv2 oturum tabanlıdır.",
           "Önce bir PUT isteğiyle belirteç alınır, sonra belirteç başlıkta gönderilir.",
           "Basit SSRF yöntem ve başlıkları denetleyemez."),
          puan=20, baslik="IMDSv2"),
    Gorev("SSRF'e karşı neden 'yasak listesi' yerine **izin listesi** tercih edilir?",
          Secmeli([
              ("Yasak listesi başka gösterimlerle aşılır; izin listesi yalnızca bilinene izin verir",
               "Doğru. Yasak listesindeki bir adresi ondalık, DNS adı ya da yönlendirmeyle gizlemek mümkündür."),
              ("İzin listesi daha kısa yazıldığı için bilgisayarı daha hızlı çalıştırır",
               "Yanlış. Seçim hızla değil, güvenlik garantisiyle ilgilidir."),
              ("Yasak listesi yalnızca Windows'ta çalışır, izin listesi ise sadece Linux'ta",
               "Yanlış. İkisi de platformdan bağımsız mantıksal denetimlerdir."),
              ("İzin listesi kullanıcıdan hiç adres almayı bırakır, bu yüzden uygulama özelliği kaybolur",
               "Yanlış. İzin listesi, özelliği korur; yalnızca izinli hedeflere sınırlar."),
          ], dogru=0),
          ("Yasak listesi 'bilinen kötüleri' sayar; kötüyü yazmanın kaç yolu var?",
           "Ondalık IP, DNS adı, yönlendirme.",
           "İzin listesi: bilinen iyiye izin, gerisi red."),
          puan=20, baslik="İzin listesi neden"),
]


def _kapanis():
    return """
SSRF, bulutta bir web açığının doğrudan bulut kimliğine açılmasıdır: uygulama saldırganın yerine iç
servise istek atar ve geçici kimlik bilgileri dışarı sızar. Saldırgan metadata dizinini gezer, rol adını
öğrenir ve o rolün kimliğini ister; her adım logda bir `url=` satırıdır. Savunma dersi: kullanıcıdan
alınan adresi **izin listesiyle** ve `hostname` tam eşleşmesiyle denetle, şemayı kısıtla, yönlendirmeleri
(redirect) izleme, IMDSv2'yi zorunlu kıl, rolü en az yetkiyle sınırla ve `169.254.169.254` isteklerini
uygulama loglarında alarm olarak tanımla.
"""


SEVIYE = Seviye(
    kimlik="c12b04",
    cilt=12,
    bolum=4,
    baslik="Metadata, SSRF ve Bulut Savunması",
    brifing="""
Selin acil bir not bırakmış: "**<<musteri>>**. <<sahne>> Uygulama kodunun bir kopyasını ve web erişim
logunu aldık. Üç şey lazım: kodda zafiyetli işlev hangisi, logda saldırgan ne yaptı, ve işlevi nasıl
düzeltiriz? İç adreslere **hiç istek atmayacaksın**: her şey dosyada."

Deniz ekliyor: "Saldırgan hangi rolün kimliğini istemişse, o rolü hemen kısıtlayacağım. Rol adı bende
yok."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Capital One 2019:** Kamuya açıklanan bilgilere göre saldırgan, internete açık bir uygulamanın
  yanlış yapılandırılmasından yararlanarak sunucunun metadata servisine istek attırdı ve bir rolün
  geçici kimlik bilgilerini aldı; rol gereğinden geniş yetkiliydi. Bu bölümdeki üç ders aynıdır:
  SSRF'i kapat, metadata'yı koru, rolü daralt.
- **IMDSv2:** Bulut sağlayıcıları, metadata servisi için oturum belirteci isteyen korumalı sürümler
  sunar; kamuya açık belgelerde bu, SSRF türü saldırılara karşı alınan bir önlem olarak anılır.
- **Tespit ve önleme:** Uygulama erişim loglarında `169.254.169.254` ya da iç adres aralıkları
  için alarm kuralı, bulut günlüklerinde bir rolün alışılmadık bir IP'den kullanılması, uygulamada
  giden istekler için izin listesi ve ağ düzeyinde çıkış (egress) kısıtlaması en yaygın önlemlerdir.
""",
    sure_hedef_dk=40,
)
