"""Cilt 10 · Bölüm 7 — Uyum, Standartlar ve Türkiye'de Finansal Düzenleme.

Beceri: PCI-DSS bakış açısıyla kart verisi taşıyan kayıt ve logları denetlemek (saklanmaması gereken
CVV'yi saymak, tam kart numarası sızdıran log dosyalarını bulmak), veriyi maskeleyen bir dosya
üretmek, loglama kodunu düzeltmek; KVKK ve Türkiye finansal düzenleyicilerini (BDDK, TCMB, KVKK
Kurumu, MASAK...) doğru ilişkilendirmek.

Dikkat: kart numaraları (`9999...` ön ekli, Luhn kurallı) tamamen kurgusaldır. Madde numarası ve ceza
tutarı verilmez; yalnızca kurumların rolleri ve genel ilkeler anlatılır.
Vakalar: banka, dijital cüzdan, ödeme/e-ticaret, hastane tahsilat.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

VAKALAR = {
    "ferah": {"ad": "Ferah Bank — kart işlemleri", "musteri": "Ferah Bank", "klasor": "kart_islemleri",
              "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)", "kurum": ["bddk"],
              "kurum_sorusu": "Ferah Bank bir bankadır. Bankaların bilgi sistemlerinin düzenli sızma testinden geçirilmesini "
                              "şart koşan düzenleyici kurum hangisidir? (kısaltmasıyla yaz)",
              "sahne": "Ferah Bank'ın denetim ekibi, yıllık uyum incelemesi öncesinde kart verisi akışını sana kontrol ettiriyor."},
    "paramix": {"ad": "Paramix — cüzdan kartları", "musteri": "Paramix", "klasor": "cuzdan_kartlari",
                "kisi": "Ece Hanım (CTO)", "kurum": ["tcmb"],
                "kurum_sorusu": "Paramix banka değil, ödeme ve elektronik para hizmeti veren bir fintech şirketi. Kitaba göre "
                                "bu tür kuruluşlar hangi kurumun gözetimindedir? (kısaltmasıyla yaz)",
                "sahne": "Paramix, kuruluş izni sürecinde kart verisi yönetimini kanıtlamak zorunda; Ece Hanım sana bir inceleme istiyor."},
    "pazarix": {"ad": "Pazarix — sanal pos", "musteri": "Pazarix", "klasor": "sanalpos",
                "kisi": "Tuncay Bey (sistem yöneticisi)", "kurum": ["kvkk kurumu", "kvkk", "kişisel verileri koruma kurumu", "kvkk kurulu"],
                "kurum_sorusu": "Pazarix'in veritabanından müşteri kişisel verileri sızarsa, kişisel verilerin korunmasından "
                                "sorumlu kurum hangisidir?",
                "sahne": "Pazarix bir veri ihlali tatbikatı yapıyor; ilk soru, kart ve kişisel verinin nerede açıkta kaldığı."},
    "medora": {"ad": "Medora Sağlık — hasta tahsilatı", "musteri": "Medora Sağlık", "klasor": "tahsilat",
               "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)", "kurum": ["kvkk kurumu", "kvkk", "kişisel verileri koruma kurumu", "kvkk kurulu"],
               "kurum_sorusu": "Medora, hastaların sağlık bilgisi gibi özel nitelikli kişisel verileri de işliyor. Bu verilerin "
                               "korunmasını denetleyen kurum hangisidir?",
               "sahne": "Medora, hasta tahsilat ekranında kart bilgilerinin nasıl saklandığını denetletmek istiyor."},
}
SIZAN_ADAYLAR = ["uygulama.log", "debug.log", "odeme_servisi.log", "iade_servisi.log", "hata.log"]
GUVENLI_ADAYLAR = ["erisim.log", "entegrasyon.log", "ag_gecidi.log", "denetim.log"]


def _luhn_son(govde: str) -> str:
    toplam = 0
    for i, ch in enumerate(reversed(govde)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        toplam += d
    return str((10 - toplam % 10) % 10)


def sahte_pan(rng) -> str:
    govde = "9999" + "".join(rng.choice("0123456789") for _ in range(11))
    return govde + _luhn_son(govde)


def maskele(pan: str) -> str:
    return pan[:6] + "*" * 6 + pan[-4:]


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    n = rng.randint(12, 16)
    adlar = o.kisi_adlari(rng, n)
    kayitlar = []
    for i, ad in enumerate(adlar, 1):
        pan = sahte_pan(rng)
        skt = f"{rng.randint(1, 12):02d}/{rng.randint(27, 31)}"
        cvv = f"{rng.randint(100, 999)}" if rng.random() < 0.75 else ""
        kayitlar.append((i, ad, pan, skt, cvv, rng.randrange(2500, 480000, 25)))
    if not any(k[4] for k in kayitlar):
        kayitlar[0] = kayitlar[0][:4] + ("417",) + kayitlar[0][5:]
    sizan = sorted(rng.sample(SIZAN_ADAYLAR, rng.randint(2, 3)))
    guvenli = rng.sample(GUVENLI_ADAYLAR, rng.randint(2, 3))
    logs = {}
    for ad in sizan:
        satir = []
        for i in range(rng.randint(8, 12)):
            k = rng.choice(kayitlar)
            satir.append(f"2026-03-{rng.randint(1, 28):02d} {rng.randint(8, 21):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} "
                         f"{rng.choice(['INFO', 'INFO', 'DEBUG'])} odeme kart={k[2]} tutar={k[5]} islem_no={rng.randint(10**9, 10**10 - 1)}")
        logs[ad] = satir
    for ad in guvenli:
        satir = []
        for i in range(rng.randint(8, 12)):
            k = rng.choice(kayitlar)
            satir.append(f"2026-03-{rng.randint(1, 28):02d} {rng.randint(8, 21):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} "
                         f"INFO odeme kart={maskele(k[2])} tutar={k[5]} islem_no={rng.randint(10**9, 10**10 - 1)}")
        logs[ad] = satir
    s = {
        "vaka": v["ad"], "v": v, "kayitlar": kayitlar, "logs": logs, "klasor": v["klasor"], "log_k": "loglar",
        "panlar": [k[2] for k in kayitlar],
        "metin": {"musteri": v["musteri"], "klasor": v["klasor"], "kisi": v["kisi"], "sahne": v["sahne"],
                  "kurum_sorusu": v["kurum_sorusu"], "ornek_pan": kayitlar[0][2]},
        "cevaplar": {
            "cvv_adet": sum(1 for k in kayitlar if k[4]),
            "sizan": sizan,
            "kurum": v["kurum"],
        },
    }
    return s


MANTIK = '''# Ödeme servisi — loglama kodu (düzelteceğin dosya).
# odeme_logla(kart_no, tutar_kurus, sonuc) bir log SATIRI döndürür; servis bunu loglar/uygulama.log'a yazar.


def odeme_logla(kart_no, tutar_kurus, sonuc):
    return f"ODEME kart={kart_no} tutar={tutar_kurus} sonuc={sonuc}"
'''


def yaz(lab: Path, s: dict) -> None:
    k = s["klasor"]
    u.yaz(lab / k / "odeme_kayitlari.csv", "no;kart_sahibi;kart_no;skt;cvv;tutar_kurus\n" + "".join(
        f"{a};{b};{c};{d};{e};{f}\n" for a, b, c, d, e, f in s["kayitlar"]))
    for ad, satir in s["logs"].items():
        u.yaz(lab / "loglar" / ad, "\n".join(satir) + "\n")
    u.yaz(lab / "uygulama" / "mantik.py", MANTIK)
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — kart verisi (PCI-DSS) incelemesi\n\n"
          f"{k}/odeme_kayitlari.csv   ödeme kayıt tablosunun dışa aktarımı (KURGUSAL kart numaraları)\n"
          "loglar/                    uygulamanın log dosyaları\n"
          "uygulama/mantik.py         loglama kodu\n\n"
          "Not: Bu cildin diğer bölümlerindeki gibi, bütün veriler kurgusaldır.\n")


def _maskeli_dosya(b) -> Sonuc:
    s = b.senaryo
    yol = b.lab / s["klasor"] / "odeme_kayitlari_maskeli.csv"
    if not yol.exists():
        return Sonuc(False, f"`{s['klasor']}/odeme_kayitlari_maskeli.csv` dosyası yok. Maskeli kopyayı bu adla oluştur.")
    satirlar = [l for l in yol.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not satirlar:
        return Sonuc(False, "Dosya boş.")
    baslik = satirlar[0].split(";")
    if "cvv" in [h.strip().lower() for h in baslik]:
        return Sonuc(False, "CVV sütunu hâlâ dosyada. PCI-DSS, yetkilendirmeden sonra kart doğrulama kodunun saklanmasına izin vermez: sütunu at.", yakin=True)
    if len(satirlar) - 1 != len(s["kayitlar"]):
        return Sonuc(False, f"{len(s['kayitlar'])} kayıt olmalı, dosyada {len(satirlar) - 1} var. Satırları atma, yalnızca maskele.")
    try:
        ik = [h.strip().lower() for h in baslik].index("kart_no")
    except ValueError:
        return Sonuc(False, "`kart_no` sütunu bulunamadı; başlık satırını koru.")
    for sat, ham in zip(satirlar[1:], s["kayitlar"]):
        p = sat.split(";")
        if len(p) != len(baslik):
            return Sonuc(False, f"Bir satırda sütun sayısı başlıkla tutmuyor: {sat[:40]}")
        if re.search(r"\d{11,}", sat):
            return Sonuc(False, "Dosyada hâlâ uzun bir rakam dizisi var; kart numarası yalnızca ilk 6 ve son 4 hane görünecek biçimde maskelenmeli.", yakin=True)
        if p[ik].strip()[-4:] != ham[2][-4:] or "*" not in p[ik]:
            return Sonuc(False, f"Maskelenen kart numarası beklenen biçimde değil ({p[ik]}). Örnek biçim: ilk 6 hane, altı yıldız, son 4 hane.", yakin=True)
        if str(ham[5]) not in p or ham[1] not in p:
            return Sonuc(False, "Kart sahibi adı ve tutar sütunları korunmalı; yalnızca kart numarası maskelenir, CVV atılır.")
    return Sonuc(True, "Maskeli dosya hazır: CVV yok, kart numaraları ilk 6 + son 4 hane görünecek biçimde maskelenmiş.")


def _test_kod(ns, s) -> Sonuc:
    if "odeme_logla" not in ns:
        return Sonuc(False, "`odeme_logla` fonksiyonu yok (silmiş olabilir misin?)")
    for pan in s["panlar"][:3]:
        try:
            satir = str(ns["odeme_logla"](pan, 12550, "onaylandi"))
        except Exception as e:  # noqa: BLE001
            return Sonuc(False, f"odeme_logla hata verdi: {type(e).__name__}: {e}")
        if any(pan[i:i + 11] in satir for i in range(len(pan) - 10)):
            return Sonuc(False, "Log satırında kart numarasının büyük kısmı hâlâ açık. En fazla ilk 6 ve son 4 hane görünebilir.", yakin=True)
        if pan[-4:] not in satir:
            return Sonuc(False, "Son 4 hane log satırında olmalı ki destek ekibi işlemi bulabilsin.", yakin=True)
        if "12550" not in satir or "onaylandi" not in satir:
            return Sonuc(False, "Tutar ve sonuç log satırında kalmalı; yalnızca kart numarası maskelenir.")
    return Sonuc(True, "Log satırlarında kart numarası maskeli: ilk 6 ve son 4 hane dışında görünmüyor.")


def coz(lab: Path, s: dict) -> dict:
    k = s["klasor"]
    cvv = o.sh(f"awk -F';' 'NR>1 && $5!=\"\"' {k}/odeme_kayitlari.csv | wc -l", lab)
    sizan = o.sh("grep -rlE '[0-9]{16}' loglar | cut -d/ -f2 | tr '\\n' ' '", lab)
    o.sh(f"awk -F';' 'BEGIN{{OFS=\";\"}} NR==1{{print $1,$2,$3,$4,$6; next}} "
         f"{{$3=substr($3,1,6) \"******\" substr($3,13,4); print $1,$2,$3,$4,$6}}' "
         f"{k}/odeme_kayitlari.csv > {k}/odeme_kayitlari_maskeli.csv", lab)
    yol = lab / "uygulama" / "mantik.py"
    yol.write_text(o.fonksiyon_degistir(yol.read_text(encoding="utf-8"), "odeme_logla", '''def odeme_logla(kart_no, tutar_kurus, sonuc):
    maskeli = kart_no[:6] + "******" + kart_no[-4:]
    return f"ODEME kart={maskeli} tutar={tutar_kurus} sonuc={sonuc}"
'''), encoding="utf-8")
    cozum = {1: cvv, 2: sizan, 3: "", 4: "", 5: s["v"]["kurum"][0]}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


def _kume_hatasi(g, beklenen, b):
    if "/" in g:
        return "Dosya adlarını klasör olmadan yaz (örn. `uygulama.log`); `grep -rl` çıktısındaki `loglar/` ön ekini at."
    return None


ADIMLAR = [
    Adim("PCI-DSS: ne saklanır, ne saklanmaz", """
**PCI-DSS**, kart verisini saklayan, ileten ya da işleyen her kurumun uyması gereken güvenlik
standardıdır. Temel fikir sade: **saklamadığın veri çalınamaz.** Kart numarası (PAN) saklanacaksa
korunmalı ve görüntülenirken **maskelenmelidir** (en fazla ilk 6 ve son 4 hane). **CVV** gibi kart
doğrulama kodu ise yetkilendirme tamamlandıktan sonra **hiç saklanamaz**.

Önce ödeme kayıt tablosunun dışa aktarımına bak (bütün numaralar kurgusal):
""", komut="head -3 <<klasor>>/odeme_kayitlari.csv"),
    Adim("Saklanmaması gerekeni say", """
CVV, `cvv` sütununda (5. alan). Boş olmayanları `awk` ile süzüp `wc -l` ile sayabilirsin
(`$5!=""` beşinci alan boş değil demektir):
""", komut="awk -F';' 'NR>1 && $5!=\"\"' <<klasor>>/odeme_kayitlari.csv | wc -l", sonra="""
Bu sayı, standardı ihlal eden **kayıt sayısı**dır. Her biri bir veri ihlalinde doğrudan kullanılabilecek
bir doğrulama kodu demek.
"""),
    Adim("Loglarda sızıntı avı", """
Kart numarası yalnızca veritabanında değil, **loglarda** da açıkta kalır. Bunu bulmanın yolu desen
aramaktır: 16 art arda rakam. `-r` klasörü gezer, `-l` yalnızca eşleşen dosyaların adını yazar,
`-E` genişletilmiş desen kullanır:
""", komut="grep -rlE '[0-9]{16}' loglar", sonra="""
Listelenen dosyalarda tam kart numarası var. Diğer log dosyalarında numaralar maskeli ya da yok.
Gerçek sızma testlerinde bu tür desen avı (kart, TC kimlik no, IBAN) rutin bir adımdır.
"""),
    Adim("Bir sızıntıya bak", """
Sızıntılı bir satırı görmek için `grep -m1` her dosyadan ilk eşleşmeyi alır, `-h` dosya adını
gizler:
""", komut="grep -rhm1 -E '[0-9]{16}' loglar"),
    Adim("Maskelemeyi dene", """
Maskeleme: ilk 6 hane (kartı çıkaran bankayı gösterir), ortası yıldız, son 4 hane. `awk`'ta
`substr(metin, başlangıç, uzunluk)` bir parça keser. Örnek bir kart numarasıyla dene:
""", komut="echo <<ornek_pan>> | awk '{print substr($0,1,6) \"******\" substr($0,13,4)}'", sonra="""
Aynı mantığı hem bir **dosyaya** (CSV'yi maskeli kopyaya çevirmek) hem de **koda** (log yazarken
numarayı maskelemek) uygulayacaksın. Asıl çözüm kaynakta: numarayı hiç loglamamak ya da baştan
maskelemek.
"""),
    Adim("Loglama kodunu oku", """
Log satırını üreten fonksiyon `uygulama/mantik.py` içinde. Ne yazdırdığına bak:
""", komut="cat uygulama/mantik.py", sonra="""
`kart_no` olduğu gibi log satırına giriyor. Kodun düzeltmesi küçük: satıra girmeden önce numarayı
maskele. Tek satırlık bir hata, aylarca açık kalan bir sızıntıya dönüşebilir.

**Hacker gözüyle:** Sızma testlerinde log dosyaları, yedekler ve hata ayıklama çıktıları en
verimli veri kaynaklarıdır; çünkü kimse "kayıt"ın bir veri sızıntısı olabileceğini düşünmez.
"""),
    Adim("Türkiye'de kim neyi denetler?", """
Finansal sistemleri test eden biri, hangi kurumun neyi düzenlediğini bilmelidir. Özet: **BDDK**
bankaları ve finansal kuruluşları denetler (bankaların bilgi sistemlerinin düzenli sızma testinden
geçmesi de bu düzenlemelerle zorunludur); **TCMB** ödeme sistemlerini ve ödeme kuruluşlarını
gözetir; **SPK** sermaye piyasalarını; **SEDDK** sigorta ve emekliliği; **MASAK** kara para aklama ve
mali suçlarla mücadeleyi; **KVKK Kurumu** kişisel verilerin korunmasını; **GİB** vergi ve
e-dönüşümü (e-fatura, e-defter) düzenler.

Bu bölümde madde numarası ya da ceza tutarı ezberlemene gerek yok; ama kurumların rolünü ve
"bu bulgu hangi çerçeveyi ilgilendirir?" sorusunu bilmek, raporunu ciddiye aldırır. Bir sonraki
görevlerde bu bilgiyle çalışacaksın.
""", komut=None),
]

GOREVLER = [
    Gorev("`<<klasor>>/odeme_kayitlari.csv` içinde **CVV saklanan kayıt sayısı** kaçtır? (PCI-DSS'e göre "
          "yetkilendirmeden sonra hiç saklanmaması gereken veri)",
          Sayi("cvv_adet", sik_hatalar=lambda g, b, bg: "Başlık satırını da saymış olabilirsin (`NR>1` ile atla)."
                if g.isdigit() and int(g) == b + 1 else None),
          ("CVV, tablonun beşinci sütununda; bazı kayıtlarda boş.",
           "Boş olmayan beşinci alanları süzüp say: `awk` ile `$5!=\"\"` koşulu işine yarar.",
           "`awk -F';' 'NR>1 && $5!=\"\"' <<klasor>>/odeme_kayitlari.csv | wc -l`"),
          puan=30, baslik="Saklanmaması gereken veri"),
    Gorev("`loglar/` klasöründe **tam kart numarası** (16 hane) içeren log dosyaları hangileri? "
          "(dosya adlarını klasörsüz, virgülle ya da boşlukla ayırarak yaz)",
          Kume("sizan", sik_hatalar=_kume_hatasi, bicim="dosya adları (örn. uygulama.log debug.log)"),
          ("16 art arda rakamı arayan bir desen, klasördeki bütün dosyalarda aransın.",
           "`grep -r` klasörü gezer, `-l` yalnızca dosya adlarını yazar, `-E` ile `[0-9]{16}` desenini kullan.",
           "`grep -rlE '[0-9]{16}' loglar` — çıktıdaki `loglar/` ön ekini atıp dosya adlarını yaz."),
          puan=40, baslik="Log sızıntısı"),
    Gorev("**Düzelt (veri):** `odeme_kayitlari.csv` dosyasının **maskeli bir kopyasını** `<<klasor>>/odeme_kayitlari_maskeli.csv` "
          "adıyla oluştur: CVV sütunu atılsın, kart numaraları ilk 6 + `******` + son 4 hane biçiminde olsun, diğer "
          "sütunlar ve satırlar korunsun. Bitince `cevap 3` yaz.",
          Durum(_maskeli_dosya, cozum="awk -F';' 'BEGIN{OFS=\";\"} NR==1{print $1,$2,$3,$4,$6; next} "
                                      "{$3=substr($3,1,6) \"******\" substr($3,13,4); print $1,$2,$3,$4,$6}' "
                                      "<<klasor>>/odeme_kayitlari.csv > <<klasor>>/odeme_kayitlari_maskeli.csv"),
          ("Eğitimde `substr` ile maskelemeyi denedin; aynısını her satırın üçüncü alanına uygula. CVV beşinci alan, onu yazdırma.",
           "`awk` ile her satırda `$3`'ü değiştirip `$1,$2,$3,$4,$6` alanlarını yazdır (5'i atla). Başlık satırı için ayrı kural ve çıktıyı `>` ile yeni dosyaya yönlendir.",
           "`awk -F';' 'BEGIN{OFS=\";\"} NR==1{print $1,$2,$3,$4,$6; next} {$3=substr($3,1,6) \"******\" substr($3,13,4); "
           "print $1,$2,$3,$4,$6}' <<klasor>>/odeme_kayitlari.csv > <<klasor>>/odeme_kayitlari_maskeli.csv`"),
          puan=60, baslik="Düzelt: maskeli kopya"),
    Gorev("**Düzelt (kod):** `uygulama/mantik.py` içindeki `odeme_logla` fonksiyonunu, log satırına tam kart numarası "
          "girmeyecek şekilde değiştir: yalnızca ilk 6 ve son 4 hane görünsün; tutar ve sonuç satırda kalsın. "
          "Bitince `cevap 4` yaz.",
          Durum(o.durum_testi(_test_kod), cozum="`maskeli = kart_no[:6] + \"******\" + kart_no[-4:]` ve satırda `kart={maskeli}` kullan."),
          ("Kart numarasını log satırına koymadan önce bir değişkende maskele.",
           "Python'da dilim: `kart_no[:6]` ilk altı, `kart_no[-4:]` son dört hane.",
           "`maskeli = kart_no[:6] + \"******\" + kart_no[-4:]` yaz, f-string'de `kart_no` yerine `maskeli` kullan."),
          puan=50, baslik="Düzelt: loglama kodu"),
    Gorev("<<kurum_sorusu>>",
          Metin("kurum", bicim="kurum kısaltması"),
          ("Türkiye'deki yedi finansal düzenleyiciyi hatırla: BDDK, SPK, SEDDK, TCMB, MASAK, KVKK Kurumu, GİB.",
           "Sorunun anahtar kelimesi: banka, ödeme kuruluşu ya da kişisel veri.",
           "Bankalar → BDDK; ödeme sistemleri ve ödeme kuruluşları → TCMB; kişisel veri → KVKK Kurumu."),
          puan=20, baslik="Doğru kurum"),
    Gorev("PCI-DSS'e göre ödeme yetkilendirmesi tamamlandıktan sonra aşağıdakilerden hangisi **hiçbir koşulda "
          "saklanmamalıdır**?",
          Secmeli([
              ("Kartın arkasındaki üç haneli doğrulama kodu", "Doğru: kart doğrulama kodu, yetkilendirmeden sonra saklanması yasak olan hassas kimlik doğrulama verisidir."),
              ("Kartın son dört hanesi (maskeli numara)", "Yanlış: maskeli numaranın son dört hanesinin görüntülenmesi ve saklanması izinlidir."),
              ("Kart sahibinin adı ve soyadı (korunarak)", "Yanlış: kart sahibi adı saklanabilir (korunarak); yasak olan, doğrulama kodudur."),
              ("Kartın ilk altı hanesi (kartı çıkaran kurum)", "Yanlış: ilk 6 hane (kartı çıkaran kurumu gösterir), maskeli gösterimin izinli bir parçasıdır."),
          ], dogru=0),
          ("Maskelenmiş numaranın hangi parçaları gösterilebiliyordu? Geriye ne kalıyor?",
           "Kimlik doğrulama amaçlı kullanılan, kartın arkasındaki kod.",
           "Doğru şık, 'CVV' içeren şık."),
          puan=20, baslik="Asla saklanmayacak veri"),
    Gorev("Bir bordro sisteminde KVKK'nın **özel nitelikli kişisel veri** kategorisine girebilecek bilgi aşağıdakilerden hangisidir?",
          Secmeli([
              ("Sendika üyeliği ya da sağlık raporu bilgisi", "Doğru: sağlık ve sendika üyeliği gibi bilgiler özel nitelikli kişisel verilerdir; ekstra koruma (şifreleme, sıkı erişim, minimizasyon) gerektirir."),
              ("Çalışanın çalıştığı bölüm ve unvanı bilgisi", "Yanlış: bu bilgi kişisel veridir ama özel nitelikli kategoriye girmez."),
              ("Çalışanın maaşının yatırıldığı hesabın IBAN numarası", "Yanlış: IBAN finansal olarak çok hassastır ve korunmalıdır, ancak KVKK'nın sayılan özel nitelikli veri türleri arasında değildir."),
              ("Çalışanın şirket içindeki sicil numarası", "Yanlış: kişisel veridir, özel nitelikli değildir."),
          ], dogru=0),
          ("Kitapta bordro bölümünde örnek olarak verilen iki özel nitelikli veri türünü hatırla.",
           "Sağlıkla ve örgütlenmeyle ilgili veriler.",
           "Doğru şık 'sendika' ve 'sağlık' sözcüklerini içeren şık."),
          puan=20, baslik="Özel nitelikli veri"),
    Gorev("Bir sistem PCI-DSS'e uygun bulunmuş olsa da yine güvensiz olabilir mi?",
          Secmeli([
              ("Evet, uyum minimum çizgidir; kontrol varlığını ölçer, riski garanti etmez", "Doğru: uyum 'kutuları işaretlemek'tir; iyi bir güvenlikçi uyumun ötesine geçip gerçek riski arar."),
              ("Hayır, standart bütün saldırı yollarını kapsadığı için uyumlu sistem güvenlidir", "Yanlış: hiçbir standart bütün saldırı yollarını kapsamaz; denetim bir ana ait fotoğraftır."),
              ("Hayır, ancak yalnızca sertifika yenilendiği yıl için geçerli olduğunu varsayabiliriz", "Yanlış: süre değil kapsam sorunu; sertifikalı ve güvensiz olmak aynı yıl içinde de mümkündür."),
              ("Evet, ama bu yalnızca denetimi yapan kişi bir hata yaptığında mümkün olabilir", "Yanlış: denetçi hatasız olsa bile uyum, gerçek güvenlikle eşdeğer değildir."),
          ], dogru=0),
          ("Bu bölümün başında kayıtta CVV bulduk; peki bu sistem standardın dışında mıydı?",
           "Uyum ile güvenlik arasındaki fark: biri minimum çizgi, öteki gerçek risk.",
           "Doğru şık 'uyum minimum çizgidir' diyen şık."),
          puan=20, baslik="Uyum ≠ güvenlik"),
]


def _kapanis():
    return """
Uyum çerçeveleri (PCI-DSS, KVKK, BDDK düzenlemeleri) bu kitabın iyi uygulamalarının finans sektörü için
zorunlu hâle getirilmiş biçimidir: erişim kontrolü, loglama, şifreleme, düzenli sızma testi. Bu bölümde
gördüğün sızıntı (CVV'nin saklanması, loglardaki tam kart numarası) hiçbir "hack" gerektirmez; yalnızca
dikkat eksikliğidir ve tam da bu yüzden en yaygın bulgulardandır. Saldırgan için log dosyaları ve
yedekler altın madenidir; savunma için ilke nettir: **saklamadığın veri çalınamaz**. Bulgularını rapora
yazarken hangi çerçeveyi ilgilendirdiğini (PCI-DSS, KVKK) belirtmek raporuna ağırlık katar. Uyum
asgari çizgidir: sertifika, güvenliğin garantisi değildir.
"""


SEVIYE = Seviye(
    kimlik="c10b07",
    cilt=10,
    bolum=7,
    baslik="Uyum, Standartlar ve Türkiye'de Finansal Düzenleme",
    brifing="""
<<sahne>> <<kisi>>: "Denetçi gelmeden önce kart verisinin nerede durduğunu bilmek istiyoruz." Selin sana bir
dışa aktarım ve bir log klasörü veriyor: "Burada exploit yok, **veri hijyeni** var. Önce saklanmaması gereken
veriyi say, sonra loglarda tam kart numarası sızdıran dosyaları bul. En sonunda hem veriyi hem kodu
düzelt. Raporunda hangi kurumun ya da standardın ilgilendiğini de söyleyebilmelisin."

Mert ekliyor: "Denetçiye 'güvenliyiz' deme. 'Kart verisini şu kadar azalttık, şu kadarı maskeli' de."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Kart verisini saklamamak:** PCI-DSS, yetkilendirme sonrasında kart doğrulama kodunun (CVV)
  saklanmasını yasaklar ve kart numarasının saklanıyorsa korunmasını ve görüntülenirken
  maskelenmesini şart koşar. Kart verisi ihlalleri (örneğin web sitesine yerleştirilen kart
  çalan betikler) pek çok kez kamuoyuna yansımıştır; ders, "veriyi hiç tutma ya da tokenla".
- **Türkiye'de ihlal bildirimi ve düzenleme:** KVKK kapsamında kişisel veri ihlali, Kurul'un
  yayımladığı karara göre en kısa sürede ve en geç 72 saat içinde Kurul'a bildirilir.
  Bankalar için BDDK'nın bilgi sistemleri ve elektronik bankacılık düzenlemeleri sızma testi dahil
  düzenli güvenlik testlerini zorunlu kılar. Ayrıntılı madde ve yaptırım için güncel mevzuata
  (kurumların resmî sitelerine) bakılmalıdır.
- **Tespit ve önleme:** Tespit için loglarda kart/TC kimlik/IBAN deseni taraması ve veri sızıntısı
  önleme (DLP) araçları kullanılır. Önlemek için kaynağında maskeleme, hassas alanları loglamayı
  yasaklayan kod incelemesi, tokenizasyon ve saklama süresi sınırı uygulanır.
""",
    sure_hedef_dk=30,
)
