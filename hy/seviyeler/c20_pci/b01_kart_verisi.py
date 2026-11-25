"""Cilt 20 · Bölüm 1 — Kart Verisi Nedir, Neden Hassas?

Beceri: kart verisi bileşenlerini (PAN, son kullanma, kart sahibi, CVV/CVC, track/çip verisi) ayırt etmek,
bir veritabanı şemasında saklanması yasak alanları bulmak, bir yedek dosyasında açık PAN içeren satırları
saymak ve eski terminal kayıtlarında tam track verisi tutan dosyayı bulmak.

Kart numaraları YALNIZCA herkesçe bilinen test kartı numaralarıdır. Vakalar: e-ticaret, fintech, hastane
tahsilat sistemi.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c20_pci.ortak import TEST_PAN, maske, sec_doldur, sh, token

PAN_YORUM = "kartın 16 haneli numarası (PAN)"
CVV_YORUM = "kartın arkasındaki güvenlik kodu"
TRK_YORUM = "manyetik şerit (track) verisi"

VAKALAR = [
    {"vaka": "Pazarix — e-ticaret ödeme tablosu", "musteri": "Pazarix", "tablo": "odemeler",
     "klasorler": ("veritabani", "yedekler", "terminal_kayitlari"), "pan": "kart_no", "yasak": ["cvv"],
     "kolonlar": [("siparis_no", "TEXT", "sipariş numarası"), ("kart_no", "VARCHAR(19)", PAN_YORUM),
                  ("son_kullanma", "CHAR(5)", "AA/YY"), ("kart_sahibi", "TEXT", "kart üzerindeki isim"),
                  ("cvv", "CHAR(3)", CVV_YORUM), ("tutar", "NUMERIC", "TL")],
     "track_dosya": "eski_test.log", "taklit_dosya": "pos_gunluk.txt", "kisi": "Tuncay Bey (sistem yöneticisi)",
     "sahne": "Pazarix, kampanya haftası öncesi PCI hazırlık denetiminde. Tuncay Bey: \"Ödeme tablosunun şemasını ve "
              "eski bir yedeği çıkardım. Ne tuttuğumuzu bilmiyorum; kart verisinin ne kadarını saklıyoruz, "
              "bakar mısın?\""},
    {"vaka": "Paramix — işlem kayıtları", "musteri": "Paramix", "tablo": "islem_kayitlari",
     "klasorler": ("db", "arsiv", "pos_kayitlari"), "pan": "pan", "yasak": ["guvenlik_kodu", "track2_verisi"],
     "kolonlar": [("islem_id", "TEXT", "işlem kimliği"), ("pan", "VARCHAR(19)", PAN_YORUM),
                  ("skt", "CHAR(5)", "AA/YY"), ("kart_sahibi_adi", "TEXT", "kart üzerindeki isim"),
                  ("guvenlik_kodu", "CHAR(3)", CVV_YORUM), ("track2_verisi", "TEXT", TRK_YORUM),
                  ("tutar", "NUMERIC", "TL")],
     "track_dosya": "terminal_01.dmp", "taklit_dosya": "gunluk_ozet.txt", "kisi": "Ece Hanım (CTO)",
     "sahne": "Paramix, bir bankanın iş ortağı olmak için PCI uyum başvurusu yapıyor. Ece Hanım: \"Denetçi ilk iş "
              "'hangi kart verisini saklıyorsunuz' diye soracak. Şemayı ve eski terminal kayıtlarını önünüze "
              "koyuyorum.\""},
    {"vaka": "Medora Sağlık — online tahsilat", "musteri": "Medora Sağlık", "tablo": "tahsilat",
     "klasorler": ("sema", "eski_aktarimlar", "kasa_cihazlari"), "pan": "kart_numarasi", "yasak": ["cvc"],
     "kolonlar": [("tahsilat_no", "TEXT", "tahsilat numarası"), ("kart_numarasi", "VARCHAR(19)", PAN_YORUM),
                  ("ay_yil", "CHAR(5)", "AA/YY"), ("ad_soyad", "TEXT", "kart üzerindeki isim"),
                  ("cvc", "CHAR(3)", CVV_YORUM), ("tutar", "NUMERIC", "TL")],
     "track_dosya": "kasa3_kayit.txt", "taklit_dosya": "ozet.log", "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
     "sahne": "Medora Sağlık'ın hasta portalındaki online tahsilat, banka denetiminden önce gözden geçiriliyor. "
              "Dr. Aslı Hanım: \"Muhasebe kart bilgilerini 'ileride lazım olur' diye saklamış. Şema ve yedek elimde; "
              "neyin yasak olduğunu bulalım.\""},
]


def uret(rng):
    v = rng.choice(VAKALAR)
    acik = rng.randint(6, 9)
    maskeli = rng.randint(3, 5)
    tok = rng.randint(3, 5)
    satirlar = (["acik"] * acik) + (["maske"] * maskeli) + (["token"] * tok)
    rng.shuffle(satirlar)
    kayitlar = []
    for i, tur in enumerate(satirlar, 1):
        pan = rng.choice(TEST_PAN)
        deger = pan if tur == "acik" else maske(pan) if tur == "maske" else token(rng)
        kayitlar.append((f"K{rng.randint(1000, 9999)}-{i:03d}", rng.choice(u.ISIMLER), deger,
                         f"{rng.randint(20, 3500)}.{rng.randint(0, 99):02d}",
                         f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"))
    return {
        "vaka": v["vaka"], "v": v, "kayitlar": kayitlar, "track_pan": rng.choice(TEST_PAN),
        "metin": {"musteri": v["musteri"], "sahne": v["sahne"], "kisi": v["kisi"], "tablo": v["tablo"],
                  "sema_k": v["klasorler"][0], "yedek_k": v["klasorler"][1], "term_k": v["klasorler"][2],
                  "pan_alan": v["pan"], "taklit": v["taklit_dosya"]},
        "cevaplar": {
            "pan_kolon": v["pan"],
            "yasak": list(v["yasak"]),
            "acik_sayi": acik,
            "track_dosya": v["track_dosya"],
            "maskeli": maskeli,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    sema, yedek, term = v["klasorler"]
    u.yaz(lab / "OKUBENI.txt", f"{v['musteri']} kart verisi denetim kopyası (kurgusal).\n"
          "Kart numaraları herkesçe bilinen TEST numaralarıdır; gerçek kimseye ait değildir.\n"
          f"{sema}/ şema · {yedek}/ eski yedek · {term}/ terminal kayıtları\n")
    satir = [f"-- {v['musteri']} ödeme veritabanı", f"CREATE TABLE {v['tablo']} ("]
    for i, (ad, tip, yorum) in enumerate(v["kolonlar"]):
        virgul = "," if i < len(v["kolonlar"]) - 1 else ""
        satir.append(f"  {ad} {tip}{virgul} -- {yorum}")
    satir.append(");")
    u.yaz(lab / sema / "semasi.sql", "\n".join(satir) + "\n")
    u.yaz(lab / yedek / "odeme_dump.csv", "kayit_no,ad,kart,tutar,tarih\n" + "".join(",".join(r) + "\n" for r in s["kayitlar"]))
    pan = s["track_pan"]
    u.yaz(lab / term / v["track_dosya"],
          "# eski terminal test kaydı\nPOS=03 ONAY=ok\n"
          f"TRK2=;{pan}=2912101123456789012?\nTUTAR=125.00\n")
    u.yaz(lab / term / v["taklit_dosya"],
          "# günlük özet\nPOS=01 ONAY=ok KART=" + maske(TEST_PAN[0]) + "\nTRK2=- (saklanmaz)\nPOS=02 ONAY=ok KART=" + maske(TEST_PAN[1]) + "\n")
    u.yaz(lab / term / "kasa_notlari.txt", "Gün sonu: 14 işlem, 0 hata.\nTRK ve CVV alanları boş bırakıldı.\n")


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    sema, yedek, term = v["klasorler"]
    pan_kolon = sh(f"grep '(PAN)' {sema}/semasi.sql | awk '{{print $1}}'", lab)
    yasak = sh(f"grep 'arkasındaki\\|şerit' {sema}/semasi.sql | awk '{{print $1}}'", lab).replace("\n", " ")
    acik = sh(f"grep -c -E '[0-9]{{16}}' {yedek}/odeme_dump.csv", lab)
    trk = sh(f"grep -rl 'TRK2=;' {term} | head -1 | xargs -n1 basename", lab)
    return sec_doldur({2: pan_kolon, 3: yasak, 4: acik, 5: trk}, GOREVLER, lab, s)


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + b.senaryo["cevaplar"]["maskeli"]:
        return "Maskeli (yıldızlı) satırlar tam PAN değildir. Yalnızca 16 rakamı **ardışık** olanları say."
    if n == beklenen + 1:
        return "Başlık satırını ya da başka bir satırı da saymış olabilirsin; yalnızca 16 ardışık rakamı say."
    return None


def _track_hata(g, beklenen, b):
    taklit = b.senaryo["v"]["taklit_dosya"]
    if g.rsplit("/", 1)[-1] == taklit.casefold():
        return "Bu dosyadaki `TRK2=` satırı boş (`- (saklanmaz)`). Gerçek track verisi `=` işaretinden sonra rakamlarla başlar."
    return None


ADIMLAR = [
    Adim("Kart verisi neyden oluşur?", """
Bir kartın üzerinde ve içinde birkaç ayrı veri vardır; PCI-DSS bunları farklı kurallara bağlar:

- **PAN**: kartın 16 haneli numarası.
- **Son kullanma tarihi** ve **kart sahibi adı**.
- **CVV/CVC**: kartın arkasındaki 3 haneli güvenlik kodu.
- **Track/çip verisi**: manyetik şeritteki ya da çipteki tam veri.

Kural özeti: **CVV ve tam track/çip verisi hiçbir koşulda saklanmaz** (işlem onaylandıktan sonra bile).
PAN ise yalnızca gerçekten gerekliyse ve **şifreli/maskeli** saklanır.
""", komut="cat OKUBENI.txt", sonra="""
Bu lab'daki kart numaraları herkesçe bilinen **test numaralarıdır**. Gerçek kart verisi hiçbir yerde yok.
"""),
    Adim("Şemayı okumak", """
Bir veritabanında hangi verinin tutulduğunu ilk olarak **şemadan** anlarsın. Ödeme tablosunun tanımı:
""", komut="cat <<sema_k>>/semasi.sql", sonra="""
Her kolonun yanındaki yorum ne tuttuğunu söylüyor. Bir kolon adına bakarak karar verme (`cvv` yerine
`guvenlik_kodu` da olabilir); **yoruma ve içeriğe** bak.
"""),
    Adim("Yasak alanı aramak", """
Yasak alanlar kartın arkasındaki kod ve track verisidir. Yorumlarında "arkasındaki" ya da "şerit" geçen
kolonları `grep` ile bul (`\\|` "ya da" demektir):
""", komut="grep -n 'arkasındaki\\|şerit' <<sema_k>>/semasi.sql", sonra="""
**Hacker gözüyle:** Saldırganın aradığı şey tam da bu alanlardır: CVV ve track verisi, kartı **fiziksel olmadan**
kullanabilmenin anahtarıdır. Saklamazsan, çalamaz.
"""),
    Adim("Bir yedeğe bakmak", """
Şema tablonun yapısını söyler; asıl soru **içinde ne olduğu**. Eski bir yedek dosyasının ilk satırları:
""", komut="head -5 <<yedek_k>>/odeme_dump.csv", sonra="""
Kart sütununda üç farklı biçim olabilir: açık numara (16 rakam), **maskeli** numara (`411111******1111`) ve
**token** (anlamsız bir kimlik). İlk biçim sorun, diğer ikisi çözümdür.
"""),
    Adim("Açık PAN'ı saymak", """
`grep -E '[0-9]{16}'` ardışık 16 rakam geçen satırları bulur; `-c` bu satırları sayar:
""", komut="grep -c -E '[0-9]{16}' <<yedek_k>>/odeme_dump.csv", sonra="""
Bu sayı, yedeğin sızması hâlinde **doğrudan kullanılabilecek kart sayısıdır**. Yıldızlı satırlar bu
desene uymaz, çünkü rakamlar ardışık değil.
"""),
    Adim("Terminal kayıtlarında track verisi", """
Eski terminallerin kayıtları unutulmuş dosyalarda yaşar. `TRK2` alanı track verisini taşır; her dosyada bu
alanı ara:
""", komut="grep -rn 'TRK2' <<term_k>>", sonra="""
Bir dosyada alan **boş** (`- (saklanmaz)`), diğerinde `=` işaretinden sonra rakamlar var: bu **gerçek track
verisi**. Aranacak şey kelimenin kendisi değil, yanında veri olup olmadığı.
"""),
]

GOREVLER = [
    Gorev("Aşağıdakilerden hangisi kart verisi için doğru kuraldır?",
          Secmeli([
              ("CVV/CVC ve tam track (çip) verisi hiçbir koşulda saklanamaz",
               "Doğru. Doğrulama verisi işlem onayından sonra bile saklanmaz."),
              ("Kart sahibi adı ve son kullanma tarihi hiçbir koşulda saklanamaz",
               "Yanlış. Bunlar kısıtlı ve korumalı biçimde saklanabilir; asla saklanamayan doğrulama verisidir."),
              ("PAN şifreli olsa bile hiçbir koşulda saklanamaz ve silinmesi zorunludur",
               "Yanlış. PAN, gerçekten gerekliyse şifreli/maskeli saklanabilir; asla saklanamayan CVV ve track verisidir."),
              ("Yalnızca son kullanma tarihi korunur; geri kalan kart verisi serbestçe saklanır",
               "Yanlış. PAN ve diğer alanlar da korunmak zorundadır; CVV/track ise hiç saklanmaz."),
          ], dogru=0),
          ("Kitabın tablosunda 'ASLA saklanamaz' yazan iki satırı hatırla.",
           "Kartın arkasındaki kod ve şeritteki/çipteki tam veri.",
           "Cevap: CVV/CVC ve tam track/çip verisi."),
          puan=20, baslik="Saklanamayan veri"),
    Gorev("`<<sema_k>>/semasi.sql` içinde kartın 16 haneli numarasını (PAN) tutan kolonun adı nedir?",
          Metin("pan_kolon", bicim="kolon adı"),
          ("Kolonların yanındaki yorumlara bak.",
           "Yorumunda '(PAN)' yazan satırın ilk kelimesi kolon adıdır.",
           "`grep '(PAN)' <<sema_k>>/semasi.sql`"),
          puan=20, baslik="PAN kolonu"),
    Gorev("Aynı şemada **hiçbir koşulda saklanmaması gereken** kolonlar var (kartın arkasındaki kod, track verisi). "
          "Kolon adlarını boşlukla yaz.",
          Kume("yasak", tur="metin", bicim="kolon adları, boşlukla ayrılmış"),
          ("Yorumlara bak: 'arkasındaki güvenlik kodu' ve 'manyetik şerit (track)' ifadeleri.",
           "Kolon adı değil, **yorum** belirleyici; `grep` ile iki ifadeyi birlikte ara.",
           "`grep 'arkasındaki\\|şerit' <<sema_k>>/semasi.sql` ve satırların ilk kelimesi."),
          puan=40, baslik="Yasak kolonlar"),
    Gorev("`<<yedek_k>>/odeme_dump.csv` içinde kaç satırda **tam (maskesiz) kart numarası** açık duruyor? "
          "(16 ardışık rakam.)",
          Sayi("acik_sayi", sik_hatalar=_sayi_hata),
          ("Maskeli ve tokenlı satırlar tam PAN değildir.",
           "`grep -E` ile ardışık 16 rakam desenini arayıp sayabilirsin: `[0-9]{16}`.",
           "`grep -c -E '[0-9]{16}' <<yedek_k>>/odeme_dump.csv`"),
          puan=40, baslik="Açık PAN"),
    Gorev("`<<term_k>>` içinde **gerçek track verisi** tutan dosya hangisi? (`TRK2=` alanında veri olan; boş "
          "olanı sayma.) Dosya adını yaz.",
          Metin("track_dosya", sadece_ad=True, bicim="dosya adı", sik_hatalar=_track_hata),
          ("`TRK2` kelimesi birden fazla dosyada geçiyor ama her birinde veri yok.",
           "`grep -rn 'TRK2' <<term_k>>` çıktısında `=` işaretinden sonra rakam olan satırı bul.",
           "`grep -rl 'TRK2=;' <<term_k>>`"),
          puan=40, baslik="Track verisi"),
    Gorev("PAN hangi koşullarda saklanabilir?",
          Secmeli([
              ("Yalnızca gerçekten gerekliyse ve şifreli ya da maskeli biçimde",
               "Doğru. PAN, gereksizse tutulmaz; tutulacaksa korunur."),
              ("Ödeme sağlayıcıdan ayrı bir tabloya kopyalandığı sürece açık biçimde de saklanabilir",
               "Yanlış. Ayrı tablo bir koruma değildir; açık PAN yine açıktır."),
              ("Müşteri 'sonraki alışverişte hatırla' kutusunu işaretlediğinde her biçimde saklanabilir",
               "Yanlış. Müşteri onayı güvenlik kuralını değiştirmez; saklanan PAN yine korunmalıdır."),
              ("İşlem tutarı küçükse korumasız saklanabilir; kural yalnızca yüksek tutarlar içindir",
               "Yanlış. Kural, tutara bakmaz; her kart verisi aynı biçimde korunur."),
          ], dogru=0),
          ("Kitaptaki PAN satırının 'Saklanabilir mi?' sütununu hatırla: şifreli/maskeli, kısıtlı.",
           "Önce 'gerçekten gerekli mi' sorusu, sonra 'korunmuş mu' sorusu.",
           "Cevap: gerekliyse ve şifreli/maskeli."),
          puan=20, baslik="PAN koşulu"),
    Gorev("PCI-DSS'in ana felsefesi 'saklamadığın veri çalınamaz'dır. Bu, yukarıdaki bulgulara nasıl uygulanır?",
          Secmeli([
              ("CVV/track'i hiç saklamamak ve gereksiz PAN'ı silmek; risk kaynağında yok olur",
               "Doğru. Çalınacak veri yoksa ihlalin değeri de yoktur."),
              ("Verileri sakladıktan sonra çok güçlü bir güvenlik duvarı arkasına almak yeterlidir",
               "Yanlış. Savunma katmanları gerekli ama en güçlü savunma, veriyi hiç tutmamaktır."),
              ("Yalnızca erişim günlüklerini tutmak; kimin okuduğu belli olunca risk kalmaz",
               "Yanlış. Günlük, olayı sonradan gösterir; çalınmayı önlemez."),
              ("Veriyi daha uzun süre saklayıp ihlalde müşteriye bildirim yapmaya hazırlanmak",
               "Yanlış. Bildirim hazırlığı zararı önlemez; asıl hedef, tutulan veri miktarını azaltmaktır."),
          ], dogru=0),
          ("En iyi savunma, savunacak bir şeyin olmamasıdır.",
           "Bulduğun yasak kolonlar ve açık PAN'lar, 'tutmamak' ilkesinin tersidir.",
           "Cevap: tutma, ya da tutuyorsan azalt."),
          puan=20, baslik="Tutmamak"),
]


def _kapanis():
    return """
Kart verisi saldırganlar için nakit gibidir: çalındığı anda satılır ya da kullanılır. Saldırgan gözüyle
en çok aranan şey şemada duran CVV kolonu, yedekte duran açık PAN'lar ve unutulmuş bir terminal
kaydındaki track verisidir. Savunma gözüyle çözüm bellidir: doğrulama verisini asla saklama, PAN'ı gerekmedikçe
tutma, tutuyorsan maskele ya da şifrele, eski yedeklerin ve terminal kayıtlarının peşinden düzenli git.
"""


SEVIYE = Seviye(
    kimlik="c20b01", cilt=20, bolum=1, baslik="Kart Verisi Nedir, Neden Hassas?",
    brifing="""
<<sahne>>

Selin: "PCI-DSS'e girmeden önce **neyi koruduğumuzu** bilmeliyiz. Şema, yedek ve terminal kayıtları `<<sema_k>>`,
`<<yedek_k>>` ve `<<term_k>>` klasörlerinde. Hepsi test kart numaralarıyla dolu, gerçek veri yok; ama müşterinin
sistemi gerçek olsaydı bunlar bir ihlalin ilk satırı olurdu."

Mert: "Yedekler hep unutulur. Üretim temizdir ama dört yıllık bir yedek ağzına kadar kart dolu çıkar."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Saklama yasakları:** PCI-DSS, doğrulama verisinin (CVV/CVC, tam track/çip verisi) yetkilendirmeden sonra
  saklanmasını yasaklar; PAN saklanacaksa okunamaz hâle getirilmesini (şifreleme, maskeleme, token) şart koşar.
  Bu kurallar standardın en temel ve en bilinen maddeleridir.
- **Tespit:** Kart verisi keşfi (data discovery) için yedekler, günlükler ve paylaşılan klasörler düzenli taranır;
  taramada 16 ardışık rakam deseni (ve ödeme sağlayıcının test numaraları dışında kalan eşleşmeler) aranır. Pratikte
  eşleşmeler ayrıca doğrulanır, çünkü her 16 haneli sayı kart değildir.
- **Önleme:** Sistemi tasarlarken kart verisini hiç almamak (ödeme sayfasını sağlayıcıya yaptırmak), eski yedekleri
  imha etmek ve şemalarda CVV/track kolonu bulunmamasını geliştirme sürecinde kontrol etmek. "Saklamadığın veri
  çalınamaz" ilkesi bu yüzden PCI-DSS'in omurgasıdır.
""",
    sure_hedef_dk=30,
)
