"""Cilt 10 · Bölüm 1 — Finansal Sistemler Neden Farklı?

Beceri: finansal bir uygulamayı tanımak (canlı uç nokta + defter), hesap bakiyelerini işlem
defteriyle karşılaştırıp "sessiz" sapmayı bulmak (tespit ve denetim), dört farkı ve iş mantığı
açığı kavramını ayırt etmek.

Vakalar: banka, dijital cüzdan, ödeme altyapısı, lojistik tahsilat, hastane fatura — her birinde
aynı mutabakat (bakiye = defter toplamı) farklı hikâye ve klasör adlarıyla sorulur.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

KLASORLER = {"ferah": "muhasebe", "paramix": "cuzdan_defteri", "pazarix": "mutabakat",
             "kuzgun": "tahsilat_kayitlari", "medora": "fatura_kayitlari"}
ACIKLAMALAR = {
    "ferah": ["EFT gelen", "havale giden", "maaş yatışı", "kredi kartı ödemesi", "ATM çekimi", "faiz geliri"],
    "paramix": ["cüzdana yükleme", "market ödemesi", "kişiden kişiye gönderim", "iade", "ulaşım ödemesi", "kampanya puanı"],
    "pazarix": ["sipariş tahsilatı", "iade", "komisyon kesintisi", "hakediş aktarımı", "kargo bedeli", "chargeback"],
    "kuzgun": ["bayi tahsilatı", "iade faturası", "navlun bedeli", "gecikme faizi", "mahsup", "çek tahsili"],
    "medora": ["fatura ödemesi", "sigorta mahsubu", "iade", "ek muayene bedeli", "peşinat", "indirim"],
}


def uret(rng):
    kod, v = o.vaka_sec(rng, KLASORLER)
    s = o.taban(rng, kod)
    for m in s["musteriler"]:
        m["bakiye_kurus"] = rng.randrange(900000, 4000000, 25)
    sapan = rng.choice(s["musteriler"][1:])
    fark = rng.randint(3, 19)
    ledger = []                                         # (hesap_id, zaman, tutar, aciklama)
    gun = u.gun(rng)
    for m in s["musteriler"]:
        hedef = m["bakiye_kurus"] - (fark if m is sapan else 0)
        hareketler = [rng.choice([-1, 1]) * rng.randrange(2000, 40000, 25) for _ in range(rng.randint(4, 8))]
        acilis = hedef - sum(hareketler)
        ledger.append((m["hesap_id"], gun, acilis, "açılış bakiyesi"))
        for h, t in zip(hareketler, u.zamanlar(rng, gun, len(hareketler), 600, 5400)):
            ledger.append((m["hesap_id"], t, h, rng.choice(ACIKLAMALAR[kod])))
    rng.shuffle(ledger)
    ledger.sort(key=lambda x: x[1])
    s["ledger"] = ledger
    s["klasor"] = KLASORLER[kod]
    s["sapan"] = sapan
    ben = s["musteriler"][0]
    s["metin"].update({"klasor": s["klasor"]})
    s["cevaplar"] = {
        "bakiye": ben["bakiye_kurus"],
        "toplam": sum(m["bakiye_kurus"] for m in s["musteriler"]),
        "sapan": sapan["hesap_id"],
        "fark": fark,
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    k = s["klasor"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['musteri']} — {s['v']['ad']}\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Senin test hesabın    : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}   (isteklerde  -H 'X-Oturum: <anahtar>'  ile gönder)\n\n"
          f"Dosyalar:\n  uygulama/mantik.py        uygulamanın iş kuralları\n"
          f"  {k}/hesap_bakiyeleri.csv  gün sonu bakiye özeti\n"
          f"  {k}/islem_defteri.csv     bütün hareketlerin defteri (açılış bakiyesi dahil)\n\n"
          "Selin'den not: Para her zaman bir yerden bir yere gider. Yoktan var olmamalı.\n")
    o.uygulama_yaz(lab, s, o.KOD_SAGLIK)
    u.yaz(lab / k / "hesap_bakiyeleri.csv", "hesap_id;sahip;bakiye_kurus\n" + "".join(
        f"{m['hesap_id']};{m['ad']};{m['bakiye_kurus']}\n" for m in sorted(s["musteriler"], key=lambda m: m["hesap_id"])))
    u.yaz(lab / k / "islem_defteri.csv", "no;zaman;hesap_id;tutar_kurus;aciklama\n" + "".join(
        f"{i};{t:%Y-%m-%d %H:%M:%S};{h};{tutar};{ac}\n" for i, (h, t, tutar, ac) in enumerate(s["ledger"], 1)))


FARK_KOMUT = ("awk -F';' 'NR==FNR{if(FNR>1)b[$1]=$3; next} FNR>1{t[$3]+=$4} "
              "END{for(h in t) if(t[h]!=b[h]) print h, b[h]-t[h]}' {k}/hesap_bakiyeleri.csv {k}/islem_defteri.csv")


def coz(lab: Path, s: dict) -> dict:
    k = s["klasor"]
    ben = s["musteriler"][0]
    _, yanit = o.curl(s, lab, "GET", "/hesabim")
    bak = o.sh(f"awk -F';' 'NR>1{{s+=$3}} END{{print s}}' {k}/hesap_bakiyeleri.csv", lab)
    sapma = o.sh(FARK_KOMUT.replace("{k}", k), lab).split()
    cozum = {1: str(yanit["bakiye_kurus"]), 2: bak, 3: sapma[0], 4: sapma[1].lstrip("-")}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Para her zaman iz bırakır", """
Bu cilt sıradan bir web uygulamasına değil, **paranın aktığı bir uygulamaya** bakıyor. Bir
blogu hacklemekle bir bankayı hacklemek arasındaki fark teknik değil, **sonuç** farkıdır:
saldırganın ödülü soyut bir "erişim" değil, doğrudan paradır.

Bu cildin tamamında **oyunun kendi küçük bankacılık uygulaması** üzerinde çalışacaksın:
`Ferah Mini`. Kurgusaldır, sadece senin bilgisayarında (127.x adresinde) çalışır, gerçek para
ya da gerçek kişi yoktur. Önce lab klasörüne bak:
""", komut="cat OKUBENI.txt"),
    Adim("Canlı uygulama ayakta mı?", """
Uygulama, görev kabuğu açık olduğu sürece arka planda çalışır. Web'deki gibi `curl` ile
konuşursun. `/saglik` kimlik istemeyen basit bir "yaşıyor musun?" ucudur:
""", komut="curl -s http://<<adres>>/saglik", sonra="""
Cevap JSON biçiminde (süslü parantezli anahtar-değer listesi). API'ler insan için değil,
**makineler için** konuşur; bu yüzden güvenlik testlerinden kaçmaları kolaydır.
"""),
    Adim("Kimliğini göster", """
Finansal uygulamalarda neredeyse her uç, **kim olduğunu** ister. Burada kimlik, isteğe eklenen
`X-Oturum` başlığındaki anahtardır (gerçekte JWT ya da oturum çerezi olurdu). Kendi hesabının
bilgisini iste:
""", komut="curl -s -H 'X-Oturum: <<token>>' http://<<adres>>/hesabim", sonra="""
Bakiyeye dikkat: **kuruş** cinsinden tam sayı. 125,50 TL, `12550` olarak saklanır. Para için
ondalıklı sayı (float) kullanmak klasik bir hatadır; nedenini ilerleyen bölümlerde göreceksin.
"""),
    Adim("Defter: paranın günlüğü", """
Her ciddi finansal sistem iki şeyi ayrı tutar: **bakiye** (şu an ne kadar var) ve **defter**
(her hareket, tek tek). İkisi her zaman tutmalıdır: bir hesabın bakiyesi, defterdeki
hareketlerin toplamına eşit olmalıdır. Muhasebedeki **mutabakat** (karşılaştırıp tutturma)
budur. Defterin ilk satırlarına bak:
""", komut="head -4 <<klasor>>/islem_defteri.csv"),
    Adim("Hesap hesap topla", """
`awk` ile defteri hesap numarasına göre toplayacağız. `-F';'` alan ayırıcıyı `;` yapar;
`t[$3]+=$4` 3. alana (hesap) göre 4. alanı (tutar) biriktirir; `NR>1` başlık satırını atlar.
Sonucu bir dosyaya yazıp sıralayalım:
""", komut="awk -F';' 'NR>1{t[$3]+=$4} END{for(h in t) print h\";\"t[h]}' <<klasor>>/islem_defteri.csv | sort > defter_toplam.txt",
         sonra="""
Ekrana bir şey basmadı, çıktı `defter_toplam.txt` dosyasına gitti. Şimdi bakiye özetiyle
karşılaştırma zamanı.
"""),
    Adim("diff ile sapmayı yakala", """
Bakiye özetinden aynı biçimde (`hesap;bakiye`) bir liste çıkarıp `diff` ile defter toplamıyla
karşılaştır. `diff` iki dosyanın farkını gösterir; `-` karakteri "ilk girdi standart girdidir"
demektir. **Hiçbir şey basmazsa her şey tutuyor demektir.**
""", komut="awk -F';' 'NR>1{print $1\";\"$3}' <<klasor>>/hesap_bakiyeleri.csv | sort | diff - defter_toplam.txt",
         sonra="""
Gördüğün `<` satırı bakiye özetindeki, `>` satırı defterden hesaplanan değerdir. Aradaki fark
**kuruşlar**; kimse bunu gözle fark etmez, ama otomatik mutabakat yakalar.

**Hacker gözüyle:** Finansal saldırganlar çoğu zaman sistemi çökertmek istemez, **fark
edilmeden değer çıkarmak** ister. Çalınan bir veritabanı belli olur; her işlemden bir kuruş
fazla ya da eksik hesaplayan bir hata aylarca fark edilmeyebilir. Bu yüzden finansta tespit
ve denetim, önleme kadar önemlidir.
"""),
]

GOREVLER = [
    Gorev("Canlı uygulamadan kendi hesabının bakiyesini iste (`/hesabim`). Bakiyen **kaç kuruş**?",
          Sayi("bakiye"),
          ("Önceki eğitim adımında kimlikle bir istek attın; yanıtta bakiye iki biçimde duruyor.",
           "`curl -s -H 'X-Oturum: <<token>>' http://<<adres>>/hesabim` yaz; `bakiye_kurus` alanına bak.",
           "Yanıttaki `bakiye_kurus` değerini `cevap 1 <sayı>` olarak gönder. TL değil, kuruş."),
          puan=20, baslik="Kendi bakiyem"),
    Gorev("`<<klasor>>/hesap_bakiyeleri.csv` dosyasındaki **tüm hesapların toplam bakiyesi** kaç kuruş?",
          Sayi("toplam"),
          ("Bir sütunu toplamak için `awk` işine yarar; bakiye üçüncü sütun.",
           "`awk -F';' 'NR>1{s+=$3} END{print s}' dosya` gibi bir kalıp.",
           "`awk -F';' 'NR>1{s+=$3} END{print s}' <<klasor>>/hesap_bakiyeleri.csv`"),
          puan=30, baslik="Toplam bakiye"),
    Gorev("Defter toplamı ile bakiyesi **tutmayan** tek bir hesap var. Hesap numarası ne?",
          Metin("sapan", bicim="hesap numarası"),
          ("Önce defteri hesaba göre topla, sonra bakiye özetiyle karşılaştır. Eğitimdeki iki komut yeter.",
           "`diff` çıktısında yalnızca iki farklı satır görünür; ikisi de aynı hesap numarasıyla başlar.",
           "`defter_toplam.txt` ve bakiye listesini `diff` ile karşılaştır; satırın başındaki sayı hesap numarasıdır."),
          puan=40, baslik="Tutmayan hesap"),
    Gorev("Bu hesabın bakiyesi defter toplamından **kaç kuruş** farklı? (mutlak değeri yaz)",
          Sayi("fark", sik_hatalar=lambda g, b, bg: "Fark küçük bir kuruş değeri; iki sayıyı birbirinden "
                "çıkarman yeter, TL'ye çevirme." if g.lstrip("-").isdigit() and abs(int(g)) > 1000 else None),
          ("İki sayı var: bakiye özetindeki ve defterden çıkan. Farklarını al.",
           "Eğitimdeki `diff` çıktısında `<` ve `>` satırlarındaki sayıları çıkar.",
           "`awk` ile aynı anda iki dosyayı okuyup `b[h]-t[h]` yazdırabilirsin; ya da elle çıkar. Negatifse eksiyi at."),
          puan=40, baslik="Fark kaç kuruş"),
    Gorev("Aşağıdakilerden hangisi finansal sistemleri sıradan bir web uygulamasından **ayıran bir fark DEĞİLDİR**?",
          Secmeli([
              ("Finansal sistemler HTTP yerine ayrı bir protokol kullanmak zorundadır", "Doğru: finansal sistemler de çoğunlukla aynı HTTP/HTTPS ve web teknolojilerini kullanır. Fark protokolde değil, sonuçta ve kurallardadır."),
              ("Saldırının ödülü soyut bir erişim değil, doğrudan paradır", "Bu gerçek bir farktır: saldırganın kazancı parayla ölçülür, bu da motivasyonu ve saldırgan profilini değiştirir."),
              ("Transfer, limit, faiz gibi karmaşık iş kuralları güvenliğin parçasıdır", "Bu da gerçek bir farktır: kuralların kendisi saldırı yüzeyidir (iş mantığı açıkları)."),
              ("PCI-DSS, KVKK ve bankacılık mevzuatı gibi düzenlemeler zorunludur", "Bu da gerçek bir farktır: finansal sistemler yoğun düzenlemeye tabidir."),
          ], dogru=0),
          ("Kitaptaki dört farkı hatırla: değer, kurallar, düzenleme, motivasyon.",
           "Üç şık dört farktan birini anlatıyor. Biri hiçbirini anlatmıyor.",
           "Bir bankanın internet şubesi de tarayıcıdan HTTPS ile açılır; protokol aynıdır."),
          puan=20, baslik="Dört fark"),
    Gorev("`<<musteri>>` ekibi \"bizde güvenlik açığı taraması düzenli yapılıyor\" diyor, ama mutabakat farkını "
          "tarayıcı yakalamadı. Aşağıdakilerden hangisi iş mantığı açığını en iyi anlatır?",
          Secmeli([
              ("Uygulama hatasız çalışır ama kural kötüye kullanılabilir", "Doğru: iş mantığı açığında kodda 'hata' yoktur, kötü tasarlanmış bir kural vardır. Tarayıcı imza ya da hata arar; burada ikisi de yok."),
              ("Sunucu yazılımının eski bir sürümünde bilinen bir açık bulunması", "Bu teknik bir açıktır: bilinen sürümler tarayıcılarla yakalanır. İş mantığı açığı sürümden bağımsızdır."),
              ("Veritabanına gönderilen bir girdinin sorguyu bozması", "Bu SQL enjeksiyonudur, teknik bir açıktır. Tarayıcılar bunu çoğu zaman bulur."),
              ("Bir ağ cihazının varsayılan parolasının değiştirilmemesi", "Bu yapılandırma hatasıdır; tarayıcı ya da denetim listesi yakalar. Kural kötüye kullanımı değildir."),
          ], dogru=0),
          ("Tarayıcılar neyi arar? İmzaları ve hata davranışlarını. Peki orada hata yoksa?",
           "Kod 'doğru' çalışıyor; sorun kodun uyguladığı kuralın kendisinde.",
           "Doğru şık, 'çalışıyor ama kural kötüye kullanılabilir' fikrini anlatan şık."),
          puan=30, baslik="İş mantığı açığı"),
    Gorev("Mutabakat farkını insanlar değil otomatik bir karşılaştırma yakaladı. Finansal güvenlikte bu neden bir "
          "**ders**dir?",
          Secmeli([
              ("Önleme yetmediğinde sessiz değer çıkarmayı denetim ve izleme yakalar", "Doğru: kuruşlarla yapılan sessiz kayıplar saldırı gibi görünmez; yakalayan tek şey tutarsızlık denetimidir."),
              ("Mutabakat yapılırsa güvenlik duvarına ve parolalara artık gerek kalmaz", "Yanlış: denetim önlemenin yerine geçmez, onu tamamlar. Savunma katmanlıdır."),
              ("Hesaplardaki farklar yalnızca yuvarlama kaynaklıdır ve her zaman zararsızdır", "Yanlış: bazı farklar yuvarlamadır ama aynı iz bir hırsızlığın ya da hatanın da işareti olabilir; her fark açıklanana kadar şüphelidir."),
              ("Tarayıcılar kuruş farklarını zaten bulur, ek denetim gereksizdir", "Yanlış: tarayıcılar kuralları değil imzaları arar; kuruş farkı onlar için görünmezdir."),
          ], dogru=0),
          ("Saldırgan fark edilmek istemiyorsa seni ne yakalar?",
           "'Önleme' ile 'tespit' arasındaki ilişkiyi düşün: biri başarısız olursa ikincisi devrede.",
           "Doğru şık, denetimin önlemeyi tamamladığını söyleyen şık."),
          puan=30, baslik="Tespit ve denetim"),
]


def _kapanis():
    return """
Bu bölümde hiçbir açık sömürmedin; yalnızca uygulamayı tanıdın ve bir **sapma** yakaladın. Ama
finansal güvenliğin özü bu: hesap bakiyesi ile defterin tutmadığı yerde ya bir hata ya da bir
saldırgan vardır. Saldırgan tarafında hedef çoğu zaman gürültü çıkarmadan küçük miktarlarla uzun
süre değer çıkarmaktır. Savunma tarafında ders: her işlemin izi tutulmalı, bakiye ile defter
otomatik karşılaştırılmalı ve her tutarsızlık açıklanana kadar bir olay sayılmalı. Senin
muhasebe ve bordro geçmişin burada altın değerinde: "bir kuruş nerede kaybolabilir?" sorusunu en
iyi sen sorarsın.
"""


SEVIYE = Seviye(
    kimlik="c10b01",
    cilt=10,
    bolum=1,
    baslik="Finansal Sistemler Neden Farklı?",
    brifing="""
<<sahne>> Selin masana bir klasör bırakıyor: "Bu cildin tamamında **<<musteri>>**'nin küçük, kurgusal
bir kopyası olan Ferah Mini ile çalışacağız. Adresi `<<adres>>`. Önce uygulamayı tanı, sonra
**muhasebe** gözüyle bak: bakiyeler defterle tutuyor mu?"

Mert omzunun üzerinden ekliyor: "Tarayıcılar kuralları bilmez, sayıları bilir. Sen ikisini de
bileceksin. <<kisi>> bu konuda hassas; sonuçları ona anlatman gerekecek."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Bangladeş Merkez Bankası, Şubat 2016:** Saldırganlar ele geçirdikleri erişimle SWIFT ağı
  üzerinden çok sayıda sahte ödeme talimatı gönderdi; bir kısmı yerine ulaştı. Talimatlardan
  birindeki yazım hatası, muhabir bir bankanın şüphelenip durdurmasına yol açtı. Ders: tek bir
  kontrole güvenme; her talimatın ikinci bir gözle ve otomatik tutarlılık denetimiyle
  doğrulanması gerekir (bu bölümdeki mutabakat fikri).
- **Tespit:** Banka ve ödeme şirketleri günlük mutabakat, işlem hacmi/tutar anormalliği alarmları
  ve defter-bakiye karşılaştırmasıyla sessiz sapmaları yakalar. Sızma testlerinde "işlem izi
  yok" ya da "mutabakat otomatik değil" bulgusu bu yüzden önemlidir.
- **Önleme:** Para hareketini yapan kod, her adımda yalnızca bakiyeyi değil defteri de yazmalı;
  para tam sayı kuruşla tutulmalı ve içeriden gelen tehdit de varsayılarak yetki ayrımı
  uygulanmalıdır.
""",
    sure_hedef_dk=20,
)
