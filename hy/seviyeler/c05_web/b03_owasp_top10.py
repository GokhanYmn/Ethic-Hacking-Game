"""Cilt 5 · Bölüm 3 — OWASP Top 10: Tehdit Haritası.

Beceri: OWASP Top 10 kategorilerini tanımak, kurgusal bir bulgu listesini doğru kategoriye
eşlemek, risk = olasılık x etki ile öncelik sıralamak, ilk müdahale edilecek bulguyu seçip yönetici
özetine dökmek.

Laboratuvar: web servisi yok; lab'da OWASP listesi (kitaptaki sıralama), bir bulgu listesi ve risk
matrisi var. Bulgular tohumdan üretilir; kategori dağılımı ve risk puanları her oyunda değişir.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Sayi, Secmeli, Serbest
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

KATEGORILER = {
    1: ("Broken Access Control", "Kullanıcı yetkisi olmayan şeye erişir"),
    2: ("Cryptographic Failures", "Zayıf/eksik şifreleme, açık veri"),
    3: ("Injection", "SQLi, komut enjeksiyonu"),
    4: ("Insecure Design", "Tasarımdan gelen güvenlik eksikliği"),
    5: ("Security Misconfiguration", "Varsayılan ayarlar, açık hata mesajları"),
    6: ("Vulnerable Components", "Güncellenmemiş kütüphaneler"),
    7: ("Authentication Failures", "Zayıf giriş, oturum yönetimi"),
    8: ("Data Integrity Failures", "Doğrulanmamış güncellemeler, deserialization"),
    9: ("Logging Failures", "Yetersiz log, saldırıyı görememe"),
    10: ("SSRF", "Sunucuyu kendi iç ağına istek atmaya kandırma"),
}

# Her kategori için üç bulgu cümlesi. {s}: sistem adı. Anahtar sözcükler (coz sınıflandırıcısı) cümlelerde geçer.
HAVUZ = {
    1: ["{s} üzerinde fatura adresindeki `id` değiştirilince başka müşterinin faturası açılıyor.",
        "Normal bir kullanıcı `/yonetim` adresini yazınca yönetici paneline giriyor.",
        "Başka kullanıcının dosyası, adresteki dosya numarası değiştirilerek indirilebiliyor."],
    2: ["{s} kullanıcı parolalarını veritabanında düz metin olarak saklıyor.",
        "Giriş sayfası HTTPS yerine HTTP üzerinden sunuluyor; parola ağda açık gidiyor.",
        "Parolalar tuzsuz MD5 ile özetlenerek saklanıyor."],
    3: ["{s} arama kutusuna tek tırnak girilince 500 hatası ve SQL sorgusu ekrana basılıyor.",
        "Raporlama modülü dosya adını denetlemeden sistem komutuna ekliyor.",
        "Giriş formunda `' OR '1'='1` girdisi parolasız girişe izin veriyor."],
    4: ["{s} parola sıfırlama sorusu \"anne kızlık soyadı\"; cevabı sosyal medyadan bulunabiliyor.",
        "Hediye kartı bakiyesi sınırsız deneme ile sorgulanabiliyor; tasarımda hız sınırı hiç düşünülmemiş.",
        "Kampanya kodu aynı siparişte sınırsız kez kullanılabiliyor; iş kuralı tasarlanmamış."],
    5: ["{s} web kökünde `config.php.bak` yedek dosyası herkese açık.",
        "Hata sayfaları yığın izini (stack trace) ve sunucudaki dosya yollarını gösteriyor.",
        "Dizin listeleme açık: `/yedekler/` klasörünün içeriği tarayıcıda listeleniyor."],
    6: ["{s} sunucusunda dört yıl önceki bir kütüphane sürümü çalışıyor; bilinen CVE kaydı var.",
        "İçerik yönetim sisteminin bir eklentisi güncellenmemiş ve üreticisi kritik açık bildirmiş.",
        "Sayfalarda yıllar önce desteği biten eski bir JavaScript kütüphanesi kullanılıyor."],
    7: ["{s} giriş denemelerine sınır koymuyor; saniyede yüzlerce parola denenebiliyor.",
        "Oturum kimliği kullanıcı adından üretildiği için tahmin edilebiliyor.",
        "Yönetici hesapları çok faktörlü doğrulama olmadan yalnızca parolayla korunuyor."],
    8: ["{s} yazılım güncelleme paketini imza doğrulanmadan indirip kuruyor.",
        "Sunucu, istemciden gelen serileştirilmiş nesneyi doğrulamadan işliyor.",
        "Derleme hattı, üçüncü taraf bir betiği sağlama toplamı denetlemeden çalıştırıyor."],
    9: ["{s} başarısız girişler loglanmıyor; parola deneme saldırıları fark edilmiyor.",
        "Loglar yalnızca sunucuda tutuluyor ve 3 gün sonra siliniyor; olay sonrası inceleme yapılamıyor.",
        "Yönetici panelindeki hiçbir işlem için denetim kaydı yok."],
    10: ["{s} görsel indirme özelliği, kullanıcının verdiği adresi sunucudan çekiyor; iç ağ adresleri de çekilebiliyor.",
         "Webhook test düğmesi sunucunun herhangi bir adrese istek atmasına izin veriyor.",
         "Önizleme servisi verilen URL'yi sunucu tarafında getiriyor; bulut meta veri adresi bile çekilebiliyor."],
}

# coz sınıflandırıcısı: cümleyi gören bir analistin "anahtar" okuması (her kategori için ayırt edici parçalar)
ANAHTARLAR = {
    1: ("başka müşterinin", "yönetici paneline giriyor", "başka kullanıcının dosyası"),
    2: ("düz metin", "HTTPS yerine HTTP", "MD5"),
    3: ("tek tırnak", "sistem komutuna", "' OR '1'='1"),
    4: ("sıfırlama sorusu", "hız sınırı hiç", "iş kuralı tasarlanmamış"),
    5: ("config.php.bak", "yığın izini", "Dizin listeleme"),
    6: ("CVE", "eklentisi güncellenmemiş", "JavaScript kütüphanesi"),
    7: ("giriş denemelerine sınır", "Oturum kimliği kullanıcı adından", "çok faktörlü"),
    8: ("imza doğrulanmadan", "serileştirilmiş", "sağlama toplamı"),
    9: ("loglanmıyor", "3 gün sonra", "denetim kaydı yok"),
    10: ("adresi sunucudan", "Webhook", "URL'yi sunucu tarafında"),
}

VAKALAR = [
    {"kod": "pazarix", "sistem": "Pazarix mağaza sitesinde",
     "olay": "Pazarix, kampanya haftası öncesi bir web uygulaması testi yaptırdı. Tuncay Bey bulgu listesini "
             "yönetime sunacak ama hangi bulgu hangi kategoride ve hangisine önce bakılmalı, bilmiyor."},
    {"kod": "medora", "sistem": "Medora hasta portalında",
     "olay": "Medora Sağlık'ın hasta portalı için bir güvenlik değerlendirmesi bitti. Dr. Aslı Hanım, KVKK "
             "denetimi öncesi bulguları sınıflandırıp önceliklendirmemizi istiyor."},
    {"kod": "ferahbank", "sistem": "Ferah Bank internet şubesinde",
     "olay": "Ferah Bank'ın internet şubesi için yapılan testin bulgu listesi yönetim kuruluna gidecek. "
             "Kaan Bey, her bulgunun OWASP karşılığını ve risk sırasını görmek istiyor."},
    {"kod": "yesiltepe", "sistem": "Yeşiltepe e-Belediye portalında",
     "olay": "Yeşiltepe Belediyesi'nin e-Belediye portalı test edildi. Nurcan Hanım, bütçe talebini haklı "
             "çıkarmak için bulguları kategorilere ayırıp en riskli olanı öne çıkarmak istiyor."},
]


def risk_bandi(p: int) -> str:
    return "Kritik" if p >= 15 else "Yüksek" if p >= 8 else "Orta" if p >= 4 else "Düşük"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    adetler = {1: rng.choice((2, 3)), 3: rng.choice((2, 3)), 5: rng.choice((2, 3))}
    ekstra = rng.sample([2, 4, 6, 7, 8, 9, 10], 4)
    kategoriler = [k for k, n in adetler.items() for _ in range(n)] + ekstra
    rng.shuffle(kategoriler)
    secilen = {k: rng.sample(HAVUZ[k], len(HAVUZ[k])) for k in HAVUZ}
    en_riskli = rng.randrange(len(kategoriler))
    bulgular = []
    for i, kat in enumerate(kategoriler):
        if i == en_riskli:
            ol, et = 5, 5
        else:
            while True:
                ol, et = rng.randint(1, 5), rng.randint(1, 5)
                if ol * et <= 20:
                    break
        bulgular.append({"no": i + 1, "kat": kat, "ol": ol, "et": et, "puan": ol * et,
                         "metin": secilen[kat].pop().format(s=v["sistem"])})
    no_kat = {b["no"]: b["kat"] for b in bulgular}
    ekstra_nolar = [b["no"] for b in bulgular if b["kat"] in ekstra]
    hedefler = ekstra_nolar[:2]
    kritik = sum(1 for b in bulgular if b["puan"] >= 15)
    return {
        "vaka": f"{m['ad']} — bulgu listesi sınıflandırma",
        "musteri": m, "v": v, "bulgular": bulgular, "hedefler": hedefler,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "toplam": len(bulgular),
            "hedef1": hedefler[0], "hedef2": hedefler[1],
            "en_riskli": en_riskli + 1,
            "en_riskli_ozet": bulgular[en_riskli]["metin"],
            "en_riskli_kategori": KATEGORILER[bulgular[en_riskli]["kat"]][0],
        },
        "cevaplar": {
            "a01": [b["no"] for b in bulgular if b["kat"] == 1],
            "a03": [b["no"] for b in bulgular if b["kat"] == 3],
            "a05": [b["no"] for b in bulgular if b["kat"] == 5],
            "k1": no_kat[hedefler[0]],
            "k2": no_kat[hedefler[1]],
            "en_riskli": en_riskli + 1,
            "kritik": kritik,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    u.yaz(lab / "owasp_top10.txt",
          "OWASP Top 10 — kitaptaki sıralama\n\n#   Kategori                     Kısaca\n"
          + "\n".join(f"{n:<3} {ad:<27} {k}" for n, (ad, k) in KATEGORILER.items()) + "\n")
    satirlar = [f"#{b['no']:02d} | Olasılık {b['ol']} | Etki {b['et']} | {b['metin']}" for b in s["bulgular"]]
    u.yaz(lab / "bulgular.txt",
          f"# {m['ad']} — web uygulaması testi, ham bulgu listesi (kategori ve risk henüz atanmadı)\n"
          "# olasılık ve etki 1 (çok düşük) ile 5 (çok yüksek) arasında\n" + "\n".join(satirlar) + "\n")
    u.yaz(lab / "risk_matrisi.txt",
          "Risk puanı = olasılık x etki (en yüksek 25)\n\n"
          "15 - 25 : Kritik  (hemen müdahale)\n 8 - 14 : Yüksek  (bu sprint içinde)\n"
          " 4 -  7 : Orta    (planlı iş)\n 1 -  3 : Düşük   (izle)\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} — bulgu sınıflandırma çalışması (web servisi yok, sadece dosyalar)\n\n"
          "owasp_top10.txt  kategori listesi (numaralar bu dosyadaki sıraya göre)\n"
          "bulgular.txt     sınıflandırılacak ham bulgular\n"
          "risk_matrisi.txt risk puanı ve bantları\n")


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout


def _siniflandir(metin: str) -> int:
    kucuk = metin.lower()
    for kat, anahtarlar in ANAHTARLAR.items():
        if any(a.lower() in kucuk for a in anahtarlar):
            return kat
    raise ValueError(metin)


def coz(lab: Path, s: dict) -> dict:
    bulgular = {}
    for satir in _sh("grep '^#[0-9]' bulgular.txt", lab).splitlines():
        no = int(satir.split("|")[0].strip("# "))
        bulgular[no] = _siniflandir(satir)
    riskler = _sh("awk -F'|' '/^#[0-9]/ {split($2,o,\" \"); split($3,e,\" \"); print substr($1,2)+0, o[2]*e[2]}' bulgular.txt "
                  "| sort -k2 -nr", lab).split("\n")
    en_riskli = int(riskler[0].split()[0])
    kritik = int(_sh("awk -F'|' '/^#[0-9]/ {split($2,o,\" \"); split($3,e,\" \"); if (o[2]*e[2] >= 15) n++} "
                     "END {print n+0}' bulgular.txt", lab).strip())
    def kume(k):
        return " ".join(str(n) for n, kat in bulgular.items() if kat == k)
    secmeli = SEVIYE.gorevler[7].kontrol.cevabi_goster(Baglam(s, lab, 8))[0]
    return {1: kume(1), 2: kume(3), 3: kume(5), 4: str(bulgular[s["hedefler"][0]]),
            5: str(bulgular[s["hedefler"][1]]), 6: str(en_riskli), 7: str(kritik), 8: secmeli,
            9: "Önce bu bulgu çünkü en yüksek risk puanlı; saldırması kolay ve etkisi büyük. Düzeltmesi kısa sürer."}


# ---------------------------------------------------------------- eğitim

def _kat_hata(g, beklenen, b):
    if g.isdigit() and not 1 <= int(g) <= 10:
        return "Kategori numaraları `owasp_top10.txt` içinde 1 ile 10 arasında."
    return None


ADIMLAR = [
    Adim("Web güvenliğinin haritası", """
**OWASP** (Open Worldwide Application Security Project), web güvenliğinin en saygın topluluğudur
ve düzenli olarak en kritik on web açığı kategorisini **Top 10** listesinde yayınlar. Bu liste bir
pentestin kontrol listesidir ve ezberlemen gereken ilk şeydir. Laboratuvardaki kopya, kitaptaki sıralamayı taşır:
""", komut="cat owasp_top10.txt", sonra="""
On kategori, ama bu cilt en sık ve en öğretici üçüne odaklanıyor: **1 Broken Access Control**
(Bölüm 6), **3 Injection** (Bölüm 4) ve **7 Authentication Failures** (Bölüm 7). Diğerlerini
kavradığında geri kalanı aynı mantığın uzantısıdır.
"""),
    Adim("Ham bulgular", """
Bir testin sonunda elinde kategorisi belli olmayan bir bulgu yığını olur. Raporu yazan sensin;
önce ham listeyi oku:
""", komut="cat bulgular.txt", sonra="""
Her satırda bir **olasılık** (saldırının ne kadar kolay/olası olduğu) ve bir **etki** (olursa ne
kadar zarar) puanı var. Satırların metni bir bulguyu tek cümleyle anlatıyor.
"""),
    Adim("Kategoriye eşleme: ipuçları", """
Bir bulguyu doğru kategoriye koymak için "kök neden"e bak, belirtiye değil:

- Başkasının verisi/sayfası açılıyorsa: **erişim kontrolü** (1).
- Girdi bir sorguya ya da komuta karışıyorsa: **injection** (3).
- Açık yedek dosya, ayrıntılı hata sayfası, dizin listeleme: **yanlış yapılandırma** (5).
- Eski kütüphane: **savunmasız bileşen** (6). Zayıf giriş/oturum: **kimlik doğrulama** (7).
- Hiç alarm/log yok: **logging** (9). Sunucu bizim adımıza istek atıyor: **SSRF** (10).

Kategorilerde grep ile avlanmak da bir yöntem: "yedek" geçen bulguları listele:
""", komut="grep -i 'yedek' bulgular.txt", sonra="""
Dikkat: bir kelime tek başına yetmez. "Yedek" kelimesi hem açıkta duran bir dosyada (yanlış yapılandırma)
hem başka bağlamlarda geçebilir; cümlenin **neden** tehlikeli olduğuna bak.
"""),
    Adim("Risk: olasılık x etki", """
Her şey aynı acillikte değildir. Risk matrisine bak:
""", komut="cat risk_matrisi.txt", sonra="""
Basit ama işe yarar bir kural: **risk = olasılık x etki**. Kolay saldırılan ve büyük zarar veren
bulgu en üste çıkar. Bu, "önce neyi düzeltmeliyim?" sorusunun cevabıdır.
"""),
    Adim("awk ile puanla", """
Puanları elle çarpmak yerine awk'a yaptır. Çıktıda ilk sütun bulgu numarası, ikincisi risk
puanı; en yüksek üçü:
""", komut="""awk -F'|' '/^#[0-9]/ {split($2,o," "); split($3,e," "); print $1, o[2]*e[2]}' bulgular.txt | sort -k2 -nr | head -3""",
         sonra="""
Cilt 1'de öğrendiğin `awk`, `sort` ve `head` bir pentesterın rapor önceliklendirme aracı
oldu. Görevlerde bu çıktının tamamını kullanacaksın.

**Hacker gözüyle:** OWASP Top 10, hem saldırganın kontrol listesi hem savunmacının öncelik
sırasıdır. Bir web testine başladığında bu on kategoriyi sırayla kontrol edersin; savunmacı ise aynı listeyi
"önce neyi düzeltmeliyim?" için kullanır. İki taraf da aynı haritayı okur; fark, biri giriş
ararken diğerinin kapıları kapatmasıdır.
"""),
]


GOREVLER = [
    Gorev("`bulgular.txt` içinde **Broken Access Control** (kategori 1) kapsamına giren bulguların numaralarını yaz "
          "(örn. `2 5 9`).",
          Kume("a01", tur="sayi", bicim="bulgu numaraları, boşlukla ayrılmış"),
          ("Başka birinin verisine ya da yetkisiz sayfaya erişim anlatan cümlelere bak.",
           "`grep -n -iE 'başka|yönetim|dosya numarası' bulgular.txt` ile aday satırlar çıkar; sonra cümleleri tek tek oku.",
           "Üç tür cümle: başkasının faturası/dosyası açılıyor, normal kullanıcı yönetici sayfasına giriyor. Numaralar `#NN` biçiminde."),
          puan=30, baslik="Erişim kontrolü bulguları"),
    Gorev("**Injection** (kategori 3) kapsamına giren bulguların numaralarını yaz.",
          Kume("a03", tur="sayi", bicim="bulgu numaraları, boşlukla ayrılmış"),
          ("Girdinin bir sorguya ya da komuta karıştığı belirtilere bak.",
           "`grep -n -iE 'tırnak|sorgu|komut|OR' bulgular.txt`; ama \"OR\" başka kelimelerin içinde de geçer, cümleyi oku.",
           "Tek tırnakla SQL hatası, dosya adının sistem komutuna eklenmesi, `' OR '1'='1` ile girişin bu kategoride olduğunu hatırla."),
          puan=30, baslik="Injection bulguları"),
    Gorev("**Security Misconfiguration** (kategori 5) kapsamına giren bulguların numaralarını yaz.",
          Kume("a05", tur="sayi", bicim="bulgu numaraları, boşlukla ayrılmış"),
          ("Kod hatası değil, ayar/bırakılmış dosya sorunu olanlar.",
           "Açık yedek dosya, ayrıntılı hata sayfası ve dizin listeleme belirtilerini ara: `grep -n -iE 'yedek|hata sayfa|listeleme' bulgular.txt`",
           "Cümlelerde `config.php.bak`, yığın izi (stack trace) ve `/yedekler/` klasörü geçiyor."),
          puan=30, baslik="Yanlış yapılandırma"),
    Gorev("Bulgu **#<<hedef1>>** hangi OWASP kategorisine girer? Kategorinin `owasp_top10.txt` içindeki numarasını yaz.",
          Sayi("k1", sik_hatalar=_kat_hata),
          ("Cümlede belirtiyi değil kök nedeni bul.",
           "`grep '^#0*<<hedef1>> ' bulgular.txt` ile satırı çek; `cat owasp_top10.txt` ile karşılaştır.",
           "Satırı oku; eşleşen kategorinin yanındaki numarayı yaz."),
          puan=25, baslik="Kategori eşleme 1"),
    Gorev("Bulgu **#<<hedef2>>** hangi OWASP kategorisine girer? (Kategori numarası.)",
          Sayi("k2", sik_hatalar=_kat_hata),
          ("Bu bulgu cildin odaklandığı üç kategoriden biri olmayabilir; haritanın tamamına bak.",
           "`grep '^#0*<<hedef2>> ' bulgular.txt` ve `owasp_top10.txt`'deki \"Kısaca\" sütunu.",
           "Kısaca sütununda cümleyle eşleşen ifadeyi bul; sol sütundaki sayı cevap."),
          puan=25, baslik="Kategori eşleme 2"),
    Gorev("Risk puanını (olasılık x etki) hesapla: **en yüksek** puanlı bulgunun numarası nedir?",
          Sayi("en_riskli"),
          ("Her satır için iki sayıyı çarpmalısın.",
           "Eğitimdeki `awk` komutu bunu yapar; sonuna `sort -k2 -nr | head -1` ekle.",
           "`awk -F'|' '/^#[0-9]/ {split($2,o,\" \"); split($3,e,\" \"); print $1, o[2]*e[2]}' bulgular.txt | sort -k2 -nr | head -1`"),
          puan=30, baslik="En riskli bulgu"),
    Gorev("Kaç bulgunun risk puanı **15 ya da daha yüksek** (Kritik)?",
          Sayi("kritik", sik_hatalar=lambda g, b, bg: "Kritik bandın alt sınırı 15; 15'in kendisi de dahil." if g == str(int(b) - 1) else None),
          ("Risk matrisindeki bantlara bak.",
           "awk komutunu önce `print $1, puan` olarak çalıştır; 15 ve üstünü say.",
           "`awk -F'|' '/^#[0-9]/ {split($2,o,\" \"); split($3,e,\" \"); if (o[2]*e[2] >= 15) n++} END {print n+0}' bulgular.txt`"),
          puan=30, baslik="Kritik bulgular"),
    Gorev("Bir kurumun saldırısı dört ay boyunca sürüyor, ama güvenlik ekibi hiç alarm görmedi çünkü uygulama hiçbir "
          "başarısız giriş ya da yönetici işlemini kaydetmiyor. Hangi OWASP kategorisi?",
          Secmeli([
              ("Logging Failures: yetersiz kayıt ve izleme yüzünden saldırı görülemiyor",
               "Doğru. Kaydı ve alarmı olmayan bir sistemde saldırı aylarca fark edilmeden sürebilir."),
              ("Security Misconfiguration: sunucunun varsayılan ayarları değiştirilmemiş",
               "Yanlış yapılandırma ayar hatalarını anlatır; buradaki sorun izleme ve kayıt eksikliğidir."),
              ("Insecure Design: uygulamanın iş kuralları baştan yanlış düşünülmüş",
               "Tasarım hatası başka bir sınıf; bu senaryo saldırının neden fark edilmediğini anlatıyor."),
              ("Authentication Failures: kullanıcıların parolaları çok zayıf seçilmiş",
               "Zayıf parola giriş tarafının sorunudur; senaryodaki ana sorun, saldırının hiç görülmemesi."),
          ]),
          ("Senaryoda saldırının neden bu kadar uzun sürdüğüne odaklan.",
           "Hangi kategori \"saldırıyı görememe\" olarak tanımlanıyor? `cat owasp_top10.txt`",
           "Listedeki 9 numaralı kategori."),
          puan=20, baslik="Alarmsız saldırı"),
    Gorev("Yönetime gidecek özet: en yüksek riskli bulguyu (#<<en_riskli>>) bir iki cümleyle özetle ve neden **ilk** onun "
          "düzeltilmesi gerektiğini söyle. Cevabı tırnak içinde yaz.",
          Serbest("Bulgu #<<en_riskli>> (<<en_riskli_kategori>>): \"<<en_riskli_ozet>>\" Hem olasılığı hem etkisi en yüksek "
                  "(5 x 5 = 25); kolayca istismar edilir ve büyük veri/itibar kaybı yaratır. Önce bu kapatılmalı, "
                  "çünkü risk puanı diğer bulguların hepsinden yüksek.", min_kelime=10),
          ("Rapor okuyan müdür teknik terim bilmez; sade yaz.",
           "İki şey söyle: ne bulundu, neden önce bu.",
           "\"Bulgu #N en yüksek puanlı (5x5); kolay istismar edilir ve etkisi büyük, bu yüzden önce kapatılmalı.\""),
          puan=30, baslik="Yönetici özeti"),
]


SEVIYE = Seviye(
    kimlik="c05b03",
    cilt=5,
    bolum=3,
    baslik="OWASP Top 10: Tehdit Haritası",
    brifing="""
Selin bir klasörü masaya bırakıyor: "Test bitti ve elimizde <<toplam>> bulgu var. Ama müşteri
\"hangisi neyin nesi, hangisini önce kapatalım?\" diye soruyor."

"**<<musteri>>**. <<olay>> Bulgular `bulgular.txt` içinde, ham haliyle: kategori ve risk
atanmamış. İşin iki parçası var: her bulguyu **OWASP Top 10** kategorisine koy, sonra
**olasılık x etki** ile önceliklendir."

Deniz ekliyor: "Bu iş saldırı değil, haritacılık. İyi bir pentester bulduğu açığı doğru
etiketler ve doğru sıraya koyar; çünkü müşterinin bütçesi sınırlıdır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
OWASP Top 10, hem saldırganın hem savunmacının kullandığı ortak bir haritadır. Saldırgan onu "nereye
bakayım?" diye okur: erişim kontrolü, enjeksiyon, kimlik doğrulama, yanlış yapılandırma... Savunmacı ise
aynı listeyi "önce neyi kapatayım?" diye okur. Fark, listeyi **risk** ile birleştirmektir: kolay
istismar edilen ve büyük zarar veren bulgu en üste çıkar. Kategoriyi doğru koymak, aynı kök nedenin başka
yerde de olup olmadığını aramanı sağlar; örneğin bir yerde IDOR bulduysan başka uç noktalarda da arayacaksın.
""",
    gercek_hayat="""
- **Equifax 2017:** Şirket, kamuya duyurulmuş bir Apache Struts açığını zamanında yamalamadı ve
  ciddi bir veri sızıntısı yaşadı. OWASP'ın "Vulnerable Components" kategorisinin ders kitabı örneğidir;
  bileşen envanteri tutmak ve yamaları izlemek önleme yoludur.
- **Capital One 2019:** Yanlış yapılandırılmış bir web uygulaması güvenlik duvarı, saldırganın
  uygulamayı sunucu tarafında istek atmaya yönlendirmesine (SSRF) ve bulut meta veri servisine
  ulaşmasına yol açtı. Tespit için bulut ve uygulama günlüklerinde alışılmadık iç adres isteklerini
  izlemek, önleme için sunucu tarafı isteklerde adres izin listesi kullanmaktır.
- **Önceliklendirme gerçek hayatın kendisidir:** Pek çok sızma testi raporunda onlarca bulgu
  çıkar ve ekip hepsini aynı anda düzeltemez; risk puanı (olasılık x etki) ya da CVSS gibi bir
  ölçek, ilk müdahale edilecek bulguyu belirler.
""",
    sure_hedef_dk=25,
)
