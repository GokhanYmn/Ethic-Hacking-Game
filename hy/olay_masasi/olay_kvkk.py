"""Olay Masası — KVKK Veri Sızıntısı Vakası.

Bir kurumun log, dışa aktarım ve not dosyalarında kişisel veri (sahte TCKN, kurgusal kart no, telefon, e-posta,
adres) açıkta kalmıştır; dışa aktarım dosyasını bir yabancı IP indirmiştir. Oyuncu hangi dosyanın en çok
sızdırdığını, kaç farklı kişinin etkilendiğini, dosyayı kimin indirdiğini bulur; en hassas veri türünü,
KVKK bildirim yükümlülüğünü ve doğru müdahaleyi değerlendirir.

ETİK: Tüm TCKN'ler kurgusaldır ve TCKN sağlama algoritmasını BİLEREK geçmez; kartlar `99` ile başlar ve Luhn'u
geçmez. Gerçek kişisel veri yoktur. Veri üretici `hy.seviyeler.c23_edonusum.b04_kvkk._akis` içindedir.

Determinizm: `uret` ağır veriyi saklamaz; `_alt` alt-tohumunu saklar, `uret` ve `yaz` aynı `_akis(alt)`'i kullanır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh
from hy.seviyeler.c23_edonusum.b04_kvkk import (DOSYA_ADLARI, KART_GREP, TC_GREP, _akis, dosyalari_yaz)


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — KVKK veri sızıntısı",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"]},
        "cevaplar": {"en_cok": [v["en_cok"]], "tc_uniq": v["tc_uniq"], "kart_uniq": v["kart_uniq"],
                     "ip": [v["ip"]]},
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    dosyalari_yaz(lab / "dosyalar", v)
    u.yaz(lab / "erisim.log", v["erisim"])
    u.yaz(lab / "OKUBENI.txt",
          f"{s['metin']['musteri']} — KVKK sızıntı vakası (tüm veriler kurgusaldır)\n\n"
          "dosyalar/uygulama.log       : uygulama logu\n"
          "dosyalar/hata_ayiklama.log  : DEBUG logu\n"
          "dosyalar/disa_aktarim.csv   : müşteri dışa aktarımı; dosya sunucusunda /paylasim/ altında duruyor\n"
          "dosyalar/destek_notlari.txt : destek notları\n"
          "erisim.log                  : dosya sunucusunun web erişim logu\n\n"
          "Maskeli kayıtlar yıldızlıdır (123*****901). Açıktakiler maskesizdir.\n"
          "TCKN: 11 hane, 0 ile başlamaz. Kart: 16 bitişik rakam. Telefon: 05 ile başlayan 11 hane.\n"
          "Sahte TCKN'ler sağlama algoritmasını geçmez; kart numaraları da kurgusaldır.\n")


def _uniq_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    v = _akis(b.senaryo["_alt"])
    if n == v["tc_satir"]:
        return "Bu satır sayısı. Aynı kişi birden çok dosyada geçiyor; etkilenen FARKLI kişiyi sayıyoruz (`sort -u`)."
    if n == v["naif11"]:
        return "Telefon numaralarını da saymışsın (onlar da 11 hane ama `05` ile başlar). TCKN `0` ile başlamaz."
    return None


def _kart_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    v = _akis(b.senaryo["_alt"])
    if n == v["kart_satir"]:
        return "Bu satır sayısı. Aynı kart birden çok yerde geçiyor; FARKLI kartları say (`sort -u`)."
    return None


def coz(lab: Path, s: dict) -> dict:
    en = sh(f"grep -cE '{TC_GREP}' dosyalar/* | sort -t: -k2 -rn | head -1 | cut -d: -f1 | sed 's#.*/##'", lab)
    tc = sh(f"grep -ohE '{TC_GREP}' dosyalar/* | sort -u | wc -l", lab)
    kart = sh(f"grep -ohE '{KART_GREP}' dosyalar/* | sort -u | wc -l", lab)
    ip = sh(f"grep 'GET /paylasim/{DOSYA_ADLARI['export']}' erisim.log | grep ' 200 ' | awk '{{print $1}}' "
            "| grep -vE '^(10|192\\.168|172\\.16)\\.' | sort -u", lab)
    cozum = {1: en, 2: tc, 3: kart, 4: ip}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("Maskesiz **TC kimlik no** (11 hane, `0` ile başlamaz) bulunan satır sayısı en yüksek olan **dosya** hangisi? "
          "(`dosyalar/` altında bak)",
          Metin("en_cok", bicim="dosya adı", sadece_ad=True),
          ("Her dosya için ayrı bir sayı çıkar; sonra en büyüğünü seç.",
           "`grep -c` her dosyada eşleşen satırı sayar. Deseni `\\b[1-9][0-9]{10}\\b` kur.",
           "`grep -cE '\\b[1-9][0-9]{10}\\b' dosyalar/* | sort -t: -k2 -rn | head -1`"),
          puan=20, baslik="En çok sızdıran dosya"),
    Gorev("Açıktaki TC kimlik numaraları **kaç farklı kişiye** ait? (aynı numara birden çok dosyada geçebilir)",
          Sayi("tc_uniq", sik_hatalar=_uniq_hata),
          ("Aynı kişi hem logda hem dışa aktarımda olabilir; onu bir kez saymalısın.",
           "Numaraları çıkar (`grep -o`), tekilleştir (`sort -u`), say.",
           "`grep -ohE '\\b[1-9][0-9]{10}\\b' dosyalar/* | sort -u | wc -l`"),
          puan=25, baslik="Etkilenen kişi sayısı"),
    Gorev("Açıkta duran **farklı kart numarası** (16 bitişik rakam) sayısı kaç?",
          Sayi("kart_uniq", sik_hatalar=_kart_hata),
          ("Kart numarası dosyalarda birden çok kez geçebilir.",
           "`\\b[0-9]{16}\\b` ile çıkar, tekilleştir, say.",
           "`grep -ohE '\\b[0-9]{16}\\b' dosyalar/* | sort -u | wc -l`"),
          puan=20, baslik="Sızan kart sayısı"),
    Gorev("`erisim.log` içinde, dışa aktarım dosyasını (`/paylasim/disa_aktarim.csv`) **başarıyla (200) indiren, kurum dışı** "
          "IP adresi ne? (iç ağ `10.x` sayılmaz; 403 alanlar indirememiştir)",
          Metin("ip", bicim="IP adresi"),
          ("Önce dosyaya yapılan istekleri süz, sonra yalnızca başarılıları (durum 200) tut.",
           "İç ağ adresleri `10.0.0.x`; 403 'yasak' demektir, indirme olmamıştır.",
           "`grep 'GET /paylasim/disa_aktarim.csv' erisim.log | grep ' 200 ' | grep -v '^10\\.'`"),
          puan=25, baslik="Dosyayı indiren"),
    Gorev("Sızan veriler arasında **en hassas** tür hangisi ve neden?",
          Secmeli([
              ("TC kimlik numarası: ömür boyu değişmez, tek başına kimliğe bürünmeye ve dolandırıcılığa yarar",
               "Doğru. Kart iptal edilir, e-posta ve telefon değişir; TCKN değiştirilemez ve resmi işlemlerde "
               "kimlik yerine geçer."),
              ("E-posta adresi, çünkü sayısı en fazladır",
               "Hassasiyet sayıyla değil, kalıcılık ve kötüye kullanım gücüyle ölçülür."),
              ("Adres, çünkü kargo ve fatura için gereklidir",
               "Adres de kişisel veridir ama TCKN kadar kalıcı ve güçlü bir kimlik anahtarı değildir."),
              ("Hepsi aynı; hassasiyet sıralaması yoktur",
               "Vardır: risk değerlendirmesi ve önceliklendirme buna dayanır."),
          ]),
          ("Hangi veri, hayat boyu değişmeyen bir anahtardır?",
           "Kart ve e-posta sızarsa kişi değiştirebilir; hangisi değişmez?",
           "Kimlik numarası: değiştirilemez ve kimlik doğrulamada kullanılır."),
          puan=15, baslik="En hassas veri"),
    Gorev("Dışa aktarım dosyasını **kurum dışı bir IP başarıyla indirdi**. KVKK açısından bu durum için en doğru "
          "değerlendirme hangisi?",
          Secmeli([
              ("Yetkisiz erişimle kişisel veri ele geçmiş, bu bir veri ihlali; veri sorumlusu ihlali öğrendiği andan "
               "itibaren en kısa sürede, en geç 72 saat içinde Kurul'a ve etkilenen kişilere bildirmeli",
               "Doğru. Yetkisiz kişiye ulaşan kişisel veri ihlaldir; Kurul kararı (2019/10) bildirimin hızlı, "
               "en geç 72 saat içinde yapılmasını ister."),
              ("Dosya şirketin kendi sunucusundaydı, o hâlde ihlal sayılmaz, bildirim gerekmez",
               "Yanlış. Sunucu şirketin olsa da, veriyi yetkisiz bir dış IP indirdi; bu ihlaldir."),
              ("Önce her şeyi düzeltelim, bildirimi yıl sonu raporuna ekleriz",
               "Yanlış. Bildirim yıl sonu raporu değil, ihlalin öğrenilmesinden sonraki kısa süre içindir."),
              ("Yalnızca kart numaraları için bildirim gerekir, TCKN ve diğerleri için gerekmez",
               "Yanlış. Tüm kişisel veriler KVKK kapsamındadır; TCKN en hassas olanlardandır."),
          ]),
          ("Veriyi yetkisi olmayan biri aldı mı, almadı mı?",
           "Bildirim süresi 'ihlali öğrendiğin an'dan başlar ve kısadır (saatlerle ölçülür).",
           "Yetkisiz erişim = ihlal; Kurul'a ve etkilenen kişilere en geç 72 saat içinde bildirim."),
          puan=25, baslik="KVKK bildirimi"),
    Gorev("Sızıntıyı bulduktan sonra **doğru ilk müdahale** hangisi?",
          Secmeli([
              ("Paylaşımı hemen kapat, erişim logunu ve dosyaları kanıt olarak koru, kaynağı (debug/maskeleme) düzelt, "
               "hukuk ve KVKK sorumlusunu bilgilendirip bildirim sürecini başlat",
               "Doğru. Önce yayılımı durdur, kanıtı koru, kök nedeni kapat; sonra hukuki bildirimi yürüt."),
              ("Dosyaları ve logları hemen sil, böylece iz kalmaz",
               "Yanlış. Kanıt silinirse neyin sızdığı kanıtlanamaz, bildirim ve soruşturma zorlaşır; üstelik suç."),
              ("İndiren IP'ye ulaşıp dosyayı silmesini rica et, sonrasını beklemeden kapat",
               "Yanlış. Karşı tarafa güvenmek çözüm değil; resmi yollar ve bildirim gerekir."),
              ("Kimseye söylemeden sessizce maskeleme ayarını düzelt",
               "Yanlış. Sessiz düzeltme yükümlülüğü ortadan kaldırmaz; ihlal gizlenirse ceza riski büyür."),
          ]),
          ("Kanıtı yok etmek ya da gizlemek her zaman kötü fikirdir.",
           "Sıra: durdur, koru, düzelt, bildir.",
           "Paylaşımı kapat, kanıtı koru, kök nedeni düzelt, hukuk ve KVKK sürecini başlat."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_kvkk",
    cilt=23,
    bolum=122,
    baslik="KVKK Veri Sızıntısı Vakası",
    brifing="""
Selin Aksoy acil bir dosya uzatıyor: "**<<musteri>>** (<<sektor>>) bize başvurdu. <<hikaye>> <<kisi>> dört dosya ve dosya
sunucusunun erişim logunu (`erisim.log`) gönderdi."

"İçlerinde kişisel veri maskelenmemiş duruyor: TC kimlik no, kart no, telefon, e-posta, adres. Hepsi kurgusal
ama desenler gerçek. Hukuk birimi şunları soruyor: hangi dosya en çok sızdırdı, kaç kişi etkilendi, kaç kart
açıkta, dosyayı kim indirdi, en hassas veri ne, **KVKK bildirimi gerekir mi** ve şimdi ne yapmalıyız?"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bu vakada üç ayrı iş yaptın: **bulmak** (hangi dosya, kaç kişi, kaç kart), **ispatlamak** (erişim logunda dosyayı
dışarıdan kimin indirdiği) ve **değerlendirmek** (en hassas veri, bildirim, müdahale). Kritik fark şu: veri
sadece açıkta durmak ihlal olmayabilir; ama yetkisiz biri ona ulaştıysa bu bir veri ihlalidir ve bildirim süresi
başlar. Kanıtı koru, yayılımı durdur, kök nedeni düzelt (maskeleme, debug kapatma, paylaşım yetkisi), sonra
bildir. Önleme tarafında: log ve dışa aktarımlarda zorunlu maskeleme, test için gerçek veri kullanmama,
paylaşımlarda kimlik doğrulama ve düzenli desen taraması.
""",
    gercek_hayat="""
- **KVKK / GDPR bildirim yükümlülüğü:** Veri sorumlusu, ihlali öğrendiğinde Kişisel Verileri Koruma Kurulu'na ve
  etkilenen kişilere bildirim yapmakla yükümlüdür; Kurul'un 24 Ocak 2019 tarihli 2019/10 sayılı kararı bunu "en
  kısa sürede, en geç 72 saat içinde" yapılacak şekilde düzenler. AB'de GDPR (25 Mayıs 2018'den beri) da aynı 72
  saati getirir. Kurul, bildirilen ihlalleri kamuoyuna duyurur.
- **Veri ihlali cezaları gerçektir:** Yemeksepeti'nin 2021'de yaşadığı kullanıcı verisi ihlali sonrasında Kurul
  idari para cezası vermiştir; GDPR'da ceza yıllık cironun %4'üne ya da 20 milyon avroya kadar çıkabilir.
  Mayıs 2023'te İrlanda veri koruma kurumu Meta'ya veri aktarımı nedeniyle 1,2 milyar avroluk ceza verdi.
- **Tespit ve önleme:** Gerçek şirketler log ve dosya paylaşımlarını DLP (veri kaybı önleme) araçlarıyla TCKN / kart
  desenleri için tarar (Luhn ve TCKN sağlama kuralı ile hatalı eşleşmeleri eler) ve test ortamlarında gerçek
  veri yerine maskelenmiş ya da sentetik veri kullanır.
""",
    sure_hedef_dk=20,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c23b04",),
)
