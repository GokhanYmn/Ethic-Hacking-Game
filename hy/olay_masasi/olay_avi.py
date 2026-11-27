"""Olay Masası — Tehdit Avı: Alarm Vermeyen Yerleşiği Bul.

TAMAMEN SAVUNMACI: oyuncu avcı analisttir. Kurgusal, dosya-tabanlı sahte veri (dış IP'ler TEST-NET):
`baglantilar.csv`, `surecler.csv`, `bilinen_ipler.txt`. Hiçbir alarm yoktur; yerleşik tehdit, jitter'lı (küçük
rastgele sapmalı) ve alışılmış 443 portundan konuşan bir beacon'dır; aynı makinede Office → LOLBin → kalıcılık zinciri var.
Gürültü: bilinen-iyi hizmetler, düzenli ama meşru zaman eşitleme, çok bağlanan ama DÜZENSİZ hedef, nadir meşru süreçler.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar (`_tohum` motor tarafından ezilir).
Üreteç `hy.seviyeler.c07_savunma.b10_tehdit_avi.av_verisi` içindedir (zor=True).
"""
from __future__ import annotations

import random
from functools import lru_cache
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.b10_tehdit_avi import (
    av_verisi, av_yaz, beacon_cozumu, norm_, surec_cozumu,
)
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

SENARYOLAR = [
    {"musteri": "Ceylan Tekstil", "sektor": "tekstil ve hazır giyim", "kisi": "Bilgi işlem sorumlusu Murat Bey",
     "hikaye": "Ortak çalıştıkları bir tedarikçi sızmaya uğradı ve 'sizde de olabilir' diye uyardı. Ceylan'ın güvenlik "
               "yazılımı hiçbir alarm üretmedi; yine de tasarım dosyaları çok değerli."},
    {"musteri": "Deniz Enerji Dağıtım", "sektor": "enerji dağıtımı", "kisi": "Güvenlik mühendisi Sevgi Hanım",
     "hikaye": "Düzenleyici kurum, kritik altyapı işletmecilerinden sessiz yerleşik taraması istedi. Sevgi Hanım "
               "'alarm yok diye temiz demek istemiyorum' diyor ve iki kayıt dosyası gönderiyor."},
    {"musteri": "Lale Eğitim Kurumları", "sektor": "özel okul ve kolejler", "kisi": "BT koordinatörü Fatih Bey",
     "hikaye": "Öğrenci ve veli verisi tutuyorlar. Bir öğretmenin sunum belgesinden sonra bilgisayarı tuhaf davranmış "
               "olabilir, ama kimse bir şey bildirmedi ve alarm da çalmadı."},
]

OLAYLAR = {
    "belge": "Kullanıcı bir Office belgesini açar",
    "lolbin": "Office belgesi, beklenmedik bir yardımcı sistem süreci başlatır",
    "indir": "Bir sistem aracı, dışarıdaki bir sunucudan dosya indirilir",
    "calis": "İndirilen dosya çalışmaya başlar",
    "beacon": "İlk beacon bağlantısı dışarı atılır",
    "kalici": "Zamanlanmış görevle kalıcılık kurulur",
}
ANAHTAR = {"belge": "belgesini", "lolbin": "yardımcı", "indir": "indirilir", "calis": "çalışmaya",
           "beacon": "beacon", "kalici": "kalıcılık"}
HARFLER = "abcdef"


@lru_cache(maxsize=32)
def _akis(alt: int) -> dict:
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    v = av_verisi(rng, zor=True)
    v["sen"] = sen
    kinds = list(OLAYLAR)
    rng.shuffle(kinds)
    v["harf"] = {kind: HARFLER[i] for i, kind in enumerate(kinds)}             # olay türü -> harf
    zam = v["zamanlar"]
    v["sira"] = [v["harf"][kd] for kd in sorted(OLAYLAR, key=lambda kd: zam[kd])]
    v["olaylar_metni"] = "\n".join(f"- **{v['harf'][kd]}** — {OLAYLAR[kd]}"
                                   for kd in sorted(OLAYLAR, key=lambda kd: v["harf"][kd]))
    return v


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — alarmsız av",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"], "hikaye": sen["hikaye"],
                  "olaylar": v["olaylar_metni"]},
        "cevaplar": {"ip": v["c2"], "periyot": v["periyot"], "makine": v["host"], "surec": v["lolbin1"],
                     "gorev": v["gorev"], "sira": v["sira"]},
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    av_yaz(lab, v)
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} av dosyaları. KURGUSAL.\n"
          "baglantilar.csv   : ağ bağlantı günlüğü (zaman,kaynak,hedef_ip,port,bayt)\n"
          "surecler.csv      : süreç kaydı (zaman,host,kullanici,surec,ust_surec,komut)\n"
          "bilinen_ipler.txt : kurumun bilinen-iyi hedef IP'leri (taban çizgisi)\n")


# ----------------------------------------------------------------------------- kontroller

def _ip_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["decoy_ip"]:
        return "Bu hedefe çok bağlanılıyor ama aralıklar rastgele: insan davranışı. Aranan, aralığı neredeyse sabit olan hedef."
    if g == v["ntp_ip"]:
        return "Bu hedef düzenli ama bilinen_ipler.txt içinde: meşru zaman eşitleme. Önce bilinen-iyiyi ele."
    return None


def _periyot_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["ntp_p"]:
        return "Bu, zaman eşitleme hizmetinin (meşru) aralığı. Şüpheli hedefin aralığını ölç."
    if n == v["n_beacon"]:
        return "Bu bağlantı SAYISI. İstenen, ardışık iki bağlantı arasındaki süre (saniye)."
    return None


def _makine_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == norm_(v["decoy_host"]):
        return "Bu makine çok bağlanıyor ama düzensiz; beacon atmıyor. Beacon IP'sine bağlanan `kaynak` aranıyor."
    if g == norm_(v["ntp_host"]):
        return "Bu sunucu yalnızca zaman eşitliyor (bilinen-iyi)."
    if g == norm_(v["it_host"]):
        return "Bu makinede yönetici betikleri çalışıyor ama dışarıya beacon yok."
    return None


def _surec_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g in ("splwow64", "splwow64.exe"):
        return "Yazdırma yardımcısı Office'in meşru çocuğudur. Şüpheli olanı ara."
    if g in (v["lolbin2"], v["lolbin2"][:-4]):
        return "Bu ikinci halka (onu zaten şüpheli bir süreç başlatmış). Office'in DOĞRUDAN başlattığına bak."
    if g in ("explorer", "explorer.exe", v["ofis"], v["ofis"][:-4]):
        return "Office'in kendisi değil, onun doğurduğu beklenmedik çocuk süreç aranıyor (`ust_surec` sütunu)."
    return None


def _gorev_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g in (v["impl"], v["impl"] + ".exe"):
        return "Bu çalıştırılan dosyanın adı. Aranan, `schtasks` komutundaki `/tn` (görev adı) değeri."
    return None


def _sira_hata(verilen, beklenen, b):
    if verilen == list(reversed(beklenen)):
        return "Sıra tersine dönmüş: önce neden, sonra sonuç. Zaman damgalarına göre eskiden yeniye diz."
    return None


def coz(lab: Path, s: dict) -> dict:
    host, ip, port, per, sayi = beacon_cozumu("bilinen_ipler.txt", "baglantilar.csv", lab)
    surec = surec_cozumu("surecler.csv", host, lab)
    gorev = sh(f"grep ',{host},' surecler.csv | grep schtasks.exe | grep -o '/tn [^ ]*' | cut -d' ' -f2 | head -1", lab)
    ust = sh(f"awk -F, -v h='{host}' -v s='{surec}' '$2==h && $4==s {{print $5}}' surecler.csv | head -1", lab)
    zaman = {
        "belge": sh(f"awk -F, -v h='{host}' -v p='{ust}' '$2==h && $4==p {{print $1; exit}}' surecler.csv", lab),
        "lolbin": sh(f"awk -F, -v h='{host}' -v s='{surec}' '$2==h && $4==s {{print $1; exit}}' surecler.csv", lab),
        "indir": sh(f"awk -F, -v h='{host}' -v s='{surec}' '$2==h && $5==s && ($4==\"certutil.exe\"||$4==\"bitsadmin.exe\") "
                    f"{{print $1; exit}}' surecler.csv", lab),
        "calis": sh(f"awk -F, -v h='{host}' '$2==h && $6 ~ /^C:.Users.Public/ && $4!=\"schtasks.exe\" {{print $1; exit}}' "
                    f"surecler.csv", lab),
        "beacon": sh(f"awk -F, -v h='{host}' -v i='{ip}' '$2==h && $3==i {{print $1; exit}}' baglantilar.csv", lab),
        "kalici": sh(f"awk -F, -v h='{host}' '$2==h && $4==\"schtasks.exe\" && $6 ~ /create/ {{print $1; exit}}' "
                     f"surecler.csv", lab),
    }
    harf = {}
    for kd, anahtar in ANAHTAR.items():
        for h, satir in zip(HARFLER, s["metin"]["olaylar"].split("\n")):
            pass
        for satir in s["metin"]["olaylar"].split("\n"):
            if anahtar in satir:
                harf[kd] = satir.split("**")[1]
    sira = " ".join(harf[kd] for kd in sorted(zaman, key=lambda kd: zaman[kd]))
    return sec_doldur({1: ip, 2: per, 3: host, 4: surec, 5: gorev, 6: sira}, GOREVLER, lab, s)


GOREVLER = [
    Gorev("`baglantilar.csv` içinde **beacon** atan hedef IP hangisi? (Bilinen-iyi listesinde OLMAYAN; aynı makineden "
          "neredeyse sabit aralıkla gidilen hedef. Çok bağlanılan ama düzensiz hedefler ve meşru zaman eşitleme beacon değildir.)",
          IP("ip", sik_hatalar=_ip_hata),
          ("Önce bilinen-iyiyi ele; kalan hedeflerde 'çok bağlanan' değil 'düzenli bağlanan' olanı ara.",
           "`grep -vwFf bilinen_ipler.txt baglantilar.csv | cut -d, -f3 | sort | uniq -c | sort -rn` adayları verir; her adayın "
           "bağlantı aralıklarını `awk -F'[, :]' '{t=$2*3600+$3*60+$4; if (p) print t-p; p=t}' | sort | uniq -c` ile ölç.",
           "Doğru adayda aralıklar birkaç yakın sayıya (örn. 297-303) toplanır; düzensiz adayda onlarca farklı değer çıkar. "
           "Bu vakada beacon sıradan 443 portundan konuşuyor: port seni kurtarmaz."),
          puan=15, baslik="Beacon hedefi"),
    Gorev("Bu beacon'ın **periyodu** kaç saniye? (Beacon küçük rastgele sapma, yani jitter içeriyor: aralıkların "
          "ortalamasına yakın tam sayıyı yaz.)",
          Sayi("periyot", tolerans=2, sik_hatalar=_periyot_hata),
          ("Hedefe giden satırların zaman farklarına bak; hepsi aynı değil ama birbirine yakın.",
           "Farkları `awk` ile saniyeye çevirip `sort | uniq -c` ile say; en kalabalık grubun ortasındaki değeri al.",
           "Sapma birkaç saniyedir; sonuç 120, 180, 300 ya da 600 gibi yuvarlak bir değere yakın çıkar."),
          puan=15, baslik="Beacon periyodu"),
    Gorev("Beacon hangi **makineden** (`kaynak`) atılıyor? Makine adını yaz.",
          Metin("makine", sik_hatalar=_makine_hata, bicim="makine adı (PC-...)"),
          ("Beacon IP'sine giden satırların `kaynak` sütununa bak.",
           "`grep -w <ip> baglantilar.csv | cut -d, -f2 | sort | uniq -c`",
           "Tek bir makine çıkmalı."),
          puan=15, baslik="Enfekte makine"),
    Gorev("Aynı makinede `surecler.csv`'ye bak: bir **Office uygulaması** (`winword.exe`/`excel.exe`) tarafından "
          "başlatılmış, meşru olmayan sistem aracı (LOLBin) hangisi? (Yazdırma yardımcısı meşrudur.)",
          Metin("surec", sik_hatalar=_surec_hata, son_ekleri_at=(".exe",), bicim="süreç adı (örn. xyz.exe)"),
          ("`ust_surec` sütunu Office olan, ama normal olmayan çocuğu ara.",
           "`grep ',<makine>,' surecler.csv | awk -F, '$5==\"winword.exe\" || $5==\"excel.exe\" {print $4}' | sort | uniq -c`",
           "Çıkan iki-üç adaydan biri yazdırma yardımcısı (splwow64); LOLBin olanı yaz."),
          puan=15, baslik="LOLBin"),
    Gorev("Saldırgan kalıcılığı **zamanlanmış görevle** kurmuş. Bu makinede `schtasks.exe /create` komutundaki "
          "**görev adı** (`/tn` değeri) nedir?",
          Metin("gorev", sik_hatalar=_gorev_hata, bicim="görev adı"),
          ("Makinenin süreç satırlarında `schtasks.exe` geçenlere bak; yalnız biri görev OLUŞTURUR.",
           "`grep ',<makine>,' surecler.csv | grep schtasks.exe` ve `/create` içeren satırın `komut` alanını oku.",
           "`... | grep -o '/tn [^ ]*'` görev adını verir."),
          puan=15, baslik="Kalıcılık görevi"),
    Gorev("Saldırının adımlarını **zaman damgalarına göre eskiden yeniye** diz. Olaylar:\n\n<<olaylar>>\n\n"
          "(Zaman damgaları iki dosyadadır: süreç olayları `surecler.csv`'de, ilk beacon `baglantilar.csv`'de. "
          "Bu makinenin satırlarına bak.)",
          Dizi("sira", sik_hatalar=_sira_hata, bicim="harfler sırayla, örn. c a e b d f"),
          ("Enfekte makinenin süreç satırlarını ve beacon'ın ilk satırını zamana göre yan yana düşün.",
           "`grep ',<makine>,' surecler.csv | cut -d, -f1,4,5` zinciri verir; beacon'ın ilk zamanı için "
           "`grep -w <ip> baglantilar.csv | head -n 1`.",
           "Office açılır, ardından aracı başlatır, indirir, çalıştırır. İlk beacon ile kalıcılık görevinin sırası vakaya göre "
           "değişir: zaman damgalarını gerçekten karşılaştır."),
          puan=20, baslik="Saldırı zinciri"),
    Gorev("Bulgularla şimdi **en doğru müdahale** hangisi?",
          Secmeli([
              ("Makineyi ağdan ayır, bellek ve dosyaları kanıt olarak sakla, kalıcılık görevini ve indirilen dosyayı "
               "topla, çıkış trafiğinde hedef IP'yi engelle ve aynı deseni diğer makinelerde ara",
               "Doğru. Önce yayılmayı durdur (izole), sonra kanıtı sakla, kalıcılığı ve dosyayı belgeleyip temizle, IP "
               "engelini ek önlem olarak koy ve aynı IOC (iz) ile bütün ağı tara."),
              ("Yalnızca kalıcılık görevini sil ve makineyi yeniden başlat; çalışan süreç zaten kapanır ve saldırgan "
               "böylece bağlantıyı kaybeder",
               "Yanlış. Görevi silmek kanıtı yok eder, saldırganın başka kalıcılıkları ve çaldığı kimlikleri kalır. "
               "Yeniden başlatma ayrıca bellek kanıtını siler."),
              ("Hiçbir şeye dokunmadan beacon'ı bir hafta daha izle; saldırganın asıl hedefini görmek için en iyi yol "
               "bu, ayrıca kimseye haber vermeye gerek yok",
               "Yanlış. İzlemek bazen gerekir ama bilinçli, yetkili ve sınırlı olmalı; yönetime ve olay müdahale ekibine "
               "haber vermeden beklemek veri kaybını büyütür."),
              ("Makineyi hemen silip yeniden kur, kayıtları sil ve olayı kapat; temiz makine temiz ağ demektir, diğer "
               "makineleri taramaya gerek yoktur",
               "Yanlış. Kanıt silinince saldırganın başka makinelerde izi kalıp kalmadığı anlaşılamaz. Yeniden kurulum "
               "gerekebilir ama kanıt toplandıktan sonra ve ağ geneli taramayla birlikte yapılır."),
          ], dogru=0),
          ("Yayılmayı durdurmak ve kanıtı korumak aynı anda gerekir; hangi şık ikisini birden yapıyor?",
           "Silmek ve yeniden kurmak kanıtı yok eder; sadece beklemek ise zarar büyütür. IP engeli tek başına yetmez.",
           "Doğru şık: izole et, kanıt sakla, kalıcılığı belgele, IP'yi engelle, aynı iz için bütün ağı tara."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_avi",
    cilt=7,
    bolum=118,
    baslik="Tehdit Avı: Alarm Vermeyen Yerleşiği Bul",
    brifing="""
Deniz Kara ekranını sana çeviriyor: "**<<musteri>>** (<<sektor>>) için acil bir olay yok, ama av zamanı. <<hikaye>>
<<kisi>> bize üç dosya yolladı: `baglantilar.csv` (ağ bağlantı günlüğü), `surecler.csv` (süreç kaydı) ve
`bilinen_ipler.txt` (kurumun bilinen-iyi hedefleri)."

"Hiçbir alarm yok, yani elimizde tek bir şüpheli bile yok. Hipotezimiz: **düzenli aralıkla dışarı yoklama atan bir
yerleşik var** ve aynı makinede Office belgesiyle başlayan bir zincir iz bırakmış olabilir. Bilinen-iyiyi ele, düzeni
ölç, ikinci kaynakla doğrula." Mert ekliyor: "Bu kez saldırgan akıllı: bağlantılar tam aynı aralıkta değil ve sıradan
443 portundan konuşuyor. Çok bağlanan şüpheli değil, DÜZENLİ bağlanan şüpheli."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Alarm vermeyen saldırgan, sıradan trafiğe benzemeye çalışır: yaygın bir port, küçük sapmalar (jitter),
sistemin kendi araçları (LOLBin). Savunmacı için ders: tehdit avı alarmın yerine geçmez, alarmın görmediği yeri arar.
Taban çizgisini bilirsen sapma görünür; iki bağımsız kaynağı (ağ ve süreç) birleştirirsen bulgu güçlenir; bulduğun deseni
kalıcı kurala çevirirsen bir dahaki sefere av gerekmez. Müdahalede ilk iş yayılmayı durdurmak ve kanıtı korumaktır.
""",
    gercek_hayat="""
- **LOLBin / living-off-the-land:** Saldırganların Windows'un kendi araçlarını (`certutil`, `mshta`, `regsvr32`,
  `rundll32`, `powershell` gibi) kötüye kullanması iyi belgelenmiştir; kamuya açık **LOLBAS** projesi bu araçların
  kötüye kullanım yollarını derler. Microsoft, Mayıs 2023'te Volt Typhoon grubunun da büyük ölçüde bu yaklaşımı
  kullandığını yayımladı. Tespit: Office'ten doğan sistem aracı ve internetten dosya indiren `certutil` gibi anne-çocuk ve
  komut satırı sapmaları; önleme: uygulama kontrolü ve gereksiz araçların kısıtlanması.
- **APT beaconing:** SolarWinds olayında (Aralık 2020) SUNBURST arka kapısı kurulumdan sonra bir süre beklemiş ve komuta
  sunucusuyla iletişimde zamanlamayı gizlemeye çalışmıştı; Cobalt Strike gibi çerçevelerde "sleep" ve "jitter" ayarı
  yoklama aralığını rastgeleleştirir. Tespit: tek makineden, bilinen-iyi dışı hedefe, küçük ve benzer boyutlu, istatistiksel
  olarak düzenli bağlantılar; önleme: çıkış trafiğinde izinli hedef listesi, proxy/DNS kaydı izleme.
- **Av çıktısını kalıcılaştırmak:** Av ekipleri bulduğu deseni (aralık, hedef, anne-çocuk zinciri) SIEM kuralına çevirir;
  böylece bir dahaki saldırıda av değil alarm çalışır.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b10",),
)
