"""Cilt 11 · Bölüm 5 — AD Savunması (düzeltme planı).

Beceri: kurgusal bir AD denetiminin çıktı dosyalarında (servis hesapları, ön kimlik doğrulama,
yerel yönetici parolaları, katman GPO'ları) riskli ayarları bulup dosyaları düzeltmek: servis
hesaplarını gMSA'ya taşıma, ön kimlik doğrulamasını açma, LAPS devreye alma, Domain Admin'in
alt katmanlarda oturum açmasını reddetme. `cevap <no>`, dosyaların son halini kontrol eder.

Vakalar: banka, lojistik, belediye, hastane. Riskli satırlar ve paylaşılan yerel yönetici
özetleri her vakada farklı hesaplara/makinelere denk gelir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c11_ad.ortak import hesap_adlari, sec_doldur, sh, sirket_sec

SVC = ["svc-sql", "svc-yedek", "svc-web", "svc-rapor", "svc-baski", "svc-izleme", "svc-crm", "svc-ik"]
ESKI = ["eski.uygulama", "test.hesabi", "stajyer.ornek", "demo.kullanici"]
SAHNE = {
    "ferahbank": "Ferah Bank, sızma testi raporundaki AD bulgularını kapatmak için bir düzeltme planı istiyor.",
    "kuzgun": "Kuzgun Lojistik, bir saldırı tatbikatından sonra 'domain'i nasıl sağlamlaştırırız?' diye soruyor.",
    "yesiltepe": "Yeşiltepe Belediyesi, denetim bulgularına cevap vermek için ay sonuna kadar süre aldı.",
    "medora": "Medora Sağlık, yönetici hesaplarının KVKK denetimine hazır olmasını istiyor.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on = sk["on"]
    svc = rng.sample(SVC, 6)
    riskli, guvenli_gmsa, spnsiz = svc[:rng.randint(3, 4)], [], []
    kalan = svc[len(riskli):]
    guvenli_gmsa = [kalan[0]]
    spnsiz = [kalan[1]]
    servis = ([(a, "evet", "user", rng.randint(400, 2400)) for a in riskli]
              + [(a, "evet", "gmsa", 0) for a in guvenli_gmsa]
              + [(a, "hayir", "user", rng.randint(30, 300)) for a in spnsiz])
    rng.shuffle(servis)
    kotu_onkimlik = rng.sample(ESKI, 2)
    normal = hesap_adlari(rng, 6)
    onkimlik = [(a, "evet", "hayir") for a in kotu_onkimlik] + [(normal[0], "hayir", "hayir")]
    onkimlik += [(a, "evet", "evet") for a in normal[1:]]
    rng.shuffle(onkimlik)
    # LAPS: ortak yerel yönetici özeti paylaşan makineler
    pcler = [f"{on}-pc{n}" for n in sorted(rng.sample(range(100, 900), 9))]
    ortak = rng.sample(pcler, rng.randint(3, 4))
    ortak_ozet = "".join(rng.choice("0123456789abcdef") for _ in range(8))
    yerel = []
    for p in pcler:
        if p in ortak:
            yerel.append((p, ortak_ozet, "hayir"))
        else:
            yerel.append((p, "".join(rng.choice("0123456789abcdef") for _ in range(8)), "evet"))
    return {
        "vaka": f"{sk['ad']} — AD düzeltme planı",
        "sirket": sk, "servis": servis, "onkimlik": onkimlik, "yerel": yerel,
        "riskli": riskli, "guvenli": guvenli_gmsa + spnsiz, "kotu_onkimlik": kotu_onkimlik, "ortak": ortak,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "alan": sk["alan"]},
        "cevaplar": {"riskli": riskli, "ortak": ortak},
    }


def yaz(lab: Path, s: dict) -> None:
    k = lab / "ad/denetim"
    u.yaz(lab / "ad/OKUBENI.txt",
          f"{s['sirket']['ad']} — AD denetim çıktıları (KURGUSAL, `ad/denetim/` altında).\n"
          "Bulguları bul, dosyaları düzelt, sonra `cevap <no>` ile kontrol et. Düzeltmeyi gerçek AD'de\n"
          "önce test ortamında dene; bu dosyalar yalnızca bir kopyadır.\n")
    u.yaz(k / "servis_hesaplari.csv", "ad,spn_var,tur,parola_yasi_gun\n" +
          "".join(f"{a},{b},{c},{d}\n" for a, b, c, d in s["servis"]))
    u.yaz(k / "onkimlik.csv", "ad,aktif,onkimlik_gerekli\n" + "".join(f"{a},{b},{c}\n" for a, b, c in s["onkimlik"]))
    u.yaz(k / "yerel_admin.csv", "bilgisayar,yerel_admin_ozet,laps\n" + "".join(f"{a},{b},{c}\n" for a, b, c in s["yerel"]))
    u.yaz(k / "katman_gpo.txt",
          "# GPO  baglanti  deny_logon (oturum açması reddedilen gruplar, virgülle)\n"
          "GPO-DC-Politikasi baglanti=OU=DomainControllers deny_logon=Guests\n"
          "GPO-Sunucu-Kisitlari baglanti=OU=Sunucular deny_logon=Guests\n"
          "GPO-Istasyon-Kisitlari baglanti=OU=Istasyonlar deny_logon=Guests\n")


def _csv(yol: Path):
    satirlar = [x.strip() for x in yol.read_text(errors="replace").splitlines() if x.strip()]
    return [x.split(",") for x in satirlar[1:]]


def _gmsa(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "ad/denetim/servis_hesaplari.csv"
    if not yol.is_file():
        return Sonuc(False, "servis_hesaplari.csv yok.")
    satir = {r[0]: r for r in _csv(yol) if len(r) == 4}
    ilk = {a for a, *_ in s["servis"]}
    if set(satir) != ilk:
        return Sonuc(False, "Satır silinmiş ya da eklenmiş. Servis hesaplarını silmiyoruz, `tur` sütununu değiştiriyoruz.")
    hala = [a for a in s["riskli"] if satir[a][2] != "gmsa"]
    if hala:
        return Sonuc(False, f"Hâlâ kullanıcı tipi servis hesabı olan SPN'li satır var: {', '.join(hala)}. Bunların `tur` değeri `gmsa` olmalı.", yakin=True)
    bozuk = [a for a, _, tur, _ in s["servis"] if a in s["guvenli"] and satir[a][2] != tur]
    if bozuk:
        return Sonuc(False, f"Riskli olmayan satırı da değiştirmişsin: {', '.join(bozuk)}. SPN'siz kullanıcı hesabı ve zaten gMSA olan satır olduğu gibi kalmalı.", yakin=True)
    return Sonuc(True, "SPN'li servis hesaplarının hepsi gMSA oldu; parolalarını artık sistem yönetiyor.")


def _onkimlik(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "ad/denetim/onkimlik.csv"
    if not yol.is_file():
        return Sonuc(False, "onkimlik.csv yok.")
    satir = {r[0]: r for r in _csv(yol) if len(r) == 3}
    if set(satir) != {a for a, *_ in s["onkimlik"]}:
        return Sonuc(False, "Satır silinmiş ya da eklenmiş; hesapları silme, ayarı düzelt.")
    hala = [a for a, akt, gerekli in s["onkimlik"] if akt == "evet" and gerekli == "hayir" and satir[a][2] != "evet"]
    if hala:
        return Sonuc(False, f"Hâlâ ön kimlik doğrulaması kapalı **aktif** hesap var: {', '.join(hala)}.", yakin=True)
    return Sonuc(True, "Bütün aktif hesaplarda Kerberos ön kimlik doğrulaması açık; AS-REP roasting yüzeyi kapandı.")


def _laps(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "ad/denetim/yerel_admin.csv"
    if not yol.is_file():
        return Sonuc(False, "yerel_admin.csv yok.")
    satir = {r[0]: r for r in _csv(yol) if len(r) == 3}
    if set(satir) != {a for a, *_ in s["yerel"]}:
        return Sonuc(False, "Makine satırı silinmiş ya da eklenmiş; LAPS'ı açmak için `laps` sütununu değiştir.")
    hala = [a for a in s["ortak"] if satir[a][2] != "evet"]
    if hala:
        return Sonuc(False, f"Aynı yerel yönetici özetini paylaşan şu makinelerde LAPS hâlâ kapalı: {', '.join(hala)}.", yakin=True)
    return Sonuc(True, "Ortak yerel yönetici parolası paylaşan makinelerde LAPS açıldı; her makinenin parolası ayrılacak.")


def _tier(b: Baglam) -> Sonuc:
    yol = b.lab / "ad/denetim/katman_gpo.txt"
    if not yol.is_file():
        return Sonuc(False, "katman_gpo.txt yok.")
    gpo = {}
    for ham in yol.read_text(errors="replace").splitlines():
        m = re.match(r"^(\S+)\s+baglanti=(\S+)\s+deny_logon=(\S*)\s*$", ham.strip())
        if m:
            gpo[m.group(1)] = set(x for x in m.group(3).split(",") if x)
    gerekli = {"GPO-DC-Politikasi", "GPO-Sunucu-Kisitlari", "GPO-Istasyon-Kisitlari"}
    if set(gpo) != gerekli:
        return Sonuc(False, "GPO satırlarından biri silinmiş ya da biçimi bozulmuş. Biçim: `AD baglanti=OU=... deny_logon=Grup1,Grup2`.")
    if "Domain_Admins" in gpo["GPO-DC-Politikasi"]:
        return Sonuc(False, "DC politikasına `Domain_Admins` reddi koymuşsun: yöneticiler DC'ye giremez. Katman 0 yalnızca Katman 0'da oturum açabilir; DC'de **izinli** olmalı.", yakin=True)
    for ad in ("GPO-Sunucu-Kisitlari", "GPO-Istasyon-Kisitlari"):
        if "Domain_Admins" not in gpo[ad]:
            return Sonuc(False, f"`{ad}` içinde `Domain_Admins` reddi yok: Katman 0 hesapları hâlâ Katman {'1' if 'Sunucu' in ad else '2'}'de oturum açabilir.", yakin=True)
        if "Guests" not in gpo[ad]:
            return Sonuc(False, f"`{ad}` içindeki mevcut `Guests` reddini silmişsin; yenisini **ekle**, eskiyi silme.", yakin=True)
    return Sonuc(True, "Domain Admin'ler sunucu ve istasyonlarda oturum açamıyor; yalnızca Katman 0'da çalışabilirler.")


def coz(lab: Path, s: dict) -> dict:
    d = "ad/denetim"
    riskli = sh(f"awk -F, 'NR>1 && $2==\"evet\" && $3==\"user\" {{print $1}}' {d}/servis_hesaplari.csv | tr '\\n' ' '", lab)
    ortak = sh(f"awk -F, 'NR==FNR {{if (FNR>1) c[$2]++; next}} FNR>1 && c[$2]>1 {{print $1}}' {d}/yerel_admin.csv {d}/yerel_admin.csv | tr '\\n' ' '", lab)
    sh(f"awk -F, 'BEGIN{{OFS=\",\"}} NR>1 && $2==\"evet\" && $3==\"user\" {{$3=\"gmsa\"}} {{print}}' {d}/servis_hesaplari.csv > {d}/.t && mv {d}/.t {d}/servis_hesaplari.csv", lab)
    sh(f"awk -F, 'BEGIN{{OFS=\",\"}} NR>1 && $2==\"evet\" && $3==\"hayir\" {{$3=\"evet\"}} {{print}}' {d}/onkimlik.csv > {d}/.t && mv {d}/.t {d}/onkimlik.csv", lab)
    sh(f"awk -F, 'BEGIN{{OFS=\",\"}} NR==FNR {{if (FNR>1) c[$2]++; next}} FNR>1 && c[$2]>1 {{$3=\"evet\"}} {{print}}' {d}/yerel_admin.csv {d}/yerel_admin.csv > {d}/.t && mv {d}/.t {d}/yerel_admin.csv", lab)
    sh(f"sed -i -E '/^GPO-(Sunucu|Istasyon)/ s/deny_logon=([^ ]*)/deny_logon=\\1,Domain_Admins/' {d}/katman_gpo.txt", lab)
    return sec_doldur({1: riskli, 2: "", 3: ortak, 4: "", 5: "", 6: ""}, GOREVLER, lab, s)


def _riskli_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen & {x.lower() for x in b.senaryo["guvenli"]}:
        return "Listende riskli olmayan bir hesap var: zaten gMSA olan ya da SPN'si olmayan hesap bu sorunun konusu değil."
    return None


def _ortak_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen and verilen - {x.lower() for x in b.senaryo["ortak"]}:
        return "Listende kendi özeti olan bir makine var. Aradığın, **aynı** özeti birden çok makinede gören satırlar."
    return None


ADIMLAR = [
    Adim("Denetim bulgularından düzeltmeye", """
Selin: "Saldırıları anladın; şimdi onları durdurma sırası sende. **<<musteri>>**. <<sahne>>
`ad/denetim/` klasöründe dört denetim çıktısı var; her biri bir savunmanın eksiğini gösteriyor."

AD savunmasının dört direği (kitaptaki tablo):

- **gMSA:** güçlü, otomatik servis parolaları → Kerberoasting'i zorlaştırır.
- **LAPS:** her makinede benzersiz yerel yönetici parolası → pass-the-hash yayılımını kırar.
- **Tiering:** ayrıcalıklı kimlik bilgisi yayılmaz → yanal hareketi engeller.
- **MFA ve izleme:** çalınan parola yetmez; anormal bilet/giriş görülür.

Önce klasöre bak:
""", komut="ls -l ad/denetim"),
    Adim("Servis hesapları ve gMSA", """
**gMSA** (grup yönetilen hizmet hesabı), parolasını AD'nin kendisinin ürettiği ve düzenli
değiştirdiği, çok uzun ve rastgele bir parolalı servis hesabıdır. İnsan parola bilmez, bu yüzden
çevrimdışı kırılamaz. Dosyada `tur` sütunu hesabın kullanıcı mı gMSA mı olduğunu söyler:
""", komut="cat ad/denetim/servis_hesaplari.csv", sonra="""
Yüksek `parola_yasi_gun` ile `user` türü ve `spn_var=evet` birleşimi Kerberoasting'in hedefidir.
`spn_var=hayir` olan kullanıcı hesabı bilet isteğine açık değildir; o satır riskli sayılmaz.
"""),
    Adim("Ön kimlik doğrulaması", """
Kerberos ön kimlik doğrulaması kapalı olan hesaplar AS-REP roasting'e açıktır (Bölüm 3).
Kapalı olması çoğu zaman eski bir uygulama uyumu için bırakılır. Savunma: **hiçbir hesapta kapatma**.
""", komut="cat ad/denetim/onkimlik.csv", sonra="""
Pasif (aktif=hayir) bir hesapta kapalı olması ayrıca tehlike değildir; öncelik aktif hesaplardır.
"""),
    Adim("LAPS: her makineye ayrı parola", """
Tüm bilgisayarlarda **aynı** yerel yönetici parolası varsa, bir makinede yakalanan özet
(hash) hepsinde kullanılabilir; saldırgan makineden makineye atlar. **LAPS** (Local Administrator
Password Solution), her makinenin yerel yönetici parolasını benzersiz ve düzenli değişen yapar.
Yerel yönetici özetlerine bak:
""", komut="cat ad/denetim/yerel_admin.csv", sonra="""
Aynı özet birden çok satırda görünüyorsa o makineler aynı parolayı paylaşıyor demektir.
`awk` ile bir sütunda tekrar edenleri bulabilirsin (iki geçişli: önce say, sonra yaz).
"""),
    Adim("Tiering'i GPO ile zorlamak", """
Katman kuralı ("üst katman kimlik bilgisi alt katmanda kullanılmaz") yazılı bir niyet değil,
**teknik bir kısıt** olmalıdır: sunucu ve istasyon GPO'larında Domain Admin grubuna
"yerel oturum açmayı reddet" hakkı verilir. DC politikasında ise Domain Admin'lere izin kalır.
""", komut="cat ad/denetim/katman_gpo.txt", sonra="""
Bir ayarı değiştirirken mevcut değerleri (burada `Guests`) silme, **ekle**.
Gerçek AD'de bu ayarı üretimde değiştirmeden önce bir test OU'sunda dene ve yönetici oturumlarını
açık tut: kendi kendini dışarıda bırakmak klasik hatadır.
"""),
]

GOREVLER = [
    Gorev("`servis_hesaplari.csv` içinde **gMSA'ya taşınması gereken** hesapları yaz: kullanıcı tipinde (`user`) "
          "**ve** SPN'si olan (`spn_var=evet`) hesaplar.",
          Kume("riskli", sik_hatalar=_riskli_hata, bicim="hesap adları, virgülle ayrılmış"),
          ("İki koşul birlikte: tür ve SPN.",
           "`tur=user` ve `spn_var=evet` olan satırlar. Zaten `gmsa` olanı ya da SPN'si olmayanı alma.",
           "`awk -F, 'NR>1 && $2==\"evet\" && $3==\"user\" {print $1}' ad/denetim/servis_hesaplari.csv`"),
          puan=30, baslik="gMSA adayları"),
    Gorev("Riskli servis hesaplarının hepsinin `tur` değerini `gmsa` yap. Diğer satırlara dokunma. Bitince `cevap 2`.",
          Durum(_gmsa, "riskli satırlarda tur=gmsa"),
          ("Hesabı silmiyoruz; hesabın türünü değiştiriyoruz.",
           "`servis_hesaplari.csv`'de bir önceki görevde bulduğun satırların üçüncü sütunu.",
           "`awk -F, 'BEGIN{OFS=\",\"} NR>1 && $2==\"evet\" && $3==\"user\" {$3=\"gmsa\"} {print}' ad/denetim/servis_hesaplari.csv > ad/denetim/.t && mv ad/denetim/.t ad/denetim/servis_hesaplari.csv`"),
          puan=40, baslik="gMSA'ya taşı"),
    Gorev("Hangi makineler **aynı yerel yönetici özetini** paylaşıyor? (`yerel_admin.csv`)",
          Kume("ortak", sik_hatalar=_ortak_hata, bicim="makine adları, virgülle ayrılmış"),
          ("Aynı değer birden çok satırda geçiyor.",
           "İkinci sütunda (`yerel_admin_ozet`) tekrar eden değeri bul; o değeri taşıyan makineler.",
           "`awk -F, 'NR==FNR {if (FNR>1) c[$2]++; next} FNR>1 && c[$2]>1 {print $1}' ad/denetim/yerel_admin.csv ad/denetim/yerel_admin.csv`"),
          puan=40, baslik="Paylaşılan yerel parola"),
    Gorev("Bu makinelerde LAPS'ı aç: `laps` sütununu `evet` yap. Bitince `cevap 4`.",
          Durum(_laps, "ortak özetli makinelerde laps=evet"),
          ("Bir önceki görevin makineleri.",
           "`yerel_admin.csv` üçüncü sütun. Diğer makinelerde zaten `evet` yazıyor.",
           "Satırları tek tek `sed -i 's/^<makine>,\\(.*\\),hayir$/<makine>,\\1,evet/' ad/denetim/yerel_admin.csv` ile ya da `nano` ile düzelt."),
          puan=40, baslik="LAPS'ı aç"),
    Gorev("`onkimlik.csv` içinde **aktif** hesaplarda ön kimlik doğrulaması kapalı olanları düzelt "
          "(`onkimlik_gerekli=evet`). Bitince `cevap 5`.",
          Durum(_onkimlik, "aktif hesaplarda onkimlik_gerekli=evet"),
          ("İki koşul: aktif ve gereklilik kapalı.",
           "`aktif=evet` ve `onkimlik_gerekli=hayir` satırlarının üçüncü sütunu.",
           "`awk -F, 'BEGIN{OFS=\",\"} NR>1 && $2==\"evet\" && $3==\"hayir\" {$3=\"evet\"} {print}' ad/denetim/onkimlik.csv > ad/denetim/.t && mv ad/denetim/.t ad/denetim/onkimlik.csv`"),
          puan=40, baslik="Ön kimlik doğrulaması"),
    Gorev("`katman_gpo.txt` dosyasında **sunucu ve istasyon** GPO'larının `deny_logon` listesine `Domain_Admins` "
          "ekle (mevcut `Guests` kalsın). **DC politikasına dokunma.** Bitince `cevap 6`.",
          Durum(_tier, "Sunucu ve İstasyon GPO'larında deny_logon=Guests,Domain_Admins; DC GPO'su değişmez"),
          ("İki GPO değişecek, biri değişmeyecek.",
           "Domain Admin DC'de oturum açabilmeli; sunucu ve istasyonda açamamalı.",
           "`sed -i -E '/^GPO-(Sunucu|Istasyon)/ s/deny_logon=([^ ]*)/deny_logon=\\1,Domain_Admins/' ad/denetim/katman_gpo.txt`"),
          puan=50, baslik="Katman GPO'su"),
    Gorev("Tiering'in doğru ifadesi hangisidir?",
          Secmeli([
              ("Bir katmanın kimlik bilgisi, daha düşük bir katmandaki makinede asla kullanılmaz",
               "Doğru. Böylece kullanıcı makinesini ele geçiren saldırgan oradan Domain Admin bilgisi toplayamaz."),
              ("Her yönetici tüm katmanlarda aynı hesapla oturum açar ki kimlik sayısı az kalsın",
               "Yanlış. Aynı hesabın her yerde kullanılması tiering'in tam tersidir."),
              ("Katmanlar sadece fiziksel binaları ayırır; kimlik bilgilerini hiçbir şekilde etkilemez",
               "Yanlış. Tiering mantıksal ve kimlik tabanlı bir ayrımdır."),
              ("Katman 2'deki bir hesap, gerektiğinde Katman 0 bilgisayarlarının parolasını bilmelidir",
               "Yanlış. Üst katman bilgisi alt katman hesaplarında bulunmaz; yetki yukarı doğru akmaz."),
          ], dogru=0),
          ("Ayrıcalığın yayılmasını nasıl durdurursun?",
           "Katman 0 hesabı Katman 2'de oturum açarsa ne olur?",
           "Üst kimlik bilgisi alt katmanda kullanılmaz."),
          puan=20, baslik="Tiering ilkesi"),
    Gorev("Hangi eşleştirme **doğrudur**?",
          Secmeli([
              ("LAPS pass-the-hash yayılımını, gMSA ise Kerberoasting'i zorlaştırır",
               "Doğru. LAPS benzersiz yerel parola verir; gMSA servis parolasını güçlü ve otomatik kılar."),
              ("LAPS Kerberoasting'i, gMSA ise pass-the-hash yayılımını engeller",
               "Yanlış. Eşleştirme ters çevrilmiş."),
              ("İkisi de yalnızca güvenlik duvarı kurallarını yönetir ve kimlikle ilgisi yoktur",
               "Yanlış. İkisi de kimlik ve parola hijyeni araçlarıdır."),
              ("LAPS yalnızca MFA kodları üretir, gMSA ise yalnızca log dosyalarını sıkıştırır",
               "Yanlış. Bunlar o araçların işi değildir."),
          ], dogru=0),
          ("Kitaptaki savunma tablosuna dön: hangi araç hangi saldırıyı engeller?",
           "LAPS = yerel yönetici, gMSA = servis hesabı.",
           "Yerel yönetici parolası → pass-the-hash; servis parolası → Kerberoasting."),
          puan=20, baslik="Savunma eşleştirmesi"),
]


def _kapanis():
    return """
AD savunmasında hiçbir önlem "yeni" değildir: gMSA, LAPS, tiering, ön kimlik doğrulaması. Hepsi
bilinir, ama çoğu kurum kolaylık için erteler. Saldırgan bu ihmalleri arar; sen kapatırsın. Yeni bir
ayarı üretimde değiştirmeden önce test OU'sunda dene, yönetici oturumunu açık tut, değişikliği
sonradan **yeniden denetleyip** doğrula ve düzeltmeyi izlemeyle destekle (LAPS ve gMSA
olayları, katman GPO'sundaki ihlal denemeleri).
"""


SEVIYE = Seviye(
    kimlik="c11b05",
    cilt=11,
    bolum=5,
    baslik="AD Savunması",
    brifing="""
Selin düzeltme planı taslağını sana uzatıyor: "**<<musteri>>**. <<sahne>> Dört denetim çıktısı
var: servis hesapları, ön kimlik doğrulama, yerel yönetici parolaları ve katman GPO'ları. Hepsini
sen düzelt. Ama bir şeyi unutma: düzeltirken iş yapan hesapları bozma."

Deniz ekliyor: "Düzelttiğin her şeyin bir de **tespit** karşılığı olsun; ben alarmlarımı ona göre
yazacağım."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Yaygın AD bulguları:** Pek çok kurumsal sızma testi raporunda aynı yerel yönetici parolasının
  birçok makinede kullanılması, eski parolalı servis hesapları ve Domain Admin'lerin sıradan
  bilgisayarlarda oturum açması en sık görülen bulgular arasındadır.
- **LAPS ve gMSA:** Microsoft'un yayımladığı çözümlerdir; birincisi yerel yönetici parolalarını
  benzersiz kılar, ikincisi servis hesabı parolalarını sistem yönetimine alır. Bunlar saldırıyı
  "imkânsız" kılmaz ama yayılımı ve çevrimdışı kırmayı belirgin biçimde zorlaştırır.
- **Tespit:** Ayrıcalıklı grup değişiklikleri, ön kimlik doğrulaması kapalı hesaplar için 4768
  olaylarındaki `OnKimlik=0` izi ve Domain Admin'lerin alt katman oturum açma denemeleri SIEM'de
  alarm olarak tanımlanabilir. Önleme için katmanlı yönetim modeli GPO ile **zorlanır**.
""",
    sure_hedef_dk=40,
)
