"""Cilt 11 · Bölüm 3 — Kimlik Bilgisi Saldırıları (tespit gözüyle).

Beceri: kurgusal bir Domain Controller güvenlik olay günlüğünde (4624/4625/4768/4769) üç
klasik kimlik saldırısının izini okumak: parola püskürtme (çok hesap, az deneme), Kerberoasting
(tek hesaptan çok sayıda RC4 servis bileti isteği) ve AS-REP roasting (ön kimlik doğrulaması
kapalı hesap). Saldırı komutu yoktur; yalnızca savunmanın gördüğü izler okunur.

Vakalar: banka, lojistik, belediye, hastane. Her günlükte aynı sayıda satır yoktur ve "tuzak"
davranışlar (tek hesaba kaba kuvvet, eski uygulamanın RC4 isteği) bulunur.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c11_ad.ortak import hesap_adlari, sec_doldur, sh, sirket_sec

HIZMETLER = ["MSSQLSvc/{on}-sql01.{alan}:1433", "HTTP/{on}-web01.{alan}", "CIFS/{on}-dosya01.{alan}",
             "BackupSvc/{on}-yedek01.{alan}", "HOST/{on}-baski01.{alan}", "MSSQLSvc/{on}-rapor01.{alan}:1433",
             "HTTP/{on}-izle01.{alan}"]
SAHNE = {
    "ferahbank": "Ferah Bank'ın SOC'u gece yarısı alışılmadık bir kimlik doğrulama yoğunluğu gördü.",
    "kuzgun": "Kuzgun Lojistik'te sabah vardiyasında onlarca kişi 'parolam yanlış diyor' diye destek hattını aradı.",
    "yesiltepe": "Yeşiltepe Belediyesi'nde bilgi işlem, hafta sonu boyunca DC'nin güvenlik günlüğünün şiştiğini fark etti.",
    "medora": "Medora Sağlık'ta bir hemşire hesabı gece 03:00'te kilitlendi; kimse nedenini bilmiyor.",
}
ESKI_HESAPLAR = ["eski.uygulama", "test.hesabi", "stajyer.ornek", "demo.kullanici"]


def uret(rng):
    sk = sirket_sec(rng)
    on, alan = sk["on"], sk["alan"]
    dcler = [f"{on}-dc01", f"{on}-dc02"]
    hesaplar = hesap_adlari(rng, 26)
    ipler = {}
    kullanilan = set()
    ag = rng.choice(["10.20.1", "10.20.4", "10.30.2"])

    def yeni_ip():
        while True:
            ip = u.ic_ip(rng, ag)
            if ip not in kullanilan:
                kullanilan.add(ip)
                return ip

    for h in hesaplar:
        ipler[h] = yeni_ip()
    sp_ip, bf_ip, uyg_ip = yeni_ip(), yeni_ip(), yeni_ip()
    kurban = hesaplar[0]
    bf_hesap = hesaplar[1]
    n_sp = rng.randint(12, 18)
    sp_hedefler = rng.sample(hesaplar[2:], n_sp - 1) + [kurban]       # kurban da püskürtülen hesaplardan biri
    asrep = rng.choice(ESKI_HESAPLAR)
    eski_svc = "svc-eskiapp"
    gun = u.gun(rng) + timedelta(hours=rng.randint(0, 2))
    hizmetler = [h.format(on=on, alan=alan) for h in HIZMETLER]
    olaylar = []

    def tz(t):
        return f"{t:%Y-%m-%dT%H:%M:%S}+03:00"

    def e4624(t, h, ip):
        olaylar.append((t, f"{tz(t)} {rng.choice(dcler)} EventID=4624 Hesap={h} Kaynak={ip} GirisTuru=3"))

    def e4625(t, h, ip, kod="0xC000006A"):
        olaylar.append((t, f"{tz(t)} {rng.choice(dcler)} EventID=4625 Hesap={h} Kaynak={ip} GirisTuru=3 Durum={kod}"))

    def e4768(t, h, ip, onkimlik=1, sif="0x12"):
        olaylar.append((t, f"{tz(t)} {rng.choice(dcler)} EventID=4768 Hesap={h} Kaynak={ip} OnKimlik={onkimlik} SifrelemeTuru={sif} Sonuc=0x0"))

    def e4769(t, h, hz, ip, sif="0x12"):
        olaylar.append((t, f"{tz(t)} {rng.choice(dcler)} EventID=4769 Hesap={h} Hizmet={hz} Kaynak={ip} SifrelemeTuru={sif} Sonuc=0x0"))

    # arka plan
    for _ in range(rng.randint(70, 90)):
        h = rng.choice(hesaplar)
        t = gun + timedelta(seconds=rng.randint(-5400, 5400))
        r = rng.random()
        if r < 0.5:
            e4624(t, h, ipler[h])
        elif r < 0.75:
            e4768(t, h, ipler[h])
        else:
            e4769(t, h, rng.choice(hizmetler), ipler[h])
    for _ in range(rng.randint(5, 8)):                              # tek tük yanlış parola
        h = rng.choice(hesaplar[2:])
        e4625(gun + timedelta(seconds=rng.randint(-5400, 5400)), h, ipler[h])
    # tuzak 1: tek hesaba kaba kuvvet (satır sayısı püskürtmeden fazla)
    t = gun + timedelta(minutes=rng.randint(-40, -10))
    for _ in range(rng.randint(24, 30)):
        t += timedelta(seconds=rng.randint(3, 9))
        e4625(t, bf_hesap, bf_ip)
    # saldırı 1: parola püskürtme
    t = gun + timedelta(minutes=rng.randint(5, 15))
    for h in sp_hedefler:
        t += timedelta(seconds=rng.randint(20, 45))
        e4625(t, h, sp_ip, "0xC000006A")
    for h in rng.sample(sp_hedefler[:-1], 2):                       # iki hesaba ikinci deneme
        t += timedelta(seconds=rng.randint(20, 45))
        e4625(t, h, sp_ip, "0xC000006A")
    yok = [rng.choice(["admin", "test", "backup"]) for _ in range(2)]   # var olmayan hesap adı denemeleri
    for a in yok:
        t += timedelta(seconds=rng.randint(20, 45))
        e4625(t, a, sp_ip, "0xC0000064")
    t += timedelta(seconds=30)
    e4624(t, kurban, sp_ip)
    # saldırı 2: Kerberoasting izi (başarılı girişten sonra, kısa sürede çok servis, RC4)
    t += timedelta(minutes=2)
    e4768(t, kurban, sp_ip)
    for hz in rng.sample(hizmetler, rng.randint(5, 7)):
        t += timedelta(seconds=rng.randint(2, 8))
        e4769(t, kurban, hz, sp_ip, "0x17")
    # tuzak 2: eski uygulama sürekli RC4 ile ama hep tek servise
    for _ in range(rng.randint(7, 10)):
        e4769(gun + timedelta(seconds=rng.randint(-5400, 5400)), eski_svc, hizmetler[0], uyg_ip, "0x17")
    # saldırı 3: AS-REP (ön kimlik doğrulaması kapalı hesap)
    t += timedelta(minutes=1)
    for _ in range(2):
        t += timedelta(seconds=rng.randint(2, 6))
        e4768(t, asrep, sp_ip, 0, "0x17")
    olaylar.sort(key=lambda x: x[0])
    return {
        "vaka": f"{sk['ad']} — DC güvenlik günlüğü",
        "sirket": sk, "satirlar": [x[1] for x in olaylar], "bf_ip": bf_ip, "eski_svc": eski_svc,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "alan": alan},
        "cevaplar": {"sp_ip": sp_ip, "sp_sayi": len(set(sp_hedefler) | set(yok)), "kerberoast": kurban, "asrep": asrep},
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "ad/dc_guvenlik_olaylari.log", "\n".join(s["satirlar"]) + "\n")
    u.yaz(lab / "ad/olay_kimlikleri.txt",
          "Windows güvenlik olay kimlikleri (özet)\n"
          "4624  başarılı oturum açma\n"
          "4625  başarısız oturum açma (Durum 0xC000006A = yanlış parola, 0xC0000064 = böyle bir hesap yok)\n"
          "4768  Kerberos kimlik bileti (TGT) isteği (OnKimlik=0: ön kimlik doğrulaması kullanılmadı)\n"
          "4769  Kerberos servis bileti (TGS) isteği (SifrelemeTuru 0x12 = AES, 0x17 = RC4, eski ve zayıf)\n")


def coz(lab: Path, s: dict) -> dict:
    f = "ad/dc_guvenlik_olaylari.log"
    hesap_kaynak = f"grep EventID=4625 {f} | awk '{{print $5, $4}}' | sort -u | awk '{{print $1}}' | uniq -c | sort -rn | head -1"
    return sec_doldur({
        2: sh(hesap_kaynak + " | awk '{print $2}' | cut -d= -f2", lab),
        3: sh(hesap_kaynak + " | awk '{print $1}'", lab),
        4: sh(f"grep EventID=4769 {f} | grep 'SifrelemeTuru=0x17' | awk '{{print $4, $5}}' | sort -u | awk '{{print $1}}' "
              "| uniq -c | sort -rn | head -1 | awk '{print $2}' | cut -d= -f2", lab),
        5: sh(f"grep EventID=4768 {f} | grep 'OnKimlik=0' | awk '{{print $4}}' | sort -u | cut -d= -f2", lab),
    }, GOREVLER, lab, s)


def _ip_hata(g, beklenen, b):
    if g == b.senaryo["bf_ip"]:
        return ("Bu IP en çok başarısız denemeyi yapmış ama hep **tek bir hesaba**: bu kaba kuvvet (brute force). "
                "Parola püskürtme tersidir: çok hesap, hesap başına az deneme. Kaynak başına **farklı hesap** say.")
    return None


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    toplam = sum(1 for x in b.senaryo["satirlar"] if "EventID=4625" in x and f"Kaynak={b.senaryo['cevaplar']['sp_ip']} " in x)
    if n == toplam:
        return "Bu, o IP'den gelen **satır** sayısı. Bazı hesaplar iki kez denenmiş; sorulan farklı (benzersiz) hesap sayısı."
    return None


def _kerb_hata(g, beklenen, b):
    if g == b.senaryo["eski_svc"]:
        return ("Bu hesap çok RC4 isteği yapmış ama hep **aynı tek servise**: eski bir uygulamanın meşru davranışı. "
                "Kerberoasting izi, **çok sayıda farklı servis** için kısa sürede bilet istemektir.")
    return None


ADIMLAR = [
    Adim("Kimlik saldırıları yazılım açığı değildir", """
AD'de saldırgan çoğu zaman exploit kullanmaz, **kimlik bilgisi** kullanır. Bu yüzden bu saldırılar
yamayla düzelmez; yalnızca iyi yapılandırma ve izlemeyle azaltılır. Bu bölümde saldırıları
**saldırganın gözünden değil, günlüğün gözünden** okuyacağız.

**<<musteri>>**: <<sahne>> Elimizde DC'nin güvenlik olay günlüğü var. Satırın yapısına bak:
""", komut="head -4 ad/dc_guvenlik_olaylari.log", sonra="""
Her satır: zaman, DC adı, olay kimliği, hesap, kaynak IP ve olaya özgü ek alanlar.
Kimliklerin anlamı `ad/olay_kimlikleri.txt` içinde; oku:
"""),
    Adim("Olay kimlikleri", """
Savunmacı için dört olay kimliği ezberdir: **4624** (başarılı giriş), **4625** (başarısız giriş),
**4768** (Kerberos TGT isteği) ve **4769** (servis bileti, TGS, isteği).
""", komut="cat ad/olay_kimlikleri.txt"),
    Adim("Parola tahmin saldırısı: iki yüz", """
İki farklı saldırı 4625 üretir:

- **Kaba kuvvet (brute force):** tek hesaba çok parola. Hesap kilitlenir, dikkat çeker.
- **Parola püskürtme (password spraying):** çok hesaba, hesap başına **birkaç** deneme. Kilit
  eşiğini aşmadığı için sessizdir.

Önce kaynak IP başına başarısız giriş sayısına bak:
""", komut="grep EventID=4625 ad/dc_guvenlik_olaylari.log | grep -o 'Kaynak=[0-9.]*' | sort | uniq -c | sort -rn | head -3",
         sonra="""
En üstteki IP en çok denemeyi yapmış ama bu onu püskürtme yapmaz. Ayırt edici ölçü **farklı hesap
sayısıdır**.
"""),
    Adim("Kaynak başına farklı hesap", """
`sort -u` ile (kaynak, hesap) çiftlerini benzersizleştir, sonra kaynağa göre say:
""", komut="grep EventID=4625 ad/dc_guvenlik_olaylari.log | awk '{print $5, $4}' | sort -u | awk '{print $1}' | uniq -c | sort -rn | head -3",
         sonra="""
Bir IP'den onlarca **farklı** hesaba başarısız deneme geliyorsa bu bir püskürtmedir. Savunma:
çok faktörlü kimlik doğrulama (MFA), yaygın zayıf parolaların yasaklanması ve bu örüntü için
alarm kuralı.
"""),
    Adim("Kerberoasting'in günlükteki izi", """
**Kerberoasting** (kavram): SPN'li bir servis hesabı için herhangi bir kullanıcı servis bileti
(TGS) isteyebilir. Bilet o hesabın parolasıyla şifrelidir; saldırgan bileti alıp **çevrimdışı**
parola kırmayı dener. DC'ye karşı ek bir istek göndermediği için sadece biletin alındığı an görünür.

Günlükte iz şudur: tek bir hesap, kısa sürede **çok sayıda farklı servis** için, **RC4 (0x17)**
şifrelemeyle bilet ister. Modern ortamlar AES (0x12) kullanır; RC4 zayıf ve nadirdir.
""", komut="grep EventID=4769 ad/dc_guvenlik_olaylari.log | grep 'SifrelemeTuru=0x17' | awk '{print $4, $5}' | sort -u | awk '{print $1}' | uniq -c | sort -rn | head -3",
         sonra="""
En üstteki hesap, çok sayıda farklı servis için RC4 bileti istemiş. Altındaki satırlar daha az
servisli hesaplardır; bir hesabın hep aynı tek servisi RC4 ile istemesi çoğu zaman eski bir
uygulamanın meşru davranışıdır.
"""),
    Adim("AS-REP roasting'in izi", """
Bazı hesaplarda **Kerberos ön kimlik doğrulaması kapalıdır**. Bu hesaplar için saldırgan, parola
bilmeden şifreli bir yapı alıp çevrimdışı kırabilir. Günlükte 4768 satırında `OnKimlik=0` görünür.
""", komut="grep EventID=4768 ad/dc_guvenlik_olaylari.log | grep 'OnKimlik=0'", sonra="""
Savunma: ön kimlik doğrulamasını **hiçbir** hesapta kapatma; kapalı olanları AD dökümünden
düzenli ara (Bölüm 2'deki gibi) ve aç. `OnKimlik=0` içeren olaylar için alarm kur.

**Hacker gözüyle:** İkisinin de ortak noktası, AD'nin tasarımının sonucu olmaları: yazılım açığı
yok, yapılandırma ve parola hijyeni var.
"""),
]

GOREVLER = [
    Gorev("Kerberoasting'de saldırgan servis biletini neden **çevrimdışı** kırabilir?",
          Secmeli([
              ("Bilet servis hesabının parolasıyla şifrelidir; denemeler DC'ye dokunmadan yapılır",
               "Doğru. DC'ye başarısız giriş düşmediği için kilit ve alarm devreye girmez."),
              ("Çünkü DC her bileti düz metin olarak e-postayla istek yapan kullanıcıya gönderir",
               "Yanlış. Bilet şifrelidir; sorun şifrelemenin servis hesabının parolasına bağlı olmasıdır."),
              ("Çünkü saldırgan servis sunucusunu fiziksel olarak ele geçirir ve disk imajını alır",
               "Yanlış. Kerberoasting için sunucuya erişmek gerekmez; yalnızca geçerli bir domain hesabı yeter."),
              ("Çünkü bilet süresiz geçerlidir ve parola değişse bile aynı bilet kullanılmaya devam eder",
               "Yanlış. Biletin geçerlilik süresi sınırlıdır; sorun, kırılan parolanın kendisidir."),
          ], dogru=0),
          ("Bilet neyle şifrelendi?",
           "Çevrimdışı = hedef sisteme dokunmadan, yani DC'de iz bırakmadan.",
           "Şifreleme anahtarı, servis hesabının parolasından türer."),
          puan=20, baslik="Neden çevrimdışı"),
    Gorev("Günlükte **parola püskürtme** yapan kaynak IP hangisi? (En çok satır üreten değil, çok "
          "**farklı hesaba** deneme yapan.)",
          IP("sp_ip", sik_hatalar=_ip_hata),
          ("Püskürtme: çok hesap, hesap başına az deneme.",
           "4625 satırlarında kaynak başına **benzersiz hesap** sayısını çıkar.",
           "`grep EventID=4625 ad/dc_guvenlik_olaylari.log | awk '{print $5, $4}' | sort -u | awk '{print $1}' | uniq -c | sort -rn | head -3`"),
          puan=40, baslik="Püskürtme kaynağı"),
    Gorev("O IP'den kaç **farklı hesaba** başarısız giriş denendi?",
          Sayi("sp_sayi", sik_hatalar=_sayi_hata),
          ("Satır sayısı değil, benzersiz hesap sayısı.",
           "Önceki görevdeki komutta ilk sütun (`uniq -c` çıktısı) bu sayıdır.",
           "`grep EventID=4625 ad/dc_guvenlik_olaylari.log | grep 'Kaynak=<bulduğun IP> ' | awk '{print $4}' | sort -u | wc -l`"),
          puan=30, baslik="Hedeflenen hesap sayısı"),
    Gorev("Kerberoasting izi taşıyan hesap hangisi? (Kısa sürede çok sayıda **farklı** servis için RC4 bileti "
          "isteyen hesap.)",
          Metin("kerberoast", sik_hatalar=_kerb_hata, bicim="hesap adı"),
          ("4769 olayları ve RC4 (0x17) şifrelemesi.",
           "Hesap başına **farklı servis** sayısına bak; bir hesap hep aynı servisi isteyebilir.",
           "`grep EventID=4769 ad/dc_guvenlik_olaylari.log | grep 'SifrelemeTuru=0x17' | awk '{print $4, $5}' | sort -u | awk '{print $1}' | uniq -c | sort -rn | head -3`"),
          puan=40, baslik="Kerberoasting hesabı"),
    Gorev("Ön kimlik doğrulaması kapalı olduğu için AS-REP roasting'e açık hesap hangisi? (`OnKimlik=0`)",
          Metin("asrep", bicim="hesap adı"),
          ("Hangi olay kimliği TGT isteğini kaydeder?",
           "4768 olaylarında `OnKimlik=0` içeren satır.",
           "`grep EventID=4768 ad/dc_guvenlik_olaylari.log | grep 'OnKimlik=0'`"),
          puan=30, baslik="AS-REP hesabı"),
    Gorev("Servis bileti (TGS) isteklerini hangi olay kimliği kaydeder?",
          Secmeli([
              ("4769", "Doğru. 4769 servis bileti isteğidir; Kerberoasting avında ana veri kaynağıdır."),
              ("4624", "Yanlış. 4624 başarılı oturum açmayı kaydeder."),
              ("4625", "Yanlış. 4625 başarısız oturum açma denemesidir (kaba kuvvet/püskürtmede kullanılır)."),
              ("4768", "Yanlış. 4768, TGT (kimlik bileti) isteğidir; servis bileti değil."),
          ], dogru=0, karistir=True),
          ("`ad/olay_kimlikleri.txt` dosyasında özet var.",
           "TGS = Ticket Granting **Service** bileti.",
           "Servis = 4769; TGT = 4768."),
          puan=20, baslik="Olay kimliği"),
    Gorev("Kerberoasting'e karşı en etkili kalıcı önlem hangisidir?",
          Secmeli([
              ("Servis hesaplarına gMSA ile uzun, rastgele ve otomatik değişen parolalar vermek",
               "Doğru. Parola kırılamayacak kadar uzun ve rastgele olunca çevrimdışı deneme anlamsızlaşır."),
              ("Servis hesaplarının SPN'lerini silip servislerin bilet istemesini tamamen yasaklamak",
               "Yanlış. SPN olmadan servis Kerberos ile çalışmaz; sorun SPN değil, zayıf parolayı kırmaya açık olmaktır."),
              ("Bütün DC günlüklerini silerek saldırganın izleri görmesini önlemek",
               "Yanlış. Günlük silmek tespiti ortadan kaldırır ve saldırıyı durdurmaz."),
              ("Servis hesaplarını Domain Admins grubuna alarak parolayı gereksiz kılmak",
               "Yanlış. Bu, tehlikeyi büyütür: kırılan parola doğrudan domain hakimiyeti olur."),
          ], dogru=0),
          ("Sorun parolanın kırılabilir olması.",
           "Parola insan değil sistem tarafından, çok uzun ve rastgele yönetilse?",
           "gMSA (grup yönetilen hizmet hesapları)."),
          puan=20, baslik="Kerberoasting önlemi"),
    Gorev("Pass-the-hash ile pass-the-ticket'ın ortak mantığı nedir?",
          Secmeli([
              ("AD parolanın kendisini değil, hash'i ya da bileti kabul eder",
               "Doğru. Kimlik bilgisinin kanıtı kabul edildiği için çalınan hash ya da bilet yeterlidir."),
              ("İkisi de bir yazılım açığı kullanır ve yamayla tamamen ortadan kalkar",
               "Yanlış. Tasarımın sonucudurlar; yama yerine yapılandırma ve izleme gerekir."),
              ("İkisi de yalnızca fiziksel olarak DC'nin başına geçilerek uygulanabilir",
               "Yanlış. Ağ üzerinden, geçerli kimlik bilgisiyle uygulanır."),
              ("İkisi de parolayı tahmin ederek denemekten ibarettir ve bu yüzden 4625 üretir",
               "Yanlış. Parola tahmini yapılmaz; zaten ele geçirilmiş bir hash ya da bilet kullanılır."),
          ], dogru=0),
          ("Biletin ve hash'in ortak noktası: ikisi de bir 'kanıt'.",
           "AD parolanın düz halini sormuyorsa neyi kabul ediyor?",
           "Kimlik bilgisi: hash ya da bilet."),
          puan=20, baslik="Ortak mantık"),
]


def _kapanis():
    return """
Üç saldırı, üç iz: püskürtmede **çok hesap, az deneme**, Kerberoasting'de **tek hesap, çok servis,
RC4**, AS-REP roasting'de `OnKimlik=0`. Saldırgan bunları parola kırma araçlarıyla yapar ama DC'nin
günlüğü hepsini kaydeder. Savunma dersi: bu üç örüntü için alarm yaz, servis hesaplarını gMSA'ya
taşı, ön kimlik doğrulamasını her hesapta açık tut, MFA'yı yaygınlaştır, RC4'ü mümkün olduğunca
kapat. Saldırıyı bilmek, günlüğü okuyabilmenin yarısıdır.
"""


SEVIYE = Seviye(
    kimlik="c11b03",
    cilt=11,
    bolum=3,
    baslik="Kimlik Bilgisi Saldırıları",
    brifing="""
Deniz'in sesi telefondan geliyor: "**<<musteri>>** için DC'nin güvenlik günlüğünü aldık. <<sahne>>
Bir şeyler oldu ama ne olduğunu bilmiyoruz. Üç şüphem var: parola püskürtme, Kerberoasting ve
AS-REP. Hangisi var, kim yapıyor, hangi hesap etkilendi?"

Selin: "Saldırı aracı kullanmayacaksın. Günlüğü okuyacak ve izleri bulacaksın; gerçek hayatta
SOC'un yaptığı da bu."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Parola püskürtme:** Kimlik bulutu ve AD ortamlarında, tek bir parolanın çok hesapta denenmesi
  kamuya açık güvenlik bültenlerinde sık anılan bir tekniktir. Hesap kilitleme eşiğine takılmadığı
  için kaba kuvvetten daha sessizdir; MFA ve yaygın parola yasak listeleri bu yüzden önerilir.
- **Kerberoasting ve AS-REP roasting:** Kamuya açık rehberlerde (örneğin MITRE ATT&CK'in Kerberos
  biletlerini çalma teknikleri) tarif edilir ve yazılım açığı değil tasarım sonucudur. Tespitte 4769
  olaylarında RC4 şifreleme ve tek hesaptan çok servis isteği, 4768'de ön kimlik doğrulamasız istek
  izlenir.
- **Önleme:** Servis hesapları için gMSA, uzun rastgele parolalar, ön kimlik doğrulamasını açık
  tutmak, RC4'ü kapatmak ve ilgili olay kimlikleri için SIEM kuralları.
""",
    sure_hedef_dk=30,
)
