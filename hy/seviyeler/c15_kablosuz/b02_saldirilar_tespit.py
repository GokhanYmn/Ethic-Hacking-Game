"""Cilt 15 · Bölüm 2 — Kablosuz Saldırılar (kavramsal) ve Tespit.

Beceri: kurgusal tarama kayıtlarında, meşru bir ağla aynı adı yayınlayan ama envanterde olmayan sahte erişim
noktasını (evil twin) bulmak; kurgusal bir WIDS olay logunda beklenmedik deauth (bağlantı koparma kareleri)
yoğunluğunu görmek; el sıkışma yakalama + çevrimdışı kırmanın neden parola kalitesine bağlı olduğunu anlamak.

Vakalar: Atölye Kahve, Kuzgun Lojistik, Medora Sağlık, Ferah Bank. Bu seviyede hiçbir saldırı yapılmaz ve
saldırı aracı komutu verilmez; yalnızca kurgusal kayıtlar analiz edilir (savunma bakışı).
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c15_kablosuz.ortak import (KOMSU_ADLARI, ap_satiri, mac, macler, sec_doldur, sh,
                                              tarama_csv, vaka_sec)

YERLER = ["giris", "kat2", "otopark", "arka_kapi", "toplanti_odasi"]


def uret(rng):
    v = vaka_sec(rng)
    gun = u.gun(rng)
    t0 = gun + timedelta(hours=rng.randint(9, 15), minutes=rng.randint(0, 40))
    mesru = macler(rng, 4)               # 3 kurum AP + 1 misafir AP
    sahte = mac(rng, mesru)
    kanallar = [1, 6, 11]
    fk = rng.choice([2, 3, 4, 5, 7, 8, 9, 10])
    ftur = rng.choice(["OPN", "WPA2"])
    yerler = rng.sample(YERLER, 3)
    yok = rng.randrange(3)               # sahte AP bu taramada görülmez
    komsu = rng.sample(KOMSU_ADLARI, 6)
    komsu_mac = macler(rng, 6, set(mesru) | {sahte})
    taramalar = []
    for i, yer in enumerate(yerler):
        ti = t0 + timedelta(minutes=25 * i)
        satir = []
        for k in range(3):
            satir.append(ap_satiri(mesru[k], ti - timedelta(minutes=20), ti, kanallar[k], "WPA2-MGT",
                                   rng.randint(-72, -50), v["kurum"]))
        satir.append(ap_satiri(mesru[3], ti - timedelta(minutes=20), ti, 6, "WPA2", rng.randint(-75, -55), v["misafir"]))
        for j in range(rng.randint(2, 3)):
            q = rng.randrange(6)
            satir.append(ap_satiri(komsu_mac[q], ti - timedelta(minutes=18), ti, rng.choice([1, 6, 11]),
                                   rng.choice(["WPA2", "WPA3"]), rng.randint(-88, -65), komsu[q]))
        if i != yok:
            satir.append(ap_satiri(sahte, ti - timedelta(minutes=6), ti, fk, ftur, rng.randint(-38, -26), v["kurum"]))
        rng.shuffle(satir)
        taramalar.append((yer, tarama_csv(satir)))
    gorulme = 2
    # WIDS olay logu
    istemciler = macler(rng, 4, set(mesru) | {sahte})
    hedef, diger = istemciler[0], istemciler[1:3]
    olay = []
    pencere = t0 + timedelta(minutes=rng.randint(5, 20))
    for k in range(rng.randint(7, 9)):
        olay.append((pencere + timedelta(seconds=k * rng.randint(2, 6)), "deauth", mesru[rng.randrange(3)], hedef,
                     rng.randint(25, 70)))
    for d in diger:
        for k in range(rng.randint(1, 2)):
            olay.append((pencere + timedelta(seconds=rng.randint(0, 40)), "deauth", mesru[rng.randrange(3)], d,
                         rng.randint(3, 12)))
    for k in range(3):   # gürültü: normal dolaşma (roaming) kaynaklı tek kare
        olay.append((t0 - timedelta(minutes=rng.randint(5, 50)), "deauth", mesru[rng.randrange(3)],
                     istemciler[3], 1))
    for k in range(18):
        olay.append((t0 - timedelta(minutes=rng.randint(1, 55), seconds=rng.randint(0, 59)), "bilgi",
                     mesru[rng.randrange(3)], istemciler[rng.randrange(4)], rng.choice(["baglandi", "ayrildi"])))
    olay.sort()
    toplam = sum(n for _, tur, _, _, n in olay if tur == "deauth")
    deauth_satir = sum(1 for _, tur, *_ in olay if tur == "deauth")
    return {
        "vaka": f"{v['ad']} — sahte erişim noktası ve deauth olayı",
        "v": v, "mesru": mesru, "sahte": sahte, "fk": fk, "ftur": ftur, "taramalar": taramalar,
        "olay": olay, "kanallar": kanallar,
        "metin": {"musteri": v["ad"], "kurum": v["kurum"], "yer": v["yer"], "hikaye": v["hikaye"]},
        "cevaplar": {"sahte": sahte, "kanal": fk, "gorulme": gorulme, "ftur": "OPN" if ftur == "OPN" else "PSK", "hedef": hedef,
                     "toplam": toplam, "_satir": deauth_satir},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} kablosuz olay dosyası. KURGUSAL tarama kayıtları ve WIDS (kablosuz saldırı tespit) logu.\n"
          "Selin'den not: Bu seviyede saldırıyı yapmıyoruz; kaydı okuyup ne olduğunu çözüyoruz.\n")
    yetkili = [f"{v['kurum']} {s['mesru'][k]} {s['kanallar'][k]} WPA2-Enterprise(802.1X)" for k in range(3)]
    yetkili.append(f"{v['misafir']} {s['mesru'][3]} 6 WPA2-PSK")
    u.yaz(lab / "envanter" / "yetkili_apler.txt",
          "# ESSID BSSID kanal şifreleme   (BT ekibinin yetkili erişim noktası listesi)\n" + "\n".join(yetkili) + "\n")
    for i, (yer, csv) in enumerate(s["taramalar"], 1):
        u.yaz(lab / "tarama" / f"tarama_{i}_{yer}.csv", csv)
    u.yaz(lab / "loglar" / "wids.log",
          "# zaman | kaynak | olay (KURGUSAL WIDS logu; adet = o saniyede görülen kare sayısı)\n" +
          "".join((f"{t:%Y-%m-%d %H:%M:%S} WIDS deauth ap={a} istemci={c} adet={n}\n" if tur == "deauth"
                   else f"{t:%Y-%m-%d %H:%M:%S} WIDS bilgi istemci={c} ap={a} olay={n}\n")
                  for t, tur, a, c, n in s["olay"]))


def coz(lab: Path, s: dict) -> dict:
    kurum = s["v"]["kurum"]
    sahte = sh(f"awk -F', ' '$14==\"{kurum}\" {{print $1}}' tarama/*.csv | sort -u | "
               "grep -v -i -F -f <(awk '{print $2}' envanter/yetkili_apler.txt)", lab)
    kanal = sh(f"awk -F', ' '$1==\"{sahte}\" {{print $4}}' tarama/*.csv | sort -u", lab)
    gorulme = sh(f"grep -l '{sahte}' tarama/*.csv | wc -l", lab)
    ftur = sh(f"awk -F', ' '$1==\"{sahte}\" {{print ($6==\"OPN\") ? \"OPN\" : $8}}' tarama/*.csv | sort -u", lab)
    hedef = sh("awk '$4==\"deauth\" {split($6,a,\"=\"); split($7,b,\"=\"); t[a[2]]+=b[2]} END {for (k in t) print t[k], k}' "
               "loglar/wids.log | sort -rn | head -1 | awk '{print $2}'", lab)
    toplam = sh("awk '$4==\"deauth\" {split($7,b,\"=\"); t+=b[2]} END {print t}' loglar/wids.log", lab)
    return sec_doldur({2: sahte, 3: kanal, 4: gorulme, 5: ftur, 6: hedef, 7: toplam}, GOREVLER, lab, s)


def _istemci_hata(g, beklenen, b):
    if g in {m.lower() for m in b.senaryo["mesru"]}:
        return "Bu bir erişim noktasının adresi (deauth karelerinin **kaynağı** gibi görünen). Sorulan, kareleri alan **istemci**."
    return None


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["cevaplar"]["_satir"]:
        return "Satır sayısını saymışsın. Her satırdaki `adet=` değerini toplaman gerekiyor (`awk` ile)."
    return None


def _kanal_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n in b.senaryo["kanallar"]:
        return "Bu, meşru erişim noktalarının kullandığı kanallardan biri. Sahte AP farklı bir kanalda yayın yapıyor."
    return None


ADIMLAR = [
    Adim("El sıkışma ve çevrimdışı tahmin (kavramsal)", """
WPA2'de bir cihaz ağa bağlanırken bir **el sıkışma (handshake)** olur. Menzildeki biri bunu, ağa bağlanmadan yalnızca
dinleyerek yakalayabilir; sonra parolayı **kendi bilgisayarında, çevrimdışı** tahmin etmeyi dener. Çevrimdışı olduğu için
sunucunun hız sınırı ya da kilitleme gibi bir engeli yoktur: saniyede milyonlarca deneme yapılır. Parola kelime listesinde
varsa ağ düşer. Bu, Cilt 3 ve 5'teki brute-force'un kablosuz hâlidir. Bu bölümde bu saldırıyı **yapmıyoruz**; asıl savunma
sorusu: parola ne kadar uzun ve rastgele?
"""),
    Adim("Sahte erişim noktası (evil twin)", """
Evil twin, meşru ağla **aynı adı** taşıyan sahte bir erişim noktasıdır. Kullanıcıların cihazı onu gerçek ağ sanıp bağlanırsa
tüm trafik saldırgandan geçer (Cilt 2'deki ortadaki adam). Ağ adı kopyalanabilir ama **BSSID (donanım adresi)**, kanal ve
şifreleme ayarı gerçek altyapıyla uyuşmaz. Savunmacı bu farkı envanterle karşılaştırarak yakalar.

Önce BT'nin yetkili AP listesine bak:
""", komut="cat envanter/yetkili_apler.txt"),
    Adim("Tarama kayıtlarında aynı ad", """
Üç farklı konumda alınmış üç tarama kaydı var. Kurum ağının adı geçen satırlardaki BSSID'leri (1. sütun), kanalı (4.) ve
şifrelemeyi (6.) yan yana getir:
""", komut="awk -F', ' '$14==\"<<kurum>>\" {print $1, $4, $6, $8, FILENAME}' tarama/*.csv"),
    Adim("Envanterde olmayanı bulmak", """
`grep -v -F -f liste dosya` listedekiler **dışındaki** satırları verir. Önce kayıtlardaki benzersiz BSSID'leri çıkar, sonra
envanterdeki adreslerle karşılaştır:
""", komut="awk -F', ' '$14==\"<<kurum>>\" {print $1}' tarama/*.csv | sort -u", sonra="""
Listede envanterdeki üç adresin dışında bir tane daha var: aynı ağ adını yayınlayan **bilinmeyen** bir cihaz. Ayrıca onu
gerçek ağlardan ayıran diğer ipuçları: kanal (meşruların 1/6/11 kanalları), şifreleme türü (meşru ağ 802.1X) ve sinyal
gücü (sahte AP yakında, güçlü sinyalle yayın yapar).
"""),
    Adim("Deauth kareleri nedir?", """
Deauth (bağlantı koparma) kareleri, bir cihazı ağdan düşürür. Normalde ara sıra görülür (cihaz dolaşırken). Ama bir
istemciye **kısa sürede çok sayıda** deauth gelmesi kötü niyetli olabilir: amaç, cihazı koparıp sahte bir noktaya
bağlanmaya itmek ya da el sıkışmayı yeniden tetiklemektir. Kablosuz saldırı tespit sistemi (WIDS) bunları kaydeder:
""", komut="grep deauth loglar/wids.log | head -12"),
    Adim("Yoğunluğu saymak", """
`awk` ile her istemci için toplam `adet` değerini hesapla; en yoğun hedef bellidir:
""", komut="awk '$4==\"deauth\" {split($6,a,\"=\"); split($7,b,\"=\"); t[a[2]]+=b[2]} END {for (k in t) print t[k], k}' loglar/wids.log | sort -rn",
         sonra="""
**Hacker gözüyle:** Kablosuz saldırıların çoğu Cilt 2-6'da gördüklerinin havadaki hâlidir: brute-force (çevrimdışı kırma),
ortadaki adam (evil twin) ve trafik dinleme. Yeni kavram yok, yeni ortam var. Savunma da tanıdık: güçlü kimlik doğrulama,
doğrulanabilir sunucu kimliği (802.1X'te sertifika), korumalı yönetim kareleri (PMF) ve **izleme**.
"""),
]

GOREVLER = [
    Gorev("El sıkışma yakalanıp **çevrimdışı** tahmin edilirken, WPA2 parolasının **uzun ve rastgele** olması neden bu kadar kritiktir?",
          Secmeli([
              ("Çevrimdışı tahminde hız sınırı yoktur; yalnızca uzun ve rastgele parola dayanır",
               "Doğru. Sunucu tarafında kilitleme olmadığı için saldırgan kendi donanımının hızıyla dener."),
              ("Çünkü erişim noktası yanlış parola denemelerini sayıp birkaç denemeden sonra ağı kilitler",
               "Yanlış. Çevrimdışı tahminde erişim noktasıyla hiç konuşulmaz; kilitleme devreye girmez."),
              ("Çünkü kısa parolalar sinyal gücünü düşürür ve bağlantıyı kararsız ve yavaş hâle getirir",
               "Yanlış. Parola uzunluğunun sinyal gücüyle ilgisi yoktur."),
              ("Çünkü uzun parolalar, el sıkışmanın havadan dinlenerek yakalanmasını tamamen engeller",
               "Yanlış. El sıkışma parolaya bakmaksızın havada görülür; uzun parola yalnızca tahmini zorlaştırır."),
          ], dogru=0),
          ("Tahmin işlemi nerede yapılıyor: erişim noktasında mı, saldırganın bilgisayarında mı?",
           "Hız sınırı ya da kilitleme olmadığında deneme hızını ne belirler?",
           "Doğru şık, çevrimdışı olmanın hız sınırını kaldırdığını söyleyen şık."),
          puan=25, baslik="Neden uzun parola"),
    Gorev("`<<kurum>>` adını yayınlayan ama **BT envanterinde olmayan sahte erişim noktasının BSSID'sini** yaz.",
          Metin("sahte", bicim="BSSID (AA:BB:CC:DD:EE:FF)"),
          ("Aynı ağ adının BSSID'leri envanterdekilerle uyuşmalı; uyuşmayanı ara.",
           "Kayıtlardaki benzersiz BSSID'leri çıkar: `awk -F', ' '$14==\"<<kurum>>\" {print $1}' tarama/*.csv | sort -u`; envanterle karşılaştır.",
           "`... | grep -v -i -F -f <(awk '{print $2}' envanter/yetkili_apler.txt)` envanterde olmayan adresi verir."),
          puan=40, baslik="Sahte erişim noktası"),
    Gorev("Sahte erişim noktası hangi **kanalda** yayın yapıyor?",
          Sayi("kanal", sik_hatalar=_kanal_hata),
          ("Kayıttaki 4. sütun kanaldır.",
           "Sahte AP'nin BSSID'sini içeren satırı bul: `grep <BSSID> tarama/*.csv`.",
           "`awk -F', ' '$1==\"<BSSID>\" {print $4}' tarama/*.csv | sort -u`"),
          puan=25, baslik="Sahte AP kanalı"),
    Gorev("Sahte erişim noktası **kaç tarama kaydında** görüldü?",
          Sayi("gorulme"),
          ("Her dosya ayrı bir tarama. BSSID'yi hangi dosyalarda bulabiliyorsun?",
           "`grep -l <BSSID> tarama/*.csv` eşleşen dosyaların adlarını listeler.",
           "`grep -l <BSSID> tarama/*.csv | wc -l`"),
          puan=25, baslik="Kaç taramada"),
    Gorev("Gerçek kurum ağı **802.1X (`MGT`)** kullanır. Sahte erişim noktası ise ya **şifresizdir (`OPN`)** ya da **ortak parolalıdır "
          "(`PSK`)**. Hangisi?",
          Metin("ftur", bicim="OPN ya da PSK"),
          ("Privacy (6.) ve Authentication (8.) sütunlarına bak.",
           "`grep <BSSID> tarama/*.csv`: Privacy `OPN` ise şifresiz, değilse 8. sütundaki yönteme bak.",
           "`awk -F', ' '$1==\"<BSSID>\" {print $6, $8}' tarama/*.csv | sort -u`"),
          puan=25, baslik="Sahte AP şifrelemesi"),
    Gorev("`loglar/wids.log` içinde **en çok deauth kare alan istemcinin MAC adresini** yaz (kare sayısı `adet` toplamı).",
          Metin("hedef", bicim="MAC adresi", sik_hatalar=_istemci_hata),
          ("Her istemci için `adet` değerlerini topla; en büyüğü bul.",
           "`awk` ile `split($7,b,\"=\")` yaparak `adet` değerini ayır, istemci başına topla.",
           "`awk '$4==\"deauth\" {split($6,a,\"=\"); split($7,b,\"=\"); t[a[2]]+=b[2]} END {for (k in t) print t[k], k}' loglar/wids.log | sort -rn | head -1`"),
          puan=40, baslik="En çok koparılan istemci"),
    Gorev("`loglar/wids.log` içindeki **toplam deauth kare sayısı** (tüm `deauth` satırlarındaki `adet` toplamı) kaçtır?",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Her satırdaki `adet=` değerini topla; satır sayısını değil.",
           "`awk` ile 7. sütunu `=` işaretinden böl.",
           "`awk '$4==\"deauth\" {split($7,b,\"=\"); t+=b[2]} END {print t}' loglar/wids.log`"),
          puan=30, baslik="Toplam deauth"),
    Gorev("Deauth karelerinin istemcileri koparmak için kolayca sahtelenmesini zorlaştıran **savunma önlemi** hangisidir?",
          Secmeli([
              ("Korumalı yönetim kareleri (PMF, 802.11w): yönetim kareleri doğrulanır",
               "Doğru. PMF açıkken sahte deauth kareleri istemci tarafından reddedilir."),
              ("Erişim noktasının sinyal gücünü artırarak sahte karelerin menzile girmesini engellemek",
               "Yanlış. Güçlü sinyal sahte kareleri engellemez; hatta menzili genişletir."),
              ("Ağ adını (SSID) gizleyip yayından kaldırmak, böylece saldırganın ağı bulmasını engellemek",
               "Yanlış. Gizli SSID güvenlik sağlamaz, cihazlar yine ağ adını yayınlar (probe isteği ile)."),
              ("Kanal numarasını her gün değiştirerek saldırganın karelerini yanlış kanala düşürmek",
               "Yanlış. Kanal değişikliği yönetim karelerinin doğrulanmasıyla ilgili değildir."),
          ], dogru=0),
          ("Sorun, yönetim karelerinin kimliğinin doğrulanmamasında. Bunu çözen standart ne?",
           "802.11w olarak da bilinen PMF'i hatırla; WPA3'te zorunludur.",
           "Doğru şık, yönetim karelerini koruyan özelliği anlatan şık."),
          puan=30, baslik="Deauth'a karşı PMF"),
]

SEVIYE = Seviye(
    kimlik="c15b02",
    cilt=15,
    bolum=2,
    baslik="Kablosuz Saldırılar ve Tespit",
    brifing="""
Deniz'in sesi telaşlı: "**<<musteri>>**'de personel Wi-Fi'ı gün içinde defalarca düştü. Bazı çalışanlar **<<kurum>>** adlı ağa
bağlandıklarını ama ağın başka türlü davrandığını söylüyor. <<hikaye>>"

Selin: "Elimizde BT'nin yetkili erişim noktası listesi, üç farklı konumdan alınmış tarama kaydı ve kablosuz saldırı tespit
sisteminin (WIDS) logu var. Saldırıyı **yeniden üretmiyoruz**; kayıtları okuyup ne olduğunu belirleyeceğiz." Mert ekliyor:
"Ağ adı kopyalanır, donanım adresi ve kanal kopyalanamaz. Envanterle karşılaştır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Evil twin, kullanıcının "bu ağın adı doğru" sezgisine oynar; deauth ise cihazı gerçek ağdan koparıp ona yaklaştırmaya yarar.
Saldırgan açısından bu ikili, ortadaki adamı havada kurmanın yoludur. Savunma tarafında ders: yetkili erişim noktası envanteri
tut, tarama kayıtlarını bu envanterle karşılaştır, yönetim karelerini koru (PMF/WPA3), kurumsal ağda sunucu sertifikasını
doğrulayan 802.1X kullan ve WIDS gibi bir izleme katmanı bulundur.
""",
    gercek_hayat="""
- **Sahte erişim noktaları:** Kamuya açık Wi-Fi'larda, aynı adı yayınlayan sahte noktalar iyi bilinen bir saldırı yöntemidir;
  kurumlarda ise yetkisiz erişim noktası taraması (rogue AP detection) standart bir kablosuz denetim maddesidir.
- **Tespit:** Kablosuz saldırı tespit sistemleri (WIDS/WIPS) envanterde olmayan BSSID'leri ve olağandışı deauth yoğunluğunu
  alarm olarak üretir. **Önleme:** WPA3 ve PMF, 802.1X'te sunucu sertifikasının istemcide doğrulanması, kullanıcılara bilinmeyen
  açık ağlara otomatik bağlanmamayı öğreten farkındalık.
- **Parola kalitesi:** WPA2'de yakalanan el sıkışmanın çevrimdışı tahmini, kısa ve sözlükte geçen parolalara karşı etkilidir;
  bu yüzden kurumsal ağlar paylaşılan parola yerine kişiye özel kimlik kullanır.
""",
    sure_hedef_dk=30,
)
