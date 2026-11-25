"""Cilt 15 · Bölüm 1 — Kablosuz Temelleri ve Şifreleme.

Beceri: kurgusal bir tarama çıktısını (airodump benzeri CSV) okuyup ağları şifreleme türüne göre ayırmak,
Açık ve WEP gibi zayıf/kırık korumalı ağları bulmak, WPA2'nin neden "sağlam ama parolaya bağlı" olduğunu
ve 802.1X'in paylaşılan parolaya göre neden iyi olduğunu anlamak.

Vakalar: Atölye Kahve, Kuzgun Lojistik, Medora Sağlık, Ferah Bank. Tarama çıktısı kurgusaldır; kimsenin
gerçek ağı değildir. Bu seviyede yalnızca dosya okunur; hiçbir kablosuz araç çalıştırılmaz.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c15_kablosuz.ortak import (KOMSU_ADLARI, ap_satiri, macler, sec_doldur, sh,
                                              tarama_csv, vaka_sec)

ACIK_ADLAR = ["Bar_Acik_Ag", "Ucretsiz_Internet", "Misafir_Ag_Plaza"]


def uret(rng):
    v = vaka_sec(rng)
    gun = u.gun(rng)
    t0 = gun + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 50))
    adlar = rng.sample(KOMSU_ADLARI, 6)
    wpa3, wep1 = adlar[0], adlar[1]
    wep2 = adlar[2] if rng.random() < 0.5 else None
    wpa = adlar[3] if rng.random() < 0.5 else None
    acik_komsu = rng.choice(ACIK_ADLAR) if rng.random() < 0.5 else None
    aglar = [(v["kurum"], "WPA2-MGT"), (v["misafir"], "OPN"), (wpa3, "WPA3"), (wep1, "WEP")]
    if wep2:
        aglar.append((wep2, "WEP"))
    if wpa:
        aglar.append((wpa, "WPA"))
    if acik_komsu:
        aglar.append((acik_komsu, "OPN"))
    for a in adlar[4:]:
        aglar.append((a, "WPA2"))
    rng.shuffle(aglar)
    bssidler = macler(rng, len(aglar) + 3)
    satirlar = []
    for i, (essid, tur) in enumerate(aglar):
        satirlar.append(ap_satiri(bssidler[i], t0 - timedelta(minutes=rng.randint(5, 40)),
                                  t0 + timedelta(minutes=rng.randint(1, 10)),
                                  rng.choice([1, 6, 11, 3, 9]), tur, rng.randint(-85, -30), essid,
                                  hiz=rng.choice([54, 130, 195, 270]), beacon=rng.randint(40, 600)))
    istasyonlar = [(bssidler[len(aglar) + k], t0 - timedelta(minutes=10), t0, rng.randint(-80, -35),
                    rng.randint(3, 400), bssidler[rng.randrange(len(aglar))]) for k in range(3)]
    zayif = [e for e, t in aglar if t in ("OPN", "WEP")]
    opn = sum(1 for _, t in aglar if t == "OPN")
    wep = sum(1 for _, t in aglar if t == "WEP")
    return {
        "vaka": f"{v['ad']} — çevre kablosuz taraması ({v['sektor']})",
        "v": v, "csv": tarama_csv(satirlar, istasyonlar),
        "metin": {"musteri": v["ad"], "kurum": v["kurum"], "misafir": v["misafir"], "yer": v["yer"],
                  "hikaye": v["hikaye"]},
        "cevaplar": {"opn": opn, "wep_dummy": wep, "zayif": zayif, "wpa3": wpa3, "mgt": v["kurum"]},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} çevresinde alınmış KURGUSAL kablosuz tarama kaydı (airodump benzeri CSV).\n"
          "Selin'den not: bu kayıt metin dosyasıdır; sadece okuyacaksın. Kendi ağın dışındakilere dokunmuyoruz.\n")
    u.yaz(lab / "tarama" / "gece_tarama.csv", s["csv"])
    u.yaz(lab / "tarama" / "sutunlar.txt",
          "CSV sütunları (virgül + boşlukla ayrılmış):\n"
          " 1 BSSID (erişim noktasının MAC adresi)   4 kanal        6 Privacy (OPN/WEP/WPA/WPA2/WPA3)\n"
          " 7 Cipher (şifreleme: CCMP/TKIP/WEP)       8 Authentication (PSK=ortak parola, MGT=802.1X, SAE=WPA3)\n"
          " 9 Power (sinyal gücü, 0'a yakın = güçlü)  14 ESSID (ağ adı)\n")
    u.yaz(lab / "standartlar.txt",
          "Standart   Durum\n"
          "OPN        Şifresiz: menzildeki herkes her paketi okur\n"
          "WEP        Tamamen kırık, asla kullanılmamalı\n"
          "WPA        Eski (TKIP), terk edilmeli\n"
          "WPA2       Hâlâ yaygın; güçlü ve uzun parolayla makul\n"
          "WPA3       Modern, en güvenli; mümkünse tercih edilmeli\n")


def coz(lab: Path, s: dict) -> dict:
    f = "tarama/gece_tarama.csv"
    opn = sh(f"awk -F', ' '$6==\"OPN\"' {f} | wc -l", lab)
    zayif = sh(f"awk -F', ' '$6==\"OPN\" || $6==\"WEP\" {{print $14}}' {f} | tr '\\n' ' '", lab)
    wpa3 = sh(f"awk -F', ' '$8==\"SAE\" {{print $14}}' {f}", lab)
    mgt = sh(f"awk -F', ' '$8==\"MGT\" {{print $14}}' {f}", lab)
    return sec_doldur({2: opn, 3: zayif, 4: wpa3, 5: mgt}, GOREVLER, lab, s)


def _opn_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + b.senaryo["cevaplar"]["wep_dummy"]:
        return "WEP ağlarını da saymışsın. Soru yalnızca **şifresiz (OPN)** ağları soruyor."
    if n == beklenen + 1:
        return "Başlık satırını da saymış olabilirsin; `Privacy` sütunu tam olarak `OPN` olanlar sayılır."
    return None


ADIMLAR = [
    Adim("Havada her şey herkese yayılır", """
Kablolu ağda veri bir tele hapsolur; kablosuzda **havaya yayılır**. Menzildeki herkes paketleri yakalayabilir; tek koruma
şifrelemedir. Şifreleme zayıfsa ya da yoksa ağ pratikte açıktır. Bu yüzden kablosuz güvenliğin ilk sorusu "bu ağ hangi
şifrelemeyi kullanıyor?"dur.

Lab'da bir tarama kaydı var; önce sütunların anlamına bak:
""", komut="cat tarama/sutunlar.txt"),
    Adim("Şifreleme standartları", """
Kablosuz şifreleme standartlarının güvenlik sıralaması şöyle: WEP (kırık) < WPA < WPA2 < WPA3.
""", komut="cat standartlar.txt", sonra="""
WEP yıllar önce kırıldı; hâlâ WEP kullanan bir ağ pratikte açıktır. WPA2 matematiksel olarak sağlamdır ama zayıf parolaya
karşı korumasızdır. WPA3 bu zayıflıkların çoğunu giderir.
"""),
    Adim("Tarama kaydını okumak", """
Kayıt, bir CSV dosyası. Önce ilk birkaç satırı gör:
""", komut="head -6 tarama/gece_tarama.csv"),
    Adim("Ağ adı ve şifreleme yan yana", """
`awk -F', '` ayracı virgül+boşluk yapar. 14. sütun ağ adı (ESSID), 6. sütun Privacy:
""", komut="awk -F', ' 'NR>1 && NF>=15 {print $14, $6, $8}' tarama/gece_tarama.csv", sonra="""
Üçüncü sütun kimlik doğrulama yöntemidir: `PSK` hepsi aynı ortak parolayı kullanır, `MGT` her kullanıcının kendi kimliğiyle
girdiği 802.1X'tir, `SAE` WPA3'ün el sıkışmasıdır.
"""),
    Adim("Zayıf şifrelemeli ağları ayıklamak", """
Açık (`OPN`) ve WEP ağları süz:
""", komut="awk -F', ' '$6==\"OPN\" || $6==\"WEP\" {print $14, $6}' tarama/gece_tarama.csv", sonra="""
**Hacker gözüyle:** Kablosuz güvenliğin ironisi: standartlar yıllardır güçlü ama ağların çoğu **zayıf parolalar** ya da eski,
unutulmuş cihazlar yüzünden düşer. Savunma tarafında dersler: en güncel standardı seç, uzun ve rastgele bir parola kullan,
unutulmuş WEP/Açık ağları kapat; kurumsal ortamda paylaşılan parola yerine 802.1X kullan.
"""),
    Adim("Say ve sırala", """
Her şifreleme türünden kaç ağ var? Sütunu al, say:
""", komut="awk -F', ' 'NR>1 && NF>=15 {print $6}' tarama/gece_tarama.csv | sort | uniq -c | sort -rn"),
]

GOREVLER = [
    Gorev("Kablosuz ağlarda **tek savunma neden şifrelemedir**?",
          Secmeli([
              ("Çünkü sinyal havaya yayılır; paketleri yakalayan şifreyi çözemezse okuyamaz",
               "Doğru. Kablosuzda veriyi fiziksel olarak hapsetmek mümkün değildir; şifreleme tek bariyerdir."),
              ("Çünkü Wi-Fi donanımı kablolu karttan daha az güvenilirdir ve sık sık arızalanıp veri kaybeder",
               "Yanlış. Sorun donanımın kalitesi değil, sinyalin havaya yayılmasıdır."),
              ("Çünkü Wi-Fi şifreleri yalnızca bağlantı hızına sınır koymak ve bant genişliğini paylaştırmak için vardır",
               "Yanlış. Şifre, trafiği okunamaz kılmak ve kimlik doğrulamak içindir; hız ile ilgisi yok."),
              ("Çünkü güvenlik duvarları ve diğer ağ cihazları kablosuz trafiği hiçbir şekilde göremez",
               "Yanlış. Güvenlik duvarları ağ geçidinde çalışır; sorun, havadaki paketlerin zaten herkese ulaşmasıdır."),
          ], dogru=0),
          ("Kabloda veri bir tele hapsolur; peki kablosuzda?",
           "Sinyal havaya yayılırsa, paketlere kim ulaşabilir?",
           "Doğru şık, havada yayılan veriyi şifrelemenin zorunluluğunu anlatan şık."),
          puan=20, baslik="Neden şifreleme"),
    Gorev("`tarama/gece_tarama.csv` içinde kaç ağ **şifresiz (Privacy = OPN)**?",
          Sayi("opn", sik_hatalar=_opn_hata),
          ("Privacy sütunu 6. sütundur; değeri tam olarak `OPN` olanlar şifresizdir.",
           "`awk -F', ' '$6==\"OPN\"' tarama/gece_tarama.csv` bu satırları süzer.",
           "Çıktıyı `wc -l` ile say: `awk -F', ' '$6==\"OPN\"' tarama/gece_tarama.csv | wc -l`"),
          puan=25, baslik="Açık ağlar"),
    Gorev("**Açık (OPN) ya da WEP** korumalı olan ağların adlarını (ESSID) yaz (virgülle ayır).",
          Kume("zayif", bicim="ağ adları, virgülle ayrılmış"),
          ("İki türü birlikte ara: Privacy `OPN` ya da `WEP`.",
           "`awk -F', ' '$6==\"OPN\" || $6==\"WEP\"' tarama/gece_tarama.csv`: ağ adı 14. sütundur.",
           "`awk -F', ' '$6==\"OPN\" || $6==\"WEP\" {print $14}' tarama/gece_tarama.csv`"),
          puan=35, baslik="Zayıf şifrelemeli ağlar"),
    Gorev("Kayıtta **WPA3** (kimlik doğrulama `SAE`) kullanan ağın adı nedir?",
          Metin("wpa3", bicim="ağ adı"),
          ("WPA3'ün kimlik doğrulama yöntemi `SAE`'dir.",
           "`grep SAE tarama/gece_tarama.csv` yalnızca bu ağın satırını gösterir.",
           "`awk -F', ' '$8==\"SAE\" {print $14}' tarama/gece_tarama.csv`"),
          puan=25, baslik="WPA3 ağı"),
    Gorev("**<<musteri>>**'nin kurumsal ağı kullanıcı başına kimlik veren **802.1X (`MGT`)** ağıdır. Kayıtta `MGT` "
          "kullanan ağın adını yaz.",
          Metin("mgt", bicim="ağ adı"),
          ("802.1X kayıtlarda `MGT` olarak görünür.",
           "`grep MGT tarama/gece_tarama.csv`",
           "`awk -F', ' '$8==\"MGT\" {print $14}' tarama/gece_tarama.csv`"),
          puan=25, baslik="802.1X ağı"),
    Gorev("WPA2 matematiksel olarak sağlam kabul edilir. Peki WPA2 ağlarını **pratikte en çok ne düşürür**?",
          Secmeli([
              ("Zayıf, tahmin edilebilir parolalar: çevrimdışı denenebilir",
               "Doğru. Şifreleme sağlamdır; zayıf bir parola (12345678 gibi) çevrimdışı tahmin edilebilir."),
              ("AES (CCMP) şifrelemesinin matematiksel olarak kırılmış ve herkesçe çözülebilir olması",
               "Yanlış. WPA2'nin kullandığı AES (CCMP) pratikte kırılmış değildir."),
              ("Erişim noktasının kanal numarasının ve ağ adının saldırgan tarafından tahmin edilebilir olması",
               "Yanlış. Kanal numarası sır değildir ve güvenliğe katkısı yoktur."),
              ("Sinyal gücünün çok yüksek olması ve ağın uzak mesafelerden de görülebilmesi",
               "Yanlış. Güçlü sinyal güvenlik açığı değildir; paketlerin okunabilirliği şifrelemeye bağlıdır."),
          ], dogru=0),
          ("Standart sağlamsa, insanın seçtiği hangi şey zayıf kalabilir?",
           "Sözlükte geçen bir kelimeyle parola belirlenirse ne olur?",
           "Doğru şık, parolanın zayıflığını anlatan şık."),
          puan=25, baslik="WPA2'yi ne düşürür"),
    Gorev("Kurumsal bir ortamda, herkesin aynı Wi-Fi parolasını kullanması yerine **802.1X** tercih edilmesinin asıl nedeni nedir?",
          Secmeli([
              ("Her kullanıcı ayrı kimlikle girer; sızan kimlik tek başına iptal edilir ve izlenebilir",
               "Doğru. Paylaşılan parola sızınca bütün ağ düşer; kişisel kimlikte yalnızca o kullanıcı etkilenir ve iz sürülebilir."),
              ("Daha hızlıdır, çünkü sinyal gücünü ve bant genişliğini artırarak bağlantıyı genel olarak iyileştirir",
               "Yanlış. 802.1X bir kimlik doğrulama yöntemidir; sinyal gücüyle ilgisi yoktur."),
              ("Kullanıcıların parola hatırlamasına gerek kalmaz ve sistemde hiçbir kimlik bilgisi tutulmaz hâle gelir",
               "Yanlış. Kullanıcılar kimlik bilgisi kullanır; fark, bunların kişiye özel olmasıdır."),
              ("Yalnızca eski cihazları destekler, bu yüzden yeni saldırılara daha az maruz kalır",
               "Yanlış. 802.1X modern bir yöntemdir; eski olmak güvenlik sağlamaz."),
          ], dogru=0),
          ("Aynı parolayı 200 kişi bilirse, biri ayrıldığında ne olur?",
           "Kişiye özel kimlik, iptal ve iz sürmeyi nasıl kolaylaştırır?",
           "Doğru şık, kimliğin kişiye özel olmasını (iptal ve izlenebilirlik) anlatan şık."),
          puan=25, baslik="Neden 802.1X"),
]

SEVIYE = Seviye(
    kimlik="c15b01",
    cilt=15,
    bolum=1,
    baslik="Kablosuz Temelleri ve Şifreleme",
    brifing="""
**<<musteri>>**, **<<yer>>** için bir kablosuz değerlendirmesi istedi. <<hikaye>>

Selin tarama kaydını masana bırakıyor: "Çevrede ne kadar ağ yayın yapıyor, hangileri zayıf şifreli? **<<kurum>>** ve
**<<misafir>>** bizim müşterimizin ağları, gerisi komşular. Kendi ağın dışındakilere dokunmuyoruz; sadece kaydı okuyorsun."
Mert ekliyor: "Kablosuzda ilk hamle hep aynı: ağları şifreleme türüne göre ayır." Deniz: "Ben her ay bu sayımı yapıp
eski ağların kapanıp kapanmadığına bakıyorum."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kablosuzda binanın duvarı bir güvenlik sınırı değildir: otoparktaki biri aynı kaydı alabilir. Saldırgan açısından ilk iş,
çevredeki ağları şifreleme türüne göre ayırmaktır; Açık ve WEP ağlar "kolay hedef" listesinin başındadır. Savunma dersi:
envanterinde olmayan ağları ve eski şifrelemeleri düzenli tarama kaydında ara, WPA3'e (olmuyorsa güçlü parolalı WPA2'ye)
geç ve kurumsal ağlarda paylaşılan parola yerine kişiye özel kimlik (802.1X) kullan.
""",
    gercek_hayat="""
- **Eski şifrelemeler:** WEP yıllar önce kırıldı; buna rağmen sızma testi raporlarında hâlâ WEP ya da zayıf parolalı WPA2
  ağlarına rastlanır. Bu, bir ağın en zayıf halkasının çoğunlukla "unutulmuş" cihaz ya da kolay parola olduğunu gösterir.
- **Önleme:** WPA3 (ya da uzun, rastgele parolalı WPA2), kurumsal ağda 802.1X, eski ağların kapatılması, yetkisiz erişim
  noktalarına karşı düzenli kablosuz envanteri. **Tespit:** kablosuz saldırı tespit sistemi (WIDS) ya da düzenli tarama
  kayıtları; envanterde olmayan her ağ bir bulgudur.
- **Hukuki çerçeve:** Başkasının Wi-Fi ağına izinsiz bağlanmak ya da trafiğini dinlemek Türkiye'de suç oluşturabilir (bilişim sistemine girme: TCK 243; haberleşmenin gizliliğini ihlal: TCK 132);
  bu yüzden kablosuz denemeler yalnızca kendi ağında ya da yazılı izinle yapılır.
""",
    sure_hedef_dk=20,
)
