"""Cilt 22 · Bölüm 6 — Kuantum Sonrası Kriptografi Farkındalığı (hafif).

Beceri: kurumun TLS/sertifika envanterini okuyup kuantum bilgisayara karşı kırılgan algoritmaları (RSA, ECDSA,
Ed25519) bulmak, bunları veri sınıflandırmasıyla (verinin kaç yıl gizli kalması gerektiği) birleştirip "şimdi topla,
sonra çöz" (harvest now, decrypt later) riskine göre geçiş önceliği çıkarmak. Savunmacı/analiz odaklıdır; kuantum
bilgisayara saldırı yapılmaz, yalnızca dosya okunur.

Vakalar: üç kurgusal kurum (Ferah Bank, Medora Sağlık, Yeşiltepe Belediyesi). Tüm servisler kurgusaldır.
"""
from __future__ import annotations

import random
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

KIRILGAN = ("RSA", "ECDSA", "Ed25519")
SERT_BASLIK = "servis,algoritma,anahtar_bits,son_kullanma"
SINIF_BASLIK = "servis,veri_turu,gizlilik_yil"

# Her vaka: uzun ömürlü/çok hassas veri taşıyan servisler ve kısa ömürlü/düşük hassasiyetli servisler
VAKALAR = [
    {"kod": "ferahbank", "sektor": "banka",
     "uzun": [("kredi-arsiv-api", "kredi_sozlesme_arsivi"), ("musteri-kimlik-kasa", "kimlik_ve_imza_kayitlari"),
              ("vasiyet-mevduat-api", "uzun_vadeli_mevduat_kayitlari"), ("sube-vpn-gecidi", "sube_ici_hesap_trafigi"),
              ("havale-mutabakat", "bankalar_arasi_mutabakat"), ("hazine-raporlama", "hazine_stratejisi_raporlari")],
     "kisa": [("kampanya-sitesi", "kampanya_afisleri"), ("doviz-kuru-api", "anlik_kur_bilgisi"),
              ("sube-bul-api", "sube_adresleri"), ("sss-portali", "sik_sorulan_sorular"),
              ("atm-durum-izleme", "atm_calisma_durumu"), ("blog-sitesi", "herkese_acik_yazilar"),
              ("kredi-hesaplama-demo", "ornek_faiz_hesabi")]},
    {"kod": "medora", "sektor": "hastane",
     "uzun": [("hasta-dosya-api", "tani_ve_tedavi_gecmisi"), ("genetik-test-portali", "genetik_test_sonuclari"),
              ("goruntuleme-arsivi", "radyoloji_goruntuleri"), ("sigorta-entegrasyon", "sigorta_ve_kimlik_bilgileri"),
              ("klinik-arastirma-vpn", "arastirma_katilimci_verisi"), ("doktor-kayit-kasa", "doktor_lisans_kayitlari")],
     "kisa": [("randevu-hatirlatma", "yarinki_randevu_saati"), ("otopark-doluluk", "otopark_bilgisi"),
              ("yemekhane-menu", "gunluk_menu"), ("duyuru-sitesi", "genel_duyurular"),
              ("ziyaret-saatleri", "ziyaret_saat_bilgisi"), ("bekleme-ekrani", "siramatik_numaralari"),
              ("kafeterya-siparis", "kafeterya_siparisleri")]},
    {"kod": "yesiltepe", "sektor": "belediye",
     "uzun": [("tapu-imar-arsivi", "tapu_ve_imar_dosyalari"), ("nufus-eslestirme", "vatandas_kimlik_eslestirme"),
              ("emlak-vergi-api", "emlak_vergi_kayitlari"), ("meclis-gizli-oturum", "gizli_meclis_tutanaklari"),
              ("altyapi-sozlesme-kasa", "uzun_vadeli_ihale_sozlesmeleri"), ("zabita-vpn", "denetim_ve_ceza_dosyalari")],
     "kisa": [("duyuru-portali", "genel_duyurular"), ("etkinlik-takvimi", "etkinlik_listesi"),
              ("park-bahce-harita", "park_konumlari"), ("hava-kalitesi-panosu", "anlik_olcumler"),
              ("ulasim-saatleri", "otobus_saatleri"), ("kutuphane-katalog", "kitap_katalogu"),
              ("anket-sitesi", "kamuya_acik_anketler")]},
]


def _veri(rng: random.Random, v: dict) -> dict:
    """Tüm lab verisini ve cevap hesaplarını üretir; uret ve yaz aynı rng akışını kullanır."""
    uzun = rng.sample(v["uzun"], len(v["uzun"]))
    kisa = rng.sample(v["kisa"], len(v["kisa"]))
    n_orta = rng.randint(2, 3)
    n_kisa_k = rng.randint(2, 4)

    def kirilgan_alg():
        a = rng.choice(["RSA", "RSA", "ECDSA", "Ed25519"])
        if a == "RSA":
            return a, rng.choice([2048, 2048, 3072, 4096])
        return (a, rng.choice([256, 384])) if a == "ECDSA" else (a, 256)

    satirlar = []   # (servis, veri_turu, algoritma, bits, gizlilik)
    hedef = uzun.pop()
    a, b = kirilgan_alg()
    satirlar.append((hedef[0], hedef[1], a, b, rng.choice([30, 40])))
    for s_ in [uzun.pop() for _ in range(n_orta)]:
        a, b = kirilgan_alg()
        satirlar.append((s_[0], s_[1], a, b, rng.choice([10, 15, 20, 25])))
    tuzak = uzun.pop()                          # kuantum-güvenli ama çok uzun gizlilik: öncelik DEĞİL
    satirlar.append((tuzak[0], tuzak[1], "ML-DSA-65", "yok", 50))
    for s_ in kisa[:n_kisa_k]:
        a, b = kirilgan_alg()
        satirlar.append((s_[0], s_[1], a, b, rng.choice([1, 2, 3, 5])))
    for s_ in kisa[n_kisa_k:n_kisa_k + 2]:
        satirlar.append((s_[0], s_[1], "ML-DSA-65", "yok", rng.choice([1, 2])))
    rng.shuffle(satirlar)
    sert = []
    for s_ in satirlar:
        t = f"{rng.choice([2026, 2027, 2027, 2028])}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
        sert.append([s_[0], s_[2], str(s_[3]), t])
    sinif = [[s_[0], s_[1], str(s_[4])] for s_ in satirlar]
    kir = [s_ for s_ in satirlar if s_[2] in KIRILGAN]
    return {
        "sert": sert, "sinif": sinif, "hedef": hedef[0], "tuzak": tuzak[0],
        "kirilgan": len(kir), "oncelik": sum(1 for s_ in kir if s_[4] >= 10),
        "sadece_rsa": sum(1 for s_ in kir if s_[2] == "RSA"),
        "kisa_kirilgan": [s_[0] for s_ in satirlar if s_[2] in KIRILGAN and s_[4] < 10],
    }


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alt = rng.randint(1, 10**9)
    d = _veri(random.Random(alt), v)
    return {
        "vaka": f"{m['ad']} — kuantum sonrası geçiş envanteri ({m['sektor']})",
        "v": v, "_alt": alt,
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "n": len(d["sert"])},
        "cevaplar": {"hedef": d["hedef"], "kirilgan": d["kirilgan"], "oncelik": d["oncelik"]},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = musteri(v["kod"])
    d = _veri(random.Random(s["_alt"]), v)
    u.yaz(lab / "sertifikalar.csv", SERT_BASLIK + "\n" + "\n".join(",".join(x) for x in d["sert"]) + "\n")
    u.yaz(lab / "veri_siniflama.csv", SINIF_BASLIK + "\n" + "\n".join(",".join(x) for x in d["sinif"]) + "\n")
    u.yaz(lab / "pqc_notlari.txt",
          "Kuantum sonrası (PQC) kısa notlar — kurgusal iç belge\n\n"
          "Tehdit      : Yeterince büyük bir kuantum bilgisayar, Shor algoritmasıyla RSA, ECDSA ve Ed25519 gibi\n"
          "              açık anahtarlı sistemleri kırabilir. Anahtarı büyütmek bunu çözmez.\n"
          "Kısa vadeli : Saldırgan şifreli trafiği BUGÜN kaydedip saklayabilir; kuantum bilgisayar gelince çözer.\n"
          "              (harvest now, decrypt later = şimdi topla, sonra çöz)\n"
          "Standartlar : NIST, Ağustos 2024'te FIPS 203 (ML-KEM, anahtar değişimi) ve FIPS 204 (ML-DSA, dijital\n"
          "              imza) ile FIPS 205 (SLH-DSA, imza) standartlarını yayımladı.\n"
          "Plan        : Önce verisi UZUN yıllar gizli kalması gereken ve kırılgan algoritma kullanan servisler.\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} ({m['sektor']}) — TLS/sertifika envanteri (kurgusal veri)\n\n"
          "sertifikalar.csv    : servis, algoritma, anahtar_bits, son_kullanma\n"
          "veri_siniflama.csv  : servis, veri_turu, gizlilik_yil (verinin kaç yıl gizli kalması gerekir)\n"
          "pqc_notlari.txt     : kısa kuantum sonrası notları\n")


# ---------------------------------------------------------------- sık hatalar

def _d(b):
    return _veri(random.Random(b.senaryo["_alt"]), b.senaryo["v"])


def _hedef_hata(g, beklenen, b):
    d = _d(b)
    if g == d["tuzak"]:
        return ("Bu servis çok uzun süre gizli kalmalı ama algoritması kuantum-güvenli (ML-DSA). Hem kırılgan "
                "algoritma **hem** uzun gizlilik gerekir.")
    if g in d["kisa_kirilgan"]:
        return "Algoritması kırılgan ama verisi kısa süre gizli kalıyor. En uzun gizlilik süresine bak."
    return None


def _kirilgan_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    d = _d(b)
    if n == beklenen + 1:
        return "Bir fazla: başlık satırını ya da kuantum-güvenli (ML-DSA) bir servisi saymış olabilirsin."
    if n == d["sadece_rsa"]:
        return "Sadece RSA'yı saymışsın. ECDSA ve Ed25519 de Shor algoritmasına kırılgan."
    return None


def _oncelik_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    d = _d(b)
    if n == d["kirilgan"]:
        return "Bu, tüm kırılgan servislerin sayısı. Bir de gizlilik süresi **10 yıl ve üstü** koşulunu ekle."
    if n == beklenen + 1:
        return "Bir fazla: kuantum-güvenli (ML-DSA) ama uzun gizlilikli servisi de saymış olabilirsin."
    return None


def coz(lab: Path, s: dict) -> dict:
    alg = "($2==\"RSA\"||$2==\"ECDSA\"||$2==\"Ed25519\")"
    birlestir = ("awk -F, 'NR==FNR{if(NR>1)g[$1]=$3; next} FNR>1 && " + alg + "{print g[$1], $1}' "
                 "veri_siniflama.csv sertifikalar.csv")
    hedef = sh(birlestir + " | sort -rn | head -1 | cut -d' ' -f2", lab)
    kir = sh("awk -F, 'NR>1 && " + alg + "' sertifikalar.csv | wc -l", lab)
    onc = sh(birlestir + " | awk '$1>=10' | wc -l", lab)
    cozum = {1: hedef, 2: kir, 3: onc, 4: "", 5: "", 6: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Kuantum tehdidi nedir?", """
Bugünkü internet güvenliğinin büyük kısmı iki "zor matematik problemine" dayanır: büyük sayıları çarpanlarına
ayırmak (**RSA**) ve eliptik eğri problemi (**ECDSA**, **Ed25519**). Klasik bilgisayarlar bunları çözemez. Ama
yeterince büyük bir **kuantum bilgisayar**, **Shor algoritması** (1994) ile bu problemleri hızla çözebilir.

Selin: "Bugün öyle bir bilgisayar yok. Ama tehdit yarın değil, **bugünden** başlıyor; nedenini birazdan göreceksin."
Önce kurumun notlarına bak:
""", komut="cat pqc_notlari.txt", sonra="""
**Önemli:** Anahtarı büyütmek (RSA-2048 yerine RSA-4096) Shor algoritmasını durdurmaz; sadece klasik saldırıyı
zorlaştırır. Çare, **yeni tür algoritmalara** (kuantum sonrası, PQC) geçmektir.
"""),
    Adim("Şimdi topla, sonra çöz", """
**Harvest now, decrypt later (şimdi topla, sonra çöz):** Saldırgan şifreli trafiği ya da çalınmış şifreli yedeği
bugün kaydeder; çözemez ama saklar. Yıllar sonra kuantum bilgisayar gelince hepsini açar.

Bu yüzden önemli olan **verinin kaç yıl gizli kalması gerektiğidir**. Bir kampanya afişi yarın herkese açık olabilir;
bir genetik test sonucu ya da tapu arşivi 30 yıl sır kalmalı. `veri_siniflama.csv` bunu söylüyor:
""", komut="head -6 veri_siniflama.csv", sonra="""
Basit bir kural: verinin gizli kalması gereken süre **uzunsa** (örneğin 10 yıl ve üstü) ve servis kırılgan bir
algoritma kullanıyorsa, geçiş acildir.
"""),
    Adim("Sertifika envanteri", """
`sertifikalar.csv`, hangi serviste hangi algoritmanın kullanıldığını gösterir. Önce ilk satırlara bak:
""", komut="head -6 sertifikalar.csv"),
    Adim("Kırılgan algoritmalar", """
`awk` ile algoritma sütununu (2. sütun) alıp `sort | uniq -c` ile kaç serviste hangi algoritma var diye say:
""", komut="awk -F, 'NR>1{print $2}' sertifikalar.csv | sort | uniq -c | sort -rn", sonra="""
`RSA`, `ECDSA` ve `Ed25519` Shor algoritmasına kırılgandır. `ML-DSA-65` ise NIST'in kuantum sonrası imza
standardıdır, yani kırılgan değildir.
"""),
    Adim("Öncelik: kırılgan + uzun gizlilik", """
İki dosyayı servis adından birleştirmek gerekiyor: `awk` önce `veri_siniflama.csv`'yi okuyup bir tabloya
(`g[servis]=yıl`) koyar, sonra `sertifikalar.csv`'deki kırılgan servislerin yanına gizlilik yılını yazar. `sort -rn`
en uzun gizliliği üste alır:
""", komut="awk -F, 'NR==FNR{if(NR>1)g[$1]=$3; next} FNR>1 && ($2==\"RSA\"||$2==\"ECDSA\"||$2==\"Ed25519\"){print g[$1], $1}' "
              "veri_siniflama.csv sertifikalar.csv | sort -rn | head -5", sonra="""
Listenin başı, "şimdi topla, sonra çöz" saldırısından en çok zarar görecek servislerdir: geçişe oradan başlanır.
**Hacker gözüyle:** Saldırgan açısından en değerli trafik, yıllarca değerini koruyan trafiktir.
"""),
    Adim("NIST PQC geçişi", """
NIST, **Ağustos 2024'te** ilk kuantum sonrası standartları yayımladı: **ML-KEM** (anahtar değişimi, FIPS 203),
**ML-DSA** (dijital imza, FIPS 204) ve **SLH-DSA** (yedek imza, FIPS 205). Geçiş genellikle üç adımda yürür:

1. **Envanter:** hangi servis hangi algoritmayı kullanıyor (az önce yaptığın iş).
2. **Önceliklendirme:** kırılgan algoritma + uzun gizlilik.
3. **Hibrit geçiş:** klasik ve PQC algoritmasını birlikte kullanıp kademeli olarak PQC'ye geçmek.
""", calistir=False),
]

GOREVLER = [
    Gorev("`sertifikalar.csv` ve `veri_siniflama.csv`'yi birleştir: **kuantuma kırılgan** algoritma (RSA, ECDSA, "
          "Ed25519) kullanan servisler arasında verisi **en uzun yıl gizli kalması gereken** servis hangisi? "
          "Servis adı?",
          Metin("hedef", sik_hatalar=_hedef_hata, bicim="servis adı (örn. xxx-api)"),
          ("İki dosyada ortak alan servis adı. Kırılgan algoritma ve gizlilik yılını birlikte düşün.",
           "Adım 5'teki `awk` birleştirmesini kullan; `sort -rn` ile en yüksek gizlilik yılını üste al.",
           "`awk -F, 'NR==FNR{...}' veri_siniflama.csv sertifikalar.csv | sort -rn | head -1`; satırdaki ikinci alan servis adıdır."),
          puan=40, baslik="En riskli servis"),
    Gorev("`sertifikalar.csv`'de **kaç servis** kuantum bilgisayara karşı kırılgan bir algoritma (RSA, ECDSA veya "
          "Ed25519) kullanıyor?",
          Sayi("kirilgan", sik_hatalar=_kirilgan_hata),
          ("Algoritma 2. sütunda. Kırılgan üç algoritma var; başlık satırı sayılmaz.",
           "`awk -F, 'NR>1 && ($2==\"RSA\"||...)' sertifikalar.csv` ile süz, sonra `wc -l` ile say.",
           "`awk -F, 'NR>1 && ($2==\"RSA\"||$2==\"ECDSA\"||$2==\"Ed25519\")' sertifikalar.csv | wc -l`"),
          puan=30, baslik="Kırılgan servis sayısı"),
    Gorev("Geçişte **öncelikli** adaylar: kırılgan algoritma kullanan **ve** verisi **10 yıl ya da daha uzun** gizli "
          "kalması gereken servisler. Kaç tane?",
          Sayi("oncelik", sik_hatalar=_oncelik_hata),
          ("Önce kırılgan olanları süz, sonra her birinin gizlilik yılına bak: iki koşul birlikte.",
           "Birleştirme çıktısında (`yıl servis`) ilk sütun 10 ve üstü olanları `awk '$1>=10'` ile süz.",
           "`awk -F, 'NR==FNR{...}' veri_siniflama.csv sertifikalar.csv | awk '$1>=10' | wc -l`"),
          puan=35, baslik="Öncelikli aday sayısı"),
    Gorev("Bir sertifika **RSA-4096** kullanıyor. Kuantum bilgisayar tehdidine karşı hakkında hangisi doğrudur?",
          Secmeli([
              ("Güvenli değil: anahtarı büyütmek Shor algoritmasını durdurmaz, PQC gerekir",
               "Doğru. Shor, RSA'yı anahtar boyundan bağımsız olarak polinom sürede çözer; büyük anahtar sadece klasik saldırıyı zorlaştırır."),
              ("Güvenli: 4096 bit, kuantum bilgisayarın kırabileceği sınırın çok üstündedir",
               "Yanlış. Kuantum saldırısı, bit sayısını artırarak zorlaştırılamaz; algoritmanın kendisi kırılgandır."),
              ("Güvenli: RSA, eliptik eğrilerden farklı olduğu için Shor algoritması onu etkilemez",
               "Yanlış. Shor hem büyük sayı çarpanlarına ayırmayı (RSA) hem eliptik eğri problemini (ECDSA) çözer."),
              ("Güvenli değil ama yalnızca sertifika süresi 1 yıldan uzunsa",
               "Yanlış. Sertifikanın süresi algoritmanın kırılganlığını değiştirmez; asıl mesele korunan verinin ömrüdür."),
          ]),
          ("Shor algoritmasının neyi çözdüğünü hatırla.",
           "Bit sayısını artırmak klasik saldırılara karşı işe yarar.",
           "Çözüm, algoritmanın kendisini değiştirmek: ML-KEM / ML-DSA."),
          puan=25, baslik="RSA-4096 güvenli mi"),
    Gorev("\"Şimdi topla, sonra çöz\" saldırısı neden **bugün** bir risk, kuantum bilgisayar henüz yokken bile?",
          Secmeli([
              ("Saldırgan şifreli veriyi bugün saklayıp ileride kuantum bilgisayarla açabilir",
               "Doğru. Gizliliği uzun süre korunması gereken veri için tehdit, kuantum bilgisayar gelmeden önce başlar."),
              ("Kuantum bilgisayarlar kurumların ağında çalışıyor ve trafiği şu an çözüyor",
               "Yanlış. Bu kadar büyük bir kuantum bilgisayar henüz yok; risk, kaydedilen verinin ileride çözülmesi."),
              ("Şifreli veri zamanla kendiliğinden bozulur, bu yüzden hemen taşımak gerekir",
               "Yanlış. Şifreli veri bozulmaz; saldırgan onu yıllarca saklayabilir."),
              ("Saldırgan sadece sertifika süresi dolduğunda trafiği çözebilir, o yüzden süreler uzatılmalı",
               "Yanlış. Sertifika süresi kaydedilen trafiğin çözülebilirliğini etkilemez."),
          ]),
          ("Saldırganın bugün ne yapıp yarın ne yapacağını düşün.",
           "Kaydetmek için kuantum bilgisayara gerek yok.",
           "Verinin ömrü, kuantum bilgisayarın geleceği tarihten uzunsa risk bugünden başlar."),
          puan=25, baslik="Harvest now, decrypt later"),
    Gorev("Sınırlı bütçeyle geçişe başlayacaksın. **Önce hangi servisi** kuantum sonrası (PQC) algoritmaya taşımalısın?",
          Secmeli([
              ("Kırılgan algoritma kullanan ve verisi yıllarca gizli kalması gereken servisi",
               "Doğru. Hem kırılgan hem uzun ömürlü veri: saldırganın bugün kaydedeceği trafik yıllar sonra bile değerli olur."),
              ("En çok kullanıcı ya da trafik alan servisi, gizlilik süresi ne olursa olsun",
               "Yanlış. Trafik miktarı değil, verinin gizlilik ömrü belirleyicidir; kampanya sitesi çok trafik alsa da sır içermez."),
              ("Kısa ömürlü, herkese açık veri taşıyan servisi, çünkü en kolay taşınan o",
               "Yanlış. Kolay olması öncelik değildir; herkese açık veri çözülse de kayıp yoktur."),
              ("Zaten ML-DSA kullanan servisi, yeni standart olduğu için yeniden doğrulamak",
               "Yanlış. Zaten kuantum-güvenli olanı değil, kırılgan olanı taşımak gerekir."),
          ]),
          ("İki koşulu birlikte düşün: algoritma ve verinin ömrü.",
           "Kırılgan olmayan servis taşınmaz; kırılgan ama kısa ömürlü veri daha sonra gelir.",
           "Önce kırılgan + uzun gizlilik, sonra kırılgan + kısa gizlilik."),
          puan=25, baslik="Doğru öncelik"),
]

SEVIYE = Seviye(
    kimlik="c22b06",
    cilt=22,
    bolum=6,
    baslik="Kuantum Sonrası Kriptografi Farkındalığı",
    brifing="""
**<<musteri>>** (<<sektor>>) için bir "kuantum hazırlığı" çalışması istiyor: <<kisi>> kurumun <<n>> servislik
TLS/sertifika envanterini ve veri sınıflandırma tablosunu laboratuvara koydu.

Selin: "Kuantum bilgisayar yarın gelmeyecek ama **şimdi topla, sonra çöz** saldırısı bugün başlayabilir. Bana şunu
söyle: hangi servisler kırılgan algoritma kullanıyor, hangilerinin verisi yıllarca sır kalmalı ve önce hangisini
taşımalıyız?"
Deniz: "Hepsini birden taşıyamayız. Öncelik şart."
Mert: "Bunun bir saldırı değil, bir **envanter ve planlama** işi olduğunu unutma. Önce neyin nerede olduğunu bil."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kuantum tehdidi bir bilgisayar arızası gibi bir gün aniden gelmez; **bugünden toplanan veriyle** başlar. Saldırgan
için yıllarca değerini koruyan şifreli veri, bugün saklanıp yarın açılacak bir hazinedir. Savunmacı için çare
paniğe kapılmak değil, sırayla ilerlemektir: önce **envanter**, sonra **kırılgan algoritma + uzun gizlilik**
kesişimine öncelik, ardından **hibrit** (klasik + PQC) geçiş ve nihayetinde NIST'in ML-KEM/ML-DSA standartlarına
geçiş. Anahtar boyunu büyütmek bu sorunu çözmez; algoritmanın kendisi değişmelidir.
""",
    gercek_hayat="""
- **NIST PQC standartları (Ağustos 2024):** NIST, 13 Ağustos 2024'te ilk üç kuantum sonrası standardı yayımladı:
  FIPS 203 (**ML-KEM**, anahtar değişimi), FIPS 204 (**ML-DSA**, imza) ve FIPS 205 (**SLH-DSA**, imza). Bu bölümdeki
  envanter çıkarma becerisi, bu standartlara geçişin ilk şartıdır: hangi servis neyi kullanıyor bilinmeden taşınamaz.
- **"Harvest now, decrypt later":** Güvenlik kurumları ve standart kuruluşları, uzun süre gizli kalması gereken
  verilerin (devlet sırları, sağlık ve genetik veriler, uzun vadeli sözleşmeler) bugünden kaydedilip ileride
  çözülebileceği riskine dikkat çekiyor. Önlem: uzun ömürlü veriyi taşıyan servisleri önce PQC ya da hibrit
  algoritmaya geçirmek; tespit tarafında ise hangi servislerin kırılgan algoritma kullandığını düzenli envanterle izlemek.
- **Hibrit geçiş uygulamaları:** Büyük tarayıcılar ve bulut sağlayıcıları, TLS bağlantılarında klasik anahtar
  değişimiyle PQC anahtar değişimini birlikte kullanan hibrit yöntemleri devreye almaya başladı. Böylece biri
  kırılsa bile diğeri korur.
""",
    sure_hedef_dk=25,
)
