"""Cilt 23 · Bölüm 1 — e-Dönüşüm Ekosistemi.

Beceri: e-fatura, e-arşiv, e-irsaliye ve e-defter'in ne işe yaradığını ayırt etmek; mükellef, entegratör ve
GİB rollerini ve akışı eşlemek; belge kayıtlarında yoğunlaşma (tek entegratöre bağımlılık) riskini
görmek; belgelerin neden "yasal delil" olduğunu ve neden bütünlüğünün kritik olduğunu anlamak.
Mevzuatın ayrıntıları (tebliğ, eşik, tarih) kasıtlı olarak verilmez; kalıcı ilkeler anlatılır.

Vakalar: Kuzgun Lojistik (irsaliye ağırlıklı), Pazarix (e-arşiv ağırlıklı), Medora Sağlık (e-fatura
ağırlıklı). Tüm şirketler, numaralar ve belgeler kurgusaldır.
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, csv_yaz, sec_doldur, sh

ENTEGRATORLER = ["AkisNet", "BeyazKopru", "DikeyBulut", "EvrenBelge", "FiloEntegre"]

VAKALAR = [
    {"kod": "kuzgun", "agirlik": {"e-fatura": 25, "e-arsiv": 10, "e-irsaliye": 65}, "kisi": "Serdar Bey",
     "olay": "Kuzgun Lojistik'in depo ve nakliye operasyonu her gün yüzlerce sevk irsaliyesi ve navlun faturası "
             "üretiyor; belgelerin hepsi birkaç entegratörün üzerinden akıyor.",
     "senaryolar": {
         "a": "Kuzgun, e-fatura sistemine kayıtlı bir üretici firmaya navlun hizmeti sattı ve bunun faturasını kesecek.",
         "b": "Kuzgun'un ön büro hizmetinden yararlanan, e-fatura sistemine kayıtlı olmayan bir bireysel müşteriye "
              "yapılan kargo satışının faturası.",
         "c": "Depodan çıkan malın yolda taşınırken yanında bulunması gereken sevk belgesinin elektronik karşılığı.",
         "d": "Kuzgun'un yevmiye ve defter-i kebir kayıtlarının elektronik ortamda oluşturulup saklanması."}},
    {"kod": "pazarix", "agirlik": {"e-fatura": 15, "e-arsiv": 75, "e-irsaliye": 10}, "kisi": "Tuncay Bey",
     "olay": "Pazarix'in e-ticaret satışlarından doğan binlerce belge, çoğunlukla bireysel müşterilere kesiliyor "
             "ve bir entegratör üzerinden iletiliyor.",
     "senaryolar": {
         "a": "Pazarix, e-fatura sistemine kayıtlı bir tedarikçisinden toptan ürün aldı; tedarikçi faturayı kesecek.",
         "b": "Pazarix'in web sitesinden bir tüketicinin yaptığı bireysel alışverişin faturası.",
         "c": "Pazarix deposundan kargoya verilen toplu ürün sevkiyatının, yolda yanında taşınması gereken belgesi.",
         "d": "Pazarix'in yevmiye ve defter-i kebir kayıtlarının elektronik ortamda oluşturulup saklanması."}},
    {"kod": "medora", "agirlik": {"e-fatura": 70, "e-arsiv": 15, "e-irsaliye": 15}, "kisi": "Dr. Aslı Hanım",
     "olay": "Medora Sağlık'ın tıbbi sarf malzeme alımı ve hizmet faturaları, çok sayıda tedarikçi ve bir kaç "
             "entegratör üzerinden akıyor; belgelerde çalışan ve hasta bilgisi bulunabiliyor.",
     "senaryolar": {
         "a": "Medora, e-fatura sistemine kayıtlı bir tıbbi malzeme tedarikçisinden alım yaptı; tedarikçi faturayı kesecek.",
         "b": "Medora'nın poliklinik hizmetinden yararlanan ve e-fatura sistemine kayıtlı olmayan bir hastaya "
              "kesilen faturası.",
         "c": "Tedarikçi deposundan hastaneye getirilen tıbbi malzemenin yolda taşıma sırasında yanında bulunması "
              "gereken sevk belgesi.",
         "d": "Medora'nın yevmiye ve defter-i kebir kayıtlarının elektronik ortamda oluşturulup saklanması."}},
]

TURLER = {"a": "e-fatura (e-fatura sistemine kayıtlı mükellefler arası fatura)",
          "b": "e-arşiv fatura (e-fatura mükellefi olmayan alıcıya, örn. bireysel müşteriye)",
          "c": "e-irsaliye (mal taşımada sevk belgesi)", "d": "e-defter (yevmiye ve defter-i kebir)"}

EYLEMLER = [
    ("Faturayı düzenler ve elektronik olarak imzalar", "a"),
    ("Çok sayıda mükellef adına belgeleri iletir ve saklama/hizmet sağlar", "b"),
    ("Mevzuatı ve merkezi sistemi yönetir; sistemin otoritesidir", "c"),
    ("Belgeyi kesen işletmedir; belgenin içeriğinden vergisel olarak sorumludur", "a"),
    ("Birçok işletmenin belgesi tek bir sistemden geçtiği için ele geçirilirse en geniş etkiyi yaratabilir", "b"),
    ("Vergi uyumunu izlemek ve denetlemek için belgelere merkezi bakış sağlar", "c"),
]
TARAFLAR = {"a": "mükellef (belgeyi kesen işletme)", "b": "entegratör / özel entegratör",
            "c": "GİB (Gelir İdaresi Başkanlığı, merkezi otorite)"}


def veri_uret(rng: random.Random, v: dict) -> dict:
    gun = u.gun(rng)
    entegratorler = rng.sample(ENTEGRATORLER, 3)
    n_muk = rng.randint(16, 20)
    mukellefler = list(dict.fromkeys(f"M-{rng.randint(1000, 9999)}" for _ in range(n_muk * 2)))[:n_muk]
    # birinci entegratör en çok mükellefe sahip olsun (tekil en büyük)
    pay = [rng.randint(8, 10), rng.randint(4, 5), 0]
    pay[2] = n_muk - pay[0] - pay[1]
    atama, i = {}, 0
    for e, n in zip(entegratorler, pay):
        for _ in range(n):
            atama[mukellefler[i]] = e
            i += 1
    turler = list(v["agirlik"])
    agirliklar = [v["agirlik"][t] for t in turler]
    satirlar = []
    for k in range(rng.randint(220, 280)):
        m = rng.choice(mukellefler)
        t = rng.choices(turler, agirliklar)[0]
        tarih = gun - timedelta(days=rng.randint(0, 27))
        durum = rng.choices(["iletildi", "bekliyor", "hata"], [90, 6, 4])[0]
        satirlar.append(f"B{rng.randint(10**8, 10**9 - 1)},{t},{m},{atama[m]},{tarih:%Y-%m-%d},{durum}")
    rng.shuffle(satirlar)
    return {"satirlar": satirlar, "entegratorler": entegratorler, "atama": atama, "mukellefler": mukellefler}


def sayilar(d: dict, hedef: str) -> dict:
    """{en_cok: entegratör, en_cok_muk: n, arsiv: {entegratör: sayı}}"""
    muk = {}
    for m, e in d["atama"].items():
        muk.setdefault(e, set()).add(m)
    # sadece belge kesen mükellefler sayılır
    gorulen = {}
    arsiv = {}
    for s in d["satirlar"]:
        _, t, m, e, _, _ = s.split(",")
        gorulen.setdefault(e, set()).add(m)
        if t == "e-arsiv":
            arsiv[e] = arsiv.get(e, 0) + 1
    en = max(gorulen, key=lambda e: len(gorulen[e]))
    return {"en_cok": en, "en_cok_muk": len(gorulen[en]), "arsiv": arsiv.get(hedef, 0),
            "esit": sorted(len(x) for x in gorulen.values())[-2:]}


def uret(rng):
    for _ in range(40):
        v = dict(rng.choice(VAKALAR))
        tohum = rng.randint(1, 10**9)
        d = veri_uret(random.Random(tohum), v)
        hedef = rng.choice(d["entegratorler"])
        z = sayilar(d, hedef)
        if z["esit"][0] != z["esit"][1] and z["arsiv"] > 0:
            break
    m = musteri(v["kod"])
    eylem_sira = list(range(len(EYLEMLER)))
    rng.shuffle(eylem_sira)
    sen = list("abcd")
    rng.shuffle(sen)
    return {
        "vaka": f"{m['ad']} — e-dönüşüm belge akışı",
        "musteri": m, "v": v, "tohum": tohum, "hedef": hedef, "eylem_sira": eylem_sira, "sen": sen,
        "metin": {"musteri": m["ad"], "kisi": v["kisi"], "olay": v["olay"], "hedef": hedef,
                  "n_belge": len(d["satirlar"])},
        "cevaplar": {
            "taraf": [EYLEMLER[i][1] for i in eylem_sira],
            "tur": sen,
            "arsiv": z["arsiv"],
            "en_cok": z["en_cok"],
            "en_cok_muk": z["en_cok_muk"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = veri_uret(random.Random(s["tohum"]), v)
    csv_yaz(lab / "belgeler.csv", "belge_no,tur,mukellef,entegrator,tarih,durum", d["satirlar"])
    u.yaz(lab / "roller" / "eylemler.txt",
          "Aşağıdaki her eylem hangi tarafa aittir?  a) mükellef   b) entegratör   c) GİB\n\n" + "\n".join(
              f"{i}. {EYLEMLER[j][0]}" for i, j in enumerate(s["eylem_sira"], 1)) + "\n")
    u.yaz(lab / "roller" / "senaryolar.txt",
          "Her senaryo hangi e-belge türünü gerektirir?\n"
          + "\n".join(f"  {k}) {t}" for k, t in TURLER.items()) + "\n\n" + "\n".join(
              f"{i}. {v['senaryolar'][k]}" for i, k in enumerate(s["sen"], 1)) + "\n")
    u.yaz(lab / "ornek_fatura.xml", ORNEK_XML.replace("{musteri}", s["musteri"]["ad"]), mod=0o644)
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — e-dönüşüm inceleme klasörü (hepsi kurgusal)\n\n"
          f"belgeler.csv           : son ~4 haftanın belge kayıtları ({len(d['satirlar'])} satır)\n"
          "roller/eylemler.txt    : eylemleri taraflara eşleme sorusu\n"
          "roller/senaryolar.txt  : senaryoları belge türüne eşleme sorusu\n"
          "ornek_fatura.xml       : kurgusal, sadeleştirilmiş UBL-TR benzeri bir e-fatura\n\n"
          "belgeler.csv sütunları: belge_no, tur (e-fatura | e-arsiv | e-irsaliye), mukellef, entegrator, tarih, durum\n")


ORNEK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2"
         xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <cbc:ProfileID>KURGUSAL-LAB</cbc:ProfileID>
  <cbc:ID>FTR2026000000001</cbc:ID>
  <cbc:IssueDate>2026-03-04</cbc:IssueDate>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="VKN">KVKN-000001</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>{musteri}</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="TCKN">KURGUSAL-TCKN-0000</cbc:ID></cac:PartyIdentification>
      <cac:Person><cbc:FirstName>Kurgusal</cbc:FirstName><cbc:FamilyName>Kisi</cbc:FamilyName></cac:Person>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="TRY">1200.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>
"""


def _taraf_hata(verilen, beklenen, b):
    if len(verilen) != len(beklenen):
        return None
    yanlis = [(i + 1, a) for i, (a, c) in enumerate(zip(verilen, beklenen)) if a != c]
    if len(yanlis) and all(c == "b" for _, c in [(0, beklenen[i - 1]) for i, _ in yanlis]):
        return ("Entegratör (b) eylemlerini kaçırmış olabilirsin: çok sayıda mükellef adına belge ileten ve hizmet "
                "veren aracı sistem. Mükellef tek bir işletmedir.")
    return None


def _arsiv_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Fazla: sadece `tur` sütunu `e-arsiv` olan satırları ve sadece o entegratörü say (iki koşul birlikte)."
    return None


def _en_cok_hata(g, beklenen, b):
    return None


def coz(lab: Path, s: dict) -> dict:
    # taraflar ve türler: eşleme sorusu, metni okuyup anahtar kelimelerle eşlenir
    harf = []
    for satir in sh("tail -n +3 roller/eylemler.txt", lab).splitlines():
        if any(k in satir for k in ("imzalar", "kesen işletmedir")):
            harf.append("a")
        elif any(k in satir for k in ("iletir", "ele geçirilirse")):
            harf.append("b")
        else:
            harf.append("c")
    tur = []
    for satir in sh("grep -E '^[0-9]+\\.' roller/senaryolar.txt", lab).splitlines():
        if "yevmiye" in satir:
            tur.append("d")
        elif "sevk" in satir:
            tur.append("c")
        elif "kayıtlı olmayan" in satir or "bireysel" in satir or "tüketici" in satir:
            tur.append("b")
        else:
            tur.append("a")
    hedef = s["hedef"]
    arsiv = sh(f"awk -F, '$2==\"e-arsiv\" && $4==\"{hedef}\"' belgeler.csv | wc -l", lab)
    en = sh("tail -n +2 belgeler.csv | cut -d, -f3,4 | sort -u | cut -d, -f2 | sort | uniq -c | sort -rn | head -1", lab).split()
    cozum = {1: " ".join(harf), 2: " ".join(tur), 3: arsiv, 4: en[1], 5: en[0]}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Üç taraflı bir akış", """
Selin: "Türkiye'de e-dönüşüm (e-fatura, e-arşiv, e-irsaliye, e-defter) üç tarafın dansıdır:

- **Mükellef:** belgeyi kesen işletme (müşterimiz)
- **Entegratör / özel entegratör:** çok sayıda mükellef adına belgeleri ileten aracı sistem
- **GİB** (Gelir İdaresi Başkanlığı): merkezi otorite

Veri bu üç taraf arasında akar ve **her geçiş noktası bir güvenlik sınırıdır**." Klasörün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Kayıtlar", """
`belgeler.csv`, mükellefin son haftalarda ürettiği belgelerin kaydı: belge türü, hangi entegratör üzerinden
gittiği ve durumu. İlk satırlar:
""", komut="head -5 belgeler.csv"),
    Adim("Belge türü dağılımı", """
Dört belge türü dört ayrı iş içindir: **e-fatura** (e-fatura mükellefleri arası), **e-arşiv** (e-fatura
mükellefi olmayanlara, örn. bireysel müşteri), **e-irsaliye** (taşınan malın sevk belgesi), **e-defter**
(yevmiye ve defter-i kebir kayıtları). Hangi tür kaç kez geçiyor?
""", komut="cut -d, -f2 belgeler.csv | tail -n +2 | sort | uniq -c | sort -rn"),
    Adim("Entegratöre bağımlılık", """
Belgeler hangi entegratörden akıyor? **Tek bir entegratörün çok sayıda mükellefe hizmet vermesi**, onun
güvenliğini sizin güvenliğiniz yapar: zincir en zayıf halkası kadar güçlüdür.
""", komut="cut -d, -f4 belgeler.csv | tail -n +2 | sort | uniq -c | sort -rn", sonra="""
Bu sayı **belge** sayısı; bir entegratörün kaç **farklı mükellefe** hizmet verdiğini görev sırasında bulacaksın.
Çünkü ele geçirildiğinde etkilenen taraf sayısı, risk analizinin asıl ölçüsüdür.
"""),
    Adim("Bir e-faturanın içi", """
e-fatura, UBL-TR adı verilen bir XML biçimidir. Aşağıdaki kurgusal ve sadeleştirilmiş örnekte satıcı, alıcı
ve toplam tutar var. Alıcı bir gerçek kişi olabilir, o zaman belgede **kişisel veri** de bulunur (KVKK).
""", komut="cat ornek_fatura.xml", sonra="""
Belge üç tür hassasiyeti birleştirir: **finansal veri** (tutar, vergi), **ticari sır** (kim kimle ne kadar iş
yapıyor) ve **kişisel veri**. Dahası belge **yasal delildir**: bütünlüğü (değiştirilmemiş olması) hukuken
kritiktir. Bunu bir sonraki bölümde e-imza ve hash üzerinden göreceksin.
"""),
    Adim("Hacker gözüyle", """
Bir saldırgan için e-dönüşüm sistemi üç yüzeydir: mükellefin kendi sistemi, entegratörün API'si ve belgenin
kendisi. Savunma tarafında ders: akışı tanımadan korunamazsın; **kimin ne zaman neyi imzaladığını, kimin neyi
ilettiğini** bilmek güvenlik analizinin ilk adımıdır.

Son bir komut: bu kayıtlarda toplam kaç belge var?
""", komut="tail -n +2 belgeler.csv | wc -l"),
]

GOREVLER = [
    Gorev("`roller/eylemler.txt` içindeki 6 eylemin her biri hangi tarafa aittir? a) mükellef, b) entegratör, "
          "c) GİB. Cevap: dosyadaki sırayla altı harf (örn. `a b c a b c`).",
          Dizi("taraf", sik_hatalar=_taraf_hata, bicim="altı harf sırayla, örn. a b c a b c"),
          ("Her eylemde fiil kimin işi olduğunu söylüyor: kesmek mi, iletmek mi, yönetmek mi?",
           "`cat roller/eylemler.txt`. Mükellef tek bir işletmedir; entegratör çok sayıda mükellefe hizmet verir; "
           "GİB merkezi otoritedir.",
           "Belgeyi kesen ve imzalayan = a. Çok sayıda mükellef adına ileten ve ele geçirilirse geniş etki yaratan = b. "
           "Merkezi sistemi ve mevzuatı yöneten, merkezi izleme yapan = c."),
          puan=35, baslik="Taraflar"),
    Gorev("`roller/senaryolar.txt` içindeki 4 senaryo hangi belge türünü gerektirir? Türler dosyanın başında "
          "(a e-fatura, b e-arşiv, c e-irsaliye, d e-defter). Cevap: dört harf sırayla.",
          Dizi("tur", bicim="dört harf sırayla, örn. b d a c"),
          ("İlk soru: alıcı e-fatura mükellefi mi? İkinci soru: bu belge mal taşırken mi lazım, kayıt tutarken mi?",
           "`cat roller/senaryolar.txt`. Kayıtlı mükellefe = e-fatura; kayıtlı olmayana/bireysele = e-arşiv; yoldaki mal = "
           "e-irsaliye; yevmiye/kebir = e-defter.",
           "Senaryoları sırayla okuyup anahtar kelimeyi seç: 'e-fatura sistemine kayıtlı' (a), 'kayıtlı olmayan' ya da "
           "'tüketici' (b), 'sevk' (c), 'yevmiye' (d)."),
          puan=35, baslik="Belge türleri"),
    Gorev("`belgeler.csv`: **<<hedef>>** entegratörü üzerinden geçen **e-arşiv** belgelerinin sayısı kaç?",
          Sayi("arsiv", sik_hatalar=_arsiv_hata),
          ("İki koşul: tür `e-arsiv` ve entegratör `<<hedef>>`.",
           "`awk -F, 'NR>1 && koşul1 && koşul2' belgeler.csv | wc -l`; tür `$2`, entegratör `$4`.",
           "`awk -F, '$2==\"e-arsiv\" && $4==\"<<hedef>>\"' belgeler.csv | wc -l`"),
          puan=25, baslik="Belge sayımı"),
    Gorev("Risk analizi: hangi entegratör, **en çok farklı mükellefin** belgesini taşıyor? (Ele geçirilirse en geniş "
          "etkiyi yaratacak olan.)",
          Metin("en_cok", bicim="entegratör adı"),
          ("Belge sayısı değil, **farklı mükellef** sayısı. Her (mükellef, entegratör) çiftini bir kez say.",
           "`cut -d, -f3,4 belgeler.csv | sort -u` çiftleri tekilleştirir; ardından entegratöre göre say.",
           "`tail -n +2 belgeler.csv | cut -d, -f3,4 | sort -u | cut -d, -f2 | sort | uniq -c | sort -rn`"),
          puan=35, baslik="Yoğunlaşma riski"),
    Gorev("O entegratör kaç **farklı mükellefe** hizmet veriyor? (Ele geçirilirse etkilenecek taraf sayısı.)",
          Sayi("en_cok_muk"),
          ("Önceki görevde yaptığın sayımın sayısı.",
           "Çift tekilleştirme çıktısındaki en üstteki sayı.",
           "`tail -n +2 belgeler.csv | cut -d, -f3,4 | sort -u | cut -d, -f2 | sort | uniq -c | sort -rn | head -1`"),
          puan=25, baslik="Etkilenecek taraf"),
    Gorev("e-dönüşüm belgeleri **hangi üç tür hassasiyeti** birleştirir?",
          Secmeli([
              ("Finansal veri, ticari sır ve kişisel veri",
               "Doğru. Tutar ve vergi finansal; kim kimle ne kadar iş yapıyor ticari sır; alıcı gerçek kişiyse kişisel veri (KVKK)."),
              ("Askerî sır, devlet sırrı ve sağlık verisi",
               "Faturalarda bu türler beklenmez; hassasiyet ticari ve finansal niteliktedir."),
              ("Yalnızca finansal veri; ticari ve kişisel veri fatura kapsamı dışındadır",
               "Fatura kimin kimle iş yaptığını ve çoğu zaman kişi bilgilerini de gösterir."),
              ("Yalnızca kişisel veri; tutar ve vergi bilgisi kamuya açık sayılır",
               "Fatura tutarları ticari olarak gizli ve vergisel olarak hassastır; kamuya açık değildir."),
          ]),
          ("Faturada neler yazar: tutarlar, taraflar, adresler...",
           "Üç farklı koruma gereği: vergi/finans, rekabet, kişi mahremiyeti.",
           "Cilt 10'daki KVKK ve ticari sır kavramlarını birleştir."),
          puan=20, baslik="Hassasiyet"),
    Gorev("e-dönüşüm belgeleri **yasal delil** niteliğindedir. Güvenlik açısından bu neyi özellikle kritik yapar?",
          Secmeli([
              ("Bütünlük: belgenin değiştirilmediğinin e-imza ve hash gibi yöntemlerle kanıtlanabilir olması",
               "Doğru. Delil niteliği, belgenin sonradan değiştirilmediğini gösterebilmeyi şart koşar."),
              ("Belgelerin her zaman şifreli (gizli) saklanması, bütünlük ikinci planda",
               "Gizlilik de önemlidir ama delil değeri öncelikle bütünlüğe ve inkâr edilemezliğe dayanır."),
              ("Belgelerin hızlı iletilmesi; gecikme hukuken geçersiz kılar",
               "Hız işletme için önemlidir ama delil niteliğinin dayanağı bu değildir."),
              ("Belgelerin mümkün olduğunca çok kopyasının herkese dağıtılması",
               "Kopya çoğaltmak güvenliği artırmaz; hassas veriyi daha çok yere yayar."),
          ]),
          ("Mahkemede bir faturayı sunduğunda karşı taraf ne iddia edebilir?",
           "'Bu belge sonradan değiştirilmiş' iddiasına karşı ne gerekir?",
           "Bütünlük ve imza."),
          puan=20, baslik="Yasal delil"),
]

SEVIYE = Seviye(
    kimlik="c23b01",
    cilt=23,
    bolum=1,
    baslik="e-Dönüşüm Ekosistemi",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> e-dönüşüm süreçlerinin güvenlik değerlendirmesini istiyor.

Selin: "Bir akışı korumak için önce **akışı** anlaman gerekir: kim belgeyi keser, kim iletir, kim denetler,
hangi belge ne zaman lazım?" Deniz, <<n_belge>> satırlık bir belge dökümü getiriyor: "Kayıtlar hepsi burada.
Bakalım, belgeler tek bir kapıdan mı geçiyor?" Mert ekliyor: "Çoğu güvenlikçi e-faturanın nasıl çalıştığını
bilmez. Sen finans tarafını biliyorsun; avantaj sende."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
e-dönüşümün güvenliği, akışı bilmekle başlar: mükellef belgeyi keser ve imzalar, entegratör çok sayıda
mükellef adına iletir, GİB merkezi otoritedir. Her geçiş bir güvenlik sınırı, her belge bir yasal delildir.
Saldırgan perspektifinden en değerli hedef, çok sayıda mükellefin belgesini taşıyan entegratördür; bu yüzden
yoğunlaşma, riskin ölçüsüdür. Savunma perspektifinden ders: entegratör seçimi ve denetimi bir güvenlik
kararıdır, belgelerin bütünlüğü imza ve hash ile kanıtlanabilir tutulmalı, kişisel veri içeren alanlar KVKK
gözüyle minimumda tutulmalıdır.
""",
    gercek_hayat="""
- **Üçüncü taraf zinciri:** Sağlık, finans ve perakende sektörlerinde tedarik zinciri ya da hizmet sağlayıcı
  üzerinden gerçekleşen veri ihlalleri (örneğin yazılım güncelleme zincirini hedef alan SolarWinds 2020 olayı)
  zincirin en zayıf halkası kadar güçlü olduğunu gösterdi. Tespit: üçüncü taraf bağlantılarının ve
  yetkilerinin envanteri; önlem: sözleşmede güvenlik şartları, yetkilerin asgari tutulması ve düzenli denetim.
- **Mevzuat sürekli değişir:** e-dönüşüm uygulamaları GİB'in düzenlemeleriyle şekillenir ve zamanla
  değişir. Bu yüzden güvenlik ekibi, güncel teknik ayrıntıları resmî kaynaklardan takip eder; kalıcı olan
  ilkeler (bütünlük, kimlik doğrulama, yetkilendirme, sırların korunması) ise değişmez.
- **Kişisel veri:** Fatura gibi belgeler, alıcı bir gerçek kişiyse KVKK kapsamında kişisel veri taşır.
  Veri sorumlularının teknik ve idari tedbir alma yükümlülüğü, belgelerin saklandığı ve iletildiği her
  sisteme de uzanır; erişim kontrolü ve kayıt tutma bu tedbirlerin temelidir.
""",
    sure_hedef_dk=35,
)
