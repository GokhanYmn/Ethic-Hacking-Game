"""Cilt 22 · Bölüm 4 — Para Akışını Takip Et: Zincirde Adli Analiz.

Beceri: kurban olan bir borsa/protokolün analisti olarak, çalınan paranın zincirdeki izini sürmek. İşlem
defterini (CSV) okumak, bir adresi `grep` ile izleyip elle "hop"lamak (bir sonraki adrese geçmek), tutarları
`awk` ile toplamak, zamana göre sıralamak, bilinen adres listesiyle birleştirmek (join), mikser desenini
tanımak ve paranın borsaya girdiği noktayı bulup müdahale (dondurma talebi) için kanıtı hazırlamak.

TAMAMEN SAVUNMACI/ADLİ: Nasıl aklanacağı anlatılmaz; sadece izlenir. Adresler, borsalar ve mikserler
kurgusaldır; gerçek bir zincir yoktur, her şey dosya tabanlı sahte veridir.

Vakalar: üç kurgusal kurban (Liman Kripto Borsası, Kasa-X Finans Protokolü, Ayrıt Dijital Varlık Saklama).
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

VAKALAR = [
    {"ad": "Liman Kripto Borsası", "kisi": "Aylin Hanım (güvenlik sorumlusu)",
     "kurban_etiket": "KURBAN Liman sicak cuzdan", "aralik": (600, 1500),
     "mesru": ["MUSTERI-CEKIM havuzu", "MUSTERI-CEKIM yedek havuz", "SOGUK cuzdan Liman", "PARTNER Anka Odeme"],
     "olay": "Liman Kripto Borsası'nın ETH sıcak cüzdanından gece saatlerinde izinsiz bir çıkış oldu. Para şu an "
             "zincirde hareket ediyor; ne kadar çaba harcanırsa, o kadar ihtimalle bir borsada dondurulabilir."},
    {"ad": "Kasa-X Finans Protokolü", "kisi": "Barış Bey (protokol güvenlik lideri)",
     "kurban_etiket": "KURBAN KasaX havuz sozlesmesi", "aralik": (2000, 5000),
     "mesru": ["ODUL dagitim sozlesmesi", "EKIP cuzdani KasaX", "LP-CEKIM yonlendirici", "DENETCI Pusula odeme"],
     "olay": "Kasa-X Finans Protokolü'nün likidite havuzundan, bir akıllı sözleşme (zincirde çalışan program) hatası "
             "sömürülerek ETH çekildi. Yönetim, paranın nereye gittiğini ve geri alınabilir bir noktaya gelip "
             "gelmediğini öğrenmek istiyor."},
    {"ad": "Ayrıt Dijital Varlık Saklama", "kisi": "Merve Hanım (iç denetim)",
     "kurban_etiket": "KURBAN Ayrit musteri kasasi", "aralik": (150, 400),
     "mesru": ["TEDARIKCI Kuzey Yazilim", "TEDARIKCI Orman Depo", "KASA transfer Ayrit", "PERSONEL maas cuzdani"],
     "olay": "Ayrıt Dijital Varlık Saklama'nın bir müşteri kasasından, ele geçirilen bir yönetici anahtarıyla ETH "
             "çıkarıldı. Müşteriye bildirim yapılmadan önce paranın izini ve çıkış noktasını netleştirmek gerekiyor."},
]

BORSALAR = ["Yildiz Takas", "Mavi Liman Borsa", "Kuzey Takas", "Atlas Kripto"]
MIKSERLER = ["Sis Havuzu", "Bulut Karistirici", "Duman Transfer"]
BASLIK_ISLEM = "zaman,tx,gonderen,alici,tutar_eth,etiket"
BASLIK_ADRES = "adres,etiket"


def _hex(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def veri_uret(rng: random.Random, v: dict) -> dict:
    """Bir vakanın bütün işlem defterini üretir (aynı rng -> aynı defter)."""
    kul: set = set()
    kul_tx: set = set()

    def adr() -> str:
        while True:
            a = "0x" + _hex(rng, 8)
            if a not in kul:
                kul.add(a)
                return a

    def tx() -> str:
        while True:
            t = "0x" + _hex(rng, 12)
            if t not in kul_tx:
                kul_tx.add(t)
                return t

    sat: list = []                     # (zaman, gonderen, alici, tutar, etiket)
    gun = u.gun(rng)

    kurban = adr()
    n_zincir = rng.randint(3, 4)       # saldırganın adres sayısı (A1..An), sonra mikser
    zincir = [adr() for _ in range(n_zincir)]
    mik_ad = rng.sample(MIKSERLER, 2)
    mikser, mikser_yedek = adr(), adr()
    borsa_ad = rng.sample(BORSALAR, 3)                 # [gerçek, yedek, üçüncü]
    borsa_adr = {b: adr() for b in borsa_ad}
    gercek, yedek_b, ucuncu = borsa_ad
    defi = adr()
    mesru = [(e, adr()) for e in v["mesru"]]
    havuz = [adr() for _ in range(rng.randint(9, 13))]  # sıradan kullanıcı adresleri

    bilinen = [(kurban, v["kurban_etiket"]),
               (mikser, f"MIKSER {mik_ad[0]}"), (mikser_yedek, f"MIKSER {mik_ad[1]}"),
               (defi, "DEFI Kopru Havuzu")]
    bilinen += [(borsa_adr[b], f"BORSA {b} yatirim") for b in borsa_ad]
    bilinen += [(a, e) for e, a in mesru]

    # 1) kurbanın meşru günlük hareketleri
    for _ in range(rng.randint(5, 8)):
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        sat.append((t, kurban, rng.choice(mesru)[1], rng.randint(5, 120), "odeme"))
    for _ in range(rng.randint(4, 6)):
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        sat.append((t, rng.choice(havuz), kurban, rng.randint(10, 200), "tahsilat"))

    # 2) hırsızlık: iki parça halinde, bilinmeyen tek bir adrese
    toplam = rng.randint(v["aralik"][0], v["aralik"][1])
    p1 = rng.randint(toplam * 4 // 10, toplam * 6 // 10)
    t0 = gun + timedelta(days=1, hours=rng.randint(1, 3), minutes=rng.randint(0, 50))
    sat.append((t0, kurban, zincir[0], p1, "transfer"))
    sat.append((t0 + timedelta(minutes=rng.randint(3, 9)), kurban, zincir[0], toplam - p1, "transfer"))

    # 3) hop'lar: A1 -> A2 -> ... -> An -> mikser (her adres tek bir yere gönderir)
    t = t0 + timedelta(minutes=15)
    for i in range(n_zincir - 1):
        t += timedelta(minutes=rng.randint(12, 80))
        sat.append((t, zincir[i], zincir[i + 1], toplam, "transfer"))
    t += timedelta(minutes=rng.randint(10, 60))
    t_mikser = t
    sat.append((t_mikser, zincir[-1], mikser, toplam, "transfer"))

    # 4) mikser girişleri: çok sayıda farklı adresten (bazıları tekrar eder), + yedek mikser
    n_dep = rng.randint(12, 18)
    for _ in range(n_dep):
        tz = t0 + timedelta(minutes=rng.randint(-300, 600))
        sat.append((tz, rng.choice(havuz), mikser, rng.randint(8, 90), "transfer"))
    for _ in range(rng.randint(8, 16)):
        tz = t0 + timedelta(minutes=rng.randint(-300, 600))
        sat.append((tz, rng.choice(havuz), mikser_yedek, rng.randint(8, 90), "transfer"))

    # 5) mikser çıkışları: gecikmeli, parça parça; biri gerçek borsaya, biri köprüye
    n_out = rng.randint(6, 9)
    taban = toplam * 97 // 100
    w = [rng.randint(5, 25) for _ in range(n_out)]
    parcalar = [taban * x // sum(w) for x in w]
    parcalar[-1] += taban - sum(parcalar)
    hedefler = [adr() for _ in range(n_out)]
    ib = rng.randrange(n_out)
    idefi = rng.choice([i for i in range(n_out) if i != ib])
    hedefler[ib] = borsa_adr[gercek]
    hedefler[idefi] = defi
    tc = t_mikser + timedelta(hours=rng.randint(3, 9), minutes=rng.randint(0, 50))
    for i in range(n_out):
        tc += timedelta(minutes=rng.randint(10, 90))
        sat.append((tc, mikser, hedefler[i], parcalar[i], "transfer"))
    y_borsa = parcalar[ib]
    # yedek mikserin çıkışları: biri başka bir borsaya (yanlış mikseri seçenin tuzağı)
    n_y = rng.randint(3, 5)
    iy = rng.randrange(n_y)
    tc2 = t0 + timedelta(hours=rng.randint(2, 6))
    for i in range(n_y):
        tc2 += timedelta(minutes=rng.randint(20, 100))
        hedef = borsa_adr[yedek_b] if i == iy else adr()
        sat.append((tc2, mikser_yedek, hedef, rng.randint(15, 70), "transfer"))

    # 6) gürültü: sıradan kullanıcılar arası ve borsalara yatırımlar (gerçek borsaya da)
    for _ in range(rng.randint(18, 26)):
        a, b = rng.sample(havuz, 2)
        tz = gun + timedelta(seconds=rng.randint(0, 2 * 86400))
        sat.append((tz, a, b, rng.randint(1, 200), "transfer"))
    for b in borsa_ad:
        for _ in range(rng.randint(2, 4)):
            tz = gun + timedelta(seconds=rng.randint(0, 2 * 86400))
            sat.append((tz, rng.choice(havuz), borsa_adr[b], rng.randint(3, 60), "transfer"))

    sat.sort(key=lambda x: x[0])
    satirlar = [(f"{z:%Y-%m-%dT%H:%M:%S}", tx(), g, a, tu, et) for z, g, a, tu, et in sat]
    borsaya = sum(r[4] for r in satirlar if r[3] == borsa_adr[gercek])
    tum_cikis = sum(r[4] for r in satirlar if r[2] == kurban)
    rng.shuffle(satirlar)               # defter karışık gelir: sıralamayı oyuncu yapar
    rng.shuffle(bilinen)
    return {"satirlar": satirlar, "bilinen": bilinen, "kurban": kurban, "toplam": toplam, "p1": p1,
            "zincir": zincir, "mikser": mikser, "mikser_yedek": mikser_yedek, "gercek": gercek,
            "yedek_b": yedek_b, "borsa_adr": borsa_adr[gercek], "y_borsa": y_borsa, "borsaya": borsaya,
            "tum_cikis": tum_cikis, "en_buyuk_parca": max(parcalar), "n_dep": n_dep}


def _borsa_kabul(ad: str) -> list:
    return [ad, ad.replace(" ", ""), ad.replace(" ", "_"), ad.replace(" ", "-")]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    tohum = rng.randint(1, 10**9)
    d = veri_uret(random.Random(tohum), v)
    return {
        "vaka": f"{v['ad']} — para akışı takibi",
        "v": v, "tohum": tohum,
        "metin": {"musteri": v["ad"], "kisi": v["kisi"], "olay": v["olay"], "kurban": d["kurban"]},
        "cevaplar": {
            "tutar": d["toplam"],
            "ilk": d["zincir"][0],
            "dizi": list(d["zincir"]),
            "mikser": d["mikser"],
            "borsa": _borsa_kabul(d["gercek"]),
            "borsa_tutar": d["y_borsa"],
        },
    }


def _veri(b_senaryo: dict) -> dict:
    return veri_uret(random.Random(b_senaryo["tohum"]), b_senaryo["v"])


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = veri_uret(random.Random(s["tohum"]), v)
    u.yaz(lab / "islemler.csv",
          BASLIK_ISLEM + "\n" + "\n".join(",".join(str(c) for c in r) for r in d["satirlar"]) + "\n")
    u.yaz(lab / "bilinen_adresler.csv",
          BASLIK_ADRES + "\n" + "\n".join(f"{a},{e}" for a, e in d["bilinen"]) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — zincir izleme klasörü (kurgusal veri)\n\n"
          "islemler.csv         : zincirden derlenen işlem defteri (satırlar karışık, zaman sırasına dizilmemiş)\n"
          "                       sütunlar: zaman, tx (işlem kodu), gonderen, alici, tutar_eth, etiket\n"
          "bilinen_adresler.csv : analiz ekibinin bildiği adresler (kurban, borsa yatırım adresleri,\n"
          "                       mikser, köprü, sıradan alıcılar). Listede olmayan adres = bilinmeyen.\n\n"
          f"Kurbanın adresi: {d['kurban']}\n"
          "Not: Tutarlar tam ETH olarak yazılmıştır. Bütün adresler, borsalar ve mikserler kurgusaldır.\n")


# ---------------------------------------------------------------- sık hata geri bildirimleri

def _tutar_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    n = int(g)
    if n == d["tum_cikis"]:
        return ("Kurbanın bütün çıkışlarını topladın; günlük meşru ödemeler de içinde. Sadece "
                "`bilinen_adresler.csv`'de **olmayan** adrese giden işlemleri topla.")
    if n in (d["p1"], d["toplam"] - d["p1"]):
        return "Tek bir işlemi aldın; hırsızlık iki parça halinde yapılmış. İkisini de topla."
    return None


def _ilk_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g == d["kurban"]:
        return "Bu kurbanın kendi adresi. Para ondan çıktı; parayı alan adresi ara."
    if g in (d["mikser"], d["mikser_yedek"]):
        return "Bu bir mikser (paranın izini karıştıran havuz). İlk alıcı değil, daha sonraki bir halka."
    if g in [x for x in d["zincir"][1:]]:
        return "Bu adres zincirin ilerisinde bir hop. Parayı kurbandan **doğrudan** alan adres ilk olandır."
    return None


def _dizi_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g == beklenen[::-1]:
        return "Ters yazdın. Para kurbandan çıkıp ilerler: en erken zamanlı hop başta olmalı."
    if g == beklenen + [d["mikser"]]:
        return "Mikseri de eklemişsin; mikser adres zincirinin parçası değil, bir sonraki durak. Mikserden önce dur."
    if g and set(g) == set(beklenen):
        return "Adresler doğru ama sıra yanlış. Zaman damgasına göre sırala (`sort -t, -k1`)."
    if g and len(g) < len(beklenen) and set(g) <= set(beklenen):
        return "Sıra doğru gibi ama zincirin devamı var. Mikser girişine kadar bütün hop'ları yaz."
    return None


def _mikser_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g == d["mikser_yedek"]:
        return ("Bu da bilinen bir mikser ama saldırganın parası ona gitmedi. Zinciri son hop'a kadar elle izle; "
                "son hop'un parayı gönderdiği adres cevap.")
    if g == d["zincir"][-1]:
        return "Bu, mikserin hemen önündeki son hop. Parayı **aldıkları** adres mikserdir."
    return None


def _borsa_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g in {x.casefold() for x in _borsa_kabul(d["yedek_b"])} or g in {x.casefold().replace("ı", "i") for x in _borsa_kabul(d["yedek_b"])}:
        return ("Bu borsa yedek mikserin çıkışlarında geçiyor; saldırganın kullandığı mikser değil. "
                "Doğru mikserin çıkışlarını `bilinen_adresler.csv` ile eşleştir.")
    return None


def _btutar_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    n = int(g)
    if n == d["borsaya"]:
        return ("Borsanın yatırım adresine gelen **bütün** işlemleri toplamışsın; sıradan kullanıcıların yatırımları "
                "da içinde. Sadece mikserden gelen işlemi al.")
    if n == d["en_buyuk_parca"] and n != beklenen:
        return "Bu mikserin en büyük çıkışı ama borsaya giden parça bu değil. Alıcısı borsa adresi olan satırı bul."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    kurban = sh("grep KURBAN bilinen_adresler.csv | cut -d, -f1", lab)
    birlestir = "NR==FNR{b[$1]=1;next}"
    tutar = sh(f"awk -F, -v k={kurban} '{birlestir} $3==k && !($4 in b){{s+=$5}} END{{print s}}' "
               "bilinen_adresler.csv islemler.csv", lab)
    ilk = sh(f"awk -F, -v k={kurban} '{birlestir} $3==k && !($4 in b){{print $4}}' "
             "bilinen_adresler.csv islemler.csv | sort -u | head -1", lab)
    # elle hop: her adresin tek giden işlemini izle, alıcı mikser etiketliyse dur
    zincir, mikser, cur = [ilk], "", ilk
    for _ in range(12):
        sonraki = sh(f"grep -F '{cur}' islemler.csv | awk -F, -v a={cur} '$3==a{{print $4}}' | sort -u | head -1", lab)
        if not sonraki:
            break
        if sh(f"grep -c '^{sonraki},MIKSER' bilinen_adresler.csv", lab) == "1":
            mikser = sonraki
            break
        zincir.append(sonraki)
        cur = sonraki
    ex_adr = sh(f"awk -F, -v m={mikser} 'NR==FNR{{e[$1]=$2;next}} $3==m && ($4 in e) && e[$4] ~ /^BORSA/ {{print $4}}' "
                "bilinen_adresler.csv islemler.csv | head -1", lab)
    borsa = sh(f"grep '^{ex_adr},' bilinen_adresler.csv | cut -d, -f2 | sed 's/^BORSA //; s/ yatirim$//'", lab)
    btutar = sh(f"awk -F, -v m={mikser} -v e={ex_adr} '$3==m && $4==e{{s+=$5}} END{{print s}}' islemler.csv", lab)
    cozum = {1: tutar, 2: ilk, 3: " ".join(zincir), 4: mikser, 5: borsa, 6: btutar, 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


# ---------------------------------------------------------------- eğitim adımları

ADIMLAR = [
    Adim("Zincir açık bir defterdir", """
Selin: "Blockchain'in en önemli özelliği hem kurbanın hem saldırganın gücü: **her işlem herkese açık bir
defterde durur**. Saldırgan parayı çaldı ama çaldığı her adımı da zincire yazdı. Biz de bu izi sürüp paranın
nereye gittiğini bulacağız. Adresler kişi ismi taşımaz, ama **hareketleri** görünür."

Bu bölümde bir **adli analist** gibi çalışacaksın (yalnızca izlemek ve kanıt toplamak; para geri almak için
kimsenin sistemine girmek yok). Önce klasörün haritasına bak:
""", komut="cat OKUBENI.txt"),
    Adim("İşlem defterini oku", """
`islemler.csv` zincirden derlenmiş işlem kayıtları. Her satır bir **transfer**: ne zaman, hangi işlem kodu (tx),
kimden (`gonderen`), kime (`alici`), kaç ETH. İlk birkaç satıra bak:
""", komut="head -n 6 islemler.csv", sonra="""
Dikkat: satırlar zaman sırasına dizili **değil**. Zinciri izlemek için bir şeyi sırayla okuyabilmen gerekecek.
Adresler `0x` ile başlayan uzun değerlerdir; gerçek bir cüzdan numarası gibi görünen ama tamamen kurgusal
dizelerdir.
"""),
    Adim("Bilinen adresleri gör", """
`bilinen_adresler.csv`, analiz ekibinin tanıdığı adreslerin listesi: kurban, borsaların **yatırım adresleri**,
mikserler (paranın izini karıştıran havuzlar), sıradan alıcılar. İçeriğini oku:
""", komut="cat bilinen_adresler.csv", sonra="""
Her satır `adres,etiket` biçiminde. Listede olmayan bir adres **bilinmeyen** demektir. Adli analizin yarısı
"bildiğimiz adresler"le "bilmediğimiz adresleri" karşılaştırmaktır.
"""),
    Adim("Bir adresi izle: grep", """
Bir adresin bütün hareketini görmek için adresi `grep` ile ara. Şimdi **kurbanın** adresini ara; hem gelen
hem giden her işlem çıkar (`gonderen` sütununda ise para o adresten çıkmıştır):
""", komut="grep <<kurban>> islemler.csv", sonra="""
Kurbanın adresi bazı satırlarda 3. sütunda (gönderen), bazı satırlarda 4. sütunda (alıcı) duruyor. "Giden"
işlemler 3. sütunda olanlardır. Zinciri izlerken hep **giden** işlemlere bakarsın.
"""),
    Adim("Tutarları topla: awk", """
`awk -F,` satırı virgülden böler; 3. sütun gönderen, 5. sütun tutar. Kurbanın **bütün** çıkışlarının
toplamını al:
""", komut="awk -F, '$3==\"<<kurban>>\"{s+=$5} END{print s}' islemler.csv", sonra="""
Bu sayı kurbanın bütün çıkışı: günlük meşru ödemeler **ve** hırsızlık bir arada. Çalınan tutarı bulmak için
meşru olanları ayıklaman gerekecek; bunu birazdan göreceğin birleştirme (join) ile yapacaksın.
"""),
    Adim("Zamana göre sırala: sort", """
İşlemler karışık geldi. `sort -t, -k1` satırları virgülden bölüp **1. sütuna (zaman)** göre sıralar; zaman
damgaları `2026-03-04T02:14:09` biçiminde olduğu için düz sıralama yeterli. `tail -n +2` başlığı atar:
""", komut="tail -n +2 islemler.csv | sort -t, -k1 | head -n 5", sonra="""
Artık en eski işlemleri başta görüyorsun. Para hareketi bir **zaman çizgisidir**: bir adres parayı aldıktan
sonra gönderir; sonraki hop her zaman daha geç tarihlidir. Karışık bir kaydı bu yüzden önce sıralarız.
"""),
    Adim("Bilinen adresle birleştir (join)", """
Bilinen listeyle işlem defterini birleştirmek için `awk` iki dosyayı aynı anda okuyabilir. İlk dosyayı
(`bilinen_adresler.csv`) bir sözlüğe dolduruyoruz; ikinci dosyada (`islemler.csv`) kurbanın giden işlemlerinden
alıcısı bu sözlükte **olanları** yazdırıyoruz (yani **bilinen** alıcılar):
""", komut="awk -F, 'NR==FNR{b[$1]=1;next} $3==\"<<kurban>>\" && ($4 in b)' bilinen_adresler.csv islemler.csv",
         sonra="""
Gördüğün satırlar kurbanın bilinen alıcılara yaptığı ödemeler. Aynı komutta `($4 in b)` yerine `!($4 in b)`
yazarsan tersini, yani **bilinmeyen** alıcılara gidenleri alırsın. Hırsızlık orada saklıdır; görevde bunu sen
yapacaksın.
"""),
    Adim("Mikser desenini tanı", """
**Mikser**, birçok kişinin parasını bir havuza toplayıp sonra parçalara bölerek farklı adreslere dağıtan
hizmettir. Zincirde parmak izi çok belirgindir: **çok sayıda farklı adresten GİRİŞ** ve ardından gecikmeli,
parçalı **ÇIKIŞLAR**. En çok işlem alan adresleri sayarak desenin kendisini yakalayabilirsin:
""", komut="cut -d, -f4 islemler.csv | sort | uniq -c | sort -rn | head -n 4", sonra="""
Üstteki adreslerden bazıları çok sayıda işlem alıyor. Bunları `bilinen_adresler.csv` ile eşleştirince
mikser etiketli olanları görürsün. Dikkat: listede **birden fazla** mikser olabilir; hangisinin saldırganın
parasını aldığını sadece zinciri **elle izleyerek** anlarsın. Mikser zinciri kırmaz, sadece yavaşlatır:
çıkışlar yine zincirde yazılıdır.

**Hacker gözüyle:** Saldırgan mikserin izi tamamen sildiğini düşünür; savunmacı için mikserin çıkışları
bile bir zaman çizelgesidir. Giriş ve çıkış zamanları, tutarlar ve çıkışın sonunda para bir borsaya yaklaşınca
yeniden görünür hale gelir.
"""),
    Adim("Borsa çıkış noktasını bul", """
Saldırgan parayı sonunda nakde çevirmek ister. Bunun için paranın bir **borsanın yatırım adresine** girmesi
gerekir; borsalar kimlik doğrulaması (KYC) tuttuğu için burası zincirdeki izin **en değerli** noktasıdır: borsa hesabı
dondurabilir ve hesap sahibinin kimliğini yetkili makama verebilir. Bilinen borsa yatırım adreslerini listele:
""", komut="grep BORSA bilinen_adresler.csv", sonra="""
Bir yatırım adresine kaç farklı kaynaktan para geldiğine bakmak yetmez; **hangi işlemin saldırganın paraları**
olduğunu zincir izinden bileceksin. Görevlerde bu adresleri, mikser çıkışlarıyla eşleştireceksin.
"""),
]

# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Kurbanın (<<kurban>>) adresinden **bilinmeyen** (`bilinen_adresler.csv`'de olmayan) adrese giden "
          "işlemlerin toplamı, yani **çalınan tutar**, kaç ETH?",
          Sayi("tutar", sik_hatalar=_tutar_hata),
          ("Meşru ödemeler bilinen adreslere gidiyor; hırsızlık bilinmeyen bir adrese. Önce onları ayır.",
           "`awk` iki dosyayı birleştirir: `NR==FNR{b[$1]=1;next}`; ardından `!($4 in b)` bilinmeyen alıcıları seçer.",
           "`awk -F, -v k=<<kurban>> 'NR==FNR{b[$1]=1;next} $3==k && !($4 in b){s+=$5} END{print s}' "
           "bilinen_adresler.csv islemler.csv`"),
          puan=35, baslik="Çalınan tutar"),
    Gorev("Çalınan paranın kurbandan **ilk** gittiği saldırgan adresi hangisi?",
          Metin("ilk", sik_hatalar=_ilk_hata, bicim="0x... adres"),
          ("Hırsızlık işlemlerinin **alıcısına** bak (4. sütun).",
           "Bir önceki görevdeki `!($4 in b)` süzgeciyle satırları yazdır, alıcı sütununu seç.",
           "`awk -F, -v k=<<kurban>> 'NR==FNR{b[$1]=1;next} $3==k && !($4 in b){print $4}' "
           "bilinen_adresler.csv islemler.csv | sort -u`"),
          puan=30, baslik="İlk saldırgan adresi"),
    Gorev("Paranın izlediği yolu **elle hop'layarak** takip et: ilk saldırgan adresinden başlayıp **mikser girişinden "
          "önceki** son adrese kadar bütün adresleri zaman sırasıyla, aralarına boşluk koyarak yaz.",
          Dizi("dizi", sik_hatalar=_dizi_hata, bicim="adresler sırayla, boşlukla ayrılmış"),
          ("Her adres parayı tek bir yere gönderiyor. İlk adresin **gönderen** olduğu satırı bul.",
           "`grep ADRES islemler.csv` ile adresin satırlarına bak; `alici` yeni adrestir, onu aynı yöntemle sorgula.",
           "Döngü: `grep ADRES islemler.csv | awk -F, '$3==\"ADRES\"{print $4}'` → çıkan adresi `ADRES` yerine yaz → "
           "alıcının mikser olduğunu `bilinen_adresler.csv`'de görene kadar tekrarla."),
          puan=40, baslik="Hop sırası"),
    Gorev("Saldırganın parayı soktuğu **mikser** adresi hangisi? (Listede birden fazla mikser var; zinciri izle.)",
          Metin("mikser", sik_hatalar=_mikser_hata, bicim="0x... adres"),
          ("Zincirdeki son hop parayı nereye gönderiyor? Alıcısı mikser olarak etiketli.",
           "Son hop adresini `grep` ile ara; giden işlemin alıcısı cevaptır. `grep MIKSER bilinen_adresler.csv` ile doğrula.",
           "`grep -F SONHOP islemler.csv | awk -F, '$3==\"SONHOP\"{print $4}'`, sonra `grep ALICI bilinen_adresler.csv`."),
          puan=30, baslik="Mikser girişi"),
    Gorev("Aynı mikserin çıkışlarından biri bir **borsanın yatırım adresine** gitmiş. Hangi borsa? "
          "(Sadece borsanın adı, örn. `Yildiz Takas`.)",
          Metin("borsa", sik_hatalar=_borsa_hata, bicim="borsa adı (en fazla iki-üç kelime)"),
          ("Mikserden **çıkan** işlemlerin alıcılarına bak (`gonderen` mikser olanlar).",
           "Çıkış alıcılarını `bilinen_adresler.csv` ile birleştir ve etiketi `BORSA` ile başlayanı seç.",
           "`awk -F, -v m=<MIKSER> 'NR==FNR{e[$1]=$2;next} $3==m && ($4 in e){print e[$4]}' bilinen_adresler.csv "
           "islemler.csv | grep BORSA`"),
          puan=35, baslik="Borsa çıkış noktası"),
    Gorev("O borsanın yatırım adresine **mikserden** gelen tutar kaç ETH? (Başka kaynaklardan gelen yatırımlar sayılmaz.)",
          Sayi("borsa_tutar", sik_hatalar=_btutar_hata),
          ("Yatırım adresine birçok kaynaktan para geliyor; sadece gönderen mikser olanı al.",
           "Hem gönderen (3. sütun) hem alıcı (4. sütun) koşulunu aynı `awk` satırında kullan.",
           "`awk -F, -v m=<MIKSER> -v e=<BORSA_ADRESI> '$3==m && $4==e{s+=$5} END{print s}' islemler.csv`"),
          puan=35, baslik="Yatırılan tutar"),
    Gorev("Borsanın yatırım adresine bir miktar para girdiğini buldun. **En doğru müdahale** hangisi?",
          Secmeli([
              ("Yatırım adresini, tx kodlarını ve zaman çizelgesini borsanın uyum ekibine ilet; dondurma iste, resmî "
               "suç duyurusunu yap",
               "Doğru. Zincirdeki iz delildir; asıl kontrol noktası kimlik doğrulaması yapan borsadır. Hızlı bildirim, "
               "dondurma ve resmî süreç birlikte yürür."),
              ("Saldırganın adresine geri ödeme çağrısı yapan mesajlar göndererek iade için günlerce pazarlık etmeyi dene, "
               "resmî başvuruyu da sonraya bırak ki ortam gerilmesin",
               "Zaman kaybı. Saldırganla pazarlık parayı geri getirmez; her saat paranın borsadan çıkma riski artar, "
               "resmî ve hızlı bildirim öncelik olmalı."),
              ("Mikser adresine saldırıp içindeki bakiyeyi kendi cüzdanına çekerek parayı saldırgandan geri al, böylece "
               "hukuki sürece hiç gerek kalmaz",
               "Yasadışı ve yanlış. Başkasının sistemine kendi başına karşı saldırı (hack-back) suçtur; ayrıca mikserde "
               "başka kişilerin parası da var. Müdahale yasal kanallardan olur."),
              ("Blok zincirinden bu işlemleri silmesi için ağ operatörüne başvur; defter geri alınabildiği için başka "
               "bir işlem gerekmez",
               "Zincir değiştirilemez: yazılan işlem silinmez ve bunu yapacak tek bir operatör yoktur. Para ancak "
               "kayıt tutan aracı kurumlar (borsa) ve resmî makamlar üzerinden dondurulabilir."),
          ]),
          ("Zincirdeki işlemi geri almak mümkün mü? Paranın kontrol altına alınabileceği noktayı düşün.",
           "Borsalar kimlik doğrulaması tutar; dondurma yetkisi onlarda ve yetkili makamlardadır.",
           "Doğru şık: delil (adres, tx kodları) + borsaya bildirim + resmî suç duyurusu."),
          puan=30, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="c22b04",
    cilt=22,
    bolum=4,
    baslik="Para Akışını Takip Et: Zincirde Adli Analiz",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> acil destek istiyor.

Selin elindeki dosyaları uzatıyor: "Kurbanın adresi şu: <<kurban>>. Zincirdeki işlemleri derledik
(`islemler.csv`), analiz ekibinin bildiği adresleri de ayrı bir listeye koyduk. Bana şunu söyle: ne kadar
çalındı, para hangi adreslerden geçti, mikserle izini karıştırmaya çalışmış mı ve **sonunda nerede
durdu**?"

Deniz ekliyor: "Zincirde yazılan geri alınmaz ama **görünür**. Para bir borsaya girdiği anda bir yere kimlikle
bağlanır. İşimiz onu orada yakalayıp dondurma talebini kanıtla göndermek."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Saldırgan açısından zincir bir **kayıt defteri**: her hop, her mikser girişi ve çıkışı
herkese açık yazılı kalır. Mikser izi yalnızca yavaşlatır; para nakde dönmek için bir borsaya girmek
zorunda kalınca kimlik doğrulaması olan bir nokta onu yakalar. Savunmacı açısından üç şey öne çıkar:
**kanıtı hızlı toplamak** (adresler, işlem kodları, zaman çizelgesi), **bilinen adres listelerini**
(borsa, mikser, köprü) güncel tutmak ve **borsalarla önceden kurulmuş iletişim kanalı** bulundurmak, çünkü
dondurma için her saat önemlidir. Çalınan parayı kendi başına geri almaya çalışmak (hack-back) hem yasadışıdır
hem de masum üçüncü kişilere zarar verebilir.
""",
    gercek_hayat="""
- **Zincir analiz firmaları ve soruşturmalar:** Blockchain analiz şirketleri, büyük hırsızlıklarda paranın
  adres adres izini sürer ve bunu kolluk ve borsalarla paylaşır. ABD makamlarının 2016 Bitfinex hırsızlığıyla
  ilgili 2022'de yaptığı el koymada da izleme ve borsa kayıtlarının birlikte kullanıldığı kamuya açık
  anlatılmıştır; ders: iz zincirde kalır, kimlik ise çoğu zaman borsada ortaya çıkar.
- **Mikserlere yaptırım (2022):** ABD Hazine Bakanlığı (OFAC), Ağustos 2022'de Tornado Cash adlı mikser
  hizmetine yaptırım uyguladı; bu hizmet, büyük hırsızlıklardan çıkan paranın izini karıştırmakta kullanılıyordu.
  Ders: borsalar ve analistler yaptırım listelerindeki adreslere gelen/giden paraları işaretleyebilir; bu da
  tespit ve önlem için bir araçtır.
- **Hazırlık:** İyi hazırlanmış bir kurum, olaydan önce borsalardaki uyum ekipleriyle iletişim kanalını, adres
  listesini ve olay müdahale planını hazır tutar. Dondurma talebi ne kadar hızlı ve belgeli giderse para o kadar
  yakalanabilir. Kimlik doğrulaması yapan düzenlemeye tabi kuruluşlarda bu süreç hukuki yollarla yürütülür.
""",
    sure_hedef_dk=25,
)
