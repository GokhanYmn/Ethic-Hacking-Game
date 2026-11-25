"""Cilt 21 · Bölüm 1 — Dolandırıcılık Türleri.

Beceri: kurgusal vaka açıklamalarını türlere eşlemek (hesap ele geçirme, kart testi, iade
dolandırıcılığı, sahte hesap, sosyal mühendislik) ve her türün veri üzerindeki izini bulmak.
Fraud "sistem kırıldı mı?" değil, "bu işlem/davranış meşru mu?" sorusudur.

Vakalar: Ferah Bank (internet şubesi), Pazarix (e-ticaret), Paramix (ödeme altyapısı).
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, csv_yaz, sec_doldur, sh

TURLER = {
    "a": "Hesap ele geçirme (ATO): meşru hesabın kontrolünü çalmak",
    "b": "Kart testi: çalıntı kart numaralarının çalışıp çalışmadığını küçük tutarlarla denemek",
    "c": "İade dolandırıcılığı: iade sürecini kötüye kullanıp parayı/malı almak",
    "d": "Sahte hesap açma (kimlik dolandırıcılığı): uydurma ya da çalıntı kimlikle hesap açmak",
    "e": "Sosyal mühendislik dolandırıcılığı: kurbanı kandırıp parayı kendi eliyle gönderttirmek",
}

VAKALAR = [
    {"kod": "ferahbank", "onek": "FB", "kisi": "Kaan Bey", "kanal": "internet şubesi",
     "olay": "Ferah Bank'ın internet şubesinde son haftada müşteri şikâyetleri arttı ve çağrı merkezi "
             "\"parayı ben göndermedim\" diyen müşterilerle doldu."},
    {"kod": "pazarix", "onek": "PZ", "kisi": "Tuncay Bey", "kanal": "e-ticaret sitesi",
     "olay": "Pazarix'te kampanya haftasından sonra kayıp ürün, geri ödeme ve şüpheli üyelik şikâyetleri üst "
             "üste geldi."},
    {"kod": "paramix", "onek": "PM", "kisi": "Ece Hanım", "kanal": "ödeme altyapısı",
     "olay": "Paramix'in üye işyerleri, sanal POS'larında kimsenin tanımadığı işlemler ve olağandışı "
             "reddedilen ödemeler gördüklerini bildirdi."},
]

# Her tür için üç vaka şablonu (vaka sırasıyla ferahbank, pazarix, paramix)
OYKULER = {
    "a": [
        "Müşteri {k1} yıllardır hep aynı telefondan giriş yapıyordu. Salı gecesi tanımadığı bir cihazdan, yurt "
        "dışı bir IP'den giriş yapıldı; hemen ardından şifre değiştirildi ve hesaptaki para yeni bir alıcıya gitti.",
        "{k1} adlı üyenin hesabına, daha önce hiç kullanmadığı bir cihazdan girildi; e-posta adresi ve şifre "
        "değiştirildi, kayıtlı kartla pahalı ürünler sipariş edildi. Gerçek üye hesabına giremediğini söylüyor.",
        "Üye işyeri {k1}'in panel hesabına bilinmeyen bir cihazdan girildi, şifre sıfırlandı ve hesap IBAN'ı "
        "değiştirildi. Bir sonraki hakediş ödemesi yeni IBAN'a çıktı.",
    ],
    "b": [
        "Bir IP'den birkaç dakikada yüzlerce farklı kartla 1-2 TL'lik işlem denendi. Çoğu reddedildi; "
        "birkaçı onaylandı. Ardından o onaylanan kartlarla büyük tutarlı alışverişler başladı.",
        "Sitenin ödeme sayfasında, aynı IP'den çok sayıda farklı kartla 1 TL'lik \"bağış\" ürünü satın alınmaya "
        "çalışıldı. Reddedilenler çok, onaylananlar azdı; kart sahipleri henüz şikâyet etmemişti.",
        "Sanal POS'ta kısa sürede çok sayıda farklı kart numarasıyla küçük tutarlı denemeler geldi. "
        "Banka kodları çeşitliydi, reddedilme oranı çok yüksekti ve denemeler tek bir IP'den yapılıyordu.",
    ],
    "c": [
        "Bir müşteri son dört ayda 12 kez \"kartım kopyalandı, işlemi tanımıyorum\" diyerek itiraz etti; "
        "itirazların tamamı aynı iş yerlerine aitti ve parası iade edildi. Müşterinin cihazı hep aynıydı.",
        "Bir üye onlarca siparişin neredeyse tamamında \"ürün elime ulaşmadı\" deyip para iadesi aldı, "
        "ama kargo kayıtları teslimatı gösteriyor. İade oranı diğer üyelerin kat kat üstünde.",
        "Bir üye işyeri, yüksek tutarlı satışlarının çoğunda ödeme itirazı (chargeback) aldı. Kart sahipleri "
        "\"almadım\" diyor; üye işyeri sevk belgesi gösteremiyor, itirazlar aynı kart gruplarından geliyor.",
    ],
    "d": [
        "Bir hafta içinde aynı cihazdan, aynı telefon numarasına yakın bilgilerle, farklı isimlerde 9 hesap "
        "açıldı. Kimlik bilgileri tutarsızdı ve hesaplar kredi limiti açılır açılmaz kullanılıp bırakıldı.",
        "Hoş geldin kuponu kampanyasında aynı cihazdan onlarca üyelik açıldı, kuponlar kullanıldı ve hesaplar "
        "hiç alışveriş yapılmadan terk edildi. E-posta adreslerinin hepsi aynı kalıba uyuyordu.",
        "Çok sayıda yeni üye işyeri başvurusu aynı cihazdan, uydurma vergi bilgileriyle yapıldı; "
        "hesaplar onaylanır onaylanmaz kısa sürede yüksek hacimli işlem yapıp kayboldu.",
    ],
    "e": [
        "Müşteri {k1}, kendi telefonundan, doğru şifre ve doğru onay koduyla bir havale yaptı. Birkaç saat önce "
        "\"banka güvenlik birimi\" olduğunu söyleyen biri onu aramış ve parasını \"güvenli hesaba\" taşımasını "
        "istemişti. Cihaz da, konum da müşteriye ait.",
        "Üye {k1}, kendi hesabından, kendi cihazıyla bir \"yatırım danışmanı\"nın verdiği hesaba ödeme yaptı. "
        "Sonradan danışmanın sahte olduğunu fark etti. Sistem açısından her şey olağan görünüyor.",
        "Üye işyeri çalışanı {k1}, \"genel müdürlük\" adına gelen bir e-postaya inanıp panelden kendi eliyle "
        "acil bir ödeme talimatı verdi. Giriş meşru, onay meşru, yalnızca talimatın gerekçesi yalan.",
    ],
}

SIK_HATA = {  # hangi iki tür birbirine karışır
    frozenset("ae"): "Hesap ele geçirme (a) ile sosyal mühendislik (e) sık karışır. Fark: ele geçirmede cihaz/konum "
                     "yabancıdır; sosyal mühendislikte işlemi hesabın gerçek sahibi, kendi cihazından yapar.",
    frozenset("bd"): "Kart testi (b) çok sayıda kartın denenmesidir; sahte hesap (d) çok sayıda hesabın açılmasıdır. "
                     "Vakada denenen şey kart mı, hesap mı?",
    frozenset("ac"): "İade dolandırıcılığında (c) hesap ele geçirilmez; hesabın sahibi iade sürecini kötüye kullanır.",
}


def _kisiler(rng, n):
    return u.isimler(rng, n)


def veri_uret(rng: random.Random, v: dict) -> dict:
    """Dört CSV'nin içeriği ve cevapları. Aynı rng aynı veriyi üretir."""
    onek = v["onek"]
    gun = u.gun(rng)
    # ---- giris_kayitlari.csv (ATO)
    hesaplar = [f"{onek}-{rng.randint(1000, 9999)}" for _ in range(60)]
    hesaplar = list(dict.fromkeys(hesaplar))[:40]
    ev = {h: (f"cihaz-{rng.randrange(16**5):05x}", u.dis_ip(rng)) for h in hesaplar}
    satirlar = []
    for h in hesaplar:
        for _ in range(rng.randint(3, 7)):
            t = gun - timedelta(days=rng.randint(0, 4)) + timedelta(seconds=rng.randint(8 * 3600, 22 * 3600))
            satirlar.append((t, h, "giris_basarili", ev[h][1], "TR", ev[h][0]))
    ato, gezgin, *normal_sifre = rng.sample(hesaplar, 5)
    for h in normal_sifre:                               # kendi cihazından şifre değiştirenler (yanlış alarm)
        t = gun - timedelta(hours=rng.randint(2, 70))
        satirlar.append((t, h, "giris_basarili", ev[h][1], "TR", ev[h][0]))
        satirlar.append((t + timedelta(minutes=2), h, "sifre_degisti", ev[h][1], "TR", ev[h][0]))
    t = gun - timedelta(hours=rng.randint(5, 40))        # yurt dışından giriş yapan ama şifre değiştirmeyen
    satirlar.append((t, gezgin, "giris_basarili", u.dis_ip(rng), "DE", f"cihaz-{rng.randrange(16**5):05x}"))
    yeni_cihaz, yeni_ip = f"cihaz-{rng.randrange(16**5):05x}", u.dis_ip(rng)
    ulke = rng.choice(["RO", "NL", "US", "AE", "GB"])
    t = gun - timedelta(hours=rng.randint(3, 20))
    for i in range(rng.randint(3, 6)):                    # önce başarısız denemeler
        satirlar.append((t + timedelta(seconds=i * 7), ato, "giris_basarisiz", yeni_ip, ulke, yeni_cihaz))
    t += timedelta(minutes=1)
    satirlar.append((t, ato, "giris_basarili", yeni_ip, ulke, yeni_cihaz))
    satirlar.append((t + timedelta(minutes=1), ato, "sifre_degisti", yeni_ip, ulke, yeni_cihaz))
    satirlar.append((t + timedelta(minutes=4), ato, "para_cikisi", yeni_ip, ulke, yeni_cihaz))
    satirlar.sort(key=lambda x: x[0])
    giris = [f"{t:%Y-%m-%d %H:%M:%S},{h},{o},{ip},{ul},{c}" for t, h, o, ip, ul, c in satirlar]
    # ---- kart_denemeleri.csv
    sald_ip = u.dis_ip(rng)
    yogun_ip = u.benzersiz(rng, u.dis_ip, 1, {sald_ip})[0]
    diger_ipler = u.benzersiz(rng, u.dis_ip, 60, {sald_ip, yogun_ip})
    kartlar = [f"{rng.randint(4000, 5599)}-****-{rng.randint(1000, 9999)}" for _ in range(400)]
    kartlar = list(dict.fromkeys(kartlar))
    n_kart = rng.randint(70, 110)
    kart_satir = []
    t0 = gun + timedelta(hours=rng.randint(1, 5))
    for i in range(n_kart + 25):                          # bazı kartlar iki kez denendi
        k = kartlar[i % n_kart]
        sonuc = "onay" if rng.random() < 0.08 else "red"
        kart_satir.append((t0 + timedelta(seconds=i * rng.randint(1, 3)), k, sald_ip,
                           f"{rng.choice([1, 1, 2]):.2f}", sonuc))
    for i in range(70):                                   # kurumsal çıkış IP'si: çok satır, az kart, normal tutar
        k = kartlar[300 + rng.randint(0, 5)]
        kart_satir.append((gun + timedelta(seconds=rng.randint(9 * 3600, 18 * 3600)), k, yogun_ip,
                           f"{rng.randint(300, 4500)}.00", "onay"))
    for _ in range(160):
        kart_satir.append((gun + timedelta(seconds=rng.randint(8 * 3600, 23 * 3600)), rng.choice(kartlar[150:290]),
                           rng.choice(diger_ipler), f"{rng.randint(40, 2500)}.00", rng.choice(["onay"] * 9 + ["red"])))
    kart_satir.sort(key=lambda x: x[0])
    kart = [f"{t:%Y-%m-%d %H:%M:%S},{k},{ip},{tu},{s}" for t, k, ip, tu, s in kart_satir]
    # ---- iadeler.csv
    kul = [f"M{rng.randint(10000, 99999)}" for _ in range(60)]
    kul = list(dict.fromkeys(kul))[:45]
    iade = []
    hileci, kucuk = kul[0], kul[1]
    for m in kul:
        if m == hileci:
            sip = rng.randint(12, 16)
            ia = sip - rng.randint(0, 2)
        elif m == kucuk:
            sip, ia = 1, 1                                # %100 ama tek sipariş (örneklem küçük)
        elif m == kul[2]:
            sip, ia = rng.randint(30, 40), rng.randint(12, 16)   # çok sipariş, makul iade
        else:
            sip = rng.randint(3, 25)
            ia = rng.randint(0, max(1, sip // 6))
        iade.append(f"{m},{sip},{ia},{ia * rng.randint(150, 900)}")
    rng.shuffle(iade)
    # ---- yeni_hesaplar.csv
    ana = f"cihaz-{rng.randrange(16**5):05x}"
    aile = f"cihaz-{rng.randrange(16**5):05x}"
    n_ana = rng.randint(9, 14)
    yeni = []
    kisi = _kisiler(rng, 30)
    def hesap_satiri(cihaz, i):
        t = gun - timedelta(days=rng.randint(0, 6), hours=rng.randint(0, 10))
        return f"{onek}-N{rng.randint(10000, 99999)},{t:%Y-%m-%d},{cihaz},0{rng.randint(530, 539)}{rng.randint(100, 999)}{rng.randint(1000, 9999)},{rng.choice(['evet', 'evet', 'hayir'])}"
    for i in range(n_ana):
        yeni.append(hesap_satiri(ana, i))
    for i in range(3):
        yeni.append(hesap_satiri(aile, i))
    for i in range(90):
        yeni.append(hesap_satiri(f"cihaz-{rng.randrange(16**5):05x}", i))
    rng.shuffle(yeni)
    return {
        "giris": giris, "kart": kart, "iade": iade, "yeni": yeni,
        "ato": ato, "gezgin": gezgin, "normal_sifre": normal_sifre,
        "kart_sayi": n_kart, "kart_satir_sayi": n_kart + 25, "sald_ip": sald_ip, "yogun_ip": yogun_ip,
        "hileci": hileci, "kucuk": kucuk, "n_ana": n_ana,
    }


def uret(rng):
    vi = rng.randrange(len(VAKALAR))
    v = dict(VAKALAR[vi])
    m = musteri(v["kod"])
    veri_tohum = rng.randint(1, 10**9)
    d = veri_uret(random.Random(veri_tohum), v)
    kodlar = list("abcde")
    rng.shuffle(kodlar)
    k1 = [u.ISIMLER[rng.randrange(len(u.ISIMLER))].capitalize() + " " + rng.choice(["Yılmaz", "Demir", "Şahin", "Çelik", "Koç"])
          for _ in range(5)]
    return {
        "vaka": f"{m['ad']} — {v['kanal']} şikâyetleri",
        "musteri": m, "v": v, "veri_tohum": veri_tohum, "kodlar": kodlar, "kisiler": k1,
        "metin": {"musteri": m["ad"], "kisi": v["kisi"], "olay": v["olay"], "kanal": v["kanal"],
                  "kanal_k": v["kanal"]},
        "cevaplar": {
            "dizi": kodlar,
            "ato": d["ato"],
            "kart_sayi": d["kart_sayi"],
            "iade": d["hileci"],
            "sahte": d["n_ana"],
        },
        "_d": {x: d[x] for x in ("gezgin", "normal_sifre", "kart_satir_sayi", "yogun_ip", "kucuk")},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    vi = [x["kod"] for x in VAKALAR].index(v["kod"])
    d = veri_uret(random.Random(s["veri_tohum"]), v)
    for i, kod in enumerate(s["kodlar"], 1):
        sablon = OYKULER[kod][vi]
        u.yaz(lab / "vakalar" / f"vaka_{i}.txt",
              f"VAKA {i} — {v['kanal']}\n\n" + sablon.format(k1=s["kisiler"][i - 1]) + "\n")
    csv_yaz(lab / "veri" / "giris_kayitlari.csv", "zaman,hesap,olay,ip,ulke,cihaz", d["giris"])
    csv_yaz(lab / "veri" / "kart_denemeleri.csv", "zaman,kart,ip,tutar,sonuc", d["kart"])
    csv_yaz(lab / "veri" / "iadeler.csv", "musteri,siparis_sayisi,iade_sayisi,iade_tutari", d["iade"])
    csv_yaz(lab / "veri" / "yeni_hesaplar.csv", "hesap,acilis_tarihi,cihaz,telefon,bonus_cekildi", d["yeni"])
    tur_metni = "\n".join(f"  {k}) {t}" for k, t in TURLER.items())
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — dolandırıcılık analiz klasörü (hepsi kurgusal veri)\n\n"
          f"vakalar/vaka_1.txt ... vaka_5.txt : şikâyet özetleri\n"
          f"veri/giris_kayitlari.csv          : hesap girişleri ve hesap olayları\n"
          f"veri/kart_denemeleri.csv          : ödeme denemeleri (kart numaraları maskeli ve kurgusal)\n"
          f"veri/iadeler.csv                  : müşteri başına sipariş ve iade sayısı\n"
          f"veri/yeni_hesaplar.csv            : yeni açılan hesaplar\n\n"
          f"Dolandırıcılık türleri:\n{tur_metni}\n")


def _dizi_hata(verilen, beklenen, b):
    if len(verilen) != len(beklenen):
        return None
    yanlis = [(a, c) for a, c in zip(verilen, beklenen) if a != c]
    if len(yanlis) == 2 and yanlis[0] == yanlis[1][::-1]:
        return SIK_HATA.get(frozenset(yanlis[0]))
    return None


def _ato_hata(g, beklenen, b):
    if g in [x.lower() for x in b.senaryo["_d"]["normal_sifre"]]:
        return ("Bu hesap şifresini değiştirmiş ama kendi alışıldık cihazından ve Türkiye'den. Şifre değişikliğinin "
                "**hemen öncesindeki girişin** cihazı ve ülkesi bilinmeyen biriydi.")
    if g == b.senaryo["_d"]["gezgin"].lower():
        return "Bu hesap yurt dışından girmiş ama şifresini değiştirmemiş: büyük olasılıkla tatildeki müşteri."
    return None


def _kart_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["_d"]["kart_satir_sayi"]:
        return "Satır sayısını saymışsın; bazı kartlar iki kez denenmiş. **Farklı** kart sayısı için `sort -u` kullan."
    return None


def _iade_hata(g, beklenen, b):
    if g == b.senaryo["_d"]["kucuk"].lower():
        return "Bu müşterinin tek siparişi var ve onu iade etmiş (%100); örneklem çok küçük. Yeterli sipariş geçmişi ara."
    return None


def _sahte_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == 3:
        return "3 hesaplı cihaz muhtemelen aile ya da ortak kullanılan bir telefon. En çok hesap açılan cihazı bul."
    if n == beklenen + 1 or n == beklenen - 1:
        return "Bir sayı kaymış: başlık satırını saymış ya da bir hesabı atlamış olabilirsin."
    return None


def coz(lab: Path, s: dict) -> dict:
    ato = sh("awk -F, '$3==\"sifre_degisti\"{print $2}' veri/giris_kayitlari.csv | sort -u | while read h; do "
             "grep \",$h,giris_basarili,\" veri/giris_kayitlari.csv | grep -v ',TR,' | cut -d, -f2; done | sort -u", lab)
    ip = sh("awk -F, '$4==\"1.00\"||$4==\"2.00\"{c[$3]++} END{for(i in c) if(c[i]>50) print i}' "
            "veri/kart_denemeleri.csv", lab)
    kart = sh(f"grep -F ',{ip},' veri/kart_denemeleri.csv | cut -d, -f2 | sort -u | wc -l", lab)
    iade = sh("awk -F, 'NR>1 && $2>=10 && $3/$2>0.7{print $1}' veri/iadeler.csv", lab)
    sahte = sh("cut -d, -f3 veri/yeni_hesaplar.csv | tail -n +2 | sort | uniq -c | sort -rn | head -1 | awk '{print $1}'", lab)
    cozum = {1: " ".join(s["kodlar"]), 2: ato, 3: kart, 4: iade, 5: sahte}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Fraud, hacking değildir", """
Selin: "Bugün sistem kırmıyoruz. Dolandırıcı sistemi **olması gerektiği gibi** kullanır, ama hileli
bir amaçla. Bu yüzden güvenlik duvarı da, imza tabanlı antivirüs de onu yakalamaz; ortada
'kötü bir dosya' yok, **olağandışı bir davranış** var."

Klasörün haritasına bak:
""", komut="cat OKUBENI.txt", sonra="""
Beş tür var. Çoğu teknik bir açık değil, iş mantığının ve insanın kötüye kullanımıdır.
Aklında şu soru kalsın: "Bu işlem meşru mu?"
"""),
    Adim("Vakaları okumak", """
Önce şikâyet özetlerinden biri. Her vakada türü ele veren **ipuçları** vardır: kimin cihazı,
kaç hesap, kaç kart, kimin elinden çıkmış işlem?
""", komut="cat vakalar/vaka_1.txt", sonra="""
Ayrımı cihazdan, sayıdan ve niyetten yap: yabancı cihaz = ele geçirme; çok kart = kart testi;
aynı cihazda çok hesap = sahte hesap; kurban kendi elleriyle yaptıysa sosyal mühendislik.
"""),
    Adim("Hesap ele geçirme izi", """
Hesap ele geçirmenin (ATO, account takeover) klasik izi: **yabancı cihaz + şifre değişikliği +
para çıkışı**, sırayla ve kısa sürede. Giriş kayıtlarında kaç şifre değişikliği var?
""", komut="grep -c sifre_degisti veri/giris_kayitlari.csv", sonra="""
Hepsi saldırı değil: insanlar kendi cihazından şifresini değiştirir. Ayırt eden, şifre
değişikliğinden **hemen önceki girişin** cihazı ve ülkesidir.
"""),
    Adim("Kart testi izi", """
Çalıntı bir kart listesini alan dolandırıcı, hangilerinin çalıştığını 1-2 TL'lik denemelerle
yoklar. İz: **tek IP, çok sayıda farklı kart, küçük tutar, çok red**. IP başına satır sayısı:
""", komut="cut -d, -f3 veri/kart_denemeleri.csv | tail -n +2 | sort | uniq -c | sort -rn | head -3", sonra="""
En üstteki IP'lerden biri kurumsal bir çıkış noktası (çok satır ama az kart, normal tutar).
Sadece satır sayısına değil, **farklı kart sayısına** ve tutara da bak.
"""),
    Adim("İade ve sahte hesap verileri", """
İadelerde oran önemlidir: bir müşterinin 1 siparişi 1 iade ise oran %100'dür ama bu kanıt değil,
örneklem küçüktür. Sahte hesapta ise ortak **cihaz**, **telefon** ya da **e-posta kalıbı** aranır.
Dosyaların biçimine bak:
""", komut="head -4 veri/iadeler.csv veri/yeni_hesaplar.csv"),
    Adim("awk ile oran hesaplamak", """
`awk -F,` CSV'yi virgülden böler; `$2` ikinci sütun, `NR>1` başlık satırını atlar. Bir koşul
yazıp eşleşen satırları yazdırabilirsin. Toplam sipariş sayısı:
""", komut="awk -F, 'NR>1{t+=$2} END{print t}' veri/iadeler.csv", sonra="""
**Hacker gözüyle:** Dolandırıcı da kuralları öğrenir. Eşiğin altında kalır, tek cihaz yerine
cihaz havuzu kullanır. Bu yüzden tek bir göstergeye değil **birkaç göstergenin birleşimine**
bakılır: cihaz + ülke + şifre değişikliği + tutar. Finans bilgin burada avantajın: "normal bir
havale ya da iade neye benzer?" sorusunun cevabını sen biliyorsun.
"""),
]

GOREVLER = [
    Gorev("`vakalar/` klasöründeki 5 vakayı oku ve `OKUBENI.txt`'deki türlere eşle. Cevap: vaka 1'den 5'e "
          "sırayla tür harfleri (örn. `c a e b d`).",
          Dizi("dizi", sik_hatalar=_dizi_hata),
          ("Her vakada kimin cihazı, kaç kart/hesap ve kimin niyeti olduğunu işaretle.",
           "`cat vakalar/vaka_*.txt` hepsini sırayla gösterir. Türü ele veren kelimeler: yabancı cihaz, çok kart, aynı "
           "cihaz, kendi elleriyle.",
           "Kod listesi: `a` ele geçirme, `b` kart testi, `c` iade, `d` sahte hesap, `e` sosyal mühendislik. "
           "Beş harfi boşlukla yaz."),
          puan=40, baslik="Vaka eşleme"),
    Gorev("`veri/giris_kayitlari.csv`'de bir hesap ele geçirilmiş: tanımadığı bir **yabancı ülke ve cihazdan** "
          "girilmiş, hemen ardından şifre değiştirilmiş. Hesap numarası?",
          Metin("ato", sik_hatalar=_ato_hata, bicim="hesap no (örn. XX-1234)"),
          ("Önce şifre değişikliği olan hesapları listele; sonra her birinin önceki girişinin ülkesine bak.",
           "`grep sifre_degisti veri/giris_kayitlari.csv` ile adayları çıkar; her aday için `grep HESAP "
           "veri/giris_kayitlari.csv` ile satırlarını oku.",
           "Ülkesi TR olmayan bir `giris_basarili` satırı olan adayı ara: `grep HESAP veri/giris_kayitlari.csv | "
           "grep -v ',TR,'`"),
          puan=40, baslik="Ele geçirilen hesap"),
    Gorev("`veri/kart_denemeleri.csv`'de kart testi yapan IP'yi bul. Bu IP kaç **farklı kart** denedi?",
          Sayi("kart_sayi", sik_hatalar=_kart_hata),
          ("Küçük tutarlı (1.00 / 2.00) çok sayıda satırı olan IP'yi bul; kurumsal IP'ye kanma.",
           "IP'nin satırlarını `grep -F ',IP,'` ile süz, kart sütununu (`cut -d, -f2`) çıkar, tekrarları at "
           "(`sort -u`).",
           "`grep -F ',IP,' veri/kart_denemeleri.csv | cut -d, -f2 | sort -u | wc -l`"),
          puan=40, baslik="Kart testi"),
    Gorev("`veri/iadeler.csv`: iade dolandırıcılığı yapan müşteri hangisi? (En az 10 siparişi olan ve iade "
          "oranı %70'in üstünde olan tek müşteri.)",
          Metin("iade", sik_hatalar=_iade_hata, bicim="müşteri no (örn. M12345)"),
          ("Oran = iade sayısı / sipariş sayısı. Ama az siparişli müşteriyi eleyen bir koşul da gerek.",
           "`awk -F, 'NR>1 && koşul {print $1}' veri/iadeler.csv` biçiminde; koşulda `$2` ve `$3` kullan.",
           "`awk -F, 'NR>1 && $2>=10 && $3/$2>0.7{print $1}' veri/iadeler.csv`"),
          puan=35, baslik="İade oranı"),
    Gorev("`veri/yeni_hesaplar.csv`: sahte hesap açan kişi aynı cihazdan çok sayıda hesap açmış. En çok hesap "
          "açılan cihazdan **kaç hesap** açılmış?",
          Sayi("sahte", sik_hatalar=_sahte_hata),
          ("Hesapları cihaza göre grupla ve say; en kalabalık grubu bul.",
           "Cihaz 3. sütun: `cut -d, -f3`. Başlık satırını `tail -n +2` ile at.",
           "`cut -d, -f3 veri/yeni_hesaplar.csv | tail -n +2 | sort | uniq -c | sort -rn | head -3`"),
          puan=35, baslik="Cihaz kümesi"),
    Gorev("Fraud ile klasik hacking arasındaki temel fark nedir?",
          Secmeli([
              ("Dolandırıcı sistemi olması gerektiği gibi kullanır ama hileli bir amaçla; hacker sistemi kırar",
               "Doğru. Fraud'da teknik bir 'imza' yoktur; işlem meşru görünür, anormal olan davranış ve bağlamdır."),
              ("Fraud yalnızca bankalarda olur, hacking ise yalnızca web sitelerinde",
               "Her ikisi de her sektörde görülür; fark sektörde değil yöntemde."),
              ("Fraud'da saldırgan her zaman zararlı yazılım kullanır, hacking'de kullanmaz",
               "Fraud'ın büyük kısmı zararlı yazılım gerektirmez; hesabın kendi işlevleri kullanılır."),
              ("Hacker kimlik bilgisi kullanmaz, dolandırıcı yalnızca kimlik bilgisiyle çalışır",
               "Her ikisi de çalıntı kimlik bilgisi kullanabilir; ayrım bu değil."),
          ]),
          ("Vakalardaki dolandırıcıların hiçbirinin bir sunucuyu kırmadığını düşün.",
           "Ele geçirme, iade, sosyal mühendislik: hepsinde sistemin normal özellikleri kullanıldı.",
           "Fark kırmak ile kötüye kullanmak arasındadır."),
          puan=25, baslik="Fraud nedir"),
    Gorev("Sosyal mühendislik vakasında (kurban kendi cihazında, doğru şifre ve kodla havale yaptı) "
          "**hesap ele geçirme kuralları** neden işe yaramaz?",
          Secmeli([
              ("Cihaz, konum ve kimlik doğrulama meşrudur; anormal olan işlemin gerekçesi ve alıcıdır",
               "Doğru. Bu yüzden alıcı yeniliği, tutar ve acele davranışı gibi bağlam göstergeleri ve müşteriyi "
               "uyaran sürtünme (uyarı ekranı, bekleme) gerekir."),
              ("Çünkü saldırgan sunucuyu kırmıştır ve loglar silinmiştir",
               "Vakada sunucu kırılmadı; her şey kurbanın kendi oturumunda oldu."),
              ("Çünkü kurban işlemi hiç yapmamıştır",
               "Tersine: işlemi kurban kendisi yaptı, bu yüzden 'yabancı cihaz' sinyali yoktur."),
              ("Çünkü ele geçirme kuralları yalnızca kartlı işlemlerde çalışır",
               "Kuralların kapsamı kanala göre değişebilir ama sorun bu değil; sinyallerin hiçbiri tetiklenmiyor."),
          ]),
          ("Ele geçirme kuralları hangi sinyallere bakar? Bu vakada o sinyaller ne durumda?",
           "Cihaz, konum, şifre değişikliği: hepsi 'normal'.",
           "Anormali nerede arayacağını düşün: alıcı, tutar, işlemin amacı."),
          puan=25, baslik="Kurallar neden kaçırır"),
]

SEVIYE = Seviye(
    kimlik="c21b01",
    cilt=21,
    bolum=1,
    baslik="Dolandırıcılık Türleri",
    brifing="""
Selin yeni bir masa açtı: "Bugün klasik pentest yok. **<<musteri>>**: <<olay>> <<kisi>> bir
dolandırıcılık analiz ekibi kurmak istiyor ama önce herkesin aynı dili konuşmasını istiyor."

Deniz dosyaları getirdi: "Beş şikâyet özeti ve dört veri dosyası var. Önce şikâyetleri doğru
türe oturtalım, sonra her türün veri üzerindeki parmak izini bulalım." Mert ekliyor: "Burada
kimse sunucuyu kırmadı. Soru 'sistem kırıldı mı?' değil, 'bu işlem meşru mu?'"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Beş vaka, beş farklı dolandırıcılık ve hiçbirinde bir sunucu kırılmadı. Her türün veri üzerinde
ayrı bir parmak izi var: yabancı cihazla şifre değişikliği, tek IP'den çok kart, aşırı iade oranı,
tek cihazda çok hesap, ve kurbanın kendi eliyle yaptığı işlem. Saldırgan perspektifi: iz bırakmamak
için normal kullanıcı gibi davranır, eşiklerin altında kalır. Savunma perspektifi: tek bir sinyale
güvenme, bağlamı birleştir; normalin neye benzediğini bilen (finans bilgisi olan) analist, yanlış
alarmı da gerçek dolandırıcılığı da daha hızlı ayırır.
""",
    gercek_hayat="""
- **Kart testi (carding):** Ödeme sektörü, çalıntı kart listelerinin çok küçük tutarlı işlemlerle
  denendiğini uzun zamandır bilir. Tespit: tek IP/cihazdan çok sayıda farklı kart ve yüksek red oranı;
  önlem: hız sınırı, CAPTCHA, düşük tutarlı işlemlere de 3D Secure ve kara liste.
- **Sosyal mühendislik ve "güvenli hesap" oyunu:** Kurbanı arayıp parasını başka hesaba taşımaya ikna
  etmek pek çok ülkede bankaların karşılaştığı yaygın bir dolandırıcılık biçimidir. Teknik sinyaller temiz
  olduğundan önlem; yeni alıcıya yüksek tutarlı havalede uyarı, bekleme süresi ve müşteri eğitimidir.
- **Sahte hesap ve kampanya suistimali:** Hoş geldin bonusu veren platformlar, aynı cihazdan açılan
  çok sayıda hesabı izler. Cihaz parmak izi, telefon/e-posta kalıbı ve ilk işlem davranışı birlikte
  değerlendirilir; tek başına hiçbiri kesin kanıt sayılmaz.
""",
    sure_hedef_dk=30,
)
