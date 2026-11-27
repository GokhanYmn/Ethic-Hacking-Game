"""Cilt 23 · Bölüm 4 — KVKK ve Veri Sızıntısı: Açıkta Kalan Kişisel Veriyi Bulmak.

Beceri: log, dışa aktarım ve not dosyalarında **maskelenmemiş kişisel veriyi** (TC kimlik no, kart no, telefon,
e-posta) `grep -E` ile bulmak, kaç kayıt / kaç farklı kişi etkilendiğini saymak ve hassasiyetine göre sınıflamak.

ETİK: Tüm veriler KURGUSALDIR. Üretilen TC kimlik numaraları 11 hanelidir ama **TCKN sağlama algoritmasını
bilerek geçmez** (son hane her zaman yanlış); gerçek bir kişiye ait olamaz. Kart numaraları `99` ile başlar ve
Luhn sağlamasını geçmez; gerçek/çalışan bir kart deseni değildir. E-postalar `.lab`, telefonlar kurgusaldır.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem `yaz`, aynı
`_akis(alt)` ile veriyi yeniden üretir. (`_tohum` motor tarafından üzerine yazıldığı için ayrı anahtar.)
Bu modüldeki üretici, `hy.olay_masasi.olay_kvkk` tarafından da kullanılır.
"""
from __future__ import annotations

import random
import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

# ---------------------------------------------------------------------------------------------- desenler
TC_RE = re.compile(r"(?<![0-9A-Za-z_])[1-9][0-9]{10}(?![0-9A-Za-z_])")
KART_RE = re.compile(r"(?<![0-9A-Za-z_])[0-9]{16}(?![0-9A-Za-z_])")
TEL_RE = re.compile(r"(?<![0-9A-Za-z_])05[0-9]{9}(?![0-9A-Za-z_])")
EPOSTA_RE = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+")
TC_GREP = r"\b[1-9][0-9]{10}\b"
KART_GREP = r"\b[0-9]{16}\b"
TEL_GREP = r"\b05[0-9]{9}\b"
EPOSTA_GREP = r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+"

DOSYA_ADLARI = {"app": "uygulama.log", "debug": "hata_ayiklama.log", "export": "disa_aktarim.csv",
                "notes": "destek_notlari.txt"}
ROLLER = list(DOSYA_ADLARI)

SOYADLAR = [("Yılmaz", "yilmaz"), ("Kaya", "kaya"), ("Demir", "demir"), ("Şahin", "sahin"), ("Çelik", "celik"),
            ("Yıldız", "yildiz"), ("Aydın", "aydin"), ("Özdemir", "ozdemir"), ("Arslan", "arslan"),
            ("Doğan", "dogan"), ("Kılıç", "kilic"), ("Aslan", "aslan"), ("Çetin", "cetin"), ("Koç", "koc")]
ISIM_GOSTER = {"ayse": "Ayşe", "busra": "Büşra", "baris": "Barış", "pinar": "Pınar", "nazli": "Nazlı",
               "ugur": "Uğur", "irem": "İrem"}
SOKAKLAR = ["Lale Sk.", "Menekşe Sk.", "Çınar Cd.", "Akasya Sk.", "Defne Sk.", "Papatya Cd.", "Kestane Sk.",
            "Mimoza Sk.", "Ihlamur Cd.", "Zambak Sk."]
ILCELER = ["Çankaya/Ankara", "Kadıköy/İstanbul", "Bornova/İzmir", "Nilüfer/Bursa", "Seyhan/Adana",
           "Konak/İzmir", "Beşiktaş/İstanbul", "Muratpaşa/Antalya"]

GENEL_GURULTU = [
    "healthcheck ok sure={ms}ms", "cache temizlendi anahtar_sayisi={n}", "yapilandirma yeniden yuklendi surum=v{v}",
    "baglanti havuzu bos={n} dolu={v}", "zamanlanmis gorev tamamlandi sure={ms}ms",
]
GENEL_NOT = ["Yazıcı kuyruğu temizlendi, sorun giderildi.", "VPN şifre sıfırlama talebi tamamlandı.",
             "Haftalık yedek kontrolü yapıldı, hata yok.", "Toplantı odası ekranı için ikinci kablo istendi.",
             "Lisans yenileme hatırlatması: yıl sonuna kadar karar verilecek."]

SENARYOLAR = [
    {"kod": "tip", "musteri": "Derya Tıp Merkezi", "sektor": "özel hastane",
     "kisi": "Bilgi güvenliği sorumlusu Aylin Hanım",
     "hikaye": "Randevu sistemini yenileyen yazılım ekibi, test için üretim verisinin kopyasını ve hata ayıklama "
               "çıktılarını ortak bir klasöre bırakmış; klasör haftalardır unutulmuş.",
     "svc": "randevu-api", "olaylar": ["randevu_olusturuldu", "randevu_iptal", "hasta_kaydi_guncellendi"],
     "yol": "/api/hasta/kaydet", "alan": "tc_no", "ekstra": ("poliklinik", ["dahiliye", "kardiyoloji", "ortopedi", "goz"]),
     "gurultu": ["slot_hesaplandi doktor_sayisi={n} sure={ms}ms", "sms_kuyrugu bekleyen={n}"],
     "sorunlar": ["randevu saati", "sonuc bekliyor", "fatura itirazi"]},
    {"kod": "banka", "musteri": "Zeytin Finans", "sektor": "banka",
     "kisi": "Operasyon müdürü Hakan Bey",
     "hikaye": "Kredi başvuru uygulamasının hata ayıklama modu bir gece açık bırakılmış; ayrıca müşteri listesi "
               "bir kampanya için dışa aktarılıp dosya sunucusunda paylaşıma konmuş.",
     "svc": "kredi-basvuru", "olaylar": ["basvuru_alindi", "skor_sorgulandi", "basvuru_onay_bekliyor"],
     "yol": "/api/kredi/basvur", "alan": "kimlik_no", "ekstra": ("sube", ["merkez", "levent", "kordon", "kizilay"]),
     "gurultu": ["skor_servisi yanit={ms}ms", "kuyruk basvuru_bekleyen={n}"],
     "sorunlar": ["limit artirimi", "basvuru durumu", "kart basvurusu"]},
    {"kod": "eticaret", "musteri": "Sepetim Pazar", "sektor": "e-ticaret",
     "kisi": "Teknik lider Murat Bey",
     "hikaye": "Kampanya haftasında siparişleri inceleyen bir analiz çalışması için müşteri dökümü alınmış; "
               "döküm ve ödeme servisinin ayrıntılı logları kontrolsüz bir paylaşıma düşmüş.",
     "svc": "siparis-api", "olaylar": ["siparis_olusturuldu", "odeme_alindi", "fatura_kesildi"],
     "yol": "/api/siparis/odeme", "alan": "tckn", "ekstra": ("sepet_tutari", ["249", "1180", "3560", "89"]),
     "gurultu": ["stok_senkron urun={n} sure={ms}ms", "kampanya_motoru kural={n} uygulandi"],
     "sorunlar": ["iade", "kargo gecikmesi", "fatura adresi"]},
]


# ---------------------------------------------------------------------------------------------- sahte veri
def _tckn_sahte(rng: random.Random) -> str:
    """11 haneli, TCKN sağlama algoritmasını BİLEREK geçmeyen kurgusal numara (son hane daima yanlış)."""
    d = [rng.randint(1, 9)] + [rng.randint(0, 9) for _ in range(8)]
    d.append(((sum(d[0::2]) * 7) - sum(d[1::2])) % 10)           # 10. hane: gerçek kuralın değeri
    dogru11 = sum(d) % 10
    d.append((dogru11 + rng.randint(1, 9)) % 10)                 # 11. hane: kasıtlı yanlış
    return "".join(map(str, d))


def tckn_gecerli_mi(t: str) -> bool:
    """Gerçek TCKN sağlama kuralı. Kurgusal numaralar için DAİMA False olmalıdır."""
    if not re.fullmatch(r"[1-9][0-9]{10}", t):
        return False
    d = list(map(int, t))
    return ((sum(d[0:9:2]) * 7 - sum(d[1:8:2])) % 10 == d[9]) and (sum(d[:10]) % 10 == d[10])


def _luhn(num: str) -> bool:
    toplam = 0
    for i, ch in enumerate(reversed(num)):
        x = int(ch)
        if i % 2:
            x = x * 2 - 9 if x * 2 > 9 else x * 2
        toplam += x
    return toplam % 10 == 0


def _kart_sahte(rng: random.Random) -> str:
    """`99` ile başlayan, Luhn sağlamasını geçmeyen kurgusal 16 haneli numara."""
    k = "99" + "".join(str(rng.randint(0, 9)) for _ in range(14))
    if _luhn(k):
        k = k[:-1] + str((int(k[-1]) + 1) % 10)
    return k


def _kisiler(rng: random.Random, n: int) -> list:
    tcler, kartlar, adlar, tel = set(), set(), set(), set()
    sonuc = []
    while len(sonuc) < n:
        isim = rng.choice(u.ISIMLER)
        soy_g, soy_a = rng.choice(SOYADLAR)
        ad_k = f"{isim}.{soy_a}"
        tc, kart = _tckn_sahte(rng), _kart_sahte(rng)
        telefon = "05" + rng.choice(["32", "33", "34", "35", "42", "43", "44", "55"]) + \
            "".join(str(rng.randint(0, 9)) for _ in range(7))
        if ad_k in adlar or tc in tcler or kart in kartlar or telefon in tel:
            continue
        adlar.add(ad_k)
        tcler.add(tc)
        kartlar.add(kart)
        tel.add(telefon)
        sonuc.append({
            "ad": f"{ISIM_GOSTER.get(isim, isim.capitalize())} {soy_g}",
            "tc": tc, "kart": kart, "tel": telefon,
            "mail": f"{ad_k}{rng.randint(1, 99)}@posta.lab",
            "adres": f"{rng.choice(SOKAKLAR)} No:{rng.randint(1, 80)} D:{rng.randint(1, 12)} {rng.choice(ILCELER)}",
        })
    return sonuc


def _m_tc(t): return t[:3] + "*****" + t[-3:]
def _m_kart(k): return k[:4] + "********" + k[-4:]
def _m_tel(t): return t[:4] + "*****" + t[-2:]
def _m_mail(e): return e[0] + "***" + e[e.index("@"):]


def _gurultu(rng, sen) -> str:
    sablon = rng.choice(sen["gurultu"] + GENEL_GURULTU)
    return sablon.format(ms=rng.randint(3, 900), n=rng.randint(1, 200), v=rng.randint(2, 60))


def _hh(rng, gun, ek=0):
    return gun + timedelta(minutes=rng.randint(0, 600) + ek, seconds=rng.randint(0, 59))


def _dosya_uret(rng, rol, sen, havuz, ham_n, gun) -> str:
    """Bir rol (uygulama logu, hata ayıklama logu, dışa aktarım, destek notları) için dosya metni."""
    ham = rng.sample(havuz, ham_n)
    maskeli = rng.sample(havuz, rng.randint(4, 8))
    satirlar = [(k, True) for k in ham] + [(k, False) for k in maskeli]
    if rol == "export":
        rng.shuffle(satirlar)
        bas, degerler = sen["ekstra"]
        cikti = [f"kayit_no,ad_soyad,tckn,telefon,eposta,adres,kart_no,{bas}"]
        for i, (k, h) in enumerate(satirlar, 1):
            tc, tel, ml, kart = (k["tc"], k["tel"], k["mail"], k["kart"]) if h else \
                (_m_tc(k["tc"]), _m_tel(k["tel"]), _m_mail(k["mail"]), _m_kart(k["kart"]))
            cikti.append(f"{1000 + i},{k['ad']},{tc},{tel},{ml},{k['adres']},{kart},{rng.choice(degerler)}")
        return "\n".join(cikti) + "\n"
    ogeler = []
    for k, h in satirlar:
        t = _hh(rng, gun)
        tc, tel, ml, kart = (k["tc"], k["tel"], k["mail"], k["kart"]) if h else \
            (_m_tc(k["tc"]), _m_tel(k["tel"]), _m_mail(k["mail"]), _m_kart(k["kart"]))
        ts = t.strftime("%Y-%m-%dT%H:%M:%S+03:00")
        if rol == "app":
            satir = f'{ts} INFO {sen["svc"]} {rng.choice(sen["olaylar"])} ad="{k["ad"]}" {sen["alan"]}={tc} eposta={ml}'
        elif rol == "debug":
            rid = "".join(rng.choice("abcdef") for _ in range(4)) + str(rng.randint(10, 99))
            satir = (f'{ts} DEBUG req={rid} POST {sen["yol"]} payload='
                     f'{{"{sen["alan"]}":"{tc}","kart":"{kart}","tel":"{tel}"}}')
        else:
            satir = (f"{t:%Y-%m-%d} destek talebi #{rng.randint(1000, 9999)}: {k['ad']} ({rng.choice(sen['sorunlar'])}) "
                     f"- tc {tc}, tel {tel}, e-posta {ml}")
        ogeler.append((t, satir))
    for _ in range(rng.randint(14, 22)):
        t = _hh(rng, gun)
        if rol == "notes":
            ogeler.append((t, f"{t:%Y-%m-%d} dahili not: {rng.choice(GENEL_NOT)}"))
        else:
            sev = "DEBUG" if rol == "debug" else "INFO"
            ogeler.append((t, f"{t:%Y-%m-%dT%H:%M:%S+03:00} {sev} {sen['svc']} {_gurultu(rng, sen)}"))
    ogeler.sort(key=lambda x: x[0])
    return "\n".join(s for _, s in ogeler) + "\n"


def _erisim(rng, gun, dosya, saldirgan) -> str:
    ua = rng.choice(u.TARAYICI_UA)
    ogeler = []
    ic_yollar = ["/paylasim/", "/paylasim/okubeni.txt", "/intranet/", "/paylasim/yardim.html"]
    for _ in range(rng.randint(14, 20)):
        t = _hh(rng, gun)
        ogeler.append((t, u.apache_satiri(u.ic_ip(rng, "10.0.0"), t, "GET", rng.choice(ic_yollar), 200,
                                           rng.randint(300, 9000), ua)))
    t = _hh(rng, gun, 60)
    ogeler.append((t, u.apache_satiri(u.ic_ip(rng, "10.0.0"), t, "GET", f"/paylasim/{dosya}", 200,
                                       rng.randint(30000, 90000), ua)))
    diger = u.dis_ip(rng)
    while diger == saldirgan:
        diger = u.dis_ip(rng)
    t = _hh(rng, gun, 120)
    ogeler.append((t, u.apache_satiri(diger, t, "GET", f"/paylasim/{dosya}", 403, 199, ua)))
    t = _hh(rng, gun, 125)
    ogeler.append((t, u.apache_satiri(diger, t, "GET", "/paylasim/okubeni.txt", 200, 640, ua)))
    for ek in (180, 181):
        t = _hh(rng, gun, ek)
        ogeler.append((t, u.apache_satiri(saldirgan, t, "GET", f"/paylasim/{dosya}", 200,
                                           rng.randint(30000, 90000), u.TARAYICI_UA[0])))
    ogeler.sort(key=lambda x: x[0])
    return "\n".join(s for _, s in ogeler) + "\n"


def _akis(alt: int) -> dict:
    """Alt-tohumdan tüm vakayı (dosyalar, erişim logu, cevaplar) deterministik üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    for _ in range(100):
        havuz = _kisiler(rng, rng.randint(14, 18))
        gun = u.gun(rng)
        sizan = ["debug", "export", rng.choice(["app", "notes"])]
        sayilar = rng.sample(range(3, 14), 3)
        ham_n = dict(zip(sizan, sayilar))
        dosyalar = {}
        for rol in ROLLER:
            dosyalar[DOSYA_ADLARI[rol]] = _dosya_uret(rng, rol, sen, havuz, ham_n.get(rol, 0), gun)
        tum = "\n".join(dosyalar.values())
        tcler, kartlar = TC_RE.findall(tum), KART_RE.findall(tum)
        tel = TEL_RE.findall(tum)
        if len(set(tcler)) < len(tcler) and len(set(kartlar)) < len(kartlar) and len(set(tel)) < len(tel):
            break
    saldirgan = u.dis_ip(rng)
    erisim = _erisim(rng, gun, DOSYA_ADLARI["export"], saldirgan)
    satir_say = {ad: len(TC_RE.findall(m)) for ad, m in dosyalar.items()}
    en_cok = max(satir_say, key=satir_say.get)
    epostalar = set(EPOSTA_RE.findall(tum.replace("***", "#")))
    return {
        "sen": sen, "dosyalar": dosyalar, "erisim": erisim, "ip": saldirgan, "en_cok": en_cok,
        "tc_satir": len(tcler), "tc_uniq": len(set(tcler)), "kart_satir": len(kartlar),
        "kart_uniq": len(set(kartlar)), "tel_uniq": len(set(tel)), "mail_uniq": len(epostalar),
        "naif11": len(set(re.findall(r"(?<![0-9A-Za-z_])[0-9]{11}(?![0-9A-Za-z_])", tum))),
        "tc_liste": sorted(set(tcler)), "hamlar": ham_n,
    }


def dosyalari_yaz(klasor: Path, v: dict) -> None:
    for ad, metin in v["dosyalar"].items():
        u.yaz(klasor / ad, metin)


# ---------------------------------------------------------------------------------------------- seviye
def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — açıkta kalan kişisel veri taraması",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"]},
        "cevaplar": {"tc_satir": v["tc_satir"], "kart_satir": v["kart_satir"], "mail": v["mail_uniq"],
                     "tel": v["tel_uniq"], "en_cok": [v["en_cok"]]},
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    dosyalari_yaz(lab / "kayitlar", v)
    u.yaz(lab / "OKUBENI.txt",
          f"{s['metin']['musteri']} — KVKK veri sızıntısı taraması (tüm veriler kurgusaldır)\n\n"
          "kayitlar/uygulama.log       : uygulama logu\n"
          "kayitlar/hata_ayiklama.log  : hata ayıklama (DEBUG) logu\n"
          "kayitlar/disa_aktarim.csv   : müşteri dışa aktarım dosyası\n"
          "kayitlar/destek_notlari.txt : çağrı merkezi / destek notları\n\n"
          "Kayıtların bir kısmı maskeli (123*****901 gibi, yıldızlı), bir kısmı AÇIKTA.\n"
          "TC kimlik no sahtedir: 11 hanedir, 0 ile başlamaz, sağlama algoritmasını geçmez.\n")


def _sayi_hata_tc(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return ("Fazla çıktı: 11 haneli HER sayı TCKN değildir. Telefonlar da 11 hane ama `05` ile başlar; "
                "TC kimlik no `0` ile başlamaz.")
    return None


def _kart_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Fazla: yalnızca bitişik 16 rakamı say. Maskeli numarada `*` var, rakamlar bitişik değil."
    return None


def coz(lab: Path, s: dict) -> dict:
    tc = sh(f"grep -hE '{TC_GREP}' kayitlar/* | wc -l", lab)
    kart = sh(f"grep -hE '{KART_GREP}' kayitlar/* | wc -l", lab)
    mail = sh(f"grep -ohE '{EPOSTA_GREP}' kayitlar/* | sort -u | wc -l", lab)
    tel = sh(f"grep -ohE '{TEL_GREP}' kayitlar/* | sort -u | wc -l", lab)
    en = sh(f"grep -cE '{TC_GREP}' kayitlar/* | sort -t: -k2 -rn | head -1 | cut -d: -f1 | sed 's#.*/##'", lab)
    cozum = {1: tc, 2: kart, 3: mail, 4: tel, 5: en, 6: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Kişisel veri nedir?", """
Selin: "KVKK (6698 sayılı Kişisel Verilerin Korunması Kanunu), **kimliği belirli ya da belirlenebilir bir gerçek
kişiye ait her bilgiye** kişisel veri der: ad, TC kimlik no, telefon, e-posta, adres, kart no... Bazıları daha
hassastır: sağlık, biyometrik, din gibi **özel nitelikli** veriler ekstra korunur. Bizim işimiz, bu verinin
**olmaması gereken yerde açıkta durup durmadığını** bulmak." Önce elimizdeki dosyalara bakalım:
""", komut="ls -l kayitlar/"),
    Adim("TC kimlik no desenini yakala", """
TC kimlik numarası **11 hanelidir ve 0 ile başlamaz**. `grep -E` (genişletilmiş düzenli ifade) ile bu deseni
yazabiliriz: `\\b` kelime sınırıdır (11 rakamın başında ve sonunda başka rakam olmasın), `[1-9]` ilk hane,
`[0-9]{10}` kalan on hane. `-c` her dosyada kaç satır eşleştiğini sayar:
""", komut=f"grep -cE '{TC_GREP}' kayitlar/*", sonra="""
Maskeli kayıtlar (`123*****901`) eşleşmedi, çünkü yıldızlı; sadece **açıktaki** numaralar sayıldı. Hangi
dosyada kaç tane olduğu ilk risk haritanı verdi.
"""),
    Adim("Telefon da 11 hane!", """
Dikkat: Türkiye'de cep telefonu da 11 hanelidir (`05xxxxxxxxx`). Sadece "11 rakam" arayan bir desen telefonları
da TCKN sanır. Fark: **telefon `0` ile başlar, TCKN başlamaz**. Bakalım ham 11 haneli sayılar neler:
""", komut="grep -ohE '\\b[0-9]{11}\\b' kayitlar/disa_aktarim.csv | head -6", sonra="""
Gördüğün gibi `05...` ile başlayanlar telefon. Bu yüzden TCKN deseni `[1-9]` ile başlıyor. Telefonu aramak için
`\\b05[0-9]{9}\\b` kullanılır.
"""),
    Adim("Kart numarası: 16 hane", """
Banka/kredi kartı numarası (PAN) **16 bitişik rakamdır**. Maskeli hâli (`9912********3456`) bitişik olmadığı
için eşleşmez. Bu kurgusal kartlar `99` ile başlar ve gerçek bir kartla karışmaz:
""", komut=f"grep -cE '{KART_GREP}' kayitlar/*"),
    Adim("E-posta için regex", """
E-posta: harf/rakam/nokta, sonra `@`, sonra alan adı. `-o` yalnızca eşleşen kısmı yazar, `sort -u` tekrarları
atar. (Maskeli `a***@posta.lab` tek harfle başlayıp yıldız içerdiği için bu desene uymaz.) İlk beş açık adres:
""", komut=f"grep -ohE '{EPOSTA_GREP}' kayitlar/* | sort -u | head -5"),
    Adim("Gerçekten TCKN mi?", """
Bir numaranın TCKN gibi görünmesi onun geçerli olduğu anlamına gelmez: gerçek numaralar bir sağlama kuralını
(10. ve 11. haneler) geçer. Bu eğitimdeki numaralar **bilerek geçmez**, yani gerçek bir kişiye ait olamaz.
Python ile ilk bulduğumuz numarayı denetleyelim (ortasını yıldızlayarak yazdırıyoruz):
""", komut=("python3 -c \"import re; t=re.search(r'\\b[1-9][0-9]{10}\\b', open('kayitlar/disa_aktarim.csv').read())"
            ".group(); d=list(map(int,t)); ok=((sum(d[0:9:2])*7-sum(d[1:8:2]))%10==d[9]) and (sum(d[:10])%10==d[10]); "
            "print(t[:3]+'*****'+t[-3:], 'saglama:', 'GECERLI' if ok else 'gecersiz (kurgusal)')\""),
         sonra="""
Gerçek hayatta böyle bir numarayı **asla** ekrana açık yazmazsın; ilk 3 ve son 3 hane görünür, ortası yıldız.
Şimdi sıra sende: açıktaki veriyi sayıp sınıflandır.
"""),
]

GOREVLER = [
    Gorev("`kayitlar/` altındaki dosyalarda **maskelenmemiş TC kimlik no** içeren toplam **satır** sayısı kaç? "
          "(11 hane, `0` ile başlamaz; telefon numaralarını TCKN sayma)",
          Sayi("tc_satir", sik_hatalar=_sayi_hata_tc),
          ("Dört dosyanın hepsine bak; her eşleşen satırı say. Maskeli kayıtlarda yıldız var, rakamlar bitişik değil.",
           "`grep -E` ile `\\b[1-9][0-9]{10}\\b` desenini kullan; `-h` dosya adlarını gizler.",
           "`grep -hE '\\b[1-9][0-9]{10}\\b' kayitlar/* | wc -l`"),
          puan=20, baslik="Açık TCKN satırı"),
    Gorev("Maskelenmemiş **kart numarası** (16 bitişik rakam) içeren toplam **satır** sayısı kaç?",
          Sayi("kart_satir", sik_hatalar=_kart_hata),
          ("Kart numarası yan yana 16 rakamdır.",
           "`\\b[0-9]{16}\\b` desenini tüm dosyalarda ara; satırları say.",
           "`grep -hE '\\b[0-9]{16}\\b' kayitlar/* | wc -l`"),
          puan=15, baslik="Açık kart satırı"),
    Gorev("Açıkta duran **farklı e-posta adresi** sayısı kaç? (aynı adres birden çok yerde geçebilir; "
          "maskeli `a***@posta.lab` olanlar sayılmaz)",
          Sayi("mail"),
          ("Önce adresleri satırlardan ayıklamalısın, sonra tekrarları atmalısın.",
           "`grep -o` yalnızca eşleşen kısmı verir; `sort -u` tekrarları siler.",
           "`grep -ohE '[A-Za-z0-9._-]+@[A-Za-z0-9.-]+' kayitlar/* | sort -u | wc -l`"),
          puan=20, baslik="Farklı e-posta"),
    Gorev("Açıkta duran **farklı cep telefonu** sayısı kaç? (`05` ile başlayan 11 haneli numaralar; maskeli olanlar sayılmaz)",
          Sayi("tel"),
          ("Telefon `05` ile başlar ve 11 hanedir. Aynı numara birden çok dosyada olabilir.",
           "`\\b05[0-9]{9}\\b` ile çıkar (`-o`), sonra tekilleştir.",
           "`grep -ohE '\\b05[0-9]{9}\\b' kayitlar/* | sort -u | wc -l`"),
          puan=20, baslik="Farklı telefon"),
    Gorev("En çok açık TC kimlik no **satırı** içeren dosyanın adı ne?",
          Metin("en_cok", bicim="dosya adı", sadece_ad=True),
          ("Dosya başına sayı lazım; `grep -c` her dosya için ayrı sayı verir.",
           "Çıktıdaki `dosya:sayı` satırlarını sayıya göre büyükten küçüğe sırala.",
           "`grep -cE '\\b[1-9][0-9]{10}\\b' kayitlar/* | sort -t: -k2 -rn | head -1`"),
          puan=20, baslik="En çok sızdıran dosya"),
    Gorev("Bulduğun veri türleri arasında, **sızarsa kişiye en kalıcı zararı** veren (değiştirilemeyen, "
          "kimlik hırsızlığına en çok yarayan) hangisi?",
          Secmeli([
              ("TC kimlik numarası: ömür boyu aynı kalır, değiştirilemez; tek başına kimliğe bürünmeye yarar",
               "Doğru. Kart iptal edilip yenilenir, e-posta ve telefon değişir; ama TCKN hayatın boyunca sabit "
               "kalan ve başvurularda kimlik yerine geçen veridir."),
              ("E-posta adresi, çünkü herkese spam gönderilebilir",
               "E-posta rahatsız edicidir ama kolayca değiştirilir; en kalıcı zarar bu değil."),
              ("Telefon numarası, çünkü arama alınır",
               "Telefon da değiştirilebilir; zararı sınırlıdır. TCKN daha kalıcı ve daha güçlüdür."),
              ("Hepsi aynı hassasiyette; sıralamaya gerek yok",
               "Hayır. Hassasiyet: ne kadar kalıcı ve ne kadar kötüye kullanılabilir olduğuna bağlı; "
               "e-posta < telefon < kart < TCKN diye düşünülür. Önceliği buna göre ver."),
          ]),
          ("Bir kart çalınırsa banka ne yapar? E-posta çalınırsa ne? TCKN çalınırsa ne yapabilirsin?",
           "Kalıcılık ve kimliğe bürünme gücü iki ölçüt.",
           "Hayat boyu değişmeyen ve resmi işlemlerde kimlik yerine geçen veri en hassasıdır."),
          puan=25, baslik="En hassas veri"),
]

SEVIYE = Seviye(
    kimlik="c23b04",
    cilt=23,
    bolum=4,
    baslik="KVKK: Açıkta Kalan Kişisel Veriyi Bulmak",
    brifing="""
**<<musteri>>** (<<sektor>>): <<hikaye>> <<kisi>> yeni bir uyum denetimi öncesi Kalkan Güvenlik'ten yardım istiyor.

Selin: "Dört dosya geldi: uygulama logu, hata ayıklama logu, bir dışa aktarım ve destek notları. İçlerinde
kişisel veri **maskelenmemiş** olarak duruyorsa bu hem bir güvenlik hem de **KVKK** (kişisel veri koruma
kanunu) sorunu. Önce neyin, ne kadar açıkta olduğunu ölçelim." Deniz: "Bana sayı lazım: kaç satır, kaç
farklı kişi, hangi dosya. Sayı olmazsa hukuka rapor yazamam." Mert: "Tüm kimlik numaraları kurgusal, ama
desenler gerçek. Önce deseni öğren."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kişisel veri sızıntısını bulmak çoğu zaman bir **desen avıdır**: TCKN 11 hane (`0` ile başlamaz), kart 16 hane,
telefon `05` ile başlayan 11 hane, e-posta `@` içeren metin. Aynı kişi birden çok dosyada geçebileceği için
"kaç satır" ile "kaç farklı kişi" farklı sorulardır; KVKK açısından önemli olan ikincisidir. Ve en hassas veri
her zaman en çok sızan değil, **en kalıcı ve en kötüye kullanılabilir** olandır. Savunmada ders: log ve
dışa aktarımlarda maskeleme zorunlu olmalı, hata ayıklama kapalı olmalı, veriler yalnızca gereken ölçüde
tutulmalı ve bu taramayı düzenli çalıştırmalısın.
""",
    gercek_hayat="""
- **Gerçek hayatta bu bir DLP taramasıdır:** Veri kaybı önleme (DLP) araçları ve kurumsal güvenlik ekipleri,
  dosya sunucularını ve logları TCKN / kart / IBAN desenleri için düzenli tarar (kart için Luhn, TCKN için
  sağlama algoritması ile hatalı eşleşmeleri eler). Bu betik, o işin en basit hâlidir.
- **KVKK ve ihlal bildirimi:** 6698 sayılı Kanun'a göre veri güvenliğinden veri sorumlusu sorumludur; ihlalde
  Kişisel Verileri Koruma Kurulu'na ve etkilenen kişilere bildirim yükümlülüğü doğar. Kurul'un 24 Ocak 2019 tarihli 2019/10 sayılı
  kararı bu bildirimi "en kısa sürede, en geç 72 saat içinde" yapmayı öngörür (AB'nin GDPR'ında da 72 saat vardır).
- **Yaptırımlar:** **Veri ihlali cezaları** gerçektir: Kurul, ihlal yaşayan şirketlere idari para cezası
  verebilir ve ihlal bildirimlerini kamuoyuna duyurur; GDPR'da ceza yıllık cironun %4'üne kadar çıkabilir.
""",
    sure_hedef_dk=35,
)
