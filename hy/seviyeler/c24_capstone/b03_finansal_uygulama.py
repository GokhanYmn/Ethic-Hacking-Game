"""Cilt 24 · Bölüm 3 — Vaka 3: Finansal uygulama değerlendirmesi (mavi takım).

Kurgusal bir ödeme uygulamasının kodu, yapılandırması ve işlem logları gözden geçirilir; iş mantığı
(negatif tutar, fazla iade, kupon tekrarı, 3-D Secure atlama) ve uyum (PCI-DSS: açık kart numarası;
KVKK: açık kişisel veri) bulguları çıkarılır, önceliklendirilir ve düzeltilir.

Vakalar (farklı sektör ve log biçimi): Paramix (fintech cüzdan, anahtar=değer log), Ferah Bank (havale/EFT, virgüllü CSV),
Pazarix (e-ticaret ödeme, noktalı virgüllü CSV). Bulgu türleri hepsinde var; sayılar, kullanıcılar ve işlem numaraları değişir.
"""
from __future__ import annotations

import re
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c24_capstone.ortak import sec_doldur, sh

TEST_PANLAR = ["4111111111111111", "5555555555554444", "4012888888881881", "5105105105105100", "6011111111111117"]
BINLER = ["411111", "555555", "401288", "510510", "601111"]

VAKALAR = [
    {"kod": "paramix", "bicim": "kv", "dosya": "islem_kaydi.log", "onek": "PMX", "kul": "u", "kuponlar": ["YENIUYE", "HAFTASONU", "ARKADASIM"],
     "tutar": (20, 1800), "urun": "cüzdan yükleme ve transfer", "iade": "iade", "uygulama": "Paramix cüzdan uygulaması"},
    {"kod": "ferahbank", "bicim": "csv", "ayrac": ",", "dosya": "havale_eft.csv", "onek": "FB", "kul": "M", "kuponlar": ["KOMISYON0", "YENIMUSTERI", "SUBEDEN50"],
     "tutar": (200, 25000), "urun": "havale/EFT ve kart harcaması", "iade": "iade", "uygulama": "Ferah Bank internet şubesi"},
    {"kod": "pazarix", "bicim": "csv", "ayrac": ";", "dosya": "siparis_odeme.csv", "onek": "PZX", "kul": "k", "kuponlar": ["YAZ10", "INDIRIM15", "ILKSIPARIS"],
     "tutar": (25, 3500), "urun": "sipariş ödemesi", "iade": "iade", "uygulama": "Pazarix sipariş ve ödeme servisi"},
]

KOD_ESKI = '''"""{baslik}: tutar ve iade doğrulama (KURGUSAL)."""


def tutar_gecerli_mi(tutar, bakiye):
    """Ödeme/transfer tutarı kabul edilebilir mi?"""
    return tutar <= bakiye        # yalnızca bakiyeye bakıyor


def iade_gecerli_mi(orijinal, onceki_iade, istenen):
    """İstenen iade tutarı kabul edilebilir mi? orijinal: ilk ödeme, onceki_iade: bugüne kadar iade edilen toplam."""
    return istenen <= orijinal    # önceki iadeleri hesaba katmıyor
'''

CONF_ESKI = """# {ad} ödeme servisi ayarları (KURGUSAL)
ORTAM=uretim
DEBUG=true
TLS_MIN_SURUM=1.0
LOG_KART_NO=acik
HMAC_ANAHTAR={anahtar}
OTURUM_SURESI_DK={oturum}
"""

KOD_TESTLERI = r'''
import importlib.util, sys
sp = importlib.util.spec_from_file_location("islem", sys.argv[1])
m = importlib.util.module_from_spec(sp)
sp.loader.exec_module(m)
vakalar = [
    ("tutar_gecerli_mi", (-50, 1000), False, "negatif tutar kabul edilmemeli"),
    ("tutar_gecerli_mi", (0, 1000), False, "sıfır tutar kabul edilmemeli"),
    ("tutar_gecerli_mi", (50, 1000), True, "normal tutar kabul edilmeli"),
    ("tutar_gecerli_mi", (1000, 1000), True, "bakiye kadar tutar kabul edilmeli"),
    ("tutar_gecerli_mi", (1500, 1000), False, "bakiyeyi aşan tutar kabul edilmemeli"),
    ("iade_gecerli_mi", (200, 0, 250), False, "orijinalden fazla iade kabul edilmemeli"),
    ("iade_gecerli_mi", (200, 150, 100), False, "önceki iadelerle birlikte orijinali aşan iade kabul edilmemeli"),
    ("iade_gecerli_mi", (200, 150, 50), True, "kalan kadar iade kabul edilmeli"),
    ("iade_gecerli_mi", (200, 0, 200), True, "tam iade kabul edilmeli"),
    ("iade_gecerli_mi", (200, 0, -10), False, "negatif iade kabul edilmemeli"),
]
for ad, args, beklenen, aciklama in vakalar:
    try:
        sonuc = bool(getattr(m, ad)(*args))
    except Exception:
        sonuc = False
    if sonuc != beklenen:
        print(f"{ad}{args}: {aciklama}")
'''


def _masked(rng) -> str:
    return rng.choice(BINLER) + "******" + "".join(rng.choice("0123456789") for _ in range(4))


def _kayitlar(rng, v: dict, gun: datetime) -> dict:
    kullanicilar = u.benzersiz(rng, lambda r: f"{v['kul']}{r.randint(1000, 9999)}", 16)
    kuponlar = v["kuponlar"]
    lo, hi = v["tutar"]

    def tutar():
        return round(rng.uniform(lo, hi) / 5) * 5 + rng.choice([0, 0, 0.5])

    satirlar = []

    def yeni(t, kul, tur, tt, kupon="-", ucd="ok", sonuc="ONAY", ref=None, tag=""):
        satirlar.append({"t": t, "kul": kul, "tur": tur, "tutar": tt, "kupon": kupon, "ucd": ucd, "kart": _masked(rng),
                         "sonuc": sonuc, "ref": ref, "tag": tag})
        return satirlar[-1]

    def zaman():
        return gun + timedelta(hours=8, seconds=rng.randint(0, 13 * 3600))

    kullanilan = set()
    normal = []
    for _ in range(rng.randint(48, 66)):
        k = rng.choice(kullanicilar[3:])
        kup = "-"
        if rng.random() < 0.3:
            ad = rng.choice(kuponlar)
            if (k, ad) not in kullanilan:
                kullanilan.add((k, ad))
                kup = ad
        sonuc = "ONAY" if rng.random() < 0.9 else "RED"
        normal.append(yeni(zaman(), k, "odeme", tutar(), kup, "ok", sonuc, tag="normal"))
    # A: negatif tutarla onaylanan ödemeler (+ reddedilen yem)
    kn = rng.randint(3, 6)
    for _ in range(kn):
        yeni(zaman(), kullanicilar[0], "odeme", -tutar(), "-", "ok", "ONAY", tag="neg")
    for _ in range(rng.randint(1, 2)):
        yeni(zaman(), rng.choice(kullanicilar[:3]), "odeme", -tutar(), "-", "ok", "RED", tag="negred")
    # B: aynı kuponu tekrar tekrar kullanan hesap + daha az tekrarlayan yem
    abuser, yem = kullanicilar[1], kullanicilar[2]
    kupon_a, kupon_b = rng.sample(kuponlar, 2)
    for _ in range(rng.randint(5, 9)):
        yeni(zaman(), abuser, "odeme", tutar(), kupon_a, "ok", "ONAY", tag="kupon")
    for _ in range(rng.randint(2, 3)):
        yeni(zaman(), yem, "odeme", tutar(), kupon_b, "ok", "ONAY", tag="kuponyem")
    # D: 3-D Secure atlanarak onaylananlar (+ reddedilen yem)
    ku = rng.randint(4, 8)
    for _ in range(ku):
        yeni(zaman(), rng.choice(kullanicilar[3:]), "odeme", tutar(), "-", "atlandi", "ONAY", tag="ucd")
    for _ in range(rng.randint(1, 2)):
        yeni(zaman(), rng.choice(kullanicilar[3:]), "odeme", tutar(), "-", "atlandi", "RED", tag="ucdred")
    # C: iadeler (biri orijinalden fazla)
    adaylar = [x for x in normal if x["sonuc"] == "ONAY" and x["tutar"] > 0]
    secilen = rng.sample(adaylar, 5)
    fazla_satir = None
    for i, o in enumerate(secilen):
        ti = o["t"] + timedelta(minutes=rng.randint(5, 300))
        if i == 0:
            tt = round(o["tutar"] * rng.choice([1.5, 2.0]), 2)
            fazla_satir = yeni(ti, o["kul"], "iade", tt, "-", "-", "ONAY", ref=o, tag="iadefazla")
        else:
            tt = round(o["tutar"] * rng.choice([0.25, 0.5, 1.0]), 2)
            yeni(ti, o["kul"], "iade", tt, "-", "-", "ONAY", ref=o, tag="iade")
    satirlar.sort(key=lambda x: x["t"])
    for i, x in enumerate(satirlar, 1):
        x["no"] = f"{v['onek']}{i:05d}"
    # E: tam kart numarası (PAN) açık yazılanlar
    pan_sayi = rng.randint(6, 12)
    for x in rng.sample(satirlar, pan_sayi):
        x["kart"] = rng.choice(TEST_PANLAR)
    return {"satirlar": satirlar, "kullanicilar": kullanicilar, "abuser": abuser, "yem": yem, "fazla": fazla_satir["no"],
            "ref_fazla": fazla_satir["ref"]["no"], "neg": kn, "neg_toplam": sum(1 for x in satirlar if x["tutar"] < 0),
            "ucd": ku, "ucd_toplam": sum(1 for x in satirlar if x["ucd"] == "atlandi"), "pan": pan_sayi}


def _bicimle(v: dict, satirlar: list) -> str:
    alanlar = ["zaman", "islem", "kul", "tur", "tutar", "kupon", "ucd", "kart", "sonuc", "ref"]
    cikti = []
    if v["bicim"] == "csv":
        cikti.append(v["ayrac"].join(alanlar))
    for x in satirlar:
        deger = {"zaman": f"{x['t']:%Y-%m-%dT%H:%M:%S}", "islem": x["no"], "kul": x["kul"], "tur": x["tur"],
                 "tutar": f"{x['tutar']:.2f}", "kupon": x["kupon"], "ucd": x["ucd"], "kart": x["kart"],
                 "sonuc": x["sonuc"], "ref": x["ref"]["no"] if x["ref"] else "-"}
        if v["bicim"] == "kv":
            cikti.append(f"{deger['zaman']} " + " ".join(f"{a}={deger[a]}" for a in alanlar[1:]))
        else:
            cikti.append(v["ayrac"].join(deger[a] for a in alanlar))
    return "\n".join(cikti) + "\n"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    gun = u.gun(rng)
    k = _kayitlar(rng, v, gun)
    anahtar = f"{v['kod'][:3]}_live_" + u.parola(rng).lower().replace("!", "x").replace(".", "y").replace("*", "z").replace("?", "q") + "k" + str(rng.randint(100, 999))
    oturum = rng.choice([60, 120, 240, 480])
    if v["bicim"] == "kv":
        neg_komut = f"grep -c 'tutar=-' {v['dosya']}"
    else:
        neg_komut = f"awk -F'{v['ayrac']}' 'NR>1 && $5<0' {v['dosya']} | wc -l"
    return {
        "vaka": f"{m['ad']} — {m['sektor']}: {v['urun']}",
        "m": m, "v": v, "k": k, "gun": gun, "anahtar": anahtar, "oturum": oturum, "tohum_tckn": rng.randint(10**6, 10**9),
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "hikaye": m["hikaye"], "uygulama": v["uygulama"], "islem_dosya": v["dosya"],
                  "neg_komut": neg_komut, "urun": v["urun"]},
        "cevaplar": {"neg": k["neg"], "kupon": k["abuser"], "iade": k["fazla"], "ucd": k["ucd"], "pan": k["pan"]},
    }


def yaz(lab: Path, s: dict) -> None:
    import random
    v, m, k = s["v"], s["m"], s["k"]
    u.yaz(lab / v["dosya"], _bicimle(v, k["satirlar"]))
    r = random.Random(s["tohum_tckn"])
    satir = []
    t = s["gun"] + timedelta(hours=8)
    for i in range(r.randint(18, 26)):
        t += timedelta(seconds=r.randint(20, 900))
        x = r.choice(k["satirlar"])
        tckn = str(r.randint(10**10, 10**11 - 1))
        tel = "05" + str(r.randint(300000000, 559999999))
        kind = r.random()
        if kind < 0.5:
            satir.append(f"{t:%Y-%m-%dT%H:%M:%S} DEBUG odeme isteği alındı: kul={x['kul']} tckn={tckn} tel={tel} tutar={x['tutar']:.2f}")
        elif kind < 0.75:
            satir.append(f"{t:%Y-%m-%dT%H:%M:%S} DEBUG istek başlığı: Authorization: Bearer eyJ{r.randint(10**8, 10**9)}.{r.randint(10**8, 10**9)}")
        elif kind < 0.9:
            satir.append(f"{t:%Y-%m-%dT%H:%M:%S} ERROR sorgu hatası: SELECT * FROM musteriler WHERE tckn='{tckn}' (zaman aşımı)")
        else:
            satir.append(f"{t:%Y-%m-%dT%H:%M:%S} INFO oturum açıldı: kul={x['kul']}")
    u.yaz(lab / "uygulama.log", "\n".join(satir) + "\n")
    u.yaz(lab / "kod/islem.py", KOD_ESKI.format(baslik=v["uygulama"]))
    u.yaz(lab / "yapilandirma/uygulama.conf", CONF_ESKI.format(ad=m["ad"], anahtar=s["anahtar"], oturum=s["oturum"]))
    u.yaz(lab / "KAPSAM.txt",
          f"{m['ad']} / {v['uygulama']} değerlendirme kapsamı (KURGUSAL)\n"
          f"Konu: {v['urun']}. İşlem günlüğü: {v['dosya']} (alanlar: zaman, islem, kul, tur, tutar, kupon, ucd, kart, sonuc, ref).\n"
          "ucd = 3-D Secure (kart sahibi doğrulaması): ok | atlandi | -  (iade işlemlerinde yok).\n"
          "Ek kaynaklar: uygulama.log (hata ve hata ayıklama kaydı), kod/islem.py, yapilandirma/uygulama.conf.\n"
          f"Selin'den not: {m['hikaye']} Gerçek müşteri verisi yok; log içindeki kart ve kimlik numaraları test verisidir.\n"
          "Düzeltmeler bu klasördeki kopyalarda yapılır.\n")


# ----------------------------------------------------------------------------- kontroller

def _conf_kontrol(b) -> Sonuc:
    yol = b.lab / "yapilandirma/uygulama.conf"
    if not yol.exists():
        return Sonuc(False, "`yapilandirma/uygulama.conf` bulunamıyor.")
    d = {}
    for sat in yol.read_text(errors="replace").splitlines():
        if sat.strip() and not sat.lstrip().startswith("#") and "=" in sat:
            a, _, deger = sat.partition("=")
            d[a.strip()] = deger.strip()
    s = b.senaryo
    sorunlar = []
    if d.get("DEBUG", "true").lower() not in ("false", "0", "kapali", "hayir"):
        sorunlar.append("`DEBUG` hâlâ açık (hata ayıklama kaydı kişisel veri yazıyor)")
    mm = re.search(r"\d+(?:\.\d+)?", d.get("TLS_MIN_SURUM", "1.0"))
    if not mm or float(mm.group(0)) < 1.2:
        sorunlar.append("`TLS_MIN_SURUM` en az 1.2 olmalı (eski TLS sürümleri kırık kabul edilir)")
    if d.get("LOG_KART_NO", "acik").lower() not in ("maskeli", "kapali", "yok"):
        sorunlar.append("`LOG_KART_NO` açık; kart numarası loga maskeli (`maskeli`) yazılmalı")
    if not re.fullmatch(r"(\$\{\w+\}|\$\w+|env:\w+|ENV:\w+)", d.get("HMAC_ANAHTAR", s["anahtar"])):
        sorunlar.append("`HMAC_ANAHTAR` dosyada düz metin duruyor; ortam değişkeninden okunmalı (örn. `${HMAC_ANAHTAR_ORTAM}`)")
    if d.get("ORTAM") != "uretim" or d.get("OTURUM_SURESI_DK") != str(s["oturum"]):
        sorunlar.append("`ORTAM` ve `OTURUM_SURESI_DK` satırları değişmemeli; sadece sorunlu ayarlara dokun")
    if sorunlar:
        return Sonuc(False, "Yapılandırmada kalan sorunlar: " + "; ".join(sorunlar) + ".", yakin=len(sorunlar) < 4)
    return Sonuc(True, "Yapılandırma sertleşti: hata ayıklama kapalı, TLS 1.2+, kart numarası maskeli, anahtar dosyada değil.")


def _kod_kontrol(b) -> Sonuc:
    yol = b.lab / "kod/islem.py"
    if not yol.exists():
        return Sonuc(False, "`kod/islem.py` bulunamıyor; dosyayı silme, düzelt.")
    try:
        p = subprocess.run([sys.executable, "-I", "-c", KOD_TESTLERI, str(yol)], capture_output=True, text=True, timeout=8)
    except subprocess.TimeoutExpired:
        return Sonuc(False, "Kod çok uzun sürdü; sonsuz döngü olmasın.")
    if p.returncode != 0:
        son = (p.stderr.strip().splitlines() or ["bilinmeyen hata"])[-1]
        return Sonuc(False, f"`islem.py` çalıştırılamadı: {son}", yakin=True)
    hatalar = [x for x in p.stdout.splitlines() if x.strip()]
    if hatalar:
        return Sonuc(False, f"{len(hatalar)} test geçmedi, ilki: {hatalar[0]}. Python sözdizimi için `python3 -m py_compile kod/islem.py` kullanabilirsin.",
                     yakin=True)
    return Sonuc(True, "Doğrulama fonksiyonları artık negatif/aşan tutarı ve fazla iadeyi reddediyor, meşru işlemleri kabul ediyor.")


def _neg_hata(g, beklenen, b):
    if g.isdigit() and int(g) == b.senaryo["k"]["neg_toplam"]:
        return "Reddedilen (RED) negatif denemeleri de saymışsın; yalnızca **ONAY** alanları say."
    return None


def _kupon_hata(g, beklenen, b):
    if g == b.senaryo["k"]["yem"]:
        return "Bu hesap da kuponu birden çok kullanmış ama daha az; en çok tekrarlayanı bul."
    return None


def _iade_hata(g, beklenen, b):
    if g == b.senaryo["k"]["ref_fazla"]:
        return "Bu, iadenin referans verdiği **orijinal ödeme**. Aradığın şey, orijinalden fazla tutarlı **iade** satırının kendi numarası."
    return None


def _ucd_hata(g, beklenen, b):
    if g.isdigit() and int(g) == b.senaryo["k"]["ucd_toplam"]:
        return "Reddedilen (RED) ödemeleri de saymışsın; 3-D Secure atlayıp **ONAY** alanları say."
    return None


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    f = v["dosya"]
    alanlar = ["islem", "kul", "tur", "tutar", "kupon", "ucd", "kart", "sonuc", "ref"]
    fmt = 'printf "' + "%s\\t" * 8 + '%s\\n", '
    if v["bicim"] == "kv":
        norm = ("awk '{delete v; for(i=1;i<=NF;i++){n=index($i,\"=\"); if(n>0) v[substr($i,1,n-1)]=substr($i,n+1)} "
                + fmt + ", ".join('v["' + a + '"]' for a in alanlar) + "}' " + f)
    else:
        norm = ("awk -F'" + v["ayrac"] + "' 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{"
                + fmt + ", ".join('$c["' + a + '"]' for a in alanlar) + "}' " + f)
    neg = sh(f"{norm} | awk -F'\\t' '$3==\"odeme\" && $4<0 && $8==\"ONAY\"' | wc -l", lab)
    kupon = sh(f"{norm} | awk -F'\\t' '$5!=\"-\" && $8==\"ONAY\" {{c[$2\" \"$5]++}} END{{for(k in c) print c[k], k}}' | sort -rn | head -1 | awk '{{print $2}}'", lab)
    iade = sh(f"{norm} | awk -F'\\t' '{{t[$1]=$4}} $3==\"iade\" && $4+0>t[$9]+0 {{print $1}}'", lab)
    ucd = sh(f"{norm} | awk -F'\\t' '$3==\"odeme\" && $6==\"atlandi\" && $8==\"ONAY\"' | wc -l", lab)
    pan = sh(f"grep -cE '[0-9]{{16}}' {f}", lab)
    sh("sed -i 's/^DEBUG=.*/DEBUG=false/; s/^TLS_MIN_SURUM=.*/TLS_MIN_SURUM=1.2/; s/^LOG_KART_NO=.*/LOG_KART_NO=maskeli/; "
       "s/^HMAC_ANAHTAR=.*/HMAC_ANAHTAR=${HMAC_ANAHTAR_ORTAM}/' yapilandirma/uygulama.conf", lab)
    sh("cat > kod/islem.py <<'SON'\n"
       "def tutar_gecerli_mi(tutar, bakiye):\n    return 0 < tutar <= bakiye\n\n\n"
       "def iade_gecerli_mi(orijinal, onceki_iade, istenen):\n    return 0 < istenen <= orijinal - onceki_iade\nSON", lab)
    rapor = ("Önceliklendirme: negatif tutar ve fazla iade doğrudan para kaybı olduğu için Kritik, açık kart numarası PCI-DSS ve açık kimlik ile telefon KVKK "
             "açısından Yüksek, 3-D Secure atlama ve kupon tekrarı Orta düzeyde. Plan: önce kod doğrulamalarını ve iade üst sınırını düzeltmek, "
             "kart numarasını maskelemek ve hata ayıklamayı kapatmak, sonra kupon başına tek kullanım ve 3-D Secure zorunluluğu getirmek, "
             "TLS ve anahtar yönetimini düzeltmek, düzeltmelerden sonra doğrulama testi yapmak.")
    return sec_doldur({1: neg, 2: kupon, 3: iade, 4: ucd, 5: pan, 6: "", 7: "", 8: "", 9: rapor}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Vaka dosyası", """
Üçüncü vaka senin uzmanlık alanın: bir **finansal uygulama**. Burada klasik web açığından çok iki şeye bakılır:
**iş mantığı** (uygulama kuralları paraya karşı doğru çalışıyor mu?) ve **uyum** (kart ve kişisel veri doğru
saklanıyor mu?). Elinde uygulamanın kodu, yapılandırması ve işlem logları var.

<<musteri>> (<<sektor>>): <<hikaye>> Dosyalara bak:
""", komut="ls -R ."),
    Adim("1. İşlem logu", """
Her satır bir işlem: zaman, işlem numarası, kullanıcı, tür (`odeme`/`iade`), **tutar**, kupon, 3-D Secure durumu
(`ucd`: kart sahibinin bankada ayrıca doğrulanması), maskeli kart, sonuç (`ONAY`/`RED`) ve iadeler için referans
(hangi ödemenin iadesi). Başlangıca bakalım:
""", komut="head -3 <<islem_dosya>>"),
    Adim("2. İş mantığı: negatif tutar", """
Bir ödeme uygulaması **negatif tutarı** kabul ederse "ödeme" para çıkışı yerine para girişi olur. Önce negatif tutarlı
satırları say (reddedilenler dahil):
""", komut="<<neg_komut>>", sonra="""
Bu sayı **hem onaylananları hem reddedilenleri** içeriyor. Bulguya yazacağın sayı yalnızca `ONAY` alanlar: reddedilen
denemeyi sistem durdurmuş, bulgu değil; onaylanan ise paraya dokunmuş demektir. Benzer iş mantığı hataları: bir
ödemeden fazla iade, aynı kuponun tekrar tekrar kullanılması, 3-D Secure adımının atlanması. Bunları görevlerde sayacaksın.
"""),
    Adim("3. Uyum: kart numarası logda", """
**PCI-DSS** (ödeme kartı verisi güvenlik standardı) tam kart numarasının (PAN) açık metin saklanmasını sınırlar; logda
görünmesi tipik bir ihlaldir. Kart numarasının doğru hâli maskelidir (`411111******1111`). 16 hane arka arkaya
duran satırları say:
""", komut="grep -cE '[0-9]{16}' <<islem_dosya>>", sonra="""
Sıfırdan farklı her sayı, o kadar satırda tam kart numarasının açıkta durması demektir. Nedenini yapılandırmada bulacaksın.
"""),
    Adim("4. Uyum: kişisel veri hata ayıklama logunda", """
**KVKK** (Kişisel Verilerin Korunması Kanunu), TCKN ve telefon gibi kişisel verilerin gereksiz yere saklanmamasını,
korunmasını ve ihlallerin bildirilmesini ister. Hata ayıklama (DEBUG) kaydı çoğu zaman bu verileri farkında olmadan açık
yazar:
""", komut="grep -c 'tckn=' uygulama.log", sonra="""
Bu satırlar çoğunlukla üretimde kapatılmayı unutulmuş `DEBUG` ayarından gelir. Bir de başlıkta `Authorization: Bearer`
satırı var: oturum belirteci loga düşmüş, yani logu okuyan oturumu taklit edebilir.
"""),
    Adim("5. Yapılandırma", """
Kodun dışında, çoğu zaman en kolay düzeltilen riskler yapılandırma dosyasında durur:
""", komut="cat yapilandirma/uygulama.conf", sonra="""
Aranacak dört şey: `DEBUG` açık mı, `TLS_MIN_SURUM` eski mi (1.0 ve 1.1 kırık kabul edilir), kart numarası loga açık
mı yazılıyor (`LOG_KART_NO`), gizli anahtar dosyada düz metin mi (`HMAC_ANAHTAR`). Anahtarlar kodda ya da yapılandırma
dosyasında değil, ortam değişkeni ya da gizli yönetimi aracında durmalıdır.
"""),
    Adim("6. Kod", """
İş mantığı kuralları kodda yaşar. İki küçük doğrulama fonksiyonuna bak:
""", komut="cat kod/islem.py", sonra="""
Fonksiyonlar yalnızca tek bir koşula bakıyor. **Hacker gözüyle:** negatif tutar, orijinalden fazla iade, kuponu
tekrar kullanma: bunların hiçbiri "açık" gibi görünmez, her biri uygulamanın **kendi kuralındaki bir boşluktur** ve
tarayıcılar bulamaz. Bunları bulmak için uygulamanın ne yapması gerektiğini bilmek gerekir: finans bilgin burada fark yaratır.
"""),
    Adim("7. Bulguyu önceliklendirmek", """
Bulguları aynı önemde yazmak yanlıştır. Pratik bir sıra: **doğrudan para kaybı** (negatif tutar, fazla iade) en üstte,
sonra **kart verisi** (PCI-DSS) ve **kişisel veri** (KVKK) ihlalleri, sonra doğrulama atlamaları, en sonda iyi
uygulama eksikleri. Her bulguyu bir uyum maddesine bağlamak, raporu bir finans kurumunun yöneticisi için daha değerli yapar.
"""),
]

GOREVLER = [
    Gorev("`<<islem_dosya>>` içinde **negatif tutarla ONAYLANAN** ödeme sayısı kaçtır? (RED olanları sayma)",
          Sayi("neg", sik_hatalar=_neg_hata),
          ("Önce negatif tutarlı satırları bul, sonra yalnızca sonucu `ONAY` olanları ayır.",
           "Her biçimde tutar ve sonuç ayrı alandır; `awk` ile iki koşulu birlikte sınayabilirsin.",
           "Alanları ayırıp `tutar < 0` ve `sonuc == ONAY` koşullarını birlikte sağlayan satırları `wc -l` ile say."),
          puan=40, baslik="Negatif tutar"),
    Gorev("Bir kuponu **en çok kez kullanan** hesap (kullanıcı) hangisi? Yalnızca onaylanan işlemleri say.",
          Metin("kupon", bicim="kullanıcı kimliği", sik_hatalar=_kupon_hata),
          ("Kuponu `-` olmayan ve onaylanan satırları (kullanıcı, kupon) çifti olarak say; normal kullanıcı bir kuponu bir kez kullanır.",
           "`sort | uniq -c | sort -rn | head` çiftleri sayıp en çok tekrar edeni başa getirir.",
           "Kullanıcı ve kupon alanlarını yan yana yazdırıp `sort | uniq -c | sort -rn | head -3` çalıştır; ilk satırdaki kullanıcı cevaptır."),
          puan=50, baslik="Kupon kötüye kullanımı"),
    Gorev("Orijinal ödeme tutarından **daha fazla iade** eden işlemin numarası nedir? (iade satırının kendi `islem` numarası)",
          Metin("iade", bicim="işlem numarası", sik_hatalar=_iade_hata),
          ("İade satırının `ref` alanı hangi ödemenin iadesi olduğunu söyler; iki tutarı karşılaştır.",
           "Her ödemenin tutarını işlem numarasıyla sakla (`awk` dizisi), iadeye gelince `ref`'teki ödemenin tutarına bak.",
           "`awk` ile `t[islem]=tutar` tutup `tur==iade` satırında `tutar > t[ref]` olanı yazdır."),
          puan=50, baslik="Fazla iade"),
    Gorev("**3-D Secure atlanarak ONAYLANAN** ödeme sayısı kaçtır? (RED olanları sayma, iade satırları zaten `-`)",
          Sayi("ucd", sik_hatalar=_ucd_hata),
          ("`ucd` alanı `ok`, `atlandi` ya da `-` olur. Hangi değer sorunlu?",
           "`ucd == atlandi` ve `sonuc == ONAY` koşullarını birlikte sağlayan ödeme satırlarını say.",
           "Biçim ne olursa olsun `awk` ile ilgili iki alanı sınayıp `wc -l` ile say."),
          puan=40, baslik="3-D Secure atlama"),
    Gorev("`<<islem_dosya>>` içinde **tam kart numarasının (PAN) açık yazıldığı** satır sayısı kaçtır?",
          Sayi("pan"),
          ("Tam kart numarası 16 rakamdır ve maskelenmemiştir (arada `*` yok).",
           "`grep -E` ile ardışık 16 rakam arayabilirsin: `[0-9]{16}`.",
           "`grep -cE '[0-9]{16}' <<islem_dosya>>` ilgili satırların sayısını verir."),
          puan=30, baslik="Açık kart numarası"),
    Gorev("Logda **tam kart numarası** ile **açık TCKN ve telefon** bulundu. Hangi uyum çerçeveleri ilgilidir?",
          Secmeli([
              ("Kart numarası PCI-DSS'i, TCKN ve telefon KVKK'yı ilgilendirir; iki ayrı bulgu yazılır",
               "Doğru. PCI-DSS kart verisi, KVKK kişisel veri içindir; aynı logda iki ayrı uyum ihlali olabilir."),
              ("Üçü de yalnızca PCI-DSS kapsamındadır, çünkü ödeme sistemindeki her veri kart verisi sayılır ve aynı kuralla korunur",
               "Yanlış. PCI-DSS kart verisini kapsar; TCKN ve telefon kişisel veridir ve KVKK'ya takılır."),
              ("Üçü de yalnızca KVKK kapsamındadır, çünkü kart numarası da kişiye ait bir veridir ve ayrıca standart gerekmez",
               "Yanlış. Kart numarası da kişisel veri olabilir ama kart verisi için asıl standart PCI-DSS'tir; ikisi birlikte düşünülür."),
              ("Hiçbiri uyum konusu değildir; yalnızca iyi uygulama tavsiyesi olarak raporun sonuna eklenir",
               "Yanlış. İkisi de düzenlemeye bağlı yükümlülüktür; ihlal yaptırım ve bildirim gerektirebilir."),
          ], dogru=0),
          ("Hangi veri hangi düzenlemenin konusu? Kart verisi ile kişisel veri aynı şey değil.",
           "PCI-DSS ödeme kartı verisinin standardıdır; KVKK Türkiye'de kişisel verinin kanunudur.",
           "Kart numarası → PCI-DSS, TCKN ve telefon → KVKK; iki ayrı bulgu."),
          puan=30, baslik="Uyum eşleştirme"),
    Gorev("`yapilandirma/uygulama.conf` içindeki dört riski kapat: hata ayıklama kapalı, TLS en az 1.2, kart numarası maskeli loglansın, "
          "gizli anahtar dosyada düz metin olmasın (ortam değişkeninden okunsun, örn. `${HMAC_ANAHTAR_ORTAM}`). Diğer satırlara dokunma. "
          "Bitince `cevap 7`.",
          Durum(_conf_kontrol, "sed ile DEBUG=false, TLS_MIN_SURUM=1.2, LOG_KART_NO=maskeli, HMAC_ANAHTAR=${HMAC_ANAHTAR_ORTAM}"),
          ("Dosyadaki `DEBUG`, `TLS_MIN_SURUM`, `LOG_KART_NO` ve `HMAC_ANAHTAR` satırlarına bak.",
           "`nano` ile değiştirebilirsin ya da `sed -i 's/^ANAHTAR=.*/ANAHTAR=yeni/' dosya` ile satır bazında.",
           "`sed -i 's/^DEBUG=.*/DEBUG=false/' yapilandirma/uygulama.conf` biçiminde dört satırı sırayla değiştir."),
          puan=60, baslik="Yapılandırmayı sertleştir"),
    Gorev("`kod/islem.py` içindeki iki fonksiyonu düzelt: negatif/sıfır tutar ve bakiyeyi aşan tutar reddedilsin; iade, **önceki iadelerle birlikte** "
          "orijinal tutarı aşmasın ve negatif olmasın. Fonksiyon adlarını değiştirme. Bitince `cevap 8`.",
          Durum(_kod_kontrol, "tutar_gecerli_mi: 0 < tutar <= bakiye; iade_gecerli_mi: 0 < istenen <= orijinal - onceki_iade"),
          ("İki fonksiyon da tek koşula bakıyor. Eksik koşulları düşün: alt sınır ve önceki iadeler.",
           "`tutar` için hem `> 0` hem `<= bakiye`; iade için `istenen`, `orijinal - onceki_iade` değerini aşmamalı.",
           "`return 0 < tutar <= bakiye` ve `return 0 < istenen <= orijinal - onceki_iade` biçiminde, fonksiyon gövdelerini `nano kod/islem.py` ile değiştir."),
          puan=70, baslik="İş mantığını düzelt"),
    Gorev("**Düzeltme planı** yaz (en az 35 kelime, tırnak içinde): bulguları önem sırasına koy (para kaybı, kart verisi, kişisel veri, doğrulama atlama), "
          "her birine ilgili standardı (PCI-DSS/KVKK) bağla ve düzeltme sırasını söyle. Bitince `cevap 9 \"...\"`.",
          Serbest("Önceliklendirme: negatif tutar ve fazla iade doğrudan para kaybı olduğu için Kritik; açık kart numarası PCI-DSS ve açık TCKN/telefon KVKK "
                  "açısından Yüksek; 3-D Secure atlama ve kupon tekrarı Orta. Plan: önce kod doğrulamalarını (tutar alt sınırı, iade üst sınırı) düzeltmek, "
                  "kart numarasını maskelemek ve hata ayıklamayı kapatmak, sonra kupon başına tek kullanım ve 3-D Secure zorunluluğu getirmek, "
                  "TLS sürümünü ve anahtar yönetimini düzeltmek, tüm düzeltmelerden sonra doğrulama testi yapmak.", min_kelime=35),
          ("Plan; önem sırası, her bulgunun uyum bağı ve düzeltme sırasından oluşur.",
           "Önce para kaybı bulgularını, sonra uyum bulgularını yaz; her birinin yanına standart adını ekle.",
           "`cevap 9 \"Önceliklendirme: ... PCI-DSS ... KVKK ... Plan: önce ... sonra ... doğrulama testi\"` biçiminde yaz."),
          puan=60, baslik="Düzeltme planı"),
]


def _kapanis():
    return """
Bu vakada teknik tarayıcıların göremediği şeyleri buldun: bir ödeme akışının **kendi kurallarındaki boşluklar** (negatif
tutar, fazla iade, tekrar kullanılan kupon, atlanan doğrulama) ve **uyum borçları** (açık kart numarası, açık kişisel
veri). Saldırgan gözüyle bunlar parayı doğrudan çıkaran, loglarda gürültüsüz bir yol; savunmacı gözüyle ise sunucu
sertleştirmesinden daha önce kodun içine konan doğrulamalar, loga ne yazılacağına dair bir politika ve her bulguyu bir
standarda bağlayan bir rapor demek. İş mantığı ve uyum bilen biri, saf teknik bir pentester'dan daha değerli bir rapor yazar.
"""


SEVIYE = Seviye(
    kimlik="c24b03",
    cilt=24,
    bolum=3,
    baslik="Vaka 3: Finansal Uygulama Değerlendirmesi",
    brifing="""
Selin Aksoy bir flash bellek uzatıyor: "Üçüncü vaka senin tam alanın. **<<musteri>>** (<<sektor>>) için <<uygulama>>
değerlendirmesi. <<hikaye>> Kapsam: kod, yapılandırma ve işlem logları. Sunucuya dokunmuyoruz, dosya kopyalarına bakıyoruz."

Mert Yavuz ekliyor: "Tarayıcılar `UNION SELECT` bulur, ama `tutar=-500` onaylanmışsa hiçbir tarayıcı bunu hata saymaz.
Bunun için uygulamanın **ne yapması gerektiğini** bilmen lazım." Deniz Kara loga bakıp kaşını çatıyor: "Bu kart
numaraları niye açık duruyor? Şu satırlar bir denetçinin eline geçmesin."

Görevin: iş mantığı ve uyum bulgularını sayılarıyla çıkarmak, önceliklendirmek ve düzeltmek.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **British Airways 2018:** Kamuya açık anlatımlara göre ödeme sayfasına yerleştirilen kötü amaçlı bir betik kart bilgilerini
  topladı ve olay yüksek bir düzenleyici cezayla sonuçlandı. Ödeme sayfasındaki betiklerin envanteri ve izlenmesi önleme
  katmanı; ödeme akışında beklenmeyen dış bağlantılar tespit katmanıdır.
- **Capital One 2019:** Kamuya açık bilgilere göre, bir uygulamadaki sunucu taraflı istek sahteciliği (SSRF) ve aşırı
  yetkili bir bulut rolü, çok sayıda müşteri kaydının sızmasına yol açtı. Bu vakadaki gibi yapılandırma ve en az yetki
  incelemesi, olayın zincirinden en az bir halkayı kırabilirdi.
- **KVKK ve ihlal bildirimi:** Kişisel veri ihlallerinde veri sorumlusunun Kurul'a kural olarak en kısa sürede ve en geç
  72 saat içinde bildirim yapması beklenir. Logda açık duran kimlik ve telefon bilgisi, ihlalin kapsamını büyütür; DEBUG
  ayarının üretimde kapalı olması ve kart/kimlik verisinin maskelenmesi basit ama etkili önlemlerdir.
""",
    sure_hedef_dk=60,
)
