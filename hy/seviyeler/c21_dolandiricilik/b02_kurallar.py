"""Cilt 21 · Bölüm 2 — Kural Motorları.

Beceri: hız (velocity), eşik, "eşiğin hemen altı" ve coğrafya ("imkânsız yolculuk") kurallarını
Python ile yazmak; yakalanan dolandırıcı ve yanlış pozitif (meşru müşteriyi işaretleme) dengesini
ölçmek. Cilt 3'teki log avcısının finansal, işlem tabanlı hali.

Laboratuvar: birkaç bin satırlık kurgusal işlem CSV'si. Oyun, oyuncunun `kurallar.py` betiğini
lab verisinde ve hiç görmediği, kontrol anında üretilen yeni bir veride çalıştırır; kaç dolandırıcı
hesabın yakalandığını ve kaç meşru hesabın yanlışlıkla işaretlendiğini ölçer.
"""
from __future__ import annotations

import os
import random
import re
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

VAKALAR = [
    {"kod": "ferahbank", "onek": "FB", "kanal": "kart ve internet şubesi işlemleri",
     "olay": "Ferah Bank'ın kart işlemlerinde son haftalarda müşteri şikâyetleri arttı."},
    {"kod": "pazarix", "onek": "PZ", "kanal": "sipariş ödemeleri",
     "olay": "Pazarix'in ödeme sayfasında kampanya haftasından sonra tuhaf işlem kümeleri görüldü."},
    {"kod": "paramix", "onek": "PM", "kanal": "sanal POS işlemleri",
     "olay": "Paramix'in sanal POS trafiğinde üye işyerleri alışılmadık işlem patlamalarından yakındı."},
]

ULKELER = ["RO", "NL", "US", "AE", "GB", "DE", "FR"]
ESIK_ALTI = (9500, 10000)
YUKSEK = 50000
HIZ_N, HIZ_SN = 5, 600
COG_SN = 7200
KANALLAR = ["pos", "pos", "online", "online", "atm"]


# ---------------------------------------------------------------- veri üretimi

def _satir(t, h, tutar, kanal, ulke, cihaz, etiket="mesru"):
    return {"t": t, "hesap": h, "tutar": tutar, "kanal": kanal, "ulke": ulke, "cihaz": cihaz, "etiket": etiket}


def ref_supheli(satirlar: list) -> dict:
    """Referans kural seti. satirlar: {t(datetime), hesap, tutar(float), ulke, ...}. {hesap: {neden,...}}"""
    hesap = {}
    for r in satirlar:
        hesap.setdefault(r["hesap"], []).append(r)
    sonuc = {}
    for h, rs in hesap.items():
        rs.sort(key=lambda r: r["t"])
        nedenler = set()
        for i in range(len(rs) - HIZ_N + 1):
            if (rs[i + HIZ_N - 1]["t"] - rs[i]["t"]).total_seconds() <= HIZ_SN:
                nedenler.add("hiz")
                break
        if sum(1 for r in rs if ESIK_ALTI[0] <= r["tutar"] < ESIK_ALTI[1]) >= 3:
            nedenler.add("esik")
        if any(r["tutar"] >= YUKSEK for r in rs):
            nedenler.add("tutar")
        for a, b in zip(rs, rs[1:]):
            if a["ulke"] != b["ulke"] and (b["t"] - a["t"]).total_seconds() < COG_SN:
                nedenler.add("cografya")
                break
        if nedenler:
            sonuc[h] = nedenler
    return sonuc


def veri_uret(rng: random.Random, onek: str, n_mesru: int = 150, ort: int = 17) -> dict:
    """{satirlar, hesaplar, dolandirici: {hesap: tur}, tuzak: {hesap: tur}, sayilar}"""
    for _ in range(30):
        d = _veri_uret(rng, onek, n_mesru, ort)
        ref = ref_supheli(d["satirlar"])
        if set(ref) == set(d["dolandirici"]):
            return d
    raise RuntimeError("tutarlı veri üretilemedi")


def _veri_uret(rng, onek, n_mesru, ort):
    gun = u.gun(rng)
    benzersiz = list(dict.fromkeys(f"{onek}-{rng.randint(1000, 9999)}" for _ in range(n_mesru * 3)))
    n_hiz, n_esik, n_yuk, n_cog = (rng.randint(3, 5) for _ in range(4))
    n_fraud = n_hiz + n_esik + n_yuk + n_cog
    hesaplar = benzersiz[: n_mesru + n_fraud]
    mesru, fraud = hesaplar[:n_mesru], hesaplar[n_mesru:]
    satirlar = []
    cihaz_of = {h: f"cihaz-{rng.randrange(16**5):05x}" for h in hesaplar}

    def an(gun_no, saat_bas=8.0, saat_son=23.0):
        return gun + timedelta(days=gun_no, seconds=rng.randint(int(saat_bas * 3600), int(saat_son * 3600)))

    def normal(h, n, gun_no=None, saat_son=23.0, ust=2500):
        for _ in range(n):
            tutar = min(ust, round(rng.choice([rng.uniform(15, 300), rng.uniform(40, 900), rng.uniform(200, 2500)]), 2))
            gn = rng.randint(0, 2) if gun_no is None else gun_no
            satirlar.append(_satir(an(gn, 8, saat_son), h, tutar, rng.choice(KANALLAR), "TR", cihaz_of[h]))

    tuzak = {}
    kalan = list(mesru)
    rng.shuffle(kalan)

    def al(n, tur):
        sec, kalan[:] = kalan[:n], kalan[n:]
        for h in sec:
            tuzak[h] = tur
        return sec

    for h in al(6, "ard_arda"):           # market turu: 3-4 işlem 5 dakikada (eşik 5)
        normal(h, rng.randint(6, 10))
        t = an(rng.randint(0, 2), 10, 20)
        for k in range(rng.randint(3, 4)):
            satirlar.append(_satir(t + timedelta(seconds=k * rng.randint(40, 80)), h,
                                   round(rng.uniform(20, 400), 2), "pos", "TR", cihaz_of[h]))
    for h in al(8, "kira"):                # düzenli ödeme: büyük ama meşru
        normal(h, rng.randint(8, 14))
        satirlar.append(_satir(an(rng.randint(0, 2), 9, 12), h, float(rng.randint(12000, 45000)), "duzenli_odeme",
                               "TR", cihaz_of[h]))
    for h in al(5, "esik_yakini"):         # 9.500-9.999 aralığında 1-2 meşru işlem
        normal(h, rng.randint(8, 14))
        for _ in range(rng.randint(1, 2)):
            satirlar.append(_satir(an(rng.randint(0, 2), 9, 20), h, float(rng.randint(ESIK_ALTI[0], ESIK_ALTI[1] - 1)),
                                   rng.choice(["online", "pos"]), "TR", cihaz_of[h]))
    for h in al(4, "gezgin"):              # tatilci: TR sabah, yurt dışı ertesi gün öğleden sonra
        ulke = rng.choice(ULKELER)
        for _ in range(rng.randint(3, 5)):
            satirlar.append(_satir(an(0, 8, 11), h, round(rng.uniform(30, 600), 2), "pos", "TR", cihaz_of[h]))
        for _ in range(rng.randint(4, 7)):
            satirlar.append(_satir(an(rng.randint(1, 2), 14, 22), h, round(rng.uniform(30, 900), 2), "pos", ulke,
                                   cihaz_of[h]))
    for h in kalan:
        normal(h, max(4, int(rng.gauss(ort, 4))))
    # dolandırıcılar
    dolandirici = {}
    fs = list(fraud)
    rng.shuffle(fs)
    for tur, n in (("hiz", n_hiz), ("esik", n_esik), ("tutar", n_yuk), ("cografya", n_cog)):
        for h in [fs.pop() for _ in range(n)]:
            dolandirici[h] = tur
            normal(h, rng.randint(2, 5), ust=1500)
            if tur == "hiz":
                t = an(rng.randint(0, 2), 0, 5)
                for k in range(rng.randint(6, 12)):
                    satirlar.append(_satir(t + timedelta(seconds=k * rng.randint(15, 40)), h, round(rng.uniform(5, 60), 2),
                                           "online", "TR", f"cihaz-{rng.randrange(16**5):05x}", "dolandirici"))
            elif tur == "esik":
                for k in range(rng.randint(5, 8)):
                    satirlar.append(_satir(an(1, 1, 16), h, float(rng.randint(ESIK_ALTI[0], ESIK_ALTI[1] - 1)), rng.choice(["online", "atm"]),
                                           "TR", f"cihaz-{rng.randrange(16**5):05x}", "dolandirici"))
            elif tur == "tutar":
                satirlar.append(_satir(an(rng.randint(0, 2), 1, 6), h, float(rng.randint(YUKSEK, 140000)), "online",
                                       "TR", f"cihaz-{rng.randrange(16**5):05x}", "dolandirici"))
            else:
                t = an(rng.randint(0, 2), 9, 21)
                satirlar.append(_satir(t, h, round(rng.uniform(40, 700), 2), "pos", "TR", cihaz_of[h]))
                satirlar.append(_satir(t + timedelta(minutes=rng.randint(10, 90)), h, round(rng.uniform(300, 2500), 2),
                                       "online", rng.choice(ULKELER), f"cihaz-{rng.randrange(16**5):05x}", "dolandirici"))
    satirlar.sort(key=lambda r: r["t"])
    sayilar = {"hiz": n_hiz, "esik": n_esik, "tutar": n_yuk, "cografya": n_cog}
    return {"satirlar": satirlar, "hesaplar": hesaplar, "dolandirici": dolandirici, "tuzak": tuzak, "sayilar": sayilar}


def csv_satirlari(d: dict, etiketli: bool = False) -> list:
    cikti = []
    for i, r in enumerate(d["satirlar"], 1):
        s = f"TX{i:06d},{r['t']:%Y-%m-%d %H:%M:%S},{r['hesap']},{r['tutar']:.2f},{r['kanal']},{r['ulke']},{r['cihaz']}"
        if etiketli:
            s += f",{r['etiket']}"
        cikti.append(s)
    return cikti


BASLIK = "islem_id,zaman,hesap,tutar,kanal,ulke,cihaz"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    tohum = rng.randint(1, 10**9)
    d = veri_uret(random.Random(tohum), v["onek"])
    g = veri_uret(random.Random(tohum + 7), v["onek"], 45, 9)
    cografya = sorted(h for h, t in d["dolandirici"].items() if t == "cografya")
    bandli = {r["hesap"] for r in d["satirlar"] if ESIK_ALTI[0] <= r["tutar"] < ESIK_ALTI[1]}
    ml_fp = sum(1 for r in g["satirlar"] if r["tutar"] >= 10000 and r["etiket"] == "mesru")
    return {
        "vaka": f"{m['ad']} — {v['kanal']}",
        "musteri": m, "v": v, "tohum": tohum, "n_satir": len(d["satirlar"]),
        "metin": {"musteri": m["ad"], "olay": v["olay"], "kanal": v["kanal"], "satir": len(d["satirlar"]),
                  "onek": v["onek"]},
        "cevaplar": {"hiz": d["sayilar"]["hiz"], "cografya": cografya, "esik": d["sayilar"]["esik"], "naif_fp": ml_fp},
        "_bandli": len(bandli),
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = veri_uret(random.Random(s["tohum"]), v["onek"])
    g = veri_uret(random.Random(s["tohum"] + 7), v["onek"], 45, 9)
    u.yaz(lab / "islemler.csv", BASLIK + "\n" + "\n".join(csv_satirlari(d)) + "\n")
    u.yaz(lab / "gecmis_etiketli.csv", BASLIK + ",etiket\n" + "\n".join(csv_satirlari(g, True)) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — işlem analizi (kurgusal veri)\n\n"
          f"islemler.csv         : {len(d['satirlar'])} işlem (inceleyeceğin veri; etiket yok)\n"
          "gecmis_etiketli.csv  : eski, sonuçlanmış işlemler; etiket = dolandirici | mesru\n\n"
          "Kural motorunu lab'ın köküne yaz: kurallar.py\n"
          "Kullanım : python3 kurallar.py islemler.csv\n"
          "Çıktı    : şüpheli HESAPLARI satır satır yaz (örn. `FB-1234 hiz`)\n\n"
          "SOC kuralları:\n"
          "  hiz     : aynı hesaptan 10 dakika içinde 5 ya da daha fazla işlem\n"
          "  esik    : 9.500 TL (dahil) ile 10.000 TL (hariç) arasında 3 ya da daha fazla işlem\n"
          "  tutar   : tek işlemde 50.000 TL ve üstü\n"
          "  cografya: aynı hesabın art arda iki işlemi, iki saatten kısa sürede farklı ülkelerden\n")
    u.yaz(lab / "ornekler" / "iskelet.py", ISKELET_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "zaman_farki.py", ZAMAN_PY, mod=0o755)


ISKELET_PY = r'''#!/usr/bin/env python3
# iskelet.py — kural motorunun iskeleti: sadece "tutar" kuralı var
import csv
import sys

hesaplar = set()
with open(sys.argv[1], encoding="utf-8", newline="") as f:
    for r in csv.DictReader(f):          # her satır bir sözlük: r["hesap"], r["tutar"] ...
        if float(r["tutar"]) >= 50000:
            hesaplar.add(r["hesap"])

for h in sorted(hesaplar):
    print(h, "tutar")

# Eksikler: kullanım mesajı (argümansızsa exit 1), hız, eşik-altı ve coğrafya kuralları.
# İpucu: hız ve coğrafya için işlemleri hesaba göre grupla ve ZAMANA göre sırala.
'''

ZAMAN_PY = r'''#!/usr/bin/env python3
# zaman_farki.py — iki zaman damgası arasındaki saniyeyi bulmak
from datetime import datetime

BICIM = "%Y-%m-%d %H:%M:%S"
a = datetime.strptime("2026-03-04 10:00:00", BICIM)
b = datetime.strptime("2026-03-04 10:07:30", BICIM)
print((b - a).total_seconds())            # 450.0
'''

KURALLAR_PY = r'''#!/usr/bin/env python3
import csv
import sys
from collections import defaultdict
from datetime import datetime

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <islemler.csv>")
    sys.exit(1)

BICIM = "%Y-%m-%d %H:%M:%S"
islemler = defaultdict(list)
with open(sys.argv[1], encoding="utf-8", newline="") as f:
    for r in csv.DictReader(f):
        islemler[r["hesap"]].append((datetime.strptime(r["zaman"], BICIM), float(r["tutar"]), r["ulke"]))

for hesap, liste in sorted(islemler.items()):
    liste.sort()
    nedenler = []
    for i in range(len(liste) - 4):                       # hız: 5 işlem 10 dakikada
        if (liste[i + 4][0] - liste[i][0]).total_seconds() <= 600:
            nedenler.append("hiz")
            break
    if sum(1 for _, t, _ in liste if 9500 <= t < 10000) >= 3:   # eşik altı
        nedenler.append("esik")
    if any(t >= 50000 for _, t, _ in liste):                     # büyük tutar
        nedenler.append("tutar")
    for (t1, _, u1), (t2, _, u2) in zip(liste, liste[1:]):       # imkânsız yolculuk
        if u1 != u2 and (t2 - t1).total_seconds() < 7200:
            nedenler.append("cografya")
            break
    if nedenler:
        print(hesap, ",".join(nedenler))
'''


# ---------------------------------------------------------------- denetim

KATEGORI_ADI = {"hiz": "hız (10 dakikada 5 işlem)", "esik": "eşik altı (9.500-9.999 TL, 3+ işlem)",
                "tutar": "büyük tutar (50.000 TL ve üstü)", "cografya": "coğrafya (imkânsız yolculuk)"}
TUZAK_IPUCU = {
    "ard_arda": "peş peşe 3-4 alışveriş yapan meşru müşteriler (hız eşiğin çok düşük; eşik 5)",
    "kira": "kira/düzenli ödeme gibi büyük ama meşru işlemler (tutar eşiğin çok düşük; 50.000 TL'ye bak)",
    "esik_yakini": "9.500-9.999 TL aralığında tek-iki işlemi olan meşru müşteriler (3 ve üstünü iste)",
    "gezgin": "yurt dışına seyahat eden müşteriler (coğrafyada iki saatten kısa süreyi iste; ülke değişimi tek başına yetmez)",
}


def _olc(calistir: bt.Calistirici, yol: Path, d: dict, ad: str) -> Sonuc | None:
    c = calistir(str(yol))
    nasil = calistir.goster(ad)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    bilinen = set(d["hesaplar"])
    isaretli = {x for x in re.findall(r"[A-Z]{2}-\d{4}", c.stdout) if x in bilinen}
    if not isaretli:
        return Sonuc(False, f"`{nasil}` çıktısında şüpheli hesap bulamadım. Her şüpheli hesabı satır satır yaz "
                     "(örn. `FB-1234 hiz`)." + bt.ozet(c), yakin=True)
    fraud = set(d["dolandirici"])
    yakalanan = isaretli & fraud
    kacan = fraud - isaretli
    yanlis = isaretli - fraud
    if len(kacan) <= 1 and len(yanlis) <= 2:
        return None
    parca = [f"`{nasil}`: {len(fraud)} dolandırıcı hesabın {len(yakalanan)}'ini yakaladın, "
             f"{len(yanlis)} meşru hesabı yanlışlıkla işaretledin."]
    for tur, ad_t in KATEGORI_ADI.items():
        toplam = [h for h, t in d["dolandirici"].items() if t == tur]
        yak = [h for h in toplam if h in isaretli]
        if len(yak) < len(toplam):
            parca.append(f"Eksik: {ad_t} kuralı ({len(toplam)} hesaptan {len(yak)}'i yakalandı).")
    if len(yanlis) > 2:
        sayac = {}
        for h in yanlis:
            tur = d["tuzak"].get(h)
            if tur:
                sayac[tur] = sayac.get(tur, 0) + 1
        for tur, n in sorted(sayac.items(), key=lambda x: -x[1]):
            parca.append(f"Yanlış pozitif: {n} hesap, {TUZAK_IPUCU[tur]}.")
    return Sonuc(False, "\n    ".join(parca), yakin=bool(yakalanan))


def _kurallar_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    lab_csv = Path(b.lab) / "islemler.csv"
    if not lab_csv.is_file():
        return Sonuc(False, f"{lab_csv} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    d = veri_uret(random.Random(s["tohum"]), s["v"]["onek"])
    sonuc = _olc(calistir, lab_csv, d, "islemler.csv")
    if sonuc:
        return sonuc
    rng = random.Random()
    yeni = veri_uret(rng, rng.choice(VAKALAR)["onek"], 90, 12)
    fd, ad = tempfile.mkstemp(prefix="hy_islem_", suffix=".csv")
    os.close(fd)
    gecici = Path(ad)
    try:
        gecici.write_text(BASLIK + "\n" + "\n".join(csv_satirlari(yeni)) + "\n", encoding="utf-8")
        sonuc = _olc(calistir, gecici, yeni, str(gecici))
        if sonuc:
            sonuc.mesaj += ("\n    (Bu, hiç görmediğin yeni bir veriydi. Kuralların lab verisine özel sayılar değil, "
                            "genel mantık olmalı.)")
            return sonuc
    finally:
        gecici.unlink(missing_ok=True)
    return Sonuc(True, "kurallar.py hem lab verisinde hem hiç görmediği yeni bir veride dolandırıcı hesapların "
                       "neredeyse hepsini yakaladı ve meşru müşterilerin neredeyse hiçbirini işaretlemedi. "
                       "Gerçek hayatta bu dengeyi ayarlamak işin asıl kısmıdır.")


def _hiz_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return ("Fazla saydın: 10 dakikada **5 ya da daha fazla** işlem şartı var. 3-4 işlemlik meşru market "
                "turları sayılmaz.")
    return None


def _esik_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["_bandli"] and n != beklenen:
        return ("9.500-9.999 TL aralığında **en az bir** işlemi olan her hesabı saymışsın. Kural 3 ya da daha fazla "
                "işlem ister; tek-iki işlemi olan meşru müşterileri ele.")
    return None


def _fp_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == 0:
        return "Etiket sütunu `mesru` olan satırları saymalısın; `>= 10000` olanlardan kaç tanesi meşru?"
    return None


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "kurallar.py", KURALLAR_PY)
    cikti = "python3 kurallar.py islemler.csv"
    hiz = sh(f"{cikti} | grep -c hiz", lab)
    cog = sh(f"{cikti} | grep cografya | awk '{{print $1}}'", lab).replace("\n", " ")
    esik = sh(f"{cikti} | grep -c esik", lab)
    fp = sh("awk -F, 'NR>1 && $4>=10000 && $8==\"mesru\"' gecmis_etiketli.csv | wc -l", lab)
    cozum = {1: "", 2: hiz, 3: cog, 4: esik, 5: fp}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Kural motoru = Cilt 3'ün log avcısı", """
Selin: "Cilt 3'te 'eşiği aşan IP'yi işaretle' diye bir araç yazmıştın. Fraud kural motoru onun
finansal, gerçek zamanlı hali: **koşul sağlanırsa işlemi (ya da hesabı) işaretle**." Dört kural
türüyle başlıyoruz: hız (velocity), eşik, coğrafya ve kara liste. Klasörün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Veriye ilk bakış", """
Her satır bir işlem: kimin (`hesap`), ne zaman, ne kadar, hangi kanaldan, hangi ülkeden, hangi
cihazla. Kaç işlem var ve nasıl görünüyorlar?
""", komut="head -5 islemler.csv && wc -l islemler.csv"),
    Adim("Zamanı sayıya çevirmek", """
Hız kuralı "10 dakikada 5 işlem" der; bunun için iki zaman arasındaki farkı **saniye** olarak
hesaplayabilmelisin. Python'da `datetime.strptime` metni zamana çevirir, iki zamanın farkı
`total_seconds()` verir:
""", komut="python3 ornekler/zaman_farki.py", sonra="""
Bir hesabın işlemlerini zamana göre sıralayıp `i` ile `i+4`. işlemi karşılaştırırsan "5 işlem
10 dakikaya sığdı mı?" sorusunu cevaplarsın (kayan pencere).
"""),
    Adim("Eşik: tutar dağılımına bak", """
Eşik rastgele seçilmez; verinin **normali** neye benziyor, ona bakılır. 10.000 TL ve üstü kaç
işlem var?
""", komut="awk -F, 'NR>1 && $4>=10000' islemler.csv | wc -l", sonra="""
Hepsi dolandırıcılık olamaz: kira ve düzenli ödemeler de büyük tutarlıdır. `kanal` sütununa bak
(`duzenli_odeme`). Eşiği yükseltmek yanlış alarmı azaltır ama kaçırmayı artırır; bu bir
**dengedir**.
"""),
    Adim("Coğrafya: ülkelere bak", """
"İmkânsız yolculuk": aynı kart iki saat içinde iki farklı ülkede kullanıldıysa biri sahtedir.
Ama tatile giden müşteri de ülke değiştirir; fark **zaman aralığıdır**. Ülke dağılımı:
""", komut="cut -d, -f6 islemler.csv | tail -n +2 | sort | uniq -c | sort -rn"),
    Adim("İskelet kural motoru", """
İskelet, `csv.DictReader` ile her satırı sözlüğe çevirip sadece tutar kuralını uyguluyor. Çalıştır:
""", komut="python3 ornekler/iskelet.py islemler.csv", sonra="""
Çalışıyor ama dört kuraldan biri var. `cat ornekler/iskelet.py` ile kodu oku. Hız ve coğrafya
için işlemleri hesaba göre gruplayıp zamana göre sıralaman gerekecek: `collections.defaultdict(list)`
bunun için birebir.
"""),
    Adim("Katı kuralın bedeli", """
Kural motoru şeffaf ve hızlıdır ama katıdır: dolandırıcı eşiği öğrenip altından geçer (9.999 TL
gibi), sıkı kural ise meşru müşteriyi engeller (**yanlış pozitif**, false positive). Etiketli
geçmiş veride dolandırıcı satır sayısı:
""", komut="grep -c dolandirici gecmis_etiketli.csv", sonra="""
**Hacker gözüyle:** Saldırgan, kuralı keşfedince altından geçer; savunmacı da eşiğin hemen
altında biriken işlemleri (3+ işlem) ayrı bir kuralla yakalar. İyi bir kural motoru tek eşik değil,
**davranış birleşimidir**.
"""),
]

GOREVLER = [
    Gorev("`kurallar.py` yaz: `python3 kurallar.py islemler.csv` şüpheli **hesapları** satır satır yazsın "
          "(örn. `<<onek>>-1234 hiz`). Dört SOC kuralı `OKUBENI.txt`'de: hız, eşik altı, büyük tutar, coğrafya. "
          "Argümansızsa `Kullanım` mesajı ve `exit 1`. Oyun betiğini hem bu veride hem hiç görmediği yeni bir "
          "veride deneyip kaç dolandırıcıyı yakaladığını ve kaç meşru hesabı yanlış işaretlediğini ölçecek.",
          bt.BetikKontrol("kurallar.py", _kurallar_denetle,
                          "Örnek `kurallar.py`:\n\n```\n" + KURALLAR_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/iskelet.py`'yi genişlet: dört kuralı tek döngüde, hesap başına uygula.",
           "İşlemleri `defaultdict(list)` ile hesaba göre grupla, her listeyi zamana göre sırala. Hız: `liste[i+4]` ile "
           "`liste[i]` arası ≤ 600 sn. Coğrafya: art arda iki işlemde ülke farklı ve fark < 7200 sn.",
           "Hız: `for i in range(len(liste)-4): if (liste[i+4][0]-liste[i][0]).total_seconds() <= 600`. Eşik altı: "
           "`sum(1 for ... if 9500 <= t < 10000) >= 3`. Coğrafya: `zip(liste, liste[1:])` ile komşu çiftler."),
          puan=70, baslik="Kural motoru"),
    Gorev("Hız kuralını (10 dakikada **5 ya da daha fazla** işlem) tetikleyen kaç hesap var?",
          Sayi("hiz", sik_hatalar=_hiz_hata),
          ("Kendi aracının çıktısına bak ya da hesap başına zamana göre sıralı pencere kaydır.",
           "Aracın her hesabın yanına nedenini yazıyorsa `grep -c hiz` işini görür.",
           "`python3 kurallar.py islemler.csv | grep -c hiz`"),
          puan=30, baslik="Hız ihlali"),
    Gorev("İmkânsız yolculuk kuralına (art arda iki işlem, iki saatten kısa sürede farklı ülkeler) takılan "
          "hesapları yaz.",
          Kume("cografya", bicim="hesap numaraları, virgülle ayrılmış"),
          ("Ülke değişimi tek başına yetmez; iki işlem arasındaki süreye de bak. Tatilciler de ülke değiştirir.",
           "Aracının çıktısındaki `cografya` satırlarını süz.",
           "`python3 kurallar.py islemler.csv | grep cografya | awk '{print $1}'`"),
          puan=35, baslik="İmkânsız yolculuk"),
    Gorev("Dolandırıcı, 10.000 TL sınırının altından geçmek için işlemleri **9.500-9.999 TL** aralığında "
          "bölmüş. Bu aralıkta **3 ya da daha fazla** işlemi olan kaç hesap var?",
          Sayi("esik", sik_hatalar=_esik_hata),
          ("Önce aralıktaki işlemleri hesaba göre say; sonra eşiğe bak.",
           "Tutar 4. sütun: `awk -F, '$4>=9500 && $4<10000 {print $3}' islemler.csv | sort | uniq -c`",
           "Yukarıdaki çıktıda sayısı 3 ve üstü olan satırları say: `... | awk '$1>=3' | wc -l`"),
          puan=30, baslik="Eşiğin altından"),
    Gorev("`gecmis_etiketli.csv` etiketli geçmiş veri. Sadece **\"tutar ≥ 10.000 TL ise işaretle\"** diye "
          "naif bir kural kullansaydık kaç **meşru** (`etiket=mesru`) işlemi yanlışlıkla işaretlerdik? "
          "(yanlış pozitif sayısı)",
          Sayi("naif_fp", sik_hatalar=_fp_hata),
          ("Etiket son sütunda; iki koşulu birlikte uygulamalısın.",
           "`awk -F, 'NR>1 && koşul1 && koşul2' gecmis_etiketli.csv | wc -l`; tutar `$4`, etiket `$8`.",
           "`awk -F, 'NR>1 && $4>=10000 && $8==\"mesru\"' gecmis_etiketli.csv | wc -l`"),
          puan=30, baslik="Yanlış pozitif"),
    Gorev("Kural motorlarının iki temel sınırı nedir?",
          Secmeli([
              ("Katıdır: dolandırıcı kuralı öğrenip altından geçer; çok sıkı olunca meşru müşteri de engellenir",
               "Doğru. İlki kaçırma (false negative), ikincisi yanlış alarm (false positive). Bu yüzden kurallar "
               "ML skorlama ve insan incelemesiyle katmanlanır."),
              ("Yavaştır ve her işlemi işlemek dakikalar sürer",
               "Tersine: kurallar çok hızlıdır, anında karar verebilir."),
              ("Şeffaf değildir: neden işaretlendiğini kimse söyleyemez",
               "Tersine: kural şeffaftır; hangi koşulun tetiklendiği açıkça bellidir."),
              ("Sadece kredi kartı işlemlerinde çalışır",
               "Kurallar havale, giriş, iade gibi her olay türüne yazılabilir."),
          ]),
          ("Eşik 9.999 TL olduğunda saldırgan ne yapar? Eşik çok düşük olursa kim zarar görür?",
           "İlk soru kaçırmayı, ikincisi yanlış alarmı anlatır.",
           "Kurallar hızlı ve şeffaf ama katı."),
          puan=25, baslik="Kuralların sınırı"),
    Gorev("\"İmkânsız yolculuk\" kuralı neden **iki saat gibi bir süre sınırı** içerir? Ülke değişimi neden tek "
          "başına yetmez?",
          Secmeli([
              ("Meşru müşteri de seyahat eder; fiziksel olarak mümkün olmayacak kadar kısa sürede ülke değişimi şüphelidir",
               "Doğru. Kural 'ülke değişti'yi değil, 'bu süre içinde fiziken gidilemez'i arar."),
              ("Çünkü kartlar yalnızca iki saat geçerlidir",
               "Kartların böyle bir süresi yoktur; sınır kuralın mantığından gelir."),
              ("Çünkü ülke bilgisi logda yalnızca iki saat saklanır",
               "Kayıt saklama süresiyle ilgisi yok."),
              ("Çünkü yurt dışı işlemler her zaman dolandırıcılıktır",
               "Tatilciler ve iş seyahatindekiler meşru yurt dışı işlem yapar; her ülke değişimini işaretlemek yanlış "
               "pozitif üretir."),
          ]),
          ("Tatildeki müşteriyi düşün.",
           "Kural zamanı ve mesafeyi birlikte değerlendirir.",
           "Mümkün olmayan hız = şüphe."),
          puan=25, baslik="Neden süre sınırı"),
]

SEVIYE = Seviye(
    kimlik="c21b02",
    cilt=21,
    bolum=2,
    baslik="Kural Motorları",
    brifing="""
**<<musteri>>**: <<olay>> Deniz, SOC'tan getirdiği dosyayı masaya bırakıyor: "<<satir>> işlemlik
bir günlük döküm var. Elle bakmak imkânsız. Cilt 3'te log avcısını yazmıştın, şimdi aynı fikri
paraya uygula: hız, eşik, büyük tutar ve coğrafya kurallarını yazan bir araç istiyoruz."

Selin uyarıyor: "Ama kuralı çok sıkı yazarsan kira ödeyen müşterileri ve tatildekileri bloklarsın.
Yakaladığın dolandırıcıyla yanlış alarm verdiğin müşteriyi birlikte ölçeceğiz." Mert: "Dolandırıcılar
kuralları öğrenir. 9.999 TL'yi hatırla."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kırk satırlık betiğin dört kuralla dolandırıcı hesapların neredeyse hepsini yakaladı; ama asıl ders
yanlış pozitiflerde: kira ödeyen, tatile çıkan ya da markette peş peşe alışveriş yapan müşteriler de
"anormal" görünür. Eşiği sıkılaştırırsan onları bloklar, gevşetirsen dolandırıcıyı kaçırırsın.
Saldırgan için ders: kuralın eşiğini bulursan altından geçebilirsin (9.999 TL); savunmacı için ders:
tek eşiğe değil, davranış birleşimine (eşik altında biriken işlemler, hız ve coğrafya birlikte) bak
ve kuralları ML ile katmanla (sonraki bölüm).
""",
    gercek_hayat="""
- **Hız ve coğrafya kuralları:** Kart ve ödeme sektöründe hız kontrolü (kısa sürede çok işlem) ve
  coğrafi tutarsızlık kontrolü yaygın, temel kurallardır; ülke değişimi tek başına değil, süre ve
  bağlamla birlikte değerlendirilir. Tespit: hesap bazında zaman penceresi; önlem: şüpheli durumda
  ek doğrulama (3D Secure, SMS/uygulama onayı) isteyip işlemi hemen reddetmemek.
- **Eşik altı bölme (structuring):** Kara para aklama literatüründe bilinen bir kalıptır: bildirim ya da
  kontrol eşiğinin hemen altında tutarlarla işlem bölmek. Bu tür davranış, eşik kuralı yerine
  "eşiğe yakın tutarlı işlemlerin sayısı" gibi davranış kurallarıyla izlenir.
- **Yanlış pozitifin maliyeti:** Bankalar ve ödeme şirketleri, meşru müşterinin işlemini reddetmenin de
  gelir ve itibar kaybı olduğunu bilir. Bu yüzden kural eşikleri geçmiş etiketli veriyle ölçülür ve
  düzenli gözden geçirilir.
""",
    sure_hedef_dk=45,
)
