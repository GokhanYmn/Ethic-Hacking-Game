"""Cilt 23 · Bölüm 3 — Bordro, SGK ve Uyumun Birleşimi.

Beceri: bir bordro dosyasında yetkisiz değişikliği hash karşılaştırmasıyla ve onaylı kopyayla fark etmek,
değişiklik günlüğüyle (audit log) karşılaştırıp **günlüğe düşmeyen** değişikliği bulmak, hayalet çalışanı ve
IBAN değişikliğini ayırt etmek, Cilt 10'daki bordro risklerini Türkiye'deki sistemlerle eşlemek ve işin KVKK
yüzünü anlamak. Mevzuatın ayrıntıları (madde, süre, tutar) kasıtlı olarak verilmez.

Vakalar: Medora Sağlık, Kuzgun Lojistik, Paramix. Tüm kişiler, sicil numaraları ve IBAN'lar kurgusaldır
(`TR00-LAB-...` biçimi geçerli bir IBAN değildir).
"""
from __future__ import annotations

import csv
import hashlib
import os
import random
import re
import tempfile
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Dinamik, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

SOYADLAR = ["Yılmaz", "Kaya", "Demir", "Şahin", "Çelik", "Yıldız", "Aydın", "Özdemir", "Arslan", "Doğan", "Kılıç", "Aslan"]
BASLIK = "sicil,ad,departman,brut,net,iban"
ALANLAR = ["ad", "departman", "brut", "net", "iban"]

VAKALAR = [
    {"kod": "medora", "kisi": "Dr. Aslı Hanım", "departmanlar": ["hemsirelik", "laboratuvar", "idari", "teknik", "eczane"],
     "olay": "Medora Sağlık'ın mart ayı bordrosu onaylandı ama ödeme dosyası bankaya gitmeden önce İK, dosyadaki "
             "toplam tutarın onaylı toplamdan farklı göründüğünü fark etti."},
    {"kod": "kuzgun", "kisi": "Serdar Bey", "departmanlar": ["depo", "sevkiyat", "muhasebe", "bilgi_islem", "filo"],
     "olay": "Kuzgun Lojistik'te mart bordrosu onaylandıktan sonra muhasebe, bir çalışanın maaş bilgisinin "
             "kendisine bildirilen tutardan farklı olduğunu söyledi."},
    {"kod": "paramix", "kisi": "Ece Hanım", "departmanlar": ["yazilim", "operasyon", "destek", "uyum", "finans"],
     "olay": "Paramix'te bordro ödeme dosyası bankaya gönderilmeden önceki rutin hash kontrolü başarısız oldu; "
             "kimse dosyayı elle değiştirdiğini söylemiyor."},
]

RISKLER = {
    "toplu": "Toplu ödeme dosyasının manipülasyonu",
    "hayalet": "Hayalet çalışan",
    "iban": "Banka hesabı değişikliği suistimali",
}
HEDEFLER = {"a": "toplu maaş ödeme (banka ödeme dosyası)", "b": "SGK bildirge / çalışan kayıtları",
            "c": "maaş hesabı (IBAN) güncelleme"}
RISK_HEDEF = {"toplu": "a", "hayalet": "b", "iban": "c"}


def _iban(rng) -> str:
    return "TR00-LAB-" + "-".join(f"{rng.randint(0, 9999):04d}" for _ in range(3))


def _csv_metin(satirlar: list) -> str:
    return BASLIK + "\n" + "\n".join(
        f"{r['sicil']},{r['ad']},{r['departman']},{r['brut']},{r['net']},{r['iban']}" for r in satirlar) + "\n"


def _calisanlar(rng, v: dict, n: int) -> list:
    sicil = sorted(rng.sample(range(1001, 1999), n))
    ads = set()
    sonuc = []
    for sc in sicil:
        while True:
            ad = f"{rng.choice(u.ISIMLER).capitalize()} {rng.choice(SOYADLAR)}"
            if ad not in ads:
                ads.add(ad)
                break
        brut = rng.randint(56, 190) * 500
        sonuc.append({"sicil": f"P{sc}", "ad": ad, "departman": rng.choice(v["departmanlar"]), "brut": str(brut),
                      "net": str(round(brut * 0.74)), "iban": _iban(rng)})
    return sonuc


def lab_veri(rng: random.Random, v: dict, n: int = 60) -> dict:
    onayli = _calisanlar(rng, v, n)
    guncel = [dict(r) for r in onayli]
    iban_i, net_i, mantik = rng.sample(range(len(guncel)), 3)
    iban_sicil, net_sicil = guncel[iban_i]["sicil"], guncel[net_i]["sicil"]
    eski_iban = guncel[iban_i]["iban"]
    guncel[iban_i]["iban"] = _iban(rng)
    artis = rng.randint(6, 18) * 1000
    guncel[net_i]["net"] = str(int(guncel[net_i]["net"]) + artis)
    son = int(onayli[-1]["sicil"][1:])
    hayalet_brut = rng.randint(80, 140) * 500
    hayalet = {"sicil": f"P{son + rng.randint(1, 9)}", "ad": f"{rng.choice(u.ISIMLER).capitalize()} {rng.choice(SOYADLAR)}",
               "departman": rng.choice(v["departmanlar"]), "brut": str(hayalet_brut), "net": str(round(hayalet_brut * 0.74)),
               "iban": _iban(rng)}
    while hayalet["ad"] in {r["ad"] for r in onayli}:
        hayalet["ad"] = f"{rng.choice(u.ISIMLER).capitalize()} {rng.choice(SOYADLAR)}"
    guncel.append(hayalet)
    ik = [{"sicil": r["sicil"], "ad": r["ad"], "departman": r["departman"]} for r in onayli]
    # değişiklik günlüğü
    gun = u.gun(rng)
    kullanicilar = [f"ik-{x}" for x in u.isimler(rng, 3)]
    sorumlu = rng.choice(kullanicilar)
    log = []
    digerleri = [r for r in onayli if r["sicil"] not in (iban_sicil, net_sicil)]
    for _ in range(rng.randint(4, 6)):              # onaydan önceki meşru departman değişiklikleri (dosyalara zaten yansımış)
        r = rng.choice(digerleri)
        eski_d = rng.choice([d for d in v["departmanlar"] if d != r["departman"]])
        t = gun - timedelta(days=rng.randint(3, 12), hours=rng.randint(0, 8)) + timedelta(hours=9)
        log.append((t, f"{t:%Y-%m-%dT%H:%M:%S}+03:00 kullanici={rng.choice(kullanicilar)} sicil={r['sicil']} alan=departman "
                       f"eski={eski_d} yeni={r['departman']}"))
    t = gun + timedelta(hours=rng.randint(20, 23), minutes=rng.randint(0, 50))   # onaydan sonra, mesai dışı
    log.append((t, f"{t:%Y-%m-%dT%H:%M:%S}+03:00 kullanici={sorumlu} sicil={iban_sicil} alan=iban eski={eski_iban} "
                   f"yeni={guncel[iban_i]['iban']}"))
    t2 = t + timedelta(minutes=rng.randint(3, 9))
    log.append((t2, f"{t2:%Y-%m-%dT%H:%M:%S}+03:00 kullanici={sorumlu} sicil={hayalet['sicil']} alan=yeni_kayit eski=- "
                    f"yeni={hayalet['ad']}"))
    log.sort(key=lambda x: x[0])
    onayli_metin, guncel_metin = _csv_metin(onayli), _csv_metin(guncel)
    return {"onayli": onayli, "guncel": guncel, "ik": ik, "log": [x for _, x in log],
            "iban_sicil": iban_sicil, "net_sicil": net_sicil, "hayalet": hayalet["sicil"], "sorumlu": sorumlu,
            "fark": int(guncel[net_i]["net"]) - int(onayli[net_i]["net"]) + int(hayalet["net"]),
            "onayli_metin": onayli_metin, "guncel_metin": guncel_metin,
            "onayli_hash": hashlib.sha256(onayli_metin.encode()).hexdigest(),
            "guncel_hash": hashlib.sha256(guncel_metin.encode()).hexdigest()}


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    tohum = rng.randint(1, 10**9)
    d = lab_veri(random.Random(tohum), v)
    riskler = list(RISKLER)
    rng.shuffle(riskler)
    return {
        "vaka": f"{m['ad']} — mart bordrosu bütünlük incelemesi",
        "musteri": m, "v": v, "tohum": tohum, "riskler": riskler,
        "metin": {"musteri": m["ad"], "kisi": v["kisi"], "olay": v["olay"], "n": len(d["onayli"])},
        "cevaplar": {
            "hash": [d["guncel_hash"][:8], d["guncel_hash"]],
            "iban": d["iban_sicil"], "hayalet": d["hayalet"], "logsuz": d["net_sicil"], "fark": d["fark"],
            "kullanici": d["sorumlu"], "dizi": [RISK_HEDEF[r] for r in riskler],
        },
        "_d": {"onayli_hash": d["onayli_hash"][:8], "net_sicil": d["net_sicil"], "iban_sicil": d["iban_sicil"]},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = lab_veri(random.Random(s["tohum"]), v)
    ay = lab / "bordro"
    u.yaz(ay / "onayli_2026_03.csv", d["onayli_metin"], mod=0o444)
    u.yaz(ay / "bordro_2026_03.csv", d["guncel_metin"])
    u.yaz(ay / "bordro_2026_03.sha256", f"{d['onayli_hash']}  bordro_2026_03.csv\n")
    u.yaz(lab / "ik_listesi.csv", "sicil,ad,departman\n" + "\n".join(f"{r['sicil']},{r['ad']},{r['departman']}" for r in d["ik"]) + "\n")
    u.yaz(lab / "degisiklik.log", "\n".join(d["log"]) + "\n")
    u.yaz(lab / "ornekler" / "iskelet.py", ISKELET_PY, mod=0o755)
    u.yaz(lab / "riskler" / "esleme.txt",
          "Cilt 10'daki bordro riskleri (karışık sırada):\n" + "\n".join(
              f"{i}. {RISKLER[r]}" for i, r in enumerate(s["riskler"], 1)) + "\n\nTürkiye'deki karşılık gelen sistem/süreç:\n"
          + "\n".join(f"  {k}) {t}" for k, t in HEDEFLER.items()) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — mart bordrosu incelemesi (kurgusal veri)\n\n"
          "bordro/onayli_2026_03.csv    : onaylandığı andaki kopya (salt okunur)\n"
          "bordro/bordro_2026_03.csv    : bankaya gidecek dosya\n"
          "bordro/bordro_2026_03.sha256 : onay anında alınan sha256 (doğrulamak için: sha256sum -c)\n"
          "ik_listesi.csv               : İK ana listesi (kimler çalışıyor)\n"
          "degisiklik.log               : bordro sisteminin değişiklik günlüğü\n"
          "riskler/esleme.txt           : Cilt 10 riskleri ve Türkiye karşılıkları\n\n"
          "Karşılaştırma aracını lab'ın köküne yaz: bordro_karsilastir.py\n"
          "Kullanım: python3 bordro_karsilastir.py <onayli.csv> <guncel.csv>\n"
          "Çıktı   : her değişiklik için bir satır: `P1017 iban`, `P1009 net`, yeni satır `P1999 yeni`,\n"
          "          silinen satır `P1004 silinmis` (alan adları: ad, departman, brut, net, iban)\n")


ISKELET_PY = r'''#!/usr/bin/env python3
# iskelet.py — iki bordro dosyasını sicile göre sözlüğe çevirir ve yeni eklenen sicilleri yazar
import csv
import sys


def oku(yol):
    with open(yol, encoding="utf-8", newline="") as f:
        return {r["sicil"]: r for r in csv.DictReader(f)}     # {sicil: satır}


eski, yeni = oku(sys.argv[1]), oku(sys.argv[2])
for sicil in sorted(set(yeni) - set(eski)):
    print(sicil, "yeni")

# Eksikler: kullanım mesajı; silinen satırlar (eskide var, yenide yok);
# ikisinde de olan sicillerde alan alan karşılaştırma (ad, departman, brut, net, iban).
'''

KARSILASTIR_PY = r'''#!/usr/bin/env python3
import csv
import sys

if len(sys.argv) < 3:
    print(f"Kullanım: {sys.argv[0]} <onayli.csv> <guncel.csv>")
    sys.exit(1)

ALANLAR = ["ad", "departman", "brut", "net", "iban"]


def oku(yol):
    with open(yol, encoding="utf-8", newline="") as f:
        return {r["sicil"]: r for r in csv.DictReader(f)}


eski, yeni = oku(sys.argv[1]), oku(sys.argv[2])
for sicil in sorted(set(eski) | set(yeni)):
    if sicil not in yeni:
        print(sicil, "silinmis")
    elif sicil not in eski:
        print(sicil, "yeni")
    else:
        for alan in ALANLAR:
            if eski[sicil][alan] != yeni[sicil][alan]:
                print(sicil, alan, eski[sicil][alan], "->", yeni[sicil][alan])
'''


# ---------------------------------------------------------------- denetim

def degisim_uret(rng: random.Random, v: dict, n: int = 30) -> tuple:
    """(onayli_metin, guncel_metin, beklenen {sicil: {token}})"""
    onayli = _calisanlar(rng, v, n)
    guncel = [dict(r) for r in onayli]
    beklenen = {}
    idx = list(range(len(guncel)))
    rng.shuffle(idx)
    for _ in range(rng.randint(1, 2)):
        i = idx.pop()
        guncel[i]["iban"] = _iban(rng)
        beklenen.setdefault(guncel[i]["sicil"], set()).add("iban")
    for _ in range(rng.randint(1, 2)):
        i = idx.pop()
        guncel[i]["net"] = str(int(guncel[i]["net"]) + rng.randint(3, 20) * 1000)
        beklenen.setdefault(guncel[i]["sicil"], set()).add("net")
    i = idx.pop()                                          # hem brüt hem net değişen
    guncel[i]["brut"] = str(int(guncel[i]["brut"]) + 5000)
    guncel[i]["net"] = str(int(guncel[i]["net"]) + 3700)
    beklenen[guncel[i]["sicil"]] = {"brut", "net"}
    i = idx.pop()
    guncel[i]["departman"] = rng.choice([d for d in v["departmanlar"] if d != guncel[i]["departman"]])
    beklenen[guncel[i]["sicil"]] = {"departman"}
    silinen = guncel.pop(idx.pop())
    kal = {r["sicil"] for r in guncel}
    if silinen["sicil"] not in kal:
        beklenen[silinen["sicil"]] = {"silinmis"}
    for _ in range(rng.randint(1, 2)):
        sc = f"P{int(max(r['sicil'][1:] for r in onayli)) + len(beklenen) + 3}"
        guncel.append({"sicil": sc, "ad": f"Kurgusal {rng.choice(SOYADLAR)}", "departman": rng.choice(v["departmanlar"]),
                       "brut": "40000", "net": "29600", "iban": _iban(rng)})
        beklenen[sc] = {"yeni"}
    rng.shuffle(guncel)
    return _csv_metin(onayli), _csv_metin(guncel), beklenen


def _kontrol(calistir: bt.Calistirici, onayli: Path, guncel: Path, beklenen: dict, goster: str) -> Sonuc | None:
    c = calistir(str(onayli), str(guncel))
    nasil = calistir.goster(goster)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    bulunan = {}
    for satir in c.stdout.splitlines():
        m = re.search(r"\bP\d{4}\b", satir)
        if not m:
            continue
        a = bt.ascii_kucuk(satir)
        # değerler arasında alan adı gibi görünen kelimeler olmasın diye yalnızca satırın ilk iki kelimesine bak
        parcalar = a.split()
        belirtec = {p.strip(":,") for p in parcalar[1:3]} & {"ad", "departman", "brut", "net", "iban", "yeni", "silinmis"}
        bulunan.setdefault(m.group(0), set()).update(belirtec)
    if not bulunan and beklenen:
        return Sonuc(False, f"`{nasil}` çıktısında değişen sicil bulamadım. Her değişiklik için `P1017 iban` gibi bir satır yaz."
                     + bt.ozet(c), yakin=True)
    fazla = set(bulunan) - set(beklenen)
    if fazla:
        return Sonuc(False, f"`{nasil}`: {sorted(fazla)[0]} değişmemiş ama listelemişsin ({len(fazla)} fazla). "
                     "Sadece iki dosyada farklı olan sicilleri yaz.", yakin=True)
    eksik = set(beklenen) - set(bulunan)
    if eksik:
        sc = sorted(eksik)[0]
        tur = sorted(beklenen[sc])[0]
        ipucu = {
            "yeni": "Güncel dosyada olup onaylıda olmayan sicilleri (yeni eklenen satırlar) da bul.",
            "silinmis": "Onaylıda olup güncelde olmayan sicilleri (silinen satırlar) da bul.",
        }.get(tur, f"İki dosyada da bulunan siciller için `{tur}` gibi alanları alan alan karşılaştır.")
        return Sonuc(False, f"`{nasil}`: {len(eksik)} değişiklik kaçmış (örn. {sc}: `{tur}`). {ipucu}", yakin=True)
    for sc, tokenler in beklenen.items():
        if bulunan[sc] != tokenler:
            return Sonuc(False, f"`{nasil}`: {sc} için alanları `{', '.join(sorted(bulunan[sc])) or '-'}` yazmışsın, "
                         f"`{', '.join(sorted(tokenler))}` olmalı. Satırın ikinci kelimesi alan adı olsun.", yakin=True)
    return None


def _karsilastir_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    lab = Path(b.lab)
    onayli, guncel = lab / "bordro" / "onayli_2026_03.csv", lab / "bordro" / "bordro_2026_03.csv"
    if not (onayli.is_file() and guncel.is_file()):
        return Sonuc(False, f"{lab / 'bordro'} içindeki dosyalar yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    d = lab_veri(random.Random(s["tohum"]), s["v"])
    beklenen = {d["iban_sicil"]: {"iban"}, d["net_sicil"]: {"net"}, d["hayalet"]: {"yeni"}}
    sonuc = _kontrol(calistir, onayli, guncel, beklenen, "bordro/onayli_2026_03.csv bordro/bordro_2026_03.csv")
    if sonuc:
        return sonuc
    rng = random.Random()
    v = rng.choice(VAKALAR)
    om, gm, bek = degisim_uret(rng, v)
    gecici = Path(tempfile.mkdtemp(prefix="hy_bordro_"))
    try:
        (gecici / "a.csv").write_text(om, encoding="utf-8")
        (gecici / "b.csv").write_text(gm, encoding="utf-8")
        sonuc = _kontrol(calistir, gecici / "a.csv", gecici / "b.csv", bek, f"{gecici}/a.csv {gecici}/b.csv")
    finally:
        for x in gecici.glob("*"):
            x.unlink(missing_ok=True)
        gecici.rmdir()
    if sonuc:
        sonuc.mesaj += ("\n    (Bu, hiç görmediğin yeni bir çiftti: satırların sırası farklı, silinen ve yeni satırlar "
                        "var, bazı çalışanlarda birden çok alan değişmiş. Karşılaştırma sicile göre olmalı, satır sırasına göre değil.)")
        return sonuc
    return Sonuc(True, "bordro_karsilastir.py hem lab dosyasında hem hiç görmediği yeni bir çiftte, sıra farklı olsa bile, "
                       "değişen, eklenen ve silinen kayıtları doğru buldu. Bu, bir bütünlük kontrolünün (FIM, file integrity "
                       "monitoring) en sade halidir.")


def _hash_hata(g, beklenen, b):
    if g == b.senaryo["_d"]["onayli_hash"]:
        return "Bu, **onaylı** dosyanın hash'i. Soru bankaya gidecek (şu anki) `bordro_2026_03.csv`'nin hash'ini soruyor."
    return None


def _iban_hata(g, beklenen, b):
    if g == b.senaryo["_d"]["net_sicil"].lower():
        return "Bu çalışanın **net maaşı** değişmiş; IBAN değil. IBAN alanı farklı olanı ara."
    return None


def _hayalet_hata(g, beklenen, b):
    if g in (b.senaryo["_d"]["iban_sicil"].lower(), b.senaryo["_d"]["net_sicil"].lower()):
        return "Bu sicil İK listesinde var; yani gerçek bir çalışan (verisi değişmiş olabilir ama hayalet değil)."
    return None


def _logsuz_hata(g, beklenen, b):
    if g == b.senaryo["_d"]["iban_sicil"].lower():
        return "Bu değişikliğin günlükte kaydı var. Dosyada farklı olup günlükte hiç **geçmeyen** sicili ara."
    if g == b.senaryo["cevaplar"]["hayalet"].lower():
        return "Bu satırın günlükte `yeni_kayit` kaydı var. Günlükte hiç geçmeyen sicili ara."
    return None


def _fark_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n < beklenen:
        return "Eksik: hem mevcut çalışanın zammını hem de hayalet çalışanın net maaşını hesaba kat."
    return None


def _kullanici_hata(g, beklenen, b):
    return None


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "bordro_karsilastir.py", KARSILASTIR_PY)
    cikti = "python3 bordro_karsilastir.py bordro/onayli_2026_03.csv bordro/bordro_2026_03.csv"
    h = sh("sha256sum bordro/bordro_2026_03.csv | awk '{print $1}'", lab)
    iban = sh(f"{cikti} | grep ' iban ' | awk '{{print $1}}'", lab)
    hayalet = sh("cut -d, -f1 bordro/bordro_2026_03.csv | tail -n +2 | sort > /tmp/hy_a_$$; "
                 "cut -d, -f1 ik_listesi.csv | tail -n +2 | sort > /tmp/hy_b_$$; comm -23 /tmp/hy_a_$$ /tmp/hy_b_$$; rm -f /tmp/hy_a_$$ /tmp/hy_b_$$", lab)
    degisenler = sh(f"{cikti} | awk '{{print $1}}'", lab).split()
    logsuz = [x for x in degisenler if sh(f"grep -c 'sicil={x} ' degisiklik.log", lab) == "0"]
    fark = sh("awk -F, 'NR>1{t+=$5} END{print t}' bordro/bordro_2026_03.csv", lab)
    eski = sh("awk -F, 'NR>1{t+=$5} END{print t}' bordro/onayli_2026_03.csv", lab)
    kullanici = sh(f"grep 'sicil={hayalet} ' degisiklik.log | awk '{{print $2}}' | cut -d= -f2", lab)
    # eşleme: metni okuyup anahtar kelimelerle
    harf = []
    for satir in sh("grep -E '^[0-9]+\\.' riskler/esleme.txt", lab).splitlines():
        harf.append("a" if "Toplu" in satir else ("b" if "Hayalet" in satir else "c"))
    cozum = {1: "", 2: h[:8], 3: iban, 4: hayalet, 5: logsuz[0], 6: str(int(fark) - int(eski)), 7: kullanici,
             8: " ".join(harf)}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Bordro: maaş + yoğun kişisel veri", """
Selin: "Bordro dosyası iki şeyi birleştirir: **para** (kime ne kadar, hangi hesaba) ve **kişisel veri**
(ad, maaş, IBAN, çoğu zaman SGK bilgisi). Hile yapmak isteyen için üç klasik yol var: ödeme dosyasındaki
tutarı değiştirmek, **hayalet çalışan** (listede olmayan biri adına maaş) eklemek ve birinin **IBAN**'ını kendi
hesabına çevirmek." Klasörün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Hash ile bütünlük", """
Bütünlüğü kanıtlamanın en basit yolu hash'tir: dosya onaylanırken `sha256sum` ile bir parmak izi alınır ve
saklanır. Sonra dosya bankaya gitmeden önce yeniden hesaplanıp karşılaştırılır. Kaydedilen değer:
""", komut="cat bordro/bordro_2026_03.sha256"),
    Adim("Doğrula", """
`sha256sum -c` dosyadaki hash ile gerçek hash'i karşılaştırır: `OK` ya da `FAILED`. Dosya adı, `.sha256`
dosyasının içinde yazan ad olduğu için `bordro` klasörüne girip çalıştırıyoruz:
""", komut="cd bordro && sha256sum -c bordro_2026_03.sha256; echo \"çıkış kodu: $?\"", sonra="""
**FAILED**: dosya onaylandığından beri değişmiş. Hash **neyin** değiştiğini söylemez, sadece **değiştiğini**
söyler. Ne değiştiğini bulmak için onaylı kopyayla karşılaştırmak gerekir.
"""),
    Adim("Onaylı kopya ve izinler", """
Onaylı kopya salt okunur (izin `r--r--r--`). Güncel dosya ise yazılabilir. `ls -l` bunu gösterir; satır
sayıları da bir ipucu verir:
""", komut="ls -l bordro/ && wc -l bordro/*.csv", sonra="""
Satır sayıları aynı değil. Ama aynı olsa bile içerik farklı olabilir; çünkü değişiklik tek bir hücrede de
olabilir. Bu yüzden satır satır değil, **sicile göre** karşılaştırırız.
"""),
    Adim("Değişiklik günlüğü", """
Bordro sistemi, uygulama üzerinden yapılan her değişikliği `degisiklik.log`'a yazar: kim, ne zaman, hangi
sicil, hangi alan, eski ve yeni değer. İlk satırlar:
""", komut="head -4 degisiklik.log", sonra="""
**Altın kural:** Dosyada olan **ama günlükte olmayan** her değişiklik, sistemi atlayarak doğrudan dosyaya yapılmış
demektir; en tehlikeli türdür, çünkü onay akışını ve izlemeyi devre dışı bırakır.
"""),
    Adim("İK listesiyle karşılaştırma", """
Hayalet çalışan, bordroda olup **İK ana listesinde olmayan** kişidir. İki listeyi sicile göre karşılaştırmanın
klasik yolu `comm`: `-23` sadece ilk dosyada olanları gösterir (girdiler sıralı olmalı). Deneme için iki küçük
liste:
""", komut="printf 'a\\nb\\nc\\n' | sort > /tmp/hy_x; printf 'b\\nc\\n' | sort > /tmp/hy_y; comm -23 /tmp/hy_x /tmp/hy_y; rm -f /tmp/hy_x /tmp/hy_y",
         sonra="""
Aynı kalıbı sicil sütunlarına uygulayacaksın (`cut -d, -f1`, `sort`, `comm`).
"""),
    Adim("Hacker gözüyle", """
Bordro dolandırıcılığı çoğu zaman **iç kaynaklıdır**: ödeme dosyasına yetkisi olan biri, sistemin dışında
dosyayı değiştirir. Sistemin kendi günlüğü bu yüzden yetmez; **dosyanın kendisinin bütünlüğü** (hash) ve
**ikinci bir göz** (maker-checker: biri hazırlar, başkası onaylar) gerekir.

Savunma: onaylı kopyayı salt okunur tut, hash'i ayrı bir yerde sakla, bankaya göndermeden önce doğrula,
değişiklikleri yalnızca uygulama üzerinden yap ve günlüğü değiştirilemez bir yere yaz.
"""),
]

GOREVLER = [
    Gorev("`bordro_karsilastir.py` yaz: `python3 bordro_karsilastir.py <onayli.csv> <guncel.csv>` iki dosyayı **sicile "
          "göre** karşılaştırsın. Değişen her alan için `P1017 iban ...`, eklenen satır için `P1999 yeni`, silinen satır "
          "için `P1004 silinmis` yazsın (satırın **ikinci kelimesi** alan adı: ad, departman, brut, net, iban). Değişmeyen "
          "sicil yazılmasın. Argümansızsa `Kullanım` mesajı ve `exit 1`. Oyun betiğini hiç görmediği, satır sırası "
          "karışık bir çiftle de deneyecek.",
          bt.BetikKontrol("bordro_karsilastir.py", _karsilastir_denetle,
                          "Örnek `bordro_karsilastir.py`:\n\n```\n" + KARSILASTIR_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/iskelet.py` dosyayı `{sicil: satır}` sözlüğüne çeviriyor; küme farkları yeni ve silinenleri verir.",
           "İkisinde de olan siciller için `for alan in [\"ad\", \"departman\", \"brut\", \"net\", \"iban\"]:` döngüsüyle "
           "`eski[sicil][alan] != yeni[sicil][alan]` karşılaştır. Silinenler: `set(eski) - set(yeni)`.",
           "```\nfor sicil in sorted(set(eski) | set(yeni)):\n    if sicil not in yeni: print(sicil, \"silinmis\")\n"
           "    elif sicil not in eski: print(sicil, \"yeni\")\n    else:\n        for alan in ALANLAR:\n"
           "            if eski[sicil][alan] != yeni[sicil][alan]: print(sicil, alan, eski[sicil][alan], \"->\", yeni[sicil][alan])\n```"),
          puan=70, baslik="Bordro karşılaştırıcı"),
    Gorev("Bankaya gidecek **şu anki** `bordro/bordro_2026_03.csv` dosyasının SHA-256'sını hesapla. İlk 8 hanesini yaz.",
          Dinamik(lambda b: b.senaryo["cevaplar"]["hash"], bicim="hash'in ilk 8 hanesi (ya da tamamı)", on_ekleri_at=()),
          ("Dosyanın parmak izini çıkaran komut.",
           "`sha256sum bordro/bordro_2026_03.csv`",
           "Çıktıdaki 64 haneli hash'in ilk 8 karakteri; `.sha256` dosyasındaki değerle karşılaştırınca fark görünür."),
          puan=20, baslik="Güncel hash"),
    Gorev("Bir çalışanın **IBAN**'ı değiştirilmiş (maaşı başka hesaba gidecekti). Bu çalışanın sicili?",
          Metin("iban", sik_hatalar=_iban_hata, bicim="sicil (örn. P1017)"),
          ("Aracının çıktısında alan olarak `iban` yazan satırı bul.",
           "`python3 bordro_karsilastir.py bordro/onayli_2026_03.csv bordro/bordro_2026_03.csv | grep iban`",
           "Satırın ilk kelimesi sicildir."),
          puan=25, baslik="IBAN değişikliği"),
    Gorev("Bordroda olup **İK ana listesinde olmayan** bir kişi var: hayalet çalışan. Sicili nedir?",
          Metin("hayalet", sik_hatalar=_hayalet_hata, bicim="sicil (örn. P1999)"),
          ("İki dosyanın sicil sütunlarını karşılaştır; biri diğerinde olmayanı gösterir.",
           "Her dosyanın sicil sütununu çıkar (`cut -d, -f1`), başlık satırını at (`tail -n +2`) ve sırala (`sort`); "
           "`comm -23 bordro_siciller ik_siciller` sadece bordroda olanı verir.",
           "`comm -23 <(cut -d, -f1 bordro/bordro_2026_03.csv | tail -n +2 | sort) <(cut -d, -f1 ik_listesi.csv | tail -n +2 | sort)`"),
          puan=30, baslik="Hayalet çalışan"),
    Gorev("Dosyada değişmiş olan üç kaydın **ikisinin** `degisiklik.log`'da izi var. **Günlükte hiç geçmeyen** (sistemi "
          "atlayarak doğrudan dosyada yapılmış) değişikliğin sicili hangisi?",
          Metin("logsuz", sik_hatalar=_logsuz_hata, bicim="sicil"),
          ("Aracının bulduğu her sicil için günlükte `sicil=` ile arama yap.",
           "`grep 'sicil=P1017 ' degisiklik.log` şeklinde her sicili dene; hiç sonuç vermeyen cevaptır.",
           "`for s in $(python3 bordro_karsilastir.py bordro/onayli_2026_03.csv bordro/bordro_2026_03.csv | awk '{print $1}'); "
           "do echo -n \"$s: \"; grep -c \"sicil=$s \" degisiklik.log; done`"),
          puan=35, baslik="Günlüğü atlayan değişiklik"),
    Gorev("Bu değişiklikler yüzünden bordro dosyasının **toplam net ödemesi**, onaylı dosyaya göre kaç TL **fazla**?",
          Sayi("fark", sik_hatalar=_fark_hata),
          ("İki dosyanın net sütunlarını (5. sütun) ayrı ayrı topla ve çıkar.",
           "`awk -F, 'NR>1{t+=$5} END{print t}' dosya`",
           "Önce onaylı, sonra güncel için çalıştır ve farkı al."),
          puan=30, baslik="Fazladan ödeme"),
    Gorev("Hayalet çalışanı sisteme **giren kullanıcı** kim? (`degisiklik.log`)",
          Metin("kullanici", bicim="kullanıcı adı (örn. ik-...)"),
          ("Hayalet sicilin günlükte `yeni_kayit` satırı var.",
           "`grep 'sicil=<hayalet sicil> ' degisiklik.log`",
           "Satırdaki `kullanici=` alanı."),
          puan=25, baslik="Kim girdi"),
    Gorev("`riskler/esleme.txt` dosyasındaki 3 bordro riskini Türkiye'deki karşılığıyla eşle (a toplu maaş ödeme, "
          "b SGK bildirge/çalışan kayıtları, c maaş hesabı güncelleme). Cevap: risklerin dosyadaki sırasıyla üç harf.",
          Dizi("dizi", bicim="üç harf sırayla, örn. b a c"),
          ("Her risk hangi iş akışını suistimal eder?",
           "Toplu ödeme manipülasyonu = ödeme dosyası; hayalet çalışan = kayıtlarda olmayan kişi; hesap değişikliği = "
           "maaşın gideceği hesap.",
           "Toplu ödeme = a, hayalet çalışan = b, banka hesabı değişikliği = c. Dosyadaki sıraya göre yaz."),
          puan=25, baslik="Risk eşleme"),
    Gorev("Bordro dosyasında yetkisiz değişiklik ve veri sızıntısı **KVKK** açısından neden ciddidir?",
          Secmeli([
              ("Maaş ve çalışan bilgileri korunması gereken kişisel veridir; veri sorumlusu teknik ve idari tedbir almak "
               "zorundadır, yetkisiz erişim ya da değişiklik bir veri güvenliği ihlali olabilir",
               "Doğru (genel çerçeve). İhlal durumunda bildirim yükümlülükleri vardır; süre ve ayrıntılar için güncel "
               "mevzuat ve hukuk birimi esas alınır."),
              ("Maaş bilgisi herkese açıktır, bu yüzden KVKK kapsamında değildir",
               "Maaş ve çalışanın kimlik/hesap bilgileri kişisel veridir ve korunur; bazı bilgiler özel nitelikli de olabilir."),
              ("KVKK yalnızca müşteri verilerini kapsar, çalışan verisini kapsamaz",
               "Çalışanlar da ilgili kişidir; çalışan verisi de aynı koruma altındadır."),
              ("İhlal yalnızca veri bir dış kişiye gönderilirse oluşur; dosyada değişiklik yapılması ihlal sayılmaz",
               "Yetkisiz erişim ya da değişiklik de güvenlik ihlali olabilir; veri bütünlüğü de korunması gereken bir unsurdur."),
          ]),
          ("Bordro dosyasında hangi bilgiler var: ad, maaş, IBAN...",
           "Veri sorumlusunun yükümlülüğü yalnızca saklamak değil, korumaktır.",
           "Gizlilik kadar bütünlük de güvenliğin parçasıdır."),
          puan=25, baslik="KVKK bağlantısı"),
]

SEVIYE = Seviye(
    kimlik="c23b03",
    cilt=23,
    bolum=3,
    baslik="Bordro, SGK ve Uyumun Birleşimi",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> acil bir inceleme istiyor.

Selin: "<<n>> çalışanlı mart bordrosu. Elimizde onay anındaki salt okunur kopya, bankaya gidecek dosya, onay
anında alınmış bir hash, İK ana listesi ve bordro sisteminin değişiklik günlüğü var. Dosya değişmiş.
**Ne değişti, kim değiştirdi, sistemi atlayan oldu mu?**" Deniz: "Bu iş hem güvenlik hem iş bilgisi hem
mevzuat. Bordro verisi KVKK gözünde de hassas; ihlal bildirimi gerekecek mi diye hukuk birimi de soracak."
Mert ekliyor: "Hayalet çalışan avı en eski muhasebe oyunlarından biri. Bir de IBAN'a bak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Üç kontrol bir arada çalıştı: hash dosyanın **değiştiğini** söyledi, onaylı kopyayla karşılaştırma **neyin**
değiştiğini gösterdi (bir IBAN, bir maaş, bir hayalet çalışan), değişiklik günlüğü ise **kimin** yaptığını ve
bir değişikliğin sistemi hiç **atlayarak** yapıldığını ortaya çıkardı. Saldırgan (ya da kötü niyetli iç kullanıcı)
için en cazip yol, günlüğe düşmeyen doğrudan dosya değişikliğidir. Savunma için ders: onaylı kopya salt okunur ve
hash ayrı yerde saklanmalı, bankaya gitmeden önce hash doğrulanmalı, hazırlayan ile onaylayan ayrı kişiler
olmalı (maker-checker) ve günlük değiştirilemez bir yerde tutulmalı. Bordro verisi KVKK kapsamında kişisel veri
olduğundan, yetkisiz değişiklik hem mali hem hukuki bir olaydır.
""",
    gercek_hayat="""
- **İç kaynaklı bordro suistimalleri:** Hayalet çalışan ve maaş hesabı değiştirme, muhasebe ve denetim
  literatüründe iyi bilinen iç dolandırıcılık türleridir; çoğu zaman tek bir kişinin hem hazırlama hem onaylama
  yetkisi olduğunda ortaya çıkar. Tespit: bordro ile İK listesinin düzenli çapraz kontrolü ve IBAN
  değişikliklerinin raporlanması; önlem: görev ayrılığı ve çift onay.
- **Dosya bütünlüğü izleme:** Kritik dosyaların (ödeme dosyaları, yapılandırmalar) onaylı hash'lerle düzenli
  karşılaştırılması, güvenlik programlarının standart bir parçasıdır (file integrity monitoring); değişikliğin
  günlükte karşılığı yoksa alarm üretilir.
- **KVKK ve bordro:** Çalışan verileri 6698 sayılı KVKK kapsamında korunur; veri sorumlusunun teknik ve idari
  tedbir alma ve bir ihlalde ilgili mercilere ve kişilere gerekli bildirimleri yapma yükümlülüğü vardır.
  Bildirim süre ve usul ayrıntıları için güncel mevzuat ve hukuk birimi esas alınmalıdır. SGK ve vergi
  bildirimleri ayrıca resmî kurumların kendi yükümlülük ve tebliğlerine tabidir.
""",
    sure_hedef_dk=50,
)
