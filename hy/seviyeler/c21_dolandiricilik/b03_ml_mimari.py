"""Cilt 21 · Bölüm 3 — Makine Öğrenmesi ve Mimari.

Beceri: bir risk skoru ve eşikle çalışan sistemin başarısını ölçmek (TP/FP/FN, precision, recall),
eşiğin iş maliyetine göre seçilmesi ve katmanlı mimari (hızlı kurallar -> ML skoru -> insan incelemesi).
Model eğitimi yok: skorlar hazır gelir; asıl iş onların nasıl yorumlanacağıdır.

Vakalar: Ferah Bank (kart), Pazarix (iade riski), Paramix (ödeme) — her vakada yanlış pozitif
ve yanlış negatif maliyeti farklıdır.
"""
from __future__ import annotations

import os
import random
import re
import tempfile
from pathlib import Path

from hy.motor.kontrol import Baglam, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

VAKALAR = [
    {"kod": "ferahbank", "alan": "kart işlemi", "fp": 40, "fn": 1500, "n": 1600, "oran": 0.035,
     "olay": "Ferah Bank, kart işlemlerini bir risk modeliyle skorluyor (0-100). Skor eşiği geçerse işlem "
             "reddedilip müşteri aranıyor. Bir yanlış alarm çağrı merkezi ve müşteri kaybı olarak ortalama "
             "40 TL, kaçan her dolandırıcılık ortalama 1.500 TL'ye mal oluyor."},
    {"kod": "pazarix", "alan": "iade talebi", "fp": 25, "fn": 220, "n": 1400, "oran": 0.05,
     "olay": "Pazarix, iade taleplerini bir risk modeliyle skorluyor (0-100). Eşiği geçen iade elle inceleniyor. "
             "Bir yanlış alarm inceleme zamanı ve mutsuz müşteri olarak ortalama 25 TL, kaçan her hileli iade "
             "ortalama 220 TL'ye mal oluyor."},
    {"kod": "paramix", "alan": "ödeme", "fp": 60, "fn": 900, "n": 1800, "oran": 0.03,
     "olay": "Paramix, üye işyeri ödemelerini bir risk modeliyle skorluyor (0-100). Eşiği geçen ödeme bekletilip "
             "incelemeye gidiyor. Bir yanlış alarm geciken ödeme ve üye işyeri şikâyeti olarak ortalama 60 TL, "
             "kaçan her dolandırıcılık ortalama 900 TL'ye mal oluyor."},
]

ADAY_ESIKLER = list(range(10, 100, 5))
ASAMALAR = {
    "kural": "Hızlı kurallar (kara liste, hız, eşik): milisaniyede karar verir",
    "ml": "ML skorlaması: kuralların kaçırdığı ince desenleri puanlar",
    "insan": "İnsan incelemesi: şüpheli vakalar analist kuyruğuna düşer",
    "geri": "Geri bildirim: sonuçlanan vakalar etiket olarak kurallara ve modele döner",
}
DOGRU_SIRA = ["kural", "ml", "insan", "geri"]


def veri_uret(rng: random.Random, n: int, oran: float) -> list:
    satirlar = []
    for i in range(n):
        fraud = rng.random() < oran
        skor = rng.gauss(70, 17) if fraud else rng.gauss(30, 17)
        satirlar.append((max(0, min(100, int(round(skor)))), 1 if fraud else 0))
    return satirlar


def olc(satirlar: list, esik: float) -> dict:
    tp = sum(1 for s, g in satirlar if s >= esik and g == 1)
    fp = sum(1 for s, g in satirlar if s >= esik and g == 0)
    fn = sum(1 for s, g in satirlar if s < esik and g == 1)
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0.0, "recall": tp / (tp + fn) if tp + fn else 0.0}


def maliyet(satirlar: list, esik: int, fp_m: int, fn_m: int) -> int:
    o = olc(satirlar, esik)
    return o["fp"] * fp_m + o["fn"] * fn_m


def uret(rng):
    for _ in range(50):
        v = dict(rng.choice(VAKALAR))
        tohum = rng.randint(1, 10**9)
        satirlar = veri_uret(random.Random(tohum), v["n"], v["oran"])
        esik = rng.choice([45, 55, 65, 75])
        maliyetler = {e: maliyet(satirlar, e, v["fp"], v["fn"]) for e in ADAY_ESIKLER}
        en_az = min(maliyetler.values())
        en_iyi = [e for e, m in maliyetler.items() if m == en_az]
        r90 = [e for e in ADAY_ESIKLER if olc(satirlar, e)["recall"] >= 0.9]
        if len(en_iyi) == 1 and r90:
            break
    m = musteri(v["kod"])
    o = olc(satirlar, esik)
    sira = list(ASAMALAR)
    rng.shuffle(sira)
    numara = {k: i for i, k in enumerate(sira, 1)}
    return {
        "vaka": f"{m['ad']} — {v['alan']} risk skoru",
        "musteri": m, "v": v, "tohum": tohum, "esik": esik, "sira": sira,
        "metin": {"musteri": m["ad"], "olay": v["olay"], "esik": esik, "alan": v["alan"],
                  "fp_m": v["fp"], "fn_m": v["fn"], "satir": len(satirlar)},
        "cevaplar": {
            "fp": o["fp"], "fn": o["fn"], "recall90": max(r90), "maliyet": en_iyi[0],
            "mimari": [numara[k] for k in DOGRU_SIRA],
        },
        "_o": o,
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    satirlar = veri_uret(random.Random(s["tohum"]), v["n"], v["oran"])
    u.yaz(lab / "skorlar.csv", "islem_id,skor,gercek\n" + "\n".join(
        f"R{i:05d},{sk},{g}" for i, (sk, g) in enumerate(satirlar, 1)) + "\n")
    u.yaz(lab / "mimari" / "asamalar.txt",
          "Bir işlemin geçtiği dört aşama (sırası karışık):\n\n" + "\n".join(
              f"{i}. {ASAMALAR[k]}" for i, k in enumerate(s["sira"], 1)) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['alan']} risk skorları (kurgusal)\n\n"
          f"skorlar.csv : {len(satirlar)} sonuçlanmış vaka. skor = modelin 0-100 risk puanı,\n"
          "              gercek = 1 (dolandırıcılık çıktı) | 0 (meşru çıktı)\n"
          f"Kural       : skor >= esik ise işlem 'dolandırıcılık' diye işaretlenir. Bizim eşik: {s['esik']}\n"
          f"Maliyetler  : yanlış alarm (FP) = {v['fp']} TL, kaçan dolandırıcılık (FN) = {v['fn']} TL\n\n"
          "Ölçüm aracını lab'ın köküne yaz: olc.py\n"
          "Kullanım    : python3 olc.py skorlar.csv <esik>\n")
    u.yaz(lab / "ornekler" / "iskelet.py", ISKELET_PY, mod=0o755)


ISKELET_PY = r'''#!/usr/bin/env python3
# iskelet.py — skorlar.csv'yi okuyup tek bir eşikte sadece TP sayar
import csv
import sys

esik = float(sys.argv[2])
tp = 0
with open(sys.argv[1], encoding="utf-8", newline="") as f:
    for r in csv.DictReader(f):
        skor = float(r["skor"])
        gercek = int(r["gercek"])
        if skor >= esik and gercek == 1:      # işaretledik VE gerçekten dolandırıcılıktı
            tp += 1
print("TP:", tp)

# Eksikler: kullanım mesajı, FP (işaretledik ama meşruydu), FN (işaretlemedik ama dolandırıcılıktı),
# precision = TP / (TP + FP), recall = TP / (TP + FN).
'''

OLC_PY = r'''#!/usr/bin/env python3
import csv
import sys

if len(sys.argv) < 3:
    print(f"Kullanım: {sys.argv[0]} <skorlar.csv> <esik>")
    sys.exit(1)

esik = float(sys.argv[2])
tp = fp = fn = 0
with open(sys.argv[1], encoding="utf-8", newline="") as f:
    for r in csv.DictReader(f):
        isaretli = float(r["skor"]) >= esik
        dolandirici = int(r["gercek"]) == 1
        if isaretli and dolandirici:
            tp += 1
        elif isaretli:
            fp += 1
        elif dolandirici:
            fn += 1

precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
print(f"TP: {tp}")
print(f"FP: {fp}")
print(f"FN: {fn}")
print(f"precision: {precision:.2f}")
print(f"recall: {recall:.2f}")
'''


# ---------------------------------------------------------------- denetim

def _deger(metin: str, ad: str):
    m = re.search(rf"(?im)^\W*{ad}\W{{0,12}}?(-?\d+(?:[.,]\d+)?)\s*(%?)", metin)
    if not m:
        return None
    x = float(m.group(1).replace(",", "."))
    if m.group(2) or x > 1:
        x /= 100
    return x


def _int_deger(metin: str, ad: str):
    m = re.search(rf"(?im)^\W*{ad}\b\W{{0,12}}?(\d+)", metin)
    return int(m.group(1)) if m else None


def _kontrol_et(calistir: bt.Calistirici, yol: Path, satirlar: list, esik: int) -> Sonuc | None:
    c = calistir(str(yol), str(esik))
    nasil = calistir.goster(yol.name if str(yol).startswith(tempfile.gettempdir()) else "skorlar.csv", esik)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    o = olc(satirlar, esik)
    cikti = c.stdout
    bulunan = {k: _int_deger(cikti, k) for k in ("TP", "FP", "FN")}
    if None in bulunan.values():
        eksik = [k for k, x in bulunan.items() if x is None]
        return Sonuc(False, f"`{nasil}` çıktısında şu satır(lar) yok: {', '.join(eksik)}. Her değeri ayrı satıra "
                     "`TP: 12` biçiminde yaz." + bt.ozet(c), yakin=True)
    if (bulunan["TP"], bulunan["FP"], bulunan["FN"]) != (o["tp"], o["fp"], o["fn"]):
        alt = olc(satirlar, esik + 1)
        if (bulunan["TP"], bulunan["FP"], bulunan["FN"]) == (alt["tp"], alt["fp"], alt["fn"]):
            return Sonuc(False, f"`{nasil}`: eşik **dahildir**: `skor >= esik` işaretlenir. Sen `>` kullanmışsın.", yakin=True)
        if bulunan["FP"] == o["fn"] and bulunan["FN"] == o["fp"]:
            return Sonuc(False, f"`{nasil}`: FP ile FN yer değiştirmiş. FP = işaretledik ama **meşruydu**; "
                         "FN = işaretlemedik ama **dolandırıcılıktı**.", yakin=True)
        return Sonuc(False, f"`{nasil}`: sayılar tutmuyor (senin: TP {bulunan['TP']}, FP {bulunan['FP']}, FN "
                     f"{bulunan['FN']}). Eşik {esik}: `skor >= {esik}` işaretlenir; `gercek == 1` dolandırıcılıktır."
                     + bt.ozet(c), yakin=True)
    for ad in ("precision", "recall"):
        v = _deger(cikti, ad)
        if v is None:
            return Sonuc(False, f"`{nasil}` çıktısında `{ad}:` satırı yok.", yakin=True)
        if abs(v - o[ad]) > 0.011:
            ipucu = ("precision = TP / (TP + FP): işaretlediklerinin ne kadarı gerçekten dolandırıcı?"
                     if ad == "precision" else "recall = TP / (TP + FN): gerçek dolandırıcıların ne kadarını yakaladın?")
            return Sonuc(False, f"`{nasil}`: {ad} {v:.2f} yazmışsın, {o[ad]:.2f} olmalı. {ipucu}", yakin=True)
    return None


def _olc_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    v = s["v"]
    satirlar = veri_uret(random.Random(s["tohum"]), v["n"], v["oran"])
    lab_csv = Path(b.lab) / "skorlar.csv"
    if not lab_csv.is_file():
        return Sonuc(False, f"{lab_csv} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    sonuc = _kontrol_et(calistir, lab_csv, satirlar, s["esik"])
    if sonuc:
        return sonuc
    rng = random.Random()
    yeni = veri_uret(rng, 700, rng.choice([0.04, 0.08, 0.12]))
    fd, ad = tempfile.mkstemp(prefix="hy_skor_", suffix=".csv")
    os.close(fd)
    gecici = Path(ad)
    try:
        gecici.write_text("islem_id,skor,gercek\n" + "\n".join(f"R{i:05d},{sk},{g}" for i, (sk, g) in enumerate(yeni, 1))
                          + "\n", encoding="utf-8")
        for esik in rng.sample([35, 50, 60, 72, 85], 2):
            sonuc = _kontrol_et(calistir, gecici, yeni, esik)
            if sonuc:
                sonuc.mesaj += "\n    (Bu, hiç görmediğin yeni bir veriydi; eşik de argümandan gelmeli.)"
                return sonuc
    finally:
        gecici.unlink(missing_ok=True)
    return Sonuc(True, "olc.py lab verisinde ve hiç görmediği yeni bir veride, farklı eşiklerle TP/FP/FN, precision ve "
                       "recall'u doğru hesapladı. Artık bir fraud modelinin karnesini çıkarabiliyorsun.")


def _fp_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["_o"]["fn"]:
        return "Bu sayı FN'ye (kaçırılan dolandırıcılık) denk geliyor. FP = eşiği geçti ama `gercek` 0 (meşru)."
    if n == b.senaryo["_o"]["tp"]:
        return "Bu TP: eşiği geçen ve gerçekten dolandırıcı olanlar. FP için `gercek` 0 olmalı."
    return None


def _fn_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["_o"]["fp"]:
        return "Bu sayı FP'ye denk geliyor. FN = eşiğin **altında** kalıp gerçekte dolandırıcı (`gercek` 1) olanlar."
    return None


def _r90_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Bu eşikte recall %90'ın altına düşüyor. Eşiği yükselttikçe daha az dolandırıcı yakalarsın."
    if n < beklenen:
        return "Bu eşik de recall'u %90'ın üstünde tutar ama daha yüksek bir eşik de tutar; **en yüksek** olanı ara."
    return None


def _maliyet_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Eşik yükselince yanlış alarm azalır ama kaçan dolandırıcılık artar; kaçanın maliyeti burada daha büyük."
    if n < beklenen:
        return "Eşik düştükçe yanlış alarm (FP) sayısı ve maliyeti hızla artıyor; toplamı hesapla."
    return None


def _mimari_hata(verilen, beklenen, b):
    if len(verilen) == len(beklenen) and verilen[::-1] == beklenen:
        return "Sıra tersine gitmiş. Ucuz ve hızlı olan başa, pahalı insan emeği sona gelir."
    return None


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "olc.py", OLC_PY)
    e = s["esik"]
    fp = sh(f"python3 olc.py skorlar.csv {e} | grep FP | awk '{{print $2}}'", lab)
    fn = sh(f"awk -F, 'NR>1 && $2<{e} && $3==1' skorlar.csv | wc -l", lab)
    r90 = sh("for e in $(seq 95 -5 10); do python3 olc.py skorlar.csv $e | awk -v e=$e '/recall/{if ($2>=0.9) {print e; exit}}'; "
             "done | head -1", lab)
    # recall 0.90 sınırı yuvarlamaya takılmasın: kesin hesabı awk ile yap
    r90 = sh("for e in $(seq 95 -5 10); do awk -F, -v e=$e 'NR>1 && $3==1{t++; if ($2>=e) y++} END{if (y/t>=0.9) print e}' "
             "skorlar.csv; done | head -1", lab)
    v = s["v"]
    mal = sh(f"for e in $(seq 10 5 95); do awk -F, -v e=$e -v a={v['fp']} -v b={v['fn']} "
             "'NR>1{if ($2>=e && $3==0) f++; if ($2<e && $3==1) n++} END{print f*a+n*b, e}' skorlar.csv; done "
             "| sort -n | head -1 | awk '{print $2}'", lab)
    sira = {k: i for i, k in enumerate(s["sira"], 1)}
    cozum = {1: "", 2: fp, 3: fn, 4: r90, 5: mal,
             6: " ".join(str(sira[k]) for k in DOGRU_SIRA)}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Skor, eşik ve dört kutu", """
Selin: "Kural motorun 'evet/hayır' der. ML ise bir **skor** verir: 0-100 arası risk puanı. Karar için
bir **eşik** seçersin: skor ≥ eşik ise işaretle." Her işlem dört kutudan birine düşer:

- **TP** (doğru alarm): işaretledin ve gerçekten dolandırıcılıktı
- **FP** (yanlış alarm, false positive): işaretledin ama meşruydu
- **FN** (kaçırma, false negative): işaretlemedin ama dolandırıcılıktı
- **TN**: işaretlemedin ve meşruydu
""", komut="cat OKUBENI.txt"),
    Adim("Veriye bakış", """
Her satır sonuçlanmış bir vaka: modelin verdiği `skor` ve sonradan öğrenilen `gercek` (1 = dolandırıcılık).
Gerçek hayatta bu etiket, itiraz (chargeback) ya da inceleme sonucundan gelir.
""", komut="head -5 skorlar.csv && wc -l skorlar.csv"),
    Adim("Bizim eşikte TP", """
Önce en kolay kutuyu say: skoru eşikte ya da üstünde ve gerçekten dolandırıcı olanlar. `awk -F,`
CSV'yi virgülden böler; `$2` skor, `$3` gerçek:
""", komut="awk -F, 'NR>1 && $2>=<<esik>> && $3==1' skorlar.csv | wc -l", sonra="""
Aynı kalıpla FP'yi (`$3==0`) ve FN'yi (`$2<<<esik>>` ve `$3==1`) görevde sen sayacaksın.
"""),
    Adim("Precision ve recall", """
İki karne notu:

- **precision** (kesinlik) = TP / (TP + FP): "İşaretlediklerimin kaçta kaçı gerçekten dolandırıcı?"
- **recall** (yakalama oranı) = TP / (TP + FN): "Gerçek dolandırıcıların kaçta kaçını yakaladım?"

Kurgusal bir sonuçla hesapla: 40 doğru alarm, 10 yanlış alarm, 20 kaçırma:
""", komut="python3 -c \"tp,fp,fn=40,10,20; print('precision', tp/(tp+fp)); print('recall', tp/(tp+fn))\"",
         sonra="""
Precision 0.80, recall 0.67: işaretlediklerinin %80'i doğru ama dolandırıcıların üçte birini kaçırıyorsun.
"""),
    Adim("Eşik oynayınca ne olur?", """
Eşiği düşürürsen daha çok dolandırıcı yakalarsın (recall artar) ama daha çok meşru müşteri de
işaretlenir (FP artar). Eşiği yükseltirsen tersi. Farklı eşiklerde yanlış alarm sayısı:
""", komut="for e in 30 50 70 90; do echo -n \"esik $e -> FP: \"; awk -F, -v e=$e 'NR>1 && $2>=e && $3==0' skorlar.csv | wc -l; done",
         sonra="""
**İyi eşik** diye tek bir doğru sayı yoktur. Ucuz yanlış alarmla pahalı kaçırma arasındaki denge,
**teknik değil bir iş kararıdır**: kaç meşru müşteriyi rahatsız etmeye razısın?
"""),
    Adim("Katmanlı mimari", """
İyi bir fraud sistemi tek bir model değil, **katmandır**: ucuz ve hızlı olan önce, pahalı olan en son.
Bir işlemin geçtiği aşamalar (karışık sırada) bu dosyada:
""", komut="cat mimari/asamalar.txt", sonra="""
Sıralamayı görevde yapacaksın. İnsan incelemesi Cilt 10'daki **maker-checker**'a (çift onay)
benzer: otomatik sistem şüpheyi işaretler, karar verecek insan bakar.
"""),
    Adim("ML'in iki yüzü", """
ML kuralların göremediği ince desenleri yakalar ve kural yazılmadan yeni dolandırıcılığı bulabilir.
Karşılığında kararını açıklamak zordur ("neden bu müşteri?") ve düzenleyici ya da müşteri sorarsa
cevap vermek gerekir.

**Hacker gözüyle:** Saldırgan modele de uyum sağlar: hangi davranışın düşük skor verdiğini
dener ve oraya çeker. Ayrıca modelin eğitim verisini zehirlemek (yanlış etiket enjekte etmek) bir
saldırı yüzeyidir. Savunma: kurallar + ML + insan, ve etiketlerin kaynağının korunması.
"""),
]

GOREVLER = [
    Gorev("`olc.py` yaz: `python3 olc.py <skorlar.csv> <esik>` şu beş satırı yazsın: `TP: n`, `FP: n`, `FN: n`, "
          "`precision: x.xx`, `recall: x.xx`. Skor eşiğe **eşit ya da büyükse** işaretli sayılır; `gercek` 1 ise "
          "dolandırıcılıktır. Argümansızsa `Kullanım` mesajı ve `exit 1`. Dene: `python3 olc.py skorlar.csv <<esik>>`",
          bt.BetikKontrol("olc.py", _olc_denetle,
                          "Örnek `olc.py`:\n\n```\n" + OLC_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/iskelet.py` sadece TP sayıyor; FP ve FN için iki `elif` ekle.",
           "`isaretli = skor >= esik`, `dolandirici = gercek == 1`. İşaretli ve dolandırıcı: TP; işaretli ama değil: "
           "FP; işaretli değil ama dolandırıcı: FN. Bölme öncesi payda sıfır mı diye bak.",
           "```\nif isaretli and dolandirici: tp += 1\nelif isaretli: fp += 1\nelif dolandirici: fn += 1\n```\n"
           "Sonra `precision = tp / (tp + fp)` ve `recall = tp / (tp + fn)`; `print(f\"precision: {precision:.2f}\")`."),
          puan=60, baslik="Ölçüm aracı"),
    Gorev("Eşik <<esik>> iken kaç **yanlış alarm** (FP: işaretlendi ama `gercek` 0) var?",
          Sayi("fp", sik_hatalar=_fp_hata),
          ("Aracının çıktısına bak ya da `awk` ile iki koşulu birlikte uygula.",
           "`awk -F, 'NR>1 && $2>=<<esik>> && $3==0' skorlar.csv | wc -l`",
           "Aynı komut; ya da `python3 olc.py skorlar.csv <<esik>> | grep FP`"),
          puan=25, baslik="Yanlış alarm"),
    Gorev("Aynı eşikte (<<esik>>) kaç dolandırıcılık **kaçırıldı** (FN: skor eşiğin altında ama `gercek` 1)?",
          Sayi("fn", sik_hatalar=_fn_hata),
          ("Bu kez skor eşiğin **altında**; gerçek değeri 1.",
           "`awk -F, 'NR>1 && $2<<<esik>> && $3==1' skorlar.csv | wc -l`",
           "Yukarıdaki komutu aynen çalıştır; ya da aracındaki FN satırına bak."),
          puan=25, baslik="Kaçan dolandırıcı"),
    Gorev("Yönetim \"dolandırıcıların en az **%90**'ını yakalayalım\" diyor (recall ≥ 0.90). Eşik adayları "
          "10, 15, 20 ... 95 (5'in katları). Bu şartı sağlayan **en yüksek** eşik hangisi?",
          Sayi("recall90", sik_hatalar=_r90_hata),
          ("Eşik yükseldikçe recall düşer. Adayları yukarıdan aşağı dene.",
           "Aracınla her eşik için recall'a bak: `for e in 95 90 85 80 75 70 65 60 55 50; do echo $e; python3 olc.py "
           "skorlar.csv $e | grep recall; done`",
           "İlk `recall: 0.90` ve üstü gördüğün eşik cevaptır (ondalık yuvarlamaya dikkat: 0.90'a çok yakınsa awk ile "
           "TP/(TP+FN)'yi kesin hesapla)."),
          puan=40, baslik="Recall hedefi"),
    Gorev("İş kararı: yanlış alarm **<<fp_m>> TL**, kaçan dolandırıcılık **<<fn_m>> TL**. Toplam maliyeti "
          "(FP × <<fp_m>> + FN × <<fn_m>>) **en düşük** olan eşik (10, 15 ... 95) hangisi?",
          Sayi("maliyet", sik_hatalar=_maliyet_hata),
          ("Her aday eşik için FP ve FN sayısını bul, maliyetle çarp, topla; en küçüğünü seç.",
           "Bir döngü: `for e in $(seq 10 5 95); do ...; done`. İçinde awk ile `f*<<fp_m>> + n*<<fn_m>>`.",
           "`for e in $(seq 10 5 95); do awk -F, -v e=$e 'NR>1{if ($2>=e && $3==0) f++; if ($2<e && $3==1) n++} "
           "END{print f*<<fp_m>>+n*<<fn_m>>, e}' skorlar.csv; done | sort -n | head -3`"),
          puan=40, baslik="Maliyete göre eşik"),
    Gorev("`mimari/asamalar.txt` dosyasında dört aşama karışık sırada. Bir işlemin geçmesi gereken **doğru sırayı** "
          "numaralarla yaz (örn. `3 1 4 2`).",
          Dizi("mimari", sik_hatalar=_mimari_hata, bicim="numaralar sırayla, örn. 3 1 4 2"),
          ("Önce hangisi en ucuz ve en hızlı, hangisi en pahalı?",
           "Hızlı kurallar -> ML skoru -> insan -> geri bildirim. Dosyadaki numaralarla eşle.",
           "`cat mimari/asamalar.txt` ve her aşamanın başındaki numarayı doğru sırada yaz."),
          puan=25, baslik="Katmanlı mimari"),
    Gorev("False positive (yanlış alarm) dengesi neden **teknik değil iş kararıdır**?",
          Secmeli([
              ("Eşiğin sıkılığı, kaç meşru müşteriyi rahatsız etmeye razı olunduğuna ve kaçan dolandırıcılığın maliyetine bağlıdır",
               "Doğru. Aynı model farklı eşiklerle farklı dengeler verir; hangisi 'doğru' diye bir cevap, "
               "maliyetlere ve iş önceliklerine bakmadan verilemez."),
              ("Çünkü yanlış alarmı ancak yönetim kurulu ölçebilir",
               "Ölçüm teknik olarak yapılır (TP/FP/FN); seçim iş kararıdır."),
              ("Çünkü model ne kadar iyi olursa olsun yanlış alarm her zaman sıfırdır",
               "Hiçbir model mükemmel değildir; yanlış alarm ile kaçırma arasında hep bir takas vardır."),
              ("Çünkü yanlış alarm yalnızca kural motorlarında olur, ML'de olmaz",
               "ML'de de yanlış alarm olur; hatta açıklaması daha zordur."),
          ]),
          ("Aynı modelle iki farklı eşik seçersen sonuç değişiyor mu?",
           "Eşiği kim ve neye göre seçiyor?",
           "Maliyet görevinde yaptığın hesabı hatırla."),
          puan=25, baslik="İş kararı"),
    Gorev("ML tabanlı fraud tespitinin kural motoruna göre **avantajı ve dezavantajı** nedir?",
          Secmeli([
              ("Kural yazılmadan yeni ve ince desenleri yakalayabilir; ama kararlarını açıklamak zordur ve yanlış alarm dengesi hassastır",
               "Doğru. Bu yüzden sistemler kuralları, ML'i ve insan incelemesini birlikte kullanır."),
              ("Her zaman daha hızlı ve şeffaftır; tek dezavantajı maliyetidir",
               "Şeffaf olması genellikle kural motorlarının özelliğidir; ML kararları açıklamak daha zordur."),
              ("Etiketli veriye ihtiyaç duymaz ve hiç yanlış alarm üretmez",
               "Denetimli modeller etiketli veriye ihtiyaç duyar ve yanlış alarm üretir."),
              ("Saldırganlar modeli aşamaz çünkü model gizlidir",
               "Saldırganlar davranışı değiştirerek ya da veriyi zehirleyerek modele uyum sağlamayı deneyebilir."),
          ]),
          ("Kuralların gücü ve zayıflığıyla kıyasla.",
           "ML'in avantajı yeni desenler, dezavantajı açıklanabilirlik.",
           "Katmanlı mimarinin neden gerektiğini düşün."),
          puan=25, baslik="ML'in iki yüzü"),
]

SEVIYE = Seviye(
    kimlik="c21b03",
    cilt=21,
    bolum=3,
    baslik="Makine Öğrenmesi ve Mimari",
    brifing="""
**<<musteri>>**: <<olay>>

Selin bir CSV bırakıyor: "<<satir>> sonuçlanmış vakanın model skoru ve gerçek sonucu var. Modeli sen
eğitmiyorsun; **karnesini** çıkaracaksın. Bizim eşik <<esik>>. Kaç dolandırıcıyı yakaladık, kaç meşru
müşteriyi yanlışlıkla işaretledik?" Deniz ekliyor: "Eşiği oynatınca iki sayı ters yönde hareket eder.
Yönetim hangi sayıyı daha çok önemsiyor, onu belirlememiz gerek." Mert: "Ve unutma, her model
'neden?' sorusuna cevap veremez."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Skor veren bir sistemde iki sayı birbirine bağlıdır: eşiği düşürdükçe dolandırıcıyı daha çok yakalar
(recall artar), ama meşru müşteriyi daha çok rahatsız edersin (precision düşer). Doğru eşik bir
matematik değil, iki hatanın maliyetini karşılaştıran bir iş kararıdır. Saldırgan açısından ders:
sistem skorun altında kalacak davranışı arar ve eşiğin hemen altına yerleşir. Savunma açısından ders:
hızlı kurallar, ML skoru ve insan incelemesini katmanla, sonuçları geri besleyip eşikleri düzenli
yeniden ölçmek.
""",
    gercek_hayat="""
- **Katmanlı fraud mimarisi:** Banka ve ödeme şirketlerinin fraud sistemlerinde hızlı kurallar,
  makine öğrenmesi skorları ve insan inceleme kuyruğu birlikte çalışır. Tespit tarafında her katman
  başka bir kaçırma türünü kapatır; önlem tarafında inceleme sonuçları modele etiket olarak döner.
- **Yanlış pozitif maliyeti:** Reddedilen meşru işlemin müşteri kaybına ve itibara mal olduğu, bu yüzden
  eşiklerin yalnızca yakalama oranıyla değil müşteri deneyimiyle birlikte ayarlandığı, sektörde geniş
  kabul gören bir ilkedir.
- **Model riskleri:** Makine öğrenmesi sistemleri için kasıtlı kötü veriyle modeli yanıltma (veri
  zehirleme) ve kararın açıklanabilirliği iyi bilinen risk başlıklarıdır. Savunma: eğitim verisinin
  kaynağını ve etiket sürecini kontrol altında tutmak, model davranışını düzenli izlemek.
""",
    sure_hedef_dk=40,
)
