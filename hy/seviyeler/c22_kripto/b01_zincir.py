"""Cilt 22 · Bölüm 1 — Blockchain Güvenlik Temelleri.

Beceri: hash zincirinin mantığı (her blok bir öncekinin hash'ini taşır), sha256 ile bir bloğu yeniden
hesaplamak, kurcalanan bloğu bulmak, kurcalamanın neden "tek blok" değil "zincirin devamı" demek olduğunu
görmek; değiştirilemezliğin güç ve risk yüzü; anahtar yönetiminin neden her şey olduğu.

Laboratuvar: kurgusal bir mini defter zinciri (JSON) ve ikinci bir düğümdeki sağlam kopyası. Gerçek bir
kripto para ya da ağ yoktur; sadece sha256 ve JSON.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Dinamik, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

VAKALAR = [
    {"kod": "paramix", "ad": "Paramix tedarikçi hakediş defteri", "tur": "HAKEDIS", "kaynak": "PMX-ODEME",
     "hedef": ["TED-014", "TED-027", "TED-033", "TED-041", "TED-052"], "aralik": (4200, 96000),
     "olay": "Paramix, tedarikçi hakedişlerini birkaç şirketin ortak tuttuğu bir defterde (konsorsiyum zinciri) "
             "kaydediyor. Ece Hanım, bir hakediş tutarının sonradan değiştirildiğinden şüpheleniyor."},
    {"kod": "ferahbank", "ad": "Ferah Bank şubeler arası mutabakat defteri", "tur": "MUTABAKAT", "kaynak": "FB-MERKEZ",
     "hedef": ["SUBE-02", "SUBE-07", "SUBE-11", "SUBE-19", "SUBE-23"], "aralik": (150000, 2400000),
     "olay": "Ferah Bank, şubeler arası mutabakat kayıtlarını bir hash zinciri defterinde tutuyor. Kaan Bey, bir "
             "mutabakat tutarının onaydan sonra değiştirildiği uyarısını iç denetimden aldı."},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik navlun hakediş zinciri", "tur": "NAVLUN", "kaynak": "KZG-DEPO",
     "hedef": ["FIRMA-12", "FIRMA-18", "FIRMA-24", "FIRMA-31", "FIRMA-40"], "aralik": (3100, 58000),
     "olay": "Kuzgun Lojistik, taşeron navlun hakedişlerini ortak bir zincir defterinde paylaşıyor. Serdar Bey, "
             "bir taşeronun hakediş tutarının kendi kopyasıyla uyuşmadığını fark etti."},
]


def blok_hash(index, zaman, veri, onceki) -> str:
    return hashlib.sha256(f"{index}|{zaman}|{veri}|{onceki}".encode("utf-8")).hexdigest()


def _islem(rng, v) -> tuple:
    return v["tur"], v["kaynak"], rng.choice(v["hedef"]), rng.randint(v["aralik"][0] // 100, v["aralik"][1] // 100) * 100


def _veri(islemler) -> str:
    return "; ".join(f"{t} {k} -> {h} {tu} TRY" for t, k, h, tu in islemler)


def zincir_uret(rng: random.Random, v: dict, n: int, kurcala: str | None = None) -> dict:
    """Zincir (sağlam) + kurcalanmışı. kurcala: None | 'A' (hash eski kalır) | 'B' (hash yeniden hesaplanır)."""
    t = u.gun(rng) + timedelta(hours=9)
    sag, onceki = [], "0" * 64
    islemler_listesi = []
    for i in range(n):
        t += timedelta(minutes=rng.randint(7, 55))
        isl = [_islem(rng, v) for _ in range(rng.randint(1, 3))]
        islemler_listesi.append(isl)
        zaman = f"{t:%Y-%m-%dT%H:%M:%S}"
        veri = _veri(isl)
        h = blok_hash(i, zaman, veri, onceki)
        sag.append({"index": i, "zaman": zaman, "veri": veri, "onceki_hash": onceki, "hash": h})
        onceki = h
    bilgi = {"k": None, "eski_tutar": None, "yeni_tutar": None}
    bozuk = json.loads(json.dumps(sag))
    if kurcala:
        k = rng.randint(2, n - 3) if kurcala == "B" else rng.randint(2, n - 2)
        isl = [list(x) for x in islemler_listesi[k]]
        eski = isl[0][3]
        yeni = eski * rng.choice([5, 8, 10])
        isl[0][3] = yeni
        b = bozuk[k]
        b["veri"] = _veri([tuple(x) for x in isl])
        if kurcala == "B":
            b["hash"] = blok_hash(b["index"], b["zaman"], b["veri"], b["onceki_hash"])
        bilgi = {"k": k, "eski_tutar": eski, "yeni_tutar": yeni}
    ilk_bozuk = None
    if kurcala == "A":
        ilk_bozuk = bilgi["k"]
    elif kurcala == "B":
        ilk_bozuk = bilgi["k"] + 1
    return {"ad": v["ad"], "sag": sag, "bozuk": bozuk, "bilgi": bilgi, "ilk_bozuk": ilk_bozuk, "n": n}


def json_yaz(yol: Path, ad: str, bloklar: list) -> None:
    u.yaz(yol, json.dumps({"defter": ad, "algoritma": "sha256", "bloklar": bloklar}, indent=2, ensure_ascii=False) + "\n")


def _sha_komut(metin: str) -> str:
    return subprocess.run(["sha256sum"], input=metin.encode(), capture_output=True).stdout.decode().split()[0]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    tip = rng.choice(["A", "B"])
    n = rng.randint(8, 11)
    tohum = rng.randint(1, 10**9)
    z = zincir_uret(random.Random(tohum), v, n, tip)
    b = z["bilgi"]
    kontrol_blok = rng.choice([i for i in range(1, n) if i not in (b["k"], b["k"] + 1)])
    h = z["sag"][kontrol_blok]["hash"]
    return {
        "vaka": f"{m['ad']} — {v['ad']}",
        "musteri": m, "v": v, "tip": tip, "n": n, "tohum": tohum, "kontrol_blok": kontrol_blok,
        "metin": {"musteri": m["ad"], "olay": v["olay"], "defter": v["ad"], "n": n, "blok": kontrol_blok,
                  "son": n - 1},
        "cevaplar": {
            "hash": [h[:10], h],
            "ilk_bozuk": z["ilk_bozuk"],
            "kurcalanan": b["k"],
            "eski_tutar": b["eski_tutar"],
            "yeniden": n - b["k"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    z = zincir_uret(random.Random(s["tohum"]), s["v"], s["n"], s["tip"])
    json_yaz(lab / "zincir.json", s["v"]["ad"], z["bozuk"])
    json_yaz(lab / "dugum_b.json", s["v"]["ad"], z["sag"])
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — kurgusal hash zinciri\n\n"
          f"zincir.json : bizim düğümdeki defter ({s['n']} blok, 0'dan {s['n'] - 1}'e)\n"
          "dugum_b.json: ortak çalıştığımız B düğümünün, olay duyulmadan önce aldığı kopya\n\n"
          "Her blokta: index, zaman, veri, onceki_hash, hash\n"
          "Blok hash'i şöyle hesaplanır (sha256, hex):\n\n"
          "    sha256( index + \"|\" + zaman + \"|\" + veri + \"|\" + onceki_hash )\n\n"
          "Örnek: printf '%s' \"3|2026-...|veri...|onceki\" | sha256sum\n"
          "Genesis (0. blok) bloğunun onceki_hash değeri 64 tane sıfırdır.\n\n"
          "Kendi doğrulayıcını lab'ın köküne yaz: zincir_dogrula.py\n"
          "Kullanım: python3 zincir_dogrula.py zincir.json\n"
          "Çıktı   : sağlamsa `ZINCIR GECERLI`, değilse ilk bozuk bloğu `BOZUK: <index>` diye yaz.\n")
    u.yaz(lab / "ornekler" / "iskelet.py", ISKELET_PY, mod=0o755)


ISKELET_PY = r'''#!/usr/bin/env python3
# iskelet.py — zinciri okuyup her bloğun hash'ini yeniden hesaplar ve kayıtlı hash ile karşılaştırır
import hashlib
import json
import sys

bloklar = json.load(open(sys.argv[1], encoding="utf-8"))["bloklar"]

for b in bloklar:
    metin = f"{b['index']}|{b['zaman']}|{b['veri']}|{b['onceki_hash']}"
    hesap = hashlib.sha256(metin.encode("utf-8")).hexdigest()
    print(b["index"], "tamam" if hesap == b["hash"] else "UYUSMUYOR")

# Eksikler: kullanım mesajı; ZİNCİR BAĞI (her bloğun onceki_hash'i, bir önceki bloğun hash'ine eşit mi?);
# ilk bozuk bloğu `BOZUK: <index>` diye yazıp bitirmek; hiçbiri bozuk değilse `ZINCIR GECERLI`.
'''

DOGRULA_PY = r'''#!/usr/bin/env python3
import hashlib
import json
import sys

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <zincir.json>")
    sys.exit(1)

bloklar = json.load(open(sys.argv[1], encoding="utf-8"))["bloklar"]
onceki = "0" * 64
for b in bloklar:
    metin = f"{b['index']}|{b['zaman']}|{b['veri']}|{b['onceki_hash']}"
    hesap = hashlib.sha256(metin.encode("utf-8")).hexdigest()
    if hesap != b["hash"] or b["onceki_hash"] != onceki:
        print(f"BOZUK: {b['index']}")
        sys.exit(2)
    onceki = b["hash"]
print("ZINCIR GECERLI")
'''


# ---------------------------------------------------------------- denetim

def _dene(calistir: bt.Calistirici, yol: Path, beklenen, goster: str, etiket: str) -> Sonuc | None:
    c = calistir(str(yol))
    nasil = calistir.goster(goster)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` ({etiket}) çalışırken: {cokme}")
    a = bt.ascii_kucuk(c.stdout)
    if beklenen is None:
        if "bozuk" in a or "gecersiz" in a:
            return Sonuc(False, f"`{nasil}` ({etiket}): sağlam bir zincire BOZUK demişsin. Hash'i yeniden hesaplarken "
                         "formülü birebir uygula: `index|zaman|veri|onceki_hash`." + bt.ozet(c), yakin=True)
        if "gecerli" not in a:
            return Sonuc(False, f"`{nasil}` ({etiket}): sağlam zincirde `ZINCIR GECERLI` yazmalı." + bt.ozet(c), yakin=True)
        return None
    if "bozuk" not in a:
        return Sonuc(False, f"`{nasil}` ({etiket}): kurcalanmış zincire `BOZUK: <index>` demedin." + bt.ozet(c), yakin=True)
    import re
    m = re.search(r"bozuk\D{0,12}(\d+)", a)
    if not m or int(m.group(1)) != beklenen:
        verilen = m.group(1) if m else "?"
        ek = ""
        if m and int(m.group(1)) == beklenen - 1:
            ek = " (Bir blok erken bildirmişsin: zinciri bağlayan `onceki_hash` karşılaştırması bozuk bloğu bir sonraki blokta yakalar.)"
        elif m and int(m.group(1)) == beklenen + 1:
            ek = " (Bir blok geç: önce hash'i yeniden hesapla, sonra zincir bağını kontrol et; ilk başarısız olan raporlanır.)"
        elif beklenen and m is None:
            ek = " (Çıktıda `BOZUK:` ardından blok numarası olmalı.)"
        return Sonuc(False, f"`{nasil}` ({etiket}): ilk bozuk blok {beklenen}, sen {verilen} demişsin.{ek}"
                     + ("" if m else bt.ozet(c)), yakin=True)
    return None


def _dogrula_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    lab_json = Path(b.lab) / "zincir.json"
    if not lab_json.is_file():
        return Sonuc(False, f"{lab_json} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    z = zincir_uret(random.Random(s["tohum"]), s["v"], s["n"], s["tip"])
    sonuc = _dene(calistir, lab_json, z["ilk_bozuk"], "zincir.json", "lab zinciri")
    if sonuc:
        return sonuc
    rng = random.Random()
    v = rng.choice(VAKALAR)
    for tip, etiket in ((None, "sağlam yeni zincir"), ("A", "hash'i eski kalmış yeni zincir"),
                        ("B", "hash'i yeniden hesaplanmış yeni zincir")):
        yeni = zincir_uret(rng, v, rng.randint(7, 12), tip)
        fd, ad = tempfile.mkstemp(prefix="hy_zincir_", suffix=".json")
        os.close(fd)
        gecici = Path(ad)
        try:
            json_yaz(gecici, v["ad"], yeni["bozuk"])
            sonuc = _dene(calistir, gecici, yeni["ilk_bozuk"], str(gecici), etiket)
        finally:
            gecici.unlink(missing_ok=True)
        if sonuc:
            sonuc.mesaj += "\n    (Bu, hiç görmediğin yeni bir zincirdi.)"
            return sonuc
    return Sonuc(True, "zincir_dogrula.py hem lab zincirini hem hiç görmediği üç yeni zinciri doğru değerlendirdi: sağlamı "
                       "geçirdi, hash'i eski kalmış bloğu ve zincir bağı kopan bloğu yakaladı. Bir blockchain düğümünün "
                       "yaptığı temel doğrulama tam olarak budur.")


def _ilk_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["cevaplar"]["kurcalanan"] and n != beklenen:
        return ("Değiştirilen blok bu ama zincirde **doğrulamanın ilk kırıldığı** blok farklı: saldırgan bu bloğun "
                "hash'ini yeniden hesaplamış; kopukluk bir sonraki bloğun `onceki_hash` alanında görünür.")
    return None


def _kurc_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return ("Bu, bağın koptuğu blok. Soru **verisi değiştirilen** bloğu soruyor: B düğümündeki sağlam kopyayla "
                "`diff` alıp farklı satırın hangi bloğa ait olduğuna bak.")
    return None


def _yeniden_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen - 1:
        return "Kurcalanan bloğun kendisini de say: onun hash'i de değişti."
    if n == beklenen + 1:
        return ("Blok numaraları 0'dan başlar. Kurcalanan blok k ise k'dan son bloğa kadar olan blok sayısı = "
                "(blok sayısı - k).")
    return None


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "zincir_dogrula.py", DOGRULA_PY)
    bozuk = sh("python3 zincir_dogrula.py zincir.json | grep -o '[0-9]*'", lab)
    # blok N'in hash'i: formülü uygulayarak sha256sum ile
    n = s["kontrol_blok"]
    metin = sh(f"python3 -c \"import json;b=json.load(open('zincir.json'))['bloklar'][{n}];"
               "print(str(b['index'])+'|'+b['zaman']+'|'+b['veri']+'|'+b['onceki_hash'],end='')\"", lab)
    h = _sha_komut(metin)
    # kurcalanan blok: iki dosyanın veri satırı farkı
    satir_no = sh("diff zincir.json dugum_b.json | head -1 | grep -o '^[0-9]*'", lab)
    kurc = sh(f"awk -v s={satir_no} 'NR<s && /\"index\"/{{i=$2}} END{{gsub(/,/,\"\",i); print i}}' zincir.json", lab)
    eski = sh("diff zincir.json dugum_b.json | grep '^>' | grep -o '[0-9]* TRY' | head -1 | awk '{print $1}'", lab)
    n_blok = sh("grep -c '\"index\"' zincir.json", lab)
    yeniden = str(int(n_blok) - int(kurc))
    cozum = {1: "", 2: h[:10], 3: bozuk, 4: kurc, 5: eski, 6: yeniden}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Zincir nedir?", """
Selin: "Blockchain, özünde **kendinden öncekini mühürleyen bloklar** zinciridir. Her blok, bir
önceki bloğun hash'ini (parmak izi) içinde taşır. Birini değiştirirsen onun hash'i değişir, bir
sonraki blok eski hash'i beklediği için bağ kopar, sonraki de, sonraki de..." Defterin tanımı ve
hash formülü:
""", komut="cat OKUBENI.txt"),
    Adim("sha256: tek harf, tamamen başka parmak izi", """
`sha256sum` bir metnin 64 haneli parmak izini (hash) çıkarır. Aynı girdi her zaman aynı çıktıyı verir,
ama girdideki **tek harf** değişince çıktı tamamen değişir. `printf '%s'` metni sonuna satır sonu
eklemeden yazar (satır sonu da hash'i değiştirir!). Önce `merhaba`:
""", komut="printf '%s' 'merhaba' | sha256sum"),
    Adim("Bir harf değişince", """
Şimdi son harfi değiştir ve karşılaştır:
""", komut="printf '%s' 'merhabb' | sha256sum", sonra="""
Hiçbir benzerlik yok. Bu, hash'in **çığ etkisi**dir (avalanche): kurcalamayı gizlemek için
"küçük bir değişiklik" diye bir şey yoktur.
"""),
    Adim("Bir bloğun anatomisi", """
Zincir dosyasının ilk bloğuna bak: `index`, `zaman`, `veri` (işlemler), `onceki_hash` ve `hash`.
Genesis bloğunun önceki hash'i 64 sıfırdır:
""", komut="head -12 zincir.json"),
    Adim("Zincirin bağı", """
Her bloğun `onceki_hash` değeri, bir önceki bloğun `hash` değeriyle **aynı** olmalı. İlk üç bloğun
üç alanını alt alta görelim:
""", komut="grep -E '\"(index|onceki_hash|hash)\"' zincir.json | head -9", sonra="""
Bir bloğun `veri`sini değiştirmek hash'ini değiştirir. Saldırgan o bloğun hash'ini yeniden hesaplarsa
bu sefer **bir sonraki bloğun** `onceki_hash`'i uyuşmaz; zinciri tutarlı kılmak için sondan başa
**her bloğu** yeniden hesaplaması gerekir. Gerçek ağlarda buna bir de çoğunluğun onayı eklenir.
"""),
    Adim("İki düğüm, iki kopya", """
Zincir birden çok düğümde tutulur. B düğümünün kopyasıyla bizimkini karşılaştırmanın en hızlı yolu:
`cmp` dosyaları bayt bayt karşılaştırır, `-s` sessiz çalışır; çıkış kodu 0 aynı, 1 farklı demektir.
""", komut="cmp -s zincir.json dugum_b.json; echo \"cmp çıkış kodu: $?\"", sonra="""
Fark var. Nerede olduğunu görev sırasında `diff` ile bulacaksın (`diff dosya1 dosya2` farklı satırları
`<` ve `>` ile gösterir).
"""),
    Adim("İskelet doğrulayıcı", """
`ornekler/iskelet.py` her bloğun hash'ini yeniden hesaplayıp kayıtlı hash'le karşılaştırıyor ama zincir
bağını denetlemiyor. Çalıştır:
""", komut="python3 ornekler/iskelet.py zincir.json", sonra="""
Çıktıda hangi blokların UYUSMUYOR dediğine bak. Hepsi UYUSMUYOR demeyebilir: saldırgan hash'i de
güncellemişse bu denetim tek başına yetmez; **bağ** denetimi şart.

**Hacker gözüyle:** Değiştirilemezlik güçtür: kayıt kurcalanamaz. Ama aynı özellik risktir: yanlış ya da
hırsızlıkla oluşmuş bir işlem de geri alınamaz. Bankada hileli havale iptal edilir; zincirde "geri al"
düğmesi yoktur. Bu yüzden kripto dünyasında **anahtar yönetimi** her şeydir.
"""),
]

GOREVLER = [
    Gorev("`zincir_dogrula.py` yaz: `python3 zincir_dogrula.py zincir.json` her bloğun hash'ini formülle yeniden "
          "hesaplasın **ve** zincir bağını (`onceki_hash` = bir önceki bloğun `hash`i; genesis için 64 sıfır) "
          "denetlesin. İlk başarısız blokta `BOZUK: <index>` yazıp çıksın (`exit 2`); hepsi sağlamsa "
          "`ZINCIR GECERLI`. Argümansızsa `Kullanım` mesajı ve `exit 1`. Oyun betiğini senin hiç görmediğin "
          "sağlam ve kurcalanmış yeni zincirlerle de deneyecek.",
          bt.BetikKontrol("zincir_dogrula.py", _dogrula_denetle,
                          "Örnek `zincir_dogrula.py`:\n\n```\n" + DOGRULA_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/iskelet.py` hash'i yeniden hesaplıyor; bir `onceki` değişkeni tutup bağı da denetle.",
           "`onceki = \"0\" * 64` ile başla. Her blokta iki şart: hesaplanan hash == `b['hash']` ve "
           "`b['onceki_hash'] == onceki`. Biri bozuksa yazdır ve `sys.exit(2)`. Döngü sonunda `onceki = b['hash']`.",
           "```\nonceki = \"0\" * 64\nfor b in bloklar:\n    ...hesap...\n    if hesap != b['hash'] or b['onceki_hash'] != onceki:\n"
           "        print(f\"BOZUK: {b['index']}\"); sys.exit(2)\n    onceki = b['hash']\nprint(\"ZINCIR GECERLI\")\n```"),
          puan=70, baslik="Zincir doğrulayıcı"),
    Gorev("`zincir.json` içindeki **blok <<blok>>**'un hash'ini formülü kullanarak kendin yeniden hesapla "
          "(`index|zaman|veri|onceki_hash`, sha256). Hash'in ilk 10 hanesini yaz.",
          Dinamik(lambda b: b.senaryo["cevaplar"]["hash"], bicim="hash'in ilk 10 hanesi (ya da tamamı)"),
          ("Formül `OKUBENI.txt`'de. Bloğun dört alanını tam sırayla ve `|` ile birleştir.",
           "`printf '%s' \"index|zaman|veri|onceki_hash\" | sha256sum`; alanları dosyadan kopyala (ya da python'la "
           "`json.load` ile oku).",
           "`python3 -c \"import json;b=json.load(open('zincir.json'))['bloklar'][<<blok>>];print(str(b['index'])+'|'+b['zaman']+'|'+"
           "b['veri']+'|'+b['onceki_hash'],end='')\" | sha256sum`"),
          puan=30, baslik="Hash'i kendin hesapla"),
    Gorev("Doğrulamanın zincirde **ilk kırıldığı** blok numarası kaç? (Hash uyuşmazlığı ya da zincir bağı fark etmez.)",
          Sayi("ilk_bozuk", sik_hatalar=_ilk_hata),
          ("Aracının çıktısına bak.",
           "`python3 zincir_dogrula.py zincir.json`",
           "Hash uyuşmazlığı o bloğun kendisinde, bağ kopukluğu ise bir sonraki blokta görünür; hangisi önce geliyorsa o."),
          puan=20, baslik="İlk kırılma"),
    Gorev("Asıl soru: **verisi değiştirilen** blok hangisi? (B düğümündeki sağlam kopyayla karşılaştır.)",
          Sayi("kurcalanan", sik_hatalar=_kurc_hata),
          ("Sağlam kopya `dugum_b.json`. İki dosyada farklı satırı bul; satırın hangi bloğa ait olduğuna bak.",
           "`diff zincir.json dugum_b.json` farklı satır numaralarını verir. O satırdan geriye doğru en yakın `\"index\"` "
           "satırı, bloğun numarasıdır.",
           "`diff zincir.json dugum_b.json | head`; ardından `grep -n '\"index\"' zincir.json` ile satır numaralarını "
           "blok numaralarıyla eşle."),
          puan=35, baslik="Kurcalanan blok"),
    Gorev("O bloktaki ilk işlemin **orijinal tutarı** (B düğümündeki kopyaya göre, TRY) kaçtı?",
          Sayi("eski_tutar"),
          ("Sağlam kopya hangi dosya? Farklı satırın `>` ile gösterilen tarafı sağlam kopyadır.",
           "`diff zincir.json dugum_b.json` çıktısında `>` ile başlayan satırdaki `veri` alanını oku; ilk işlemin "
           "tutarı `TRY`'den hemen önce.",
           "`diff zincir.json dugum_b.json | grep '^>'`"),
          puan=25, baslik="Gerçek tutar"),
    Gorev("Saldırgan kurcalamayı **gizlemek** isteseydi, kurcaladığı blok **dahil** kaç bloğun hash'ini yeniden "
          "hesaplayıp güncellemesi gerekirdi? (Kurcalanan bloktan son bloğa kadar.)",
          Sayi("yeniden", sik_hatalar=_yeniden_hata),
          ("Kurcalanan bloğun hash'i değişince bir sonraki bloğun `onceki_hash`'i de eski kalır, o da değişmeli...",
           "Blok numarası k ise zincirde k, k+1, ..., son blok değişmeli. Toplam blok sayısı <<n>> (0'dan <<son>>'e).",
           "Cevap = (toplam blok sayısı) - (kurcalanan blok numarası)."),
          puan=25, baslik="Gizlemenin bedeli"),
    Gorev("Blockchain'in **değiştirilemezliği** neden hem güçtür hem risk?",
          Secmeli([
              ("Kayıt kurcalanamaz ve güven sağlar; ama hatalı ya da hırsızlıkla oluşmuş bir işlem de geri alınamaz",
               "Doğru. Geleneksel bankacılıkta hileli transfer iptal edilebilir; zincirde çalınan varlık gitmiştir."),
              ("Kayıtlar kolayca silinebilir, bu yüzden güvenilmezdir",
               "Tersine: kayıtlar silinip değiştirilemez; sorun geri alınamama."),
              ("Yalnızca küçük işlemler geri alınabilir, büyükler alınamaz",
               "Tutarla ilgisi yok; onaylanmış işlem büyüklüğüne bakılmadan kalıcıdır."),
              ("Blockchain her işlem için bir yönetici onayı ister ve bu yavaşlatır",
               "Merkezi bir yönetici yoktur; risk onay yavaşlığı değil geri alınamazlıktır."),
          ]),
          ("Zincirde çalınan bir varlık geri istenebilir mi?",
           "Güç ve risk aynı özellikten çıkar.",
           "Banka havalesini iptal edebilirsin; zincirde edemezsin."),
          puan=25, baslik="Güç ve risk"),
    Gorev("Bir geliştirici, cüzdanın **özel anahtarını** yanlışlıkla ortak bir kod deposuna yükledi ve 10 dakika "
          "sonra silmiş. Anahtarda hâlâ varlık var. En doğru adım hangisi?",
          Secmeli([
              ("Anahtarı ele geçirilmiş say, varlığı yeni ve güvenli bir anahtara hemen taşı, eskisini bir daha kullanma",
               "Doğru. Depodan silmek yetmez: kopyalanmış olabilir ve zincirde geri alma yoktur."),
              ("Depodaki dosyayı sildiği için sorun kalmadı; yalnızca geçmişi temizle",
               "Silme, başkasının aldığı kopyayı geri getirmez; anahtar artık güvenilmezdir."),
              ("Anahtarı değiştirmek gerekmez, sadece depoyu özel yap",
               "Erişim daraltmak, daha önce görülmüş olabilecek anahtarı güvenli yapmaz."),
              ("Önce yedeklerin olup olmadığına bak, sonra bir hafta bekle",
               "Beklemek saldırgana zaman verir; bu durumda dakikalar önemlidir."),
          ]),
          ("Anahtarı başka biri görmüş olabilir mi? Zincirde geri alma var mı?",
           "Sır sızdıysa 'silmek' çözüm değildir; sırrı geçersiz kılmak gerekir.",
           "Cilt 12'deki sır yönetimi kuralı burada geri alınamaz kayıpla birleşir."),
          puan=25, baslik="Sızan anahtar"),
]

SEVIYE = Seviye(
    kimlik="c22b01",
    cilt=22,
    bolum=1,
    baslik="Blockchain Güvenlik Temelleri",
    brifing="""
**<<musteri>>**: <<olay>> Defter bir hash zinciri olarak tutuluyor: **<<n>> blok**, her biri bir
öncekinin parmak izini taşıyor.

Selin: "Bir blok kurcalanmış olabilir. Hangisi? Neyi, ne kadar değiştirmişler? Ve kurcalamayı
gizlemek için ne kadar iş yapmaları gerekirdi?" Deniz, B düğümünden gelen sağlam kopyayı uzatıyor:
"Olay duyulmadan önce aldığımız kopya. Aradaki farkı bul." Mert: "Önce zinciri **kendin** doğrula.
Başkasının 'sağlam' demesine güvenme; blockchain'in bütün fikri bu."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kendi doğrulayıcınla bir zincirin sağlam olup olmadığını **kimseye güvenmeden** kanıtladın. Bir bloğun
verisini değiştirmek hash'ini bozar; saldırgan hash'i güncelleyebilir ama o zaman bağ bir sonraki blokta
kopar ve sonuna kadar her bloğu yeniden yazması gerekir. Gerçek ağlarda buna çoğunluğun onayı eklenir ve
iş imkânsıza yaklaşır. Ama aynı değiştirilemezlik, çalınan ya da yanlış gönderilen paranın geri
alınamaması demektir. Savunma dersi: kayıt değil, **anahtar** zayıf halkadır; sızan anahtar hemen
geçersiz kılınmalı, varlık yeni bir anahtara taşınmalıdır.
""",
    gercek_hayat="""
- **Anahtar sızıntıları kod depolarında:** Kod depolarına yanlışlıkla yüklenen gizli anahtar ve parolalar
  uzun süredir bilinen, yaygın bir güvenlik sorunudur; otomatik tarayıcılar yüklenen sırları çoğu
  zaman dakikalar içinde bulur. Tespit: depoda gizli bilgi tarayıcıları; önlem: sırları kodun dışında
  tutmak ve sızanı hemen geçersiz kılmak.
- **Hash ile bütünlük kontrolü:** Aynı fikir blockchain dışında da kullanılır: yazılım indirmelerinin
  yayımlanan sha256 değeriyle karşılaştırılması ya da bir dosyanın onaylı hash'iyle denetlenmesi,
  değişikliği fark etmenin en basit yoludur.
- **Geri alınamazlığın bedeli:** Kripto hizmet sağlayıcılarında yaşanan bazı hırsızlıklarda, ağ
  kurallarına göre geçerli sayılan işlemler geri alınamadığı için çözüm hukuki ve operasyonel
  yollara kaldı. Bu yüzden onay süreçlerinin (çoklu imza, limit, bekleme) işlemden **önce** işletilmesi gerekir.
""",
    sure_hedef_dk=45,
)
