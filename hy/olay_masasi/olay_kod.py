"""Olay Masası — Güvenli Kod Denetimi: Açığı Satırında Bul.

TAMAMEN SAVUNMACI: oyuncu, yayına çıkmadan önce kaynak kodu okuyan güvenlik denetçisidir (code review).
Kod kurgusaldır, hiçbir şey çalıştırılmaz ve hiçbir istismar (exploit) yazılmaz: yalnızca OKUNUR.
`kod/` klasöründe 3-4 küçük kaynak dosya (Python ve PHP) gelir. Bunların YALNIZ BİRİNDE tek bir açık
vardır: komut enjeksiyonu, SQL birleştirme, sabit-kodlu sır, yol gezinme (path traversal) ya da güvensiz
deserileştirme. Diğer işlevler temizdir; hatta aynı türün GÜVENLİ karşılığı başka dosyalarda yem olarak durur.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem `yaz`, aynı
`_akis(alt)` ile (aynı `random.Random(alt)`) dosyaları yeniden üretir. (`_tohum` motor tarafından ezildiği
için ayrı bir anahtar kullanılır.) Açıklı satırın numarası dosya içeriğiyle birlikte tohumla değişir; `coz`
onu sabit varsaymaz, `grep -n` ile bulur.
"""
from __future__ import annotations

import random
from pathlib import Path

from hy.motor.kontrol import Baglam, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

TURLER = ["komut", "sql", "sir", "yol", "deser"]

SENARYOLAR = [
    {"musteri": "Yıldız Kargo", "sektor": "kargo ve lojistik", "slug": "yildizkargo", "tablo": "gonderiler",
     "kisi": "Yazılım ekibi lideri Murat Bey",
     "hikaye": "Yeni müşteri takip portalı bu hafta yayına çıkacak. İç denetim, canlıya almadan önce "
               "kaynak kodun güvenlik gözüyle okunmasını şart koştu."},
    {"musteri": "Liman Sigorta", "sektor": "sigorta", "slug": "limansigorta", "tablo": "policeler",
     "kisi": "Bilgi güvenliği uzmanı Pelin Hanım",
     "hikaye": "Acentelerin kullanacağı poliçe sorgulama servisi hazır. Denetim ekibi, sızma testinden önce "
               "kodu bir de elle taramak istiyor."},
    {"musteri": "Çınar Eğitim", "sektor": "online eğitim platformu", "slug": "cinaregitim", "tablo": "kayitlar",
     "kisi": "Teknik direktör Orhan Bey",
     "hikaye": "Öğrenci portalının arka yüzünden birkaç dosya bir dış geliştiriciden geldi. Teknik direktör, "
               "bunları birleştirmeden önce güvenlik okuması istiyor."},
]

PY_AD = ["handler.py", "siparis.py", "rapor.py", "yonetim.py", "islem.py"]
PHP_AD = ["auth.php", "giris.php", "dosya.php", "api.php"]

# (python adı, php adı) — türlere göre işlev adı havuzları (türler arası ayrık)
FONK = {
    "komut": ["sunucu_sinama", "ag_kontrol", "erisim_testi"],
    "sql": ["kayit_getir", "gonderi_ara", "liste_cek"],
    "sir": ["dis_servis_cagri", "bildirim_gonder", "entegrasyon_baglan"],
    "yol": ["dosya_ver", "belge_indir", "ek_getir"],
    "deser": ["oturum_oku", "tercih_yukle", "sepet_oku"],
}
YORUM = {
    "komut": "ağdaki cihazın ulaşılabilirliğini ölçer",
    "sql": "kayıtları sahibine göre listeler",
    "sir": "dış servise yetkili istek yollar",
    "yol": "kullanıcının istediği belgeyi gönderir",
    "deser": "tarayıcıdan gelen çerezi okur",
}
SIR_AD = ["api_anahtari", "db_parolasi", "servis_token", "imza_secret"]

TUR_BILGI = {
    "komut": ("Komut enjeksiyonu", "kullanıcı girdisi bir işletim sistemi komutuna karışıyor",
              "system( / shell_exec( gibi çağrılara bakın"),
    "sql": ("SQL birleştirme", "girdi, sorgu metnine yapıştırılarak veritabanına gidiyor",
            "execute( / query( satırında + , {} ya da . $ ile birleştirmeye bakın"),
    "sir": ("Sabit-kodlu sır", "parola ya da anahtar doğrudan kodun içine yazılmış",
            "parola/anahtar/token adlı değişkene tırnaklı bir değer atanmasına bakın"),
    "yol": ("Yol gezinme (path traversal)", "dosya adı doğrulanmadan klasör yoluna ekleniyor",
            "open(os.path.join( / readfile( içinde ham girdiye bakın"),
    "deser": ("Güvensiz deserileştirme", "güvenilmeyen veri doğrudan nesneye çevriliyor",
              "pickle.loads / yaml.load / unserialize çağrılarına bakın"),
}

DUZELTME = {
    "komut": [
        ("Kabuğu hiç kullanma: komutu argüman listesiyle ya da hazır bir işlevle çağır ve girdiyi izin verilen "
         "desene göre doğrula",
         "Doğru. Kabuk devreden çıkınca girdideki `;` ya da `&` gibi karakterler komut ayırıcı olmaktan çıkar; "
         "doğrulama da beklenmeyen girdiyi baştan eler."),
        ("Girdideki `;` ve `&` karakterlerini silen bir filtre ekle, kabuk çağrısını olduğu gibi bırak",
         "Yetersiz. Kara liste filtreleri hep bir karakter kaçırır; asıl sorun girdinin kabuğa gitmesi."),
        ("Çağrıyı try/except içine al ki hata olursa kullanıcı görmesin",
         "Yanlış. Hata yakalamak girdinin komuta karışmasını engellemez; yalnızca hatayı gizler."),
        ("Komutun başına `sudo` ekle ki her zaman yetkiyle çalışsın",
         "Tam tersi: yetkiyi artırmak açığın etkisini büyütür."),
    ],
    "sql": [
        ("Parametreli (hazır) sorgu kullan: değer `?` yer tutucusuyla ayrı gönderilsin, sorgu metnine eklenmesin",
         "Doğru. Veritabanı, girdiyi kod değil yalnızca veri olarak ele alır; metin birleştirme ortadan kalkar."),
        ("Girdideki tırnak işaretlerini kendin `replace` ile değiştir ve birleştirmeye devam et",
         "Yetersiz. Elle kaçırma hataya açıktır; hazır sorgu bu işi güvenilir şekilde yapar."),
        ("Sorguyu try/except içine al ve hata mesajını gizle",
         "Yanlış. Hata gizlemek sorgunun değiştirilebilmesini engellemez."),
        ("Tablo adını büyük harfle yaz",
         "Alakasız: harf büyüklüğü sorgunun güvenliğini değiştirmez."),
    ],
    "sir": [
        ("Sırrı koddan çıkarıp ortam değişkenine ya da gizli kasaya taşı; koda girmiş değeri geçersiz sayıp "
         "yenisini üret (rotate)",
         "Doğru. Kodda bir kez görünen sır sızmış sayılır; yalnız taşımak yetmez, eskisini iptal edip yenilemek gerekir."),
        ("Sırrı base64 ile kodlayıp kodun içinde tut",
         "Yanlış. Base64 şifreleme değildir; herkes tek komutla geri çevirir."),
        ("Değişkenin adını daha az belli bir adla değiştir",
         "Yanlış. Değer hâlâ kodun içinde; adı gizlemek onu saklamaz."),
        ("Kodu özel (private) depoda tut, başka bir şey yapma",
         "Yetersiz. Depoya erişen herkes sırrı görür; depo sızarsa sır da gider."),
    ],
    "yol": [
        ("Dosya adını `basename` ile arındır, tam yolu `realpath` ile çöz ve sonucun kök klasörün altında "
         "kaldığını doğrula",
         "Doğru. Üst klasöre çıkma denemeleri baştan temizlenir; çözülen yol kökün dışına düşüyorsa istek reddedilir."),
        ("Girdide `..` geçiyorsa bir kez silmek yeter",
         "Yetersiz. Tek seferlik silme atlatılabilir; yolu çözüp kök kontrolü yapmak gerekir."),
        ("Kök klasörün adını daha uzun ve tahmin edilmesi zor yap",
         "Yanlış. Yolun gizli olması, girdinin doğrulanmaması sorununu çözmez."),
        ("Dosya uzantısını büyük harfe çevir",
         "Alakasız: uzantının harf büyüklüğü dosyanın klasör dışına çıkmasını engellemez."),
    ],
    "deser": [
        ("Güvenilmeyen veriyi yalnızca veri taşıyan bir biçimle oku (JSON ya da güvenli yükleyici); gerekirse imzala",
         "Doğru. JSON gibi biçimler kod çalıştırmaz, yalnızca veri taşır; imza da verinin değişmediğini kanıtlar."),
        ("Veriyi bir kez daha base64 ile kodla",
         "Yanlış. Kodlama güven sağlamaz; saldırgan aynı kodlamayı kendisi yapar."),
        ("Başka bir nesne serileştirme kütüphanesine geç (örn. marshal)",
         "Yanlış. Aynı sınıftan bir kütüphane aynı riski taşır; sorun biçimin kendisi."),
        ("Çağrıyı try/except içine al",
         "Yetersiz. Hata yakalamak, verinin işlenirken kod çalıştırmasını engellemez."),
    ],
}

_DOGRU_TUR = {t: i for i, t in enumerate(TURLER)}


class TureGoreSecmeli(Secmeli):
    """Doğru şık senaryodaki açık türüne göre değişen çoktan seçmeli.

    `mod="tur"`: şıklar 5 açık türü; doğru olan senaryonun türü.
    `mod="duzeltme"`: şıklar senaryonun türüne ait 4 düzeltme; ilki doğru.
    """

    def __init__(self, mod: str):
        super().__init__([("-", "-")], dogru=0, karistir=True)
        self.mod = mod

    def _sec(self, b: Baglam) -> tuple:
        tur = b.senaryo["cevaplar"]["tur"]
        if self.mod == "duzeltme":
            return DUZELTME[tur], 0
        siklar = []
        for t in TURLER:
            ad, kalip, desen = TUR_BILGI[t]
            if t == tur:
                siklar.append((f"{ad}: {kalip}", f"Doğru. {ad}: {kalip}."))
            else:
                siklar.append((f"{ad}: {kalip}",
                               f"Hayır. {ad} kalıbı şöyle aranır: {desen}. Ama açıklı satırdaki kod bu kalıba "
                               "uymuyor; satırı yeniden oku."))
        return siklar, TURLER.index(tur)

    def _sira(self, b: Baglam) -> list:
        sira = list(range(len(self._sec(b)[0])))
        random.Random(f"{b.senaryo.get('_tohum', '')}:{b.gorev_no}").shuffle(sira)
        return sira

    def ek_metin(self, b: Baglam) -> str:
        siklar = self._sec(b)[0]
        return "\n".join(f"   {'abcdefgh'[i]}) {siklar[j][0]}" for i, j in enumerate(self._sira(b)))

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        siklar, dogru = self._sec(b)
        sira = self._sira(b)
        g = str(girdi).strip().strip("\"'`").strip().casefold()[:1]
        harfler = "abcdefgh"[: len(sira)]
        if not g or g not in harfler:
            return Sonuc(False, f"Şıklardan birini yaz: {', '.join(harfler)}.")
        secilen = sira[harfler.index(g)]
        return Sonuc(secilen == dogru, siklar[secilen][1])

    def cevabi_goster(self, b: Baglam) -> str:
        siklar, dogru = self._sec(b)
        return f"{'abcdefgh'[self._sira(b).index(dogru)]}) {siklar[dogru][0]}"


# ------------------------------------------------------------------ blok üreticileri
# Her üretici: dict(lines, sink (blok içi 0 tabanlı satır sırası), sinkad, imports, ust)

def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _py_komut(rng, sen, t, fn):
    host = rng.choice(["host", "sunucu", "hedef"])
    komut = rng.choice(["ping -c 1", "nslookup", "traceroute -m 5"]).split()
    ust = [f"def {fn}({host}):", f"    # {YORUM['komut']}"]
    if t:
        # komut metnine girdi eklenir (açık deseni)
        k = " ".join(komut)
        return {"lines": ust + [f'    os.system("{k} " + {host})', "    return True"], "sink": 2,
                "sinkad": "os.system", "imports": {"import os"}, "ust": []}
    liste = "[" + ", ".join(f'"{x}"' for x in komut) + f", {host}]"
    return {"lines": ust + [f'    if not re.fullmatch(r"[A-Za-z0-9.-]{{1,60}}", {host}):',
                            '        raise ValueError("gecersiz sunucu adi")',
                            f"    sonuc = subprocess.run({liste}, capture_output=True)",
                            "    return sonuc.returncode == 0"],
            "sink": None, "sinkad": "", "imports": {"import re", "import subprocess"}, "ust": []}


def _py_sql(rng, sen, t, fn):
    col = rng.choice(["sahip", "musteri_no", "hesap"])
    p = rng.choice(["kul", "musteri", "hesap_no"])
    tablo = sen["tablo"]
    ust = [f"def {fn}({p}):", f"    # {YORUM['sql']}", "    cur = db.cursor()"]
    if t:
        if rng.random() < 0.5:
            q = f'    cur.execute("SELECT * FROM {tablo} WHERE {col} = \'" + {p} + "\'")'
        else:
            q = f'    cur.execute(f"SELECT * FROM {tablo} WHERE {col} = \'{{{p}}}\'")'
        sink = 3
    else:
        q = f'    cur.execute("SELECT * FROM {tablo} WHERE {col} = ?", ({p},))'
        sink = None
    return {"lines": ust + [q, "    return cur.fetchall()"], "sink": sink, "sinkad": "execute",
            "imports": {"import sqlite3"}, "ust": [f'db = sqlite3.connect("{sen["slug"]}.db")']}


def _py_sir(rng, sen, t, fn):
    ad = rng.choice(SIR_AD)
    ust = [f"def {fn}(yol):", f"    # {YORUM['sir']}"]
    if t:
        atama, imp = f'    {ad} = "anh_{_hex(rng, 12)}"', {"import requests"}
        sink = 2
    else:
        atama, imp = f'    {ad} = os.environ.get("{ad.upper()}")', {"import os", "import requests"}
        sink = None
    return {"lines": ust + [atama, f'    basliklar = {{"Authorization": "Bearer " + {ad}}}',
                            "    return requests.get(DIS_SERVIS + yol, headers=basliklar)"],
            "sink": sink, "sinkad": ad, "imports": imp,
            "ust": [f'DIS_SERVIS = "https://api.{sen["slug"]}.example"']}


def _py_yol(rng, sen, t, fn):
    p = rng.choice(["ad", "dosya_adi"])
    ust = [f"def {fn}({p}):", f"    # {YORUM['yol']}"]
    if t:
        return {"lines": ust + [f'    with open(os.path.join(KOK_DIZIN, {p}), "rb") as f:', "        return f.read()"],
                "sink": 2, "sinkad": "open", "imports": {"import os"},
                "ust": [f'KOK_DIZIN = "/srv/{sen["slug"]}/dosyalar"']}
    return {"lines": ust + [f"    yol = os.path.realpath(os.path.join(KOK_DIZIN, os.path.basename({p})))",
                            "    if not yol.startswith(KOK_DIZIN + os.sep):",
                            '        raise PermissionError("izin yok")',
                            '    with open(yol, "rb") as f:', "        return f.read()"],
            "sink": None, "sinkad": "", "imports": {"import os"},
            "ust": [f'KOK_DIZIN = "/srv/{sen["slug"]}/dosyalar"']}


def _py_deser(rng, sen, t, fn):
    p = rng.choice(["cerez", "veri"])
    yaml_mi = rng.random() < 0.5
    ust = [f"def {fn}({p}):", f"    # {YORUM['deser']}"]
    if t:
        if yaml_mi:
            return {"lines": ust + [f"    return yaml.load(base64.b64decode({p}), Loader=yaml.Loader)"],
                    "sink": 2, "sinkad": "yaml.load", "imports": {"import base64", "import yaml"}, "ust": []}
        return {"lines": ust + [f"    return pickle.loads(base64.b64decode({p}))"], "sink": 2,
                "sinkad": "pickle.loads", "imports": {"import base64", "import pickle"}, "ust": []}
    if yaml_mi:
        return {"lines": ust + [f"    return yaml.safe_load(base64.b64decode({p}))"], "sink": None, "sinkad": "",
                "imports": {"import base64", "import yaml"}, "ust": []}
    return {"lines": ust + [f"    return json.loads(base64.b64decode({p}))"], "sink": None, "sinkad": "",
            "imports": {"import base64", "import json"}, "ust": []}


def _php_komut(rng, sen, t, fn):
    k = rng.choice(["nslookup", "ping -c 1", "traceroute -m 5"])
    ust = [f"function {fn}($host) {{", f"    // {YORUM['komut']}"]
    if t:
        return {"lines": ust + [f'    $cikti = shell_exec("{k} " . $host);', "    return $cikti;", "}"],
                "sink": 2, "sinkad": "shell_exec", "imports": set(), "ust": []}
    return {"lines": ust + ["    if (!filter_var($host, FILTER_VALIDATE_IP)) {", "        return false;", "    }",
                            "    return gethostbyaddr($host);", "}"],
            "sink": None, "sinkad": "", "imports": set(), "ust": []}


def _php_sql(rng, sen, t, fn):
    col = rng.choice(["sahip", "musteri_no", "hesap"])
    p = rng.choice(["kul", "musteri", "hesap_no"])
    tablo = sen["tablo"]
    ust = [f"function {fn}($db, ${p}) {{", f"    // {YORUM['sql']}"]
    if t:
        return {"lines": ust + [f'    $sonuc = $db->query("SELECT * FROM {tablo} WHERE {col} = \'" . ${p} . "\'");',
                                "    return $sonuc->fetchAll();", "}"],
                "sink": 2, "sinkad": "query", "imports": set(), "ust": []}
    return {"lines": ust + [f'    $st = $db->prepare("SELECT * FROM {tablo} WHERE {col} = ?");',
                            f"    $st->execute([${p}]);", "    return $st->fetchAll();", "}"],
            "sink": None, "sinkad": "", "imports": set(), "ust": []}


def _php_sir(rng, sen, t, fn):
    ad = rng.choice(SIR_AD)
    ust = [f"function {fn}($yol) {{", f"    // {YORUM['sir']}"]
    atama = f"    ${ad} = 'anh_{_hex(rng, 12)}';" if t else f"    ${ad} = getenv('{ad.upper()}');"
    return {"lines": ust + [atama, f"    return http_al(DIS_SERVIS . $yol, ${ad});", "}"],
            "sink": 2 if t else None, "sinkad": ad if t else "", "imports": set(),
            "ust": [f"const DIS_SERVIS = 'https://api.{sen['slug']}.example';"]}


def _php_yol(rng, sen, t, fn):
    ust = [f"function {fn}() {{", f"    // {YORUM['yol']}"]
    kok = [f"const KOK_DIZIN = '/srv/{sen['slug']}/dosyalar';"]
    if t:
        return {"lines": ust + ["    readfile(KOK_DIZIN . '/' . $_GET['dosya']);", "}"],
                "sink": 2, "sinkad": "readfile", "imports": set(), "ust": kok}
    return {"lines": ust + ["    $ad = basename($_GET['dosya']);", "    $yol = realpath(KOK_DIZIN . '/' . $ad);",
                            "    if ($yol === false || strpos($yol, KOK_DIZIN) !== 0) {",
                            "        http_response_code(403);", "        return;", "    }",
                            "    readfile($yol);", "}"],
            "sink": None, "sinkad": "", "imports": set(), "ust": kok}


def _php_deser(rng, sen, t, fn):
    c = rng.choice(["oturum", "tercih", "sepet"])
    ust = [f"function {fn}() {{", f"    // {YORUM['deser']}"]
    if t:
        return {"lines": ust + [f"    return unserialize(base64_decode($_COOKIE['{c}']));", "}"],
                "sink": 2, "sinkad": "unserialize", "imports": set(), "ust": []}
    return {"lines": ust + [f"    return json_decode(base64_decode($_COOKIE['{c}']), true);", "}"],
            "sink": None, "sinkad": "", "imports": set(), "ust": []}


BLOK = {
    "py": {"komut": _py_komut, "sql": _py_sql, "sir": _py_sir, "yol": _py_yol, "deser": _py_deser},
    "php": {"komut": _php_komut, "sql": _php_sql, "sir": _php_sir, "yol": _php_yol, "deser": _php_deser},
}


def _akis(alt: int) -> dict:
    """Alt-tohumdan tüm vakayı (dosyalar, açık yeri) deterministik üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    tur = rng.choice(TURLER)
    adlar = [(f"kod/{a}", "py") for a in rng.sample(PY_AD, 2)]
    adlar += [(f"kod/{a}", "php") for a in rng.sample(PHP_AD, rng.choice([1, 2]))]
    rng.shuffle(adlar)
    iv = rng.randrange(len(adlar))
    dosyalar, acik = {}, {}
    for i, (ad, dil) in enumerate(adlar):
        k = rng.choice([2, 3])
        tipler = rng.sample(TURLER, k)
        if i == iv and tur not in tipler:
            tipler[rng.randrange(k)] = tur
        bloklar = []
        for t in tipler:
            fn = rng.choice(FONK[t])
            b = BLOK[dil][t](rng, sen, i == iv and t == tur, fn)
            b["fonk"] = fn
            bloklar.append(b)
        imports = sorted({x for b in bloklar for x in b["imports"]})
        ust = []
        for b in bloklar:
            for x in b["ust"]:
                if x not in ust:
                    ust.append(x)
        yorum = "#" if dil == "py" else "//"
        L = []
        if dil == "php":
            L.append("<?php")
        L.append(f"{yorum} {ad} — {sen['musteri']} ({sen['sektor']}), kurgusal örnek")
        for _ in range(rng.randint(0, 3)):
            L.append(f"{yorum} {rng.choice(['sürüm', 'taslak', 'not', 'gözden geçirme'])}: "
                     f"{rng.choice(['v0.3', 'v0.7', 'v1.2', 'v1.4'])}")
        L += imports + ([""] if imports else [])
        L += ust + [""]
        for b in bloklar:
            L += [""] if (L and L[-1] != "") else []
            if b["sink"] is not None:
                acik = {"dosya": ad, "satir": len(L) + b["sink"] + 1, "fonk": b["fonk"], "sink": b["sinkad"]}
            L += b["lines"]
            L.append("")
        # fazla boş satırları tek tutan sade biçim
        dosyalar[ad] = "\n".join(L).rstrip("\n") + "\n"
    return {"sen": sen, "tur": tur, "dosyalar": dosyalar, "acik": acik, "adlar": [a for a, _ in adlar]}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen, a = v["sen"], v["acik"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — yayın öncesi kod denetimi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "dosya_listesi": ", ".join(f"`{d}`" for d in sorted(v["adlar"]))},
        "cevaplar": {
            "dosya": a["dosya"],
            "tur": v["tur"],
            "satir": a["satir"],
            "sink": a["sink"],
            "islev": a["fonk"],
            "duzeltme": v["tur"],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    for ad, metin in v["dosyalar"].items():
        u.yaz(lab / ad, metin)
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} — kod inceleme klasörü (kurgusal kod)\n\n"
          "kod/ altındaki dosyalar:\n" + "".join(f"  {a}\n" for a in sorted(v["adlar"])) + "\n"
          "Bu dosyalardan YALNIZ BİRİNDE tek bir güvenlik açığı var; diğer işlevler temiz.\n"
          "Hiçbir şey çalıştırılmayacak: yalnızca okunacak (cat -n, grep -n, awk).\n")


# ------------------------------------------------------------------ cevap yardımcıları

def _satir_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    v = _akis(b.senaryo["_alt"])
    satirlar = v["dosyalar"][v["acik"]["dosya"]].splitlines()
    if 1 <= n <= len(satirlar) and satirlar[n - 1].startswith(("def ", "function ")):
        return "Bu, işlevin başlık satırı. Açık, tehlikeli verinin kullanıldığı satırda; işlevin gövdesine bak."
    if abs(n - beklenen) == 1:
        return "Bir satır kaymış. `grep -n` numarayı dosyadaki gerçek satır numarasıyla verir; `cat -n` de aynısını gösterir."
    return None


def _sink_hata(g, beklenen, b):
    islev = b.senaryo["cevaplar"]["islev"].casefold()
    if g.rstrip("()") == islev:
        return "Bu, işlevin adı. Sink, işlevin içindeki tehlikeli çağrı (ya da sır için değişken adı)."
    return None


# kalıp -> grep komutu (kod/ altında ara). Tek tırnak içinde `\$` literal dolardır.
ARA = {
    "komut": r"grep -nE 'os\.system\(|shell_exec\(|passthru\(|shell=True' kod/*",
    "sql": r"grep -nE '(execute|query)\(.*(\+|\{|\. ?\$)' kod/*",
    "sir": r"""grep -niE "(parola|password|secret|anahtar|token|sifre)[A-Za-z_]* *= *[\"'][^\"']+[\"']" kod/*""",
    "yol": r"grep -nE 'open\(os\.path\.join|readfile\(.*\.' kod/*",
    "deser": r"grep -nE 'pickle\.loads?\(|yaml\.load\(|unserialize\(' kod/*",
}
SINK_RE = {
    "komut": r"os\.system|shell_exec|passthru",
    "sql": r"execute|query",
    "sir": r"[A-Za-z_]*(parola|password|secret|anahtar|token|sifre)[A-Za-z_]*",
    "yol": r"open|readfile",
    "deser": r"pickle\.loads|yaml\.load|unserialize",
}


def coz(lab: Path, s: dict) -> dict:
    tur, bulgu = "", ""
    for t in TURLER:                                  # her kalıbı gerçekten grep'le ara
        cikti = sh(ARA[t], lab)
        if cikti:
            tur, bulgu = t, cikti.splitlines()[0]
            break
    dosya = bulgu.split(":")[0]
    satir = bulgu.split(":")[1] if bulgu else ""
    sink = sh(f"sed -n '{satir}p' {dosya} | grep -oiE '{SINK_RE[tur]}' | head -1", lab) if tur else ""
    islev = sh(f"awk -v n={satir} '/^(def |function )/{{f=$0}} NR==n{{print f; exit}}' {dosya} "
               "| sed -E 's/^(def|function) +([A-Za-z_0-9]+).*/\\2/'", lab)
    cozum = sec_doldur({1: dosya, 2: "", 3: satir, 4: sink, 5: islev, 6: ""}, SEVIYE.gorevler, lab, s)
    # tür şıkkının harfi: grep'in bulduğu türün şıktaki yeri (cevaplardan kopyalama yok)
    tur_kontrol = SEVIYE.gorevler[1].kontrol
    sira = tur_kontrol._sira(Baglam(s, lab, 2))
    cozum[2] = "abcdefgh"[sira.index(TURLER.index(tur))]
    return cozum


GOREVLER = [
    Gorev("`kod/` klasöründeki dosyalardan (<<dosya_listesi>>) **yalnız birinde** tek bir güvenlik açığı var; "
          "diğer işlevler temiz. Açığı taşıyan dosya hangisi? (Yalnızca OKU; çalıştırma.)",
          Metin("dosya", sadece_ad=True, bicim="dosya adı, örn. kod/ornek.py"),
          ("Hepsini baştan sona okumak gerekmez: tehlikeli işlemleri yapan satırları `grep -n` ile ara "
           "(komut çalıştıran, sorgu yollayan, dosya açan, veriyi nesneye çeviren çağrılar; parola/anahtar atamaları).",
           "`grep -nE 'system\\(|shell_exec\\(|execute\\(|query\\(|open\\(|readfile\\(|loads?\\(|unserialize\\(' kod/*` "
           "ve ayrıca `grep -niE 'parola|anahtar|token|secret' kod/*`. Çok aday çıkacak; her adayda şunu sor: "
           "dışarıdan gelen girdi bu çağrıya doğrudan, doğrulanmadan ulaşıyor mu?",
           "Güvenli olanlar ayırt edilir: parametreli sorguda `?`, komutta argüman listesi, sırda `environ`/`getenv`, "
           "dosyada `basename`/`realpath`, veride `json`. Girdi metne `+` ya da `.` ile yapıştırılıyorsa tehlikelidir. "
           "Bu işaretlerden birinin EKSİK olduğu dosya aranan dosyadır."),
          puan=15, baslik="Açıklı dosya"),
    Gorev("Bu dosyadaki açık hangi **türde**?",
          TureGoreSecmeli("tur"),
          ("Açık satırın ne yaptığına bak: komut mu çalıştırıyor, sorgu mu yolluyor, dosya mı açıyor, "
           "veriyi nesneye mi çeviriyor, yoksa bir parola/anahtar mı tutuyor?",
           "Şu desenler tanıdıktır: `os.system`/`shell_exec` (komut); `execute`/`query` içinde `+` ya da `{}` (SQL); "
           "tırnaklı parola atamak (sır); ham girdiyle `open`/`readfile` (yol gezinme); "
           "`pickle`/`yaml.load`/`unserialize` (deserileştirme).",
           "Önceki görevde bulduğun dosyayı `cat -n` ile aç ve şüpheli satırı yukarıdaki desenlerden biriyle eşleştir."),
          puan=15, baslik="Açık türü"),
    Gorev("Açığın bulunduğu **satırın numarası** kaç? (Dosyadaki gerçek numara; işlevin başlık satırını değil, "
          "tehlikeli verinin kullanıldığı satırı say.)",
          Sayi("satir", sik_hatalar=_satir_hata),
          ("Satır numarasını `grep -n` ya da `cat -n` verir.",
           "Önceki görevlerde elde ettiğin desenle yeniden ara: `grep -n '<desen>' kod/<dosya>`; çıktının başındaki sayı "
           "iki nokta üst üsteye kadar satır numarasıdır.",
           "Aynı desen başka dosyalarda **güvenli** biçimde de görünebilir; bu yüzden aramayı yalnız açıklı dosyada yap "
           "ve eşleşen satırın girdiyi doğrulamadan kullandığından emin ol."),
          puan=15, baslik="Satır numarası"),
    Gorev("O satırdaki **tehlikeli çağrı ya da değişken** (sink: tehlikeli verinin vardığı yer) nedir? "
          "Komut/sorgu/dosya/deserileştirme için çağrının adını (örn. `adi` ya da `modul.adi`), "
          "sabit-kodlu sırda sırrı tutan **değişkenin adını** yaz.",
          Metin("sink", on_ekleri_at=("os.", "cur.", "db.", "pickle.", "yaml.", "$db->", "$"),
                son_ekleri_at=("()", "("), sik_hatalar=_sink_hata, bicim="çağrı ya da değişken adı"),
          ("Sink, kötü verinin zarar verebileceği yerdir. Açık satırda bir işlev çağrısı var; sır açığında ise "
           "tırnaklı değerin atandığı değişken.",
           "Satırı yeniden `grep -n` ile yazdır ve parantezden hemen önceki adı oku (sırda `=` işaretinin solundaki ad).",
           "Parantezden önceki kelime çağrıdır (ör. `modul.islev(`); `=` solundaki kelime değişkendir. "
           "`$` işareti ve modül öneki cevaba yazılmayabilir."),
          puan=15, baslik="Tehlikeli çağrı (sink)"),
    Gorev("Bu satır hangi **işlevin** (`def` / `function`) içinde? İşlevin adını yaz.",
          Metin("islev", on_ekleri_at=("def ", "function "), son_ekleri_at=("()", "("), bicim="işlev adı"),
          ("Satırdan yukarı doğru çık; ilk karşılaştığın `def` ya da `function` satırı işlevin başlığıdır.",
           "`awk -v n=<satır> '/^(def |function )/{f=$0} NR==n{print f; exit}' kod/<dosya>` o satırdan önceki son "
           "başlığı yazar.",
           "Çıkan satırda `def` ya da `function` kelimesinden sonraki ad, parantezden önceye kadar, aranan işlevdir."),
          puan=10, baslik="Açıklı işlev"),
    Gorev("Bu açık için **en doğru düzeltme** hangisi?",
          TureGoreSecmeli("duzeltme"),
          ("Düzeltme, açığın kök nedenini kapatmalı; belirtiyi gizlemek ya da şekil değiştirmek yetmez.",
           "Kök neden: güvenilmeyen girdi, doğrulanmadan tehlikeli bir yere ulaşıyor. İyi düzeltme bu yolu kapatır.",
           "Girdiyi kod/komut/sorgudan **ayır**, güvenli bir arayüz (parametre, argüman listesi, ortam değişkeni, "
           "yol doğrulama, yalnız veri biçimi) kullan."),
          puan=20, baslik="Doğru düzeltme"),
]

SEVIYE = Seviye(
    kimlik="olay_kod",
    cilt=5,
    bolum=121,
    baslik="Güvenli Kod Denetimi: Açığı Satırında Bul",
    brifing="""
Selin Aksoy bir klasörü masaya bırakıyor: "**<<musteri>>** (<<sektor>>) bir kod incelemesi istiyor.
<<hikaye>> <<kisi>> bize `kod/` klasörünü yolladı: <<dosya_listesi>>."

"Bunlar kurgusal kaynak dosyalar; **çalıştırmayacaksın**, yalnızca okuyacaksın. Bir güvenlik denetçisi gibi
(code review): önce tehlikeli işleri yapan satırları `grep -n` ile tara, sonra her adayda tek soru sor:
**dışarıdan gelen girdi buraya doğrulanmadan ulaşıyor mu?** Dosyalardan yalnız birinde gerçek bir açık var;
diğerleri temiz ve bazıları aynı işi güvenli yapıyor, bu yüzden dikkatli ol. Dosyayı, açık türünü, satırını ve
doğru düzeltmeyi bul."

"Mavi taraftayız: bul, anlat, düzelt. İstismar kodu yazmak yok."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Kaynak kod açıkları çoğu zaman tek bir satırda saklıdır, ama o satırı bulmak için binlerce satır
okumak gerekmez: tehlikeli çağrılar (komut, sorgu, dosya, deserileştirme) ve tırnaklı sırlar `grep` ile hızla
sınırlanır. Hepsinin ortak kökü aynıdır: **güvenilmeyen girdi, doğrulanmadan kod ya da komut gibi yorumlanıyor**.
Düzeltmenin ortak ilkesi de aynıdır: girdiyi koddan ayır. Komutta argüman listesi, SQL'de parametreli sorgu, dosyada
yol doğrulama, veride yalnızca veri taşıyan biçim (JSON), sırda ortam değişkeni ya da gizli kasa. Savunma tarafı için:
yayından önce kod incelemesi yap, statik analiz (SAST) ve sır tarayıcılarını derleme hattına koy, ve koda girmiş
her sırrı sızmış say, yenile.
""",
    gercek_hayat="""
- **Komut enjeksiyonu ve Log4Shell:** Aralık 2021'de Log4j kütüphanesindeki açık (CVE-2021-44228, Log4Shell),
  günlüğe yazılan metnin kod gibi işlenmesine izin verdiği için dünya çapında sistemlerde uzaktan kod çalıştırmaya
  yol açtı. Eylül 2014'te Bash'teki Shellshock (CVE-2014-6271) de girdinin komut olarak yorumlanmasından doğdu.
  Tespit: kodda kabuk/komut çağrılarını ve eski kütüphane sürümlerini tarama; önlem: girdiyi komuttan ayırmak ve güncel kalmak.
- **SQL birleştirme:** SQL enjeksiyonu on yıllardır en çok görülen web açıklarındandır ve OWASP Top 10 listesinde
  yıllardır yer alır; 2008'deki Heartland ödeme sisteminin ihlali gibi büyük kart verisi sızıntılarında rol oynadığı
  bilinir. Tespit: sorgu çağrılarında metin birleştirme araması; önlem: parametreli sorgu.
- **Sabit-kodlu sır:** 2016'da Uber'in, bir geliştiricinin herkese açık bir kod deposuna koyduğu bulut erişim
  bilgileri yüzünden verisinin ele geçirildiği, olayın 2017'de kamuoyuna açıklandığı bilinir. Tespit: depoda sır
  tarayıcıları; önlem: sırları koddan çıkarıp ortam değişkeni ya da gizli kasaya taşımak ve sızanı yenilemek.
- **Yol gezinme (path traversal):** Aralık 2019'da Citrix ADC / Gateway ürünlerindeki dizin gezinme açığı
  (CVE-2019-19781) yaygın şekilde kötüye kullanıldı. Tespit: dosya açma çağrılarında ham girdi araması; önlem:
  dosya adını arındırıp çözülen yolun kök klasörde kaldığını doğrulamak.
- **Güvensiz deserileştirme:** 2015'te Apache Commons Collections üzerindeki "gadget zinciri" araştırması,
  Java uygulama sunucularının birçok ürününde deserileştirme açığını görünür kıldı; o zamandan beri güvenilmeyen veriyi
  nesneye çevirmek ciddi bir risk sınıfı sayılır. Tespit: `pickle`, `unserialize` gibi çağrıların araması; önlem:
  yalnızca veri taşıyan biçimler ve imzalı veri.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c05b01",),
)
