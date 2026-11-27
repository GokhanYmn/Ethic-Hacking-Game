"""Cilt 3 · Bölüm 8 — Tedarik Zinciri: Zehirli Paketi Yakala.

Beceri: bir yazılım ekibinin güvenlik analisti olarak bağımlılık listesini (paket + sürüm) okumak, bilinen-paket
listesiyle `awk` ile birleştirip (join) güvensiz paketleri bulmak, ad benzeten (typosquat) paketi "bir harf
farkı"ndan yakalamak, sürümü sabitlenmemiş (pinlenmemiş) bağımlılıkları saymak, CI kurulum günlüğünde
`postinstall` (kurulum sonrası otomatik çalışan betik) izini sürüp bir paketin anahtarları dışarı sızdırdığı
host'u çıkarmak ve doğru müdahaleyi seçmek (paketi kaldır + sırları döndür + sürümleri sabitle + denetle).

TAMAMEN SAVUNMACI/ADLİ: Zehirli paket nasıl yazılır/yayınlanır anlatılmaz; sadece iz sürülür. Şirketler, paket
adları (gerçek paketlere benzeyen taklitler dahil) ve sızdırma host'ları kurgusaldır (`.lab` alanı, TEST-NET
adresleri); her şey dosya tabanlı sahte veridir.

Vakalar: dört kurgusal ekip (e-ticaret/npm, fintech/pip, hastane/pip, lojistik/npm).
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

NPM = ["express", "react", "react-dom", "axios", "lodash", "moment", "dayjs", "chalk", "commander", "debug",
       "uuid", "dotenv", "cors", "body-parser", "jsonwebtoken", "mongoose", "webpack", "eslint", "prettier",
       "typescript", "jest", "vue", "nodemailer", "helmet", "morgan", "redis", "bcrypt", "multer", "yargs",
       "husky", "esbuild", "rimraf"]
PIP = ["requests", "numpy", "pandas", "flask", "django", "sqlalchemy", "pydantic", "boto3", "urllib3",
       "certifi", "pyyaml", "jinja2", "click", "pytest", "cryptography", "paramiko", "celery", "redis",
       "gunicorn", "beautifulsoup4", "pillow", "openpyxl", "httpx", "setuptools", "psycopg2-binary"]
KOTU = ["log-tail-pro", "env-sync-helper", "color-utils-ng", "cache-boost-lite", "fast-pdf-helper", "ui-colorz-kit"]
SIZDIRMA_HOST = ["telemetri-cdn.lab", "paket-metrik.lab", "kurulum-stat.lab", "analitik-edge.lab"]

VAKALAR = [
    {"kod": "pazarix", "eko": "npm", "taklit": "lodahs", "gercek": "lodash", "ci": "build-web",
     "sirlar": ["NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "DEPLOY_SSH_KEY"],
     "olay": "Pazarix'in kampanya sitesi derleme hattında (CI) yeni bir bağımlılık eklendikten sonra deploy anahtarlarının "
             "başka bir ağdan kullanıldığına dair bir uyarı geldi. Tuncay Bey, bağımlılıklardan şüpheleniyor."},
    {"kod": "paramix", "eko": "pip", "taklit": "reqeusts", "gercek": "requests", "ci": "build-api",
     "sirlar": ["PYPI_TOKEN", "DB_PASSWORD", "PAYMENT_API_KEY"],
     "olay": "Paramix'in ödeme API'sinin CI hattında bir sürüm yayını sonrası üretim veritabanı parolasına yabancı bir "
             "adresten erişim denemesi görüldü. Ece Hanım, bağımlılık zincirinin kontrol edilmesini istiyor."},
    {"kod": "medora", "eko": "pip", "taklit": "crpytography", "gercek": "cryptography", "ci": "build-portal",
     "sirlar": ["PYPI_TOKEN", "HL7_GATEWAY_KEY", "BACKUP_BUCKET_SECRET"],
     "olay": "Medora Sağlık'ın hasta portalı için yeni kurulan CI hattında yedek deposunun anahtarı beklenmedik bir "
             "yerden kullanıldı. Dr. Aslı Hanım, kurulum günlüğü ve bağımlılık listesiyle birlikte analiz istiyor."},
    {"kod": "kuzgun", "eko": "npm", "taklit": "axois", "gercek": "axios", "ci": "build-wms",
     "sirlar": ["NPM_TOKEN", "WMS_API_SECRET", "REGISTRY_PUSH_KEY"],
     "olay": "Kuzgun Lojistik'in depo yönetim arayüzünün CI hattından sonra, ekipten biri paket yöneticisi anahtarının "
             "başka bir ülkeden kullanıldığını fark etti. Serdar Bey, kurulumda bir şey olup olmadığını soruyor."},
]

ISARETLEYICI = ["^", "~", ">=", "*", "latest"]


def _surum(rng) -> str:
    return f"{rng.randint(1, 9)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"


def _ters(ad: str, rng) -> str:
    """Bir harf farkıyla (iki bitişik harfin yer değiştirmesi) ad benzeten bir isim türetir."""
    idx = [i for i in range(len(ad) - 1) if ad[i].isalnum() and ad[i + 1].isalnum() and ad[i] != ad[i + 1]]
    i = rng.choice(idx)
    return ad[:i] + ad[i + 1] + ad[i] + ad[i + 2:]


def _belirt(rng, ver: str) -> str:
    """Sabitlenmemiş sürüm belirteci üretir."""
    t = rng.choice(ISARETLEYICI)
    if t in ("*", "latest"):
        return t
    if t == ">=":
        return ">=" + ".".join(ver.split(".")[:2])
    return t + ver


def veri_uret(rng: random.Random, v: dict) -> dict:
    """Bir vakanın bütün dosyalarını üretir (aynı rng -> aynı veri)."""
    havuz = NPM if v["eko"] == "npm" else PIP
    taklit, gercek = v["taklit"], v["gercek"]
    aday = [p for p in havuz if p != gercek]
    proje = sorted(rng.sample(aday, rng.randint(18, 22)))
    kotu = rng.sample(KOTU, rng.randint(1, 2))
    kotu_disi = [k for k in KOTU if k not in kotu]
    bilinmeyen = rng.sample(proje, rng.randint(1, 2))          # listede hiç olmayan (değerlendirilmemiş) paketler
    fazla = [p for p in havuz if p not in proje and p != gercek]
    rng.shuffle(fazla)
    fazla = fazla[:rng.randint(5, 7)]

    # --- bagimliliklar: ad -> (belirtilen sürüm, çözümlenen sürüm)
    surumler: dict = {}
    pinsiz_say = rng.randint(3, 5)
    pinsiz_aday = rng.sample(proje, pinsiz_say)
    for p in proje + kotu + [taklit]:
        cozulen = _surum(rng)
        if p == taklit:
            surumler[p] = ("latest", cozulen)
        elif p in pinsiz_aday or (p in kotu and rng.random() < 0.5):
            surumler[p] = (_belirt(rng, cozulen), cozulen)
        else:
            surumler[p] = (cozulen, cozulen)
    adlar = sorted(surumler)
    pinsiz = sum(1 for p in adlar if not _pinli(surumler[p][0]))

    # --- bilinen_paketler.csv
    satir = [(p, "guvenli") for p in proje if p not in bilinmeyen] + [(gercek, "guvenli")] + \
            [(p, "guvenli") for p in fazla] + [(taklit, "typosquat")] + [(k, "kotu") for k in kotu]
    disi_typo: list = []
    for p in rng.sample(fazla, 2):
        t = _ters(p, rng)
        if t not in surumler and t not in havuz and t not in disi_typo:
            disi_typo.append(t)
    satir += [(t, "typosquat") for t in disi_typo]
    satir += [(k, "kotu") for k in kotu_disi[:rng.randint(1, 2)]]
    rng.shuffle(satir)

    # --- sızdırma ucu
    if rng.random() < 0.5:
        host = rng.choice(SIZDIRMA_HOST)
        hostport, yol = host, "/collect"
    else:
        host = f"{rng.choice(u.TEST_NET)}.{rng.randint(10, 250)}"
        hostport, yol = f"{host}:8443", "/u"
    url = f"http://{hostport}{yol}"

    # --- kurulum.log
    reg = "https://registry.npmjs.org" if v["eko"] == "npm" else "https://files.pythonhosted.org"
    benign_cmd = (["husky install", "node scripts/postinstall.js", "node-gyp rebuild"] if v["eko"] == "npm"
                  else ["python build_ext.py", "python -m compileall .", "python setup_native.py"])
    benign = rng.sample([p for p in proje if p != taklit], 3)
    gun = u.gun(rng) + timedelta(hours=rng.randint(8, 16), minutes=rng.randint(0, 50))
    t = gun
    log: list = []

    def ekle(etiket: str, mesaj: str, ara=(1, 4)):
        nonlocal t
        t += timedelta(seconds=rng.randint(*ara))
        log.append(f"{t:%Y-%m-%dT%H:%M:%SZ} [{etiket}] {mesaj}")

    ekle("ci", f"job={v['ci']} runner=ci-runner-{rng.randint(1, 6)} adim=install basladi")
    ekle("ci", f"ekosistem={v['eko']} onbellek=bos kilit-dosyasi=yok")
    for p in adlar:
        belirt, cozulen = surumler[p]
        if not _pinli(belirt):
            ekle("resolve", f"{p}@{belirt} -> {cozulen}")
        ekle("install", f"{p}@{cozulen} kuruldu", (1, 6))
        if p in benign:
            ekle("postinstall", f"{p}@{cozulen} > {rng.choice(benign_cmd)}")
            if p == benign[0]:
                ekle("postinstall", f"{p}@{cozulen} GET {reg}/{p}/derleme-ikili-dosyasi (ikili dosya indirildi) -> 200")
            ekle("postinstall", f"{p}@{cozulen} exit=0")
        if p == taklit:
            ekle("postinstall", f"{p}@{cozulen} > node setup.js" if v["eko"] == "npm"
                 else f"{p}@{cozulen} > python _kurulum_sonrasi.py")
            ekle("postinstall", f"{p}@{cozulen} ortam degiskenleri okundu: {', '.join(v['sirlar'])}")
            ekle("postinstall", f"{p}@{cozulen} POST {url} ({rng.randint(180, 900)} bytes) -> 200")
            ekle("postinstall", f"{p}@{cozulen} exit=0")
    ekle("audit", f"{len(adlar)} paket tarandi, bilinen zafiyet: 0")
    ekle("ci", "adim=install tamam")
    ekle("ci", "adim=deploy basladi", (20, 90))
    return {"adlar": adlar, "surumler": surumler, "csv": satir, "log": log, "host": host, "hostport": hostport,
            "url": url, "pinsiz": pinsiz, "bilinmeyen": bilinmeyen, "kotu": kotu, "taklit": taklit,
            "gercek": gercek, "guvensiz": 1 + len(kotu), "csv_riskli": sum(1 for _, d in satir if d != "guvenli"),
            "toplam": len(adlar)}


def _pinli(belirt: str) -> bool:
    return all(p.isdigit() for p in belirt.split(".")) and belirt.count(".") == 2


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alt = rng.randint(1, 10**9)
    d = veri_uret(random.Random(alt), v)
    cozulen = d["surumler"][d["taklit"]][1]
    return {
        "vaka": f"{m['ad']} — {m['sektor']}, {v['eko']} tedarik zinciri",
        "musteri": m, "v": v, "_alt": alt,
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "olay": v["olay"],
                  "eko": v["eko"], "ci": v["ci"]},
        "cevaplar": {
            "paket": [d["taklit"], f"{d['taklit']}@{cozulen}", f"{d['taklit']}@latest"],
            "gercek": d["gercek"],
            "host": [d["host"], d["hostport"], d["url"], d["url"].removeprefix("http://")],
            "guvensiz": d["guvensiz"],
            "pinsiz": d["pinsiz"],
        },
    }


def _veri(s: dict) -> dict:
    return veri_uret(random.Random(s["_alt"]), s["v"])


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = _veri(s)
    govde = [f"{p}@{d['surumler'][p][0]}" for p in d["adlar"]]
    u.yaz(lab / "bagimliliklar.txt",
          f"# {s['musteri']['ad']} / {v['eko']} projesi: bağımlılık listesi (ad@sürüm)\n" + "\n".join(govde) + "\n")
    u.yaz(lab / "bilinen_paketler.csv",
          "paket,durum\n" + "\n".join(f"{p},{dr}" for p, dr in d["csv"]) + "\n")
    u.yaz(lab / "kurulum.log", "\n".join(d["log"]) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} ({s['musteri']['sektor']}) — tedarik zinciri incelemesi (kurgusal veri)\n\n"
          f"bagimliliklar.txt     : projenin paket listesi, her satır `ad@sürüm` ({v['eko']}). Sürüm düz sayıysa "
          "(4.17.21)\n"
          "                        SABİTLENMİŞ; `^`, `~`, `>=`, `*` ya da `latest` ise sabitlenmemiştir.\n"
          "bilinen_paketler.csv  : güvenlik ekibinin listesi: paket,durum (guvenli / typosquat / kotu).\n"
          "                        Listede hiç olmayan paket = henüz değerlendirilmemiş (güvensiz SAYILMAZ).\n"
          f"kurulum.log           : CI hattının ({v['ci']}) kurulum günlüğü.\n\n"
          "Not: Bütün paket adı taklitleri, alan adları ve adresler kurgusaldır (.lab, TEST-NET).\n")


# ---------------------------------------------------------------- sık hata geri bildirimleri

def _paket_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g in {k.casefold() for k in d["kotu"]}:
        return ("Bu paket de güvensiz listede ama kurulumda veri sızdıran o değil. Soru, **ad benzeterek** "
                "(typosquat) araya sokulan ve `postinstall` ile dışarı bağlanan paketi soruyor.")
    if g == d["gercek"]:
        return "Bu gerçek paketin kendisi (temiz). Aranan, onun adını taklit eden paket."
    return None


def _gercek_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    if g == d["taklit"].casefold():
        return "Bu taklitçinin kendisi. Soru, taklit ettiği GERÇEK paketi soruyor."
    return None


def _host_hata(g, beklenen, b):
    if "npmjs" in g or "pythonhosted" in g:
        return ("Bu paket deposunun (registry) adresi; kurulum sırasında zaten oradan indirilir. "
                "Aranan, `postinstall` satırında verinin **gönderildiği** (POST) host.")
    return None


def _guvensiz_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    n = int(g)
    if n == 1:
        return "Sadece typosquat'ı saymışsın; `kotu` durumundaki paketler de güvensizdir."
    if n == d["csv_riskli"]:
        return ("Listedeki bütün riskli satırları saymışsın; ama bazıları senin projende yok. Sadece "
                "`bagimliliklar.txt` ile **eşleşenleri** say.")
    return None


def _pinsiz_hata(g, beklenen, b):
    d = _veri(b.senaryo)
    n = int(g)
    if n == d["toplam"]:
        return "Bütün paketleri saymışsın. Sadece sürümü düz sayı OLMAYANları (`^ ~ >= * latest`) say."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    birles = "awk -F'[@,]' 'NR==FNR{d[$1]=$2;next} "
    paket = sh(birles + "($1 in d) && d[$1]==\"typosquat\"{print $1}' bilinen_paketler.csv bagimliliklar.txt", lab)
    gercek = sh(
        "python3 -c \"import csv,difflib,sys;a=list(csv.reader(open('bilinen_paketler.csv')))[1:];"
        "g=[x[0] for x in a if x[1]=='guvenli'];print(difflib.get_close_matches(sys.argv[1],g,1,0.8)[0])\" "
        + paket, lab)
    url = sh("grep -i postinstall kurulum.log | grep POST | grep -oE 'https?://[^ /]+' | head -1", lab)
    host = url.split("://", 1)[1]
    guvensiz = sh(birles + "($1 in d) && d[$1]!=\"guvenli\"{n++} END{print n+0}' bilinen_paketler.csv "
                  "bagimliliklar.txt", lab)
    pinsiz = sh("grep -v '^#' bagimliliklar.txt | grep -vcE '@[0-9]+\\.[0-9]+\\.[0-9]+$'; true", lab)
    cozum = {1: paket, 2: gercek, 3: host, 4: guvensiz, 5: pinsiz, 6: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


# ---------------------------------------------------------------- eğitim adımları

ADIMLAR = [
    Adim("Kodu sen yazmadın ama sen çalıştırıyorsun", """
Selin: "Bir yazılım ekibi kodunun çoğunu **başkalarından** alır: yüzlerce açık kaynak paket. Bir paket kurulduğunda
yalnızca dosya kopyalanmaz; bazı paketler kurulum sonrası **kendiliğinden bir betik** çalıştırır (`postinstall`).
Saldırgan kötü bir paketi bu yolla ekibin kendi CI makinesinde (derleme sunucusu) çalıştırabilir. Buna
**tedarik zinciri saldırısı** denir: kapıyı kırmazsın, kapıdan *davet edilmiş* gibi girersin."

Bu bölümde bir yazılım ekibinin **güvenlik analisti** olarak çalışacaksın: zehirli paket nasıl yazılır
anlatılmıyor, sadece **izini sürüp müdahale ediyorsun**. Önce klasörün haritasına bak:
""", komut="cat OKUBENI.txt"),
    Adim("Bağımlılık listesini oku", """
`bagimliliklar.txt` projenin paket listesi. Her satır `ad@sürüm`. Hepsini oku, adlara dikkatli bak:
""", komut="cat bagimliliklar.txt", sonra="""
Sürümlere bak: `4.17.21` gibi düz sayı **sabitlenmiş** (pinlenmiş) sürümdür, her kurulumda aynı kod gelir. `^1.2.0`,
`~2.0.1`, `>=1.0`, `*`, `latest` ise "en yeniyi getir" demektir. Saldırgan paketin yeni bir sürümünü zehirlerse,
sabitlenmemiş proje o zehirli sürümü **otomatik** çeker.
"""),
    Adim("Sabitlenmemiş sürümleri ayıkla", """
`grep -v` bir kalıbı **içermeyen** satırları gösterir. `^#` yorum satırını, ikinci kalıp da `x.y.z` biçimindeki
sabit sürümleri eler. Geriye sabitlenmemişler kalır:
""", komut="""grep -vE '^#|@[0-9]+\\.[0-9]+\\.[0-9]+$' bagimliliklar.txt""", sonra="""
`-c` ekleyerek satırları saymak da mümkündür. Bu liste, "zehirli sürüm gelirse hangileri otomatik etkilenir?"
sorusunun cevabıdır.
"""),
    Adim("Bilinen listeyle birleştir (join)", """
`bilinen_paketler.csv` ekibin elindeki liste: `paket,durum`. Durum `guvenli`, `typosquat` (ad benzeten
taklit) ya da `kotu` (bilinen zararlı) olabilir. `awk` iki dosyayı aynı anda okur: ilkini (`csv`) sözlüğe
dolduruyor, ikincide (proje listesi) adı sözlükte **olan** paketlerin durumunu yazdırıyor. `-F'[@,]'` hem `@`
hem virgülle böler:
""", komut='''awk -F'[@,]' 'NR==FNR{d[$1]=$2;next} ($1 in d){print $1, "->", d[$1]}' bilinen_paketler.csv bagimliliklar.txt''',
         sonra="""
`guvenli` olmayanlar sorunludur. Dikkat: listede hiç olmayan bir paket çıktıda **görünmez**; o "bilinmiyor"
demektir, "güvensiz" demek değil. Ayrıca csv'de olup projende olmayan riskli paketler de var; onlar ilgilendirmez.
"""),
    Adim("Bir harf farkı: typosquat", """
**Typosquat**, popüler bir paketin adını bir harf değiştirerek ya da iki harfin yerini çevirerek kopyalayan
taklittir (`expres` ya da `djnago` gibi). Geliştirici acele edip yanlış yazınca taklit kurulur. İnsan gözü bunu
kaçırır; ama bilgisayar benzerliği ölçebilir. Python'un `difflib` modülü 0 ile 1 arası benzerlik verir:
""", komut='''python3 -c "import difflib; print(difflib.SequenceMatcher(None,'djnago','django').ratio())"''', sonra="""
0.83 çok yüksek bir benzerlik: farklı iki kelime değil, **aynı kelimenin bozuk hali**. Taklitçiyi bulunca gerçeğini
de `difflib.get_close_matches(taklit, guvenli_adlar, 1, 0.8)` ile `bilinen_paketler.csv`'deki güvenli adlar
arasında bulabilirsin (görevde).
"""),
    Adim("postinstall izini sür", """
CI'ın kurulum günlüğü (`kurulum.log`) her paketin kurulumunu ve varsa kurulum sonrası betiğini yazar. Önce
`postinstall` etiketli kaç satır var, say:
""", komut="grep -ci postinstall kurulum.log", sonra="""
Bunların çoğu masum: bir paket kendi ikili dosyasını derliyor ya da paket deposundan bir şey indiriyor. Zehirli
olanı ayıran şey **ne yaptığı**: gizli bilgileri (ortam değişkenleri: token, parola, anahtar) okuyup **tanımadığın
bir hosta** veri göndermesi. `grep -i postinstall kurulum.log | grep POST` bunu daraltır.
"""),
    Adim("Sızdırma adresini çıkar", """
Günlük satırından yalnızca adresi almak için `grep -o` (yalnızca eşleşen kısmı yaz) ve bir kalıp kullanılır.
Örnek bir satır üzerinde dene:
""", komut='''echo "x POST http://ornek-sunucu.lab/yol (10 bytes) -> 200" | grep -oE 'https?://[^ /]+' ''', sonra="""
Aynı kalıbı gerçek günlüğe uyguladığında dışarı veri giden host çıkar. Bu host bir **göstergedir** (IoC):
güvenlik duvarında engellenir, başka sunucuların günlüklerinde aranır, kaç makinenin bağlandığına bakılır.
**Hacker gözüyle:** Saldırgan, paketin "zararsız görünmesine" güvenir; savunmacı ise kurulum anında **ağa kim
çıkıyor** diye bakar.
"""),
]

# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("<<musteri>>'in (<<sektor>>) projesinde `kurulum.log`'da kurulum sonrası betiği (`postinstall`) ile "
          "dışarı veri sızdıran, **ad benzeterek (typosquat) araya sokulmuş** paket hangisi? (Sadece paket adı.)",
          Metin("paket", sik_hatalar=_paket_hata, bicim="paket adı"),
          ("`bilinen_paketler.csv`'de durumu `typosquat` olan ve aynı zamanda proje listesinde bulunan paket.",
           "`awk` ile iki dosyayı birleştir: `NR==FNR{d[$1]=$2;next}` ardından durumu `typosquat` olanı seç; "
           "kurulum günlüğündeki POST satırıyla doğrula.",
           "`awk -F'[@,]' 'NR==FNR{d[$1]=$2;next} ($1 in d) && d[$1]==\"typosquat\"{print $1}' "
           "bilinen_paketler.csv bagimliliklar.txt`"),
          puan=35, baslik="Taklit paket"),
    Gorev("Bu taklit paketin adını taklit ettiği **gerçek** (güvenli) paket hangisi?",
          Metin("gercek", sik_hatalar=_gercek_hata, bicim="paket adı"),
          ("Adı bir harf farkıyla (iki harfin yer değiştirmesiyle) kopyalanmış.",
           "Gerçek paket `bilinen_paketler.csv`'de `guvenli` olarak durur ve taklide çok benzer: `difflib.get_close_matches`.",
           "`python3 -c \"import csv,difflib;a=list(csv.reader(open('bilinen_paketler.csv')))[1:];"
           "g=[x[0] for x in a if x[1]=='guvenli'];print(difflib.get_close_matches('TAKLIT',g,1,0.8))\"`"),
          puan=30, baslik="Gerçek paket"),
    Gorev("Zehirli paketin `postinstall` betiği ortam değişkenlerini (anahtarlar, tokenlar) okuyup bir adrese gönderiyor. "
          "Veriyi alan **host** hangisi? (Adres ya da alan adı.)",
          Metin("host", sik_hatalar=_host_hata, bicim="host (alan adı ya da IP)"),
          ("Kurulum günlüğünde `postinstall` satırlarına bak; masum olanlar sadece paket deposuyla konuşur.",
           "`grep -i postinstall kurulum.log | grep POST` yalnızca veri gönderen satırı bırakır.",
           "`grep -i postinstall kurulum.log | grep POST | grep -oE 'https?://[^ /]+'`; `http://` sonrası host'tur."),
          puan=40, baslik="Sızdırma ucu"),
    Gorev("`bagimliliklar.txt`'deki paketlerden kaçı `bilinen_paketler.csv`'ye göre **güvensiz** (durumu `guvenli` "
          "olmayan: `typosquat` ya da `kotu`)? Listede hiç olmayan paketler sayılmaz.",
          Sayi("guvensiz", sik_hatalar=_guvensiz_hata),
          ("Sadece **projende bulunan** paketlere bak; listedeki başka riskli adlar seni ilgilendirmez.",
           "İki dosyayı `awk` ile birleştir; `$1 in d` projede olup listede de olanı, `d[$1]!=\"guvenli\"` riskliyi seçer.",
           "`awk -F'[@,]' 'NR==FNR{d[$1]=$2;next} ($1 in d) && d[$1]!=\"guvenli\"{n++} END{print n+0}' "
           "bilinen_paketler.csv bagimliliklar.txt`"),
          puan=35, baslik="Güvensiz paket sayısı"),
    Gorev("Kaç paketin sürümü **sabitlenmemiş** (`^`, `~`, `>=`, `*` ya da `latest`; düz `x.y.z` değil)?",
          Sayi("pinsiz", sik_hatalar=_pinsiz_hata),
          ("Sabit sürüm yalnızca üç sayı ve iki noktadan oluşur: `4.17.21`.",
           "`grep -v` ile yorum satırını ve sabit sürümleri ele, kalanı say (`-c`).",
           "`grep -v '^#' bagimliliklar.txt | grep -vcE '@[0-9]+\\.[0-9]+\\.[0-9]+$'`"),
          puan=30, baslik="Pinlenmemiş sürümler"),
    Gorev("Zehirli paketin CI makinesinde çalıştığı ve anahtarları okuduğu anlaşıldı. **En doğru müdahale** hangisi?",
          Secmeli([
              ("Paketi kaldır; günlükte adı geçen anahtar ve tokenları (CI sırları) döndür (rotate) / iptal et; "
               "bağımlılık sürümlerini sabitle (kilit dosyası); sızdırma host'unu engelle ve kurulumu denetle",
               "Doğru. Zehirli paketin okuduğu her sır artık çalınmış sayılır; yalnızca paketi silmek yetmez. "
               "Sabitleme ve denetim bir sonraki olayı önler."),
              ("Sadece paketi `uninstall` et, başka hiçbir şey yapma; paket gittiğine göre sorun da bitmiştir",
               "Yetersiz. Betik zaten çalıştı ve sırlar dışarı gitti; paketi silmek onları geri getirmez. "
               "Sırları döndürmeden saldırgan hâlâ içeri girebilir."),
              ("Sırları döndür ama paketi ve sabitlenmemiş sürümleri olduğu gibi bırak; yeni anahtarlar gelsin "
               "yeter",
               "Eksik. Zehirli paket hâlâ projede; yeni anahtarlar bir sonraki kurulumda yine çalınır. "
               "Paket çıkmalı, sürümler sabitlenmeli."),
              ("Sızdırma host'una karşı misilleme olarak o sunucuya saldırıp çalınan verileri geri al",
               "Yasadışı ve yanlış. Başkasının sistemine karşı saldırı (hack-back) suçtur; savunmacı olarak host'u "
               "engeller, kanıtı toplar, yetkili makamlara ve paket deposuna bildirirsin."),
          ]),
          ("Betik çalıştıysa neyi okudu? Okunan her şey artık güvende mi?",
           "Üç kalem: temizlik (paketi kaldır), telafi (sırları döndür), önlem (sürümleri sabitle, denetle).",
           "Doğru şık dördünü birden içerir: kaldır + sırları döndür + pinle + denetle."),
          puan=35, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="c03b08",
    cilt=3,
    bolum=8,
    baslik="Tedarik Zinciri: Zehirli Paketi Yakala",
    brifing="""
**<<musteri>>** (<<sektor>>): <<olay>>

Selin üç dosyayı masana bırakıyor: "Projenin bağımlılık listesi, güvenlik ekibinin bilinen-paket listesi ve
`<<ci>>` hattının kurulum günlüğü. Bu <<eko>> projesinde kimse zararlı bir şey yazmadı; ama kod **dışarıdan
gelen paketlerle** dolu. Biri bu paketlerden birini bize istemeden kurdurmuş olabilir. Hangisi, ne yaptı, nereye
veri gitti? <<kisi>> bunu bilmek istiyor."

Mert ekliyor: "Paket adlarına dikkat. Acele yazılmış bir `pip install` ya da `npm install`, bir harf farkıyla
başka birinin tuzağına düşer."

Deniz kulaklığını çıkarıyor: "Zehirli betik çoğu zaman gürültüsüz çalışır: hata yok, uyarı yok, sadece sessizce
bağlanıp gider. Günlükte **kim ağa çıktı** diye bak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Saldırgan açısından en ucuz yol, savunmasını aşmak değil, **senin kendi elinle içeri almandır**:
popüler bir paketin adını bozup bekler, bir bağımlılığı zehirler ve kurulum betiğinin senin makinende, senin
yetkinle çalışmasını sağlar. Savunmacı için dört alışkanlık öne çıkar: **sürümleri sabitle** (kilit dosyası),
**bilinen-paket listesiyle denetle**, kurulum sırasında **ağa çıkanı izle** (CI'da dışarı çıkışı kısıtla) ve CI
sırlarını **kısa ömürlü ve en az yetkili** tut ki çalınsalar bile hasar küçük kalsın. Olay olursa paketi silmek
yetmez: betik çalıştıysa okuduğu her sırrı çalınmış say ve döndür.
""",
    gercek_hayat="""
- **xz backdoor, Mart 2024:** Linux'ta yaygın kullanılan `xz` sıkıştırma kütüphanesinin (CVE-2024-3094) yeni
  sürümlerine, yıllarca güven kazanmış bir "bakımcı" hesabı üzerinden arka kapı gizlendi. Bir Microsoft mühendisi,
  SSH girişindeki küçük bir yavaşlamayı fark ederek yakaladı. Ders: bağımlılığın kendisi saldırı yüzeyidir.
- **npm Shai-Hulud, 2025:** Eylül 2025'te ilk dalgası, Kasım 2025'te ikinci dalgası görülen, **kendini çoğaltan
  bir npm solucanı**. Ele geçirilen geliştirici hesaplarındaki tokenları çalıp o hesabın yayınladığı diğer
  paketlere de bulaştı. Bu bölümde gördüğün "sırları döndür" adımı tam olarak bu yüzden hayati.
- **crossenv typosquat, Ağustos 2017:** `cross-env` paketinin adını taklit eden `crossenv` adlı npm paketi,
  kurulumda ortam değişkenlerini dışarı gönderen bir betik içeriyordu. Bu bölümdeki bir harf farkı tuzağının
  gerçek hayattaki örneklerinden biri; npm kaldırdı ama paket kısa sürede indirilmişti.
- **Codecov, 2021:** Popüler bir kod kapsama aracının CI'da kullanılan yükleme betiği değiştirildi ve CI
  ortamlarındaki sırlar çalındı. Ders: CI sırları değerli bir hedeftir; bu yüzden kısa ömürlü ve en az yetkili
  tutulmalıdır.
""",
    sure_hedef_dk=30,
)
