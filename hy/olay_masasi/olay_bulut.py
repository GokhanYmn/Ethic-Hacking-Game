"""Olay Masası — Bulut Yanlış Yapılandırma Denetimi.

Her vakada başka bir müşteri ve başka bir yanlış yapılandırma karışımı: bir depolama
(bucket) politikası herkese açık, bir ya da iki IAM rolü aşırı yetkili, bir güvenlik grubu
hassas bir portu tüm internete açmış, bir uygulama ayar dosyasında bulut anahtarı sızmış.
Oyuncu yalnızca statik yapılandırma dosyalarını DENETLER; saldırı yok, ağ yok. Ayrıca her
vakada "korkutucu görünen ama sorunsuz" tuzak kayıtlar vardır (Deny ifadesi, kapsamı dar
yetki, iç ağa açık port, kasaya bağlı sır).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

HASSAS_PORTLAR = [22, 3389, 5432, 3306, 6379, 27017]
BUCKET_ISIMLERI = ["musteri-belgeleri", "yedekler", "raporlar", "log-arsivi", "medya", "ihracat",
                   "sozlesmeler", "paylasim"]
ROL_ISIMLERI = ["yedekleme-servisi", "rapor-uygulamasi", "ci-dagitim", "veri-ambari", "log-toplayici",
                "destek-ekibi", "ml-egitim", "fatura-isleyici"]
SG_ISIMLERI = ["web", "uygulama", "veritabani", "bakim", "yonetim", "depo"]
ENV_ISIMLERI = ["odeme-servisi", "rapor-servisi", "bildirim-servisi", "admin-paneli"]
HEX = "0123456789abcdef"
BUYUK = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
KARISIK = BUYUK + BUYUK.lower() + "+/"
HESAP = "123456789012"


def _hex(rng, n=4):
    return "".join(rng.choice(HEX) for _ in range(n))


def _json(veri) -> str:
    return json.dumps(veri, indent=2, ensure_ascii=False) + "\n"


def _bucket_dosyalari(rng, m, adlar, acik):
    """Dört bucket politikası. `acik` herkese açık; bir diğeri tuzak (Deny ifadesinde '*')."""
    deny_ad = rng.choice([a for a in adlar if a != acik])
    dosyalar = {}
    for ad in adlar:
        arn = f"arn:aws:s3:::{ad}"
        ifadeler = []
        if ad == acik:
            ifadeler.append({
                "Sid": "ErisimIzni",
                "Effect": "Allow",
                "Principal": rng.choice(["*", {"AWS": "*"}]),
                "Action": rng.choice([["s3:GetObject"], ["s3:GetObject", "s3:ListBucket"]]),
                "Resource": [f"{arn}/*", arn],
            })
        else:
            ifadeler.append({
                "Sid": "UygulamaOkuma",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{HESAP}:role/{m['kod']}-{rng.choice(ROL_ISIMLERI)}"},
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": f"{arn}/*",
            })
        if ad == deny_ad:
            ifadeler.append({
                "Sid": "SadeceSifreliBaglanti",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"{arn}/*", arn],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            })
        dosyalar[f"depolama/{ad}.json"] = _json(
            {"Bucket": ad, "Version": "2012-10-17", "Statement": ifadeler})
    return dosyalar, deny_ad


def _iam_dosyalari(rng, m, roller, asiri):
    """Rol politikaları. `asiri` kümesindekiler Action:* + Resource:*; bir tuzak 's3:*' ama dar kapsamlı."""
    dar = [r for r in roller if r not in asiri]
    tuzak = rng.choice(dar)
    dosyalar = {}
    for r in roller:
        if r in asiri:
            ifade = {"Effect": "Allow",
                     "Action": rng.choice(["*", ["*"]]),
                     "Resource": rng.choice(["*", ["*"]])}
        elif r == tuzak:
            ifade = {"Effect": "Allow", "Action": "s3:*",
                     "Resource": f"arn:aws:s3:::{m['kod']}-{rng.choice(BUCKET_ISIMLERI)}/*"}
        else:
            ifade = rng.choice([
                {"Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:DescribeVolumes"], "Resource": "*"},
                {"Effect": "Allow", "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                 "Resource": f"arn:aws:logs:eu-west-1:{HESAP}:log-group:/{m['kod']}/*"},
                {"Effect": "Allow", "Action": ["sqs:SendMessage"],
                 "Resource": f"arn:aws:sqs:eu-west-1:{HESAP}:{m['kod']}-kuyruk"},
            ])
        dosyalar[f"iam/{r}.json"] = _json(
            {"RolAdi": r, "Version": "2012-10-17", "Statement": [ifade]})
    return dosyalar, tuzak


def _sg_dosyasi(rng, m, tehlikeli_ad, port):
    adlar = rng.sample(SG_ISIMLERI, 4)
    if tehlikeli_ad is None:
        tehlikeli_ad = rng.choice(adlar)
    elif tehlikeli_ad not in adlar:
        adlar[0] = tehlikeli_ad
    ic = rng.choice(["10.0.0.0/16", "10.10.5.0/24", "172.16.4.0/24", "192.168.10.0/24"])
    ofis = f"{u.dis_ip(rng)}/32"
    gruplar = []
    for a in adlar:
        ad = f"sg-{m['kod']}-{a}"
        kurallar = []
        if a == adlar[0] or rng.random() < 0.5:
            kurallar += [{"Protokol": "tcp", "Port": 443, "Kaynak": "0.0.0.0/0", "Not": "genel web"},
                         {"Protokol": "tcp", "Port": 80, "Kaynak": "0.0.0.0/0", "Not": "https'e yönlendirme"}]
        guvenli_port = rng.choice([p for p in HASSAS_PORTLAR if p != port])
        kurallar.append({"Protokol": "tcp", "Port": guvenli_port,
                         "Kaynak": rng.choice([ic, ofis]), "Not": "yalnızca iç ağ / ofis"})
        if a == tehlikeli_ad:
            kurallar.insert(rng.randint(0, len(kurallar)),
                            {"Protokol": "tcp", "Port": port, "Kaynak": "0.0.0.0/0",
                             "Not": rng.choice(["geçici erişim", "bakım için açıldı", "test", "tedarikçi erişimi"])})
        gruplar.append({"Ad": ad, "Aciklama": f"{m['ad']} {a} katmanı", "GirisKurallari": kurallar})
    return _json({"GuvenlikGruplari": gruplar}), f"sg-{m['kod']}-{tehlikeli_ad}"


def _env_dosyalari(rng, m, sizan):
    """Üç ayar dosyası; biri gerçek anahtar sızdırır, diğerleri kasaya bağlanır ya da yer tutucu içerir."""
    adlar = rng.sample(ENV_ISIMLERI, 3)
    if sizan is not None:
        adlar[0] = sizan
    dosyalar = {}
    anahtar = "AKIA" + "".join(rng.choice(BUYUK) for _ in range(16))
    gizli = "".join(rng.choice(KARISIK) for _ in range(40))
    for a in adlar:
        ic = u.ic_ip(rng)
        satirlar = ["APP_ENV=production", f"APP_ADI={a}", f"DB_HOST={ic}", "DB_PORT=5432"]
        if a == adlar[0]:
            satirlar += [f"CLOUD_ACCESS_KEY_ID={anahtar}", f"CLOUD_SECRET_ACCESS_KEY={gizli}",
                         "# TODO: kasaya taşı"]
        elif rng.random() < 0.5:
            satirlar += [f"CLOUD_ACCESS_KEY_ID=${{SIR_KASASI:{m['kod']}/{a}/anahtar}}",
                         f"CLOUD_SECRET_ACCESS_KEY=${{SIR_KASASI:{m['kod']}/{a}/gizli}}"]
        else:
            satirlar += ["CLOUD_ACCESS_KEY_ID=<anahtar-buraya>", "CLOUD_SECRET_ACCESS_KEY=<gizli-buraya>"]
        dosyalar[f"uygulama/{a}.env"] = "\n".join(satirlar) + "\n"
    return dosyalar, adlar[0]


def uret(rng):
    m = musteri_sec(rng)
    on = m["kod"]
    adlar = [f"{on}-{x}-{_hex(rng)}" for x in rng.sample(BUCKET_ISIMLERI, 4)]
    acik = rng.choice(adlar)
    bucketlar, deny_ad = _bucket_dosyalari(rng, m, adlar, acik)

    roller = [f"{on}-{x}" for x in rng.sample(ROL_ISIMLERI, 4)]
    asiri = set(rng.sample(roller, rng.randint(1, 2)))
    iam, tuzak_rol = _iam_dosyalari(rng, m, roller, asiri)

    port = rng.choice(HASSAS_PORTLAR)
    sg_metin, sg_ad = _sg_dosyasi(rng, m, None, port)

    env, sizan_ad = _env_dosyalari(rng, m, None)
    sizan_dosya = f"{sizan_ad}.env"

    toplam = 1 + len(asiri) + 1 + 1
    dosyalar = {**bucketlar, **iam, "ag/guvenlik_gruplari.json": sg_metin, **env}
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — bulut yapılandırma denetimi",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"]},
        "cevaplar": {
            "acik_bucket": acik,
            "asiri_roller": sorted(asiri),
            "sg_ad": sg_ad,
            "port": port,
            "sizan_dosya": [sizan_dosya, f"uygulama/{sizan_dosya}"],
            "toplam": toplam,
        },
        "_dosyalar": dosyalar,
        "_deny_bucket": deny_ad,
        "_tuzak_rol": tuzak_rol,
    }


def yaz(lab: Path, s: dict) -> None:
    for yol, icerik in s["_dosyalar"].items():
        u.yaz(lab / yol, icerik)


def _deny_hata(g, beklenen, b):
    if g == b.senaryo["_deny_bucket"].casefold():
        return ("Bu bucket'taki `\"Principal\": \"*\"` bir **Deny** ifadesinde; erişimi açmıyor, "
                "tersine şifresiz bağlantıyı yasaklıyor. `Effect` alanına bak.")
    return None


def _rol_hata(g, beklenen, b):
    if b.senaryo["_tuzak_rol"].casefold() in g.split():
        return ("Listende `s3:*` yetkili ama **tek bir bucket'a** sınırlı bir rol var. Geniş ama kapsamlı; "
                "aşırı yetkili olan hem Action hem Resource'u `*` olandır.")
    return None


def _port_hata(g, beklenen, b):
    if int(g) in (80, 443):
        return "80 ve 443 web sitesi içindir; herkese açık olmaları normal. Hassas (yönetim/veri tabanı) portu ara."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _py(kod: str, lab: Path) -> str:
    return _sh("python3 - <<'PY'\n" + kod + "\nPY", lab)


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]


def coz(lab: Path, s: dict) -> dict:
    acik = _py(
        "import json,glob\n"
        "for f in sorted(glob.glob('depolama/*.json')):\n"
        "    d=json.load(open(f))\n"
        "    for x in d['Statement']:\n"
        "        p=x.get('Principal')\n"
        "        if x['Effect']=='Allow' and (p=='*' or (isinstance(p,dict) and p.get('AWS')=='*')):\n"
        "            print(d['Bucket'])\n", lab).split()[0]
    roller = _py(
        "import json,glob\n"
        "for f in sorted(glob.glob('iam/*.json')):\n"
        "    d=json.load(open(f))\n"
        "    for x in d['Statement']:\n"
        "        a=x['Action'] if isinstance(x['Action'],list) else [x['Action']]\n"
        "        r=x['Resource'] if isinstance(x['Resource'],list) else [x['Resource']]\n"
        "        if x['Effect']=='Allow' and '*' in a and '*' in r:\n"
        "            print(d['RolAdi'])\n", lab).split()
    sg = _py(
        "import json\n"
        "d=json.load(open('ag/guvenlik_gruplari.json'))\n"
        "for g in d['GuvenlikGruplari']:\n"
        "    for k in g['GirisKurallari']:\n"
        "        if k['Kaynak']=='0.0.0.0/0' and k['Port'] in (22,3389,5432,3306,6379,27017):\n"
        "            print(g['Ad'],k['Port'])\n", lab).split()
    sizan = _sh("grep -lE 'AKIA[A-Z0-9]{16}' uygulama/* | head -1", lab)
    toplam = len(roller) + 3
    return {1: acik, 2: " ".join(roller), 3: sg[0], 4: sg[1], 5: sizan, 6: toplam,
            7: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("`depolama/` altındaki politikalardan hangi bucket **herkese açık**? Bucket adını yaz.",
          Metin("acik_bucket", bicim="bucket adı", sik_hatalar=_deny_hata),
          ("Herkese açık demek, politikada erişim verilen kişinin 'herkes' olması demektir.",
           "`Principal` alanı `\"*\"` (ya da `{\"AWS\": \"*\"}`) olan **Allow** ifadesini ara. Deny ifadesi erişim açmaz.",
           "`grep -n '\"Principal\": \"\\*\"' depolama/*.json` — sonra `Effect` alanına bak; `{\"AWS\": \"*\"}` biçimini de dene."),
          puan=20, baslik="Herkese açık bucket"),
    Gorev("`iam/` altındaki rollerden hangileri **aşırı yetkili** (her işlem, her kaynak)? "
          "Rol adlarını boşlukla ayırarak yaz.",
          Kume("asiri_roller", sik_hatalar=_rol_hata, bicim="boşlukla ayrılmış rol adları"),
          ("Aşırı yetki, hem yapılabilecek işlemin hem de kaynağın sınırsız olması demektir.",
           "`Action` ve `Resource` ikisi de `*` olan Allow ifadesini ara. Dikkat: `*` bazen liste içinde `[\"*\"]` gelir.",
           "`grep -l '\"\\*\"' iam/*.json` ilk eleme olur; sonra her dosyada Action ve Resource'a ayrı ayrı bak."),
          puan=25, baslik="Aşırı yetkili roller"),
    Gorev("`ag/guvenlik_gruplari.json` içinde hassas bir portu **tüm internete** (`0.0.0.0/0`) açan "
          "güvenlik grubunun adı ne?",
          Metin("sg_ad", bicim="güvenlik grubu adı"),
          ("Her kuralın bir `Kaynak` alanı var: kime açık?",
           "`0.0.0.0/0` kaynağı tüm internet demektir. Ama 80/443 web için normaldir; yönetim ve veri tabanı portlarına odaklan.",
           "`grep -n -B3 '0.0.0.0/0' ag/guvenlik_gruplari.json` — portlara bak; grubun adı yukarıdaki `Ad` alanında."),
          puan=20, baslik="Açık güvenlik grubu"),
    Gorev("Aynı kuralda internete açılan **hassas port numarası** kaç?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Önceki görevde bulduğun kuralın `Port` alanı.",
           "Yaygın hassas portlar: 22 (SSH), 3389 (RDP), 5432 (PostgreSQL), 3306 (MySQL), 6379 (Redis), 27017 (MongoDB).",
           "`grep -B2 -A2 '0.0.0.0/0' ag/guvenlik_gruplari.json | grep Port` — 80 ve 443 dışındakini al."),
          puan=15, baslik="Tehlikeli port"),
    Gorev("`uygulama/` altındaki ayar dosyalarından hangisinde **gerçek bir bulut erişim anahtarı** sızmış? "
          "(`${SIR_KASASI:...}` ve `<...-buraya>` gerçek değer değildir) Dosya adını yaz.",
          Metin("sizan_dosya", bicim="dosya adı", sadece_ad=True),
          ("Üç dosyadan ikisi sırrı başka yerden alıyor ya da boş bırakıyor.",
           "Bulut erişim anahtar kimlikleri `AKIA` ile başlar ve ardından 16 büyük harf/rakam gelir.",
           "`grep -lE 'AKIA[A-Z0-9]{16}' uygulama/*`"),
          puan=20, baslik="Sızan anahtar"),
    Gorev("Toplam kaç **hatalı kaynak** buldun? (herkese açık bucket'lar + aşırı yetkili roller + "
          "internete açık hassas portlu güvenlik grupları + sır sızdıran dosyalar)",
          Sayi("toplam"),
          ("Önceki görevlerin cevaplarını topla; rol sayısına dikkat, birden fazla olabilir.",
           "Bucket'lar, roller, güvenlik grupları ve dosyalar için ayrı ayrı say, sonra hepsini topla.",
           "Her bulgu tek bir kaynaktır: bucket + (aşırı yetkili rol sayısı) + güvenlik grubu + sızdıran dosya."),
          puan=15, baslik="Toplam bulgu"),
    Gorev("Sızdırılmış bulut anahtarını fark ettin. Müdahalede **ilk** doğru adım hangisi?",
          Secmeli([
              ("Anahtarı hemen iptal et (devre dışı bırak/döndür), kullanım kayıtlarını incele, sırrı kasaya taşı",
               "Doğru. Sızan anahtar artık güvenilmezdir; önce geçerliliğini sonlandır, sonra izini sür."),
              ("Dosyadaki satırı silip sürümü yeniden dağıt",
               "Yetmez: anahtar geçmişte kopyalanmış olabilir ve hâlâ geçerlidir. Önce iptal et."),
              ("Anahtar kullanılana kadar bekle, kötüye kullanım görürsen müdahale et",
               "Hayır. Beklemek saldırgana süre verir; sızan sır varsayılan olarak ele geçirilmiş sayılır."),
              ("Sadece sürüm geçmişinden temizle",
               "Geçmişi temizlemek tek başına güvenli değildir; anahtar iptal edilmedikçe geçerliliğini korur."),
          ]),
          ("Sızan bir sırrı kimlerin görmüş olabileceğini bilemezsin.",
           "Sırrın geçerliliğini sonlandırmadan yapılan temizlik yarım kalır.",
           "Sıra: iptal/döndür → kullanım kayıtlarını incele → sırrı kasaya taşı."),
          puan=15, baslik="İlk müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_bulut",
    cilt=12,
    bolum=102,
    baslik="Bulut Yanlış Yapılandırma Denetimi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) bulut ortamı için bağımsız bir
yapılandırma denetimi istedi. <<hikaye>> <<kisi>> yapılandırma dosyalarının dışa aktarımını
gönderdi."

"Dosyalar sende: `depolama/` (bucket politikaları), `iam/` (rol yetkileri),
`ag/guvenlik_gruplari.json` (güvenlik grupları) ve `uygulama/` (ayar dosyaları). Saldırı
yok, sadece okuma: yanlış yapılandırmayı bulup raporlayacaksın. Dikkat, her yerde `*` görmek
hata demek değil; bağlam önemli. Hangisi gerçekten açık, hangisi sadece öyle görünüyor?"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bulutta çoğu ihlal sofistike bir saldırı değil, unutulmuş bir yapılandırmadır. Üç ilke
bunların çoğunu önler: **en az yetki** (rol yalnızca ihtiyacı olan işlemi ve kaynağı
görsün), **varsayılan kapalı** (bucket ve portlar ancak gerekçeyle açılsın) ve **sır
yönetimi** (anahtarlar kodda değil kasada dursun, sızarsa hemen döndürülsün). Bu denetimi
bir betiğe koyup her dağıtımda otomatik çalıştırmak, bulguları saldırgandan önce yakalar.
""",
    gercek_hayat="""
- **Capital One, 2019:** Yanlış yapılandırılmış bir web uygulaması güvenlik duvarı, SSRF
  zafiyetiyle birleşerek saldırganın sunucunun bulut kimlik bilgilerini almasına izin verdi.
  Rol gereğinden geniş yetkiliydi; saldırgan S3'teki yüz milyonu aşkın müşteri kaydına
  ulaştı. Dar yetkili bir rol, zararı çok sınırlardı.
- **Herkese açık S3 bucket sızıntıları:** Yıllar boyunca birçok kurumun müşteri verisi,
  yalnızca bucket "herkese açık" bırakıldığı için internetten okunabilir hâlde bulundu;
  araştırmacılar bu bucket'ları rutin olarak tarayıp bildirdi. Bulut sağlayıcıları sonradan
  varsayılan olarak "genel erişimi engelle" ayarını getirdi.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c12b01",),
)
