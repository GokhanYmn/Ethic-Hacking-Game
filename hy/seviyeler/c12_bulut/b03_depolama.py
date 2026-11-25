"""Cilt 12 · Bölüm 3 — Depolama ve Veri Açıkları.

Beceri: kurgusal bucket (kova) politikası ve ACL dosyalarında herkese açık nesneleri bulmak;
erişim logundan dışarıdan toplu indirme yapan istemciyi saptamak; açığı kapatmak (politika,
ACL, şifreleme, erişim günlüğü). `cevap <no>` dosyaların son halini kontrol eder (Durum görevleri).

Vakalar: e-ticaret, hastane, fintech, lojistik, banka. Bilinçli olarak herkese açık bir kova
(statik site) tuzak olarak vardır; hassas iki kovadan biri politikayla, diğeri ACL ile açık kalmıştır
ve hangisinin hangi yolla açık olduğu her vakada değişir.
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, IP, Kume, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c12_bulut.ortak import json_satirli, json_yaz, liste, py, sec_doldur, sh, sirket_sec

SLUG = {"pazarix": "siparis", "medora": "hasta", "paramix": "odeme", "kuzgun": "sevkiyat", "ferahbank": "hesap"}
STATIK_ANAHTAR = ["banner-kampanya.jpg", "logo.png", "stil.css", "site.js", "menu.pdf", "ikon.svg"]
SAHNE = {
    "pazarix": "Pazarix'e bir araştırmacı e-posta atıp 'müşteri dosyalarınız internette' dedi.",
    "medora": "Medora Sağlık'ın KVKK sorumlusu, bir hasta dosyası kovasının dışarıdan görünür olduğundan şüpheleniyor.",
    "paramix": "Paramix'in ödeme kayıtları kovasına alışılmadık miktarda anonim istek geldi.",
    "kuzgun": "Kuzgun Lojistik'te bir ortak firma, alıcı adres listesinin bağlantısını yanlışlıkla herkese paylaştı.",
    "ferahbank": "Ferah Bank'ın bulut denetimi, hassas veri kovalarında 'herkes' erişimi aradı.",
}
HESAP = "123456789012"


def uret(rng):
    sk = sirket_sec(rng)
    on, slug = sk["on"], SLUG[sk["kod"]]
    statik, musteri, yedek = f"{on}-statik-site", f"{on}-{slug}-verisi", f"{on}-{slug}-yedek"
    ic, logk = f"{on}-uygulama-ici", f"{on}-erisim-gunlukleri"
    politikayla, aclyle = (musteri, yedek) if rng.random() < 0.5 else (yedek, musteri)
    prensip_bicim = rng.choice(["*", "{AWS}"])
    kovalar = [(statik, "web sitesi statik dosyaları", "herkese-acik"), (musteri, f"{sk['veri']}", "hassas"),
               (yedek, "veritabanı yedekleri", "hassas"), (ic, "uygulama iç dosyaları", "ic"),
               (logk, "erişim günlükleri", "ic")]
    # --- erişim logu
    gun = u.gun(rng) + timedelta(hours=10)
    satirlar = []
    dis = u.benzersiz(rng, u.dis_ip, 5)
    tarayici, kalabalik = dis[0], dis[1]
    musteri_anahtar = [f"{slug}_ihracat_{n:03d}.csv" for n in rng.sample(range(1, 90), 40)]
    yedek_anahtar = [f"yedek_{rng.randint(2025, 2026)}_{m:02d}.sql.gz" for m in rng.sample(range(1, 13), 6)]
    n_tarama = rng.randint(12, 20)
    hedefler = rng.sample(musteri_anahtar + yedek_anahtar[:3], n_tarama)

    def sat(t, bucket, ip, istekci, islem, anahtar, kod, bayt):
        satirlar.append((t, f"{bucket} {t:%Y-%m-%dT%H:%M:%S}+03:00 {ip} {istekci} {islem} {anahtar} {kod} {bayt}"))

    t = gun
    for k in hedefler:                                           # toplu indirme
        t += timedelta(seconds=rng.randint(2, 9))
        b = yedek if k.startswith("yedek_") else musteri
        sat(t, b, tarayici, "-", "REST.GET.OBJECT", k, 200, rng.randint(20000, 900000))
    for k in rng.sample(hedefler, 3):                            # bazı dosyalar iki kez
        t += timedelta(seconds=rng.randint(2, 9))
        b = yedek if k.startswith("yedek_") else musteri
        sat(t, b, tarayici, "-", "REST.GET.OBJECT", k, 200, rng.randint(20000, 900000))
    for _ in range(rng.randint(2, 4)):                           # özel kovaya yetkisiz deneme
        t += timedelta(seconds=rng.randint(2, 9))
        sat(t, ic, tarayici, "-", "REST.GET.OBJECT", "ayarlar.json", 403, 0)
    for _ in range(rng.randint(40, 60)):                         # sitenin meşru, kalabalık ziyaretçisi
        sat(gun + timedelta(seconds=rng.randint(-1800, 3600)), statik, kalabalik, "-", "REST.GET.OBJECT",
            rng.choice(STATIK_ANAHTAR[:2]), 200, rng.randint(2000, 90000))
    for ip in dis[2:]:                                           # küçük meraklı ziyaretçiler
        for _ in range(rng.randint(3, 7)):
            sat(gun + timedelta(seconds=rng.randint(-1800, 3600)), statik, ip, "-", "REST.GET.OBJECT",
                rng.choice(STATIK_ANAHTAR), 200, rng.randint(2000, 90000))
    ic_ip = [u.ic_ip(rng, "10.40.1") for _ in range(3)]
    for _ in range(rng.randint(25, 40)):                         # iç servis erişimleri
        b = rng.choice([musteri, yedek, ic])
        sat(gun + timedelta(seconds=rng.randint(-1800, 3600)), b, rng.choice(ic_ip), "rol/rapor-servisi",
            "REST.GET.OBJECT", rng.choice(musteri_anahtar if b == musteri else yedek_anahtar if b == yedek else ["ayarlar.json"]),
            200, rng.randint(2000, 90000))
    satirlar.sort(key=lambda x: x[0])
    tarama_say = len({(b, k) for b, k in
                      ((yedek if k.startswith("yedek_") else musteri, k) for k in hedefler)})
    return {
        "vaka": f"{sk['ad']} — depolama denetimi",
        "sirket": sk, "kovalar": kovalar, "statik": statik, "musteri": musteri, "yedek": yedek, "ic": ic, "logk": logk,
        "politikayla": politikayla, "aclyle": aclyle, "bicim": prensip_bicim, "satirlar": [x[1] for x in satirlar],
        "tarayici": tarayici, "kalabalik": kalabalik,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "veri": sk["veri"], "statik": statik,
                  "politikayla": politikayla, "aclyle": aclyle, "hassas1": musteri, "hassas2": yedek},
        "cevaplar": {"acik_hassas": [musteri, yedek], "tarayici": tarayici, "tarama_say": tarama_say},
    }


def _politika(s, kova, acik: bool) -> dict:
    prensip = "*" if s["bicim"] == "*" else {"AWS": "*"}
    stm = [{"Sid": "IcOkuma", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{HESAP}:role/rapor-servisi"},
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{kova}/*"}]
    if acik:
        stm.append({"Sid": "HerkesOkusun", "Effect": "Allow", "Principal": prensip, "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{kova}/*"})
    if kova == s["ic"]:
        stm.append({"Sid": "SadeceTLS", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                    "Resource": [f"arn:aws:s3:::{kova}", f"arn:aws:s3:::{kova}/*"],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}}})
    return {"Version": "2012-10-17", "Statement": stm}


def yaz(lab: Path, s: dict) -> None:
    k = lab / "bulut/depolama"
    u.yaz(k / "kovalar.csv", "kova,amac,veri_sinifi\n" + "".join(f"{a},{b},{c}\n" for a, b, c in s["kovalar"]))
    for kova, _, sinif in s["kovalar"]:
        acik_pol = kova == s["statik"] or kova == s["politikayla"]
        u.yaz(k / f"kovalar/{kova}.politika.json", json_yaz(_politika(s, kova, acik_pol)))
        acl = [f"Owner: hesap-sahibi", "Grant: hesap-sahibi FULL_CONTROL"]
        if kova == s["aclyle"]:
            acl.append("Grant: AllUsers READ")
        u.yaz(k / f"kovalar/{kova}.acl.txt", "\n".join(acl) + "\n")
    ayar = [{"kova": kova, "sifreleme": "yok", "erisim_gunlugu": False, "herkese_acik_engeli": False}
            for kova, _, _ in s["kovalar"]]
    u.yaz(k / "kovalar/ayarlar.json", json_satirli({"not": "kova başına güvenlik ayarları (KURGUSAL)"}, {"kovalar": ayar}))
    u.yaz(k / "erisim_logu.txt",
          "# kova zaman istemci-IP istekçi işlem anahtar durum bayt   (istekçi '-' = anonim/kimliksiz)\n" +
          "\n".join(s["satirlar"]) + "\n")


def _herkese_acik(politika_yolu: Path) -> bool | None:
    try:
        d = json.loads(politika_yolu.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    stm = d.get("Statement", [])
    for x in stm if isinstance(stm, list) else [stm]:
        if x.get("Effect") != "Allow":
            continue
        p = x.get("Principal")
        if p == "*" or (isinstance(p, dict) and "*" in liste(p.get("AWS", []))):
            return True
    return False


def _politika_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    k = b.lab / "bulut/depolama/kovalar"
    kova = s["politikayla"]
    yol = k / f"{kova}.politika.json"
    acik = _herkese_acik(yol)
    if acik is None:
        return Sonuc(False, f"`{yol.name}` bulunamadı ya da geçerli JSON değil (`python3 -m json.tool` ile doğrula).")
    if acik:
        return Sonuc(False, f"`{kova}` politikasında hâlâ herkese (`Principal: *`) izin veren bir `Allow` ifadesi var.", yakin=True)
    d = json.loads(yol.read_text(encoding="utf-8"))
    if not any("rapor-servisi" in json.dumps(x.get("Principal", "")) for x in d["Statement"]):
        return Sonuc(False, "Meşru iç okuma kuralını (`rapor-servisi`) da silmişsin; sadece **herkese açık** ifadeyi sil.", yakin=True)
    if not _herkese_acik(k / f"{s['statik']}.politika.json"):
        return Sonuc(False, "Bilinçli olarak herkese açık olan statik site kovasını da kapatmışsın; web sitesi çalışmaz. Yalnızca hassas kovaları kapat.", yakin=True)
    return Sonuc(True, f"`{kova}` artık herkese açık değil; iç servisin okuması devam ediyor, statik site yerinde.")


def _acl_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    kova = s["aclyle"]
    yol = b.lab / f"bulut/depolama/kovalar/{kova}.acl.txt"
    if not yol.is_file():
        return Sonuc(False, f"`{yol.name}` yok.")
    metin = yol.read_text(encoding="utf-8", errors="replace")
    if "AllUsers" in metin or "AuthenticatedUsers" in metin:
        return Sonuc(False, f"`{kova}` ACL'sinde hâlâ `AllUsers` (herkes) için bir izin satırı var.", yakin=True)
    if "hesap-sahibi FULL_CONTROL" not in metin:
        return Sonuc(False, "Sahibin kendi izin satırını (`hesap-sahibi FULL_CONTROL`) silmişsin; sadece herkese açık satırı sil.", yakin=True)
    return Sonuc(True, f"`{kova}` ACL'si artık yalnızca hesap sahibine izin veriyor.")


def _ayar_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "bulut/depolama/kovalar/ayarlar.json"
    try:
        d = json.loads(yol.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Sonuc(False, "`ayarlar.json` bulunamadı ya da geçerli JSON değil.")
    kay = {x.get("kova"): x for x in d.get("kovalar", [])}
    if set(kay) != {k for k, _, _ in s["kovalar"]}:
        return Sonuc(False, "Kova satırı silinmiş ya da eklenmiş; sadece değerleri düzelt.")
    for kova in (s["musteri"], s["yedek"]):
        a = kay[kova]
        if a.get("sifreleme") in (None, "yok", ""):
            return Sonuc(False, f"`{kova}` hâlâ şifrelenmiyor (`sifreleme`). Veri dururken de şifreli olmalı (`aes256`).", yakin=True)
        if a.get("erisim_gunlugu") is not True:
            return Sonuc(False, f"`{kova}` için erişim günlüğü kapalı: kim neye eriştiği kaydedilmiyor. `erisim_gunlugu` true olmalı.", yakin=True)
        if a.get("herkese_acik_engeli") is not True:
            return Sonuc(False, f"`{kova}` için herkese açık erişim engeli kapalı: ileride biri yine yanlışlıkla açabilir.", yakin=True)
    if kay[s["statik"]].get("herkese_acik_engeli") is True:
        return Sonuc(False, "Statik site kovasında herkese açık engelini de açmışsın; bu kova bilinçli olarak herkese açık, web sitesi çalışmaz.", yakin=True)
    return Sonuc(True, "Hassas kovalar şifreli, günlüğü açık ve herkese açık erişime karşı korumalı; statik site olduğu gibi.")


def coz(lab: Path, s: dict) -> dict:
    j = "import json,csv,glob,os\n"
    acik = py(j + "k='bulut/depolama/kovalar/'\nfor r in csv.DictReader(open('bulut/depolama/kovalar.csv')):\n"
              " if r['veri_sinifi']!='hassas': continue\n n=r['kova'];a=False\n"
              " for x in json.load(open(k+n+'.politika.json'))['Statement']:\n"
              "  p=x.get('Principal')\n"
              "  if x['Effect']=='Allow' and (p=='*' or (isinstance(p,dict) and p.get('AWS')=='*')): a=True\n"
              " if 'AllUsers' in open(k+n+'.acl.txt').read(): a=True\n"
              " if a: print(n)\n", lab).split()
    kovalar = "|".join(acik)
    filtre = f"awk '($1==\"{acik[0]}\"||$1==\"{acik[1]}\") && $4==\"-\" && $5==\"REST.GET.OBJECT\" && $7==200'"
    ip = sh(f"{filtre} bulut/depolama/erisim_logu.txt | awk '{{print $3}}' | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    sayi = sh(f"{filtre} bulut/depolama/erisim_logu.txt | awk '$3==\"{ip}\" {{print $1, $6}}' | sort -u | wc -l", lab)
    # düzeltmeler
    kk = "bulut/depolama/kovalar/"
    py(j + f"f='{kk}{s['politikayla']}.politika.json';d=json.load(open(f));"
       "d['Statement']=[x for x in d['Statement'] if x.get('Sid')!='HerkesOkusun'];json.dump(d,open(f,'w'),indent=2)", lab)
    sh(f"sed -i '/AllUsers/d' {kk}{s['aclyle']}.acl.txt", lab)
    for kova in (s["musteri"], s["yedek"]):
        sh(f"sed -i '/\"kova\": \"{kova}\"/ s/\"sifreleme\": \"yok\"/\"sifreleme\": \"aes256\"/; /\"kova\": \"{kova}\"/ s/\"erisim_gunlugu\": false/\"erisim_gunlugu\": true/; "
           f"/\"kova\": \"{kova}\"/ s/\"herkese_acik_engeli\": false/\"herkese_acik_engeli\": true/' {kk}ayarlar.json", lab)
    return sec_doldur({1: "", 2: " ".join(acik), 3: ip, 4: sayi, 5: "", 6: "", 7: ""}, GOREVLER, lab, s)


def _acik_hata(g, beklenen, b):
    verilen = set(g.split())
    if b.senaryo["statik"].lower() in verilen:
        return "Statik site kovası da herkese açık ama **bilinçli**: web sitesinin görselleri halka açık olmak zorunda. Soru, **hassas** veri taşıyıp herkese açık olanları soruyor."
    if len(verilen) == 1 and verilen <= {x.lower() for x in beklenen}:
        return "Bir kova eksik. Açıklığı iki farklı yoldan yapabilirsin: kova **politikası** ve **ACL**. İkisine de bak."
    return None


def _ip_hata(g, beklenen, b):
    if g == b.senaryo["kalabalik"]:
        return ("Bu IP en çok istek yapmış ama hep **statik site** dosyalarına (logo, banner): sitenin meşru ziyaretçisi. "
                "Aradığın, **hassas** kovalardan indirme yapan IP.")
    return None


ADIMLAR = [
    Adim("Açık bırakılmış kovalar", """
Bulut ihlallerinin en bilinen türü, **açık bırakılmış veri depolamasıdır**. Kovalar (AWS S3, Azure Blob,
Google Cloud Storage) varsayılan olarak özeldir; ama bir yanlış yapılandırma onları herkese açık yapar.
Açık bir kova, internetteki herkesin içindeki veriyi indirebilmesi demektir. Bu, Cilt 1'deki açık `.bak`
dosyasının **bulut ölçeğindeki** halidir: aynı hata, çok daha fazla veri.

**<<musteri>>**. <<sahne>> Önce kovaların envanterine bak:
""", komut="cat bulut/depolama/kovalar.csv", sonra="""
`veri_sinifi` sütunu önemli: `herkese-acik` olması **bilinçli** bir kovadır (statik web sitesi);
`hassas` ise içinde <<veri>> gibi gizli veri vardır ve **asla** herkese açık olmamalıdır.
"""),
    Adim("Politika ile açıklık", """
Bir kova iki yoldan herkese açılabilir. Birincisi **kova politikası**: bir `Allow` ifadesindeki
`Principal` (kim) alanı `*` ise **herkes** demektir. Bir politikaya bak:
""", komut="python3 -m json.tool bulut/depolama/kovalar/<<statik>>.politika.json", sonra="""
`IcOkuma` ifadesinin `Principal` alanı belirli bir **rol**: yalnızca o rol okuyabilir. `HerkesOkusun`
ifadesinde ise `Principal` `*` (ya da `{"AWS": "*"}`): herkes. Dikkat: `Effect: Deny` olan bir
`Principal: *` herkesi **engeller**, yetki vermez.
"""),
    Adim("ACL ile açıklık", """
İkinci yol **ACL** (erişim kontrol listesi): eski ve nesne/kova bazlı izin listesi. `AllUsers` herkes
demektir. ACL dosyalarında `AllUsers` ara:
""", komut="grep -l 'AllUsers' bulut/depolama/kovalar/*.acl.txt", sonra="""
Bir kovayı kontrol ederken **iki yere de** bakmalısın: politika ve ACL. Biri temiz diye kova temiz
olmaz.
"""),
    Adim("Politikada herkes arama", """
Politikalarda `Principal` değerinin `*` olduğu yerleri bulalım (iki yazım var: `"Principal": "*"` ve
`"AWS": "*"`):
""", komut="grep -n '\"\\*\"' bulut/depolama/kovalar/*.politika.json", sonra="""
Çıktıyı dikkatlice oku: `Resource` ya da `Action` alanındaki `*` değil, **`Principal`** satırlarındaki
`*` aranan şey. Hangi dosya hem `Principal: *` hem `Allow` içeriyor?
"""),
    Adim("Erişim logu: kim indirdi?", """
Erişim günlüğü, kovanın **kimin neye eriştiğini** kaydeder. Satırlar: kova, zaman, istemci IP'si, istekçi
(`-` = kimliksiz/anonim), işlem, anahtar (dosya), durum kodu, bayt. Anonim bir `GET` ve `200`, bir
dosyanın **indirildiği** anlamına gelir:
""", komut="head -6 bulut/depolama/erisim_logu.txt", sonra="""
Dışarıdan toplu indirme izi: **tek bir IP**, **hassas** kovadan, **çok sayıda farklı dosya**. Kalabalık
bir statik site ziyaretçisinden ayırt etmek için kovaya ve dosya çeşitliliğine bak.
"""),
    Adim("Kaynak başına sayma", """
`awk` ile koşullu süzüp `sort | uniq -c` ile sayabilirsin. Anonim (`$4=="-"`), başarılı (`$7==200`)
indirmeleri IP'ye göre say:
""", komut="awk '$4==\"-\" && $5==\"REST.GET.OBJECT\" && $7==200 {print $3}' bulut/depolama/erisim_logu.txt | sort | uniq -c | sort -rn | head -3",
         sonra="""
Bu sayı **tüm** kovalar için. Gerçek soru, yalnızca hassas kovalardan kimin indirdiği: önce satırları
kova adına göre süz.
"""),
    Adim("Düzeltme: üç katman", """
Açığı kapatmanın üç katmanı var:

1. **Açıklığın kendisi:** politikadaki `Principal: *` ifadesini sil, ACL'den `AllUsers` satırını kaldır.
2. **Koruma:** kovada "herkese açık erişimi engelle" ayarını aç; böylece ileride biri yine yanlışlıkla
   açmaya çalışsa bile işe yaramaz.
3. **Veri güvenliğinin temelleri:** varsayılan özel, **şifreleme** (hem dururken hem taşınırken),
   **erişim günlüğü** (kim neye erişti) ve **veri minimizasyonu** (gerekmeyen hassas veriyi hiç tutma).

Meşru erişimi (iç servis) ve bilinçli açık kovayı bozma: yalnızca gereken satırı sil.
"""),
]

GOREVLER = [
    Gorev("Varsayılan olarak özel olan bir depolama kovası **nasıl** herkese açık hale gelir?",
          Secmeli([
              ("Bir yapılandırma hatasıyla: politikada ya da ACL'de herkese izin veren bir ifade eklenerek",
               "Doğru. Kova kendiliğinden açılmaz; birisi politikaya `Principal: *` ya da ACL'ye `AllUsers` ekler."),
              ("Sağlayıcı kovaları belirli bir süre sonra otomatik olarak herkese açar",
               "Yanlış. Sağlayıcı böyle bir şey yapmaz; açıklık müşterinin yapılandırmasından gelir."),
              ("Kovanın adı çok uzun olduğu için sistem koruma ayarını kendiliğinden kapatır",
               "Yanlış. Kova adının uzunluğunun erişim ayarıyla ilgisi yoktur."),
              ("Bir saldırgan yalnızca kova adını tahmin ederek içindeki dosyaları özel bir kova olsa da okur",
               "Yanlış. Özel kovada tahmin edilen ad tek başına yetmez; izin yapılandırmasında bir açıklık gerekir."),
          ], dogru=0),
          ("İzinleri kim tanımlar?",
           "Hangi iki dosyada izin ifadeleri var?",
           "Politika ya da ACL'ye yanlış ifade eklenir."),
          puan=20, baslik="Nasıl açılır"),
    Gorev("**Hassas** veri taşıyıp **herkese açık** (politika ya da ACL yoluyla) olan kovalar hangileri? "
          "(Bilinçli olarak açık olan kovayı yazma.)",
          Kume("acik_hassas", sik_hatalar=_acik_hata, bicim="kova adları, virgülle ayrılmış"),
          ("`kovalar.csv`'de `hassas` olanlara bak, sonra her birinin hem politikasına hem ACL'sine.",
           "Politikada `Principal` `*` olan `Allow`, ACL'de `AllUsers`.",
           "`grep -l 'AllUsers' bulut/depolama/kovalar/*.acl.txt` ve `grep -n '\"\\*\"' bulut/depolama/kovalar/*.politika.json`; hassas olanları seç."),
          puan=40, baslik="Açık hassas kovalar"),
    Gorev("Hassas kovalardan **en çok dosya indiren dış IP** hangisi? (Anonim, başarılı `GET`'ler.)",
          IP("tarayici", sik_hatalar=_ip_hata),
          ("Önce satırları hassas kova adlarına göre süz, sonra IP'ye göre say.",
           "Statik site ziyaretçisi çok istek yapar ama hassas veriyle ilgisi yoktur.",
           "`awk '($1==\"HASSAS1\"||$1==\"HASSAS2\") && $4==\"-\" && $5==\"REST.GET.OBJECT\" && $7==200 {print $3}' bulut/depolama/erisim_logu.txt | sort | uniq -c | sort -rn | head -3`"),
          puan=40, baslik="Toplu indirme"),
    Gorev("O IP hassas kovalardan **kaç farklı dosya** indirdi? (Başarılı, `200`; aynı dosyayı iki kez "
          "indirdiyse bir say.)",
          Sayi("tarama_say"),
          ("Satır sayısı değil, benzersiz (kova, dosya) çifti sayısı.",
           "Süzdüğün satırlarda 1. ve 6. sütunu birlikte benzersizleştir.",
           "`... | awk '$3==\"IP\" {print $1, $6}' | sort -u | wc -l`"),
          puan=30, baslik="Etkilenen dosya sayısı"),
    Gorev("`<<politikayla>>` kovası **politikayla** açılmış. Herkese izin veren ifadeyi sil; iç servisin "
          "okumasına dokunma. Bitince `cevap 5`.",
          Durum(_politika_kontrol, "HerkesOkusun ifadesi silinir; IcOkuma kalır; statik site kovası değişmez"),
          ("Politikada iki ifade var: biri meşru, biri fazla.",
           "`Sid: HerkesOkusun` olan, `Principal` `*` olan ifade.",
           "`nano bulut/depolama/kovalar/<<politikayla>>.politika.json` ile ifadeyi sil; sonra `python3 -m json.tool` ile JSON'u doğrula."),
          puan=50, baslik="Politikayı kapat"),
    Gorev("`<<aclyle>>` kovası **ACL ile** açılmış. `AllUsers` satırını sil; sahibin kendi izni kalsın. Bitince `cevap 6`.",
          Durum(_acl_kontrol, "AllUsers satırı silinir; sahip FULL_CONTROL kalır"),
          ("ACL dosyası çok kısa; hangi satır fazla?",
           "`Grant: AllUsers READ` satırı.",
           "`sed -i '/AllUsers/d' bulut/depolama/kovalar/<<aclyle>>.acl.txt`"),
          puan=40, baslik="ACL'yi kapat"),
    Gorev("`ayarlar.json` içinde **iki hassas kovayı** (`<<hassas1>>`, `<<hassas2>>`) güvenceye al: "
          "`sifreleme` `aes256`, `erisim_gunlugu` `true`, `herkese_acik_engeli` `true`. Statik site "
          "kovasına dokunma. Bitince `cevap 7`.",
          Durum(_ayar_kontrol, "hassas kovalarda sifreleme=aes256, erisim_gunlugu=true, herkese_acik_engeli=true"),
          ("Her kova tek satırda; ilgili iki satırı düzenle.",
           "Üç alan: şifreleme, erişim günlüğü, herkese açık erişim engeli. Statik site kovasında engel **kapalı** kalmalı.",
           "`sed -i '/\"kova\": \"KOVA\"/ s/\"sifreleme\": \"yok\"/\"sifreleme\": \"aes256\"/' bulut/depolama/kovalar/ayarlar.json` (diğer iki alan için benzer)."),
          puan=50, baslik="Şifreleme ve günlük"),
    Gorev("Açık bir depolama kovası, Cilt 1'deki hangi açığın bulut ölçeğindeki halidir?",
          Secmeli([
              ("Herkese açık unutulmuş `.bak` yedek dosyasının",
               "Doğru. Aynı hata; ama bulutta tek kovada milyonlarca kayıt olabilir."),
              ("Komut geçmişinde (`.bash_history`) kalmış parolanın",
               "Yanlış. O, gizli bilginin yanlış yerde durmasıdır; kovanın herkese açılmasıyla aynı türden değil."),
              ("Dosya izinlerinin yanlışlıkla `000` yapılmasının",
               "Yanlış. Bu, erişimi aşırı kısıtlar; açıklık değildir."),
              ("Bir kullanıcının `sudo` grubundan çıkarılmasının",
               "Yanlış. Bu bir yetki azaltmadır, veri açığı değil."),
          ], dogru=0),
          ("Cilt 1 ve 5'te web sunucusunda açık bırakılan dosyaları hatırla.",
           "Hata aynı, ölçek farklı.",
           "Açık bırakılmış `.bak` yedek dosyası."),
          puan=20, baslik="Eski hatanın büyük hali"),
    Gorev("Aşağıdakilerden hangisi veri güvenliğinin dört temel kontrolünden **biri değildir**?",
          Secmeli([
              ("Kovayı herkese açık tutmak ve erişim günlüğünü kapatmak",
               "Doğru cevap (temel kontrol değil). Temel kontroller: varsayılan özel, şifreleme, erişim günlüğü, veri minimizasyonu."),
              ("Varsayılan olarak özel kova: kaynak gereksiz yere açılmaz",
               "Bu bir temel kontroldür: varsayılan özel."),
              ("Verinin hem dururken hem taşınırken şifrelenmesi",
               "Bu bir temel kontroldür: şifreleme."),
              ("Gereksiz hassas verinin hiç tutulmaması (veri minimizasyonu)",
               "Bu bir temel kontroldür: veri minimizasyonu."),
          ], dogru=0),
          ("Dört kontrol: özel, şifreli, kayıtlı, minimum.",
           "Hangisi güvenliğin tersini söylüyor?",
           "Sürekli açık tutmak ve günlüğü kapatmak temel kontrol olamaz."),
          puan=20, baslik="Dört temel kontrol"),
]


def _kapanis():
    return """
Açık kova, saldırgan için bedava bir hazinedir: tahmin edilebilir kova adları ve sızmış bağlantılarla
bulunur, tek bir yanlış ayar bütün müşteri verisini herkese açar. Savunma dersi: varsayılanı özel
tut, iki yere de bak (politika **ve** ACL), herkese açık erişimi kova düzeyinde engelle, veriyi şifrele,
erişim günlüğünü aç ve günlüğü gerçekten oku: bir IP'nin hassas kovadan onlarca farklı dosya indirmesi
bir alarmdır. Bilinçli açık kovaları (statik site) belgele ki gerçek açıklarla karışmasın.
"""


SEVIYE = Seviye(
    kimlik="c12b03",
    cilt=12,
    bolum=3,
    baslik="Depolama ve Veri Açıkları",
    brifing="""
Deniz'in sesi acele: "**<<musteri>>**. <<sahne>> Elimizde kovaların politika ve ACL dosyaları, ayar
listesi ve bir erişim logu var. Üç sorunun cevabı lazım: hangi hassas kova açık, dışarıdan kim ne
indirdi, ve açığı nasıl kapatırız?"

Selin ekliyor: "Dikkat: statik site kovası bilinçli olarak herkese açık. Yanlışlıkla onu kapatırsan
müşterinin web sitesi çöker. Düzeltmeyi cerrah gibi yap."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Açık kovalar:** Yanlış yapılandırılmış, herkese açık bulut depolama kovaları nedeniyle
  müşteri verilerinin açığa çıktığı olaylar güvenlik haberlerinde ve araştırmacı raporlarında
  defalarca yer almıştır. Sağlayıcılar bu yüzden "herkese açık erişimi engelle" ayarlarını
  sunar ve yeni kovalarda varsayılan olarak etkinleştirir.
- **Capital One 2019:** Kamuya açıklanan bilgilere göre saldırgan, buluttaki depolama alanlarından
  veri indirdi. Bu bölümdeki erişim logu okuma becerisi (kim, hangi dosyayı, kaç kez, anonim mi)
  böyle bir indirmenin boyutunu anlamanın temelidir.
- **Tespit ve önleme:** Erişim günlüklerini açık tutmak, tek bir istemciden olağandışı sayıda
  farklı nesne indirmesine alarm kurmak, CSPM araçlarıyla herkese açık kovaları sürekli taramak
  ve herkese açık erişim engelini hesap düzeyinde açmak en yaygın önerilerdir.
""",
    sure_hedef_dk=40,
)
