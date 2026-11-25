"""Cilt 19 · Bölüm 3 — Saldırı Yüzeyi ve Savunma (API ağ geçidi yapılandırması).

Beceri: kurgusal bir açık bankacılık API ağ geçidinin yapılandırmasında riskli ayarları (imzasız token kabulü,
`alg: none`, süre/hedef kitle kontrolü yok, kapsam ve nesne sahipliği kontrolü yok, hız sınırı yok, uzun ömürlü
token, token'ı loga yazma) bulup düzeltmek. Ayarlar ana dosyada ve `gateway.d/` altındaki ek dosyalarda olabilir;
**son okunan değer geçerlidir**. `cevap <no>` komutu yapılandırmanın son halini kontrol eder (Durum görevleri).

Vakalar: üç banka. Her vakada bir ayar ek dosyada, ana dosyadan farklı bir değerle ezilmiş durumdadır.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c19_acik_bankacilik.ortak import sec_doldur, sh

KLASOR = "api_gecidi"

# anahtar: (riskli değer, ezilme durumunda ana dosyada görünen 'iyi' değer)
KOTU = {
    "jwt_imza_dogrula": ("hayir", "evet"),
    "jwt_izinli_alg": ("RS256,none", "RS256"),
    "jwt_exp_kontrol": ("hayir", "evet"),
    "jwt_aud_kontrol": ("hayir", "evet"),
    "kapsam_kontrolu": ("kapali", "acik"),
    "nesne_sahiplik_kontrolu": ("kapali", "acik"),
    "hiz_siniri_dk": ("0", "120"),
    "token_omru_sn": ("86400", "600"),
    "token_logla": ("evet", "hayir"),
}
SIRA = list(KOTU)

VAKALAR = [
    {"vaka": "Ferah Bank — açık API ağ geçidi", "banka": "Ferah Bank", "ezilen": "hiz_siniri_dk",
     "ek": "90-test-ortami.conf", "kisi": "Kaan Bey (bilgi güvenliği müdürü)",
     "sahne": "Ferah Bank'ın açık bankacılık ağ geçidi, sızma testi öncesi yapılandırma incelemesinden geçiyor. Kaan "
              "Bey: \"Ayar dosyası ana dosyadan ibaret değil; bir de `gateway.d` klasörü var, ona kimse "
              "bakmıyor.\""},
    {"vaka": "Yıldız Bank — ödeme API'si", "banka": "Yıldız Bank", "ezilen": "jwt_izinli_alg",
     "ek": "50-uyumluluk.conf", "kisi": "Defne Hanım (API ürün sahibi)",
     "sahne": "Yıldız Bank'ın ödeme API'sinde, eski bir ortakla uyumluluk için yapılan bir ayar yıllardır duruyor. "
              "Defne Hanım: \"Hangi ayarlar riskli, hangisi kimin eski kalıntısı, çıkaramıyorum; bir bakar mısın?\""},
    {"vaka": "Kuzgun Katılım — hesap bilgisi API'si", "banka": "Kuzgun Katılım", "ezilen": "kapsam_kontrolu",
     "ek": "10-gecici.conf", "kisi": "Serdar Bey (entegrasyon sorumlusu)",
     "sahne": "Kuzgun Katılım'da bir entegrasyon hatası sırasında birisi 'geçici' bir ayar eklemiş ve geri almayı "
              "unutmuş. Serdar Bey: \"Kapsam kontrolü açık görünüyor ama bir şey yanlış; ağ geçidinin gerçekte ne "
              "yaptığını bilmem gerek.\""},
]


def uret(rng):
    v = rng.choice(VAKALAR)
    return {
        "vaka": v["vaka"], "v": v,
        "metin": {"banka": v["banka"], "sahne": v["sahne"], "kisi": v["kisi"], "klasor": KLASOR, "ek": v["ek"],
                  "ezilen": v["ezilen"]},
        "cevaplar": {"ornek": u.bayrak(rng, "yapilandirma")},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = lab / KLASOR
    u.yaz(lab / "OKUBENI.txt", f"{v['banka']} API ağ geçidi yapılandırma kopyası (kurgusal).\n"
          f"{KLASOR}/gateway.conf ve {KLASOR}/gateway.d/*.conf düzenlenebilir; her düzeltmeden sonra "
          "`cevap <görev no>` ile kontrol et.\n")
    ana = ["# Ağ geçidi ana yapılandırması",
           "# Önce bu dosya, sonra gateway.d/*.conf alfabetik sırayla okunur; SON OKUNAN DEĞER GEÇERLİDİR.",
           "tls_min_surum=1.2", "cors_izinli_kaynak=https://portal." + v["banka"].split()[0].lower() + ".lab"]
    for ad in SIRA:
        kotu, iyi = KOTU[ad]
        ana.append(f"{ad}={iyi if ad == v['ezilen'] else kotu}")
    u.yaz(k / "gateway.conf", "\n".join(ana) + "\n")
    kotu, _ = KOTU[v["ezilen"]]
    u.yaz(k / "gateway.d" / v["ek"],
          f"# test ortamından kalma / geçici ayar\n{v['ezilen']}={kotu}\n")
    u.yaz(k / "gateway.d" / "99-bos.conf", "# (bilerek boş)\n")


# ----------------------------------------------------------------------------- etkin ayar okuma


def _etkin(lab: Path) -> dict:
    dosyalar = [lab / KLASOR / "gateway.conf"] + sorted((lab / KLASOR / "gateway.d").glob("*.conf"))
    ayar = {}
    for d in dosyalar:
        try:
            satirlar = d.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for satir in satirlar:
            satir = satir.strip()
            if satir and not satir.startswith("#") and "=" in satir:
                a, de = satir.split("=", 1)
                ayar[a.strip()] = de.strip()
    return ayar


def _ezen_ipucu(b, anahtar: str) -> str:
    """Ayarı ana dosya dışında bir dosya ezmişse oyuncuya hatırlat."""
    ek = b.senaryo["v"]["ek"]
    if anahtar == b.senaryo["v"]["ezilen"]:
        return f" (İpucu: `{anahtar}` birden çok dosyada tanımlı; **son okunan** geçerli. `grep -rn {anahtar} {KLASOR}`)"
    return ""


def _imza_kontrol(b) -> Sonuc:
    a = _etkin(b.lab)
    if a.get("jwt_imza_dogrula") != "evet":
        return Sonuc(False, "Ağ geçidi token imzasını doğrulamıyor (`jwt_imza_dogrula=evet` olmalı)." + _ezen_ipucu(b, "jwt_imza_dogrula"))
    algler = [x.strip().lower() for x in a.get("jwt_izinli_alg", "").split(",") if x.strip()]
    if "none" in algler:
        return Sonuc(False, "İzinli algoritmalar arasında `none` (imzasız token) var." + _ezen_ipucu(b, "jwt_izinli_alg"), yakin=True)
    if not algler:
        return Sonuc(False, "İzinli algoritma listesi boş; en az bir gerçek algoritma (örn. RS256) bırak.")
    return Sonuc(True, "İmza doğrulaması açık ve `none` algoritması kabul edilmiyor.")


def _sure_aud_kontrol(b) -> Sonuc:
    a = _etkin(b.lab)
    eksik = [k for k in ("jwt_exp_kontrol", "jwt_aud_kontrol") if a.get(k) != "evet"]
    if eksik:
        return Sonuc(False, f"Hâlâ kapalı: {', '.join(eksik)}. Süresi geçmiş ve başka API için üretilmiş token'lar kabul ediliyor.",
                     yakin=len(eksik) == 1)
    return Sonuc(True, "Süre (`exp`) ve hedef kitle (`aud`) kontrolü açık.")


def _kapsam_kontrol(b) -> Sonuc:
    a = _etkin(b.lab)
    eksik = [k for k in ("kapsam_kontrolu", "nesne_sahiplik_kontrolu") if a.get(k) != "acik"]
    if eksik:
        ipucu = "".join(_ezen_ipucu(b, k) for k in eksik)
        return Sonuc(False, f"Hâlâ kapalı: {', '.join(eksik)} (`acik` olmalı)." + ipucu, yakin=len(eksik) == 1)
    return Sonuc(True, "Kapsam ve nesne sahipliği (BOLA) kontrolü açık.")


def _hiz_kontrol(b) -> Sonuc:
    a = _etkin(b.lab)
    try:
        n = int(a.get("hiz_siniri_dk", "0"))
    except ValueError:
        return Sonuc(False, "`hiz_siniri_dk` bir sayı olmalı.")
    if n <= 0:
        return Sonuc(False, "Hız sınırı yok (0 = sınırsız)." + _ezen_ipucu(b, "hiz_siniri_dk"))
    if n > 600:
        return Sonuc(False, "Sınır var ama çok yüksek; dakikada en fazla 600 istek olsun.", yakin=True)
    return Sonuc(True, f"Hız sınırı etkin: dakikada {n} istek.")


def _omur_kontrol(b) -> Sonuc:
    a = _etkin(b.lab)
    try:
        n = int(a.get("token_omru_sn", "0"))
    except ValueError:
        return Sonuc(False, "`token_omru_sn` bir sayı olmalı.")
    if n > 900 or n < 60:
        return Sonuc(False, f"Token ömrü {n} sn. 60 ile 900 sn (15 dk) arasında olmalı: kısa ömür, çalınan token'ın hasarını sınırlar.",
                     yakin=False)
    if a.get("token_logla") != "hayir":
        return Sonuc(False, "Token'ın kendisi günlüğe yazılıyor (`token_logla=hayir` olmalı): günlüğü okuyan herkes token'ı kullanabilir.",
                     yakin=True)
    return Sonuc(True, "Token ömrü kısa ve token'lar günlüğe yazılmıyor.")


def coz(lab: Path, s: dict) -> dict:
    def ayarla(anahtar: str, deger: str) -> None:
        sh(f"sed -i 's/^{anahtar}=.*/{anahtar}={deger}/' {KLASOR}/gateway.conf {KLASOR}/gateway.d/*.conf", lab)

    ayarla("jwt_imza_dogrula", "evet")
    ayarla("jwt_izinli_alg", "RS256")
    ayarla("jwt_exp_kontrol", "evet")
    ayarla("jwt_aud_kontrol", "evet")
    ayarla("kapsam_kontrolu", "acik")
    ayarla("nesne_sahiplik_kontrolu", "acik")
    ayarla("hiz_siniri_dk", "100")
    ayarla("token_omru_sn", "600")
    ayarla("token_logla", "hayir")
    return sec_doldur({2: "", 3: "", 4: "", 5: "", 6: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Yapılandırmanın yeri", """
Bir API ağ geçidi (gateway) tüm isteklerin önünde duran kapıcıdır: token'ı doğrular, kapsamı denetler, hızı
sınırlar. Bu kapıcının davranışı **yapılandırma** dosyalarından gelir. Klasöre bak:
""", komut="ls -R <<klasor>>", sonra="""
Ana dosyanın yanında `gateway.d/` adlı bir klasör var. Bu tür "ek ayar" klasörleri sistemlerde yaygındır ve
unutulur: kimse ana dosyaya bakıp işi bitirdiğini sanmasın.
"""),
    Adim("Ana yapılandırmayı okumak", """
Ayarlar `anahtar=değer` biçiminde. `#` ile başlayan satırlar yorumdur. Başlıktaki kurala dikkat:
""", komut="cat <<klasor>>/gateway.conf", sonra="""
"**Son okunan değer geçerlidir.**" Önce ana dosya, sonra `gateway.d/` altındaki dosyalar alfabetik sırayla
okunur. Ana dosyada **doğru görünen** bir ayar, sonradan başka bir dosyada ezilmiş olabilir.
"""),
    Adim("Ek dosyalar", """
Şimdi ek dosyalara bak. Dosya adlarındaki sayılar okuma sırasını belirler:
""", komut="cat <<klasor>>/gateway.d/*.conf", sonra="""
**Hacker gözüyle:** Sızma testinde "yapılandırma doğru görünüyor" demek yetmez; **etkin** (gerçekte uygulanan)
yapılandırmayı bulmak gerekir. İlk dosyaya bakıp bırakanlar, ezilen ayarı kaçırır.
"""),
    Adim("Etkin değeri bulmak", """
Bir ayarın **tüm** tanımlarını sırayla listele ve **sonuncuya** bak. `grep -h` dosya adını gizler, `tail -1`
son satırı alır:
""", komut="grep -h '^token_omru_sn=' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf | tail -1", sonra="""
Aynı komutu `hiz_siniri_dk`, `kapsam_kontrolu`, `jwt_izinli_alg` için de dene; birinde ana dosyayla
ek dosya farklı değer taşıyor.
"""),
    Adim("Her yerde aramak", """
`grep -rn` bir klasörün altındaki her dosyada arar ve satır numarasını gösterir. Riskli bir değeri
(örneğin `none` algoritmasını) her yerde ara:
""", komut="grep -rn 'none' <<klasor>>", sonra="""
Riskli değerlerin listesi: imza doğrulaması kapalı, `none` algoritmasına izin, `exp`/`aud` kontrolü yok,
kapsam ve nesne sahipliği kontrolü yok, hız sınırı yok, çok uzun token ömrü, token'ın günlüğe yazılması.
"""),
    Adim("sed ile düzeltmek", """
`sed -i 's/eski/yeni/' dosya` dosyayı yerinde değiştirir. Önce **ne değişecek** diye bak: `-n` ve `p` yalnızca
değişen satırı basar, dosyaya dokunmaz:
""", komut="sed -n 's/^token_logla=.*/token_logla=hayir/p' <<klasor>>/gateway.conf", sonra="""
Bir ayar birden çok dosyada tanımlıysa, **etkin olanı** (sonuncusunu) düzeltmen gerekir. En kolayı hepsini
düzeltmek: `sed -i '...' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`. Her düzeltmeden sonra `cevap` ile
kontrol et.
"""),
]

GOREVLER = [
    Gorev("Bir fintech'in **yalnızca okuma** kapsamlı token'ıyla ödeme başlatabildiği bir API'de asıl sorun nedir?",
          Secmeli([
              ("Sunucu kapsamı denetlemiyor: istek, token'daki kapsamla karşılaştırılmıyor",
               "Doğru. Cilt 5'teki erişim kontrolü açığının token'daki hâli: yetki sunucuda zorlanmıyor."),
              ("Token çok kısa ömürlü olduğu için fintech sürekli yenisini alıp işlem yapabiliyor",
               "Yanlış. Kısa ömür bir savunmadır; sorun, token'ın kapsamının hiç denetlenmemesi."),
              ("Banka ile fintech arasındaki bağlantı şifrelenmediği için kapsam bilgisi değişiyor",
               "Yanlış. Taşıma şifreleme ayrı bir konu; burada kapsam sunucuda hiç kontrol edilmiyor."),
              ("Fintech, müşteriden fazla rıza almış olduğu için ödemeye izni var ve bu normal",
               "Yanlış. Rıza yalnızca okumayı kapsıyorsa ödeme izni yoktur; sunucu bunu reddetmelidir."),
          ], dogru=0),
          ("Token'daki kapsam kime ne izin verdiğini söyler; ama onu kim zorlar?",
           "Kapsamı sunucu her istekte denetlemezse token'ın kapsamı süs olur.",
           "Cevap: kapsam kontrolü yok."),
          puan=20, baslik="Kapsam neden önemli"),
    Gorev("Ağ geçidi token imzasını doğrulamıyor ya da imzasız (`none`) token'ı kabul ediyor. **Etkin** ayarları düzelt: "
          "imza doğrulaması açık, izinli algoritmalar arasında `none` yok. Sonra `cevap 2`.",
          Durum(_imza_kontrol, "jwt_imza_dogrula=evet ve jwt_izinli_alg=RS256 (etkin değer)"),
          ("İki ayar var: `jwt_imza_dogrula` ve `jwt_izinli_alg`. Biri birden çok dosyada olabilir.",
           "`grep -rn jwt_ <<klasor>>` ile hepsini gör; sonuncu tanım geçerli.",
           "`sed -i 's/^jwt_imza_dogrula=.*/jwt_imza_dogrula=evet/;s/^jwt_izinli_alg=.*/jwt_izinli_alg=RS256/' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`"),
          puan=40, baslik="İmza doğrulaması"),
    Gorev("Süresi geçmiş ve başka bir API için üretilmiş token'lar kabul ediliyor. `exp` ve `aud` kontrolünü aç. "
          "Sonra `cevap 3`.",
          Durum(_sure_aud_kontrol, "jwt_exp_kontrol=evet ve jwt_aud_kontrol=evet"),
          ("İki ayarın adı `exp` ve `aud` kelimelerini içeriyor.",
           "`grep -rn 'exp_\\|aud_' <<klasor>>` ile bul; değerleri `evet` yap.",
           "`sed -i 's/^jwt_exp_kontrol=.*/jwt_exp_kontrol=evet/;s/^jwt_aud_kontrol=.*/jwt_aud_kontrol=evet/' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`"),
          puan=40, baslik="Süre ve hedef kitle"),
    Gorev("Kapsam kontrolü ve nesne sahipliği (BOLA: başka müşterinin hesabına erişme) kontrolü kapalı. **Etkin** "
          "değerlerini `acik` yap. Sonra `cevap 4`.",
          Durum(_kapsam_kontrol, "kapsam_kontrolu=acik ve nesne_sahiplik_kontrolu=acik"),
          ("İki ayar var; biri ana dosyada doğru görünüp başka bir dosyada ezilmiş olabilir.",
           "Her iki ayarı `grep -rn` ile bütün dosyalarda ara; sonuncu tanımı düzelt.",
           "`sed -i 's/^kapsam_kontrolu=.*/kapsam_kontrolu=acik/;s/^nesne_sahiplik_kontrolu=.*/nesne_sahiplik_kontrolu=acik/' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`"),
          puan=40, baslik="Kapsam ve BOLA"),
    Gorev("Hız sınırı yok: bir fintech (ya da onu ele geçiren biri) saniyede binlerce istek atabilir. `hiz_siniri_dk` "
          "değerini 1 ile 600 arasında bir sayı yap (0 sınırsız demek). Sonra `cevap 5`.",
          Durum(_hiz_kontrol, "hiz_siniri_dk=100 (etkin değer)"),
          ("Ayarın adı `hiz_siniri_dk`; ana dosyaya bakıp geçme.",
           "`grep -rn hiz_siniri_dk <<klasor>>` kaç yerde tanımlı gösterir; hangisi son okunuyor?",
           "`sed -i 's/^hiz_siniri_dk=.*/hiz_siniri_dk=100/' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`"),
          puan=40, baslik="Hız sınırı"),
    Gorev("Token ömrü 24 saat ve token'ın kendisi günlüğe yazılıyor. Ömrü 60-900 saniye arasına çek ve token'ı "
          "günlüğe yazmayı kapat (`token_logla=hayir`). Sonra `cevap 6`.",
          Durum(_omur_kontrol, "token_omru_sn=600 ve token_logla=hayir"),
          ("İki ayar: `token_omru_sn` ve `token_logla`.",
           "Ömür saniye cinsinden; 15 dakika = 900 sn. Günlükte token'ın bulunması neden tehlikeli, düşün.",
           "`sed -i 's/^token_omru_sn=.*/token_omru_sn=600/;s/^token_logla=.*/token_logla=hayir/' <<klasor>>/gateway.conf <<klasor>>/gateway.d/*.conf`"),
          puan=40, baslik="Ömür ve günlük"),
    Gorev("Güçlü müşteri doğrulama (SCA) açık bankacılıkta hangi saldırıyı etkisizleştirir?",
          Secmeli([
              ("Çalınmış tek bir parolanın ya da token'ın tek başına ödeme yaptırabilmesini",
               "Doğru. Önemli işlemde ikinci bir faktör istenirse çalınan tek bilgi yetmez."),
              ("Ağ trafiğinin dinlenmesini; SCA sayesinde veri artık ağda hiç görünmez",
               "Yanlış. Trafik şifrelemesi ayrı bir önlemdir; SCA, kimlik doğrulamayı güçlendirir."),
              ("Fintech uygulamasındaki bütün yazılım hatalarını; SCA onları kendiliğinden kapatır",
               "Yanlış. SCA kimlik doğrulama katmanıdır; uygulama hataları ayrıca düzeltilmelidir."),
              ("Bankanın sunucularına yönelik hizmet reddi saldırılarını ve aşırı yüklenmeyi",
               "Yanlış. Hizmet reddine karşı hız sınırı ve kapasite önlemleri gerekir."),
          ], dogru=0),
          ("SCA'nın açılımını hatırla: güçlü müşteri doğrulama, çok faktör.",
           "Bir saldırgan yalnızca parolayı ya da token'ı çalmışsa ne eksik kalır?",
           "Cevap: tek bilginin yetmemesi."),
          puan=20, baslik="SCA"),
]


def _kapanis():
    return """
Ağ geçidi, açık bankacılığın **tek kapısıdır**: imza, süre, hedef kitle, kapsam, nesne sahipliği ve hız sınırı
birlikte çalışmazsa tek bir açık yeter. Saldırgan gözüyle en cazip hata, "doğru görünen ama başka dosyada ezilmiş"
ayarlardır; savunma gözüyle **etkin yapılandırmayı** doğrulamak, yalnızca dosyaya bakmaktan farklıdır. Yapılandırma
değişikliklerini gözden geçirmek, test ayarlarını üretime taşımamak ve güçlü müşteri doğrulamayı unutmamak, bu
bölümün özetidir.
"""


SEVIYE = Seviye(
    kimlik="c19b03", cilt=19, bolum=3, baslik="Saldırı Yüzeyi ve Savunma: Ağ Geçidini Düzelt",
    brifing="""
<<sahne>>

Selin: "Bu kez bulgu yazmayacaksın, **düzelteceksin**. Yapılandırma kopyası `<<klasor>>` klasöründe. Altı alanı
kapatacağız: imza, süre ve hedef kitle, kapsam ve BOLA, hız, token ömrü. Dikkat: bir ayar ana dosyada doğru
görünüyor ama başka bir dosya onu eziyor."

Deniz: "Ağ geçidi o dosyaları nasıl okuyorsa sen de öyle oku: sırayla, sonuncusu kazanır."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Yapılandırma kalıntıları:** Pek çok sızma testi raporunda, test ortamından kalan geçici ayarların üretimde aktif
  kalması sık görülen bir bulgudur. Bu yüzden yapılandırma, dosyaya bakarak değil **etkin değeri** doğrulayarak
  denetlenir (örneğin ayar yükleyicinin döktüğü birleşik çıktı ya da uygulamadan alınan canlı ayar).
- **BOLA ve kapsam:** OWASP'ın API güvenliği listesinde nesne düzeyinde yetkilendirme eksikliği (BOLA) en
  başta yer alır; bu açıklar API'lerde kamuya açık olarak belgelenmiş olaylarda defalarca görülmüştür. Tespit:
  bir istemcinin kendi dışındaki kayıt kimliklerini art arda denemesi (kimlik sıralı tarama), kapsam dışı isteklerin
  200 dönmesi. Önleme: sahipliğin her istekte sunucuda denetlenmesi.
- **Hız sınırı ve token ömrü:** Hız sınırı hem kaba kuvvet denemelerini hem de ele geçirilmiş bir istemcinin toplu
  veri çekmesini yavaşlatır; kısa token ömrü çalınan token'ın kullanım penceresini daraltır. Günlüklere token
  yazılmaması, günlük erişimini token erişimine dönüştürmemek içindir.
""",
    sure_hedef_dk=35,
)
