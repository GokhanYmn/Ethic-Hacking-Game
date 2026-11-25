"""Cilt 14 · Bölüm 4 — Mobil Savunma ve Lab.

Beceri: kurgusal bir proje dizinindeki savunmasız Android yapılandırmasını DÜZELTMEK: manifest bayrakları,
şifresiz trafik ve ağ güvenliği yapılandırması, korunmasız dışa açık bileşenler, gömülü anahtar, açık metin
token. Ayrıca savunma önlemlerini OWASP MASVS gruplarına eşlemek.

Vakalar: Ferah Bank, Paramix, Kuzey Yatırım, Pazarix. Her şey kurgusaldır; düzeltmeler düz metin dosyalarındadır.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c14_mobil.ortak import (Esle, harfli, hex_, manifest_oku, korunmasiz,
                                           sec_doldur, sh, vaka_sec)

ETKINLIKLER = ["GirisEkrani", "HesapOzeti", "OdemeOnay", "ProfilAyarlari", "KartYonetimi"]
SERVISLER = ["SenkronServisi", "BildirimServisi"]
ALICILAR = ["AcilisAlicisi", "SmsAlicisi"]
SAGLAYICILAR = ["BelgeSaglayici", "DisaAktarSaglayici"]

MASVS = ["MASVS-STORAGE", "MASVS-NETWORK", "MASVS-PLATFORM", "MASVS-RESILIENCE"]
ONLEMLER = {
    "MASVS-STORAGE": ["Oturum token'ını Keystore/Keychain'de saklamak ve cihazda düz metin veri bırakmamak",
                      "Hassas verilerin yedeğe alınmasını kapatmak ve ekran görüntüsü önbelleğini temizlemek"],
    "MASVS-NETWORK": ["Bütün trafiği TLS ile taşımak ve sunucu sertifikasını sabitlemek (pinning)",
                      "Şifresiz HTTP'ye izin veren ağ yapılandırmasını kaldırmak"],
    "MASVS-PLATFORM": ["Bileşenleri varsayılan olarak dışarıya kapatmak, açılması gerekenleri izinle korumak",
                       "Başka uygulamaların tetikleyebildiği ekran ve servisleri izinsiz bırakmamak"],
    "MASVS-RESILIENCE": ["Kök (root) ve kurcalama tespiti ile kod gizlemeyi etkinleştirmek",
                         "Uygulamanın yeniden paketlenip değiştirildiğini algılayan bütünlük kontrolleri eklemek"],
}


def uret(rng):
    v = vaka_sec(rng)
    etk = rng.sample(ETKINLIKLER, 3)
    adaylar = [("activity", etk[0]), ("activity", etk[1]), ("activity", etk[2]),
               ("service", rng.choice(SERVISLER)), ("receiver", rng.choice(ALICILAR)),
               ("provider", rng.choice(SAGLAYICILAR))]
    rng.shuffle(adaylar)
    acik, izinli, kapali = adaylar[:2], adaylar[2], adaylar[3:]
    anahtar = "lab_key_" + hex_(rng, 24)
    tkn, rtk = "tkn_" + hex_(rng, 28), "rtk_" + hex_(rng, 24)
    ogeler = [(rng.choice(ONLEMLER[k]), k) for k in MASVS]
    esle_metni, esle = harfli(rng, ogeler, MASVS)
    return {
        "vaka": f"{v['ad']} — {v['uyg']} yayın öncesi sertleştirme",
        "v": v, "acik": acik, "izinli": izinli, "kapali": kapali,
        "anahtar": anahtar, "tkn": tkn, "rtk": rtk,
        "metin": {"musteri": v["ad"], "uyg": v["uyg"], "paket": v["paket"], "veri": v["veri"],
                  "hikaye": v["hikaye"], "esle": esle_metni},
        "cevaplar": {"esle": esle, "anahtar_dummy": anahtar},
    }


def _bilesen(tur, ad, exported, izin=None) -> str:
    e = f'        <{tur} android:name=".{ad}" android:exported="{exported}"'
    if izin:
        e += f' android:permission="{izin}"'
    return e + "/>"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    p = lab / "proje"
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['uyg']} ({v['paket']}) yayın öncesi proje kopyası. KURGUSAL.\n"
          "Selin'den not: Düzeltmeleri doğrudan proje/ klasöründeki dosyalarda yap; her düzeltmeden sonra `cevap <no>`.\n")
    satirlar = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{v["paket"]}">',
        '    <uses-permission android:name="android.permission.INTERNET"/>',
        f'    <permission android:name="{v["paket"]}.IC_ERISIM" android:protectionLevel="signature"/>',
        '    <application',
        f'        android:label="{v["uyg"]}"',
        '        android:debuggable="true"',
        '        android:allowBackup="true"',
        '        android:usesCleartextTraffic="true"',
        '        android:networkSecurityConfig="@xml/network_security_config">',
        '',
        '        <activity android:name=".AnaEkran" android:exported="true">',
        '            <intent-filter>',
        '                <action android:name="android.intent.action.MAIN"/>',
        '                <category android:name="android.intent.category.LAUNCHER"/>',
        '            </intent-filter>',
        '        </activity>',
    ]
    for tur, ad in s["acik"]:
        satirlar.append(_bilesen(tur, ad, "true"))
    satirlar.append(_bilesen(*s["izinli"], "true", f'{v["paket"]}.IC_ERISIM'))
    for tur, ad in s["kapali"]:
        satirlar.append(_bilesen(tur, ad, "false"))
    satirlar += ["    </application>", "</manifest>", ""]
    u.yaz(p / "AndroidManifest.xml", "\n".join(satirlar))
    u.yaz(p / "res" / "xml" / "network_security_config.xml",
          '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
          '    <base-config cleartextTrafficPermitted="true">\n'
          '        <trust-anchors>\n'
          '            <certificates src="system"/>\n'
          '            <certificates src="user"/>\n'
          '        </trust-anchors>\n'
          '    </base-config>\n'
          '</network-security-config>\n')
    u.yaz(p / "src" / "ApiClient.java.txt",
          "// KURGUSAL kaynak parçası\n"
          f"package {v['paket']}.net;\n\n"
          "public class ApiClient {\n"
          f'    private static final String BASE_URL = "https://{v["api"]}/v2/";\n'
          f'    private static final String API_KEY = "{s["anahtar"]}";\n'
          "}\n")
    u.yaz(p / "cihaz_depo" / "oturum.xml",
          "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n<map>\n"
          f'    <string name="access_token">{s["tkn"]}</string>\n'
          f'    <string name="refresh_token">{s["rtk"]}</string>\n'
          '    <string name="tema">koyu</string>\n'
          "</map>\n")


def coz(lab: Path, s: dict) -> dict:
    m = "proje/AndroidManifest.xml"
    sh(f"sed -i 's/debuggable=\"true\"/debuggable=\"false\"/; s/allowBackup=\"true\"/allowBackup=\"false\"/' {m}", lab)
    c1 = ""
    sh(f"sed -i 's/usesCleartextTraffic=\"true\"/usesCleartextTraffic=\"false\"/' {m}; "
       "sed -i 's/cleartextTrafficPermitted=\"true\"/cleartextTrafficPermitted=\"false\"/; /src=\"user\"/d' "
       "proje/res/xml/network_security_config.xml", lab)
    sh(f"sed -i '/permission/!{{/AnaEkran/!s/exported=\"true\"/exported=\"false\"/}}' {m}", lab)
    sh("sed -i 's/API_KEY = \"[^\"]*\"/API_KEY = BackendOturum.anahtarAl()/' proje/src/ApiClient.java.txt", lab)
    sh("sed -i 's/>tkn_[0-9a-f]*</>keystore:alias=oturum_anahtari</; s/>rtk_[0-9a-f]*</>keystore:alias=yenileme_anahtari</' "
       "proje/cihaz_depo/oturum.xml", lab)
    esle = GOREVLER[5].kontrol.cevabi_goster(Baglam(s, lab, 6))
    return sec_doldur({1: c1, 2: c1, 3: c1, 4: c1, 5: c1, 6: esle}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- durum kontrolleri

def _m(b):
    return manifest_oku(b.lab / "proje" / "AndroidManifest.xml")


def _bayraklar(b) -> Sonuc:
    m = _m(b)
    if m["hata"]:
        return Sonuc(False, m["hata"])
    u_ = m["uygulama"]
    if u_.get("debuggable") == "true":
        return Sonuc(False, "`android:debuggable` hâlâ `true`. Yayın sürümünde hata ayıklama kapalı olmalı.", yakin=True)
    if u_.get("allowBackup") != "false":
        return Sonuc(False, "`android:allowBackup` hâlâ `false` değil. Uygulama verisi yedeğe alınabiliyor.", yakin=True)
    return Sonuc(True)


def _ag(b) -> Sonuc:
    m = _m(b)
    if m["hata"]:
        return Sonuc(False, m["hata"])
    if m["uygulama"].get("usesCleartextTraffic") == "true":
        return Sonuc(False, "Manifest'te `usesCleartextTraffic` hâlâ `true`.")
    yol = b.lab / "proje" / "res" / "xml" / "network_security_config.xml"
    try:
        metin = yol.read_text(encoding="utf-8")
    except OSError:
        return Sonuc(False, "network_security_config.xml okunamadı; dosyayı silme, düzelt.")
    if 'cleartextTrafficPermitted="true"' in metin:
        return Sonuc(False, "network_security_config.xml içinde `cleartextTrafficPermitted=\"true\"` kalmış.", yakin=True)
    if 'src="user"' in metin:
        return Sonuc(False, "Kullanıcı sertifikalarına güven (`src=\"user\"`) hâlâ açık: yayın sürümünde araya giren "
                            "sertifikalar kabul edilmemeli.", yakin=True)
    if "cleartextTrafficPermitted=\"false\"" not in metin:
        return Sonuc(False, "Açık bir `cleartextTrafficPermitted=\"false\"` satırı yok; ayarı silmek yerine `false` yap.")
    return Sonuc(True)


def _bilesenler(b) -> Sonuc:
    m = _m(b)
    if m["hata"]:
        return Sonuc(False, m["hata"])
    bl = m["bilesenler"]
    if not any(x["launcher"] and x["etkili"] for x in bl):
        return Sonuc(False, "Ana ekran (LAUNCHER) bileşeni açık kalmak zorunda; onu kapatma.")
    if len(bl) < 7:
        return Sonuc(False, "Bileşenleri silmişsin; düzeltme bileşeni kaldırmak değil, dışarıya kapatmaktır.")
    acik = [x["ad"] for x in bl if korunmasiz(x)]
    if acik:
        return Sonuc(False, f"Hâlâ dışarıya açık ve izinsiz: {', '.join(acik)}.", yakin=len(acik) < 2)
    return Sonuc(True)


def _anahtar(b) -> Sonuc:
    yol = b.lab / "proje" / "src" / "ApiClient.java.txt"
    try:
        metin = yol.read_text(encoding="utf-8")
    except OSError:
        return Sonuc(False, "ApiClient.java.txt okunamadı; dosyayı silme, anahtarı çıkar.")
    if "lab_key_" in metin:
        return Sonuc(False, "Anahtar hâlâ kaynakta duruyor. Sır, istemci kodunda olmamalı.")
    if "API_KEY" not in metin or "BASE_URL" not in metin:
        return Sonuc(False, "Dosyanın geri kalanını bozmuşsun; yalnızca anahtar değerini çıkar.")
    return Sonuc(True)


def _token(b) -> Sonuc:
    yol = b.lab / "proje" / "cihaz_depo" / "oturum.xml"
    try:
        metin = yol.read_text(encoding="utf-8")
    except OSError:
        return Sonuc(False, "oturum.xml okunamadı.")
    if re.search(r"\b(tkn|rtk)_[0-9a-f]{8,}", metin):
        return Sonuc(False, "Dosyada hâlâ açık metin token var (`tkn_...` / `rtk_...`).")
    if "keystore" not in metin.lower():
        return Sonuc(False, "Token'ı sildin ama nereye taşındığını göstermiyorsun; dosyaya bir `keystore:...` "
                            "referansı yaz (token Keystore'da tutulacak).", yakin=True)
    return Sonuc(True)


ADIMLAR = [
    Adim("Savunma özeti", """
Mobil savunmanın beş ilkesi şunlar:

1. **Arka uçta doğrula:** her kritik kararı sunucuda al.
2. **Cihazda sır tutma:** hassas veriyi açık saklama; Keystore/Keychain kullan.
3. **Güçlü iletişim:** HTTPS + sertifika sabitleme.
4. **İstemci koruması:** kök/kurcalama tespiti, kod gizleme (işi zorlaştırır, durdurmaz).
5. **Minimum veri:** cihazda gereksiz hassas veri bırakma.

Bu seviyede bir yayın öncesi projenin açıklarını **kendin düzelteceksin**. Önce projeye bak:
""", komut="ls -R proje"),
    Adim("OWASP MASVS", """
OWASP MASVS (Mobile Application Security Verification Standard), mobil güvenlik kontrollerini gruplara ayırır:
**STORAGE** (depolama), **CRYPTO** (şifreleme), **AUTH** (kimlik doğrulama), **NETWORK** (iletişim), **PLATFORM**
(işletim sistemiyle etkileşim: bileşenler, izinler), **CODE** (kod kalitesi) ve **RESILIENCE** (dayanıklılık: kök/kurcalama
tespiti, gizleme). Test rehberi MASTG, her kontrolü nasıl sınayacağını anlatır. Bir önlemi doğru gruba koymak, rapora
doğru şekilde yazmanın ilk adımıdır.
"""),
    Adim("Manifest bayraklarını düzeltmek", """
Bir dosyadaki ayarı değiştirmek için `sed -i 's/ESKİ/YENİ/' dosya` kullanabilirsin ya da `nano` ile açıp elle
düzeltebilirsin. Önce hangi bayraklar açık, gör:
""", komut="grep -n -E 'debuggable|allowBackup|usesCleartextTraffic' proje/AndroidManifest.xml"),
    Adim("Ağ yapılandırması", """
Şifresiz trafiği iki yerde kapatırsın: manifest'te `usesCleartextTraffic="false"` ve ağ güvenliği yapılandırmasında
`cleartextTrafficPermitted="false"`. Yayın sürümlerinde ayrıca kullanıcı sertifikalarına güvenilmez (`src="user"` satırı
silinir); yoksa araya giren sertifikalar da kabul edilir.
""", komut="cat proje/res/xml/network_security_config.xml"),
    Adim("Dışarıya açık bileşenler", """
Ana ekran dışında hiçbir bileşenin izinsiz dışarıya açık olmaması gerekir. Hangileri açık?
""", komut="grep -n 'exported=\"true\"' proje/AndroidManifest.xml", sonra="""
Düzeltme: `exported="false"` yap (ya da gerçekten dışarıya açman gerekiyorsa `android:permission` ile koru). Ana ekranın
`exported="true"` olarak kalması gerekir; onu kapatırsan uygulama başlatılamaz.
"""),
    Adim("Gömülü sır ve açık metin token", """
Kaynakta anahtar, cihaz deposunda açık token var. Önce bul:
""", komut="grep -rn -E 'lab_key_|tkn_|rtk_' proje", sonra="""
**Hacker gözüyle:** Anahtarı koddan çıkarmak tek başına yetmez (eski sürümler ortada); gerçek hayatta anahtarı iptal edip
yenilersin. Burada kaynak ve depo düzeltmesini yap; anahtar döndürme sunucu ekibinin işidir. Token'ı silmek yerine
**güvenli depoya taşıdığını** gösteren bir `keystore:...` referansı bırak.
"""),
]

GOREVLER = [
    Gorev("`proje/AndroidManifest.xml` içinde yayın sürümüne yakışmayan iki bayrağı düzelt: `android:debuggable` **`false`** "
          "olsun ve `android:allowBackup` **`false`** olsun. Bitince `cevap 1` yaz.",
          Durum(_bayraklar, "debuggable=\"false\" ve allowBackup=\"false\""),
          ("İki ayar da `<application>` etiketinin içinde.",
           "`sed -i 's/ESKİ/YENİ/' dosya` ile iki değeri de `false` yap ya da `nano proje/AndroidManifest.xml` ile elle düzelt.",
           "`sed -i 's/debuggable=\"true\"/debuggable=\"false\"/; s/allowBackup=\"true\"/allowBackup=\"false\"/' proje/AndroidManifest.xml`"),
          puan=30, baslik="Manifest bayrakları"),
    Gorev("Şifresiz trafiği kapat: manifest'te `usesCleartextTraffic` `false` olsun, `network_security_config.xml` içinde "
          "`cleartextTrafficPermitted` `false` olsun ve **kullanıcı sertifikalarına güveni (`src=\"user\"` satırını) kaldır**. "
          "Bitince `cevap 2`.",
          Durum(_ag, "usesCleartextTraffic=false, cleartextTrafficPermitted=false, src=user satırı silinmiş"),
          ("Üç ayrı yer var: manifest'teki bayrak, ağ yapılandırmasındaki izin ve sertifika satırı.",
           "`sed -i` ile iki `true`'yu `false` yap; `src=\"user\"` içeren satırı `sed -i '/src=\"user\"/d' dosya` ile sil.",
           "`sed -i 's/usesCleartextTraffic=\"true\"/usesCleartextTraffic=\"false\"/' proje/AndroidManifest.xml` ve "
           "`sed -i 's/cleartextTrafficPermitted=\"true\"/cleartextTrafficPermitted=\"false\"/; /src=\"user\"/d' proje/res/xml/network_security_config.xml`"),
          puan=40, baslik="Şifresiz trafiği kapat"),
    Gorev("Ana ekran dışındaki, **izinsiz dışarıya açık iki bileşeni** kapat (`exported=\"false\"`). Ana ekran açık kalsın, "
          "izinle korunan bileşene ve diğerlerine dokunma, hiçbir bileşeni silme. Bitince `cevap 3`.",
          Durum(_bilesenler, "izinsiz ve LAUNCHER olmayan exported bileşenler exported=\"false\" yapılmış"),
          ("`exported=\"true\"` olan satırları listele; hangisi ana ekran, hangisi izinli?",
           "`grep -n 'exported=\"true\"' proje/AndroidManifest.xml`: `.AnaEkran` ve `android:permission` taşıyan hariç iki satır kalır.",
           "`nano proje/AndroidManifest.xml` ile bu iki satırdaki `\"true\"` değerini `\"false\"` yap."),
          puan=40, baslik="Bileşenleri kapat"),
    Gorev("`proje/src/ApiClient.java.txt` içindeki **gömülü API anahtarını kaynak koddan çıkar** (değeri sil; dosyanın "
          "geri kalanını bozma). Bitince `cevap 4`.",
          Durum(_anahtar, "API_KEY değeri kaynaktan çıkarılmış"),
          ("Anahtar `lab_key_` ile başlayan bir dizgidir.",
           "`grep -n lab_key_ proje/src/ApiClient.java.txt` satırı gösterir; değeri başka bir ifadeyle (örn. çalışma anında sunucudan alınan) değiştir.",
           "`sed -i 's/API_KEY = \"[^\"]*\"/API_KEY = BackendOturum.anahtarAl()/' proje/src/ApiClient.java.txt`"),
          puan=35, baslik="Gömülü anahtarı çıkar"),
    Gorev("`proje/cihaz_depo/oturum.xml` dosyasında **açık metin token'lar** var. Token değerlerini sil ve yerlerine "
          "Keystore'daki kaydın referansını yaz (örneğin `keystore:alias=oturum_anahtari`). `tema` satırına dokunma. "
          "Bitince `cevap 5`.",
          Durum(_token, "tkn_/rtk_ değerleri silinmiş, yerine keystore: referansı yazılmış"),
          ("İki satırda token var: `access_token` ve `refresh_token`.",
           "Değerleri `keystore:alias=...` gibi bir referansla değiştir; asıl token Keystore'da şifreli durur.",
           "`sed -i 's/>tkn_[0-9a-f]*</>keystore:alias=oturum_anahtari</; s/>rtk_[0-9a-f]*</>keystore:alias=yenileme_anahtari</' proje/cihaz_depo/oturum.xml`"),
          puan=40, baslik="Token'ı güvenli depoya taşı"),
    Gorev("Aşağıdaki dört savunma önlemini OWASP MASVS gruplarına eşle (örn. `1b 2a 3d 4c`):\n\n<<esle>>",
          Esle("esle"),
          ("Her önlemin korunan şeyi nedir: veri deposu, ağ hattı, işletim sistemi arayüzü, uygulamanın dayanıklılığı?",
           "STORAGE depolama, NETWORK iletişim, PLATFORM bileşen/izin, RESILIENCE kök-kurcalama tespiti ve gizleme.",
           "Önce kolay olanları eşle (Keystore → depolama, TLS → iletişim), kalan ikisini bileşen/izin ve dayanıklılık olarak ayır."),
          puan=35, baslik="MASVS eşleme"),
    Gorev("Kök (root) tespiti ve kod gizleme gibi **istemci korumaları neden tek başına yeterli değildir**?",
          Secmeli([
              ("Çalışırken müdahale eden araçlarla atlanabilirler; asıl güvenlik arka uçtadır",
               "Doğru. İstemci tamamen saldırganın elindedir; korumalar işi zorlaştırır ama durdurmaz."),
              ("Yalnızca eski telefon modellerinde ve eski Android sürümlerinde çalışırlar, yenilerinde işe yaramaz",
               "Yanlış. Sorun cihaz modeli değil, istemcinin saldırganın kontrolünde olmasıdır."),
              ("Uygulamayı çok yavaşlatırlar, bu yüzden kullanıcılar uygulamayı silip başka uygulamaya geçer",
               "Yanlış. Performans bir maliyet olabilir ama güvenlik yetersizliğinin nedeni değildir."),
              ("Mağaza kuralları bu korumaların kullanılmasını yasakladığı için uygulama yayımlanamaz",
               "Yanlış. Mağazalar bu korumaları yasaklamaz; sınırlarının teknik olduğunu bilmek gerekir."),
          ], dogru=0),
          ("Cilt 5'teki 'istemciye asla güvenme' ilkesini hatırla.",
           "Çalışan bir uygulamaya müdahale eden araçlar var; korumayı da atlayabilirler.",
           "Doğru şık, güvenliğin asıl yerinin arka uç olduğunu söyleyen şık."),
          puan=25, baslik="İstemci koruması yeter mi"),
]

SEVIYE = Seviye(
    kimlik="c14b04",
    cilt=14,
    bolum=4,
    baslik="Mobil Savunma ve Lab",
    brifing="""
Bulgular teslim edildi; sıra düzeltmede. **<<musteri>>** geliştirme ekibi **<<uyg>>** için yayın öncesi sertleştirmeyi Kalkan'dan
istedi: "Düzeltmeyi bize tarif etmeyin, projede gösterin." <<hikaye>>

Selin proje klasörünü laboratuvarına bıraktı: "Manifest, ağ yapılandırması, kaynak kod ve cihaz deposu hazır. Her düzeltmeyi
kendin yap, ben sonra kontrol ederim." Mert ekliyor: "Mobil + finans + API güvenliği çok az kişinin bildiği bir üçlü; bunu
sahiplenen kolay iş bulur." Deniz de MASVS gruplarını bilmeni istiyor: "Raporda bulguları öyle sınıflıyoruz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Savunma tarafında mobil güvenlik bir kontrol listesidir: debuggable ve allowBackup kapalı, şifresiz trafik yasak, kullanıcı
sertifikalarına güven yok, dışarıya açık her bileşen ya kapalı ya izinli, kodda sır yok, cihazda düz metin token yok. Saldırgan
açısından bu listenin her maddesi bir kapıdır; kapatılan her madde onun işini zorlaştırır. Ama unutma: istemci korumaları
yalnızca zorlaştırır, asıl güvenlik her zaman arka uçtadır.
""",
    gercek_hayat="""
- **Yayın öncesi kontrol:** Pek çok mobil güvenlik incelemesinde, yayın sürümünde unutulmuş hata ayıklama bayrakları,
  yedeklemeye açık veri ve şifresiz trafik izni bulunur. Bunlar OWASP MASVS ve MASTG'deki kontrol listelerinde yer alır ve
  otomatik taramalarla yakalanabilir.
- **Önleme:** Yayın hattına (CI) manifest ve ağ yapılandırması denetimi, gömülü sır taraması ve MASVS kontrol listesi eklemek;
  sırları kaynak yerine sunucuda tutmak; sızan anahtarları hızla iptal edebilmek. **Tespit:** arka uç tarafında beklenmedik
  istemci sürümleri, kök açılmış cihaz kümeleri ve anormal API kullanımı izlenir.
- **Finans uygulamaları:** Bankacılık ve ödeme uygulamaları en çok incelenen mobil yüzeylerdir; bu yüzden mobil güvenlik
  önlemleri hem düzenleyici beklentilerin hem müşteri güveninin parçasıdır.
""",
    sure_hedef_dk=30,
)
