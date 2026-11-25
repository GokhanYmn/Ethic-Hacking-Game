"""Cilt 14 · Bölüm 2 — İstemci Tarafı Analizi.

Beceri: statik analizle (uygulamayı çalıştırmadan) kurgusal bir AndroidManifest.xml'de dışarıya açık
bileşenleri, tehlikeli bayrakları (debuggable, allowBackup, usesCleartextTraffic) bulmak; ayrıştırılmış
kaynak parçalarında gömülü anahtarı ve şifresiz uç noktayı yakalamak.

Vakalar: Ferah Bank, Paramix, Kuzey Yatırım, Pazarix. Dosyalar kurgusaldır; "anahtarlar" rastgele
üretilmiş sahte dizgilerdir. Saldırı aracı (Frida, objection vb.) kullanılmaz ve öğretilmez.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c14_mobil.ortak import hex_, sec_doldur, sh, vaka_sec

ETKINLIKLER = ["GirisEkrani", "HesapOzeti", "OdemeOnay", "ProfilAyarlari", "KartYonetimi", "BelgeGoruntule"]
SERVISLER = ["SenkronServisi", "BildirimServisi", "KonumServisi"]
ALICILAR = ["AcilisAlicisi", "SmsAlicisi", "GuncellemeAlicisi"]
SAGLAYICILAR = ["BelgeSaglayici", "DisaAktarSaglayici"]
BAYRAKLAR = ["debuggable", "allowBackup", "usesCleartextTraffic"]


def uret(rng):
    v = vaka_sec(rng)
    etk = rng.sample(ETKINLIKLER, 3)
    srv = rng.sample(SERVISLER, 1)
    alc = rng.sample(ALICILAR, 1)
    sag = rng.sample(SAGLAYICILAR, 1)
    adaylar = [("activity", e) for e in etk] + [("service", srv[0]), ("receiver", alc[0]), ("provider", sag[0])]
    rng.shuffle(adaylar)
    acik = adaylar[:2]        # exported + izinsiz + ana giriş değil: ASIL SORUN
    izinli = adaylar[2]       # exported ama izinle korunuyor: kabul edilebilir
    kapali = adaylar[3:]
    n_true = rng.choice([2, 3])
    acik_bayrak = sorted(rng.sample(BAYRAKLAR, n_true), key=BAYRAKLAR.index)
    anahtar = "lab_key_" + hex_(rng, 24)
    test_host = rng.choice(["test", "dev", "staging", "uat"]) + "-" + v["api"]
    return {
        "vaka": f"{v['ad']} — {v['uyg']} paket analizi",
        "v": v,
        "acik": acik, "izinli": izinli, "kapali": kapali,
        "acik_bayrak": acik_bayrak,
        "anahtar": anahtar, "test_host": test_host,
        "metin": {"musteri": v["ad"], "uyg": v["uyg"], "paket": v["paket"], "api": v["api"], "veri": v["veri"],
                  "hikaye": v["hikaye"]},
        "cevaplar": {
            "acik_bilesenler": [a for _, a in acik],
            "exported_sayisi": 1 + len(acik) + 1,
            "bayraklar": acik_bayrak,
            "anahtar": anahtar,
            "test_url": [f"http://{test_host}/v2/", test_host],
        },
    }


def _manifest(s: dict) -> str:
    v = s["v"]
    b = {k: ("true" if k in s["acik_bayrak"] else "false") for k in BAYRAKLAR}
    satirlar = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{v["paket"]}">',
        '    <uses-permission android:name="android.permission.INTERNET"/>',
        '    <uses-permission android:name="android.permission.USE_BIOMETRIC"/>',
        f'    <permission android:name="{v["paket"]}.IC_ERISIM" android:protectionLevel="signature"/>',
        '    <application',
        f'        android:label="{v["uyg"]}"',
        f'        android:debuggable="{b["debuggable"]}"',
        f'        android:allowBackup="{b["allowBackup"]}"',
        f'        android:usesCleartextTraffic="{b["usesCleartextTraffic"]}"',
        '        android:networkSecurityConfig="@xml/network_security_config">',
        '',
        '        <activity android:name=".AnaEkran" android:exported="true">',
        '            <intent-filter>',
        '                <action android:name="android.intent.action.MAIN"/>',
        '                <category android:name="android.intent.category.LAUNCHER"/>',
        '            </intent-filter>',
        '        </activity>',
    ]

    def bilesen(tur, ad, exported, izin=None):
        e = f'        <{tur} android:name=".{ad}" android:exported="{exported}"'
        if izin:
            e += f' android:permission="{izin}"'
        return e + "/>"

    for tur, ad in s["acik"]:
        satirlar.append(bilesen(tur, ad, "true"))
    tur, ad = s["izinli"]
    satirlar.append(bilesen(tur, ad, "true", f'{v["paket"]}.IC_ERISIM'))
    for tur, ad in s["kapali"]:
        satirlar.append(bilesen(tur, ad, "false"))
    satirlar += ["    </application>", "</manifest>", ""]
    return "\n".join(satirlar)


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['uyg']} ({v['paket']}) paketinden ayrıştırılmış KURGUSAL dosyalar.\n"
          "Gerçek bir uygulama değil. Selin'den not: uygulamayı çalıştırmadan, sadece dosyalara bakarak analiz et (statik analiz).\n")
    u.yaz(lab / "paket" / "AndroidManifest.xml", _manifest(s))
    u.yaz(lab / "paket" / "kaynak" / "ApiClient.java.txt",
          "// KURGUSAL ayrıştırılmış kaynak parçası (decompiler çıktısı gibi)\n"
          f"package {v['paket']}.net;\n\n"
          "public class ApiClient {\n"
          f'    private static final String BASE_URL = "https://{v["api"]}/v2/";\n'
          f'    private static final String API_KEY = "{s["anahtar"]}";\n'
          f'    private static final String ESKI_TEST_URL = "http://{s["test_host"]}/v2/";\n'
          "    private static final int ZAMAN_ASIMI_MS = 15000;\n"
          "}\n")
    u.yaz(lab / "paket" / "kaynak" / "Ayarlar.kt.txt",
          "// KURGUSAL ayrıştırılmış kaynak parçası\n"
          f"package {v['paket']}.config\n\n"
          "object Ayarlar {\n"
          f'    const val PROJE_ADI = "{v["kod"]}-mobil"        // herkese açık bir ad, sır değil\n'
          '    const val SURUM_ADI = "3.8.1"\n'
          '    const val ANALITIK_AKTIF = true\n'
          "}\n")
    u.yaz(lab / "paket" / "res" / "values" / "strings.xml",
          '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n'
          f'    <string name="app_name">{v["uyg"]}</string>\n'
          '    <string name="destek_hatti">0850 000 00 00</string>\n'
          f'    <string name="yardim_alani">https://{v["alan"]}/yardim</string>\n'
          '</resources>\n')
    u.yaz(lab / "paket" / "res" / "xml" / "network_security_config.xml",
          '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
          f'    <base-config cleartextTrafficPermitted="{"true" if "usesCleartextTraffic" in s["acik_bayrak"] else "false"}"/>\n'
          '</network-security-config>\n')


def coz(lab: Path, s: dict) -> dict:
    acik = sh("grep 'exported=\"true\"' paket/AndroidManifest.xml | grep -v permission | grep -v '\\.AnaEkran' "
              "| grep -o 'name=\"\\.[A-Za-z]*' | cut -c8- | tr '\\n' ' '", lab)
    sayi = sh("grep -c 'exported=\"true\"' paket/AndroidManifest.xml", lab)
    bayrak = sh("grep -o -E '(debuggable|allowBackup|usesCleartextTraffic)=\"true\"' paket/AndroidManifest.xml "
                "| cut -d= -f1 | tr '\\n' ' '", lab)
    anahtar = sh("grep -rho 'API_KEY = \"[^\"]*\"' paket/kaynak | cut -d'\"' -f2", lab)
    url = sh("grep -rho 'http://[^\"]*' paket/kaynak", lab)
    return sec_doldur({1: acik, 2: sayi, 3: bayrak, 4: anahtar, 5: url}, GOREVLER, lab, s)


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen - 1:
        return "Ana ekranı (LAUNCHER) ya da izinle korunan bileşeni saymayı unutmuş olabilirsin; bu soruda `exported=\"true\"` olan **her** bileşen sayılır."
    if n == beklenen - 2:
        return "İki tane eksik: `grep -c 'exported=\"true\"'` tüm satırları sayar, filtre eklemene gerek yok."
    return None


def _anahtar_hata(g, beklenen, b):
    if "api_key" in g.lower():
        return "Sadece tırnak içindeki değeri yaz (`lab_key_...`), değişken adını değil."
    return None


ADIMLAR = [
    Adim("Statik analiz: paketi açıp bakmak", """
Android uygulaması (APK) aslında bir arşivdir; içinde bir manifest dosyası (uygulamanın kimlik kartı), kaynaklar ve kod
bulunur. **Statik analiz**, uygulamayı hiç çalıştırmadan bu dosyaları incelemektir. Lab'da kurgusal bir paketin
ayrıştırılmış hali var:
""", komut="ls -R paket"),
    Adim("Manifest: uygulamanın kimlik kartı", """
`AndroidManifest.xml`, uygulamanın bileşenlerini (ekranlar = activity, arka plan işleri = service, yayın dinleyicileri =
receiver, veri paylaşımı = provider) ve izinlerini listeler. `android:exported="true"` olan bir bileşene **başka
uygulamalar da** erişebilir.
""", komut="cat paket/AndroidManifest.xml"),
    Adim("Dışarıya açık bileşenler", """
`grep -n` eşleşen satırları satır numarasıyla gösterir:
""", komut="grep -n 'exported=\"true\"' paket/AndroidManifest.xml", sonra="""
Ana ekran (`LAUNCHER`) açık olmak zorundadır; kullanıcı onu başlatır. Asıl sorun, **izinle korunmayan** ve ana ekran
olmayan açık bileşenlerdir: telefondaki zararlı bir uygulama onları doğrudan tetikleyebilir. İzin (`android:permission`)
taşıyan bileşen yalnızca o izne sahip uygulamalara açıktır.
"""),
    Adim("Tehlikeli bayraklar", """
Uygulama etiketinde üç bayrağa dikkat et: `debuggable` (hata ayıklama açık kalmış), `allowBackup` (uygulama verisi
yedeğe alınabilir) ve `usesCleartextTraffic` (şifresiz HTTP'ye izin). Bir finans uygulamasında bunların hepsi `false`
olmalıdır. Hangileri `true`?
""", komut="grep -n -E 'debuggable|allowBackup|usesCleartextTraffic' paket/AndroidManifest.xml"),
    Adim("Ayrıştırılmış kaynak: gömülü sırlar", """
Saldırgan APK'yı bir decompiler ile okunabilir koda çevirir. `kaynak/` klasöründe bunun kurgusal bir parçası var.
Gömülü anahtar ve adres arayan klasik komut:
""", komut="grep -rn -E 'KEY|SECRET|http' paket/kaynak", sonra="""
**Hacker gözüyle:** `https://` adresi sorun değil; `API_KEY` değeri ise **saldırganın elinde** demektir: uygulamayı
indiren herkes aynı sırrı görür. `http://` ile başlayan bir test adresi hem şifresizdir hem de çoğu zaman daha zayıf
korunan bir ortama çıkar.
"""),
    Adim("Sır mı, değil mi?", """
Her sabit değer sır değildir. Bir proje adı ya da sürüm numarası herkese açık olabilir; anahtar, parola ve token ise
sırdır. Ayrım yapmayı öğren: `Ayarlar.kt.txt` içinde sır var mı?
""", komut="cat paket/kaynak/Ayarlar.kt.txt"),
    Adim("Dinamik analiz nedir? (kavramsal)", """
Statik analiz bu kadar; **dinamik analiz** ise uygulamayı çalışırken incelemektir: trafiği yakalamak (Cilt 5'teki Burp
mantığı), davranışı gözlemek. Saldırgan açısından çoğu zaman daha verimlidir, çünkü seni doğrudan arka uca (Cilt 10'daki
finansal API'lere) götürür. Savunma tarafı bunu bilir: şifreli iletişim ve sertifika sabitleme (certificate pinning)
trafiği araya girip okumayı zorlaştırır; ama asıl güvenlik arka uçtadır. Bu seviyede dinamik analiz yapmıyoruz.
"""),
]

GOREVLER = [
    Gorev("`AndroidManifest.xml` içinde **dışarıya açık (`exported=\"true\"`), izinle korunmayan ve ana ekran (LAUNCHER) olmayan** "
          "bileşenlerin adlarını yaz (virgülle ayır, `.` işareti olmadan).",
          Kume("acik_bilesenler", bicim="bileşen adları, virgülle ayrılmış"),
          ("Önce açık bileşenleri bul, sonra izinli olanı ve ana ekranı ele.",
           "`grep 'exported=\"true\"' paket/AndroidManifest.xml` bütün açıkları verir; `android:permission` taşıyan ve `.AnaEkran` olanı çıkar.",
           "`grep 'exported=\"true\"' paket/AndroidManifest.xml | grep -v permission | grep -v AnaEkran` kalan iki bileşeni gösterir."),
          puan=40, baslik="Korunmasız bileşenler"),
    Gorev("Manifest'te kaç bileşen `exported=\"true\"` olarak işaretli? (ana ekran ve izinli olan dahil, hepsi)",
          Sayi("exported_sayisi", sik_hatalar=_sayi_hata),
          ("Aradığın kalıp tam olarak `exported=\"true\"`.",
           "`grep -c` eşleşen satırları sayar.",
           "`grep -c 'exported=\"true\"' paket/AndroidManifest.xml`"),
          puan=25, baslik="Açık bileşen sayısı"),
    Gorev("`debuggable`, `allowBackup` ve `usesCleartextTraffic` bayraklarından **hangileri `true`**? (virgülle ayır)",
          Kume("bayraklar", bicim="bayrak adları, virgülle ayrılmış"),
          ("Uygulama etiketinde üç bayrak var; değerlerini oku.",
           "`grep -n -E 'debuggable|allowBackup|usesCleartextTraffic' paket/AndroidManifest.xml`",
           "Sadece `true` olanları süz: `grep -o -E '(debuggable|allowBackup|usesCleartextTraffic)=\"true\"' paket/AndroidManifest.xml`."),
          puan=30, baslik="Tehlikeli bayraklar"),
    Gorev("Kaynak parçalarında gömülü olan **API anahtarının değerini** yaz.",
          Metin("anahtar", bicim="anahtar değeri (lab_key_...)", sik_hatalar=_anahtar_hata),
          ("Anahtarlar kodda genellikle `KEY` içeren bir değişken adıyla durur.",
           "`grep -rn KEY paket/kaynak` ile ara.",
           "`grep -rho 'API_KEY = \"[^\"]*\"' paket/kaynak | cut -d'\"' -f2` yalnızca değeri verir."),
          puan=30, baslik="Gömülü anahtar"),
    Gorev("Kaynak kodda geçen **şifresiz (`http://`) test adresini** yaz (adresin tamamı ya da yalnızca alan adı olur).",
          Metin("test_url", bicim="http://... adresi ya da alan adı"),
          ("Şifresiz adres `http://` ile başlar, güvenli olanlar `https://`.",
           "`grep -rn 'http://' paket/kaynak` (dikkat: `https://` satırları bu kalıpla eşleşmez).",
           "`grep -rho 'http://[^\"]*' paket/kaynak` adresi verir."),
          puan=30, baslik="Şifresiz uç nokta"),
    Gorev("Geliştirici kaynak koddaki API anahtarını silip uygulamanın yeni sürümünü yayımladı. Bu **yeterli mi**?",
          Secmeli([
              ("Hayır: anahtar eski sürümlerde de durur; iptal edilip yenilenmeli",
               "Doğru. İndirilmiş eski paketlerdeki anahtar hâlâ geçerlidir; anahtarı döndürmek (rotate) gerekir."),
              ("Evet: yeni sürümde anahtar olmadığı için artık kimse onu bulamaz ve sorun tamamen kapanmıştır",
               "Yanlış. Mağazadan inmiş eski sürümler ve arşivlenmiş paketler anahtarı taşımaya devam eder."),
              ("Evet, ama yalnızca uygulama mağazası eski sürümü yayından kaldırırsa sorun kapanmış sayılır",
               "Yanlış. Kaldırılan sürüm daha önce indirilmiş kopyalardan ve arşivlerden yine okunabilir."),
              ("Hayır: asıl sorun anahtarın adının tahmin edilebilir olması, yani adın değiştirilmesi yeterlidir",
               "Yanlış. Sorun adı değil, sırrın istemcide bulunmasıdır."),
          ], dogru=0),
          ("Anahtar yalnızca son sürümde mi durur?",
           "Eski APK dosyaları kullanıcı telefonlarında ve çeşitli arşivlerde durmaya devam eder.",
           "Doğru şık, anahtarın geçersiz kılınmasını (iptal/yenileme) söyleyen şık."),
          puan=30, baslik="Anahtarı silmek yeter mi?"),
    Gorev("Sertifika sabitleme (certificate pinning) saldırgan için **neyi zorlaştırır**?",
          Secmeli([
              ("Uygulama ile sunucu arasındaki trafiğe araya girmeyi",
               "Doğru. Uygulama yalnızca beklediği sertifikaya güvenir, araya giren sahte sertifikayı reddeder. Yine de asıl güvenlik arka uçtadır."),
              ("Manifest dosyasındaki bayrakları ve izinleri düz metin olarak okumayı",
               "Yanlış. Manifest APK içinde düz durur; pinning onunla ilgili değildir."),
              ("Uygulamanın kaynak kodunun bir decompiler ile ayrıştırılıp okunmasını",
               "Yanlış. Kodun okunması kod gizleme konusudur; pinning ağ trafiğini korur."),
              ("Cihazın yedeğinden uygulama verisinin çıkarılıp okunmasını",
               "Yanlış. Yedekler `allowBackup` ile ilgilidir; pinning ağ katmanındadır."),
          ], dogru=0),
          ("Pinning hangi katmanı korur: dosyalar mı, ağ trafiği mi?",
           "Uygulama sunucunun sertifikasını 'sabitler'; araya giren başka bir sertifika sunarsa ne olur?",
           "Doğru şık, ağ trafiğine araya girmeyi anlatan şık."),
          puan=25, baslik="Pinning neyi zorlaştırır"),
]

SEVIYE = Seviye(
    kimlik="c14b02",
    cilt=14,
    bolum=2,
    baslik="İstemci Tarafı Analizi",
    brifing="""
**<<musteri>>**, yayına alacağı **<<uyg>>** sürümünün paketini Kalkan'a gönderdi. <<hikaye>>

Selin: "Elimizde uygulamanın ayrıştırılmış dosyaları var: manifest, kaynak parçaları, ayarlar. Uygulamayı **çalıştırmadan**
bakıyoruz: dışarıya fazla kapı açık mı, kodun içinde saklanmaması gereken bir şey var mı?" Mert ekliyor: "Saldırganın
ilk yaptığı iş de bu: paketi indirir, açar, `grep` atar." Deniz: "Bulduğun her şeyi geliştirici ekibine anlaşılır bir
dille yazacağız."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırgan açısından bir mobil uygulama, indirilip `grep` ile taranabilen bir arşivdir: manifest hangi kapıların açık
olduğunu, kaynak kod hangi sırların gömülü olduğunu söyler. Savunma dersi: bileşenleri varsayılan olarak kapalı tut
(`exported="false"`), açman gerekenleri izinle koru, hata ayıklama/yedek/şifresiz trafik bayraklarını yayında kapat ve
hiçbir sırrı istemciye gömme. Sır sızdıysa kodu temizlemek yetmez; anahtarı iptal edip yenile.
""",
    gercek_hayat="""
- **Gömülü anahtarlar:** Pek çok uygulama incelemesinde kaynak kodda ya da kaynak dosyalarında unutulmuş API anahtarları
  ve geliştirme/test adresleri bulunur; bu, mobil güvenlik raporlarının en sık bulgularındandır. Mağazaya yüklenen paket
  herkes tarafından indirilip açılabildiği için gömülü sır fiilen herkese açıktır.
- **Önleme:** Yayın öncesi otomatik statik tarama (OWASP MASVS ve MASTG'deki kontroller), manifest bayraklarının yayın
  sürümünde `debuggable=false` olarak doğrulanması, sırların arka uçta tutulması ve kısa ömürlü token'lar. **Tespit:**
  arka uçta bir anahtarın beklenmedik yerlerden ya da hacimlerde kullanılması izlenir; sızan anahtarın hızla iptal
  edilebilmesi için yenileme süreci önceden hazır olmalıdır.
- **Dışarıya açık bileşenler:** Android uygulamalarında izinsiz `exported` bileşenler, aynı telefondaki başka bir
  uygulamanın korunmasız ekranları ya da servisleri tetiklemesine yol açabileceği için iyi bilinen bir risk sınıfıdır;
  Android geliştirici belgeleri de bileşenleri gerekmedikçe dışarıya açmamayı önerir.
""",
    sure_hedef_dk=25,
)
