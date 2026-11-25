"""Cilt 14 · Bölüm 3 — Veri Depolama ve İletişim.

Beceri: kurgusal bir SharedPreferences XML'inde açık metin saklanan hassas verileri ayırt etmek,
network_security_config'te şifresiz trafiğe izin veren satırı bulmak, kurgusal bir trafik kaydında
HTTP ile giden ve oturum bilgisi taşıyan isteği yakalamak.

Vakalar: Ferah Bank, Paramix, Kuzey Yatırım, Pazarix. Token/kart/PIN değerleri rastgele üretilmiş
sahte dizgilerdir; gerçek kimseye ait değildir.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c14_mobil.ortak import hex_, sec_doldur, sh, vaka_sec

HASSAS_ADAYLAR = ["refresh_token", "pin_kodu", "kart_no", "tc_kimlik", "hesap_sifresi"]
HASSAS_DEGERSIZ = [("tema", "koyu"), ("dil", "tr"), ("onboarding_bitti", "true"), ("yazi_boyutu", "orta")]
YOLLAR_GUVENSIZ = ["/v2/hesaplar/ozet", "/v2/bakiye", "/v2/islemler/son", "/v2/profil", "/v2/limitler"]
YOLLAR_GUVENLI = ["/v2/giris", "/v2/kampanyalar", "/v2/subeler", "/v2/kur"]
STATIK_YOLLAR = ["/statik/logo.png", "/yardim/sss.html", "/statik/uygulama.css", "/yardim/iletisim.html"]
ESKI_HOSTLAR = ["eski-api", "legacy", "kampanya-cdn", "yedek-api"]


def _deger(rng, ad: str, tkn: str) -> str:
    if ad == "access_token":
        return tkn
    if ad == "refresh_token":
        return "rtk_" + hex_(rng, 24)
    if ad == "pin_kodu":
        return "".join(rng.choice("0123456789") for _ in range(rng.choice([4, 6])))
    if ad == "kart_no":
        return "0000 " + " ".join("".join(rng.choice("0123456789") for _ in range(4)) for _ in range(3))
    if ad == "tc_kimlik":
        return "0" + "".join(rng.choice("0123456789") for _ in range(10))
    return "Gizli" + str(rng.randint(100, 999)) + "!"


def uret(rng):
    v = vaka_sec(rng)
    tkn = "tkn_" + hex_(rng, 28)
    hassas = ["access_token"] + rng.sample(HASSAS_ADAYLAR, 2)
    prefs = [(a, _deger(rng, a, tkn)) for a in hassas]
    prefs += rng.sample(HASSAS_DEGERSIZ, 3)
    rng.shuffle(prefs)
    eski = rng.choice(ESKI_HOSTLAR) + "." + v["alan"]
    gun = u.gun(rng)
    n_http = rng.randint(3, 5)
    olaylar = []
    t = gun + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59))
    sorunlu_yol = rng.choice(YOLLAR_GUVENSIZ)
    kayitlar = [("http", sorunlu_yol, True, eski)]
    for yol in rng.sample(STATIK_YOLLAR, n_http - 1):
        kayitlar.append(("http", yol, False, eski))
    for yol in rng.sample(YOLLAR_GUVENSIZ + YOLLAR_GUVENLI, 8):
        kayitlar.append(("https", yol, yol in YOLLAR_GUVENSIZ, v["api"]))
    rng.shuffle(kayitlar)
    for sema, yol, oturumlu, host in kayitlar:
        t += timedelta(seconds=rng.randint(2, 40))
        olaylar.append((t, "GET", f"{sema}://{host}{yol}", f"Bearer {tkn}" if oturumlu else "-",
                        rng.choice([200, 200, 200, 304])))
    return {
        "vaka": f"{v['ad']} — {v['uyg']} cihaz ve trafik incelemesi",
        "v": v,
        "prefs": prefs, "hassas": hassas, "eski": eski, "olaylar": olaylar,
        "metin": {"musteri": v["ad"], "uyg": v["uyg"], "veri": v["veri"], "paket": v["paket"],
                  "hikaye": v["hikaye"], "api": v["api"]},
        "cevaplar": {
            "token": tkn,
            "hassas_anahtarlar": hassas,
            "http_sayisi": n_http,
            "http_yol": [sorunlu_yol, f"http://{eski}{sorunlu_yol}"],
            "alan": eski,
        },
    }


def _prefs_xml(prefs) -> str:
    satir = ["<?xml version='1.0' encoding='utf-8' standalone='yes' ?>", "<map>"]
    for ad, d in prefs:
        if d in ("true", "false"):
            satir.append(f'    <boolean name="{ad}" value="{d}" />')
        else:
            satir.append(f'    <string name="{ad}">{d}</string>')
    satir += ["</map>", ""]
    return "\n".join(satir)


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['uyg']} için KURGUSAL cihaz ve trafik kayıtları.\n"
          "Cihaz, Kalkan'ın kendi test telefonudur; trafik kendi test proxy'mizden alındı. Hiçbir değer gerçek değildir.\n")
    u.yaz(lab / "cihaz" / "shared_prefs" / "oturum.xml", _prefs_xml(s["prefs"]))
    u.yaz(lab / "cihaz" / "shared_prefs" / "ayarlar.xml",
          _prefs_xml([("tema", "koyu"), ("dil", "tr"), ("bildirim_acik", "true")]))
    u.yaz(lab / "paket" / "res" / "xml" / "network_security_config.xml",
          '<?xml version="1.0" encoding="utf-8"?>\n<network-security-config>\n'
          '    <base-config cleartextTrafficPermitted="false">\n'
          '        <trust-anchors><certificates src="system"/></trust-anchors>\n'
          '    </base-config>\n'
          '    <domain-config cleartextTrafficPermitted="true">\n'
          f'        <domain includeSubdomains="true">{s["eski"]}</domain>\n'
          '    </domain-config>\n'
          '</network-security-config>\n')
    u.yaz(lab / "trafik" / "oturum_kaydi.txt",
          "# zaman | yöntem | adres | auth | durum   (KURGUSAL test proxy kaydı)\n" +
          "".join(f"{t:%Y-%m-%dT%H:%M:%S} {m} {adr} auth={a} {d}\n" for t, m, adr, a, d in s["olaylar"]))


def coz(lab: Path, s: dict) -> dict:
    token = sh("grep -o 'tkn_[0-9a-f]*' cihaz/shared_prefs/oturum.xml", lab)
    anahtarlar = sh("grep -E 'tkn_|rtk_|pin_kodu|kart_no|tc_kimlik|hesap_sifresi' cihaz/shared_prefs/oturum.xml "
                    "| cut -d'\"' -f2 | tr '\\n' ' '", lab)
    sayi = sh("grep -c ' http://' trafik/oturum_kaydi.txt", lab)
    yol = sh("grep ' http://' trafik/oturum_kaydi.txt | grep 'auth=Bearer' | awk '{print $3}' | cut -d/ -f4- | sed 's|^|/|'", lab)
    alan = sh("grep -B1 'cleartextTrafficPermitted=\"true\"' paket/res/xml/network_security_config.xml >/dev/null; "
              "grep '<domain ' paket/res/xml/network_security_config.xml | sed 's/<[^>]*>//g' | tr -d ' '", lab)
    return sec_doldur({1: token, 2: anahtarlar, 3: sayi, 4: yol, 5: alan}, GOREVLER, lab, s)


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Başlık satırı ya da `https://` satırı karışmış olabilir. `http://` ile `https://` farklı kalıplardır."
    return None


ADIMLAR = [
    Adim("Cihazda ne saklanıyor?", """
Android uygulamaları küçük ayarları ve oturum bilgilerini `shared_prefs` klasöründeki XML dosyalarında tutar
(SharedPreferences). Bu dosyalar **varsayılan olarak şifrelenmez**; telefonun kilidi aşılırsa, cihaz kök (root) açılırsa
ya da yedek alınırsa okunabilirler. Lab'daki kurgusal test telefonuna bak:
""", komut="ls -R cihaz"),
    Adim("Oturum dosyasını oku", """
Bir finans uygulamasında bu dosyada hiçbir sır durmamalıdır.
""", komut="cat cihaz/shared_prefs/oturum.xml", sonra="""
Hangi satırlar **sır**? Token'lar, PIN, kart numarası, TC kimlik, parola: bunlar. Tema, dil, yazı boyutu: değil.
Ayrımı yapmak bu görevin temel becerisi.
"""),
    Adim("Anahtar adlarını çıkarmak", """
`grep -o` yalnızca eşleşen kısmı basar. Dosyadaki bütün `name="..."` değerlerini listele:
""", komut="grep -o 'name=\"[a-z_]*\"' cihaz/shared_prefs/oturum.xml"),
    Adim("İletişim: ağ güvenliği yapılandırması", """
Android, uygulamanın ağ kurallarını `network_security_config.xml` dosyasında tutar. `cleartextTrafficPermitted="true"`
bir alan adı için **şifresiz HTTP'ye izin** demektir. Geliştiriciler test sırasında bunu açar ve unutur.
""", komut="cat paket/res/xml/network_security_config.xml"),
    Adim("Trafik kaydı", """
`trafik/oturum_kaydi.txt` kendi test proxy'mizden alınmış kurgusal bir kayıttır. `http://` ile giden satırlar
şifresizdir: aynı ağdaki biri (ortak Wi-Fi'da) bunları okuyabilir. Bu satırların sayısı:
""", komut="grep -c ' http://' trafik/oturum_kaydi.txt"),
    Adim("Şifresiz hat ve oturum bilgisi", """
En kötü durum: şifresiz giden bir isteğin `Authorization` başlığında oturum token'ı da taşınması. `awk` ile ilgili
sütunları yan yana al:
""", komut="grep ' http://' trafik/oturum_kaydi.txt | awk '{print $3, $4}'", sonra="""
**Hacker gözüyle:** "Cihaz güvenli değildir" varsayımıyla çalışırsın: telefon çalınabilir, kök açılmış olabilir, yanında
zararlı bir uygulama çalışıyor olabilir, Wi-Fi kötü niyetli olabilir. Uygulama en kötü senaryoya göre tasarlanmalı:
hassas bir şeyi açık saklama (Keystore/Keychain kullan), her şeyi HTTPS ile taşı, asıl güveni arka uca bırak.
"""),
]

GOREVLER = [
    Gorev("`cihaz/shared_prefs/oturum.xml` içindeki **erişim (access) token'ının** değerini yaz.",
          Metin("token", bicim="token değeri (tkn_...)"),
          ("Token'lar `tkn_` ile başlayan uzun dizgilerdir.",
           "`grep tkn_ cihaz/shared_prefs/oturum.xml` satırı gösterir.",
           "`grep -o 'tkn_[0-9a-f]*' cihaz/shared_prefs/oturum.xml` yalnızca değeri verir."),
          puan=25, baslik="Açık metin token"),
    Gorev("`oturum.xml` içinde **hassas veri taşıyan** (token, PIN, kart no, TC kimlik, parola gibi) anahtarların "
          "adlarını yaz (virgülle ayır). Tema, dil gibi zararsız ayarları alma.",
          Kume("hassas_anahtarlar", bicim="anahtar adları, virgülle ayrılmış"),
          ("Önce bütün anahtar adlarını listele, sonra her birinin değerine bak: 'sır' mı, 'ayar' mı?",
           "`grep -o 'name=\"[a-z_]*\"' cihaz/shared_prefs/oturum.xml` adları verir; değerler için dosyanın kendisine bak.",
           "Dosyada üç hassas satır var; token, PIN, kart no, TC kimlik ya da parola içerenlerin `name=` değerlerini yaz."),
          puan=35, baslik="Hassas anahtarlar"),
    Gorev("`trafik/oturum_kaydi.txt` içinde **şifresiz `http://`** ile giden kaç istek var?",
          Sayi("http_sayisi", sik_hatalar=_sayi_hata),
          ("`http://` ile `https://` farklı kalıplardır; ikincisinin içinde `http://` geçmez.",
           "`grep -c ' http://' trafik/oturum_kaydi.txt` yalnızca şifresiz satırları sayar.",
           "Komutun çıktısındaki sayı cevaptır."),
          puan=25, baslik="Şifresiz istek sayısı"),
    Gorev("Şifresiz (`http://`) giden isteklerden **birinde oturum token'ı (`auth=Bearer ...`) de taşınmış**. "
          "Bu isteğin yolunu yaz (örn. `/v2/...`).",
          Metin("http_yol", bicim="adres yolu (/v2/...)"),
          ("Önce http satırlarını süz, sonra içlerinden `auth=Bearer` taşıyanı seç.",
           "`grep ' http://' trafik/oturum_kaydi.txt | grep 'auth=Bearer'`",
           "Çıkan tek satırda adres üçüncü sütundur; alan adından sonraki kısım yoldur."),
          puan=35, baslik="Token şifresiz gidiyor"),
    Gorev("`network_security_config.xml` içinde şifresiz trafiğe izin verilen **alan adı** hangisi?",
          Metin("alan", bicim="alan adı (...lab)"),
          ("Dosyada `domain-config` bloğuna bak: `cleartextTrafficPermitted=\"true\"` olanı.",
           "`grep -A1 'cleartextTrafficPermitted=\"true\"' paket/res/xml/network_security_config.xml`",
           "Bir sonraki satırdaki `<domain>` etiketinin içindeki metin cevaptır."),
          puan=30, baslik="Açık bırakılan alan"),
    Gorev("Oturum token'ını cihazda saklamanın **doğru** yolu hangisi?",
          Secmeli([
              ("Güvenli depoda (Keystore/Keychain) tutmak ve token'ı kısa ömürlü yapmak",
               "Doğru. Güvenli depo, anahtarı uygulamanın dosyalarından ayırır; kısa ömür çalınma zararını sınırlar."),
              ("SharedPreferences dosyasında tutmak ama dosya adını sıradan olmayan bir adla kaydetmek",
               "Yanlış. Dosya adı gizlilik sağlamaz; içerik hâlâ açık metindir."),
              ("Token'ı Base64 ile kodlayıp, okunmasın diye aynı SharedPreferences dosyasına yazmak",
               "Yanlış. Base64 şifreleme değil kodlamadır; tek komutla geri çevrilir."),
              ("Token'ı uygulama her açıldığında dosyaya yeniden yazıp eski kaydı silerek korumak",
               "Yanlış. Yeniden yazmak okunabilirlik sorununu çözmez; dosya her seferinde açık metindir."),
          ], dogru=0),
          ("Cihazdaki sırlar 'saklanamaz', ama zorlaştırılabilir. İşletim sistemi bunun için ne sunuyor?",
           "Android'de Keystore, iOS'ta Keychain adlı özel depolar vardır.",
           "Doğru şık güvenli deponun adını ve token ömrünü anlatan şık; kodlama (Base64) şifreleme değildir."),
          puan=30, baslik="Doğru depolama"),
    Gorev("Bir finans uygulamasının trafiğinde `http://` isteklerinin bulunması **neden kabul edilemez**?",
          Secmeli([
              ("Ortadaki adam saldırısına açıktır: aynı ağdaki biri trafiği okuyabilir",
               "Doğru. HTTP düz metindir; ortak Wi-Fi'daki biri istekleri (token dahil) görebilir (Cilt 2 ve 6'daki MITM)."),
              ("HTTP yanıtları HTTPS'ten çok daha yavaştır, bu yüzden uygulama donar ve kullanıcı kaybedilir",
               "Yanlış. Sorun hız değil gizlilik ve bütünlüktür."),
              ("HTTP'yi yalnızca eski telefonlar destekler, yeni telefonlarda hiç çalışmaz ve hata verir",
               "Yanlış. Android varsayılan olarak engeller ama yapılandırmayla açılabilir; asıl tehlike budur."),
              ("HTTP, sunucunun IP adresini ve sürüm bilgisini herkese açık biçimde ifşa eder",
               "Yanlış. IP adresi zaten bağlantıda görünür; fark HTTPS'in içeriği şifrelemesidir."),
          ], dogru=0),
          ("Aynı Wi-Fi'daki biri şifresiz trafiğe ne yapabilir?",
           "Cilt 2'de ağı dinlemeyi (tcpdump) öğrendin; şifresiz içerik düz okunur.",
           "Doğru şık, trafiğin okunup değiştirilebilmesini (ortadaki adam) anlatan şık."),
          puan=25, baslik="Neden HTTPS"),
]

SEVIYE = Seviye(
    kimlik="c14b03",
    cilt=14,
    bolum=3,
    baslik="Veri Depolama ve İletişim",
    brifing="""
**<<musteri>>** test aşamasında. Kalkan'ın kendi test telefonuna **<<uyg>>** kuruldu; telefonun dosyalarından ve test
proxy'sinin kaydından kurgusal bir kopya laboratuvarına geldi. <<hikaye>>

Selin: "Uygulama <<veri>> ile çalışıyor. İki soru: telefonda hassas bir şey açık duruyor mu, ve uygulama sunucuyla
konuşurken şifresiz bir yol var mı?" Deniz ekliyor: "Aynı Wi-Fi'daki biri bunları okuyabilir. İzlediğim bir
kafe vakasında tam böyle bir kayıt görmüştüm."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Telefon çalınabilir, kök açılabilir, yanında zararlı bir uygulama çalışabilir; ağ da güvenilir değildir. Saldırgan açısından
`shared_prefs` klasörü ve şifresiz bir HTTP isteği altın madenidir: bir token okumak, hesabı ele geçirmek demektir.
Savunma dersi: hassas veriyi cihazda saklama ya da güvenli depoda (Keystore/Keychain) tut, token'ları kısa ömürlü yap,
bütün trafiği HTTPS'e taşı, yayın sürümünde şifresiz trafiğe izin veren her satırı sil ve asıl güveni arka uca bırak.
""",
    gercek_hayat="""
- **Açık metin oturum bilgisi:** Mobil uygulama incelemelerinde cihazda açık saklanan token, parola ve kişisel veriler
  çok sık görülen bulgulardır; OWASP Mobile Top 10 listesinde güvensiz veri depolama ayrı bir kategoridir. Yedeklerden
  ya da kök açılmış cihazlardan okunabilen bu dosyalar, hesabın ele geçirilmesine yol açabilir.
- **Önleme:** Hassas veri için Android Keystore / iOS Keychain, `allowBackup=false`, yayın sürümünde `cleartextTraffic`
  kapalı, tüm hatlar TLS, kısa ömürlü token ve sunucuda iptal mekanizması. **Tespit:** Arka uçta aynı token'ın birden
  çok cihazdan ya da beklenmedik konumlardan kullanılması izlenir; şüpheli oturumlar sonlandırılır.
- **Kamusal Wi-Fi riski:** Şifresiz uygulama trafiği, ortak ağda araya girilerek okunabilir; bu nedenle finans uygulamaları
  yalnızca TLS ile konuşmalı, ideal olarak sertifika sabitleme de kullanmalıdır.
""",
    sure_hedef_dk=25,
)
