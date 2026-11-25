"""Cilt 2 · Bölüm 5 — HTTP: Web'in Dili.

Beceri: `curl` ile istek göndermek (`-v`, `-I`, `-X POST -d`, `-b`), yanıt başlıklarını okumak,
robots.txt'deki yolları denemek, form ile giriş yapıp oturum çerezini almak, çerezle korunan
sayfaya erişmek, durum kodlarını (200/301/401/403/404/500) yorumlamak.

Servis: senaryonun web uygulaması 127.0.0.1'de rastgele bir portta çalışır
(`SessizIsleyici`'den türer). Bir bayrak ana sayfanın özel bir yanıt başlığında, ikincisi
çerezle korunan panelde.

Vakalar: e-ticaret kampanya paneli, kafe sadakat kartı sitesi, fintech üye işyeri paneli,
belediye e-belediye portalı.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import SessizIsleyici, calistir, http_sunucu
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "pazarix", "site": "Pazarix Kampanya Yönetimi", "server": "nginx/1.18.0",
        "ozel_baslik": "X-Debug-Token",
        "gizli": ["/kampanya-yonetim-eski/", "/kampanya-test/", "/yonetim-v1/"],
        "bos": ["/eski-site/", "/tmp/", "/kargo-entegrasyon/", "/beta/"],
        "alanlar": ("kullanici", "parola"), "kullanicilar": ["test_kampanya", "deneme_admin", "kampanya_qa"],
        "yasak": ["/yedekler/", "/db-yedek/", "/export/"],
        "eski": ("/eski-kampanya", ["/kampanyalar/kis-2026", "/kampanyalar/efsane-cuma", "/kampanyalar/yilbasi"]),
        "brifing": """
**Pazarix** kampanya haftası için yeni bir yönetim paneli yazdırmış; canlıya çıkmadan önce
Kalkan'dan hızlı bir web kontrolü istediler. Panelin kopyası laboratuvarında
**http://127.0.0.1:<<port>>/** adresinde çalışıyor.

Selin: "Tarayıcı sana sadece sunucunun göstermek istediğini gösterir. Bugün tarayıcı yok:
`curl` ile ham isteği ve ham cevabı göreceksin. Başlıklar, çerezler, durum kodları... hepsi
bir şey anlatır."

Mert: "Geliştiriciler canlıya çıkarken bir şeyleri kapatmayı hep unutur. Bul bakalım
neleri unutmuşlar."
""",
    },
    {
        "kod": "atolye", "site": "Atölye Kahve Sadakat Kartı", "server": "Apache/2.4.52 (Ubuntu)",
        "ozel_baslik": "X-Gelistirici-Notu",
        "gizli": ["/menu-taslak/", "/kart-test/", "/eski-panel/"],
        "bos": ["/wp-old/", "/tmp/", "/beta/", "/kampanya-2024/"],
        "alanlar": ("eposta", "sifre"), "kullanicilar": ["test@atolye.lab", "kasa@atolye.lab", "deneme@atolye.lab"],
        "yasak": ["/yedekler/", "/uploads/private/", "/db/"],
        "eski": ("/menu.php", ["/menu/kis", "/menu/sonbahar", "/menu/2026"]),
        "brifing": """
**Atölye Kahve**'nin sahibi Berk, bir serbest çalışana sadakat kartı sitesi yaptırmış: puan
biriktirme, kampanyalar, küçük bir yönetim paneli. "Müşterilerin e-postaları orada, içim
rahat etsin istiyorum," diyor. Sitenin kopyası laboratuvarında **http://127.0.0.1:<<port>>/**
adresinde çalışıyor.

Selin: "Küçük işletme siteleri genelde aceleyle yapılır. Başlıklara, robots.txt'ye ve giriş
formuna bak; çerezin nasıl korunduğunu da gör."

Deniz: "Ben de logları izleyeceğim. Senin isteklerin bende nasıl görünüyor, sonra konuşuruz."
""",
    },
    {
        "kod": "paramix", "site": "Paramix Üye İşyeri Paneli", "server": "nginx/1.24.0",
        "ozel_baslik": "X-Backend-Trace",
        "gizli": ["/merchant-v1-legacy/", "/sandbox-panel/", "/eski-merchant/"],
        "bos": ["/v0/", "/tmp/", "/beta/", "/staging/"],
        "alanlar": ("kullanici_adi", "sifre"), "kullanicilar": ["qa_merchant", "test_isyeri", "demo_odeme"],
        "yasak": ["/internal/", "/actuator/", "/yedekler/"],
        "eski": ("/api/v1/", ["/api/v2/", "/api/v3/", "/api/2026/"]),
        "brifing": """
**Paramix**'in CTO'su Ece Hanım, üye işyerlerinin kullandığı yeni paneli denetime girmeden
önce kontrol ettirmek istiyor: "Bir üye işyeri başka birinin işlemlerini görebilir mi, ya da
dışarıdan biri içeri girebilir mi?" Panelin kopyası laboratuvarında
**http://127.0.0.1:<<port>>/** adresinde çalışıyor.

Selin: "Ödeme sektöründe başlıktaki tek satırlık bir hata ayıklama izi bile bulgudur. Her
cevabın başlıklarına bak."

Mert: "Bir de eski sürüm yollarını dene. Kimse v1'i kapatmaz."
""",
    },
    {
        "kod": "yesiltepe", "site": "Yeşiltepe e-Belediye", "server": "Apache/2.2.15 (CentOS)",
        "ozel_baslik": "X-Eski-Surum-Notu",
        "gizli": ["/ebelediye-test/", "/yonetim-eski/", "/personel-test/"],
        "bos": ["/eski-site/", "/tmp/", "/ihale-arsiv-2019/", "/beta/"],
        "alanlar": ("sicil", "sifre"), "kullanicilar": ["test01", "bilgiislem_test", "deneme99"],
        "yasak": ["/yedekler/", "/arsiv/", "/backup/"],
        "eski": ("/borc-sorgula.php", ["/e-belediye/borc/", "/e-belediye/odeme/", "/hizmetler/borc/"]),
        "brifing": """
**Yeşiltepe Belediyesi** yeni e-belediye portalını açmadan önce Kalkan'dan web kontrolü istedi.
Nurcan Hanım: "Vatandaşın borç bilgisi bu portalda. Eski yazılımdan kalan bir şey var mı,
bilmek istiyorum." Portalın kopyası laboratuvarında **http://127.0.0.1:<<port>>/**
adresinde çalışıyor.

Selin: "Web'in dili HTTP. Bugün o dili okumayı öğreneceksin: hangi istek hangi cevabı
alıyor, sunucu neyi saklıyor, neyi yanlışlıkla söylüyor."
""",
    },
]


def _parola(rng) -> str:
    return (rng.choice(["Yaz", "Kis", "Bahar", "Galata", "Kartal", "Deniz", "Admin", "Sistem", "Depo", "Kampanya"])
            + rng.choice(["2024", "2025", "2026", "123", "1903", "1907"]) + rng.choice(["", ".", "_x", "_01"]))


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    gizli = rng.choice(v["gizli"])
    bos = rng.sample(v["bos"], 2)
    robots = [bos[0], gizli, bos[1]]
    rng.shuffle(robots)
    kullanici = rng.choice(v["kullanicilar"])
    parola = _parola(rng)
    token = "".join(rng.choice("0123456789abcdef") for _ in range(24))
    yasak = rng.choice(v["yasak"])
    eski_yol, hedefler = v["eski"]
    yeni_yol = rng.choice(hedefler)
    yok_yol = rng.choice(["/admin.php", "/test/", "/phpinfo.php", "/kurulum/", "/old/"])
    yollar = ["/iletisim", "/panel", yasak, eski_yol, yok_yol]
    rng.shuffle(yollar)
    b1 = u.bayrak(rng, rng.choice(["sessiz_iz", "derin_iz", "golge", "sinyal"]))
    b2 = u.bayrak(rng, rng.choice(["acik_pencere", "kirik_kilit", "arka_oda", "anahtar"]))
    taban = f"http://127.0.0.1:{port}"
    return {
        "vaka": f"{m['ad']} — {v['site']} web kontrolü",
        "brifing": v["brifing"],
        "v": v, "port": port, "gizli": gizli, "robots": robots, "kullanici": kullanici, "parola": parola,
        "token": token, "yasak": yasak, "eski_yol": eski_yol, "yeni_yol": yeni_yol, "yollar": yollar,
        "bayrak1": b1, "bayrak2": b2,
        "metin": {
            "musteri": m["ad"], "port": port, "site": v["site"], "eski_yol": eski_yol,
            "k_alan": v["alanlar"][0], "p_alan": v["alanlar"][1],
        },
        "cevaplar": {
            "bayrak1": b1,
            "gizli": [gizli, gizli.strip("/"), "/" + gizli.strip("/")],
            "parola": parola,
            "token": token,
            "bayrak2": b2,
            "yeni_yol": [yeni_yol, yeni_yol.rstrip("/"), taban + yeni_yol, taban + yeni_yol.rstrip("/")],
            "yasak": [yasak, yasak.rstrip("/"), yasak.strip("/")],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['site']} kopyası bu görev boyunca çalışıyor:\n"
          f"  http://127.0.0.1:{s['port']}/\n\n"
          "Tarayıcı yerine curl kullan. Örnek: curl -v http://127.0.0.1:%d/iletisim\n" % s["port"])
    u.yaz(lab / "yollar.txt",
          "# Mert'in dizin taraması (yarım kaldı, durum kodları yazılmadı)\n"
          + "\n".join(s["yollar"]) + "\n")


def _sayfa(baslik: str, govde: str) -> str:
    return (f"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{baslik}</title></head>\n"
            f"<body>\n<h1>{baslik}</h1>\n{govde}\n</body></html>\n")


def servis(s: dict, lab: Path, dur) -> None:
    v = s["v"]
    k_alan, p_alan = v["alanlar"]
    site = v["site"]
    robots = "User-agent: *\n" + "".join(f"Disallow: {y}\n" for y in s["robots"])
    gizli = s["gizli"].rstrip("/")
    yasak = s["yasak"].rstrip("/")

    class Site(SessizIsleyici):
        server_version = v["server"]
        timeout = 15

        def version_string(self):
            return self.server_version

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            yol, sorgu = ag.yol_ve_sorgu(self)
            yol_k = yol.rstrip("/") or "/"
            if yol_k == "/":
                self.yanit(200, _sayfa(site, "<p>Hoş geldiniz.</p>\n<a href=\"/giris\">Giriş</a> · "
                                             "<a href=\"/iletisim\">İletişim</a>"),
                           basliklar={v["ozel_baslik"]: s["bayrak1"], "X-Frame-Options": "SAMEORIGIN"})
            elif yol_k == "/robots.txt":
                self.yanit(200, robots, tur="text/plain; charset=utf-8")
            elif yol_k == "/iletisim":
                self.yanit(200, _sayfa("İletişim", f"<p>Destek: destek@{musteri(v['kod'])['alan']}</p>"))
            elif yol_k == gizli:
                self.yanit(200, _sayfa("Eski test paneli",
                                       "<p>Geliştirici notu: canlıya çıkmadan bu sayfa kaldırılacak.</p>\n"
                                       f"<pre>Test hesabı\nKullanıcı: {s['kullanici']}\nParola: {s['parola']}\n"
                                       "Giriş: /giris (POST)</pre>"))
            elif yol_k == "/giris":
                self.yanit(200, _sayfa("Giriş", (
                    "<form method=\"POST\" action=\"/giris\">\n"
                    f"  <input type=\"text\" name=\"{k_alan}\" placeholder=\"{k_alan}\">\n"
                    f"  <input type=\"password\" name=\"{p_alan}\" placeholder=\"{p_alan}\">\n"
                    "  <button type=\"submit\">Giriş</button>\n</form>")))
            elif yol_k == "/panel":
                if ag.cerezler(self).get("oturum") == s["token"]:
                    self.yanit(200, _sayfa("Yönetim paneli",
                                           f"<p>Hoş geldin, {s['kullanici']}.</p>\n<p>Panel anahtarı: {s['bayrak2']}</p>"))
                else:
                    self.yanit(401, _sayfa("401 Yetkisiz", "<p>Bu sayfa için önce giriş yapmalısınız.</p>"))
            elif yol_k == yasak:
                self.yanit(403, _sayfa("403 Forbidden", "<p>Bu dizine erişim izniniz yok.</p>"))
            elif yol_k == s["eski_yol"].rstrip("/"):
                self.yanit(301, _sayfa("301 Moved Permanently", f"<p>Taşındı: {s['yeni_yol']}</p>"),
                           basliklar={"Location": s["yeni_yol"]})
            elif yol_k == s["yeni_yol"].rstrip("/"):
                self.yanit(200, _sayfa("Yeni sayfa", "<p>Bu içerik yeni adresine taşındı.</p>"))
            elif yol_k == "/api/urun":
                kimlik = sorgu.get("id", "1")
                if "'" in kimlik or '"' in kimlik:
                    self.yanit(500, "Internal Server Error\nYou have an error in your SQL syntax; check the manual "
                                    f"that corresponds to your MySQL server version for the right syntax to use near "
                                    f"''{kimlik}'' at line 1\n", tur="text/plain; charset=utf-8")
                else:
                    self.yanit(200, f'{{"id": "{kimlik}", "ad": "Ornek urun", "stok": 12}}\n',
                               tur="application/json")
            else:
                self.yanit(404, _sayfa("404 Not Found", "<p>Aradığınız sayfa bulunamadı.</p>"))

        def do_POST(self):
            yol, _ = ag.yol_ve_sorgu(self)
            form = ag.form_oku(self)
            if yol.rstrip("/") != "/giris":
                self.yanit(404, _sayfa("404 Not Found", "<p>Aradığınız sayfa bulunamadı.</p>"))
                return
            if form.get(k_alan) == s["kullanici"] and form.get(p_alan) == s["parola"]:
                self.yanit(302, _sayfa("Yönlendiriliyor", "<p>Giriş başarılı. <a href=\"/panel\">Panel</a></p>"),
                           basliklar={"Location": "/panel",
                                      "Set-Cookie": f"oturum={s['token']}; Path=/"})
            else:
                self.yanit(401, _sayfa("401 Yetkisiz", "<p>Hatalı kullanıcı adı veya parola.</p>"))

    calistir([http_sunucu("127.0.0.1", s["port"], Site)], dur)


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: curl ile siteyi gezer."""
    t = f"http://127.0.0.1:{s['port']}"
    b1 = _sh(f"curl -sI {t}/ | grep -o 'FLAG{{[^}}]*}}'", lab)
    gizli = _sh(f"for y in $(curl -s {t}/robots.txt | awk '/^Disallow/ {{print $2}}'); do "
                f"echo \"$y $(curl -s -o /dev/null -w '%{{http_code}}' {t}$y)\"; done | awk '$2==200 {{print $1}}'", lab)
    sayfa = _sh(f"curl -s {t}{gizli}", lab)
    kullanici = re.search(r"Kullanıcı: (\S+)", sayfa).group(1)
    parola = re.search(r"Parola: (\S+)", sayfa).group(1)
    alanlar = re.findall(r'name="([^"]+)"', _sh(f"curl -s {t}/giris", lab))
    token = _sh(f"curl -s -i -X POST -d '{alanlar[0]}={kullanici}&{alanlar[1]}={parola}' {t}/giris "
                "| grep -i '^Set-Cookie' | grep -o 'oturum=[^;]*' | cut -d= -f2", lab)
    b2 = _sh(f"curl -s -b 'oturum={token}' {t}/panel | grep -o 'FLAG{{[^}}]*}}'", lab)
    yeni = _sh(f"curl -sI {t}{s['eski_yol']} | grep -i '^Location' | awk '{{print $2}}' | tr -d '\\r'", lab)
    yasak = _sh(f"for y in $(grep -v '^#' yollar.txt); do echo \"$y $(curl -s -o /dev/null -w '%{{http_code}}' {t}$y)\"; "
                "done | awk '$2==403 {print $1}'", lab)
    return {1: b1, 2: gizli, 3: parola, 4: token, 5: b2, 6: yeni, 7: yasak,
            8: _secmeli(s, lab, 8), 9: _secmeli(s, lab, 9)}


# ---------------------------------------------------------------- sık hatalar

def _gizli_hata(g, beklenen, b):
    s = b.senaryo
    for y in s["robots"]:
        if y != s["gizli"] and g.strip("/") == y.strip("/"):
            return "Bu yol robots.txt'de var ama sunucu ona 404 diyor: artık yok. Hepsini dene, 200 döneni bul."
    return None


def _parola_hata(g, beklenen, b):
    if g == b.senaryo["kullanici"].casefold():
        return "Bu kullanıcı adı. Sayfadaki Parola satırını yaz."
    return None


def _token_hata(g, beklenen, b):
    if g.startswith("oturum="):
        return "Çerezin adını değil, sadece değerini yaz (oturum= kısmından sonrası, noktalı virgüle kadar)."
    return None


def _yasak_hata(g, beklenen, b):
    g = "/" + g.strip("/")
    if g == "/panel":
        return "Panel 401 dönüyor: 'önce giriş yap'. Giriş yapınca açılır. Aradığın, giriş yapsan da açılmayan yol (403)."
    if g == "/" + b.senaryo["eski_yol"].strip("/"):
        return "Bu yol 301 dönüyor: başka bir adrese taşınmış, yasak değil."
    if g == "/iletisim":
        return "Bu yol 200 dönüyor: herkese açık."
    if g in {"/" + y.strip("/") for y in b.senaryo["yollar"]}:
        return "Bu yol 404 dönüyor: sunucu 'böyle bir şey yok' diyor. Aradığın 'var ama yasak' diyen yol."
    return None


ADIMLAR = [
    Adim("İstek ve cevap", """
Web, **istek-cevap** mantığıyla çalışır: istemci (tarayıcı, curl) bir istek gönderir, sunucu
bir cevap döner. HTTP düz metindir; yani insan okuyabilir. Bir isteğin anatomisi:

```
GET /urunler/5 HTTP/1.1
Host: ornek.lab
User-Agent: Mozilla/5.0
Cookie: oturum=abc123
```

İlk satır: **metot** (GET), **yol** (/urunler/5) ve sürüm. Altındakiler **başlıklar** (headers).
Metotlar: `GET` veri al, `POST` veri gönder (form), `PUT` güncelle, `DELETE` sil, `HEAD` sadece
başlıkları al.

Cevap bir **durum koduyla** başlar:

- `2xx` başarı: `200 OK`
- `3xx` yönlendirme: `301` kalıcı taşındı, `302` geçici
- `4xx` istemci hatası: `401` yetkisiz (giriş yap), `403` yasak, `404` bulunamadı
- `5xx` sunucu hatası: `500` iç hata, `503` servis yok
"""),
    Adim("curl: komut satırındaki tarayıcı", """
`curl` komut satırından HTTP isteği göndermenin standart aracıdır. En yalın hali bir sayfayı
indirip içeriğini ekrana basar. <<musteri>> sitesinin iletişim sayfasını isteyelim:
""", komut="curl http://127.0.0.1:<<port>>/iletisim"),
    Adim("Perde arkası: curl -v", """
`-v` (verbose) isteği ve cevabı başlıklarıyla gösterir: `>` ile başlayan satırlar senin
gönderdiklerin, `<` ile başlayanlar sunucunun cevabı.
""", komut="curl -v http://127.0.0.1:<<port>>/iletisim", sonra="""
`Server:` başlığı sunucunun yazılımını ve çoğu zaman sürümünü ele verir. `Content-Type`
içeriğin türünü, `Content-Length` boyutunu söyler.

**Hacker gözüyle:** Tarayıcı sana sadece sunucunun göstermek istediğini gösterir; `curl -v` ham
gerçeği gösterir. Güvenlik başlıklarının (`Content-Security-Policy`, `Strict-Transport-Security`,
`X-Frame-Options`) eksikliği de bir bulgudur. Web testinin ilk adımı bu yüzden neredeyse her
zaman `curl -v`'dir.
"""),
    Adim("Sadece başlıklar: curl -I", """
`-I` sadece başlıkları ister (HEAD metodu). Sayfayı indirmeden "bu adres ne diyor?" diye
bakmanın en hızlı yolu. Geliştiricilerin unuttuğu hata ayıklama başlıkları da çoğu zaman
burada durur.
""", komut="curl -I http://127.0.0.1:<<port>>/iletisim"),
    Adim("Sadece durum kodu", """
Birçok yolu hızlıca denerken sayfanın kendisi değil, sadece durum kodu ilgini çeker. `-s`
sessiz, `-o /dev/null` gövdeyi çöpe at, `-w '%{http_code}\\n'` sadece kodu yaz:
""", komut="curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:<<port>>/boyle-bir-sayfa-yok", sonra="""
**Hacker gözüyle:** Dizin taramasında `403`, "burada bir şey var ama erişimin yok" demektir; bu
yüzden `404`'ten çok daha ilginçtir. `401` "giriş yap" derken `403` "giriş yapsan da olmaz" der.
`500` ise gönderdiğin girdinin sunucuyu şaşırttığını gösterir: bir enjeksiyon açığının ilk
ipucu olabilir.
"""),
    Adim("robots.txt", """
`robots.txt` sitenin kökünde durur ve arama motorlarına "şu yolları dizinleme" der. Ama bir
güvenlik önlemi **değildir**: herkes okuyabilir ve saldırganlar okur. Geliştiriciler bazen
gizlemek istedikleri yolları tam da buraya yazar; yani robots.txt, "bakmamamı istediğin yerler"
listesine dönüşür. Görevlerde bu dosyayı sen okuyacaksın.
"""),
    Adim("Formlar ve POST", """
Giriş formları kullanıcı adı ve parolayı **POST** ile, istek gövdesinde gönderir (GET olsaydı
parola adres çubuğuna ve loglara düşerdi). Formun hangi alan adlarını beklediğini sayfanın
HTML'inden okursun:
""", komut="curl http://127.0.0.1:<<port>>/giris", sonra="""
`<input ... name="<<k_alan>>">` ve `name="<<p_alan>>"`: sunucu bu iki alanı bekliyor. curl ile
formu doldurmak için `-X POST` metodu seçer, `-d` gövdeyi gönderir:

```
curl -i -X POST -d '<<k_alan>>=KULLANICI&<<p_alan>>=PAROLA' http://127.0.0.1:<<port>>/giris
```

`-i` cevabın başlıklarını da gösterir. `&` ve `=` kabuk için özel karakter olabileceğinden
veriyi tek tırnak içine yaz.
"""),
    Adim("Çerezler: oturumun anahtarı", """
HTTP hafızasızdır: her istek bağımsızdır. Sunucu seni hatırlamak için giriş başarılı olunca bir
**çerez** (cookie) atar: cevapta `Set-Cookie: oturum=...` başlığı gelir. Tarayıcı sonraki her
istekte bunu `Cookie: oturum=...` başlığıyla geri gönderir. curl'de bunu `-b` ile yaparsın:

```
curl -b 'oturum=DEGER' http://127.0.0.1:<<port>>/panel
```

**Hacker gözüyle:** Çerez, oturumun kendisidir. Bir saldırgan oturum çerezini çalarsa kullanıcı
adı ve parola bilmeden o kullanıcı gibi davranabilir (oturum çalma). XSS saldırılarının
(Cilt 5) en sık hedefi bu yüzden çerezlerdir.
"""),
]

GOREVLER = [
    Gorev("Ana sayfanın (`/`) yanıt başlıklarından biri, geliştiricinin unuttuğu bir hata ayıklama "
          "başlığı. İçindeki bayrağı bul.",
          Bayrak("bayrak1"),
          ("Sayfanın içeriğine değil, başlıklarına bakman gerek.",
           "`curl -I` sadece başlıkları gösterir.",
           "`curl -I http://127.0.0.1:<<port>>/` ve `X-` ile başlayan standart dışı başlık."),
          puan=25, baslik="Unutulan başlık"),
    Gorev("`robots.txt`'de arama motorlarından gizlenen yollardan **hangisi gerçekten açık** (200 "
          "dönüyor)?",
          Metin("gizli", sik_hatalar=_gizli_hata, bicim="yol (örn. /ornek/)"),
          ("robots.txt sitenin kökündedir.",
           "`curl http://127.0.0.1:<<port>>/robots.txt` her `Disallow:` satırında bir yol verir. Her birini dene.",
           "Her yol için `curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:<<port>>/YOL`; 200 döneni yaz."),
          puan=30, baslik="robots.txt"),
    Gorev("O gizli sayfada unutulmuş bir test hesabı var. Parolası ne?",
          Metin("parola", sik_hatalar=_parola_hata, bicim="parola"),
          ("Bir önceki görevde bulduğun yolu iste.",
           "`curl http://127.0.0.1:<<port>>/GIZLI_YOL/` ve sayfadaki `<pre>` bloğu.",
           "Sayfadaki `Parola:` satırının değeri."),
          puan=20, baslik="Unutulan hesap"),
    Gorev("Bu hesapla `/giris` formuna **POST** ile giriş yap. Giriş başarılı olunca sunucu `oturum` "
          "çerezine hangi değeri atıyor?",
          Metin("token", sik_hatalar=_token_hata, bicim="çerez değeri"),
          ("Önce formun hangi alan adlarını beklediğini öğren: `curl http://127.0.0.1:<<port>>/giris`.",
           "`curl -i -X POST -d '<<k_alan>>=...&<<p_alan>>=...' http://127.0.0.1:<<port>>/giris` ve "
           "`Set-Cookie` başlığı.",
           "`Set-Cookie: oturum=DEGER; Path=/` satırında `oturum=`'dan sonra, `;`'den önceki kısım."),
          puan=35, baslik="POST ile giriş"),
    Gorev("Bu çerezle korunan `/panel` sayfasına gir. Paneldeki anahtar (bayrak) ne?",
          Bayrak("bayrak2"),
          ("Çerezsiz istersen sunucu 401 der. Çerezi isteğe eklemelisin.",
           "curl'de çerez göndermek için `-b` seçeneği.",
           "`curl -b 'oturum=DEGER' http://127.0.0.1:<<port>>/panel`"),
          puan=35, baslik="Çerezle içeri"),
    Gorev("`<<eski_yol>>` adresi kalıcı olarak taşınmış. Sunucu seni **nereye** yönlendiriyor?",
          Metin("yeni_yol", bicim="yol (örn. /yeni/adres)"),
          ("Kalıcı taşınma hangi durum koduyla bildirilir ve yeni adres hangi başlıkta gelir?",
           "`curl -I http://127.0.0.1:<<port>><<eski_yol>>` ile başlıklara bak.",
           "`301` cevabındaki `Location:` başlığının değeri."),
          puan=25, baslik="Yönlendirme"),
    Gorev("`yollar.txt`'teki yollardan hangisi için sunucu \"burada bir şey var ama sana yasak\" "
          "diyor?",
          Metin("yasak", sik_hatalar=_yasak_hata, bicim="yol"),
          ("Her yol için durum kodunu öğrenmen gerek; sayfaların içeriği önemli değil.",
           "Eğitimdeki `curl -s -o /dev/null -w '%{http_code}\\n' ...` kalıbını her yol için çalıştır.",
           "`for y in $(grep -v '^#' yollar.txt); do echo $y $(curl -s -o /dev/null -w '%{http_code}' "
           "http://127.0.0.1:<<port>>$y); done` ve 'yasak' anlamına gelen kod."),
          puan=30, baslik="403 mü 404 mü"),
    Gorev("`/api/urun?id=5` normal çalışıyor; ama `id=5'` (sonuna tek tırnak) gönderince sunucu "
          "500 dönüyor ve bir SQL hata mesajı basıyor. Bu sana ne düşündürmeli?",
          Secmeli([
              ("Girdi denetlenmeden sorguya ekleniyor; SQL injection açığı olabilir",
               "Doğru. Tek tırnak sorgunun yapısını bozdu; girdi doğrudan SQL'e ekleniyor olabilir. Cilt 5'te derinleşeceğiz."),
              ("Sunucu aşırı yüklendi; birkaç dakika sonra aynı istek 200 döner",
               "Aşırı yük genelde 503 ile ve girdiden bağımsız görülür. Burada hatayı tetikleyen, gönderdiğin tırnak."),
              ("Tek tırnak URL'de geçersiz karakter; hata tamamen istemci tarafında",
               "İstemci kaynaklı hatalar 4xx'tir. 5xx, isteği işlerken sunucunun kendisinin hata yaptığını söyler."),
              ("Sayfa silinmiş; sunucu bunu yanlışlıkla 404 yerine 500 ile bildiriyor",
               "Silinmiş sayfa her girdide hata verir. Burada sadece tırnaklı girdi hata veriyor ve SQL'den söz ediyor."),
          ]),
          ("500 hangi tarafın hatasıdır? Ve hatayı ne tetikledi?",
           "Tırnaksız istek çalışıyor, tırnaklı istek bozuyor. Tırnak SQL'de ne işe yarar?",
           "Kullanıcı girdisi sorgunun bir parçası haline geliyor olabilir."),
          puan=20, baslik="500'ün anlattığı"),
    Gorev("Giriş formları parolayı neden genellikle GET değil **POST** ile gönderir?",
          Secmeli([
              ("POST veriyi URL'de değil gövdede taşır; parola adres çubuğuna düşmez",
               "Doğru. GET ile parola URL'ye yazılır; tarayıcı geçmişine, sunucu loglarına, Referer başlığına sızar."),
              ("POST istekleri tarayıcı tarafından otomatik olarak şifrelenir, GET şifrelenmez",
               "Şifrelemeyi metot değil HTTPS (TLS) sağlar. Düz HTTP'de POST gövdesi de açık metindir."),
              ("GET isteği ile en fazla sekiz karakterlik bir parola gönderilebilir",
               "Böyle bir sınır yok. URL'lerin pratik bir uzunluk sınırı vardır ama sekiz karakterden çok büyüktür."),
              ("POST istekleri sunucu loglarına hiç yazılmaz, bu yüzden saldırı izi kalmaz",
               "POST isteğinin satırı (metot, yol, kod) da loglanır; loglanmayan sadece gövdesidir."),
          ]),
          ("Bir GET isteğinde gönderilen veri isteğin neresinde durur?",
           "Adres çubuğu, tarayıcı geçmişi ve erişim logları neyi kaydeder?",
           "GET: veri URL'de. POST: veri gövdede."),
          puan=20, baslik="GET mi POST mu"),
]

SEVIYE = Seviye(
    kimlik="c02b05",
    cilt=2,
    bolum=5,
    baslik="HTTP: Web'in Dili",
    brifing="""
**<<musteri>>** sitesinin (<<site>>) kopyası **http://127.0.0.1:<<port>>/** adresinde çalışıyor.
Selin: "Tarayıcı yok, sadece curl. Başlıklar, çerezler ve durum kodları ne anlatıyor?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Bu seviyede bir saldırganın web'de izlediği klasik zinciri yürüdün: başlıklar bir sır verdi,
robots.txt gizlenmek istenen yolu gösterdi, o yolda unutulmuş bir test hesabı vardı, hesap bir
çerez getirdi ve çerez paneli açtı. Hiçbiri "hack" sayılmayacak kadar basit adımlardı; tehlike
tam da burada. Savunma tarafının dersleri: hata ayıklama başlıklarını canlıda kapat,
robots.txt'yi gizlilik aracı sanma, test hesaplarını ve sayfalarını yayından önce sil, oturum
çerezlerini `Secure` ve `HttpOnly` bayraklarıyla koru ve 500 hatalarında ayrıntılı veritabanı
mesajı gösterme.
""",
    gercek_hayat="""
- **Ayrıntılı hata mesajları:** OWASP'ın test rehberi (WSTG), uygulamanın hata mesajlarında
  yığın izi (stack trace) ya da SQL hatası göstermesini ayrı bir bilgi sızıntısı bulgusu olarak
  ele alır; bu mesajlar SQL injection gibi açıkların bulunmasını ciddi biçimde kolaylaştırır.
- **robots.txt ve gizli yollar:** Sızma testi raporlarında robots.txt'de listelenen yönetim
  ya da yedek dizinlerinin aslında erişilebilir olması tekrar tekrar görülen bir bulgudur.
  robots.txt bir erişim kontrolü değil, sadece arama motorlarına yapılan bir ricadır.
- **Oturum çerezleri:** Çerezlere `HttpOnly` bayrağı eklemek JavaScript'in (dolayısıyla XSS ile
  çalışan bir saldırganın) çerezi okumasını engeller; `Secure` bayrağı da çerezin düz HTTP
  üzerinden gönderilmesini önler. Web güvenliği rehberleri her ikisini de temel öneri olarak
  sayar.
""",
    sure_hedef_dk=30,
)
