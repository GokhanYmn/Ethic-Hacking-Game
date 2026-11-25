"""Cilt 4 · Bölüm 5 — Web Keşfi.

Beceri: yanıt başlıklarından teknoloji tespiti (Server, X-Powered-By), sayfa kaynağında unutulmuş yorum,
robots.txt ve sitemap.xml'den yol haritası, kelime listesiyle (curl döngüsü) bağlantısı verilmemiş yolları bulmak,
durum kodlarını (200/301/401/403/404) yorumlamak, açık /.git/ dizininin ne demek olduğunu bilmek ve dizin
taramasının web sunucusu logunda bıraktığı izi tanımak.

Servis: seviyenin web sitesi 127.0.0.1'de rastgele portta çalışır (`ortak.site_sunucusu`).

Vakalar: kafe sitesi (Atölye Kahve, Apache+PHP), belediye (Yeşiltepe, IIS+ASP.NET), fintech (Paramix, nginx+Express).
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Bayrak, Kume, Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

VAKALAR = [
    {
        "kod": "atolye", "server": "Apache/2.4.29 (Ubuntu)", "xp": "PHP/5.6.40", "ek": {},
        "yedek": "yedek", "admin": "yonetim", "yasak": "server-status", "robots_gercek": "/panel-eski/",
        "sitemap_gizli": "/kampanya-2023.html", "nav": ["/menu.html", "/subeler.html", "/hakkimizda.html", "/iletisim.html"],
        "kelime": "kelimeler.txt", "log": "erisim.log", "baslik": "Atölye Kahve",
        "brifing": """
**Atölye Kahve**'nin sahibi Berk, sitenin yeniden tasarımından önce Kalkan'dan bir keşif raporu istedi: "Dışarıdan
bakan biri sitemin içinde neler görür?" Selin sana sitenin laboratuvardaki kopyasının adresini verdi:
**http://127.0.0.1:<<port>>/**

Selin: "nmap portu buldu, ama web sitesinin içi ayrı bir iş. Bugün tarayıcı yok: `curl` ile başlıklara, sayfa
kaynağına, robots.txt'e bakacaksın."

Mert: "Siteyi yapan kişi bir şeyleri unutmuş olabilir. Yorum satırı, yedek klasörü... Kafe sitelerinde sık
görürüz."
""",
    },
    {
        "kod": "yesiltepe", "server": "Microsoft-IIS/7.5", "xp": "ASP.NET", "ek": {"X-AspNet-Version": "4.0.30319"},
        "yedek": "eski", "admin": "kontrol", "yasak": "bin", "robots_gercek": "/ebys-eski/",
        "sitemap_gizli": "/ihale-2022.aspx", "nav": ["/duyurular.aspx", "/ihaleler.aspx", "/meclis.aspx", "/iletisim.aspx"],
        "kelime": "yol_listesi.txt", "log": "web_erisim.log", "baslik": "Yeşiltepe Belediyesi",
        "brifing": """
**Yeşiltepe Belediyesi** e-belediye portalının yeni sürümünü yayına almadan önce Kalkan'dan keşif istedi.
Nurcan Hanım: "Eski portalı kuran firma gitti, içinde ne kaldığını bilmiyoruz." Portalın laboratuvardaki
kopyası **http://127.0.0.1:<<port>>/** adresinde.

Selin: "Bugün web sunucusunun kendini nasıl tanıttığına, hangi yolları açıkça yasakladığına ve yasaklamadığı
ama saklamadığı şeylere bakacaksın."

Deniz: "Bir de kendi tarafımızdan: belediyenin web sunucu loglarında bir tarama izi var mı? O da görevin parçası."
""",
    },
    {
        "kod": "paramix", "server": "nginx/1.14.0", "xp": "Express", "ek": {},
        "yedek": "backup", "admin": "admin", "yasak": "internal", "robots_gercek": "/docs-v1/",
        "sitemap_gizli": "/changelog-2023.html", "nav": ["/fiyat.html", "/gelistirici.html", "/destek.html", "/blog.html"],
        "kelime": "sozluk.txt", "log": "access.log", "baslik": "Paramix",
        "brifing": """
**Paramix** yeni geliştirici portalını açmadan önce web yüzeyinin dışarıdan nasıl göründüğünü öğrenmek istiyor.
CTO Ece Hanım: "Ekip hızlı çalıştı; geçmişte kalan bir şey var mı bakın." Portalın laboratuvardaki kopyası
**http://127.0.0.1:<<port>>/** adresinde.

Selin: "Teknoloji tespiti, robots.txt, sitemap ve kelime listesiyle yol bulma: dört parça. Hepsini `curl` ile
yapacaksın."

Mert: "Ve unutma: yüzlerce istek göndermek gürültüdür. Yetkin var ama bunu müşteriye söylemiş olman gerek."
""",
    },
]

DECOY_ROBOTS = ["/gizli-test/", "/tmp-yukleme/", "/eski-sunucu/", "/dev/", "/ozel-dosyalar/", "/rapor-arsivi/"]
DECOY_KELIME = ["login", "test", "dev", "api", "uploads", "images", "config", "wp-admin", "phpmyadmin", "db", "sql",
                "old", "tmp", "private", "files", "install", "setup", "cache", "logs", "docs", "download", "static"]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    port = rng.randint(20000, 45000)
    bayrak = u.bayrak(rng, rng.choice(["unutulan_not", "kayip_yedek", "sessiz_iz", "eski_yol"]))
    d = rng.sample(DECOY_ROBOTS, 2)
    robots = [d[0], v["robots_gercek"], d[1]]
    rng.shuffle(robots)
    bulunan = [v["yedek"], v["admin"], ".git/HEAD", v["yasak"]]
    decoy = [k for k in DECOY_KELIME if k not in bulunan]
    kelimeler = bulunan + rng.sample(decoy, 16)
    rng.shuffle(kelimeler)
    gun = u.gun(rng)
    # erişim logu: normal trafik, yoğun ama masum bir istemci, gobuster tarayıcısı
    tarayici, mesgul = u.benzersiz(rng, u.dis_ip, 2)
    normal_ipler = u.benzersiz(rng, u.dis_ip, 5, {tarayici, mesgul})
    satirlar = []
    t0 = gun + timedelta(hours=rng.randint(9, 14), minutes=rng.randint(0, 40))
    sayfalar = v["nav"] + ["/"]
    for i, ip in enumerate(normal_ipler * 4):
        t = t0 + timedelta(minutes=i * 3 + rng.randint(0, 2), seconds=rng.randint(0, 50))
        satirlar.append((t, u.apache_satiri(ip, t, "GET", rng.choice(sayfalar), 200, rng.randint(900, 5200),
                                            rng.choice(u.TARAYICI_UA))))
    for i in range(14):
        t = t0 + timedelta(minutes=i * 4 + 1, seconds=rng.randint(0, 59))
        satirlar.append((t, u.apache_satiri(mesgul, t, "GET", rng.choice(sayfalar), 200, rng.randint(900, 5200),
                                            rng.choice(u.TARAYICI_UA))))
    tara_bas = t0 + timedelta(minutes=rng.randint(20, 40))
    sozluk = kelimeler[:]
    for i, k in enumerate(sozluk):
        t = tara_bas + timedelta(seconds=i)
        kod, boyut = (404, 196)
        if k == v["yedek"]:
            kod, boyut = 301, 235
        elif k == v["admin"]:
            kod, boyut = 401, 381
        elif k == v["yasak"]:
            kod, boyut = 403, 279
        elif k == ".git/HEAD":
            kod, boyut = 200, 23
        satirlar.append((t, u.apache_satiri(tarayici, t, "GET", "/" + k, kod, boyut, u.ARAC_UA["gobuster"])))
    satirlar.sort(key=lambda x: x[0])
    nav0 = v["nav"][0]
    return {
        "vaka": f"{m['ad']} — web keşfi ({v['server'].split('/')[0]})",
        "brifing": v["brifing"], "v": v, "m": m, "port": port, "bayrak": bayrak, "robots": robots,
        "kelimeler": kelimeler, "bulunan": bulunan, "log": [x[1] for x in satirlar], "tarayici": tarayici,
        "mesgul": mesgul, "alan": alan,
        "metin": {
            "musteri": m["ad"], "port": port, "alan": alan, "kelime": v["kelime"], "log": v["log"],
            "sayfa0": nav0.lstrip("/"), "ornek_yol": "login", "sunucu_tur": v["server"].split("/")[0],
        },
        "cevaplar": {
            "server": [v["server"], v["server"].lower(), v["server"].split(" ")[0], v["server"].split(" ")[0].lower()],
            "xp": [v["xp"], v["xp"].lower()],
            "robots_gercek": [v["robots_gercek"], v["robots_gercek"].rstrip("/"), v["robots_gercek"].strip("/")],
            "yorum_yol": [f"/{v['yedek']}/", f"/{v['yedek']}", v["yedek"]],
            "kelimeler": bulunan, "bayrak": bayrak, "tarayici": tarayici,
            "sitemap": [v["sitemap_gizli"], v["sitemap_gizli"].lstrip("/")],
        },
    }


def _sayfa(baslik: str, govde: str, yorum: str = "") -> str:
    y = f"\n<!-- {yorum} -->" if yorum else ""
    return f"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{baslik}</title></head>\n<body>\n" \
           f"<h1>{baslik}</h1>\n{govde}{y}\n</body></html>\n"


def _rotalar(s: dict) -> dict:
    v = s["v"]
    baslik = v["baslik"]
    alan = s["alan"]
    nav = v["nav"]
    yedek = v["yedek"]
    nav_html = "<ul>\n" + "\n".join(f'  <li><a href="{p}">{p.strip("/").split(".")[0]}</a></li>' for p in nav) + "\n</ul>"
    r = {
        "/": (200, _sayfa(baslik, "<p>Hoş geldiniz.</p>\n" + nav_html,
                          f"TODO: eski yedekler /{yedek}/ altinda duruyor, yayindan once kaldirilacak")),
        "/robots.txt": (200, "User-agent: *\n" + "".join(f"Disallow: {y}\n" for y in s["robots"])
                        + f"Sitemap: http://{alan}/sitemap.xml\n", {"Content-Type": "text/plain"}),
        "/sitemap.xml": (200, '<?xml version="1.0" encoding="UTF-8"?>\n<urlset>\n'
                         + "".join(f"  <url><loc>https://{alan}{p}</loc></url>\n" for p in nav + [v["sitemap_gizli"]])
                         + "</urlset>\n", {"Content-Type": "application/xml"}),
        v["robots_gercek"]: (200, _sayfa(baslik + " — Eski Yönetim", "<p>Bu panel kullanımdan kaldırıldı.</p>")),
        v["sitemap_gizli"]: (200, _sayfa(baslik + " — Eski Duyuru", "<p>Bu sayfa arşivdedir.</p>")),
        f"/{yedek}": (301, "", {"Location": f"/{yedek}/"}),
        f"/{yedek}/": (200, _sayfa(f"Index of /{yedek}", '<ul><li><a href="not.txt">not.txt</a></li>'
                                   '<li><a href="eski_site.zip">eski_site.zip</a></li></ul>')),
        f"/{yedek}/not.txt": (200, f"Gecici not (silinecek): panel yedegi tasinirken buraya birakildi.\n{s['bayrak']}\n",
                              {"Content-Type": "text/plain"}),
        f"/{v['admin']}": (401, _sayfa("401", "<p>Yetkisiz.</p>"), {"WWW-Authenticate": 'Basic realm="Yonetim"'}),
        f"/{v['yasak']}": (403, _sayfa("403 Forbidden", "<p>Erişim engellendi.</p>")),
        "/.git/HEAD": (200, "ref: refs/heads/main\n", {"Content-Type": "text/plain"}),
    }
    for p in nav:
        r[p] = (200, _sayfa(p.strip("/").split(".")[0].capitalize(), "<p>İçerik.</p>", "sayfa sablonu v2"))
    return r


def servis(s: dict, lab: Path, dur) -> None:
    v = s["v"]
    ek = {"X-Powered-By": v["xp"], **v["ek"]}
    calistir([o.site_sunucusu("127.0.0.1", s["port"], v["server"], _rotalar(s), ek)], dur)


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['m']['ad']} sitesinin kopyası bu görev boyunca çalışıyor:\n  http://127.0.0.1:{s['port']}/\n\n"
          f"  {v['kelime']}   dizin keşfi için kelime listesi\n"
          f"  {v['log']}      sunucunun erişim logu (savunma tarafı)\n\n"
          f"Örnek: curl -I http://127.0.0.1:{s['port']}/\n")
    u.yaz(lab / v["kelime"], "\n".join(s["kelimeler"]) + "\n")
    u.yaz(lab / v["log"], "\n".join(s["log"]) + "\n")


# ---------------------------------------------------------------- sık hatalar

def _server_hata(g, beklenen, b):
    ad = b.senaryo["v"]["server"].split("/")[0].lower()
    if g == ad:
        return "Yazılımı buldun ama sürümüyle birlikte yaz: `Server:` başlığının değerini olduğu gibi (ad/sürüm)."
    return None


def _xp_hata(g, beklenen, b):
    if g in ("php", "express", "asp", "aspnet", "asp.net") and g != beklenen.lower():
        return "Başlığın değerini yazıldığı gibi yaz (sürüm numarası varsa onunla birlikte)."
    return None


def _robots_hata(g, beklenen, b):
    s = b.senaryo
    for y in s["robots"]:
        if g in (y.lower(), y.strip("/").lower()) and y != s["v"]["robots_gercek"]:
            return "Bu yol robots.txt'te var ama sunucu 404 veriyor; sayfa yok. Gerçekten **cevap veren** (200) yolu ara."
    return None


def _yorum_hata(g, beklenen, b):
    if g.strip("/") == b.senaryo["v"]["robots_gercek"].strip("/"):
        return "Bu robots.txt'teki yol. Sorulan, ANA SAYFANIN yorum satırında anılan yedek klasörü."
    return None


def _kume_hata(g, beklenen, b):
    return None


def _sitemap_hata(g, beklenen, b):
    if g.lstrip("/") in [p.lstrip("/") for p in b.senaryo["v"]["nav"]]:
        return "Bu sayfaya ana sayfadaki menüden zaten ulaşılıyor. Menüde olmayan ama sitemap'te listelenen sayfayı ara."
    return None


def _tarayici_hata(g, beklenen, b):
    if g == b.senaryo["mesgul"]:
        return "Bu IP çok istek yapmış ama hepsi 200 (başarılı) ve masum tarayıcı kimliğiyle. Tarama izi 404'lerin selidir."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    t = f"http://127.0.0.1:{s['port']}"
    server = o.sh(f"curl -sI {t}/ | tr -d '\\r' | grep -i '^server:' | cut -d' ' -f2-", lab)
    xp = o.sh(f"curl -sI {t}/ | tr -d '\\r' | grep -i '^x-powered-by:' | cut -d' ' -f2-", lab)
    gercek = o.sh(f"for y in $(curl -s {t}/robots.txt | grep -i '^Disallow' | cut -d' ' -f2); do "
                  f"c=$(curl -s -o /dev/null -w '%{{http_code}}' {t}$y); [ \"$c\" = 200 ] && echo $y; done", lab)
    yorum = o.sh(f"curl -s {t}/ | grep -o '<!--.*-->' | grep -o ' /[a-z0-9_-]*/'", lab).strip()
    kume = o.sh(f"for k in $(cat {v['kelime']}); do c=$(curl -s -o /dev/null -w '%{{http_code}}' {t}/$k); "
                f"[ \"$c\" != 404 ] && echo $k; done", lab)
    bayrak = o.sh(f"curl -s {t}{yorum}not.txt | grep -o 'FLAG{{[^}}]*}}'", lab)
    tarayici = o.sh(f"awk '$9==404 {{print $1}}' {v['log']} | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    sm = o.sh(f"for p in $(curl -s {t}/sitemap.xml | grep -o '<loc>[^<]*</loc>' | sed 's|<loc>https://[^/]*||;s|</loc>||'); do "
              f"curl -s {t}/ | grep -q \"href=\\\"$p\\\"\" || echo $p; done", lab)
    return {1: server, 2: xp, 3: gercek, 4: yorum, 5: kume, 6: bayrak, 7: tarayici, 8: sm,
            9: o.secmeli_cevap(SEVIYE, s, lab, 9)}


ADIMLAR = [
    Adim("Web keşfi: nereye bakılır", """
nmap bir web sunucusunun **portunu** bulur (80, 443, 8080...). Uygulamanın **içini** keşfetmek ayrı bir iştir:
hangi teknolojiyle çalışıyor, hangi yollar var, hangileri bağlantısı verilmeden saklı? Bu bölüm Cilt 5'teki web
saldırılarının zeminidir: bir şeyi test etmeden önce var olduğunu bilmelisin.

Bugün tarayıcı yerine `curl` kullanacağız. Tarayıcı sana sunucunun göstermek istediğini gösterir; `curl` ham
başlıkları ve ham sayfa kaynağını gösterir. Önce teknoloji tespiti: `-I` seçeneği yalnızca yanıt **başlıklarını**
ister.
""", komut="curl -I http://127.0.0.1:<<port>>/", sonra="""
İki başlık özellikle önemli:

- **Server**: web sunucusu yazılımı ve çoğu zaman sürümü.
- **X-Powered-By**: uygulamanın arkasındaki dil/çatı (PHP, ASP.NET, Express...).

Bu bilgi hangi zafiyetleri arayacağını söyler. Kali'de `whatweb <adres>` bu işi (ve CMS, JavaScript kütüphanesi
tespitini) tek komutta yapar, ama ham başlıkları okumak temeldir.
"""),
    Adim("Sayfa kaynağı ve yorumlar", """
Tarayıcıda görünmeyen ama sayfa kaynağında duran şeyler vardır: **yorum satırları** (`<!-- ... -->`), gizli
form alanları, eski bağlantılar. Geliştiriciler yayın öncesi notlarını bu satırlara yazıp silmeyi unutur.
Bir sayfanın ham kaynağını `curl -s` ile alırsın (`-s` ilerleme çubuğunu gizler):
""", komut="curl -s http://127.0.0.1:<<port>>/<<sayfa0>>", sonra="""
Küçük bir sayfa, küçük bir yorum. Aynı yöntemi ana sayfaya ve diğer sayfalara da uygulayacaksın:
**her sayfanın kaynağını oku**, yalnızca görüneni değil.
"""),
    Adim("robots.txt: yol haritası", """
`robots.txt` arama motorlarına "şu yolları dizinleme" der. Bu, site sahibinin **gizli tutmak istediği
yolların bir listesi** olabilir; saldırgan için bir yol haritasıdır. (Gizlilik değil, nezaket kuralıdır:
hiçbir şeyi engellemez.)
""", komut="curl -s http://127.0.0.1:<<port>>/robots.txt", sonra="""
Listedeki her yolun gerçekten var olup olmadığını **sınamak** gerekir: bazıları eski kalmıştır (404), bazıları hâlâ
cevap verir. Ayrıca `Sitemap:` satırı ikinci bir kaynağı gösteriyor.
"""),
    Adim("sitemap.xml", """
`sitemap.xml` arama motorlarına "sitemde şu sayfalar var" der. Sahibi sayfaları listelerken **menüye
koymadığı** (ama silmediği) sayfaları da yazmış olabilir: eski kampanyalar, taslaklar.
""", komut="curl -s http://127.0.0.1:<<port>>/sitemap.xml", sonra="""
`<loc>` etiketleri sayfa adreslerini verir. Menüdeki sayfalarla karşılaştır: menüde olmayan bir adres, "unutulmuş
ama hâlâ yayında" bir sayfadır.
"""),
    Adim("Durum kodları ve kelime listesi", """
Bir yolu denemek için yalnızca **durum koduna** bakmak yeter (`-o /dev/null` gövdeyi atar, `-w` kodu yazar):
""", komut="curl -s -o /dev/null -w \"%{http_code}\\n\" http://127.0.0.1:<<port>>/<<ornek_yol>>", sonra="""
Durum kodlarının dili:

- **200** var ve açık.  **301/302** başka bir adrese yönlendiriyor (genelde yol var, sonuna `/` ister).
- **401** var ve kimlik istiyor.  **403** var ama sana yasak.  **404** yok.

Yani **404 olmayan her cevap** bir ipucudur. Kelime listesiyle yol bulma (dizin keşfi) bunu otomatikleştirir:

```
for k in $(cat <<kelime>>); do
  c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:<<port>>/$k)
  [ "$c" != 404 ] && echo $k $c
done
```

Kali'de `gobuster dir -u <adres> -w <liste>` ve `ffuf -u <adres>/FUZZ -w <liste>` aynı işi çok daha hızlı yapar.
`<<kelime>>` içindeki `.git/HEAD` gibi alt yollu girdiler de çalışır.
"""),
    Adim("Gürültü ve açık .git", """
Dizin taraması hedefe **yüzlerce istek** gönderir: gürültülüdür, izinsiz yapılırsa suçtur. Aynı zamanda iz
bırakır: web sunucusu loglarında kısa sürede onlarca `404` ve `gobuster` ya da `ffuf` gibi araç adlarını taşıyan
tarayıcı kimliği (User-Agent) görürsün. Bu, savunmacının tarama tespiti yoludur.

Kelime listelerinde en değerli satırlardan biri **`.git/HEAD`**'dir: sitenin sunucusuna yanlışlıkla kopyalanmış
bir git deposunun işaretidir. Bu klasör açıksa sitenin bütün kaynak kodu ve değişiklik geçmişi indirilebilir
(parolalar, anahtarlar, iç mantık). Bunu bulursan **kanıt olarak o tek dosyayı** (örneğin HEAD) kaydet, raporla
ve dur: depoyu indirip içini karıştırmak keşfin değil sömürünün işidir.
""", calistir=False),
    Adim("Savunma tarafı: tarama izi", """
Aynı bilgiyi sunucunun **erişim logunda** görürsün. Lab'daki log dosyası, bir dizin taramasının izini taşıyor.
Tarama aracı adını User-Agent'ta açıkça yazıyor:
""", komut="grep -c gobuster <<log>>", sonra="""
Bir istemcinin kısa sürede çok sayıda `404` alması ve bir araç adı taşıması, tarama imzasıdır (Cilt 1'deki Nikto
taramasını hatırla). Savunma: tek IP'den gelen yüksek 404 oranına alarm kur, otomatik tarayıcı kimliklerini ve
hızlı istek seslerini engelleyen bir WAF ya da hız sınırlayıcı kullan.
"""),
]

GOREVLER = [
    Gorev("`http://127.0.0.1:<<port>>/` yanıtındaki **Server** başlığının tam değeri nedir?",
          Metin("server", sik_hatalar=_server_hata, bicim="Server başlığı değeri"),
          ("Yanıt başlıklarını görmek için `curl`'ün `-I` seçeneğini kullan.",
           "`curl -I http://127.0.0.1:<<port>>/` ve `Server:` satırı.",
           "`curl -sI http://127.0.0.1:<<port>>/ | grep -i '^server'`"),
          puan=20, baslik="Server başlığı"),
    Gorev("Aynı yanıtın **X-Powered-By** başlığındaki değer nedir? (Sürümüyle birlikte, yazıyorsa.)",
          Metin("xp", sik_hatalar=_xp_hata, bicim="başlık değeri"),
          ("Uygulamanın arkasındaki dili ya da çatıyı gösteren başlık.",
           "Aynı `curl -I` çıktısında `X-Powered-By` satırı.",
           "`curl -sI http://127.0.0.1:<<port>>/ | grep -i 'x-powered-by'`"),
          puan=20, baslik="X-Powered-By"),
    Gorev("`robots.txt` bazı yolları dizinlememeyi istiyor. Bunlardan **hangisi gerçekten var** (cevabı 200)?",
          Metin("robots_gercek", sik_hatalar=_robots_hata, on_ekleri_at=(), bicim="yol"),
          ("robots.txt'teki her yolu ayrı ayrı sınamalısın.",
           "Her yol için durum kodunu yazdır: `curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:<<port>><yol>`",
           "200 veren tek bir yol var; diğerleri 404."),
          puan=25, baslik="robots.txt'te gerçek olan"),
    Gorev("Ana sayfanın **kaynağındaki bir yorum satırında**, yayından önce kaldırılması gereken bir klasör "
          "anılıyor. Klasörün yolu nedir? (Örn. `/klasor/`)",
          Metin("yorum_yol", sik_hatalar=_yorum_hata, bicim="yol"),
          ("Tarayıcıda görünmeyen, sayfa kaynağında duran satırlar.",
           "`curl -s http://127.0.0.1:<<port>>/` çıktısında `<!--` ile başlayan satıra bak.",
           "`curl -s http://127.0.0.1:<<port>>/ | grep '<!--'`"),
          puan=25, baslik="Unutulmuş yorum"),
    Gorev("`<<kelime>>` içindeki kelimeleri `http://127.0.0.1:<<port>>/<kelime>` olarak dene. **404 dışında** cevap "
          "veren (200, 301, 401, 403) kelimelerin hepsini yaz. (Listede yazıldığı gibi, başına `/` koymadan.)",
          Kume("kelimeler", sik_hatalar=_kume_hata, bicim="boşlukla ayrılmış kelimeler"),
          ("Adım 5'teki döngüyü kendi listene uygula.",
           "Döngünün koşulunu `[ \"$c\" != 404 ] && echo $k` yap: sadece 404 olmayanlar yazılsın.",
           "`for k in $(cat <<kelime>>); do c=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:<<port>>/$k); "
           "[ \"$c\" != 404 ] && echo $k $c; done`"),
          puan=35, baslik="Kelime listesiyle dizin keşfi"),
    Gorev("Yorumda anılan klasörün içinde, yanlışlıkla bırakılmış bir not dosyası (`not.txt`) var. İçindeki "
          "bayrağı bul.",
          Bayrak("bayrak"),
          ("Klasörün dizin listesine bak, sonra içindeki dosyayı iste.",
           "`curl -s http://127.0.0.1:<<port>><klasör>/` ile listeyi gör; sonra `<klasör>/not.txt`.",
           "`curl -s http://127.0.0.1:<<port>><klasör>/not.txt`"),
          puan=25, baslik="Unutulan not"),
    Gorev("`<<log>>` sunucunun erişim logu. İçinde bir **dizin taraması** izi var: kısa sürede çok sayıda `404` "
          "üreten istemci. Bu istemcinin IP adresi nedir?",
          IP("tarayici", sik_hatalar=_tarayici_hata),
          ("Tarama araçları çoğu yolu bulamaz: yanıt kodu 404 olan satırları say.",
           "Apache log biçiminde durum kodu 9. alandır. Kodu 404 olan satırların IP'lerini grupla ve say.",
           "`awk '$9==404 {print $1}' <<log>> | sort | uniq -c | sort -rn | head -1`"),
          puan=30, baslik="Tarama izi"),
    Gorev("`sitemap.xml` listesindeki sayfalardan biri ana sayfanın menüsünde **bağlantısı olmayan** unutulmuş "
          "bir sayfa. Yolu nedir? (Örn. `/sayfa.html`)",
          Metin("sitemap", sik_hatalar=_sitemap_hata, bicim="yol"),
          ("Menüdeki sayfalarla sitemap'teki sayfaları karşılaştır.",
           "`curl -s http://127.0.0.1:<<port>>/sitemap.xml` ile listeyi, ana sayfanın kaynağıyla birlikte oku.",
           "Sitemap'te olup ana sayfada `href=\"...\"` olarak geçmeyen adres aradığındır."),
          puan=25, baslik="Menüde olmayan sayfa"),
    Gorev("Bir web sitesinde `/.git/` dizini erişilebilir durumda. Bu neden kritik bir bulgudur?",
          Secmeli([
              ("Sitenin kaynak kodu ve değişiklik geçmişi indirilebilir; içinde parola ve anahtarlar bulunabilir",
               "Doğru. Kaynak kod ve geçmiş iç mantığı, eski parolaları ve API anahtarlarını ele verir."),
              ("Yalnızca sitenin sürüm numarasını gösterir, bu yüzden düşük riskli bir bilgi sızıntısıdır",
               "Git deposu sürüm numarasından çok fazlasını taşır: bütün kod ve geçmiş indirilebilir."),
              ("Arama motorlarının siteyi dizinlemesini engeller, yani görünürlüğü kötü etkiler ve başka bir şey yapmaz",
               "Dizinleme ile ilgisi yok; `.git` bir sürüm kontrol deposudur."),
              ("Dizin listesi yalnızca görsel dosyaları gösterir, kaynak kod içermez ve tehlikesizdir",
               "Git deposu görselleri değil, kodun tamamını ve geçmişini içerir."),
          ], dogru=0),
          ("`.git` bir sürüm kontrol sisteminin dizinidir. Ne saklar?",
           "Kod ve onun bütün geçmişi.",
           "Geçmişte silinen parola ve anahtarlar bile kayıtlıdır."),
          puan=20, baslik="Neden .git kritik"),
]

SEVIYE = Seviye(
    kimlik="c04b05",
    cilt=4,
    bolum=5,
    baslik="Web Keşfi",
    brifing="""
**<<musteri>>**'nin sitesinin kopyası **http://127.0.0.1:<<port>>/** adresinde çalışıyor. Selin: "Tarayıcı kullanma,
`curl` kullan: hangi teknoloji, hangi yollar, hangi unutulmuş şeyler?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Birkaç `curl` ile sitenin teknolojisini (sunucu ve dil), unutulmuş yorumunu, robots ve sitemap'in sakladıklarını,
kelime listesiyle bulunan saklı yolları ve içinde unutulmuş bir notu çıkardın. Bir saldırgan aynı yolu izler:
sürüm bilgisinden zafiyet arar, yedek ve yönetim yollarını dener, açık `.git` bulursa kaynak koda ulaşır. Savunma
tarafında: yanıt başlıklarındaki sürüm bilgisini azalt, yayın öncesi sayfa kaynağını temizle, yedek ve eski
dosyaları web kökünde tutma, robots.txt'e gizli yol yazma, `.git` gibi dizinleri sunucu düzeyinde engelle ve
tarama izlerini (tek IP'den çok 404, araç adlı User-Agent) logda izle.
""",
    gercek_hayat="""
- **Açık .git dizinleri:** Web kökünde unutulmuş `.git` klasörleri, sızma testlerinde ve bug bounty programlarında
  çok sık raporlanan, kaynak kod ve parola sızıntısına yol açan bir bulgu türüdür. Önleme: dağıtım sırasında
  sadece derlenmiş dosyaları kopyala, web sunucusunda `.git` erişimini reddet. Tespit: kendi sitende
  `/.git/HEAD` istegini düzenli kontrol et.
- **Yedek ve eski dosyalar:** `yedek`, `backup`, `eski` gibi adlı klasörler ve `.bak`/`.old` dosyaları web
  kökünde unutulduğunda veritabanı parolalarını ele verir. Önleme: yedekleri web kökünün dışında sakla.
  Tespit: kendi sitene kelime listesiyle (yetkin varken) tarama yapmak ve 200/301 verenleri gözden geçirmek.
- **Tarama izi ve tespit:** Dizin taramaları loglarda tek bir IP'den kısa sürede çok sayıda 404 ve araç adlı
  User-Agent ile görünür. Tespit: bu örüntüye alarm kuran bir SIEM kuralı ya da WAF hız sınırı. Önleme: gereksiz
  yolları sunucudan kaldırmak, çünkü bulunamayan bir yol taramada hiçbir şey vermez.
""",
    sure_hedef_dk=30,
)
