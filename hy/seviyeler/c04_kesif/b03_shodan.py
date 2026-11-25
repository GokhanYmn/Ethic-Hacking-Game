"""Cilt 4 · Bölüm 3 — Shodan: İnternetin Arama Motoru.

Beceri: Shodan benzeri bir arama motorunun JSON verisini okumak, `org:` / `port:` / `ssl.cert.subject.cn:`
filtrelerini grep ve python ile taklit etmek, açık bırakılmış servisi, eski sürümü ve yanlış yapılandırmayı
(kimliksiz veritabanı, Telnet, açık dizin listesi) ayıklamak, aynı aracı savunma için kullanmak.

Gerçek Shodan'a hiçbir sorgu yapılmaz. Veri, Shodan'ın JSON çıktı biçimini taklit eden kurgusal bir dosyadır
(satır başına bir kayıt). Dış IP'ler yalnızca TEST-NET bloklarından; kurumlar kurgusaldır.

Vakalar: banka (Ferah Bank), belediye (Yeşiltepe Belediyesi), lojistik (Kuzgun Lojistik).
"""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

VAKALAR = [
    {
        "kod": "ferahbank", "org": "Ferah Bank A.S.", "sehir": "Istanbul", "db": "redis", "dosya": "shodan_cikti.json",
        "telnet_cihaz": "Sube Yonlendirici v2.1", "dizin_ad": "yedek_2026", "web": "nginx/1.24.0",
        "cert_ad": ["swift-test", "kart-test", "mobil-deneme"],
        "brifing": """
**Ferah Bank**'ın bilgi güvenliği müdürü Kaan Bey: "Bizim internetten nasıl göründüğümüzü bilmek istiyorum.
Şube sunucularımızdan biri dışarıya bir şey açıyor olabilir." Selin sana bir Shodan çıktısı verdi: bankanın
IP bloğunu ve alan adını kapsayan, kurgusal bir veri dosyası (<<dosya>>).

Selin: "Shodan'ı internetin arama motoru gibi düşün: o zaten her IP'yi ve her portu tarayıp cevapları
kaydetmiş. Biz yalnızca o kayıtları okuyoruz, bankanın sunucularına tek paket göndermiyoruz."

Deniz: "Bu aynı zamanda bizim aynamız. Saldırgan da aynı kaydı okuyor; onun gördüğünü biz de görmeliyiz."
""",
    },
    {
        "kod": "yesiltepe", "org": "Yesiltepe Belediyesi", "sehir": "Ankara", "db": "mongodb",
        "dosya": "internet_kaydi.json", "telnet_cihaz": "IP Kamera Yonetim Konsolu", "dizin_ad": "ihale_arsivi",
        "web": "Microsoft-IIS/10.0", "cert_ad": ["test-ebys", "eski-portal", "emlak-deneme"],
        "brifing": """
**Yeşiltepe Belediyesi**'nin bilgi işlem müdürü Nurcan Hanım: "Kent kameralarımızdan ihale arşivimize kadar
pek çok şey internete bağlı. Hangileri dışarıdan görünüyor, bilmiyorum." Selin sana kurgusal bir Shodan çıktısı
(<<dosya>>) verdi.

Selin: "Bu veri önceden toplanmış. Sen aratırken belediyenin sunucularına hiçbir şey gitmiyor; yani pasif
keşif. Ama belediyenin bilmediği şeyleri gösterebilir."

Mert: "Kamu kurumlarında 'bu cihaz kimin?' sorusu sık çıkar. Hangi kaydın gerçekten onlara ait olduğunu
ayırt etmen lazım."
""",
    },
    {
        "kod": "kuzgun", "org": "Kuzgun Lojistik Ltd.", "sehir": "Izmir", "db": "redis", "dosya": "tarama_arsivi.json",
        "telnet_cihaz": "El Terminali Agi Gecidi", "dizin_ad": "sevkiyat_yedek", "web": "Apache/2.4.57",
        "cert_ad": ["test-takip", "depo-deneme", "bayi-eski"],
        "brifing": """
**Kuzgun Lojistik**'in IT sorumlusu Serdar Bey: "Depo ağını yenilerken bazı cihazları geçici olarak
internete açtık. Hepsini kapattığımızdan emin değilim." Selin sana kurgusal bir Shodan çıktısı (<<dosya>>)
verdi.

Selin: "Veri tek satırda bir JSON kaydı. Filtreleri Shodan'daki gibi düşün: `org:`, `port:`, `ssl.cert.subject.cn:`.
Bizde bunlar grep ve python."

Mert: "Bir şeyi görmek yasal; ona bağlanmak değil. Sınırı hiç unutma."
""",
    },
]

ESKI_SSH = ["5.3", "5.9p1", "6.6.1p1", "6.7p1"]
YENI_SSH = ["7.4", "8.9p1", "9.2p1"]
YABANCI = ["Lab Yazilim Hizmetleri", "Mavi Ofis Danismanlik", "Orta Anadolu Tarim Koop."]
BARINDIRMA = "Lab Bulut Barindirma"


def _kayit(ip, port, org, host, sehir, urun, surum, data, modul, zaman, cn=None):
    r = {
        "ip_str": ip, "port": port, "transport": "tcp", "product": urun, "version": surum, "org": org,
        "hostnames": host, "domains": sorted({h.split(".", 1)[1] for h in host if "." in h}),
        "location": {"country_code": "TR", "city": sehir}, "timestamp": zaman,
        "data": data, "_shodan": {"module": modul},
    }
    if cn:
        r["ssl"] = {"cert": {"subject": {"CN": cn}, "expired": False}}
    return r


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan, org = m["alan"], v["org"]
    kullanilan: set = set()

    def ip():
        x = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(x)
        return x

    gun = u.gun(rng)

    def zaman():
        t = gun - timedelta(days=rng.randint(1, 40)) + timedelta(seconds=rng.randint(0, 86000))
        return f"{t:%Y-%m-%dT%H:%M:%S}.{rng.randint(100, 999)}"

    kayitlar = []
    sehir = v["sehir"]
    # kuruma ait ana makineler
    ip_web, ip_mail, ip_yeni = ip(), ip(), ip()
    yeni_sv = rng.choice(YENI_SSH[1:])
    web_surum = v["web"].split("/")[1]
    web_data = f"HTTP/1.1 200 OK\r\nServer: {v['web']}\r\nContent-Type: text/html\r\n\r\n"
    kayitlar += [
        _kayit(ip_web, 80, org, [f"www.{alan}"], sehir, v["web"].split("/")[0], web_surum, web_data[:60] + "...", "http", zaman()),
        _kayit(ip_web, 443, org, [f"www.{alan}"], sehir, v["web"].split("/")[0], web_surum, web_data[:60] + "...", "https", zaman(),
               cn=f"www.{alan}"),
        _kayit(ip_mail, 25, org, [f"mail.{alan}"], sehir, "Postfix smtpd", "", f"220 mail.{alan} ESMTP Postfix\r\n", "smtp", zaman()),
        _kayit(ip_mail, 22, org, [f"mail.{alan}"], sehir, "OpenSSH", "9.2p1", "SSH-2.0-OpenSSH_9.2p1\r\n", "ssh", zaman()),
        _kayit(ip_yeni, 22, org, [], sehir, "OpenSSH", rng.choice(YENI_SSH[1:]), "SSH-2.0-OpenSSH_8.9p1\r\n", "ssh", zaman()),
    ]
    # eski OpenSSH: ilk makinede iki kayıt (22 ve 2222), IP sayısı ile kayıt sayısı farklı olsun
    eski_sayisi = rng.choice([2, 3])
    eski_ipler = [ip() for _ in range(eski_sayisi)]
    eski_surumler = rng.sample(ESKI_SSH, eski_sayisi)
    for i, (x, sv) in enumerate(zip(eski_ipler, eski_surumler)):
        portlar = [22, 2222] if i == 0 else [22]
        for p in portlar:
            kayitlar.append(_kayit(x, p, org, [], sehir, "OpenSSH", sv, f"SSH-2.0-OpenSSH_{sv}\r\n", "ssh", zaman()))
    # veritabanları: biri kimliksiz (açık), biri kimlik istiyor
    d_ac, d_kapali, d_yabanci = ip(), ip(), ip()
    if v["db"] == "redis":
        acik = ("Redis key-value store", "4.0.9", 6379, "redis",
                "# Server\r\nredis_version:4.0.9\r\nredis_mode:standalone\r\nos:Linux 4.19.0-21-amd64 x86_64\r\n"
                "tcp_port:6379\r\nuptime_in_days:212\r\n")
        kapali = ("Redis key-value store", "6.2.14", 6379, "redis", "-NOAUTH Authentication required.\r\n")
    else:
        acik = ("MongoDB", "3.4.24", 27017, "mongodb",
                "MongoDB Server Information\n{\n  \"ok\": 1,\n  \"version\": \"3.4.24\",\n"
                "  \"databases\": [\"admin\", \"ebys\", \"local\"]\n}")
        kapali = ("MongoDB", "6.0.12", 27017, "mongodb",
                  "MongoDB Server Information\n{\n  \"ok\": 0,\n  \"errmsg\": \"command listDatabases requires authentication\"\n}")
    kayitlar.append(_kayit(d_ac, acik[2], org, [], sehir, acik[0], acik[1], acik[4], acik[3], zaman()))
    kayitlar.append(_kayit(d_kapali, kapali[2], org, [], sehir, kapali[0], kapali[1], kapali[4], kapali[3], zaman()))
    yab_org = rng.choice(YABANCI)
    kayitlar.append(_kayit(d_yabanci, acik[2], yab_org, [], "Bursa", acik[0], acik[1], acik[4], acik[3], zaman()))
    # Telnet
    t_ip, t_yab = ip(), ip()
    tdata = f"\r\n{v['telnet_cihaz']}\r\nlogin: "
    kayitlar.append(_kayit(t_ip, 23, org, [], sehir, "Linux telnetd", "", tdata, "telnet", zaman()))
    kayitlar.append(_kayit(t_yab, 23, yab_org, [], "Bursa", "Linux telnetd", "", "\r\nlogin: ", "telnet", zaman()))
    # Açık dizin listesi
    x_ip = ip()
    x_port = rng.choice([8000, 8080, 8888, 9000])
    xdata = ("HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.6.9\r\nContent-type: text/html; charset=utf-8\r\n\r\n"
             f"<!DOCTYPE HTML>\n<title>Directory listing for /</title>\n<h1>Directory listing for /</h1>\n"
             f"<li><a href=\"{v['dizin_ad']}.zip\">{v['dizin_ad']}.zip</a></li>")
    kayitlar.append(_kayit(x_ip, x_port, org, [], sehir, "Python http.server", "3.6.9", xdata, "http", zaman()))
    kayitlar.append(_kayit(x_ip, 22, org, [], sehir, "OpenSSH", "9.2p1", "SSH-2.0-OpenSSH_9.2p1\r\n", "ssh", zaman()))
    # başka bir kurumun eski ssh'ı (org filtresi olmadan yanlış sayılır)
    y_ssh = ip()
    kayitlar.append(_kayit(y_ssh, 22, yab_org, [], "Bursa", "OpenSSH", rng.choice(ESKI_SSH), "SSH-2.0-OpenSSH_5.3\r\n", "ssh", zaman()))
    # kurumun alan adıyla sertifikalı ama başka bir barındırma sağlayıcısındaki unutulmuş test sunucusu
    c_ip = ip()
    cn = f"{rng.choice(v['cert_ad'])}.{alan}"
    kayitlar.append(_kayit(c_ip, 443, BARINDIRMA, [], "Frankfurt", "nginx", "1.14.0",
                           "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n\r\n", "https", zaman(), cn=cn))
    rng.shuffle(kayitlar)

    org_ipler = sorted({r["ip_str"] for r in kayitlar if r["org"] == org})
    farkli = len({r["ip_str"] for r in kayitlar})
    eski_kayit = sum(1 for r in kayitlar if r["org"] == org and r["product"] == "OpenSSH"
                     and int(r["version"].split(".")[0]) < 7)
    return {
        "vaka": f"{m['ad']} — Shodan verisi ({org})",
        "brifing": v["brifing"], "v": v, "m": m, "kayitlar": kayitlar, "org": org, "gun": gun,
        "metin": {"musteri": m["ad"], "alan": alan, "dosya": v["dosya"], "org": org, "port_db": acik[2]},
        "cevaplar": {
            "farkli_ip": farkli, "org_ipler": org_ipler, "acik_db": d_ac, "telnet": t_ip,
            "eski_ssh": eski_sayisi, "cert_ip": c_ip, "dizin_port": x_port,
        },
        "yanlis": {
            "kapali_db": d_kapali, "yab_db": d_yabanci, "yab_telnet": t_yab, "eski_kayit": eski_kayit,
            "kayit_sayisi": len(kayitlar), "yab_ssh": y_ssh, "org_hepsi": org_ipler,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / v["dosya"], "\n".join(json.dumps(r, ensure_ascii=False) for r in s["kayitlar"]) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['m']['ad']} için kurgusal Shodan verisi. Gerçek Shodan'a sorgu yapılmaz.\n\n"
          f"  {v['dosya']}  satır başına bir JSON kaydı (bir IP:port için tek banner)\n\n"
          f"Kurum: {s['org']}   Alan adı: {s['m']['alan']}\n\n"
          "Shodan filtresi → bu dosyadaki alan:\n"
          "  org:\"...\"                  → \"org\"\n"
          "  port:443                    → \"port\"\n"
          "  product:nginx               → \"product\"\n"
          "  ssl.cert.subject.cn:...     → \"ssl\" → \"cert\" → \"subject\" → \"CN\"\n"
          "Banner'ın kendisi \"data\" alanındadır.\n")


# ---------------------------------------------------------------- sık hatalar

def _farkli_hata(g, beklenen, b):
    if str(g) == str(b.senaryo["yanlis"]["kayit_sayisi"]):
        return "Bu satır (kayıt) sayısı. Aynı IP birden fazla portla birden çok kez geçiyor; benzersiz IP'leri say."
    return None


def _db_hata(g, beklenen, b):
    y = b.senaryo["yanlis"]
    if g == y["kapali_db"]:
        return "Bu veritabanı kimlik istiyor (banner'ında kimlik doğrulama gerektiğini söylüyor). Kimliksiz olanı ara."
    if g == y["yab_db"]:
        return "Bu veritabanı kimliksiz ama `org` alanı başka bir kuruma ait. Soru <<org>>'in sistemini soruyor.".replace(
            "<<org>>", b.senaryo["org"])
    return None


def _telnet_hata(g, beklenen, b):
    if g == b.senaryo["yanlis"]["yab_telnet"]:
        return "Bu Telnet cihazı başka bir kuruma ait (`org` alanına bak)."
    return None


def _ssh_hata(g, beklenen, b):
    y = b.senaryo["yanlis"]
    if str(g) == str(y["eski_kayit"]) and y["eski_kayit"] != beklenen:
        return "Bu kayıt sayısı. Aynı IP iki portta (22 ve 2222) görünüyor; benzersiz IP sayısını ver."
    return None


def _cert_hata(g, beklenen, b):
    if g in b.senaryo["yanlis"]["org_hepsi"]:
        return "Bu IP kurumun kendi bloğunda. Sertifikada kurumun alan adı olan ama `org`'u başka biri olan kaydı ara."
    return None


# ---------------------------------------------------------------- test çözücüsü

def _py(kod: str, lab: Path, s: dict) -> str:
    on = (f"import json\nR=[json.loads(l) for l in open('{s['v']['dosya']}')]\nORG='{s['org']}'\n"
          f"ALAN='{s['m']['alan']}'\n")
    return o.sh("python3 - <<'PY'\n" + on + kod + "\nPY", lab)


def coz(lab: Path, s: dict) -> dict:
    return {
        1: _py("print(len({r['ip_str'] for r in R}))", lab, s),
        2: _py("print(*sorted({r['ip_str'] for r in R if r['org']==ORG}))", lab, s),
        3: _py("print(*[r['ip_str'] for r in R if r['org']==ORG and r['port'] in (6379,27017) "
               "and 'NOAUTH' not in r['data'] and 'requires authentication' not in r['data']])", lab, s),
        4: _py("print(*[r['ip_str'] for r in R if r['org']==ORG and r['port']==23])", lab, s),
        5: _py("print(len({r['ip_str'] for r in R if r['org']==ORG and r['product']=='OpenSSH' "
               "and int(r['version'].split('.')[0])<7}))", lab, s),
        6: _py("print(*[r['ip_str'] for r in R if r.get('ssl',{}).get('cert',{}).get('subject',{}).get('CN','')"
               ".endswith(ALAN) and r['org']!=ORG])", lab, s),
        7: _py("print(*[r['port'] for r in R if r['org']==ORG and 'Directory listing' in r['data']])", lab, s),
        8: o.secmeli_cevap(SEVIYE, s, lab, 8),
        9: o.secmeli_cevap(SEVIYE, s, lab, 9),
    }


ADIMLAR = [
    Adim("Shodan nedir, nasıl çalışır?", """
Google web sayfalarını dizinler; **Shodan** ise internete bağlı **cihazları** dizinler. Sürekli olarak
internetteki IP adreslerini ve portları tarar, her servisin verdiği ilk cevabı (**banner**) kaydeder:
hangi yazılım, hangi sürüm, hangi ülke, hangi sertifika. Böylece "internette açık olan tüm X" aranabilir
hale gelir: kameralar, router'lar, veritabanları, endüstriyel sistemler.

Önemli nokta: bu veri **önceden toplanmıştır**. Sen Shodan'da arama yaparken hedefe tek paket bile
gitmez; bu yüzden Shodan **pasif keşiftir**. (nmap ise canlı tarar: aktif.)

Burada gerçek Shodan yok. Selin, Shodan'ın JSON çıktı biçimini taklit eden kurgusal bir veri dosyası
hazırladı: <<dosya>>. Önce görevin kuralını okuyalım:
""", komut="cat OKUBENI.txt"),
    Adim("Bir kayıt neye benzer?", """
Dosyada satır başına bir JSON kaydı var; her kayıt bir IP'nin bir portundaki banner'dır. İlk kaydı
okunur biçimde bakalım:
""", komut="head -n 1 <<dosya>> | python3 -m json.tool", sonra="""
Önemli alanlar: `ip_str` (IP), `port`, `product` ve `version` (yazılım ve sürümü), `org` (IP bloğunun
sahibi olan kurum ya da barındırma firması), `hostnames`, `ssl.cert.subject.cn` (sertifikadaki ad) ve
`data` (servisin ham cevabı). Uyarı: `org`, IP'nin **kayıtlı sahibini** gösterir; bir kuruma ait ama başka bir
barındırma firmasındaki sunucu `org` ile bulunmaz. Onu sertifika adı gösterir.
"""),
    Adim("Filtre = grep", """
Shodan'ın gücü **filtrelerdedir**: `port:3389`, `org:"Kurum"`, `product:nginx`,
`ssl.cert.subject.cn:ornek.com`. Bizim dosyada aynı iş `grep` ile yapılır. Kaç kayıtta 443 portu var?
""", komut="grep -c '\"port\": 443' <<dosya>>", sonra="""
Filtreler **birleştirilebilir**: Shodan'da `org:"Kurum" port:23`. Burada bunu boru (`|`) ile iki `grep`
zincirleyerek ya da python ile yaparsın.
"""),
    Adim("Python ile filtre", """
Birden fazla koşul gerektiğinde python daha rahattır: JSON'u gerçekten ayrıştırır, alan alan karşılaştırır.
Örnek: 443 portunda hangi IP'ler var?
""", komut="python3 -c \"import json;[print(r['ip_str'],r['product']) for r in map(json.loads,open('<<dosya>>')) if r['port']==443]\"",
         sonra="""
Aynı kalıbı `r['org']=='...'`, `'metin' in r['data']` ya da `int(r['version'].split('.')[0])<7` gibi koşullarla
genişletirsin. Görevlerde bu kalıbı kullanacaksın.
"""),
    Adim("Banner'ı yorumlamak", """
Bir banner üç şey söyler: **ne** çalışıyor, **hangi sürüm** ve **nasıl yapılandırılmış**. Bir veritabanı
banner'ı örnek: kimlik doğrulaması olan bir Redis ya da MongoDB bağlanana `-NOAUTH Authentication required`
ya da `requires authentication` der. Kimliksiz olan ise sorgulayana sunucu bilgisini (sürüm, veritabanı adları)
**olduğu gibi döker**: bu, internetteki herkesin o veriye erişebileceği anlamına gelir.
""", komut="grep -c NOAUTH <<dosya>>", sonra="""
Kimlik isteyen kayıt sayısı yukarıda. Kimliksiz olanlar bu aramaya takılmaz: onları bulmak için "veritabanı
portunda olup kimlik istemeyen" koşulu yazmalısın. Aynı mantık Telnet (şifresiz uzaktan yönetim), açık dizin
listesi (`Directory listing for /`) ve eski sürümler için geçerli.

**Hacker gözüyle:** Shodan bir kurumun "dışarıdan nasıl göründüğünü" tek paket göndermeden gösterir.
`org:` ve `ssl.cert.subject.cn:` filtreleriyle bir kuruma ait tüm açık sistemleri haritalayabilirsin.
"""),
    Adim("Savunma tarafı: ayna", """
Savunmacı için Shodan bir **aynadır**. Kurumlar düzenli olarak kendi `org` adlarını ve IP aralıklarını
aratıp "dışarıdan ne görünüyor?" diye bakmalıdır, çünkü saldırgan kesinlikle bakıyor. Shodan Monitor gibi
izleme servisleri, kendi IP'lerinde beklenmeyen bir servis açıldığında ya da zafiyetli bir sürüm göründüğünde
uyarı gönderir. Kendi sertifika adlarını da izle: bir test sunucusu kuruluşun alan adıyla başka bir
barındırma firmasında yayına girmiş olabilir.
""", calistir=False),
    Adim("Görmek ile girmek", """
**Shodan'da bir sistemi görmek yasaldır; o sisteme bağlanmak, veri çekmek ya da değiştirmek değildir.**
Kimliksiz bir veritabanı gördüğünde etik hacker not alır, ilgili kuruma (yetkiliyse müşterisine) bildirir ve
durur. Kimliksiz bir sunucuya "sadece bakmak için" girmek bile TCK 243/244 kapsamında suç olabilir:
görmek ile girmek farklıdır.
""", calistir=False),
]

GOREVLER = [
    Gorev("<<dosya>> içinde kaç **farklı** IP adresi var? (Aynı IP birden çok port ile geçebilir.)",
          Sayi("farkli_ip", sik_hatalar=_farkli_hata),
          ("Bir IP birden fazla satırda (farklı portlarla) geçiyor. Sayman gereken benzersiz IP'ler.",
           "`ip_str` değerlerini ayıkla, tekrarları at (`sort -u` ya da python `set`).",
           "`python3 -c \"import json;print(len({json.loads(l)['ip_str'] for l in open('<<dosya>>')}))\"`"),
          puan=20, baslik="Kaç farklı IP"),
    Gorev("`org` alanı **<<org>>** olan (yani Shodan'da `org:\"<<org>>\"` filtresiyle çıkan) bütün IP'leri yaz.",
          Kume("org_ipler", tur="ip"),
          ("Filtre `org`: tam kurum adını `org` alanında ara.",
           "Her kayıtta `org` alanını `<<org>>` ile karşılaştır, `ip_str`'leri topla, tekrarları at.",
           "`python3 -c \"import json;print(*sorted({r['ip_str'] for r in map(json.loads,open('<<dosya>>')) "
           "if r['org']=='<<org>>'}))\"`"),
          puan=30, baslik="org: filtresi"),
    Gorev("<<org>>'e ait bir veritabanı sunucusu **kimlik doğrulaması olmadan** sorgulara cevap veriyor "
          "(banner'ı bilgi döküyor, kimlik istemiyor). IP'si nedir?",
          IP("acik_db", sik_hatalar=_db_hata),
          ("Veritabanı portları: Redis 6379, MongoDB 27017. Kimlik isteyen banner farklı görünür.",
           "`org` <<org>> olan ve portu <<port_db>> olan kayıtları listele, `data` alanlarını karşılaştır.",
           "Banner'da `NOAUTH` ya da `requires authentication` GEÇMEYEN, org'u doğru olan kayıt aradığındır."),
          puan=35, baslik="Kimliksiz veritabanı"),
    Gorev("<<org>>'e ait hangi IP'de **Telnet** (port 23) açık?",
          IP("telnet", sik_hatalar=_telnet_hata),
          ("Telnet'in standart portu 23. Soruda kurum da belirtilmiş.",
           "`port` 23 olan kayıtları `org` filtresiyle birleştir.",
           "Telnet ayrıca bu görevde başka bir kuruma ait bir cihaz için de görünüyor; `org` ile ayır."),
          puan=25, baslik="Telnet açık"),
    Gorev("<<org>>'e ait IP'lerden **kaçında** (benzersiz IP olarak) OpenSSH'ın 7.0'dan **eski** bir sürümü çalışıyor?",
          Sayi("eski_ssh", sik_hatalar=_ssh_hata),
          ("`product` alanı OpenSSH olan kayıtlara bak; `version` alanı sürümü verir.",
           "Sürümün ilk sayısı 7'den küçükse eskidir. Bir IP iki portta görünebilir: IP'leri say, kayıtları değil.",
           "`int(r['version'].split('.')[0])<7` koşulunu `org` filtresiyle birleştir ve `set` kullan."),
          puan=30, baslik="Eski OpenSSH"),
    Gorev("`ssl.cert.subject.cn` alanı `<<alan>>` ile biten ama `org`'u <<org>> **olmayan** (başka bir barındırma "
          "firmasında duran) kaydın IP'si nedir?",
          IP("cert_ip", sik_hatalar=_cert_hata),
          ("Kurumun alan adı sertifikada geçiyor ama IP bloğu kurumun değil.",
           "`ssl` alanı olan kayıtlarda `CN`'yi `<<alan>>` ile karşılaştır, sonra `org`'u ele.",
           "`r.get('ssl',{}).get('cert',{}).get('subject',{}).get('CN','').endswith('<<alan>>')` ve `r['org']!='<<org>>'`"),
          puan=35, baslik="Sertifikadan bulunan sunucu"),
    Gorev("<<org>>'e ait bir sunucu, banner'ında `Directory listing for /` geçen bir web servisi çalıştırıyor "
          "(açık dizin listesi). Bu servis **hangi portta**?",
          Sayi("dizin_port"),
          ("Açık dizin listesi bir yanlış yapılandırmadır: sayfa yok, dosya listesi var.",
           "`data` alanında `Directory listing` ifadesini ara ve `org`'u kontrol et.",
           "`grep 'Directory listing' <<dosya>>` satırında `\"port\":` değerine bak."),
          puan=25, baslik="Açık dizin"),
    Gorev("Bir kurum kendi internet görünümünü Shodan'la **savunma amaçlı** nasıl kullanmalıdır?",
          Secmeli([
              ("Kendi org adını ve IP aralıklarını düzenli sorgulayıp beklenmeyen açık servis için uyarı almalı",
               "Doğru. Saldırganın gördüğünü sen de görürsün ve yeni açılan her servisi hemen fark edersin."),
              ("Shodan'da çıkan kayıtların silinmesi için Shodan'a başvurmalı; kayıt kalkınca servis de güvenli sayılır",
               "Kayıt silinse bile servis açık kalır ve tarayıcılar yeniden bulur. Çözüm servisi kapatmaktır."),
              ("Dışarıdan bakmaya gerek yok; iç ağı haftada bir tarayıp sonuçları saklamak yeterli bir görünüm sağlar",
               "İç tarama dışarıdan görünenle aynı değildir; güvenlik duvarında yanlışlıkla açılan bir port yalnızca "
               "dışarıdan fark edilir."),
              ("Yılda bir kez güvenlik duvarı kurallarını elle gözden geçirmek, tarayıcı araçlarından daha güvenilirdir",
               "Kural gözden geçirmek yararlı ama yılda bir yetersiz; yeni açılan servisleri sürekli izleme yakalar."),
          ], dogru=0),
          ("Saldırgan senin hakkında hangi kaydı okuyor? Sen de aynısını nasıl okursun?",
           "Sürekli ve dışarıdan bakan bir izleme istiyoruz.",
           "Kendi varlıklarını internetin gözüyle düzenli denetlemek."),
          puan=20, baslik="Savunmada Shodan"),
    Gorev("Shodan'da bir kurumun kimliksiz MongoDB sunucusunu gördün. Bir etik hacker olarak ne yaparsın?",
          Secmeli([
              ("Bulguyu not edip yetkiliyse kuruma bildirir, veritabanına bağlanmazsın",
               "Doğru. Görmek yasaldır; bağlanmak, veri okumak ya da değiştirmek TCK 243/244 kapsamında suçtur."),
              ("Sadece birkaç kaydın içeriğini okuyup sunucunun gerçekten açık olduğunu kanıtlarsın, sonra çıkarsın",
               "Veriyi okumak yetkisiz erişimdir; açık olması izin anlamına gelmez. Kanıt olarak Shodan kaydı yeter."),
              ("Veritabanındaki bütün veriyi yedekleyip sahibine geri vereceğini söylersin",
               "Veriyi çekmek, iyi niyetle bile olsa, veri ihlalidir ve KVKK'ya aykırı kopya üretir."),
              ("Sunucuyu kapatmak için bir komut gönderirsin, böylece saldırganlar kullanamaz",
               "Başkasının sistemine müdahale yetkisizdir; bildirmek senin işin, kapatmak sahibinin."),
          ], dogru=0),
          ("Görmek ile girmek arasındaki çizgi.",
           "Hangi eylemler yetkisiz erişim sayılır?",
           "Raporla, bildir, dur."),
          puan=25, baslik="Görmek, girmek değildir"),
]

SEVIYE = Seviye(
    kimlik="c04b03",
    cilt=4,
    bolum=3,
    baslik="Shodan: İnternetin Arama Motoru",
    brifing="""
**<<musteri>>** için kurgusal bir Shodan çıktısını (<<dosya>>) inceliyorsun. Selin: "Bu veri önceden toplanmış:
hedefe tek paket gitmiyor. Dışarıdan nasıl göründüğümüze bir bak: açık bırakılmış servis, eski sürüm,
yanlış yapılandırma ara."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Tek bir JSON dosyasından, kuruma ait kimliksiz bir veritabanını, Telnet'i, eski OpenSSH sürümlerini, açık
dizin listesini ve başka bir barındırma firmasında unutulmuş bir test sunucusunu buldun; hedefe tek paket
göndermeden. Saldırgan da aynı kayıtları okuyor. Savunma tarafının dersi: kendi `org` adını, IP aralıklarını
ve sertifika adlarını düzenli olarak aynı gözle ara; yeni açılan her servisi hemen fark et; kimlik doğrulamasız
servis, Telnet ve açık dizin listesi internete hiç çıkmasın. Ve etik sınır: Shodan'da görmek yasaldır, bağlanmak
suçtur.
""",
    gercek_hayat="""
- **Kimliksiz veritabanları ve fidye:** 2017 başında internete açık, kimlik doğrulaması olmayan çok sayıda
  MongoDB sunucusu silinip yerine fidye notu bırakıldı; o dönem bu tür açık sunucuları arama motorlarıyla
  bulmak çok kolaydı. Önleme: veritabanını yalnızca iç ağa dinlet, kimlik doğrulamasını aç. Tespit: kendi IP
  aralığını düzenli olarak aratıp 27017, 6379 gibi veritabanı portlarının dışarıdan görünüp görünmediğine bak.
- **Telnet ve varsayılan parolalar:** 2016'daki Mirai botnet'i, internete açık ve varsayılan parolalı IoT
  cihazlarını (kameralar, yönlendiriciler) ele geçirerek büyüdü. Önleme: Telnet'i kapat, varsayılan parolaları
  değiştir, yönetim arayüzlerini internete açma. Tespit: Shodan benzeri bir servisle kendi aralığında Telnet
  portunu ara.
- **Eski sürüm bilgisi:** Equifax 2017 ihlalinde, yaması çıkmış ama uygulanmamış bir Apache Struts sürümü kullanıldı.
  Banner'lardaki sürüm numarası, saldırganın hangi sunucunun yamasız olduğunu uzaktan anlamasını sağlar.
  Önleme: yama yönetimi; tespit: dışarıdan görünen sürümlerle kendi envanterini karşılaştırmak.
""",
    sure_hedef_dk=30,
)
