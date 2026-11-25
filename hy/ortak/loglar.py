"""Web erişim logu (access.log) ve SSH giriş kaydı (auth.log) için saldırı senaryosu üreteci.

Bir müşteri vakası (`hy.ortak.vakalar`) ve `rng` alır; hem log satırlarını hem de cevapları
(saldırgan IP'leri, başarılı giriş zamanı, tarayıcı adı, sızan dosya...) döndürür. Aynı rng
durumu her zaman aynı logu üretir. Dış IP'ler TEST-NET, iç IP'ler RFC1918 bloklarındandır.

Kullanım:
    from hy.ortak import loglar
    from hy.ortak.vakalar import musteri_sec

    m = musteri_sec(rng)
    web = loglar.web_logu(rng, m, saldirilar=("brute", "tarama"), basari={"brute": True})
    loglar.metin(web)              # access.log içeriği ("\\n" ile biten tek metin)
    web["saldirilar"]["brute"]     # {"ip", "arac", "ua", "istek", "basarili", "zaman", "hedef", ...}
    web["ozet"]                    # toplam, ip_sayisi, en_cok_ip, sayi_401, saldirgan_ipler, ...
    ssh = loglar.ssh_logu(rng, m, baslangic=web["baslangic"], haric=web["ipler"])
    ssh["ozet"]                    # basarisiz {ip: sayı}, gecersiz_kullanicilar, root_olan_ip, ...
    olay = loglar.olay_uret(rng, m)    # ikisi birden, tutarlı tek hikâye (Olay Masası için)

Web saldırı türleri (SALDIRI_TURLERI):
    brute     — giriş sayfasına parola deneme (yavaş: meşru trafiğe karışır); başarılı olabilir
    sqli      — ID parametreli sayfaya SQL injection denemesi (elle ya da sqlmap)
    tarama    — Nikto/gobuster/ffuf ile dizin ve yedek dosya taraması; yedek 200 alırsa sızar
    traversal — dosya gösteren sayfada ../ ile dizin atlama denemesi
`saldirilar=None` ise `zorunlu` türlere ek olarak rastgele bir alt küme seçilir.
Zamanlar cevaplarda "SS:DD:SS" metni olarak, başlangıç ise datetime olarak verilir.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta

from hy.ortak import uretec as u

SALDIRI_TURLERI = ("brute", "sqli", "tarama", "traversal")

STATIK = ["/css/site.css", "/js/app.js", "/img/logo.png", "/img/banner.jpg", "/fonts/ana.woff2"]
TARAMA_YOLLARI = [
    "/robots.txt", "/.git/HEAD", "/.env", "/phpmyadmin/", "/admin/", "/backup.zip", "/db.sql",
    "/config.php.bak", "/wp-config.php.bak", "/.htaccess", "/.htpasswd", "/server-status",
    "/test.php", "/info.php", "/old/", "/dump.sql", "/.svn/entries", "/web.config", "/.DS_Store",
    "/administrator/", "/uploads/", "/cgi-bin/", "/backup.tar.gz", "/site.zip", "/.ssh/id_rsa",
    "/composer.json", "/install.php", "/debug.log", "/yedek/", "/eski/",
]
TARAMA_KODU = {"/robots.txt": 200, "/admin/": 301, "/.htaccess": 403, "/.htpasswd": 403,
               "/server-status": 403, "/uploads/": 403, "/cgi-bin/": 403}
TARAYICILAR = ("Nikto", "gobuster", "ffuf")
INDIRME_SAYFALARI = ["/indir.php?dosya=", "/belge.php?f=", "/goster.php?sayfa=", "/ek.php?ad="]
TRAVERSAL_YUKLERI = [
    "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd",
    "../../../../etc/shadow", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhosts", "..%5c..%5c..%5cwindows%5cwin.ini",
]
GECERSIZ_ADLAR = ["test", "oracle", "ubuntu", "pi", "postgres", "guest", "user", "ftpuser", "git",
                  "support", "teamspeak", "minecraft", "hadoop", "nagios", "tomcat", "ansible"]
ELE_GECEN_HESAPLAR = ["deploy", "admin", "webadmin", "yonetici", "operator", "devops"]
KALICI_KULLANICILAR = ["destek", "sistem", "yedek_svc", "monitor", "bakim", "guncelleme", "svc_log"]
OFIS_AGLARI = ["192.168.1", "192.168.10", "10.0.0", "10.10.5", "172.16.4"]


def metin(log: dict) -> str:
    """Log sözlüğünü dosyaya yazılacak metne çevirir."""
    return "\n".join(log["satirlar"]) + "\n"


def saat(t: datetime) -> str:
    return t.strftime("%H:%M:%S")


def _yeni_ip(rng, kullanilan: set, ic: str | None = None) -> str:
    while True:
        ip = u.ic_ip(rng, ic) if ic else u.dis_ip(rng)
        if ip not in kullanilan:
            kullanilan.add(ip)
            return ip


def _sayfa(yol: str) -> str:
    return yol.split("?", 1)[0]


def _panel(giris: str) -> str:
    return "/wp-admin/" if giris.endswith("wp-login.php") else giris.rsplit("/", 1)[0] + "/panel.php"


def _id_degeri(rng, id_sayfa: str) -> str:
    return f"KZ{rng.randint(10000, 99999)}" if id_sayfa.endswith("kod=") else str(rng.randint(2, 980))


# --------------------------------------------------------------------- web: parçalar

def _mesru_oturum(rng, m, ip, ua, t, boyut, admin=False, hatali_giris=False) -> list:
    """Normal bir ziyaretçinin bir oturumu: ana sayfa, statik dosyalar, birkaç sayfa."""
    olay, onceki = [], None

    def ekle(metod, yol, kod=200, b=None):
        nonlocal t, onceki
        ref = f"https://{m['alan']}{onceki}" if onceki else "-"
        olay.append((t, ip, metod, yol, kod, b if b is not None else boyut(yol), ua, ref))
        if metod == "GET" and kod == 200 and not yol.startswith(("/css", "/js", "/img", "/fonts")):
            onceki = yol
        t += timedelta(seconds=rng.randint(1, 4) if yol.startswith(("/css", "/js", "/img", "/fonts"))
                       else rng.randint(6, 55))

    ekle("GET", rng.choice(["/", "/index.php"]))
    for s in rng.sample(STATIK, rng.randint(1, 3)):
        ekle("GET", s)
    if rng.random() < 0.3:
        ekle("GET", "/favicon.ico", 404, 196)
    for yol in rng.sample(m["normal_sayfalar"], rng.randint(1, 3)):
        ekle("GET", yol)
    if rng.random() < 0.6:
        ekle("GET", m["id_sayfa"] + _id_degeri(rng, m["id_sayfa"]))
    if admin:
        ekle("GET", m["giris"])
        if hatali_giris:
            ekle("POST", m["giris"], 401, boyut("401"))
        ekle("POST", m["giris"], 200, boyut("giris_ok"))
        ekle("GET", _panel(m["giris"]))
    return olay


def _brute(rng, m, ip, t, deneme, basarili, boyut) -> tuple:
    ua = rng.choice(u.KOMUT_SATIRI_UA)
    giris = m["giris"]
    olay = [(t, ip, "GET", giris, 200, boyut(giris), ua, "-")]
    for _ in range(deneme):
        t += timedelta(seconds=rng.randint(25, 95))      # yavaş deneme: alarm eşiğinin altında kalır
        olay.append((t, ip, "POST", giris, 401, boyut("401"), ua, "-"))
    zaman = None
    if basarili:
        t += timedelta(seconds=rng.randint(25, 95))
        zaman = t
        olay.append((t, ip, "POST", giris, 200, boyut("giris_ok"), ua, "-"))
        ikinci = "/wp-admin/users.php" if giris.endswith("wp-login.php") else giris.rsplit("/", 1)[0] + "/kullanicilar.php"
        for yol in (_panel(giris), ikinci):
            t += timedelta(seconds=rng.randint(3, 20))
            olay.append((t, ip, "GET", yol, 200, boyut(yol), ua, "-"))
    bilgi = {"tur": "brute", "ip": ip, "ua": ua, "arac": ua.split("/")[0], "hedef": giris,
             "deneme": deneme, "basarili": basarili, "zaman": saat(zaman) if zaman else None,
             "panel": _panel(giris)}
    return olay, bilgi


def _sqli(rng, m, ip, t, basarili, boyut, arac="elle") -> tuple:
    ua = u.ARAC_UA["sqlmap"] if arac == "sqlmap" else rng.choice(u.TARAYICI_UA)
    id_ = _id_degeri(rng, m["id_sayfa"])
    yukler = [(id_, 200), (id_ + "'", 500), (id_ + "%27+OR+%271%27=%271", 500), (id_ + "+AND+1=1", 200),
              (id_ + "+AND+1=2", 200), (id_ + "+ORDER+BY+3--", 200), (id_ + "+ORDER+BY+9--", 500),
              (id_ + "+UNION+SELECT+1,2,3--", 200), ("-1+UNION+SELECT+1,version(),3--", 200),
              ("-1+UNION+SELECT+1,group_concat(kullanici,0x3a,parola),3+FROM+kullanicilar--", 200)]
    olay = []
    for i, (yuk, kod) in enumerate(yukler):
        if not basarili and "UNION" in yuk:
            kod = 403                                      # WAF engelledi
        b = boyut(m["id_sayfa"]) + (rng.randint(40, 900) if kod == 200 and i > 6 else 0)
        olay.append((t, ip, "GET", m["id_sayfa"] + yuk, kod, b if kod == 200 else rng.randint(80, 320), ua, "-"))
        t += timedelta(seconds=rng.randint(2, 6) if arac == "sqlmap" else rng.randint(8, 40))
    bilgi = {"tur": "sqli", "ip": ip, "ua": ua, "arac": "sqlmap" if arac == "sqlmap" else "elle",
             "hedef": _sayfa(m["id_sayfa"]), "parametre": m["id_sayfa"].split("?")[1].rstrip("="),
             "basarili": basarili}
    return olay, bilgi


def _tarama(rng, m, ip, t, basarili, istek, arac) -> tuple:
    ua = u.ARAC_UA[arac]
    yollar = [y for y in TARAMA_YOLLARI if y != m["yedek"]]
    secilen = rng.sample(yollar, min(len(yollar), max(5, istek - 1)))
    secilen.insert(rng.randint(len(secilen) // 3, len(secilen) - 1), m["yedek"])
    olay, zaman = [], None
    for yol in secilen:
        if yol == m["yedek"]:
            kod = 200 if basarili else 404
            b = len(m["yedek_icerik"].encode()) + rng.randint(4, 30) if basarili else 196
            zaman = t if basarili else None
        else:
            kod = TARAMA_KODU.get(yol, 404)
            b = {200: rng.randint(60, 140), 301: 239, 403: 278}.get(kod, 196)
        olay.append((t, ip, "GET", yol, kod, b, ua, "-"))
        t += timedelta(seconds=rng.choice([0, 0, 1]))
    bilgi = {"tur": "tarama", "ip": ip, "ua": ua, "arac": arac, "hedef": "/", "basarili": basarili,
             "dosya": m["yedek"] if basarili else None, "zaman": saat(zaman) if zaman else None,
             "yollar": secilen}
    return olay, bilgi


def _traversal(rng, m, ip, t, basarili) -> tuple:
    ua = rng.choice(u.KOMUT_SATIRI_UA)   # tarayıcı (scanner) UA'sı sadece "tarama"da: soru tek anlamlı kalsın
    sayfa = rng.choice(INDIRME_SAYFALARI)
    yukler = rng.sample(TRAVERSAL_YUKLERI, rng.randint(4, 6))
    if basarili:
        yukler.append("../../../../etc/passwd" if "../../../../etc/passwd" not in yukler else "....//....//....//etc/passwd")
    olay = [(t, ip, "GET", sayfa + "katalog.pdf", 200, rng.randint(30000, 90000), ua, "-")]
    for i, yuk in enumerate(yukler):
        t += timedelta(seconds=rng.randint(1, 12))
        son_basari = basarili and i == len(yukler) - 1
        kod = 200 if son_basari else rng.choice([403, 404, 500])
        olay.append((t, ip, "GET", sayfa + yuk, kod, rng.randint(1700, 2600) if son_basari else rng.randint(150, 400), ua, "-"))
    bilgi = {"tur": "traversal", "ip": ip, "ua": ua, "arac": ua.split("/")[0], "hedef": _sayfa(sayfa),
             "basarili": basarili, "dosya": "/etc/passwd" if basarili else None}
    return olay, bilgi


def _ozet(satirlar: list, saldirilar: dict, mesru: list) -> dict:
    ipler = [s.split(" ", 1)[0] for s in satirlar]
    sayac = Counter(ipler)
    en_cok = max(sayac.values())
    ardisik, en_uzun, onceki, uzunluk = None, 0, None, 0
    for ip in ipler:                       # `uniq -c` sırasız kullanılınca görülen en büyük blok
        uzunluk = uzunluk + 1 if ip == onceki else 1
        onceki = ip
        if uzunluk > en_uzun:
            ardisik, en_uzun = ip, uzunluk
    kodlar = Counter(s.split('" ', 1)[1].split()[0] for s in satirlar)
    tarama = saldirilar.get("tarama")
    return {
        "toplam": len(satirlar), "ip_sayisi": len(sayac), "ip_sayilari": dict(sayac),
        "en_cok_ip": sorted(ip for ip, c in sayac.items() if c == en_cok), "en_cok_sayi": en_cok,
        "ardisik_en_cok_ip": ardisik, "ardisik_blok_sayisi": sum(1 for i, ip in enumerate(ipler) if i == 0 or ipler[i - 1] != ip),
        "kodlar": dict(kodlar), "sayi_401": kodlar.get("401", 0),
        "saldirgan_ipler": sorted({b["ip"] for b in saldirilar.values()}), "mesru_ipler": sorted(mesru),
        "tarayici": tarama["arac"] if tarama else None,
        "sizan_dosya": tarama["dosya"] if tarama else None,
        "sizan_ip": tarama["ip"] if tarama and tarama["dosya"] else None,
    }


# --------------------------------------------------------------------- web: ana fonksiyon

def web_logu(rng, musteri: dict, saldirilar=None, zorunlu=(), basari: dict | None = None,
             baslangic: datetime | None = None, mesru_kisi=(4, 7), brute_deneme=(10, 22),
             tarama_istek=(22, 34), tarayici: str | None = None, sqli_arac: str = "elle",
             haric=()) -> dict:
    """access.log senaryosu üretir.

    saldirilar : çalıştırılacak türler (SALDIRI_TURLERI'nden); None ise zorunlu + rastgele alt küme
    basari     : {"brute": True, "tarama": False, ...}; verilmeyen tür için rastgele
    baslangic  : log penceresinin başlangıcı (None: rastgele bir iş günü, 08-19 arası)
    haric      : kullanılmaması gereken IP'ler (başka bir logla çakışmasın diye)

    Dönüş: {"satirlar", "baslangic", "bitis", "ipler", "mesru", "ofis", "admin_ip",
            "saldirilar": {tur: bilgi}, "ozet": {...}}
    """
    m = musteri
    if saldirilar is None:
        digerleri = [t for t in SALDIRI_TURLERI if t not in zorunlu]
        saldirilar = tuple(zorunlu) + tuple(rng.sample(digerleri, rng.randint(1, len(digerleri))))
    basari = dict(basari or {})
    bas = baslangic or (u.gun(rng) + timedelta(hours=rng.randint(8, 19), minutes=rng.randint(0, 59)))
    pencere = rng.randint(100, 150) * 60
    kullanilan = set(haric)
    boyutlar: dict = {"401": rng.randint(110, 480), "giris_ok": rng.randint(900, 2400),
                      "/": rng.choice([2401, 3401, 4012, 4015, 5401, 7401])}  # 401 içeren boyut: grep tuzağı
    boyutlar["/index.php"] = boyutlar["/"]

    def boyut(yol):
        anahtar = _sayfa(yol) if yol not in boyutlar else yol
        if anahtar not in boyutlar:
            boyutlar[anahtar] = rng.randint(300, 9000) if not anahtar.startswith(("/img", "/fonts")) \
                else rng.randint(9000, 60000)
        return boyutlar[anahtar]

    olaylar = []
    ofis_ag = rng.choice(OFIS_AGLARI)
    mesru, ofis = [], []
    kisi = rng.randint(*mesru_kisi)
    for i in range(kisi):
        ic = i < max(1, kisi // 3)
        ip = _yeni_ip(rng, kullanilan, ofis_ag if ic else None)
        (ofis if ic else mesru).append(ip)
        ua = rng.choice(u.TARAYICI_UA)
        for _ in range(rng.randint(1, 2)):
            t = bas + timedelta(seconds=rng.randint(0, pencere))
            olaylar += _mesru_oturum(rng, m, ip, ua, t, boyut, admin=(i == 0), hatali_giris=rng.random() < 0.5)
    mesru = ofis + mesru
    bilgiler = {}
    for tur in saldirilar:
        ip = _yeni_ip(rng, kullanilan)
        t = bas + timedelta(seconds=rng.randint(pencere // 10, pencere * 6 // 10))
        ok = basari.get(tur, rng.random() < 0.5)
        if tur == "brute":
            o, bilgi = _brute(rng, m, ip, t, rng.randint(*brute_deneme), ok, boyut)
        elif tur == "sqli":
            o, bilgi = _sqli(rng, m, ip, t, ok, boyut, sqli_arac)
        elif tur == "tarama":
            o, bilgi = _tarama(rng, m, ip, t, ok, rng.randint(*tarama_istek), tarayici or rng.choice(TARAYICILAR))
        elif tur == "traversal":
            o, bilgi = _traversal(rng, m, ip, t, ok)
        else:
            raise ValueError(f"Bilinmeyen saldırı türü: {tur}")
        bilgi["ilk"], bilgi["son"], bilgi["istek"] = saat(o[0][0]), saat(o[-1][0]), len(o)
        olaylar += o
        bilgiler[tur] = bilgi
    sirali = sorted(enumerate(olaylar), key=lambda x: (x[1][0], x[0]))
    satirlar = [u.apache_satiri(ip, t, mt, yol, kod, b, ua, ref) for _, (t, ip, mt, yol, kod, b, ua, ref) in sirali]
    return {
        "satirlar": satirlar, "baslangic": bas, "bitis": sirali[-1][1][0], "ipler": sorted(kullanilan - set(haric)),
        "mesru": mesru, "ofis": ofis, "admin_ip": ofis[0], "saldirilar": bilgiler,
        "ozet": _ozet(satirlar, bilgiler, mesru),
    }


# --------------------------------------------------------------------- ssh (auth.log)

def ssh_logu(rng, musteri: dict, baslangic: datetime | None = None, sure_dk: int = 180,
             brute: bool = True, brute_basari: bool = False, ele_gecirme: bool = True,
             ele_zaman: datetime | None = None, saldirgan_ip: str | None = None,
             mesru_ipler=(), haric=(), deneme=(6, 14)) -> dict:
    """auth.log senaryosu üretir.

    brute        : bir IP'den root ve var olmayan kullanıcılarla parola denemesi
    brute_basari : brute-force sonunda root parolası tutar mı
    ele_gecirme  : başka bir IP (ya da verilen saldirgan_ip) bir hesaba parolayla girer,
                   sudo ile root kabuğu açar ve kalıcılık için yeni bir kullanıcı ekler
    mesru_ipler  : meşru yöneticilerin bağlandığı IP'ler (verilmezse iç ağdan üretilir)

    Dönüş: {"satirlar", "baslangic", "sunucu", "ipler", "mesru", "hesaplar",
            "brute": {...} | None, "ele_gecirme": {...} | None, "ozet": {...}}
    """
    m = musteri
    sunucu = m["sunucu"]
    bas = baslangic or (u.gun(rng) + timedelta(hours=rng.randint(7, 18)))
    kullanilan = set(haric) | set(mesru_ipler)
    pid = [rng.randint(1200, 30000)]
    olaylar = []

    def yeni_pid():
        pid[0] += rng.randint(1, 40)
        return pid[0]

    def ekle(t, surec, p, olay):
        olaylar.append((t, len(olaylar), surec, p, olay))

    yoneticiler = u.isimler(rng, rng.randint(1, 2))
    mesru = list(mesru_ipler) or [_yeni_ip(rng, kullanilan, rng.choice(OFIS_AGLARI)) for _ in yoneticiler]
    hesap = rng.choice([h for h in ELE_GECEN_HESAPLAR if h not in yoneticiler])
    hesaplar = ["root"] + yoneticiler + [hesap]
    uid = {ad: 1000 + i for i, ad in enumerate(yoneticiler + [hesap])}
    uid["root"] = 0
    for i, ad in enumerate(yoneticiler):                       # meşru anahtar ile girişler
        for _ in range(rng.randint(1, 2)):
            t = bas + timedelta(seconds=rng.randint(0, sure_dk * 60))
            ip, p, port = mesru[i % len(mesru)], yeni_pid(), rng.randint(40000, 65000)
            parmak = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(43))
            ekle(t, "sshd", p, f"Accepted publickey for {ad} from {ip} port {port} ssh2: ED25519 SHA256:{parmak}")
            ekle(t, "sshd", p, f"pam_unix(sshd:session): session opened for user {ad}(uid={uid[ad]}) by (uid=0)")
            t2 = t + timedelta(minutes=rng.randint(3, 40))
            ekle(t2, "sshd", p, f"Disconnected from user {ad} {ip} port {port}")
            ekle(t2, "sshd", p, f"pam_unix(sshd:session): session closed for user {ad}")
    aralik = rng.choice([10, 15, 30])                          # cron oturumları (gürültü)
    t = bas.replace(second=0) + timedelta(minutes=aralik - bas.minute % aralik)
    while t < bas + timedelta(minutes=sure_dk):
        p = yeni_pid()
        ekle(t + timedelta(seconds=1), "CRON", p, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        ekle(t + timedelta(seconds=2), "CRON", p, "pam_unix(cron:session): session closed for user root")
        t += timedelta(minutes=aralik)

    brute_bilgi = None
    if brute:
        ip = _yeni_ip(rng, kullanilan)
        t = bas + timedelta(seconds=rng.randint(sure_dk * 6, sure_dk * 30))
        gecersiz = rng.sample([g for g in GECERSIZ_ADLAR if g not in hesaplar], rng.randint(2, 5))
        denenen = ["root"] * rng.randint(2, 5) + gecersiz + ["root"] * rng.randint(0, 3)
        denenen += ["root"] * max(0, rng.randint(*deneme) - len(denenen))
        zaman = None
        for i, ad in enumerate(denenen):
            p, port = yeni_pid(), rng.randint(30000, 60000)
            t += timedelta(seconds=rng.randint(2, 9))
            if ad == "root":
                if rng.random() < 0.5:
                    ekle(t, "sshd", p, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                                       f"tty=ssh ruser= rhost={ip}  user=root")
                ekle(t, "sshd", p, f"Failed password for root from {ip} port {port} ssh2")
                ekle(t + timedelta(seconds=1), "sshd", p, f"Connection closed by authenticating user root {ip} port {port} [preauth]")
            else:
                ekle(t, "sshd", p, f"Invalid user {ad} from {ip} port {port}")
                ekle(t + timedelta(seconds=2), "sshd", p, f"Failed password for invalid user {ad} from {ip} port {port} ssh2")
                ekle(t + timedelta(seconds=3), "sshd", p, f"Disconnected from invalid user {ad} {ip} port {port} [preauth]")
        if brute_basari:
            t += timedelta(seconds=rng.randint(3, 9))
            p, zaman = yeni_pid(), t
            ekle(t, "sshd", p, f"Accepted password for root from {ip} port {rng.randint(30000, 60000)} ssh2")
            ekle(t, "sshd", p, "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")
        brute_bilgi = {"ip": ip, "deneme": len(denenen), "gecersiz": sorted(set(gecersiz)),
                       "basarili": brute_basari, "zaman": saat(zaman) if zaman else None}

    ele_bilgi = None
    if ele_gecirme:
        ip = saldirgan_ip or _yeni_ip(rng, kullanilan)
        kullanilan.add(ip)
        t = ele_zaman or bas + timedelta(seconds=rng.randint(sure_dk * 30, sure_dk * 50))
        p, port = yeni_pid(), rng.randint(30000, 60000)
        onceki = rng.randint(0, 2)
        for _ in range(onceki):
            ekle(t, "sshd", p, f"Failed password for {hesap} from {ip} port {port} ssh2")
            t += timedelta(seconds=rng.randint(2, 6))
        giris = t
        ekle(t, "sshd", p, f"Accepted password for {hesap} from {ip} port {port} ssh2")
        ekle(t, "sshd", p, f"pam_unix(sshd:session): session opened for user {hesap}(uid={uid[hesap]}) by (uid=0)")
        t += timedelta(seconds=rng.randint(15, 70))
        root_zaman = t
        ekle(t, "sudo", None, f"   {hesap} : TTY=pts/1 ; PWD=/home/{hesap} ; USER=root ; COMMAND=/bin/bash")
        ekle(t, "sudo", None, f"pam_unix(sudo:session): session opened for user root(uid=0) by {hesap}(uid={uid[hesap]})")
        yeni = rng.choice([k for k in KALICI_KULLANICILAR if k not in hesaplar])
        t += timedelta(seconds=rng.randint(20, 90))
        p2, yuid = yeni_pid(), 1000 + len(uid)
        ekle(t, "useradd", p2, f"new group: name={yeni}, GID={yuid}")
        ekle(t, "useradd", p2, f"new user: name={yeni}, UID={yuid}, GID={yuid}, home=/home/{yeni}, shell=/bin/bash, from=/dev/pts/1")
        t += timedelta(seconds=rng.randint(5, 30))
        ekle(t, "usermod", yeni_pid(), f"add '{yeni}' to group 'sudo'")
        t += timedelta(seconds=rng.randint(5, 30))
        ekle(t, "passwd", yeni_pid(), f"pam_unix(passwd:chauthtok): password changed for {yeni}")
        ele_bilgi = {"ip": ip, "hesap": hesap, "onceki_deneme": onceki, "zaman": saat(giris),
                     "root_zaman": saat(root_zaman), "yeni_kullanici": yeni}

    sirali = sorted(olaylar, key=lambda x: (x[0], x[1]))
    gercek_pid: dict = {}                      # PID'ler zamanla artsın: ilk görünüş sırasıyla ata
    sayac = rng.randint(1200, 30000)
    satirlar = []
    for t, _, surec, p, olay in sirali:
        if p is not None and p not in gercek_pid:
            sayac += rng.randint(1, 60)
            gercek_pid[p] = sayac
        etiket = f"{surec}[{gercek_pid[p]}]" if p is not None else surec   # sudo satırlarında PID yok
        satirlar.append(f"{u.syslog_zamani(t)} {sunucu} {etiket}: {olay}")
    basarisiz = Counter(s.split(" from ")[1].split()[0] for s in satirlar if "Failed password" in s)
    en_cok = max(basarisiz.values()) if basarisiz else 0
    return {
        "satirlar": satirlar, "baslangic": bas, "sunucu": sunucu, "mesru": mesru, "hesaplar": hesaplar,
        "ipler": sorted(kullanilan - set(haric)), "brute": brute_bilgi, "ele_gecirme": ele_bilgi,
        "ozet": {
            "toplam": len(satirlar), "basarisiz": dict(basarisiz),
            "en_cok_basarisiz_ip": sorted(ip for ip, c in basarisiz.items() if c == en_cok),
            "en_cok_basarisiz": en_cok,
            "gecersiz_kullanicilar": brute_bilgi["gecersiz"] if brute_bilgi else [],
            "root_olan_ip": ele_bilgi["ip"] if ele_bilgi else (brute_bilgi["ip"] if brute_basari else None),
        },
    }


# --------------------------------------------------------------------- birleşik olay

def olay_uret(rng, musteri: dict | None = None, ekstra=None, ayni_aktor: bool | None = None) -> dict:
    """Web + SSH logundan oluşan tek, tutarlı bir olay: tarayıcı yedek dosyayı indirir, panel
    brute-force ile ele geçirilir, ardından biri SSH ile girip root olur ve kalıcılık bırakır.

    ekstra     : ek web saldırıları (None: sqli/traversal'dan rastgele 0-2 tane)
    ayni_aktor : SSH'a giren IP, yedeği indiren tarayıcı IP'siyle aynı mı (None: rastgele)
    Dönüş: {"musteri", "web", "ssh", "ozet": {"saldirgan_ipler", "ssh_ip", "ayni_aktor", ...}}
    """
    if musteri is None:
        from hy.ortak.vakalar import musteri_sec
        musteri = musteri_sec(rng)
    if ekstra is None:
        ekstra = rng.sample(["sqli", "traversal"], rng.randint(0, 2))
    web = web_logu(rng, musteri, saldirilar=("brute", "tarama", *ekstra),
                   basari={"brute": True, "tarama": True})
    if ayni_aktor is None:
        ayni_aktor = rng.random() < 0.5
    tarama = web["saldirilar"]["tarama"]
    sizma = datetime.strptime(f"{web['baslangic']:%Y-%m-%d} {tarama['zaman']}", "%Y-%m-%d %H:%M:%S")
    ssh = ssh_logu(rng, musteri, baslangic=web["baslangic"] - timedelta(minutes=rng.randint(20, 60)),
                   sure_dk=240, ele_zaman=sizma + timedelta(minutes=rng.randint(8, 40), seconds=rng.randint(0, 59)),
                   saldirgan_ip=tarama["ip"] if ayni_aktor else None, mesru_ipler=[web["admin_ip"]],
                   haric=web["ipler"])
    return {
        "musteri": musteri, "web": web, "ssh": ssh,
        "ozet": {"web_saldirganlar": web["ozet"]["saldirgan_ipler"], "ssh_ip": ssh["ele_gecirme"]["ip"],
                 "ayni_aktor": ayni_aktor, "sizan_dosya": tarama["dosya"], "sizan_ip": tarama["ip"],
                 "panel_giris": web["saldirilar"]["brute"]["zaman"]},
    }
