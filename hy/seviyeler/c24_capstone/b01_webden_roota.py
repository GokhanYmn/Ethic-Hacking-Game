"""Cilt 24 · Bölüm 1 — Vaka 1: "Web'den root'a" olayının incelemesi (mavi takım).

Kitaptaki senaryo saldırganın zincirini yürütür; burada aynı zincir **kanıttan geriye doğru** kurulur:
web logundaki ilk erişim izinden sistem logundaki yetki yükseltme izine kadar zaman çizelgesi, kök nedenler
ve düzeltmeler. Oyuncu saldırı yapmaz; log okur, kanıtı yorumlar, kapıları kapatır.

Üç vaka (farklı sektör ve farklı giriş açığı):
  - Pazarix (e-ticaret): ürün sayfasında SQL enjeksiyonu, yönetim panelinden dosya yükleme, sudo ile `find`.
  - Medora Sağlık (hastane): ping aracı sayfasında komut enjeksiyonu, sudo ile `vim.basic`.
  - Yeşiltepe Belediyesi: dilekçe ek yükleme formunda dosya türü denetimi yok, sudo ile `awk`.
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Sayi, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c24_capstone import ortak
from hy.seviyeler.c24_capstone.ortak import SAAT, LogYigini, sec_doldur, sh, sira_cevabi, sira_hata, sys_satiri

KLASORLER = ["loglar", "kayitlar", "olay_loglari"]
KABUK_ADLARI = ["tema_onizle", "ikon_v2", "thumb_cache", "belge_ek", "sayac", "galeri_ek", "ekran_goruntusu"]
STATIK = ["/css/site.css", "/js/app.js", "/img/logo.png", "/fonts/ana.woff2"]
OLAYLAR = [
    "Saldırgan IP'nin web sunucusuna ilk isteği",
    "Web açığının ilk **başarılı** sömürü isteği (HTTP 200 dönen UNION SELECT, komut ayırıcılı ping ya da yükleme POST'u)",
    "Web kabuğu dosyasına ilk başarılı erişim (HTTP 200)",
    "www-data hesabının sudo ile root olarak komut çalıştırması",
    "Yeni kullanıcı hesabının oluşturulması (useradd)",
    "root crontab'ının değiştirilmesi",
]

VAKALAR = [
    {"kod": "pazarix", "tur": "sqli", "arac": ["find"], "kabuk_yol": "/img/urun/",
     "sudo_dosya": "etc/sudoers.d/90-web-bakim", "kod_yolu": "var/www/html/urun.php",
     "ad": "SQL enjeksiyonu (ürün sayfası) ve yönetim panelinden dosya yükleme"},
    {"kod": "medora", "tur": "komut", "arac": ["vim.basic", "vim"], "kabuk_yol": "/img/",
     "sudo_dosya": "etc/sudoers", "kod_yolu": "var/www/html/araclar/ping.php",
     "ad": "komut enjeksiyonu (ping aracı sayfası)"},
    {"kod": "yesiltepe", "tur": "yukleme", "arac": ["awk"], "kabuk_yol": "/dilekce/ekler/",
     "sudo_dosya": "etc/sudoers.d/ytb-destek", "kod_yolu": "var/www/html/dilekce/ek-yukle.php",
     "ad": "dosya türü denetimi olmayan yükleme formu"},
]

KOD_ICERIK = {
    "sqli": """<?php
// urun.php: ürün detay sayfası
$id = $_GET['id'];
$sonuc = $db->query("SELECT ad, fiyat, aciklama FROM urunler WHERE id = " . $id);
echo goster($sonuc);
""",
    "komut": """<?php
// araclar/ping.php: personelin ağ kontrol aracı
$host = $_GET['host'];
echo "<pre>" . shell_exec("ping -c 1 " . $host) . "</pre>";
""",
    "yukleme": """<?php
// dilekce/ek-yukle.php: vatandaş dilekçe eki yükleme
$hedef = "ekler/" . $_FILES['ek']['name'];
move_uploaded_file($_FILES['ek']['tmp_name'], $hedef);
echo "Ek yüklendi.";
""",
}


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    klasor = rng.choice(KLASORLER)
    gun = u.gun(rng)
    bas = gun + timedelta(hours=rng.randint(1, 4), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    T = ortak.zaman_zinciri(rng, bas, [(90, 500), (150, 500), (150, 700), (60, 300), (60, 300)])
    ipler = u.benzersiz(rng, u.dis_ip, 9)
    saldirgan, tarayici, mesru = ipler[0], ipler[1], ipler[2:]
    ad = f"{rng.choice(KABUK_ADLARI)}_{ortak.hex_ek(rng)}.php"
    yeni = u.isimler(rng, 1, haric={"www-data", "root"})[0] + rng.choice(["_svc", "_destek", "2", "_yedek"])
    yoneticiler = u.isimler(rng, 2, haric={yeni})
    kabuk_istek = rng.randint(5, 9)
    perm = list(range(6))
    rng.shuffle(perm)
    return {
        "vaka": f"{m['ad']} — {m['sektor']}: {v['ad']}",
        "m": m, "v": v, "klasor": klasor, "gun": gun, "T": T, "saldirgan": saldirgan, "tarayici": tarayici,
        "mesru": mesru, "kabuk": ad, "yeni": yeni, "yoneticiler": yoneticiler, "kabuk_istek": kabuk_istek,
        "perm": perm, "ua": rng.choice(u.KOMUT_SATIRI_UA), "tohum_log": rng.randint(1, 10**9),
        "uid": rng.randint(1001, 1099), "pid_taban": rng.randint(900, 4000),
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "klasor": klasor,
                  "hikaye": m["hikaye"], "hassas": m["hassas_veri"], "kod_yolu": v["kod_yolu"],
                  "sudo_dosya": v["sudo_dosya"], "yeni_ad": yeni},
        "cevaplar": {"ip": saldirgan, "kabuk": ad, "sayi": kabuk_istek - 1,
                     "sira": sira_cevabi(perm), "arac": v["arac"]},
    }


def _web_log(s: dict) -> str:
    import random
    r = random.Random(s["tohum_log"])
    m, v, T = s["m"], s["v"], s["T"]
    ip, kabuk = s["saldirgan"], s["kabuk"]
    L = LogYigini()
    gun = s["gun"]

    def ekle(ipx, t, metod, yol, kod, boyut, ua):
        L.ekle(t, u.apache_satiri(ipx, t, metod, yol, kod, boyut, ua))

    # meşru trafik: gün boyunca
    for ipx in s["mesru"]:
        ua = r.choice(u.TARAYICI_UA)
        t = gun + timedelta(hours=r.randint(0, 5), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
        for _ in range(r.randint(4, 9)):
            t += timedelta(seconds=r.randint(3, 400))
            yol = r.choice(m["normal_sayfalar"] + STATIK)
            ekle(ipx, t, "GET", yol, r.choice([200, 200, 200, 304]), r.randint(900, 18000), ua)
    # gürültü: hiçbir isteği başarılı olmayan tarayıcı
    t = gun + timedelta(hours=r.randint(0, 2), minutes=r.randint(10, 59))
    for _ in range(r.randint(25, 40)):
        t += timedelta(seconds=r.randint(1, 9))
        yol = r.choice(["/admin/", "/.git/config", "/phpmyadmin/", "/backup.zip", "/wp-login.php", "/.env", "/server-status",
                        "/test.php", "/config.php.old", "/cgi-bin/"])
        ekle(s["tarayici"], t, "GET", yol, r.choice([404, 404, 404, 403]), r.randint(150, 330), "Nikto/2.5.0")
    ekle(s["tarayici"], t + timedelta(seconds=3), "GET", "/", 200, 5120, "Nikto/2.5.0")
    # saldırgan
    ua = s["ua"]
    a = T[0]
    for k, (yol, kod, boyut) in enumerate([("/", 200, 5120), ("/robots.txt", 200, 68), (v["kod_yolu"].split("html", 1)[1], 200, 1400)]):
        ekle(ip, a + timedelta(seconds=k * r.randint(3, 12)), "GET", yol, kod, boyut, ua)
    som, kab = T[1], T[2]
    tur = v["tur"]
    if tur == "sqli":
        ekle(ip, som - timedelta(seconds=70), "GET", "/urun.php?id=1%27", 500, 612, ua)
        ekle(ip, som - timedelta(seconds=44), "GET", "/urun.php?id=1%20UNION%20SELECT%201,2", 500, 612, ua)
        ekle(ip, som - timedelta(seconds=21), "GET", "/urun.php?id=1%20UNION%20SELECT%201,2,3,4", 500, 612, ua)
        for k in range(r.randint(2, 4)):
            ekle(ip, som + timedelta(seconds=k * r.randint(5, 20)), "GET",
                 f"/urun.php?id=-1%20UNION%20SELECT%201,{k + 2},3,4", 200, r.randint(6000, 14000), ua)
        ekle(ip, som + timedelta(seconds=75), "POST", "/admin/giris.php", 302, 0, ua)
        ekle(ip, kab - timedelta(seconds=50), "POST", "/admin/gorsel-yukle.php", 200, 38, ua)
        yol = v["kabuk_yol"] + kabuk
    elif tur == "komut":
        ekle(ip, som - timedelta(seconds=60), "GET", "/araclar/ping.php?host=127.0.0.1", 200, 412, ua)
        ekle(ip, som, "GET", "/araclar/ping.php?host=127.0.0.1%3Bid", 200, 448, ua)
        ekle(ip, som + timedelta(seconds=19), "GET", "/araclar/ping.php?host=127.0.0.1%3Buname%20-a", 200, 497, ua)
        ekle(ip, som + timedelta(seconds=41), "GET", "/araclar/ping.php?host=127.0.0.1%3Bls%20-la", 200, 903, ua)
        yol = v["kabuk_yol"] + kabuk
    else:
        ekle(ip, som - timedelta(seconds=80), "GET", "/dilekce/ek-yukle.php", 200, 1900, ua)
        ekle(ip, som - timedelta(seconds=35), "POST", "/dilekce/ek-yukle.php", 403, 199, ua)
        ekle(ip, som, "POST", "/dilekce/ek-yukle.php", 200, 41, ua)
        yol = v["kabuk_yol"] + kabuk
    komutlar = ["id", "whoami", "sudo%20-l", "ls%20-la", "id", "pwd", "ls%20-la%20/home", "uname%20-a", "id"]
    n = s["kabuk_istek"]
    zamanlar = [kab] + sorted(kab + timedelta(seconds=r.randint(8, 900)) for _ in range(n - 1))
    kotu = r.randint(1, n - 1)                      # tek bir başarısız istek (500)
    for i, t in enumerate(zamanlar):
        kod, boyut = (500, 612) if i == kotu else (200, r.randint(40, 2400))
        ekle(ip, t, "GET", f"{yol}?c={komutlar[i]}", kod, boyut, ua)
    return L.metin()


def _auth_log(s: dict) -> str:
    import random
    r = random.Random(s["tohum_log"] + 7)
    m, v, T = s["m"], s["v"], s["T"]
    host, gun = m["sunucu"], s["gun"]
    L = LogYigini()
    pid = [s["pid_taban"]]

    def p():
        pid[0] += r.randint(1, 40)
        return pid[0]

    y1, y2 = s["yoneticiler"]
    ic = u.ic_ip(r, "10.0.0")
    for k in range(r.randint(2, 4)):                # meşru yönetici girişleri
        t = gun + timedelta(hours=r.randint(0, 5), minutes=r.randint(0, 59), seconds=r.randint(0, 59))
        L.ekle(t, sys_satiri(t, host, "sshd", p(), f"Accepted publickey for {r.choice([y1, y2])} from {ic} port {r.randint(30000, 60000)} ssh2"))
    for h in range(0, 7):                            # saatlik cron oturumları
        t = gun + timedelta(hours=h, minutes=17)
        q = p()
        L.ekle(t, sys_satiri(t, host, "CRON", q, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
        L.ekle(t + timedelta(seconds=1), sys_satiri(t, host, "CRON", q, "pam_unix(cron:session): session closed for user root"))
    t = gun + timedelta(hours=r.randint(0, 1), minutes=r.randint(20, 50), seconds=r.randint(0, 59))   # meşru sudo ve crontab
    L.ekle(t, sys_satiri(t, host, "sudo", p(), f"{y1} : TTY=pts/0 ; PWD=/home/{y1} ; USER=root ; COMMAND=/usr/bin/apt-get update"))
    L.ekle(t + timedelta(minutes=3), sys_satiri(t, host, "crontab", p(), f"({y1}) REPLACE ({y1})"))
    # saldırı izleri
    t_sudo, t_user, t_cron = T[3], T[4], T[5]
    arac = v["arac"][0]
    q = p()
    L.ekle(t_sudo, sys_satiri(t_sudo, host, "sudo", q,
                              f"www-data : TTY=unknown ; PWD={v['kabuk_yol'].rstrip('/') or '/'} ; USER=root ; COMMAND=/usr/bin/{arac}"))
    L.ekle(t_sudo, sys_satiri(t_sudo, host, "sudo", q, "pam_unix(sudo:session): session opened for user root(uid=0) by (uid=33)"))
    uid = s["uid"]
    L.ekle(t_user, sys_satiri(t_user, host, "groupadd", p(), f"group added to /etc/group: name={s['yeni']}, GID={uid}"))
    L.ekle(t_user, sys_satiri(t_user, host, "useradd", p(),
                              f"new user: name={s['yeni']}, UID={uid}, GID={uid}, home=/home/{s['yeni']}, shell=/bin/bash, from=none"))
    L.ekle(t_cron, sys_satiri(t_cron, host, "crontab", p(), "(root) REPLACE (root)"))
    for k in range(1, 4):
        tc = t_cron + timedelta(minutes=5 * k)
        qc = p()
        L.ekle(tc, sys_satiri(tc, host, "CRON", qc, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"))
        L.ekle(tc, sys_satiri(tc, host, "CRON", qc, "pam_unix(cron:session): session closed for user root"))
    return L.metin()


def yaz(lab: Path, s: dict) -> None:
    k, v, m = lab / s["klasor"], s["v"], s["m"]
    u.yaz(k / "access.log", _web_log(s))
    u.yaz(k / "auth.log", _auth_log(s))
    olaylar = [f"{i + 1}. {OLAYLAR[e]}".replace("**", "") for i, e in enumerate(s["perm"])]
    u.yaz(lab / "olay_listesi.txt", "Zaman çizelgesi için altı olay (karışık sırada):\n" + "\n".join(olaylar) + "\n")
    sis = lab / "sistem"
    y1, y2 = s["yoneticiler"]
    arac = "/usr/bin/" + v["arac"][0]
    ana = ["# sudoers — kurgusal kopya", "Defaults\tenv_reset", "Defaults\tsecure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\"",
           "root\tALL=(ALL:ALL) ALL", "%sudo\tALL=(ALL:ALL) ALL", f"{y1}\tALL=(root) NOPASSWD: /usr/bin/apt-get update"]
    if v["sudo_dosya"] == "etc/sudoers":
        ana.append(f"www-data\tALL=(root) NOPASSWD: {arac}")
    ana.append("@includedir /etc/sudoers.d")
    u.yaz(sis / "etc/sudoers", "\n".join(ana) + "\n")
    if v["sudo_dosya"] == "etc/sudoers":
        u.yaz(sis / "etc/sudoers.d/README", "# sudoers.d: alt dosyalar buraya.\n")
        u.yaz(sis / "etc/sudoers.d/10-izleme", f"{y2}\tALL=(root) /usr/bin/journalctl\n")
    elif v["kod"] == "pazarix":
        u.yaz(sis / v["sudo_dosya"], f"# web bakım işi için geçici verildi\nwww-data ALL=(root) NOPASSWD: {arac}\n")
    else:
        u.yaz(sis / v["sudo_dosya"], f"# destek ekibi\ndestek\tALL=(root) /usr/sbin/service apache2 restart\n"
                                     f"www-data\tALL=(root) NOPASSWD: {arac}\n")
    u.yaz(sis / v["kod_yolu"], KOD_ICERIK[v["tur"]])
    pw = ["root:x:0:0:root:/root:/bin/bash", "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
          f"{y1}:x:1000:1000::/home/{y1}:/bin/bash", f"{y2}:x:1001:1001::/home/{y2}:/bin/bash",
          f"{s['yeni']}:x:{s['uid']}:{s['uid']}::/home/{s['yeni']}:/bin/bash"]
    u.yaz(sis / "etc/passwd", "\n".join(pw) + "\n")
    u.yaz(sis / "var/spool/cron/crontabs/root",
          "# m h  dom mon dow   command\n17 * * * * cd / && run-parts --report /etc/cron.hourly\n"
          f"*/5 * * * * /var/tmp/.{s['kabuk'].split('_')[0]} >/dev/null 2>&1\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} / {m['sunucu']} olay incelemesi (KURGUSAL).\n"
          f"{s['klasor']}/ : web (access.log) ve sistem (auth.log) kayıtları. Dokunma, sadece oku.\n"
          "sistem/ : sunucunun canlı kopyası. Düzeltmeler burada yapılır.\n"
          f"Selin'den not: {m['hikaye']} Etkilenen veri: {m['hassas_veri']}.\n"
          "Sömürü satırının loglarda nasıl göründüğünü Deniz anlattı: açığa özgü, HTTP 200 dönen ilk istek.\n")


# ----------------------------------------------------------------------------- kontroller

def _satirlar(yol: Path) -> list:
    try:
        return yol.read_text(errors="replace").splitlines()
    except OSError:
        return []


def _sudo_kontrol(b) -> Sonuc:
    sis = b.lab / "sistem"
    dosyalar = [sis / "etc/sudoers"] + sorted((sis / "etc/sudoers.d").glob("*")) if (sis / "etc/sudoers.d").is_dir() else [sis / "etc/sudoers"]
    aktif = []
    for d in dosyalar:
        for sat in _satirlar(d):
            if sat.strip() and not sat.lstrip().startswith("#"):
                aktif.append((d.name, sat.strip()))
    kotu = [(d, x) for d, x in aktif if re.match(r"%?www-data\b", x)]
    if kotu:
        d, x = kotu[0]
        return Sonuc(False, f"`{d}` içinde web sunucusu hesabına hâlâ sudo yetkisi var: `{x}`. "
                            "Web hesabının sudo'ya ihtiyacı yok; sudoers ve sudoers.d altındaki bütün dosyalara bak.", yakin=True)
    ana = (sis / "etc/sudoers").read_text(errors="replace") if (sis / "etc/sudoers").exists() else ""
    if not re.search(r"^root\s+ALL=\(ALL:ALL\)\s+ALL", ana, re.M) or "@includedir" not in ana:
        return Sonuc(False, "`etc/sudoers` bozulmuş: `root` satırı ve `@includedir` satırı yerinde kalmalı. Sadece web hesabının satırını sil.", yakin=True)
    y1, y2 = b.senaryo["yoneticiler"]
    metin = "\n".join(x for _, x in aktif)
    if f"{y1}\tALL=(root) NOPASSWD: /usr/bin/apt-get update".replace("\t", " ") not in re.sub(r"\s+", " ", metin):
        return Sonuc(False, f"Meşru yönetici `{y1}`'in sudo satırı silinmiş. Yalnızca web hesabının (`www-data`) satırını kaldır.", yakin=True)
    return Sonuc(True, "www-data hesabının sudo yetkisi kalktı; meşru satırlar yerinde.")


def _web_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = b.lab / "sistem" / v["kod_yolu"]
    if not yol.exists():
        return Sonuc(False, f"`sistem/{v['kod_yolu']}` bulunamıyor; dosyayı silme, güvenli hâle getir.")
    kod = yol.read_text(errors="replace")
    satirlar = [x for x in kod.splitlines() if not x.strip().startswith("//")]
    tur = v["tur"]
    if tur == "sqli":
        kotu = [x for x in satirlar if "SELECT" in x and re.search(r"\$(_GET|_POST|id)\b", x)]
        iyi = "prepare(" in kod or re.search(r"intval\(|\(int\)", kod)
        if kotu or not iyi:
            return Sonuc(False, "Sorgu hâlâ kullanıcı girdisini doğrudan birleştiriyor. Parametreli sorgu (`prepare(` ve `execute`) kullan; "
                                "yalnızca sayı bekleniyorsa `intval(...)` ile sayıya çevirmek de kabul. Girdi filtresi tek başına yetmez.", yakin=True)
    elif tur == "komut":
        iyi = "escapeshellarg(" in kod or "FILTER_VALIDATE_IP" in kod
        kotu = [x for x in satirlar if re.search(r"shell_exec|system\(|exec\(|passthru", x) and re.search(r"\$_(GET|POST)", x)
                and "escapeshellarg(" not in x]
        if not iyi or (kotu and "FILTER_VALIDATE_IP" not in kod):
            return Sonuc(False, "`ping` komutuna kullanıcı girdisi olduğu gibi gidiyor. Girdiyi `escapeshellarg(...)` ile sar "
                                "ya da `filter_var($host, FILTER_VALIDATE_IP)` ile sadece geçerli bir IP kabul et.", yakin=True)
    else:
        ht = b.lab / "sistem/var/www/html/dilekce/ekler/.htaccess"
        htok = ht.exists() and re.search(r"engine\s+off|Require all denied|RemoveHandler", ht.read_text(errors="replace"), re.I)
        iyi = "in_array(" in kod
        if not (iyi or htok):
            return Sonuc(False, "Yükleme formu her dosyayı kabul ediyor. Uzantıyı izin listesiyle sınırla (`in_array(` ile `jpg, png, pdf`) "
                                "ya da `ekler/.htaccess` ile o klasörde PHP çalışmasını kapat (`php_flag engine off`).", yakin=True)
    return Sonuc(True, "Web kodu artık güvensiz girdiyi doğrudan kullanmıyor.")


def _sudo_hata(g, beklenen, b):
    if g in ("vim", "vi"):
        return "Tam adı sudo satırından oku; ikili `/usr/bin/` altında hangi adla geçiyor?"
    if g in ("apt-get", "apt", "journalctl", "service"):
        return "Bu, meşru yöneticinin ya da destek ekibinin komutu. Saldırının izi `www-data` kullanıcısının sudo satırındadır."
    return None


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["tarayici"]:
        return ("Bu IP çok sayıda 404/403 üretti ama bir tane bile başarılı sömürü ve web kabuğu isteği yok; tarayıcı gürültüsü. "
                "Saldırgan, kabuk dosyasına HTTP 200 alan IP'dir.")
    if g in s["mesru"]:
        return "Bu IP sadece normal sayfaları gezmiş meşru bir ziyaretçi."
    return None


def _sayi_hata(g, beklenen, b):
    if g == str(int(beklenen) + 1):
        return "Hata dönen (500) isteği de saymış olabilirsin; yalnızca HTTP 200 alanları say."
    return None


DUZELTME = {
    "sqli": """<?php
$id = intval($_GET['id']);
$st = $db->prepare("SELECT ad, fiyat, aciklama FROM urunler WHERE id = ?");
$st->execute([$id]);
echo goster($st);
""",
    "komut": """<?php
$host = escapeshellarg($_GET['host']);
echo "<pre>" . shell_exec("ping -c 1 " . $host) . "</pre>";
""",
    "yukleme": """<?php
$uzanti = strtolower(pathinfo($_FILES['ek']['name'], PATHINFO_EXTENSION));
if (!in_array($uzanti, ['jpg', 'png', 'pdf'])) { die("Tür kabul edilmiyor."); }
$hedef = "ekler/" . bin2hex(random_bytes(8)) . "." . $uzanti;
move_uploaded_file($_FILES['ek']['tmp_name'], $hedef);
""",
}


def coz(lab: Path, s: dict) -> dict:
    k, v = s["klasor"], s["v"]
    web, auth = f"{k}/access.log", f"{k}/auth.log"
    kabuk_ip = sh(f"grep -E '\\.php\\?c=' {web} | grep ' 200 ' | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    ad = sh(f"grep -w {kabuk_ip} {web} | grep -oE '[a-z0-9_]+_[0-9a-f]{{3}}\\.php' | head -1", lab)
    sayi = sh(f"grep -w {kabuk_ip} {web} | grep -F '{ad}?c=' | grep -c ' 200 '", lab)
    sombur = {"sqli": "UNION", "komut": "%3Bid", "yukleme": "POST /dilekce/ek-yukle.php"}[v["tur"]]
    komutlar = {
        "ilk isteği": f"grep -w {kabuk_ip} {web} | head -1",
        "sömürü": f"grep -w {kabuk_ip} {web} | grep -F '{sombur}' | grep ' 200 ' | head -1",
        "kabuğu": f"grep -w {kabuk_ip} {web} | grep -F '{ad}' | grep ' 200 ' | head -1",
        "sudo ile": f"grep 'sudo.[0-9]*.: www-data' {auth} | head -1",
        "useradd": f"grep 'new user:' {auth} | head -1",
        "crontab": f"grep -m1 '(root) REPLACE' {auth}",
    }
    zamanlar = []
    for satir in (lab / "olay_listesi.txt").read_text().splitlines()[1:]:
        no = int(satir.split(".", 1)[0])
        for anahtar, komut in komutlar.items():
            if anahtar in satir:
                zamanlar.append((sh(f"{komut} | grep -oP '{SAAT}' | head -1", lab), no))
    sira = " ".join(str(no) for _, no in sorted(zamanlar))
    arac = sh(f"grep 'sudo.[0-9]*.: www-data' {auth} | grep -oE 'COMMAND=[^ ]+' | head -1 | cut -d= -f2", lab).rsplit("/", 1)[-1]
    # düzeltmeler (gerçekten uygula)
    sh("grep -rl 'www-data' sistem/etc/sudoers sistem/etc/sudoers.d 2>/dev/null | while read f; do sed -i '/^[[:space:]]*www-data/d' \"$f\"; done", lab)
    sh("cat > sistem/" + v["kod_yolu"] + " <<'SON'\n" + DUZELTME[v["tur"]] + "SON", lab)
    rapor = ("Saldırgan IP önce siteyi taradı, açığı sömürüp web kabuğu yükledi, www-data hesabının parolasız sudo yetkisiyle root oldu, "
             "yeni bir hesap ve cron görevi bıraktı. Kök nedenler giriş denetimi eksik web kodu ile web hesabına verilmiş gereksiz sudo yetkisi. "
             "Düzeltme: kodu güvenli yazmak, sudo satırını kaldırmak, hesap ve cron kalıntısını temizleyip izleme alarmı eklemek.")
    return sec_doldur({1: kabuk_ip, 2: ad, 3: sayi, 4: sira, 5: arac, 6: "", 7: "", 8: "", 9: rapor}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Vaka dosyası", """
Capstone'a hoş geldin. Bu cilt yeni kavram öğretmez; kitabın hepsini **tek bir olay incelemesinde** toplar.
Bu kez saldırgan sen değilsin: ele geçirilmiş bir ortamın **kanıtlarını** okuyup saldırının baştan sona nasıl
ilerlediğini yeniden kuran mavi takım analistisin.

<<musteri>> (<<sektor>>) vakası: <<hikaye>> Elinde iki log (web ve sistem) ve sunucunun canlı kopyası var.
""", komut="ls -R <<klasor>> sistem"),
    Adim("1. Web logunda kim başarılı oldu?", """
Web logundaki satırın biçimi: IP, tarih, istek, **durum kodu** (200 başarılı, 404 yok, 500 sunucu hatası).
Gürültü ile saldırıyı ayıran şey sayı değil **başarıdır**: bir tarayıcı bin kez 404 alabilir ve hiçbir şey kazanmamış
olur. Önce her IP'nin kaç başarılı (200) isteği olduğuna bak:
""", komut="awk '$9==200 {print $1}' <<klasor>>/access.log | sort | uniq -c | sort -rn | head -5", sonra="""
Listenin başında en çok başarılı isteği olan IP'ler var; ama başarılı istek sayısı tek başına saldırgan demek değildir.
Meşru ziyaretçiler de 200 alır. Asıl ayırt edici, **normal sayfalar dışında bir yere** (yükleme, yönetim, `.php?c=`)
başarıyla erişmektir.
"""),
    Adim("2. Saldırının izini sürmek", """
Bir IP'yi seçince onun **bütün** isteklerini zaman sırasıyla oku: keşif, açığın denenmesi, sömürü, kabuk.
`grep -w` IP'yi kelime olarak arar (`203.0.113.4` ile `203.0.113.45` karışmaz). Örnek: POST isteklerine bak:
""", komut="grep POST <<klasor>>/access.log", sonra="""
POST istekleri veri gönderir: giriş formu, yükleme formu. Normal bir ziyaretçide pek görmezsin; bir yönetim paneline
ya da yükleme sayfasına POST, o sayfanın saldırı yüzeyi olduğunu gösterir. Sömürü satırı **açığa özgü** bir
işaret taşır: `UNION SELECT` (SQL enjeksiyonu), `%3B` (URL'de `;` yani komut ayırıcı) ya da yükleme sayfasına POST.
Bunlar loglarda yalnızca metindir; sen onları okuyorsun, çalıştırmıyorsun.
"""),
    Adim("3. Sistem logu: yetki yükseltmenin izi", """
Web kabuğu **www-data** (web sunucusunun düşük yetkili hesabı) olarak çalışır. Saldırgan root olmak için
`sudo`'yu kullandıysa bunu `auth.log` kaydeder. `sudo` ve hesap oluşturma izlerine bak:
""", komut="grep -E 'sudo|useradd|REPLACE' <<klasor>>/auth.log", sonra="""
Satırların başındaki `Mar  4 02:31:07` gibi saatleri web logundaki saatlerle yan yana koyabilirsin: web
kabuğunun ilk kullanımından kısa süre sonra gelen `sudo: www-data` satırı, **iki logu bağlayan** halkadır.
`(root) REPLACE (root)` root'un crontab'ının değiştirildiğini, `new user:` yeni hesabı gösterir. Meşru
yöneticinin kendi `sudo` ve `crontab` kayıtları da var; hesap adından ayırt et.
"""),
    Adim("4. Kök neden: sudo ayarı", """
Yetki yükseltme neden mümkündü? `www-data`'nın sudo yetkisi olduğu için. Bu yetki sudoers dosyasında ya da
`sudoers.d` altındaki bir dosyada tanımlıdır; ikisine de bak:
""", komut="grep -rn www-data sistem/etc/sudoers sistem/etc/sudoers.d", sonra="""
`NOPASSWD`, parola sormadan çalıştır demektir. Bazı programlar (`find`, `awk`, `vim` gibi) çalıştırdıkları
başka komutlara izin verir; bu yüzden onları sudo ile vermek fiilen **root vermek** demektir. Burada ders: bir web
hesabına hiçbir koşulda sudo gerekmez (en az yetki ilkesi).
"""),
    Adim("5. Kök neden: web kodu", """
Zincirin ilk halkası web uygulamasındaki bir kod hatasıydı. Sorunlu dosya `sistem/<<kod_yolu>>`:
""", komut="cat sistem/<<kod_yolu>>", sonra="""
Gördüğün satırda kullanıcıdan gelen değer **doğrulanmadan** bir sorguya, bir komuta ya da bir dosya yoluna
girmiş. Çözüm hep aynı fikre dayanır: kullanıcı girdisi **veri** olarak ele alınır, **komut** olarak değil
(parametreli sorgu, argüman kaçışı, uzantı izin listesi). Düzeltmeyi görevlerde sen yapacaksın.
"""),
    Adim("6. Zaman çizelgesi yöntemi", """
İyi bir olay raporu, olayların **hangi sırayla** olduğunu söyler. Yöntem: her olayın kanıt satırını bul, saatini
çıkar, saate göre diz. Bir logdan saati çıkarmayı dene:
""", komut="grep -m1 'new user:' <<klasor>>/auth.log", sonra="""
Satır başındaki saat olayın zamanıdır. Web logunda saat tarihin içinde durur (`04/Mar/2026:02:31:07`), sistem
logunda satır başındadır. Hepsi aynı saat dilimindeyse doğrudan karşılaştırabilirsin. **Hacker gözüyle:** bu zinciri
kitapta kendin yürütmüştün; şimdi aynı halkaları iz olarak okuyorsun ve her halkaya bir önlem koyacaksın.
"""),
]

GOREVLER = [
    Gorev("<<musteri>>'in `<<klasor>>/` klasöründe: web kabuğuna başarılı (HTTP 200) istek yapan **saldırgan IP** hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Saldırgan, normal sayfaların dışında bir PHP dosyasına `?c=` parametresiyle başarılı istek yapan IP'dir.",
           "`grep '?c=' <<klasor>>/access.log` ile o istekleri bul; hangi IP 200 alıyor?",
           "`grep '?c=' <<klasor>>/access.log | cut -d' ' -f1 | sort | uniq -c`"),
          puan=40, baslik="Saldırgan IP"),
    Gorev("Saldırganın sunucuya yerleştirdiği **web kabuğunun dosya adı** nedir? (örn. `ornek_ab1.php`)",
          Metin("kabuk", sadece_ad=True, bicim="dosya adı"),
          ("Saldırgan IP'nin `?c=` parametreli isteklerinde hep aynı dosya geçiyor.",
           "`grep ?c= <<klasor>>/access.log` çıktısında istek yoluna bak; son parça dosya adıdır.",
           "`grep '?c=' <<klasor>>/access.log | grep -o '[a-z0-9_]*\\.php' | sort -u`"),
          puan=30, baslik="Web kabuğu"),
    Gorev("Saldırgan IP'nin web kabuğu dosyasına yaptığı **başarılı (HTTP 200)** istek sayısı kaçtır?",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Aynı dosyaya yapılan bütün istekleri bul, sonra yalnızca başarılı olanları ayır.",
           "`grep DOSYA_ADI access.log | grep -c ' 200 '` sadece 200 dönenleri sayar.",
           "`grep -F '<DOSYA>?c=' <<klasor>>/access.log | grep -c ' 200 '`"),
          puan=30, baslik="Başarılı kabuk isteği"),
    Gorev("`olay_listesi.txt` içindeki altı olayı **gerçekleşme sırasına** diz. Cevap olarak listedeki **numaraları** "
          "sırayla yaz (örn. `4 2 1 6 3 5`).",
          ortak.Sira("sira", sik_hatalar=sira_hata),
          ("Her olay için kanıt satırını bul: web logu ya da auth.log. Saatlerine göre sıralayacaksın.",
           "Saati çıkar: `grep -oP '(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}'`; web logunda tarihin içindeki parçaya takılma.",
           "Altı saati yan yana yaz (kâğıda ya da bir dosyaya), saate göre sırala, olay numaralarını o sırayla oku."),
          puan=60, baslik="Zaman çizelgesi"),
    Gorev("`www-data` hesabı sudo ile root olarak **hangi programı** çalıştırdı? (yalnızca program adı)",
          Metin("arac", sadece_ad=True, bicim="program adı", sik_hatalar=_sudo_hata),
          ("Yetki yükseltmenin izi sistem logundadır, web logunda değil.",
           "`grep sudo <<klasor>>/auth.log`; `www-data` ile başlayan satırın `COMMAND=` kısmına bak.",
           "`grep 'sudo.[0-9]*.: www-data' <<klasor>>/auth.log | grep -o 'COMMAND=.*'`"),
          puan=30, baslik="Sudo ile çalışan program"),
    Gorev("Raporunda **kök neden** olarak hangisini yazarsın?",
          Secmeli([
              ("Girdi denetimi eksik bir web kodu ile web hesabına verilmiş gereksiz sudo yetkisinin zincirlenmesi",
               "Doğru. Biri içeri girişi, diğeri root'a yükselmeyi sağladı; iki yapılandırma/kod hatası birbirine bağlandı."),
              ("Saldırganın gece saatlerinde, güvenlik ekibi yokken saldırmayı seçmesi ve olayın o saate denk gelmesi",
               "Yanlış. Saldırı saati bir fırsat, neden değildir; savunmasız kod ve yetki olmasa gece de gündüz de başarısız olurdu."),
              ("Sunucuda kurulu bir güvenlik duvarı ya da antivirüs ürününün bulunmaması veya güncel olmaması",
               "Yanlış. Bu katmanlar zararı azaltabilirdi ama olayı mümkün kılan, düzeltilebilir kod ve yetki hatalarıdır."),
              ("Logların gereğinden fazla ayrıntılı tutulması ve saldırganın izlerinin kolayca okunabilmesi",
               "Yanlış. Ayrıntılı log savunmacının en büyük yardımcısıdır; sorun logda değil, açığın kendisindedir."),
          ], dogru=0),
          ("Kök neden, olayı mümkün kılan düzeltilebilir hatadır; saldırganın seçimi ya da saati değil.",
           "İki ayrı halka vardı: içeri giriş ve root'a yükselme. Her birini mümkün kılan neydi?",
           "İlk halka web kodunda, ikinci halka sudoers dosyalarında. İkisi birlikte doğru şıkta."),
          puan=30, baslik="Kök neden"),
    Gorev("`sistem/etc/sudoers` ve `sistem/etc/sudoers.d/` altında web sunucusu hesabına (`www-data`) verilmiş **sudo yetkisini kaldır**. "
          "Meşru yöneticilerin satırlarına ve `root` satırına dokunma. Bitince `cevap 7`.",
          Durum(_sudo_kontrol, "www-data satırını silmek: sed -i '/^www-data/d' <dosya>"),
          ("Yetki bir dosyada tanımlı ama hangisinde? Hem ana dosyaya hem alt klasöre bak.",
           "`grep -rn www-data sistem/etc/sudoers sistem/etc/sudoers.d` satırı ve dosyasını gösterir; yalnızca o satırı sil.",
           "`sed -i '/^[[:space:]]*www-data/d' DOSYA`; dosya sadece o satırdan ibaretse silinebilir ama diğer satırlara dokunma."),
          puan=60, baslik="Sudo yetkisini kaldır"),
    Gorev("Zincirin ilk halkasını kapat: `sistem/<<kod_yolu>>` dosyasındaki kodu **güvenli hâle getir** (parametreli sorgu / argüman kaçışı / "
          "uzantı izin listesi; dosyayı silme). Bitince `cevap 8`.",
          Durum(_web_kontrol, "dosyadaki güvensiz girdi kullanımını düzeltmek"),
          ("Kullanıcıdan gelen değer, sorguya/komuta/dosya yoluna doğrudan giriyor mu? Önce `cat` ile oku.",
           "Sorgu için `prepare(...)`, komut için `escapeshellarg(...)` ya da `filter_var(..., FILTER_VALIDATE_IP)`, yükleme için `in_array(...)` izin listesi.",
           "`nano sistem/<<kod_yolu>>` ile sorunlu satırı yeniden yaz; girdiyi doğrulamadan kullanma. Yükleme vakasında alternatif: `ekler/.htaccess` içinde `php_flag engine off`."),
          puan=70, baslik="Web kodunu düzelt"),
    Gorev("**Kısa bulgu yaz** (en az 30 kelime, tırnak içinde): saldırının web logundaki ilk izden root'a kadar nasıl ilerlediğini, "
          "kök nedenleri ve alacağın düzeltmeleri anlat. Bitince `cevap 9 \"...\"`.",
          Serbest("Saldırgan IP önce siteyi taradı, <<musteri>> web uygulamasındaki bir girdi denetimi açığını sömürüp sunucuya web kabuğu yerleştirdi, "
                  "ardından www-data hesabının parolasız sudo yetkisiyle root oldu, yeni bir hesap ve root cron görevi bıraktı. "
                  "Kök nedenler: girdisi doğrulanmayan web kodu ve web hesabına verilmiş gereksiz sudo yetkisi. "
                  "Önem: Kritik (tam sistem ele geçirme, etkilenen veri: <<hassas>>). Öneri: kodu parametreli/doğrulamalı yazmak, sudo satırını kaldırmak, "
                  "hesap ve cron kalıntısını temizlemek, web hesabı ve yükleme dizinleri için izleme alarmı kurmak.", min_kelime=30),
          ("Bir bulgu şu parçalardan oluşur: ne oldu, neden oldu, ne kadar kötü, ne yapılmalı.",
           "Zinciri tek cümlede özetle (giriş, kabuk, sudo, kalıcılık), sonra iki kök nedeni, sonra önerileri yaz.",
           "`cevap 9 \"Saldırgan ... sömürdü ... root oldu. Kök neden ... Öneri ...\"` biçiminde, tırnak içinde yaz."),
          puan=60, baslik="Kısa bulgu"),
]


def _kapanis():
    return """
Bir saldırıyı baştan sona yazmak, onu yürütmekten farklı bir beceridir: kanıtı bulmayı, kanıtlar arasında
**köprü kurmayı** (web logundaki IP'den sistem logundaki sudo satırına) ve her halkaya bir önlem koymayı öğrendin.
Saldırgan gözüyle bakınca zincirin her halkası bir sonrakine bağlı; savunmacı gözüyle ise **tek bir halkayı kırmak**
bütün zinciri durdurur. Burada en ucuz kırma noktaları ikisi de yapılandırmaydı: girdi doğrulaması ve en az yetki.
"""


SEVIYE = Seviye(
    kimlik="c24b01",
    cilt=24,
    bolum=1,
    baslik="Vaka 1: Web'den Root'a (Olay İncelemesi)",
    brifing="""
Selin Aksoy sizi toplantı odasına çağırıyor; masada üç klasör var. "Stajın son aşamasına geldin. Capstone: üç gerçek
vakayı baştan sona inceleyip final raporunu yazacaksın. Bu sefer saldırgan değilsin, **mavi takımsın**: kanıtlara bakıp
olayı yeniden kuracaksın."

İlk dosya **<<musteri>>** (<<sektor>>), sunucu **<<sunucu>>**. <<hikaye>> Deniz Kara loglardan çıktı aldı: "Web logu bir
yanda, sistem logu bir yanda. İkisini birbirine bağlayan şey bir IP, bir saat ve bir `sudo` satırı." Mert Yavuz ekliyor:
"Raporu kim yazacak? Sen. O yüzden her şeyi not al."

Görevin: giriş izinden root'a kadar zaman çizelgesini çıkar, kök nedenleri bul, kapıları kapat ve kısa bulguyu yaz.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Equifax 2017:** Kamuya açık anlatımlara göre saldırı, yaması yayımlanmış bir web uygulaması bileşenindeki (Apache Struts)
  zafiyetle başladı. Web katmanında bir halkanın düzeltilmemesi tüm zinciri açtı. Tespit tarafı: web logundaki olağandışı
  isteklerin izlenmesi ve yama yönetimi; önleme tarafı: yamanın zamanında uygulanması.
- **Heartland Payment Systems 2008:** Kamuya açık bilgilere göre kart verisi sızıntısı bir SQL enjeksiyonuyla başladı.
  Parametreli sorgu bu sınıfın temel önlemidir; web logunda `UNION SELECT` gibi izleri alarm kuralıyla yakalamak da tespit katmanıdır.
- Pek çok sızma testi ve olay raporunda web hesabına verilmiş fazla sudo yetkisi ya da yazılabilir yükleme dizini sık
  görülen yetki yükseltme halkasıdır. `auth.log` içindeki `sudo: www-data` satırı, hiçbir zaman beklenmemesi gereken bir
  alarmdır; bu satır için kural yazmak ucuz ve etkili bir tespittir.
""",
    sure_hedef_dk=45,
)
