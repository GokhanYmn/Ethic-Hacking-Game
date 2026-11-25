"""Cilt 6 · Bölüm 7 — Kapanış: Ele Geçirilmiş Bir Makinenin Olay Sonrası İncelemesi.

Beceri: web ve sistem loglarından saldırganın girişini, yetki yükselmesini ve bıraktığı kalıcılığı bulmak;
hepsini kapatmak ve kısa bir olay özeti yazmak.

Tamamen savunma gözüyle: oyuncu saldırı yapmaz, izleri okur ve temizler. Log satırlarındaki dosya ve yol adları
yalnızca metindir.
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

VAKALAR = [
    {"kod": "pazarix", "host": "pzx-web01", "web_kul": "www-data", "web": "nginx", "giris_yol": "/yonetim/dosya_yukle.php",
     "yukle_dizin": "/yuklemeler", "sayfalar": ["/index.php", "/sepet.php", "/kampanyalar.php", "/hakkimizda.php", "/urun.php?id=41"],
     "oturum_sayfa": "/giris.php", "cron_mesru": ["yedek", "temizlik"],
     "olay": "Kampanya sitesinde kimsenin eklemediği bir dosya belirdi ve sunucuda root yetkisiyle işlem yapılmış."},
    {"kod": "atolye", "host": "atolye-web", "web_kul": "www-data", "web": "apache2", "giris_yol": "/eklenti/galeri/yukle.php",
     "yukle_dizin": "/icerik", "sayfalar": ["/index.php", "/menu.php", "/subeler.php", "/iletisim.php", "/hakkimizda.php"],
     "oturum_sayfa": "/wp-login.php", "cron_mesru": ["yedek", "sertifika"],
     "olay": "Kafenin sitesinde galeri eklentisi sonrası sunucu garip davranıyor; sahibi artık sunucuya güvenmiyor."},
    {"kod": "kuzgun", "host": "kzg-depo", "web_kul": "depo-app", "web": "nginx", "giris_yol": "/panel/rapor_aktar.php",
     "yukle_dizin": "/panel/ciktilar", "sayfalar": ["/index.php", "/sube-bul.php", "/fiyat-hesapla.php", "/kurumsal.php", "/kargo-takip.php?kod=KZ48213"],
     "oturum_sayfa": "/panel/giris.php", "cron_mesru": ["yedek", "rapor"],
     "olay": "Depo panelinde kimsenin onaylamadığı bir rapor dosyası var; BT sunucudan şüphelenip kopyasını aldırdı."},
]
SUDO_RISKLI = ["find", "awk", "env", "tar"]
LEGIT_PASSWD = [
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
]
ARKA_KAPI_ADLARI = ["sysbackup", "svc_update", "maint", "helpdesk2", "ops_admin", "bakim_svc"]


def _hex(rng, n):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    sud = rng.choice(SUDO_RISKLI)
    isimler = u.isimler(rng, 3)
    kurban = rng.choice(isimler)
    ipler = u.benzersiz(rng, u.dis_ip, 7)
    saldirgan, tarayici, ziyaretciler = ipler[0], ipler[1], ipler[2:]
    arka = rng.choice(ARKA_KAPI_ADLARI)
    gizli_cron = rng.choice(["sistem-guncelle", "guvenlik-tarama", "log-bakim", "paket-denetim"])
    kabuk_dosya = f"{_hex(rng, 8)}.php"
    sifre_tag = _hex(rng, 6)
    onayli = [f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{_hex(rng, 20).upper()} {ad}@laptop" for ad in isimler]
    kotu = f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI{_hex(rng, 20).upper()} bakim@gecici"
    gun = u.gun(rng)
    t0 = gun + timedelta(hours=rng.randint(10, 21), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    return {
        "vaka": f"{m['ad']} — {v['host']} olay sonrası inceleme",
        "musteri": m, "v": v, "sud": sud, "isimler": isimler, "kurban": kurban, "saldirgan": saldirgan,
        "tarayici": tarayici, "ziyaretciler": ziyaretciler, "arka": arka, "gizli_cron": gizli_cron,
        "kabuk_dosya": kabuk_dosya, "tag": sifre_tag, "onayli": onayli, "kotu": kotu, "gun": gun, "t0": t0,
        "brifing": f"""
Selin Aksoy ve Deniz Kara aynı odada, ekranda **{m['ad']}**'in **{v['host']}** sunucusunun kopyası. Selin:
"{v['olay']} Müşteri bizden bir **olay sonrası inceleme** istiyor: saldırgan nereden girdi, hangi yanlış
yapılandırmayla yükseldi, ne bıraktı? Hepsini bul ve temizle."

Deniz ekliyor: "Bu cildin kapanış görevi bu. Hem saldırganın gözüyle düşün, hem savunmacı gibi hareket et.
Elinde web logu, sistem logu ve sunucunun dosya kopyası var. Bir şeyi unutursan saldırgan geri gelir."
""",
        "metin": {"musteri": m["ad"], "host": v["host"], "web_kul": v["web_kul"],
                  "yukle_dizin": v["yukle_dizin"], "giris_yol": v["giris_yol"]},
        "cevaplar": {
            "ip": saldirgan,
            "yol": [v["giris_yol"], v["giris_yol"].lstrip("/"), v["giris_yol"].rsplit("/", 1)[-1]],
            "sudo": sud,
            "arka": arka,
            "cron": gizli_cron,
            "ssh_kul": kurban,
        },
    }


def _web_logu(s: dict) -> str:
    v = s["v"]
    rng = random.Random(f"web:{s['saldirgan']}:{s['kabuk_dosya']}")
    t0 = s["t0"]
    gun0 = s["gun"].replace(hour=6)
    satir = []
    t = gun0
    for _ in range(rng.randint(50, 70)):
        t += timedelta(minutes=rng.randint(1, 18), seconds=rng.randint(0, 59))
        ip = rng.choice(s["ziyaretciler"])
        yol = rng.choice(v["sayfalar"])
        satir.append((t, u.apache_satiri(ip, t, "GET", yol, 200, rng.randint(900, 9000), rng.choice(u.TARAYICI_UA))))
        if rng.random() < 0.12:
            tt = t + timedelta(seconds=rng.randint(5, 40))
            satir.append((tt, u.apache_satiri(ip, tt, "POST", v["oturum_sayfa"], 302, 0, rng.choice(u.TARAYICI_UA))))
    # Tarayıcı araç: çoğu 404
    ts = t0 - timedelta(minutes=rng.randint(40, 120))
    for yol, kod in [("/admin/", 404), ("/phpmyadmin/", 404), ("/.git/config", 404), ("/yedek.zip", 404),
                     ("/admin/login.php", 404), ("/robots.txt", 200), ("/.env", 404), ("/backup.sql", 404)]:
        ts += timedelta(seconds=rng.randint(1, 4))
        satir.append((ts, u.apache_satiri(s["tarayici"], ts, "GET", yol, kod, rng.randint(150, 600), u.ARAC_UA["gobuster"])))
    # Saldırgan
    ua = rng.choice(u.KOMUT_SATIRI_UA)
    k = t0 - timedelta(seconds=40)
    ust = v["giris_yol"].rsplit("/", 1)[0] + "/"
    satir.append((k, u.apache_satiri(s["saldirgan"], k, "GET", ust, 200, 2210, ua)))
    k += timedelta(seconds=rng.randint(8, 20))
    satir.append((k, u.apache_satiri(s["saldirgan"], k, "GET", v["giris_yol"], 200, 1180, ua)))
    satir.append((t0, u.apache_satiri(s["saldirgan"], t0, "POST", v["giris_yol"], 200, 96, ua)))
    k = t0 + timedelta(seconds=rng.randint(15, 30))
    for _ in range(rng.randint(5, 9)):
        satir.append((k, u.apache_satiri(s["saldirgan"], k, "GET", f"{v['yukle_dizin']}/{s['kabuk_dosya']}", 200,
                                         rng.randint(40, 600), ua)))
        k += timedelta(seconds=rng.randint(10, 150))
    satir.sort(key=lambda x: x[0])
    return "\n".join(x[1] for x in satir) + "\n"


def _sistem_logu(s: dict) -> str:
    v = s["v"]
    rng = random.Random(f"sys:{s['saldirgan']}:{s['arka']}")
    t0 = s["t0"]
    h = v["host"]
    olaylar = []

    def sat(t, proc, pid, mesaj):
        etiket = "sudo:" if proc == "sudo" else f"{proc}[{pid}]:"
        olaylar.append((t, f"{u.syslog_zamani(t)} {h} {etiket} {mesaj}"))

    # Meşru gürültü: yönetici girişleri ve apt
    t = s["gun"].replace(hour=7)
    admin = s["isimler"][0]
    for _ in range(rng.randint(5, 8)):
        t += timedelta(minutes=rng.randint(20, 90))
        ic = u.ic_ip(rng)
        sat(t, "sshd", rng.randint(1000, 3000), f"Accepted publickey for {admin} from {ic} port {rng.randint(30000, 60000)} ssh2")
        sat(t + timedelta(seconds=40), "sudo", rng.randint(3000, 4000),
            f"  {admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/bin/apt update")
    # Saldırı zinciri
    t1 = t0 + timedelta(minutes=3)
    for i in range(rng.randint(1, 3)):
        sat(t1 + timedelta(seconds=i * 20), "sudo", rng.randint(5000, 6000),
            f"  {v['web_kul']} : TTY=unknown ; PWD={'/var/www'} ; USER=root ; COMMAND=/usr/bin/{s['sud']}")
    t2 = t1 + timedelta(minutes=1)
    sat(t2, "useradd", rng.randint(6000, 6500),
        f"new user: name={s['arka']}, UID=0, GID=0, home=/var/lib/{s['arka']}, shell=/bin/bash, from=none")
    t3 = t2 + timedelta(minutes=6)
    ks = t3
    for _ in range(rng.randint(4, 8)):
        sat(ks, "CRON", rng.randint(7000, 9000), f"(root) CMD (/dev/shm/.{s['tag']})")
        ks += timedelta(minutes=5)
    t4 = t3 + timedelta(minutes=rng.randint(12, 25))
    sat(t4, "sshd", rng.randint(9100, 9300),
        f"Accepted publickey for {s['kurban']} from {s['saldirgan']} port {rng.randint(30000, 60000)} ssh2")
    olaylar.sort(key=lambda x: x[0])
    return "\n".join(x[1] for x in olaylar) + "\n"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} · {v['host']} olay sonrası inceleme kopyası (KURGUSAL).\n"
          "kayitlar/access.log           : web sunucusu erişim logu\n"
          "kayitlar/sistem.log           : sudo, useradd, sshd ve cron kayıtları (auth.log + syslog özeti)\n"
          "kayitlar/onayli_anahtarlar.txt: BT'nin onayladığı SSH anahtarları (tek satır = bir anahtar)\n"
          "kopya/etc/                    : passwd, sudoers.d, cron.d\n"
          "kopya/home/                   : kullanıcı ev dizinleri (.ssh/authorized_keys)\n")
    u.yaz(lab / "kayitlar" / "access.log", _web_logu(s))
    u.yaz(lab / "kayitlar" / "sistem.log", _sistem_logu(s))
    # passwd
    passwd = list(LEGIT_PASSWD)
    passwd.append(f"{v['web_kul']}:x:33:33:{v['web_kul']}:/var/www:/usr/sbin/nologin")
    for i, ad in enumerate(s["isimler"]):
        passwd.append(f"{ad}:x:{1001 + i}:{1001 + i}:{ad.capitalize()}:/home/{ad}:/bin/bash")
    passwd.insert(len(passwd) // 2 + 1, f"{s['arka']}:x:0:0::/var/lib/{s['arka']}:/bin/bash")
    u.yaz(lab / "kopya" / "etc" / "passwd", "\n".join(passwd) + "\n", mod=0o644)
    # sudoers
    u.yaz(lab / "kopya" / "etc" / "sudoers.d" / f"90-{v['web_kul']}",
          f"# {v['web_kul']} için bakım yetkileri\n"
          f"{v['web_kul']} ALL=(root) NOPASSWD: /usr/bin/systemctl reload {v['web']}\n"
          f"{v['web_kul']} ALL=(root) NOPASSWD: /usr/bin/{s['sud']}\n", mod=0o440)
    # cron.d
    u.yaz(lab / "kopya" / "etc" / "cron.d" / v["cron_mesru"][0], "0 2 * * * root /opt/yedek/gece.sh\n", mod=0o644)
    u.yaz(lab / "kopya" / "etc" / "cron.d" / v["cron_mesru"][1], f"30 3 * * 0 {s['isimler'][0]} /opt/bakim/haftalik.sh\n", mod=0o644)
    u.yaz(lab / "kopya" / "etc" / "cron.d" / s["gizli_cron"], f"*/5 * * * * root /dev/shm/.{s['tag']}\n", mod=0o644)
    # ssh anahtarları
    for ad, anahtar in zip(s["isimler"], s["onayli"]):
        satirlar = [anahtar]
        if ad == s["kurban"]:
            satirlar.append(s["kotu"])
        u.yaz(lab / "kopya" / "home" / ad / ".ssh" / "authorized_keys", "\n".join(satirlar) + "\n", mod=0o600)
    u.yaz(lab / "kayitlar" / "onayli_anahtarlar.txt", "\n".join(s["onayli"]) + "\n")


def _okunur(yol: Path) -> list:
    try:
        return yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


def _hepsi_kapandi(b) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    lab = b.lab
    kalan = []
    # 1) sudoers
    sud = _okunur(lab / "kopya" / "etc" / "sudoers.d" / f"90-{v['web_kul']}")
    aktif = [x.strip() for x in sud if x.strip() and not x.strip().startswith("#")]
    if any("NOPASSWD" in x and x.endswith(f"/{s['sud']}") for x in aktif):
        kalan.append(f"sudoers: `{s['sud']}` için parolasız root yetkisi duruyor")
    elif not any("systemctl reload" in x for x in aktif):
        return Sonuc(False, "sudoers dosyasında meşru `systemctl reload` satırı da gitmiş; web sunucusunun bakımı bozulur. "
                            "Sadece riskli satırı çıkar.", yakin=True)
    # 2) arka kapı hesabı
    passwd = _okunur(lab / "kopya" / "etc" / "passwd")
    if any(x.startswith(f"{s['arka']}:") for x in passwd):
        kalan.append(f"hesap: `{s['arka']}` hâlâ /etc/passwd içinde")
    else:
        mesru = [x.split(":")[0] for x in passwd]
        eksik = [x.split(":")[0] for x in LEGIT_PASSWD + [f"{v['web_kul']}:"] if x.split(":")[0] not in mesru]
        eksik += [ad for ad in s["isimler"] if ad not in mesru]
        if eksik:
            return Sonuc(False, f"passwd dosyasından meşru hesap `{eksik[0]}` da silinmiş. Yalnızca arka kapı hesabı gitmeli.",
                         yakin=True)
    # 3) cron
    cron_dizin = lab / "kopya" / "etc" / "cron.d"
    if (cron_dizin / s["gizli_cron"]).exists():
        kalan.append(f"cron: `{s['gizli_cron']}` hâlâ cron.d içinde")
    for ad in v["cron_mesru"]:
        if not (cron_dizin / ad).exists():
            return Sonuc(False, f"Meşru cron işi `{ad}` da silinmiş. Yalnızca şüpheli olanı sil.", yakin=True)
    # 4) authorized_keys
    for ad in s["isimler"]:
        satirlar = _okunur(lab / "kopya" / "home" / ad / ".ssh" / "authorized_keys")
        if ad == s["kurban"] and s["kotu"] in satirlar:
            kalan.append(f"anahtar: `{ad}` kullanıcısının authorized_keys dosyasında yabancı anahtar duruyor")
        for onayli in s["onayli"]:
            if onayli.endswith(f" {ad}@laptop") and onayli not in satirlar:
                return Sonuc(False, f"`{ad}` kullanıcısının **onaylı** anahtarı da silinmiş; yalnızca yabancı olanı çıkarmalıydın.",
                             yakin=True)
    if kalan:
        return Sonuc(False, "Hâlâ açık kapılar var:\n   - " + "\n   - ".join(kalan), yakin=len(kalan) < 4)
    return Sonuc(True, "Dört kapı da kapandı: yanlış sudo satırı, arka kapı hesabı, gizli cron işi ve yabancı SSH anahtarı. "
                       "Gerçek olayda bu temizlik yetmez: ilk girişi sağlayan açığı yama ile kapatır, "
                       "parolaları/anahtarları yeniler ve sunucuyu temiz bir yedekten yeniden kurmayı değerlendirirsin.")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    v = s["v"]
    ip = sh("""grep -E '"GET [^ ]*/[0-9a-f]{8}\\.php' kayitlar/access.log | grep ' 200 ' | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'""", lab)
    yol = sh(f"""grep '^{ip} ' kayitlar/access.log | awk '$6=="\\"POST"{{print $7}}' | sort -u""", lab)
    sud = sh(f"x=$(grep 'sudo: *{v['web_kul']} ' kayitlar/sistem.log | grep -o 'COMMAND=[^ ]*' | head -1 | cut -d= -f2); echo ${{x##*/}}", lab)
    arka = sh("""awk -F: '$3==0 && $1!="root"{print $1}' kopya/etc/passwd""", lab)
    cron = sh("""x=$(grep -l -E '/dev/shm|/tmp' kopya/etc/cron.d/*); echo ${x##*/}""", lab)
    ssh = sh("""grep -r -v -x -F -f kayitlar/onayli_anahtarlar.txt kopya/home --include=authorized_keys | head -1 | cut -d/ -f3""", lab)
    sec = SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]
    ornek = "x " * 20
    # Temizlik
    sh(f"sed -i '/NOPASSWD: \\/usr\\/bin\\/{s['sud']}$/d' kopya/etc/sudoers.d/90-{v['web_kul']}", lab)
    sh(f"grep -v '^{arka}:' kopya/etc/passwd > kopya/etc/.t && mv kopya/etc/.t kopya/etc/passwd", lab)
    sh(f"rm kopya/etc/cron.d/{cron}", lab)
    sh(f"f=kopya/home/{ssh}/.ssh/authorized_keys; grep -x -F -f kayitlar/onayli_anahtarlar.txt $f > $f.t; mv $f.t $f", lab)
    return {1: ip, 2: yol, 3: sud, 4: arka, 5: cron, 6: ssh, 7: sec, 8: "", 9: ornek.strip() + " " + "olay özeti kelime " * 4}


def _yol_hata(g, beklenen, b):
    if b.senaryo["kabuk_dosya"] in g:
        return ("Bu, saldırganın sonradan çağırdığı dosya. Aradığın, saldırganın **POST** ile istek gönderdiği ve "
                "içeri girmesini sağlayan savunmasız sayfa.")
    return None


def _sudo_hata(g, beklenen, b):
    if g in ("systemctl", "apt"):
        return "Bu satır tek bir alt komuta kilitli ya da meşru bir yönetici işi. Web hesabının sınırsız kullandığı programı ara."
    return None


ADIMLAR = [
    Adim("Olay sonrası inceleme: üç soru", """
Bir sunucu ele geçirildiğinde savunmacının üç sorusu vardır:

1. **Nereden girdi?** (ilk erişim; hangi açık)
2. **Nasıl yükseldi?** (yetki yükseltme; hangi yanlış yapılandırma)
3. **Ne bıraktı?** (kalıcılık; kapıyı arkadan açık bırakmak)

Cevaplar farklı kaynaklarda saklıdır: web logu ilk girişi, sistem logu yükselmeyi, dosya sistemi kalıcılığı
gösterir. Bu üçünü birleştirmek, bir olay müdahalecisinin işidir. MITRE ATT&CK bilgi tabanındaki taktik adlarıyla:
*Initial Access* (ilk erişim), *Privilege Escalation* (yetki yükseltme), *Persistence* (kalıcılık).

Lab:
""", komut="cat OKUBENI.txt"),
    Adim("Web logu: POST istekleri", """
Bir web açığıyla içeri girmek genelde bir sayfaya **veri göndermek (POST)** ile olur. Meşru kullanıcılar da
giriş formu gibi sayfalara POST yapar; bu yüzden POST'lara **tek tek** bakmak gerekir. Hepsini listele:
""", komut="grep POST kayitlar/access.log", sonra="""
Bazıları giriş sayfasına (yönlendirme kodu `302`) giden sıradan ziyaretçilerin istekleri. Birinde ise yönetim
ya da yükleme sayfasına giden, `200` dönen bir POST var; üstelik diğerlerinden farklı bir IP'den ve araç
benzeri bir istemciyle (kullanıcı aracı alanına bak).
"""),
    Adim("Tarama gürültüsü ile gerçek giriş", """
Her kötü niyetli IP içeri girmiş değildir. **Tarayıcı** araçlar çok sayıda yolu dener ve çoğu zaman `404`
(bulunamadı) alır. Gerçek girişte ise istekler **başarılı** (`200`) döner. Kaynak IP'ye göre `404` sayısı:
""", komut="grep ' 404 ' kayitlar/access.log | cut -d' ' -f1 | sort | uniq -c", sonra="""
Bu IP ağırlıkla `404` alıyor: **taradı ama bir şey bulamadı**. Önceliğin, başarılı istek yapanlar.
"""),
    Adim("Web dizininde beklenmeyen dosya", """
Yükleme dizinleri (`<<yukle_dizin>>`) normalde resim ve belge barındırır, **çalıştırılabilir betik değil**. Bu
dizindeki bir `.php` dosyasına gelen istek, yüklenmiş bir dosyanın çalıştırıldığının işaretidir. Dizine gelen
istek sayısına bak:
""", komut="grep -c '<<yukle_dizin>>/' kayitlar/access.log", sonra="""
Sıradan bir sitede bu dizine yapılan istekler resim ve belge istekleridir. Bu sayının içinde bir de **tek bir
`.php` dosyasına** tekrar tekrar gelen istekler var; kim istiyor, görevlerde bulacaksın.
"""),
    Adim("Sistem logu: yükseliş izi", """
Web uygulamasını çalıştıran hesabın (`<<web_kul>>`) normalde `sudo` ile işi olmaz. Sistem logunda `sudo:`
satırlarına bak; yöneticilerin meşru satırlarıyla karışık olacak:
""", komut="grep 'sudo:' kayitlar/sistem.log", sonra="""
Web hesabının root yetkisiyle bir **program** çalıştırması, yetki yükseltmenin kanıtıdır. Hangi program ve neden
buna izin verilmiş? Cevap sudoers dosyasında.
"""),
    Adim("Sudoers: yükselişin kapısı", """
`sudoers.d` altındaki dosyalar kimin hangi komutları parolasız root olarak çalıştırabileceğini söyler:
""", komut="ls kopya/etc/sudoers.d", sonra="""
Dosya adı hesabın adını taşıyor. İçine `cat` ile bakıp, hangi program(lar) için `NOPASSWD` verilmiş görebilirsin.
Bölüm 4'te öğrendiğin gibi: **argümansız** program vermek, programın tüm yeteneklerini root'a vermektir.
"""),
    Adim("Kalıcılık: üç klasik yer", """
Saldırgan yeniden girebilmek için kapıyı açık bırakır. Üç klasik yer:

- **Yeni hesap**, genelde UID'i 0 (root'a eşit) bir hesap.
- **Zamanlanmış görev** (cron), sunucu temizlense bile yeniden çalışır.
- **SSH anahtarı**: bir kullanıcının `authorized_keys` dosyasına eklenen yabancı anahtar, parolasız giriş sağlar.

İlk yer: `passwd` dosyasında hesap adı ve UID (3. alan).
""", komut="cut -d: -f1,3 kopya/etc/passwd", sonra="""
`root` dışında UID'i `0` olan bir hesap varsa o, saldırganın bıraktığı yönetici hesabıdır. Diğer iki yer:
`kopya/etc/cron.d/` ve `kopya/home/*/.ssh/authorized_keys`. Cron'da yeni görevler çoğunlukla `/tmp` ya da
`/dev/shm` gibi herkesin yazabildiği bir yerdeki dosyayı çalıştırır; SSH anahtarını da BT'nin onayladığı
anahtar listesiyle karşılaştırırsın.
"""),
    Adim("Temizlik ve kök neden", """
Temizlik sırası: **önce kalıcılığı kapat**, sonra yükseliş kapısını, en son ilk girişteki açığı yama ile kapat.
Kapıların **hepsini** kapatmak gerekir; biri açık kalırsa saldırgan geri döner. Gerçek bir olayda ayrıca:
parolalar ve anahtarlar yenilenir, loglar güvenli yere alınır ve en emin yol sunucuyu **temiz bir yedekten
yeniden kurmaktır**.

Kök neden analizi: zinciri en ucuza **hangi halkada** kırabilirdin?
""", komut="ls kopya/etc/cron.d", sonra="""
Zincirin üç halkasından ikisi **yanlış yapılandırma** (parolasız sudo, düzgün denetlenmeyen anahtar/cron), biri
bir **uygulama açığı**. Web hesabının sudo yetkisi olmasaydı, web açığı olsa bile saldırgan root olamazdı: **en az
yetki** zinciri erken keser.
"""),
]

GOREVLER = [
    Gorev("`kayitlar/access.log` içinde, yüklenen bir `.php` dosyasını (rastgele harf-rakam adı, `<<yukle_dizin>>` "
          "altında) başarıyla (`200`) çağıran ve içeri girişi yapan IP hangisi?",
          IP("ip", sik_hatalar=lambda g, beklenen, b: (
              "Bu IP yalnızca yolları denemiş ve çoğunlukla `404` almış; içeri girmemiş." if g == b.senaryo["tarayici"] else None)),
          ("Çok sayıda `404` alan IP, taramadır; sen içeri girip bir dosyayı **çağıran** IP'yi arıyorsun.",
           "`grep '.php' kayitlar/access.log` ve `<<yukle_dizin>>` altında, sekiz karakterlik rastgele adlı bir dosyayı arayan satırlara bak.",
           "`grep -E '\"GET [^ ]*/[0-9a-f]{8}\\.php' kayitlar/access.log | grep ' 200 '` satırlarının ilk alanı IP'dir."),
          puan=30, baslik="Nereden girdi"),
    Gorev("Bu IP, **hangi sayfaya POST** ile istek göndererek içeri girdi? (Sayfanın yolunu ya da dosya adını yaz.)",
          Metin("yol", sadece_ad=True, sik_hatalar=_yol_hata, bicim="sayfa yolu ya da dosya adı"),
          ("Saldırganın POST isteklerini ayıkla; meşru ziyaretçilerin POST'ları farklı bir sayfaya gider.",
           "`grep '<ip>' kayitlar/access.log | grep POST`",
           "Tek bir POST satırı var; 7. alan sayfa yolu."),
          puan=25, baslik="Açık sayfa"),
    Gorev("`kayitlar/sistem.log` içinde web hesabı `<<web_kul>>` root olarak **hangi programı** çalıştırmış? "
          "(Program adını yaz.)",
          Metin("sudo", sadece_ad=True, sik_hatalar=_sudo_hata, bicim="program adı"),
          ("Yöneticilerin meşru sudo satırları da var; web hesabının satırlarını ayıkla.",
           "`grep 'sudo: *<<web_kul>>' kayitlar/sistem.log` ve `COMMAND=` alanına bak.",
           "Programın tam yolundan sadece adı al; aynı program `sudoers.d` altındaki dosyada da `NOPASSWD` olarak tanımlı."),
          puan=25, baslik="Yetki yükseltme"),
    Gorev("`kopya/etc/passwd` içinde root olmadığı halde **UID'i 0** olan arka kapı hesabının adı nedir?",
          Metin("arka", bicim="hesap adı"),
          ("passwd satırı `ad:x:UID:GID:...`: 3. alan UID.",
           "`awk -F:` ile alanlara böl, 3. alanı `0` olanları yazdır.",
           "`awk -F: '$3==0 && $1!=\"root\"{print $1}' kopya/etc/passwd`"),
          puan=20, baslik="Arka kapı hesabı"),
    Gorev("`kopya/etc/cron.d/` içinde **şüpheli** (herkesin yazabildiği bir yerdeki dosyayı root olarak "
          "çalıştıran) cron dosyasının adı nedir?",
          Metin("cron", sadece_ad=True, bicim="dosya adı"),
          ("Cron dosyalarının içindeki yollara bak: meşru işler `/opt` altındaki betikleri çağırır.",
           "`/tmp` ya da `/dev/shm` gibi geçici bir yer şüphelidir.",
           "`grep -l -E '/dev/shm|/tmp' kopya/etc/cron.d/*`"),
          puan=25, baslik="Gizli cron"),
    Gorev("`kopya/home/*/.ssh/authorized_keys` dosyalarından **hangi kullanıcıda**, BT'nin onayladığı "
          "listede (`kayitlar/onayli_anahtarlar.txt`) **olmayan** bir anahtar var? (Kullanıcı adını yaz.)",
          Metin("ssh_kul", sadece_ad=True, bicim="kullanıcı adı"),
          ("Onaylı anahtar listesi var; onda olmayan satırlar yabancıdır.",
           "`grep -v -x -F -f onay_listesi dosya` listede olmayan satırları gösterir; `-r` ile klasörü tara.",
           "`grep -r -v -x -F -f kayitlar/onayli_anahtarlar.txt kopya/home --include=authorized_keys`; satırın başındaki yolda kullanıcı adı var."),
          puan=30, baslik="Yabancı anahtar"),
    Gorev("Bu olayda zincirin **en ucuz kırılabileceği** ve root'a yükselmeyi engelleyecek halka hangisiydi?",
          Secmeli([
              ("Web hesabına parolasız sudo vermemek; açık olsa da saldırgan root olamazdı",
               "Doğru. En az yetki ilkesi, bir uygulama açığının etkisini sınırlar: saldırgan web hesabının yetkisiyle kalır."),
              ("Web sunucusunun adını gizlemek; saldırgan hedef sistemi tanıyamaz hale gelirdi",
               "Sunucu adı gizlemek güvenlik sağlamaz; saldırgan zaten sayfanın kendisini bulmuştu."),
              ("Log dosyalarını daha sık silmek; saldırgan iz bulamaz ve saldırıyı bırakırdı",
               "Log silmek savunmacıyı kör eder; saldırgan için bir şey değişmez."),
              ("Bütün kullanıcıların SSH parolasını aynı yapmak; böylece yönetmek kolaylaşırdı",
               "Aynı parola riski büyütür; ayrıca olayda kullanılan anahtar tabanlı giriş."),
          ]),
          ("Zincirde iki halka yanlış yapılandırma; hangisini kapatmak root'u engelliyor?",
           "Web uygulamasının hesabı neden sudo kullanabiliyor?",
           "En az yetki ilkesi."),
          puan=20, baslik="Kök neden"),
    Gorev("Dört kapıyı kapat: (1) `sudoers.d` içindeki **riskli program** satırını çıkar, (2) arka kapı hesabını "
          "`passwd`'den sil, (3) şüpheli cron dosyasını sil, (4) yabancı SSH anahtarını `authorized_keys`'ten çıkar. "
          "Meşru yetkiler, hesaplar, işler ve anahtarlar kalsın. Bitince `cevap 8` yaz.",
          Durum(_hepsi_kapandi, "sudoers satırı, arka kapı hesabı, gizli cron ve yabancı anahtarı sil; meşrulara dokunma"),
          ("Hangi dört şeyi bulduğunu hatırla (görev 3, 4, 5, 6). Her biri ayrı bir dosyada.",
           "Satır silmek için `sed -i '/kalıp/d' dosya` ya da `grep -v kalıp dosya > geçici && mv geçici dosya`; dosya silmek için `rm`. Her silmeden önce hedefi `cat` ile kontrol et.",
           "sudoers: `sed -i '/NOPASSWD: \\/usr\\/bin\\/<program>$/d' kopya/etc/sudoers.d/90-<hesap>`; passwd: `grep -v '^<arka>:' ...`; cron: `rm kopya/etc/cron.d/<ad>`; anahtar: onaylı satırları `grep -x -F -f` ile süz."),
          puan=40, baslik="Hepsini kapat"),
    Gorev("Olayı üç kısa cümleyle özetle: **nereden girdi, nasıl yükseldi, ne bıraktı** ve **neyi düzelttin**?",
          Serbest("<<musteri>>: saldırgan <<giris_yol>> sayfasındaki açığı kullanarak içeri girdi ve web sitesinin "
                  "hesabıyla bir dosya çalıştırdı. Bu hesaba verilmiş gereksiz parolasız sudo yetkisiyle root oldu. "
                  "Arkasında yeni bir yönetici hesap, gizli bir cron işi ve yabancı bir SSH anahtarı bıraktı; hepsini "
                  "kaldırdık, sudo yetkisini daralttık ve uygulama açığının yamalanmasını önerdik.",
                  min_kelime=12),
          ("Üç cümle: giriş, yükselme, kalıcılık. Dördüncü olarak düzeltmeyi ekle.",
           "Rapor yazarken kimin (hangi hesap/IP), ne yaptığını (ne zaman, hangi yolla) ve ne bıraktığını belirt.",
           "Örnek yapı: \"X sayfasındaki açıkla girdi; Y yanlış yapılandırmasıyla yükseldi; Z kalıcılığı bıraktı; hepsini kapattık.\""),
          puan=25, baslik="Olay özeti"),
]


def _kapanis():
    return """
Saldırganın gözüyle: bu makine bir zincirdi. Bir uygulama açığıyla girdi, gereksiz bir sudo yetkisiyle root
oldu ve üç kapı bıraktı. Savunmanın gözüyle: her halkanın bir izi vardı (web logu, sudo/useradd kaydı,
dosya sisteminde yeni hesap, cron ve anahtar). Cilt 6'nın özeti: **en az yetki** zinciri erken keser,
**yama yönetimi** zinciri başında keser, **log izleme** zinciri çalışırken yakalar. Bu cildin uygulamalı saldırı
pratiğini yalnızca **kendi laboratuvarında** yap: Cilt 9'da Kali'nde kuracağın savunmasız hedefler ve bu
oyunun yerel vakaları. Sırada Cilt 7: Savunma tarafı. Buradaki her "Hacker gözüyle" kutusunu, orada bir bütün
haline getireceksin.
"""


SEVIYE = Seviye(
    kimlik="c06b07",
    cilt=6,
    bolum=7,
    baslik="Kapanış: Ele Geçirilmiş Bir Makinenin İncelemesi",
    brifing="""
**<<musteri>>**'nin **<<host>>** sunucusu ele geçirildi. Selin: "Nereden girdi, nasıl yükseldi, ne bıraktı?
Hepsini bul ve kapat."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Zincir mantığı gerçektir:** Pek çok kamuya açık ihlal incelemesi (örneğin Equifax 2017) aynı kalıbı gösterir:
  yamalanmamış ya da yanlış yapılandırılmış bir internete açık sistem, sonrasında ağ içinde yetki ve erişim
  genişlemesi. Her halkada savunma yapılabilirdi.
- **MITRE ATT&CK:** İlk erişim (TA0001), yetki yükseltme (TA0004) ve kalıcılık (TA0003) gibi taktikleri ortak bir
  dille adlandırır; olay raporlarında bulguları bu sınıflara eşlemek yaygın uygulamadır.
- **Tespit ve önleme:** Web loglarında yükleme dizinlerinden betik çalışması, web hesabının `sudo` kullanması,
  yeni UID 0 hesapları ve `authorized_keys`/cron değişiklikleri; bunlar `auditd`, dosya bütünlüğü izleme (örneğin AIDE)
  ve SIEM kurallarıyla izlenebilir. Önleme: yama yönetimi, yükleme dizinlerinde betik çalıştırmayı kapatmak,
  web hesabına sudo vermemek ve ayrıcalıklı yapılandırmaları düzenli denetlemek.
""",
    sure_hedef_dk=40,
    tamamlama_bonusu=100,
)
