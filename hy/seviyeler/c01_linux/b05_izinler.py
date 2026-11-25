"""Cilt 1 · Bölüm 5 — Kullanıcılar, Gruplar ve İzinler.

Beceri: /etc/passwd okumak (kabuğu olan kullanıcılar, UID 0 arka kapısı), izinleri okumak,
rwx ↔ oktal dönüşüm, chmod ile düzeltmek, x izni olmayan klasörde gerçek deney, sudo -l
çıktısını yorumlamak ve SUID avı.

Vakalar: farklı müşterilerin sunucularından alınan kopyalar. passwd içeriği, arka kapı
hesabı, beklenmeyen SUID programı, kilitli klasör, izin soruları ve yedek dosyası değişir.
/etc/passwd lab içindeki sahte bir kopyadan okunur (deterministik).
"""
from __future__ import annotations

import stat
import subprocess
from pathlib import Path

from hy.motor.kontrol import Bayrak, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye, yer_tut
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

DUZENLER = [
    # (web klasörü, sunucu kopyası klasörü, kilitli klasör)
    ("web", "sunucu_kopyasi", "kasa"),
    ("site", "toplanan", "arsiv_kilitli"),
    ("public_html", "dokum", "ozel"),
    ("www", "kanitlar", "gizli_dolap"),
]
IZINLER = [0o750, 0o640, 0o711, 0o700, 0o644, 0o755, 0o775, 0o664, 0o744, 0o751, 0o740, 0o705,
           0o604, 0o660, 0o770, 0o550, 0o444, 0o400]          # 754 eğitimde, 600 görevde kullanılıyor
SISTEM = [
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin", "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin", "sync:x:4:65534:sync:/bin:/bin/sync",
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin", "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin", "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin", "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin", "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
    "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin",
    "messagebus:x:100:107::/nonexistent:/usr/sbin/nologin", "sshd:x:101:65534::/run/sshd:/usr/sbin/nologin",
]
SECMELI_SERVIS = [
    "mysql:x:102:110:MySQL Server,,,:/nonexistent:/bin/false",
    "postgres:x:103:111:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash",
    "redis:x:104:112::/var/lib/redis:/usr/sbin/nologin",
    "postfix:x:105:113::/var/spool/postfix:/usr/sbin/nologin",
]
ARKA_KAPILAR = ["toor", "sysadm", "destek", "yedekci", "admin2", "svc_bakim"]
TUZAKLAR = [("yedekleme", "Yedekleme ajanı (bash betikleri)"), ("otomasyon", "Gece işleri - bash/zsh betik kullanıcısı"),
            ("betikci", "Eski bash betikleri deposu")]
STANDART_SUID = ["/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount", "/usr/bin/newgrp",
                 "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/umount", "/usr/bin/fusermount3",
                 "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
                 "/usr/lib/polkit-1/polkit-agent-helper-1"]
SUID_ADAYLARI = [("/usr/bin/find", ["find"]), ("/usr/bin/python3.11", ["python3.11", "python3", "python"]),
                 ("/usr/bin/vim.basic", ["vim.basic", "vim"]), ("/usr/local/bin/yedek_al", ["yedek_al"]),
                 ("/usr/bin/env", ["env"]), ("/usr/bin/cp", ["cp"]), ("/opt/{kod}/rapor_araci", ["rapor_araci"])]
SUDO_PROGRAMLARI = ["find", "vim", "less", "awk", "tar", "python3"]


class _Durum(Durum):
    def cevabi_goster(self, b):
        return yer_tut(self.cozum, b.senaryo)


def sembolik(mod: int) -> str:
    return "".join(("r" if d & 4 else "-") + ("w" if d & 2 else "-") + ("x" if d & 1 else "-")
                   for d in ((mod >> 6) & 7, (mod >> 3) & 7, mod & 7))


def uret(rng):
    m = musteri_sec(rng)
    web, kopya_k, kilitli_k = rng.choice(DUZENLER)
    izin_a, izin_b = rng.sample(IZINLER, 2)
    # passwd
    insanlar = u.isimler(rng, rng.randint(2, 4))
    kabuklar = {ad: rng.choice(["/bin/bash", "/usr/bin/zsh"]) for ad in insanlar}
    arka = rng.choice(ARKA_KAPILAR)
    tuzak_ad, tuzak_aciklama = rng.choice(TUZAKLAR)
    servisler = rng.sample(SECMELI_SERVIS, rng.randint(1, 3))
    satirlar = ["root:x:0:0:root:/root:/bin/bash"] + SISTEM + servisler
    satirlar.insert(rng.randint(6, len(satirlar) - 2), f"{arka}:x:0:0::/root:/bin/bash")
    satirlar.append(f"{tuzak_ad}:x:996:996:{tuzak_aciklama}:/var/lib/{tuzak_ad}:/usr/sbin/nologin")
    for i, ad in enumerate(insanlar):
        satirlar.append(f"{ad}:x:{1000 + i}:{1000 + i}:{ad.capitalize()},,,:/home/{ad}:{kabuklar[ad]}")
    kabuklu = ["root", arka] + insanlar + [s.split(":")[0] for s in servisler if s.endswith(("bash", "zsh"))]
    # SUID listesi
    suid_yol, suid_adlar = rng.choice(SUID_ADAYLARI)
    suid_yol = suid_yol.format(kod=m["kod"])
    suid = rng.sample(STANDART_SUID, rng.randint(9, len(STANDART_SUID)))
    suid.insert(rng.randint(2, len(suid) - 1), suid_yol)
    # Kilitli klasör ve yedek
    kilitli_dosya = f"{rng.choice(['devir_notu', 'anahtar', 'kasa_kodu', 'gece_notu'])}_{rng.randint(10, 99)}.txt"
    yedek = m["yedek"].lstrip("/")
    sudo_kul, sudo_prog = rng.choice(insanlar), rng.choice(SUDO_PROGRAMLARI)
    return {
        "vaka": f"{m['ad']} — {m['sunucu']} izin denetimi",
        "musteri": m,
        "duzen": (web, kopya_k, kilitli_k),
        "passwd": "\n".join(satirlar) + "\n",
        "suid": "\n".join(suid) + "\n",
        "tuzak": tuzak_ad, "arka": arka,
        "yedek": yedek, "yedek_parola": u.parola(rng),
        "kilitli_dosya": kilitli_dosya,
        "sudo": (sudo_kul, sudo_prog),
        "izin_a": izin_a, "izin_b": izin_b,
        "metin": {
            "musteri": m["ad"], "sunucu": m["sunucu"], "kisi": m["kisi"], "web": web, "kopya_k": kopya_k,
            "kilitli_k": kilitli_k, "yedek": yedek, "sembolik_a": sembolik(izin_a), "oktal_b": f"{izin_b:o}",
            "sudo_kul": sudo_kul, "sudo_prog": sudo_prog,
        },
        "cevaplar": {
            "oktal_a": int(f"{izin_a:o}"),
            "sembolik_b": [sembolik(izin_b), "-" + sembolik(izin_b)],
            "kilitli_dosya": kilitli_dosya,
            "bayrak": u.bayrak(rng, rng.choice(["yanlis_izin", "kirik_kilit", "arka_oda", "gizli_kapi"])),
            "kabuklu": kabuklu,
            "arka_kapi": arka,
            "suid": [suid_yol] + suid_adlar,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    web, kopya_k, kilitli_k = s["duzen"]
    m = s["musteri"]
    c = s["cevaplar"]
    u.yaz(lab / web / "index.php", "<?php echo 'Hoş geldiniz'; ?>\n", mod=0o644)
    u.yaz(lab / web / "giris.php", "<?php // oturum açma formu ?>\n", mod=0o644)
    u.yaz(lab / web / s["yedek"], m["yedek_icerik"].format(parola=s["yedek_parola"]), mod=0o644)
    u.yaz(lab / kopya_k / "etc" / "passwd", s["passwd"], mod=0o644)
    u.yaz(lab / kopya_k / "suid_listesi.txt", s["suid"])
    sudo_kul, sudo_prog = s["sudo"]
    u.yaz(lab / kopya_k / "sudo_l.txt",
          f"$ sudo -l   ({sudo_kul} kullanıcısı olarak)\n"
          f"Matching Defaults entries for {sudo_kul} on {m['sunucu']}:\n"
          "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
          f"User {sudo_kul} may run the following commands on {m['sunucu']}:\n"
          f"    (root) NOPASSWD: /usr/bin/{sudo_prog}\n")
    u.yaz(lab / kopya_k / "OKUBENI.txt",
          f"{m['sunucu']} sunucusundan toplananlar:\n"
          "  etc/passwd        -> sunucunun /etc/passwd dosyası\n"
          "  suid_listesi.txt  -> find / -perm -4000 -type f 2>/dev/null çıktısı\n"
          f"  sudo_l.txt        -> {sudo_kul} kullanıcısının sudo -l çıktısı\n")
    kasa = lab / kilitli_k
    u.yaz(kasa / s["kilitli_dosya"], f"Eski yöneticinin devir notu.\nKasa kodu: {c['bayrak']}\n")
    kasa.chmod(0o640)          # okuma var, çalıştırma (x) yok: ls adları gösterir, cd ve cat çalışmaz


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: chmod/stat/grep/awk/find mantığıyla çözer."""
    from hy.motor.kontrol import Baglam
    web, kopya_k, kilitli_k = s["duzen"]
    v = s["metin"]
    sem = v["sembolik_a"]
    sembolik_chmod = ",".join(f"{k}={sem[i * 3:i * 3 + 3].replace('-', '')}" for i, k in enumerate("ugo"))
    oktal = _sh(f"touch .deneme && chmod {sembolik_chmod} .deneme && stat -c %a .deneme; rm -f .deneme", lab)
    sembol = _sh(f"touch .deneme && chmod {v['oktal_b']} .deneme && stat -c %A .deneme | cut -c2-; rm -f .deneme", lab)
    _sh(f"chmod 600 '{web}/{s['yedek']}'", lab)
    kilitli = _sh(f"ls {kilitli_k} 2>/dev/null", lab)
    bayrak = _sh(f"chmod u+x {kilitli_k} && cat {kilitli_k}/* | grep -o 'FLAG{{[^}}]*}}'", lab)
    kabuklu = _sh(f"grep -E '(bash|zsh)$' {kopya_k}/etc/passwd | cut -d: -f1", lab)
    arka = _sh(f"awk -F: '$3 == 0 && $1 != \"root\" {{print $1}}' {kopya_k}/etc/passwd", lab)
    standart = "|".join(p.rsplit("/", 1)[1].replace(".", "\\.") for p in STANDART_SUID)
    suid = _sh(f"grep -vE '/({standart})$' {kopya_k}/suid_listesi.txt", lab)
    secmeli = SEVIYE.gorevler[8].kontrol.cevabi_goster(Baglam(s, lab, 9))[0]
    return {1: oktal, 2: sembol, 3: "", 4: kilitli, 5: bayrak, 6: ",".join(kabuklu.split()), 7: arka, 8: suid,
            9: secmeli}


# ---------------------------------------------------------------- kontroller ve geri bildirim

def _yedek_izni(b) -> Sonuc:
    web = b.senaryo["duzen"][0]
    yol = b.lab / web / b.senaryo["yedek"]
    if not yol.exists():
        return Sonuc(False, "Dosya yerinde yok. Silmen değil, iznini değiştirmen gerekiyordu; `sifirla` ile lab'ı tazele.")
    mod = stat.S_IMODE(yol.stat().st_mode)
    if mod == 0o600:
        return Sonuc(True, f"`{sembolik(mod)}` (600): sadece sahibi okuyup yazabiliyor. Yedek ve anahtar dosyaları için doğru izin bu.")
    if mod & 0o077:
        return Sonuc(False, f"Şu an `{sembolik(mod)}` ({mod:o}): grup ya da diğerleri hâlâ bir şey yapabiliyor. "
                            "Sadece sahibin okuma+yazma izni kalmalı.", yakin=True)
    if mod == 0o700:
        return Sonuc(False, "Sahibe gereksiz bir çalıştırma (x) izni verdin; bir yedek dosyası program değildir. 600 yap.", yakin=True)
    return Sonuc(False, f"Şu an `{sembolik(mod)}` ({mod:o}). Sahibin hem okuyup hem yazabilmesi gerekiyor: r=4 + w=2.", yakin=True)


def _oktal_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    mod = b.senaryo["izin_a"]
    rakamlar = [(mod >> 6) & 7, (mod >> 3) & 7, mod & 7]
    ters = int("".join(str((d & 4 and 1) + (d & 2) + (d & 1 and 4)) for d in rakamlar))
    if n == ters:
        return "Ağırlıkları ters kullanmış olabilirsin: r=4, w=2, x=1."
    if n == int("".join(str(d) for d in reversed(rakamlar))):
        return "Rakamlar doğru ama sıra ters. Sıra her zaman: sahip, grup, diğerleri."
    return None


def _sembolik_hata(g, beklenen, b):
    if len(g.lstrip("-d")) != 9:
        return "Dokuz karakter yaz: sahip, grup, diğerleri için üçer harf (örn. `rwxr-x---`). Boş izin `-` ile gösterilir."
    return None


def _kabuklu_hata(g, beklenen, b):
    verilen = set(g.split())
    tuzak = b.senaryo["tuzak"]
    if tuzak in verilen:
        return (f"`{tuzak}` fazla: onun kabuğu `/usr/sbin/nologin`. `bash` kelimesi satırın başka bir yerinde "
                "(açıklama alanında) geçtiği için `grep` onu da yakaladı. Sadece son alana bak: "
                "`grep -E '(bash|zsh)$'` ya da `awk -F: '$7 ~ /(bash|zsh)$/'`.")
    if "root" not in verilen:
        return "root'u unutma: onun da giriş kabuğu bash."
    return None


def _arka_hata(g, beklenen, b):
    if g == "root":
        return "root'un UID'si zaten 0; bu normal. UID'si 0 olan başka bir hesap var."
    return None


def _suid_hata(g, beklenen, b):
    if g in {p.rsplit("/", 1)[1] for p in STANDART_SUID}:
        return f"`{g}` SUID'li olması beklenen standart bir program. Listede yeri olmayan birini ara."
    return None


ADIMLAR = [
    Adim("Kullanıcılar nerede yaşar?", """
Linux'ta her kullanıcı `/etc/passwd` dosyasında bir satırdır; iki nokta ile ayrılmış yedi alan:

```
kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
```

1. kullanıcı adı, 2. `x` (parola başka yerde), 3. **UID** (kullanıcı numarası; 0 her zaman root),
4. GID (ana grup), 5. açıklama, 6. ev dizini, 7. **giriş kabuğu**. Kendi sistemindekine bak:
""", komut="head -n 3 /etc/passwd", sonra="""
**Hacker gözüyle:** `/etc/passwd` herkesçe okunabilir, bu normaldir. Ama iki şeye bak:
giriş kabuğu `/bin/bash` (ya da zsh) olan kullanıcılar (gerçek insanlar) ve UID'si 0 olan
birden fazla kullanıcı (arka kapı belirtisi).
"""),
    Adim("Parola özetleri: /etc/shadow", """
Parola özetleri (hash) `/etc/shadow` dosyasında durur ve onu sadece root (ve `shadow` grubu)
okuyabilir. İznine bak:
""", komut="ls -l /etc/shadow", sonra="""
`/etc/shadow`'un herkesçe okunabilir olması ciddi bir yapılandırma hatasıdır: hash'leri alan
saldırgan onları kendi bilgisayarında, çevrimdışı kırmaya çalışabilir.
"""),
    Adim("İzinleri okumak", """
`ls -l` çıktısındaki ilk on karakter: 1. karakter tür (`-` dosya, `d` klasör, `l` kısayol),
sonra üçer karakterlik üç grup: **sahip** (user), **grup** (group), **diğerleri** (others).
`-a` eklersen nokta ile başlayan gizli dosyalar da görünür.
""", komut="ls -la <<web>>"),
    Adim("r, w, x: dosyada ve klasörde", """
Harfler dosyada ve klasörde farklı anlama gelir:

- **r**: dosyada içeriği okumak; klasörde içindekileri **listelemek**
- **w**: dosyada değiştirmek; klasörde içinde dosya oluşturmak ya da silmek
- **x**: dosyada program olarak çalıştırmak; klasörde **içine girmek** (`cd`) ve içindeki
  dosyalara erişmek

Laboratuvarındaki `<<kilitli_k>>` klasörünün iznine bak (`-d` klasörün içini değil kendisini gösterir):
""", komut="ls -ld <<kilitli_k>>", sonra="""
Sahipte `rw-` var ama `x` yok. Yani içini listeleyebilirsin ama içine giremezsin. Saha
görevinde bunu kendi elinle deneyeceksin.
"""),
    Adim("chmod: sembolik yazım", """
`chmod` izinleri değiştirir. Sembolik yazım okunaklıdır: kim (`u` sahip, `g` grup, `o`
diğerleri, `a` herkes), ne (`+` ver, `-` al), hangi izin (`r`, `w`, `x`).
""", komut="touch deneme.sh && chmod u+x deneme.sh && ls -l deneme.sh"),
    Adim("chmod: oktal (sayısal) yazım", """
Her izin bir sayıdır: **r=4, w=2, x=1**. Her grup için topla: `7`=rwx, `6`=rw-, `5`=r-x,
`4`=r--, `0`=---. Üç rakam sırasıyla sahip, grup, diğerleri: `755` = `rwxr-xr-x`,
`600` = `rw-------` (SSH özel anahtarları için zorunlu), `644` = `rw-r--r--`.
""", komut="chmod 754 deneme.sh && ls -l deneme.sh", sonra="""
7 = 4+2+1 (rwx), 5 = 4+1 (r-x), 4 = r--. **Dikkat:** internette bir şey çalışmayınca
`chmod 777` önerisiyle çok karşılaşırsın. Bu "herkes her şeyi yapabilsin" demektir ve bir
güvenlik açığıdır. Doğru çözüm, kimin hangi izne ihtiyacı olduğunu bulup sadece onu vermektir.
"""),
    Adim("chown ve sudo -l", """
`sudo chown ayse dosya` sahibi, `sudo chown ayse:muhasebe dosya` sahibi ve grubu değiştirir;
ikisi de root yetkisi ister. `sudo -l` ise "bu kullanıcı sudo ile neleri çalıştırabilir?"
sorusunu cevaplar (bu oyunda çalıştırmayacağız, çünkü parola ister).

**Hacker gözüyle:** `sudo -l`, düşük yetkiyle girilen bir sistemde çalıştırılan ilk üç
komuttan biridir. Bir kullanıcı sadece `sudo find` ya da `sudo vim` çalıştırabiliyorsa bile
bu çoğu zaman tam root demektir, çünkü bu programlar içeriden kabuk açmaya izin verir. Bu
hileleri **GTFOBins** adlı ücretsiz site kataloglar.
"""),
    Adim("SUID: sahibinin yetkisiyle çalışmak", """
Normalde bir program **senin** yetkinle çalışır. **SUID** bitli bir program ise dosyanın
**sahibinin** yetkisiyle çalışır. `passwd` böyledir: root'a ait olduğu için normal kullanıcı
kendi parolasını `/etc/shadow`'a yazabilir.
""", komut="ls -l /usr/bin/passwd", sonra="""
Sahip izinlerinde `x`'in yerinde `s` görüyorsun: bu SUID'dir.
"""),
    Adim("SUID avı", """
Sistemdeki SUID dosyalarını `find / -perm -4000 -type f 2>/dev/null` bulur. Hız için sadece
`/usr/bin` içinde arayalım:
""", komut="find /usr/bin -perm -4000 2>/dev/null", sonra="""
**Hacker gözüyle:** Listede `passwd`, `sudo`, `mount` gibi beklenen programlar olur. Dikkat
edilecek olanlar **beklenmeyenlerdir**: SUID'li bir `find`, `python`, `bash` ya da bir
geliştiricinin yazdığı özel bir program doğrudan root kabuğu demek olabilir. Savunmacı aynı
listeyi düzenli çıkarır ve yeni bir girdi belirince alarm verir.
"""),
]

GOREVLER = [
    Gorev("`<<sembolik_a>>` izninin oktal (sayısal) karşılığı nedir?",
          Sayi("oktal_a", sik_hatalar=_oktal_hata),
          ("Dokuz karakteri üçlü gruplara böl: sahip, grup, diğerleri.",
           "Her grupta r=4, w=2, x=1 değerlerini topla.",
           "Örnek: `rwx` = 4+2+1 = 7, `r-x` = 4+1 = 5, `---` = 0. Üç rakamı yan yana yaz."),
          puan=20, baslik="Harften sayıya"),
    Gorev("`<<oktal_b>>` izni hangi sembolik izne karşılık gelir? (dokuz karakter, örn. `rwxr-x---`)",
          Metin("sembolik_b", sik_hatalar=_sembolik_hata, bicim="rwxrwxrwx biçiminde"),
          ("Her rakam bir grubun izni: sırayla sahip, grup, diğerleri.",
           "Her rakamı 4 (r), 2 (w), 1 (x) toplamına ayır.",
           "Örnek: 6 = 4+2 = `rw-`, 4 = `r--`, 0 = `---`. İstersen dene: `touch x; chmod <<oktal_b>> x; ls -l x`"),
          puan=20, baslik="Sayıdan harfe"),
    Gorev("`<<web>>` klasöründe bir yedek dosyası (`<<yedek>>`) herkesin okuyabileceği izinlerle duruyor. "
          "İzinlerini **sadece sahibin okuyup yazabileceği** şekilde değiştir, sonra `cevap 3` yaz.",
          _Durum(_yedek_izni, "chmod 600 <<web>>/<<yedek>>"),
          ("Önce mevcut izne bak: `ls -la <<web>>`.",
           "Sahip: okuma+yazma (4+2). Grup ve diğerleri: hiçbir şey (0).",
           "`chmod 6?? <<web>>/<<yedek>>` — grup ve diğerleri için hangi rakam 'hiçbir izin' demek?"),
          puan=30, baslik="Yedeği kilitle"),
    Gorev("`<<kilitli_k>>` klasöründe **r** izni var ama **x** izni yok. `ls` ile içine bak: "
          "içindeki dosyanın adı ne? (Bir de `cd <<kilitli_k>>` dene ve ne olduğunu gör.)",
          Metin("kilitli_dosya", sadece_ad=True, bicim="dosya adı"),
          ("r izni klasörde 'listelemek' demek.",
           "`ls <<kilitli_k>>` adları gösterir (ayrıntılar için hata alabilirsin). `cd` ise reddedilir.",
           "`ls <<kilitli_k>>` çıktısındaki tek dosya adını yaz; `ls -l` soru işaretleri gösterse bile ad görünür."),
          puan=25, baslik="Görünüyor ama girilmiyor"),
    Gorev("Şimdi o dosyanın içindeki kasa kodunu (bayrak) oku. Klasör senin; gerekeni yapabilirsin.",
          Bayrak("bayrak"),
          ("`cat <<kilitli_k>>/...` neden 'Permission denied' veriyor? Hangi izin eksikti?",
           "Klasöre girmek ve içindeki dosyalara ulaşmak için klasörde **x** gerekir. Sahibi sensin: `chmod` ile ekleyebilirsin.",
           "`chmod u+x <<kilitli_k>>`, sonra `cat <<kilitli_k>>/<dosya adı>`."),
          puan=30, baslik="Kilidi aç"),
    Gorev("`<<kopya_k>>/etc/passwd` dosyasında giriş kabuğu **bash ya da zsh** olan kullanıcılar kimler? "
          "(virgülle ayır)",
          Kume("kabuklu", sik_hatalar=_kabuklu_hata, bicim="virgülle ayrılmış kullanıcı adları"),
          ("Giriş kabuğu her satırın 7. (son) alanı.",
           "`grep` ile bash/zsh geçen satırları bul, `cut -d: -f1` ile kullanıcı adını al. Ama `grep` satırın tamamına bakar!",
           "`grep -E '(bash|zsh)$' <<kopya_k>>/etc/passwd | cut -d: -f1` — `$` 'satır sonu' demek."),
          puan=35, baslik="Kabuğu olanlar"),
    Gorev("Aynı dosyada **root dışında** UID'si 0 olan bir hesap var: klasik arka kapı belirtisi. Adı ne?",
          Metin("arka_kapi", sik_hatalar=_arka_hata, bicim="kullanıcı adı"),
          ("UID 3. alan. 0 her zaman root demek; ikinci bir 0 olmamalı.",
           "`awk -F:` ile 3. alanı 0 olan satırları süz.",
           "`awk -F: '$3 == 0 {print $1}' <<kopya_k>>/etc/passwd` — root dışındaki ad."),
          puan=30, baslik="İkinci root"),
    Gorev("`<<kopya_k>>/suid_listesi.txt` sunucudaki SUID dosyalarının listesi. Orada olmaması gereken, "
          "**beklenmeyen** SUID'li program hangisi?",
          Metin("suid", sadece_ad=True, sik_hatalar=_suid_hata, bicim="program adı ya da yolu"),
          ("Eğitimdeki SUID avı adımında hangi programların listede olmasının normal olduğunu gördün.",
           "passwd, su, sudo, mount, umount, chsh, chfn, gpasswd, newgrp, pkexec, ssh-keysign... bunlar standart.",
           "`cat <<kopya_k>>/suid_listesi.txt` — standart listede olmayan, kabuk açabilecek ya da özel yazılmış programı bul."),
          puan=30, baslik="Beklenmeyen SUID"),
    Gorev("`<<kopya_k>>/sudo_l.txt` dosyasına göre <<sudo_kul>> kullanıcısının `(root) NOPASSWD: "
          "/usr/bin/<<sudo_prog>>` hakkı var. Bu ne anlama gelir?",
          Secmeli([
              ("Bu programı root olarak parolasız çalıştırır; kabuk açabildiği için pratikte root olur",
               "Doğru. find, vim, less, awk, tar, python gibi programlar içeriden komut ya da kabuk çalıştırabilir. "
               "GTFOBins bunları listeler; savunma tarafında sudo hakkı sadece gerçekten gereken komuta verilir."),
              ("Program yalnızca dosya okuyup yazdığı için zararsızdır; bu hak yetki yükseltmeye hiç yaramaz",
               "Bu programların çoğu içeriden kabuk açabilir. Root olarak çalışan bir kabuk, tam yetki demektir."),
              ("Program root adına başlar ama sudo onu hemen kullanıcının kendi yetkisine düşürür, risk yoktur",
               "sudo programı gerçekten root yetkisiyle çalıştırır; yetkiyi düşürmez. Bütün mesele de bu."),
              ("Bu satır, root kullanıcısının o programı kullanmasını yasaklayan bir kısıtlama kuralıdır",
               "Satır bir izin tanımıdır, yasak değil: kullanıcı bu programı root olarak çalıştırabilir."),
          ]),
          ("`(root)` kimin yetkisiyle, `NOPASSWD` parola sorulup sorulmayacağı demek.",
           "Bu program root olarak çalışırken içinden başka bir komut ya da kabuk başlatabilir mi?",
           "Evet: bu tür programlar kabuk açabildiği için kullanıcı pratikte root olur (GTFOBins)."),
          puan=25, baslik="sudo -l"),
]


SEVIYE = Seviye(
    kimlik="c01b05",
    cilt=1,
    bolum=5,
    baslik="Kullanıcılar, Gruplar ve İzinler",
    brifing="""
**<<musteri>>**, sunucusu **<<sunucu>>** için bir izin denetimi istedi. <<kisi>> dün akşam
sunucudan `/etc/passwd`, SUID listesi ve bir kullanıcının `sudo -l` çıktısını topladı; web
klasörünün bir kopyasını da ekledi.

Selin dosyayı uzatıyor: "Yetki yükseltme çoğu zaman yanlış ayarlanmış tek bir izni bulmaktan
ibarettir. Bu bölümü iyi anlarsan, ileride yapacağın işlerin yarısını anlamış olursun."

Mert gülüyor: "Bir de `chmod 777` gören olursa bana haber versin. Koleksiyon yapıyorum."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırgan bir sisteme düşük yetkiyle girdiğinde ilk baktığı yerler bu bölümdekilerdir:
`/etc/passwd`'de ikinci bir UID 0, `sudo -l`'de kabuk açabilen bir program, SUID listesinde
beklenmeyen bir girdi, herkesin okuyabildiği bir yedek. Savunma tarafının cevabı da aynı
yerde: en az yetki ilkesi (herkese sadece gerektiği kadar), `chmod 777` yerine doğru izin,
hassas dosyalar için 600 ve SUID listesinin düzenli karşılaştırılması.
""",
    gercek_hayat="""
- **PwnKit (CVE-2021-4034):** `pkexec`, çoğu Linux dağıtımında varsayılan olarak kurulu gelen
  SUID root bir programdır. 2022'de yayımlanan bu açık, yerel bir kullanıcının root olmasına
  izin veriyordu ve programın ilk sürümünden beri vardı. SUID'li tek bir programdaki hata,
  sistemdeki herkesi root yapabilir; SUID listesinin önemli olmasının sebebi bu.
- **SSH anahtar izinleri:** OpenSSH, özel anahtar dosyası başkalarınca okunabiliyorsa onu
  kullanmayı reddeder ve "UNPROTECTED PRIVATE KEY FILE" uyarısı verir. Bu yüzden `id_rsa`
  için `chmod 600` zorunludur.
- **GTFOBins:** sudo ya da SUID ile çalışan yaygın programların nasıl kabuk açabildiğini
  listeleyen açık bir katalogdur; hem pentester'lar hem de sudo kurallarını denetleyen
  yöneticiler tarafından kullanılır.
""",
    sure_hedef_dk=30,
)
