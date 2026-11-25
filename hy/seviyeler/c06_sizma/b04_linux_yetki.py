"""Cilt 6 · Bölüm 4 — Linux Yetki Yükseltme: Yanlış Yapılandırma Denetimi.

Beceri: düşük yetkili bir hesabın root'a çıkmasına yol açabilecek yanlış yapılandırmaları (sudo, SUID,
capabilities, yazılabilir cron betiği, yazılabilir PATH dizini) bir sistem kopyasında bulmak, nedenini anlamak
ve düzeltmek.

Kabuk açma yöntemi anlatılmaz; "bu neden bir kapı" sorusu kavramsal olarak yanıtlanır.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

VAKALAR = [
    {"kod": "pazarix", "host": "pzx-web01", "kul": "www-data", "servis": "nginx", "dizin": "bakim",
     "betik": "yedekle.sh", "betik2": "temizlik.sh", "pathdir": "/usr/local/yerel_bin", "log": "/var/log/nginx/error.log",
     "olay": "Web sitesinin hesabı bir saldırıda ele geçirilirse en fazla neye ulaşabileceğini bilmek istiyorlar."},
    {"kod": "kuzgun", "host": "kzg-depo", "kul": "depo-app", "servis": "depo-api", "dizin": "otomasyon",
     "betik": "sevkiyat_aktar.sh", "betik2": "log_dondur.sh", "pathdir": "/opt/araclar/bin", "log": "/var/log/depo/hata.log",
     "olay": "Depo uygulamasının hesabı sızma testinde root'a çıkabildi mi diye teyit istiyorlar."},
    {"kod": "paramix", "host": "pmx-api01", "kul": "api-svc", "servis": "paramix-api", "dizin": "scripts",
     "betik": "rapor_gonder.sh", "betik2": "senkron.sh", "pathdir": "/srv/betikler/bin", "log": "/var/log/paramix/api.log",
     "olay": "Ödeme API'sini çalıştıran hesabın yetkileri, denetimden önce gözden geçiriliyor."},
]
SUDO_RISKLI = ["find", "awk", "env", "tar"]
SUID_RISKLI = [("python3.11", "/usr/local/bin"), ("nmap", "/usr/local/bin"), ("vim.basic", "/usr/bin"), ("cp", "/usr/local/bin")]
CAP_RISKLI = ["perl", "ruby", "php8.2", "node"]
SUID_STANDART = ["passwd", "sudo", "su", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd", "pkexec"]


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    sudo_prog = rng.choice(SUDO_RISKLI)
    suid_prog, suid_dizin = rng.choice(SUID_RISKLI)
    cap_prog = rng.choice(CAP_RISKLI)
    gun = u.gun(rng)
    return {
        "vaka": f"{m['ad']} — {v['host']} yetki denetimi",
        "musteri": m, "v": v, "sudo_prog": sudo_prog, "suid_prog": suid_prog, "suid_dizin": suid_dizin,
        "cap_prog": cap_prog, "gun": gun,
        "brifing": f"""
Selin Aksoy raporu ekrana yansıtıyor: "**{m['ad']}**, **{v['host']}** sunucusunu bizden denetlemek istiyor. {v['olay']}
Elimizde sunucunun bir **kopyası** var: `sudo -l` çıktısı, SUID listesi, capabilities çıktısı, `/etc` klasörü
ve cron betikleri."

Mert gülerek ekliyor: "Linux'ta yetki yükselmesinin yüzde doksanı keşiftir. Saldırgan da senin bakacağın
yerlere bakar: `sudo`, SUID, cron, yazılabilir dizinler. Önce **sen** bak, ne bulursan kapat."
""",
        "metin": {"musteri": m["ad"], "host": v["host"], "kul": v["kul"], "betik": v["betik"], "pathdir": v["pathdir"]},
        "cevaplar": {
            "sudo": sudo_prog, "suid": suid_prog, "cap": cap_prog,
            "betik": [f"/opt/{v['dizin']}/{v['betik']}", f"opt/{v['dizin']}/{v['betik']}",
                      f"kopya/opt/{v['dizin']}/{v['betik']}", f"./kopya/opt/{v['dizin']}/{v['betik']}"],
            "pathdir": [v["pathdir"], v["pathdir"].lstrip("/"), "kopya" + v["pathdir"], "./kopya" + v["pathdir"]],
        },
    }


def _ls_satir(prog: str, dizin: str, rng_boyut: int) -> str:
    return f"-rwsr-xr-x 1 root root {rng_boyut} Jan 15  2026 {dizin}/{prog}"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = s["musteri"]
    k = lab / "kopya"
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} · {v['host']} sunucusunun denetim kopyası.\n"
          f"kopya/sudo_l.txt       : `sudo -l -U {v['kul']}` çıktısı\n"
          "kopya/suid_listesi.txt  : `find / -perm -4000 -ls` benzeri SUID listesi\n"
          "kopya/getcap.txt        : `getcap -r /` çıktısı\n"
          "kopya/etc/             : crontab ve sudoers.d\n"
          "kopya/opt/ ve diğerleri: betikler (gerçek izinleriyle)\n")
    # sudo
    sudoers = (
        f"# {v['kul']} için bakım yetkileri\n"
        f"{v['kul']} ALL=(root) NOPASSWD: /usr/bin/systemctl restart {v['servis']}\n"
        f"{v['kul']} ALL=(root) NOPASSWD: /usr/bin/{s['sudo_prog']}\n"
        f"{v['kul']} ALL=(root) NOPASSWD: /usr/bin/tail -n 50 {v['log']}\n"
    )
    u.yaz(k / "etc" / "sudoers.d" / f"90-{v['kul']}", sudoers, mod=0o440)
    u.yaz(lab / "kopya" / "sudo_l.txt",
          f"Matching Defaults entries for {v['kul']} on {v['host']}:\n"
          "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
          f"User {v['kul']} may run the following commands on {v['host']}:\n"
          f"    (root) NOPASSWD: /usr/bin/systemctl restart {v['servis']}\n"
          f"    (root) NOPASSWD: /usr/bin/{s['sudo_prog']}\n"
          f"    (root) NOPASSWD: /usr/bin/tail -n 50 {v['log']}\n")
    # SUID
    satirlar = []
    for i, ad in enumerate(SUID_STANDART[:8]):
        satirlar.append(_ls_satir(ad, "/usr/bin", 30000 + i * 7919))
    satirlar.append(_ls_satir(s["suid_prog"], s["suid_dizin"], 142000))
    satirlar.sort(key=lambda x: x.split()[-1])
    u.yaz(lab / "kopya" / "suid_listesi.txt", "\n".join(satirlar) + "\n")
    # capabilities
    u.yaz(lab / "kopya" / "getcap.txt",
          "/usr/bin/ping cap_net_raw=ep\n"
          "/usr/bin/mtr-packet cap_net_raw=ep\n"
          f"/usr/bin/{s['cap_prog']} cap_setuid=ep\n")
    # cron ve betikler
    d, b1, b2 = v["dizin"], v["betik"], v["betik2"]
    u.yaz(k / "etc" / "crontab",
          "SHELL=/bin/sh\n"
          f"PATH={v['pathdir']}:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
          "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
          f"*/10 *  * * *   root    /opt/{d}/{b1}\n"
          f"30 2    * * *   root    /opt/{d}/{b2}\n", mod=0o644)
    u.yaz(k / "opt" / d / b1, "#!/bin/bash\ntar czf /var/backups/uygulama.tgz /srv/uygulama\ngzip -t /var/backups/uygulama.tgz\n", mod=0o777)
    u.yaz(k / "opt" / d / b2, "#!/bin/bash\nfind /tmp -mtime +7 -delete\n", mod=0o755)
    p = k / v["pathdir"].lstrip("/")
    p.mkdir(parents=True, exist_ok=True)
    u.yaz(p / "OKUBENI.txt", "Yerel yönetim betikleri bu klasörde durur.\n", mod=0o644)
    os.chmod(p, 0o777)


def _sudoers_duzeldi(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = b.lab / "kopya" / "etc" / "sudoers.d" / f"90-{v['kul']}"
    try:
        satirlar = [x.strip() for x in yol.read_text(encoding="utf-8").splitlines()
                    if x.strip() and not x.strip().startswith("#")]
    except OSError:
        return Sonuc(False, "sudoers dosyası yok. Dosyayı komple silmek, gerekli yetkileri de götürür; "
                            "sadece riskli satırı çıkar (`sifirla` ile geri getirebilirsin).")
    risk = b.senaryo["sudo_prog"]
    for x in satirlar:
        if "NOPASSWD" in x and (x.endswith(f"/{risk}") or x.endswith(" ALL")):
            return Sonuc(False, f"`{risk}` için parolasız root yetkisi hâlâ duruyor. O satırı çıkar.")
    if not any("systemctl restart" in x for x in satirlar):
        return Sonuc(False, "Servisi yeniden başlatma yetkisini de silmişsin; uygulama bakımı bozulur. "
                            "Sadece riskli satırı kaldır.", yakin=True)
    if not any("tail -n 50" in x for x in satirlar):
        return Sonuc(False, "Log okuma satırı da gitmiş; yalnızca riskli satırı kaldırmalıydın.", yakin=True)
    return Sonuc(True, "Riskli satır gitti, işe yarayan sınırlı yetkiler kaldı. Gerçek sunucuda dosyayı "
                       "`visudo -c` ile doğrulardın; bozuk bir sudoers yöneticileri dışarıda bırakabilir.")


def _betik_duzeldi(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = b.lab / "kopya" / "opt" / v["dizin"] / v["betik"]
    if not yol.exists():
        return Sonuc(False, "Betik silinmiş! Silmek yerine iznini düzelt (`sifirla` ile geri getirebilirsin).")
    mod = stat.S_IMODE(yol.stat().st_mode)
    if mod & 0o002:
        return Sonuc(False, f"Betik hâlâ herkes tarafından yazılabilir (izin: {mod:o}).")
    if mod & 0o020:
        return Sonuc(False, f"Başkalarının yazma izni gitti ama grup hâlâ yazabiliyor (izin: {mod:o}). "
                            "Root'un çalıştırdığı betiği yalnız sahibi yazabilmeli.", yakin=True)
    if not mod & 0o100:
        return Sonuc(False, "Yazma iznini kapatmışsın ama çalıştırma iznini de kaldırmışsın; cron işi bozulur.", yakin=True)
    return Sonuc(True, f"Yeni izin: {mod:o}. Gerçek sunucuda sahibini de `chown root:root` yapardın.")


def _pathdir_duzeldi(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = b.lab / "kopya" / v["pathdir"].lstrip("/")
    if not yol.is_dir():
        return Sonuc(False, "Dizin silinmiş! Silmek yerine iznini düzelt (`sifirla` ile geri getirebilirsin).")
    mod = stat.S_IMODE(yol.stat().st_mode)
    if mod & 0o002:
        return Sonuc(False, f"Dizin hâlâ herkes tarafından yazılabilir (izin: {mod:o}).")
    if mod & 0o020:
        return Sonuc(False, f"Dizini grup hâlâ yazabiliyor (izin: {mod:o}). Root cron'unun PATH'indeki bir dizini "
                            "yalnız sahibi yazabilmeli.", yakin=True)
    if not mod & 0o100:
        return Sonuc(False, "Dizin için arama (x) izni kalmamış; içindeki betikler bulunamaz.", yakin=True)
    return Sonuc(True, f"Yeni izin: {mod:o}. Bu dizinin PATH'te sistem dizinlerinden önce durması da ayrıca "
                       "gözden geçirilmeli; mümkünse PATH'ten tamamen çıkar.")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    v = s["v"]
    sudo = sh("x=$(awk '/NOPASSWD/ && !/systemctl/ && !/tail/ {print $NF}' kopya/sudo_l.txt); echo ${x##*/}", lab)
    suid = sh("awk '{print $NF}' kopya/suid_listesi.txt | grep -v -E '/usr/bin/(passwd|sudo|su|mount|umount|chsh|chfn|newgrp|gpasswd|pkexec)$'", lab)
    cap = sh("grep cap_setuid kopya/getcap.txt | awk '{print $1}'", lab)
    betik = sh("find kopya -type f -perm -o+w | grep '/opt/'", lab)
    betik = betik[len("kopya"):]
    pathdir = sh("find kopya -type d -perm -o+w", lab)[len("kopya"):]
    sec = SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]
    sh(f"sed -i '/NOPASSWD: \\/usr\\/bin\\/{s['sudo_prog']}$/d' kopya/etc/sudoers.d/90-{v['kul']}", lab)
    sh(f"chmod 755 kopya{betik}; chmod 755 kopya{pathdir}", lab)
    return {1: sudo, 2: suid, 3: cap, 4: betik, 5: pathdir, 6: sec, 7: "", 8: "", 9: ""}


def _sudo_hata(g, beklenen, b):
    if g in ("systemctl", "tail"):
        return ("Bu satır tek bir alt komuta kilitli (`restart <servis>` ya da belirli bir log dosyası): yetki "
                "dar. Ben **sınırsız** çalıştırılabilen bir programı soruyorum.")
    return None


def _suid_hata(g, beklenen, b):
    if g in SUID_STANDART:
        return f"`{g}` her Linux'ta SUID taşır: kullanıcı parolasını değiştirme gibi işler için gerekli. Olağan dışı olanı ara."
    return None


ADIMLAR = [
    Adim("Yetki yükseltme = yanlış yapılandırma", """
Bir saldırgan çoğunlukla **düşük yetkili bir hesapla** (örneğin web uygulamasının hesabı) içeri girer. Sonra
root olmak ister. Cilt 6'nın temel fikri şu: bunun **büyük çoğunluğu zafiyet değil, yanlış yapılandırmadır**.
Yöneticinin kolaylık olsun diye verdiği bir sudo izni, `chmod 777` yapılmış bir betik, gereksiz bir SUID...

Savunmacı olarak senin işin, saldırganın bakacağı yerlere önce bakmak ve **en az yetki ilkesine** (herkese,
her servise yalnızca ihtiyacı olan yetkiyi ver) uymayanları düzeltmektir. Lab:
""", komut="cat OKUBENI.txt"),
    Adim("sudo -l: neyi root olarak çalıştırabilirim?", """
`sudo -l` bir kullanıcının `sudo` ile **hangi komutları** çalıştırabileceğini gösterir. `NOPASSWD` parola
sorulmadan demektir. Bu çıktı, hesabın ele geçirilmesi durumunda **saldırgana verilen yetkinin listesidir**.
""", komut="cat kopya/sudo_l.txt", sonra="""
Üç satırdan ikisi **dar**: belirli bir servisi yeniden başlatmak ve belirli bir log dosyasının son 50 satırını
okumak. Üçüncü satır ise bir programa **argümansız** izin veriyor. Argümansız izin demek, programın **tüm
yeteneklerini** root yetkisiyle kullanabilmek demektir.

**Hacker gözüyle:** GTFOBins adında herkese açık bir katalog var: hangi standart Linux programlarının
yüksek yetkiyle verildiğinde kötüye kullanılabileceğini listeler. Savunmacı için bu, "sudo ile hangi programları
**vermemeliyim**?" kontrol listesidir. Burada bir yöntem değil, **neden tehlikeli** olduğunu bilmen yeterli.
"""),
    Adim("SUID: sahibinin yetkisiyle çalışan dosya", """
Bir dosyanın izinlerinde **`s`** harfi varsa (örneğin `-rwsr-xr-x`), o dosya **sahibinin yetkisiyle** çalışır.
`passwd` bunun meşru örneğidir: sıradan kullanıcı, root'a ait `/etc/shadow`'a yazabilen bu program sayesinde
kendi parolasını değiştirir. Aşağıda `find / -perm -4000` benzeri bir listenin kopyası var:
""", komut="cat kopya/suid_listesi.txt", sonra="""
Standart Linux'ta bu listede `passwd`, `sudo`, `su`, `mount`, `umount`, `chsh`, `chfn`, `newgrp`, `gpasswd`,
`pkexec` gibi birkaç tanıdık ad olur. **Listede olmaması gereken** bir tane var: özellikle `/usr/local/bin`
gibi sonradan kurulan yerlerdeki, kabuk ya da betik çalıştırabilen programlar şüphelidir.
"""),
    Adim("Capabilities: parçalara bölünmüş root", """
Linux root yetkisini küçük parçalara böler: **capabilities**. `cap_net_raw` ham ağ paketi gönderme, `cap_setuid`
ise bir sürecin kullanıcı kimliğini değiştirebilmesi demektir. Bir programa bu yetki verilebilir
(`getcap -r /` ile görülür).
""", komut="cat kopya/getcap.txt", sonra="""
`ping` için `cap_net_raw` meşru: ağ paketi göndermek ister. `cap_setuid` ise kullanıcı kimliğini değiştirebilmek
demektir; bir **yorumlayıcı programa** (betik dili çalıştıran program) verilirse, onu çalıştıran herkes
kendisini istediği kullanıcı olarak çalıştırabilir. Tehlikesi SUID root'a eşdeğerdir.
"""),
    Adim("Cron: root'un zamanlanmış işleri", """
`/etc/crontab` root'un zamanlayıcısıdır. Önce içine bak:
""", komut="cat kopya/etc/crontab", sonra="""
Bu betiklerden biri her **10 dakikada** root olarak çalışıyor. Root'un çalıştırdığı bir dosyayı **başkası
değiştirebiliyorsa**, eklediği her satır bir sonraki çalışmada root olarak yürür. Betiğin kendisinin izinleri
bu yüzden bir yetki sorusudur.
"""),
    Adim("Yazılabilir dosya aramak", """
İzin bitleriyle arama `find` ile yapılır: `-perm -o+w` "başkaları yazabilir" demektir. Önce `/etc`
altındaki dosyalara bak:
""", komut="find kopya/etc -type f -perm -o+w", sonra="""
`/etc` içinde herkesin yazabildiği bir dosya yok; çıktı boş. Ama betikler `/opt` altında. Aramayı genişletmek
senin işin. **Dizinler** için de aynısı geçerli: `-type d -perm -o+w`.
"""),
    Adim("PATH: komut nerede aranır?", """
Bir betik `tar` gibi bir komutu **tam yol vermeden** çağırırsa, sistem komutu `PATH` listesindeki dizinlerde
**soldan sağa** arar; ilk bulduğunu çalıştırır. Crontab'ın en üstünde kendi `PATH` satırı vardır:
""", komut="grep PATH kopya/etc/crontab", sonra="""
Listenin **en başındaki** dizine dikkat: orası standart sistem dizinlerinden **önce** aranıyor. Bu dizine
herkes yazabiliyorsa, root'un çağırdığı bir komutun yerine kendi dosyasını koyabilir. Bu yüzden root'un PATH'indeki
her dizin yalnızca root'a ait ve yalnızca root'un yazabildiği bir yer olmalı.
"""),
    Adim("Düzeltme: en az yetki", """
Bu bölümde bulduğun her bulgunun düzeltmesi aynı ilkedir:

- sudo'da **argümansız** program verme; gerekliyse belirli bir komut ve argümanla sınırla.
- Gereksiz SUID bitini kaldır (`chmod u-s`).
- Yorumlayıcılara `cap_setuid` gibi yetkiler verme (`setcap -r`).
- Root'un çalıştırdığı betik ve dizinleri yalnız root yazabilsin (`chmod 755`, `chown root:root`).
- Root'un PATH'ine yazılabilir dizin koyma.

Bu çıktılar bir kopya olduğu için sudoers ve izinleri gerçekten düzenleyebilirsin. Sudoers dosyasına bak:
""", komut="ls -l kopya/etc/sudoers.d"),
]

GOREVLER = [
    Gorev("`kopya/sudo_l.txt` içinde **parolasız root olarak sınırsız** çalıştırılabilen, yani yalnızca "
          "tek bir alt komuta kilitlenmemiş program hangisi? (Program adını yaz, örn. `cat`.)",
          Metin("sudo", sadece_ad=True, sik_hatalar=_sudo_hata, bicim="program adı"),
          ("Çıktıda üç `NOPASSWD` satırı var; ikisi argümanlarla sınırlanmış.",
           "Argümanı olmayan satır, programı her seçenekle çalıştırmaya izin verir.",
           "`grep NOPASSWD kopya/sudo_l.txt` ve sonunda argüman olmayan satırı seç."),
          puan=25, baslik="Riskli sudo"),
    Gorev("`kopya/suid_listesi.txt` içinde **olmaması gereken** SUID program hangisi? (Standart Linux "
          "SUID programları: passwd, sudo, su, mount, umount, chsh, chfn, newgrp, gpasswd, pkexec.)",
          Metin("suid", sadece_ad=True, sik_hatalar=_suid_hata, bicim="program adı"),
          ("Her satır bir SUID dosyası; tanıdık olanlar standart.",
           "Standart olmayan ad, genelde sonradan kurulan bir dizinde (örneğin `/usr/local/bin`) bulunur.",
           "`awk '{print $NF}' kopya/suid_listesi.txt` yolları verir; standart olmayanı seç."),
          puan=25, baslik="Şüpheli SUID"),
    Gorev("`kopya/getcap.txt` içinde **kullanıcı kimliği değiştirme** yetkisi (`cap_setuid`) verilmiş "
          "program hangisi?",
          Metin("cap", sadece_ad=True, bicim="program adı"),
          ("Capabilities çıktısı `yol yetki=ep` biçiminde.",
           "`cap_net_raw` ping içindir; farklı bir yetki arıyoruz.",
           "`grep cap_setuid kopya/getcap.txt`"),
          puan=25, baslik="Riskli capability"),
    Gorev("`kopya/etc/crontab` içinde root'un çalıştırdığı betiklerden hangisi **herkes tarafından "
          "yazılabilir?** (Sunucudaki yolunu yaz, örn. /opt/x/y.sh)",
          Metin("betik", bicim="dosya yolu"),
          ("İki şeyi birleştir: cron'daki root betikleri ve herkese yazma izni olan dosyalar.",
           "`find kopya -type f -perm -o+w` yazılabilir dosyaları bulur; crontab'da aynı yol geçiyor mu bak.",
           "Çıktıdaki yolun başındaki `kopya` kısmını at; cevabın sunucudaki yoldur."),
          puan=25, baslik="Yazılabilir cron betiği"),
    Gorev("Crontab'daki `PATH=` satırının **en başındaki dizin herkes tarafından yazılabilir**. "
          "O dizinin sunucudaki yolu nedir?",
          Metin("pathdir", bicim="dizin yolu"),
          ("`grep PATH kopya/etc/crontab` listeyi gösterir; ilk dizine bak.",
           "Aynı dizin için `find kopya -type d -perm -o+w` de sonuç verir.",
           "`kopya` önekini at: cevabın sunucudaki yoldur."),
          puan=25, baslik="Yazılabilir PATH dizini"),
    Gorev("Bir kullanıcıya bir programı `sudo` ile **argümansız, parolasız** vermek neden tehlikelidir?",
          Secmeli([
              ("Programın komut çalıştırma ve dosya yazma yetenekleri root olarak kullanılabilir",
               "Doğru. Güvenli görünen birçok araç, içinden komut çalıştırabilir ya da dosya değiştirebilir; root'la çalışınca bu yeteneklerin tamamı root olur."),
              ("Program çalışırken diske çok fazla yazacağı için sunucu belirgin biçimde yavaşlar",
               "Performans burada konu değil; sorun programın yeteneklerinin root yetkisiyle kullanılması."),
              ("sudo, parolasız çalıştırılan komutları günlüğe yazmaz ve olay kaydı tutulamaz",
               "sudo bu kullanımı da günlüğe yazar. Tehlike günlük yokluğu değil yetkinin genişliği."),
              ("Program güncellenemez hale gelir, çünkü sudo ile verilen paketler kilitlenir",
               "sudo paket güncellemesini kilitlemez; bu seçenek yanlış bir kavram."),
          ]),
          ("Güvenli görünen bir program neler yapabilir? Sadece asıl işini mi?",
           "Birçok araç, ek özellik olarak başka bir programı çalıştırabilir ya da dosya yazabilir.",
           "Yetki programın kendisine değil, tüm yeteneklerine verilmiş olur."),
          puan=20, baslik="Neden tehlikeli"),
    Gorev("`kopya/etc/sudoers.d/` altındaki dosyadan **riskli satırı** çıkar; ama servisi yeniden başlatma "
          "ve log okuma satırlarını bozma. Bitince `cevap 7` yaz.",
          Durum(_sudoers_duzeldi, "riskli programın NOPASSWD satırını sil (sed -i '/riskli/d' ...)"),
          ("Dosyada üç yetki satırı var. Hangisi gereğinden geniş?",
           "Yalnızca o satırı sil; `sed -i` ile satıra özgü bir kalıp kullanabilirsin.",
           "`sed -i '/NOPASSWD: \\/usr\\/bin\\/<program>$/d' kopya/etc/sudoers.d/<dosya>`"),
          puan=30, baslik="sudoers düzelt"),
    Gorev("Root cron'unun çalıştırdığı **herkesçe yazılabilir betiğin** iznini düzelt: yalnız sahibi "
          "yazabilsin, çalıştırma izni kalsın. Bitince `cevap 8` yaz.",
          Durum(_betik_duzeldi, "chmod 755 kopya<betik yolu>"),
          ("Yazma iznini başkalarından ve gruptan almak için `chmod` kullan.",
           "Sembolik: `chmod o-w,g-w <dosya>`; oktal: `chmod 755 <dosya>`.",
           "`chmod 755 kopya` + dördüncü görevdeki yol."),
          puan=25, baslik="Betiği kapat"),
    Gorev("Root cron'unun `PATH`'indeki **yazılabilir dizinin** iznini düzelt: yalnız sahibi yazabilsin, "
          "girilebilir kalsın. Bitince `cevap 9` yaz.",
          Durum(_pathdir_duzeldi, "chmod 755 kopya<dizin yolu>"),
          ("Dizinlerde `x` izni, içine girebilmek demektir.",
           "`chmod o-w,g-w <dizin>` ya da `chmod 755 <dizin>`",
           "`chmod 755 kopya` + beşinci görevdeki yol."),
          puan=25, baslik="PATH dizinini kapat"),
]


def _kapanis():
    return """
Saldırganın gözüyle: düşük yetkili hesaptan root'a çıkış çoğunlukla sıfır-gün değildir, yöneticinin
"kolay olsun" diye bıraktığı bir kapıdır: sudo, SUID, capability, yazılabilir cron betiği ya da PATH dizini.
Savunmanın gözüyle: aynı beş yere her denetimde bak, hepsi tek ilkeyle kapanır: **en az yetki**. Bir hesap
ele geçirilirse en fazla neye ulaşabileceği, o hesaba verdiğin yetkilerle sınırlıdır. Uygulamalı pratiği
**kendi laboratuvarında** yap: Cilt 9'da Kali'nde kuracağın savunmasız hedefler.
"""


SEVIYE = Seviye(
    kimlik="c06b04",
    cilt=6,
    bolum=4,
    baslik="Linux Yetki Yükseltme: Yanlış Yapılandırma Denetimi",
    brifing="""
**<<musteri>>**'nin sunucusu **<<host>>** için bir yetki denetimi var. Selin: "`<<kul>>` hesabı
ele geçirilirse root'a giden kapıları bul ve kapat."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **GTFOBins:** SUID ya da sudo ile verilmiş yaygın programların kötüye kullanılabilme biçimlerini
  listeleyen, kamuya açık bir projedir. Hem saldırganlar hem denetçiler bu listeyi kullanır; sızma
  testi raporlarında yanlış verilmiş sudo ve SUID en sık bulgulardandır.
- **Çekirdek açıkları da var:** Örneğin Dirty COW (2016) bir çekirdek zafiyetiydi. Ama pek çok sızma
  testinde yetki yükseltme kapısı yanlış yapılandırmadır; çünkü yama yönetimi kadar yapılandırma
  denetimi de ihmal edilir.
- **Tespit ve önleme:** `auditd` ile sudoers, crontab ve izin değişikliklerini izlemek; AIDE gibi
  dosya bütünlüğü araçlarıyla kritik betik ve dizin izinlerinin değişimini fark etmek; Lynis gibi
  denetim araçlarını periyodik çalıştırmak; sudoers'da argümansız program vermemek.
""",
    sure_hedef_dk=30,
)
