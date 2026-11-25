"""Olay Masası — İzin ve Cron Denetimi.

Her vakada başka bir müşterinin sunucu kopyası gelir. Oyuncu Cilt 1'de öğrendiği find,
izin ve cron bilgisiyle yetki yükseltme kapılarını bulur ve birini kapatır.
"""
from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

MESRU_SUID = ["passwd", "sudo", "su", "mount", "umount", "chsh", "chfn", "newgrp", "gpasswd"]
# GTFOBins'te SUID ile kabuk açabildiği bilinen programlar
TEHLIKELI_SUID = ["find", "vim.basic", "python3", "env", "bash", "less", "tar", "cp", "awk", "nano"]
BETIK_ADLARI = ["yedekle.sh", "temizlik.sh", "rapor_gonder.sh", "log_dondur.sh", "senkron.sh"]
DIZIN_ADLARI = ["bakim", "scripts", "araclar", "otomasyon", "gorevler"]
ARKA_KAPI = ["sysbackup", "toor", "svc_update", "maint", "helpdesk2", "ops_admin"]
SIKLIK = [("*/5 * * * *", "her 5 dakikada"), ("*/10 * * * *", "her 10 dakikada"),
          ("0 * * * *", "her saat başı"), ("*/2 * * * *", "her 2 dakikada")]


def uret(rng):
    m = musteri_sec(rng)
    dizinler = rng.sample(DIZIN_ADLARI, 2)
    betikler = rng.sample(BETIK_ADLARI, 3)
    acik_betik = f"/opt/{dizinler[0]}/{betikler[0]}"
    sik, sik_metin = rng.choice(SIKLIK)
    kullanicilar = u.isimler(rng, 4)
    arka_kapi = rng.choice(ARKA_KAPI)
    tehlikeli = rng.choice(TEHLIKELI_SUID)
    yazilabilir_anahtar = rng.choice(kullanicilar[:3])
    return {
        "vaka": f"{m['ad']} — {m['sunucu']} yetki denetimi",
        "musteri": m,
        "dizinler": dizinler,
        "betikler": betikler,
        "sik": sik,
        "kullanicilar": kullanicilar,
        "metin": {"musteri": m["ad"], "sunucu": m["sunucu"], "sektor": m["sektor"], "siklik": sik_metin},
        "cevaplar": {
            "betik": [acik_betik, acik_betik.lstrip("/"), "kopya" + acik_betik, "./kopya" + acik_betik],
            "arka_kapi": arka_kapi,
            "suid": tehlikeli,
            "anahtar": yazilabilir_anahtar,
        },
        "_acik_betik": acik_betik,
    }


def yaz(lab: Path, s: dict) -> None:
    k = lab / "kopya"
    c = s["cevaplar"]
    kul = s["kullanicilar"]
    passwd = [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "sshd:x:110:65534::/run/sshd:/usr/sbin/nologin",
    ]
    for i, ad in enumerate(kul):
        passwd.append(f"{ad}:x:{1001 + i}:{1001 + i}:{ad.capitalize()}:/home/{ad}:/bin/bash")
    # Arka kapı hesabı listenin ortasına gizlenir
    passwd.insert(len(passwd) // 2 + 1, f"{c['arka_kapi']}:x:0:0::/var/backups:/bin/bash")
    u.yaz(k / "etc" / "passwd", "\n".join(passwd) + "\n", mod=0o644)

    acik = s["_acik_betik"]
    d0, d1 = s["dizinler"]
    b0, b1, b2 = s["betikler"]
    u.yaz(k / "etc" / "crontab",
          "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
          "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
          f"{s['sik']}   root    {acik}\n"
          f"30 2    * * *   root    /opt/{d1}/{b1}\n", mod=0o644)
    u.yaz(k / "etc" / "cron.d" / "rapor", f"0 8 * * 1  {kul[0]}  /opt/{d1}/{b2}\n", mod=0o644)
    u.yaz(k / acik.lstrip("/"), "#!/bin/bash\ntar czf /var/backups/web.tgz /var/www\n", mod=0o777)
    u.yaz(k / "opt" / d1 / b1, "#!/bin/bash\nfind /tmp -mtime +7 -delete\n", mod=0o755)
    u.yaz(k / "opt" / d1 / b2, "#!/bin/bash\necho rapor\n", mod=0o755)

    for ad in MESRU_SUID[:6]:
        u.yaz(k / "usr" / "bin" / ad, "#!/bin/sh\n# yer tutucu\n", mod=0o4755)
    u.yaz(k / "usr" / "local" / "bin" / c["suid"], "#!/bin/sh\n# yer tutucu\n", mod=0o4755)
    for ad in ("ls", "cat", "grep"):
        u.yaz(k / "usr" / "bin" / ad, "#!/bin/sh\n# yer tutucu\n", mod=0o755)

    for ad in kul[:3]:
        mod = 0o666 if ad == c["anahtar"] else 0o600
        u.yaz(k / "home" / ad / ".ssh" / "authorized_keys",
              f"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA{ad.upper()}ORNEK {ad}@laptop\n", mod=mod)
        os.chmod(k / "home" / ad / ".ssh", 0o700)


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _betik_duzeldi(b) -> Sonuc:
    yol = b.lab / "kopya" / b.senaryo["_acik_betik"].lstrip("/")
    if not yol.exists():
        return Sonuc(False, "Betik silinmiş! Silmek yerine iznini düzelt (`sifirla` ile geri getirebilirsin).")
    mod = stat.S_IMODE(yol.stat().st_mode)
    if mod & 0o002:
        return Sonuc(False, f"Betik hâlâ herkes tarafından yazılabilir (izin: {mod:o}).")
    if mod & 0o020:
        return Sonuc(False, f"Başkalarının yazma izni gitti ama grup hâlâ yazabiliyor (izin: {mod:o}). "
                            "Root'un çalıştırdığı bir betiği sadece sahibi yazabilmeli.", yakin=True)
    if not mod & 0o100:
        return Sonuc(False, "Yazma iznini kapattın ama çalıştırma iznini de kaldırmışsın; cron işi bozulur.",
                     yakin=True)
    return Sonuc(True, f"Yeni izin: {mod:o}. Gerçek sunucuda sahibini de `chown root:root` yapardın.")


def coz(lab: Path, s: dict) -> dict:
    yazilabilir = _sh("find kopya -type f -perm -o+w", lab).splitlines()
    cron = _sh("cat kopya/etc/crontab kopya/etc/cron.d/*", lab)
    betik = next(y[len("kopya"):] for y in yazilabilir if y[len("kopya"):] in cron)
    arka = _sh("awk -F: '$3==0 && $1!=\"root\" {print $1}' kopya/etc/passwd", lab)
    suidler = _sh("find kopya -type f -perm -4000", lab).splitlines()
    suid = next(Path(x).name for x in suidler if Path(x).name not in MESRU_SUID)
    anahtar = _sh("find kopya/home -name authorized_keys -perm -o+w", lab).split("/")[2]
    _sh(f"chmod o-w,g-w kopya{betik}", lab)
    from hy.motor.kontrol import Baglam
    secim = SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]
    return {1: betik, 2: arka, 3: suid, 4: anahtar, 5: "", 6: secim}


GOREVLER = [
    Gorev("`kopya/` altındaki sunucuda root'un <<siklik>> çalıştırdığı ve **herkesin yazabildiği** "
          "betiğin yolu ne? (sunucudaki haliyle, örn. /opt/x/y.sh)",
          Metin("betik", bicim="dosya yolu"),
          ("İki şeyi birleştir: cron'da root'un çalıştırdığı betikler ve herkese yazma izni olan dosyalar.",
           "`cat kopya/etc/crontab` ile root satırlarına bak; `find kopya -type f -perm -o+w` ile yazılabilir dosyaları bul.",
           "find çıktısındaki yolun başındaki `kopya` kısmını at; crontab'da aynı yol geçiyor mu bak."),
          puan=25, baslik="Açık cron"),
    Gorev("`passwd` dosyasında root olmadığı halde **UID'i 0** olan (yani root yetkili) hesap hangisi?",
          Metin("arka_kapi", bicim="kullanıcı adı"),
          ("passwd satırı `ad:x:UID:GID:...` biçiminde. 3. alan UID.",
           "`awk -F:` ile alanlara böl, 3. alanı 0 olanları yazdır.",
           "`awk -F: '$3==0 {print $1}' kopya/etc/passwd` — root dışındaki isim cevabın."),
          puan=25, baslik="Arka kapı hesap"),
    Gorev("SUID biti taşıyan programlardan hangisi orada olmamalı? (GTFOBins'te kabuk açtığı bilinen)",
          Metin("suid", sadece_ad=True, bicim="program adı"),
          ("SUID'li dosyalar `find` ile izin bitinden bulunur.",
           "`find kopya -type f -perm -4000` hepsini listeler; passwd, sudo, su, mount gibileri normaldir.",
           "Listede normal olmayan, kabuk açabilen (dosya bulan, düzenleyen, betik çalıştıran) bir araç var."),
          puan=25, baslik="Şüpheli SUID"),
    Gorev("Hangi kullanıcının `authorized_keys` dosyası **başkaları tarafından yazılabilir**? "
          "(saldırgan kendi anahtarını ekleyip o kullanıcı olarak girebilir)",
          Metin("anahtar", bicim="kullanıcı adı"),
          ("SSH anahtar dosyaları `home/<kullanıcı>/.ssh/` altında.",
           "`ls -la kopya/home/*/.ssh/` ya da `find kopya/home -name authorized_keys -perm -o+w`",
           "İzni `-rw-rw-rw-` olan dosyanın yolundaki kullanıcı adı cevabın."),
          puan=25, baslik="SSH anahtarı"),
    Gorev("İlk bulgudaki betiğin iznini düzelt: sadece sahibi yazabilsin, çalıştırma izni kalsın. "
          "Bitince `cevap 5` yaz.",
          Durum(_betik_duzeldi, "chmod 755 kopya<betik yolu>  (ya da chmod o-w,g-w)"),
          ("Yazma iznini başkalarından (ve gruptan) almak için chmod kullanılır.",
           "Sembolik yol: `chmod o-w,g-w <dosya>`; oktal yol: `chmod 755 <dosya>`.",
           "`chmod 755 kopya` + birinci görevdeki yol."),
          puan=30, baslik="Kapıyı kapat"),
    Gorev("Root cron'unda çalışan bir betiğin herkesçe yazılabilir olması neden kritik?",
          Secmeli([
              ("Herhangi bir kullanıcı betiğe satır ekler; cron onu birkaç dakika içinde root olarak çalıştırır",
               "Doğru. Saldırganın yapması gereken tek şey beklemek: eklediği komut root yetkisiyle çalışır."),
              ("Betik herkese açık olduğu için içindeki yedekleme yolları dışarıdan okunabilir hale gelir",
               "Okunabilirlik ayrı bir sorun; buradaki asıl tehlike yazılabilirlik ve root olarak çalışması."),
              ("Cron, izinleri bozuk betikleri çalıştırmayı reddeder ve yedekler alınamaz hale gelir",
               "Cron izinlere bu şekilde bakmaz; betiği olduğu gibi çalıştırır. Tehlike de tam bu."),
              ("Disk dolabilir, çünkü herkes betiğe büyük dosyalar yazıp sunucuyu yavaşlatabilir",
               "Mümkün ama ikincil. Asıl risk yetki yükseltmedir."),
          ]),
          ("Betiği kim çalıştırıyor, kim değiştirebiliyor?",
           "Root'un çalıştırdığı bir dosyayı sıradan bir kullanıcı değiştirebilirse ne olur?",
           "Eklenen satır, bir sonraki cron çalışmasında root yetkisiyle çalışır."),
          puan=20, baslik="Neden kritik"),
]

SEVIYE = Seviye(
    kimlik="olay_izin",
    cilt=1,
    bolum=90,
    baslik="İzin ve Cron Denetimi",
    brifing="""
Deniz Kara SOC ekranından başını kaldırıyor: "**<<musteri>>**'den (<<sektor>>) acil bir
çağrı. **<<sunucu>>** sunucusunda biri root olmuş ama nasıl olduğunu bilmiyorlar. Disk
kopyasını aldılar, `kopya/` klasöründe."

"Klasik kapılara bak: root'un cron'unda herkesin yazabildiği bir betik, UID'i 0 olan
fazladan bir hesap, olmaması gereken bir SUID program, başkalarının yazabildiği bir SSH
anahtar dosyası. Bul, birini de hemen kapat."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırganın gözünden bunlar dört ayrı merdiven: herhangi birini bulan, sıradan bir
kullanıcıdan root'a çıkar. Savunmanın gözünden ise hepsi tek bir alışkanlıkla yakalanır:
düzenli izin denetimi. `find / -perm -4000`, `find / -perm -o+w -type f` ve
`awk -F: '$3==0' /etc/passwd` üç satırlık bir denetim betiğidir; her gece çalıştır.
""",
    gercek_hayat="""
- **GTFOBins:** SUID biti verilmiş find, vim, python, bash gibi programların nasıl kabuk
  açtığını listeleyen açık bir projedir. Hem saldırganlar hem denetçiler bu listeyi
  kullanır; yanlışlıkla SUID verilmiş bir araç, sızma testlerinde en sık bulunan yetki
  yükseltme yollarındandır.
- **Yazılabilir cron betikleri:** Linux yetki yükseltme kontrol listelerinin (örn. LinPEAS
  gibi araçların taradığı maddeler) değişmez başlıklarındandır; özellikle yedekleme ve
  bakım betiklerinde sık görülür.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c01b05", "c01b06"),
)
