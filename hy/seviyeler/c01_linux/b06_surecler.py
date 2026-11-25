"""Cilt 1 · Bölüm 6 — Süreçler, Servisler ve Ağ Bağlantıları.

Beceri: ps aux okumak (kanıt dosyasında root süreçleri ve işlemciyi sömüren şüpheli süreç),
kendi makinende arka plan süreci başlatıp PID'ini bulmak ve öldürmek (/proc ile doğrulanır),
ss -tlnp ile yalnızca 127.0.0.1'de dinleyen servisi bulup nc ile bağlanmak, cron satırlarını
okumak ve herkesin yazabildiği root cron betiğini düzeltmek.

Servis: seviye 127.0.0.1 üzerinde rastgele bir portta bir karşılama (banner) servisi açar ve
oyuncunun başlattığı `sleep <N>` süreçlerini /proc üzerinden izleyip PID'lerini lab'ın yanındaki
bir dosyaya yazar (öldürüldükten sonra da "bu PID gerçekten o süreçti" diyebilmek için).

Vakalar: farklı müşterilerin sunucu kopyaları; ps kanıtı, şüpheli sürecin adı, cron betikleri,
zayıf betik, sleep süresi ve port her vakada değişir.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import threading
import time
from pathlib import Path

from hy.motor import servis as srv
from hy.motor.kontrol import Bayrak, Durum, Kontrol, Sayi, Secmeli, Sonuc, sayi_cek
from hy.motor.seviye import Adim, Gorev, Seviye, yer_tut
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

KIMLIK = "c01b06"
DUZENLER = [("kanit", "sunucu_kopyasi"), ("toplanan", "kopya"), ("olay_dosyasi", "dokum"),
            ("inceleme", "sistem_kopyasi")]
BETIK_SETLERI = [
    ("yedekle.sh", "disk_kontrol.sh", "log_temizle.sh", "onbellek_temizle.sh"),
    ("db_yedek.sh", "saglik_kontrol.sh", "eski_loglari_sil.sh", "rapor_uret.sh"),
    ("gece_yedegi.sh", "servis_izle.sh", "arsivle.sh", "gecici_temizle.sh"),
]
SUPHELILER = ["/tmp/.ICE-unix/.x/kworkerd", "/dev/shm/.cache/systemd-upd", "/var/tmp/.font/kthreadd2",
              "/tmp/.X11-unix/.s/dbus-helper"]
CEKIRDEK = ["[kthreadd]", "[rcu_gp]", "[rcu_par_gp]", "[kworker/0:0H-events_highpri]", "[mm_percpu_wq]",
            "[ksoftirqd/0]", "[rcu_sched]", "[migration/0]", "[cpuhp/0]", "[kdevtmpfs]", "[kauditd]",
            "[khungtaskd]", "[oom_reaper]", "[kswapd0]", "[kworker/u8:1-events_unbound]", "[jbd2/sda1-8]",
            "[ext4-rsv-conver]", "[kworker/1:2-events]", "[ksoftirqd/1]", "[migration/1]"]
SERVIS_ADLARI = ["yönetim konsolu", "iç izleme ajanı", "yedekleme paneli", "eski hata ayıklama servisi"]


class _Durum(Durum):
    def cevabi_goster(self, b):
        return yer_tut(self.cozum, b.senaryo)


# ---------------------------------------------------------------- senaryo

def _ps_kaniti(rng, m, gun):
    ay = u.AYLAR_EN[gun.month - 1]
    acilis = f"{ay}{gun.day:02d}"
    kayitlar = []

    def ekle(kul, pid, komut, cpu=0.0, mem=0.0, tty="?", durum="S", basla=acilis, sure="0:00"):
        if komut.startswith("["):              # çekirdek iş parçacıklarının belleği yok
            vsz = rss = 0
        else:
            vsz = rng.randint(6000, 400000) if mem < 5 else rng.randint(1200000, 2600000)
            rss = max(900, int(vsz * rng.uniform(0.05, 0.3))) if mem < 5 else rng.randint(300000, 600000)
        kayitlar.append((pid, f"{kul:<9}{pid:>7} {cpu:>4.1f} {mem:>4.1f} {vsz:>7} {rss:>6} {tty:<8} {durum:<5}"
                              f"{basla:>5} {sure:>7} {komut}", kul, cpu, komut))

    ekle("root", 1, "/sbin/init", 0.0, 0.3, durum="Ss", sure="0:07")
    pid = 2
    for k in rng.sample(CEKIRDEK, rng.randint(8, 16)):
        ekle("root", pid, k, durum=rng.choice(["S", "I<", "I", "S<"]))
        pid += rng.randint(1, 12)
    pid = rng.randint(280, 330)
    for kul, komut in [("root", "/lib/systemd/systemd-journald"), ("root", "/lib/systemd/systemd-udevd"),
                       ("systemd+", "/lib/systemd/systemd-timesyncd"), ("systemd+", "/lib/systemd/systemd-resolved"),
                       ("message+", "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation"),
                       ("syslog", "/usr/sbin/rsyslogd -n -iNONE"), ("root", "/usr/sbin/cron -f"),
                       ("bind", "/usr/sbin/named -u bind -t /var/named/chroot"),
                       ("root", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"),
                       ("root", "/sbin/agetty -o -p -- \\u --noclear tty1 linux"),
                       ("root", "/usr/lib/postfix/sbin/master -w"), ("postfix", "qmgr -l -t unix -u"),
                       ("root", "/usr/sbin/apache2 -k start")]:
        ekle(kul, pid, komut, round(rng.uniform(0, 0.4), 1), round(rng.uniform(0.1, 1.2), 1), durum="Ss",
             sure=f"0:{rng.randint(1, 59):02d}")
        pid += rng.randint(3, 60)
    mysql_pid = pid + rng.randint(5, 40)
    ekle("mysql", mysql_pid, "/usr/sbin/mysqld", round(rng.uniform(9, 34), 1), round(rng.uniform(14, 26), 1),
         durum="Ssl", sure=f"{rng.randint(40, 300)}:{rng.randint(0, 59):02d}")
    pid = mysql_pid + rng.randint(200, 900)
    for _ in range(rng.randint(3, 6)):
        ekle("www-data", pid, "/usr/sbin/apache2 -k start", round(rng.uniform(0.2, 4.5), 1),
             round(rng.uniform(0.6, 2.4), 1), sure=f"0:{rng.randint(2, 59):02d}")
        pid += rng.randint(1, 30)
    ekle("postfix", pid + 400, "pickup -l -t unix -u -c", basla=f"{rng.randint(8, 11):02d}:{rng.randint(0, 59):02d}")
    supheli_pid = rng.randint(4000, 15000)
    supheli = rng.choice(SUPHELILER)
    ekle("www-data", supheli_pid, supheli, round(rng.uniform(85, 99), 1), round(rng.uniform(1.5, 4.5), 1),
         durum="Sl", sure=f"{rng.randint(1200, 4000)}:{rng.randint(0, 59):02d}")
    admin = rng.choice(u.ISIMLER)
    s_pid = rng.randint(20000, 30000)
    saat = f"{rng.randint(12, 17):02d}:{rng.randint(0, 59):02d}"
    ekle("root", s_pid, f"sshd: {admin} [priv]", durum="Ss", basla=saat)
    ekle(admin, s_pid + 9, f"sshd: {admin}@pts/0", basla=saat)
    ekle(admin, s_pid + 10, "-bash", tty="pts/0", durum="Ss", basla=saat)
    ekle(admin, s_pid + rng.randint(40, 300), "ps aux", tty="pts/0", durum="R+", basla=saat)
    kayitlar.sort()
    baslik = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    metin = "\n".join([baslik] + [k[1] for k in kayitlar]) + "\n"
    root_sayi = sum(1 for k in kayitlar if k[2] == "root")
    root_gecen = sum(1 for k in kayitlar if "root" in k[1])
    return metin, root_sayi, root_gecen, len(kayitlar), supheli_pid, supheli, mysql_pid


def uret(rng):
    m = musteri_sec(rng)
    kanit_k, kopya_k = rng.choice(DUZENLER)
    gun = u.gun(rng)
    ps, root_sayi, root_gecen, surec_sayi, supheli_pid, supheli, mysql_pid = _ps_kaniti(rng, m, gun)
    betikler = rng.choice(BETIK_SETLERI)
    n_dk, m_dk = rng.sample([2, 3, 5, 10, 15, 20, 30], 2)
    zayif_i = rng.randint(0, 1)
    zayif = betikler[zayif_i]
    gece_saat = f"{rng.randint(1, 4)}"
    port = rng.randint(20000, 45000)
    sleep_sure = rng.randint(3000, 9999)
    return {
        "vaka": f"{m['ad']} — {m['sunucu']} sunucusu yavaşladı",
        "musteri": m,
        "duzen": (kanit_k, kopya_k),
        "ps": ps, "supheli": supheli, "mysql_pid": mysql_pid, "root_gecen": root_gecen, "surec_sayi": surec_sayi,
        "betikler": betikler, "araliklar": (n_dk, m_dk), "zayif": zayif, "gece_saat": gece_saat,
        "port": port, "sleep_sure": sleep_sure,
        "servis_adi": rng.choice(SERVIS_ADLARI),
        "metin": {
            "musteri": m["ad"], "sunucu": m["sunucu"], "kisi": m["kisi"], "kod": m["kod"], "kanit_k": kanit_k,
            "kopya_k": kopya_k, "sleep_sure": sleep_sure, "zayif": zayif,
        },
        "cevaplar": {
            "root_sayi": root_sayi,
            "supheli_pid": supheli_pid,
            "port": port,
            "banner": u.bayrak(rng, rng.choice(["arka_oda", "sessiz_iz", "kapali_devre", "ucuncu_goz"])),
            "cron_dk": (n_dk, m_dk)[zayif_i],
        },
    }


def _crontab(s) -> str:
    m = s["musteri"]
    a, b, c, d = s["betikler"]
    n_dk, m_dk = s["araliklar"]
    return f"""# /etc/crontab: {m['sunucu']} sistem geneli zamanlanmış görevler
# crontab -e kullanmayın, bu dosyayı düzenleyin. Alanlar:
# dakika saat ayın-günü ay haftanın-günü  kullanıcı  komut
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
*/{n_dk} * * * *  root    /opt/{m['kod']}/{a}
*/{m_dk} * * * *  root    /opt/{m['kod']}/{b}
30 {s['gece_saat']} * * *   root    /opt/{m['kod']}/{c}
0 */6 * * *  www-data /opt/{m['kod']}/{d}
"""


def yaz(lab: Path, s: dict) -> None:
    kanit_k, kopya_k = s["duzen"]
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} — {m['sunucu']} incelemesi\n"
          f"  {kanit_k}/ps_aux.txt     -> sunucu yavaşken alınmış 'ps aux' çıktısı\n"
          f"  {kopya_k}/etc/crontab    -> sunucunun /etc/crontab dosyasının kopyası\n"
          f"  {kopya_k}/opt/{m['kod']}/  -> cron'un çağırdığı betiklerin kopyası (/opt/{m['kod']})\n"
          "Not: Kopyadaki dosyaların sahibi sensin; gerçek sunucuda sahipleri root.\n")
    u.yaz(lab / kanit_k / "ps_aux.txt", s["ps"])
    u.yaz(lab / kopya_k / "etc" / "crontab", _crontab(s))
    modlar = {s["betikler"][0]: 0o755, s["betikler"][1]: 0o700, s["betikler"][2]: 0o775, s["betikler"][3]: 0o750}
    modlar[s["zayif"]] = 0o777
    for ad, mod in modlar.items():
        u.yaz(lab / kopya_k / "opt" / m["kod"] / ad,
              f"#!/bin/bash\n# {m['ad']} — {ad}\n# Bakım: {m['kisi']}\necho \"$(date) {ad} çalıştı\" >> /var/log/{m['kod']}_bakim.log\n",
              mod=mod)


# ---------------------------------------------------------------- süreç izleme (/proc)

def _izleme_yolu(lab: Path) -> Path:
    return Path(lab).parent / f".{KIMLIK}.izleme.json"


def _sleep_pidleri(n: int) -> list:
    """/proc altında komut satırı tam olarak `sleep <n>` olan canlı süreçlerin PID'leri."""
    pidler = []
    try:
        girdiler = os.listdir("/proc")
    except OSError:
        return pidler
    for d in girdiler:
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/cmdline", "rb") as f:
                parca = f.read().rstrip(b"\0").split(b"\0")
        except OSError:
            continue
        if len(parca) == 2 and os.path.basename(parca[0]) == b"sleep" and parca[1] == str(n).encode():
            pidler.append(int(d))
    return sorted(pidler)


def _izleme_oku(lab: Path, n: int) -> list:
    try:
        veri = json.loads(_izleme_yolu(lab).read_text())
    except (OSError, ValueError):
        return []
    return list(veri.get("pidler", [])) if veri.get("n") == n else []


def _izleme_yaz(lab: Path, n: int, pidler: list) -> None:
    yol = _izleme_yolu(lab)
    gecici = yol.with_suffix(".tmp")
    gecici.write_text(json.dumps({"n": n, "pidler": pidler}))
    os.replace(gecici, yol)


def _izle(s: dict, lab: Path, dur) -> None:
    n = s["sleep_sure"]
    gorulen = _izleme_oku(lab, n)
    _izleme_yaz(lab, n, gorulen)
    while not dur.wait(0.3):
        yeni = [p for p in _sleep_pidleri(n) if p not in gorulen]
        if yeni:
            gorulen += yeni
            _izleme_yaz(lab, n, gorulen)


def servis(s: dict, lab: Path, dur) -> None:
    m = s["musteri"]
    banner = (f"{m['ad']} {s['servis_adi']} v2.{s['port'] % 9} — yalnızca yerel erişim ({m['sunucu']})\n"
              "Bu port dışarıdan taranamaz, ama makinenin içindeki herkes bağlanabilir.\n"
              f"Bayrak: {s['cevaplar']['banner']}\n")
    sunucu = srv.tcp_banner("127.0.0.1", s["port"], banner)
    threading.Thread(target=_izle, args=(s, lab, dur), daemon=True).start()
    srv.calistir([sunucu], dur)


class _SleepPID(Kontrol):
    """Oyuncunun başlattığı `sleep <N>` sürecinin PID'i: canlıysa /proc'tan, öldürüldüyse izleme kaydından."""
    bicim = "PID (bir sayı)"

    def dogrula(self, girdi: str, b) -> Sonuc:
        n = b.senaryo["sleep_sure"]
        pid = sayi_cek(girdi)
        if pid is None:
            return Sonuc(False, "Cevap olarak bir sayı (PID) yaz.")
        canli, kayit = _sleep_pidleri(n), _izleme_oku(b.lab, n)
        if pid in canli or pid in kayit:
            return Sonuc(True, f"/proc/{pid} bu süreç için açılmış klasördü. Şimdi sırada onu öldürmek var.")
        if not canli and not kayit:
            return Sonuc(False, f"Şu an çalışan bir `sleep {n}` süreci yok. Görev kabuğunda önce `sleep {n} &` yaz.")
        if pid < 100:
            return Sonuc(False, "Köşeli parantezdeki `[1]` iş (job) numarasıdır; PID onun yanındaki büyük sayı.", yakin=True)
        if pid == n:
            return Sonuc(False, f"{n} uyku süresi (saniye), PID değil. `sleep {n} &` yazınca ekrana basılan sayıya bak.", yakin=True)
        return Sonuc(False, f"Bu PID `sleep {n}` sürecine ait değil. `pgrep -a sleep` ile kontrol et.")

    def cevabi_goster(self, b) -> str:
        n = b.senaryo["sleep_sure"]
        pidler = _sleep_pidleri(n) or _izleme_oku(b.lab, n)
        if pidler:
            return str(pidler[-1])
        return f"`sleep {n} &` yazınca `[1]` yanında basılan sayı (ya da `pgrep -f 'sleep {n}'` çıktısı)"


def _sleep_bitti(b) -> Sonuc:
    n = b.senaryo["sleep_sure"]
    canli = _sleep_pidleri(n)
    if canli:
        return Sonuc(False, f"`sleep {n}` hâlâ çalışıyor (PID {canli[0]}). `kill {canli[0]}` yaz, sonra tekrar dene.",
                     yakin=True)
    kayit = _izleme_oku(b.lab, n)
    if not kayit:
        return Sonuc(False, f"İzleme kaydında hiç `sleep {n}` süreci yok. Önce 3. görevdeki gibi başlat, PID'ini bul, "
                            "sonra öldür.")
    return Sonuc(True, f"Süreç gitti: `/proc/{kayit[-1]}` artık yok. `kill` önce kibarca kapanma sinyali (SIGTERM) "
                       "gönderir; dinlemeyen süreç için `kill -9` (SIGKILL) son çaredir.")


def _cron_izin(b) -> Sonuc:
    kanit_k, kopya_k = b.senaryo["duzen"]
    yol = b.lab / kopya_k / "opt" / b.senaryo["musteri"]["kod"] / b.senaryo["zayif"]
    if not yol.exists():
        return Sonuc(False, "Betik yerinde yok. Silmek cron görevini bozar; izni düzeltmek gerekiyordu. `sifirla` ile tazele.")
    mod = stat.S_IMODE(yol.stat().st_mode)
    if mod & 0o002:
        return Sonuc(False, f"Hâlâ herkes yazabiliyor (`{oct(mod)[2:]}`). Herkesin hangi betiğe yazabildiğini "
                            "`find <<kopya_k>>/opt -perm -o+w` ile bul.".replace("<<kopya_k>>", kopya_k))
    if mod & 0o020:
        return Sonuc(False, f"Diğerleri artık yazamıyor ama grup hâlâ yazabiliyor (`{oct(mod)[2:]}`). 755 ya da 700 yap.",
                     yakin=True)
    if not mod & 0o100:
        return Sonuc(False, "Betik artık çalıştırılamıyor; cron görevi bozulur. Sahibin x izni kalmalı (755 ya da 700).",
                     yakin=True)
    return Sonuc(True, f"`{oct(mod)[2:]}`: artık sadece sahibi yazabiliyor. Gerçek sunucuda bir de "
                       "`chown root:root` ile sahibinin root olduğundan ve klasörün de başkalarınca yazılamadığından emin olunur.")


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: ps/grep/sort/kill/ss/nc/find ile çözer. Servis testte aynı süreçte çalışır."""
    from hy.motor.kontrol import Baglam
    kanit_k, kopya_k = s["duzen"]
    n = s["sleep_sure"]
    root = _sh(f"grep -c '^root' {kanit_k}/ps_aux.txt", lab)
    supheli = _sh(f"sort -k3 -nr {kanit_k}/ps_aux.txt | head -1 | awk '{{print $2}}'", lab)
    # Oyuncunun kabuğundaki `sleep N &` gibi: süreç bizim çocuğumuz olsun ki öldürülünce biçilsin (zombi kalmasın)
    surec = subprocess.Popen(["bash", "-c", f"exec sleep {n}"], cwd=lab,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    pid = ""
    for _ in range(50):                    # pgrep ile bul, izleme servisinin görmesini bekle
        pid = _sh(f"pgrep -f '^sleep {n}$'", lab)
        if pid and int(pid) in _izleme_oku(lab, n):
            break
        time.sleep(0.1)
    _sh(f"kill {pid}", lab)
    surec.wait(timeout=5)
    port = _sh(f"ss -tlnp | grep 'pid={os.getpid()},' | awk '{{print $4}}' | grep '^127.0.0.1:' | cut -d: -f2 | head -1", lab)
    banner = _sh(f"timeout 5 nc 127.0.0.1 {port} < /dev/null | grep -o 'FLAG{{[^}}]*}}'", lab)
    zayif = _sh(f"find {kopya_k}/opt -type f -perm -o+w", lab)
    dk = _sh(f"grep \"$(basename {zayif})\" {kopya_k}/etc/crontab | awk '{{print $1}}' | cut -d/ -f2", lab)
    _sh(f"chmod 755 {zayif}", lab)
    secmeli = SEVIYE.gorevler[8].kontrol.cevabi_goster(Baglam(s, lab, 9))[0]
    return {1: root, 2: supheli, 3: pid, 4: "", 5: port, 6: banner, 7: dk, 8: "", 9: secmeli}


# ---------------------------------------------------------------- sık hatalar

def _root_hata(g, beklenen, b):
    n = int(g)
    if n == b.senaryo["root_gecen"]:
        return ("`grep root` satırın herhangi bir yerinde root geçenleri sayar; bir süreç root olmadığı halde "
                "komutunda `chroot` geçiyor. Sadece satır başındaki kullanıcıya bak: `grep -c '^root'`.")
    if n == b.senaryo["surec_sayi"] + 1:
        return "Dosyadaki bütün satırları saydın (başlık satırı dahil). Sadece USER sütunu root olanları say."
    if n == b.senaryo["surec_sayi"]:
        return "Bu bütün süreçlerin sayısı. Sadece root kullanıcısıyla çalışanları say."
    return None


def _supheli_hata(g, beklenen, b):
    n = int(g)
    if n == b.senaryo["mysql_pid"]:
        return ("Bu `mysqld`: belleği en çok kullanan ama meşru veritabanı süreci. Soru işlemciyi (%CPU, 3. sütun) "
                "sömüren ve tuhaf bir klasörden çalışan süreci soruyor.")
    return None


def _port_hata(g, beklenen, b):
    n = int(g)
    if n in (22, 25, 53, 80, 443, 631, 3306, 5432):
        return "Bu bilinen bir servis portu. Aradığın, `python3` sürecinin 127.0.0.1 üzerinde açtığı yüksek numaralı port."
    return None


def _cron_hata(g, beklenen, b):
    n = int(g)
    n_dk, m_dk = b.senaryo["araliklar"]
    diger = m_dk if beklenen == n_dk else n_dk
    if n == diger:
        return "Bu, root'un çalıştırdığı diğer betiğin aralığı. Önce herkesin yazabildiği betiği bul (`ls -l` ya da `find -perm -o+w`)."
    if n in (17, 25, 30, 0):
        return "Bu sayı satırın dakika alanı ama `*/N` biçiminde değil. `*/N` 'her N dakikada bir' demek."
    return None


ADIMLAR = [
    Adim("Süreçlerin fotoğrafı: ps aux", """
Diskteki dosyalar sistemin hafızasıysa, süreçler o an yaşayan kısmıdır. Bir saldırganın arka
kapısı da, savunmacının izleme aracı da sonuçta bir süreçtir. `ps aux` bütün süreçlerin anlık
fotoğrafını verir. En önemli sütunlar: **USER** (kim çalıştırıyor), **PID** (süreç numarası),
**%CPU / %MEM** (kaynak kullanımı), **COMMAND** (çalışan komut).
""", komut="ps aux | head -n 5", sonra="""
`top` (ya da daha okunaklısı `htop`) aynı bilgiyi canlı ve sürekli güncellenen bir ekranda
verir; çıkmak için `q`.
"""),
    Adim("Bir süreci aramak", """
`ps aux | grep ssh` gibi süzebilirsin; `pgrep -a ad` ise adı eşleşen süreçlerin PID'ini ve
komut satırını doğrudan verir. Şu an bu oyunun kendisi de birkaç python3 süreci olarak
çalışıyor:
""", komut="pgrep -a python3"),
    Adim("Süreçleri yönetmek: kill ve arka plan", """
- `komut &` komutu arka planda başlatır; kabuk `[1] 12345` gibi bir satır basar: köşeli
  parantezdeki **iş numarası** (job), yanındaki büyük sayı **PID**'dir. `$!` son arka plan
  sürecinin PID'ini tutar.
- `jobs` arka plandaki işleri listeler, `fg %1` 1 numaralı işi öne getirir.
- `kill 1234` sürece "kibarca kapan" sinyali (SIGTERM) gönderir, `kill -9 1234` zorla
  öldürür (SIGKILL), `pkill firefox` adına göre öldürür.

Saha görevinde kendi makinende bir süreç başlatıp onu bulacak ve öldüreceksin.
"""),
    Adim("/proc: her süreç bir klasör", """
Linux'ta çalışan her süreç için `/proc/<PID>/` adında sanal bir klasör vardır: komut satırı
(`cmdline`), durumu (`status`), açık dosyaları (`fd/`)... Süreç ölünce klasör de kaybolur.
`/proc/self` o an komutu çalıştıran sürecin kendisidir:
""", komut="head -n 5 /proc/self/status"),
    Adim("Servisler: systemd", """
Arka planda sürekli çalışan programlara **servis** (daemon) denir: web sunucusu, SSH,
veritabanı. Modern dağıtımlarda `systemctl` yönetir: `systemctl status ssh`,
`sudo systemctl start ssh`, `sudo systemctl enable ssh` (açılışta başlasın). Logları
`journalctl -u ssh` okur. Çalışan servislere bak:
""", komut="systemctl list-units --type=service --state=running --no-pager | head -n 8"),
    Adim("Hangi portlar dinleniyor? ss", """
Bir servis ağdan bağlantı kabul ediyorsa bir port **dinler**. `ss -tulpn`: `-t`/`-u` TCP/UDP,
`-l` sadece dinleyenler, `-p` hangi süreç, `-n` port adları yerine numaralar.

`0.0.0.0:22` görürsen servis bütün ağ arayüzlerinden bağlantı kabul ediyor demektir;
`127.0.0.1:22` görürsen sadece makinenin kendisinden.
""", komut="ss -tln", sonra="""
**Hacker gözüyle:** Saldırgan için `ss -tulpn`, sızdığı makinenin içinden "dışarıdan
görünmeyen" servisleri bulmanın yoludur: sadece 127.0.0.1'de dinleyen bir veritabanı ya da
yönetim paneli dışarıdan taranamaz ama içeriden ulaşılabilir. Savunmacı için ise tanımadığı
bir portu dinleyen şüpheli süreci (olası arka kapıyı) bulmanın en hızlı yolu.
"""),
    Adim("Zamanlanmış görevler: cron", """
`cron` komutları belirli zamanlarda çalıştırır. `crontab -l` kendi görevlerin,
`/etc/crontab` sistem geneli görevler. İlk beş alan zamandır: **dakika, saat, ayın günü, ay,
haftanın günü**. `*/5 * * * *` her 5 dakikada bir, `30 2 * * *` her gece 02:30'da. Sistem
crontab'ında 6. alan, görevi **hangi kullanıcının** çalıştıracağıdır.
""", komut="cat <<kopya_k>>/etc/crontab", sonra="""
**Hacker gözüyle:** Root olarak çalışan bir cron görevi, normal kullanıcının yazabildiği bir
betiği çağırıyorsa, o betiğe eklenen her satır birkaç dakika içinde **root olarak** çalışır.
Saldırganlar cron'u kalıcılık için de kullanır: sistem yeniden başlasa bile arka kapı kendini
tekrar çalıştırır. Tanımadığın cron girdilerini her zaman sorgula.
"""),
    Adim("Kanıt dosyası", """
Müşteri, sunucu yavaşken bir `ps aux` çıktısı almış. Canlı sisteme dokunmadan önce kanıtı
oku: ilk satır sütun başlıklarıdır, süreç değildir.
""", komut="head -n 4 <<kanit_k>>/ps_aux.txt"),
]

GOREVLER = [
    Gorev("`<<kanit_k>>/ps_aux.txt` kanıtında **root** kullanıcısıyla çalışan kaç süreç var?",
          Sayi("root_sayi", sik_hatalar=_root_hata),
          ("Kullanıcı adı her satırın ilk sütunu.",
           "`grep` ile root satırlarını süz, `-c` ile say. Ama `root` kelimesi başka bir yerde de geçebilir.",
           "`grep -c '^root' <<kanit_k>>/ps_aux.txt` — `^` 'satır başında' demek."),
          puan=25, baslik="Root süreçleri"),
    Gorev("Sunucu neden yavaş? Kanıtta işlemciyi sömüren **şüpheli** bir süreç var. PID'i ne?",
          Sayi("supheli_pid", sik_hatalar=_supheli_hata),
          ("%CPU 3. sütun. En çok işlemci kullanan süreç hangisi, nereden çalışıyor?",
           "`sort -k3 -nr` 3. sütuna göre büyükten küçüğe sıralar.",
           "`sort -k3 -nr <<kanit_k>>/ps_aux.txt | head -3` — en üstteki satırın 2. sütunu PID. Çalıştığı klasöre de bak."),
          puan=30, baslik="İşlemci hırsızı"),
    Gorev("Görev kabuğunda arka planda `sleep <<sleep_sure>> &` komutunu başlat. Bu sürecin **PID**'i ne?",
          _SleepPID(),
          ("Komutun sonundaki `&` onu arka plana atar ve kabuk sana iki sayı söyler.",
           "`[1] 12345` biçimindeki satırda köşeli parantez iş numarası, yanındaki sayı PID. Kaçırdıysan `pgrep` kullan.",
           "`pgrep -f 'sleep <<sleep_sure>>'` ya da `ps aux | grep 'sleep <<sleep_sure>>'` — çıkan PID'i gönder."),
          puan=25, baslik="Süreç başlat"),
    Gorev("Şimdi o `sleep <<sleep_sure>>` sürecini sonlandır ve `cevap 4` yaz. (Oyun bunu `/proc` üzerinden kontrol eder.)",
          _Durum(_sleep_bitti, "kill <PID>   (PID: pgrep -f 'sleep <<sleep_sure>>')"),
          ("Bir sürece kapanma sinyali gönderen komutu eğitimde gördün.",
           "`kill PID` yeterli; inatçı süreçler için `kill -9`. Adla öldürmek de mümkün.",
           "`kill $(pgrep -f 'sleep <<sleep_sure>>')` ya da `kill <PID>`; sonra `cevap 4`."),
          puan=25, baslik="Süreci öldür"),
    Gorev("Bu görev sırasında makinende, sadece **127.0.0.1** üzerinde dinleyen bir `python3` servisi açıldı. "
          "Hangi portta dinliyor?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Dinleyen portları ve onları açan süreçleri gösteren komutu eğitimde gördün.",
           "`ss -tlnp`: `-l` dinleyenler, `-p` süreç adı. `127.0.0.1:` ile başlayan ve `python3` yazan satır.",
           "`ss -tlnp | grep python3` — 4. sütundaki `127.0.0.1:` sonrası sayı port."),
          puan=30, baslik="Gizli dinleyen"),
    Gorev("O porta `nc` ile bağlan. Servisin karşılama mesajındaki bayrağı gönder.",
          Bayrak("banner"),
          ("Dışarıdan görünmeyen bir servise içeriden bağlanabilirsin.",
           "`nc` (netcat) bir adrese ve porta TCP bağlantısı açar.",
           "`nc 127.0.0.1 <port>` — mesaj gelince bağlantı kapanır (kapanmazsa Ctrl+C)."),
          puan=30, baslik="İçeriden bağlan"),
    Gorev("`<<kopya_k>>/opt/<<kod>>/` klasöründeki betiklerden biri **herkes tarafından yazılabilir**. "
          "`<<kopya_k>>/etc/crontab`'a göre root bu betiği **kaç dakikada bir** çalıştırıyor?",
          Sayi("cron_dk", sik_hatalar=_cron_hata),
          ("Önce zayıf betiği bul, sonra crontab'daki satırını oku.",
           "`ls -l <<kopya_k>>/opt/<<kod>>/` ya da `find <<kopya_k>>/opt -perm -o+w`; `rwxrwxrwx` olanı ara. "
           "`rwxrwxr-x` olan herkese değil, sadece gruba açık.",
           "`grep <betik_adı> <<kopya_k>>/etc/crontab` — satırın başındaki `*/N` ifadesindeki N."),
          puan=30, baslik="Zayıf halka"),
    Gorev("Bu betiğin iznini düzelt: herkes ve grup **yazamasın** ama cron onu **çalıştırabilsin**. "
          "Sonra `cevap 8` yaz.",
          _Durum(_cron_izin, "chmod 755 <<kopya_k>>/opt/<<kod>>/<<zayif>>   (ya da 700)"),
          ("Hangi izin bitlerinin kalkması gerekiyor? Sahibin hangi izinleri kalmalı?",
           "Oktal düşün: sahip rwx (7), grup ve diğerleri en fazla r-x (5) ya da hiç (0).",
           "`chmod 755 <<kopya_k>>/opt/<<kod>>/<betik>` (ya da 700)."),
          puan=30, baslik="Kapıyı kapat"),
    Gorev("Bu düzeltmeyi yapmasaydık, sunucuya düşük yetkiyle giren bir saldırgan bu betiği nasıl kullanırdı?",
          Secmeli([
              ("Betiğe kendi komutunu ekler; cron birkaç dakika içinde onu root olarak çalıştırır",
               "Doğru. Root'un çalıştırdığı ama herkesin yazabildiği bir betik, yetki yükseltmenin klasik yollarından "
               "biridir. Aynı yol kalıcılık için de kullanılır."),
              ("Betiği okuyup içindeki yorum satırlarından root parolasını öğrenir ve sudo ile oturum açar",
               "Yazma izni okumaktan çok daha güçlü: içeriği değiştirebilir. Betikte parola olması da gerekmez."),
              ("Betiği silerek cron servisini çökertir; çöken servisin yerine kendi kabuğunu başlatır",
               "Betiği silmek sadece o görevi bozar; cron çökmez. Asıl tehlike betiği değiştirmek."),
              ("Betiğin değiştirilme tarihini oynayıp cron'un onu saniyede bir çalıştırmasını sağlar",
               "Çalışma sıklığını crontab satırı belirler, dosyanın tarihi değil. Mesele kimin yetkisiyle çalıştığı."),
          ]),
          ("Betik kimin yetkisiyle çalışıyor, kim ona yazabiliyor?",
           "Root'un çalıştırdığı bir dosyaya herkes satır ekleyebiliyorsa, eklenen satır kimin yetkisiyle çalışır?",
           "Eklenen satır birkaç dakika içinde root olarak çalışır: yetki yükseltme."),
          puan=20, baslik="Saldırgan gözüyle"),
]


SEVIYE = Seviye(
    kimlik=KIMLIK,
    cilt=1,
    bolum=6,
    baslik="Süreçler, Servisler ve Ağ Bağlantıları",
    brifing="""
**<<musteri>>**'den <<kisi>> arıyor: "**<<sunucu>>** birkaç gündür sürünüyor. Yeniden
başlattık, düzelmedi. Yavaşken bir `ps aux` çıktısı ve sunucunun crontab'ını aldım,
gönderiyorum."

Deniz kulaklığını çıkarıyor: "Yavaşlık bazen bir arka kapının yan etkisidir. Süreçlere bak,
cron'a bak, kim neyi dinliyor ona bak."

Selin ekliyor: "Önce kanıtı oku. Sonra aynı komutları kendi makinende dene; `ss`, `kill` ve
`/proc` elinin altında olsun. Bu görev boyunca makinende küçük bir yerel servis de çalışacak,
onu da bulmanı istiyorum."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Arka kapı da izleme aracı da sonuçta bir süreçtir; `ps`, `ss` ve `/proc` onları ortaya
çıkarır. Saldırgan içeriden `ss -tulpn` ile dışarıdan görünmeyen servisleri bulur, root'un
çalıştırdığı ama herkesin yazabildiği bir cron betiğiyle yetkisini yükseltir ya da kalıcılık
kurar. Savunmacı aynı komutlarla tanımadığı süreci, portu ve cron satırını sorgular; cron
betiklerinin sahibinin root olduğundan ve başkalarınca yazılamadığından emin olur.
""",
    gercek_hayat="""
- **Kripto madencileri:** Ele geçirilen Linux sunucularında en sık bulunan zararlılardan biri,
  işlemciyi sömüren gizli kripto para madencileridir. Çoğu `/tmp` ya da `/dev/shm` gibi
  geçici klasörlerden çalışır, kendine sistem süreci gibi görünen adlar verir ve cron ile
  kendini yeniden başlatır. "Sunucu yavaşladı" şikâyeti bu yüzden bir güvenlik ipucudur.
- **Cron ile yetki yükseltme ve kalıcılık:** Herkesçe yazılabilir cron betikleri hem CTF'lerde
  hem gerçek sızma testlerinde sık görülen bir yetki yükseltme yoludur. Linux yetki yükseltme
  kontrol listeleri (ve linPEAS gibi araçlar) bu yüzden zamanlanmış görevleri ve onların
  çağırdığı dosyaların izinlerini özellikle denetler.
""",
    sure_hedef_dk=30,
)
