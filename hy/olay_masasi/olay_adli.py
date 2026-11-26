"""Olay Masası — Süreç ve Kalıcılık Adli İncelemesi.

Ele geçmiş bir sunucudan alınmış ANLIK GÖRÜNTÜLER (ps, ss, cron/systemd, son değişen dosyalar)
statik metin dosyası olarak gelir. Gerçek süreç ya da ağ bağlantısı yoktur; oyuncu yalnızca
artefaktları okur: şüpheli süreç, C2 bağlantısı, kalıcılık mekanizması ve doğru müdahale sırası.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli, norm
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

KOTU_AD = [".kworkerds", "kdevtmpfsi", ".sysupdate", ".ag_yardimci", "kswapd1x", ".dbus-helper"]
KOTU_DIZIN = ["/tmp", "/dev/shm", "/var/tmp"]
CRON_AD = ["sistem_bakim", "ag_izleme", "log_ek", "disk_kontrol"]
SERVIS_AD = ["sistem-guncelle", "udev-yardimci", "ag-izleme", "disk-saglik"]
HAVUZ_PORT = [3333, 4444, 5555, 14444, 8443]


def uret(rng):
    m = musteri_sec(rng)
    kul = u.isimler(rng, 3)
    gun = u.gun(rng)
    kotu_ad = rng.choice(KOTU_AD)
    yol = f"{rng.choice(KOTU_DIZIN)}/{kotu_ad}"
    pid = rng.randint(20000, 40000)
    c2 = u.dis_ip(rng)
    c2_diger = u.dis_ip(rng)
    while c2_diger == c2:
        c2_diger = u.dis_ip(rng)
    ic = u.ic_ip(rng)
    tur = rng.choice(["cron", "servis"])
    if tur == "cron":
        dosya = f"/etc/cron.d/{rng.choice(CRON_AD)}"
        mekanizma = ["cron", "crontab"]
    else:
        dosya = f"/etc/systemd/system/{rng.choice(SERVIS_AD)}.service"
        mekanizma = ["servis", "service", "systemd"]
    t_birak = gun + timedelta(hours=rng.randint(1, 5), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    t_kalici = t_birak + timedelta(seconds=rng.randint(20, 240))
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {m['sunucu']} süreç ve kalıcılık incelemesi",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "yol": [yol, yol.lstrip("/")],
            "pid": pid,
            "c2": c2,
            "mekanizma": mekanizma,
            "dosya": [dosya, dosya.lstrip("/"), Path(dosya).name],
            "zaman": t_birak.strftime("%H:%M:%S"),
        },
        "_kul": kul,
        "_gun": gun,
        "_yol": yol,
        "_pid": pid,
        "_c2": c2,
        "_c2_diger": c2_diger,
        "_ic": ic,
        "_tur": tur,
        "_dosya": dosya,
        "_port": rng.choice(HAVUZ_PORT),
        "_sik": rng.choice([5, 10, 15]),
        "_t_birak": t_birak,
        "_t_kalici": t_kalici,
        "_pid_diger": [rng.randint(40001, 50000) for _ in range(3)],
        "_yan_zaman": [rng.randint(0, 59) for _ in range(6)],
    }


def _ps(s: dict) -> str:
    kul = s["_kul"]
    satirlar = [
        ("root", 1, 0.0, 0.1, 169436, 11204, "?", "Ss", "Mar01", "0:04", "/sbin/init"),
        ("root", 2, 0.0, 0.0, 0, 0, "?", "S", "Mar01", "0:00", "[kthreadd]"),
        ("root", 412, 0.0, 0.2, 31288, 9876, "?", "Ss", "Mar01", "0:02", "/lib/systemd/systemd-journald"),
        ("root", 598, 0.0, 0.1, 25480, 6120, "?", "Ss", "Mar01", "0:00", "/usr/sbin/cron"),
        ("root", 812, 0.0, 0.1, 15852, 7040, "?", "Ss", "Mar01", "0:01", "/usr/sbin/sshd"),
        ("www-data", 903, 0.1, 0.9, 188420, 36212, "?", "S", "Mar01", "1:12", "/usr/sbin/apache2"),
        ("root", 1104, 0.0, 0.3, 112300, 14560, "?", "Ssl", "Mar01", "0:09",
         "/usr/bin/python3 /usr/bin/unattended-upgrade-shutdown"),
        ("root", 2210, 0.0, 0.1, 17800, 5300, "pts/0", "Ss", "08:02", "0:00", "/bin/bash"),
        (kul[0], s["_pid_diger"][0], 0.2, 0.2, 21500, 5400, "pts/1", "Ss", "09:15", "0:00", "-bash"),
        (kul[1], s["_pid_diger"][1], 46.0, 1.2, 98200, 24100, "pts/2", "R+", "10:41", "0:33",
         "/tmp/derleme/make -j4"),
        ("root", s["_pid_diger"][2], 0.0, 0.0, 8100, 3200, "pts/0", "R+", "11:20", "0:00", "ps aux"),
        ("root", s["_pid"], 98.7, 3.4, 712000, 140200, "?", "Sl", s["_t_birak"].strftime("%H:%M"), "812:44",
         f"{s['_yol']} -s {s['_port']} --quiet"),
    ]
    satirlar.sort(key=lambda x: x[1])
    ust = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    govde = [f"{a:<10} {b:>6} {c:>4} {d:>4} {e:>7} {f:>6} {g:<8} {h:<4} {i:<6} {j:>6} {k}"
             for a, b, c, d, e, f, g, h, i, j, k in satirlar]
    return ust + "\n" + "\n".join(govde) + "\n"


def _ss(s: dict) -> str:
    ic = s["_ic"]
    ust = "Netid State  Recv-Q Send-Q Local:Port Peer:Port Process"
    satirlar = [
        'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
        'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("apache2",pid=903,fd=4))',
        f'tcp ESTAB 0 0 {ic}:22 10.99.0.{20 + s["_pid"] % 200}:51844 '
        'users:(("sshd",pid=2190,fd=4))',
        f'tcp ESTAB 0 0 {ic}:51022 {s["_c2_diger"]}:443 users:(("python3",pid=1104,fd=7))',
        f'tcp ESTAB 0 1432 {ic}:40196 {s["_c2"]}:{s["_port"]} users:(("{Path(s["_yol"]).name}",pid={s["_pid"]},fd=3))',
        'udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=655,fd=12))',
    ]
    return ust + "\n" + "\n".join(satirlar) + "\n"


def _zamanlama(s: dict) -> str:
    sik = s["_sik"]
    p = []
    p.append("==> /etc/crontab <==\nSHELL=/bin/sh\n"
             "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
             "25 6    * * *   root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily\n")
    p.append("==> /etc/cron.d/yedekle <==\n0 3 * * *  root  /usr/local/bin/yedekle.sh\n")
    p.append("==> /etc/cron.d/logrotate_ek <==\n30 4 * * 0  root  /usr/sbin/logrotate /etc/logrotate.conf\n")
    p.append("==> /etc/systemd/system/yedek-tetik.service <==\n[Unit]\nDescription=Yedek tetikleyici\n"
             "[Service]\nExecStart=/usr/local/bin/yedekle.sh\n[Install]\nWantedBy=multi-user.target\n")
    p.append("==> /etc/systemd/system/apache2-izle.service <==\n[Unit]\nDescription=Apache izleme\n"
             "[Service]\nExecStart=/usr/local/bin/apache_izle.sh\nRestart=on-failure\n"
             "[Install]\nWantedBy=multi-user.target\n")
    if s["_tur"] == "cron":
        p.append(f"==> {s['_dosya']} <==\n*/{sik} * * * *  root  {s['_yol']} -s {s['_port']} --quiet >/dev/null 2>&1\n")
    else:
        ad = Path(s["_dosya"]).stem
        p.append(f"==> {s['_dosya']} <==\n[Unit]\nDescription={ad}\nAfter=network.target\n"
                 f"[Service]\nExecStart={s['_yol']} -s {s['_port']} --quiet\nRestart=always\nRestartSec=30\n"
                 "[Install]\nWantedBy=multi-user.target\n")
    return "\n".join(p)


def _degisen(s: dict) -> str:
    gun = s["_gun"]
    f = s["_yan_zaman"]
    kul = s["_kul"]
    sat = [
        (gun + timedelta(hours=1, minutes=f[0], seconds=f[1]), "root", "0640", "/var/log/auth.log"),
        (gun + timedelta(hours=2, minutes=f[2], seconds=f[3]), "root", "0644", "/var/lib/apt/periodic/update-success-stamp"),
        (gun + timedelta(hours=6, minutes=f[4], seconds=f[5]), kul[0], "0644", f"/home/{kul[0]}/rapor_taslak.xlsx"),
        (gun + timedelta(hours=7, minutes=f[0]), kul[1], "0755", "/tmp/derleme/make"),
        (s["_t_birak"], "root", "0755", s["_yol"]),
        (s["_t_kalici"], "root", "0644", s["_dosya"]),
    ]
    sat.sort(key=lambda x: x[0])
    return "".join(f"{t:%Y-%m-%d %H:%M:%S} {o} {m} {y}\n" for t, o, m, y in sat)


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "ps.txt", _ps(s))
    u.yaz(lab / "ss.txt", _ss(s))
    u.yaz(lab / "zamanlama.txt", _zamanlama(s))
    u.yaz(lab / "degisen_dosyalar.txt", _degisen(s))


def _yol_hata(g, beklenen, b):
    if g == norm(Path(b.senaryo["_yol"]).name):
        return "Süreç adı doğru ama tam yolu yaz; sürecin nereden çalıştığı da kanıttır."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    yol = _sh("awk '" + r"""$1=="root" && $11 ~ /^\/(tmp|dev\/shm|var\/tmp)\//{print $11}""" + "' ps.txt | head -1", lab)
    pid = _sh("awk '" + r"""$1=="root" && $11 ~ /^\/(tmp|dev\/shm|var\/tmp)\//{print $2}""" + "' ps.txt | head -1", lab)
    c2 = _sh(f"grep 'pid={pid},' ss.txt | awk '{{print $6}}' | cut -d: -f1 | head -1", lab)
    dosya = _sh(f"awk -v y='{yol}' '/^==> /{{f=$2}} index($0,y){{print f; exit}}' zamanlama.txt", lab)
    mekanizma = "cron" if "cron" in dosya else "servis"
    zaman = _sh(f"awk -v y='{yol}' '$5==y {{print $2}}' degisen_dosyalar.txt", lab)
    secim = SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]
    return {1: yol, 2: pid, 3: c2, 4: mekanizma, 5: dosya, 6: zaman, 7: secim}


GOREVLER = [
    Gorev("`ps.txt` bir `ps aux` anlık görüntüsü. **Root** olarak, `/tmp`, `/dev/shm` ya da `/var/tmp` gibi "
          "olağandışı bir yerden çalışan sürecin **tam yolu** ne?",
          Metin("yol", sik_hatalar=_yol_hata, bicim="dosya yolu"),
          ("Sistem programları /usr, /sbin, /lib gibi yerlerden çalışır. Geçici dizinden çalışan root süreci arıyorsun.",
           "COMMAND sütunu 11. alan; kullanıcı 1. alan. `awk` ile iki koşulu birleştir.",
           "`awk '$1==\"root\" && $11 ~ /^\\/(tmp|dev\\/shm|var\\/tmp)\\//' ps.txt` — /tmp'ten çalışan root dışı süreç tuzaktır."),
          puan=15, baslik="Şüpheli süreç"),
    Gorev("Aynı şüpheli sürecin **PID**'i kaç?",
          Sayi("pid"),
          ("PID, `ps aux` çıktısında ikinci sütun.",
           "Bir önceki görevin awk komutunda `print $11` yerine `print $2` yaz.",
           "`awk '$1==\"root\" && $11 ~ /^\\/(tmp|dev\\/shm|var\\/tmp)\\//{print $2}' ps.txt`"),
          puan=10, baslik="PID"),
    Gorev("`ss.txt` bir `ss -tunap` anlık görüntüsü. Bu PID'nin bağlı olduğu **dış (C2) IP adresi** hangisi?",
          IP("c2"),
          ("Son sütun hangi sürecin bağlantıyı açtığını gösterir: `pid=...`.",
           "PID'ye göre `grep` ile satırı bul; Peer sütunundaki IP:port'un IP kısmını al. Başka bir sürecin dış bağlantısı da var.",
           "`grep 'pid=<PID>,' ss.txt | awk '{print $6}' | cut -d: -f1`"),
          puan=15, baslik="C2 adresi"),
    Gorev("Saldırgan süreci nasıl **kalıcı** yapmış? Mekanizmayı yaz: `cron` mu, `servis` (systemd) mi?",
          Metin("mekanizma", bicim="cron ya da servis"),
          ("`zamanlama.txt` cron dosyalarını ve systemd servis dosyalarını art arda gösteriyor.",
           "Şüpheli sürecin yolunu `zamanlama.txt` içinde ara: `grep` ile hangi bölümde geçtiğine bak.",
           "`grep -n '<süreç yolu>' zamanlama.txt` — satırın üstündeki `==> ... <==` başlığı bölümün adını verir."),
          puan=15, baslik="Kalıcılık türü"),
    Gorev("Kalıcılığı kuran **dosyanın yolunu** yaz (`==> ... <==` başlığındaki yol).",
          Metin("dosya", bicim="dosya yolu"),
          ("Şüpheli yolu içeren satır bir dosyanın bölümünde; başlık satırı dosyanın yolunu verir.",
           "Başlıklar `==>` ile başlıyor. Yolu bulduğun satırdan geriye doğru ilk başlığa bak.",
           "`awk '/^==> /{f=$2} /<süreç yolu>/{print f}' zamanlama.txt`"),
          puan=20, baslik="Kalıcılık dosyası"),
    Gorev("`degisen_dosyalar.txt` son değişen dosyaları gösteriyor. Şüpheli yürütülebilir dosya sunucuya "
          "**hangi saatte** (SS:DD:SS) bırakılmış?",
          Metin("zaman", bicim="SS:DD:SS"),
          ("Her satırda tarih, saat, sahip, izin ve yol var; senin dosyan listede.",
           "Yol 5. alan, saat 2. alan. Yolu `awk` ile eşleştir.",
           "`awk '$5==\"<süreç yolu>\" {print $2}' degisen_dosyalar.txt` — cron/servis dosyası daha sonra eklenmiştir."),
          puan=15, baslik="Bırakılış saati"),
    Gorev("Canlı sunucuda bu bulgulardan sonra **doğru müdahale sırası** hangisi?",
          Secmeli([
              ("Önce sunucuyu ağdan izole et, bellek ve disk imajı al; sonra süreci sonlandır, kalıcılığı kaldır, "
               "kimlik bilgilerini yenile",
               "Doğru. Önce yayılmayı ve C2'yi kes, sonra kanıtı koru; süreci öldürmek bellekteki kanıtı yok eder, "
               "bu yüzden imaj temizlikten önce gelir."),
              ("Süreci hemen `kill -9` ile öldür, dosyayı sil, sonra sunucuyu yeniden başlat",
               "Bellekteki kanıt (anahtarlar, bağlantılar) kaybolur; kalıcılık duruyorsa süreç geri gelir."),
              ("Sadece cron/servis dosyasını sil ve işin bittiğini varsay",
               "Çalışan süreç ve açık bağlantı sürer; ayrıca saldırganın nasıl girdiğini bilmeden başka kapılar kalır."),
              ("Sunucuyu yeniden başlat; geçici dizindeki dosyalar silinir, sorun kendiliğinden biter",
               "Cron/servis kalıcılığı yeniden başlatmada süreci geri getirir, kanıt da kaybolur."),
          ]),
          ("Kanıtı kaybetmeden saldırganın erişimini kesmen gerek.",
           "Süreç sonlanınca bellekteki izler gider; yayılma ve C2 ise hemen kesilmeli.",
           "İzole et, imaj al, sonra temizle."),
          puan=20, baslik="Müdahale sırası"),
]

SEVIYE = Seviye(
    kimlik="olay_adli",
    cilt=1,
    bolum=108,
    baslik="Süreç ve Kalıcılık Adli İncelemesi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> **<<sunucu>>** sunucusundan dört anlık görüntü aldı: `ps.txt` (süreçler), `ss.txt`
(ağ bağlantıları), `zamanlama.txt` (cron ve systemd) ve `degisen_dosyalar.txt` (son değişen dosyalar)."

"Bunlar gerçek süreç değil, sadece metin dosyaları: güvenle oku. Şüpheli süreci bul, hangi dış
adrese bağlandığını söyle, geri gelmesini sağlayan kalıcılığı yakala. Sonra canlı sunucuda önce
neyi yapacağımıza karar ver."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Canlı müdahalede sıra önemlidir: önce yayılmayı ve C2'yi kesmek için izole et, sonra kanıtı
(bellek, süreç listesi, disk imajı) koru, en son temizle. Süreci erkenden öldürmek ya da yeniden
başlatmak en değerli kanıtı siler. Kalıcılık avı için cron, systemd servisleri, başlangıç
betikleri ve SSH anahtarlarını düzenli tara; geçici dizinlerden çalışan root süreçleri her zaman
şüphelidir. Bunu ölçekte yapan araç EDR'dir: uç noktada süreç ağacını, ağ bağlantısını ve dosya
değişikliğini kaydeder, şüpheli davranışta makineyi tek tuşla izole eder.
""",
    gercek_hayat="""
- **Kripto-madenci kalıcılığı:** Yamalanmamış Redis, Docker API ve Jenkins gibi servislere sızan
  gruplar (Kinsing ve benzeri kampanyalar), `/tmp` ya da `/dev/shm` altına madenci bırakıp
  cron ile her dakika yeniden başlatır. Belirtisi sürekli yüksek CPU ve bir havuz adresine
  uzun süreli bağlantıdır.
- **Cron ile kalıcılık:** Kötücül yazılımlar `/etc/cron.d` ya da kullanıcı crontab'ına tek bir
  satır ekleyerek süreci öldürüldüğünde bile geri getirir; MITRE ATT&CK bunu T1053 olarak
  listeler, systemd servisleri ise T1543 altındadır.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c01b06",),
)
