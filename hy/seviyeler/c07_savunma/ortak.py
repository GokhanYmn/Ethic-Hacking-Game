"""Cilt 7 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

- `sh`            : bash ile komut çalıştırır (test çözücüleri için).
- `Sira`          : numaralı adımları doğru sıraya dizdirme kontrolü.
- `fw_logu`       : güvenlik duvarı logu (iptables ya da anahtar=değer biçimi).
- `tam_olay`      : web + SSH + güvenlik duvarı loglarından oluşan tek, tutarlı olay.
- `host_izleri`   : ele geçirilmiş sunucunun artefaktları (ps, ss, passwd, cron...).
Saldırı yükü ya da çalışır kod içermez; bütün izler düz metindir.
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Kontrol, Secmeli, Sonuc
from hy.ortak import loglar
from hy.ortak import uretec as u

# ----------------------------------------------------------------------------- küçük araçlar


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


_TR = str.maketrans("ıİöÖüÜşŞçÇğĞ", "iIoOuUsScCgG")


def ascii_norm(s: str) -> str:
    return s.translate(_TR).strip().lower()


def saat_al(satir: str) -> str:
    """Satırdaki ilk SS:DD:SS metni."""
    m = re.search(r"\d{2}:\d{2}:\d{2}", satir)
    return m.group(0) if m else ""


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Test çözücüsü için: çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır (rehber bölüm 10)."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


class Sira(Kontrol):
    """Numaralı öğeleri doğru sıraya dizme. Cevap: numaralar sırayla (`3 1 2 ...`)."""
    bicim = "numaralar sırayla, örn. 3 1 2"

    def __init__(self, anahtar: str, sik_hatalar=None):
        self.anahtar = anahtar
        self.sik_hatalar = sik_hatalar

    def dogrula(self, girdi: str, b) -> Sonuc:
        beklenen = [int(x) for x in self.beklenen(b)]
        verilen = [int(x) for x in re.findall(r"\d+", girdi)]
        if not verilen:
            return Sonuc(False, "Numaraları sırayla yaz, örn. `3 1 2`.")
        if verilen == beklenen:
            return Sonuc(True)
        if self.sik_hatalar:
            mesaj = self.sik_hatalar(verilen, beklenen, b)
            if mesaj:
                return Sonuc(False, mesaj, yakin=True)
        if len(verilen) != len(beklenen):
            return Sonuc(False, f"{len(beklenen)} numara bekleniyor, sen {len(verilen)} tane yazdın.")
        dogru = sum(1 for a, c in zip(verilen, beklenen) if a == c)
        return Sonuc(False, f"{dogru}/{len(beklenen)} numara doğru yerde." if dogru else "", yakin=dogru > 0)

    def cevabi_goster(self, b) -> str:
        return " ".join(str(x) for x in self.beklenen(b))


# ----------------------------------------------------------------------------- güvenlik duvarı logu

TARAMA_PORTLARI = [21, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 993, 1433, 3306, 3389, 5432,
                   5900, 8080, 8443, 9200]
SERBEST_PORTLAR = [22, 80, 443]
FW_BICIMLERI = ("iptables", "anahtar")


def fw_satiri(bicim: str, t: datetime, ip: str, hedef: str, dport: int, eylem: str, sport: int, ad: str) -> str:
    if bicim == "iptables":
        return (f"{u.syslog_zamani(t)} {ad} kernel: [FW-{eylem}] IN=eth0 OUT= SRC={ip} DST={hedef} "
                f"PROTO=TCP SPT={sport} DPT={dport} SYN")
    return (f"{t:%Y-%m-%dT%H:%M:%S}+03:00 {ad} action={eylem.lower()} proto=tcp src={ip} dst={hedef} "
            f"sport={sport} dport={dport}")


def fw_logu(rng, bas: datetime, saldirgan: str, hedef: str, bicim: str, haric: set, mesru: list,
            ad: str = "fw01") -> dict:
    """Saldırganın port taraması + arka plan gürültüsü. `bas`: taramanın başlangıcı."""
    portlar = rng.sample(TARAMA_PORTLARI, rng.randint(12, 18))
    olaylar = []                      # (t, ip, port, eylem, sport)
    t = bas
    sport = rng.randint(33000, 60000)
    sira = portlar + rng.sample(SERBEST_PORTLAR, rng.randint(1, 3))
    rng.shuffle(sira)
    for p in sira:
        t += timedelta(seconds=rng.choice([0, 1, 1, 2]))
        olaylar.append((t, saldirgan, p, "ACCEPT" if p in SERBEST_PORTLAR else "DROP", sport))
    for p in rng.sample(portlar, rng.randint(3, 5)):          # tekrar denemeler: satır sayısı ≠ port sayısı
        olaylar.append((bas + timedelta(seconds=rng.randint(0, max(1, int((t - bas).total_seconds())))),
                        saldirgan, p, "DROP", sport + 1))
    kullanilan = set(haric) | {saldirgan}
    for _ in range(rng.randint(4, 7)):                        # arka plan gürültüsü
        ip = u.dis_ip(rng)
        while ip in kullanilan:
            ip = u.dis_ip(rng)
        kullanilan.add(ip)
        for _ in range(rng.randint(2, 6)):
            olaylar.append((bas + timedelta(seconds=rng.randint(-1800, 5400)), ip,
                            rng.choice([23, 445, 3389, 1433, 5900, 22]), "DROP", rng.randint(33000, 60000)))
    for ip in mesru:
        for _ in range(rng.randint(1, 3)):
            olaylar.append((bas + timedelta(seconds=rng.randint(-1800, 5400)), ip,
                            rng.choice([443, 443, 80]), "ACCEPT", rng.randint(33000, 60000)))
    olaylar.sort(key=lambda x: x[0])
    satirlar = [fw_satiri(bicim, t, ip, hedef, p, e, sp, ad) for t, ip, p, e, sp in olaylar]
    ilk = next(t for t, ip, *_ in olaylar if ip == saldirgan)
    dsat = [x for x in olaylar if x[1] == saldirgan and x[3] == "DROP"]
    accept = {x[2] for x in olaylar if x[1] == saldirgan and x[3] == "ACCEPT"}
    return {"satirlar": satirlar, "ilk": f"{ilk:%H:%M:%S}", "drop_port": len({x[2] for x in dsat}),
            "drop_satir": len(dsat), "accept_port": len(accept),
            "satir_toplam": sum(1 for x in olaylar if x[1] == saldirgan),
            "ipler": sorted(kullanilan - set(haric) - {saldirgan})}


# ----------------------------------------------------------------------------- tam olay (web + ssh + fw)

OLAY_ADLARI = [
    "Güvenlik duvarında saldırgan IP'nin ilk kaydı",
    "Web sunucusundan sızan yedek dosyanın indirilmesi (HTTP 200)",
    "Aynı IP'nin SSH ile parolayla başarılı girişi",
    "sudo ile root kabuğunun açılması",
    "Yeni kullanıcı hesabının oluşturulması (useradd)",
    "SSH'ta root hesabına ilk parola denemesi",
]


def tam_olay(rng, m: dict, bicim: str) -> dict:
    """Tek aktörlü (SSH'a giren IP = yedeği indiren IP) tutarlı olay. Altı olay anı birbirinden farklıdır."""
    for _ in range(60):
        o = loglar.olay_uret(rng, m, ayni_aktor=True)
        web, ssh = o["web"], o["ssh"]
        tarama, ele = web["saldirilar"]["tarama"], ssh["ele_gecirme"]
        gun = web["baslangic"].replace(hour=0, minute=0, second=0, microsecond=0)
        ilk_istek = datetime.strptime(f"{gun:%Y-%m-%d} {tarama['ilk']}", "%Y-%m-%d %H:%M:%S")
        fw_bas = ilk_istek - timedelta(minutes=rng.randint(5, 15), seconds=rng.randint(0, 59))
        yeni_zaman = next(saat_al(s) for s in ssh["satirlar"] if "new user:" in s)
        root_deneme = next(saat_al(s) for s in ssh["satirlar"] if "Failed password for root" in s)
        hedef = u.ic_ip(rng, "10.20.0")
        fw = fw_logu(rng, fw_bas, tarama["ip"], hedef, bicim, set(web["ipler"]) | set(ssh["ipler"]),
                     web["mesru"][:3], ad="fw-" + m["kod"][:3])
        zamanlar = [fw["ilk"], tarama["zaman"], ele["zaman"], ele["root_zaman"], yeni_zaman, root_deneme]
        if len(set(zamanlar)) == 6:
            sirali = sorted(range(6), key=lambda i: zamanlar[i])
            return {"olay": o, "web": web, "ssh": ssh, "fw": fw, "ip": tarama["ip"], "zamanlar": zamanlar,
                    "sira": sirali, "yeni_zaman": yeni_zaman, "hedef": hedef}
    raise RuntimeError("Olay anları ayrışmadı")


# ----------------------------------------------------------------------------- ele geçirilmiş sunucu artefaktları

NORMAL_SURECLER = [
    ("root", "/sbin/init"), ("root", "/usr/sbin/sshd -D"), ("root", "/usr/sbin/cron -f"),
    ("syslog", "/usr/sbin/rsyslogd -n"), ("root", "/usr/lib/systemd/systemd-journald"),
    ("www-data", "/usr/sbin/apache2 -k start"), ("mysql", "/usr/sbin/mysqld"),
    ("root", "/usr/sbin/apache2 -k start"), ("messagebus", "/usr/bin/dbus-daemon --system"),
]
SAHTE_IKILI_ADLARI = [".guncelleme_servisi", ".sistem_yardimci", ".log_toplayici", ".onbellek_surucu", ".ag_izleyici"]
_ALFA = "abcdefghijklmnopqrstuvwxyz0123456789"


def host_izleri(rng, m: dict, yeni: str, saldirgan_ip: str, giris: datetime, anahtar_olsun: bool,
                hesaplar: list | None = None) -> dict:
    """ps, ss, passwd, cron ve (isteğe bağlı) yetkili anahtar kopyaları. Dosya içerikleri + cevaplar."""
    ikili = "/var/tmp/" + rng.choice(SAHTE_IKILI_ADLARI)
    ad = ikili.rsplit("/", 1)[1]
    pids = sorted(rng.sample(range(300, 2400), len(NORMAL_SURECLER)))
    satir = []
    for (kul, kmt), pid in zip(NORMAL_SURECLER, pids):
        satir.append((pid, f"{kul:<12}{pid:>5}  0.{rng.randint(0, 9)}  {rng.randint(0, 3)}.{rng.randint(0, 9)} "
                           f"{rng.randint(15000, 240000):>6} {rng.randint(3000, 90000):>5} ?        Ss   Nov10   "
                           f"0:0{rng.randint(1, 9)} {kmt}"))
    sup_pid = rng.randint(5200, 9800)
    yeni_t = giris + timedelta(minutes=rng.randint(4, 9))
    satir.append((sup_pid, f"{yeni:<12}{sup_pid:>5} 38.{rng.randint(0, 9)}  1.2 {rng.randint(90000, 200000):>6} "
                           f"{rng.randint(20000, 60000):>5} ?        Sl   {yeni_t:%H:%M}  {rng.randint(11, 59)}:"
                           f"{rng.randint(10, 59)} {ikili}"))
    ps_pid = rng.randint(9900, 12000)
    satir.append((ps_pid, f"kali        {ps_pid:>5}  0.0  0.1  10532  3700 pts/0    R+   {yeni_t:%H:%M}   0:00 ps aux"))
    ps = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"] + [s for _, s in sorted(satir)]
    c2 = u.dis_ip(rng)
    while c2 == saldirgan_ip:
        c2 = u.dis_ip(rng)
    ic = u.ic_ip(rng, "10.20.0")
    ss = ["Netid State  Recv-Q Send-Q    Local Address:Port      Peer Address:Port Process",
          f'tcp   LISTEN 0      128             0.0.0.0:22             0.0.0.0:*     users:(("sshd",pid={pids[1]},fd=3))',
          f'tcp   LISTEN 0      511                   *:80                   *:*     users:(("apache2",pid={pids[5]},fd=4))',
          f'tcp   LISTEN 0      70            127.0.0.1:3306           0.0.0.0:*     users:(("mysqld",pid={pids[6]},fd=21))',
          f'tcp   ESTAB  0      0              {ic}:22      {saldirgan_ip}:{rng.randint(30000, 60000)}   users:(("sshd",pid={sup_pid - 40},fd=4))',
          f'tcp   ESTAB  0      0              {ic}:{rng.randint(40000, 60000)}   {c2}:8443    users:(("{ad[1:]}",pid={sup_pid},fd=3))']
    sistem_kul = [("root", 0, "/root", "/bin/bash"), ("daemon", 1, "/usr/sbin", "/usr/sbin/nologin"),
                  ("www-data", 33, "/var/www", "/usr/sbin/nologin"), ("mysql", 110, "/nonexistent", "/bin/false")]
    passwd = [f"{k}:x:{uid}:{uid}:{k}:{ev}:{kabuk}" for k, uid, ev, kabuk in sistem_kul]
    yoneticiler = list(hesaplar) if hesaplar else u.isimler(rng, 2, haric={yeni})
    for i, y in enumerate(yoneticiler):
        passwd.append(f"{y}:x:{1000 + i}:{1000 + i}:{y.capitalize()}:/home/{y}:/bin/bash")
    yuid = 1000 + len(yoneticiler) + 1
    passwd.append(f"{yeni}:x:{yuid}:{yuid}::/home/{yeni}:/bin/bash")
    cron = ["# m h  dom mon dow   command", "17 * * * * cd / && run-parts --report /etc/cron.hourly",
            "30 2 * * * /usr/local/bin/yedek_al.sh", "0 4 * * 0 /usr/local/bin/log_donder.sh"]
    dk = rng.choice([5, 10, 15])
    cron.insert(rng.randint(2, 3), f"*/{dk} * * * * {ikili} >/dev/null 2>&1")
    kimlikler, yabanci = [], None
    if anahtar_olsun:
        for y in yoneticiler[:2]:
            kimlikler.append("ssh-ed25519 AAAA" + "".join(rng.choice(_ALFA) for _ in range(24)) + f" {y}@{m['sunucu']}")
        yabanci = "ssh-ed25519 AAAA" + "".join(rng.choice(_ALFA) for _ in range(24)) + " destek@gecici-laptop"
        kimlikler.insert(rng.randint(0, len(kimlikler)), yabanci)
    return {"ikili": ikili, "ps": "\n".join(ps) + "\n", "ss": "\n".join(ss) + "\n", "passwd": "\n".join(passwd) + "\n",
            "cron": "\n".join(cron) + "\n", "pid": sup_pid, "c2": c2, "dakika": dk, "anahtarlar": kimlikler,
            "yabanci_anahtar": yabanci, "yoneticiler": yoneticiler, "yeni_uid": yuid}
