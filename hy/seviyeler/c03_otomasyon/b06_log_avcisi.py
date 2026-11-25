"""Cilt 3 · Bölüm 6 — Log Analiz Aracı: Brute-Force Avcısı.

Beceri: re.compile + search ile desen ve yakalama grubu, collections.Counter ve most_common,
eşik parametresi (sys.argv), "Failed password for invalid user" satırlarını kaçırmamak,
başarısız denemelerden sonra gelen başarılı girişle gerçek ihlali ayırmak, dağıtık ("düşük ve
yavaş") saldırıyı kullanıcı adı üzerinden görmek.

Laboratuvar: birkaç bin satırlık gerçekçi bir auth.log (cron, sudo, meşru girişler, parolasını
yanlış yazan çalışanlar, brute-force yapan IP'ler, eşiğin hemen altında/üstünde kalanlar, bir
gerçek ihlal ve dağıtık bir deneme). Oyun oyuncunun aracını lab logunda verilen eşikle ve
kontrol anında üretilen yeni bir logda başka eşiklerle çalıştırır.
"""
from __future__ import annotations

import os
import random
import re
import subprocess
import tempfile
from collections import Counter
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {"kod": "kuzgun", "sunucu": "kzg-depo", "ag": "10.30.8", "servis": ["yedek", "depo_sync", "etiket"],
     "olay": "Depo sunucusu kzg-depo'da gece bir sevkiyat kaydı silinmiş. Serdar Bey sunucuya kimin girdiğini "
             "bilmek istiyor; elimizde son 24 saatin auth.log kopyası var."},
    {"kod": "ferahbank", "sunucu": "fb-bastion", "ag": "10.50.1", "servis": ["denetim", "yedek", "otomasyon"],
     "olay": "Ferah Bank'ın internet şubesi sunucularına giriş kapısı olan fb-bastion'da gece yarısı alarm düştü. "
             "Kaan Bey, alarmın gerçek bir ihlal mi yoksa gürültü mü olduğunu soruyor."},
    {"kod": "medora", "sunucu": "medora-portal", "ag": "172.16.20", "servis": ["yedek", "rapor", "hl7"],
     "olay": "Hasta portalı medora-portal'da bir hastanın başkasının bilgilerini görmesinden sonra Dr. Aslı Hanım "
             "sunucunun SSH loglarının da incelenmesini istedi."},
    {"kod": "paramix", "sunucu": "pmx-api01", "ag": "10.12.0", "servis": ["deploy", "mutabakat", "izleme"],
     "olay": "Paramix'in ödeme API sunucusu pmx-api01'de bir üye işyeri kendine ait olmayan işlemler gördü. "
             "Ece Hanım sunucuya yetkisiz bir giriş olup olmadığını öğrenmek istiyor."},
    {"kod": "yesiltepe", "sunucu": "ytb-ebelediye", "ag": "192.168.40", "servis": ["yedek", "vezne", "ebys"],
     "olay": "E-belediye sunucusu ytb-ebelediye'de borç sorgulama sayfası çöktükten sonra Nurcan Hanım "
             "sunucunun SSH loglarında bir saldırı izi olup olmadığını soruyor."},
]

ESKI_KULLANICI = ["admin", "test", "oracle", "ubuntu", "user", "postgres", "git", "pi", "guest", "ftpuser",
                  "support", "administrator", "mysql", "www-data", "minecraft"]


class _Log:
    """auth.log satırlarını zaman damgasıyla toplar."""

    def __init__(self, rng, sunucu: str):
        self.rng = rng
        self.sunucu = sunucu
        self.olaylar = []
        self.pid = rng.randint(1200, 4000)

    def ekle(self, t, surec: str, metin: str, pid: int | None = None):
        if pid is None:
            self.pid += self.rng.randint(1, 37)
            pid = self.pid
        etiket = surec if pid == 0 else f"{surec}[{pid}]"      # sudo satırlarında PID olmaz
        self.olaylar.append((t, f"{u.syslog_zamani(t)} {self.sunucu} {etiket}: {metin}"))
        return pid

    def satirlar(self) -> list:
        return [s for _, s in sorted(self.olaylar, key=lambda x: x[0])]


def _deneme(log: _Log, t, ip: str, kullanici: str, gecersiz: bool):
    rng = log.rng
    port = rng.randint(30000, 65000)
    if gecersiz:
        pid = log.ekle(t, "sshd", f"Invalid user {kullanici} from {ip} port {port}")
        log.ekle(t + timedelta(seconds=2), "sshd",
                 f"Failed password for invalid user {kullanici} from {ip} port {port} ssh2", pid)
        if rng.random() < 0.4:
            log.ekle(t + timedelta(seconds=3), "sshd",
                     f"Disconnected from invalid user {kullanici} {ip} port {port} [preauth]", pid)
    else:
        pid = log.ekle(t, "sshd", f"Failed password for {kullanici} from {ip} port {port} ssh2")
        if rng.random() < 0.3:
            log.ekle(t + timedelta(seconds=2), "sshd",
                     f"Connection closed by authenticating user {kullanici} {ip} port {port} [preauth]", pid)


def _giris(log: _Log, t, kullanici: str, ip: str, yontem: str, uid: int):
    port = log.rng.randint(30000, 65000)
    ek = f": RSA SHA256:{''.join(log.rng.choice('ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789') for _ in range(43))}" \
        if yontem == "publickey" else ""
    pid = log.ekle(t, "sshd", f"Accepted {yontem} for {kullanici} from {ip} port {port} ssh2{ek}")
    log.ekle(t + timedelta(seconds=1), "sshd",
             f"pam_unix(sshd:session): session opened for user {kullanici}(uid={uid}) by (uid=0)", pid)
    log.ekle(t + timedelta(seconds=1), "systemd-logind", f"New session {log.rng.randint(10, 999)} of user {kullanici}.")
    return pid


def log_uret(rng: random.Random, v: dict, esik: int, olcek: float = 1.0, gurultu: bool = True) -> tuple:
    """(satırlar, bilgi). bilgi: ihlal ip/kullanıcı/saat, dağıtık hedef, saldırgan sayıları."""
    log = _Log(rng, v["sunucu"])
    gun = u.gun(rng)
    kullanicilar = u.isimler(rng, 6)
    hesaplar = kullanicilar + v["servis"]
    uid = {k: 1001 + i for i, k in enumerate(hesaplar)}
    uid["root"] = 0
    gun_sonu = gun + timedelta(hours=23, minutes=50)

    def zaman(bas=0, son=23.5):
        return gun + timedelta(seconds=rng.randint(int(bas * 3600), int(son * 3600)))

    if gurultu:
        t = gun + timedelta(minutes=rng.randint(0, 4))
        while t < gun_sonu:          # cron: birkaç dakikada bir
            pid = log.ekle(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            log.ekle(t + timedelta(seconds=rng.randint(1, 50)), "CRON",
                     "pam_unix(cron:session): session closed for user root", pid)
            t += timedelta(minutes=rng.choice([1, 1, 2, 3]))
        for k in kullanicilar:      # meşru girişler + sudo
            for _ in range(rng.randint(2, 5)):
                t = zaman(7, 19)
                ip = u.ic_ip(rng, v["ag"])
                pid = _giris(log, t, k, ip, rng.choice(["publickey", "publickey", "password"]), uid[k])
                if rng.random() < 0.5:
                    komut = rng.choice(["/usr/bin/systemctl restart nginx", "/usr/bin/apt update",
                                        "/usr/bin/journalctl -u ssh", "/usr/bin/tail -f /var/log/syslog"])
                    log.ekle(t + timedelta(minutes=2), "sudo",
                             f"   {k} : TTY=pts/{rng.randint(0, 4)} ; PWD=/home/{k} ; USER=root ; COMMAND={komut}", 0)
                log.ekle(t + timedelta(minutes=rng.randint(5, 90)), "sshd",
                         f"pam_unix(sshd:session): session closed for user {k}", pid)

    # Parolasını yanlış yazan çalışanlar: 1-2 başarısız, sonra başarılı (yanlış pozitif tuzağı)
    yanlis_yazanlar = {}
    for k in rng.sample(kullanicilar, 2):
        ip = u.ic_ip(rng, v["ag"])
        t = zaman(8, 18)
        n = rng.randint(1, min(2, esik - 1))
        for i in range(n):
            _deneme(log, t + timedelta(seconds=i * 9), ip, k, False)
        _giris(log, t + timedelta(seconds=n * 9 + 5), k, ip, "password", uid[k])
        yanlis_yazanlar[ip] = n

    # Brute-force yapan IP'ler: biri tam eşikte, biri eşiğin bir altında, gerisi çok üstünde
    saldirgan = {}
    adaylar = u.benzersiz(rng, u.dis_ip, 30, set(yanlis_yazanlar))
    sayilar = [esik, esik - 1] + [int(rng.randint(3 * esik, 18 * esik) * olcek) + esik
                                   for _ in range(rng.randint(2, 4))]
    for ip, n in zip(adaylar, sayilar):
        saldirgan[ip] = n
    # Gerçek ihlal: çok sayıda başarısız denemeden sonra bir hesapla başarılı giriş
    ihlal_ip = adaylar[len(sayilar)]
    ihlal_kullanici = rng.choice([s for s in v["servis"]])
    saldirgan[ihlal_ip] = int(rng.randint(3 * esik, 10 * esik) * olcek) + esik
    for ip, n in saldirgan.items():
        bas = zaman(0, 20)
        hedef_kullanicilar = ["root"] + rng.sample(ESKI_KULLANICI, 4) + ([ihlal_kullanici] if ip == ihlal_ip else [])
        for i in range(n):
            kul = rng.choice(hedef_kullanicilar)
            if ip == ihlal_ip and i >= n - 3:
                kul = ihlal_kullanici
            gecersiz = kul in ESKI_KULLANICI
            _deneme(log, bas + timedelta(seconds=i * rng.randint(2, 6)), ip, kul, gecersiz)
        if ip == ihlal_ip:
            ihlal_t = bas + timedelta(seconds=n * 6 + rng.randint(5, 40))
            pid = _giris(log, ihlal_t, ihlal_kullanici, ip, "password", uid[ihlal_kullanici])
            log.ekle(ihlal_t + timedelta(minutes=1), "sudo",
                     f"{ihlal_kullanici} : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/{ihlal_kullanici} ; "
                     "USER=root ; COMMAND=/bin/bash", 0)
            log.ekle(ihlal_t + timedelta(minutes=rng.randint(8, 30)), "sshd",
                     f"pam_unix(sshd:session): session closed for user {ihlal_kullanici}", pid)
    # Dağıtık ("düşük ve yavaş") deneme: çok sayıda IP, her biri 1-2 deneme, aynı hesap
    dagitik_hedef = rng.choice([k for k in v["servis"] if k != ihlal_kullanici])
    dagitik_ipler = adaylar[len(sayilar) + 1: len(sayilar) + 1 + rng.randint(12, 18)]
    for ip in dagitik_ipler:
        for _ in range(rng.randint(1, min(2, esik - 1))):
            _deneme(log, zaman(), ip, dagitik_hedef, False)
            saldirgan[ip] = saldirgan.get(ip, 0) + 1
    bilgi = {
        "ihlal_ip": ihlal_ip, "ihlal_kullanici": ihlal_kullanici, "ihlal_saat": f"{ihlal_t:%H:%M:%S}",
        "dagitik_hedef": dagitik_hedef, "yanlis_yazanlar": yanlis_yazanlar,
    }
    return log.satirlar(), bilgi


DESEN = re.compile(r"Failed password.* from (\d+\.\d+\.\d+\.\d+)")


def basarisiz_say(satirlar) -> Counter:
    sayac = Counter()
    for s in satirlar:
        m = DESEN.search(s)
        if m:
            sayac[m.group(1)] += 1
    return sayac


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    esik = rng.choice([5, 6, 8, 10])
    veri_tohum = rng.randint(1, 10**9)
    satirlar, bilgi = log_uret(random.Random(veri_tohum), v, esik)
    sayac = basarisiz_say(satirlar)
    supheli = sorted(ip for ip, n in sayac.items() if n >= esik)
    en_fazla = sayac.most_common(1)[0][1]
    en_cok = sorted(ip for ip, n in sayac.items() if n == en_fazla)   # eşitlik olursa hepsi kabul
    return {
        "vaka": f"{m['ad']} — {v['sunucu']} auth.log incelemesi",
        "musteri": m,
        "v": v,
        "esik": esik,
        "veri_tohum": veri_tohum,
        "yanlis_yazanlar": sorted(bilgi["yanlis_yazanlar"]),
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "sunucu": v["sunucu"], "esik": esik,
            "satir": len(satirlar),
        },
        "cevaplar": {
            "supheli_sayi": len(supheli),
            "en_cok": en_cok,
            "ihlal_ip": bilgi["ihlal_ip"],
            "ihlal_kullanici": bilgi["ihlal_kullanici"],
            "ihlal_saat": bilgi["ihlal_saat"],
            "dagitik_hedef": bilgi["dagitik_hedef"],
        },
    }


REGEX_DENE_PY = r'''#!/usr/bin/env python3
# regex_dene.py — iki desenin aynı satırlarda ne yakaladığını karşılaştırır
import re

satirlar = [
    "Failed password for root from 203.0.113.9 port 40122 ssh2",
    "Failed password for invalid user admin from 198.51.100.4 port 51022 ssh2",
    "Invalid user admin from 198.51.100.4 port 51022",
    "Accepted publickey for ayse from 10.0.0.5 port 50211 ssh2",
]
dar = re.compile(r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)")
genis = re.compile(r"Failed password.* from (\d+\.\d+\.\d+\.\d+)")

for s in satirlar:
    m1, m2 = dar.search(s), genis.search(s)
    print(s)
    print("   dar  :", m1.group(2) if m1 else "-")
    print("   geniş:", m2.group(1) if m2 else "-")
'''

ISKELET_PY = r'''#!/usr/bin/env python3
# iskelet.py — log avcısının iskeleti (eksik parçalar ... ile işaretli)
import re
import sys
from collections import Counter

desen = re.compile(r"Failed password.* from (\d+\.\d+\.\d+\.\d+)")
sayac = Counter()

with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for satir in f:
        eslesme = desen.search(satir)
        if eslesme:
            sayac[eslesme.group(1)] += 1      # group(1): parantez içinde yakalanan IP

for ip, adet in sayac.most_common(5):        # en çoktan en aza ilk 5
    print(f"{adet:4d}  {ip}")

# Eksikler: kullanım mesajı, eşik argümanı (sys.argv[2], verilmezse 3),
# dosya yoksa düzgün hata, eşiği aşanları "ŞÜPHELİ" diye işaretlemek, hepsini yazmak.
'''

LOGAVCI_PY = r'''#!/usr/bin/env python3
import re
import sys
from collections import Counter

if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <auth.log> [esik]")
    sys.exit(1)

log = sys.argv[1]
esik = int(sys.argv[2]) if len(sys.argv) > 2 else 3
ip_deseni = re.compile(r"Failed password.* from (\d+\.\d+\.\d+\.\d+)")
sayac = Counter()
try:
    with open(log, encoding="utf-8", errors="replace") as f:
        for satir in f:
            eslesme = ip_deseni.search(satir)
            if eslesme:
                sayac[eslesme.group(1)] += 1
except FileNotFoundError:
    print(f"Hata: {log} bulunamadı.")
    sys.exit(1)

print(f"[*] Başarısız giriş denemeleri (eşik: {esik}):\n")
for ip, adet in sayac.most_common():
    isaret = "  <-- ŞÜPHELİ" if adet >= esik else ""
    print(f"  {adet:3d}  {ip}{isaret}")
'''


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    satirlar, _ = log_uret(random.Random(s["veri_tohum"]), v, s["esik"])
    u.yaz(lab / "loglar" / "auth.log", "\n".join(satirlar) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['sunucu']} sunucusunun son 24 saatlik auth.log kopyası\n\n"
          f"Log        : loglar/auth.log ({len(satirlar)} satır)\n"
          f"Eşik (SOC) : {s['esik']} başarısız deneme ve üstü = şüpheli\n\n"
          "Kendi aracını lab'ın köküne yaz: logavci.py\n"
          f"Kullanım   : python3 logavci.py loglar/auth.log {s['esik']}\n")
    u.yaz(lab / "ornekler" / "regex_dene.py", REGEX_DENE_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "iskelet.py", ISKELET_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "cilt1_yontemi.sh",
          "#!/bin/bash\n# Cilt 1 yöntemi: boru hattıyla IP başına başarısız deneme sayısı\n"
          "grep 'Failed password' loglar/auth.log | grep -oE 'from [0-9.]+' \\\n"
          "    | sort | uniq -c | sort -rn | head -5\n", mod=0o755)


# ---------------------------------------------------------------- denetimler

def _arac_cikti(c: bt.Cikti) -> dict:
    """{ip: (adet, işaretli_mi)} — tek IP içeren satırlardan."""
    sonuc = {}
    for satir in c.stdout.splitlines():
        ipler = bt.ipler(satir)
        if len(ipler) != 1:
            continue
        sayilar = bt.sayilar(satir)
        if not sayilar:
            continue
        a = bt.ascii_kucuk(satir)
        sonuc[ipler[0]] = (sayilar[0], "supheli" in a or "alarm" in a or "suspicious" in a)
    return sonuc


def _dar_say(satirlar) -> Counter:
    desen = re.compile(r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)")
    sayac = Counter()
    for s in satirlar:
        m = desen.search(s)
        if m:
            sayac[m.group(2)] += 1
    return sayac


def _her_ip_say(satirlar) -> Counter:
    sayac = Counter()
    for s in satirlar:
        for ip in set(bt.ipler(s)):
            sayac[ip] += 1
    return sayac


def _calistir_karsilastir(calistir: bt.Calistirici, dosya: Path, esik: int | None, goster: str) -> Sonuc | None:
    satirlar = dosya.read_text(encoding="utf-8", errors="replace").splitlines()
    sayac = basarisiz_say(satirlar)
    gercek_esik = esik if esik is not None else 3
    args = [str(dosya)] + ([str(esik)] if esik is not None else [])
    c = calistir(*args)
    nasil = calistir.goster(goster, *([esik] if esik is not None else []))
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    bulunan = _arac_cikti(c)
    if not bulunan:
        return Sonuc(False, f"`{nasil}` çıktısında `sayı IP` satırı bulamadım. Her IP'yi deneme sayısıyla aynı "
                     "satırda yaz (örn. `  42  203.0.113.9  <-- ŞÜPHELİ`)." + bt.ozet(c), yakin=True)
    sayilar = {ip: n for ip, (n, _) in bulunan.items()}
    supheli = {ip for ip, n in sayac.items() if n >= gercek_esik}
    isaretli = {ip for ip, (_, i) in bulunan.items() if i}
    # Sayımlar
    yanlis = {ip: n for ip, n in sayilar.items() if sayac.get(ip) != n}
    if yanlis:
        dar = _dar_say(satirlar)
        genis = _her_ip_say(satirlar)
        if all(dar.get(ip) == n for ip, n in yanlis.items()):
            return Sonuc(False, f"`{nasil}`: bazı IP'lerin sayısı eksik. `Failed password for invalid user admin from "
                         "...` satırlarını kaçırıyorsun; desenin kullanıcı adından sonra doğrudan `from` bekliyor. "
                         "`Failed password.* from (...)` gibi daha geniş bir desen kullan (`ornekler/regex_dene.py`).",
                         yakin=True)
        if all(genis.get(ip) == n for ip, n in yanlis.items()):
            return Sonuc(False, f"`{nasil}`: IP'nin geçtiği BÜTÜN satırları saymışsın (`Invalid user`, `Connection "
                         "closed`, `Disconnected`...). Sadece `Failed password` satırlarını say.", yakin=True)
        ip, n = next(iter(yanlis.items()))
        return Sonuc(False, f"`{nasil}`: {ip} için {n} başarısız deneme dedin, {sayac.get(ip, 0)} olmalı."
                     + bt.ozet(c), yakin=True)
    eksik = supheli - set(sayilar)
    if eksik:
        return Sonuc(False, f"`{nasil}`: eşiği aşan {len(eksik)} IP çıktında hiç yok (örn. {sorted(eksik)[0]}).",
                     yakin=True)
    if isaretli == supheli:
        return None
    ust = {ip for ip, n in sayac.items() if n > gercek_esik}
    if isaretli == ust:
        return Sonuc(False, f"`{nasil}`: tam {gercek_esik} denemesi olan IP'yi işaretlemedin. Eşik DAHİLDİR: "
                     "`adet >= esik`.", yakin=True)
    if esik is not None and isaretli == {ip for ip, n in sayac.items() if n >= 3}:
        return Sonuc(False, f"`{nasil}`: eşik olarak {esik} verdim ama 3'e göre işaretledin. Eşiği `sys.argv[2]`'den "
                     "oku (`int()` ile sayıya çevir).", yakin=True)
    if not isaretli:
        return Sonuc(False, f"`{nasil}`: hiçbir IP'yi işaretlemedin. Eşiği aşan satırların sonuna `ŞÜPHELİ` yaz."
                     + bt.ozet(c), yakin=True)
    fazla = isaretli - supheli
    return Sonuc(False, f"`{nasil}`: işaretlediğin IP'ler eşik {gercek_esik} ile uyuşmuyor "
                 f"({len(supheli - isaretli)} eksik, {len(fazla)} fazla).", yakin=True)


def _avci_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    olmayan = str(Path(tempfile.gettempdir()) / f"hy_yok_{random.randint(1000, 9999)}.log")
    c = calistir(olmayan)
    if "Traceback" in c.stderr:
        return Sonuc(False, "Olmayan bir log verdiğimde betiğin çöktü (FileNotFoundError). Dosyayı açmayı `try/except "
                     "FileNotFoundError` içine al, hata mesajı yazıp `sys.exit(1)` ile çık.", yakin=True)
    if c.kod == 0:
        return Sonuc(False, "Olmayan bir log verdiğimde betiğin 0 koduyla bitti; hata mesajı + `sys.exit(1)` bekliyordum.",
                     yakin=True)
    lab_log = Path(b.lab) / "loglar" / "auth.log"
    if not lab_log.is_file():
        return Sonuc(False, f"{lab_log} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    sonuc = _calistir_karsilastir(calistir, lab_log, s["esik"], "loglar/auth.log")
    if sonuc:
        return sonuc
    rng = random.Random()
    v = dict(rng.choice(VAKALAR))
    esik = rng.choice([4, 5, 7])
    satirlar, _ = log_uret(rng, v, esik, olcek=0.15, gurultu=False)
    fd, ad = tempfile.mkstemp(prefix="hy_auth_", suffix=".log")
    os.close(fd)
    gecici = Path(ad)
    try:
        gecici.write_text("\n".join(satirlar) + "\n", encoding="utf-8")
        for e in (esik, None):
            sonuc = _calistir_karsilastir(calistir, gecici, e, str(gecici))
            if sonuc:
                if e is None:
                    sonuc.mesaj += "\n    (Eşik vermedim; varsayılan 3 olmalı.)"
                return sonuc
    finally:
        gecici.unlink(missing_ok=True)
    return Sonuc(True, "logavci.py lab logunda ve senin hiç görmediğin yeni bir logda, farklı eşiklerle doğru saydı "
                       "ve doğru işaretledi; eşik verilmeyince 3'e düştü. Bu, bir SIEM kuralının en sade hali.")


def _supheli_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen - 1:
        return "Bir eksik: tam eşik kadar deneme yapan IP de şüphelidir (`>=`)."
    if n == beklenen + 1:
        return "Bir fazla: eşiğin bir altında kalan IP'yi de saymış olabilirsin."
    return None


def _ihlal_hata(g, beklenen, b):
    if g in b.senaryo["yanlis_yazanlar"]:
        return ("Bu IP birkaç kez yanlış parola girip sonra başarıyla girmiş, ama eşiğin çok altında ve iç ağdan: "
                "büyük olasılıkla parolasını yanlış yazan bir çalışan. Eşiği aşan IP'lere bak.")
    return None


def _kullanici_hata(g, beklenen, b):
    if g == "root":
        return "root çok denendi ama hiç başarılı olmadı. İhlal IP'sinin `Accepted` satırındaki hesaba bak."
    return None


def _dagitik_hata(g, beklenen, b):
    if g == "root":
        return ("root en çok denemeyi alıyor olabilir ama birkaç IP'den. Soru FARKLI IP sayısını soruyor: her "
                "(kullanıcı, IP) çiftini bir kez say.")
    return None


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "logavci.py", LOGAVCI_PY)
    esik = s["metin"]["esik"]
    cikti = _sh(f"python3 logavci.py loglar/auth.log {esik}", lab)
    satirlar = [x for x in cikti.splitlines() if re.search(r"\d+\.\d+\.\d+\.\d+", x)]
    supheli = [x for x in satirlar if "ŞÜPHELİ" in x]
    en_cok = satirlar[0].split()[1]
    ihlal_ip = kullanici = saat = ""
    for x in supheli:
        ip = x.split()[1]
        kabul = _sh(f"grep 'Accepted' loglar/auth.log | grep -F 'from {ip} '", lab).strip()
        if kabul:
            ihlal_ip = ip
            parca = kabul.split()
            saat = parca[2]
            kullanici = parca[parca.index("for") + 1]
    dagitik = _sh("grep 'Failed password' loglar/auth.log | sed -E 's/.*Failed password for (invalid user )?([^ ]+) "
                  "from ([0-9.]+).*/\\2 \\3/' | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head -1",
                  lab).split()[1]
    secmeli = SEVIYE.gorevler[7].kontrol.cevabi_goster(Baglam(s, lab, 8))[0]
    return {1: "", 2: len(supheli), 3: en_cok, 4: ihlal_ip, 5: kullanici, 6: saat, 7: dagitik, 8: secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Mavi takımın klasik işi", """
Deniz ekranını çeviriyor: "Bir SSH logunda aynı IP'den çok sayıda `Failed password` satırı
varsa, bu bir **brute-force** (kaba kuvvet: parolaları sırayla deneme) saldırısıdır. Ben
bunu her gün yakalıyorum; sen de bugün aracını yazacaksın." Önce kaç başarısız deneme var:
""", komut="grep -c 'Failed password' loglar/auth.log", sonra="""
<<satir>> satırlık bir logda yüzlerce deneme. Elle okumak imkânsız; saymak gerek.
"""),
    Adim("Cilt 1'deki yöntem", """
Cilt 1'de bunu boru hattıyla yapmıştın: deseni bul, IP'yi ayıkla, sırala, say. Uzun olduğu
için bir dosyaya koyduk (sonra `cat ornekler/cilt1_yontemi.sh` ile oku):

```
grep 'Failed password' loglar/auth.log | grep -oE 'from [0-9.]+' \\
    | sort | uniq -c | sort -rn | head -5
```
""", komut="bash ornekler/cilt1_yontemi.sh", sonra="""
İşe yarıyor. Ama eşik, işaretleme, başarılı girişle karşılaştırma ve rapor eklemek
istediğinde boru hattı hızla okunmaz hale gelir. Bu işi bir programa devredeceğiz.
"""),
    Adim("Düzenli ifade ve yakalama grubu", """
`re.compile(r"Failed password.* from (\\d+\\.\\d+\\.\\d+\\.\\d+)")` bir **düzenli ifade**
(regex) hazırlar. `\\d+` bir veya daha fazla rakam, `\\.` gerçek bir nokta, `.*` "arada ne
olursa", parantez ise **yakalama grubu**dur: `group(1)` ile yakalanan IP'yi alırsın.
Örnek betik iki deseni aynı satırlarda karşılaştırıyor:
""", komut="python3 ornekler/regex_dene.py", sonra="""
"Dar" desen `invalid user` satırını kaçırdı: kullanıcı adından sonra doğrudan `from`
bekliyordu. Saldırganlar olmayan kullanıcı adlarını (admin, test, oracle...) sık dener;
o satırları kaçıran araç saldırganın denemelerini eksik sayar.
"""),
    Adim("invalid user satırları", """
Logda bu satırlardan çok var. Bir kısmına bak:
""", komut="grep -m 4 'invalid user' loglar/auth.log", sonra="""
Aynı denemenin izleri birden fazla satıra dağılır: `Invalid user`, `Failed password for
invalid user`, `Disconnected from invalid user`. Sadece `Failed password` satırlarını
sayarsan her deneme bir kez sayılır.
"""),
    Adim("Counter: hazır sayaç", """
`collections.Counter`, sözlükle elle saymanın (`get(..., 0) + 1`) hazır hali.
`most_common()` en çoktan en aza sıralı liste verir. Bir metni harf harf saydır:
""", komut="""python3 -c 'import collections as c; print(c.Counter("abaca").most_common())'""",
         sonra="""
Aracında `sayac[ip] += 1` yazman yeter; olmayan anahtar otomatik 0'dan başlar.
"""),
    Adim("İskelet", """
Aracın iskeleti laboratuvarında. Oku ve çalıştır:
""", komut="python3 ornekler/iskelet.py loglar/auth.log", sonra="""
Çalışıyor ama eksik: kullanım mesajı, eşik argümanı, dosya yoksa düzgün hata, eşiği aşanları
işaretlemek. `cat ornekler/iskelet.py` ile kodu oku; görevde bunları ekleyeceksin.
"""),
    Adim("Başarısızdan sonra başarı", """
Brute-force'un en tehlikeli hali **başarıya ulaşmasıdır**: çok sayıda başarısız denemeden
sonra aynı IP'den bir `Accepted` satırı. Ama dikkat: parolasını bir kez yanlış yazıp sonra
giren bir çalışan da "başarısızdan sonra başarı" üretir. Fark, deneme SAYISINDA ve IP'nin
nereden geldiğinde. Başarılı girişlere bak:
""", komut="grep 'Accepted' loglar/auth.log | head -6", sonra="""
**Hacker gözüyle:** Bu araç bir SIEM'in (güvenlik olay yönetimi) en sade halidir: logu oku,
deseni ara, say, eşiği aşanı alarma dök. Saldırganın dersi ise şu: her başarısız denemen
sayılıyor; "düşük ve yavaş" gitmezsen yakalanırsın. Akıllı saldırgan da tam bunu yapar.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`logavci.py` yaz: `python3 logavci.py <auth.log> [esik]` her IP'nin `Failed password` sayısını bulsun "
          "(`invalid user` denemeleri dahil), IP'leri en çoktan en aza, sayılarıyla aynı satırda yazsın ve sayısı "
          "eşiğe **eşit ya da büyük** olanları `ŞÜPHELİ` diye işaretlesin. Eşik verilmezse 3. Argümansızsa kullanım "
          "mesajı, log yoksa çökmeden hata; ikisinde de `sys.exit(1)`. Dene: `python3 logavci.py loglar/auth.log <<esik>>`",
          bt.BetikKontrol("logavci.py", _avci_denetle,
                          "Örnek `logavci.py`:\n\n```\n" + LOGAVCI_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/iskelet.py`'nin eksiklerini tamamla.",
           "`esik = int(sys.argv[2]) if len(sys.argv) > 2 else 3`; `for ip, adet in sayac.most_common():` ve "
           "`adet >= esik` ise satırın sonuna `ŞÜPHELİ` ekle.",
           "İskelet:\n\n```\nif len(sys.argv) < 2: ...\nesik = ...\ntry:\n    with open(sys.argv[1], ...) as f:\n"
           "        for satir in f: ...\nexcept FileNotFoundError: ...\nfor ip, adet in sayac.most_common():\n"
           "    isaret = \"  <-- ŞÜPHELİ\" if ... else \"\"\n    print(f\"{adet:4d}  {ip}{isaret}\")\n```"),
          puan=60, baslik="Log avcısı"),
    Gorev("Eşik <<esik>> iken kaç IP şüpheli?",
          Sayi("supheli_sayi", sik_hatalar=_supheli_hata),
          ("Aracını SOC eşiğiyle çalıştır.",
           "`python3 logavci.py loglar/auth.log <<esik>>`",
           "`python3 logavci.py loglar/auth.log <<esik>> | grep -c ŞÜPHELİ`"),
          puan=25, baslik="Kaç şüpheli"),
    Gorev("En çok başarısız deneme yapan IP hangisi?",
          IP("en_cok"),
          ("Aracın IP'leri en çoktan en aza sıralıyor.",
           "Çıktının ilk IP satırına bak.",
           "`python3 logavci.py loglar/auth.log | sed -n 3p`"),
          puan=20, baslik="Baş şüpheli"),
    Gorev("Asıl soru: şüpheli IP'lerden biri sonunda **başarıyla giriş yapmış**. Gerçek ihlali yapan IP hangisi?",
          IP("ihlal_ip", sik_hatalar=_ihlal_hata),
          ("Şüpheli IP'lerin hangisinin `Accepted` satırı var?",
           "Her şüpheli IP için `grep 'Accepted' loglar/auth.log | grep -F 'from IP '` dene; ya da aracına `Accepted` "
           "satırlarını da sayan ikinci bir Counter ekle.",
           "`for ip in $(python3 logavci.py loglar/auth.log <<esik>> | grep ŞÜPHELİ | awk '{print $2}'); do grep "
           "'Accepted' loglar/auth.log | grep -F \"from $ip \"; done`"),
          puan=40, baslik="Gerçek ihlal"),
    Gorev("Saldırgan hangi hesapla içeri girdi?",
          Metin("ihlal_kullanici", sik_hatalar=_kullanici_hata, bicim="kullanıcı adı"),
          ("İhlal IP'sinin `Accepted` satırını oku.",
           "`Accepted password for KULLANICI from IP` kalıbında `for`'dan sonraki kelime.",
           "`grep 'Accepted' loglar/auth.log | grep -F 'from <ihlal_ip> '`"),
          puan=25, baslik="Ele geçen hesap"),
    Gorev("Olay zaman çizelgesi için: başarılı giriş saat kaçta oldu? (SS:DD:ss)",
          Metin("ihlal_saat", bicim="SS:DD:ss"),
          ("Aynı `Accepted` satırının başındaki zaman damgası.",
           "auth.log satırı `Ay Gün SS:DD:ss sunucu ...` diye başlar.",
           "`grep 'Accepted' loglar/auth.log | grep -F 'from <ihlal_ip> ' | awk '{print $3}'`"),
          puan=20, baslik="Saat"),
    Gorev("Deniz'in şüphesi: \"Bir de düşük ve yavaş giden biri var. Hiçbir IP'si eşiği aşmıyor ama hep aynı "
          "hesabı deniyor.\" En çok **farklı IP**'den başarısız denemeye maruz kalan kullanıcı adı hangisi?",
          Metin("dagitik_hedef", sik_hatalar=_dagitik_hata, bicim="kullanıcı adı"),
          ("Bu kez IP'ye göre değil, kullanıcı adına göre düşün; ama her IP'yi bir kez say.",
           "`Failed password` satırlarından (kullanıcı, IP) çiftlerini çıkar, tekrarları at, sonra kullanıcıları say.",
           "`grep 'Failed password' loglar/auth.log | sed -E 's/.*for (invalid user )?([^ ]+) from ([0-9.]+).*/\\2 "
           "\\3/' | sort -u | awk '{print $1}' | sort | uniq -c | sort -rn | head -3`"),
          puan=40, baslik="Düşük ve yavaş"),
    Gorev("Bu tür bir eşik sayacını atlatmak isteyen saldırgan büyük olasılıkla ne yapar?",
          Secmeli([
              ("Denemeleri birçok IP'ye dağıtır ve zamana yayar",
               "Doğru. Dağıtık ve \"düşük ve yavaş\" saldırıda her IP eşiğin altında kalır. Bu yüzden gerçek tespit, "
               "kullanıcı adı ve zaman penceresi gibi başka boyutlara da bakar."),
              ("Tek IP'den çok daha hızlı deneyip logların dolmasını bekler",
               "Hız sayacı atlatmaz; tersine sayıyı hızla eşiğin üstüne çıkarır."),
              ("Parolaları şifreli gönderir, böylece log satırı oluşmaz",
               "SSH zaten şifreli çalışır; başarısız her deneme yine loglanır."),
              ("Sadece root yerine admin kullanıcısını dener",
               "Hangi kullanıcıyı denediği IP başına sayımı değiştirmez."),
          ]),
          ("Sayacın neyi saydığını düşün: IP başına deneme.",
           "Her IP'nin sayısını eşiğin altında tutmanın iki yolu var.",
           "Bir önceki görevde gördüğün davranış."),
          puan=20, baslik="Atlatma"),
]


SEVIYE = Seviye(
    kimlik="c03b06",
    cilt=3,
    bolum=6,
    baslik="Log Analiz Aracı: Brute-Force Avcısı",
    brifing="""
Bu sefer vakayı Deniz getiriyor, SOC ekranlarının önünden: "**<<musteri>>**. <<olay>>"

"`<<sunucu>>`'nun son 24 saatlik auth.log'u laboratuvarında: <<satir>> satır. SOC
kuralımız basit: <<esik>> ve üstü başarısız deneme yapan IP şüphelidir. Senden bu kuralı
uygulayan bir araç istiyorum. Sonra asıl soruya geçeceğiz: bu denemelerden biri **başarılı
oldu mu**?"

Mert omzunun üstünden bakıyor: "Bir de şu var: akıllı saldırgan eşiğine takılmaz.
Sayının arkasına da bak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kırk satırlık araç, Splunk'ın, Wazuh'un ya da ELK'nin her gün milyonlarca satırda yaptığı işin
çekirdeğini yapıyor: logu oku, deseni ara, say, eşiği aşanı alarma dök. Ama bu vaka iki şeyi
gösterdi: alarmların çoğu sonuçsuz denemelerdir; asıl tehlike, çok sayıda denemeden sonra
gelen tek bir `Accepted` satırıdır. Ve eşik, düşük ve yavaş giden saldırganı göremez; onu
ancak veriyi başka bir boyuttan (kullanıcı adına göre) sayınca yakalarsın. Saldırgan için
ders: her denemen sayılıyor. Savunmacı için: tek bir sayaca güvenme, MFA ve parola
yerine SSH anahtarı kullan.
""",
    gercek_hayat="""
- **Fail2ban:** Linux sunucularda yaygın kullanılan açık kaynak Fail2ban aracı tam bu
  bölümdeki mantıkla çalışır: logları tarar, belirli bir süre içinde çok sayıda başarısız
  giriş yapan IP'leri güvenlik duvarında geçici olarak engeller.
- **MITRE ATT&CK T1110:** ATT&CK çerçevesi kaba kuvvet saldırılarını (Brute Force, T1110)
  alt tekniklere ayırır: parola tahmini, parola püskürtme (password spraying: çok sayıda
  hesapta birkaç yaygın parolayı denemek) ve kimlik bilgisi doldurma (credential stuffing:
  başka sızıntılardan alınan kullanıcı adı-parola çiftlerini denemek). Püskürtme, tam da IP
  başına eşiğin altında kalmak için kullanılır.
- **İnternete açık SSH:** Bal küpü (honeypot) çalışmaları, internete açılan her SSH
  sunucusunun kısa süre içinde otomatik parola denemeleri almaya başladığını sürekli
  gösterir. Parola ile girişi kapatıp yalnızca anahtar kabul etmek bu gürültünün neredeyse
  tamamını etkisiz kılar.
""",
    sure_hedef_dk=45,
)
