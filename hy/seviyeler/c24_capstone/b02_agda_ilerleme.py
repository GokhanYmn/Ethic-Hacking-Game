"""Cilt 24 · Bölüm 2 — Vaka 2: "Ağda ilerleme (pivoting)" olayının incelemesi (mavi takım).

Birden çok makinenin logları, iç güvenlik duvarı kaydı ve bir pcap ile saldırganın iç ağda **bir makineden
diğerine** nasıl geçtiğinin izi sürülür; segmentasyon eksikliği bulunur ve güvenlik duvarı kuralları düzeltilir.

Vakalar (farklı müşteri, ağ ve servis): Kuzgun Lojistik (MySQL, 3306), Medora Sağlık (PostgreSQL, 5432),
Yeşiltepe Belediyesi (SQL Server, 1433). Hepsinde aynı kök neden ailesi: DMZ'den uygulama katmanına ve
uygulamadan veritabanına gereğinden fazla port açık + sunucular arasında paylaşılan servis hesabı.
"""
from __future__ import annotations

import calendar
import ipaddress
import random
import re
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Sayi, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c24_capstone import ortak
from hy.seviyeler.c24_capstone.ortak import SAAT, LogYigini, Sira, sec_doldur, sh, sira_cevabi, sira_hata, sys_satiri

VAKALAR = [
    {"kod": "kuzgun", "adlar": ("kzg-web01", "kzg-app01", "kzg-db01"), "ag": ("10.10.10", "10.20.20", "10.30.30"),
     "hesaplar": ["svc_depo", "svc_yedek", "svc_rapor"], "uyg": "kargo takip uygulaması", "dbport": 3306, "dbad": "MySQL"},
    {"kod": "medora", "adlar": ("medora-portal", "medora-randevu", "medora-hastadb"), "ag": ("172.16.10", "172.16.20", "172.16.30"),
     "hesaplar": ["svc_randevu", "svc_hbys", "svc_lab"], "uyg": "randevu uygulaması", "dbport": 5432, "dbad": "PostgreSQL"},
    {"kod": "yesiltepe", "adlar": ("ytb-web01", "ytb-borc01", "ytb-vergidb"), "ag": ("192.168.10", "192.168.20", "192.168.30"),
     "hesaplar": ["svc_borc", "svc_tahsilat", "svc_arsiv"], "uyg": "borç sorgulama uygulaması", "dbport": 1433, "dbad": "SQL Server"},
]
OLAYLAR = [
    "İç güvenlik duvarında sıçrama makinesinden gelen ilk DROP kaydı (tarama)",
    "Sıçrama makinesinden uygulama sunucusuna ilk izinli (ALLOW) yönetim bağlantısı",
    "Uygulama sunucusunda parolayla başarılı giriş (sıçrama makinesinden)",
    "Uygulama sunucusundan veritabanı sunucusuna ilk izinli (ALLOW) yönetim bağlantısı",
    "Veritabanı sunucusunda parolayla başarılı giriş (uygulama sunucusundan)",
    "Veritabanı sunucusunda yeni kullanıcı hesabının oluşturulması (useradd)",
]
TARAMA_PORTLARI = [23, 25, 80, 110, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    dmz, uyg, dbn = v["ag"]
    web, app, db = f"{dmz}.{rng.randint(10, 60)}", f"{uyg}.{rng.randint(10, 60)}", f"{dbn}.{rng.randint(10, 60)}"
    mgmt, izleme = f"10.99.0.{rng.randint(5, 9)}", f"10.99.0.{rng.randint(20, 30)}"
    h1, h2 = rng.choice([22, 2222, 2200]), rng.choice([22, 2222, 22022])
    gun = u.gun(rng)
    bas = gun + timedelta(hours=rng.randint(1, 4), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    dur = rng.randint(40, 90)
    T = ortak.zaman_zinciri(rng, bas, [(dur + 60, dur + 300), (4, 20), (90, 400), (4, 20), (60, 300)])
    # tarama hedefleri: uygulama ve veritabanı sunucuları dahil
    hedefler = [app, db]
    while len(hedefler) < rng.randint(9, 13):
        a = rng.choice([uyg, dbn, "10.99.0"])
        ipx = f"{a}.{rng.randint(70, 200)}"
        if ipx not in hedefler:
            hedefler.append(ipx)
    rng.shuffle(hedefler)
    portlar = rng.sample(TARAMA_PORTLARI, rng.randint(4, 6))
    hesap = rng.choice(v["hesaplar"])
    yeni = rng.choice(["destek2", "bakim_svc", "monitor2", "yedek_admin", "sistem_ops"])
    yoneticiler = u.isimler(rng, 2)
    perm = list(range(6))
    rng.shuffle(perm)
    return {
        "vaka": f"{m['ad']} — {m['sektor']}: DMZ'den {v['dbad']} sunucusuna sıçrama",
        "m": m, "v": v, "web": web, "app": app, "db": db, "mgmt": mgmt, "izleme": izleme, "h1": h1, "h2": h2, "T": T, "dur": dur,
        "hedefler": hedefler, "portlar": portlar, "hesap": hesap, "yeni": yeni, "yoneticiler": yoneticiler, "perm": perm,
        "tohum_log": rng.randint(1, 10**9), "gun": gun, "uid": rng.randint(1001, 1090),
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "hikaye": m["hikaye"], "web_ad": v["adlar"][0], "app_ad": v["adlar"][1],
                  "db_ad": v["adlar"][2], "dmz": dmz + ".0/24", "uyg": uyg + ".0/24", "dbn": dbn + ".0/24",
                  "dbport": str(v["dbport"]), "dbad": v["dbad"], "uygad": v["uyg"], "hesap_ornek": v["hesaplar"][0]},
        "cevaplar": {"web": web, "tarama": len(hedefler), "port": h2, "hesap": hesap, "sira": sira_cevabi(perm), "db": db},
    }


def _ts(t: datetime) -> float:
    return float(calendar.timegm(t.timetuple()))


def _fw(s: dict) -> str:
    r = random.Random(s["tohum_log"])
    T, v = s["T"], s["v"]
    L = LogYigini()
    gun = s["gun"]

    def satir(t, eylem, src, dst, sport, dport):
        L.ekle(t, f"{u.syslog_zamani(t)} fw-ic kernel: [FW-{eylem}] IN=eth1 OUT=eth2 SRC={src} DST={dst} PROTO=TCP SPT={sport} DPT={dport} SYN")

    # meşru uygulama trafiği
    for _ in range(r.randint(25, 40)):
        t = gun + timedelta(seconds=r.randint(0, 6 * 3600))
        satir(t, "ALLOW", s["web"], s["app"], r.randint(33000, 60000), 8443)
    for _ in range(r.randint(25, 40)):
        t = gun + timedelta(seconds=r.randint(0, 6 * 3600))
        satir(t, "ALLOW", s["app"], s["db"], r.randint(33000, 60000), v["dbport"])
    for _ in range(r.randint(3, 5)):               # yönetim ağından meşru bakım bağlantıları
        t = gun + timedelta(seconds=r.randint(0, 6 * 3600))
        hdf, prt = r.choice([(s["app"], s["h1"]), (s["db"], s["h2"])])
        satir(t, "ALLOW", s["mgmt"], hdf, r.randint(33000, 60000), prt)
    for _ in range(r.randint(4, 8)):               # başka iç makinelerden gürültü
        t = gun + timedelta(seconds=r.randint(0, 6 * 3600))
        satir(t, "DROP", f"10.40.5.{r.randint(10, 90)}", r.choice([s["app"], s["db"]]), r.randint(33000, 60000), r.choice([445, 3389, 23]))
    # tarama: sıçrama makinesinden gelen DROP satırları
    toplam = len(s["hedefler"]) * len(s["portlar"])
    aralik = s["dur"] / toplam
    k = 0
    for h in s["hedefler"]:
        for p in s["portlar"]:
            satir(T[0] + timedelta(seconds=k * aralik), "DROP", s["web"], h, r.randint(33000, 60000), p)
            k += 1
    satir(T[1], "ALLOW", s["web"], s["app"], r.randint(33000, 60000), s["h1"])
    satir(T[3], "ALLOW", s["app"], s["db"], r.randint(33000, 60000), s["h2"])
    return L.metin()


def _auth(s: dict, hedef: str) -> str:
    r = random.Random(s["tohum_log"] + (1 if hedef == "app" else 2))
    T, v, gun = s["T"], s["v"], s["gun"]
    host = v["adlar"][1 if hedef == "app" else 2]
    L = LogYigini()
    pid = [r.randint(700, 3000)]

    def p():
        pid[0] += r.randint(1, 40)
        return pid[0]

    for _ in range(r.randint(3, 6)):                # meşru yönetim girişleri (anahtarla, yönetim ağından)
        t = gun + timedelta(seconds=r.randint(0, 6 * 3600))
        L.ekle(t, sys_satiri(t, host, "sshd", p(), f"Accepted publickey for {r.choice(s['yoneticiler'])} from {s['mgmt']} port {r.randint(30000, 60000)} ssh2"))
    t = gun + timedelta(hours=2, minutes=30)         # gece yedek işi
    L.ekle(t, sys_satiri(t, host, "sshd", p(), f"Accepted publickey for yedek_robot from {s['mgmt']} port {r.randint(30000, 60000)} ssh2"))
    if hedef == "app":
        L.ekle(T[2], sys_satiri(T[2], host, "sshd", p(), f"Accepted password for {s['hesap']} from {s['web']} port {r.randint(30000, 60000)} ssh2"))
        L.ekle(T[2], sys_satiri(T[2], host, "sshd", p(), f"pam_unix(sshd:session): session opened for user {s['hesap']}(uid=998) by (uid=0)"))
    else:
        L.ekle(T[4], sys_satiri(T[4], host, "sshd", p(), f"Accepted password for {s['hesap']} from {s['app']} port {r.randint(30000, 60000)} ssh2"))
        L.ekle(T[4], sys_satiri(T[4], host, "sshd", p(), f"pam_unix(sshd:session): session opened for user {s['hesap']}(uid=998) by (uid=0)"))
        uid = s["uid"]
        L.ekle(T[5], sys_satiri(T[5], host, "useradd", p(),
                                f"new user: name={s['yeni']}, UID={uid}, GID={uid}, home=/home/{s['yeni']}, shell=/bin/bash, from=none"))
    return L.metin()


def _pcap(s: dict) -> ag.Pcap:
    r = random.Random(s["tohum_log"] + 3)
    T, v = s["T"], s["v"]
    p = ag.Pcap()
    t0 = _ts(T[0])
    aralik = s["dur"] / (len(s["hedefler"]) * len(s["portlar"]))
    t = t0
    for h in s["hedefler"]:
        t = p.syn_tarama(s["web"], h, s["portlar"], acik=(), t=t, aralik=aralik, sport=r.randint(40000, 60000))
    for ci, sr, ds, port, ti in ((s["web"], r.randint(40000, 60000), s["app"], s["h1"], T[1]),
                                 (s["app"], r.randint(40000, 60000), s["db"], s["h2"], T[3])):
        o = p.tcp_oturum(ci, sr, ds, port, t=_ts(ti) + 0.2)
        o.el_sikis()
        o.istemci(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n")
        o.sunucu(b"SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n")
        o.kapat()
    for _ in range(r.randint(4, 7)):                # meşru şifreli trafik
        p.tls_oturumu(s["web"], s["app"], t=t0 - r.randint(30, 3000), r=r, port=8443)
        p.tls_oturumu(s["app"], s["db"], t=t0 - r.randint(30, 3000), r=r, port=v["dbport"])
    for hedef, pt in ((s["web"], 22), (s["app"], 8443), (s["db"], v["dbport"])):   # izleme sunucusunun sağlık kontrolü (meşru)
        p.syn_tarama(s["izleme"], hedef, [pt], acik={pt}, t=t0 - r.randint(10, 2500), aralik=0.5)
    return p


def yaz(lab: Path, s: dict) -> None:
    v, m = s["v"], s["m"]
    web_ad, app_ad, db_ad = v["adlar"]
    u.yaz(lab / "loglar/ic_guvenlik_duvari.log", _fw(s))
    u.yaz(lab / f"loglar/{app_ad}_auth.log", _auth(s, "app"))
    u.yaz(lab / f"loglar/{db_ad}_auth.log", _auth(s, "db"))
    _pcap(s).kaydet(lab / "yakalama.pcap")
    olaylar = [f"{i + 1}. {OLAYLAR[e]}" for i, e in enumerate(s["perm"])]
    u.yaz(lab / "olay_listesi.txt", "Zaman çizelgesi için altı olay (karışık sırada):\n" + "\n".join(olaylar) + "\n")
    dmz, uyg, dbn = v["ag"]
    u.yaz(lab / "ag_semasi.txt",
          f"{m['ad']} iç ağ yapısı (KURGUSAL)\n"
          f"  DMZ          {dmz}.0/24   dışa açık web sunucusu ({web_ad})\n"
          f"  Uygulama     {uyg}.0/24   {v['uyg']} ({app_ad}); web sunucusundan yalnızca 8443/tcp ile erişilmeli\n"
          f"  Veritabanı   {dbn}.0/24   {v['dbad']} ({db_ad}); uygulama sunucusundan yalnızca {v['dbport']}/tcp ile erişilmeli\n"
          f"  Yönetim      10.99.0.0/24 yönetim sunucuları; uygulama ve veritabanı sunucularına ssh ile erişir\n"
          f"Güvenlik duvarı kopyası: sistem/fw/kurallar.rules (loglar: loglar/ic_guvenlik_duvari.log, pcap: yakalama.pcap).\n")
    kural = ["# iç güvenlik duvarı kuralları (iptables-save biçimi, KURGUSAL kopya)", "*filter", ":INPUT DROP [0:0]",
             ":FORWARD DROP [0:0]", ":OUTPUT ACCEPT [0:0]",
             "-A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
             f"-A FORWARD -s {dmz}.0/24 -d {uyg}.0/24 -p tcp --dport 8443 -j ACCEPT",
             f"-A FORWARD -s {dmz}.0/24 -d {uyg}.0/24 -p tcp --dport {s['h1']} -j ACCEPT",
             f"-A FORWARD -s {uyg}.0/24 -d {dbn}.0/24 -p tcp --dport {v['dbport']} -j ACCEPT",
             f"-A FORWARD -s {uyg}.0/24 -d {dbn}.0/24 -p tcp --dport {s['h2']} -j ACCEPT",
             f"-A FORWARD -s 10.99.0.0/24 -d {uyg}.0/24 -p tcp --dport {s['h1']} -j ACCEPT",
             f"-A FORWARD -s 10.99.0.0/24 -d {dbn}.0/24 -p tcp --dport {s['h2']} -j ACCEPT", "COMMIT"]
    u.yaz(lab / "sistem/fw/kurallar.rules", "\n".join(kural) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} iç ağ olayı (KURGUSAL). Selin'den not: {m['hikaye']}\n"
          "loglar/ : iç güvenlik duvarı ve iki sunucunun auth.log kopyası. yakalama.pcap: iç güvenlik duvarında alınmış paket yakalaması.\n"
          "pcap'i `tcpdump -nr yakalama.pcap` ile oku (saatler pcap'te saat dilimine göre kayabilir; saat sorularında logları kullan).\n"
          "sistem/ : düzeltme burada yapılır.\n")


# ----------------------------------------------------------------------------- kontroller

def _kural_ayristir(satir: str):
    if not satir.startswith("-A FORWARD") or "-j ACCEPT" not in satir or "conntrack" in satir:
        return None
    k = {"s": None, "d": None, "p": None, "dport": None}
    for anahtar, desen in (("s", r"-s (\S+)"), ("d", r"-d (\S+)"), ("p", r"-p (\S+)"), ("dport", r"--dports? (\S+)")):
        mm = re.search(desen, satir)
        if mm:
            k[anahtar] = mm.group(1)
    return k


def _portta(dport, port) -> bool:
    if dport is None:
        return True
    for parca in dport.split(","):
        if ":" in parca:
            a, b = parca.split(":", 1)
            if a.isdigit() and b.isdigit() and int(a) <= port <= int(b):
                return True
        elif parca.isdigit() and int(parca) == port:
            return True
    return False


def _izin(kurallar: list, src: str, dst: str, port: int, proto: str = "tcp") -> bool:
    for k in kurallar:
        try:
            if k["s"] and ipaddress.ip_address(src) not in ipaddress.ip_network(k["s"], strict=False):
                continue
            if k["d"] and ipaddress.ip_address(dst) not in ipaddress.ip_network(k["d"], strict=False):
                continue
        except ValueError:
            continue
        if k["p"] not in (None, "all", proto):
            continue
        if _portta(k["dport"], port):
            return True
    return False


def _fw_kontrol(b) -> Sonuc:
    s, v = b.senaryo, b.senaryo["v"]
    yol = b.lab / "sistem/fw/kurallar.rules"
    metin = yol.read_text(errors="replace") if yol.exists() else ""
    satirlar = [x.strip() for x in metin.splitlines()]
    if ":FORWARD DROP" not in " ".join(x[:13] for x in satirlar):
        return Sonuc(False, "`:FORWARD DROP` (varsayılan ret) satırı yerinde kalmalı; izin verilmeyen her şey düşsün.", yakin=True)
    if "COMMIT" not in satirlar:
        return Sonuc(False, "Dosya bozulmuş: `COMMIT` satırı olmalı.", yakin=True)
    kurallar = [k for k in map(_kural_ayristir, satirlar) if k]
    web, app, db, mgmt = s["web"], s["app"], s["db"], s["mgmt"]
    dbp = v["dbport"]
    eksik = []
    if not _izin(kurallar, web, app, 8443):
        eksik.append("web → uygulama 8443/tcp (meşru uygulama trafiği)")
    if not _izin(kurallar, app, db, dbp):
        eksik.append(f"uygulama → veritabanı {dbp}/tcp (meşru veritabanı trafiği)")
    if not _izin(kurallar, mgmt, app, s["h1"]):
        eksik.append(f"yönetim ağı → uygulama {s['h1']}/tcp (meşru bakım)")
    if not _izin(kurallar, mgmt, db, s["h2"]):
        eksik.append(f"yönetim ağı → veritabanı {s['h2']}/tcp (meşru bakım)")
    if eksik:
        return Sonuc(False, "Meşru erişim kopmuş: " + "; ".join(eksik) + ". Fazla kuralı sil/daralt ama bunları bozma.", yakin=True)
    for port in sorted({22, 2222, 2200, 22022, 3389, 445, 23, 80, 3306, 5432, 1433, s["h1"], s["h2"]}):
        if _izin(kurallar, web, app, port) and port != 8443:
            return Sonuc(False, f"DMZ'deki web sunucusu hâlâ uygulama sunucusunun {port}/tcp portuna ulaşabiliyor. "
                                "Web sunucusu uygulama katmanında yalnızca 8443'e erişmeli.", yakin=True)
        if _izin(kurallar, web, db, port):
            return Sonuc(False, f"DMZ'deki web sunucusu veritabanı sunucusunun {port}/tcp portuna ulaşabiliyor; DMZ'den veritabanına hiç yol olmamalı.", yakin=True)
        if _izin(kurallar, app, db, port) and port != dbp:
            return Sonuc(False, f"Uygulama sunucusu hâlâ veritabanı sunucusunun {port}/tcp portuna ulaşabiliyor. "
                                f"Uygulama → veritabanı yalnızca {dbp}/tcp olmalı; yönetim erişimi yönetim ağından gelir.", yakin=True)
    return Sonuc(True, "Segmentasyon düzeldi: DMZ yalnızca 8443'e, uygulama yalnızca veritabanı portuna, yönetim ağı ise bakım portlarına erişiyor.")


def _web_hata(g, beklenen, b):
    if g == b.senaryo["izleme"]:
        return "Bu, meşru izleme sunucusu: az sayıda SYN, hep aynı portlar. Saldırgan makine çok sayıda farklı hedefe SYN gönderen."
    if g in (b.senaryo["app"], b.senaryo["db"]):
        return "Bu makine taranan hedeflerden biri; taramayı yapan, çok sayıda hedefe SYN gönderen kaynaktır."
    return None


def _tarama_hata(g, beklenen, b):
    if g.isdigit() and int(g) > int(beklenen):
        return "Hedefleri tekilleştirmeden satır ya da paket saymış olabilirsin; kaç **farklı** hedef IP var? (`sort -u`)"
    return None


def _port_hata(g, beklenen, b):
    if g == str(b.senaryo["v"]["dbport"]):
        return "Bu, meşru uygulama→veritabanı portu; her gün binlerce kez geçiyor. Saldırının izi nadir, beklenmeyen bir portta."
    if g == "8443":
        return "8443 web→uygulama arasındaki meşru port; aradığın uygulamadan veritabanına giden beklenmeyen port."
    return None


def _hesap_hata(g, beklenen, b):
    if g in b.senaryo["yoneticiler"]:
        return "Yöneticiler anahtarla ve yönetim ağından girdi; aradığın hesap iki sunucuda **parolayla**, iç makinelerden girdi."
    if g == "yedek_robot":
        return "Bu gece yedek işinin anahtarla girişi, meşru. Aradığın hesap parolayla girdi."
    return None


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    web_ad, app_ad, db_ad = v["adlar"]
    fw = "loglar/ic_guvenlik_duvari.log"
    tcp = "tcpdump -nr yakalama.pcap 'tcp[tcpflags] == tcp-syn' 2>/dev/null"
    ip = sh(tcp + " | awk '{split($3,a,\".\"); print a[1]\".\"a[2]\".\"a[3]\".\"a[4]}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    tarama = sh(tcp + f" | awk -v ip={ip} '{{split($3,a,\".\"); sk=a[1]\".\"a[2]\".\"a[3]\".\"a[4]; split($5,b,\".\"); "
                      "if (sk==ip) print b[1]\".\"b[2]\".\"b[3]\".\"b[4]}' | sort -u | wc -l", lab)
    app = sh(f"grep -h 'Accepted password' loglar/{db_ad}_auth.log | grep -oE 'from [0-9.]+' | cut -d' ' -f2", lab)
    hesap = sh(f"grep -h 'Accepted password' loglar/{db_ad}_auth.log | grep -oE 'for [a-z_0-9]+' | cut -d' ' -f2", lab)
    legit = v["dbport"]
    port = sh(f"grep ALLOW {fw} | grep SRC={app} | grep -v DPT={legit} | grep -oE 'DPT=[0-9]+' | head -1 | cut -d= -f2", lab)
    db = sh(f"grep ALLOW {fw} | grep SRC={app} | grep -v DPT={legit} | grep -oE 'DST=[0-9.]+' | head -1 | cut -d= -f2", lab)
    komutlar = {
        "ilk DROP": f"grep SRC={ip} {fw} | grep DROP | head -1",
        "uygulama sunucusuna ilk": f"grep ALLOW {fw} | grep SRC={ip} | grep -v DPT=8443 | head -1",
        "Uygulama sunucusunda parolayla": f"grep 'Accepted password' loglar/{app_ad}_auth.log | head -1",
        "veritabanı sunucusuna ilk": f"grep ALLOW {fw} | grep SRC={app} | grep -v DPT={legit} | head -1",
        "Veritabanı sunucusunda parolayla": f"grep 'Accepted password' loglar/{db_ad}_auth.log | head -1",
        "useradd": f"grep 'new user:' loglar/{db_ad}_auth.log | head -1",
    }
    zamanlar = []
    for satir in (lab / "olay_listesi.txt").read_text().splitlines()[1:]:
        no = int(satir.split(".", 1)[0])
        for anahtar, komut in komutlar.items():
            if anahtar in satir:
                zamanlar.append((sh(f"{komut} | grep -oP '{SAAT}' | head -1", lab), no))
    sira = " ".join(str(no) for _, no in sorted(zamanlar))
    # güvenlik duvarını düzelt: iki fazla kuralı sil
    sh(f"sed -i '/--dport {s['h1']} -j ACCEPT/{{/-s {v['ag'][0]}/d}}; /--dport {s['h2']} -j ACCEPT/{{/-s {v['ag'][1]}/d}}' sistem/fw/kurallar.rules", lab)
    rapor = ("Saldırgan önce DMZ'deki web sunucusunu sıçrama tahtası yapıp iç ağı taradı, sonra paylaşılan servis hesabının parolasıyla uygulama "
             "sunucusuna, oradan da aynı hesapla veritabanı sunucusuna SSH ile geçti ve yeni hesap oluşturdu. Kök nedenler: DMZ ile uygulama, "
             "uygulama ile veritabanı arasında gereğinden fazla açık port ve sunucular arasında paylaşılan parola. Önlem: kuralları daraltmak, "
             "hesapları ayırıp anahtarla giriş kullanmak, iç ağ taramasına alarm kuralı eklemek.")
    return sec_doldur({1: ip, 2: tarama, 3: port, 4: hesap, 5: sira, 6: db, 7: "", 8: "", 9: rapor}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Vaka dosyası", """
İkinci vaka, bir makineyi değil bir **ağı** ilgilendiriyor. Saldırgan dışa açık bir makineden içeri girdi (o kısım
Vaka 1'deki gibi; burada konumuz değil) ve oradan **iç ağda bir makineden diğerine** geçti. Buna **pivoting**
(sıçrama tahtası olarak kullanma) deniyor. Senin işin izini sürmek: hangi makine, hangisine, hangi saatte, hangi servisle.

<<musteri>> (<<sektor>>): <<hikaye>> Önce ağ şemasını ve dosyaları gör:
""", komut="cat ag_semasi.txt"),
    Adim("1. Paketlere bakış (pcap)", """
`yakalama.pcap`, iç güvenlik duvarında alınmış bir trafik kaydı. `tcpdump -nr` bu dosyayı okur (`-n` adları IP olarak
bırakır, `-r` dosyadan okur; sen hiçbir şey yakalamıyorsun, hazır kaydı okuyorsun). İlk beş paket:
""", komut="tcpdump -nr yakalama.pcap | head -5", sonra="""
Her satır: saat, `IP`, **kaynak.port > hedef.port**, TCP bayrakları (`Flags [S]` bağlantı isteği, `[S.]` isteğe
cevap, `[.]` onay, `[R.]` ret). Saat dilimi pcap'te bilgisayarının ayarına göre kayabilir; bu yüzden saat sorularını
sistem loglarıyla çöz.
"""),
    Adim("2. Tarama paterni: çok hedefe SYN", """
Bir makinenin ağdaki diğer makineleri taraması, tek başına yüzlerce **saf SYN** (yalnızca bağlantı isteği, cevapsız
`[S]`) olarak görünür. Saf SYN paketlerini süz ve kaç tane olduğuna bak:
""", komut="tcpdump -nr yakalama.pcap 'tcp[tcpflags] == tcp-syn' | wc -l", sonra="""
Bu filtre yalnızca bayrağı tam olarak SYN olanları alır; SYN-ACK cevapları (`[S.]`) dışarıda kalır. Şimdi sıra
"kim gönderiyor?" sorusunda.
"""),
    Adim("3. Kim en çok SYN gönderiyor?", """
Kaynak adresini ayıklayıp sayarsan tarayan makine öne çıkar. `awk '{print $3}'` kaynağı (`IP.port`), `cut -d. -f1-4`
port kısmını atar:
""", komut="tcpdump -nr yakalama.pcap 'tcp[tcpflags] == tcp-syn' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -3", sonra="""
Listede birkaç kaynak olabilir: biri **çok sayıda farklı hedefe** SYN gönderiyorsa tarayandır; bir diğeri az sayıda
SYN ile hep aynı portlara bakıyorsa büyük olasılıkla bir izleme aracıdır. Sayıya ve çeşitliliğe birlikte bak.
"""),
    Adim("4. Güvenlik duvarı: hangi portlar geçiyor?", """
Güvenlik duvarı logu, geçen (**ALLOW**) ve düşürülen (**DROP**) bağlantıları kaydeder. Meşru trafik hep aynı
birkaç porttan geçer; saldırı o düzenin dışındaki nadir bir porttan geçer. İzinli bağlantıların hedef portlarını say:
""", komut="grep ALLOW loglar/ic_guvenlik_duvari.log | grep -o 'DPT=[0-9]*' | sort | uniq -c | sort -rn", sonra="""
En üstteki portlar uygulamanın normal trafiği. Aşağıdaki **nadir** portlar (ssh gibi yönetim portları) genelde bakım
içindir; ama o bakım yönetim ağından mı yapılıyor, yoksa DMZ'deki bir web sunucusundan mı? Kaynağa bak.
"""),
    Adim("5. Sunucu logları: parolayla giriş", """
İki sunucunun `auth.log` dosyaları var. Meşru yöneticiler anahtarla (`publickey`) ve yönetim ağından girer. Bir
hesabın **parolayla** ve iç sunuculardan gelmesi ilginçtir:
""", komut="grep -h 'Accepted password' loglar/*_auth.log", sonra="""
Aynı hesap adı iki farklı makinede görünüyorsa, bu hesabın parolası makineler arasında **paylaşılıyor** demektir.
Saldırgan birini ele geçirince aynı parolayı ötekinde de denemek zorunda bile kalmaz: bilir. Bu, kimlik bilgisi
yeniden kullanımı (credential reuse) ve ağların en eski zayıflığıdır.
"""),
    Adim("6. Kural dosyası", """
Şimdi savunma tarafına geç. Güvenlik duvarının kural kopyasını oku; her `ACCEPT` satırı bir kapıdır ve ağ şemasındaki
niyetle karşılaştırılmalıdır (web → uygulama sadece 8443, uygulama → veritabanı sadece veritabanı portu):
""", komut="cat sistem/fw/kurallar.rules", sonra="""
**Hacker gözüyle:** pivoting'i kitapta kendi lab'ında yürüttün: ele geçirdiğin makineden iç ağa baktın. Şimdi aynı
hareketi izden okudun. Saldırgan her kapıdan geçemezdi; gereğinden fazla kapı açık bırakıldığı için geçti.
Savunmanın cevabı bölümlendirme ve en az yetkidir: her yönde yalnızca gerçekten gereken port.
"""),
]

GOREVLER = [
    Gorev("`yakalama.pcap` içinde iç ağı tarayan, yani **en çok saf SYN gönderen** makinenin IP'si hangisi? (sıçrama tahtası)",
          IP("web", sik_hatalar=_web_hata),
          ("Tarama, çok sayıda SYN'in tek kaynaktan çıkması demektir. Pcap'i bayrağa göre süz, kaynağa göre say.",
           "`tcpdump -nr yakalama.pcap 'tcp[tcpflags] == tcp-syn'` çıktısında üçüncü sütun kaynak; `cut -d. -f1-4` portu atar.",
           "`tcpdump -nr yakalama.pcap 'tcp[tcpflags] == tcp-syn' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -3`"),
          puan=40, baslik="Sıçrama tahtası"),
    Gorev("Bu makine pcap'te **kaç farklı iç IP adresine** saf SYN gönderdi?",
          Sayi("tarama", sik_hatalar=_tarama_hata),
          ("Hedef sütunu (beşinci sütun) kaynak değil, bakılan makineleri verir; tekrarları bir say.",
           "Önce kaynağı seç (awk), hedefi `IP.port:` olarak al, port kısmını at, `sort -u` ile tekilleştir.",
           "`... | awk -v ip=KAYNAK '{split($3,a,\".\"); k=a[1]\".\"a[2]\".\"a[3]\".\"a[4]; split($5,b,\".\"); if (k==ip) print b[1]\".\"b[2]\".\"b[3]\".\"b[4]}' | sort -u | wc -l`"),
          puan=50, baslik="Taranan hedef sayısı"),
    Gorev("Saldırgan uygulama sunucusundan <<dbad>> veritabanı sunucusuna geçerken meşru uygulama portu (<<dbport>>) dışında hangi **hedef portu** kullandı?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Güvenlik duvarı logunda uygulama sunucusundan veritabanı sunucusuna giden izinli bağlantılara bak; meşru olanlar hep aynı portta.",
           "Önce uygulama sunucusunun IP'sini bul (veritabanı logunda parolayla giriş yapılan kaynak), sonra o kaynaktan çıkan ALLOW satırlarında <<dbport>> dışını ara.",
           "`grep ALLOW loglar/ic_guvenlik_duvari.log | grep SRC=<APP_IP> | grep -v DPT=<<dbport>>`"),
          puan=40, baslik="Beklenmeyen servis portu"),
    Gorev("İki sunucuda (<<app_ad>> ve <<db_ad>>) da **parolayla başarıyla giren** paylaşılan hesabın adı nedir?",
          Metin("hesap", bicim="hesap adı", sik_hatalar=_hesap_hata),
          ("İki `auth.log` dosyasında 'Accepted password' satırlarına bak; ortak hesap adını ara.",
           "`grep 'Accepted password' loglar/*_auth.log` iki satır verir; `for` sözcüğünden sonra hesap adı gelir.",
           "`grep -h 'Accepted password' loglar/*_auth.log | grep -o 'for [a-z_0-9]*'`"),
          puan=30, baslik="Paylaşılan hesap"),
    Gorev("`olay_listesi.txt` içindeki altı olayı **gerçekleşme sırasına** diz. Cevap olarak listedeki **numaraları** sırayla yaz "
          "(örn. `4 2 1 6 3 5`).",
          Sira("sira", sik_hatalar=sira_hata),
          ("Her olayın kanıtı farklı bir dosyada: iç güvenlik duvarı, uygulama sunucusu, veritabanı sunucusu.",
           "Saatleri `grep -oP '(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}'` ile çek; güvenlik duvarında saldırgan IP'nin DROP'u ve ilk beklenmeyen ALLOW'u ayrı olaylar.",
           "Altı saati yan yana yaz, saate göre sırala ve olay numaralarını o sırayla oku."),
          puan=60, baslik="Zaman çizelgesi"),
    Gorev("Saldırganın iç ağda ulaştığı **son hedef** (veritabanı sunucusu) hangi IP'de?",
          IP("db"),
          ("Son sıçrama, uygulama sunucusundan beklenmeyen bir porta giden bağlantıdır.",
           "Güvenlik duvarı logunda uygulama sunucusunun beklenmeyen porta giden ALLOW satırına bak; `DST=` hedeftir.",
           "`grep ALLOW loglar/ic_guvenlik_duvari.log | grep SRC=<APP_IP> | grep -v DPT=<<dbport>> | grep -o 'DST=[0-9.]*'`"),
          puan=30, baslik="Son hedef"),
    Gorev("`sistem/fw/kurallar.rules` kopyasını düzelt: DMZ'den yalnızca uygulama sunucusunun **8443** portuna, uygulama katmanından "
          "yalnızca veritabanının **<<dbport>>** portuna izin kalsın; yönetim ağının bakım erişimine ve `:FORWARD DROP` satırına dokunma. "
          "Bitince `cevap 7`.",
          Durum(_fw_kontrol, "DMZ→uygulama ve uygulama→veritabanı için fazla ssh kurallarını silmek"),
          ("Hangi `ACCEPT` satırları şemada yazan niyetin dışında bir port açıyor? Yönetim ağının kuralları ise meşru.",
           "`grep -n ACCEPT sistem/fw/kurallar.rules`; DMZ kaynaklı ve uygulama kaynaklı fazla porta izin veren iki satırı bul; `sed -i 'NUMARAd' dosya` satır siler.",
           "Satır numarasını bulup `sed -i 'Nd' sistem/fw/kurallar.rules`; ya da `sed -i '/-s <DMZ>.*--dport <PORT> -j ACCEPT/d'`. Yönetim satırlarındaki `-s 10.99.0.0/24` kalsın."),
          puan=70, baslik="Güvenlik duvarını düzelt"),
    Gorev("Bu olayın **kök nedeni** hangisidir?",
          Secmeli([
              ("Bölümler arasında gereğinden fazla port açık ve sunucular arasında aynı hesap parolası paylaşılıyor",
               "Doğru. Biri saldırganın makineler arası yolunu, diğeri her makinede yeniden giriş yapabilmesini sağladı."),
              ("Saldırgan, güvenlik duvarının loglarını silerek izini kaybettirdi ve tespit edilmesi bu yüzden gecikti",
               "Yanlış. Loglar duruyor ve bütün zinciri gösteriyor; tespit gecikmesi olsa bile kök neden bu değildir."),
              ("SSH protokolünün kendisi güvensizdir; bu yüzden hiçbir kurumda SSH kullanılmamalı, kaldırılmalıdır",
               "Yanlış. SSH doğru yapılandırılınca (anahtarla giriş, dar erişim) güvenlidir; sorun SSH'ın kimden kime açık ve parolayla kullanılmasıdır."),
              ("Veritabanı sunucusunun kapasitesi düşük olduğu için saldırı sırasında belirgin biçimde yavaşlamış olması",
               "Yanlış. Performans bir belirti olabilir, neden değildir; saldırının yolu erişim kuralları ve kimlik bilgisiydi."),
          ], dogru=0),
          ("Kök neden, saldırganın yolunu açan düzeltilebilir hatadır. Yol iki şeyden oluştu: nereye gidebildi, hangi anahtarla girdi?",
           "Birinci hata ağ kurallarında (güvenlik duvarı), ikinci hata kimlik bilgisinde (hesap) idi.",
           "Doğru şık, bölümlendirme eksikliği ile paylaşılan parolayı birlikte söyleyen şıktır."),
          puan=30, baslik="Kök neden"),
    Gorev("**Ağdaki ilerleme yolunu** kısaca yaz (en az 30 kelime, tırnak içinde): hangi makineden hangisine, hangi servisle, kök neden ve ilk iki önlem. "
          "Bitince `cevap 9 \"...\"`.",
          Serbest("Saldırgan DMZ'deki <<web_ad>> sunucusunu sıçrama tahtası yapıp önce iç ağı taradı (çok sayıda farklı hedefe SYN), sonra paylaşılan servis "
                  "hesabının parolasıyla SSH üzerinden <<app_ad>> sunucusuna, oradan aynı hesapla <<db_ad>> veritabanı sunucusuna geçti ve orada yeni bir "
                  "hesap oluşturdu. Kök neden: DMZ'den uygulama katmanına ve uygulamadan veritabanına gereğinden fazla ssh portu açık (segmentasyon "
                  "eksikliği) ve hesap parolasının sunucular arasında paylaşılması. Önlemler: güvenlik duvarı kurallarını yalnızca gereken porta daraltmak, "
                  "sunucu başına ayrı hesap ve anahtarla giriş kullanmak, iç ağ taramasına alarm kuralı yazmak.", min_kelime=30),
          ("Yolu bir diyagram gibi anlat: A makinesinden B'ye, B'den C'ye. Her sıçramaya servis ve saat ekle.",
           "Önce makine zincirini, sonra kök nedeni (bölümlendirme + paylaşılan hesap), sonra iki önlemi yaz.",
           "`cevap 9 \"Saldırgan A'dan B'ye ... B'den C'ye ... Kök neden ... Önlem ...\"` biçiminde, tırnak içinde yaz."),
          puan=60, baslik="Ağdaki ilerleme yolu"),
]


def _kapanis():
    return """
Gerçek ağlar düz değil katmanlıdır; saldırgan nadiren doğrudan hedefe gelir, zayıf bir dış makineden başlayıp içeri
doğru ilerler. Bu vakada yolu **üç şey** belirledi: açık bırakılmış fazla kapılar, makineler arası paylaşılan bir parola
ve iç ağda hiçbir alarmın çalmaması. Savunmacı olarak her biri için bir önlem koyarsın: dar güvenlik duvarı kuralları
(bölümlendirme), makine başına ayrı kimlik ve anahtarla giriş, tarama ve beklenmeyen bağlantılar için alarm. Saldırgan
olarak ise bölümlendirmeyi okumak, hangi kapıların gerçekten açık olduğunu bilmek demektir.
"""


SEVIYE = Seviye(
    kimlik="c24b02",
    cilt=24,
    bolum=2,
    baslik="Vaka 2: Ağda İlerleme (Olay İncelemesi)",
    brifing="""
Deniz Kara ekranını sana çeviriyor: "İkinci vaka daha zor, çünkü kanıt tek yerde değil. İç güvenlik duvarında bir
log, iki sunucuda birer `auth.log` ve ağdan alınmış bir paket kaydı var." Selin Aksoy ekliyor: "**<<musteri>>**
(<<sektor>>). <<hikaye>> Saldırgan dışarıdan bir makineyi ele geçirmiş; asıl soru **içeride ne kadar ilerlediği**."

Mert Yavuz, kahvesini bırakıp ağ şemasına parmağını koyuyor: "Kitapta bu hareketi kendin yürüttün: ele geçirdiğin
makineden iç ağa baktın. Şimdi aynı izi karşı taraftan oku. Bir de şunu unutma: kimse bir makineden ötekine sihirle
geçmez, **bir kapı açıktır ve bir parola işe yarar**."

Görevin: makineden makineye yolu, saatleri ve servisleri çıkarmak; segmentasyon eksikliğini bulup güvenlik duvarı
kurallarını düzeltmek.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Target 2013:** Kamuya açık anlatımlara göre saldırganlar, bir dış hizmet sağlayıcısının kimlik bilgileriyle ağa girdi ve
  oradan kart verisi işleyen sistemlere ilerledi. Ağ bölümlendirmesinin yetersizliği, olayın tartışılan temel dersidir.
  Tespit tarafı: iç ağda beklenmeyen bağlantı ve tarama için alarm; önleme tarafı: bölümlendirme ve en az yetki.
- **NotPetya 2017:** Birçok kurumda düz (bölümlenmemiş) iç ağlar zararlı yazılımın çok kısa sürede yayılmasını kolaylaştırdı.
  Savunma katmanında segmentasyon, yayılmayı sınırlayan en etkili yapı önlemlerinden biridir.
- **PCI-DSS ve ağ bölümlendirmesi:** Kart verisi ortamını diğer ağlardan ayırmak, hem saldırı yüzeyini hem uyum kapsamını küçültür.
  İç güvenlik duvarı loglarının izlenmesi (beklenmeyen kaynaktan yönetim portlarına izinli bağlantı) ucuz ve etkili bir tespit kuralıdır.
""",
    sure_hedef_dk=60,
)
