"""Cilt 3 · Bölüm 4 — Kendi Port Tarayıcını Yaz.

Beceri: socket, settimeout, connect_ex; bir port aralığını tarama (range'in son değeri
dahil değildir!), açık portları servis adıyla yazma, banner okuma (recv) ve zaman aşımının
önemi; connect taraması ile SYN taraması arasındaki fark.

Laboratuvar: müşteri sunucusu, her tohumda farklı bir loopback adresinde (127.a.b.c) 5-8
portta dinler. Oyuncunun kendi makinesinde 127.0.0.1'de çalışan servisler (Burp, eski bir
http.server...) sonuçları kirletmesin diye 127.0.0.1 kullanılmaz. Oyun, oyuncunun
tarayıcısını hem bu hedefte hem de kontrol anında açılan geçici bir hedefte çalıştırır.
"""
from __future__ import annotations

import contextlib
import random
import re
import socket
import subprocess
import time
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Kontrol, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import SessizIsleyici, calistir, tcp_banner
from hy.seviyeler.c03_otomasyon.ortak import http_sunucu
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "kuzgun", "sunucu": "kzg-depo", "uygulama": "KZG-STOK-API", "panel": "Kuzgun Depo Stok Paneli",
        "ftp_not": "etiket yazıcılarına dosya aktarımı",
        "olay": "Kuzgun Lojistik'in depo sunucusu kzg-depo için yetkilendirme mektubu imzalandı; kapsam tek "
                "sunucu. Serdar Bey sunucuda \"sadece SSH ve stok paneli\" olduğunu söylüyor.",
    },
    {
        "kod": "paramix", "sunucu": "pmx-api01", "uygulama": "PMX-ODEME-KUYRUK", "panel": "Paramix Üye İşyeri Paneli",
        "ftp_not": "bankalarla gece mutabakat dosyası alışverişi",
        "olay": "Paramix'in ödeme API sunucusu pmx-api01 yeni bir veri merkezine taşındı. Ece Hanım taşıma "
                "sırasında unutulmuş bir servis açık kalmış mı diye soruyor.",
    },
    {
        "kod": "atolye", "sunucu": "atolye-web", "uygulama": "KASA-SENKRON", "panel": "Atölye Kahve Yönetim",
        "ftp_not": "eski siteyi yüklemek için kurulmuş, \"kapatılmıştı\"",
        "olay": "Atölye Kahve'nin tek sunucusu atolye-web hem siteyi hem kasa senkronizasyonunu taşıyor. Berk "
                "sunucuyu bir arkadaşına kurdurmuş ve üzerinde ne çalıştığını bilmiyor.",
    },
    {
        "kod": "medora", "sunucu": "medora-pacs", "uygulama": "MDR-HL7-KOPRU", "panel": "Medora Görüntü Arşivi",
        "ftp_not": "eski görüntüleme cihazlarından dosya alımı",
        "olay": "Medora'nın görüntü arşivi sunucusu medora-pacs, hastane ağından erişilebilir durumda. Dr. Aslı "
                "Hanım üzerinde hangi servislerin açık olduğunun tam listesini istiyor.",
    },
]

ARALIKLAR = [(1000, 8080), (1024, 9000), (2000, 8443), (1000, 9090), (1500, 6000)]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    hedef = f"127.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(2, 250)}"
    bas, son = rng.choice(ARALIKLAR)
    turler = ["ssh", "ftp", "smtp", "http", "yavas"] + rng.sample(["sessiz", "sessiz2", "ssh2"], rng.randint(0, 3))
    rng.shuffle(turler)
    portlar = [son] + rng.sample(range(max(bas, 1025) + 1, son), len(turler) - 1)
    servisler = dict(zip(portlar, turler))
    ters = {t: p for p, t in servisler.items()}
    kapali = rng.choice([p for p in range(max(bas, 1025), son) if p not in servisler])
    return {
        "vaka": f"{m['ad']} — {v['sunucu']} port taraması",
        "musteri": m,
        "v": v,
        "hedef": hedef,
        "aralik": (bas, son),
        "servisler": {str(p): t for p, t in servisler.items()},
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "sunucu": v["sunucu"], "hedef": hedef,
            "bas": bas, "son": son, "ssh": ters["ssh"], "kapali": kapali, "alan": m["alan"],
            "ftp_not": v["ftp_not"],
        },
        "cevaplar": {
            "portlar": sorted(portlar),
            "ftp": ters["ftp"],
            "http": ters["http"],
            "bayrak": u.bayrak(rng, "sabirli_dinleyici"),
        },
    }


def _bannerlar(s: dict) -> dict:
    v = s["v"]
    m = s["musteri"]
    bayrak = s["cevaplar"]["bayrak"]

    def yavas():
        time.sleep(1.5)
        return f"{v['uygulama']} v3.2 hazir | oturum_anahtari={bayrak}\n"

    return {
        "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
        "ssh2": "SSH-2.0-dropbear_2022.83\r\n",
        "ftp": f"220 ({v['sunucu']} FTP sunucusu - vsFTPd 3.0.5)\r\n",
        "smtp": f"220 {v['sunucu']}.{m['alan']} ESMTP Postfix (Ubuntu)\r\n",
        "sessiz": "",
        "sessiz2": "",
        "yavas": yavas,
    }


def servis(s: dict, lab: Path, dur) -> None:
    hedef = s["hedef"]
    panel = s["v"]["panel"]

    class Panel(SessizIsleyici):
        server_version = "nginx/1.24.0"

        def do_GET(self):
            self.yanit(200, f"<html><head><title>{panel}</title></head><body><h1>{panel}</h1>"
                            "<p>Giriş yapın.</p></body></html>\n")

        do_HEAD = do_GET

    bannerlar = _bannerlar(s)
    sunucular = []
    for p, tur in s["servisler"].items():
        if tur == "http":
            sunucular.append(http_sunucu(hedef, int(p), Panel))
        else:
            sunucular.append(tcp_banner(hedef, int(p), bannerlar[tur]))
    calistir(sunucular, dur)


TEK_PORT_PY = '''#!/usr/bin/env python3
# tek_port.py — tek bir portu dener
import socket
import sys

ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # TCP soketi
s.settimeout(1)                                         # en fazla 1 sn bekle
sonuc = s.connect_ex((ip, port))                        # 0 = bağlandı
s.close()
print(f"{ip}:{port} ->", "açık" if sonuc == 0 else f"kapalı (kod {sonuc})")
'''

BANNER_PY = '''#!/usr/bin/env python3
# banner.py — bir porta bağlanıp servisin ilk söylediğini okur
import socket
import sys

ip, port = sys.argv[1], int(sys.argv[2])
s = socket.socket()
s.settimeout(1)                 # DİKKAT: 1 saniyeden geç konuşan servisi kaçırır
try:
    s.connect((ip, port))
    veri = s.recv(1024)
    print(veri.decode(errors="replace").strip() or "(bağlandı ama servis bir şey söylemedi)")
except socket.timeout:
    print("(zaman aşımı: servis 1 saniye içinde bir şey göndermedi)")
except OSError as e:
    print(f"(hata: {e})")
finally:
    s.close()
'''

KITAP_TARAYICI_PY = '''#!/usr/bin/env python3
# kitap_tarayici.py — kitaptaki ilk sürüm: sadece bilinen 10 portu dener
import socket
import sys

servisler = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
             443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt"}


def port_tara(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


if len(sys.argv) < 2:
    print(f"Kullanım: {sys.argv[0]} <ip>")
    sys.exit(1)

hedef = sys.argv[1]
print(f"[*] {hedef} taranıyor...")
for port in sorted(servisler):
    if port_tara(hedef, port):
        print(f"[+] {port}/tcp açık  ({servisler[port]})")
print("[*] Tarama bitti.")
'''

TARAYICI_PY = '''#!/usr/bin/env python3
import socket
import sys

servisler = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
             443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-alt"}


def port_tara(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


if len(sys.argv) < 4:
    print(f"Kullanım: {sys.argv[0]} <ip> <ilk_port> <son_port>")
    sys.exit(1)

hedef = sys.argv[1]
try:
    ilk, son = int(sys.argv[2]), int(sys.argv[3])
except ValueError:
    print("Hata: portlar sayı olmalı.")
    sys.exit(1)

print(f"[*] {hedef} taranıyor ({ilk}-{son})...")
bulunan = 0
for port in range(ilk, son + 1):          # son + 1: son port da dahil
    if port_tara(hedef, port):
        print(f"[+] {port}/tcp açık  ({servisler.get(port, '?')})")
        bulunan += 1
if bulunan == 0:
    print("[-] Açık port bulunamadı.")
print("[*] Tarama bitti.")
'''


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    bas, son = s["aralik"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['sunucu']} (laboratuvar kopyası)\n\n"
          f"Hedef adres : {s['hedef']}   (127.0.0.0/8 loopback; gerçek sunucuyu temsil eder)\n"
          f"Kapsam      : TCP {bas}-{son} (iki uç dahil)\n\n"
          "Kendi tarayıcını lab'ın köküne yaz: tarayici.py\n"
          f"Kullanım    : python3 tarayici.py {s['hedef']} {bas} {son}\n")
    u.yaz(lab / "ornekler" / "tek_port.py", TEK_PORT_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "banner.py", BANNER_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "kitap_tarayici.py", KITAP_TARAYICI_PY, mod=0o755)


# ---------------------------------------------------------------- denetimler

def port_acik_mi(host: str, port: int, zaman: float = 0.5) -> bool:
    with contextlib.suppress(OSError):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(zaman)
            return s.connect_ex((host, port)) == 0
    return False


def tcp_portlari(metin: str) -> set:
    return {int(p) for p in re.findall(r"\b(\d{1,5})\s*/\s*tcp\b", metin, re.I)}


class AcikPortlar(Kontrol):
    """Açık port listesi. Vakanın portlarının hepsi olmalı; fazlalar ancak oyuncunun kendi
    makinesinde gerçekten açık başka bir servise aitse (0.0.0.0'da dinleyen) kabul edilir."""

    def __init__(self, anahtar: str = "portlar", host_yolu=("hedef",), aralik_yolu=("aralik",),
                 bicim: str = "port listesi (virgül/boşlukla)"):
        self.anahtar = anahtar
        self.host_yolu = host_yolu
        self.aralik_yolu = aralik_yolu
        self.bicim = bicim

    def _al(self, s: dict, yol: tuple):
        for k in yol:
            s = s[k]
        return s

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        verilen = set(bt.sayilar(girdi))
        beklenen = set(self.beklenen(b))
        if not verilen:
            return Sonuc(False, f"Cevabı {self.bicim} olarak yaz.")
        if verilen == beklenen:
            return Sonuc(True)
        bas, son = self._al(b.senaryo, self.aralik_yolu)
        eksik = beklenen - verilen
        fazla = verilen - beklenen
        if eksik:
            mesaj = f"{len(verilen & beklenen)} doğru, {len(eksik)} eksik"
            if fazla:
                mesaj += f", {len(fazla)} fazla"
            mesaj += "."
            if son in eksik:
                mesaj += (f" {son} listende yok: Python'da `range({bas}, {son})` son değeri DAHİL ETMEZ; "
                          f"`range({bas}, {son} + 1)` yaz.")
            return Sonuc(False, mesaj, yakin=bool(verilen & beklenen))
        host = self._al(b.senaryo, self.host_yolu)
        gercek = sorted(p for p in fazla if bas <= p <= son and port_acik_mi(host, p))
        if len(gercek) == len(fazla):
            return Sonuc(True, f"Vakanın bütün portlarını buldun. Fazladan yazdığın {', '.join(map(str, gercek))} "
                               "gerçekten açık, ama o port senin makinende her adreste (0.0.0.0) dinleyen başka bir "
                               "programa ait; bu vakanın sunucusuna değil. Kabul ediyorum.")
        return Sonuc(False, f"Bütün portları buldun ama {len(fazla) - len(gercek)} fazladan port yazdın; şu an "
                            "kapalılar.", yakin=True)

    def cevabi_goster(self, b: Baglam) -> str:
        return ", ".join(map(str, sorted(self.beklenen(b))))


def tarama_denetle(calistir: bt.Calistirici, host: str, bas: int, son: int, beklenen: set,
                   sabit: set | None = None, zaman: float = 90) -> Sonuc | None:
    """Tarayıcıyı bir hedefte çalıştırıp sonucu denetler. Sorun yoksa None (b07 de kullanır)."""
    c = calistir(host, bas, son, zaman_asimi=zaman)
    nasil = calistir.goster(host, bas, son)
    cokme = calistir.cokme(c)
    if cokme:
        if c.zaman_asimi:
            cokme += " Her denemeye `settimeout(0.5)` gibi kısa bir zaman aşımı verdin mi?"
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    bulunan = {p for p in tcp_portlari(c.stdout) if bas <= p <= son}
    if bulunan == beklenen:
        return None
    if not bulunan:
        if any(re.search(r"\d", sat) and re.search(r"a[cç][iı]k|open", sat, re.I) and "/tcp" not in sat
               and not re.search(r"bulunamad|yok|no open", sat, re.I) for sat in c.stdout.splitlines()):
            return Sonuc(False, f"`{nasil}` çıktısında `PORT/tcp` biçiminde satır bulamadım. Açık her portu "
                         "`[+] 8080/tcp açık` gibi yaz." + bt.ozet(c), yakin=True)
        return Sonuc(False, f"`{nasil}` hiç açık port bulamadı ({len(beklenen)} olmalıydı). `connect_ex` 0 "
                     "döndürünce port AÇIKTIR; hedef IP'yi ve aralığı argümanlardan aldığını kontrol et."
                     + bt.ozet(c))
    if len(bulunan) > max(20, (son - bas) // 2):
        return Sonuc(False, f"`{nasil}` {len(bulunan)} port açık dedi; bu aralıkta sadece {len(beklenen)} açık. "
                     "Mantık ters olabilir: `connect_ex` 0 dönerse AÇIK, başka bir sayı dönerse KAPALI.", yakin=True)
    if sabit is not None and bulunan == sabit:
        return Sonuc(False, "Farklı bir hedefte laboratuvarın sonuçlarını verdin; portları sabit yazmış olabilir "
                     "misin? Hedefi ve aralığı `sys.argv`'den al.", yakin=True)
    eksik = beklenen - bulunan
    fazla = {p for p in bulunan - beklenen if not port_acik_mi(host, p)}
    if not eksik and not fazla:
        return None   # fazlalar oyuncunun makinesindeki gerçek açık portlar
    if eksik == {son}:
        return Sonuc(False, f"`{nasil}` son portu ({son}) kaçırdı. `range({bas}, {son})` son değeri DAHİL ETMEZ; "
                     f"`range(ilk, son + 1)` yaz.", yakin=True)
    if eksik == {bas}:
        return Sonuc(False, f"`{nasil}` ilk portu ({bas}) kaçırdı; döngü `ilk` değerinden başlamalı.", yakin=True)
    mesaj = f"`{nasil}` {len(beklenen)} açık port bulmalıydı, {len(bulunan & beklenen)} tanesini buldu"
    if eksik:
        mesaj += (f"; {len(eksik)} eksik. Zaman aşımı çok mu kısa (en az 0.2-0.5 sn)? Aralığın iki ucunu da "
                  "dahil ettin mi?")
    if fazla:
        mesaj += f"; kapalı olduğu halde açık dediğin {len(fazla)} port var ({', '.join(map(str, sorted(fazla)[:3]))})."
    return Sonuc(False, mesaj + bt.ozet(c), yakin=True)


def _tarayici_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    for args in ((), (s["hedef"],)):
        hata = bt.kullanim_denetle(calistir, *args)
        if hata:
            return Sonuc(False, hata, yakin=True)
    rng = random.Random()

    def adresler(r):
        host = f"127.{r.randint(1, 250)}.{r.randint(1, 250)}.{r.randint(2, 250)}"
        bas = r.randint(3000, 9000)
        son = bas + r.randint(80, 200)
        return [(host, p) for p in [bas, son] + r.sample(range(bas + 1, son), r.randint(1, 3))]

    gecici = bt.gecici_dinleyici_ac(rng, adresler)
    try:
        host = gecici.adresler[0][0]
        portlar = {p for _, p in gecici.adresler}
        sonuc = tarama_denetle(calistir, host, min(portlar), max(portlar), portlar,
                               sabit=set(s["cevaplar"]["portlar"]))
        if sonuc:
            return sonuc
    finally:
        gecici.__exit__()
    bas, son = s["aralik"]
    sonuc = tarama_denetle(calistir, s["hedef"], bas, son, set(s["cevaplar"]["portlar"]))
    if sonuc:
        return sonuc
    return Sonuc(True, "tarayici.py hem laboratuvar sunucusunda hem de kontrol anında açtığım, senin hiç "
                       "görmediğin bir hedefte doğru çalıştı; iki uç dahil. Bu, `nmap -sT`'nin özü.")


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path, zaman: int = 120) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=zaman).stdout


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "tarayici.py", TARAYICI_PY)
    hedef = s["metin"]["hedef"]
    bas, son = s["metin"]["bas"], s["metin"]["son"]
    portlar = sorted(tcp_portlari(_sh(f"python3 tarayici.py {hedef} {bas} {son}", lab)))
    # Banner'ları sabırla (3 sn) oku; HTTP'yi curl ile sor.
    ftp, http, bayrak = None, None, ""
    for p in portlar:
        banner = _sh(f"python3 -c 'import socket; s = socket.create_connection((\"{hedef}\", {p}), 3); "
                     f"s.settimeout(3)\ntry:\n    print(s.recv(1024).decode(errors=\"replace\"))\n"
                     f"except OSError:\n    pass'", lab)
        if banner.startswith("220") and "FTP" in banner:
            ftp = p
        m = re.search(r"FLAG\{[^}]+\}", banner)
        if m:
            bayrak = m.group(0)
        kod = _sh(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 http://{hedef}:{p}/", lab)
        if kod.strip() == "200":
            http = p
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (6, 7, 8)}
    return {1: "", 2: " ".join(map(str, portlar)), 3: ftp, 4: http, 5: bayrak, **secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("socket: ağın yapı taşı", """
Cilt 2'de üçlü el sıkışmasını (SYN, SYN-ACK, ACK) öğrendin. Port açıksa bağlantı kurulur,
kapalıysa karşı taraf RST ile reddeder. Tarayıcımız tam olarak bunu dener. Python'ın
`socket` kütüphanesiyle tek bir portu deneyen örneğe bak:
""", komut="cat ornekler/tek_port.py", sonra="""
`socket.socket(AF_INET, SOCK_STREAM)` bir IPv4 TCP soketi oluşturur. `settimeout(1)` her
denemeye en fazla 1 saniye tanır. `connect_ex` bağlanmayı dener ve sonucu **sayı** olarak
döndürür: 0 ise bağlantı kuruldu, yani port açık.
"""),
    Adim("Açık ve kapalı", """
Hedef sunucu laboratuvarda `<<hedef>>` adresinde (127.0.0.0/8'in tamamı loopback).
SSH'ın dinlediği portu dene:
""", komut="python3 ornekler/tek_port.py <<hedef>> <<ssh>>", sonra="""
Şimdi aynı komutu kapalı bir portla (`<<kapali>>`) kendin dene: kod 111 göreceksin.
111, Linux'ta ECONNREFUSED'dır (bağlantı reddedildi): karşıda biri var ama o kapıda
kimse yok. Filtrelenmiş (güvenlik duvarının sessizce düşürdüğü) bir portta ise hiç cevap
gelmez ve `settimeout` dolana kadar beklersin.
"""),
    Adim("Kitaptaki ilk tarayıcı", """
Kitaptaki ilk sürüm bilinen 10 portu tek tek dener ve açık olanları servis adıyla yazar.
Oku ve hedefte çalıştır:
""", komut="python3 ornekler/kitap_tarayici.py <<hedef>>", sonra="""
Bulduğu portlar (bulduysa) sunucudaki servislerin çok azı. Servisler alışılmış portlarda
değil! Gerçek sunucularda da yöneticiler servisleri sık sık standart dışı
portlara taşır. Çözüm: bilinen listeyi değil, bir **aralığı** taramak. `cat
ornekler/kitap_tarayici.py` ile kodu oku; kendi tarayıcını bunun üzerine kuracaksın.
"""),
    Adim("range'in tuzağı", """
Bir aralığı taramak için `for port in range(ilk, son):` yazılır. Ama Python'da `range`'in
**son değeri dahil değildir**:
""", komut="python3 -c 'print(list(range(1, 5)))'", sonra="""
5 yok! `range(1000, 8080)` 8080'i hiç denemez. Kapsam "1000-8080, iki uç dahil" diyorsa
`range(ilk, son + 1)` yazmalısın. Bu hata gerçek taramalarda kritik portu (8080 gibi)
kaçırmana yol açar.
"""),
    Adim("Banner: kapıyı açan ne diyor?", """
Bağlantı kurulduktan sonra `recv(1024)` ile servisin ilk söylediğini okuyabilirsin
(**banner grabbing**). SSH, FTP, SMTP gibi servisler bağlanana kendini tanıtır; HTTP ise
önce senin istek göndermeni bekler.
""", komut="python3 ornekler/banner.py <<hedef>> <<ssh>>", sonra="""
Sürüm bilgisi bile geldi: saldırgan için altın değerinde (o sürümün bilinen açıkları var
mı?). Ama dikkat: bu örnek `settimeout(1)` kullanıyor. Bir servis karşılamasını 1
saniyeden geç gönderirse "zaman aşımı" görürsün ve servisin konuştuğunu hiç öğrenemezsin.
Zaman aşımı hızla doğruluk arasında bir **pazarlıktır**.
"""),
    Adim("HTTP konuşturmak", """
Banner vermeyen bir port HTTP olabilir. `curl` ile sor; `-s` sessiz, `-I` sadece başlıklar
(Cilt 2, Bölüm 5). Hangi portta deneyeceğini tarayıcın söyleyecek; şimdilik kalıbı gör:
""", komut="curl -s -I --max-time 2 http://<<hedef>>:<<ssh>>/", sonra="""
SSH portuna HTTP konuşmaya çalıştık; curl anlamlı bir cevap alamadı ve hiçbir şey yazmadı
(`-s` hata mesajını da susturur). Doğru porta sorunca `HTTP/1.0 200 OK` ve bir `Server:` başlığı göreceksin.

**Hacker gözüyle:** Bu tarayıcı tam bağlantı kurar (connect taraması); hedefte loglanır,
gürültülüdür. nmap'in SYN taraması el sıkışmayı tamamlamadığı için daha sessizdir. Gerçek
testte ne zaman gürültü yapacağını bilerek seçersin.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`tarayici.py` yaz: `python3 tarayici.py <ip> <ilk_port> <son_port>` verilen aralığı (**iki uç "
          "dahil**) TCP connect ile tarasın ve açık her portu ayrı satırda `PORT/tcp` biçiminde yazsın (örn. "
          "`[+] 8080/tcp açık`). Üç argüman gelmezse kullanım mesajı + `sys.exit(1)`. Kendin dene: "
          "`python3 tarayici.py <<hedef>> <<bas>> <<son>>`",
          bt.BetikKontrol("tarayici.py", _tarayici_denetle,
                          "Örnek `tarayici.py`:\n\n```\n" + TARAYICI_PY.rstrip() + "\n```", zaman_asimi=90),
          ("`ornekler/kitap_tarayici.py`'deki `port_tara` fonksiyonu hazır; sadece port listesini bir aralıkla "
           "değiştirmen ve argümanları okuman gerek.",
           "`ilk, son = int(sys.argv[2]), int(sys.argv[3])` ve `for port in range(ilk, son + 1):`. Kısa bir "
           "zaman aşımı (`settimeout(0.5)`) yeterli.",
           "İskelet:\n\n```\nimport socket, sys\ndef port_tara(ip, port):\n    s = socket.socket()\n    "
           "s.settimeout(0.5)\n    ...connect_ex... == 0\nif len(sys.argv) < 4: ...\nfor port in range(..., ... + 1):\n"
           "    if port_tara(...):\n        print(f\"[+] {port}/tcp açık\")\n```"),
          puan=60, baslik="Port tarayıcı"),
    Gorev("<<sunucu>> (<<hedef>>) üzerinde <<bas>>-<<son>> aralığında açık olan **bütün** portlar hangileri?",
          AcikPortlar(),
          ("Tarayıcını kapsam aralığıyla çalıştır.",
           "`python3 tarayici.py <<hedef>> <<bas>> <<son>>`",
           "Çıktıdaki `/tcp` öncesindeki sayıları boşlukla ayırarak yaz: `cevap 2 1234 5678 ...`"),
          puan=40, baslik="Açık portlar"),
    Gorev("<<kisi>> FTP'nin \"<<ftp_not>>\" için kurulduğunu söylüyor. Açık portlardan hangisi kendini "
          "**FTP** sunucusu olarak tanıtıyor?",
          Sayi("ftp"),
          ("Servisin adı banner'ında yazar.",
           "Her açık porta `python3 ornekler/banner.py <<hedef>> PORT` ile bak; FTP banner'ı `220` ile başlar.",
           "`for p in PORTLAR; do echo \"== $p\"; python3 ornekler/banner.py <<hedef>> $p; done` (PORTLAR yerine "
           "bulduğun portları yaz)"),
          puan=30, baslik="FTP nerede"),
    Gorev("Panel (web arayüzü) hangi portta? Web sunucuları banner vermez; önce sen istek göndermelisin.",
          Sayi("http"),
          ("Banner'da \"zaman aşımı\" ya da hiçbir şey dönmeyen portlardan biri HTTP konuşuyor olabilir.",
           "Şüpheli portlara `curl -s -I --max-time 2 http://<<hedef>>:PORT/` ile istek gönder.",
           "`HTTP/1.0 200 OK` ve `Server:` başlığı dönen port panelin portudur."),
          puan=30, baslik="Panel"),
    Gorev("Bir servis acelecileri sevmiyor: karşılama mesajını bağlantıdan biraz sonra gönderiyor ve içinde bir "
          "oturum anahtarı (bayrak) sızdırıyor. Bayrağı bul.",
          Bayrak("bayrak"),
          ("`ornekler/banner.py` her portta 1 saniye bekliyor. Bir servis daha geç konuşursa ne olur?",
           "banner.py'nin bir kopyasını al ve `settimeout(1)`'i `settimeout(3)` yap; sonra bütün açık portlarda dene.",
           "`cp ornekler/banner.py banner3.py`, `sed -i 's/settimeout(1)/settimeout(3)/' banner3.py`, sonra her port "
           "için `python3 banner3.py <<hedef>> PORT`"),
          puan=40, baslik="Sabırlı dinleyici"),
    Gorev("Kitaptaki tarayıcı neden `connect` yerine `connect_ex` kullanıyor?",
          Secmeli([
              ("`connect` hata fırlatır, `connect_ex` hata kodu döndürür",
               "Doğru. Kapalı portta `connect` istisna fırlatır ve ayrı bir try/except ister; `connect_ex` 0 ya da bir "
               "hata kodu döndürür, döngüde daha temizdir."),
              ("`connect_ex` bağlantıyı şifrelediği için daha güvenlidir",
               "İkisi de şifresiz düz bir TCP bağlantısı kurar; fark hata bildirme biçiminde."),
              ("`connect_ex` UDP portlarını da tarar, `connect` sadece TCP'yi",
               "Protokolü soketin türü (SOCK_STREAM/SOCK_DGRAM) belirler, bu iki fonksiyon değil."),
              ("`connect_ex` hedefte iz bırakmaz, `connect` log bırakır",
               "İkisi de tam bağlantı kurar ve hedefte aynı şekilde loglanabilir."),
          ]),
          ("Kapalı bir portta iki fonksiyon nasıl davranır?",
           "Biri istisna (exception) fırlatır, diğeri bir sayı döndürür.",
           "`connect_ex` = connect + \"hata yerine kod\" (ex: extended)."),
          puan=20, baslik="connect_ex"),
    Gorev("Tarayıcıdan `settimeout` satırını silersen ne olur?",
          Secmeli([
              ("Filtreli portlarda soket uzun süre bekler, tarama kilitlenir",
               "Doğru. Cevap vermeyen (filtrelenmiş) bir portta soket işletim sisteminin varsayılan süresince "
               "(dakikalarca olabilir) bekler; binlerce portta tarama pratikte durur."),
              ("Python varsayılan olarak 1 saniye bekler, hiçbir şey değişmez",
               "Varsayılan zaman aşımı yoktur (None); soket işletim sistemi pes edene kadar bekler."),
              ("Kapalı portlar da açık görünmeye başlar ve sonuç şişer",
               "Zaman aşımı sonucu değiştirmez; kapalı port yine RST ile reddedilir."),
              ("Soket oluşturulamaz ve betik hemen hata verip durur",
               "Soket zaman aşımı olmadan da oluşturulur; sorun bekleme süresinde."),
          ]),
          ("Laboratuvarda kapalı portlar anında reddediliyor; gerçek ağda her zaman öyle mi?",
           "Güvenlik duvarı paketi sessizce düşürürse istemci ne kadar bekler?",
           "Zaman aşımı yoksa cevapsız her port için işletim sisteminin varsayılan süresi kadar beklenir."),
          puan=20, baslik="Zaman aşımı"),
    Gorev("Deniz soruyor: \"Senin tarayıcın uygulama loglarına düşüyor ama nmap'in SYN taraması çoğu zaman düşmüyor. "
          "Neden?\"",
          Secmeli([
              ("SYN taraması el sıkışmayı yarıda bırakır, uygulama görmez",
               "Doğru. SYN-ACK gelince nmap ACK yerine RST gönderir; bağlantı kurulmadığı için uygulama onu hiç görmez. "
               "Ama güvenlik duvarı ve IDS yine görebilir."),
              ("SYN taraması paketleri şifreler, IDS içeriği okuyamaz",
               "SYN taraması şifreleme yapmaz; sadece el sıkışmayı yarıda bırakır."),
              ("connect taraması UDP kullandığı için daha gürültülüdür",
               "connect taraması TCP'dir; farkı el sıkışmayı tamamlaması."),
              ("SYN taraması yalnızca açık olduğu bilinen portlara paket gönderir",
               "SYN taraması da bütün aralığı dener; fark paket sayısında ve el sıkışmanın tamamlanmamasında."),
          ]),
          ("Üçlü el sıkışmanın adımlarını hatırla.",
           "Uygulama bir bağlantıyı ne zaman \"görür\"? El sıkışma bitince mi, ilk SYN'de mi?",
           "SYN taraması üçüncü adımı (ACK) göndermez."),
          puan=20, baslik="Gürültü"),
]


SEVIYE = Seviye(
    kimlik="c03b04",
    cilt=3,
    bolum=4,
    baslik="Kendi Port Tarayıcını Yaz",
    brifing="""
Selin yetkilendirme mektubunu masaya bırakıyor: "<<olay>>"

"Sunucunun laboratuvar kopyası `<<hedef>>` adresinde. Kapsam TCP <<bas>>-<<son>>, iki uç
dahil. Senden açık portların tam listesini ve hangisinin ne olduğunu istiyorum."

Mert sandalyesini çeviriyor: "Bu hafta nmap yok. nmap'in neyi neden yaptığını bilmeyen biri
çıktısını da yanlış okur. Kendi tarayıcını yaz. Bir de ipucu: sunucudakiler alışılmış
portlarda değil; bir tanesi de karşılamasını geç yapıyor. Sabırsız olanı kaçırır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Kırk satırlık tarayıcın nmap'in temel fikrini taşıyor: bağlanmayı dene, sonuca göre karar
ver. nmap bunu binlerce portta paralel, daha sessiz (SYN) ve daha akıllı (servis sürümü,
işletim sistemi tahmini) yapar; ama artık "open", "closed" ve "filtered" kelimelerinin
arkasında ne olduğunu biliyorsun. Bu vakada standart dışı portlara saklanmış FTP ve geç
konuşan bir servis vardı: savunma tarafının dersi, bir servisi alışılmadık bir porta
taşımanın onu gizlemediği; gereksiz her servisi kapatmanın ve açık kalanları envantere
yazmanın tek gerçek önlem olduğudur.
""",
    gercek_hayat="""
- **nmap'in doğuşu:** Gordon Lyon (Fyodor) nmap'i 1997'de Phrack dergisinde yayımladı.
  Bugün hâlâ sızma testlerinin ilk aracıdır. nmap root yetkisiyle çalışınca varsayılan
  olarak SYN taraması yapar; yetkisiz bir kullanıcıyla ise senin yazdığın gibi tam
  bağlantılı (connect, `-sT`) taramaya düşer.
- **İnternet ölçeğinde tarama:** masscan gibi araçların belgeleri, yeterli bant genişliğiyle
  bütün IPv4 internetinin dakikalar içinde taranabileceğini söyler. Shodan ve Censys de
  interneti sürekli tarayıp banner'ları kaydeder. "Kimse benim sunucumu bulamaz"
  varsayımı bu yüzden geçersizdir.
- **Standart dışı port güvenlik değildir:** Sızma testi raporlarında, "güvenlik için"
  standart dışı bir porta taşınmış ama kimlik doğrulaması zayıf servisler sık geçer. Bu
  yaklaşıma "belirsizlikle güvenlik" (security through obscurity) denir; tam bir aralık
  taraması onu birkaç saniyede boşa çıkarır.
""",
    sure_hedef_dk=45,
)
