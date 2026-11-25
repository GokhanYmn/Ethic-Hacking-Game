"""Ağ seviyeleri için ortak yardımcılar: pcap yazıcı, küçük bir yetkili DNS sunucusu, HTTP
parçaları ve gerçekçi komut çıktıları (ip a / ip r / ip neigh / traceroute).

Sadece standart kütüphane kullanır; Raspberry Pi'de hafif çalışır. Servisler yalnızca
127.x.x.x üzerinde dinler (motorun kuralı). Cilt 2'de doğdu; Olay Masası ve sonraki ciltler
de kullanabilir.

Kullanım özeti
--------------
1) Pcap (tcpdump -r ve Wireshark'ın açtığı trafik dosyası)::

    from hy.ortak import ag
    p = ag.Pcap(yerel="10.20.30.0/24", ag_gecidi="10.20.30.1")
    o = p.tcp_oturum("10.20.30.23", 51515, "203.0.113.80", 80, t=bas)   # bas: epoch saniye
    o.el_sikis()
    o.istemci(ag.http_istek("GET", "/", "ornek.lab"))
    o.sunucu(ag.http_yanit(200, "<h1>Merhaba</h1>"))
    o.kapat()
    p.dns("10.20.30.23", "10.20.30.53", "ornek.lab", "A", ["203.0.113.80"], t=bas - 0.05)
    p.syn_tarama("10.20.30.99", "10.20.30.10", portlar=range(20, 30), acik={22}, t=bas + 5)
    p.tls_oturumu("10.20.30.24", "198.51.100.7", t=bas + 9, r=random.Random(7))  # şifreli gürültü
    p.kaydet(lab / "yakalama.pcap")

   Diğerleri: `p.tcp(...)`, `p.udp(...)`, `p.icmp_echo(...)`, `p.arp(...)` tek paket;
   `p.tcp_oturum(..., mss=400)` + `o.istemci(veri, ack_aralik=2)` çok segmentli akış;
   `p.paket_sayisi()` ve `p.kaynak_sayilari()` senaryo cevaplarını pcap'ten hesaplamak için.

   MAC adresleri otomatik ve tutarlıdır: yerel ağdaki IP'ler kendi (IP'den türetilen ya da
   `p.mac(ip, "..")` ile verilen) MAC'ini, yerel ağ dışındaki IP'ler ise ağ geçidinin MAC'ini
   taşır; tıpkı gerçek bir yakalamadaki gibi. IP ve TCP/UDP sağlama toplamları doğrudur.
   Paketler zaman damgasına göre sıralanarak yazılır; oturumları iç içe üretebilirsin.
   Pcap'i `uret` içinde de kurabilirsin (saf, hızlı): cevapları (paket sayısı vb.) oradan al,
   `yaz` içinde aynı fonksiyonla yeniden kurup kaydet (bkz. c02_ag/b06_trafik.py).
   Tuzak: tcpdump `-A` çıktısında `\\r` basılmaz; DNS cevabında adı görmek için `-v` gerekir.

2) DNS sunucusu (UDP + TCP aynı portta; A, AAAA, MX, TXT, NS, CNAME, PTR, SOA, ANY, AXFR)::

    b = ag.Bolge("kuzgun.lab")                       # SOA otomatik eklenir
    b.ekle("@", "NS", "ns1"); b.ekle("@", "A", "203.0.113.10")
    b.ekle("@", "MX", (10, "mail")); b.ekle("www", "CNAME", "cdn.hizli.lab.")
    b.ekle("not", "TXT", "FLAG{...}")                # TXT'de sadece ASCII kullan
    ters = ag.ters_bolge({"203.0.113.10": "kuzgun.lab"})   # dig -x için PTR kayıtları
    calistir(ag.dns_sunuculari("127.0.0.1", port, [b, ters]), dur)

   Göreli adlar alan adına eklenir; nokta ile biten adlar mutlaktır. Tanımsız ad NXDOMAIN,
   kaydı olmayan tür NOERROR (boş cevap) döner; CNAME zinciri izlenir. AXFR (alan transferi)
   sadece TCP ile, sunucuda `axfr=True` ve bölgede `Bolge(..., axfr=True)` (varsayılan) iken
   verilir; `axfr=False` bölge dig'de "Transfer failed." gösterir. Oyuncu tarafı:
   `dig @127.0.0.1 -p PORT kuzgun.lab MX +short`. Aynı mesaj kodlayıcı (`dns_mesaj`) pcap
   içindeki DNS paketlerini de üretir.

3) HTTP parçaları: `http_istek` / `http_yanit` pcap içine ham HTTP baytları üretir;
   `form_oku(isleyici)`, `cerezler(isleyici)` ve `yol_ve_sorgu(isleyici)` ise motorun
   `SessizIsleyici`'sinden türeyen işleyicilerde POST gövdesini, Cookie başlığını ve
   yol/sorgu parametrelerini okur. İpucu: `Server:` başlığının sonunda boşluk kalmasın diye
   işleyicide `version_string()`'i `return self.server_version` ile ez.

4) Basit servisler: `udp_sunucu(host, port, cevapla)` (UDP) ve `tcp_satir_sunucu(host, port,
   cevapla, karsilama)` (FTP/SMTP gibi karşılama satırı basıp komut bekleyen, `QUIT` ile
   kapanabilen TCP servisi). Diğerleri için motorun `tcp_banner` / `http_sunucu`'su yeter.

5) Komut çıktıları (lab dosyaları için): `Arayuz`, `ip_a_cikti`, `ip_r_cikti`,
   `ip_neigh_cikti`, `traceroute_cikti`, `mac_uret`. Biçimleri iproute2/traceroute'un
   gerçek çıktısını taklit eder.
"""
from __future__ import annotations

import ipaddress
import socket
import socketserver
import struct
import zlib
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs

# ============================================================================ genel

def _yerel_host(host: str) -> None:
    if not host.startswith("127."):
        raise ValueError("Servisler sadece 127.x.x.x üzerinde dinleyebilir")


def _kararli_sayi(*parcalar, mod: int = 2**32) -> int:
    """Tohumdan bağımsız ama girdiye göre hep aynı sayı (Python'un hash()'i rastgeledir)."""
    return zlib.crc32(":".join(map(str, parcalar)).encode()) % mod


def mac_uret(rng, onek: str | None = None) -> str:
    """Rastgele ama gerçekçi bir MAC adresi. `onek` verilmezse yaygın üreticilerden seçilir."""
    onek = onek or rng.choice(["52:54:00", "00:0c:29", "08:00:27", "dc:a6:32", "00:1a:2b",
                               "3c:52:82", "f4:8e:38", "00:50:56", "b8:27:eb", "e4:5f:01"])
    return onek + "".join(f":{rng.randint(0, 255):02x}" for _ in range(3))


def _mac_bayt(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.replace("-", ":").split(":"))


# ============================================================================ pcap

def _sagla(veri: bytes) -> int:
    """İnternet sağlama toplamı (RFC 1071)."""
    if len(veri) % 2:
        veri += b"\0"
    toplam = sum(struct.unpack(f"!{len(veri) // 2}H", veri))
    while toplam >> 16:
        toplam = (toplam & 0xFFFF) + (toplam >> 16)
    return (~toplam) & 0xFFFF


_TCP_BAYRAK = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10, "U": 0x20}


class Pcap:
    """Ethernet + IPv4 + TCP/UDP/ICMP/ARP paketlerinden klasik pcap dosyası üretir.

    yerel: yakalamanın yapıldığı yerel ağ (örn. "10.20.30.0/24"). None ise herkes yerel sayılır.
    ag_gecidi: yerel ağın çıkış kapısı (router) IP'si; yerel dışı trafiğin MAC'i onunkidir.
    """

    def __init__(self, yerel: str | None = None, ag_gecidi: str | None = None):
        self.yerel = ipaddress.ip_network(yerel, strict=False) if yerel else None
        self.ag_gecidi = ag_gecidi
        self._mac: dict = {}
        self._paketler: list = []     # (zaman, sıra, çerçeve)
        self._ip_id = _kararli_sayi(yerel, ag_gecidi, mod=50000) + 1000

    # ---------------------------------------------------------------- adresler
    def mac(self, ip: str, mac: str | None = None) -> str:
        """IP'nin MAC'ini ayarlar (mac verilirse) ya da döndürür (yoksa IP'den türetir)."""
        if mac:
            self._mac[ip] = mac.lower()
        if ip not in self._mac:
            h = _kararli_sayi("mac", ip, mod=2**24)
            self._mac[ip] = "52:54:00:" + ":".join(f"{(h >> s) & 0xFF:02x}" for s in (16, 8, 0))
        return self._mac[ip]

    def _yerel_mi(self, ip: str) -> bool:
        return self.yerel is None or ipaddress.ip_address(ip) in self.yerel

    def _l2(self, kaynak_ip: str, hedef_ip: str) -> tuple:
        gw = self.ag_gecidi
        k = self.mac(kaynak_ip) if self._yerel_mi(kaynak_ip) or not gw else self.mac(gw)
        h = self.mac(hedef_ip) if self._yerel_mi(hedef_ip) or not gw else self.mac(gw)
        return k, h

    # ---------------------------------------------------------------- ham paketler
    def _ekle(self, t: float, cerceve: bytes) -> None:
        self._paketler.append((float(t), len(self._paketler), cerceve))

    def _ipv4(self, t, kaynak, hedef, proto, yuk, ttl=None) -> None:
        if ttl is None:
            ttl = 64 if self._yerel_mi(kaynak) else 52
        self._ip_id = (self._ip_id + 1) % 65536
        bas = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(yuk), self._ip_id, 0x4000, ttl, proto, 0,
                          socket.inet_aton(kaynak), socket.inet_aton(hedef))
        bas = bas[:10] + struct.pack("!H", _sagla(bas)) + bas[12:]
        k_mac, h_mac = self._l2(kaynak, hedef)
        self._ekle(t, _mac_bayt(h_mac) + _mac_bayt(k_mac) + b"\x08\x00" + bas + yuk)

    def _sahte_baslik(self, kaynak, hedef, proto, uzunluk) -> bytes:
        return socket.inet_aton(kaynak) + socket.inet_aton(hedef) + struct.pack("!BBH", 0, proto, uzunluk)

    def tcp(self, t, kaynak, sport, hedef, dport, bayraklar: str, seq: int, ack: int = 0,
            veri: bytes = b"", pencere: int = 64240, ttl=None) -> None:
        """Tek TCP segmenti. bayraklar: "S", "SA", "A", "PA", "FA", "R", "RA" ..."""
        b = sum(_TCP_BAYRAK[c] for c in bayraklar)
        secenek = struct.pack("!BBH", 2, 4, 1460) if "S" in bayraklar else b""   # MSS
        ofset = (20 + len(secenek)) // 4
        ack = ack if "A" in bayraklar else 0
        bas = struct.pack("!HHIIBBHHH", sport, dport, seq % 2**32, ack % 2**32, ofset << 4, b,
                          pencere, 0, 0) + secenek
        segment = bas + veri
        cs = _sagla(self._sahte_baslik(kaynak, hedef, 6, len(segment)) + segment)
        segment = segment[:16] + struct.pack("!H", cs) + segment[18:]
        self._ipv4(t, kaynak, hedef, 6, segment, ttl)

    def udp(self, t, kaynak, sport, hedef, dport, veri: bytes, ttl=None) -> None:
        uz = 8 + len(veri)
        segment = struct.pack("!HHHH", sport, dport, uz, 0) + veri
        cs = _sagla(self._sahte_baslik(kaynak, hedef, 17, uz) + segment) or 0xFFFF
        segment = segment[:6] + struct.pack("!H", cs) + segment[8:]
        self._ipv4(t, kaynak, hedef, 17, segment, ttl)

    def icmp_echo(self, t, kaynak, hedef, kimlik: int, sira: int, cevap: bool = False,
                  veri: bytes = bytes(range(16, 64))) -> None:
        bas = struct.pack("!BBHHH", 0 if cevap else 8, 0, 0, kimlik, sira) + veri
        bas = bas[:2] + struct.pack("!H", _sagla(bas)) + bas[4:]
        self._ipv4(t, kaynak, hedef, 1, bas)

    def arp(self, t, op: str, gonderen_mac, gonderen_ip, hedef_ip, hedef_mac=None) -> None:
        """op: "istek" (who-has) ya da "cevap" (is-at). İstek yayınla gider."""
        istek = op == "istek"
        hmac = "00:00:00:00:00:00" if istek else (hedef_mac or self.mac(hedef_ip))
        eth_hedef = "ff:ff:ff:ff:ff:ff" if istek else hmac
        govde = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1 if istek else 2) + _mac_bayt(gonderen_mac) \
            + socket.inet_aton(gonderen_ip) + _mac_bayt(hmac) + socket.inet_aton(hedef_ip)
        self._ekle(t, _mac_bayt(eth_hedef) + _mac_bayt(gonderen_mac) + b"\x08\x06" + govde)

    # ---------------------------------------------------------------- üst düzey
    def tcp_oturum(self, istemci, sport, sunucu, dport, t: float, rtt: float = 0.004,
                   mss: int = 1448) -> "TcpOturum":
        """Bir TCP bağlantısı başlatır (paket üretmez; el_sikis/istemci/sunucu/kapat çağır).
        mss: veri bu boyutta parçalara bölünür (küçük mss = çok paket, küçük dosya)."""
        return TcpOturum(self, istemci, sport, sunucu, dport, t, rtt, mss)

    def syn_tarama(self, saldirgan, hedef, portlar, acik=(), t: float = 0.0,
                   aralik: float = 0.0015, sport: int | None = None) -> float:
        """nmap -sS benzeri yarı açık tarama: SYN → (SYN-ACK → RST) ya da RST-ACK."""
        sport = sport or 40000 + _kararli_sayi(saldirgan, hedef, mod=20000)
        acik = set(acik)
        for i, port in enumerate(portlar):
            seq = _kararli_sayi("syn", saldirgan, port)
            self.tcp(t, saldirgan, sport, hedef, port, "S", seq, pencere=1024, ttl=44 + i % 3)
            if port in acik:
                isn = _kararli_sayi("synack", hedef, port)
                self.tcp(t + 0.0004, hedef, port, saldirgan, sport, "SA", isn, seq + 1, pencere=65160)
                self.tcp(t + 0.0007, saldirgan, sport, hedef, port, "R", seq + 1, pencere=0)
            else:
                self.tcp(t + 0.0003, hedef, port, saldirgan, sport, "RA", 0, seq + 1, pencere=0)
            t += aralik
        return t

    def dns(self, istemci, sunucu, ad: str, tip: str, cevaplar=(), t: float = 0.0,
            kimlik: int | None = None, sport: int | None = None, rcode: int = 0,
            gecikme: float = 0.012) -> float:
        """Bir DNS sorgusu ve cevabı (UDP 53). `cevaplar` tipe uygun değerler listesi;
        CNAME zinciri için (ad, tip, deger) üçlüleri de verilebilir."""
        kimlik = kimlik if kimlik is not None else _kararli_sayi("dnsid", istemci, ad, t, mod=65536)
        sport = sport or 32768 + _kararli_sayi("dnsport", istemci, ad, t, mod=28000)
        sorgu = dns_mesaj(kimlik, (ad, tip), yanit=False)
        rr = []
        for c in cevaplar:
            if isinstance(c, tuple) and len(c) == 3:
                rr.append((c[0], c[1], 300, c[2]))
            else:
                rr.append((ad, tip, 300, c))
        cevap = dns_mesaj(kimlik, (ad, tip), rr, rcode=rcode, ra=True)
        self.udp(t, istemci, sport, sunucu, 53, sorgu)
        self.udp(t + gecikme, sunucu, 53, istemci, sport, cevap)
        return t + gecikme

    def tls_oturumu(self, istemci, hedef, t: float, r, port: int = 443) -> "TcpOturum":
        """Şifreli (TLS benzeri) kısa bir HTTPS oturumu: el sıkışma, rastgele baytlar, kapanış.
        `r` bir random.Random'dur (baytlar ve süreler ondan gelir). İçeriği `-A` ile okunamaz."""
        o = self.tcp_oturum(istemci, r.randint(40000, 60999), hedef, port, t, rtt=r.uniform(0.008, 0.03))
        o.el_sikis()
        o.istemci(b"\x16\x03\x01\x01\xfc" + r.randbytes(r.randint(250, 500)))
        o.sunucu(b"\x16\x03\x03" + r.randbytes(r.randint(1500, 2600)))
        o.istemci(b"\x17\x03\x03" + r.randbytes(r.randint(120, 400)))
        o.sunucu(b"\x17\x03\x03" + r.randbytes(r.randint(300, 1300)))
        return o.kapat()

    def paket_sayisi(self) -> int:
        return len(self._paketler)

    def kaynak_sayilari(self) -> dict:
        """{kaynak_ip: paket_sayısı} (sadece IPv4). Senaryo cevaplarını doğrulamak için."""
        sayac: dict = {}
        for _t, _s, c in self._paketler:
            if c[12:14] == b"\x08\x00":
                ip = socket.inet_ntoa(c[26:30])
                sayac[ip] = sayac.get(ip, 0) + 1
        return sayac

    def baytlar(self) -> bytes:
        cikti = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
        for t, _, c in sorted(self._paketler, key=lambda x: (x[0], x[1])):
            sn = int(t)
            us = int(round((t - sn) * 1_000_000))
            if us >= 1_000_000:
                sn, us = sn + 1, us - 1_000_000
            cikti.append(struct.pack("<IIII", sn, us, len(c), len(c)) + c)
        return b"".join(cikti)

    def kaydet(self, yol: Path) -> Path:
        yol = Path(yol)
        yol.parent.mkdir(parents=True, exist_ok=True)
        yol.write_bytes(self.baytlar())
        return yol


class TcpOturum:
    """Sıra/onay numaraları doğru ilerleyen tek bir TCP bağlantısı."""

    def __init__(self, pcap: Pcap, istemci, sport, sunucu, dport, t: float, rtt: float = 0.004,
                 mss: int = 1448):
        self.p, self.i, self.sp, self.s, self.dp = pcap, istemci, sport, sunucu, dport
        self.t, self.rtt, self.mss = float(t), rtt, mss
        self.i_seq = _kararli_sayi("isn", istemci, sport, sunucu, dport)
        self.s_seq = _kararli_sayi("isn", sunucu, dport, istemci, sport)

    def _ilerle(self, dt=None):
        self.t += self.rtt / 2 if dt is None else dt

    def el_sikis(self) -> "TcpOturum":
        p = self.p
        p.tcp(self.t, self.i, self.sp, self.s, self.dp, "S", self.i_seq)
        self._ilerle()
        p.tcp(self.t, self.s, self.dp, self.i, self.sp, "SA", self.s_seq, self.i_seq + 1, pencere=65160)
        self.i_seq += 1
        self.s_seq += 1
        self._ilerle()
        p.tcp(self.t, self.i, self.sp, self.s, self.dp, "A", self.i_seq, self.s_seq, pencere=502)
        self._ilerle(0.001)
        return self

    def reddet(self) -> "TcpOturum":
        """Kapalı port: SYN → RST-ACK."""
        self.p.tcp(self.t, self.i, self.sp, self.s, self.dp, "S", self.i_seq)
        self._ilerle()
        self.p.tcp(self.t, self.s, self.dp, self.i, self.sp, "RA", 0, self.i_seq + 1, pencere=0)
        return self

    def _gonder(self, istemciden: bool, veri: bytes, bekle: float, ack_aralik: int = 1):
        if isinstance(veri, str):
            veri = veri.encode("utf-8")
        p = self.p
        parcalar = [veri[i:i + self.mss] for i in range(0, len(veri), self.mss)]
        for n, parca in enumerate(parcalar, 1):
            son = n == len(parcalar)
            if istemciden:
                p.tcp(self.t, self.i, self.sp, self.s, self.dp, "PA", self.i_seq, self.s_seq, parca, pencere=502)
                self.i_seq += len(parca)
                self._ilerle()
                if son or n % ack_aralik == 0:
                    p.tcp(self.t, self.s, self.dp, self.i, self.sp, "A", self.s_seq, self.i_seq, pencere=509)
            else:
                p.tcp(self.t, self.s, self.dp, self.i, self.sp, "PA", self.s_seq, self.i_seq, parca, pencere=509)
                self.s_seq += len(parca)
                self._ilerle()
                if son or n % ack_aralik == 0:
                    p.tcp(self.t, self.i, self.sp, self.s, self.dp, "A", self.i_seq, self.s_seq, pencere=502)
            self._ilerle(0.0005)
        self._ilerle(bekle)

    def istemci(self, veri: bytes | str, bekle: float = 0.01, ack_aralik: int = 1) -> "TcpOturum":
        """İstemciden sunucuya veri. ack_aralik=2: karşı taraf her iki segmentte bir onaylar."""
        self._gonder(True, veri, bekle, ack_aralik)
        return self

    def sunucu(self, veri: bytes | str, bekle: float = 0.01, ack_aralik: int = 1) -> "TcpOturum":
        self._gonder(False, veri, bekle, ack_aralik)
        return self

    def kapat(self) -> "TcpOturum":
        p = self.p
        p.tcp(self.t, self.i, self.sp, self.s, self.dp, "FA", self.i_seq, self.s_seq, pencere=502)
        self.i_seq += 1
        self._ilerle()
        p.tcp(self.t, self.s, self.dp, self.i, self.sp, "FA", self.s_seq, self.i_seq, pencere=509)
        self.s_seq += 1
        self._ilerle()
        p.tcp(self.t, self.i, self.sp, self.s, self.dp, "A", self.i_seq, self.s_seq, pencere=502)
        self._ilerle(0.001)
        return self


# ============================================================================ DNS

TIPLER = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28,
          "OPT": 41, "AXFR": 252, "ANY": 255}
TIP_ADI = {v: k for k, v in TIPLER.items()}
NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5
_AD_TURLERI = {"NS", "CNAME", "PTR"}


def _tip_no(tip) -> int:
    return tip if isinstance(tip, int) else TIPLER[str(tip).upper()]


def _ad_kodla(ad: str) -> bytes:
    ad = ad.rstrip(".")
    cikti = b""
    if ad:
        for etiket in ad.split("."):
            e = etiket.encode("idna") if not etiket.isascii() else etiket.encode()
            if not 0 < len(e) < 64:
                raise ValueError(f"Geçersiz DNS etiketi: {etiket!r}")
            cikti += bytes([len(e)]) + e
    return cikti + b"\0"


def _ad_coz(veri: bytes, i: int) -> tuple:
    """(ad, sonraki_konum). Sıkıştırma işaretçilerini izler."""
    etiketler, atlandi, son, adim = [], False, i, 0
    while True:
        adim += 1
        if adim > 128 or i >= len(veri):
            raise ValueError("bozuk ad")
        n = veri[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if i + 1 >= len(veri):
                raise ValueError("bozuk işaretçi")
            if not atlandi:
                son = i + 2
            i = ((n & 0x3F) << 8) | veri[i + 1]
            atlandi = True
            continue
        etiketler.append(veri[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return ".".join(etiketler), (son if atlandi else i)


def _rdata(tip: str, deger) -> bytes:
    if tip == "A":
        return socket.inet_aton(deger)
    if tip == "AAAA":
        return socket.inet_pton(socket.AF_INET6, deger)
    if tip in _AD_TURLERI:
        return _ad_kodla(deger)
    if tip == "MX":
        return struct.pack("!H", int(deger[0])) + _ad_kodla(deger[1])
    if tip == "TXT":
        parcalar = [deger] if isinstance(deger, str) else list(deger)
        cikti = b""
        for p in parcalar:
            b = p.encode("utf-8")
            for k in range(0, max(len(b), 1), 255):
                cikti += bytes([len(b[k:k + 255])]) + b[k:k + 255]
        return cikti
    if tip == "SOA":
        mname, rname, seri, yenile, tekrar, bitis, enaz = deger
        return _ad_kodla(mname) + _ad_kodla(rname) + struct.pack("!IIIII", seri, yenile, tekrar, bitis, enaz)
    raise ValueError(f"Desteklenmeyen kayıt türü: {tip}")


def _rr(ad: str, tip, ttl: int, deger) -> bytes:
    tip = TIP_ADI[_tip_no(tip)]
    veri = _rdata(tip, deger)
    return _ad_kodla(ad) + struct.pack("!HHIH", TIPLER[tip], 1, ttl, len(veri)) + veri


def dns_mesaj(kimlik: int, soru=None, cevaplar=(), yetki=(), ek=(), *, yanit: bool = True,
              aa: bool = False, rd: bool = True, ra: bool = False, tc: bool = False,
              rcode: int = 0) -> bytes:
    """DNS mesajı üretir. soru: (ad, tip) ya da None; kayıtlar: (ad, tip, ttl, deger)."""
    bayrak = (0x8000 if yanit else 0) | (0x0400 if aa else 0) | (0x0200 if tc else 0) \
        | (0x0100 if rd else 0) | (0x0080 if ra else 0) | (rcode & 0xF)
    sorular = [soru] if soru else []
    cikti = struct.pack("!HHHHHH", kimlik % 65536, bayrak, len(sorular), len(cevaplar), len(yetki), len(ek))
    for ad, tip in sorular:
        cikti += _ad_kodla(ad) + struct.pack("!HH", _tip_no(tip), 1)
    for kume in (cevaplar, yetki, ek):
        for kayit in kume:
            cikti += _rr(*kayit)
    return cikti


def dns_ayristir(veri: bytes) -> dict:
    """Gelen sorguyu ayrıştırır: kimlik, bayraklar, sorular [(ad, tip_no)], edns UDP boyutu."""
    if len(veri) < 12:
        raise ValueError("kısa mesaj")
    kimlik, bayrak, qd, an, ns, ar = struct.unpack("!HHHHHH", veri[:12])
    i, sorular = 12, []
    for _ in range(qd):
        ad, i = _ad_coz(veri, i)
        tip, _sinif = struct.unpack("!HH", veri[i:i + 4])
        i += 4
        sorular.append((ad, tip))
    edns = None
    try:
        for _ in range(an + ns + ar):
            _, i = _ad_coz(veri, i)
            tip, sinif, _ttl, uz = struct.unpack("!HHIH", veri[i:i + 10])
            i += 10 + uz
            if tip == 41:
                edns = sinif
    except (ValueError, struct.error):
        pass
    return {"kimlik": kimlik, "bayrak": bayrak, "sorular": sorular, "edns": edns}


def _tam_ad(ad: str, alan: str) -> str:
    ad = ad.strip()
    if ad in ("@", ""):
        return alan
    if ad.endswith("."):
        return ad[:-1].lower()
    return f"{ad}.{alan}".lower()


@dataclass
class Bolge:
    """Bir alan adının (zone) kayıtları. SOA otomatik eklenir.

    ekle(ad, tip, deger, ttl): ad "@" (kök), göreli ("www") ya da mutlak ("x.lab.").
      A/AAAA: "203.0.113.5" · NS/CNAME/PTR: "ns1" ya da "baska.lab." · MX: (10, "mail")
      TXT: "metin" ya da ("parça1", "parça2") — sadece ASCII.
    """
    alan: str
    ttl: int = 3600
    seri: int = 2026010101
    axfr: bool = True              # False: bu bölge alan transferini reddeder (doğru yapılandırma)
    kayitlar: list = field(default_factory=list)

    def __post_init__(self):
        self.alan = self.alan.rstrip(".").lower()
        self.kayitlar.append((self.alan, "SOA", self.ttl,
                              (f"ns1.{self.alan}", f"hostmaster.{self.alan}", self.seri, 7200, 3600, 1209600, 300)))

    def ekle(self, ad: str, tip: str, deger, ttl: int | None = None) -> "Bolge":
        tip = tip.upper()
        if tip in _AD_TURLERI:
            deger = _tam_ad(deger, self.alan)
        elif tip == "MX":
            deger = (int(deger[0]), _tam_ad(deger[1], self.alan))
        self.kayitlar.append((_tam_ad(ad, self.alan), tip, ttl or self.ttl, deger))
        return self

    def soa(self) -> tuple:
        return self.kayitlar[0]

    def kapsar(self, ad: str) -> bool:
        return ad == self.alan or ad.endswith("." + self.alan)

    def adlar(self) -> set:
        return {k[0] for k in self.kayitlar}

    def bul(self, ad: str, tip: str | None = None) -> list:
        return [k for k in self.kayitlar if k[0] == ad and (tip is None or k[1] == tip)]


def ters_ad(ip: str) -> str:
    """203.0.113.5 → 5.113.0.203.in-addr.arpa"""
    return ipaddress.ip_address(ip).reverse_pointer


def ters_bolge(eslesme: dict, ttl: int = 3600) -> Bolge:
    """{ip: ad} sözlüğünden PTR kayıtları içeren bir 'in-addr.arpa' bölgesi üretir (dig -x)."""
    b = Bolge("in-addr.arpa", ttl=ttl)
    for ip, ad in eslesme.items():
        b.ekle(ters_ad(ip) + ".", "PTR", ad if ad.endswith(".") else ad + ".")
    return b


class DnsCozucu:
    """Bölgelere bakarak sorgulara yetkili cevap verir."""

    def __init__(self, bolgeler: list, axfr: bool = True):
        self.bolgeler = sorted(bolgeler, key=lambda b: -len(b.alan))
        self.axfr = axfr

    def _bolge(self, ad: str):
        for b in self.bolgeler:
            if b.kapsar(ad):
                return b
        return None

    def _cevapla(self, ad: str, tip: str):
        """(rcode, cevaplar, yetki, aa)"""
        b = self._bolge(ad)
        if b is None:
            return REFUSED, [], [], False
        cevaplar, hedef, gorulen = [], ad, set()
        while True:
            gorulen.add(hedef)
            kb = self._bolge(hedef)
            if kb is None:
                break
            uygun = kb.bul(hedef) if tip == "ANY" else kb.bul(hedef, tip)
            if uygun:
                cevaplar += uygun
                break
            cname = kb.bul(hedef, "CNAME")
            if cname and tip != "CNAME":
                cevaplar += cname
                hedef = cname[0][3]
                if hedef in gorulen or len(gorulen) > 8:
                    break
                continue
            if not cevaplar:
                var = any(n == hedef or n.endswith("." + hedef) for n in kb.adlar())
                soa = kb.soa()
                yetki = [(soa[0], "SOA", soa[3][6], soa[3])]
                return (NOERROR if var else NXDOMAIN), [], yetki, True
            break
        return NOERROR, cevaplar, [], True

    def yanitla(self, veri: bytes, tcp: bool = False) -> list:
        """Ham sorguya ham cevap(lar) döndürür (AXFR birden çok mesaj olabilir). Boş liste: cevap yok."""
        try:
            s = dns_ayristir(veri)
        except (ValueError, struct.error):
            return []
        kimlik, bayrak = s["kimlik"], s["bayrak"]
        rd = bool(bayrak & 0x0100)
        if bayrak & 0x8000:          # bu zaten bir cevap
            return []
        opkod = (bayrak >> 11) & 0xF
        if opkod != 0 or len(s["sorular"]) != 1:
            return [dns_mesaj(kimlik, s["sorular"][0] if s["sorular"] else None, rd=rd, ra=rd,
                              rcode=NOTIMP if opkod else FORMERR)]
        ad_ham, tip_no = s["sorular"][0]
        ad = ad_ham.rstrip(".").lower()
        soru = (ad_ham, tip_no)
        tip = TIP_ADI.get(tip_no)
        if tip is None or tip == "OPT":
            return [dns_mesaj(kimlik, soru, rd=rd, ra=rd, rcode=NOTIMP)]
        if tip == "AXFR":
            b = self._bolge(ad)
            if not (tcp and self.axfr and b is not None and b.axfr and b.alan == ad):
                return [dns_mesaj(kimlik, soru, rd=rd, ra=rd, rcode=REFUSED)]
            soa = b.soa()
            govde = [soa] + [k for k in b.kayitlar[1:]] + [soa]
            return [dns_mesaj(kimlik, soru, govde, aa=True, rd=rd, ra=rd)]
        rcode, cevaplar, yetki, aa = self._cevapla(ad, tip)
        # Yetkili ama özyinelemesiz bir sunucuyuz; dig'in "recursion requested but not
        # available" uyarısıyla yeni başlayanın kafasını karıştırmamak için RA'yı RD'ye eşitliyoruz.
        mesaj = dns_mesaj(kimlik, soru, cevaplar, yetki, aa=aa, rd=rd, ra=rd, rcode=rcode)
        if not tcp:
            sinir = max(512, min(s["edns"] or 512, 1232))
            if len(mesaj) > sinir:
                mesaj = dns_mesaj(kimlik, soru, aa=aa, rd=rd, ra=rd, tc=True, rcode=rcode)
        return [mesaj]


class _DnsUDPSunucu(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = False   # UDP'de SO_REUSEADDR aynı portu iki sürece paylaştırabilir


class _DnsTCPSunucu(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _tam_oku(sock, n: int) -> bytes:
    veri = b""
    while len(veri) < n:
        parca = sock.recv(n - len(veri))
        if not parca:
            return b""
        veri += parca
    return veri


def dns_sunuculari(host: str, port: int, bolgeler: list, axfr: bool = True, tcp: bool = True) -> list:
    """Aynı portta UDP (ve istenirse TCP) dinleyen yetkili DNS sunucuları. `calistir`a verilir."""
    _yerel_host(host)
    cozucu = DnsCozucu(bolgeler, axfr=axfr)

    class UDPIsleyici(socketserver.BaseRequestHandler):
        def handle(self):
            veri, sock = self.request
            for m in cozucu.yanitla(veri, tcp=False):
                try:
                    sock.sendto(m, self.client_address)
                except OSError:
                    pass

    class TCPIsleyici(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                while True:
                    bas = _tam_oku(self.request, 2)
                    if not bas:
                        return
                    veri = _tam_oku(self.request, struct.unpack("!H", bas)[0])
                    if not veri:
                        return
                    for m in cozucu.yanitla(veri, tcp=True):
                        self.request.sendall(struct.pack("!H", len(m)) + m)
            except OSError:
                return

    sunucular = [_DnsUDPSunucu((host, port), UDPIsleyici)]
    if tcp:
        sunucular.append(_DnsTCPSunucu((host, port), TCPIsleyici))
    return sunucular


# ============================================================================ basit servisler

class _TCPSunucu(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def tcp_satir_sunucu(host: str, port: int, cevapla, karsilama: str = "",
                     zaman_asimi: float = 60.0, fabrika: bool = False) -> socketserver.BaseServer:
    """Satır satır konuşan TCP servisi (FTP/SMTP benzeri karşılama + komut).

    Motorun `tcp_sohbet`'inden farkı: `cevapla(satir)` bir `(yanit, True)` ikilisi döndürürse
    cevabı gönderip bağlantıyı kapatır (QUIT gibi); `None` dönerse cevapsız kapatır. Boşta
    kalan bağlantı `zaman_asimi` saniye sonra kapanır (Pi'de asılı bağlantı birikmesin).
    `fabrika=True` ise `cevapla()` her bağlantıda bir kez çağrılır ve dönen fonksiyon o
    bağlantıya özel durum tutar (örn. FTP'de önce USER sonra PASS).
    """
    _yerel_host(host)

    class Isleyici(socketserver.StreamRequestHandler):
        timeout = zaman_asimi

        def handle(self):
            fonk = cevapla() if fabrika else cevapla
            try:
                if karsilama:
                    self.wfile.write(karsilama.encode("utf-8"))
                for ham in self.rfile:
                    y = fonk(ham.decode("utf-8", "replace").rstrip("\r\n"))
                    if y is None:
                        break
                    kapat = False
                    if isinstance(y, tuple):
                        y, kapat = y
                    if y:
                        self.wfile.write(y.encode("utf-8"))
                    if kapat:
                        break
            except OSError:
                pass

    return _TCPSunucu((host, port), Isleyici)


class _UDPSunucu(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = False


def udp_sunucu(host: str, port: int, cevapla) -> socketserver.BaseServer:
    """Her datagrama `cevapla(veri: bytes) -> bytes | str | None` ile cevap veren UDP servisi."""
    _yerel_host(host)

    class Isleyici(socketserver.BaseRequestHandler):
        def handle(self):
            veri, sock = self.request
            y = cevapla(veri)
            if y:
                try:
                    sock.sendto(y.encode("utf-8") if isinstance(y, str) else y, self.client_address)
                except OSError:
                    pass

    return _UDPSunucu((host, port), Isleyici)


# ============================================================================ HTTP parçaları

def http_istek(metod: str, yol: str, host: str, basliklar: dict | None = None, govde: bytes | str = b"",
               ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                         "Chrome/131.0 Safari/537.36") -> bytes:
    """Ham HTTP/1.1 isteği (pcap içine konmak için)."""
    govde = govde.encode("utf-8") if isinstance(govde, str) else govde
    satirlar = [f"{metod} {yol} HTTP/1.1", f"Host: {host}", f"User-Agent: {ua}", "Accept: */*"]
    for k, v in (basliklar or {}).items():
        satirlar.append(f"{k}: {v}")
    if govde:
        if not any(k.lower() == "content-type" for k in (basliklar or {})):
            satirlar.append("Content-Type: application/x-www-form-urlencoded")
        satirlar.append(f"Content-Length: {len(govde)}")
    satirlar.append("Connection: close")
    return ("\r\n".join(satirlar) + "\r\n\r\n").encode("utf-8") + govde


def http_yanit(kod: int, govde: bytes | str = b"", basliklar: dict | None = None,
               sunucu: str = "nginx/1.24.0", tur: str = "text/html; charset=utf-8",
               tarih: str = "Tue, 10 Nov 2026 09:14:07 GMT") -> bytes:
    """Ham HTTP/1.1 cevabı (pcap içine konmak için)."""
    govde = govde.encode("utf-8") if isinstance(govde, str) else govde
    satirlar = [f"HTTP/1.1 {kod} {HTTPStatus(kod).phrase}", f"Date: {tarih}", f"Server: {sunucu}"]
    if govde or kod not in (204, 304):
        satirlar.append(f"Content-Type: {tur}")
    for k, v in (basliklar or {}).items():
        satirlar.append(f"{k}: {v}")
    satirlar += [f"Content-Length: {len(govde)}", "Connection: close"]
    return ("\r\n".join(satirlar) + "\r\n\r\n").encode("utf-8") + govde


def form_oku(isleyici) -> dict:
    """POST gövdesini (application/x-www-form-urlencoded) {alan: değer} olarak okur."""
    try:
        n = int(isleyici.headers.get("Content-Length") or 0)
    except ValueError:
        n = 0
    ham = isleyici.rfile.read(min(n, 65536)).decode("utf-8", "replace") if n > 0 else ""
    return {k: v[0] for k, v in parse_qs(ham, keep_blank_values=True).items()}


def cerezler(isleyici) -> dict:
    """İstekteki Cookie başlığını {ad: değer} olarak döndürür."""
    c = SimpleCookie()
    try:
        c.load(isleyici.headers.get("Cookie") or "")
    except Exception:  # bozuk çerez: boş say
        return {}
    return {k: m.value for k, m in c.items()}


def yol_ve_sorgu(isleyici) -> tuple:
    """('/yol', {param: değer})"""
    yol, _, sorgu = isleyici.path.partition("?")
    return yol, {k: v[0] for k, v in parse_qs(sorgu, keep_blank_values=True).items()}


# ============================================================================ komut çıktıları

def _eui64(mac: str) -> str:
    b = bytearray(_mac_bayt(mac))
    b[0] ^= 0x02
    h = bytes(b[:3]) + b"\xff\xfe" + bytes(b[3:])
    gruplar = [f"{(h[i] << 8) | h[i + 1]:x}" for i in range(0, 8, 2)]
    return "fe80::" + ":".join(gruplar)


@dataclass
class Arayuz:
    """`ip a` için bir ağ arayüzü. cidr: "10.20.30.15/24" (None ise IP'siz)."""
    ad: str
    mac: str
    cidr: str | None = None
    durum: str = "UP"              # UP / DOWN
    dhcp: bool = True
    mtu: int = 1500
    ipv6: bool = True


def ip_a_cikti(arayuzler: list, lo: bool = True) -> str:
    satirlar, no = [], 1
    if lo:
        satirlar += [
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000",
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00",
            "    inet 127.0.0.1/8 scope host lo",
            "       valid_lft forever preferred_lft forever",
            "    inet6 ::1/128 scope host noprefixroute ",
            "       valid_lft forever preferred_lft forever",
        ]
        no = 2
    for a in arayuzler:
        sanal = a.ad.startswith(("docker", "br-", "virbr"))
        if a.durum == "UP" and not sanal:
            bayrak, qdisc, durum = "<BROADCAST,MULTICAST,UP,LOWER_UP>", "fq_codel", "UP"
        elif sanal:
            bayrak, qdisc, durum = "<NO-CARRIER,BROADCAST,MULTICAST,UP>", "noqueue", "DOWN"
        else:
            bayrak, qdisc, durum = "<BROADCAST,MULTICAST>", "noop", "DOWN"
        qlen = "" if sanal else " qlen 1000"
        satirlar.append(f"{no}: {a.ad}: {bayrak} mtu {a.mtu} qdisc {qdisc} state {durum} group default{qlen}")
        satirlar.append(f"    link/ether {a.mac} brd ff:ff:ff:ff:ff:ff")
        if a.cidr:
            ag = ipaddress.ip_interface(a.cidr)
            brd = ag.network.broadcast_address
            if a.dhcp:
                satirlar.append(f"    inet {a.cidr} brd {brd} scope global dynamic noprefixroute {a.ad}")
                satirlar.append("       valid_lft 85613sec preferred_lft 85613sec")
            else:
                satirlar.append(f"    inet {a.cidr} brd {brd} scope global {a.ad}")
                satirlar.append("       valid_lft forever preferred_lft forever")
        if a.ipv6 and a.durum == "UP" and not sanal:
            satirlar.append(f"    inet6 {_eui64(a.mac)}/64 scope link noprefixroute ")
            satirlar.append("       valid_lft forever preferred_lft forever")
        no += 1
    return "\n".join(satirlar) + "\n"


def ip_r_cikti(ag_gecidi: str | None, arayuzler: list, varsayilan_arayuz: str | None = None,
               ek: list | None = None) -> str:
    """`ip r` çıktısı. ek: [("10.50.0.0/16", "10.20.30.254", "eth0")] gibi statik yollar."""
    satirlar = []
    ipli = [a for a in arayuzler if a.cidr]
    if ag_gecidi:
        dev = varsayilan_arayuz or ipli[0].ad
        a = next(x for x in ipli if x.ad == dev)
        kaynak = a.cidr.split("/")[0]
        proto = "dhcp" if a.dhcp else "static"
        satirlar.append(f"default via {ag_gecidi} dev {dev} proto {proto} src {kaynak} metric 100 ")
    for g, via, dev in (ek or []):
        satirlar.append(f"{g} via {via} dev {dev} proto static metric 100 ")
    for a in ipli:
        ag = ipaddress.ip_interface(a.cidr)
        kaynak = a.cidr.split("/")[0]
        son = " linkdown " if a.ad.startswith(("docker", "br-", "virbr")) else " metric 100 "
        satirlar.append(f"{ag.network} dev {a.ad} proto kernel scope link src {kaynak}{son}".rstrip() + " ")
    return "\n".join(satirlar) + "\n"


def ip_neigh_cikti(girdiler: list) -> str:
    """girdiler: [(ip, arayüz, mac, durum)]  durum: REACHABLE/STALE/DELAY/PERMANENT/FAILED"""
    satirlar = []
    for ip, dev, mac, durum in girdiler:
        if durum == "FAILED" or not mac:
            satirlar.append(f"{ip} dev {dev} FAILED")
        else:
            satirlar.append(f"{ip} dev {dev} lladdr {mac} {durum}")
    return "\n".join(satirlar) + "\n"


def traceroute_cikti(hedef_ad: str, hedef_ip: str, duraklar: list, rng=None) -> str:
    """duraklar: [(ad_ya_da_None, ip_ya_da_None, ort_ms)]; ip None ise '* * *' basılır.
    Son durak hedefin kendisi olmalı."""
    satirlar = [f"traceroute to {hedef_ad} ({hedef_ip}), 30 hops max, 60 byte packets"]
    for i, (ad, ip, ms) in enumerate(duraklar, 1):
        if ip is None:
            satirlar.append(f"{i:2d}  * * *")
            continue
        olcumler = []
        for k in range(3):
            sapma = (rng.uniform(-0.08, 0.08) if rng else (k - 1) * 0.03) * ms
            olcumler.append(f"{max(ms + sapma, 0.1):.3f} ms")
        satirlar.append(f"{i:2d}  {ad or ip} ({ip})  " + "  ".join(olcumler))
    return "\n".join(satirlar) + "\n"
