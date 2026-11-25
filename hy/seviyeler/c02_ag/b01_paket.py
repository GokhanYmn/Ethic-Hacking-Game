"""Cilt 2 · Bölüm 1 — Bir Paketin Yolculuğu.

Beceri: dört katman (uygulama, taşıma, internet, ağ erişimi), kapsülleme, `ip a` / `ip r`
okumak, traceroute çıktısında durakları ve gecikmeyi yorumlamak, MAC adresinin yalnızca bir
sonraki durağa kadar geçerli olduğunu görmek.

Oyuncunun kendi ağına bağımlı olmamak için sorular, bir müşteri sunucusundan alınmış gerçekçi
komut çıktıları üzerinden sorulur. Tek dinamik soru oyuncunun kendi varsayılan ağ geçidi.

Vakalar: depo sunucusu (lojistik), hasta portalı (hastane), e-belediye sunucusu (belediye),
kafe kasa bilgisayarı (Wi-Fi, küçük işletme).
"""
from __future__ import annotations

import socket
import struct
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Dinamik, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "kuzgun", "sunucu": "kzg-depo", "klasor": "kzg-depo_ciktilar",
        "arayuzler": ["ens18", "ens19"], "docker": True,
        "hedef": "stok.kuzgun.lab", "port": 8080, "uygulama": "http",
        "istek": ["GET /api/v2/stok?depo=IST-3 HTTP/1.1", "Host: stok.kuzgun.lab:8080",
                  "User-Agent: el-terminal/4.2", "Accept: application/json"],
        "komsular": ["el-terminal-07", "yazici-depo", "kamera-nvr"],
        "brifing": """
Pazartesi sabahı **Kuzgun Lojistik**'ten Serdar Bey aradı: depodaki el terminalleri, merkezdeki
stok servisine (**<<hedef>>**) bağlanırken dakikalarca bekliyor. Kalkan'ın SOC analisti
**Deniz Kara**, depo sunucusu **<<sunucu>>** üzerinden alınan ağ çıktılarını laboratuvarındaki
`<<klasor>>` klasörüne koydu: `ip a`, `ip r`, `traceroute`, `ip neigh` ve tek bir paketin
ayrıntısı.

Selin: "Bu hafta ağın dilini öğreneceksin. Önce bu sunucunun kim olduğunu, paketlerini kime
teslim ettiğini ve yolda nerede yavaşladığını çıkar. Tahmin yok; her cevabın bir çıktı
satırına dayanacak."

Deniz gülümsüyor: "Bir paketin yolunu okuyabilen, saldırganın yolunu da okur."
""",
    },
    {
        "kod": "medora", "sunucu": "medora-portal", "klasor": "portal_tanilama",
        "arayuzler": ["eth0", "eth1"], "docker": False,
        "hedef": "lab-sonuc.medora.lab", "port": 80, "uygulama": "http",
        "istek": ["GET /sonuc/liste?hasta=TR-88412 HTTP/1.1", "Host: lab-sonuc.medora.lab",
                  "User-Agent: MedoraPortal/3.1 (+java)", "Accept: application/json"],
        "komsular": ["poliklinik-pc12", "yazici-kat2", "pacs-on"],
        "brifing": """
**Medora Sağlık**'ın hasta portalı **<<sunucu>>**, tahlil sonuçlarını çektiği laboratuvar
servisine (**<<hedef>>**) ulaşırken zaman aşımına düşüyor; hastalar sonuçlarını göremiyor.
Dr. Aslı Hanım'ın ekibi sunucudan birkaç komut çıktısı alıp Kalkan'a gönderdi, Deniz de
hepsini `<<klasor>>` klasörüne koydu.

Selin dosyaları açarken anlatıyor: "Sorun ağda mı, uygulamada mı? Bunu bilmeden kimseyi
suçlayamayız. Sunucunun adresini, ağ geçidini ve paketin yolunu çıkar."

Mert arkadan ekliyor: "Bir de paketin içine bak. Zarfın üstünde yazanlar, içindekinden
çoğu zaman daha çok şey anlatır."
""",
    },
    {
        "kod": "yesiltepe", "sunucu": "ytb-ebelediye", "klasor": "ebelediye_ag",
        "arayuzler": ["enp3s0", "enp4s0"], "docker": True,
        "hedef": "entegrasyon.yesiltepe.lab", "port": 8080, "uygulama": "http",
        "istek": ["POST /tapu/sorgu HTTP/1.1", "Host: entegrasyon.yesiltepe.lab:8080",
                  "User-Agent: ebelediye-cron/1.0", "Content-Type: application/json"],
        "komsular": ["muhtarlik-pc", "arsiv-nas", "ups-yonetim"],
        "brifing": """
**Yeşiltepe Belediyesi**'nin e-belediye sunucusu **<<sunucu>>**, emlak bilgilerini aldığı
entegrasyon servisine (**<<hedef>>**) her öğleden sonra çok yavaş bağlanıyor. Nurcan Hanım
telefonda endişeli: "Saldırı mı var, yoksa hat mı kötü?"

Deniz sunucudan alınan çıktıları `<<klasor>>` klasörüne koydu. Selin: "Önce gözlem, sonra
yorum. Sunucunun kimliğini, çıkış kapısını ve paketin geçtiği durakları çıkar; yavaşlığın
nerede başladığını bulan rapora adını yazar."
""",
    },
    {
        "kod": "atolye", "sunucu": "atolye-kasa", "klasor": "kasa_ag_ciktisi",
        "arayuzler": ["wlan0", "eth0"], "docker": False,
        "hedef": "odeme.paramix.lab", "port": 443, "uygulama": "tls",
        "istek": [],
        "komsular": ["berk-telefon", "misafir-laptop", "akilli-tv"],
        "brifing": """
**Atölye Kahve**'nin kasa bilgisayarı **<<sunucu>>** kafenin Wi-Fi ağına bağlı. Sahibi Berk,
kartlı ödemelerin ödeme kuruluşuna (**<<hedef>>**) giderken takıldığını, kuyruğun kapıya kadar
uzadığını söylüyor. Deniz kasadan alınan ağ çıktılarını `<<klasor>>` klasörüne koydu.

Selin: "Küçük işletmelerde kasa, misafir telefonlarıyla aynı ağda olabilir. Önce kasanın
kim olduğunu ve paketlerini kime teslim ettiğini çıkar; yavaşlığın nerede başladığını da
traceroute söyleyecek."
""",
    },
]

AGLAR = ["10.{a}.{b}", "192.168.{b}", "172.{c}.{b}"]


def _yerel_ag(rng) -> str:
    sablon = rng.choice(AGLAR)
    return sablon.format(a=rng.randint(1, 250), b=rng.randint(0, 250), c=rng.randint(16, 31))


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    ag3 = _yerel_ag(rng)
    hostlar = rng.sample(range(10, 240), 2 + len(v["komsular"]))
    gw_son = rng.choice([1, 254])
    gw = f"{ag3}.{gw_son}"
    ip = f"{ag3}.{hostlar[0]}"
    arayuz = rng.choice(v["arayuzler"][:1] * 3 + v["arayuzler"][1:])
    ikinci = [a for a in v["arayuzler"] if a != arayuz][0]
    mac = ag.mac_uret(rng)
    gw_mac = ag.mac_uret(rng, rng.choice(["00:1a:2b", "c8:3a:35", "f4:f2:6d", "e8:48:b8"]))
    komsular = [(f"{ag3}.{h}", ag.mac_uret(rng), ad) for h, ad in zip(hostlar[2:], v["komsular"])]
    hedef_ip = u.dis_ip(rng)
    # traceroute durakları: 1 = ağ geçidi, sonra iç/ISS yönlendiricileri, son = hedef
    n = rng.randint(6, 9)
    sicrama = rng.randint(3, n - 1)          # gecikmenin sıçradığı ilk durak (1 tabanlı)
    yildiz = rng.choice([i for i in range(2, n) if i != sicrama])
    taban = rng.uniform(0.4, 1.2)
    yuksek = rng.uniform(38, 95)
    duraklar = []
    kullanilan = {hedef_ip}
    for i in range(1, n + 1):
        if i == 1:
            duraklar.append(("_gateway", gw, taban))
            continue
        if i == n:
            duraklar.append((v["hedef"], hedef_ip, yuksek + rng.uniform(1, 6)))
            continue
        if i == yildiz:
            duraklar.append((None, None, 0))
            continue
        while True:
            dip = f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.1" if i == 2 else u.dis_ip(rng)
            if dip not in kullanilan:
                kullanilan.add(dip)
                break
        ms = (taban + (i - 1) * rng.uniform(0.4, 1.4)) if i < sicrama else (yuksek + rng.uniform(-3, 4))
        duraklar.append((None, dip, ms))
    sicrama_ip = duraklar[sicrama - 1][1]
    sport = rng.randint(40000, 60999)
    traceroute = ag.traceroute_cikti(v["hedef"], hedef_ip, duraklar, rng=rng)
    return {
        "vaka": f"{m['ad']} — {v['sunucu']} ağ çıktıları",
        "brifing": v["brifing"],
        "v": v,
        "ag3": ag3, "ip": ip, "gw": gw, "arayuz": arayuz, "ikinci": ikinci, "mac": mac, "gw_mac": gw_mac,
        "komsular": komsular, "hedef_ip": hedef_ip, "sport": sport, "traceroute": traceroute,
        "ikinci_mac": ag.mac_uret(rng), "docker_mac": ag.mac_uret(rng, "02:42:ac"),
        "basarisiz": f"{ag3}.{hostlar[1]}",
        "metin": {
            "musteri": m["ad"], "sunucu": v["sunucu"], "klasor": v["klasor"], "hedef": v["hedef"],
            "port": v["port"],
        },
        "cevaplar": {
            "arayuz": arayuz, "ip": ip, "gw": gw, "hop": n, "sicrama": sicrama_ip,
            "mac_sahibi": gw,
        },
    }


def _paket_ozeti(s: dict) -> str:
    v = s["v"]
    if v["uygulama"] == "http":
        govde = "\r\n".join(v["istek"]) + "\r\n\r\n"
        uygulama = ["Hypertext Transfer Protocol"] + [f"    {x}\\r\\n" for x in v["istek"]] + ["    \\r\\n"]
        proto = "HTTP"
        yuk = len(govde.encode())
    else:
        yuk = 517
        proto = "TLSv1.3"
        uygulama = [
            "Transport Layer Security",
            "    TLSv1.3 Record Layer: Handshake Protocol: Client Hello",
            "        Content Type: Handshake (22)",
            "        Handshake Protocol: Client Hello",
            f"            Extension: server_name (len={len(v['hedef']) + 5}) name={v['hedef']}",
        ]
    toplam = 14 + 20 + 20 + yuk
    satirlar = [
        "# Wireshark 'Paket Ayrıntıları' bölmesinden kopyalandı (Deniz)",
        f"# Yakalama: {v['sunucu']} üzerinde, {s['arayuz']} arayüzü",
        "",
        "No.    Kaynak            Hedef             Protokol  Uzunluk",
        f"1482   {s['ip']:<17} {s['hedef_ip']:<17} {proto:<9} {toplam}",
        "",
        f"Frame 1482: {toplam} bytes on wire ({toplam * 8} bits), {toplam} bytes captured ({toplam * 8} bits) on interface {s['arayuz']}",
        f"Ethernet II, Src: {s['mac']}, Dst: {s['gw_mac']}",
        f"    Destination: {s['gw_mac']}",
        f"    Source: {s['mac']}",
        "    Type: IPv4 (0x0800)",
        f"Internet Protocol Version 4, Src: {s['ip']}, Dst: {s['hedef_ip']}",
        "    Time to Live: 64",
        "    Protocol: TCP (6)",
        f"    Source Address: {s['ip']}",
        f"    Destination Address: {s['hedef_ip']}",
        f"Transmission Control Protocol, Src Port: {s['sport']}, Dst Port: {v['port']}, Seq: 1, Ack: 1, Len: {yuk}",
        f"    Source Port: {s['sport']}",
        f"    Destination Port: {v['port']}",
        "    Flags: 0x018 (PSH, ACK)",
    ] + uygulama
    return "\n".join(satirlar) + "\n"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = lab / v["klasor"]
    cidr = f"{s['ip']}/24"
    arayuzler = [ag.Arayuz(s["arayuz"], s["mac"], cidr, dhcp=v["kod"] in ("atolye", "medora"))]
    arayuzler.append(ag.Arayuz(s["ikinci"], s["ikinci_mac"], None, durum="DOWN"))
    if v["docker"]:
        arayuzler.append(ag.Arayuz("docker0", s["docker_mac"], "172.17.0.1/16", dhcp=False))
    u.yaz(k / "ip_a.txt", f"# {v['sunucu']}$ ip a\n" + ag.ip_a_cikti(arayuzler))
    u.yaz(k / "ip_r.txt", f"# {v['sunucu']}$ ip r\n" + ag.ip_r_cikti(s["gw"], arayuzler, s["arayuz"]))
    u.yaz(k / "traceroute.txt", f"# {v['sunucu']}$ traceroute {v['hedef']}\n" + s["traceroute"])
    girdiler = [(s["gw"], s["arayuz"], s["gw_mac"], "REACHABLE")]
    durumlar = ["STALE", "REACHABLE", "DELAY"]
    for i, (kip, kmac, _ad) in enumerate(s["komsular"]):
        girdiler.append((kip, s["arayuz"], kmac, durumlar[i % 3]))
    girdiler.append((s["basarisiz"], s["arayuz"], None, "FAILED"))
    sirali = sorted(girdiler, key=lambda g: (g[3] == "FAILED", g[0] != s["gw"], g[0]))
    u.yaz(k / "ip_neigh.txt", f"# {v['sunucu']}$ ip neigh\n" + ag.ip_neigh_cikti(sirali))
    u.yaz(k / "paket_ozeti.txt", _paket_ozeti(s))
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sunucu']} makinesinden alınan ağ çıktıları `{v['klasor']}/` klasöründe.\n"
          "Her dosyanın ilk satırında hangi komutla alındığı yazıyor.\n"
          "Deniz'den not: Satır satır oku. Cevap hep orada; acele eden atlar.\n")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: çıktı dosyalarını awk/grep ile okur."""
    k = s["v"]["klasor"]
    arayuz = _sh(f"awk '/state UP/ {{print $2}}' {k}/ip_a.txt | tr -d ':' | head -1", lab)
    ip = _sh(f"grep -A3 'state UP' {k}/ip_a.txt | awk '/inet / {{print $2}}' | cut -d/ -f1 | head -1", lab)
    gw = _sh(f"awk '/^default/ {{print $3}}' {k}/ip_r.txt", lab)
    hop = _sh(f"tail -1 {k}/traceroute.txt | awk '{{print $1}}'", lab)
    sicrama = _sh(f"awk 'NR>2 && $2!=\"*\" && $4+0 > 25 {{gsub(/[()]/, \"\", $3); print $3; exit}}' "
                  f"{k}/traceroute.txt", lab)
    mac_sahibi = _sh(f"mac=$(awk '/^Ethernet II/ {{print $NF}}' {k}/paket_ozeti.txt); "
                     f"grep -i \"$mac\" {k}/ip_neigh.txt | awk '{{print $1}}'", lab)
    kendi = _sh("ip r | awk '/^default/ {print $3; exit}'", lab) or "yok"
    return {1: arayuz, 2: ip, 3: gw, 4: hop, 5: sicrama, 6: mac_sahibi,
            7: _secmeli(s, lab, 7), 8: _secmeli(s, lab, 8), 9: kendi}


# ---------------------------------------------------------------- dinamik ve sık hatalar

def _kendi_ag_gecidim(b) -> list:
    adaylar = []
    try:
        for satir in Path("/proc/net/route").read_text().splitlines()[1:]:
            p = satir.split()
            if len(p) > 2 and p[1] == "00000000" and p[2] != "00000000":
                gw = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
                if gw not in adaylar:
                    adaylar.append(gw)
    except (OSError, ValueError):
        pass
    return adaylar or ["yok", "yok.", "hiç yok", "varsayılan yol yok"]


def _arayuz_hata(g, beklenen, b):
    if g in ("lo", "lo:"):
        return "`lo` geri döngü (loopback) arayüzüdür; makine sadece kendisiyle konuşur. Durumu UP olan, IP'li arayüze bak."
    if g.startswith("docker"):
        return "`docker0` Docker'ın sanal köprüsü; durumu DOWN. Yerel ağa bağlı gerçek arayüzü ara."
    if g == b.senaryo["ikinci"].lower():
        return "Bu arayüzün durumu DOWN ve IP adresi yok. `state UP` yazan arayüze bak."
    return None


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g == "127.0.0.1":
        return "Bu `lo` arayüzünün adresi; her makinede aynıdır. Asıl arayüzün `inet` satırına bak."
    if g.endswith(".255"):
        return "`brd` ile başlayan adres yayın (broadcast) adresidir. `inet`'ten hemen sonra gelen adresi yaz."
    if g == "172.17.0.1":
        return "Bu `docker0`'ın adresi. Yerel ağa bağlı (state UP) arayüzün `inet` satırına bak."
    if g == s["gw"]:
        return "Bu ağ geçidinin adresi (ip_r.txt). Sunucunun kendi adresi `ip_a.txt`'deki `inet` satırında."
    return None


def _gw_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["ip"]:
        return "Bu sunucunun kendi adresi (`src`). Ağ geçidi `default via` kelimelerinden hemen sonra gelir."
    if g == s["hedef_ip"]:
        return "Bu traceroute'un hedefi. Ağ geçidi, `ip r`'deki `default via` satırında."
    return None


def _hop_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla. İlk satır (`traceroute to ...`) bir durak değil, başlıktır."
    if n == beklenen - 1:
        return "Bir eksik. `* * *` satırı da bir duraktır (cevap vermese de paket oradan geçti) ve son satır hedefin kendisidir."
    return None


def _sicrama_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["hedef_ip"]:
        return "Hedefin gecikmesi de yüksek, ama yüksek gecikme ondan önce başlıyor. Sıçramanın görüldüğü İLK durağı bul."
    if g == s["gw"]:
        return "Ağ geçidinin gecikmesi çok düşük (1 ms civarı). Milisaniyelerin birden büyüdüğü satırı ara."
    return None


def _mac_sahibi_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["hedef_ip"]:
        return ("IP katmanındaki hedef uzaktaki sunucu, doğru. Ama MAC adresi (ağ erişimi katmanı) sadece "
                "bir sonraki durağa kadar geçerlidir. Dst MAC'ini `ip_neigh.txt`'de ara.")
    if g == s["ip"]:
        return "Bu paketi gönderenin (Src) adresi. Soru, hedef (Dst) MAC'in kime ait olduğu."
    return None


ADIMLAR = [
    Adim("Katmanlar: işi parçalara bölmek", """
Tarayıcına bir adres yazıp Enter'a bastığında saniyenin çok altında onlarca adım gerçekleşir.
Ağ iletişimi bu yüzden **katmanlara** bölünmüştür; her katman sadece kendi işini yapar. Pratikte
dört katman yeterli (TCP/IP modeli):

- **Uygulama:** veriyi üreten program. HTTP, DNS, SSH. Adres: (yok, veri kendisi)
- **Taşıma:** veriyi doğru **programa** ulaştırır. TCP, UDP. Adres: **port**
- **İnternet:** veriyi doğru **makineye** yönlendirir. IP. Adres: **IP adresi**
- **Ağ erişimi:** veriyi fiziksel olarak taşır. Ethernet, Wi-Fi. Adres: **MAC adresi**

Mektup benzetmesi: mektubun içeriği uygulama, zarftaki "3. kat muhasebe" taşıma (port),
sokak adresi internet (IP), posta kamyonu ağ erişimi (MAC).

**Hacker gözüyle:** Her katman ayrı bir saldırı yüzeyidir. Uygulamada SQL injection, taşımada
port taraması, internette IP sahteciliği (spoofing), ağ erişiminde ARP zehirlemesi. Bir
zafiyeti anlamak çoğu zaman "bu hangi katmanda?" sorusuyla başlar.
"""),
    Adim("Kapsülleme: zarfların içinde zarflar", """
Veri aşağı inerken her katman kendi **başlığını** (header) ekler: HTTP verisi önce TCP başlığıyla
(portlar), sonra IP başlığıyla (IP adresleri), en son Ethernet başlığıyla (MAC adresleri)
sarılır. Buna **kapsülleme** denir. Karşı tarafta zarflar ters sırayla açılır.

Deniz, <<sunucu>>'dan yakalanmış tek bir paketin Wireshark ayrıntısını kopyalamış. Satırları
yukarıdan aşağı oku: her blok bir katman.
""", komut="cat <<klasor>>/paket_ozeti.txt", sonra="""
`Ethernet II` satırı ağ erişimi (MAC), `Internet Protocol` satırı internet (IP),
`Transmission Control Protocol` taşıma (port), en alttaki blok da uygulama katmanı. Tek paket,
dört zarf. Bölüm 6'da bunu Wireshark ve tcpdump ile kendi gözünle açacaksın.
"""),
    Adim("Kendi ağ kimliğin: ip a", """
`ip a` (address) makinedeki ağ arayüzlerini ve adreslerini listeler. Tipik olarak şunları görürsün:

- `lo`: geri döngü (loopback). Makinenin kendisiyle konuşma kapısı, hep `127.0.0.1`.
- `eth0` / `wlan0` / `ens18` gibi: gerçek (ya da sanal makinede sanal) ağ kartı.

Önce kendi makinene bak:
""", komut="ip a", sonra="""
Okuma kılavuzu: `state UP` arayüz çalışıyor demek. `link/ether` satırı **MAC adresi**,
`inet` satırı **IPv4 adresi/ağ maskesi** (örn. `192.168.1.50/24`), `brd` ise yayın
(broadcast) adresi. `inet6 fe80::...` IPv6 yerel bağlantı adresidir.
"""),
    Adim("Sunucunun kimliği", """
Şimdi aynı çıktıyı <<musteri>>'nin sunucusu **<<sunucu>>** için oku. Birden fazla arayüz
görürsen hangisinin çalıştığına (`state UP`) ve hangisinde `inet` satırı olduğuna dikkat et.
""", komut="cat <<klasor>>/ip_a.txt", sonra="""
`docker0` gibi arayüzler Docker'ın kurduğu sanal köprülerdir; durumları DOWN olabilir.
**Hacker gözüyle:** Bir sunucuda `docker0` görmek "bu makinede konteyner çalışıyor" bilgisidir;
iki farklı ağa bağlı iki arayüz görmek ise o makinenin iki ağ arasında **köprü** olabileceğini
gösterir. Cilt 6'da buna pivoting diyeceğiz.
"""),
    Adim("Yol tarifi: ip r", """
`ip r` (route) şu soruyu cevaplar: "Bu makine bilmediği bir adrese paket göndereceğinde nereye
yollar?" Cevap **varsayılan ağ geçidi**dir (default gateway); genelde ağdaki yönlendiricidir
(router). Kendi makinene bak:
""", komut="ip r", sonra="""
`default via X dev Y` satırı: "yerel ağ dışındaki her şeyi Y arayüzünden X'e gönder." Altındaki
`.../24 dev ... scope link src Z` satırı ise yerel ağı ve makinenin o ağdaki adresini (Z)
söyler. <<sunucu>>'nun çıktısı `<<klasor>>/ip_r.txt` dosyasında.
"""),
    Adim("traceroute: durak durak yolculuk", """
`traceroute` bir paketin hedefe giderken geçtiği yönlendiricileri (durak, **hop**) listeler.
Hilesi şudur: IP başlığındaki **TTL** (yaşam süresi) her durakta bir azalır, sıfıra inince o
durak "süren doldu" diye cevap döner. traceroute TTL'i 1, 2, 3... diye artırarak her durağı
sırayla konuşturur.

Her satırda durak numarası, adresi ve üç ölçümün gidiş-dönüş süresi (ms) yazar. `* * *`, o
durağın cevap vermediği anlamına gelir (çoğu zaman güvenlik duvarı); paket yine de oradan geçer.
""", komut="cat <<klasor>>/traceroute.txt", sonra="""
İlk durak neredeyse her zaman senin ağ geçidindir (Linux onu `_gateway` diye adlandırır).
Süreler birkaç milisaniyeden birden onlarca milisaniyeye sıçrıyorsa, yavaşlık o duraktan
itibaren başlıyor demektir. Sonraki duraklar da yüksekse sorun kalıcıdır.
"""),
    Adim("Komşular: yerel ağda MAC ile konuşmak", """
IP adresi paketi **uzaktaki hedefe** kadar taşır; ama yerel ağda kablodan geçen çerçeve **MAC
adresine** gönderilir. Uzaktaki bir sunucuya giden paketin hedef MAC'i o sunucunun değil,
**bir sonraki durağın** (ağ geçidinin) MAC'idir. Her durakta Ethernet zarfı yenilenir, IP zarfı
aynı kalır.

Makine "hangi IP hangi MAC'te?" eşleşmelerini ARP tablosunda tutar; `ip neigh` bunu gösterir.
""", komut="cat <<klasor>>/ip_neigh.txt", sonra="""
**Hacker gözüyle:** ARP'ın hiçbir doğrulaması yoktur; "ağ geçidi benim" diye cevap veren
herkese inanılır. ARP zehirlemesi (ARP spoofing) bu yüzden çalışır. Ama ARP yayınları
yönlendiriciden öteye geçmez; bu saldırı ancak **aynı yerel ağın içinden** yapılabilir.
Bölüm 2'de bir zehirlemeyi ARP tablosunda yakalayacaksın.
"""),
]

GOREVLER = [
    Gorev("`<<klasor>>/ip_a.txt`'e göre <<sunucu>> yerel ağa hangi arayüzle bağlı? "
          "(Durumu UP olan, IP adresli arayüzün adı)",
          Metin("arayuz", son_ekleri_at=(":",), sik_hatalar=_arayuz_hata, bicim="arayüz adı (örn. eth0)"),
          ("Her arayüz `2: ad: <...>` biçiminde numaralı bir satırla başlar.",
           "`cat <<klasor>>/ip_a.txt` çıktısında `state UP` yazan satırı bul. `lo` sayılmaz.",
           "`grep 'state UP' <<klasor>>/ip_a.txt` satırındaki ikinci kelime (iki noktadan önceki kısım)."),
          puan=20, baslik="Arayüz"),
    Gorev("O arayüzün IPv4 adresi ne?",
          IP("ip", sik_hatalar=_ip_hata),
          ("IPv4 adresi `inet` ile başlayan satırdadır (`inet6` değil).",
           "Bir önceki görevde bulduğun arayüzün bloğundaki `inet` satırına bak; `/24` ağ maskesidir.",
           "`grep -A3 'state UP' <<klasor>>/ip_a.txt` ile bloğu süz; `inet`'ten sonraki adresin `/`'dan önceki kısmı."),
          puan=20, baslik="IP adresi"),
    Gorev("<<sunucu>>, yerel ağ dışındaki adreslere giden paketleri hangi cihaza teslim ediyor? "
          "(Varsayılan ağ geçidinin IP'si)",
          IP("gw", sik_hatalar=_gw_hata),
          ("Bu bilgi yönlendirme tablosunda (route).",
           "`cat <<klasor>>/ip_r.txt` ve `default` ile başlayan satır.",
           "`default via X dev ...` satırında `via`'dan sonraki adres."),
          puan=25, baslik="Ağ geçidi"),
    Gorev("`traceroute.txt`'e göre hedef (<<hedef>>) kaçıncı durakta (hop) cevap veriyor?",
          Sayi("hop", sik_hatalar=_hop_hata),
          ("Her durak numaralı bir satırdır; başlık satırı durak değildir.",
           "`cat <<klasor>>/traceroute.txt` çıktısında hedefin adının geçtiği satırın numarasına bak.",
           "`tail -1 <<klasor>>/traceroute.txt` son durağı gösterir; satırın başındaki sayı."),
          puan=25, baslik="Durak sayısı"),
    Gorev("<<hedef>>'e giden yolda gecikme hangi durakta **birden sıçrıyor**? Sıçramanın görüldüğü "
          "ilk durağın IP adresini yaz.",
          IP("sicrama", sik_hatalar=_sicrama_hata),
          ("Her satırdaki üç ms değerini bir öncekiyle karşılaştır.",
           "İlk duraklarda süreler 1-15 ms civarında; bir yerden sonra 40 ms'nin üstüne çıkıyor. "
           "`* * *` satırını atla.",
           "Süreler küçükken birden onlarca katına çıkan İLK satırın parantez içindeki adresi."),
          puan=30, baslik="Yavaşlık nerede"),
    Gorev("`paket_ozeti.txt`'deki paket uzaktaki <<hedef>>'e gidiyor. Peki Ethernet başlığındaki "
          "**hedef MAC adresi** hangi cihaza ait? O cihazın IP adresini yaz.",
          IP("mac_sahibi", sik_hatalar=_mac_sahibi_hata),
          ("IP zarfı uzak hedefe kadar aynı kalır; Ethernet zarfı her durakta yenilenir.",
           "`Ethernet II` satırındaki `Dst:` MAC'ini al, `<<klasor>>/ip_neigh.txt` dosyasında ara.",
           "`grep -i <Dst_MAC> <<klasor>>/ip_neigh.txt` satırının ilk sütunu."),
          puan=35, baslik="Bir sonraki durak"),
    Gorev("`paket_ozeti.txt`'deki hedef port (<<port>>) hangi katmanın başlığında taşınır?",
          Secmeli([
              ("Taşıma katmanı (TCP başlığı)",
               "Doğru. Port, veriyi makinedeki doğru programa ulaştırmak için taşıma katmanında (TCP/UDP) bulunur."),
              ("İnternet katmanı (IP başlığı)",
               "IP başlığında kaynak ve hedef IP adresleri, TTL ve protokol numarası vardır; port yoktur."),
              ("Ağ erişimi katmanı (Ethernet başlığı)",
               "Ethernet başlığında MAC adresleri ve tür (IPv4) alanı vardır; port bilgisi taşımaz."),
              ("Uygulama katmanı (HTTP verisi)",
               "Uygulama verisi bazen `Host: ...:8080` gibi bir port yazsa da, paketin gideceği port TCP başlığındadır."),
          ]),
          ("Paket özetinde `Dst Port` hangi bloğun satırında geçiyor?",
           "Portun görevi: makinedeki doğru **programı** bulmak. Bu hangi katmanın işiydi?",
           "`Transmission Control Protocol, Src Port: ..., Dst Port: ...`"),
          puan=20, baslik="Port hangi katmanda"),
    Gorev("ARP zehirlemesi neden internetin öbür ucundan değil, ancak **aynı yerel ağın içinden** "
          "yapılabilir?",
          Secmeli([
              ("ARP yayınla çalışır ve yönlendiriciler bu yayınları başka ağlara geçirmez",
               "Doğru. ARP, ağ erişimi katmanında aynı yayın alanı (broadcast domain) içinde konuşur; router'da durur."),
              ("ARP paketleri şifreli olduğu için uzaktan gönderilen sahte cevaplar çözülemez",
               "ARP'ta şifreleme de doğrulama da yoktur; saldırının işe yaramasının sebebi zaten bu."),
              ("İnternet servis sağlayıcıları ARP paketlerini güvenlik duvarında engellemek zorunda",
               "Engellenmesine gerek bile yok: ARP, IP paketi değildir ve yönlendirilemez; yerel ağdan hiç çıkmaz."),
              ("ARP sadece IPv6 ağlarında kullanıldığı için çoğu internet hattında desteklenmez",
               "Tersine, ARP IPv4'ün protokolüdür. IPv6 aynı işi Neighbor Discovery ile yapar."),
          ]),
          ("ARP hangi katmanda çalışıyordu?",
           "MAC adresleri bir sonraki durağa kadar geçerliydi. ARP mesajları bir yönlendiriciyi aşabilir mi?",
           "Cevap 'yayın alanı' ve 'yönlendirici' kavramlarında."),
          puan=20, baslik="ARP'ın sınırı"),
    Gorev("Şimdi kendi makinene dön: **senin** varsayılan ağ geçidin hangi adres? "
          "(Varsayılan yol yoksa `yok` yaz.)",
          Dinamik(_kendi_ag_gecidim, on_ekleri_at=("default via ",), bicim="IP adresi ya da yok"),
          ("Eğitimde kendi makinende çalıştırdığın ikinci komutu hatırla.",
           "`ip r` çalıştır ve `default` ile başlayan satıra bak.",
           "`ip r | grep default` satırında `via`'dan sonraki adres."),
          puan=20, baslik="Senin kapın"),
]

SEVIYE = Seviye(
    kimlik="c02b01",
    cilt=2,
    bolum=1,
    baslik="Bir Paketin Yolculuğu",
    brifing="""
**<<musteri>>**'nin sunucusu **<<sunucu>>**, **<<hedef>>** servisine ulaşırken yavaşlıyor.
Deniz sunucudan alınan ağ çıktılarını `<<klasor>>` klasörüne koydu. Selin: "Sunucunun kim
olduğunu, paketlerini kime teslim ettiğini ve yolda nerede yavaşladığını çıkar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bir paketin yolunu okuyabilen, hem saldırganın hem savunmacının haritasını okur. Saldırgan bir
sisteme girdiğinde ilk iş `ip a` ve `ip r` ile nerede olduğunu, hangi ağlara dokunduğunu ve
çıkış kapısının kim olduğunu öğrenir. Savunmacı da aynı çıktılarla "bu makine hangi ağlara
köprü?" sorusunu sorar. Unutma: IP zarfı uzak hedefe kadar gider, MAC zarfı her durakta
değişir; ARP zehirlemesi bu yüzden sadece yerel ağda işe yarar ve tam da bu yüzden misafir
Wi-Fi'ı ile kasa bilgisayarı aynı ağda olmamalıdır.
""",
    gercek_hayat="""
- **Ağ ayrımı (segmentasyon):** Kart verisiyle ilgili standart PCI DSS, kart verisi işleyen
  sistemlerin diğer ağlardan ayrılmasını kapsam daraltmanın temel yolu olarak tarif eder.
  Kasa bilgisayarının misafir Wi-Fi'ıyla aynı yerel ağda olması, ARP zehirlemesi gibi yerel
  ağ saldırılarına kapı açar.
- **traceroute ile arıza ayırma:** Ağ ekipleri "yavaşlık bizde mi, sağlayıcıda mı?" sorusunu
  çoğu zaman traceroute ve onun sürekli ölçüm yapan türevleriyle (örn. mtr) cevaplar;
  gecikmenin hangi duraktan itibaren başladığı, sorunu kimin çözeceğini belirler.
- **Pivoting:** Sızma testi raporlarında sık görülen bir bulgu, internete açık bir sunucunun
  ikinci bir arayüzle iç ağa da bağlı olmasıdır. Saldırgan o sunucuyu ele geçirdiğinde iç
  ağa doğrudan erişir; `ip a` ve `ip r` çıktıları bunu ilk dakikada ele verir.
""",
    sure_hedef_dk=25,
)
