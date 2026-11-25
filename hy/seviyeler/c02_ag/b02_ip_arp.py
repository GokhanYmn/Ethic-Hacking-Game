"""Cilt 2 · Bölüm 2 — IP, Alt Ağlar ve ARP.

Beceri: IPv4 adresini ve CIDR gösterimini okumak (ağ adresi, yayın adresi, kullanılabilir
host sayısı), özel (iç ağ) ve genel adresleri ayırmak, ARP tablosunda ARP zehirlemesini
(ağ geçidinin MAC'inin başka bir IP'de de görünmesi) yakalamak, ping'in sınırını bilmek.

Vakalar: banka şubesi gişe ağı, kafe misafir Wi-Fi'ı, hastane poliklinik katı, lojistik
deposu el terminali ağı. Hepsinde Deniz'in SOC'una düşen bir "ARP değişti" alarmı var.
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "ferahbank", "makine": "gise-03", "klasor": "sube_kadikoy",
        "arayuz": "eth0", "bugun": "arp_0915.txt", "dun": "arp_dun_1700.txt",
        "kapsam": "alarm_KG-4471.txt", "baglanti": "gise03_ss_tn.txt",
        "ic_portlar": [445, 3389, 1433, 8443, 389, 135],
        "brifing": """
Saat 09.15. Deniz'in ekranında kırmızı bir satır: **Ferah Bank** Kadıköy şubesinde, gişe
bilgisayarı **<<makine>>** üzerinde "ağ geçidinin MAC adresi değişti" alarmı. Aynı dakikalarda iki
gişe görevlisi, internet şubesine girerken tarayıcının sertifika uyarısı verdiğini bildirdi.

Deniz sandalyesini sana çeviriyor: "Bu tablo bir ortadaki adam (man-in-the-middle) saldırısı
gibi kokuyor. Şubeden alınan ARP tablolarını ve bağlantı listesini `<<klasor>>` klasörüne
koydum. Önce ağın sınırlarını çıkar, sonra sahte ağ geçidini bul."

Selin kapıdan ekliyor: "Kaan Bey bir saat içinde rapor bekliyor. Kanıtsız tek cümle yazmayın."
""",
    },
    {
        "kod": "atolye", "makine": "kasa-pc", "klasor": "kafe_wifi",
        "arayuz": "wlan0", "bugun": "neigh_simdi.txt", "dun": "neigh_pazartesi.txt",
        "kapsam": "ag_bilgisi.txt", "baglanti": "kasa_baglantilar.txt",
        "ic_portlar": [9100, 445, 8080, 554, 1883, 5353],
        "brifing": """
**Atölye Kahve**'nin sahibi Berk telaşlı: "Müşteriler Wi-Fi'da sitelere girerken güvenlik
uyarısı alıyor, kasa da ara ara takılıyor." Kafede kasa ile misafir Wi-Fi'ı aynı ağda.

Deniz uzaktan bağlanıp kasa bilgisayarı **<<makine>>**'den ARP tablolarını ve bağlantı
listesini aldı, `<<klasor>>` klasörüne koydu. "Biri kafede oturmuş, kendini modem gibi
tanıtıyor olabilir," diyor. "Ama önce ağın kendisini anlayalım: kaç cihaz sığar, sınırları
nerede?"

Mert gülüyor: "Kahve bedava, Wi-Fi şifresi duvarda. Saldırgan için cennet."
""",
    },
    {
        "kod": "medora", "makine": "poliklinik-pc12", "klasor": "kat3_poliklinik",
        "arayuz": "eth0", "bugun": "ip_neigh_bugun.txt", "dun": "ip_neigh_dun.txt",
        "kapsam": "vlan_tanimi.txt", "baglanti": "pc12_baglantilar.txt",
        "ic_portlar": [445, 104, 1433, 3389, 8080, 135],
        "brifing": """
**Medora Sağlık**'ın 3. kat polikliniğinde muayene bilgisayarları gün içinde birkaç kez hasta
sisteminden atılıyor. Bilgi işlemden Dr. Aslı Hanım, **<<makine>>** üzerinde alınmış ARP
tablolarını ve bağlantı listesini Kalkan'a gönderdi; Deniz hepsini `<<klasor>>` klasörüne koydu.

Deniz: "Oturum düşmesi bazen ağdaki bir sahtekârın trafiği kendi üzerinden geçirmeye
çalışmasının yan etkisidir. Önce bu katın ağ sınırlarını hesapla, sonra ARP tablosunda
iki kimlikli bir cihaz ara."
""",
    },
    {
        "kod": "kuzgun", "makine": "el-terminali-07", "klasor": "depo_b_blok",
        "arayuz": "wlan0", "bugun": "arp_sabah.txt", "dun": "arp_aksam_once.txt",
        "kapsam": "depo_ag_plani.txt", "baglanti": "terminal07_ss.txt",
        "ic_portlar": [8080, 9100, 445, 502, 1883, 5432],
        "brifing": """
**Kuzgun Lojistik**'in B blok deposunda el terminalleri sabahtan beri stok servisine
bağlanırken "güvenilmeyen sertifika" uyarısı veriyor. Serdar Bey depo ağına yabancı bir
cihaz takılmış olabileceğinden şüpheleniyor.

Deniz, **<<makine>>** üzerinden alınan ARP tablolarını ve bağlantı listesini `<<klasor>>`
klasörüne koydu: "Depo ağı küçük bir alt ağ. Önce sınırlarını çıkar: Mert tarama yaparken
bir adres bile taşmasın. Sonra ARP tablosunda kendini ağ geçidi gibi gösteren cihazı bul."
""",
    },
]

BLOKLAR = ["10.{a}.{b}.{c}", "172.{d}.{b}.{c}", "192.168.{b}.{c}"]


def _rastgele_ag(rng, onek: int) -> ipaddress.IPv4Network:
    sablon = rng.choice(BLOKLAR)
    ip = sablon.format(a=rng.randint(1, 250), b=rng.randint(0, 254), c=rng.randint(1, 254),
                       d=rng.randint(16, 31))
    return ipaddress.ip_network(f"{ip}/{onek}", strict=False)


def _blok_aciklama(onek: int) -> str:
    if onek >= 24:
        return f"/{onek} maskesi son oktette biter: blok boyutu 2^(32-{onek}) = {2 ** (32 - onek)}"
    return (f"/{onek} maskesi üçüncü oktette biter: üçüncü oktette blok boyutu 2^(24-{onek}) = "
            f"{2 ** (24 - onek)}, son oktet ağ adresinde 0, yayın adresinde 255 olur")


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    onek = rng.choice([23, 25, 26, 26, 27, 27, 28, 29])
    net = _rastgele_ag(rng, onek)
    hostlar = list(net.hosts())
    gw = hostlar[0] if rng.random() < 0.6 else hostlar[-1]
    digerleri = [h for h in hostlar if h != gw]
    secilen = rng.sample(digerleri, 5)
    makine_ip, saldirgan_ip = str(secilen[0]), str(secilen[1])
    komsular = [str(x) for x in secilen[2:]]
    gw = str(gw)
    gw_mac = ag.mac_uret(rng, rng.choice(["00:1a:2b", "c8:3a:35", "f4:f2:6d", "e8:48:b8", "50:c7:bf"]))
    saldirgan_mac = ag.mac_uret(rng, rng.choice(["3c:52:82", "f4:8e:38", "dc:a6:32", "e4:5f:01"]))
    komsu_mac = [ag.mac_uret(rng) for _ in komsular]
    # bağlantılar: iç ağ adresleri + tek bir genel (TEST-NET) adres
    ic_adresler = [komsular[0], str(_rastgele_ag(rng, 24).network_address + rng.randint(2, 250)),
                   f"172.{rng.choice([16, 20, 24, 31])}.{rng.randint(0, 254)}.{rng.randint(2, 250)}",
                   f"192.168.{rng.randint(0, 254)}.{rng.randint(2, 250)}",
                   f"10.{rng.randint(0, 254)}.{rng.randint(0, 254)}.{rng.randint(2, 250)}"]
    genel = u.dis_ip(rng)
    baglantilar = []
    for i, ip in enumerate(ic_adresler):
        baglantilar.append((ip, v["ic_portlar"][i % len(v["ic_portlar"])]))
    baglantilar.insert(rng.randint(1, len(baglantilar)), (genel, rng.choice([443, 8443, 4444, 9001])))
    portlar = rng.sample(range(40000, 60999), len(baglantilar) + 1)
    kullanilabilir = net.num_addresses - 2
    gercek_mac = gw_mac
    return {
        "vaka": f"{m['ad']} — {v['makine']} ARP alarmı",
        "brifing": v["brifing"],
        "v": v,
        "onek": onek, "net": str(net), "makine_ip": makine_ip, "saldirgan_ip": saldirgan_ip, "gw": gw,
        "gw_mac": gw_mac, "saldirgan_mac": saldirgan_mac, "komsular": list(zip(komsular, komsu_mac)),
        "baglantilar": baglantilar, "portlar": portlar,
        "metin": {
            "musteri": m["ad"], "makine": v["makine"], "klasor": v["klasor"], "bugun": v["bugun"],
            "dun": v["dun"], "kapsam": v["kapsam"], "baglanti": v["baglanti"],
            "cidr": f"{makine_ip}/{onek}", "onek": onek, "blok_aciklama": _blok_aciklama(onek),
            "gw": gw,
        },
        "cevaplar": {
            "ag_adresi": str(net.network_address),
            "yayin": str(net.broadcast_address),
            "host_sayisi": kullanilabilir,
            "genel": genel,
            "saldirgan": saldirgan_ip,
            "gercek_mac": [gercek_mac, gercek_mac.replace(":", "-")],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = lab / v["klasor"]
    dev = v["arayuz"]
    u.yaz(k / v["kapsam"],
          f"Alarm / ağ bilgisi\n"
          f"------------------\n"
          f"Makine      : {v['makine']}\n"
          f"Adres       : {s['makine_ip']}/{s['onek']}   (CIDR gösterimi)\n"
          f"Ağ geçidi   : {s['gw']}\n"
          f"Arayüz      : {dev}\n"
          f"Not (Mert)  : Tarama kapsamını bu alt ağla sınırlayacağım; ağ ve yayın adresini\n"
          f"              doğru yazın, bir adres bile taşarsa başka bir ağa paket atmış oluruz.\n")
    # bugünkü tablo: ağ geçidi saldırganın MAC'ini gösteriyor
    durum = ["REACHABLE", "STALE", "DELAY", "STALE"]
    bugun = [(s["gw"], dev, s["saldirgan_mac"], "REACHABLE"),
             (s["saldirgan_ip"], dev, s["saldirgan_mac"], "STALE")]
    for i, (ip, mac) in enumerate(s["komsular"]):
        bugun.append((ip, dev, mac, durum[i % 4]))
    bugun.sort(key=lambda g: tuple(int(x) for x in g[0].split(".")))
    u.yaz(k / v["bugun"], f"# {v['makine']}$ ip neigh   (bugün)\n" + ag.ip_neigh_cikti(bugun))
    dun = [(s["gw"], dev, s["gw_mac"], "REACHABLE")]
    for i, (ip, mac) in enumerate(s["komsular"]):
        dun.append((ip, dev, mac, durum[(i + 1) % 4]))
    dun.sort(key=lambda g: tuple(int(x) for x in g[0].split(".")))
    u.yaz(k / v["dun"], f"# {v['makine']}$ ip neigh   (dün)\n" + ag.ip_neigh_cikti(dun))
    satirlar = [f"# {v['makine']}$ ss -tn",
                "State  Recv-Q Send-Q   Local Address:Port      Peer Address:Port Process"]
    for (ip, port), yerel in zip(s["baglantilar"], s["portlar"]):
        satirlar.append(f"ESTAB  0      0      {s['makine_ip'] + ':' + str(yerel):>22} {ip + ':' + str(port):>22}")
    satirlar.append(f"ESTAB  0      0      {'127.0.0.1:631':>22} {'127.0.0.1:' + str(s['portlar'][-1]):>22}")
    u.yaz(k / v["baglanti"], "\n".join(satirlar) + "\n")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: CIDR'ı Python'un ipaddress modülüyle, tabloları awk/sort/uniq ile çözer."""
    v = s["v"]
    k = v["klasor"]
    cidr = _sh(f"awk '/^Adres/ {{print $3}}' {k}/{v['kapsam']}", lab)
    py = f"import ipaddress as i; n=i.ip_network('{cidr}', strict=False); print(n.network_address, n.broadcast_address, n.num_addresses-2)"
    ag_adresi, yayin, sayi = _sh(f"python3 -c \"{py}\"", lab).split()
    genel = _sh(f"awk 'NR>2 {{print $5}}' {k}/{v['baglanti']} | cut -d: -f1 | "
                "grep -v -E '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.)'", lab)
    sahte_mac = _sh(f"awk 'NR>1 {{print $5}}' {k}/{v['bugun']} | sort | uniq -d", lab)
    gw = _sh(f"awk '/^Ağ geçidi/ {{print $4}}' {k}/{v['kapsam']}", lab)
    saldirgan = _sh(f"grep -i '{sahte_mac}' {k}/{v['bugun']} | awk '{{print $1}}' | grep -v -x '{gw}'", lab)
    gercek = _sh(f"grep '^{gw} ' {k}/{v['dun']} | awk '{{print $5}}'", lab)
    return {1: ag_adresi, 2: yayin, 3: sayi, 4: genel, 5: saldirgan, 6: gercek,
            7: _secmeli(s, lab, 7), 8: _secmeli(s, lab, 8)}


# ---------------------------------------------------------------- sık hatalar

def _ag_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["makine_ip"]:
        return "Bu makinenin kendi adresi. Ağ adresi, bu adresin içinde bulunduğu bloğun İLK adresidir."
    if g.endswith(".0") and s["onek"] > 24:
        return f"Bu cevap /24 için doğru olurdu. Maske /{s['onek']}; blok boyutunu hesapla ve son okteti onun katına aşağı yuvarla."
    if g == s["cevaplar"]["yayin"]:
        return "Bu bloğun SON adresi, yani yayın adresi. Ağ adresi ilk adrestir."
    return None


def _yayin_hata(g, beklenen, b):
    s = b.senaryo
    if g.endswith(".255") and s["onek"] > 24:
        return f"Bu cevap /24 için doğru olurdu. Maske /{s['onek']}; yayın adresi bloğun son adresidir (ağ adresi + blok boyutu - 1)."
    if g == s["cevaplar"]["ag_adresi"]:
        return "Bu bloğun ilk adresi, yani ağ adresi. Yayın adresi bloğun son adresidir."
    try:
        bek = ipaddress.ip_address(beklenen)
        if ipaddress.ip_address(g) == bek + 1:
            return "Bir fazla: bu bir sonraki bloğun ağ adresi. Yayın adresi kendi bloğunun son adresidir."
    except ValueError:
        pass
    return None


def _host_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 2:
        return "Bu bloktaki toplam adres sayısı. İlk (ağ) ve son (yayın) adres makinelere verilemez; ikisini çıkar."
    if n == beklenen + 1:
        return "Bir eksik çıkardın: hem ağ adresi hem yayın adresi rezervedir."
    if n == 254 and beklenen != 254:
        return "254, /24 için geçerli. Bu ağın maskesi farklı; 2^(32-önek) - 2 formülünü kullan."
    return None


OZEL_BLOKLAR = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _genel_hata(g, beklenen, b):
    if g.startswith("127."):
        return "127.x geri döngü (loopback) adresidir; makine kendisiyle konuşuyor. İnternete çıkan bağlantı bu değil."
    try:
        adres = ipaddress.ip_address(g)
    except ValueError:
        return None
    if any(adres in blok for blok in OZEL_BLOKLAR):
        return "Bu adres özel (iç ağ) bloklarından birinde: 10/8, 172.16/12 ya da 192.168/16. İnternet adresi değil."
    return None


def _saldirgan_hata(g, beklenen, b):
    if g == b.senaryo["gw"]:
        return "Bu, ağ geçidinin IP'si; o kurban, saldırgan değil. Aynı MAC'i taşıyan DİĞER IP'yi bul."
    if g == b.senaryo["makine_ip"]:
        return "Bu, alarmın geldiği makinenin kendi adresi. ARP tablosunda kendi adresi görünmez."
    return None


def _mac_hata(g, beklenen, b):
    s = b.senaryo
    if g.replace("-", ":") == s["saldirgan_mac"]:
        return "Bu bugünkü (sahte) MAC: saldırganın kartı. Ağ geçidinin gerçek MAC'i dünkü tabloda."
    return None


ADIMLAR = [
    Adim("IPv4 adresi: dört oktet, 32 bit", """
Bir IPv4 adresi noktalarla ayrılmış dört sayıdır: `192.168.1.50`. Her sayıya **oktet** denir;
8 bittir, bu yüzden 0-255 arasında olur. Toplam 32 bit.

Deniz'in alarm kaydına bakalım. `Adres` satırındaki `/<<onek>>` kısmına birazdan geleceğiz.
""", komut="cat <<klasor>>/<<kapsam>>"),
    Adim("Özel adresler: iç ağın işareti", """
Bazı adres blokları **özeldir**: sadece yerel ağlarda kullanılır, internette yönlendirilmez.

- `10.0.0.0/8` → 10.0.0.0 - 10.255.255.255 (büyük kurum ağları)
- `172.16.0.0/12` → 172.16.0.0 - 172.31.255.255 (orta ölçek, Docker) — dikkat: 172.32 ve
  üstü özel **değildir**
- `192.168.0.0/16` → 192.168.0.0 - 192.168.255.255 (ev ve küçük ofis)
- `127.0.0.0/8` → makinenin kendisi (loopback)

Bu oyunda internet adreslerini temsil etmek için belgelendirmeye ayrılmış blokları kullanıyoruz
(`192.0.2.x`, `198.51.100.x`, `203.0.113.x`). Gerçekte kimseye ait değiller ama özel blokların da
dışındalar; lab'da "internet" demek.

`ss -tn` kurulu TCP bağlantılarını gösterir. <<makine>>'nin bağlantılarında sağdaki sütun
(Peer) karşı taraftır:
""", komut="cat <<klasor>>/<<baglanti>>", sonra="""
**Hacker gözüyle:** Sızdığın bir makinede `10.x` ya da `172.16-31.x` görmek iç ağa açıldığın
anlamına gelir. Dışarıdan görünmeyen bu makineler çoğu zaman en zayıf olanlardır (Cilt 6:
pivoting). Savunmacı için tersi önemlidir: iç ağdaki bir iş istasyonunun internette
tanımadığı bir adresle kurulu bağlantısı, ilk bakılacak satırdır.
"""),
    Adim("CIDR: /24 ne demek?", """
`192.168.1.0/24` gösterimindeki `/24`, 32 bitin ilk 24'ünün **ağ**, kalan 8'inin **makine**
kısmı olduğunu söyler. 8 bit = 256 adres; ilki **ağ adresi**, sonuncusu **yayın (broadcast)
adresi**dir. Geriye 254 kullanılabilir makine adresi kalır.

Genel formül: kullanılabilir host = 2^(32 - önek) - 2.

- `/24` → 254 host · `/16` → 65.534 · `/30` → 2 (iki router arası) · `/32` → tek host

Önek 24'ten büyükse son oktet bloklara bölünür. Örnek: `192.168.1.77/26`

1. Blok boyutu: 2^(32-26) = 64. Bloklar: 0-63, 64-127, 128-191, 192-255
2. 77 hangi blokta? 64-127 → ağ adresi `192.168.1.64`, yayın `192.168.1.127`
3. Kullanılabilir: 64 - 2 = 62 host (`.65` - `.126`)

Önek 24'ten küçükse aynı hesap üçüncü oktette yapılır: `10.4.7.9/23` için blok 2^(24-23) = 2;
7, 6-7 bloğunda → ağ `10.4.6.0`, yayın `10.4.7.255`.

**Hacker gözüyle:** Keşifte bir hedefin IP'sini bulunca aynı alt ağdaki komşularına da
bakmak istersin; ama kapsam dışına taşmamak için sınırları doğru hesaplaman şart.
"""),
    Adim("ARP: IP'yi MAC'e çevirmek", """
Yerel ağda makineler aslında **MAC adresiyle** konuşur. Bir makine `192.168.1.1`'e paket
göndereceğinde önce yayınla sorar: "192.168.1.1 kimde? MAC'ini söyle." Sahibi cevap verir ve
eşleşme bir süre **ARP tablosunda** tutulur. `ip neigh` bu tabloyu gösterir. Kendi makinene
bak (boş çıkabilir; yakın zamanda kimseyle konuşmadıysa normal):
""", komut="ip neigh", sonra="""
Durum sütunu: `REACHABLE` (yakında doğrulandı), `STALE` (bayat ama hâlâ kullanılır),
`DELAY` (doğrulanıyor), `FAILED` (cevap gelmedi).
"""),
    Adim("ARP zehirlemesi: iki kimlikli cihaz", """
ARP'ın hiçbir güvenlik kontrolü yoktur; kim cevap verirse ona inanılır. ARP zehirlemesinde
(ARP spoofing) saldırgan "ağ geçidi benim" diye sahte cevaplar yayınlar. Kurbanın tablosunda
ağ geçidinin IP'si artık **saldırganın MAC'ine** bağlanır ve trafik önce saldırgana gider:
ortadaki adam (man-in-the-middle).

İz nasıl görünür? Normalde her MAC tabloda tek bir IP'yle görünür. **Aynı MAC iki farklı
IP'nin yanında** duruyorsa ve bunlardan biri ağ geçidiyse, alarm zilleri çalmalı.
<<makine>>'nin bugünkü tablosuna bak; ağ geçidi `<<gw>>`:
""", komut="cat <<klasor>>/<<bugun>>", sonra="""
**Hacker gözüyle:** Cilt 5 ve 6'da bettercap ve arpspoof ile bu saldırıyı kendi lab'ında
yapacaksın. Savunma tarafında statik ARP girdileri, anahtarlardaki (switch) **Dynamic ARP
Inspection** ve "ağ geçidinin MAC'i değişti" alarmları bu saldırıyı engeller ya da yakalar.
Deniz'in alarmı tam olarak sonuncusu.
"""),
    Adim("ping: orada mısın?", """
`ping` hedefe küçük bir ICMP echo paketi gönderir ve cevabın kaç milisaniyede döndüğünü ölçer.
`-c 2` iki paket gönder demektir. Kendi makinene (loopback) dene:
""", komut="ping -c 2 127.0.0.1", sonra="""
`time=` gidiş-dönüş süresidir. Cevap geliyorsa makine ayakta ve erişilebilir. Ama cevap
gelmemesi makinenin kapalı olduğunu **kanıtlamaz**: birçok sistem ve güvenlik duvarı ICMP'yi
bilerek engeller. Cilt 4'te nmap'in `-Pn` seçeneğini bu yüzden öğreneceğiz.
"""),
]

GOREVLER = [
    Gorev("<<makine>>'nin adresi `<<cidr>>`. Bu alt ağın **ağ adresi** ne?",
          IP("ag_adresi", sik_hatalar=_ag_hata),
          ("Ağ adresi, bloğun ilk adresidir. Önce blok boyutunu bul.",
           "<<blok_aciklama>>.",
           "Makinenin adresindeki ilgili okteti blok boyutunun katına AŞAĞI yuvarla; o oktetten "
           "sonraki oktetler 0 olur."),
          puan=30, baslik="Ağ adresi"),
    Gorev("Aynı alt ağın **yayın (broadcast) adresi** ne?",
          IP("yayin", sik_hatalar=_yayin_hata),
          ("Yayın adresi bloğun son adresidir.",
           "Ağ adresine (blok boyutu - 1) ekle. <<blok_aciklama>>.",
           "Bir sonraki bloğun ağ adresini bul ve ondan bir çıkar."),
          puan=30, baslik="Yayın adresi"),
    Gorev("Bu alt ağda kaç **kullanılabilir** makine (host) adresi var? Mert tarama kapsamını "
          "buna göre ayarlayacak.",
          Sayi("host_sayisi", sik_hatalar=_host_hata),
          ("Toplam adres sayısı maskeden gelir; iki adres makinelere verilmez.",
           "Önek /<<onek>>: makine kısmı 32 - <<onek>> bit.",
           "2^(32 - <<onek>>) hesapla ve ağ ile yayın adresini çıkar."),
          puan=25, baslik="Kaç host"),
    Gorev("`<<baglanti>>` dosyasına göre <<makine>> iç ağ dışında, **internetteki** hangi adresle "
          "kurulu bir bağlantıya sahip?",
          IP("genel", sik_hatalar=_genel_hata),
          ("Karşı taraf (Peer) sütunundaki adresleri özel bloklarla karşılaştır.",
           "10/8, 172.16/12, 192.168/16 ve 127/8 dışında kalan tek adresi ara. "
           "172.x'te ikinci okteti kontrol etmeyi unutma.",
           "`awk 'NR>2 {print $5}' <<klasor>>/<<baglanti>> | cut -d: -f1` ile karşı adresleri listele ve tek tek ele."),
          puan=25, baslik="Dışarıyla konuşan"),
    Gorev("Bugünkü ARP tablosunda (`<<bugun>>`) kendini ağ geçidi gibi gösteren cihazın **kendi IP "
          "adresi** ne?",
          IP("saldirgan", sik_hatalar=_saldirgan_hata),
          ("Saldırganın MAC'i tabloda iki kez görünür: bir kez kendi IP'siyle, bir kez ağ geçidinin IP'siyle.",
           "MAC sütununda tekrar eden değeri bul; o MAC'in yanındaki iki IP'den biri ağ geçidi (<<gw>>).",
           "`awk 'NR>1 {print $5}' <<klasor>>/<<bugun>> | sort | uniq -d` tekrarlanan MAC'i verir; "
           "sonra onu `grep` ile tabloda ara."),
          puan=35, baslik="Sahte ağ geçidi"),
    Gorev("Ağ geçidinin (<<gw>>) **gerçek** MAC adresi ne olmalı? (Dünkü tablo: `<<dun>>`)",
          Metin("gercek_mac", sik_hatalar=_mac_hata, bicim="MAC adresi (aa:bb:cc:dd:ee:ff)"),
          ("Saldırı bugün başladı; dün tablo temizdi.",
           "`cat <<klasor>>/<<dun>>` ve ağ geçidinin satırı.",
           "`grep '^<<gw>> ' <<klasor>>/<<dun>>` satırındaki `lladdr`'den sonraki değer."),
          puan=30, baslik="Gerçek MAC"),
    Gorev("Mert, kapsamdaki bir sunucuya `ping` attı ve hiç cevap alamadı. Hangi sonuç doğru?",
          Secmeli([
              ("Kapalı olmayabilir; ICMP engelleniyor olabilir, başka yollarla da denemek gerekir",
               "Doğru. Birçok sistem ve güvenlik duvarı ICMP'yi bilerek engeller; 'ping atmıyor' ile 'kapalı' aynı şey değildir."),
              ("Makine kesinlikle kapalıdır; açık bir makine ping'e her zaman cevap vermek zorundadır",
               "Hiçbir kural ping'e cevap vermeyi zorunlu kılmaz; Windows güvenlik duvarı bile varsayılan olarak çoğu zaman engeller."),
              ("Makine açık ama ağ dışındadır; ping sadece aynı alt ağdaki makinelere ulaşabilir",
               "ping yönlendirilebilir bir protokoldür (ICMP); internetteki makinelere de gider."),
              ("Makine ayakta ama ARP tablosunda olmadığı için IP adresi yanlış yazılmış demektir",
               "ARP tablosu sadece yerel ağdaki yakın zamanlı eşleşmeleri tutar; ping'in cevapsız kalmasının sebebini söylemez."),
          ]),
          ("ping hangi protokolü kullanır ve o protokol engellenebilir mi?",
           "Güvenlik duvarları neyi engeller? Sadece portları mı?",
           "Cevapsızlık iki şey olabilir: makine kapalı ya da ICMP filtreleniyor."),
          puan=20, baslik="Sessiz ping"),
    Gorev("Deniz, bu saldırının <<musteri>> ağında bir daha işe yaramaması için ne önermeli?",
          Secmeli([
              ("Anahtarlarda Dynamic ARP Inspection'ı açmak, kritik cihazlara statik ARP yazmak",
               "Doğru. DAI, anahtarın ARP cevaplarını doğrulamasını sağlar; statik girdi de ağ geçidinin MAC'ini sabitler."),
              ("Ağ geçidinin IP adresini değiştirip yeni adresi sadece çalışanlarla paylaşmak",
               "Saldırgan yeni adresi ARP yayınlarından saniyeler içinde öğrenir; gizlilik bir savunma değildir."),
              ("Tüm bilgisayarlarda ping'i (ICMP) kapatarak saldırganın cihazları bulmasını engellemek",
               "ARP zehirlemesi ICMP'ye ihtiyaç duymaz; ARP, ICMP kapalıyken de çalışır."),
              ("Alt ağı /24'ten /16'ya büyütüp saldırganın hedef seçmesini zorlaştırmak",
               "Daha büyük bir ağ, daha büyük bir yayın alanı demektir; saldırıyı zorlaştırmaz, kolaylaştırır."),
          ]),
          ("Saldırı ARP'ın neyinden faydalanıyordu?",
           "ARP cevapları doğrulanmıyordu. Doğrulamayı kim yapabilir: anahtar mı, router mı?",
           "Hem ağ cihazında doğrulama hem de kritik eşleşmeyi sabitlemek."),
          puan=20, baslik="Savunma"),
]

SEVIYE = Seviye(
    kimlik="c02b02",
    cilt=2,
    bolum=2,
    baslik="IP, Alt Ağlar ve ARP",
    brifing="""
**<<musteri>>** ağındaki **<<makine>>** üzerinde "ağ geçidinin MAC adresi değişti" alarmı
düştü. Deniz ARP tablolarını ve bağlantı listesini `<<klasor>>` klasörüne koydu: "Önce ağın
sınırlarını hesapla, sonra sahte ağ geçidini bul."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
ARP zehirlemesi on yıllardır bilinir ve hâlâ çalışır, çünkü yerel ağ "içerideki herkes
dürüsttür" varsayımıyla tasarlandı. Saldırgan için yerel ağa girmek (açık Wi-Fi, boş bir
duvar prizi) yeterlidir; gerisini araçlar halleder. Savunmacının elindeki en güçlü iz ise
basittir: aynı MAC'in iki IP'de görünmesi ve ağ geçidinin MAC'inin bir gecede değişmesi. Alt
ağ hesabı da aynı derecede pratik bir beceridir; kapsamı bir adres bile taşıran bir tarama,
izinsiz bir sisteme paket göndermek demektir.
""",
    gercek_hayat="""
- **Kafe ve otel Wi-Fi'ları:** Ortak ve parolası herkese açık kablosuz ağlarda ortadaki adam
  saldırıları yıllardır uyarı konusudur; tarayıcıların sertifika uyarıları ve HSTS gibi
  mekanizmalar, ARP zehirlemesiyle araya giren birinin HTTPS trafiğini okumasını büyük ölçüde
  engeller. Bu yüzden bir sertifika uyarısını "geç" deyip kapatmak tehlikelidir.
- **Dynamic ARP Inspection:** Kurumsal anahtarlarda (switch) bulunan bu özellik, ARP
  cevaplarını DHCP kayıtlarıyla karşılaştırıp sahte olanları düşürür. Ağ sertleştirme
  rehberleri, kullanıcıların bağlandığı ağlarda açılmasını önerir.
- **Kapsam ve CIDR hataları:** Sızma testlerinde kapsam genellikle CIDR bloklarıyla yazılır.
  Yanlış hesaplanan bir maske, testi müşterinin değil başka bir kurumun adreslerine
  taşıyabilir; bu yüzden test ekipleri kapsam listesini taramadan önce iki kez doğrular.
""",
    sure_hedef_dk=30,
)
