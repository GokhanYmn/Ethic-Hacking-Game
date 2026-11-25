"""Cilt 4 · Bölüm 4 — nmap: Keşfin Ana Aracı.

Beceri: bir hedefte hangi portların açık olduğunu bulmak, açık portların banner'ından servisi ve sürümü
okumak, sürümü bir eşik listesiyle karşılaştırıp eskiyi seçmek, tarama türlerini (-sS/-sT/-sU) ve nmap
çıktısını (open/closed/filtered) yorumlamak.

Servis: seviyenin hedefi 127.a.b.c adresinde (rastgele) 5 TCP servisi açar: SSH, FTP ya da SMTP, bir banner
vermeyen web servisi (curl ister) ve bir ek servis. Port aralığı 20000-45000.
Görev metni Kali'de nmap'i öğretir; kontrol, aracın kendisini değil, bulunan gerçeği doğrular (nmap
test konteynerinde yoktur): `coz` python socket ile tarar.

Vakalar: lojistik (Kuzgun depo sunucusu), hastane (Medora portal sunucusu), kafe (Atölye Kahve).
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir, tcp_banner
from hy.ortak.vakalar import musteri

from . import ortak as o

ESIKLER = """# Kalkan Güvenlik: bu müşteride kabul edilen EN DÜŞÜK sürümler (altı "eski" sayılır)
openssh 8.4
vsftpd 3.0.3
proftpd 1.3.6
exim 4.94
apache 2.4.54
nginx 1.22
"""

VAKALAR = [
    {
        "kod": "kuzgun", "sunucu": "kzg-depo", "eski": ("ftp", "vsFTPd", "2.3.4"), "ornek": ("smtp", "Exim", "4.96"),
        "ek": "imap", "http": ["Apache/2.4.57", "Apache/2.4.58"], "sayfa": "Kuzgun Depo Paneli",
        "brifing": """
**Kuzgun Lojistik**'in depo sunucusu (**<<sunucu>>**) yeni bir yazılım kurulumundan sonra "bir şeyler fazladan
açık kalmış olabilir" şüphesiyle Kalkan'a getirildi. Serdar Bey: "Bakım penceresi bu gece, o zamana kadar ne
açık ne değil bilmek istiyorum." Sunucunun laboratuvardaki kopyası **<<adres>>** adresinde.

Selin: "Bu bir port taraması görevi. Kali'nde nmap varsa `nmap -sV` işini görür, yoksa `nc` ve `curl` yeter.
Bizi ilgilendiren araç değil, **gerçek**: hangi portlar açık, ne çalışıyor, hangisi eski."

Mert: "Port aralığı 20000-45000, hepsini tara. Sürüm numarası altın değerindedir; bu müşterinin kabul
ettiği en düşük sürümleri Selin `guncel_surumler.txt`'e yazdı."
""",
    },
    {
        "kod": "medora", "sunucu": "medora-portal", "eski": ("smtp", "Exim", "4.87"),
        "ornek": ("ftp", "ProFTPD", "1.3.8"), "ek": "pop3", "http": ["nginx/1.24.0", "nginx/1.26.0"],
        "sayfa": "Medora Hasta Portalı",
        "brifing": """
**Medora Sağlık**'ın hasta portalı sunucusu (**<<sunucu>>**) yeni bir hastane birimi bağlandıktan sonra
denetimden geçiyor. Bilgi işlem sorumlusu Dr. Aslı Hanım: "Sunucuda hangi servislerin dışarıya açık olduğunu
bilmiyorum, kuran firma gitti." Sunucunun laboratuvardaki kopyası **<<adres>>** adresinde.

Selin: "Hastane verisi: bu yüzden sürümlere özellikle dikkat. Bu görevde nmap'in yaptığını elle yapacağız:
port bulma, banner okuma, sürüm karşılaştırma."

Deniz: "Dikkat: aktif tarama hastanenin IDS'ine alarm düşürür. Müşteriye tarama saatini önceden söyledik."
""",
    },
    {
        "kod": "atolye", "sunucu": "atolye-web", "eski": ("ftp", "ProFTPD", "1.3.3c"),
        "ornek": ("smtp", "Exim", "4.96"), "ek": "imap", "http": ["Apache/2.4.57", "Apache/2.4.58"],
        "sayfa": "Atölye Kahve Sadakat Sitesi",
        "brifing": """
**Atölye Kahve**'nin sitesini yapan serbest çalışan, sunucuyu bir barındırma paketinden alıp kendi
kurmuş (**<<sunucu>>**). Berk: "Siteyi bir arkadaşım kurdu, içinde neler çalışıyor hiç bilmiyorum." Sunucunun
laboratuvardaki kopyası **<<adres>>** adresinde.

Selin: "Küçük işletmelerde en sık gördüğümüz: kuruluşu yapan kişi eski bir dosya aktarım servisini açık
bırakmıştır. Haritasını çıkar, sürümleri gör."

Mert: "Banner'ı olmayan bir servis de çıkacak. Bağlanınca susuyorsa, ne olabileceğini düşün: web sunucusu
önce senin konuşmanı bekler."
""",
    },
]

SSH_SURUMLERI = ["8.4p1", "8.9p1", "9.2p1"]


def _banner(tur: str, urun: str, surum: str, sunucu: str) -> str:
    if tur == "ssh":
        return f"SSH-2.0-OpenSSH_{surum}\r\n"
    if tur == "ftp":
        if urun == "vsFTPd":
            return f"220 (vsFTPd {surum})\r\n"
        return f"220 ProFTPD {surum} Server (Debian) [::ffff:127.0.0.1]\r\n"
    if tur == "smtp":
        return f"220 {sunucu} ESMTP Exim {surum} Wed, 04 Nov 2026 03:12:44 +0300\r\n"
    if tur == "imap":
        return "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Dovecot ready.\r\n"
    if tur == "pop3":
        return "+OK Dovecot ready.\r\n"
    raise ValueError(tur)


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    adres = o.lab_adresi(rng)
    while True:
        ports = o.portlar(rng, 5)
        if all(b - a > 14 for a, b in zip(ports, ports[1:])):
            break
    rng.shuffle(ports)
    p_ssh, p_http, p_eski, p_ornek, p_ek = ports
    ssh_v = rng.choice(SSH_SURUMLERI)
    http_server = rng.choice(v["http"])
    eski_tur, eski_urun, eski_surum = v["eski"]
    ornek_tur, ornek_urun, ornek_surum = v["ornek"]
    kapali = next(p for p in range(rng.randint(20000, 44000), 45001) if all(abs(p - q) > 12 for q in ports))
    bannerlar = {
        p_ssh: _banner("ssh", "OpenSSH", ssh_v, v["sunucu"]),
        p_eski: _banner(eski_tur, eski_urun, eski_surum, v["sunucu"]),
        p_ornek: _banner(ornek_tur, ornek_urun, ornek_surum, v["sunucu"]),
        p_ek: _banner(v["ek"], "Dovecot", "", v["sunucu"]),
    }
    return {
        "vaka": f"{m['ad']} — {v['sunucu']} port taraması",
        "brifing": v["brifing"], "v": v, "m": m, "adres": adres, "ports": sorted(ports),
        "p": {"ssh": p_ssh, "http": p_http, "eski": p_eski, "ornek": p_ornek, "ek": p_ek},
        "bannerlar": bannerlar, "http_server": http_server, "ssh_v": ssh_v, "kapali": kapali,
        "eski_ad": f"{eski_urun} {eski_surum}",
        "metin": {
            "musteri": m["ad"], "sunucu": v["sunucu"], "adres": adres, "ornek_port": p_ornek, "kapali_port": kapali,
            "pencere": f"{p_ornek - 5}-{p_ornek + 5}",
            "ornek_tur": ornek_tur.upper(), "eski_tur": eski_tur.upper(),
        },
        "cevaplar": {
            "acik_sayi": 5, "acik_portlar": sorted(ports), "ssh": [ssh_v, f"openssh_{ssh_v}", f"openssh {ssh_v}"],
            "eski_port": p_eski, "eski_surum": eski_surum, "http_server": [http_server, http_server.lower()],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    from hy.ortak import uretec as u
    u.yaz(lab / "OKUBENI.txt",
          f"{s['m']['ad']} sunucusunun ({s['v']['sunucu']}) laboratuvar kopyası bu görev boyunca çalışıyor:\n"
          f"  adres: {s['adres']}   (127.0.0.0/8 bloğunun tamamı bu makinenin kendisidir)\n"
          "  taranacak port aralığı: 20000-45000 (TCP)\n\n"
          "Kali'de nmap varsa:  nmap -sV -p 20000-45000 " + s["adres"] + "\n"
          "Yoksa nc ve curl:    nc -z -v -w1 " + s["adres"] + " 20000-45000 2>&1 | grep succeeded\n")
    u.yaz(lab / "guncel_surumler.txt", ESIKLER)


def servis(s: dict, lab: Path, dur) -> None:
    sunucular = []
    for port, metin in s["bannerlar"].items():
        sunucular.append(tcp_banner(s["adres"], port, metin))
    sayfa = (f"<html><head><title>{s['v']['sayfa']}</title></head><body><h1>{s['v']['sayfa']}</h1>"
             "<p>Bakımdayız.</p></body></html>\n")
    sunucular.append(o.site_sunucusu(s["adres"], s["p"]["http"], s["http_server"], {"/": (200, sayfa)}))
    calistir(sunucular, dur)


# ---------------------------------------------------------------- sık hatalar

def _sayi_hata(g, beklenen, b):
    if g in ("4", "6"):
        return ("Bir port eksik ya da fazla. Banner vermeyen (sessiz kalan) bir port da açık sayılır; "
                "taramanın sonucundaki her portu say.")
    return None


def _eski_port_hata(g, beklenen, b):
    s = b.senaryo
    for ad, p in s["p"].items():
        if g == str(p) and ad != "eski":
            return ("Bu servisin sürümü eşik listesinin üstünde. `guncel_surumler.txt` ile her servisin sürümünü "
                    "karşılaştır; eşiğin ALTINDA kalanı seç.")
    return None


def _eski_surum_hata(g, beklenen, b):
    s = b.senaryo
    if g in (s["ssh_v"], s["http_server"].lower()):
        return "Bu servis eşik listesinin üstünde. Önce hangi servisin eski olduğunu bul, sürümünü yaz."
    return None


def _server_hata(g, beklenen, b):
    ad = b.senaryo["http_server"].split("/")[0].lower()
    if g == ad:
        return "Ürünü buldun ama sürüm numarası da gerekli: `Server:` başlığının tamamını yaz (örn. ad/1.2.3)."
    return None


def _ssh_hata(g, beklenen, b):
    if g.startswith("ssh-2.0") or g.startswith("openssh"):
        return "Sürüm numarasını yaz (banner'daki `OpenSSH_` den sonraki kısım, örn. 8.9p1)."
    return None


# ---------------------------------------------------------------- test çözücüsü

def _tuple(sv: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", sv.split("p")[0]))


def coz(lab: Path, s: dict) -> dict:
    adres = s["adres"]
    acik = o.tara(adres, lab)
    esik = {}
    for satir in (lab / "guncel_surumler.txt").read_text(encoding="utf-8").splitlines():
        if satir and not satir.startswith("#"):
            ad, sv = satir.split()
            esik[ad] = _tuple(sv)
    ssh_v = eski_p = eski_v = http_h = None
    for p in acik:
        b = o.banner_oku(adres, p, lab)
        if b.startswith("SSH-2.0-OpenSSH_"):
            ssh_v = b.split("OpenSSH_")[1].split()[0]
        elif not b:
            h = o.sh(f"curl -s -m 3 -I http://{adres}:{p}/ | grep -i '^server:' | cut -d' ' -f2-", lab)
            if h:
                http_h = h.strip()
        elif b.startswith("220"):
            m = re.search(r"(vsFTPd|ProFTPD|Exim) ([0-9][0-9a-z.]*)", b)
            if m and _tuple(m.group(2)) < esik[m.group(1).lower()]:
                eski_p, eski_v = p, m.group(2)
    return {1: len(acik), 2: " ".join(map(str, acik)), 3: ssh_v, 4: eski_p, 5: eski_v, 6: http_h,
            7: o.secmeli_cevap(SEVIYE, s, lab, 7), 8: o.secmeli_cevap(SEVIYE, s, lab, 8),
            9: o.secmeli_cevap(SEVIYE, s, lab, 9)}


ADIMLAR = [
    Adim("Keşfin ikinci aşaması: aktif", """
Pasif keşif bitti: biliyorsun ki hedefin alan adı, e-posta kalıbı ve alt alanları var. Şimdi hedefe
**doğrudan** dokunma zamanı: hangi makineler ayakta, hangi portlar açık, arkada hangi yazılım çalışıyor?
Bu iş için standart araç **nmap**'tir (Network Mapper). Cilt 3'te yazdığın ilkel tarayıcının profesyonel hali.

İlk adım **host keşfi**: ağda hangi makineler canlı?

```
nmap -sn 192.168.1.0/24
```

`-sn` "port tarama yapma, sadece canlıları bul" demektir (Cilt 3'teki ping sweep). Bizim görevimizde hedef
tek bir makine: **<<adres>>**. (127.0.0.0/8 bloğunun tamamı bu bilgisayarın kendisidir, o yüzden her adres
"canlı"dır.) Aktif tarama hedefe paket gönderir ve iz bırakır: **yalnızca izinli sistemlerde** kullan.
""", calistir=False),
    Adim("Kapalı port neye benzer?", """
Bir TCP portuna bağlanmak, Cilt 2'deki **üçlü el sıkışmayı** başlatmaktır (SYN, SYN-ACK, ACK). Port **kapalıysa**
hedef bağlantıyı reddeder; port **açıksa** el sıkışma tamamlanır. nmap'in yaptığı da budur, yalnızca binlerce
porta, hızlı ve paralel. `nc` ile (`-z`: veri göndermeden sadece dene, `-v`: sonucu yaz, `-w1`: 1 saniye bekle)
tek bir kapalı porta bakalım:
""", komut="nc -z -v -w1 <<adres>> <<kapali_port>>", sonra="""
`Connection refused`: nmap bunu **closed** olarak raporlar. Bir de **filtered** diye bir durum var: güvenlik
duvarı cevabı hiç göndermiyor, port açık mı kapalı mı belli değil.
"""),
    Adim("Açık port ve banner", """
Açık bir porta bağlanınca birçok servis kendini **banner** (karşılama satırı) ile tanıtır: yazılımın adı, çoğu
zaman sürümü. Bu görevde bildiğimiz bir açık port: <<ornek_port>> (bir <<ornek_tur>> servisi). Bağlanıp ne
söylediğine bakalım:
""", komut="nc -w2 <<adres>> <<ornek_port>>", sonra="""
Banner'daki yazılım adı ve sürüm numarası, nmap'in `-sV` (servis/sürüm tespiti) seçeneğinin yaptığının özü:
portun arkasında **ne** çalıştığını ve **hangi sürümde** olduğunu söyler.

**Hacker gözüyle:** nmap çıktısındaki sürüm numaraları altın değerindedir. "vsftpd 2.3.4" ya da
"Apache 2.4.49" gibi bir sürüm görünce o sürüme ait bilinen zafiyetleri (CVE) araştırırsın. Açık port + sürüm +
bilinen zafiyet = bir sonraki aşamanın giriş noktası.
"""),
    Adim("Bir aralığı taramak", """
nmap'in `-p` seçeneği taranacak portları söyler: `-p 22,80,443` (belirli portlar), `-p 20000-45000` (aralık),
`-p-` (65535 portun tamamı), `--top-ports 100` ya da `-F` (en yaygın portlar). **Dikkat:** varsayılan tarama
yalnızca en yaygın 1000 portu dener; yaygın olmayan bir portta çalışan servis kaçar. Pentester'lar bu yüzden
`-p-` ile başlar. Aynı işi `nc` ile bir aralık için yapabilirsin. Bildiğimiz portun çevresindeki dar bir pencereyi
tarayalım:
""", komut="nc -z -v -w1 <<adres>> <<pencere>> 2>&1 | grep succeeded", sonra="""
Bu pencerede tek bir port açık. Gerçek taramada aynı komutu bütün aralığa (20000-45000) uygularsın: beklemen
gereken birkaç saniye. Cilt 3'te yazdığın python tarayıcı da aynı işi yapar; ikisi de görevde işe yarar.
"""),
    Adim("nmap çıktısını okumak", """
Kali'de nmap ile aynı iş tek komuttur: `nmap -sV -p 20000-45000 <adres>`. Çıktı şöyle görünür (kurgusal örnek):

```
PORT      STATE  SERVICE  VERSION
22/tcp    open   ssh      OpenSSH 8.9p1 Ubuntu
80/tcp    open   http     nginx 1.18.0
21/tcp    open   ftp      vsftpd 2.3.4
3306/tcp  closed mysql
```

Sütunlar: **PORT** (numara/protokol), **STATE** (`open` açık, `closed` kapalı, `filtered` güvenlik duvarı
engelliyor), **SERVICE** (portun genelde ne için kullanıldığı), **VERSION** (`-sV`'nin bulduğu yazılım ve sürüm).
Pratikte çoğu pentester `nmap -sC -sV -oN tarama.txt <adres>` ile başlar: `-sC` varsayılan betikleri çalıştırır,
`-oN` çıktıyı dosyaya yazar. Bu görevde aynı bilgiyi elle çıkaracaksın.
""", calistir=False),
    Adim("Tarama türleri", """
nmap'in tarama türleri Cilt 2'deki el sıkışmaya dayanır:

- **-sS** (SYN taraması, yarı açık): el sıkışmayı yarıda bırakır (son ACK'yi göndermez); hızlı, çoğu uygulama
  tarafından loglanmaz. Ham paket gönderdiği için **root gerektirir**.
- **-sT** (TCP connect): tam bağlantı kurar; uygulama loglarına düşer, root gerekmez.
- **-sU** (UDP): yavaş, ama DNS ve SNMP gibi servisler için şart.
- **-O** işletim sistemi tahmini, **--script** NSE betikleri (belirli yanlış yapılandırmaları kontrol eder).

Hiçbir aktif tarama "görünmez" değildir; sadece daha az ya da daha çok gürültü yapar.
""", calistir=False),
    Adim("Sürüm bilgisi iki kenarlı bıçaktır", """
**Savunma tarafında** ders iki yönlüdür. Birincisi, banner'daki sürüm bilgisini gizlemek saldırganı yavaşlatır
(ama güvenlik sağlamaz). İkincisi ve asıl önemlisi, güncel olmayan yazılımları **yamalamaktır**: saldırgan
senin nmap çıktını da görebilir; tek fark, onun o sürüm için bir istismar araması, senin ise yamayı yüklemiş
olmandır. Bu yüzden müşteri bir **eşik listesi** verir: bunun altındaki her sürüm bir bulgudur. Görevlerde
`guncel_surumler.txt` ile böyle bir karşılaştırma yapacaksın.
""", calistir=False),
]

GOREVLER = [
    Gorev("<<adres>> adresinde, 20000-45000 aralığında **kaç TCP portu açık**? (Banner vermeyen portlar da dahil.)",
          Sayi("acik_sayi", sik_hatalar=_sayi_hata),
          ("Aralığın tamamını taramalısın; adımdaki pencere çok dardı.",
           "`nc -z -v -w1 <<adres>> 20000-45000 2>&1 | grep succeeded` (ya da Cilt 3'teki python tarayıcın, ya da "
           "Kali'de `nmap -p 20000-45000 <<adres>>`).",
           "Çıktıdaki `succeeded` satırlarının sayısı cevaptır; her satır bir açık port."),
          puan=25, baslik="Kaç port açık"),
    Gorev("Açık olan **bütün** portları yaz.",
          Kume("acik_portlar", tur="sayi", bicim="virgülle ayrılmış port numaraları"),
          ("Önceki görevin taramasının çıktısı.",
           "`succeeded` satırlarındaki port numaraları: satır `Connection to <adres> <port> port [tcp/*] succeeded!` biçiminde, port 4. sütunda.",
           "`nc -z -v -w1 <<adres>> 20000-45000 2>&1 | grep succeeded | awk '{print $4}'`"),
          puan=25, baslik="Açık portlar"),
    Gorev("Açık portlardan biri SSH konuşuyor. Banner'ında yazan **OpenSSH sürümü** nedir? "
          "(Örn. `8.9p1`; `OpenSSH_` önekini yazma.)",
          Metin("ssh", on_ekleri_at=("ssh-2.0-", "openssh_", "openssh "), sik_hatalar=_ssh_hata, bicim="sürüm numarası"),
          ("SSH servisleri bağlanınca `SSH-2.0-` ile başlayan bir satır gönderir.",
           "Açık portlara tek tek `nc -w2 <<adres>> <port>` ile bağlan; `SSH-2.0-` diyeni bul.",
           "Satırda `OpenSSH_` ifadesinden sonraki kısım sürümdür."),
          puan=25, baslik="SSH sürümü"),
    Gorev("`guncel_surumler.txt` müşterinin kabul ettiği **en düşük** sürümleri listeliyor. Açık servislerden biri "
          "bu eşiğin **altında** (eski). Bu servis hangi portta?",
          Sayi("eski_port", sik_hatalar=_eski_port_hata),
          ("Her açık portun banner'ını oku; yazılım adını ve sürümü eşik listesiyle karşılaştır.",
           "`220` ile başlayan banner'lar FTP ya da SMTP servisidir ve sürümü yazar. Eşik listesindeki sayıyla kıyasla.",
           "FTP ya da SMTP olan portlardan sürümü eşiğin altında kalanı seç."),
          puan=35, baslik="Eski servis"),
    Gorev("Bu eski servisin **sürüm numarası** nedir? (Yalnızca numara, örn. `1.2.3`.)",
          Metin("eski_surum", on_ekleri_at=("vsftpd ", "proftpd ", "exim "), sik_hatalar=_eski_surum_hata,
                bicim="sürüm numarası"),
          ("Önceki görevde bulduğun portun banner'ına tekrar bak.",
           "`nc -w2 <<adres>> <eski servisin portu>`",
           "Banner'da yazılım adından sonra sürüm numarası geliyor."),
          puan=20, baslik="Eski sürüm"),
    Gorev("Açık portlardan biri bağlanınca **hiçbir şey göndermiyor**; çünkü bir web sunucusu ve senin konuşmanı "
          "bekliyor. `Server:` yanıt başlığının tam değeri nedir?",
          Metin("http_server", sik_hatalar=_server_hata, bicim="Server başlığı değeri"),
          ("Susan port bir HTTP sunucusu: onunla HTTP ile konuşmalısın.",
           "`curl -I http://<<adres>>:<port>/` ile yanıt başlıklarını al; `Server:` satırına bak.",
           "Susan portu bul (nc ile boş dönen), sonra `curl -sI http://<<adres>>:<port>/ | grep -i server`."),
          puan=30, baslik="Susan port: web sunucusu"),
    Gorev("<<sunucu>> için, açık portların **hepsinde** hangi yazılım ve sürümün çalıştığını bulmak istiyorsun. "
          "Kali'de aşağıdakilerden hangi nmap komutu bunu 20000-45000 aralığı için yapar?",
          Secmeli([
              ("`nmap -sV -p 20000-45000 <adres>`",
               "Doğru. `-sV` servis ve sürümü bulur; `-p` ile aralığı belirttin."),
              ("`nmap -sn <adres>`",
               "`-sn` yalnızca makinenin canlı olup olmadığına bakar (host keşfi); port taramaz, sürüm bulmaz."),
              ("`nmap -F <adres>`",
               "`-F` yalnızca en yaygın 100 portu dener. Bu servisler 20000'in üstünde olduğu için kaçar."),
              ("`nmap -sU -p 20000-45000 <adres>`",
               "`-sU` UDP taraması yapar; bu servisler TCP üzerinde ve `-sV` de yok, sürüm öğrenemezsin."),
          ], dogru=0),
          ("Sürümü hangi seçenek bulur? Aralığı hangi seçenek verir?",
           "Host keşfi, hızlı tarama ve UDP taraması bu iş için uygun değil.",
           "Servis/sürüm için `-sV`; aralık için `-p`."),
          puan=20, baslik="Doğru nmap komutu"),
    Gorev("`nmap -sS` ile `nmap -sT` arasındaki fark nedir?",
          Secmeli([
              ("-sS el sıkışmayı yarıda bırakır, çoğunlukla loglanmaz, root ister; -sT tam bağlantı kurar, loglanır",
               "Doğru. -sS daha sessizdir ama ham paket gönderdiği için root gerekir; -sT her zaman çalışır ama iz bırakır."),
              ("-sT el sıkışmayı yarıda bırakır ve root ister; -sS tam bağlantı kurduğu için her uygulamada loglanır, iz bırakır",
               "Tersini söylüyorsun: yarıda bırakan ve root isteyen -sS'dir; tam bağlantı kuran ve loglanan -sT."),
              ("İkisi aynı işi yapar; -sS sadece UDP, -sT sadece TCP içindir",
               "İkisi de TCP taraması. UDP taraması için -sU kullanılır."),
              ("-sS yalnızca kapalı portları, -sT yalnızca açık portları raporlar",
               "İkisi de hem açık hem kapalı hem filtreli portları raporlar; fark bağlantının nasıl kurulduğunda."),
          ], dogru=0),
          ("Cilt 2'deki üçlü el sıkışmayı hatırla: SYN, SYN-ACK, ACK.",
           "Biri el sıkışmayı tamamlıyor, biri tamamlamıyor. Hangisi loglanır?",
           "Yarıda bırakan sessizdir ama ham paket için root gerekir."),
          puan=20, baslik="-sS ve -sT"),
    Gorev("nmap bir portu **filtered** olarak işaretledi. Bu ne anlama gelir?",
          Secmeli([
              ("Bir güvenlik duvarı cevabı engelliyor; port açık mı kapalı mı belli değil",
               "Doğru. Saldırgan için can sıkıcıdır: bilgi gizlenir ve tarama yavaşlar (zaman aşımını beklemek zorunda kalır)."),
              ("Port kapalı; hedef bağlantıyı açıkça reddetti ve cevap olarak bir hata paketi gönderdi",
               "Açıkça reddedilen port `closed` olarak görünür. `filtered`, cevabın hiç gelmemesi ya da engellenmesidir."),
              ("Port açık ama üzerinde çalışan yazılımın sürüm bilgisi banner'dan gizlenmiş durumda",
               "Sürüm gizleme `open` bir portta olur. `filtered` portun durumunu bilemediğin anlamına gelir."),
              ("Port açık ve kimlik doğrulama istiyor; bu yüzden nmap içeri giremedi ve durdu",
               "nmap kimlik doğrulamaya girişmez; `filtered`, ağ düzeyinde cevabın engellenmesidir."),
          ], dogru=0),
          ("Üç durum var: open, closed, filtered. Hangisi \"cevap yok\"?",
           "Cevabı kim engelleyebilir?",
           "Güvenlik duvarı."),
          puan=20, baslik="filtered ne demek"),
]

SEVIYE = Seviye(
    kimlik="c04b04",
    cilt=4,
    bolum=4,
    baslik="nmap: Keşfin Ana Aracı",
    brifing="""
**<<musteri>>**'nin sunucusu (<<sunucu>>) laboratuvarında **<<adres>>** adresinde çalışıyor. Hangi portlar açık,
ne çalışıyor, hangi sürüm eskimiş? Kali'de nmap varsa kullan; yoksa `nc` ve `curl` aynı bilgiyi verir. Kontrol,
araca değil bulduğun gerçeğe bakar.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Birkaç saniyelik bir taramayla bir sunucunun bütün yüzü çıktı: beş açık port, her birinin arkasındaki yazılım
ve sürüm, eşiğin altında kalan bir servis ve banner vermeyen bir web sunucusu. Bir saldırgan o eski sürümü bir
sonraki aşamanın giriş noktası olarak işaretlerdi. Savunma tarafında dersler: gereksiz servisi kapat, yazılımları
yama düzeyinde tut, yönetim servislerini yalnızca iç ağa aç, banner'ları gereksiz bilgi vermeyecek biçimde
ayarla ve tarama izlerini (kısa sürede çok sayıda porta bağlantı) IDS ile izle.
""",
    gercek_hayat="""
- **Yamasız sürüm, büyük ihlal:** 2017'deki Equifax ihlalinde, yaması daha önce yayımlanmış bir Apache Struts
  açığının kapatılmamış olması kök nedenlerden biriydi. Dışarıdan görünen sürüm bilgisiyle yama durumunu
  karşılaştırmak, bu tür açığı saldırgandan önce bulmanın yoludur. Önleme: yama yönetimi ve envanter.
  Tespit: dışarıdan düzenli `nmap -sV` taraması ve sonucu müşteri eşik listesiyle karşılaştırmak.
- **Port taraması bir iz bırakır:** Kısa sürede çok sayıda porta bağlantı denemesi, güvenlik duvarı ve IDS
  loglarında kolayca tanınan bir örüntüdür (tek kaynaktan, art arda artan port numaraları). Tespit: IDS'te port
  tarama kuralı ve tek kaynaktan gelen bağlantı reddi sayısına alarm. Önleme: gereksiz portları hiç açmamak.
- **Varsayılan yapılandırmalar:** 2016'daki Mirai botnet'i, internete açık Telnet ve varsayılan parolalı cihazları
  tarayarak büyüdü; tarama + servis tespiti saldırganın da ilk adımıdır. Önleme: kullanılmayan servisi kapat,
  varsayılan parolayı değiştir.
""",
    sure_hedef_dk=30,
)
