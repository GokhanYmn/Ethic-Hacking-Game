"""Cilt 4 · Bölüm 7 — Kapanış Görevi: Bir Hedefi Haritala.

Beceri: cildin bütün adımlarını tek bir hedefte birleştirmek: DNS ile alt alan adları (kelime listesi), bir alt alanın
çözüldüğü sunucuda port taraması ve banner okuma, web keşfi (robots.txt, gizli yol), sürüm eşiğiyle eski servisi
seçme, en umut verici üç giriş noktasını `bulgular.md`'ye yazma ve kısa bir keşif özeti.

Servisler (hepsi yerel): 127.0.0.1'de DNS sunucusu (alan transferi kapalı) ve 127.a.b.c adresinde dört-beş TCP servisi
(SSH, FTP, SMTP, IMAP ve bir web sitesi). `portal.<alan>` adı bu lab sunucusuna çözülür.

Vakalar: e-ticaret (Pazarix), banka (Ferah Bank), fintech (Paramix).
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, IP, Metin, Bayrak, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir, tcp_banner
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

ESIKLER = """# Kalkan Güvenlik — bu müşteride kabul edilen EN DÜŞÜK sürümler (altı "eski" sayılır)
openssh 8.4
vsftpd 3.0.3
proftpd 1.3.6
exim 4.94
apache 2.4.54
nginx 1.22
"""

VAKALAR = [
    {
        "kod": "pazarix", "server": "nginx/1.18.0", "sunucu": "pzx-portal", "test": ["test-odeme", "eski-magaza", "stok-ic"],
        "acik": ["magaza", "odeme", "kampanya", "destek"], "gizli": ["/kampanya-yonetim-eski/", "/odeme-panel-v1/"],
        "kelime": "alt_alan_listesi.txt",
        "brifing": """
Kapanış görevi. **Pazarix** büyük kampanya haftasından önce Kalkan'a tam bir dış keşif sipariş etti. Selin: "Şimdiye
kadar öğrendiklerinin hepsini bir hedefte birleştireceksin: DNS, port, web. Sonunda bir sayfalık keşif özetine ihtiyacım var."

Pazarix'in yetkili DNS sunucusunun kopyası laboratuvarında **127.0.0.1**, port **<<dns_port>>** üzerinde. `portal.<<alan>>`
adı, müşterinin portal sunucusuna (laboratuvarda yine yerel bir adres) çözülüyor.

Mert: "Bir sızma testçisi gibi sırayla ilerle: ne var, nerede, neyin arkasında ne çalışıyor, en zayıf üç nokta hangisi?"
""",
    },
    {
        "kod": "ferahbank", "server": "Apache/2.4.52 (Ubuntu)", "sunucu": "fb-portal02",
        "test": ["swift-test", "eski-sube-test", "kart-ic"], "acik": ["sube", "kurumsal", "mobil-api", "yatirim"],
        "gizli": ["/sube-yonetim-eski/", "/kart-panel-v1/"], "kelime": "kelime_havuzu.txt",
        "brifing": """
Kapanış görevi. **Ferah Bank**'ın bilgi güvenliği müdürü Kaan Bey yıllık sızma testinin keşif aşamasını bitirmek istiyor:
"İnternet şubemizin etrafını baştan sona haritalayın." Selin: "Cilt 4'ün bütün becerileri bu görevde."

Bankanın yetkili DNS sunucusunun kopyası **127.0.0.1**, port **<<dns_port>>** üzerinde. `portal.<<alan>>` adı, bankanın
portal sunucusuna (laboratuvarda yerel bir adres) çözülüyor.

Deniz: "Bankada her aktif adım bizim SOC'un radarında. Test saatini onlara bildirdik, ama yine de gürültüyü aklında tut."
""",
    },
    {
        "kod": "paramix", "server": "nginx/1.14.0", "sunucu": "pmx-portal", "test": ["sandbox-ic", "test-gw", "admin-eski"],
        "acik": ["api", "odeme", "panel", "gelistirici"], "gizli": ["/docs-v1/", "/panel-eski/"],
        "kelime": "tahmin_kelimeleri.txt",
        "brifing": """
Kapanış görevi. **Paramix** yeni ödeme API'sinin dış keşfini istiyor. CTO Ece Hanım: "Saldırgan bizi nasıl haritalar,
önce ben bileyim." Selin: "Cilt 4'ün finali: DNS, port, web ve bir keşif özeti."

Paramix'in yetkili DNS sunucusunun kopyası **127.0.0.1**, port **<<dns_port>>** üzerinde. `portal.<<alan>>` adı,
şirketin portal sunucusuna (laboratuvarda yerel bir adres) çözülüyor.

Mert: "Bir dahaki ciltte bulduklarını denemeye başlayacağız; o yüzden bugün her şeyi düzgün not et."
""",
    },
]

DECOY = ["ftp", "vpn", "dev", "admin", "shop", "intranet", "webmail", "staging", "cdn", "git", "jenkins", "owa", "remote",
         "beta", "backup", "db", "files", "login", "mobile", "secure", "crm", "wiki"]
SSH_SURUMLERI = ["8.4p1", "8.9p1", "9.2p1"]
ESKI_FTP = [("vsFTPd", "2.3.4"), ("ProFTPD", "1.3.3c")]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    adres = o.lab_adresi(rng)
    while True:
        ports = o.portlar(rng, 5)
        if all(b - a > 14 for a, b in zip(ports, ports[1:])):
            break
    rng.shuffle(ports)
    p_ssh, p_ftp, p_smtp, p_http, p_imap = ports
    dns_port = rng.choice([p for p in range(20000, 45001) if p not in ports])
    ssh_v = rng.choice(SSH_SURUMLERI)
    ftp_urun, ftp_surum = rng.choice(ESKI_FTP)
    test_ad = rng.choice(v["test"])
    acik = rng.sample(v["acik"], 2)
    gizli = rng.choice(v["gizli"])
    d = rng.sample(["/gizli-test/", "/tmp-yukleme/", "/eski-sunucu/", "/dev/", "/rapor-arsivi/"], 2)
    robots = [d[0], gizli, d[1]]
    rng.shuffle(robots)
    bayrak = u.bayrak(rng, rng.choice(["derin_iz", "sakli_bahce", "kayip_dosya", "arka_oda"]))
    kullanilan: set = set()

    def dis():
        ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    ana_ip, ns_ip, mail_ip = dis(), dis(), dis()
    ip_map = {"www": dis(), test_ad: dis(), **{a: dis() for a in acik}}
    bulunan = sorted(["www", "portal", "mail", test_ad] + acik)
    kelimeler = bulunan + rng.sample([k for k in DECOY if k not in bulunan], 16)
    rng.shuffle(kelimeler)
    banners = {
        p_ssh: o.banner_metni("ssh", "OpenSSH", ssh_v, v["sunucu"]),
        p_ftp: o.banner_metni("ftp", ftp_urun, ftp_surum, v["sunucu"]),
        p_smtp: o.banner_metni("smtp", "Exim", "4.96", v["sunucu"]),
        p_imap: o.banner_metni("imap", "Dovecot", "", v["sunucu"]),
    }
    return {
        "vaka": f"{m['ad']} — hedefi haritala ({alan})",
        "brifing": v["brifing"], "v": v, "m": m, "alan": alan, "adres": adres, "dns_port": dns_port,
        "ports": sorted(ports), "p": {"ssh": p_ssh, "ftp": p_ftp, "smtp": p_smtp, "http": p_http, "imap": p_imap},
        "bannerlar": banners, "test_ad": test_ad, "acik": acik, "gizli": gizli, "robots": robots, "bayrak": bayrak,
        "ana_ip": ana_ip, "ns_ip": ns_ip, "mail_ip": mail_ip, "ip_map": ip_map, "bulunan": bulunan,
        "kelimeler": kelimeler, "ftp_ad": f"{ftp_urun} {ftp_surum}",
        "metin": {
            "musteri": m["ad"], "alan": alan, "dns_port": dns_port, "kelime": v["kelime"],
            "test_ad": test_ad,
        },
        "cevaplar": {
            "bulunan": bulunan, "portal_ip": adres, "portlar": sorted(ports),
            "gizli": [gizli, gizli.rstrip("/"), gizli.strip("/")], "bayrak": bayrak,
            "eski": [f"{ftp_urun} {ftp_surum}".lower(), f"{ftp_urun.lower()} {ftp_surum}"],
        },
    }


def _bolgeler(s: dict) -> list:
    alan = s["alan"]
    b = ag.Bolge(alan, axfr=False)
    b.ekle("@", "NS", "ns1").ekle("@", "A", s["ana_ip"]).ekle("ns1", "A", s["ns_ip"])
    b.ekle("@", "MX", (10, "mail")).ekle("mail", "A", s["mail_ip"])
    b.ekle("www", "A", s["ip_map"]["www"])
    b.ekle("portal", "A", s["adres"])         # laboratuvardaki portal sunucusu
    for ad in s["acik"] + [s["test_ad"]]:
        b.ekle(ad, "A", s["ip_map"][ad])
    return [b]


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['m']['ad']} hedefi, bu görev boyunca laboratuvarda çalışıyor:\n"
          f"  DNS sunucusu: 127.0.0.1  port {s['dns_port']} (UDP+TCP)   alan: {s['alan']}\n"
          "  Portal sunucusunun adresini DNS söyleyecek (portal.<alan>); port aralığı 20000-45000 (TCP).\n"
          f"  {v['kelime']}   DNS için kelime listesi\n"
          "  guncel_surumler.txt   müşterinin kabul ettiği en düşük sürümler\n")
    u.yaz(lab / v["kelime"], "\n".join(s["kelimeler"]) + "\n")
    u.yaz(lab / "guncel_surumler.txt", ESIKLER)


def servis(s: dict, lab: Path, dur) -> None:
    sunucular = ag.dns_sunuculari("127.0.0.1", s["dns_port"], _bolgeler(s))
    for port, metin in s["bannerlar"].items():
        sunucular.append(tcp_banner(s["adres"], port, metin))
    v = s["v"]
    index = (f"<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>{s['m']['ad']} Portal</title></head>\n"
             f"<body><h1>{s['m']['ad']} Portal</h1><p>Hoş geldiniz.</p></body></html>\n")
    robots = "User-agent: *\n" + "".join(f"Disallow: {y}\n" for y in s["robots"])
    rotalar = {
        "/": (200, index),
        "/robots.txt": (200, robots, {"Content-Type": "text/plain"}),
        s["gizli"]: (200, f"<html><body><h1>Eski Yönetim</h1><p>Derleme: {s['bayrak']}</p></body></html>\n"),
    }
    sunucular.append(o.site_sunucusu(s["adres"], s["p"]["http"], v["server"], rotalar))
    calistir(sunucular, dur)


# ---------------------------------------------------------------- kontroller

def _bulgular_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = o.dosya_bul(b, "bulgular.md")
    if yol is None:
        return Sonuc(False, "`bulgular.md` bulunamadı. Bulunduğun klasörde oluştur: en umut verici üç giriş noktası, "
                     "her biri ayrı bir satırda.")
    satirlar = [x.strip() for x in yol.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    anahtarlar = [
        ("eski sürümlü servisin portu", rf"(?<!\d){s['p']['ftp']}(?!\d)"),
        ("robots.txt'te işaret edilen gerçek gizli yol", re.escape(s["gizli"].strip("/"))),
        ("unutulmuş test alt alan adı", re.escape(s["test_ad"])),
    ]
    eksik, kisa, kullanilan = [], [], set()
    for ad, desen in anahtarlar:
        idx = next((i for i, x in enumerate(satirlar) if i not in kullanilan and re.search(desen, x, re.I)), None)
        if idx is None:
            eksik.append(ad)
            continue
        kullanilan.add(idx)
        if len(satirlar[idx].split()) < 6:
            kisa.append(ad)
    if eksik:
        return Sonuc(False, "Şu giriş noktaları dosyada ayrı bir satırda yok: " + "; ".join(eksik)
                     + ". (Her biri için 'nerede' bilgisi: port, yol ya da ad.)", yakin=len(eksik) < 3)
    if kisa:
        return Sonuc(False, "Bu satırlar çok kısa, 'neden umut verici' cümlesi eksik: " + "; ".join(kisa)
                     + ". Her satıra en az bir gerekçe ekle (en az 6 kelime).", yakin=True)
    return Sonuc(True, "bulgular.md hazır: üç giriş noktası, nerede ve neden bilgisiyle. Cilt 6'da bu listeden başlayacaksın.")


def _kume_hata(g, beklenen, b):
    return None


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["ana_ip"]:
        return "Bu alan adının kendisinin (ana alan) adresi. Soru `portal` alt alan adını soruyor."
    if g == s["ip_map"]["www"]:
        return "Bu `www`'nin adresi. `portal.<alan>` adını sor."
    return None


def _eski_hata(g, beklenen, b):
    s = b.senaryo
    if re.fullmatch(r"[0-9a-z.]+", g) and g[0].isdigit():
        return "Sürüm numarasını buldun; yazılımın adını da ekle (örn. `ad 1.2.3`)."
    ad = s["ftp_ad"].split()[0].lower()
    if g == ad:
        return "Yazılımı buldun; sürüm numarasını da yaz."
    return None


# ---------------------------------------------------------------- test çözücüsü

def _tuple(sv: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", sv.split("p")[0]))


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    d = f"dig @127.0.0.1 -p {s['dns_port']}"
    a = s["alan"]
    o.sh(f"for k in $(cat {v['kelime']}); do r=$({d} +short $k.{a}); [ -n \"$r\" ] && echo $k; done > alt_alanlar.txt", lab)
    bulunan = o.sh("cat alt_alanlar.txt", lab)
    portal = o.sh(f"{d} +short portal.{a}", lab)
    acik = o.tara(portal, lab)
    esik = {}
    for satir in (lab / "guncel_surumler.txt").read_text(encoding="utf-8").splitlines():
        if satir and not satir.startswith("#"):
            ad, sv = satir.split()
            esik[ad] = _tuple(sv)
    http_p = None
    eski_ad = eski_port = None
    for p in acik:
        b = o.banner_oku(portal, p, lab)
        if not b:
            http_p = p
        m = re.search(r"(vsFTPd|ProFTPD|Exim) ([0-9][0-9a-z.]*)", b)
        if b.startswith("220") and m and _tuple(m.group(2)) < esik[m.group(1).lower()]:
            eski_ad, eski_port = f"{m.group(1)} {m.group(2)}", p
    t = f"http://{portal}:{http_p}"
    gizli = o.sh(f"for y in $(curl -s {t}/robots.txt | grep -i '^Disallow' | cut -d' ' -f2); do "
                 f"c=$(curl -s -o /dev/null -w '%{{http_code}}' {t}$y); [ \"$c\" = 200 ] && echo $y; done", lab)
    bayrak = o.sh(f"curl -s {t}{gizli} | grep -o 'FLAG{{[^}}]*}}'", lab)
    test_ad = o.sh("grep -E '^(test|eski|sandbox|admin|swift|kart|stok)' alt_alanlar.txt | head -1", lab)
    (lab / "bulgular.md").write_text(
        f"- Eski FTP servisi {portal}:{eski_port} ({eski_ad}): sürüm eşiğin altında ve açık metin protokol, "
        "sonraki adım bilinen zafiyetlerini araştırmak.\n"
        f"- robots.txt'te işaretlenen {gizli} yolu gerçekten cevap veriyor ve eski bir yönetim sayfası: "
        "neden önemli, sonraki adım içeriğini incelemek.\n"
        f"- Unutulmuş test alt alanı {test_ad}.{a}: genelde bakımsız ve zayıf korunur, "
        "sonraki adım hangi sunucuya çözüldüğünü ve ne çalıştırdığını belirlemek.\n", encoding="utf-8")
    ozet = ("Hedefin dış yüzü şu: DNS'te birkaç alt alan, portal sunucusunda dört açık servis ve bir web sitesi var; "
            "en zayıf noktalar eski sürümlü FTP servisi, robots.txt'in işaret ettiği eski yönetim yolu ve unutulmuş test alt alanı.")
    return {1: " ".join(bulunan.split()), 2: portal, 3: " ".join(map(str, acik)), 4: gizli, 5: bayrak, 6: eski_ad,
            7: "", 8: o.secmeli_cevap(SEVIYE, s, lab, 8), 9: ozet}


ADIMLAR = [
    Adim("Haritalama planı", """
Cilt 4'ün bütün parçaları bu görevde birleşiyor. Bir sızma testçisi bir hedefi şu sırayla haritalar:

1. **Pasif / DNS:** hedefin alan adı altında hangi alt alanlar var? (Sertifika kayıtları, kelime listesi.)
2. **Host keşfi:** hangi adresler canlı, hangi alt alan hangi sunucuya çözülüyor?
3. **Port tarama:** o sunucuda hangi portlar açık, her birinde ne ve hangi sürüm çalışıyor?
4. **Web keşfi:** bir web servisi varsa başlıklar, robots.txt, saklı yollar.
5. **Önceliklendirme:** bulduğun her şeyi `bulgular.md`'ye yaz ve en umut verici **üç** giriş noktasını işaretle.
6. **Rapor:** bir sayfalık keşif özeti.

Bu görevde hedef bir alan adı (<<alan>>) ve onun arkasındaki bir portal sunucusu. Aktif adımlarda (DNS tahmini, port
taraması, web istekleri) yalnızca laboratuvarın kendi sunucularına gidiyorsun; gerçek bir sisteme hiçbir şey gönderilmiyor.
""", calistir=False),
    Adim("1. Alt alan adları", """
DNS sunucusu alan transferini reddediyor (doğru yapılandırılmış), bu yüzden kelime listesiyle deneyeceksin. Listeye bir
göz at:
""", komut="head -n 5 <<kelime>>", sonra="""
Her kelimeyi `<kelime>.<<alan>>` olarak sorarsın; cevap veriyorsa ad vardır:

```
for k in $(cat <<kelime>>); do
  r=$(dig @127.0.0.1 -p <<dns_port>> +short $k.<<alan>>)
  [ -n "$r" ] && echo $k
done
```

Bulduğun adların her biri bir IP'ye çözülür. İçlerinden biri (`portal`) laboratuvardaki portal sunucusuna gider: bir sonraki
aşamanın hedefi o adres.
"""),
    Adim("2-3. Host ve portlar", """
Portal adının IP'sini bulduktan sonra o adreste 20000-45000 aralığını tara. Cilt 4'ün 4. bölümündeki iki yoldan biri:

```
nc -z -v -w1 <ADRES> 20000-45000 2>&1 | grep succeeded
nmap -sV -p 20000-45000 <ADRES>        # Kali'de nmap varsa
```

Her açık port için bir banner oku (`nc -w2 <ADRES> <PORT>`): hangi yazılım, hangi sürüm? Banner'ı olmayan bir port, web
sunucusudur: onunla HTTP ile konuşmak gerekir.
""", calistir=False),
    Adim("4. Web servisi", """
Web portunu bulduktan sonra: başlıklar (`curl -I`), `robots.txt` ve onun işaret ettiği yolların gerçekten cevap verip
vermediği (durum kodu 200). Gürültüsüz ilerle: robots.txt zaten kısa bir liste veriyor, yüzlerce istek göndermene gerek yok.

```
curl -I http://<ADRES>:<WEB_PORTU>/
curl -s http://<ADRES>:<WEB_PORTU>/robots.txt
curl -s -o /dev/null -w '%{http_code}' http://<ADRES>:<WEB_PORTU>/<YOL>
```
""", calistir=False),
    Adim("5. Eşik listesi ve önceliklendirme", """
Müşterinin kabul ettiği en düşük sürümler `guncel_surumler.txt` içinde. Banner'lardaki sürümleri bununla kıyasla:
""", komut="cat guncel_surumler.txt", sonra="""
Eşiğin altındaki servis bir bulgudur. Öncelik listesine üç tür giriş noktası aday: **eski sürümlü servis**, **unutulmuş
yönetim yolu ya da panel**, **bakımsız test alt alanı**. Her biri için bir satır yaz: *ne / nerede / neden umut verici /
sonraki adım*.
"""),
    Adim("6. Keşif özeti", """
Keşfin sonunda bir sayfalık özet yazarsın: hedefin saldırı yüzeyi nedir, en zayıf noktalar nerede? Gerçek bir sızma testi
raporunun "keşif bulguları" bölümü tam olarak böyle görünür. Cilt 6'da bir makineye sızarken bu biçimle başlayacaksın.
Unutma: yaptığın her aktif adım hedefin loglarına düştü; test saatini müşteriye bildirmiş olman gerekir. Ve en önemlisi:
bulduğun şeylerle ne yaptığın, bulmaktan daha önemlidir: bir sonraki aşama yalnızca yazılı yetkin olan sistemlerde
başlar.
""", calistir=False),
]

GOREVLER = [
    Gorev("`<<kelime>>` listesindeki her kelimeyi `<kelime>.<<alan>>` olarak DNS'e sor. Cevap alan alt alan adlarının "
          "**hepsini** (yalnızca ilk etiket: `www` gibi) yaz.",
          Kume("bulunan", sik_hatalar=_kume_hata, bicim="boşlukla ayrılmış alt alan adları"),
          ("Cilt 4'ün 2. bölümündeki döngüyü kullan.",
           "`dig @127.0.0.1 -p <<dns_port>> +short <kelime>.<<alan>>`: cevap boş değilse ad vardır.",
           "`for k in $(cat <<kelime>>); do r=$(dig @127.0.0.1 -p <<dns_port>> +short $k.<<alan>>); "
           "[ -n \"$r\" ] && echo $k; done`"),
          puan=30, baslik="Alt alan adları"),
    Gorev("`portal.<<alan>>` hangi IP adresine çözülüyor? (Bu, bir sonraki aşamanın hedefi.)",
          IP("portal_ip", sik_hatalar=_ip_hata),
          ("`portal` alt alan adının A kaydını sor.",
           "`dig @127.0.0.1 -p <<dns_port>> +short portal.<<alan>>`",
           "Çıktıdaki tek adres cevaptır."),
          puan=20, baslik="Portal sunucusu"),
    Gorev("Portal sunucusunda 20000-45000 aralığında **hangi TCP portları açık**? (Hepsini yaz.)",
          Kume("portlar", tur="sayi", bicim="virgülle ayrılmış port numaraları"),
          ("Bir önceki görevde bulduğun adreste aralığı tara.",
           "`nc -z -v -w1 <portal IP'si> 20000-45000 2>&1 | grep succeeded` (ya da Kali'de `nmap -p 20000-45000 <IP>`).",
           "`succeeded` satırlarındaki 4. sütun port numarasıdır."),
          puan=30, baslik="Açık portlar"),
    Gorev("Portal sunucusunun web servisinin `robots.txt` dosyası bazı yolları dizinlememeyi istiyor. Bunlardan "
          "**gerçekten cevap veren** (200) yol hangisi? (Örn. `/klasor/`)",
          Metin("gizli", bicim="yol"),
          ("Önce hangi portun web sunucusu olduğunu bul: bağlanınca susan port.",
           "`curl -s http://<IP>:<web portu>/robots.txt` ile listeyi al; her yolun durum koduna bak.",
           "200 veren tek bir yol var; diğerleri 404."),
          puan=30, baslik="Gizli yol"),
    Gorev("Bu gizli yolun sayfasında, yayından önce unutulmuş bir derleme bilgisi var: bayrağı bul.",
          Bayrak("bayrak"),
          ("Önceki görevdeki yolu `curl` ile iste.",
           "`curl -s http://<IP>:<web portu><yol>`",
           "Sayfanın gövdesindeki `FLAG{...}` ifadesi."),
          puan=20, baslik="Unutulan derleme"),
    Gorev("Portal sunucusunda açık servislerden biri `guncel_surumler.txt` eşiğinin **altında**. Yazılımın adını ve "
          "sürümünü yaz (örn. `ad 1.2.3`).",
          Metin("eski", sik_hatalar=_eski_hata, bicim="ad ve sürüm"),
          ("Her açık portun banner'ını oku ve eşik listesiyle kıyasla; `220` ile başlayan banner'lar sürüm verir.",
           "`nc -w2 <IP> <port>` ile FTP ve SMTP portlarına bak; yazılım adı ve sürümü banner'da.",
           "Eşik listesindeki sayıyla banner'daki sürümü karşılaştır; altında kalanın adını ve sürümünü yaz."),
          puan=30, baslik="Eski servis"),
    Gorev("Keşfin en umut verici **üç giriş noktasını** `bulgular.md` dosyasına yaz, her biri ayrı bir satırda: "
          "(1) eski sürümlü servisin portu, (2) robots.txt'te işaret edilen gerçek gizli yol, (3) DNS'te bulduğun "
          "unutulmuş **test** alt alan adı (`test-`, `eski-`... ile başlayan). Her satıra kısa bir gerekçe ekle "
          "(ne / nerede / neden umut verici). Dosyayı bulunduğun klasörde oluştur; sonra `cevap <no>` yaz.",
          Durum(_bulgular_denetle,
                "bulgular.md: üç satır; port numarası, gizli yol ve test alt alan adı ayrı satırlarda, "
                "her satırda en az 6 kelimelik gerekçe"),
          ("Önceki görevlerin cevapları üç giriş noktasını zaten veriyor: bir port, bir yol, bir alt alan adı.",
           "Her satır `- <nerede>: <ne>, <neden önemli>, sonraki adım ...` biçiminde olabilir. En az 6 kelime olsun.",
           "`echo \"- <IP>:<port> eski FTP servisi, sürüm eşiğin altında, sonraki adım zafiyet araştırması\" >> bulgular.md` "
           "gibi üç satırı ekle."),
          puan=40, baslik="Üç giriş noktası"),
    Gorev("Bu haritalama çalışmasındaki adımları pasif/aktif ayrımıyla değerlendir: hangisi doğru?",
          Secmeli([
              ("DNS tahminleri, port taraması ve web istekleri iz bırakır; aktiftir ve zamanı müşteriye bildirilmelidir",
               "Doğru. Hedefe giden her paket aktif keşiftir; müşteriye saat bildirmek hem hukuki hem pratik bir gerekliliktir."),
              ("Hepsi pasiftir, çünkü yalnızca bilgi okudun ve hiçbir şeyi değiştirmedin, bu yüzden bildirim gerekmez",
               "Pasif/aktif ayrımı değiştirip değiştirmediğine değil, hedefe paket gönderip göndermediğine bakar."),
              ("Yalnızca port taraması aktiftir; DNS ve web istekleri normal trafik sayıldığı için hiç iz bırakmaz, loglanmaz",
               "DNS sorguları ve web istekleri de sunucu loglarına düşer; yüzlerce 404 ya da NXDOMAIN açıkça görülür."),
              ("Yalnızca web istekleri aktiftir; DNS ve port taraması ağ düzeyinde olduğu için görünmezdir",
               "Port taraması ve DNS sorguları da hedefin güvenlik duvarında ve sunucu loglarında görülür."),
          ], dogru=0),
          ("Hedefe giden her paket için aynı soruyu sor: hedef bunu görüyor mu?",
           "DNS, port, web: üçü de hedefin sunucusuna ulaşıyor.",
           "Aktif ve loglanabilir."),
          puan=20, baslik="Aktif mi pasif mi"),
    Gorev("Keşif özetinin ilk paragrafını kendi cümlelerinle yaz: hedefin saldırı yüzeyi neymiş ve en zayıf üç nokta "
          "nerede görünüyor?",
          Serbest("Hedefin dış yüzü: DNS'te <<alan>> altında birkaç alt alan adı (www, portal, mail, ayrıca unutulmuş bir test "
                  "alt alanı), portal sunucusunda birkaç açık servis ve bir web sitesi. En zayıf noktalar: (1) eşiğin altında "
                  "sürümle çalışan eski servis, (2) robots.txt'in işaret ettiği ve hâlâ yayında olan eski yönetim yolu, "
                  "(3) bakımsız olması muhtemel test alt alan adı. Sonraki adım: bu üç noktayı yetkili kapsamda doğrulamak.",
                  min_kelime=20),
          ("Dört parça: saldırı yüzeyi, en zayıf üç nokta, sonraki adım.",
           "Üç giriş noktasını bulgular.md'den al.",
           "Kısa, net, rakamlı yaz: hangi servis, hangi yol, hangi alt alan."),
          puan=30, baslik="Keşif özeti"),
]

SEVIYE = Seviye(
    kimlik="c04b07",
    cilt=4,
    bolum=7,
    baslik="Kapanış Görevi: Bir Hedefi Haritala",
    brifing="""
**<<musteri>>**'nin dış keşfi: DNS sunucusu 127.0.0.1:<<dns_port>> üzerinde, `portal.<<alan>>` laboratuvardaki portal
sunucusuna çözülüyor. Alt alanları bul, portalın portlarını ve sürümlerini çıkar, webine bak, en umut verici üç noktayı yaz.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Cilt 4'ün bütün becerilerini tek bir hedefte kullandın: kelime listesiyle alt alanlar, DNS'ten sunucunun adresi, port
taraması ve banner'lardan sürüm, web'de robots.txt ve unutulmuş yol, eşik listesiyle eski servis ve üç giriş noktası. Bir
saldırgan aynı sırayı izler; fark, onun amacının girmek, senin amacının raporlamak olması. Savunma tarafında bu haritayı
müşteri de çıkarmalıdır: unutulmuş alt alanları ve robots.txt'in işaret ettiği yolları kapat, eski sürümleri yamala,
banner'ları sadeleştir ve loglarda bu üç adımın izini (NXDOMAIN seli, port tarama, 404 yağmuru) izle. Bu keşif özetini
sakla: Cilt 6'da bir makineye sızarken bu biçimle başlayacaksın.
""",
    gercek_hayat="""
- **Keşif ihlalin ilk adımıdır:** Gerçek saldırılar çoğu zaman alt alan adı keşfi, port taraması ve sürüm tespiti ile
  başlar. Equifax 2017 ihlali, yaması çıkmış bir Apache Struts sürümünün internete açık bir sistemde durmasıyla ilgiliydi;
  bu tür sistemler keşifle bulunur. Önleme: dışarıdan görünen varlıkların envanteri ve yama yönetimi. Tespit: kendi
  adına düzenli dış keşif yapmak ve sonuçları envanterle karşılaştırmak.
- **Unutulmuş alt alan ve eski yönetim yolları:** Kullanılmayan test alt alanları ve robots.txt'te "dizinleme" diye
  işaretlenmiş eski paneller, sızma testlerinde ve bug bounty raporlarında sık çıkar. Önleme: yayından kalkan her
  sistemin DNS kaydını ve sayfasını sil. Tespit: DNS ve web loglarında kısa sürede çok sayıda NXDOMAIN ya da 404.
- **Keşif de yetki ister:** Aktif keşif (port taraması, dizin denemesi) izinsiz yapılırsa suçtur (TCK 243). Profesyonel
  testlerde tarama saati ve kaynak IP müşteriye önceden bildirilir; böylece SOC gerçek saldırıyla test trafiğini ayırabilir.
""",
    sure_hedef_dk=45,
)
