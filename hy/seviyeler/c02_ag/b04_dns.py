"""Cilt 2 · Bölüm 4 — DNS: İnternetin Telefon Rehberi.

Beceri: `dig` ile yetkili bir DNS sunucusunu sorgulamak (A, AAAA, MX, TXT, NS, CNAME), `+short`,
ters DNS (`-x`, PTR), `status` alanını okumak (NOERROR / NXDOMAIN), yanlış yapılandırılmış bir
sunucudan alan transferi (AXFR) ile bütün bölgeyi dökmek.

Servis: müşterinin yetkili DNS sunucusunun kopyası 127.0.0.1'de rastgele bir portta (UDP+TCP)
çalışır. Bölgeler `hy.ortak.ag.Bolge` ile kurulur; bir TXT kaydında bayrak, bir alt alan adında
iç ağ IP'si sızıntısı vardır.

Vakalar: e-ticaret (Pazarix), banka (Ferah Bank), belediye (Yeşiltepe), hastane (Medora).
"""
from __future__ import annotations

import ipaddress
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Bayrak, Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "pazarix",
        "mx": ["mx1", "mx2", "posta", "eposta"],
        "acik": ["odeme", "kampanya", "api", "magaza", "blog", "destek"],
        "ic": ["test-odeme", "stok-ic", "eski-admin", "siparis-db"],
        "yok": ["vpn", "intranet", "sso", "webmail", "jenkins", "gitlab"],
        "not": ["gelistirici-notu", "_eski-kayit", "dev-not"],
        "posta_saglayici": "postakutusu.lab",
        "brifing": """
**Pazarix** büyük kampanya haftasına hazırlanıyor ve Kalkan'dan bir dış keşif istedi: "Bir
saldırgan bizim hakkımızda internetten ne öğrenebilir?" Selin işi sana verdi. Pazarix'in
yetkili DNS sunucusunun birebir kopyası laboratuvarında **127.0.0.1**, port **<<port>>**
üzerinde çalışıyor.

Selin: "DNS keşfi hedefe tek bir saldırı paketi göndermeden yapılır ama çok şey anlatır:
sunucular, e-posta altyapısı, unutulmuş alt alan adları. Her kayıt türünü tek tek sor."

Mert: "Bir de alan transferini dene. Yanlış ayarlanmışsa bütün rehberi tek seferde verir."
""",
    },
    {
        "kod": "ferahbank",
        "mx": ["mx1", "mx2", "mail", "posta"],
        "acik": ["sube", "kurumsal", "mobil-api", "kampanya", "yatirim", "kariyer"],
        "ic": ["eski-sube-test", "swift-gw-ic", "core-db", "hsm-yonetim"],
        "yok": ["vpn", "citrix", "owa", "intranet", "sso", "remote"],
        "not": ["_dogrulama-notu", "gecici-kayit", "it-not"],
        "posta_saglayici": "guvenliposta.lab",
        "brifing": """
**Ferah Bank**'ta bilgi güvenliği müdürü Kaan Bey, yıllık sızma testinin ilk adımı olarak
pasif keşif istiyor: "İnternet şubemizi kimin nasıl gördüğünü bilmek istiyorum." Bankanın
yetkili DNS sunucusunun kopyası laboratuvarında **127.0.0.1**, port **<<port>>** üzerinde.

Deniz: "Bankalarda iç sistemlerin adları genel DNS'e sızmamalı. Sızmışsa, saldırgana bir
harita vermişiz demektir."

Selin: "Her kayıt türünü sor, ne gördüğünü not et. Alan transferini de unutma."
""",
    },
    {
        "kod": "yesiltepe",
        "mx": ["posta", "mx", "eposta", "mail"],
        "acik": ["ebelediye", "ebys", "imar", "duyuru", "kent-rehberi", "ihale"],
        "ic": ["test-ebys", "emlak-db", "eski-portal", "scada-izleme"],
        "yok": ["vpn", "webmail", "intranet", "personel", "sso", "otomasyon"],
        "not": ["bilgi-islem-notu", "_gecici", "eski-kayit"],
        "posta_saglayici": "kamuposta.lab",
        "brifing": """
**Yeşiltepe Belediyesi** yeni e-belediye portalını açmadan önce Kalkan'dan dış keşif istedi.
Nurcan Hanım: "Yıllar içinde kimin hangi alt alan adını açtığını bilmiyoruz." Belediyenin
yetkili DNS sunucusunun kopyası laboratuvarında **127.0.0.1**, port **<<port>>** üzerinde.

Selin: "Kamu kurumlarında unutulmuş test sunucuları çok sık çıkar. DNS bize hepsinin adını
söyleyebilir."

Mert: "Ve bazen IP adreslerini de. Hem de iç ağdakileri."
""",
    },
    {
        "kod": "medora",
        "mx": ["mx1", "mx2", "posta", "mail"],
        "acik": ["randevu", "portal", "lab-sonuc", "kariyer", "e-recete", "blog"],
        "ic": ["pacs-test", "his-db", "eski-randevu", "lab-cihaz-gw"],
        "yok": ["vpn", "webmail", "intranet", "citrix", "sso", "remote"],
        "not": ["kurulum-notu", "_tedarikci-not", "gecici-test"],
        "posta_saglayici": "saglikposta.lab",
        "brifing": """
**Medora Sağlık** yeni hasta portalını duyurmadan önce bir dış keşif istedi: "Bir saldırgan
bizi araştırsa ilk neyi görür?" Hastanenin yetkili DNS sunucusunun kopyası laboratuvarında
**127.0.0.1**, port **<<port>>** üzerinde çalışıyor.

Deniz: "Hastaneler tedarikçilerle dolu; her tedarikçi bir alt alan adı ister, kurulum biter,
kayıt unutulur."

Selin: "Her kayıt türünü sor. Neyin internete açık, neyin içeride olması gerektiğini ayır."
""",
    },
]

CDNLER = ["hizlicdn.lab", "bulutkenar.lab", "cdnistan.lab"]


def _ipv6(rng) -> str:
    return str(ipaddress.IPv6Address(f"2001:db8:{rng.randint(1, 0xffff):x}:{rng.randint(0, 0xff):x}::{rng.randint(1, 0xfff):x}"))


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    port = rng.randint(20000, 45000)
    kullanilan: set = set()

    def dis():
        return u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]

    def kaydet(ip):
        kullanilan.add(ip)
        return ip

    ana_ip = kaydet(dis())
    ns = [(f"ns{i}", kaydet(dis())) for i in (1, 2)]
    mx_adlar = rng.sample(v["mx"], 2)
    mx_on = sorted(rng.sample([5, 10, 20, 30, 40, 50], 2))
    mx = [(mx_on[0], mx_adlar[0], kaydet(dis())), (mx_on[1], mx_adlar[1], kaydet(dis()))]
    acik = rng.sample(v["acik"], 4)
    acik_ip = {a: kaydet(dis()) for a in acik}
    ic_ad = rng.choice(v["ic"])
    ic_ip = u.ic_ip(rng, rng.choice(["10.20.30", "10.0.12", "172.16.8", "192.168.40", "10.10.5"]))
    not_ad = rng.choice(v["not"])
    bayrak = u.bayrak(rng, rng.choice(["sessiz_iz", "eski_yol", "sakli_bahce", "unutulan_not"]))
    cdn = rng.choice(CDNLER)
    cdn_ad = f"{v['kod']}-{rng.randint(10, 99)}.{cdn}"
    cdn_ip = kaydet(dis())
    ipv6 = _ipv6(rng)
    yedek_ip = kaydet(dis())
    yedek_ad = f"{rng.choice(['yedekleme', 'yedek', 'backup', 'arsiv'])}-0{rng.randint(1, 4)}.{alan}"
    yoklar = rng.sample(v["yok"], 2)
    var_olan = rng.choice(acik)
    adaylar = [f"{x}.{alan}" for x in yoklar + [var_olan]]
    rng.shuffle(adaylar)
    dogrulama = "".join(rng.choice("0123456789abcdef") for _ in range(24))
    ic_tam = f"{ic_ad}.{alan}"
    mx_tam = f"{mx[0][1]}.{alan}"
    return {
        "vaka": f"{m['ad']} — DNS keşfi ({alan})",
        "brifing": v["brifing"],
        "v": v, "alan": alan, "port": port, "ana_ip": ana_ip, "ns": ns, "mx": mx, "acik_ip": acik_ip,
        "ic_ad": ic_ad, "ic_ip": ic_ip, "not_ad": not_ad, "bayrak": bayrak, "cdn": cdn, "cdn_ad": cdn_ad,
        "cdn_ip": cdn_ip, "ipv6": ipv6, "yedek_ip": yedek_ip, "yedek_ad": yedek_ad, "dogrulama": dogrulama,
        "adaylar": adaylar, "gun": u.gun(rng),
        "metin": {
            "musteri": m["ad"], "alan": alan, "port": port, "not_ad": not_ad, "yedek_ip": yedek_ip,
            "aday1": adaylar[0], "aday2": adaylar[1], "aday3": adaylar[2], "mx2_ip": mx[1][2],
            "cdn": cdn,
        },
        "cevaplar": {
            "ana_ip": ana_ip,
            "mx": [mx_tam, mx[0][1]],
            "cname": [cdn_ad],
            "bayrak": bayrak,
            "ipv6": [ipv6, ipaddress.IPv6Address(ipv6).exploded],
            "ptr": [yedek_ad],
            "var_olan": [f"{var_olan}.{alan}", var_olan],
            "ic_ad": [ic_tam, ic_ad],
        },
    }


def _bolgeler(s: dict) -> list:
    v = s["v"]
    b = ag.Bolge(s["alan"])
    for ad, ip in s["ns"]:
        b.ekle("@", "NS", ad)
    b.ekle("@", "A", s["ana_ip"])
    b.ekle("@", "AAAA", s["ipv6"])
    # MX kayıtlarını önceliği büyük olan önce gelecek şekilde ekle: dig sıralamaz, oyuncu okumalı
    for on, ad, _ip in reversed(s["mx"]):
        b.ekle("@", "MX", (on, ad))
    b.ekle("@", "TXT", f"v=spf1 mx include:_spf.{v['posta_saglayici']} ~all")
    b.ekle("@", "TXT", f"{v['posta_saglayici'].split('.')[0]}-dogrulama={s['dogrulama']}")
    for ad, ip in s["ns"]:
        b.ekle(ad, "A", ip)
    for _on, ad, ip in s["mx"]:
        b.ekle(ad, "A", ip)
    b.ekle("www", "CNAME", s["cdn_ad"] + ".")
    for ad, ip in s["acik_ip"].items():
        b.ekle(ad, "A", ip)
    b.ekle(s["ic_ad"], "A", s["ic_ip"])
    b.ekle(s["not_ad"], "TXT", f"Gecici test kaydi - yayina cikmadan silinecek. Anahtar: {s['bayrak']}")
    b.ekle("_dmarc", "TXT", f"v=DMARC1; p=none; rua=mailto:dmarc@{s['alan']}")
    cdn = ag.Bolge(s["cdn"], axfr=False)
    cdn.ekle("@", "NS", "ns1").ekle("ns1", "A", s["ns"][0][1])
    cdn.ekle(s["cdn_ad"] + ".", "A", s["cdn_ip"])
    ters = ag.ters_bolge({s["ana_ip"]: s["alan"], s["mx"][0][2]: f"{s['mx'][0][1]}.{s['alan']}",
                          s["mx"][1][2]: f"{s['mx'][1][1]}.{s['alan']}", s["yedek_ip"]: s["yedek_ad"]})
    return [b, cdn, ters]


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "OKUBENI.txt",
          f"{s['metin']['musteri']} yetkili DNS sunucusunun kopyası bu görev boyunca çalışıyor:\n"
          f"  adres: 127.0.0.1   port: {s['port']}   (UDP ve TCP)\n\n"
          "dig'e hangi sunucuya soracağını @ ile, portu -p ile söylersin:\n"
          f"  dig @127.0.0.1 -p {s['port']} {s['alan']}\n")
    gun = s["gun"]
    satirlar = [
        f"{gun:%Y-%m-%d} 02:14:07 ACCEPT TCP 10.0.5.20:44122 -> {s['ana_ip']}:443",
        f"{gun:%Y-%m-%d} 02:14:09 ACCEPT TCP 10.0.5.31:51870 -> {s['mx'][0][2]}:25",
        f"{gun:%Y-%m-%d} 02:31:55 ACCEPT TCP {s['yedek_ip']}:58122 -> 10.0.5.10:873   # rsync, gece",
        f"{gun:%Y-%m-%d} 02:31:56 ACCEPT TCP {s['yedek_ip']}:58124 -> 10.0.5.10:873",
        f"{gun:%Y-%m-%d} 02:47:12 DROP   TCP 198.51.100.77:40001 -> {s['ana_ip']}:3389",
    ]
    u.yaz(lab / "guvenlik_duvari.log", "\n".join(satirlar) + "\n")


def servis(s: dict, lab: Path, dur) -> None:
    calistir(ag.dns_sunuculari("127.0.0.1", s["port"], _bolgeler(s)), dur)


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: kitabın dig komutlarıyla çözer."""
    d = f"dig @127.0.0.1 -p {s['port']}"
    a = s["alan"]
    ana = _sh(f"{d} {a} +short", lab)
    mx = _sh(f"{d} {a} MX +short | sort -n | head -1 | awk '{{print $2}}'", lab)
    cname = _sh(f"{d} www.{a} CNAME +short", lab)
    bayrak = _sh(f"{d} {s['not_ad']}.{a} TXT +short | grep -o 'FLAG{{[^}}]*}}'", lab)
    ipv6 = _sh(f"{d} {a} AAAA +short", lab)
    yedek = _sh("awk '/rsync/ {print $5}' guvenlik_duvari.log | cut -d: -f1", lab)
    ptr = _sh(f"{d} -x {yedek} +short", lab)
    var = _sh(f"for x in {' '.join(s['adaylar'])}; do echo \"$x $({d} $x | grep -o 'status: [A-Z]*')\"; done "
              "| grep NOERROR | awk '{print $1}'", lab)
    ic = _sh(f"{d} {a} AXFR | awk '$4==\"A\" {{print $1, $5}}' "
             "| grep -E ' (10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)' | awk '{print $1}'", lab)
    return {1: ana, 2: mx, 3: cname, 4: bayrak, 5: ipv6, 6: ptr, 7: var, 8: ic, 9: _secmeli(s, lab, 9)}


# ---------------------------------------------------------------- sık hatalar

def _ana_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["cdn_ip"]:
        return "Bu `www`'nin (CNAME üzerinden) vardığı adres. Soru alan adının kendisinin A kaydını soruyor."
    if g in [ip for _a, ip in s["ns"]]:
        return f"Bu bir isim sunucusunun (ns) adresi. `dig ... {s['alan']}` ile alan adının kendi A kaydını sor."
    return None


def _mx_hata(g, beklenen, b):
    s = b.senaryo
    ikinci = s["mx"][1][1]
    if g.rstrip(".") in (ikinci, f"{ikinci}.{s['alan']}"):
        return "MX'te KÜÇÜK sayı önceliklidir. Bu sunucunun önceliği daha büyük; yedek olarak bekliyor."
    return None


def _cname_hata(g, beklenen, b):
    if g == b.senaryo["cdn_ip"]:
        return "Bu, takma adın sonunda varılan IP. Soru `www`'nin hangi ADA işaret ettiğini soruyor (CNAME değeri)."
    return None


def _ptr_hata(g, beklenen, b):
    if "in-addr.arpa" in g:
        return "Bu, sorduğun sorunun kendisi (ters çevrilmiş IP). Cevap bölümündeki PTR değerini yaz."
    return None


def _var_hata(g, beklenen, b):
    s = b.senaryo
    for x in s["adaylar"]:
        kisa = x.split(".")[0]
        if g.rstrip(".") in (x, kisa) and x not in beklenen:
            return "Bu ad için sunucu `status: NXDOMAIN` diyor: böyle bir ad yok. Diğerlerini de dene."
    return None


def _ic_hata(g, beklenen, b):
    s = b.senaryo
    for ad in s["acik_ip"]:
        if g.rstrip(".") in (ad, f"{ad}.{s['alan']}"):
            return "Bu adın IP'si bir TEST-NET (internet) adresi. Özel bloklara (10/8, 172.16/12, 192.168/16) çözülen adı ara."
    return None


ADIMLAR = [
    Adim("DNS nasıl çalışır?", """
İnsanlar `ornek.com` hatırlar, makineler IP adresi kullanır. İkisini birbirine çeviren sistem
**DNS**'tir (Domain Name System). Bir adı yazdığında makinen önce kendi önbelleğine bakar, yoksa
bir **çözümleyiciye** (genelde router ya da genel bir DNS servisi) sorar; o da kök
sunuculardan başlayıp `.com` sunucularına, oradan alan adının **yetkili** (authoritative)
sunucusuna ulaşır ve cevabı getirir. Hepsi milisaniyeler sürer, sonuç bir süre (TTL)
önbellekte tutulur.

Bu görevde aracıları atlayıp doğrudan <<musteri>>'nin yetkili sunucusuna soracağız. Sunucunun
kopyası 127.0.0.1, port <<port>> üzerinde.
"""),
    Adim("Kayıt türleri", """
Bir alan adının tek bir kaydı yoktur; her iş için ayrı bir tür vardır:

- **A**: IPv4 adresi → hedefin asıl sunucusu
- **AAAA**: IPv6 adresi → çoğu zaman gözden kaçan ikinci hedef
- **MX**: e-posta sunucusu (öncelik sayısıyla) → e-posta altyapısı
- **NS**: yetkili isim sunucuları → alan adını kim yönetiyor
- **TXT**: serbest metin (SPF, doğrulama kodları) → kullanılan servisleri ele verir
- **CNAME**: başka bir ada takma ad → arkadaki altyapıyı (CDN, bulut) açığa çıkarır
- **PTR**: ters kayıt, IP'den ada → "bu IP kimin?"
"""),
    Adim("İlk sorgu: dig", """
`dig` en ayrıntılı DNS aracıdır. `@127.0.0.1` hangi sunucuya sorulacağını, `-p` portu söyler.
Tür yazmazsan A kaydı sorulur:
""", komut="dig @127.0.0.1 -p <<port>> <<alan>>", sonra="""
Okuma kılavuzu:

- `status: NOERROR` sorgu başarılı demek. Ad yoksa `NXDOMAIN` görürsün.
- `flags: ... aa ...`: **authoritative answer**, cevap doğrudan yetkili sunucudan geliyor.
- `QUESTION SECTION` ne sorduğunu, `ANSWER SECTION` cevabı gösterir: ad, TTL (saniye), sınıf
  (IN), tür ve değer.
"""),
    Adim("+short ve kayıt türü seçmek", """
Belirli bir türü istemek için türü sona eklersin (`MX`, `TXT`, `NS`, `AAAA`). `+short`
gürültüyü atar, sadece cevabı basar. Alan adını kimin yönettiğine bakalım:
""", komut="dig @127.0.0.1 -p <<port>> <<alan>> NS +short", sonra="""
İsim sunucuları alanı kimin yönettiğini söyler: kendi sunucuları mı, bir barındırma firması
mı? Aynı kalıpla `MX`, `AAAA`, `CNAME` sorabilirsin.
"""),
    Adim("TXT kayıtları: servis listesi", """
TXT kayıtları serbest metindir ama pratikte en çok iki şey için kullanılır: e-postayı kimin
göndermeye yetkili olduğunu söyleyen **SPF** satırı ve "bu alan adı bizim" diye üçüncü taraf
servislere verilen **doğrulama kodları**.
""", komut="dig @127.0.0.1 -p <<port>> <<alan>> TXT +short", sonra="""
`v=spf1 ... include:_spf.X` satırı e-postanın X üzerinden de gönderildiğini söyler; doğrulama
satırları hangi bulut servislerinin kullanıldığını ele verir.

**Hacker gözüyle:** Bu bilgi oltalama (phishing) senaryosu kurarken altın değerindedir:
hedefin hangi e-posta sağlayıcısını kullandığını bilen saldırgan, sahte giriş sayfasını da
ona benzetir. Bütün bunlar hedefe tek bir saldırı paketi göndermeden öğrenilir: **pasif keşif**.
"""),
    Adim("Ters DNS: bu IP kimin?", """
Bir IP adresinin hangi ada ait olduğunu da sorabilirsin. Bunun için IP ters çevrilip sonuna
`in-addr.arpa` eklenir ve **PTR** kaydı sorulur; `dig -x` bunu senin yerine yapar. Örnek
olarak <<musteri>>'nin ikincil e-posta sunucusunun IP'sini soralım:
""", komut="dig @127.0.0.1 -p <<port>> -x <<mx2_ip>> +short", sonra="""
Ters DNS, bir IP aralığını tararken ya da bir güvenlik duvarı logunda tanımadığın bir adres
gördüğünde "bu makine kimin, ne işe yarıyor?" sorusunu cevaplar.
"""),
    Adim("Alan transferi (AXFR)", """
Yetkili sunucular, yedek isim sunucularıyla senkron kalmak için bölgenin (zone) **tamamını**
aktarabilir: buna alan transferi, sorgu türüne **AXFR** denir. Doğru yapılandırılmış bir
sunucu bunu sadece kendi yedek sunucularına izin verir. Yanlış yapılandırılmış biri ise
soran herkese bütün rehberi verir: tüm alt alan adları, iç sunucu adları, bazen iç IP'ler.

Önce düzgün yapılandırılmış bir bölgede deneyelim: `www`'nin işaret ettiği CDN firmasının alanı.
""", komut="dig @127.0.0.1 -p <<port>> <<cdn>> AXFR", sonra="""
`Transfer failed.` = sunucu reddetti; olması gereken bu. AXFR, normal sorgulardan farklı
olarak TCP üzerinden yapılır (dig bunu kendisi halleder). Görevlerde aynı denemeyi
<<musteri>>'nin kendi alanında yapacaksın.

**Hacker gözüyle:** Alt alan adları (`test.`, `admin.`, `eski-...`) çoğu zaman unutulmuş,
güncellenmemiş ve savunmasız sistemlere işaret eder. Cilt 4'te subfinder ve amass gibi
araçlarla bunları toplu halde bulacağız. Savunmanın dersi: iç sistemlerin adlarını genel
DNS'e koymak, saldırgana harita vermektir.
"""),
]

GOREVLER = [
    Gorev("`<<alan>>` alan adının IPv4 adresi (A kaydı) ne?",
          IP("ana_ip", sik_hatalar=_ana_hata),
          ("A kaydı, tür belirtmezsen dig'in varsayılan olarak sorduğu türdür.",
           "`dig @127.0.0.1 -p <<port>> <<alan>>` ve ANSWER SECTION.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> +short` tek satırda sadece IP'yi verir."),
          puan=20, baslik="A kaydı"),
    Gorev("<<musteri>>'ye gelen e-postaları **öncelikle** hangi sunucu kabul ediyor? (MX)",
          Metin("mx", son_ekleri_at=(".",), sik_hatalar=_mx_hata, bicim="sunucu adı"),
          ("E-posta sunucularını gösteren kayıt türü MX.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> MX +short` her satırda bir öncelik sayısı ve bir ad verir.",
           "İki satır var; öncelik sayısı KÜÇÜK olan birinci tercihtir. O satırdaki adı yaz."),
          puan=25, baslik="E-posta kapısı"),
    Gorev("`www.<<alan>>` bir takma ad (CNAME). Hangi ada işaret ediyor?",
          Metin("cname", son_ekleri_at=(".",), sik_hatalar=_cname_hata, bicim="alan adı"),
          ("Takma ad kayıtlarının türü CNAME.",
           "`dig @127.0.0.1 -p <<port>> www.<<alan>>` çıktısında CNAME satırına bak.",
           "`dig @127.0.0.1 -p <<port>> www.<<alan>> CNAME +short`"),
          puan=25, baslik="Takma ad"),
    Gorev("`<<not_ad>>.<<alan>>` adının TXT kaydında, yayına çıkmadan silinmesi unutulmuş bir not "
          "var. İçindeki bayrağı bul.",
          Bayrak("bayrak"),
          ("TXT kayıtları serbest metin taşır; sorgulanacak ad soruda yazıyor.",
           "Tür olarak TXT iste: `dig ... <<not_ad>>.<<alan>> TXT`",
           "`dig @127.0.0.1 -p <<port>> <<not_ad>>.<<alan>> TXT +short`"),
          puan=30, baslik="Unutulan not"),
    Gorev("`<<alan>>`'ın bir de IPv6 adresi var. Ne?",
          Metin("ipv6", bicim="IPv6 adresi"),
          ("IPv6 adresleri hangi kayıt türünde tutulur?",
           "Tür olarak `AAAA` iste.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> AAAA +short`"),
          puan=20, baslik="Unutulan ikinci kapı"),
    Gorev("`guvenlik_duvari.log`'da her gece rsync ile iç ağa bağlanan bir adres var. Ters DNS'e göre "
          "bu IP hangi ada ait?",
          Metin("ptr", son_ekleri_at=(".",), sik_hatalar=_ptr_hata, bicim="alan adı"),
          ("Önce logda `rsync` geçen satırlardaki kaynak IP'yi bul.",
           "IP'den ada gitmek için PTR kaydı sorulur; dig'de kısayolu `-x`.",
           "`dig @127.0.0.1 -p <<port>> -x <IP> +short`"),
          puan=25, baslik="Bu IP kimin"),
    Gorev("Mert üç ad tahmin etti: `<<aday1>>`, `<<aday2>>`, `<<aday3>>`. Bunlardan hangisi DNS'te "
          "**gerçekten** tanımlı?",
          Metin("var_olan", son_ekleri_at=(".",), sik_hatalar=_var_hata, bicim="alan adı"),
          ("Tanımsız bir ad sorulduğunda yetkili sunucu bunu açıkça söyler.",
           "Her biri için dig çalıştır ve HEADER satırındaki `status:` alanına bak.",
           "`dig @127.0.0.1 -p <<port>> <ad> | grep status` üç ad için: NXDOMAIN = yok, NOERROR = var."),
          puan=25, baslik="Var mı yok mu"),
    Gorev("<<musteri>>'nin sunucusu alan transferine (AXFR) izin veriyor mu? Dene. Bölgedeki hangi "
          "alt alan adı **özel (iç ağ)** bir IP adresine çözülüyor?",
          Metin("ic_ad", son_ekleri_at=(".",), sik_hatalar=_ic_hata, bicim="alt alan adı"),
          ("Eğitimde CDN alanında denediğin komutu bu kez <<alan>> için çalıştır.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> AXFR` bütün kayıtları döker; A kayıtlarının IP'lerine bak.",
           "Çıktıyı `grep -w A` ile süz; 10., 172.16-31. ya da 192.168. ile başlayan IP'nin satırındaki ad."),
          puan=35, baslik="Bütün rehber"),
    Gorev("Bir saldırgan için `test-...`, `eski-...`, `admin...` gibi alt alan adları neden çoğu "
          "zaman ana siteden daha değerli hedeflerdir?",
          Secmeli([
              ("Genelde test için kurulur, güncellenmesi unutulur ve daha zayıf korunur",
               "Doğru. Adları da ne iş yaptıklarını ele verir; ana site kadar özen görmezler."),
              ("Alt alan adlarının A kaydı olmadığı için güvenlik duvarı onları koruyamaz",
               "Alt alan adlarının da A kaydı vardır (az önce gördün); güvenlik duvarı IP'ye bakar, ada değil."),
              ("Alt alan adları hep ana siteyle aynı sunucuda çalışır, tek açık ikisini de düşürür",
               "Çoğu zaman tam tersi: farklı, daha eski ve daha az bakımlı sunucularda çalışırlar."),
              ("Alt alan adlarına HTTPS sertifikası verilemez, trafikleri hep düz metindir",
               "Alt alan adlarına da sertifika verilebilir; sorun şifreleme değil, bakımsızlık."),
          ]),
          ("Bu adları kim, ne için kurar ve iş bitince ne olur?",
           "Ana site her gün izlenir ve güncellenir. Ya geçen yılki test sunucusu?",
           "Unutulmuşluk, güncellenmemişlik ve adın kendisinin verdiği bilgi."),
          puan=20, baslik="Neden alt alan"),
]

SEVIYE = Seviye(
    kimlik="c02b04",
    cilt=2,
    bolum=4,
    baslik="DNS: İnternetin Telefon Rehberi",
    brifing="""
**<<musteri>>** dış keşif istedi. Yetkili DNS sunucusunun kopyası 127.0.0.1, port **<<port>>**
üzerinde çalışıyor. Selin: "Her kayıt türünü sor; alan transferini de dene."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
DNS keşfi, hedefe tek bir saldırı paketi göndermeden haritanın büyük kısmını çıkarır: ana
sunucu, e-posta altyapısı, kullanılan bulut servisleri, unutulmuş test sistemleri. Yanlış
yapılandırılmış bir alan transferi ise haritanın tamamını tek seferde verir. Savunma tarafı
için dersler net: AXFR'yi sadece yedek isim sunucularına aç, iç sistemlerin adlarını ve
IP'lerini genel DNS'e koyma (iç ve dış DNS'i ayır), işi biten test kayıtlarını sil ve TXT
kayıtlarına not yazma.
""",
    gercek_hayat="""
- **Açık alan transferi:** AXFR'nin herkese açık bırakılması, güvenlik denetimlerinde ve
  sızma testi raporlarında yıllardır görülen klasik bir yapılandırma hatasıdır; nmap'te bunu
  test eden hazır bir betik (`dns-zone-transfer`) bile vardır.
- **Unutulmuş alt alan adları ve devralma:** Bir alt alan adı silinmiş bir bulut servisine
  CNAME ile işaret etmeye devam ederse, saldırgan o servisi kendi adına açıp alt alan adını
  "devralabilir" (subdomain takeover). Bu, bug bounty programlarında sık raporlanan bir bulgu
  türüdür ve tek bir `dig` sorgusuyla fark edilir.
- **Sertifika şeffaflığı:** Verilen TLS sertifikaları herkese açık kayıtlarda (Certificate
  Transparency) listelenir; crt.sh gibi sitelerden bir kurumun alt alan adları DNS'e hiç
  dokunmadan bulunabilir. Cilt 4'te bunu kullanacağız.
""",
    sure_hedef_dk=30,
)
