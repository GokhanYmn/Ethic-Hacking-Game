"""Cilt 2 · Bölüm 7 — Kapanış Görevi: Bir Bağlantıyı Takip Et.

Cildi birleştiren vaka: bir çalışan oltalama (phishing) bağlantısına tıkladı. Oyuncu tek bir
bağlantıyı baştan sona izler: isim çözümleme (DNS) → hangi IP ve port (taşıma/internet) →
hangi HTTP isteği ve cevabı (uygulama) → Ethernet'te kime teslim edildi (ağ erişimi). Sonra
saldırganın sunucusunun laboratuvardaki kopyasına (DNS + web, 127.0.0.1) sorular sorar ve
pcap'teki isteği tekrar oynatır (replay).

Lab: `hy.ortak.ag.Pcap` ile üretilmiş pcap + `hy.ortak.ag.dns_sunuculari` + `http_sunucu`.

Vakalar: hastane (randevu iptali tuzağı), banka (hesap doğrulama tuzağı), lojistik (kargo
faturası tuzağı), e-ticaret (tedarikçi siparişi tuzağı).
"""
from __future__ import annotations

import random
import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Bayrak, Metin, Sayi, Secmeli, Serbest
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import SessizIsleyici, calistir, http_sunucu
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "medora", "klasor": "olay_2611", "pcap": "hemsire_pc.pcap", "kurban_ad": "hemşire istasyonu bilgisayarı",
        "supheli": ["medora-randevu-iptal.lab", "medora-hasta-bilgi.lab", "medorasaglik-portal.lab"],
        "yollar": ["/randevu/iptal-formu", "/hasta/belge-indir", "/portal/randevu-onay"],
        "dosyalar": ["Randevu_Iptal_Formu.zip", "Hasta_Bilgilendirme.zip", "Randevu_Onay_Belgesi.zip"],
        "normal": ["randevu.medora.lab", "portal.medora.lab", "e-recete.saglikbakim.lab", "lab-sonuc.medora.lab"],
        "brifing": """
Pazartesi sabahı **Medora Sağlık**'tan acil bir çağrı: bir hemşire, "randevunuz iptal edildi,
formu doldurun" diye gelen bir e-postadaki bağlantıya tıklamış ve bir dosya inmiş. Neyse ki
ağ sensörü o dakikaları kaydetmiş; **Deniz** kaydı `<<klasor>>/<<pcap>>` olarak koydu.
Saldırganın kiraladığı sunucu, barındırma firmasıyla iş birliği sayesinde kapatıldı ve disk
imajı adli inceleme için alındı. Deniz o imajdan DNS ve web servisini laboratuvarında yeniden
ayağa kaldırdı (127.0.0.1).

Selin: "Bu cildin kapanış görevi bu. Tek bir bağlantıyı baştan sona izle: isim nasıl IP'ye
döndü, paket nereye gitti, hangi kapıyı çaldı, ne istedi, ne aldı. Sonra raporunu yaz."
""",
    },
    {
        "kod": "ferahbank", "klasor": "olay_kayit", "pcap": "gise_07.pcap", "kurban_ad": "gişe bilgisayarı",
        "supheli": ["ferahbank-guvenlik-dogrulama.lab", "ferah-bank-hesap.lab", "ferahbank-destek-merkezi.lab"],
        "yollar": ["/dogrulama/belge", "/hesap/guncelle-formu", "/destek/talep-indir"],
        "dosyalar": ["Hesap_Dogrulama_Formu.zip", "Guvenlik_Guncellemesi.zip", "Destek_Talebi.zip"],
        "normal": ["sube.ferahbank.lab", "kurumsal.ferahbank.lab", "doviz-kur.lab", "intranet-haber.ferahbank.lab"],
        "brifing": """
**Ferah Bank**'ta bir gişe çalışanı, "hesabınızı doğrulamazsanız kilitlenecek" başlıklı bir
e-postadaki bağlantıya tıkladı. Kaan Bey hemen bilgisayarı ağdan ayırttı; ağ sensörünün
kaydı Deniz'in elinde: `<<klasor>>/<<pcap>>`. Saldırganın sunucusu barındırma firmasıyla
birlikte kapatıldı, disk imajı alındı; Deniz o imajdan DNS ve web servisini laboratuvarında
yeniden çalıştırıyor (127.0.0.1).

Selin: "Bankanın bilmek istediği basit: hangi adrese gidildi, ne indirildi, saldırgan kimi
hedefliyor? Her katmanı tek tek çıkar ve sonunda bir rapor yaz."
""",
    },
    {
        "kod": "kuzgun", "klasor": "muhasebe_olay", "pcap": "muhasebe_pc.pcap", "kurban_ad": "muhasebe bilgisayarı",
        "supheli": ["kuzgun-fatura-goruntule.lab", "kuzgunkargo-e-fatura.lab", "kuzgun-odeme-bildirim.lab"],
        "yollar": ["/fatura/goruntule", "/e-fatura/indir", "/odeme/dekont"],
        "dosyalar": ["Fatura_Kasim_2026.zip", "E-Fatura_Detay.zip", "Odeme_Dekontu.zip"],
        "normal": ["stok.kuzgun.lab", "www.kuzgun.lab", "kargo-api.kuzgun.lab", "harita.rotalab.lab"],
        "brifing": """
**Kuzgun Lojistik**'in muhasebesinde biri, "geciken kargo faturanız" konulu bir e-postadaki
bağlantıyı açtı. Serdar Bey bilgisayarı karantinaya aldı; o dakikaların ağ kaydı Deniz'de:
`<<klasor>>/<<pcap>>`. Saldırganın sunucusu kapatıldı ve imajı alındı; Deniz o imajdan DNS ve
web servisini laboratuvarında yeniden ayağa kaldırdı (127.0.0.1).

Selin: "Cildin son görevi. Bir bağlantının hikâyesini katman katman anlatabilirsen, bu cildi
bitirmişsin demektir."
""",
    },
    {
        "kod": "pazarix", "klasor": "tedarik_olay", "pcap": "satinalma_pc.pcap", "kurban_ad": "satın alma bilgisayarı",
        "supheli": ["pazarix-tedarikci-portal.lab", "pazarix-siparis-onay.lab", "pazarixtedarik.lab"],
        "yollar": ["/siparis/liste-indir", "/tedarikci/sozlesme", "/onay/belge"],
        "dosyalar": ["Siparis_Listesi.zip", "Tedarikci_Sozlesmesi.zip", "Siparis_Onay.zip"],
        "normal": ["www.pazarix.lab", "odeme.pazarix.lab", "kampanya.pazarix.lab", "kargo-takip.rotalab.lab"],
        "brifing": """
**Pazarix**'te satın alma ekibinden biri, "yeni tedarikçi sipariş listesi" diye gelen bir
bağlantıya tıkladı ve bir dosya indirdi. Ağ sensörünün kaydı Deniz'de: `<<klasor>>/<<pcap>>`.
Saldırganın sunucusu kapatılıp imajı alındı; Deniz o imajdan DNS ve web servisini
laboratuvarında yeniden çalıştırıyor (127.0.0.1).

Selin: "Bu cilt boyunca öğrendiğin her şey bu tek bağlantıda: DNS, IP, port, HTTP, MAC.
Baştan sona izle, sonra bir meslektaşına anlatır gibi raporla."
""",
    },
]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    ag3 = rng.choice([f"10.{rng.randint(1, 250)}.{rng.randint(0, 250)}", f"192.168.{rng.randint(0, 250)}",
                      f"172.{rng.randint(16, 31)}.{rng.randint(0, 250)}"])
    hostlar = [f"{ag3}.{h}" for h in rng.sample(range(10, 240), 4)]
    kurban, digerleri = hostlar[0], hostlar[1:]
    gw = f"{ag3}.1"
    dns = f"{ag3}.{rng.choice([2, 3, 53])}"
    kullanilan: set = set()

    def dis():
        ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    normal = [(alan, dis()) for alan in rng.sample(v["normal"], 3)]
    i = rng.randrange(3)
    supheli, yol, dosya = v["supheli"][i], v["yollar"][rng.randrange(3)], v["dosyalar"][i]
    kimlik = "".join(rng.choice("0123456789abcdef") for _ in range(8))
    yol = f"{yol}?k={kimlik}"
    saldirgan_ip = dis()
    posta_ip = dis()
    s = {
        "vaka": f"{m['ad']} — oltalama bağlantısının izi",
        "brifing": v["brifing"],
        "v": v, "ag3": ag3, "gw": gw, "dns": dns, "kurban": kurban, "digerleri": digerleri, "normal": normal,
        "supheli": supheli, "yol": yol, "dosya": dosya, "saldirgan_ip": saldirgan_ip, "posta_ip": posta_ip,
        "port": rng.choice([80, 8080, 8000, 8888]),
        "kampanya": f"kampanya={rng.choice(['kmp', 'grp', 'hdf'])}-{''.join(rng.choice('0123456789abcdef') for _ in range(12))}",
        "bayrak": u.bayrak(rng, rng.choice(["derin_iz", "son_satir", "sinyal", "ucuncu_goz"])),
        "dns_port": 0, "http_port": 0,
        "pcap_tohum": rng.randint(1, 10**9),
        "t0": u.gun(rng).timestamp() + rng.randint(8, 11) * 3600 + rng.randint(0, 3000),
    }
    s["dns_port"], s["http_port"] = rng.sample(range(20000, 45001), 2)
    s["metin"] = {
        "musteri": m["ad"], "klasor": v["klasor"], "pcap": v["pcap"], "kurban": kurban, "kurban_ad": v["kurban_ad"],
        "dns_port": s["dns_port"], "http_port": s["http_port"],
        # Serbest rapor örneği için (cevap gösterildikten sonra görünür)
        "supheli": supheli, "saldirgan_ip": saldirgan_ip, "port": s["port"], "yol": yol.split("?")[0],
        "dosya": dosya, "posta_ip": posta_ip,
    }
    s["cevaplar"] = {
        "saldirgan_ip": saldirgan_ip,
        "port": s["port"],
        "supheli": [supheli, supheli + "."],
        "yol": [yol, yol.split("?")[0]],
        "dosya": dosya,
        "posta_ip": posta_ip,
        "bayrak": s["bayrak"],
    }
    return s


def _pcap_kur(s: dict) -> ag.Pcap:
    r = random.Random(s["pcap_tohum"])
    p = ag.Pcap(yerel=f"{s['ag3']}.0/24", ag_gecidi=s["gw"])
    t0 = s["t0"]
    herkes = s["digerleri"] + [s["kurban"]]
    for i, dilim in enumerate([1, 8, 16, 41, 55]):
        ist = herkes[i % len(herkes)]
        alan, ip = s["normal"][i % len(s["normal"])]
        t = t0 + dilim + r.uniform(0, 2)
        p.dns(ist, s["dns"], alan, "A", [ip], t=t)
        p.tls_oturumu(ist, ip, t + 0.05, r)
    # kurbanın tıklaması: önce isim çözümleme, sonra düz HTTP ile dosya indirme
    tk = t0 + 27 + r.uniform(0, 2)
    p.dns(s["kurban"], s["dns"], s["supheli"], "A", [s["saldirgan_ip"]], t=tk)
    o = p.tcp_oturum(s["kurban"], r.randint(40000, 60999), s["saldirgan_ip"], s["port"], tk + 0.04,
                     rtt=r.uniform(0.03, 0.06))
    o.el_sikis()
    host = s["supheli"] if s["port"] == 80 else f"{s['supheli']}:{s['port']}"
    o.istemci(ag.http_istek("GET", s["yol"], host, {"Cookie": s["kampanya"],
                                                     "Referer": f"http://webmail.{musteri(s['v']['kod'])['alan']}/"}))
    govde = b"PK\x03\x04" + r.randbytes(r.randint(1800, 2600))
    o.sunucu(ag.http_yanit(200, govde, {"Content-Disposition": f'attachment; filename="{s["dosya"]}"'},
                           sunucu="nginx/1.22.1", tur="application/zip"))
    o.kapat()
    return p


def _bolgeler(s: dict) -> list:
    b = ag.Bolge(s["supheli"])
    b.ekle("@", "NS", "ns1").ekle("ns1", "A", s["saldirgan_ip"])
    b.ekle("@", "A", s["saldirgan_ip"])
    b.ekle("www", "CNAME", "@")
    b.ekle("@", "MX", (10, "mail")).ekle("mail", "A", s["posta_ip"])
    b.ekle("@", "TXT", f"v=spf1 ip4:{s['posta_ip']} -all")
    return [b]


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    _pcap_kur(s).kaydet(lab / v["klasor"] / v["pcap"])
    u.yaz(lab / "OKUBENI.txt",
          f"Olay: {v['kurban_ad']} ({s['kurban']}) bir oltalama bağlantısına tıkladı.\n\n"
          f"Trafik kaydı      : {v['klasor']}/{v['pcap']}\n"
          f"Saldırgan DNS'i   : 127.0.0.1 port {s['dns_port']} (UDP/TCP)  — disk imajından yeniden kuruldu\n"
          f"Saldırgan web'i   : http://127.0.0.1:{s['http_port']}/      — disk imajından yeniden kuruldu\n\n"
          "Kurallar (Selin): Gerçek saldırgan altyapısına asla dokunma; sadece bu kopyalarla çalış.\n"
          "Raporuna her bulgunun hangi komutla elde edildiğini yaz.\n")


def servis(s: dict, lab: Path, dur) -> None:
    yol_tam = s["yol"]
    yol = yol_tam.split("?")[0]
    kampanya = s["kampanya"]
    ad, deger = kampanya.split("=", 1)

    class Kopya(SessizIsleyici):
        server_version = "nginx/1.22.1"
        timeout = 15

        def version_string(self):
            return self.server_version

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            y, _ = ag.yol_ve_sorgu(self)
            if y == yol and ag.cerezler(self).get(ad) == deger:
                self.yanit(200, ("Kampanya kaydi (disk imajindan)\n"
                                 f"Kampanya: {deger}\n"
                                 f"Hedef kurum: {musteri(s['v']['kod'])['ad']}\n"
                                 f"Gonderilen dosya: {s['dosya']}\n"
                                 f"Kampanya anahtari: {s['bayrak']}\n"), tur="text/plain; charset=utf-8")
            else:
                # Oltalama sunucuları çoğu zaman doğru çerezi/bağlantıyı getirmeyene hiçbir şey göstermez
                self.yanit(404, "<html><body><h1>404 Not Found</h1></body></html>\n")

    sunucular = ag.dns_sunuculari("127.0.0.1", s["dns_port"], _bolgeler(s))
    sunucular.append(http_sunucu("127.0.0.1", s["http_port"], Kopya))
    calistir(sunucular, dur)


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: tcpdump + dig + curl ile zinciri yürür."""
    f = f"{s['v']['klasor']}/{s['v']['pcap']}"
    k = s["kurban"]
    baglanti = _sh(f"tcpdump -nn -r {f} 'src host {k} and tcp[tcpflags] == tcp-syn and not dst port 443' 2>/dev/null "
                   "| awk '{print $5}' | tr -d ':'", lab)
    ip = ".".join(baglanti.split(".")[:4])
    port = baglanti.split(".")[4]
    supheli = _sh(f"tcpdump -nn -v -r {f} port 53 2>/dev/null | grep -o '[^ ]* A {ip} ' | awk '{{print $1}}'", lab)
    akis = _sh(f"tcpdump -nn -A -r {f} 'host {ip} and port {port}' 2>/dev/null", lab)
    yol = re.search(r"GET (\S+) HTTP", akis).group(1)
    dosya = re.search(r'filename="([^"]+)"', akis).group(1)
    cerez = re.search(r"Cookie: (\S+)", akis).group(1)
    posta = _sh(f"dig @127.0.0.1 -p {s['dns_port']} {supheli} TXT +short | grep -o 'ip4:[0-9.]*' | cut -d: -f2", lab)
    bayrak = _sh(f"curl -s -b '{cerez}' 'http://127.0.0.1:{s['http_port']}{yol}' | grep -o 'FLAG{{[^}}]*}}'", lab)
    secmeli = SEVIYE.gorevler[7].kontrol.cevabi_goster(Baglam(s, lab, 8))[0]
    rapor = ("Kurban once DNS ile supheli alan adini sordu, cevaptaki IP'ye duz HTTP ile baglandi, "
             "GET istegiyle bir zip dosyasi indirdi; paketler yerel agda ag gecidine teslim edildi.")
    return {1: ip, 2: port, 3: supheli, 4: yol, 5: dosya, 6: posta, 7: bayrak, 8: secmeli, 9: rapor}


# ---------------------------------------------------------------- sık hatalar

def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["dns"]:
        return "Bu iç ağdaki DNS çözümleyicisi; kurban ona sadece isim sordu. Düz HTTP bağlantısının hedefini ara."
    if g in [ip for _a, ip in s["normal"]]:
        return "Bu bağlantı 443'e (HTTPS) gidiyor; normal trafik. Kurbanın 443 DIŞINDA kurduğu bağlantıyı bul."
    if g == s["kurban"]:
        return "Bu kurbanın kendisi. Soru, onun bağlandığı uzak sunucuyu soruyor."
    return None


def _port_hata(g, beklenen, b):
    if g == "443":
        return "443 normal HTTPS trafiği. Şüpheli bağlantı başka bir porta gidiyor."
    if g == "53":
        return "53 DNS'in portu; isim çözümleme. Asıl bağlantının hedef portunu ara."
    try:
        if int(g) > 30000:
            return "Bu büyük sayı istemcinin rastgele kaynak portu. Hedef port, `>` işaretinden SONRAKİ adresin sonunda."
    except ValueError:
        pass
    return None


def _supheli_hata(g, beklenen, b):
    for alan, _ip in b.senaryo["normal"]:
        if g.rstrip(".") == alan:
            return "Bu alan adı başka bir IP'ye çözülüyor (normal trafik). Saldırganın IP'sini DNS cevaplarında ara."
    return None


def _yol_hata(g, beklenen, b):
    if g.startswith("http"):
        return "Sadece yolu yaz: `GET`'ten sonra, `HTTP/1.1`'den önceki kısım (/ ile başlar)."
    return None


ADIMLAR = [
    Adim("Bir bağlantı, dört katman", """
Bu cildin kapanış görevi tek bir bağlantının hikâyesini çıkarmak. Her katman bir soruya cevap
verir; senin işin her birini bir komutla kanıtlamak:

1. **İsim → IP (uygulama katmanı, DNS):** Kurban hangi adı sordu, hangi IP'yi aldı? `tcpdump -v port 53`
2. **IP ve port (internet + taşıma):** Nereye, hangi kapıya bağlandı? SYN filtresi
3. **İstek ve cevap (uygulama, HTTP):** Ne istedi, ne aldı? `tcpdump -A`
4. **MAC (ağ erişimi):** Paketler yerel ağda kime teslim edildi? `tcpdump -e`

Sonra saldırganın sunucusunun kopyasına dönüp aynı soruları **canlı** sorarsın: `dig` ve `curl`.
""", komut="cat OKUBENI.txt"),
    Adim("Kaydın ilk dakikası", """
Önce genel resme bak: kim kiminle konuşuyor? Kurbanın adresi `<<kurban>>`.
""", komut="tcpdump -nn -r <<klasor>>/<<pcap>> -c 10", sonra="""
DNS sorguları (`A?`), HTTPS el sıkışmaları (port 443). Bu kayıtta çoğu trafik şifreli ve
normal; aradığın, kurbanın 443 dışında bir yere yaptığı bağlantı.
"""),
    Adim("MAC adreslerini görmek: -e", """
`-e` her satırın başına Ethernet başlığını, yani kaynak ve hedef **MAC** adreslerini ekler.
Bölüm 1'deki dersi hatırla: uzaktaki bir sunucuya giden paketin hedef MAC'i o sunucunun değil,
bir sonraki durağındır.
""", komut="tcpdump -nn -e -r <<klasor>>/<<pcap>> -c 4", sonra="""
Satırın başındaki `aa:bb:.. > cc:dd:..` çifti MAC adresleridir; ardından `ethertype IPv4` ve
tanıdık IP satırı gelir. Aynı hedef MAC'in farklı uzak IP'lere giden paketlerde tekrar ettiğini
görürsen, o MAC'in kime ait olduğunu düşün.
"""),
    Adim("Kopya sunucular", """
Saldırganın sunucusu kapatıldı; Deniz disk imajından DNS ve web servisini kendi makinende,
127.0.0.1 üzerinde yeniden çalıştırıyor. Gerçek saldırgan altyapısına dokunmak hem kapsam dışı
hem de saldırganı uyarabilir; bu yüzden olay müdahalesinde kopya ya da imaj üzerinde çalışılır.
""", komut="ss -tulnp", sonra="""
`<<dns_port>>` hem UDP hem TCP'de dinliyor (DNS sorguları UDP, alan transferi TCP),
`<<http_port>>` ise web sunucusu. Bunlara `dig @127.0.0.1 -p <<dns_port>> ...` ve
`curl http://127.0.0.1:<<http_port>>/...` ile konuşacaksın.
"""),
    Adim("İsteği tekrar oynatmak (replay)", """
Oltalama sunucuları çoğu zaman sadece "doğru" kurbana içerik gösterir: bağlantıdaki kimlik
numarası, bir çerez ya da belirli bir User-Agent gelmezse 404 der. Araştırmacıyı ve otomatik
tarayıcıları atlatmak için yapılır (cloaking).

Bunu aşmanın yolu, kayıttaki isteği **aynen** tekrarlamaktır. curl'de:

- `-b 'ad=deger'` → `Cookie:` başlığı
- `-A 'Mozilla/5.0 ...'` → `User-Agent:` başlığı
- `-H 'Baslik: deger'` → herhangi bir başlık

```
curl -b 'kampanya=...' 'http://127.0.0.1:<<http_port>>/yol?parametre=...'
```

Adreste `?` ve `&` varsa tek tırnak içine al; yoksa kabuk onları yorumlar.
"""),
    Adim("Rapor", """
Son görev bir rapor. Bir meslektaşına anlatır gibi, kısa ve kanıtlı yaz:

- İsim nasıl IP'ye çevrildi (hangi alan adı, hangi IP)?
- Paket nereye, hangi porta gitti ve yerel ağda kime teslim edildi?
- Hangi istek yapıldı, sunucu ne döndü?
- Saldırgan altyapısı hakkında DNS ne söyledi (e-posta nereden gönderiliyor)?
- Ne öneriyorsun?

**Hacker gözüyle:** Pentest raporunun yarısı tekniktir, yarısı anlatım. Bulguyu bulan ama
anlatamayan, bulguyu bulamamış sayılır. Mert'in her seferinde "raporu kim yazacak?" diye
sormasının sebebi bu.
"""),
]

GOREVLER = [
    Gorev("Kurban (<<kurban>>) 443 (HTTPS) **dışında** tek bir bağlantı kurdu. Bağlandığı sunucunun "
          "IP adresi ne?",
          IP("saldirgan_ip", sik_hatalar=_ip_hata),
          ("Bağlantıların başlangıcı SYN paketidir.",
           "Kurbanın gönderdiği SYN'leri süz ve 443'e gidenleri dışarıda bırak.",
           "`tcpdump -nn -r <<klasor>>/<<pcap>> 'src host <<kurban>> and tcp[tcpflags] == tcp-syn and not dst port 443'`"),
          puan=25, baslik="Nereye"),
    Gorev("Hangi **porta** bağlandı?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Aynı SYN satırına bak.",
           "Satırda `kaynak.port > hedef.port` yazar; hedef `>`'den sonraki adres.",
           "`>` işaretinden sonraki `ip.port:` ifadesinin son noktasından sonraki sayı."),
          puan=20, baslik="Hangi kapı"),
    Gorev("Kurban bu IP'yi hangi **alan adını** sorgulayarak öğrendi?",
          Metin("supheli", son_ekleri_at=(".",), sik_hatalar=_supheli_hata, bicim="alan adı"),
          ("İsim çözümleme bağlantıdan hemen önce, port 53'te olur.",
           "`-v` ile tcpdump DNS cevabındaki adı da basar.",
           "`tcpdump -nn -v -r <<klasor>>/<<pcap>> port 53 | grep SALDIRGAN_IP`"),
          puan=25, baslik="Hangi isim"),
    Gorev("Kurban sunucudan hangi **yolu** istedi? (`GET`'ten sonraki kısım)",
          Metin("yol", sik_hatalar=_yol_hata, bicim="yol (örn. /sayfa?x=1)"),
          ("Bağlantı şifresiz; içerik okunabilir.",
           "`-A` ile o bağlantının içeriğini göster: `host IP and port PORT`.",
           "`tcpdump -nn -A -r <<klasor>>/<<pcap>> 'host SALDIRGAN_IP and port PORT' | grep -a GET`"),
          puan=25, baslik="Ne istedi"),
    Gorev("Sunucu kurbana bir dosya gönderdi. Dosyanın adı ne?",
          Metin("dosya", sadece_ad=True, bicim="dosya adı"),
          ("Sunucunun cevabındaki başlıklara bak; indirilen dosyanın adı bir başlıkta yazar.",
           "`Content-Disposition` başlığı.",
           "Aynı `-A` çıktısında `grep -a filename` ile ara; tırnak içindeki ad."),
          puan=25, baslik="Ne aldı"),
    Gorev("Saldırganın alan adının DNS kaydına (kopya sunucu: 127.0.0.1, port <<dns_port>>) göre oltalama "
          "e-postaları hangi IP adresinden gönderiliyor? (Bu IP'yi e-posta geçidinde engelleyeceğiz.)",
          IP("posta_ip"),
          ("E-postayı göndermeye yetkili sunucular hangi kayıt türünde ilan edilir?",
           "SPF satırı bir TXT kaydıdır: `dig @127.0.0.1 -p <<dns_port>> ALAN TXT +short`",
           "`v=spf1 ip4:X -all` satırındaki `ip4:`'ten sonraki adres."),
          puan=30, baslik="Gönderen sunucu"),
    Gorev("Kopya web sunucusu (http://127.0.0.1:<<http_port>>/) kayıttaki isteğin **aynısını** "
          "alırsa (aynı yol, aynı çerez) kampanya kaydını gösteriyor. Kayıttaki anahtar (bayrak) ne?",
          Bayrak("bayrak"),
          ("Önce kayıttaki HTTP isteğinin başlıklarını oku; bir `Cookie:` satırı var.",
           "curl'de çerez `-b`, yol da adresin sonuna. Çerezsiz istek 404 alır.",
           "`curl -b 'CEREZ_ADI=DEGER' 'http://127.0.0.1:<<http_port>>/YOL?k=...'`"),
          puan=40, baslik="Replay"),
    Gorev("Kurbanın saldırgan sunucusuna giden paketlerinde Ethernet **hedef MAC** adresi kime aittir?",
          Secmeli([
              ("Yerel ağın çıkış kapısına, yani ağ geçidine (router)",
               "Doğru. Uzak bir IP'ye giden paket yerel ağda ağ geçidine teslim edilir; MAC her durakta yenilenir."),
              ("Saldırganın sunucusuna; paket kablo üzerinde doğrudan ona gider",
               "Saldırgan başka bir ağda. MAC adresleri sadece aynı yerel ağ içinde anlamlıdır."),
              ("DNS çözümleyicisine; adı o çözdüğü için paketleri de o iletir",
               "DNS sadece adı IP'ye çevirir; paketleri taşımaz. `tcpdump -e` ile kontrol et."),
              ("Kurbanın kendi kartına; hedef MAC her zaman gönderenin adresidir",
               "Gönderenin MAC'i kaynak (Src) alanındadır. Hedef MAC bir sonraki durağı gösterir."),
          ]),
          ("Bölüm 1'deki paket özetini hatırla.",
           "`tcpdump -nn -e -r <<klasor>>/<<pcap>> host SALDIRGAN_IP -c 2` ile hedef MAC'i gör; aynı MAC başka "
           "hangi uzak IP'lere giden paketlerde var?",
           "Uzak hedefe giden her paket önce yerel ağın çıkış kapısına gider."),
          puan=20, baslik="Bir sonraki durak"),
    Gorev("Raporunu yaz: bu bağlantının yolculuğunu bir meslektaşına anlatır gibi 2-4 cümlede özetle "
          "(isim → IP → port → istek → cevap) ve bir öneri ekle.",
          Serbest("""
Kurban (<<kurban>>) e-postadaki bağlantıya tıklayınca önce iç DNS çözümleyicisine
`<<supheli>>` adını sordu ve `<<saldirgan_ip>>` adresini aldı. Ardından bu adrese, şifresiz
HTTP ile port <<port>>'e bağlandı (paketler yerel ağda ağ geçidine teslim edildi) ve
`<<yol>>` yolunu istedi; sunucu `<<dosya>>` adlı bir arşiv gönderdi. Saldırganın DNS
kaydına göre oltalama e-postaları `<<posta_ip>>` adresinden çıkıyor. Öneri: alan adını ve iki
IP'yi engelle, indirilen dosyayı açılmadan karantinaya al, aynı e-postayı alan diğer
çalışanları bul ve uyar, tıklayan bilgisayarı incele.
""", min_kelime=20),
          ("Görevlerde bulduğun her parça raporun bir cümlesi.",
           "Sırayı izle: DNS sorgusu → TCP bağlantısı (IP, port) → HTTP isteği → HTTP cevabı → öneri.",
           "Her cümlede bir kanıt olsun: alan adı, IP, port, yol, dosya adı. Sonuna 'öneri:' ile bir iki madde ekle."),
          puan=40, baslik="Rapor"),
]

SEVIYE = Seviye(
    kimlik="c02b07",
    cilt=2,
    bolum=7,
    baslik="Kapanış Görevi: Bir Bağlantıyı Takip Et",
    brifing="""
**<<musteri>>**'de bir çalışan oltalama bağlantısına tıkladı. Trafik kaydı `<<klasor>>/<<pcap>>`
dosyasında; saldırganın DNS ve web sunucusunun kopyaları 127.0.0.1 üzerinde. Selin: "Tek bir
bağlantıyı baştan sona izle ve raporla."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Bir tıklama, saniyeden kısa sürede bir DNS sorgusu, bir TCP el sıkışması, bir HTTP isteği ve
bir dosya indirmesi demek; ve her biri ağda iz bırakır. Saldırgan bu zinciri kurarken senin
çalışanını, senin alan adına benzeyen bir adı ve şifresiz bir bağlantıyı kullandı; savunmacı
ise aynı zinciri ters yönde okuyarak kimin, neyi, nereden aldığını dakikalar içinde ortaya
çıkardı. Bu cildin bütün becerileri burada birleşti: isim çözümleme, adresler ve portlar,
HTTP, trafik okuma. Ders: benzer alan adlarını izle, DNS ve web trafiğini kaydet, şüpheli
indirmeleri ağ geçidinde yakala ve raporunu her zaman kanıtla yaz.
""",
    gercek_hayat="""
- **Oltalama ve ilk erişim:** Sektörün yıllık olay raporları (örneğin Verizon DBIR) oltalamayı
  ve çalınan kimlik bilgilerini, ihlallerde en sık görülen ilk erişim yolları arasında
  sayar. Bu yüzden olay müdahalesinde "kim tıkladı, ne indirdi?" sorusu ilk sorulardandır.
- **Benzer alan adları:** Saldırganlar hedef kurumun adına benzeyen alan adları
  (typosquatting, "kurum-destek", "kurum-giris" gibi) kaydeder. Birçok kurum yeni kaydedilen
  benzer alan adlarını izleyen hizmetler kullanır ve bunları e-posta ile web geçitlerinde
  önceden engeller.
- **Cloaking:** Oltalama ve zararlı yazılım dağıtan sunucuların içeriği sadece belirli
  bağlantı parametreleri, çerezler ya da IP aralıkları için göstermesi, güvenlik araştırmacılarının
  sıkça raporladığı bir kaçınma tekniğidir; analistler bu yüzden kayıttaki isteği birebir
  tekrarlamayı öğrenir.
""",
    sure_hedef_dk=40,
    tamamlama_bonusu=80,
)
