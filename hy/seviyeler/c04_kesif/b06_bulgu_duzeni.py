"""Cilt 4 · Bölüm 6 — Bulguları Düzenlemek.

Beceri: dağınık keşif notlarından (nmap çıktısı, Shodan notu, DNS notu, web notu) tekrarsız, kapsam içi,
sıralı bir varlık envanteri çıkarmak; kapsam dışı varlığı ayıklamak; bir puan tablosuyla önceliklendirmek;
iyi bir bulgu notunun dört parçasını (ne / nerede / neden önemli / sonraki adım) bilmek.

Servis yok: tüm veri lab dosyalarıdır. Oyuncu `envanter.csv` yazar, `Durum` ile doğrulanır.

Vakalar: e-ticaret (Pazarix), hastane (Medora Sağlık), lojistik (Kuzgun Lojistik).
"""
from __future__ import annotations

import csv
import ipaddress
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Durum, Kume, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

AGIRLIK = {"eski": 3, "kimliksiz": 3, "panel": 2, "metin": 2}

PAKETLER = {
    "web": [(80, "http", "nginx", "1.24.0", set()), (22, "ssh", "OpenSSH", "9.2p1", set())],
    "mail": [(25, "smtp", "Exim", "4.87", {"eski"}), (22, "ssh", "OpenSSH", "8.9p1", set())],
    "ftp": [(21, "ftp", "vsftpd", "2.3.4", {"eski", "metin"}), (22, "ssh", "OpenSSH", "9.2p1", set())],
    "panel": [(8080, "http", "Tomcat", "8.5.9", {"eski", "panel"}), (22, "ssh", "OpenSSH", "9.2p1", set())],
    "db": [(6379, "redis", "Redis", "4.0.9", {"eski", "kimliksiz"})],
}
EK = (9200, "elasticsearch", "Elasticsearch", "1.4.2", {"eski", "kimliksiz"})

VAKALAR = [
    {
        "kod": "pazarix", "klasor": "ham_notlar", "bolge": "kampanya haftası",
        "brifing": """
**Pazarix**'in kampanya haftası keşfi üç gün sürdü ve dört kişi not tuttu: Mert nmap çıktısını bıraktı, Deniz
DNS'e baktı, sen Shodan'a, bir stajyer de web sitesine. Hepsi <<klasor>> klasöründe, dört ayrı biçimde.
Selin: "Rapora yarın girecek. Bu dağınıklıktan müşterinin göreceği tek bir temiz envanter çıkarmanı istiyorum."

Selin: "Üç şeye dikkat: aynı servis birden çok notta geçiyor (tekrar), bir not başka birinin sunucusunu
kapsıyor (kapsam), ve bir servis sadece Shodan notunda var (nmap'te yok)."
""",
    },
    {
        "kod": "medora", "klasor": "dagnik_notlar", "bolge": "hasta portalı",
        "brifing": """
**Medora Sağlık**'ın hasta portalı keşfi bitti; ekip not tutmuş ama hepsi dağınık. Bilgi işlem sorumlusu Dr. Aslı
Hanım yarın bulguları görmek istiyor. Notlar <<klasor>> klasöründe: nmap çıktısı, Shodan notu, DNS notu ve web notu.

Selin: "Hastane ağında kapsam çok net çizilmiş: sözleşmedeki IP bloğu ve bir de açıkça dışarıda bırakılan bir
adres. Dışarıdakine dokunmuş olabilir miyiz? Önce envanteri çıkar, sonra bakarız."

Deniz: "Aynı bulgu üç notta üç farklı yazılmış olabilir. Tekrar sayma."
""",
    },
    {
        "kod": "kuzgun", "klasor": "calisma_notlari", "bolge": "depo ağı",
        "brifing": """
**Kuzgun Lojistik**'in depo ağı keşfi tamamlandı. Serdar Bey yarın toplantıda bulguları görmek istiyor; notlar
ise <<klasor>> klasöründe, her biri başka biçimde: nmap çıktısı, Shodan notu, DNS notu ve web notu.

Selin: "Bir iş: hepsini tek bir tutarlı envantere çevir. Kapsam dışına taşmış bir şey varsa onu da yakala."

Mert: "Kapsam, imzalı sözleşmedeki bloktur. Blok dışı ya da açıkça hariç tutulan her şey, ne kadar ilginç
görünürse görünsün, raporun dışındadır."
""",
    },
]


def _skor(hizmetler) -> int:
    return sum(AGIRLIK[b] for *_x, bayr in hizmetler for b in bayr)


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    onek = rng.choice(u.TEST_NET)
    taban = rng.choice([0, 16, 32, 48, 64, 80, 96])
    blok = f"{onek}.{taban}/28"
    adresler = [f"{onek}.{taban + i}" for i in range(1, 15)]
    while True:
        secim = rng.sample(adresler, 5)
        hariclenen, hostlar = secim[0], secim[1:]
        paketler = rng.sample(list(PAKETLER), 4)
        ek_ip = rng.choice(hostlar)
        hizmet = {ip: list(PAKETLER[p]) for ip, p in zip(hostlar, paketler)}
        hizmet[ek_ip] = hizmet[ek_ip] + [EK]
        skorlar = {ip: _skor(h) for ip, h in hizmet.items()}
        en = sorted(skorlar.values(), reverse=True)
        if en[0] > en[1]:
            break
    kullanilan = set(secim)
    cdn_ip = u.benzersiz(rng, lambda r: f"{rng.choice(u.TEST_NET)}.{rng.randint(2, 254)}", 1,
                         kullanilan | set(adresler))[0]
    sp_ip = u.benzersiz(rng, lambda r: f"{rng.choice(u.TEST_NET)}.{rng.randint(2, 254)}", 1,
                        kullanilan | set(adresler) | {cdn_ip})[0]
    while ipaddress.ip_address(cdn_ip) in ipaddress.ip_network(blok) or ipaddress.ip_address(sp_ip) in ipaddress.ip_network(blok):
        cdn_ip = f"{onek}.{(taban + 40) % 250 + 2}"
        sp_ip = f"{onek}.{(taban + 60) % 250 + 2}"
    # hariç tutulan ortak sunucusu: bir redis, kimliksiz
    hariclenen_hizmet = list(PAKETLER["db"])
    satirlar = []
    for ip in sorted(hizmet, key=lambda x: tuple(int(y) for y in x.split("."))):
        for port, serv, urun, surum, _b in sorted(hizmet[ip]):
            if (port, serv) != (EK[0], EK[1]) or ip != ek_ip:
                satirlar.append((ip, port, serv, f"{urun} {surum}"))
    ek_satir = (ek_ip, EK[0], EK[1], f"{EK[2]} {EK[3]}")
    hepsi = sorted([*satirlar, ek_satir], key=lambda x: (tuple(int(y) for y in x[0].split(".")), x[1]))
    yanlis_say = {
        str(len(hepsi) + len(hariclenen_hizmet)): "Kapsam dışı sunucunun servislerini de saymışsın; onlar envantere girmez.",
        str(len(hepsi) - 1): "Bir servis eksik: sadece Shodan notunda geçen ve nmap'te olmayan servisi de saymalısın.",
    }
    return {
        "vaka": f"{m['ad']} — {v['bolge']} bulgu düzeni ({alan})",
        "brifing": v["brifing"], "v": v, "m": m, "alan": alan, "blok": blok, "hariclenen": hariclenen,
        "hizmet": hizmet, "ek_ip": ek_ip, "cdn_ip": cdn_ip, "sp_ip": sp_ip, "envanter": hepsi, "skorlar": skorlar,
        "hariclenen_hizmet": hariclenen_hizmet, "satirlar": satirlar, "ek_satir": ek_satir, "yanlis_say": yanlis_say,
        "gun": u.gun(rng),
        "metin": {"musteri": m["ad"], "alan": alan, "klasor": v["klasor"], "blok": blok, "hariclenen": hariclenen},
        "cevaplar": {
            "kapsam_disi": sorted([hariclenen, cdn_ip, sp_ip]),
            "sayi": len(hepsi),
            "en_oncelikli": max(skorlar, key=skorlar.get),
        },
    }


def _ana_say(adr: str):
    return tuple(int(x) for x in adr.split("."))


def _nmap_metni(s: dict) -> str:
    cikti = [f"# nmap -F -sV {s['blok']}   (Mert, cuma gecesi)\n"]
    hepsi = dict(s["hizmet"])
    hepsi[s["hariclenen"]] = s["hariclenen_hizmet"]
    for ip in sorted(hepsi, key=_ana_say):
        cikti.append(f"Nmap scan report for {ip}\nHost is up (0.01{(_ana_say(ip)[3] % 9) + 1}s latency).\n"
                     "PORT     STATE  SERVICE       VERSION\n")
        for port, serv, urun, surum, _b in sorted(hepsi[ip]):
            if ip == s["ek_ip"] and (port, serv) == (EK[0], EK[1]):
                continue   # -F bu portu taramadı; yalnızca Shodan notunda var
            cikti.append(f"{port}/tcp{'':<{6 - len(str(port))}}open   {serv:<13} {urun} {surum}\n")
        cikti.append("443/tcp  closed https\n\n")
    return "".join(cikti)


def yaz(lab: Path, s: dict) -> None:
    v, alan = s["v"], s["alan"]
    k = lab / v["klasor"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['m']['ad']} keşfinin dağınık notları {v['klasor']}/ klasöründe.\n"
          "Görevin: bunlardan temiz bir envanter (envanter.csv) çıkarmak. Önce kapsam.txt'i oku.\n"
          "Önceliklendirme kuralları: oncelik_kurallari.txt\n")
    u.yaz(lab / "oncelik_kurallari.txt",
          "Kalkan Güvenlik — keşif önceliklendirme puanları (servis başına; bir makinenin puanı servislerinin toplamıdır)\n"
          "  +3  sürümü eski (müşteri eşiğinin altında / destek ömrü bitmiş)\n"
          "  +3  kimlik doğrulaması yok\n"
          "  +2  yönetim paneli\n"
          "  +2  açık metin protokol (FTP, Telnet)\n"
          "   0  güncel ve korumalı servis\n")
    u.yaz(k / "kapsam.txt",
          f"KAPSAM (imzalı sözleşme eki)\nIP bloğu:     {s['blok']}\nAlan adları:   *.{alan}\n\n"
          f"KAPSAM DIŞI (açıkça hariç):\n  {s['hariclenen']}   iş ortağının barındırma sunucusu\n"
          "  Bulut sağlayıcı, CDN ve e-posta servis sağlayıcısı adresleri\n")
    u.yaz(k / "nmap_ciktisi.txt", _nmap_metni(s))
    ip_ad = {ip: ad for ip, ad in zip(s["hizmet"], ["www", "posta", "dosya", "yonetim"])}
    dns = [f"www.{alan}   CNAME  cdn-{(_ana_say(s['cdn_ip'])[3]) % 90 + 10}.hizlicdn.lab  ->  {s['cdn_ip']}   (CDN, bizim değil)",
           f"{alan}   MX  mx.eposta-hizmeti.lab  ->  {s['sp_ip']}   (e-posta servis sağlayıcısı)"]
    for ip, ad in ip_ad.items():
        dns.append(f"{ad}-ic.{alan}   A   {ip}")
    u.yaz(k / "dns_notlari.txt", "\n".join(dns) + "\n")
    shodan = [f"Shodan'dan not düştüm ({alan}):"]
    for ip in list(s["hizmet"])[:2]:
        for port, serv, urun, surum, _b in s["hizmet"][ip][:1]:
            if (port, serv) != (EK[0], EK[1]):
                shodan.append(f"  {ip}:{port}  {urun} {surum}   (nmap'te de var)")
    shodan.append(f"  {s['ek_ip']} port {EK[0]} -> {EK[2]} {EK[3]}   (Shodan: kimlik yok, JSON döküyor)")
    shodan.append(f"  {s['cdn_ip']}  CDN ön yüzü, www bunun arkasında")
    shodan.append(f"  {s['hariclenen']} 6379 Redis 4.0.9   (kimin bu? ortaktan biri olabilir)")
    u.yaz(k / "shodan_notu.txt", "\n".join(shodan) + "\n")
    web = [f"# web notları ({alan})"]
    for ip, h in s["hizmet"].items():
        for port, serv, urun, surum, bayr in h:
            if serv == "http" and "panel" in bayr:
                web.append(f"- /manager paneli bulundu: {ip}:{port} ({urun} {surum}), giriş sayfası açık")
            elif serv == "http":
                web.append(f"- ana sayfa Server başlığı: {urun} {surum} ({ip}:{port})")
    u.yaz(k / "web_notlari.md", "\n".join(web) + "\n")


# ---------------------------------------------------------------- kontroller

def _envanter_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = o.dosya_bul(b, "envanter.csv")
    if yol is None:
        return Sonuc(False, "`envanter.csv` bulunamadı. Bulunduğun klasörde oluştur (ilk satır başlık: `ip,port,servis,surum`).")
    satirlar = [x for x in yol.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    if not satirlar or [c.strip().lower() for c in satirlar[0].split(",")] != ["ip", "port", "servis", "surum"]:
        return Sonuc(False, "İlk satır başlık olmalı: `ip,port,servis,surum` (küçük harf, virgülle).")
    satirlar = satirlar[1:]
    if not satirlar:
        return Sonuc(False, "Başlıktan sonra veri satırı yok.")
    blok = ipaddress.ip_network(s["blok"])
    beklenen = {(ip, port): (serv, surum) for ip, port, serv, surum in s["envanter"]}
    gorulen, tekrar, bicim = {}, 0, []
    for satir in csv.reader(satirlar):
        if len(satir) != 4:
            bicim.append(satir)
            continue
        ip, port, serv, surum = (x.strip() for x in satir)
        if not port.isdigit():
            bicim.append(satir)
            continue
        anahtar = (ip, int(port))
        if anahtar in gorulen:
            tekrar += 1
        gorulen[anahtar] = (serv.lower(), surum)
    if bicim:
        return Sonuc(False, f"{len(bicim)} satır biçime uymuyor: her satırda tam 4 alan (ip,port,servis,surum) "
                     "ve port bir sayı olmalı.", yakin=True)
    if tekrar:
        return Sonuc(False, f"{tekrar} satır tekrar ediyor: aynı ip:port bir kez yazılmalı (`sort -u` işe yarar).", yakin=True)
    disari = [a for a in gorulen if a[0] == s["hariclenen"] or not _blokta(a[0], blok)]
    if disari:
        return Sonuc(False, f"{len(disari)} satır kapsam dışı bir adrese ait (blok dışı ya da açıkça hariç tutulan). "
                     "Envantere yalnızca kapsam içi varlıklar girer.", yakin=True)
    eksik = [a for a in beklenen if a not in gorulen]
    fazla = [a for a in gorulen if a not in beklenen]
    if fazla:
        return Sonuc(False, f"{len(fazla)} satırdaki ip:port notlarda kapsam içi açık servis olarak görünmüyor.", yakin=True)
    if eksik:
        ipucu = " Shodan notunda olup nmap'te olmayan servisi de eklemeyi unutma." if s["ek_satir"][:2] in eksik else ""
        return Sonuc(False, f"{len(eksik)} servis eksik.{ipucu}", yakin=len(gorulen) > 0)
    yanlis = [a for a, (serv, surum) in gorulen.items()
              if serv != beklenen[a][0] or beklenen[a][1].split()[-1] not in surum]
    if yanlis:
        a = yanlis[0]
        return Sonuc(False, f"{a[0]}:{a[1]} için servis adı ya da sürüm yanlış. Beklenen biçim: servis adı küçük harf "
                     "(http, ssh, smtp...), sürüm alanı yazılımın sürüm numarasını içermeli.", yakin=True)
    sirali = sorted(gorulen, key=lambda a: (_ana_say(a[0]), a[1]))
    sira_dosya = []
    for satir in csv.reader(satirlar):
        sira_dosya.append((satir[0].strip(), int(satir[1])))
    if sira_dosya != sirali:
        return Sonuc(False, "Satırlar IP'ye (sayısal) sonra porta göre sıralı olmalı. Sayısal IP sıralaması için "
                     "`sort -t, -k1,1V -k2,2n` gibi bir şey düşün.", yakin=True)
    return Sonuc(True, f"Envanter hazır: {len(gorulen)} kapsam içi servis, tekrarsız ve sıralı. Rapora girecek tablo tam bu.")


def _blokta(ip: str, blok) -> bool:
    try:
        return ipaddress.ip_address(ip) in blok
    except ValueError:
        return False


def _kapsam_hata(g, beklenen, b):
    return None


def _sayi_hata(g, beklenen, b):
    return b.senaryo["yanlis_say"].get(str(g))


def _oncelik_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["hariclenen"]:
        return "Bu IP kapsam dışı (kapsam.txt'te açıkça hariç): hiç hesaba katma."
    if g in (s["cdn_ip"], s["sp_ip"]):
        return "Bu adres müşterinin değil, bir üçüncü tarafın (kapsam dışı)."
    return None


# ---------------------------------------------------------------- test çözücüsü

_ENVANTER_PY = """
import ipaddress, re, glob, csv
s = open('{kl}/kapsam.txt').read()
blok = ipaddress.ip_network(re.search(r'IP bloğu:\\s+(\\S+)', s).group(1))
haric = re.search(r'hariç\\):\\n\\s+(\\S+)', s).group(1)
girdi = {{}}
mevcut = None
for satir in open('{kl}/nmap_ciktisi.txt'):
    m = re.match(r'Nmap scan report for (\\S+)', satir)
    if m:
        mevcut = m.group(1)
    m = re.match(r'(\\d+)/tcp\\s+open\\s+(\\S+)\\s+(.*)$', satir)
    if m and mevcut:
        girdi[(mevcut, int(m.group(1)))] = (m.group(2), m.group(3).strip())
for satir in open('{kl}/shodan_notu.txt'):
    m = re.match(r'\\s+(\\S+) port (\\d+) -> (\\w+) ([\\d.]+)', satir)
    if m:
        girdi[(m.group(1), int(m.group(2)))] = (m.group(3).lower(), m.group(3) + ' ' + m.group(4))
satirlar = [(ip, p, sv[0], sv[1]) for (ip, p), sv in girdi.items()
            if ipaddress.ip_address(ip) in blok and ip != haric]
satirlar.sort(key=lambda x: (tuple(map(int, x[0].split('.'))), x[1]))
with open('envanter.csv', 'w', newline='') as f:
    w = csv.writer(f)
    w.writerow(['ip', 'port', 'servis', 'surum'])
    w.writerows(satirlar)
"""


def coz(lab: Path, s: dict) -> dict:
    kl = s["v"]["klasor"]
    o.sh("python3 - <<'PY'\n" + _ENVANTER_PY.format(kl=kl) + "\nPY", lab)
    sayi = o.sh("tail -n +2 envanter.csv | wc -l", lab)
    kapsam_disi = o.sh(
        "python3 - <<'PY'\nimport glob, ipaddress, re\n"
        f"s = open('{kl}/kapsam.txt').read()\n"
        "blok = ipaddress.ip_network(re.search(r'IP bloğu:\\s+(\\S+)', s).group(1))\n"
        "haric = re.search(r'hariç\\):\\n\\s+(\\S+)', s).group(1)\n"
        "gorulen = set()\n"
        f"for f in glob.glob('{kl}/*'):\n"
        "    if f.endswith('kapsam.txt'):\n        continue\n"
        "    gorulen |= set(re.findall(r'\\b\\d+\\.\\d+\\.\\d+\\.\\d+\\b', open(f).read()))\n"
        "print(*sorted(ip for ip in gorulen if ipaddress.ip_address(ip) not in blok or ip == haric))\nPY", lab)
    skorlar = o.sh(
        "python3 - <<'PY'\nimport csv, collections\n"
        "w = {'eski': 3, 'kimliksiz': 3, 'panel': 2, 'metin': 2}\n"
        "sk = collections.Counter()\n"
        "for r in csv.DictReader(open('envanter.csv')):\n"
        "    sur, ip = r['surum'], r['ip']\n"
        "    port = int(r['port'])\n"
        "    if r['servis'] == 'ftp': sk[ip] += 2\n"
        "    if port == 8080: sk[ip] += 2\n"
        "    if r['servis'] in ('redis', 'elasticsearch'): sk[ip] += 3\n"
        "    eski = {'Exim 4.87', 'vsftpd 2.3.4', 'Tomcat 8.5.9', 'Redis 4.0.9', 'Elasticsearch 1.4.2'}\n"
        "    if sur in eski: sk[ip] += 3\n"
        "print(sk.most_common(1)[0][0])\nPY", lab)
    return {1: kapsam_disi, 2: sayi, 3: "", 4: skorlar, 5: o.secmeli_cevap(SEVIYE, s, lab, 5),
            6: o.secmeli_cevap(SEVIYE, s, lab, 6), 7: o.secmeli_cevap(SEVIYE, s, lab, 7)}


ADIMLAR = [
    Adim("Dağınıklığın bedeli", """
Keşifte en sık yapılan hata dağınık çalışmaktır: yüzlerce alt alan adı, onlarca açık port, çeşitli teknolojiler...
Düzenli tutmazsan en değerli bulgu gürültüde kaybolur ve rapor yazarken "bir şey bulmuştum ama nerede
yazdığımı unuttum" olur. İyi keşif, iyi not tutmaktır.

Her hedef için tutarlı bir klasör yapısı kullan:

```
hedef/
├── kapsam.txt          test edilebilir IP ve alan adları
├── pasif/              alt alanlar, OSINT notları
├── aktif/              nmap çıktıları, web dizinleri
├── bulgular.md         ilginç olan her şey (ne/nerede/neden önemli/sonraki adım)
```

Bu görevde dört kişinin biçimsiz notlarını tek bir envantere çevireceksin.
""", calistir=False),
    Adim("Ham notlar", """
<<klasor>> klasöründe dört kişinin notları var; her biri başka bir biçimde. Önce hangi dosyalar olduğuna bak:
""", komut="ls <<klasor>>", sonra="""
Beş dosya: kapsam (sözleşmeden), nmap çıktısı, Shodan notu, DNS notu ve web notu. Aynı servis birden fazla notta
geçebilir (tekrar); farklı kaynaklar farklı portları görmüş olabilir (nmap `-F` yalnızca yaygın portları tarar).
"""),
    Adim("Önce kapsam", """
**Kapsam**, sözleşmede yazan test edilebilir varlıklar listesidir. Kapsam dışındaki hiçbir şeye dokunulmaz,
**hatta raporda da yer almaz**: bulduğun şey kapsam dışıysa, ne kadar ilginç olursa olsun, test etmeye çalışmak
yetkisiz erişimdir. Kapsam dosyasını oku:
""", komut="cat <<klasor>>/kapsam.txt", sonra="""
Kapsam bir **IP bloğu** (<<blok>>: yani o aralıktaki 14 kullanılabilir adres) ve bazı **açıkça hariç tutulan**
adresler içeriyor. Bir adresin kapsamda olması için hem blokta olmalı hem de hariç listesinde olmamalı. Bulut
sağlayıcı, CDN ve e-posta servis sağlayıcısı adresleri baştan dışarıda: onlar müşterinin değil.
"""),
    Adim("Nmap çıktısından ayıklamak", """
`nmap` çıktısının her makine bölümü `Nmap scan report for <IP>` ile başlar, açık portlar `open` içeren satırlardır.
Sadece bu satırları süzelim:
""", komut="grep -E 'report for|open' <<klasor>>/nmap_ciktisi.txt", sonra="""
Beş makinenin açık servisleri var; bunlardan biri kapsam dışı. `closed` satırlar envantere girmez (kapalı port bir
servis değildir). Aynı işi `awk` ya da python ile makine/port/servis/sürüm alanlarına bölerek yapabilirsin.
"""),
    Adim("Envanter biçimi", """
Envanter, kapsam içi her açık servis için bir satır içeren bir CSV dosyasıdır:

```
ip,port,servis,surum
198.51.100.33,22,ssh,OpenSSH 9.2p1
198.51.100.33,80,http,nginx 1.24.0
```

Kurallar: ilk satır başlık; her satırda tam 4 alan; `servis` küçük harfli ad (`http`, `ssh`, `smtp`...); `surum`
yazılımın adı ve sürüm numarası; satırlar **IP'ye (sayısal) sonra porta** göre sıralı; aynı ip:port **bir kez**.
Önemli: nmap'te olmayan ama Shodan notunda bulunan bir servis de envantere girer; bulgunun kaynağı önemli değil,
gerçek olması önemli. Görevde bu dosyayı sen yazacaksın.
""", calistir=False),
    Adim("Önceliklendirme ve bulgu notu", """
Keşfin sonunda elinde bir **öncelik listesi** olmalı: en umut verici giriş noktaları en üstte. Selin'in puan
tablosuna bak:
""", komut="cat oncelik_kurallari.txt", sonra="""
İyi bir öncelik listesi üç şeye bakar: eski/yamasız sürümler, varsayılan kimlik bilgisi olabilecek paneller ve
kimlik doğrulaması olmayan servisler. Her bulguyu aynı kalıpla not et:

- **Ne** bulundu? **Nerede** (IP/URL)? **Neden önemli**? **Sonraki adım** ne?

Örnek: "Yönetim paneli (8080/tcp) 10.0.0.9 üzerinde, Tomcat 8.5.9. Giriş sayfası dışarıya açık ve sürüm eski. Sonraki
adım: sürümün bilinen zafiyetlerini ve varsayılan kimlik bilgisi olup olmadığını araştırmak." Notlar yalnızca düzen için değil, **rapor** (Cilt 8) için de hammaddedir.
""")
]

GOREVLER = [
    Gorev("<<klasor>> altındaki notlarda geçen IP adreslerinden **kapsam dışı** olanların hepsini yaz. "
          "(Blok dışındakiler ve açıkça hariç tutulan adres.)",
          Kume("kapsam_disi", tur="ip", sik_hatalar=_kapsam_hata),
          ("Kapsam: <<blok>> bloğu, <<hariclenen>> hariç. Notlardaki her IP'yi bu kurala göre sınıflandır.",
           "Önce notlardaki bütün IP'leri çıkar (`grep -oE '[0-9.]+' ...` ya da `grep -rhoE`), sonra blokta olmayanları ve "
           "hariç tutulanı ayır.",
           "CDN adresi ve e-posta sağlayıcısı blok dışında, iş ortağı adresi blok içinde ama kapsam.txt'de açıkça hariç."),
          puan=30, baslik="Kapsam dışı olanlar"),
    Gorev("Kapsam içi, tekrarsız **kaç ip:port servisi** var? (nmap'te olmayan ama Shodan notunda bulunan da dahil.)",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Aynı servis birden çok notta geçebilir; kapsam dışı olanlar sayılmaz.",
           "Kaynakları birleştir: nmap'in open satırları + Shodan'daki ek servis; kapsam dışını çıkar.",
           "Envanteri önce hazırla (bir sonraki görev); sonra `tail -n +2 envanter.csv | wc -l`."),
          puan=25, baslik="Kaç servis"),
    Gorev("Kapsam içi bütün açık servisleri, adımdaki biçimde `envanter.csv` dosyasına yaz (başlık, tekrarsız, "
          "IP+port sıralı, kapsam dışı yok, Shodan'daki ek servis dahil). Bulunduğun klasörde oluştur; sonra "
          "`cevap <no>` yaz.",
          Durum(_envanter_denetle,
                "python3 ile <<klasor>>/nmap_ciktisi.txt (open satırları) + <<klasor>>/shodan_notu.txt'deki 'port N ->' "
                "satırını birleştir, <<blok>> dışını ve <<hariclenen>>'i at, IP'ye ve porta göre sırala, "
                "ip,port,servis,surum başlığıyla envanter.csv'ye yaz"),
          ("Üç kaynağı birleştireceksin: nmap, Shodan notundaki ek servis ve kapsam kuralı.",
           "Elle yazmak da olur (az satır var), ama `grep`/`awk`/python ile ayıklayıp `sort -t, -k1,1V -k2,2n` ile sıralamak "
           "daha güvenli.",
           "Başlığı `echo 'ip,port,servis,surum' > envanter.csv` ile yaz, satırları `>>` ile ekle ve en sonda sırala."),
          puan=50, baslik="Envanter dosyası"),
    Gorev("`oncelik_kurallari.txt`'deki puan tablosuna göre, kapsam içi makineler arasında **en yüksek toplam puanı** "
          "alan makinenin IP'si hangisi?",
          IP("en_oncelikli", sik_hatalar=_oncelik_hata),
          ("Her servisin puanı özelliklerine bağlı (eski, kimliksiz, panel, açık metin). Makinenin puanı servislerin toplamı.",
           "Envanterdeki her servisin puanını hesapla, IP'ye göre topla. Kapsam dışını hesaba katma.",
           "Redis ve Elasticsearch eski + kimliksiz (6 puan); FTP eski + açık metin (5); Tomcat paneli eski + panel (5); "
           "Exim eski (3). Aynı makinedeki servisler toplanır."),
          puan=35, baslik="En öncelikli makine"),
    Gorev("İyi bir keşif öncelik listesinde **en üstte** hangi tür bulgular yer almalıdır?",
          Secmeli([
              ("Yamasız eski sürümler, kimliksiz servisler ve varsayılan parolalı olabilecek yönetim panelleri",
               "Doğru. Bunlar saldırganın en az emekle ilerleyebileceği ve etkisi en yüksek giriş noktalarıdır."),
              ("Sayfa başlığı, renk ve yazı tipi gibi sitenin görünüşüyle ilgili tutarsızlıklar ve küçük yazım hataları",
               "Görünüş sorunları güvenlik riski taşımaz; öncelik listesinde yeri yok."),
              ("En çok açık portu olan makine, üzerinde hangi servis çalışırsa çalışsın, çünkü en büyük saldırı yüzeyi odur",
               "Açık port sayısı tek başına risk değildir; tek bir kimliksiz eski servis, on güncel servisten daha tehlikelidir."),
              ("En son bulunan bulgular, çünkü en taze oldukları için henüz kimse tarafından düzeltilmemiştir",
               "Bulgunun ne zaman bulunduğu önceliği belirlemez; etkisi ve istismar kolaylığı belirler."),
          ], dogru=0),
          ("Saldırgan hangi giriş noktasından en az emekle ve en çok etkiyle ilerler?",
           "Üç tür var: sürüm, kimlik doğrulama, yönetim arayüzü.",
           "Eski + kimliksiz + panel."),
          puan=20, baslik="Önceliklendirme"),
    Gorev("Aşağıdaki bulgu notlarından hangisi **ne, nerede, neden önemli ve sonraki adım** dörtlüsünü eksiksiz "
          "içeriyor?",
          Secmeli([
              ("Açık FTP (21/tcp) 10.0.0.5 üzerinde, vsftpd 2.3.4: sürüm eski, şifresiz protokol; sonraki adım "
               "zafiyet araştırması.",
               "Doğru. Ne (FTP, vsftpd 2.3.4), nerede (IP:port), neden önemli (eski ve şifresiz), sonraki adım var."),
              ("Sunucuda FTP açık görünüyor ve sürümü bayağı eski, bence bu çok tehlikeli, ileride mutlaka tekrar "
               "bakılmalı, belki bir şeyler çıkar.",
               "Nerede (hangi IP ve port) yok; neden tehlikeli olduğu da ölçülebilir değil. Yazmayı unutan, bulamaz."),
              ("10.0.0.5 ilginç, FTP ve belki başka şeyler var, sürümüne ayrıca bakmak lazım, Mert'e sorulabilir "
               "bir konu gibi görünüyor.",
               "Ne bulunduğu net değil (hangi servis, hangi sürüm), neden önemli olduğu ve sonraki adım da yok."),
              ("vsftpd 2.3.4 çalışıyor; açık metin protokol ve eski sürüm olduğu için risk yüksek, ilerleyen aşamada "
               "ele alınacak bir madde.",
               "Nerede yok (hangi sunucu?) ve sonraki adım belirsiz. Rapora girecek bulgunun adresi olmalı."),
          ], dogru=0),
          ("Dört parça: ne, nerede, neden önemli, sonraki adım.",
           "Hangi not, kimse sana sormadan bulguyu yeniden bulabilecek kadar ayrıntılı?",
           "Hem IP:port hem sürüm hem gerekçe hem eylem içeren."),
          puan=25, baslik="Bulgu notu"),
    Gorev("Notlarda, kapsam dışı iş ortağı sunucusunda kimliksiz bir Redis olduğunu gördün. Ne yaparsın?",
          Secmeli([
              ("Dokunmaz, envantere almaz; kapsam dışı gözlem olarak Selin'e ve müşteriye bildirirsin",
               "Doğru. Kapsam dışına dokunulmaz; ama gözlemi yetkililere bildirmek sorumlu davranıştır."),
              ("Hızlıca bağlanıp gerçekten kimliksiz olduğunu doğrularsın, sonra yetkililere bildirirsin",
               "Bağlanmak kapsam dışı bir sisteme yetkisiz erişimdir; doğrulamak için bile yapılmaz."),
              ("Raporun kapsam içi bulgular bölümüne en yüksek öncelikle eklersin, çünkü çok kritik bir durum",
               "Kapsam dışı bir varlık, ne kadar kritik olursa olsun, kapsam içi bulgu listesine girmez."),
              ("Hiçbir şey yapmaz ve kimseye söylemezsin, çünkü bu senin işin değil, kapsam dışı",
               "Sessiz kalmak da doğru değil: müşterinin riski bilmesi gerekir; gözlemi kayıtlı kanalla ilet."),
          ], dogru=0),
          ("Kapsam dışına dokunmak ve kapsam dışını görmek ayrı şeyler.",
           "Gözlemi kime, hangi kanaldan iletirsin?",
           "Dokunma, envantere alma, bildir."),
          puan=25, baslik="Kapsam dışı bulgu"),
]

SEVIYE = Seviye(
    kimlik="c04b06",
    cilt=4,
    bolum=6,
    baslik="Bulguları Düzenlemek",
    brifing="""
**<<musteri>>** keşfinin dağınık notları <<klasor>> klasöründe. Selin'in isteği: kapsam kuralına uyan,
tekrarsız, sıralı bir envanter ve bir öncelik listesi. Kapsam bloğu **<<blok>>**; <<hariclenen>> açıkça dışarıda.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Dört kişinin dört biçimli notundan, kapsam kuralına uyan, tekrarsız ve sıralı bir envanter çıkardın ve en öncelikli
makineyi bir puan tablosuyla belirledin. Bu disiplin, gerçek bir sızma testinde keşif ile saldırı arasındaki köprüdür:
bir sonraki aşama bu listeyi alıp sırayla deneyecek. Kapsam dışı bir şeye dokunmamak ve gözlemi bildirmek ise hem
hukuki hem profesyonel sınırındır. Savunma tarafında da aynı envanter, müşterinin kendi saldırı yüzeyini bilmesinin
ve yama önceliğini belirlemesinin temelidir.
""",
    gercek_hayat="""
- **Kapsam dışına taşmak:** Sözleşmede yazmayan bir sisteme dokunmak, niyet iyi olsa bile yetkisiz erişim sayılır
  (TCK 243). Pek çok sızma testi sözleşmesi kapsam dışı bir bulgu görüldüğünde dokunmadan bildirilmesini şart koşar.
  Önleme: kapsamı yazılı al, araçlara hedef olarak yalnızca kapsam listesini ver. Tespit: tarama araçlarının hedef
  listesini kapsam listesiyle otomatik karşılaştıran bir kontrol.
- **Envanter eksikliği, ihlalin ortak nedeni:** Birçok büyük ihlalde saldırganın girdiği sistem, kurumun envanterinde
  olmayan ya da unutulmuş bir sistemdi. Güncel bir varlık envanteri, yama önceliğinin başlangıcıdır. Tespit: dışarıdan
  düzenli keşifle bulunan her varlığı envanterle karşılaştırmak.
- **Önceliklendirme ve yama:** Equifax 2017 örneğinde, yaması çıkmış bir Apache Struts açığı uygulanmamıştı; bunun
  gibi bilinen zafiyetli sürümler öncelik listesinin en üstüne konmalıdır. Önleme: sürüm eşik listesi ve düzenli
  tarama.
""",
    sure_hedef_dk=35,
)
