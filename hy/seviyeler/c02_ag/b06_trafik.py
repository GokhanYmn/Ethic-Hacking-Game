"""Cilt 2 · Bölüm 6 — Trafiği Dinlemek: tcpdump ve Wireshark.

Beceri: bir pcap dosyasını `tcpdump -r` ile okumak (root gerekmez), `-nn`, `-A`, `-v`, `-c`
seçenekleri, `host` / `port` / `tcp[tcpflags]` filtreleri, tcpdump çıktısını awk/sort/uniq ile
saymak; port taramasını, düz metin parolayı, en çok konuşan makineyi ve şüpheli DNS sorgusunu
yakalamak.

Lab: `hy.ortak.ag.Pcap` ile üretilmiş küçük (onlarca KB) ve geçerli bir pcap: normal HTTPS ve DNS
trafiği, bir SYN taraması, düz metin bir giriş (FTP / HTTP Basic Auth / HTTP POST) ve dışarıya
veri kaçıran bir makine.

Vakalar: lojistik deposu (FTP), kafe (modem paneline Basic Auth), belediye (eski panele POST),
hastane (laboratuvar cihazına Basic Auth).
"""
from __future__ import annotations

import base64
import random
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "kuzgun", "klasor": "yakalamalar", "pcap": "depo_gece.pcap", "protokol": "ftp",
        "kullanicilar": ["terminal_guncelle", "depo_ftp", "el_terminal"],
        "normal": ["stok.kuzgun.lab", "www.kuzgun.lab", "guncelleme.terminalos.lab", "harita.rotalab.lab",
                   "kargo-api.kuzgun.lab"],
        "supheli": ["cdn-guncelleme-servisi.lab", "depo-yedek-bulut.lab", "telemetri-toplayici.lab"],
        "brifing": """
Gece 02.10'da **Kuzgun Lojistik**'in depo ağındaki sensör bir alarm üretti; **Deniz** o
dakikaların trafiğini kaydetmiş: `<<klasor>>/<<pcap>>`. Sabah kahvesini bırakıp ekranı sana
çeviriyor: "Üç şey arıyorum. Biri ağı tarıyor mu? Biri parolasını açık metin gönderiyor mu?
Biri dışarıya veri kaçırıyor mu?"

Selin: "tcpdump ile oku. Canlı dinlemek root ister ama kaydedilmiş bir dosyayı okumak istemez.
Her cevabı bir filtreyle kanıtla."

Mert: "Ve depo terminallerinin hâlâ FTP kullandığına bahse girerim."
""",
    },
    {
        "kod": "atolye", "klasor": "kafe_kayit", "pcap": "kafe_ag.pcap", "protokol": "basic",
        "kullanicilar": ["admin", "berk", "yonetici"], "basic_yol": "/cgi-bin/yonetim",
        "realm": "Modem Yonetim Paneli", "basic_sunucu": "mini_httpd/1.30",
        "normal": ["www.atolye.lab", "odeme.paramix.lab", "muzik-akis.lab", "harita.rotalab.lab",
                   "sosyal-ag.lab"],
        "supheli": ["foto-yedekle-ucretsiz.lab", "kupon-kazan.lab", "hizli-vpn-bedava.lab"],
        "brifing": """
**Atölye Kahve**'de Berk, kafe ağında garip şeyler olduğundan şüpheleniyor: modemin ayarları
kendi kendine değişmiş gibi. Deniz kafeye küçük bir cihaz bırakıp birkaç dakikalık trafik
kaydetti: `<<klasor>>/<<pcap>>`.

Deniz: "Misafir Wi-Fi'ı ile kasa aynı ağda. Yani buradaki herkes, herkesin trafiğini
görebilir. Bakalım bu kayıtta neler var: tarama, açık metin parola, dışarı giden veri..."

Selin: "Kayıt dosyasını okumak root istemez. `tcpdump -r` ile başla."
""",
    },
    {
        "kod": "yesiltepe", "klasor": "dmz_kayit", "pcap": "belediye_dmz.pcap", "protokol": "post",
        "kullanicilar": ["bilgiislem", "yonetici01", "admin_eski"], "post_yol": "/yonetim/giris.php",
        "alanlar": ("sicil", "sifre"),
        "normal": ["ebelediye.yesiltepe.lab", "www.yesiltepe.lab", "imar.yesiltepe.lab", "kamuposta.lab",
                   "guncelleme.ofisyazilim.lab"],
        "supheli": ["belge-arsiv-yukle.lab", "e-imza-guncelle.lab", "veri-aktarim-servisi.lab"],
        "brifing": """
**Yeşiltepe Belediyesi**'nin DMZ ağında (internete açık sunucuların durduğu bölge) dün akşam
bir trafik artışı görüldü. Nurcan Hanım'ın ekibi ağ anahtarının ayna portundan birkaç
dakikalık kayıt aldı ve Kalkan'a gönderdi: `<<klasor>>/<<pcap>>`.

Deniz: "SOC'ta bir kayıt geldiğinde hep aynı üç soruyu sorarım: kim kiminle konuşuyor, hangi
protokolle, içerik ne? Sen de öyle yap."

Mert: "Eski yönetim paneli hâlâ düz HTTP ile çalışıyorsa, parolayı okumak için hacker olmana
gerek yok."
""",
    },
    {
        "kod": "medora", "klasor": "poliklinik_kayit", "pcap": "poliklinik.pcap", "protokol": "basic",
        "kullanicilar": ["labadmin", "servis", "teknisyen"], "basic_yol": "/cihaz/ayarlar",
        "realm": "Analizor Yonetim", "basic_sunucu": "GoAhead-Webs",
        "normal": ["randevu.medora.lab", "portal.medora.lab", "e-recete.saglikbakim.lab",
                   "guncelleme.ofisyazilim.lab", "lab-sonuc.medora.lab"],
        "supheli": ["hasta-dosya-paylas.lab", "pacs-bulut-yedek.lab", "dicom-aktar.lab"],
        "brifing": """
**Medora Sağlık**'ta laboratuvar katındaki bir analiz cihazının ayarlarının değiştiği fark
edildi. Bilgi işlem, o katın ağından birkaç dakikalık trafik kaydı alıp Kalkan'a gönderdi:
`<<klasor>>/<<pcap>>`.

Deniz: "Tıbbi cihazların web arayüzleri çoğu zaman eski ve şifresizdir. Bu kayıtta bir
tarama, bir açık metin giriş ve dışarıya giden şüpheli bir akış görürsem şaşırmam."

Selin: "Kanıt istiyorum: her cevabın arkasında bir tcpdump filtresi olsun."
""",
    },
]

TARAMA_HAVUZU = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521,
                 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]


def _parola(rng) -> str:
    return (rng.choice(["Depo", "Kartal", "Galata", "Yaz", "Kis", "Modem", "Sistem", "Lab", "Servis", "Admin"])
            + rng.choice(["2023", "2024", "2025", "2026", "123", "1907"]) + rng.choice(["", "_x", ".", "_01"]))


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    ag3 = rng.choice([f"10.{rng.randint(1, 250)}.{rng.randint(0, 250)}", f"192.168.{rng.randint(0, 250)}",
                      f"172.{rng.randint(16, 31)}.{rng.randint(0, 250)}"])
    hostlar = [f"{ag3}.{h}" for h in rng.sample(range(10, 240), 7)]
    istemciler, kurban, tarayici, hedef, sunucu_ic = hostlar[:3], hostlar[3], hostlar[4], hostlar[5], hostlar[6]
    gw = f"{ag3}.1"
    dns = f"{ag3}.{rng.choice([2, 3, 53])}"
    kullanici = rng.choice(v["kullanicilar"])
    parola = _parola(rng)
    if v["protokol"] == "basic" and v["kod"] == "atolye":
        parola_sunucu = gw
    else:
        parola_sunucu = sunucu_ic
    parola_istemci = istemciler[1]
    portlar = rng.sample(TARAMA_HAVUZU, rng.randint(16, 24))
    acik = sorted(rng.sample(portlar, rng.randint(2, 4)))
    kullanilan: set = set()
    normal = []
    for alan in rng.sample(v["normal"], 4):
        ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(ip)
        normal.append((alan, ip))
    exfil_ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
    supheli = rng.choice(v["supheli"])
    s = {
        "vaka": f"{m['ad']} — {v['pcap']} trafik kaydı",
        "brifing": v["brifing"],
        "v": v, "ag3": ag3, "gw": gw, "dns": dns, "istemciler": istemciler, "kurban": kurban,
        "tarayici": tarayici, "hedef": hedef, "parola_istemci": parola_istemci, "parola_sunucu": parola_sunucu,
        "kullanici": kullanici, "parola": parola, "portlar": portlar, "acik": acik, "normal": normal,
        "exfil_ip": exfil_ip, "exfil_port": rng.choice([443, 8443, 9001]), "supheli": supheli,
        "pcap_tohum": rng.randint(1, 10**9), "t0": u.gun(rng).timestamp() + rng.randint(1, 4) * 3600 + rng.randint(0, 3000),
    }
    p = _pcap_kur(s)
    sayac = p.kaynak_sayilari()
    en_cok = max(sayac, key=lambda ip: sayac[ip])
    s["metin"] = {
        "musteri": m["ad"], "klasor": v["klasor"], "pcap": v["pcap"], "ornek_ip": istemciler[0],
        "hedef": hedef,
    }
    s["cevaplar"] = {
        "paket": p.paket_sayisi(),
        "tarayici": tarayici,
        "port_sayisi": len(portlar),
        "acik": acik,
        "parola": parola,
        "en_cok": en_cok,
        "supheli": [supheli, supheli + "."],
    }
    return s


def _rb(r: random.Random, n: int) -> bytes:
    return r.randbytes(n)


def _parola_oturumu(p, r, s, t):
    v = s["v"]
    ist, srv, k, pw = s["parola_istemci"], s["parola_sunucu"], s["kullanici"], s["parola"]
    if v["protokol"] == "ftp":
        o = p.tcp_oturum(ist, r.randint(40000, 60999), srv, 21, t, rtt=0.002)
        o.el_sikis()
        o.sunucu("220 (vsFTPd 3.0.5)\r\n")
        for istek, cevap in [(f"USER {k}\r\n", "331 Please specify the password.\r\n"),
                             (f"PASS {pw}\r\n", "230 Login successful.\r\n"),
                             ("SYST\r\n", "215 UNIX Type: L8\r\n"),
                             ("TYPE I\r\n", "200 Switching to Binary mode.\r\n"),
                             ("QUIT\r\n", "221 Goodbye.\r\n")]:
            o.istemci(istek, bekle=r.uniform(0.2, 0.8))
            o.sunucu(cevap)
        o.kapat()
    elif v["protokol"] == "basic":
        host = srv
        o = p.tcp_oturum(ist, r.randint(40000, 60999), srv, 80, t, rtt=0.002)
        o.el_sikis()
        o.istemci(ag.http_istek("GET", v["basic_yol"], host))
        o.sunucu(ag.http_yanit(401, "<h1>401 Unauthorized</h1>", {"WWW-Authenticate": f'Basic realm="{v["realm"]}"'},
                               sunucu=v["basic_sunucu"]))
        o.kapat()
        jeton = base64.b64encode(f"{k}:{pw}".encode()).decode()
        o = p.tcp_oturum(ist, r.randint(40000, 60999), srv, 80, o.t + r.uniform(2, 4), rtt=0.002)
        o.el_sikis()
        o.istemci(ag.http_istek("GET", v["basic_yol"], host, {"Authorization": f"Basic {jeton}"}))
        o.sunucu(ag.http_yanit(200, f"<html><title>{v['realm']}</title><body>Ayarlar</body></html>",
                               sunucu=v["basic_sunucu"]))
        o.kapat()
    else:
        ka, pa = v["alanlar"]
        o = p.tcp_oturum(ist, r.randint(40000, 60999), srv, 80, t, rtt=0.002)
        o.el_sikis()
        o.istemci(ag.http_istek("POST", v["post_yol"], f"yonetim.{musteri(v['kod'])['alan']}",
                                govde=f"{ka}={k}&{pa}={pw}"))
        o.sunucu(ag.http_yanit(302, "", {"Location": "/yonetim/panel.php",
                                         "Set-Cookie": f"PHPSESSID={_rb(r, 13).hex()}; path=/"},
                               sunucu="Apache/2.2.15 (CentOS)"))
        o.kapat()


def _pcap_kur(s: dict) -> ag.Pcap:
    """Senaryodan pcap'i kurar. Saf: aynı senaryo hep aynı baytları üretir."""
    r = random.Random(s["pcap_tohum"])
    p = ag.Pcap(yerel=f"{s['ag3']}.0/24", ag_gecidi=s["gw"])
    t0 = s["t0"]
    istemciler = s["istemciler"] + [s["kurban"]]
    # normal trafik: DNS + HTTPS; zaman dilimleri şüpheli olaylarla çakışmasın
    dilimler = [1, 9, 17, 27, 44, 63, 78]
    for i, dilim in enumerate(dilimler):
        ist = istemciler[i % len(istemciler)]
        alan, ip = s["normal"][i % len(s["normal"])]
        t = t0 + dilim + r.uniform(0, 2)
        p.dns(ist, s["dns"], alan, "A", [ip], t=t)
        p.tls_oturumu(ist, ip, t + 0.05, r)
    # biri ağ geçidine ping atıyor
    ping_ist = s["istemciler"][2]
    for k in range(4):
        tp = t0 + 70 + k
        p.icmp_echo(tp, ping_ist, s["gw"], 0x1a2b, k + 1)
        p.icmp_echo(tp + 0.0011, s["gw"], ping_ist, 0x1a2b, k + 1, cevap=True)
    # düz metin giriş
    _parola_oturumu(p, r, s, t0 + 22 + r.uniform(0, 1))
    # SYN taraması
    p.syn_tarama(s["tarayici"], s["hedef"], s["portlar"], s["acik"], t=t0 + 33 + r.uniform(0, 2),
                 aralik=r.uniform(0.001, 0.003))
    # veri kaçırma: önce DNS, sonra çok sayıda küçük segment
    te = t0 + 52 + r.uniform(0, 1)
    p.dns(s["kurban"], s["dns"], s["supheli"], "A", [s["exfil_ip"]], t=te)
    o = p.tcp_oturum(s["kurban"], r.randint(40000, 60999), s["exfil_ip"], s["exfil_port"], te + 0.05,
                     rtt=r.uniform(0.04, 0.07), mss=r.choice([360, 400, 440]))
    o.el_sikis()
    o.istemci(b"\x16\x03\x01\x01\xfc" + _rb(r, 300))
    o.sunucu(b"\x16\x03\x03" + _rb(r, 900))
    o.istemci(b"\x17\x03\x03" + _rb(r, o.mss * r.randint(70, 90) - 3), ack_aralik=2)
    o.kapat()
    return p


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    _pcap_kur(s).kaydet(lab / v["klasor"] / v["pcap"])
    u.yaz(lab / "OKUBENI.txt",
          f"Trafik kaydı: {v['klasor']}/{v['pcap']}\n\n"
          "Dosyadan okumak root istemez:\n"
          f"  tcpdump -nn -r {v['klasor']}/{v['pcap']}\n\n"
          "Wireshark kuruluysa aynı dosyayı grafik arayüzle de açabilirsin:\n"
          f"  wireshark {v['klasor']}/{v['pcap']} &\n")


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: gerçek tcpdump çıktısını awk/sort/uniq ile işler."""
    f = f"{s['v']['klasor']}/{s['v']['pcap']}"
    td = f"tcpdump -nn -r {f}"
    paket = _sh(f"{td} 2>/dev/null | wc -l", lab)
    tarayici = _sh(f"{td} 'tcp[tcpflags] == tcp-syn' 2>/dev/null | awk '{{print $3}}' | cut -d. -f1-4 "
                   "| sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    port_sayisi = _sh(f"{td} 'src host {tarayici} and tcp[tcpflags] == tcp-syn' 2>/dev/null "
                      "| awk '{print $5}' | cut -d. -f5 | tr -d ':' | sort -u | wc -l", lab)
    acik = _sh(f"{td} 'dst host {tarayici} and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)' 2>/dev/null "
               "| awk '{print $3}' | cut -d. -f5 | sort -n | tr '\\n' ' '", lab)
    proto = s["v"]["protokol"]
    if proto == "ftp":
        parola = _sh(f"tcpdump -nn -A -r {f} port 21 2>/dev/null | grep -a -o 'PASS [^[:space:]]*' | head -1 "
                     "| awk '{print $2}'", lab)
    elif proto == "basic":
        parola = _sh(f"tcpdump -nn -A -r {f} port 80 2>/dev/null | grep -a -o 'Authorization: Basic [A-Za-z0-9+/=]*' "
                     "| head -1 | awk '{print $3}' | base64 -d | cut -d: -f2-", lab)
    else:
        ka, pa = s["v"]["alanlar"]
        parola = _sh(f"tcpdump -nn -A -r {f} port 80 2>/dev/null | grep -a -o '{pa}=[^&[:space:]]*' | head -1 "
                     "| cut -d= -f2", lab)
    en_cok = _sh(f"{td} 2>/dev/null | awk '{{print $3}}' | cut -d. -f1-4 | sort | uniq -c | sort -rn "
                 "| head -1 | awk '{print $2}'", lab)
    hedef_ip = _sh(f"{td} 'src host {en_cok} and not port 53' 2>/dev/null | awk '{{print $5}}' | cut -d. -f1-4 "
                   "| sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    supheli = _sh(f"tcpdump -nn -v -r {f} port 53 2>/dev/null | grep -o '[^ ]* A {hedef_ip} ' | head -1 "
                  "| awk '{print $1}'", lab)
    return {1: paket, 2: tarayici, 3: port_sayisi, 4: acik, 5: parola, 6: en_cok, 7: supheli,
            8: _secmeli(s, lab, 8), 9: _secmeli(s, lab, 9)}


# ---------------------------------------------------------------- sık hatalar

def _paket_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla: 'reading from file...' satırını da saymış olabilirsin. O satır stderr'e gider; `2>/dev/null` ekle."
    if n > beklenen * 2:
        return "Çok fazla: `-A` ya da `-v` ile her paket birden çok satır basar. Saymak için sadece `-nn` kullan."
    return None


def _tarayici_hata(g, beklenen, b):
    if g == b.senaryo["hedef"]:
        return "Bu taranan sunucu: SYN'leri ALAN taraf. Bağlantı isteklerini GÖNDEREN adresi ara."
    return None


def _port_sayisi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == len(b.senaryo["acik"]):
        return "Bu açık bulunan portların sayısı. Soru, tarayıcının DENEDİĞİ bütün portları soruyor."
    if n == beklenen + len(b.senaryo["acik"]):
        return "Tarayıcının açık portlara gönderdiği RST paketlerini de saymışsın. Sadece SYN'lere bak."
    return None


def _parola_hata(g, beklenen, b):
    s = b.senaryo
    jeton = base64.b64encode(f"{s['kullanici']}:{s['parola']}".encode()).decode()
    if g == jeton.casefold():
        return "Bu Base64 ile kodlanmış hali; şifreleme değil, sadece kodlama. `echo ... | base64 -d` ile çöz."
    if g == f"{s['kullanici']}:{s['parola']}".casefold():
        return "Neredeyse! `kullanıcı:parola` biçiminde; sadece iki noktadan sonrasını yaz."
    if g == s["kullanici"].casefold():
        return "Bu kullanıcı adı. Parola bir sonraki satırda/alanda."
    return None


def _en_cok_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["exfil_ip"]:
        return "Bu dışarıdaki sunucu; o sadece onay (ACK) gönderiyor, her iki segmentte bir. Asıl veriyi gönderen kim?"
    if g == s["tarayici"]:
        return "Tarayıcı çok sayıda SYN gönderdi ama toplamda daha az paket. Bütün paketlerin kaynağını say."
    return None


def _supheli_hata(g, beklenen, b):
    for alan, _ip in b.senaryo["normal"]:
        if g.rstrip(".") == alan:
            return "Bu alan adı başka bir IP'ye çözülüyor. Verinin gittiği IP'yi DNS cevaplarında ara."
    return None


ADIMLAR = [
    Adim("Trafik dinlemek", """
Şimdiye kadar paketlerden söz ettik; bu bölümde onları **göreceğiz**. Trafik dinleme (packet
sniffing) hem saldırının hem savunmanın temel becerisidir.

`tcpdump` ağdan geçen paketleri yakalayıp ekrana yazar. Canlı dinleme root ister:

```
sudo tcpdump -i eth0              # eth0'dan geçen her şey
sudo tcpdump -i eth0 -w kayit.pcap   # dosyaya kaydet
```

Kaydedilmiş bir **pcap** dosyasını okumak ise root istemez: `tcpdump -r dosya.pcap`. Deniz'in
kaydı laboratuvarında:
""", komut="ls -l <<klasor>>"),
    Adim("İlk bakış", """
`-r` dosyadan okur, `-nn` IP ve portları isme çevirmez (hızlı ve net), `-c 8` ilk 8 paketi gösterir:
""", komut="tcpdump -nn -r <<klasor>>/<<pcap>> -c 8", sonra="""
Bir satırın anatomisi: `zaman IP kaynak.port > hedef.port: Flags [..], seq, ack, win, length`.
IP'nin son noktasından sonraki sayı porttur (`10.0.0.5.443` = 10.0.0.5, port 443).

Bayraklar: `[S]` SYN, `[S.]` SYN-ACK, `[.]` ACK, `[P.]` veri (PUSH+ACK), `[F.]` FIN,
`[R]` / `[R.]` RST. UDP satırları (DNS gibi) bayraksızdır; DNS'te `A? ad.` bir sorgu,
`1/0/0 A 1.2.3.4` bir cevaptır. "reading from file..." satırı bilgi mesajıdır (stderr).
"""),
    Adim("Filtreler: host ve port", """
Binlerce paket içinde kaybolmamak için filtre kullanırsın. `host X` X'in gönderdiği ya da aldığı
paketler, `port N` o porttaki trafik; `and`, `or`, `not` ile birleşir. `src host` ve
`dst host` yönü de belirtir:
""", komut="tcpdump -nn -r <<klasor>>/<<pcap>> host <<ornek_ip>> and port 443", sonra="""
Bu, tek bir makinenin HTTPS konuşması: önce el sıkışma (`[S]`, `[S.]`, `[.]`), sonra veri
(`[P.]`), en sonda kapanış (`[F.]`). Bölüm 3'teki el sıkışmayı artık gözünle görüyorsun.
"""),
    Adim("İçeriğe bakmak: -A", """
`-A` paketin içeriğini metin olarak basar; yazdırılamayan baytlar `.` olur. Aynı HTTPS
konuşmasına içerden bakalım:
""", komut="tcpdump -nn -A -r <<klasor>>/<<pcap>> host <<ornek_ip>> and port 443 -c 6", sonra="""
Anlamsız noktalar ve karakterler: TLS ile şifrelenmiş veri böyle görünür. Şifresiz bir
protokolde (FTP, Telnet, düz HTTP) ise kullanıcı adı ve parola aynen okunur.

**Hacker gözüyle:** ARP zehirlemesiyle (Bölüm 2) trafiği kendi üzerinden geçiren bir saldırgan,
tcpdump ile şifresiz protokollerdeki parolaları düz metin olarak okur. Saldırgan için şifresiz
protokoller hediyedir; savunmacı için her yerde HTTPS, SSH ve VPN şarttır. "İç ağ güvenli"
varsayımı ARP zehirlemesi karşısında çöker.
"""),
    Adim("Bayraklara göre süzmek", """
TCP bayraklarına göre de süzebilirsin. Sadece SYN (yeni bağlantı isteği) paketleri:
`'tcp[tcpflags] == tcp-syn'`. Tırnaklar önemli: köşeli parantezleri kabuktan korur.
""", komut="tcpdump -nn -r <<klasor>>/<<pcap>> 'tcp[tcpflags] == tcp-syn' -c 5", sonra="""
Normal bir makine dakikada birkaç SYN gönderir. Tek bir kaynaktan, kısa sürede, **çok sayıda
farklı porta** giden SYN'ler port taramasının imzasıdır. SYN-ACK cevaplarını görmek için:
`'tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)'`.
"""),
    Adim("Saymak: tcpdump + awk + sort + uniq", """
tcpdump'ın çıktısı da bir metin; Cilt 1'deki araçlarla işlenir. Her satırın 3. alanı kaynak
`ip.port`'tur; `cut -d. -f1-4` portu atıp IP'yi bırakır, `sort | uniq -c` sayar. UDP
paketlerini kimin gönderdiğine bakalım:
""", komut="tcpdump -nn -r <<klasor>>/<<pcap>> udp 2>/dev/null | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c",
          sonra="""
`2>/dev/null` "reading from file" satırını gizler. Bu kalıbı `| sort -rn | head` ile bitirirsen
en çok konuşanları sıralarsın. Toplam paket sayısı için `| wc -l`.
"""),
    Adim("Wireshark ve üç soru", """
Wireshark aynı işi grafik arayüzle yapar (Kali'de kurulu: `wireshark dosya.pcap`). Gücü **görüntü
filtrelerinde**dir:

- `http` → sadece HTTP · `dns` → DNS sorgu ve cevapları
- `ip.addr == 10.0.0.5` → bu IP ile ilgili her şey · `tcp.port == 443`
- `tcp.flags.syn == 1` → SYN paketleri (bağlantı / tarama)
- `http.request.method == "POST"` → form gönderimleri

Bir pakete tıkladığında Bölüm 1'deki katmanları iç içe açılmış görürsün: Ethernet, IP, TCP, HTTP.

Hangi aracı kullanırsan kullan, bir kayıtta hep aynı **üç soruyu** sor: **Kim kiminle
konuşuyor?** (IP'ler, portlar) **Hangi protokolle?** (HTTP, DNS, FTP...) **İçerik ne?** (şifreli
mi, düz metin mi; parola, çerez, komut var mı?)
"""),
]

GOREVLER = [
    Gorev("`<<pcap>>` kaydında toplam kaç paket var?",
          Sayi("paket", sik_hatalar=_paket_hata),
          ("Her paket, `-nn` ile tek satır basılır.",
           "tcpdump çıktısını satır sayan bir komuta yönlendir.",
           "`tcpdump -nn -r <<klasor>>/<<pcap>> 2>/dev/null | wc -l`"),
          puan=20, baslik="Kaç paket"),
    Gorev("Kayıtta biri port taraması yapıyor. Taramayı yapan makinenin IP adresi ne?",
          IP("tarayici", sik_hatalar=_tarayici_hata),
          ("Tarama = tek kaynaktan çok sayıda bağlantı isteği (SYN).",
           "Sadece SYN paketlerini süz ve kaynak adresleri say.",
           "`tcpdump -nn -r <<klasor>>/<<pcap>> 'tcp[tcpflags] == tcp-syn' 2>/dev/null | awk '{print $3}' "
           "| cut -d. -f1-4 | sort | uniq -c | sort -rn`"),
          puan=30, baslik="Tarayıcı"),
    Gorev("Tarayıcı, <<hedef>> üzerinde kaç **farklı** portu denedi?",
          Sayi("port_sayisi", sik_hatalar=_port_sayisi_hata),
          ("Tarayıcının gönderdiği SYN'lerin hedef portlarını say; her port bir kez.",
           "`src host TARAYICI` ve SYN filtresini birleştir; 5. alan hedef `ip.port:`'tur.",
           "`... 'src host TARAYICI and tcp[tcpflags] == tcp-syn' | awk '{print $5}' | cut -d. -f5 | sort -u | wc -l`"),
          puan=25, baslik="Kaç port"),
    Gorev("Taramada hangi portlar **açık** çıktı?",
          Kume("acik", tur="sayi", bicim="boşlukla ayrılmış port listesi"),
          ("Açık port, SYN'e SYN-ACK ile cevap verir.",
           "Tarayıcıya giden SYN-ACK paketlerini süz: `dst host TARAYICI` ve SYN-ACK bayrak filtresi.",
           "`tcpdump -nn -r <<klasor>>/<<pcap>> 'dst host TARAYICI and tcp[tcpflags] & (tcp-syn|tcp-ack) == "
           "(tcp-syn|tcp-ack)'`; her satırın kaynak portu açık bir porttur."),
          puan=30, baslik="Açık kapılar"),
    Gorev("Kayıtta şifresiz bir protokolle yapılmış bir giriş var. Kullanılan **parola** ne?",
          Metin("parola", sik_hatalar=_parola_hata, bicim="parola"),
          ("Şifresiz giriş taşıyan tipik portlar: 21 (FTP), 23 (Telnet), 80 (HTTP).",
           "`-A` ile içeriği göster ve port 21 ya da 80'e bak; `PASS`, `Authorization` ya da form alanlarını ara.",
           "FTP'de `PASS` satırı; HTTP Basic'te `Authorization: Basic ...` değeri `base64 -d` ile çözülür "
           "(kullanici:parola); formda `...=` alanı. `grep -a` ile süz."),
          puan=35, baslik="Açık metin"),
    Gorev("Kayıtta en çok paket **gönderen** makine hangisi?",
          IP("en_cok", sik_hatalar=_en_cok_hata),
          ("Her paketin bir kaynağı var; kaynakları say.",
           "Eğitimdeki sayma kalıbını bu kez filtresiz kullan ve sırala.",
           "`tcpdump -nn -r <<klasor>>/<<pcap>> 2>/dev/null | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c "
           "| sort -rn | head -3`"),
          puan=30, baslik="Geveze makine"),
    Gorev("Bu makine verilerini dışarıdaki bir sunucuya yolluyor. O sunucunun IP'si hangi **alan adı** "
          "sorgulanarak bulunmuştu?",
          Metin("supheli", son_ekleri_at=(".",), sik_hatalar=_supheli_hata, bicim="alan adı"),
          ("Önce makinenin en çok hangi dış IP'ye paket gönderdiğini bul.",
           "`src host MAKINE and not port 53` ile hedefleri say. Sonra DNS cevaplarında o IP'yi ara.",
           "`tcpdump -nn -v -r <<klasor>>/<<pcap>> port 53` ile `-v` DNS cevabında adı da gösterir; "
           "`| grep IP_ADRESI` ile süz."),
          puan=35, baslik="Kaçış adresi"),
    Gorev("Deniz FTP ya da düz HTTP girişindeki parolayı tcpdump ile okuyabildi. Aynı kullanıcı "
          "HTTPS ile giriş yapsaydı neden okuyamazdı?",
          Secmeli([
              ("HTTPS trafiği TLS ile şifrelenir; araya giren sadece anlamsız baytlar görür",
               "Doğru. Paketler yine yakalanır ama içerik şifrelidir; `-A` sadece noktalar ve rastgele karakterler gösterir."),
              ("HTTPS paketleri tcpdump'ın varsayılan filtresine takılmaz, dosyaya kaydedilmez",
               "HTTPS paketleri de yakalanır ve kaydedilir; az önce 443 trafiğini gördün. Sadece içerik okunmaz."),
              ("HTTPS parolanın tamamını değil, sadece ilk birkaç karakterini sunucuya gönderir",
               "Parola tam olarak gönderilir; fark, TLS tünelinin içinde şifreli gitmesidir."),
              ("HTTPS 443 portunu kullandığı için o portu sadece root kullanıcısı dinleyebilir",
               "Port numarası okunabilirliği belirlemez; root canlı yakalama için gerekir, şifre çözmek için değil."),
          ]),
          ("Eğitimde 443 trafiğine `-A` ile baktığında ne gördün?",
           "Fark, paketlerin yakalanıp yakalanmamasında değil, içeriğin okunup okunmamasında.",
           "TLS: içerik şifreli."),
          puan=20, baslik="Neden okunmaz"),
    Gorev("Bütün bağlantıların HTTPS olduğu bir ağı dinleyen saldırgan yine de neleri görebilir?",
          Secmeli([
              ("Kimin hangi IP'lerle ne zaman, ne kadar konuştuğunu ve açık DNS sorgularını",
               "Doğru. Şifreleme içeriği gizler, meta veriyi değil: kim, kiminle, ne zaman, ne kadar; DNS de çoğu zaman açıktır."),
              ("Parolaları; çünkü TLS sadece sayfa içeriğini şifreler, form alanlarını şifrelemez",
               "TLS, HTTP isteğinin tamamını (başlıklar, form gövdesi, çerezler) şifreler."),
              ("Hiçbir şeyi; HTTPS IP adreslerini ve port numaralarını da tamamen gizler",
               "IP ve TCP başlıkları şifrelenmez; olmasa paketler yönlendirilemezdi."),
              ("Sadece çerezleri; çünkü tarayıcı çerezleri TLS tünelinin dışında ayrıca gönderir",
               "Çerezler HTTP başlığıdır ve TLS'in içinde gider; HTTPS'te dinleyen biri onları okuyamaz."),
          ]),
          ("Paketin hangi kısımları şifrelenemez, yoksa yönlendirilemezdi?",
           "Bu kayıtta veri kaçıran makineyi nasıl buldun? İçeriği okumadan.",
           "IP başlıkları, zaman, boyut ve şifresiz DNS."),
          puan=20, baslik="Meta veri"),
]

SEVIYE = Seviye(
    kimlik="c02b06",
    cilt=2,
    bolum=6,
    baslik="Trafiği Dinlemek: tcpdump ve Wireshark",
    brifing="""
Deniz, **<<musteri>>** ağından alınmış bir trafik kaydını laboratuvarına koydu:
`<<klasor>>/<<pcap>>`. "Biri ağı tarıyor mu, biri parolasını açık metin gönderiyor mu, biri
dışarıya veri kaçırıyor mu? Her cevabı bir tcpdump filtresiyle kanıtla."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bir trafik kaydı, olayın tanığıdır. Bu seviyede tek bir dosyadan bir port taramasını, açık
metin bir parolayı ve dışarı veri kaçıran bir makineyi çıkardın; üstelik veriyi kaçıran
bağlantının içeriğini okumadan, sadece meta veriyle. Saldırgan açısından ders: şifresiz
protokoller ve aynı ağdaki herkesin trafiği bir hazinedir. Savunma açısından ders: FTP, Telnet
ve düz HTTP girişlerini emekliye ayır, ağ sensörlerini ve kayıtlarını hazır tut ve "kim, kiminle,
ne kadar konuşuyor" sorusunu düzenli sor; şifreli trafikte bile anormallik meta veride görünür.
""",
    gercek_hayat="""
- **Firesheep, 2010:** Bir tarayıcı eklentisi, açık Wi-Fi ağlarında şifresiz HTTP üzerinden giden
  oturum çerezlerini yakalayıp tek tıkla başkasının oturumuna girmeyi gösterdi. Bu gösteri,
  büyük sitelerin bütün oturumları HTTPS'e taşımasını hızlandıran olaylardan biri olarak anılır.
- **Telnet ve FTP'nin emekliye ayrılması:** Güvenlik standartları ve sertleştirme rehberleri
  (örneğin CIS Benchmark'lar) Telnet ve düz FTP gibi kimlik bilgisini açık metin taşıyan
  servislerin kapatılmasını, yerlerine SSH/SFTP kullanılmasını önerir.
- **Meta veriyle tespit:** Ağ tabanlı saldırı tespit sistemleri (Zeek, Suricata gibi) şifreli
  trafiğin içeriğini göremese de bağlantı süreleri, veri miktarları ve DNS sorguları üzerinden
  veri kaçırma ve komuta-kontrol trafiğini yakalamaya çalışır. Cilt 7'de bunlara döneceğiz.
""",
    sure_hedef_dk=35,
)
