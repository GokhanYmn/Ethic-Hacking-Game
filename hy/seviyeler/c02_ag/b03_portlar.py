"""Cilt 2 · Bölüm 3 — Portlar, TCP ve UDP.

Beceri: dinleyen portları `ss` ile bulmak, `nc` ile elle bağlanıp karşılama satırı (banner)
okumak, FTP/SMTP gibi düz metin protokollerle elle konuşmak, TCP ile UDP'yi ayırmak,
iyi bilinen portları tanımak, üçlü el sıkışmayı ve SYN taramasının mantığını anlamak.

Servis: senaryonun "sunucusu" 127.0.0.1 üzerinde rastgele portlarda ayağa kalkar: sahte SSH,
FTP, SMTP ve HTTP; envanterde olmayan bir bakım/hata ayıklama konsolu (banner'ında bayrak)
ve bir UDP servisi.

Vakalar: depo sunucusu (lojistik), API sunucusu (fintech), e-belediye sunucusu (belediye),
hasta portalı (hastane).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import SessizIsleyici, calistir, http_sunucu, tcp_banner
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "kuzgun", "sunucu": "kzg-depo",
        "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        "ftp": "220 (vsFTPd 3.0.5)", "ftp_yazilim": ["vsFTPd 3.0.5", "vsftpd/3.0.5", "vsftpd-3.0.5"],
        "smtp": "220 {host} ESMTP Postfix (Ubuntu)",
        "http": "nginx/1.18.0 (Ubuntu)", "baslik": "Kuzgun Depo Paneli",
        "gizli": ("Kuzgun Depo Robot Bakim Konsolu v2.1 (tedarikci uzaktan erisim)\r\n"
                  "Uyari: kimlik dogrulama devre disi (bakim modu)\r\n"
                  "Servis anahtari: {bayrak}\r\n"),
        "gizli_ad": "robot bakım konsolu", "udp_ad": "syslog aktarıcısı",
        "udp": "kzg-depo syslog-aktarici: kayit alindi\n",
        "brifing": """
Deniz'in SOC ekranında yeni bir alarm: **Kuzgun Lojistik**'in depo sunucusu **<<sunucu>>**
üzerinde, envanter listesinde olmayan bir port dinliyor. Sunucunun birebir kopyası şimdi
laboratuvarında, **127.0.0.1** üzerinde çalışıyor; envanter de `envanter.txt` dosyasında.

Selin: "Bu sunucuda hangi kapılar açık ve her kapının ardında kim var? Envanterle
karşılaştıracağız. Bilinmeyen servisi bulan, rapora adını yazar."

Mert kulaklığını çıkarıyor: "Bugün tarayıcı yok. `ss` ve `nc` ile, eski usul. Bir portun
ardında ne olduğunu elle sormayı bilmeyen, nmap çıktısını da okuyamaz."
""",
    },
    {
        "kod": "paramix", "sunucu": "pmx-api01",
        "ssh": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
        "ftp": "220 ProFTPD 1.3.8 Server (Paramix Mutabakat) [127.0.0.1]",
        "ftp_yazilim": ["ProFTPD 1.3.8", "proftpd/1.3.8", "proftpd-1.3.8"],
        "smtp": "220 {host} ESMTP Exim 4.97 Tue, 10 Nov 2026 09:12:44 +0300",
        "http": "Apache/2.4.58 (Ubuntu)", "baslik": "Paramix Merchant API",
        "gizli": ("pmx debug-console 0.4.1 [GELISTIRME] -- uretimde kapatilmali!\r\n"
                  "Bellek dokumu ve ortam degiskenleri icin 'env' yazin.\r\n"
                  "session-token: {bayrak}\r\n"),
        "gizli_ad": "hata ayıklama (debug) konsolu", "udp_ad": "metrik toplayıcı (statsd)",
        "udp": "pmx-statsd: ok\n",
        "brifing": """
**Paramix**'in CTO'su Ece Hanım, ödeme API'sinin çalıştığı **<<sunucu>>** için bir "port
envanteri doğrulaması" istedi: denetim haftası yaklaşıyor ve sunucuda neyin açık olduğunu
yazılı olarak bilmek zorundalar. Sunucunun kopyası laboratuvarında, **127.0.0.1** üzerinde
çalışıyor; şirketin beyan ettiği servisler `envanter.txt` dosyasında.

Deniz: "Geliştiriciler test için bir şey açıp kapatmayı unutur. Envanterde olmayan her port,
denetçinin ilk soracağı şeydir."

Selin: "Her portu tek tek çal, ne cevap verdiğini not et."
""",
    },
    {
        "kod": "yesiltepe", "sunucu": "ytb-ebelediye",
        "ssh": "SSH-2.0-OpenSSH_7.4",
        "ftp": "220 (vsFTPd 2.3.4)", "ftp_yazilim": ["vsFTPd 2.3.4", "vsftpd/2.3.4", "vsftpd-2.3.4"],
        "smtp": "220 {host} ESMTP Sendmail 8.15.2/8.15.2; Tue, 10 Nov 2026 09:12:44 +0300",
        "http": "Apache/2.2.15 (CentOS)", "baslik": "Yesiltepe e-Belediye",
        "gizli": ("SU-DEPOSU TELEMETRI KOPRUSU v0.9 (Modbus->TCP)\r\n"
                  "Kimlik dogrulama: YOK\r\n"
                  "Bakim kodu: {bayrak}\r\n"),
        "gizli_ad": "su deposu telemetri köprüsü", "udp_ad": "telemetri yayını",
        "udp": "ytb-telemetri: OK seviye=%74\n",
        "brifing": """
**Yeşiltepe Belediyesi**'nde bilgi işlem müdürü Nurcan Hanım, yıllardır dokunulmamış e-belediye
sunucusu **<<sunucu>>** için endişeli: "Burada ne çalıştığını bilen kimse kalmadı." Sunucunun
kopyası laboratuvarında, **127.0.0.1** üzerinde ayakta; elde kalan eski envanter `envanter.txt`
dosyasında.

Deniz: "Eski sunucular sürprizlerle doludur. Bir tedarikçinin yıllar önce açıp unuttuğu bir
köprü servisi, bütün ağın en zayıf halkası olabilir."

Mert: "Sürüm numaralarına dikkat. Bazıları tarih kitabından çıkmış gibi."
""",
    },
    {
        "kod": "medora", "sunucu": "medora-portal",
        "ssh": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
        "ftp": "220 ProFTPD 1.3.6 Server (Medora PACS Arsiv) [127.0.0.1]",
        "ftp_yazilim": ["ProFTPD 1.3.6", "proftpd/1.3.6", "proftpd-1.3.6"],
        "smtp": "220 {host} ESMTP Postfix",
        "http": "nginx/1.24.0", "baslik": "Medora Hasta Portali",
        "gizli": ("DICOM Kopru Yonetim Kabugu 1.3\r\n"
                  "Varsayilan parola degistirilmedi (bkz. kurulum kilavuzu).\r\n"
                  "Yonetim anahtari: {bayrak}\r\n"),
        "gizli_ad": "DICOM köprüsü yönetim kabuğu", "udp_ad": "zaman/saat servisi",
        "udp": "medora-zaman: ok\n",
        "brifing": """
**Medora Sağlık**'ın hasta portalı **<<sunucu>>**, bir tıbbi görüntüleme (PACS) tedarikçisinin
kurulumundan sonra garip davranıyor. Dr. Aslı Hanım, sunucuda tedarikçinin ne açtığını
bilmek istiyor. Kopyası laboratuvarında, **127.0.0.1** üzerinde çalışıyor; hastanenin
onayladığı servisler `envanter.txt` dosyasında.

Selin: "Hastane ağlarında tedarikçi servisleri sık görülür ve çoğu zaman varsayılan
ayarlarla kalır. Her kapıyı çal, kim cevap veriyor yaz."

Deniz ekliyor: "Bulduğun her şeyi envanterle karşılaştır. Fark, bulgunun ta kendisi."
"""
    },
]

BILINEN = {
    445: ["SMB", "microsoft-ds", "samba", "cifs", "windows dosya paylaşımı", "dosya paylaşımı"],
    3306: ["MySQL", "mariadb", "mysql veritabanı"],
    3389: ["RDP", "ms-wbt-server", "uzak masaüstü", "remote desktop", "windows uzak masaüstü"],
    25: ["SMTP", "e-posta", "eposta", "mail", "e-posta gönderimi"],
    53: ["DNS", "domain", "alan adı çözümleme"],
    21: ["FTP", "dosya transferi"],
    8080: ["HTTP", "http-alt", "http alternatif", "web", "http-proxy", "proxy"],
}


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    portlar = rng.sample(range(20000, 45001), 6)
    p = dict(zip(["ssh", "ftp", "smtp", "http", "gizli", "udp"], portlar))
    host = f"{rng.choice(['mail', 'posta', 'smtp', 'mx'])}{rng.choice(['', '01', '02', '-ic'])}.{m['alan']}"
    anonim = rng.random() < 0.5
    bayrak = u.bayrak(rng, rng.choice(["acik_kapi", "unutulan_servis", "kor_nokta", "arka_oda"]))
    bilinen = rng.choice(sorted(BILINEN))
    dis_ip = u.dis_ip(rng)
    tcp = [p["ssh"], p["ftp"], p["smtp"], p["http"], p["gizli"]]
    return {
        "vaka": f"{m['ad']} — {v['sunucu']} port envanteri",
        "brifing": v["brifing"],
        "v": v, "p": p, "host": host, "anonim": anonim, "bayrak": bayrak, "dis_ip": dis_ip,
        "metin": {
            "musteri": m["ad"], "sunucu": v["sunucu"], "ssh_port": p["ssh"], "http_port": p["http"],
            "bilinen_port": bilinen, "dis_ip": dis_ip,
        },
        "cevaplar": {
            "tcp_portlar": tcp,
            "ftp_yazilim": v["ftp_yazilim"],
            "pass_kodu": 230 if anonim else 530,
            "smtp_host": host,
            "bayrak": bayrak,
            "udp_port": p["udp"],
            "bilinen": BILINEN[bilinen],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "envanter.txt",
          f"{v['sunucu']} — beyan edilen servisler (müşteri envanteri)\n"
          "=====================================================\n"
          "- SSH      (uzaktan yönetim)\n"
          "- FTP      (dosya aktarımı)\n"
          "- SMTP     (bildirim e-postaları)\n"
          "- HTTP     (web paneli)\n"
          "Başka servis yoktur. (İmza: bilgi işlem)\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sunucu']} sunucusunun lab kopyası bu görev boyunca 127.0.0.1 üzerinde çalışıyor.\n"
          "Portları 20000-45000 aralığında; hepsi oyunun python sürecine ait (`ss -tlnp`'de `python3` olarak görünür).\n"
          "Kendi makinende başka dinleyen portlar da görebilirsin; onlar bu vakanın parçası değil.\n"
          "\nnc ipucu: FTP ve SMTP karşılama satırından sonra komut bekler. `QUIT` yaz ya da Ctrl+C.\n")
    u.yaz(lab / "dis_tarama_ozeti.txt",
          f"# Dış tarama özeti (geçen ay, başka bir firma tarafından)\n"
          f"Hedef: {s['dis_ip']}\n"
          f"PORT       DURUM\n"
          f"22/tcp     open\n"
          f"443/tcp    open\n"
          f"{str(s['metin']['bilinen_port']) + '/tcp':<10} open\n"
          f"Not: 3. satırdaki servisin adı rapora yazılmamış.\n")


def _ftp_fabrikasi(anonim: bool):
    def fabrika():
        durum = {"kullanici": None, "giris": False}

        def cevapla(satir: str):
            komut, _, arg = satir.strip().partition(" ")
            komut = komut.upper()
            if komut == "QUIT":
                return ("221 Goodbye.\r\n", True)
            if komut == "USER":
                durum["kullanici"] = arg.strip()
                return "331 Please specify the password.\r\n"
            if komut == "PASS":
                if durum["kullanici"] is None:
                    return "503 Login with USER first.\r\n"
                if anonim and durum["kullanici"].lower() in ("anonymous", "ftp"):
                    durum["giris"] = True
                    return "230 Login successful.\r\n"
                return "530 Login incorrect.\r\n"
            if not durum["giris"]:
                return "530 Please login with USER and PASS.\r\n"
            if komut == "SYST":
                return "215 UNIX Type: L8\r\n"
            if komut == "PWD":
                return '257 "/" is the current directory\r\n'
            if komut in ("LIST", "NLST", "RETR"):
                return "425 Use PORT or PASV first.\r\n"
            return "500 Unknown command.\r\n"
        return cevapla
    return fabrika


def _smtp_cevap(host: str):
    def cevapla(satir: str):
        komut = satir.strip().split(" ")[0].upper()
        if komut == "QUIT":
            return ("221 2.0.0 Bye\r\n", True)
        if komut in ("EHLO", "HELO"):
            return f"250-{host}\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250 8BITMIME\r\n"
        if komut == "NOOP":
            return "250 2.0.0 Ok\r\n"
        if not komut:
            return ""
        return "502 5.5.2 Error: command not recognized\r\n"
    return cevapla


def servis(s: dict, lab: Path, dur) -> None:
    v, p, h = s["v"], s["p"], "127.0.0.1"
    baslik = v["baslik"]

    class Web(SessizIsleyici):
        server_version = v["http"]
        timeout = 15

        def version_string(self):
            return self.server_version

        def do_GET(self):
            if self.path.split("?")[0] in ("/", "/index.html"):
                self.yanit(200, f"<html><head><title>{baslik}</title></head>"
                                f"<body><h1>{baslik}</h1><p>Giris icin yetkili hesabinizi kullanin.</p></body></html>\n")
            else:
                self.yanit(404, "<h1>404 Not Found</h1>\n")

        def do_HEAD(self):
            self.do_GET()

    sunucular = [
        tcp_banner(h, p["ssh"], v["ssh"] + "\r\n"),
        ag.tcp_satir_sunucu(h, p["ftp"], _ftp_fabrikasi(s["anonim"]), karsilama=v["ftp"] + "\r\n", fabrika=True),
        ag.tcp_satir_sunucu(h, p["smtp"], _smtp_cevap(s["host"]), karsilama=v["smtp"].format(host=s["host"]) + "\r\n"),
        http_sunucu(h, p["http"], Web),
        tcp_banner(h, p["gizli"], v["gizli"].format(bayrak=s["bayrak"])),
        ag.udp_sunucu(h, p["udp"], lambda veri: v["udp"]),
    ]
    calistir(sunucular, dur)


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=60).stdout.strip()


def _secmeli(s, lab, no):
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: ss ile portları bulur, nc ile her portun banner'ını okur.

    Test konteynerinde başka seviyelerin servisleri de dinliyor olabilir; bu yüzden `ss -p`
    çıktısı bu sürecin pid'iyle süzülür (oyuncu için `grep python` süzgeci aynı işi görür).
    """
    pid = os.getpid()
    tcp = _sh(f"ss -tlnpH | grep 'pid={pid},' | awk '{{print $4}}' | grep '^127.0.0.1:' | cut -d: -f2 | sort -n", lab).split()
    udp = _sh(f"ss -ulnpH | grep 'pid={pid},' | awk '{{print $4}}' | grep '^127.0.0.1:' | cut -d: -f2", lab)
    # Banner'ı basıp hemen kapanan servislere veri gönderme: okunmamış veriyle kapanan soket
    # RST üretir ve banner kaybolabilir. Oyuncunun `nc -v -w 2 ...` kullanımı da böyledir.
    bannerlar = {port: _sh(f"nc -w 1 127.0.0.1 {port} < /dev/null", lab) for port in tcp}
    ftp_port = next(pt for pt, b in bannerlar.items() if b.startswith("220") and "FTP" in b.upper())
    smtp_port = next(pt for pt, b in bannerlar.items() if "SMTP" in b.upper())
    ftp = _sh(f"printf 'QUIT\\r\\n' | nc -w 2 127.0.0.1 {ftp_port} | head -1 | grep -o -E '(vsFTPd|ProFTPD) [0-9.]+'", lab)
    pass_kodu = _sh(f"printf 'USER anonymous\\r\\nPASS x@y\\r\\nQUIT\\r\\n' | nc -w 2 127.0.0.1 {ftp_port} "
                    "| sed -n 3p | cut -c1-3", lab)
    smtp_host = _sh(f"printf 'QUIT\\r\\n' | nc -w 2 127.0.0.1 {smtp_port} | head -1 | awk '{{print $2}}'", lab)
    bayrak = next((b for b in bannerlar.values() if "FLAG{" in b), "")
    bayrak = bayrak[bayrak.find("FLAG{"):].split("}")[0] + "}" if bayrak else ""
    bilinen = _sh(f"grep -w \"$(awk 'NR==6 {{print $1}}' dis_tarama_ozeti.txt)\" /etc/services | head -1 | awk '{{print $1}}'", lab)
    return {1: " ".join(tcp), 2: ftp, 3: pass_kodu, 4: smtp_host, 5: bayrak, 6: udp, 7: bilinen,
            8: _secmeli(s, lab, 8), 9: _secmeli(s, lab, 9)}


# ---------------------------------------------------------------- sık hatalar

def _tcp_hata(g, beklenen, b):
    verilen = {int(x) for x in g.split() if x.isdigit()}
    if b.senaryo["p"]["udp"] in verilen:
        return "Listende bir UDP portu var. `ss -t` sadece TCP'yi gösterir; `-u` UDP içindir."
    return None


def _pass_hata(g, beklenen, b):
    if g == "331":
        return "331, `USER` komutuna verilen cevap (\"parolayı söyle\"). `PASS`'ten SONRA gelen satırın koduna bak."
    if g == "220":
        return "220, bağlanınca gelen karşılama satırı. `USER anonymous` ve `PASS ...` gönderdikten sonraki cevabı oku."
    if g == "221":
        return "221, QUIT'e verilen veda cevabı. Ondan bir önceki satır PASS'in cevabıdır."
    return None


def _udp_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n in b.senaryo["cevaplar"]["tcp_portlar"]:
        return "Bu bir TCP portu. UDP dinleyenleri görmek için `ss -ulnp` kullan."
    return None


ADIMLAR = [
    Adim("Port: binadaki daire numarası", """
IP adresi paketi doğru **makineye** getirdi. Ama o makinede onlarca program çalışıyor olabilir:
web sunucusu, SSH, veritabanı... Paketin hangisine gideceğini **port** söyler: 0-65535 arası
16 bitlik bir sayı. IP sokak adresiyse, port daire numarasıdır.

Ezberlenecek kısa liste:

- `21` FTP (parolalar düz metin) · `22` SSH · `25` SMTP (e-posta gönderimi) · `53` DNS
- `80` HTTP · `443` HTTPS · `445` SMB (Windows dosya paylaşımı)
- `3306` MySQL · `3389` RDP (Windows uzak masaüstü) · `8080` alternatif HTTP

Unuttuğunda Linux'un kendi listesine bakabilirsin: `/etc/services`.
""", komut="grep -w 22/tcp /etc/services", sonra="""
**Hacker gözüyle:** Açık her port bir potansiyel giriştir. 3389 açıksa RDP parola denemesi,
445 açıksa SMB zafiyetleri (EternalBlue gibi), 21 açıksa anonim FTP girişi akla gelir.
Port taramasının bütün amacı "bu binada hangi daireler açık?" sorusudur.
"""),
    Adim("TCP ve UDP: telefon ve kartpostal", """
Taşıma katmanının iki ana protokolü vardır:

- **TCP** güvenilirdir: önce bağlantı kurulur, her parçanın ulaştığı teyit edilir, kaybolan
  yeniden gönderilir. Web, e-posta, SSH, dosya indirme. Telefon görüşmesi gibi: önce "alo".
- **UDP** hızlıdır ama garantisizdir: gönderir ve arkasına bakmaz. DNS, video akışı, oyunlar,
  log aktarımı. Kartpostal gibi: ulaştı mı bilmezsin.

Aynı port numarası TCP'de ve UDP'de iki ayrı kapıdır: `53/tcp` ile `53/udp` farklıdır.
"""),
    Adim("Üçlü el sıkışma", """
TCP bir bağlantıyı üç adımda kurar; port taramasının kalbi budur:

1. İstemci → Sunucu: **SYN** ("bağlanmak istiyorum")
2. Sunucu → İstemci: **SYN-ACK** ("tamam, ben de hazırım")
3. İstemci → Sunucu: **ACK** ("anlaştık, başlıyoruz")

Kapatmak için benzer şekilde **FIN** paketleri kullanılır; ani kesme ise **RST** (reset) ile olur.

**Hacker gözüyle:** nmap'in varsayılan SYN taraması (`-sS`) el sıkışmayı bilerek yarım
bırakır: SYN gönderir, SYN-ACK gelirse port **açık**tır ama ACK göndermez (yarı-açık tarama).
**RST** gelirse port **kapalı**dır: makine ayakta ama o kapıda kimse yok. Hiç cevap gelmezse
port **filtreli**dir: arada paketi sessizce düşüren bir güvenlik duvarı var. Bu üç cevabı
bildiğinde nmap çıktısı ezber olmaktan çıkar.
"""),
    Adim("Dinleyen portlar: ss", """
Cilt 1'deki `ss` komutunu hatırla. Seçenekler: `-t` TCP, `-l` sadece dinleyenler (listening),
`-n` port numaralarını isme çevirme, `-p` hangi programın dinlediği.

<<sunucu>>'nun kopyası şu an senin makinende, 127.0.0.1 üzerinde çalışıyor:
""", komut="ss -tlnp", sonra="""
`Local Address:Port` sütunu kimin nerede dinlediğini söyler: `127.0.0.1:PORT` sadece bu
makineden erişilebilir, `0.0.0.0:PORT` ise bütün ağ arayüzlerinden. Vakanın portları
20000-45000 aralığında ve `users:(("python3",...))` olarak görünüyor. O an kurulu bağlantıları
görmek istersen: `ss -t state established` ("bu makine şu an kiminle konuşuyor?").
"""),
    Adim("nc ile kapı çalmak", """
`nc` (netcat) ağın İsviçre çakısıdır: bir porta elle bağlanır, karşı tarafın söylediğini ekrana
basar, senin yazdığını karşıya gönderir. Birçok servis bağlanır bağlanmaz kendini tanıtır; bu
karşılama satırına **banner** denir. `-v` ayrıntılı, `-w 2` iki saniye sessizlikte bırak demek.
""", komut="nc -v -w 2 127.0.0.1 <<ssh_port>>", sonra="""
Tek satırda yazılım (OpenSSH), sürüm ve çoğu zaman işletim sistemi (Ubuntu) ele geçti. Buna
**banner grabbing** denir; nmap'in `-sV` sürüm tespiti de özünde bunu yapar. FTP ve SMTP gibi
servisler karşılamadan sonra komut bekler: oradan `QUIT` yazarak ya da Ctrl+C ile çıkarsın.
"""),
    Adim("Elle HTTP isteği", """
HTTP servisleri önce konuşmaz; senin bir istek göndermeni bekler. Kitaptaki yöntem: bağlan,
`GET / HTTP/1.0` yaz, iki kez Enter. Aynı şeyi tek satırda `printf` ile gönderebiliriz
(`\\r\\n` satır sonu, ikincisi "başlıklar bitti" demek):
""", komut="printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc 127.0.0.1 <<http_port>>", sonra="""
İlk satır durum kodu (`200 OK`), ardından başlıklar ve sayfa. `Server:` başlığı web sunucusunun
yazılımını ve sürümünü ele verir. Bölüm 5'te bunu `curl` ile çok daha rahat yapacağız.

**Hacker gözüyle:** Hedef makinede `nc` yoksa bash'in kendisi bağlanabilir:
`exec 3<>/dev/tcp/127.0.0.1/PORT` bir bağlantı açar, `cat <&3` gelen veriyi okur. Bu yüzden
"sunucuda araç yok" demek, "bağlantı kurulamaz" demek değildir.
"""),
    Adim("UDP dinleyicileri", """
UDP'de el sıkışma yoktur; bir UDP portunun açık olduğunu anlamak bu yüzden zordur: kapalı bir
porttan bile çoğu zaman hiçbir cevap gelmez. Kendi makinende `ss -u` ile UDP dinleyicilerini
görebilirsin:
""", komut="ss -ulnp", sonra="""
UDP'ye `nc` ile konuşmak için `-u` eklenir: `echo merhaba | nc -u -w 1 127.0.0.1 PORT`.
Servis cevap verirse ekrana düşer; vermezse sessizlik, ki UDP taramalarının yavaş ve
belirsiz olmasının sebebi tam olarak budur.
"""),
]

GOREVLER = [
    Gorev("<<sunucu>>'nun kopyası 127.0.0.1 üzerinde hangi **TCP** portlarında dinliyor? "
          "(20000-45000 aralığındaki, python sürecine ait portların hepsini yaz)",
          Kume("tcp_portlar", tur="sayi", sik_hatalar=_tcp_hata, bicim="boşlukla ayrılmış port listesi"),
          ("Dinleyen TCP portlarını gösteren komutu eğitimde gördün.",
           "`ss -tlnp` çıktısında `127.0.0.1:` ile başlayan ve süreç sütununda `python` geçen satırlar.",
           "`ss -tlnp | grep python` ile süz; `127.0.0.1:` sonrasındaki sayıları topla."),
          puan=30, baslik="Açık kapılar"),
    Gorev("FTP servisi hangi yazılımı kullanıyor? Adını ve sürümünü yaz (örn. `ProFTPD 1.3.5`).",
          Metin("ftp_yazilim", bicim="yazılım ve sürüm"),
          ("Önce hangi portun FTP olduğunu bul. FTP banner'ı `220` ile başlar.",
           "Bulduğun her porta `nc -v -w 2 127.0.0.1 PORT` ile bağlan ve karşılama satırını oku.",
           "FTP'nin `220 ...` satırındaki yazılım adı ve hemen yanındaki sürüm numarası."),
          puan=30, baslik="FTP sürümü"),
    Gorev("FTP sunucusu anonim girişe izin veriyor mu? Bağlan, `USER anonymous` ve ardından "
          "`PASS` ile herhangi bir parola gönder. Sunucu `PASS`'e hangi **durum koduyla** cevap verdi?",
          Sayi("pass_kodu", sik_hatalar=_pass_hata),
          ("FTP düz metin bir protokol; komutları sen de elle yazabilirsin.",
           "`nc 127.0.0.1 FTP_PORTU` ile bağlan, `USER anonymous` yaz, Enter; sonra `PASS deneme` yaz, Enter.",
           "Tek satırda: `printf 'USER anonymous\\r\\nPASS x\\r\\nQUIT\\r\\n' | nc 127.0.0.1 FTP_PORTU`; "
           "üçüncü satırın başındaki üç haneli sayı. 230 = giriş başarılı, 530 = reddedildi."),
          puan=30, baslik="Anonim FTP"),
    Gorev("SMTP servisinin karşılama satırı, e-posta sunucusunun **iç ağdaki adını** ele veriyor. "
          "Bu ad ne?",
          Metin("smtp_host", bicim="sunucu adı (örn. mail.ornek.lab)"),
          ("SMTP banner'ı da `220` ile başlar ve `ESMTP` kelimesini içerir.",
           "SMTP portuna `nc -v -w 2` ile bağlan; `220`'den hemen sonraki kelimeye bak.",
           "`220 <ad> ESMTP ...` satırındaki ikinci kelime."),
          puan=25, baslik="Sızan ad"),
    Gorev("Envanterde olmayan bir servis var. Ona bağlan: karşılama metninde bir anahtar (bayrak) "
          "duruyor.",
          Bayrak("bayrak"),
          ("`envanter.txt`'te dört servis var; sen beş TCP portu buldun.",
           "SSH, FTP, SMTP ve HTTP'yi tanıdıktan sonra geriye kalan portun banner'ını oku.",
           "Her porta sırayla `nc -w 2 127.0.0.1 PORT` ile bağlan; FLAG{...} içeren satırı ara."),
          puan=40, baslik="Envanter dışı"),
    Gorev("Bu sunucuda bir de **UDP** servisi dinliyor. Hangi portta?",
          Sayi("udp_port", sik_hatalar=_udp_hata),
          ("`ss` varsayılan olarak hem TCP hem UDP göstermez; seçmen gerekir.",
           "`ss -ulnp` UDP dinleyicilerini listeler.",
           "`ss -ulnp | grep python` satırında `127.0.0.1:` sonrasındaki sayı."),
          puan=25, baslik="Kartpostal kapısı"),
    Gorev("`dis_tarama_ozeti.txt`'te <<dis_ip>> için `<<bilinen_port>>/tcp` açık görünüyor ama servisin "
          "adı yazılmamış. Bu portta büyük olasılıkla hangi servis çalışır?",
          Metin("bilinen", bicim="servis adı (örn. SSH)"),
          ("Eğitimdeki iyi bilinen portlar listesini hatırla.",
           "Unuttuysan Linux'un port listesinde ara: `/etc/services`.",
           "`grep -w <<bilinen_port>>/tcp /etc/services` satırının ilk kelimesi (ya da bildiğin yaygın adı)."),
          puan=20, baslik="Port ezberi"),
    Gorev("TCP üçlü el sıkışmasının doğru sırası hangisi?",
          Secmeli([
              ("SYN → SYN-ACK → ACK",
               "Doğru. İstemci SYN ile ister, sunucu SYN-ACK ile kabul eder, istemci ACK ile onaylar."),
              ("SYN → ACK → SYN-ACK",
               "Sunucu önce kabul etmeli (SYN-ACK); istemcinin ACK'i en sondadır."),
              ("ACK → SYN → SYN-ACK",
               "Bağlantı her zaman bir SYN ile başlar; ortada onaylanacak bir şey yokken ACK gönderilmez."),
              ("SYN → SYN-ACK → FIN",
               "FIN bağlantıyı kapatır. Üçüncü adım bağlantıyı başlatan ACK'tir."),
          ]),
          ("Telefon benzetmesi: arayan, açan, sonra konuşma.",
           "İlk paket bağlanma isteğidir; ikincisi hem kabul hem karşı istek.",
           "İstek, kabul+istek, onay."),
          puan=20, baslik="El sıkışma"),
    Gorev("nmap SYN taraması bir porta SYN gönderdi ve cevap olarak **RST** aldı. Port hangi durumda?",
          Secmeli([
              ("Kapalı: makine ayakta ama o portta dinleyen yok",
               "Doğru. RST, 'burada kimse yok' demektir. Açık port SYN-ACK döner, filtreli port hiç cevap vermez."),
              ("Açık: RST, sunucunun bağlantıyı kabul ettiğini gösterir",
               "Bağlantıyı kabul eden sunucu SYN-ACK döner. RST bir reddetmedir."),
              ("Filtreli: güvenlik duvarı paketi sessizce düşürmüştür",
               "Sessizce düşürülen pakete hiç cevap gelmez. Burada bir RST geldi."),
              ("Yarı açık: el sıkışma bitmedi ama port dinliyor",
               "'Yarı açık' taramanın adıdır, portun durumu değil. Dinleyen port SYN-ACK döner."),
          ]),
          ("Eğitimdeki üç cevabı hatırla: SYN-ACK, RST, sessizlik.",
           "Hangisi 'kapı var ama içeride kimse yok' demekti?",
           "SYN-ACK = açık, RST = kapalı, cevap yok = filtreli."),
          puan=20, baslik="RST ne demek"),
]

SEVIYE = Seviye(
    kimlik="c02b03",
    cilt=2,
    bolum=3,
    baslik="Portlar, TCP ve UDP",
    brifing="""
**<<musteri>>**'nin sunucusu **<<sunucu>>**'nun kopyası 127.0.0.1 üzerinde çalışıyor.
Selin: "Hangi kapılar açık, her kapının ardında kim var? Envanterle karşılaştır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Bir saldırganın keşifteki ilk sorusu hep aynıdır: hangi kapılar açık ve ardında ne var?
Banner'lar bu soruya çoğu zaman gönüllü cevap verir: yazılım, sürüm, iç ağdaki sunucu adı,
hatta unutulmuş bir bakım konsolunun anahtarı. Savunma tarafının dersi de buradan çıkar:
envanterde olmayan her port bir bulgudur, gereksiz banner bilgisi kısılır, anonim FTP gibi
varsayılanlar kapatılır ve sadece içeriden erişilmesi gereken servisler `0.0.0.0` yerine
`127.0.0.1`'de ya da güvenlik duvarının arkasında dinler.
""",
    gercek_hayat="""
- **vsftpd 2.3.4:** 2011'de bu FTP sunucusunun resmi indirme adresindeki arşiv, arka kapı
  eklenmiş bir sürümle değiştirildi ve kısa sürede fark edilip kaldırıldı. Bu sürüm bugün
  eğitim amaçlı zafiyetli makinelerde (örn. Metasploitable 2) durur; banner'da `vsFTPd 2.3.4`
  görmek, sürüm bilgisinin neden bir saldırgan için altın değerinde olduğunu gösteren klasik
  bir örnektir.
- **EternalBlue ve 445:** 2017'deki WannaCry fidye yazılımı, internete açık SMB (445/tcp)
  servisleri üzerinden yayıldı. Sonrasında pek çok kurum 445'i dış dünyaya kapatmayı temel
  bir kural haline getirdi.
- **İnternete açık RDP:** Güvenlik raporlarında, internete açık 3389 portlarına yönelik parola
  deneme saldırıları fidye yazılımı olaylarının en yaygın giriş yollarından biri olarak
  sürekli anılır. Bu yüzden RDP'nin VPN arkasına alınması standart bir tavsiyedir.
""",
    sure_hedef_dk=30,
)
