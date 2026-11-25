"""Cilt 3 · Bölüm 7 — Kapanış Görevi: Küçük Bir Araç Takımı.

Beceri: önceki bölümlerde yazılan dört aracı (canli.sh, tarayici.py, dizin_bulucu.py,
logavci.py) tek bir iş akışında kullanmak: keşif -> port tarama -> web keşfi -> log analizi ->
bulguları birleştirip kısa bir iç değerlendirme yazmak.

Laboratuvar (her tohumda yeni): 127.0.0.1-60 arasında birkaç canlı cihaz (keşif portunda
banner), bunlardan birinde (ana sunucu) bir port aralığında birkaç servis ve bir web paneli;
web kökünde bir hesabın parolasını sızdıran unutulmuş bir yedek; ana sunucunun auth.log'unda
brute-force gürültüsü ve sızan hesapla dışarıdan yapılmış, eşiğe hiç takılmayan bir giriş.
"""
from __future__ import annotations

import random
import re
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Bayrak, Durum, Kume, Metin, Sayi, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir, tcp_banner
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c03_otomasyon.b02_canli_host import CANLI_SH, ONEK, SON_HOST
from hy.seviyeler.c03_otomasyon.b04_port_tarayici import TARAYICI_PY, AcikPortlar, tcp_portlari
from hy.seviyeler.c03_otomasyon.b05_dizin_bulucu import DIZIN_BULUCU_PY, KELIMELER, bulgular, isleyici_uret
from hy.seviyeler.c03_otomasyon.b06_log_avcisi import ESKI_KULLANICI, LOGAVCI_PY, _deneme, _giris, _Log
from hy.seviyeler.c03_otomasyon.ortak import http_sunucu

VAKALAR = [
    {
        "kod": "pazarix", "ag_ad": "mağaza ağı", "ag": "10.0.12", "sunucu": "pzx-web02",
        "panel": "Pazarix Kampanya Yönetimi", "ajan": "PZX-AJAN 1.9", "yazilim": "nginx/1.18.0",
        "hesap": "deploy", "sizinti": "deploy.sh.bak",
        "sizinti_icerik": "#!/bin/bash\n# otomatik yayin betigi (ESKI - silinecek)\nDEPLOY_USER=deploy\n"
                          "DEPLOY_PASS='{parola}'\nrsync -az ./ $DEPLOY_USER@pzx-web02:/var/www/\n",
        "yonlendir": ("yonetim", "/yonetim/giris.php"), "yasak": ".git", "acik": ["kampanyalar", "api"],
        "robots": "kampanya-taslaklari",
        "olay": "Kampanya haftası öncesi Tuncay Bey yeni mağaza ağı için bir iç değerlendirme istedi. Ağın "
                "laboratuvar kopyası hazır; ana sunucunun auth.log'u da geldi.",
    },
    {
        "kod": "kuzgun", "ag_ad": "yeni depo ağı", "ag": "10.30.9", "sunucu": "kzg-wms01",
        "panel": "Kuzgun Depo Yönetim Sistemi", "ajan": "KZG-AJAN v2.4", "yazilim": "Apache/2.4.52 (Ubuntu)",
        "hesap": "wms", "sizinti": "ayarlar.env.old",
        "sizinti_icerik": "APP_ENV=production\nWMS_DB=wms_depo\nSSH_USER=wms\nSSH_PASS={parola}\n",
        "yonlendir": ("panel", "/panel/giris.php"), "yasak": "server-status", "acik": ["sevkiyat", "api"],
        "robots": "eski-sevkiyat-raporlari",
        "olay": "Kuzgun Lojistik yeni depo ağını devreye aldı. Serdar Bey canlıya geçmeden önce ağın baştan sona "
                "bir kontrolünü istiyor; ana sunucunun auth.log'u da elimizde.",
    },
    {
        "kod": "paramix", "ag_ad": "taşınan veri merkezi ağı", "ag": "10.12.4", "sunucu": "pmx-mutabakat",
        "panel": "Paramix Mutabakat Paneli", "ajan": "PMX-AJAN 3.0", "yazilim": "nginx/1.24.0",
        "hesap": "mutabakat", "sizinti": "sync.conf.bak",
        "sizinti_icerik": "[sftp]\nhost = pmx-mutabakat\nuser = mutabakat\npass = {parola}\nkalan_gun = 30\n",
        "yonlendir": ("merchant", "/merchant/login.php"), "yasak": ".htpasswd", "acik": ["raporlar", "api"],
        "robots": "banka-dosyalari",
        "olay": "Paramix veri merkezi taşımasını bitirdi. Ece Hanım taşınan ağda unutulmuş bir şey kalmış mı, "
                "kalmışsa biri bunu kullanmış mı, öğrenmek istiyor.",
    },
    {
        "kod": "medora", "ag_ad": "laboratuvar cihaz ağı", "ag": "172.16.40", "sunucu": "medora-lims",
        "panel": "Medora Laboratuvar Bilgi Sistemi", "ajan": "MDR-CIHAZ-GW 2.0", "yazilim": "Apache/2.4.41 (Ubuntu)",
        "hesap": "lims", "sizinti": "lims_yedek.sql",
        "sizinti_icerik": "-- LIMS veritabani yedegi\n-- kullanıcı: lims / parola: {parola}\n"
                          "CREATE TABLE numune (id INT, hasta_no INT, sonuc TEXT);\n",
        "yonlendir": ("lab", "/lab/giris.php"), "yasak": "arsiv", "acik": ["sonuclar", "api"],
        "robots": "test-numune-verisi",
        "olay": "Medora'nın laboratuvar cihaz ağı yenilendi. Dr. Aslı Hanım, yeni ağın ve laboratuvar bilgi "
                "sisteminin baştan sona kontrolünü ve sunucuya yetkisiz bir giriş olup olmadığını soruyor.",
    },
]

ARALIKLAR = [(1000, 5000), (2000, 6000), (1024, 4096), (3000, 7000)]
ARACLAR = [("canli.sh", "c03b02"), ("tarayici.py", "c03b04"), ("dizin_bulucu.py", "c03b05"),
           ("logavci.py", "c03b06")]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    pd = rng.randint(20000, 45000)
    hostlar = sorted(rng.sample(range(2, SON_HOST + 1), rng.randint(5, 7)))
    ana = rng.choice(hostlar)
    bas, son = rng.choice(ARALIKLAR)
    turler = ["http", "ssh", "ftp", "sessiz"] + rng.sample(["smtp", "ssh2"], rng.randint(0, 2))
    portlar = rng.sample(range(max(bas, 1024) + 1, son), len(turler))
    servisler = dict(zip(portlar, turler))
    http = next(p for p, t in servisler.items() if t == "http")
    adlar = {}
    for i, h in enumerate(hostlar):
        adlar[h] = v["sunucu"] if h == ana else f"{rng.choice(['kasa', 'terminal', 'yazici', 'kamera', 'tablet'])}-{i + 1:02d}"
    parola = u.parola(rng)
    ihlal_ip = u.dis_ip(rng)
    return {
        "vaka": f"{m['ad']} — {v['ag_ad']} iç değerlendirmesi",
        "musteri": m,
        "v": v,
        "pd": pd,
        "hostlar": hostlar,
        "ana_ip": f"{ONEK}.{ana}",
        "aralik": (bas, son),
        "servisler": {str(p): t for p, t in servisler.items()},
        "adlar": {str(k): a for k, a in adlar.items()},
        "parola": parola,
        "ihlal_ip": ihlal_ip,
        "log_tohum": rng.randint(1, 10**9),
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "ag_ad": v["ag_ad"], "pd": pd,
            "bas": bas, "son": son, "son_host": SON_HOST, "sunucu": v["sunucu"], "ana_ip": f"{ONEK}.{ana}",
            "http": http, "hesap": v["hesap"], "sizinti": v["sizinti"], "ihlal_ip": ihlal_ip,
            "canli_sayi": len(hostlar), "ag": v["ag"],
        },
        "cevaplar": {
            "hostlar": [f"{ONEK}.{h}" for h in hostlar],
            "ana_ip": f"{ONEK}.{ana}",
            "portlar": sorted(portlar),
            "http": http,
            "hesap": v["hesap"],
            "ihlal_ip": ihlal_ip,
            "bayrak": u.bayrak(rng, "arac_takimi"),
        },
    }


def _web_tablosu(s: dict) -> dict:
    v = s["v"]
    html = "text/html; charset=utf-8"
    yonlendir, konum = v["yonlendir"]
    t = {
        "": (200, {}, f"<html><head><title>{v['panel']}</title></head><body><h1>{v['panel']}</h1></body></html>\n", html),
        "robots.txt": (200, {}, f"User-agent: *\nDisallow: /{v['robots']}/\n", "text/plain; charset=utf-8"),
        yonlendir: (301, {"Location": konum}, "", html),
        konum.strip("/"): (200, {}, f"<html><body><h1>{v['panel']} — Giriş</h1></body></html>\n", html),
        v["yasak"]: (403, {}, "<html><body><h1>403 Forbidden</h1></body></html>\n", html),
        v["sizinti"]: (200, {}, v["sizinti_icerik"].format(parola=s["parola"]), "application/octet-stream"),
        v["robots"]: (200, {}, f"<html><body><p>Taslak.</p><!-- {s['cevaplar']['bayrak']} --></body></html>\n", html),
    }
    for ad in v["acik"]:
        t[ad] = (200, {}, f"<html><body><h1>{ad}</h1></body></html>\n", html)
    return t


def _auth_log(s: dict) -> list:
    v = s["v"]
    rng = random.Random(s["log_tohum"])
    log = _Log(rng, v["sunucu"])
    gun = u.gun(rng)
    kullanicilar = u.isimler(rng, 4)
    uid = {k: 1001 + i for i, k in enumerate(kullanicilar + [v["hesap"]])}
    t = gun + timedelta(minutes=rng.randint(0, 3))
    while t < gun + timedelta(hours=23, minutes=55):
        pid = log.ekle(t, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
        log.ekle(t + timedelta(seconds=rng.randint(1, 40)), "CRON", "pam_unix(cron:session): session closed for user root", pid)
        t += timedelta(minutes=rng.choice([1, 2, 2, 3]))
    for k in kullanicilar:
        for _ in range(rng.randint(2, 4)):
            _giris(log, gun + timedelta(seconds=rng.randint(8 * 3600, 18 * 3600)), k, u.ic_ip(rng, v["ag"]),
                   "publickey", uid[k])
    ci_ip = u.ic_ip(rng, v["ag"])   # sızan hesabı normalde iç ağdaki otomasyon kullanır
    for saat in sorted(rng.sample(range(0, 23), 6)):
        _giris(log, gun + timedelta(hours=saat, minutes=rng.randint(0, 59)), v["hesap"], ci_ip, "publickey", uid[v["hesap"]])
    for ip in u.benzersiz(rng, u.dis_ip, rng.randint(3, 4), {s["ihlal_ip"]}):
        bas = gun + timedelta(seconds=rng.randint(0, 20 * 3600))
        for i in range(rng.randint(25, 140)):
            kul = rng.choice(["root", "root"] + rng.sample(ESKI_KULLANICI, 3))
            _deneme(log, bas + timedelta(seconds=i * rng.randint(2, 5)), ip, kul, kul != "root")
    # Asıl ihlal: sızan parolayla dışarıdan, bir yazım hatası sonrası tek seferde giriş — eşiğe takılmaz
    t = gun + timedelta(seconds=rng.randint(19 * 3600, 23 * 3600))
    _deneme(log, t, s["ihlal_ip"], v["hesap"], False)
    pid = _giris(log, t + timedelta(seconds=11), v["hesap"], s["ihlal_ip"], "password", uid[v["hesap"]])
    log.ekle(t + timedelta(minutes=rng.randint(4, 15)), "sshd",
             f"pam_unix(sshd:session): session closed for user {v['hesap']}", pid)
    return log.satirlar()


def _kelimeler(s: dict) -> list:
    v = s["v"]
    rng = random.Random(s["log_tohum"] + 1)
    zorunlu = [v["yonlendir"][0], v["yasak"], v["sizinti"], "robots.txt"] + v["acik"]
    liste = list(dict.fromkeys(KELIMELER + zorunlu))
    rng.shuffle(liste)
    liste.insert(rng.randint(3, len(liste) - 3), "")
    return liste


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    bas, son = s["aralik"]
    satirlar = _auth_log(s)
    u.yaz(lab / "loglar" / "auth.log", "\n".join(satirlar) + "\n")
    u.yaz(lab / "kelimeler.txt", "\n".join(_kelimeler(s)) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — {v['ag_ad']} iç değerlendirmesi (laboratuvar kopyası)\n\n"
          f"Ağ             : {ONEK}.1 - {ONEK}.{SON_HOST}   (gerçek ağ: {v['ag']}.1-{SON_HOST})\n"
          f"Keşif portu    : TCP {s['pd']} (her cihazda çalışan {v['ajan']} ajanı)\n"
          f"Tarama kapsamı : TCP {bas}-{son} (iki uç dahil)\n"
          "Web kelime list: kelimeler.txt\n"
          f"Sunucu logu    : loglar/auth.log ({v['sunucu']}, son 24 saat, {len(satirlar)} satır)\n"
          "SOC eşiği      : 5 başarısız deneme\n\n"
          "Araçlarını araclar/ klasörüne topla: canli.sh, tarayici.py, dizin_bulucu.py, logavci.py\n")
    u.yaz(lab / "araclar" / "OKUBENI.txt",
          "Önceki bölümlerde yazdığın araçları buraya kopyala, örneğin:\n"
          "  cp ../c03b02/canli.sh ../c03b04/tarayici.py ../c03b05/dizin_bulucu.py ../c03b06/logavci.py araclar/\n")


def servis(s: dict, lab: Path, dur) -> None:
    v = s["v"]
    ana = s["ana_ip"]
    sunucular = []
    for h in s["hostlar"]:
        ip = f"{ONEK}.{h}"
        sunucular.append(tcp_banner(ip, s["pd"], f"{v['ajan']} | {s['adlar'][str(h)]} | durum=hazir\n"))
    bannerlar = {
        "ssh": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n",
        "ssh2": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n",
        "ftp": f"220 ({v['sunucu']} FTP - vsFTPd 3.0.5)\r\n",
        "smtp": f"220 {v['sunucu']}.{s['musteri']['alan']} ESMTP Postfix\r\n",
        "sessiz": "",
    }
    for p, tur in s["servisler"].items():
        if tur == "http":
            sunucular.append(http_sunucu(ana, int(p), isleyici_uret(_web_tablosu(s), v["yazilim"])))
        else:
            sunucular.append(tcp_banner(ana, int(p), bannerlar[tur]))
    calistir(sunucular, dur)


# ---------------------------------------------------------------- denetimler

def _takim_denetle(b: Baglam) -> Sonuc:
    klasor = Path(b.lab) / "araclar"
    eksik = [(ad, kaynak) for ad, kaynak in ARACLAR if not (klasor / ad).is_file()]
    if eksik:
        cp = " ".join(f"../{k}/{a}" for a, k in eksik)
        return Sonuc(False, f"araclar/ klasöründe eksik araç(lar): {', '.join(a for a, _ in eksik)}. Önceki "
                     f"laboratuvarlarından kopyala: `cp {cp} araclar/` (ya da yeniden yaz).",
                     yakin=len(eksik) < len(ARACLAR))
    for ad, _ in ARACLAR:
        calistirici, hata, yakin = bt.hazirla(klasor / ad, b)
        if hata:
            return Sonuc(False, f"araclar/{ad}: {hata}", yakin=yakin)
        hata = bt.kullanim_denetle(calistirici)
        if hata:
            return Sonuc(False, f"araclar/{ad}: {hata}", yakin=True)
    return Sonuc(True, "Araç takımın hazır: dördü de yerinde, çalışıyor ve yanlış kullanımda ne beklediğini söylüyor. "
                       "Gerçek pentester'ların kişisel betik koleksiyonu tam olarak böyle başlar.")


def _hesap_hata(g, beklenen, b):
    if g == b.senaryo["parola"].casefold():
        return "Bu parola. Soru, parolası sızan HESABIN adını soruyor."
    return None


def _ihlal_hata(g, beklenen, b):
    if g.startswith(b.senaryo["v"]["ag"] + "."):
        return "Bu iç ağdan bir giriş (otomasyonun kendisi). Soru iç ağ DIŞINDAN gelen girişi soruyor."
    return None


def _ana_hata(g, beklenen, b):
    if g in b.senaryo["cevaplar"]["hostlar"]:
        return f"Bu cihaz canlı ama {b.senaryo['metin']['bas']}-{b.senaryo['metin']['son']} aralığında açık portu yok."
    return None


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path, zaman: int = 180) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=zaman).stdout


def coz(lab: Path, s: dict) -> dict:
    for ad, metin in (("canli.sh", CANLI_SH), ("tarayici.py", TARAYICI_PY), ("dizin_bulucu.py", DIZIN_BULUCU_PY),
                      ("logavci.py", LOGAVCI_PY)):
        bt.betik_yaz(lab / "araclar" / ad, metin)
    m = s["metin"]
    hostlar = re.findall(r"127\.0\.0\.\d+", _sh(f"./araclar/canli.sh 127.0.0 {m['pd']}", lab))
    ana, portlar = "", []
    for h in hostlar:
        bulunan = sorted(tcp_portlari(_sh(f"python3 araclar/tarayici.py {h} {m['bas']} {m['son']}", lab)))
        if bulunan:
            ana, portlar = h, bulunan
    http = next(p for p in portlar
                if _sh(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 3 http://{ana}:{p}/", lab).strip() == "200")
    url = f"http://{ana}:{http}"
    yollar = bulgular(_sh(f"python3 araclar/dizin_bulucu.py {url} kelimeler.txt", lab))
    hesap = ""
    for yol in yollar:
        icerik = _sh(f"curl -s {url}/{yol}", lab)
        e = re.search(r"(?:USER\s*=\s*|user\s*=\s*|kullanıcı:\s*)([A-Za-z_]\w*)", icerik)
        if e:
            hesap = e.group(1)
    ihlal = ""
    for satir in _sh(f"grep 'Accepted' loglar/auth.log | grep ' for {hesap} '", lab).splitlines():
        ip = re.search(r"from (\S+)", satir).group(1)
        if not ip.startswith(s["v"]["ag"] + "."):
            ihlal = ip
    gizli = re.search(r"Disallow: /([^/\s]+)/", _sh(f"curl -s {url}/robots.txt", lab)).group(1)
    bayrak = re.search(r"FLAG\{[^}]+\}", _sh(f"curl -s {url}/{gizli}/", lab)).group(0)
    rapor = (f"Ağda {len(hostlar)} canlı cihaz var. Ana sunucu {ana} üzerinde {len(portlar)} port açık, web paneli "
             f"{http} portunda. Web kökündeki yedek dosyası {hesap} hesabının parolasını sızdırıyor ve auth.log'a "
             f"göre bu hesapla {ihlal} adresinden dışarıdan giriş yapılmış. Yedek silinmeli, parola değişmeli.")
    return {1: "", 2: " ".join(hostlar), 3: ana, 4: " ".join(map(str, portlar)), 5: http, 6: hesap, 7: ihlal,
            8: bayrak, 9: rapor}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Araç takımını topla", """
Bu ciltte dört araç yazdın: canlı host bulucu, port tarayıcı, dizin bulucu ve log avcısı.
Gerçek pentester'ların hepsinin böyle kişisel bir betik koleksiyonu vardır ve hep aynı yerde
dururlar. Önceki bölümlerin laboratuvarları bu klasörün kardeşleri:
""", komut="ls ..", sonra="""
`c03b02`, `c03b04`, `c03b05`, `c03b06` klasörlerindeki araçlarını bu laboratuvarın
`araclar/` klasörüne kopyala:

```
cp ../c03b02/canli.sh ../c03b04/tarayici.py ../c03b05/dizin_bulucu.py ../c03b06/logavci.py araclar/
```

O bölümleri oynamadıysan araçları yeniden yazman gerekecek; görev 1 bunu denetler.
"""),
    Adim("İş akışı", """
Bir iç değerlendirme hep aynı sırayla ilerler (PTES gibi metodolojilerin özü):

1. **Keşif:** ağda kim yaşıyor? (canli.sh)
2. **Tarama:** canlı makinelerde hangi kapılar açık? (tarayici.py)
3. **Numaralandırma:** açık web servisinde neler saklı? (dizin_bulucu.py)
4. **Kanıt ve iz:** loglarda bu açıkların kullanıldığına dair bir iz var mı? (logavci.py, grep)
5. **Rapor:** hepsini birkaç cümlede, kanıtıyla anlat.

Laboratuvarın özetine bak:
""", komut="cat OKUBENI.txt"),
    Adim("Bir aracın çıktısı, diğerinin girdisi", """
Araçları birbirine bağlamanın yolu, birinin çıktısından ihtiyacın olanı süzüp diğerine
vermektir. Örneğin canli.sh'in satırlarından sadece IP'leri almak:
""", komut="""echo "[+] Canlı: 127.0.0.5" | grep -oE '127\\.0\\.0\\.[0-9]+'""", sonra="""
Bunu bir döngüyle birleştirirsen her canlı makineyi otomatik tararsın:

```
for ip in $(./araclar/canli.sh 127.0.0 PORT | grep -oE '127\\.0\\.0\\.[0-9]+'); do
    echo "== $ip"; python3 araclar/tarayici.py $ip ILK SON
done
```
"""),
    Adim("Kanıtı sakla", """
Rapor kanıtla yazılır. `tee` bir komutun çıktısını hem ekrana basar hem dosyaya yazar; `-a`
dosyanın sonuna ekler. Her aracın çıktısını bir not dosyasında topla:
""", komut='echo "[*] değerlendirme başladı: $(date +%H:%M)" | tee -a notlar.txt', sonra="""
Sonra `python3 araclar/tarayici.py ... | tee -a notlar.txt` gibi kullanırsın. Görevin sonunda
bu notlar, yazacağın kısa iç değerlendirmenin hammaddesi olacak.
"""),
    Adim("Bulgu nasıl yazılır?", """
İyi bir bulgu dört parçadan oluşur: **ne** bulundu, **kanıtı** ne (komut ve çıktı),
**etkisi** ne (saldırgan bununla ne yapabilir), **öneri** ne. "Web kökünde yedek dosyası
var" bir gözlemdir; "web kökündeki `x.bak` herkese açık, içindeki parola `y` hesabına ait ve
auth.log'a göre bu hesapla dışarıdan giriş yapılmış; dosya kaldırılmalı, parola
değiştirilmeli" bir bulgudur.

**Hacker gözüyle:** Bu vakadaki asıl ders, araçların tek tek değil **birlikte** anlam
kazanmasıdır. Log avcın eşiğe takılmayan bir girişi göremez; ama dizin bulucunun bulduğu
sızıntı sana hangi hesaba bakacağını söyler.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Araç takımını kur: lab'daki `araclar/` klasöründe dört aracın da (`canli.sh`, `tarayici.py`, "
          "`dizin_bulucu.py`, `logavci.py`) olsun ve her biri argümansız çalışınca kullanım mesajı verip sıfırdan "
          "farklı kodla çıksın. Hazır olunca `cevap 1`.",
          Durum(_takim_denetle, "```\ncp ../c03b02/canli.sh ../c03b04/tarayici.py ../c03b05/dizin_bulucu.py "
                                "../c03b06/logavci.py araclar/\n```"),
          ("Önceki bölümlerin laboratuvarları `..` altında duruyor.",
           "`ls ../c03b02 ../c03b04 ../c03b05 ../c03b06` ile araçlarını bul, `cp` ile `araclar/`'a kopyala.",
           "`cp ../c03b02/canli.sh ../c03b04/tarayici.py ../c03b05/dizin_bulucu.py ../c03b06/logavci.py araclar/` "
           "sonra `chmod +x araclar/canli.sh`"),
          puan=30, baslik="Araç takımı"),
    Gorev("Keşif: <<ag_ad>>'nda (`127.0.0.1-<<son_host>>`) keşif portu <<pd>>'den cevap veren **bütün** canlı "
          "cihazlar hangileri?",
          Kume("hostlar", tur="ip", bicim="IP listesi"),
          ("Bölüm 2'nin aracı.",
           "`./araclar/canli.sh 127.0.0 <<pd>>`",
           "Çıktıdaki IP'leri boşlukla ayırarak yaz."),
          puan=30, baslik="Keşif"),
    Gorev("Tarama: canlı cihazlardan sadece biri <<bas>>-<<son>> aralığında servis çalıştırıyor (ana sunucu "
          "<<sunucu>>). Hangisi?",
          IP("ana_ip", sik_hatalar=_ana_hata),
          ("Her canlı cihazı kapsam aralığında tara.",
           "Bölüm 4'ün aracını her canlı IP için çalıştır: `python3 araclar/tarayici.py IP <<bas>> <<son>>`",
           "`for ip in $(./araclar/canli.sh 127.0.0 <<pd>> | grep -oE '127\\.0\\.0\\.[0-9]+'); do echo \"== $ip\"; "
           "python3 araclar/tarayici.py $ip <<bas>> <<son>> | grep /tcp; done`"),
          puan=35, baslik="Ana sunucu"),
    Gorev("Ana sunucuda <<bas>>-<<son>> aralığında açık olan **bütün** portlar hangileri?",
          AcikPortlar("portlar", host_yolu=("ana_ip",), aralik_yolu=("aralik",)),
          ("Bir önceki görevde zaten taradın.",
           "`python3 araclar/tarayici.py ANA_IP <<bas>> <<son>>`",
           "`/tcp`'den önceki sayıları boşlukla ayırarak yaz."),
          puan=30, baslik="Açık portlar"),
    Gorev("Bu portlardan hangisinde web paneli (HTTP) çalışıyor?",
          Sayi("http"),
          ("Web sunucuları banner göndermez; istek bekler.",
           "Açık portların her birine `curl -s -I --max-time 2 http://ANA_IP:PORT/` gönder.",
           "`HTTP/1.0 200` ve `Server:` başlığı dönen port."),
          puan=25, baslik="Web paneli"),
    Gorev("Web: panelde dizin bulucunu `kelimeler.txt` ile çalıştır. Bulunan dosyalardan biri unutulmuş bir yedek ve "
          "bir **hesabın** parolasını sızdırıyor. Parolası sızan hesabın adı ne?",
          Metin("hesap", sik_hatalar=_hesap_hata, bicim="hesap (kullanıcı) adı"),
          ("Bölüm 5'in aracı; sonra bulduğun dosyaları oku.",
           "`python3 araclar/dizin_bulucu.py http://ANA_IP:WEB_PORT kelimeler.txt`, sonra yedeğe benzeyen yolu "
           "`curl -s` ile oku.",
           "Dosyada `USER`, `user` ya da `kullanıcı` geçen satırdaki ad."),
          puan=40, baslik="Sızıntı"),
    Gorev("İz: `loglar/auth.log`'da brute-force yapan IP'lerin hiçbiri içeri giremedi. Ama sızan hesapla **iç ağın "
          "(<<ag>>.x) dışından** başarılı bir giriş var. Hangi IP?",
          IP("ihlal_ip", sik_hatalar=_ihlal_hata),
          ("Log avcın eşik üstünü gösterir; ama bu giriş eşiğe hiç takılmamış olabilir.",
           "Sızan hesabın `Accepted` satırlarına bak: `grep Accepted loglar/auth.log | grep ' for HESAP '`",
           "İç ağ adresleri <<ag>>. ile başlar; başka bir adresten gelen `Accepted` satırını bul."),
          puan=40, baslik="Sessiz giriş"),
    Gorev("Panel, arama motorlarından gizlemek istediği bir sayfayı kendisi ilan ediyor. Oradaki bayrağı bul.",
          Bayrak("bayrak"),
          ("Bölüm 5'te arama motorlarına \"buraya bakma\" diyen dosyayı hatırla.",
           "`curl -s http://ANA_IP:WEB_PORT/robots.txt`",
           "Disallow satırındaki yolu iste; bayrak HTML yorumunun içinde."),
          puan=30, baslik="Gizli taslak"),
    Gorev("Rapor: <<kisi>> için 3-5 cümlelik bir iç değerlendirme özeti yaz (ne buldun, kanıtı, etkisi, önerin). "
          "Cevabı tırnak içinde gönder.",
          Serbest("<<musteri>> <<ag_ad>>'nda <<canli_sayi>> canlı cihaz tespit edildi. Ana sunucu <<sunucu>> "
                  "(<<ana_ip>>) üzerinde <<bas>>-<<son>> aralığında birden fazla servis açık; web paneli <<http>> "
                  "portunda. Web kökünde herkese açık kalmış `<<sizinti>>` dosyası <<hesap>> hesabının parolasını "
                  "sızdırıyor ve auth.log'a göre bu hesapla iç ağ dışındaki <<ihlal_ip>> adresinden başarılı giriş "
                  "yapılmış; brute-force denemeleri ise başarısız. Öneri: yedek dosyası hemen kaldırılmalı, "
                  "<<hesap>> parolası değiştirilip SSH'ta parola ile giriş kapatılmalı, o oturumda yapılanlar "
                  "incelenmeli ve gereksiz servisler (FTP gibi) kapatılmalı.", min_kelime=25),
          ("Önceki görevlerin cevapları raporun iskeleti.",
           "Dört parça: ne buldun, kanıtı, etkisi, önerin.",
           "Canlı cihaz sayısı, ana sunucu ve açık servisler, sızan dosya ve hesap, dışarıdan giriş yapan IP, öneriler."),
          puan=40, baslik="İç değerlendirme"),
]


SEVIYE = Seviye(
    kimlik="c03b07",
    cilt=3,
    bolum=7,
    baslik="Kapanış Görevi: Küçük Bir Araç Takımı",
    brifing="""
Cuma öğleden sonra. Selin bu haftanın son dosyasını masana bırakıyor: "**<<musteri>>**.
<<olay>>"

"Bu sefer adım adım tarif yok. Elinde dört aracın var: keşif, tarama, web, log. Ağı
bul, ana sunucuyu bul, panelde ne saklı bak, loglarda bunun izini ara. Sonunda <<kisi>>
için kısa bir iç değerlendirme yaz."

Mert ayağa kalkıp ceketini alıyor: "Ben kahve almaya gidiyorum. Döndüğümde araçların
`araclar/` klasöründe sıralı dursun. Ve evet, raporu bu sefer sen yazıyorsun."

Deniz kulaklığının tekini çıkarıyor: "Bir ipucu: eşiğe takılmayan girişler en tehlikelileridir."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Artık sadece araç kullanan değil, araç yazabilen birisin. Bu vakada hiçbir araç tek başına
hikâyeyi anlatmadı: keşif ağı gösterdi, tarama ana sunucuyu, dizin bulucu sızan parolayı;
log avcısı ise eşiğe takılmayan girişi göremedi, onu sızıntının söylediği hesaba bakarak
buldun. Saldırgan da böyle düşünür: en gürültülü yoldan değil, birinin unuttuğu bir yedekten
girer. Savunma tarafının dersi: canlı sunucuda yedek bırakma, SSH'ta parola ile girişi kapat
ve sadece "çok deneme" değil "beklenmedik yerden başarılı giriş" için de alarm kur.
""",
    gercek_hayat="""
- **Uber, 2016:** Uber'in açıklamalarına göre saldırganlar, mühendislerin kullandığı özel bir
  kod deposunda bulunan erişim anahtarlarıyla şirketin bulut depolamasına girip milyonlarca
  sürücü ve yolcunun verisine ulaştı. Unutulmuş ya da yanlış yerde duran kimlik bilgileri,
  bu bölümdeki sızan yedek gibi, gürültüsüz bir giriş kapısıdır.
- **Kimlik bilgisiyle girişin görünmezliği:** Pek çok olay müdahale raporu, geçerli bir
  kullanıcı adı-parola ile yapılan girişin brute-force alarmlarını tetiklemediğini ve
  ihlalin bu yüzden geç fark edildiğini anlatır. Bu yüzden SOC'lar "olağandışı konumdan
  başarılı giriş" gibi kurallar da çalıştırır.
- **Kişisel araç takımı:** Sızma testi uzmanlarının kendi betiklerini ve notlarını bir
  araya topladığı kişisel depolar sektörde yaygındır; birçoğu GitHub'da açık kaynak olarak
  paylaşılır. Bu cildin dört aracı senin deponun ilk sürümü.
""",
    sure_hedef_dk=50,
)
