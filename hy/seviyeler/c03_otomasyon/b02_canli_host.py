"""Cilt 3 · Bölüm 2 — İlk Aracın: Canlı Host Bulucu.

Beceri: ping sweep mantığı, TCP ile canlılık (bash /dev/tcp, nc -z; nmap -PS fikri),
döngü + `&` + `wait` ile paralel tarama, sonuçları dosyaya yazma ve doğru sıralama,
envanterle karşılaştırıp kaçak cihaz bulma, banner okuma.

Laboratuvar: Linux'ta 127.0.0.0/8'in tamamı loopback'tir. Seviyenin servisi 127.0.0.2-60
arasındaki birkaç adreste iki farklı portta dinler; bu adresler müşterinin gerçek
ağındaki cihazları temsil eder. Ping burada her adrese cevap aldığı için yanıltıcıdır;
canlılık TCP ile sınanır.
"""
from __future__ import annotations

import random
import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Durum, IP, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir, tcp_banner
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

ONEK = "127.0.0"
SON_HOST = 60

VAKALAR = [
    {
        "kod": "kuzgun", "ag_gercek": "10.30.8", "ag_ad": "depo ağı", "ajan": "KZG-AJAN v2.3",
        "cihazlar": ["el-terminali", "forklift-tablet", "etiket-yazici", "rampa-kamera", "tarti-istasyonu",
                     "sevkiyat-pc", "depo-sunucu"],
        "olay": "Depo ağında kaç cihaz olduğunu kimse bilmiyor; envanter iki yıl önce güncellenmiş. "
                "Serdar Bey geçen hafta rampada tanımadığı bir kablo görmüş.",
    },
    {
        "kod": "ferahbank", "ag_gercek": "10.50.2", "ag_ad": "Moda şubesi ağı", "ajan": "FB-SUBE-AJAN 4.1",
        "cihazlar": ["gise-pc", "atm", "kamera-kayit", "kat-yazicisi", "mudur-pc", "para-sayac", "sube-sunucu"],
        "olay": "Şube denetiminde, ağ dolabında etiketsiz bir cihaz olabileceği not edilmiş. "
                "Kaan Bey, şube ağındaki her cihazın envanterde olduğunu kanıtlamak istiyor.",
    },
    {
        "kod": "medora", "ag_gercek": "172.16.30", "ag_ad": "yoğun bakım cihaz ağı", "ajan": "MDR-CIHAZ-GW 1.8",
        "cihazlar": ["monitor-gw", "infuzyon-srv", "lab-cihaz", "hemsire-pc", "ventilator-gw", "pacs-onbellek",
                     "yatak-terminali"],
        "olay": "Yoğun bakım cihaz ağı hastanenin en hassas ağı; Dr. Aslı Hanım oraya izinsiz bir "
                "cihaz takılmış olabileceğinden şüpheleniyor ve envanteri doğrulamak istiyor.",
    },
    {
        "kod": "yesiltepe", "ag_gercek": "192.168.70", "ag_ad": "akıllı otopark ağı", "ajan": "YTB-SENSOR 2.0",
        "cihazlar": ["otopark-gw", "plaka-kamera", "bariyer", "odeme-kiosk", "tabela-kontrol", "otopark-sunucu",
                     "doluluk-sensoru"],
        "olay": "Otopark sisteminin yüklenicisi değişti ve eski firmanın sahada ne bıraktığını kimse "
                "bilmiyor. Nurcan Hanım ağdaki her cihazı envanterle karşılaştırmamızı istiyor.",
    },
]

SSH_BANNER = ["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
              "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", "SSH-2.0-dropbear_2022.83"]
KACAK_BANNER = "SSH-2.0-OpenSSH_9.2p1 Raspbian-2+deb12u3"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    p1, p2 = rng.sample(range(20000, 45000), 2)
    adresler = rng.sample(range(2, SON_HOST + 1), 15)
    k1 = rng.randint(4, 7)
    k2 = rng.randint(3, 5)
    ortak = rng.randint(1, 2)
    h1 = adresler[:k1]                                   # ajan portu açık olanlar
    h2 = h1[:ortak] + adresler[k1:k1 + k2 - ortak]       # SSH portu açık olanlar
    kacak = h2[-1]                                       # envanterde olmayan, sadece SSH
    emekli = adresler[k1 + k2 - ortak: k1 + k2 - ortak + 2]  # envanterde var ama kapalı
    adlar, kullanilan = {}, set()
    for a in sorted(set(h1) | set(h2) | set(emekli)):
        if a == kacak:
            continue
        while True:
            ad = f"{rng.choice(v['cihazlar'])}-{rng.randint(1, 12):02d}"
            if ad not in kullanilan:
                break
        kullanilan.add(ad)
        adlar[a] = ad
    bayrakli = rng.choice(h1)
    sure = rng.choice([1, 2, 3])
    canli_hepsi = sorted(set(h1) | set(h2))
    olu = rng.choice([x for x in range(2, SON_HOST + 1) if x not in canli_hepsi and x not in emekli])
    ssh_banner = {a: rng.choice(SSH_BANNER) for a in h2}
    ssh_banner[kacak] = KACAK_BANNER
    return {
        "vaka": f"{m['ad']} — {v['ag_ad']} keşfi",
        "musteri": m,
        "v": v,
        "portlar": (p1, p2),
        "h1": sorted(h1), "h2": sorted(h2), "kacak": kacak, "emekli": sorted(emekli),
        "adlar": adlar, "bayrakli": bayrakli, "ssh_banner": ssh_banner,
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "ag_ad": v["ag_ad"],
            "ag_gercek": v["ag_gercek"], "ajan": v["ajan"].split()[0], "p1": p1, "p2": p2,
            "sure": sure, "olu": olu, "ornek": sorted(h1)[0], "son": SON_HOST,
        },
        "cevaplar": {
            "h2": [f"{ONEK}.{a}" for a in sorted(h2)],
            "kacak": f"{ONEK}.{kacak}",
            "bayrak": u.bayrak(rng, "kayip_cihaz"),
            "sure_sn": (SON_HOST - len(h1)) * sure,
        },
    }


SIRALI_SH = """#!/bin/bash
# sirali.sh — SIRALI (yavaş) canlı host bulucu: her adresi sırayla dener.
# Kullanım: ./sirali.sh <ag_oneki> <port>      örn: ./sirali.sh 127.0.0 8080
if [ $# -ne 2 ]; then
    echo "Kullanım: $0 <ag_oneki> <port>"
    exit 1
fi
onek="$1"
port="$2"
for i in $(seq 1 60); do
    if timeout 1 bash -c "echo > /dev/tcp/$onek.$i/$port" 2>/dev/null; then
        echo "[+] Canlı: $onek.$i"
    fi
done
"""

CANLI_SH = """#!/bin/bash
# canli.sh — paralel canlı host bulucu (TCP ile)
if [ $# -ne 2 ]; then
    echo "Kullanım: $0 <ag_oneki> <port>   (örnek: $0 127.0.0 8080)"
    exit 1
fi
onek="$1"
port="$2"
for i in $(seq 1 60); do
    (timeout 1 bash -c "echo > /dev/tcp/$onek.$i/$port" 2>/dev/null && echo "[+] Canlı: $onek.$i") &
done
wait
"""


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = s["musteri"]
    p1, p2 = s["portlar"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} — {v['ag_ad']} (laboratuvar kopyası)\n\n"
          f"Laboratuvar ağı : {ONEK}.1 - {ONEK}.{SON_HOST}\n"
          f"Gerçek ağ       : {v['ag_gercek']}.1 - {v['ag_gercek']}.{SON_HOST}  (son sayılar birebir eşleşir)\n"
          f"Cihaz ajanı     : TCP {p1}  ({v['ajan']})\n"
          f"Uzaktan yönetim : TCP {p2}  (SSH)\n\n"
          "Not (Deniz): Ağda ICMP (ping) kapalı. Laboratuvarda da ping'e güvenme;\n"
          "127.0.0.0/8'in tamamı loopback olduğu için her adres ping'e cevap verir.\n\n"
          "Kendi betiğini lab'ın köküne yaz: canli.sh\n")
    satirlar = ["# IP            cihaz                  son kontrol",
                f"# {v['ag_ad']} envanteri — laboratuvar adresleriyle"]
    for a, ad in sorted(s["adlar"].items()):
        satirlar.append(f"{ONEK}.{a:<6} {ad:<22} 2024-0{(a % 9) + 1}-1{a % 10}")
    u.yaz(lab / "envanter.txt", "\n".join(satirlar) + "\n")
    u.yaz(lab / "ornekler" / "sirali.sh", SIRALI_SH, mod=0o755)


def servis(s: dict, lab: Path, dur) -> None:
    p1, p2 = s["portlar"]
    ajan = s["v"]["ajan"]
    bayrak = s["cevaplar"]["bayrak"]
    sunucular = []
    for a in s["h1"]:
        ad = s["adlar"].get(a, "bilinmeyen")
        ek = f" | bakim_kodu={bayrak}" if a == s["bayrakli"] else ""
        sunucular.append(tcp_banner(f"{ONEK}.{a}", p1, f"{ajan} | {ad} | durum=hazir{ek}\n"))
    for a in s["h2"]:
        sunucular.append(tcp_banner(f"{ONEK}.{a}", p2, s["ssh_banner"][a] + "\r\n"))
    calistir(sunucular, dur)


# ---------------------------------------------------------------- denetimler

def _hostlar(c: bt.Cikti, onek: str) -> list:
    sonuc = []
    for ip in bt.ipler(c.stdout):
        bas, son = ip.rsplit(".", 1)
        if bas == onek and 1 <= int(son) <= 254:
            sonuc.append(ip)
    return sonuc


def _paralel_mi(metin: str) -> bool:
    return bool(re.search(r"\bwait\b|xargs\s+.*-P|\bparallel\b", metin))


def _canli_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    p1, _ = s["portlar"]
    hata = bt.kullanim_denetle(calistir, ONEK)
    if hata:
        return Sonuc(False, hata + "\n    (Sadece ağ önekini verdim, portu vermedim.)", yakin=True)
    rng = random.Random()

    def adresler(r):
        onek = f"127.{r.randint(1, 250)}.{r.randint(1, 250)}"
        port = r.randint(20000, 45000)
        return [(f"{onek}.{x}", port) for x in r.sample(range(2, SON_HOST + 1), r.randint(2, 4))]

    gecici = bt.gecici_dinleyici_ac(rng, adresler)
    try:
        g_onek = gecici.adresler[0][0].rsplit(".", 1)[0]
        g_port = gecici.adresler[0][1]
        denemeler = [(ONEK, p1, {f"{ONEK}.{a}" for a in s["h1"]}),
                     (g_onek, g_port, {h for h, _ in gecici.adresler})]
        for onek, port, beklenen in denemeler:
            c = calistir(onek, port, zaman_asimi=30)
            nasil = calistir.goster(onek, port)
            cokme = calistir.cokme(c)
            if cokme:
                return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
            bulunan = set(_hostlar(c, onek))
            if bulunan == beklenen:
                continue
            lab_kumesi = {f"{ONEK}.{a}" for a in s["h1"]}
            if onek != ONEK and lab_kumesi <= set(bt.ipler(c.stdout)):
                return Sonuc(False, "Farklı bir ağ önekiyle çalıştırdım ama laboratuvardaki sonuçları verdin. "
                             "Önek ya da portu sabit yazmış olabilir misin? `$1` ve `$2`'yi kullan.", yakin=True)
            if len(bulunan) >= SON_HOST - 1:
                return Sonuc(False, f"`{nasil}` neredeyse her adresi ({len(bulunan)}) canlı buldu. `ping` mi "
                             "kullandın? 127.x'in tamamı loopback, ping her adrese cevap alır; canlılığı TCP "
                             "portuyla sına. Ya da `&&` yerine `;` yazdığın için bağlantı başarısız olsa da "
                             "`echo` çalışıyor olabilir.", yakin=True)
            if not bulunan:
                ek = ""
                if calistir.shebang.endswith("/sh"):
                    ek = (" Shebang'in `#!/bin/sh`: Kali'de bu `dash`'tir ve `/dev/tcp`'yi tanımaz. "
                          "`#!/bin/bash` yaz.")
                return Sonuc(False, f"`{nasil}` hiç canlı host bulamadı (beklenen {len(beklenen)}).{ek} "
                             f"Kendin `{nasil}` ile dene; `2>/dev/null`'u geçici "
                             "olarak kaldırıp hata mesajlarına bak." + bt.ozet(c), yakin=bool(ek))
            eksik = beklenen - bulunan
            fazla = bulunan - beklenen
            mesaj = f"`{nasil}` {len(beklenen)} canlı host bulmalıydı; betiğin {len(bulunan)} buldu"
            if eksik and not fazla:
                mesaj += (f", {len(eksik)} tanesini kaçırdı. Tarama aralığı 1-{SON_HOST} mı? `timeout` süresi çok mu "
                          "kısa? `wait` unutulmuş olabilir mi?")
            elif fazla:
                mesaj += f", aralarında canlı olmayan {len(fazla)} adres var: {', '.join(sorted(fazla)[:3])}."
            return Sonuc(False, mesaj + bt.ozet(c), yakin=True)
    finally:
        gecici.__exit__()
    if not _paralel_mi(calistir.metin):
        return Sonuc(False, "Sonuçların doğru ama betiğin sıralı çalışıyor (içinde `wait` yok). Görev paralel bir "
                     "tarayıcı istiyor: her denemeyi `( ... ) &` ile arka plana at, döngüden sonra `wait` yaz. "
                     "Gerçek ağda sıralı sürüm cevap vermeyen her adres için timeout kadar bekler.", yakin=True)
    return Sonuc(True, "canli.sh doğru ve paralel çalışıyor; senin hiç görmediğin bir ağda da doğru sonucu verdi. "
                       "Bu, `nmap -sn`'in ilkel ama dürüst bir kopyası.")


def _sirali_ip(ip: str) -> tuple:
    return tuple(int(x) for x in ip.split("."))


def _dosya_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    adaylar = [Path(b.calisma_dizini or b.lab) / "canlilar.txt", Path(b.lab) / "canlilar.txt"]
    yol = next((p for p in adaylar if p.is_file()), None)
    if yol is None:
        return Sonuc(False, "`canlilar.txt` bulunamadı (lab'da ya da bulunduğun klasörde). Betiğinin çıktısını "
                     "`>` ile bu dosyaya yönlendir.")
    metin = yol.read_text(encoding="utf-8", errors="replace")
    ipler = [ip for ip in bt.ipler(metin) if ip.startswith(ONEK + ".")]
    h1 = {f"{ONEK}.{a}" for a in s["h1"]}
    h2 = {f"{ONEK}.{a}" for a in s["h2"]}
    hepsi = h1 | h2
    if not ipler:
        return Sonuc(False, "canlilar.txt içinde hiç IP yok.")
    if set(ipler) == h1:
        return Sonuc(False, f"Dosyada sadece {s['metin']['p1']} portunun sonuçları var. SSH ({s['metin']['p2']}) "
                     "taramasını da ekle: iki çıktıyı birleştir.", yakin=True)
    if set(ipler) == h2:
        return Sonuc(False, f"Dosyada sadece SSH portunun sonuçları var; ajan portunu ({s['metin']['p1']}) da ekle.",
                     yakin=True)
    if set(ipler) != hepsi:
        eksik, fazla = len(hepsi - set(ipler)), len(set(ipler) - hepsi)
        return Sonuc(False, f"Dosyadaki IP'ler iki taramanın birleşimiyle uyuşmuyor ({eksik} eksik, {fazla} fazla).",
                     yakin=bool(set(ipler) & hepsi))
    if len(ipler) != len(set(ipler)):
        return Sonuc(False, "Bazı IP'ler dosyada birden fazla kez geçiyor (iki portu da açık olan cihazlar). "
                     "Tekrarları `sort -u` ile at.", yakin=True)
    if ipler != sorted(ipler, key=_sirali_ip):
        if ipler == sorted(ipler):
            return Sonuc(False, "Sıralama alfabetik olmuş: 127.0.0.12, 127.0.0.3'ten önce geliyor. Sayısal sıralama "
                         "için `sort -V` (ya da `sort -t. -k4 -n`) kullan.", yakin=True)
        return Sonuc(False, "IP'ler sıralı değil. `sort -V -u` ile hem sırala hem tekrarları at.", yakin=True)
    return Sonuc(True, f"canlilar.txt hazır: {len(ipler)} canlı cihaz, tekrarsız ve sayısal sırada. Raporun "
                       "ekine girecek dosya tam olarak bu.")


def _sure_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    s = b.senaryo
    t = s["metin"]["sure"]
    if n == SON_HOST * t:
        return "Canlı hostlar anında cevap verir; sadece cevap VERMEYEN adresler timeout kadar bekletir."
    if n == (SON_HOST - len(set(s["h1"]) | set(s["h2"]))) * t:
        return f"Bu taramada sadece {s['metin']['p1']} portu deneniyor; o portta cevap vermeyenleri say."
    if n == SON_HOST - len(s["h1"]):
        return "Adres sayısını buldun; şimdi her birinin kaç saniye beklettiğiyle çarp."
    return None


def _ps_hata(g, beklenen, b):
    if "sn" in g:
        return "`-sn` ping taramasının (port taramasız keşif) adı. TCP SYN ile canlılık soran ayrı bir `-P` seçeneği var."
    if "ss" in g:
        return "`-sS` SYN PORT taramasıdır. Canlılık (host keşfi) seçenekleri `-P` ile başlar."
    if g.startswith("-pa") or g == "pa":
        return "Yaklaştın: `-PA` TCP ACK ile sorar. SYN ile soran hangisi?"
    return None


# ---------------------------------------------------------------- test çözücüsü

def _sh(komut: str, lab: Path, zaman: int = 30) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True, timeout=zaman).stdout


def coz(lab: Path, s: dict) -> dict:
    p1, p2 = s["portlar"]
    bt.betik_yaz(lab / "canli.sh", CANLI_SH)
    h1 = re.findall(r"127\.0\.0\.\d+", _sh(f"./canli.sh 127.0.0 {p1}", lab))
    h2 = re.findall(r"127\.0\.0\.\d+", _sh(f"./canli.sh 127.0.0 {p2}", lab))
    _sh(f"(./canli.sh 127.0.0 {p1}; ./canli.sh 127.0.0 {p2}) | grep -oE '127\\.0\\.0\\.[0-9]+' "
        "| sort -V -u > canlilar.txt", lab)
    kacak = _sh("grep -v '^#' envanter.txt | awk '{print $1}' | sort > .envanter_ip; "
                "sort canlilar.txt | comm -23 - .envanter_ip; rm -f .envanter_ip", lab).strip()
    bayrak = ""
    for ip in h1:
        cikti = _sh(f"timeout 2 bash -c 'cat < /dev/tcp/{ip}/{p1}'", lab)
        m = re.search(r"FLAG\{[^}]+\}", cikti)
        if m:
            bayrak = m.group(0)
    sure = (SON_HOST - len(set(h1))) * s["metin"]["sure"]
    secmeli = SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]
    return {1: "", 2: " ".join(h2), 3: "", 4: kacak, 5: bayrak, 6: sure, 7: secmeli, 8: "-PS"}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Ping sweep: kim ayakta?", """
Bir ağa ilk girdiğinde ilk soru şudur: **hangi adreslerde gerçekten bir makine var?**
Klasik cevap **ping taraması** (ping sweep): her adrese bir ICMP "yankı isteği" (echo
request) gönder, cevap vereni "canlı" say. `ping -c 1` tek paket gönderir, `-W 1` en fazla
1 saniye bekler.

Bu laboratuvarda müşterinin ağı `127.0.0.1-<<son>>` adreslerine kuruldu. Hiçbir cihazın
olmadığını bildiğimiz bir adrese ping at:
""", komut="ping -c 1 -W 1 127.0.0.<<olu>>", sonra="""
Cevap geldi! Çünkü Linux'ta **127.0.0.0/8'in tamamı loopback**'tir (kendi makinen):
her adrese kendi bilgisayarın cevap verir. Gerçek ağlarda ise tersi olur: güvenlik
duvarları ICMP'yi sık sık engeller ve ayakta olan makineler ping'e "ölü" görünür. İki
durumda da ders aynı: **ping'e körü körüne güvenme.**
"""),
    Adim("TCP ile kapı çalmak", """
Ping yerine bir TCP portuna bağlanmayı deneyebiliriz: bağlantı kurulursa orada bir makine
(ve bir servis) var demektir. nmap'in `-PS` (TCP SYN ping) seçeneğinin fikri budur.

Bash'in gizli bir özelliği var: `/dev/tcp/IP/PORT` diye bir "dosyaya" yazmaya çalışınca
bash o adrese TCP bağlantısı açar. `timeout 1` ise denemeyi en fazla 1 saniye sürdürür.
Ajan portu (<<p1>>) açık olan bir cihazı dene:
""", komut='timeout 1 bash -c "echo > /dev/tcp/127.0.0.<<ornek>>/<<p1>>" && echo "canlı"', sonra="""
Bağlantı kuruldu, `&&` sayesinde "canlı" yazıldı. Bu özellik **bash'e** aittir; `sh`
(Kali'de dash) bunu bilmez. Betiklerinde shebang'in `#!/bin/bash` olmasının bir nedeni de bu.
"""),
    Adim("Kapalı kapı", """
Şimdi boş bir adresi dene ve çıkış koduna bak:
""", komut='timeout 1 bash -c "echo > /dev/tcp/127.0.0.<<olu>>/<<p1>>"; echo "çıkış kodu: $?"', sonra="""
"Connection refused" ve sıfırdan farklı kod: karşı taraf bağlantıyı RST ile reddetti
(Cilt 2, Bölüm 3). Gerçek ağda boş bir adres hiç cevap vermez; o zaman `timeout` devreye
girer ve 1 saniye beklersin. Bu bekleme, birazdan paralelliğin neden şart olduğunu gösterecek.
"""),
    Adim("Döngüye koy: sıralı tarayıcı", """
Tek adres için çalışan komutu bir `for` döngüsüne koyunca elinde bir tarayıcı olur.
Hazır bir **sıralı** örnek var; oku:
""", komut="cat ornekler/sirali.sh", sonra="""
`if timeout 1 bash -c "..." 2>/dev/null; then` kalıbı: komut başarılıysa (çıkış kodu 0)
`if` doğru olur. `2>/dev/null` "Connection refused" gürültüsünü çöpe atar. Bu betik
adresleri **teker teker** dener.
"""),
    Adim("Ne kadar sürüyor?", """
`time` bir komutun ne kadar sürdüğünü ölçer. Sıralı betiği ajan portunda çalıştır:
""", komut="time ./ornekler/sirali.sh 127.0.0 <<p1>>", sonra="""
Laboratuvarda hızlı, çünkü loopback'te kapalı portlar anında reddedilir. Gerçek bir ağda
cevap vermeyen her adres `timeout` kadar bekletir: 254 adreslik bir /24'te bu dakikalar
demektir.
"""),
    Adim("Paralel: & ve wait", """
Bir komutun sonuna `&` koyarsan arka planda çalışır ve döngü onu beklemeden devam eder.
`wait` ise arka plandaki **bütün** işlerin bitmesini bekler. Üç tane 1 saniyelik işi
paralel çalıştır:
""", komut='time (for i in 1 2 3; do (sleep 1; echo "iş $i bitti") & done; wait)', sonra="""
Üç iş toplam ~1 saniyede bitti; sıralı olsa 3 saniye sürerdi. Tarayıcıda da her denemeyi
`( ... ) &` ile arka plana atıp döngüden sonra `wait` yazacaksın. `wait`'i unutursan
betik sonuçlar gelmeden biter ve çıktılar istem satırının arasına karışır; dosyaya
yönlendirdiysen sonuçlar eksik kalabilir.
"""),
    Adim("Kapıyı çalınca kim cevap veriyor?", """
Bazı servisler bağlanana kendini tanıtan bir satır gönderir: **banner**. `/dev/tcp`'den
okumak için `cat <` kullanılır:
""", komut='timeout 2 bash -c "cat < /dev/tcp/127.0.0.<<ornek>>/<<p1>>"', sonra="""
Cihaz adını ve durumunu söyledi. Bulduğun her canlı host için bunu elle yapmak yerine bir
döngü yazabilirsin; görevlerden biri tam olarak bunu isteyecek. `nc -z -w 1 IP PORT` de
aynı canlılık testini yapar (nc kuruluysa).
"""),
    Adim("Sonuçları dosyaya yaz ve doğru sırala", """
Tarama sonuçlarını `>` ile dosyaya yazarsın (Cilt 1, Bölüm 4). Paralel taramada çıktılar
karışık sırada gelir, o yüzden sıralaman gerekir. Ama dikkat: `sort` varsayılan olarak
**alfabetik** sıralar. Farkı gör:
""", komut='printf "127.0.0.12\\n127.0.0.3\\n127.0.0.3\\n" | sort -V -u', sonra="""
`-V` (sürüm sıralaması) sayıları sayı gibi sıralar: .3, .12'den önce gelir. `-u` tekrarları
atar. Düz `sort` deneseydin .12 önce gelirdi.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`canli.sh` adında **paralel** bir canlı host bulucu yaz: `./canli.sh <ag_oneki> <port>` "
          "verilen önekin `.1`'den `.<<son>>`'a kadar her adresine o porttan TCP ile bağlanmayı denesin ve "
          "bağlanabildiklerini (IP'leriyle) yazsın. İki argüman gelmezse kullanım mesajı + `exit 1`. "
          "Kendin dene: `./canli.sh 127.0.0 <<p1>>`",
          bt.BetikKontrol("canli.sh", _canli_denetle,
                          "Örnek `canli.sh`:\n\n```\n" + CANLI_SH.rstrip() + "\n```", zaman_asimi=30),
          ("`ornekler/sirali.sh` neredeyse hazır; ona paralellik eklemen yeter.",
           "Döngünün içindeki denemeyi `( ... ) &` ile arka plana at; `done`'dan sonra `wait` yaz. "
           "Başarılıysa yazdırmak için `&& echo`.",
           "İskelet:\n\n```\n#!/bin/bash\nif [ $# -ne 2 ]; then ... exit 1; fi\nfor i in $(seq 1 <<son>>); do\n"
           "    (timeout 1 bash -c \"echo > /dev/tcp/$1.$i/$2\" 2>/dev/null && echo ...) &\ndone\n...\n```"),
          puan=60, baslik="Canlı host bulucu"),
    Gorev("Bazı cihazlar ajan çalıştırmıyor, sadece uzaktan yönetim (SSH) portu <<p2>> açık. Aracını "
          "bu portla çalıştır: <<p2>> portunda canlı olan **bütün** adresler hangileri?",
          Kume("h2", tur="ip", bicim="IP listesi (virgül/boşlukla)"),
          ("Aracın parametrik; portu değiştirmen yeter.",
           "`./canli.sh 127.0.0 <<p2>>`",
           "Çıktıdaki IP'leri boşlukla ayırarak yaz: `cevap 2 127.0.0.a 127.0.0.b ...`"),
          puan=30, baslik="İkinci kapı"),
    Gorev("Raporun eki için iki taramanın (<<p1>> ve <<p2>>) sonucunu birleştir: lab'da `canlilar.txt` "
          "dosyası oluştur; her satırda bir canlı IP olsun, **tekrarsız** ve **sayısal sırada**. Hazır olunca "
          "`cevap 3`.",
          Durum(_dosya_denetle, "```\n(./canli.sh 127.0.0 <<p1>>; ./canli.sh 127.0.0 <<p2>>) \\\n"
                                "  | grep -oE '127\\.0\\.0\\.[0-9]+' | sort -V -u > canlilar.txt\n```"),
          ("İki komutun çıktısını tek bir boruya vermek için onları parantez içinde `;` ile çalıştırabilirsin.",
           "IP'leri ayıklamak için `grep -oE`, sıralamak ve tekrarları atmak için `sort -V -u`, dosyaya yazmak için `>`.",
           "`(./canli.sh 127.0.0 <<p1>>; ./canli.sh 127.0.0 <<p2>>) | grep -oE '127\\.0\\.0\\.[0-9]+' | sort ... > canlilar.txt`"),
          puan=40, baslik="canlilar.txt"),
    Gorev("<<kisi>> envanteri `envanter.txt` dosyasında. Ağda canlı olan ama envanterde **olmayan** cihaz "
          "hangisi?",
          IP("kacak"),
          ("Elinde iki liste var: canlilar.txt ve envanterdeki IP'ler. Fark kümesini arıyorsun.",
           "Envanterden IP sütununu `awk '{print $1}'` ile al; iki listeyi `comm` ya da `grep -vxFf` ile karşılaştır.",
           "`grep -v '^#' envanter.txt | awk '{print $1}' > env.txt` sonra `grep -vxFf env.txt canlilar.txt`"),
          puan=40, baslik="Kaçak cihaz"),
    Gorev("Canlı cihazlardan birinin ajanı, karşılama satırında (banner) bir bakım kodu sızdırıyor. Bayrağı bul.",
          Bayrak("bayrak"),
          ("Ajan portu (<<p1>>) açık her cihaz bağlanınca bir satır gönderiyor.",
           "Eğitimdeki `cat < /dev/tcp/IP/PORT` kalıbını, aracının bulduğu her IP için bir döngüde çalıştır.",
           "`for ip in $(./canli.sh 127.0.0 <<p1>> | grep -oE '127[0-9.]+'); do timeout 2 bash -c \"cat < "
           "/dev/tcp/$ip/<<p1>>\"; done | grep ...`"),
          puan=40, baslik="Konuşkan ajan"),
    Gorev("Gerçek ağda ICMP kapalı ve boş adresler hiç cevap vermiyor (her biri `timeout` kadar bekletiyor). "
          "Mert'in eski **sıralı** betiği `timeout <<sure>>` kullanıyor ve `.1-.<<son>>` aralığında sadece ajan "
          "portunu (<<p1>>) deniyor. Canlı cihazlar anında cevap verirse bu tarama en az kaç saniye sürer?",
          Sayi("sure_sn", sik_hatalar=_sure_hata),
          ("Süreyi sadece cevap vermeyen adresler belirler.",
           "<<son>> adresten kaçı ajan portunda canlı? Gerisi bekletir.",
           "(<<son>> - ajan portunda canlı olanların sayısı) × <<sure>>"),
          puan=25, baslik="Neden paralel"),
    Gorev("Deniz soruyor: \"Müşterinin ofis ağında ping taraması 3 makine buldu, ama aynı ağda 443 portuna TCP "
          "ile bağlanmayı deneyen betik 11 makine buldu. En olası açıklama ne?\"",
          Secmeli([
              ("Güvenlik duvarı ICMP'yi engelliyor; makineler ping'e cevap vermiyor",
               "Doğru. Kurumsal ağlarda ve Windows'un varsayılan güvenlik duvarında ICMP yankı isteği sık sık "
               "kapalıdır. Bu yüzden nmap ICMP'nin yanında TCP denemeleri de yapar."),
              ("TCP betiği aynı makineyi birden çok kez sayıyor, sonuç şişmiş",
               "Her adres bir kez denenir; aynı IP iki kez sayılmaz. Fark gerçek."),
              ("Ping taraması daha doğrudur, TCP betiği yanlış pozitif üretiyor",
               "Bağlantı kurulduysa karşıda bir makine vardır; asıl yanıltıcı olan cevapsız ping'dir."),
              ("443 portu sadece sanal makinelerde açılır, fiziksel makineler sayılmaz",
               "Böyle bir kural yok; port, makinenin türünden bağımsızdır."),
          ]),
          ("Ping hangi protokolü kullanır, TCP betiği hangisini?",
           "Bir güvenlik duvarı bir protokolü engellerken diğerine izin verebilir mi?",
           "ICMP kapalı bir ağda canlı makineler ping'e \"ölü\" görünür."),
          puan=20, baslik="Ping yanılgısı"),
    Gorev("nmap'te ICMP yerine belirli bir porta **TCP SYN** göndererek canlılık soran host keşfi seçeneği "
          "hangisi? (örn. `-xY`)",
          Metin(kabul=["-PS", "PS", "-PS443", "-PS80", "-PS22"], on_ekleri_at=("nmap ",), sik_hatalar=_ps_hata,
                bicim="nmap seçeneği"),
          ("Host keşfi (ping) seçenekleri `-P` ile başlar.",
           "İkinci harf, gönderilen TCP bayrağının baş harfidir.",
           "SYN → S. `-P` + `S`."),
          puan=20, baslik="nmap karşılığı"),
]


SEVIYE = Seviye(
    kimlik="c03b02",
    cilt=3,
    bolum=2,
    baslik="İlk Aracın: Canlı Host Bulucu",
    brifing="""
Selin bir ağ şeması bırakıyor masana: "**<<musteri>>** — <<ag_ad>>. <<olay>>"

"Ağın bir kopyasını laboratuvarına kurduk: `127.0.0.1-<<son>>` adresleri, gerçek ağdaki
`<<ag_gercek>>.1-<<son>>`'u temsil ediyor. Cihazların ajanı <<p1>> portunda dinliyor,
bazılarında sadece SSH (<<p2>>) açık. Senden ağda **kimin yaşadığını** bulan bir araç
istiyorum; sonra sonuçları envanterle karşılaştıracağız."

Deniz kulaklığını çıkarıyor: "Ping'e güvenme. Bizim taraf ICMP'yi yıllar önce kapattı."
Mert gülüyor: "Ben de tek tek elle denerim diye bir gece harcamıştım. Döngü yaz, `&` koy,
`wait` de. Raporu kim yazacak, onu sonra konuşuruz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Bu yirmi satırlık betik `nmap -sn`'in ilkel bir kopyası. Gerçek işte nmap kullanacaksın;
daha hızlı ve ICMP kapalıysa başka yollar dener. Ama nmap olmayan bir makineye sızdığında
bu betik seni kurtarır ve nmap'in "Host seems down" dediği anlarda neden yanılabileceğini
artık biliyorsun. Savunma tarafının dersi de buradan çıkıyor: envanterde olmayan bir cihaz,
güvenliğini kimsenin üstlenmediği bir cihazdır; düzenli keşif taraması ve envanter
karşılaştırması kaçak cihazları yakalamanın en ucuz yoludur.
""",
    gercek_hayat="""
- **nmap'in host keşfi:** nmap kılavuzuna göre `-sn` varsayılan olarak yalnızca ICMP değil,
  443'e TCP SYN, 80'e TCP ACK ve ICMP zaman damgası isteği de gönderir; root olmayan bir
  kullanıcıyla çalışınca 80 ve 443 portlarına TCP bağlantısı dener. Yani senin bu bölümde
  yaptığın "TCP ile canlılık" fikri nmap'in kendisinde de var.
- **Mirai (2016):** Mirai botnet'i internetteki rastgele adreslerde Telnet portlarını
  tarayıp varsayılan parolalı IoT cihazlarını buldu ve ele geçirdi. Basit bir "bağlanmayı
  dene" döngüsünün internet ölçeğinde ne kadar etkili olabildiğinin en bilinen örneği.
- **Önce envanter:** CIS Kritik Güvenlik Kontrolleri listesinin ilk maddesi kurumdaki
  varlıkların (cihazların) envanteri ve kontrolüdür. Bilmediğin cihazı koruyamazsın; keşif
  taraması ile envanteri karşılaştırmak bu kontrolün pratikteki karşılığıdır.
""",
    sure_hedef_dk=40,
)
