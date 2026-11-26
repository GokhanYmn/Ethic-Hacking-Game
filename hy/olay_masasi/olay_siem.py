"""Olay Masası — SIEM Korelasyonu.

Üç ayrı log kaynağı (auth.log, web.log, firewall.log) ve tek bir saldırgan: web'de tarama,
auth'ta başarılı giriş, firewall'da C2'ye giden akış. Tek tek bakınca her log "normal"
görünür; ortak göstergeyle (IP) birleştirince saldırı zinciri ortaya çıkar.
"""
from __future__ import annotations

import re
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

C2_PORTLARI = [4444, 8443, 1337, 9001, 6667]
NORMAL_CIKIS = [("TCP", 443), ("UDP", 53), ("UDP", 123), ("TCP", 80)]


def _fw(t, act, yon, proto, src, dst, dpt, rng):
    return (t, f"{t:%Y-%m-%d %H:%M:%S} {act} {yon} {proto} SRC={src} DST={dst} "
               f"SPT={rng.randint(32768, 60999)} DPT={dpt}")


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)
    sunucu = m["sunucu"]
    srv = u.ic_ip(rng, "10.50.0")

    kullanilan = {srv}

    def yeni_dis():
        ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    def yeni_ofis():
        ip = u.benzersiz(rng, lambda r: u.ic_ip(r, "192.168.10"), 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    saldirgan = yeni_dis()
    c2 = yeni_dis()
    hesap = rng.choice(u.ISIMLER)
    sadik = u.isimler(rng, 3, {hesap})

    def rastgele_an():
        return gun + timedelta(hours=8, seconds=rng.randint(0, 36000))

    web, auth, fw = [], [], []

    # ---- Saldırgan zinciri ----
    t0 = gun + timedelta(hours=rng.randint(9, 14), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    n_web = rng.randint(18, 30)
    yollar = ["/admin/", "/login", "/.env", "/backup.zip", "/phpmyadmin/", "/wp-login.php", "/config.php",
              "/.git/HEAD", "/server-status", "/api/v1/users", "/old/", "/test.php", "/db.sql", "/uploads/",
              "/console", "/robots.txt", "/administrator/", "/cgi-bin/", "/.htaccess", "/info.php",
              "/dev/", "/staging/", "/panel/", "/manager/", "/data/", "/tmp/", "/logs/", "/secret/"]
    rng.shuffle(yollar)
    web_t = u.zamanlar(rng, t0 - timedelta(seconds=2), n_web, 1, 4)
    for i, t in enumerate(web_t):
        yol = yollar[i % len(yollar)]
        kod = 200 if (i == 0 or yol in ("/robots.txt", "/login")) else 404
        web.append((t, u.apache_satiri(saldirgan, t, "GET", "/" if i == 0 else yol, kod,
                                       rng.randint(200, 900), u.ARAC_UA["gobuster"])))
    for t in rng.sample(web_t, 3):
        fw.append(_fw(t, "ALLOW", "IN", "TCP", saldirgan, srv, 80, rng))
    ilk_saat = f"{web_t[0]:%H:%M:%S}"

    nf = rng.randint(3, 6)
    ssh_bas = web_t[-1] + timedelta(seconds=rng.randint(120, 600))
    pid = rng.randint(1000, 30000)
    fail_t = u.zamanlar(rng, ssh_bas, nf, 2, 10)
    for t in fail_t:
        kul = rng.choice(["root", "admin", "test", "oracle", hesap])
        auth.append((t, u.ssh_satiri(t, sunucu, pid,
                                     f"Failed password for {kul} from {saldirgan} port {rng.randint(33000, 60000)} ssh2")))
        fw.append(_fw(t, "ALLOW", "IN", "TCP", saldirgan, srv, 22, rng))
    giris_t = fail_t[-1] + timedelta(seconds=rng.randint(5, 20))
    auth.append((giris_t, u.ssh_satiri(t=giris_t, sunucu=sunucu, pid=pid,
                                       olay=f"Accepted password for {hesap} from {saldirgan} port {rng.randint(33000, 60000)} ssh2")))
    auth.append((giris_t, u.ssh_satiri(giris_t, sunucu, pid, f"pam_unix(sshd:session): session opened for user {hesap}")))
    fw.append(_fw(giris_t, "ALLOW", "IN", "TCP", saldirgan, srv, 22, rng))

    nb = rng.randint(4, 7)
    c2_port = rng.choice(C2_PORTLARI)
    c2_t = u.zamanlar(rng, giris_t + timedelta(seconds=rng.randint(30, 120)), nb, 30, 90)
    for t in c2_t:
        fw.append(_fw(t, "ALLOW", "OUT", "TCP", srv, c2, c2_port, rng))

    # ---- YEM: web ----
    web_ipler = [yeni_dis() for _ in range(rng.randint(8, 10))]
    for ip in web_ipler[1:]:
        for _ in range(rng.randint(2, 6)):
            t = rastgele_an()
            web.append((t, u.apache_satiri(ip, t, "GET", rng.choice(m["normal_sayfalar"]),
                                           rng.choice([200, 200, 200, 304]), rng.randint(500, 9000),
                                           rng.choice(u.TARAYICI_UA))))
    yem_tarayici = web_ipler[0]
    nikto_bas = rastgele_an()
    for i, t in enumerate(u.zamanlar(rng, nikto_bas, rng.randint(8, 12), 1, 5)):
        web.append((t, u.apache_satiri(yem_tarayici, t, "GET", rng.choice(yollar), 404,
                                       rng.randint(200, 600), u.ARAC_UA["Nikto"])))

    # ---- YEM: auth ----
    brute_ipler = [yeni_dis() for _ in range(2)]
    for ip in brute_ipler:
        bas = rastgele_an()
        for t in u.zamanlar(rng, bas, rng.randint(6, 14), 1, 4):
            auth.append((t, u.ssh_satiri(t, sunucu, rng.randint(1000, 30000),
                                         f"Failed password for {rng.choice(['root', 'admin', 'ubuntu'])} "
                                         f"from {ip} port {rng.randint(33000, 60000)} ssh2")))
            fw.append(_fw(t, "ALLOW", "IN", "TCP", ip, srv, 22, rng))
    ofis_ipler = []
    for kul in sadik:
        ip = yeni_ofis()
        ofis_ipler.append(ip)
        for _ in range(rng.randint(1, 3)):
            t = rastgele_an()
            yontem = rng.choice(["password", "publickey"])
            p = rng.randint(1000, 30000)
            auth.append((t, u.ssh_satiri(t, sunucu, p,
                                         f"Accepted {yontem} for {kul} from {ip} port {rng.randint(33000, 60000)} ssh2")))
            fw.append(_fw(t, "ALLOW", "IN", "TCP", ip, srv, 22, rng))
    # Bir meşru kullanıcının yazım hatası (başarısız ardından başarılı), ofis IP'sinden
    t = rastgele_an()
    kul, ip = sadik[0], ofis_ipler[0]
    auth.append((t, u.ssh_satiri(t, sunucu, 777, f"Failed password for {kul} from {ip} port 40111 ssh2")))
    t2 = t + timedelta(seconds=6)
    auth.append((t2, u.ssh_satiri(t2, sunucu, 777, f"Accepted password for {kul} from {ip} port 40112 ssh2")))

    # ---- YEM: firewall ----
    for ip in web_ipler:
        for _ in range(rng.randint(1, 3)):
            fw.append(_fw(rastgele_an(), "ALLOW", "IN", "TCP", ip, srv, rng.choice([80, 443]), rng))
    for _ in range(rng.randint(5, 8)):
        fw.append(_fw(rastgele_an(), "DENY", "IN", "TCP", yeni_dis(), srv,
                      rng.choice([23, 445, 3389, 3306, 8080]), rng))
    cikis_hedef = [yeni_dis() for _ in range(4)]
    for _ in range(rng.randint(16, 24)):
        proto, port = rng.choice(NORMAL_CIKIS)
        fw.append(_fw(rastgele_an(), "ALLOW", "OUT", proto, srv, rng.choice(cikis_hedef), port, rng))
    engelli = yeni_dis()
    fw.append(_fw(rastgele_an(), "DENY", "OUT", "TCP", srv, engelli, rng.choice(C2_PORTLARI), rng))

    def metne(olaylar):
        olaylar.sort(key=lambda x: x[0])
        return "\n".join(s for _, s in olaylar) + "\n"

    web_m, auth_m, fw_m = metne(web), metne(auth), metne(fw)
    desen = re.compile(rf"(?<![\d.]){re.escape(saldirgan)}(?![\d.])")
    toplam = sum(1 for metin in (web_m, auth_m, fw_m) for s in metin.splitlines() if desen.search(s))

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {sunucu} üç kaynaklı olay",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": sunucu, "kisi": m["kisi"]},
        "cevaplar": {
            "saldirgan": saldirgan,
            "ilk_saat": [ilk_saat],
            "hesap": [hesap],
            "c2": c2,
            "toplam": toplam,
        },
        "_web": web_m, "_auth": auth_m, "_fw": fw_m,
        "_yem_tarayici": yem_tarayici,
        "_yem_brute": set(brute_ipler),
        "_engelli": engelli,
        "_saldirgan": saldirgan,
        "_c2": c2,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "web.log", s["_web"])
    u.yaz(lab / "auth.log", s["_auth"])
    u.yaz(lab / "firewall.log", s["_fw"])


def _ortak_hata(g, beklenen, b):
    if g == b.senaryo["_yem_tarayici"]:
        return "Bu IP web'de tarama yapıyor ama SSH ya da firewall kayıtlarında başka izi var mı? Üç kaynakta da geçmesi gerek."
    if g in b.senaryo["_yem_brute"]:
        return "Bu IP auth.log'da parola deniyor ama web.log'da hiç görünmüyor. Üç dosyanın kesişimini ara."
    return None


def _c2_hata(g, beklenen, b):
    if g == b.senaryo["_saldirgan"]:
        return "Bu IP saldırganın kendisi. C2, sunucunun **dışarıya doğru** başlattığı bağlantının hedefidir."
    if g == b.senaryo["_engelli"]:
        return "Bu bağlantıyı firewall engellemiş (DENY). Gerçek C2'ye giden akış izin verilmiş (ALLOW) olanıdır."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]


def coz(lab: Path, s: dict) -> dict:
    ip = _sh("for f in auth.log web.log firewall.log; do grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' $f | sort -u; done "
             "| sort | uniq -c | awk '$1==3 {print $2}' | head -1", lab)
    saat = _sh(f"awk '$1==\"{ip}\" {{print $4}}' web.log | head -1 | cut -d: -f2-4", lab)
    hesap = _sh(f"grep Accepted auth.log | grep -F 'from {ip} ' | awk '{{print $9}}' | head -1", lab)
    c2 = _sh("awk '$3==\"ALLOW\" && $4==\"OUT\" && $9!=\"DPT=443\" && $9!=\"DPT=80\" && $9!=\"DPT=53\" && $9!=\"DPT=123\" "
             "{print $7}' firewall.log | cut -d= -f2 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    toplam = _sh(f"cat web.log auth.log firewall.log | grep -Fw '{ip}' | wc -l", lab)
    return {1: ip, 2: saat, 3: hesap, 4: c2, 5: toplam, 6: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("`auth.log`, `web.log` ve `firewall.log` dosyalarının **üçünde birden** geçen dış IP hangisi? "
          "(Saldırganın IP'si bu.)",
          IP("saldirgan", sik_hatalar=_ortak_hata),
          ("Her dosyadaki IP'leri ayrı ayrı çıkar; hangisi üçünde de var?",
           "`grep -oE` ile IP'leri al, her dosya için `sort -u` ile teke indir, hepsini birleştirip `uniq -c` ile say: "
           "sayısı 3 olan ortak IP'dir.",
           "`for f in auth.log web.log firewall.log; do grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' $f | sort -u; done "
           "| sort | uniq -c | sort -rn | head`"),
          puan=20, baslik="Ortak IP"),
    Gorev("Saldırgan IP'nin `web.log` içindeki **ilk isteği** hangi saatte? (SS:DD:SS)",
          Metin("ilk_saat", bicim="SS:DD:SS"),
          ("Saldırganın satırlarını süz; dosya zamana göre sıralı, ilki aradığın satır.",
           "Birinci alan IP, dördüncü alan zaman damgası: `[26/Nov/2026:10:00:00`. İlk iki ve üçüncü `:` parçasını al.",
           "`awk '$1==\"<IP>\" {print $4}' web.log | head -1 | cut -d: -f2-4`"),
          puan=15, baslik="İlk tarama saati"),
    Gorev("Saldırgan SSH'ta **hangi hesapla başarılı** giriş yaptı?",
          Metin("hesap", bicim="kullanıcı adı"),
          ("`auth.log`'ta başarılı girişleri `Accepted` kelimesi gösterir; başka IP'lerin girişleri de var.",
           "`Accepted` içeren satırları saldırganın IP'siyle daralt; hesap `for` kelimesinden sonra gelir.",
           "`grep Accepted auth.log | grep -F 'from <IP> ' | awk '{print $9}'`"),
          puan=15, baslik="Giriş hesabı"),
    Gorev("Saldırgan sunucuya girdikten sonra **sunucudan dışarıya** giden bir C2 bağlantısı kuruldu. "
          "C2 sunucusunun IP'si hangisi?",
          IP("c2", sik_hatalar=_c2_hata),
          ("`firewall.log`'ta yönü OUT olan, izin verilmiş (ALLOW) satırlara bak. Normal çıkış: 443, 80, 53, 123.",
           "Olağan dışı bir portta, tekrar tekrar (beacon) aynı hedefe giden akışı bul. 5. alan SRC, 7. alan hedef (DST=).",
           "`awk '$3==\"ALLOW\" && $4==\"OUT\" && $9!=\"DPT=443\" && $9!=\"DPT=80\" && $9!=\"DPT=53\" "
           "&& $9!=\"DPT=123\"' firewall.log` — çıkan hedefi say."),
          puan=20, baslik="C2 IP"),
    Gorev("Saldırgan IP'sini içeren **toplam satır sayısı** (üç dosyada birlikte) kaç?",
          Sayi("toplam"),
          ("Üç dosyada saldırganın izi var; hepsini say.",
           "`cat` ile dosyaları birleştir, `grep -F -w` ile IP'yi tam eşleştir, `wc -l` ile say.",
           "`cat web.log auth.log firewall.log | grep -Fw '<IP>' | wc -l`"),
          puan=15, baslik="Toplam olay"),
    Gorev("Olayların **doğru sırası** hangisi? (Zaman damgalarını üç dosyada karşılaştır.)",
          Secmeli([
              ("Web'de tarama → SSH'ta başarılı giriş → sunucudan C2'ye bağlantı",
               "Doğru. Önce keşif, sonra erişim, sonra kalıcılık/komuta bağlantısı: klasik zincir."),
              ("SSH'ta başarılı giriş → web'de tarama → sunucudan C2'ye bağlantı",
               "Zaman damgalarına bak: web taraması girişten önce başlıyor ve bitiyor."),
              ("Sunucudan C2'ye bağlantı → web'de tarama → SSH'ta başarılı giriş",
               "C2 bağlantısı ancak saldırgan içeri girdikten sonra kurulur; en sona gelir."),
              ("SSH'ta başarılı giriş → sunucudan C2'ye bağlantı → web'de tarama",
               "Tarama en başta; saldırgan hangi kapıdan gireceğini önce keşfeder."),
          ], dogru=0),
          ("Her kaynaktaki saldırgan satırlarının **ilk** zamanına bak.",
           "Web taraması, SSH girişi ve firewall'daki OUT akışının saatlerini yan yana yaz.",
           "Her adımın ilk saati: web için `awk '$1==\"<IP>\"' web.log | head -1`, giriş için `grep Accepted`, "
           "C2 için OUT satırları."),
          puan=15, baslik="Olay sırası"),
]

SEVIYE = Seviye(
    kimlik="olay_siem",
    cilt=7,
    bolum=109,
    baslik="SIEM Korelasyonu",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<kisi>> sunucuları
için bir şeylerin ters gittiğinden şüpheleniyor. **<<sunucu>>** için üç log kaynağı topladık:
`auth.log` (SSH girişleri), `web.log` (web erişimleri) ve `firewall.log` (ağ bağlantıları)."

"Tek tek bakınca her biri 'biraz gürültülü ama normal' görünüyor. Gerçek saldırı üçüne
birden dağılmış: bir IP web'de gezinmiş, SSH'a girmiş, sonra dışarıya konuşmuş. Ortak
göstergeyi bul, zinciri kur."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Korelasyon, ayrı kaynaklardaki zayıf sinyalleri tek bir güçlü hikâyeye çevirmektir. Bu
yüzden loglar tek bir yerde (log merkezileştirme / SIEM) toplanır, saatleri senkronlanır ve
ortak bir göstergeyle (IP, kullanıcı adı, host) birleştirilir. İyi bir korelasyon kuralı
şuna benzer: "aynı IP 10 dakika içinde web taraması yaptı, ardından SSH'ta başarılı giriş
yaptı, ardından sunucudan alışılmadık bir porta bağlantı çıktı" ve tek bir yüksek öncelikli
alarm üretir. Tek kaynağa bakan savunmacı gürültüde boğulur; birleşik görünüm zinciri açığa
çıkarır.
""",
    gercek_hayat="""
- **Target, 2013:** Saldırganlar bir tedarikçinin kimlik bilgileriyle ağa girdi. Güvenlik
  ürünleri ayrı ayrı uyarı üretti ve uyarılar bir araya getirilip aynı olay olarak
  değerlendirilmedi. Veri dışarı akarken izole uyarılar gözden kaçtı; birleşik bir görünüm
  zinciri çok daha erken gösterebilirdi.
- **SolarWinds, 2020:** İhlal, kaynakları birleştiren analistler alışılmadık giriş ve
  ağ bağlantılarını aynı hesapla ilişkilendirdiğinde fark edildi. Her kayıt kendi başına
  zararsızdı; birleşince hikâye ortaya çıktı.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b03",),
)
