"""Cilt 6 · Bölüm 3 — Kabuklar: Bind ve Reverse (kavramsal, tespit odaklı).

Beceri: bind ve reverse kabuk farkını ve güvenlik duvarıyla ilişkisini anlamak; kurgusal `ss -tanp`
çıktısı, süreç tablosu ve güvenlik duvarı logundan şüpheli bir giden bağlantıyı ve onu tutan süreci
bulmak; çıkış (egress) filtrelemesiyle kapatmak.

Hiçbir kabuk komutu, yük ya da terminal yükseltme komutu yazılmaz.
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

VAKALAR = [
    {"kod": "pazarix", "host": "pzx-web01", "web": "nginx", "app": "php-fpm8.2", "ag": "10.0.0", "port": None,
     "olay": "Kampanya sitesinin web sunucusu, kimsenin tanımadığı bir dış adrese bağlanıyor gibi görünüyor."},
    {"kod": "medora", "host": "medora-portal", "web": "nginx", "app": "java", "ag": "10.20.0", "port": None,
     "olay": "Randevu portalının sunucusunda, SOC'nin gece raporunda açıklanamayan bir giden bağlantı var."},
    {"kod": "atolye", "host": "atolye-web", "web": "apache2", "app": "apache2", "ag": "192.168.1", "port": 443,
     "olay": "Atölye Kahve'nin küçük sunucusunda tuhaf bir giden bağlantı var; üstelik portu masum görünüyor."},
]
OLAY_PORTLARI = [4443, 8081, 9001, 1337, 6667, 5555, 7777]
IZIN_PORT = {0: 443, 1: 8443}


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    yerel = u.ic_ip(rng, v["ag"])
    ipler = u.benzersiz(rng, u.dis_ip, 8)
    saldirgan, ayna, izleme = ipler[0], ipler[1], ipler[2]
    istemciler = ipler[3:8]
    port = v["port"] or rng.choice(OLAY_PORTLARI)
    sus_pid = rng.randint(4000, 9000)
    isci_pid = sus_pid - rng.randint(5, 30)
    usta_pid = rng.randint(700, 1200)
    cron_pid = rng.randint(400, 650)
    mesru_pid = rng.randint(9100, 9400)
    yerel_port = rng.randint(40000, 60000)
    gun = u.gun(rng)
    bas = gun + timedelta(hours=rng.randint(9, 22), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    return {
        "vaka": f"{m['ad']} — {v['host']} giden bağlantı",
        "musteri": m, "v": v, "yerel": yerel, "saldirgan": saldirgan, "ayna": ayna, "izleme": izleme,
        "istemciler": istemciler, "sus_pid": sus_pid, "isci_pid": isci_pid, "usta_pid": usta_pid,
        "cron_pid": cron_pid, "mesru_pid": mesru_pid, "port": port, "yerel_port": yerel_port, "bas": bas,
        "brifing": f"""
Deniz Kara, **{m['ad']}**'in **{v['host']}** sunucusunun kopyasını açıyor: "{v['olay']} Sunucuda
uygulamayı çalıştıran bir hesap var, ama gördüğüm bağlantıyı onun başlatmış olması için bir nedeni yok."

Selin ekliyor: "Bu bölümde kabuk almayı öğrenmiyoruz, **kabuğun izlerini** okuyoruz. Elinde sunucudan alınmış
üç kopya var: bağlantı tablosu (`ss -tanp` çıktısı), süreç tablosu ve güvenlik duvarı logu. Şüpheli bağlantıyı
bul, onu hangi sürecin başlattığını çıkar, ve sunucuyu bir daha böyle bir bağlantı kuramayacak hale getir."
""",
        "metin": {"musteri": m["ad"], "host": v["host"], "mesru_pid": str(mesru_pid)},
        "cevaplar": {
            "ip": saldirgan,
            "port": port,
            "pid": sus_pid,
            "ust": v["app"],
            "saat": f"{bas:%H:%M:%S}",
        },
    }


def _ss(s: dict) -> str:
    v = s["v"]
    rng = random.Random(f"{s['yerel']}:{s['sus_pid']}")
    y = s["yerel"]
    sat = ["State  Recv-Q Send-Q Local-Address:Port Peer-Address:Port Process"]
    sat.append(f"LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))")
    sat.append(f"LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"{v['web']}\",pid={s['usta_pid']},fd=6))")
    sat.append(f"LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"{v['web']}\",pid={s['usta_pid']},fd=7))")
    sat.append(f"LISTEN 0 80 127.0.0.1:3306 0.0.0.0:* users:((\"mariadbd\",pid=1044,fd=21))")
    for ist in s["istemciler"]:
        sat.append(f"ESTAB 0 0 {y}:443 {ist}:{rng.randint(30000, 60000)} "
                   f"users:((\"{v['web']}\",pid={s['usta_pid'] + rng.randint(1, 6)},fd={rng.randint(8, 20)}))")
    sat.append(f"ESTAB 0 0 {y}:22 {u.ic_ip(rng, v['ag'])}:{rng.randint(30000, 60000)} users:((\"sshd\",pid=3120,fd=4))")
    sat.append(f"ESTAB 0 0 127.0.0.1:{rng.randint(40000, 60000)} 127.0.0.1:3306 "
               f"users:((\"{v['app']}\",pid={s['isci_pid']},fd=12))")
    sat.append(f"ESTAB 0 0 {y}:{rng.randint(40000, 60000)} {s['ayna']}:443 users:((\"apt-get\",pid=2210,fd=5))")
    sat.append(f"ESTAB 0 0 {y}:{rng.randint(40000, 60000)} {s['izleme']}:8443 users:((\"izleme-ajani\",pid=1203,fd=7))")
    sat.append(f"ESTAB 0 0 {y}:{s['yerel_port']} {s['saldirgan']}:{s['port']} users:((\"sh\",pid={s['sus_pid']},fd=3))")
    rng.shuffle(sat[5:])
    govde = sat[1:]
    # LISTEN satırları üstte kalsın, ESTAB satırları karışsın
    listen = [x for x in govde if x.startswith("LISTEN")]
    estab = [x for x in govde if x.startswith("ESTAB")]
    rng.shuffle(estab)
    return "\n".join([sat[0]] + listen + estab) + "\n"


def _ps(s: dict) -> str:
    v = s["v"]
    sat = ["  PID  PPID USER      COMM",
           "    1     0 root      systemd",
           f"  {s['cron_pid']:>3}     1 root      cron",
           "  812     1 root      sshd",
           f" {s['usta_pid']:>4}     1 root      {v['web']}"]
    if v["app"] != v["web"]:
        sat.append(f" {s['usta_pid'] + 40:>4}     1 root      {v['app']}")
        isci_ata = s["usta_pid"] + 40
    else:
        isci_ata = s["usta_pid"]
    sat.append(f" {s['usta_pid'] + 3:>4} {s['usta_pid']:>5} www-data  {v['web']}")
    sat.append(f" {s['isci_pid']:>4} {isci_ata:>5} www-data  {v['app']}")
    sat.append(f" {s['sus_pid']:>4} {s['isci_pid']:>5} www-data  sh")
    sat.append(f" 3120   812 root      sshd")
    sat.append(f" 3188  3120 admin     bash")
    sat.append(f" {s['mesru_pid']:>4} {s['cron_pid']:>5} root      sh")
    sat.append(f" {s['mesru_pid'] + 1:>4} {s['mesru_pid']:>5} root      tar")
    return "\n".join(sat) + "\n"


def _fw_log(s: dict) -> str:
    rng = random.Random(f"fw:{s['sus_pid']}:{s['saldirgan']}")
    y = s["yerel"]
    gun = s["bas"].replace(hour=0, minute=0, second=0)
    olaylar = []
    t = gun + timedelta(hours=6)
    son = gun + timedelta(hours=23, minutes=59)
    while t < son:
        t += timedelta(minutes=rng.randint(7, 40))
        tur = rng.random()
        if tur < 0.5:
            olaylar.append((t, f"{t:%Y-%m-%d %H:%M:%S} ALLOW IN tcp {rng.choice(s['istemciler'])}:{rng.randint(30000, 60000)} -> {y}:443"))
        elif tur < 0.7:
            olaylar.append((t, f"{t:%Y-%m-%d %H:%M:%S} ALLOW OUT tcp {y}:{rng.randint(40000, 60000)} -> {s['izleme']}:8443"))
        elif tur < 0.85:
            olaylar.append((t, f"{t:%Y-%m-%d %H:%M:%S} DENY IN tcp {u.dis_ip(rng)}:{rng.randint(30000, 60000)} -> {y}:{rng.choice([23, 3389, 5900])}"))
        else:
            olaylar.append((t, f"{t:%Y-%m-%d %H:%M:%S} ALLOW OUT tcp {y}:{rng.randint(40000, 60000)} -> {s['ayna']}:443"))
    # Şüpheli bağlantı: ilk satır `bas`, sonra düzenli aralıklarla canlı tutma satırları
    k = s["bas"]
    for i in range(rng.randint(5, 9)):
        olaylar.append((k, f"{k:%Y-%m-%d %H:%M:%S} ALLOW OUT tcp {y}:{s['yerel_port']} -> {s['saldirgan']}:{s['port']}"))
        k += timedelta(minutes=rng.randint(2, 6), seconds=rng.randint(0, 59))
    olaylar.sort(key=lambda x: x[0])
    return "\n".join(x[1] for x in olaylar) + "\n"


def _kurallar(s: dict) -> str:
    return (
        "# Kurgusal güvenlik duvarı kural dili: yön eylem protokol hedef port\n"
        "# Kurallar yukarıdan aşağı okunur; ilk eşleşen kural uygulanır.\n"
        "IN   ALLOW tcp any 22\n"
        "IN   ALLOW tcp any 80\n"
        "IN   ALLOW tcp any 443\n"
        "IN   DENY  tcp any any\n"
        f"OUT  ALLOW tcp {s['ayna']} 443     # güncelleme aynası\n"
        f"OUT  ALLOW tcp {s['izleme']} 8443    # izleme ajanı\n"
        "OUT  ALLOW tcp any any              # \"şimdilik\" açık bırakıldı\n"
    )


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} · {s['v']['host']} sunucusunun kopyaları. Hepsi KURGUSAL ve metin dosyasıdır.\n"
          "kopya/ss_tanp.txt            : `ss -tanp` çıktısı (bağlantılar ve onları tutan süreçler)\n"
          "kopya/ps_agac.txt            : süreç tablosu (PID, üst süreç PID'i, kullanıcı, program)\n"
          "kopya/guvenlik_duvari.log    : güvenlik duvarı kayıtları\n"
          "kopya/etc/guvenlik_duvari.kurallar : kural dosyası\n")
    u.yaz(lab / "kopya" / "ss_tanp.txt", _ss(s))
    u.yaz(lab / "kopya" / "ps_agac.txt", _ps(s))
    u.yaz(lab / "kopya" / "guvenlik_duvari.log", _fw_log(s))
    u.yaz(lab / "kopya" / "etc" / "guvenlik_duvari.kurallar", _kurallar(s))


def _kural_satirlari(yol: Path) -> list:
    try:
        metin = yol.read_text(encoding="utf-8")
    except OSError:
        return []
    cikti = []
    for x in metin.splitlines():
        x = x.split("#", 1)[0].strip()
        if x:
            cikti.append(x.split())
    return cikti


def _egress_kapali(b) -> Sonuc:
    yol = b.lab / "kopya" / "etc" / "guvenlik_duvari.kurallar"
    kurallar = _kural_satirlari(yol)
    if not kurallar:
        return Sonuc(False, "Kural dosyası boş ya da yok. Dosyayı silmek çözüm değil; `sifirla` ile geri getirebilirsin.")
    s = b.senaryo
    for k in kurallar:
        if len(k) >= 5 and k[0] == "OUT" and k[1] == "ALLOW" and k[3] == "any":
            return Sonuc(False, "`OUT ALLOW ... any` kuralı hâlâ var: sunucu her adrese bağlanabilir. "
                                "O kuralı kaldır ya da `DENY`'a çevir.")
    giden = [(i, k) for i, k in enumerate(kurallar) if len(k) >= 5 and k[0] == "OUT"]
    reddet = [i for i, k in giden if k[1] == "DENY" and k[3] == "any"]
    if not reddet:
        return Sonuc(False, "Fazlalığı kaldırdın ama giden trafik için bir varsayılan **reddet** kuralı yok. "
                            "Kural yoksa güvenlik duvarı ürüne göre izin verebilir; `OUT DENY tcp any any` ekle.",
                     yakin=True)
    izinler = {(k[3], k[4]): i for i, k in giden if k[1] == "ALLOW"}
    for hedef in ((s["ayna"], "443"), (s["izleme"], "8443")):
        if hedef not in izinler:
            return Sonuc(False, f"Gerekli `OUT ALLOW` kuralı ({hedef[0]}:{hedef[1]}) silinmiş; güncelleme/izleme "
                                "çalışmaz. Sadece fazla kuralı kaldır.", yakin=True)
        if izinler[hedef] > reddet[0]:
            return Sonuc(False, "`OUT DENY` kuralını izinlerin **önüne** koymuşsun. Kurallar yukarıdan aşağı "
                                "okunur, ilk eşleşen kazanır: izinler reddetten önce gelmeli.", yakin=True)
    return Sonuc(True, "Artık sunucu yalnızca güncelleme aynasına ve izleme sunucusuna bağlanabilir. "
                       "Aynı bağlantı bir daha kurulsaydı güvenlik duvarı onu reddederdi ve log'a düşerdi.")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    cikis = ("awk 'NR==FNR{ if($1==\"LISTEN\"){n=split($4,a,\":\");l[a[n]]=1} next} "
             "$1==\"ESTAB\"{n=split($4,a,\":\"); if(!(a[n] in l)){print $5\"|\"$6}}' kopya/ss_tanp.txt kopya/ss_tanp.txt")
    izinli = "awk '$1==\"OUT\" && $2==\"ALLOW\" && $4!=\"any\"{print $4}' kopya/etc/guvenlik_duvari.kurallar"
    sus = sh(f"{cikis} | grep -v -F -f <({izinli}) | grep -v -E '^(10\\.|127\\.|192\\.168\\.|172\\.16\\.)'", lab)
    ip = sus.split("|")[0].rsplit(":", 1)[0]
    port = sus.split("|")[0].rsplit(":", 1)[1]
    pid = sh(f"echo '{sus}' | grep -o 'pid=[0-9]*' | cut -d= -f2", lab)
    ust = sh(f"p=$(awk -v x={pid} '$1==x{{print $2}}' kopya/ps_agac.txt); awk -v x=$p '$1==x{{print $4}}' kopya/ps_agac.txt", lab)
    saat = sh(f"grep -F -- '-> {ip}:' kopya/guvenlik_duvari.log | head -1 | cut -d' ' -f2", lab)
    sec = {n: SEVIYE.gorevler[n - 1].kontrol.cevabi_goster(Baglam(s, lab, n))[0] for n in (1, 7, 9)}
    # Egress'i kapat: any-any iznini DENY'a çevir
    sh("awk '/^OUT +ALLOW +tcp +any +any/{print \"OUT  DENY  tcp any any\"; next} {print}' "
       "kopya/etc/guvenlik_duvari.kurallar > kopya/etc/.gecici && mv kopya/etc/.gecici kopya/etc/guvenlik_duvari.kurallar", lab)
    return {1: sec[1], 2: ip, 3: port, 4: pid, 5: ust, 6: saat, 7: sec[7], 8: "", 9: sec[9]}


def _pid_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["isci_pid"]:
        return ("Bu, bağlantıyı tutan sürecin **üst süreci** (PPID). Sorulan, soketi doğrudan tutan sürecin kendi PID'i; "
                "ss çıktısında `pid=` ile yazan.")
    return None


def _ust_hata(g, beklenen, b):
    if g == "sh":
        return "`sh` kabuğun kendisi. Sorulan, onu **doğuran** (PPID'si olan) sürecin programı."
    return None


def _port_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["yerel_port"]:
        return "Bu, sunucunun kendi (geçici) portu. Uzak taraftaki, yani şüpheli IP'nin portunu yaz."
    return None


ADIMLAR = [
    Adim("İki kabuk türü", """
Bir sistemde komut çalıştırabilen oturuma **kabuk (shell)** dendiğini Cilt 1'den biliyorsun. Saldırgan bir
sistemde komut çalıştırabiliyorsa, ona uzaktan bir kabuk bağlantısı kurmak ister. İki tür vardır:

- **Bind kabuk:** hedef sunucu bir portta **dinler**, saldırgan oraya **bağlanır**. Hedefe doğrudan erişim
  gerekir; güvenlik duvarı gelen bağlantıyı engelliyorsa çalışmaz.
- **Reverse (ters) kabuk:** saldırgan **dinler**, hedef ona **geri bağlanır**. Çoğu güvenlik duvarı içeri
  gelenleri engeller ama dışarı gidene izin verir; bu yüzden reverse çok daha yaygındır.

Bu bölümde nasıl kurulduğunu değil, **nasıl görüldüğünü** öğreneceksin. Dosyalara bak:
""", komut="cat OKUBENI.txt"),
    Adim("Bağlantı tablosu: ss -tanp", """
`ss -tanp` makinedeki TCP bağlantılarını listeler: `t` TCP, `a` hepsi, `n` isim çözme yok (sayısal),
`p` bağlantıyı tutan süreç. Bize bu komutun bir **kopyası** verildi. Başlık satırı sütunları açıklar:
""", komut="head -1 kopya/ss_tanp.txt", sonra="""
Önemli sütunlar: **Local-Address:Port** (bu sunucu), **Peer-Address:Port** (karşı taraf) ve **Process**
(bağlantıyı tutan program ve PID'i).
"""),
    Adim("LISTEN ve ESTAB", """
İki durum işimize yarar:

- **LISTEN:** sunucu o portta bağlantı bekliyor. Servislerin normal hali.
- **ESTAB (established):** kurulmuş, canlı bir bağlantı.
""", komut="grep LISTEN kopya/ss_tanp.txt", sonra="""
Burada görünenler sunucunun **sunduğu** hizmetlerdir (ssh, web sunucusu, veritabanı). Bu portlara gelen
bağlantılar **içeriden gelen** bağlantılardır. Bir kabuk bind türündeyse, listede sebebini bilmediğin
bir LISTEN satırı olurdu; reverse türündeyse başka bir yere bakacaksın.
"""),
    Adim("Bağlantıyı kim başlattı?", """
Bir ESTAB bağlantısında **yüksek numaralı geçici port** (genelde 32768 üzeri) bağlantıyı **başlatan**
taraftadır. Sunucuda bir LISTEN portuna (örneğin 443) gelen bağlantıda yerel port 443'tür. Eğer yerel
port rastgele yüksek bir sayıysa, o bağlantıyı **sunucu başlatmıştır**: **giden** bağlantıdır.
""", komut="grep ESTAB kopya/ss_tanp.txt", sonra="""
Yerel port 443 olanlar web ziyaretçileri (gelen). Yerel portu yüksek ve karşı IP dışarıdaysa **giden**
bağlantıdır. Giden bağlantıların çoğu meşrudur (güncelleme, izleme); ama hangisinin meşru olduğunu
**izinli bir listeden** bilirsin. Listede olmayan giden bağlantı, incelenmesi gerekendir.
"""),
    Adim("Süreç tablosu ve üst süreç", """
Her sürecin bir **PID**'i (süreç numarası) ve onu başlatan sürecin PID'i olan **PPID**'i vardır.
Böylece süreçler bir ağaç oluşturur: kim kimi başlattı görürsün. Cilt 1'de bunu işledin.

Meşru bir örnek: aşağıdaki PID'i ve onu başlatan süreci izle.
""", komut="grep -w <<mesru_pid>> kopya/ps_agac.txt", sonra="""
Bir `sh` süreci **kendi başına** şüpheli değildir; `cron` gibi bir zamanlayıcı da kabuk başlatır. Önemli olan
**kimin başlattığı**: bir yedekleme betiğini `cron` başlatması normaldir. Bir **web sunucusu işçisi** ya da
uygulama sürecinin kabuk başlatması ise alışılmadıktır; web uygulamaları normalde kabuk çalıştırmaz.
"""),
    Adim("Güvenlik duvarı logu", """
Güvenlik duvarı her bağlantı için `ALLOW` (izin) ya da `DENY` (ret) yazar. Yön `IN` (gelen) veya `OUT`
(giden). Logun başına bakalım:
""", komut="head -5 kopya/guvenlik_duvari.log", sonra="""
Giden (`OUT`) bağlantıların `ALLOW` yazması, güvenlik duvarının onlara izin verdiği anlamına gelir. Şüpheli
bir hedefin **ilk** satırı, bağlantının **ne zaman başladığını** verir. Olay zaman çizelgesi buradan başlar.
"""),
    Adim("Kural dosyası ve çıkış filtreleme", """
Çoğu kurum **gelen** trafiği sıkı filtreler ama **giden** trafiğe güvenir. Bu alışkanlık reverse kabukları
mümkün kılar. Çözüm **çıkış filtrelemesidir (egress filtering)**: sunucunun dışarıya hangi adreslere ve
portlara bağlanabileceğini sadece gerektiği kadar açmak.
""", komut="cat kopya/etc/guvenlik_duvari.kurallar", sonra="""
Son satıra dikkat: `OUT ALLOW tcp any any`. Bu, "sunucu her yere bağlanabilir" demek. Güncelleme aynası ve
izleme sunucusu için özel kurallar zaten var; bu geniş kural gereksiz ve tehlikeli.

**Hacker gözüyle:** İlk alınan kabuk çoğunlukla kısıtlıdır; saldırgan onu tam bir terminale çevirmeye
çalışır. Savunmacı için bu, **süreç ağacında alışılmadık yeni oturumlar** olarak görünür. Ama en ucuz engel
yine çıkış filtreleridir: geri bağlanacak yol yoksa reverse kabuk kurulamaz.
"""),
]

GOREVLER = [
    Gorev("Bir saldırgan, hedef sunucunun güvenlik duvarının **gelen bağlantıları engellediğini** biliyor "
          "ve giden bağlantılara izin verildiğini fark ediyor. Hangi kabuk türünü seçer?",
          Secmeli([
              ("Reverse kabuk; hedef, saldırgana geri bağlanır",
               "Doğru. Gelen bağlantı engelliyse saldırgan bağlanamaz; ama hedef dışarıya bağlanabilir, bu yüzden geri bağlanan kabuk işe yarar."),
              ("Bind kabuk; hedef bir portta dinler, saldırgan o porta bağlanır",
               "Bind kabuk gelen bağlantı ister; güvenlik duvarı bunu engelliyorsa çalışmaz."),
              ("İkisi de eşit derecede işe yarar, çünkü yön fark etmez",
               "Yön çok önemli: güvenlik duvarları gelen ve giden trafiği ayrı değerlendirir."),
              ("Hiçbiri; güvenlik duvarı varsa kabuk kurulamaz",
               "Giden trafiğe izin verilen bir ortamda reverse kabuk kurulabilir; sorun tam budur."),
          ]),
          ("Gelen bağlantı engelli, giden bağlantı serbest. Kim kime bağlanmalı?",
           "Saldırgan hedefe bağlanamıyorsa, hedefi saldırgana bağlamalı.",
           "Hedefin saldırgana bağlandığı kabuk türü."),
          puan=15, baslik="Hangi kabuk"),
    Gorev("`kopya/ss_tanp.txt` içindeki giden bağlantılardan hangisi **izinli listede yok** ve "
          "internetteki bir adrese gidiyor? Karşı tarafın (uzak) IP'si nedir?",
          IP("ip"),
          ("Önce hangi ESTAB satırlarında yerel port yüksek ve rastgele: o satırlar giden bağlantıdır.",
           "Güvenlik duvarı kural dosyasındaki `OUT ALLOW` satırları meşru hedefleri söylüyor (güncelleme ve izleme).",
           "ESTAB satırlarını ayıkla: yerel portu 443/22 olan gelen bağlantıları ele, kuraldaki iki meşru IP'yi ele; kalan satırdaki Peer IP'si cevap."),
          puan=30, baslik="Şüpheli IP"),
    Gorev("Bu şüpheli bağlantı, uzak tarafta **hangi porta** gidiyor?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Peer-Address sütunu `IP:port` biçiminde. Port, iki noktadan sonrası.",
           "Sütunda iki port var: yerel ve uzak. Uzak olan Peer sütunundaki.",
           "Şüpheli satırdaki Peer-Address değerinin `:` sonrası."),
          puan=20, baslik="Uzak port"),
    Gorev("Bu bağlantıyı tutan sürecin **PID**'i nedir? (`ss`'in Process sütunundaki `pid=`)",
          Sayi("pid", sik_hatalar=_pid_hata),
          ("Process sütununda program adı ve `pid=` var.",
           "Şüpheli satırın sonundaki `users:((\"...\",pid=XXXX,fd=N))` içindeki sayı.",
           "`grep '<şüpheli IP>' kopya/ss_tanp.txt` ve satırın sonuna bak."),
          puan=20, baslik="Süreç PID'i"),
    Gorev("Bu süreci **hangi program başlatmış?** `kopya/ps_agac.txt` içinde sürecin PPID'sini bul ve o "
          "PID'in programını (COMM) yaz.",
          Metin("ust", sik_hatalar=_ust_hata, bicim="program adı"),
          ("Süreç tablosunda PID ve PPID sütunları var; PPID, \"beni kim başlattı\" demektir.",
           "Şüpheli PID'in satırındaki PPID'yi oku; sonra o PPID'nin kendi satırına bak.",
           "`grep -w <PID> kopya/ps_agac.txt` PPID'yi verir; sonra `grep -w <PPID> kopya/ps_agac.txt` programı verir."),
          puan=30, baslik="Üst süreç"),
    Gorev("Güvenlik duvarı logunda bu şüpheli IP'ye **ilk** giden bağlantı saat kaçta kaydedilmiş? "
          "(SS:DD:ss biçiminde)",
          Metin("saat", bicim="HH:MM:SS"),
          ("Logda IP, `->` işaretinin sağında yazılı; satırlar zamana göre sıralı.",
           "`grep -F` ile o IP'yi bul; ilk satırı al.",
           "`grep -F -- '-> <ip>:' kopya/guvenlik_duvari.log | head -1`; saat ikinci alan."),
          puan=25, baslik="İlk bağlantı"),
    Gorev("`ss` çıktısında şüpheli bağlantının yerel portu yüksek ve rastgele, karşı port ise "
          "başka bir numara. Bu bağlantıyı **hangi taraf başlatmıştır?**",
          Secmeli([
              ("Sunucu; geçici yüksek portu olan taraf başlatandır",
               "Doğru. Bağlantıyı başlatan taraf rastgele bir geçici port alır; dinleyen taraf bilinen bir port kullanır."),
              ("Dış IP; saldırgan sunucuya kendi makinesinden bağlanmıştır",
               "Dış IP'nin portu 443 ya da bilinen bir hizmet portuysa gelen bağlantı olabilirdi; burada sunucunun yerel portu rastgele."),
              ("Web sunucusu servisi, çünkü her bağlantıyı o başlatır",
               "Web sunucusu gelen istekleri bekler; bağlantıyı genelde ziyaretçi başlatır."),
              ("Bu bilgiden hangi tarafın başlattığı hiçbir şekilde çıkarılamaz",
               "Çıkarılabilir: geçici (rastgele yüksek) port, bağlantıyı başlatanındır."),
          ]),
          ("Dinleyen taraf bilinen bir port kullanır, bağlanan taraf rastgele port alır.",
           "Sunucunun yerel portu hangi tür bir sayı?",
           "Rastgele yüksek port = başlatan."),
          puan=15, baslik="Kim başlattı"),
    Gorev("Kurgusal çıkış filtreleme: `kopya/etc/guvenlik_duvari.kurallar` içinde sunucunun **her adrese** "
          "bağlanmasına izin veren kuralı kapat; ama güncelleme ve izleme için gerekli iki özel kuralı "
          "**bozma**. Giden trafik için varsayılan **reddet** kuralı da bulunsun. Bitince `cevap 8` yaz.",
          Durum(_egress_kapali, "`OUT ALLOW tcp any any` satırını `OUT DENY tcp any any` yap"),
          ("Dosyada `OUT` satırlarına bak. Hangisi gereğinden fazla geniş?",
           "Geniş izin satırını silme ya da `DENY`'a çevirme ikisi de olur; ama özel iki izin kalmalı.",
           "`sed -i 's/ALLOW tcp any any/DENY  tcp any any/' kopya/etc/guvenlik_duvari.kurallar`; ama `IN` satırlarını etkilemediğine dikkat et (sadece `OUT` satırında `any any` ALLOW var)."),
          puan=30, baslik="Çıkışı kapat"),
    Gorev("Çıkış filtrelemesi, sunucuya bir kabuk kurulmuş olsa bile neden önemli bir engeldir?",
          Secmeli([
              ("Sunucunun saldırgana geri bağlanacağı yol kapanır",
               "Doğru. Reverse kabuk, hedefin dışarıya bağlanabilmesine dayanır. Çıkış izni kısıtlıysa bağlantı reddedilir ve log'a düşer."),
              ("Dışarıdan gelen bütün bağlantı denemelerini otomatik olarak engeller",
               "Bu giriş filtrelemesidir. Çıkış filtresi sunucudan dışarı giden trafiği sınırlar."),
              ("Sunucudaki zafiyeti yamalar, böylece saldırgan ilk erişimi alamaz",
               "Çıkış filtresi yama yerine geçmez. Zafiyet yamayla kapanır; filtre ikinci bir engel katmanıdır."),
              ("Sunucunun diskini şifreler, böylece çalınan veri okunamaz",
               "Disk şifreleme farklı bir korumadır; ağ filtresiyle ilgisi yoktur."),
          ]),
          ("Reverse kabuk hangi yönde trafik gerektiriyor: gelen mi giden mi?",
           "Çıkış filtresi giden trafiği sınırlar.",
           "Geri bağlanma yolu kapanınca kabuk kurulamaz."),
          puan=20, baslik="Neden egress"),
]


def _kapanis():
    return """
Saldırganın gözüyle: reverse kabuk, "içeri girmek zor, dışarı çıkmak kolay" alışkanlığına dayanır.
Savunmanın gözüyle: bir web sunucusunun hiçbir zaman rastgele bir dış IP'ye bağlanmaması gerekir.
Üç iz yan yana bakınca tabloyu verir: `ss` (hangi bağlantı), süreç ağacı (kim başlattı), güvenlik
duvarı logu (ne zaman başladı). Çıkış filtreleme, tespit gelene kadar işi durdurur. Uygulamalı
pratiği **kendi laboratuvarında** yap: Cilt 9'da Kali'nde kuracağın savunmasız hedefler.
"""


SEVIYE = Seviye(
    kimlik="c06b03",
    cilt=6,
    bolum=3,
    baslik="Kabuklar: Bind, Reverse ve İzleri",
    brifing="""
**<<musteri>>** sunucusu **<<host>>** hakkında şüpheli bir giden bağlantı var. Deniz: "Bağlantıyı bul,
başlatan süreci çıkar, çıkışı kapat."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Log4Shell (2021):** Sömürü, savunmasız sunucunun dışarıdaki bir sunucuya (örneğin LDAP) bağlantı
  kurmasına dayanıyordu. Giden trafiği kısıtlayan ortamlar bu adımda saldırıyı kırabilirdi; çıkış
  loglarını izleyen ekipler de bu bağlantıları erken fark edebildi.
- **Tespit:** Web sunucusu veya uygulama sürecinin altında bir kabuk (`sh`, `bash`) görmek ve aynı
  sürecin dış bir IP'ye bağlantı tutması klasik bir alarmdır; EDR ürünleri ve `auditd` gibi araçlar
  süreç ağacından bunu yakalar.
- **Önleme:** Çıkış filtreleme (sadece gerekli hedef ve portlar), web uygulama hesabının kabuk
  çalıştıramaması, güncel yazılım ve giden bağlantı loglarının izlenmesi.
""",
    sure_hedef_dk=25,
)
