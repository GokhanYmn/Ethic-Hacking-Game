"""Cilt 7 · Bölüm 5 — Olay Müdahalesi (Incident Response).

Beceri: ele geçirilmiş bir sunucunun artefaktlarından (auth.log, süreç listesi, ağ bağlantıları,
passwd, cron, yetkili anahtarlar) olayı yeniden kurmak ve müdahale adımlarını doğru sıraya koymak:
tespit, sınırlama, kanıt kopyası, temizleme, kurtarma, ders çıkarma. Temizlik görevi, kanıt kopyası
alınmadan temizlemenin yetmediğini kontrol eder.

Vakalar: her tohumda farklı müşteri; bazılarında root'un yetkili anahtarlarına yabancı bir SSH
anahtarı da eklenmiştir (ek kalıcılık). İzler düz metindir; zararlı yazılım ya da saldırı yükü yoktur.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Secmeli, Sonuc, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec
from hy.seviyeler.c07_savunma import ortak
from hy.seviyeler.c07_savunma.ortak import Sira, sec_doldur, sh

# (aşama etiketi, metin, coz için anahtar kelime) — doğru sıra bu sıradır
ADIMLAR_SIRALI = [
    ("tespit", "Alarmın gerçek olduğunu doğrula: loglardan saldırganın izini çıkar ve olayı resmen ilan et", "doğrula"),
    ("sinirlama", "Ele geçirilen sunucuyu ağdan izole et (anahtar portunu kes ya da güvenlik duvarında erişimi kapat), makineyi kapatma", "izole et"),
    ("kanit", "Silmeden önce disk ve bellek kopyasını al; passwd, crontab ve logların kopyasını sakla", "kopyasını al"),
    ("yok_etme", "Saldırganın hesabını, zamanlanmış görevini ve bıraktığı dosyaları sistemden kaldır", "hesabını"),
    ("kurtarma", "Parolaları ve anahtarları yenile, temiz yedekten geri dön ve sistemi yakın izleme altında aç", "temiz yedekten"),
    ("ders", "Zaman çizelgesi ve kök nedenle olay raporu yaz; önleme ve tespit boşluklarını kapat", "raporu yaz"),
]


def uret(rng):
    m = musteri_sec(rng)
    anahtar = rng.random() < 0.5
    ssh = loglar.ssh_logu(rng, m, brute=True, brute_basari=False, ele_gecirme=True)
    ele = ssh["ele_gecirme"]
    giris = datetime.combine(ssh["baslangic"].date(), datetime.strptime(ele["zaman"], "%H:%M:%S").time())
    h = ortak.host_izleri(rng, m, ele["yeni_kullanici"], ele["ip"], giris, anahtar, ssh["hesaplar"][1:])
    perm = list(range(6))
    rng.shuffle(perm)                                   # dosyadaki gösterim sırası
    beklenen = [perm.index(i) + 1 for i in range(6)]
    return {
        "vaka": f"{m['ad']} — {m['sektor']} sunucusunda kalıcılık ({'cron + yabancı SSH anahtarı' if anahtar else 'cron + yeni hesap'})",
        "m": m, "ssh": ssh, "h": h, "anahtar": anahtar, "perm": perm, "giris": giris,
        "faz_no": {ADIMLAR_SIRALI[i][0]: perm.index(i) + 1 for i in range(6)},
        "metin": {"musteri": m["ad"], "sunucu": m["sunucu"], "hikaye": m["hikaye"], "sektor": m["sektor"],
                  "yeni_ad": ele["yeni_kullanici"]},
        "cevaplar": {"yeni": ele["yeni_kullanici"], "ip": ele["ip"], "pid": h["pid"], "ikili": h["ikili"],
                     "c2": h["c2"], "sira": beklenen},
    }


def yaz(lab: Path, s: dict) -> None:
    h, m = s["h"], s["m"]
    yeni = s["cevaplar"]["yeni"]
    u.yaz(lab / "kanit/auth.log", loglar.metin(s["ssh"]))
    u.yaz(lab / "kanit/ps_listesi.txt", h["ps"])
    u.yaz(lab / "kanit/ss_ciktisi.txt", h["ss"])
    u.yaz(lab / "sistem/etc/passwd", h["passwd"])
    u.yaz(lab / "sistem/var/spool/cron/crontabs/root", h["cron"])
    u.yaz(lab / ("sistem" + h["ikili"]), "LAB YER TUTUCUSU: zararsız metin dosyası (gerçek bir program değildir).\n", mod=0o644)
    if s["anahtar"]:
        u.yaz(lab / "sistem/root/.ssh/authorized_keys", "\n".join(h["anahtarlar"]) + "\n")
    adimlar = [f"{i + 1}. {ADIMLAR_SIRALI[e][1]}" for i, e in enumerate(s["perm"])]
    u.yaz(lab / "mudahale_adimlari.txt",
          "Müdahale ekibinin karışık sırada yazdığı altı adım (hazırlık, olaydan önce yapıldığı için listede yok):\n"
          + "\n".join(adimlar) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} / {m['sunucu']} olay klasörü (KURGUSAL).\n"
          "kanit/ : sunucudan alınmış, değiştirilmemesi gereken kopyalar (auth.log, süreç listesi, ağ bağlantıları).\n"
          "sistem/: sunucunun canlı kopyası; temizlik burada yapılır.\n"
          "Deniz'den not: önce olayı yeniden kur, sonra müdahale et. Silmeden önce kanıt!\n")


# ----------------------------------------------------------------------------- kontroller

def _dosyalar(kok: Path):
    return [p for p in kok.rglob("*") if p.is_file()] if kok.is_dir() else []


def _temizlik_kontrol(b) -> Sonuc:
    s, h = b.senaryo, b.senaryo["h"]
    yeni = s["cevaplar"]["yeni"]
    ikili = h["ikili"]
    ad = ikili.rsplit("/", 1)[1]
    kopya = None
    for d in (b.calisma_dizini, b.lab):
        if d and (Path(d) / "kanit_kopyasi").is_dir():
            kopya = Path(d) / "kanit_kopyasi"
            break
    if kopya is None:
        return Sonuc(False, "Önce kanıt: lab klasöründe `kanit_kopyasi/` oluşturup içine passwd, crontab ve bırakılan dosyanın "
                            "kopyasını koy. Silinen şeyin kanıtı yoksa olayı sonradan kimse ispatlayamaz.", yakin=True)
    dosyalar = _dosyalar(kopya)
    metinler = {p: p.read_text(errors="replace") for p in dosyalar if p.stat().st_size < 100000}
    eksik = []
    if not any(re.search(rf"^{re.escape(yeni)}:", t, re.M) for t in metinler.values()):
        eksik.append("passwd kopyası (saldırganın hesabını içeren)")
    if not any(ikili in t and "*/" in t for t in metinler.values()):
        eksik.append("crontab kopyası (şüpheli görevi içeren)")
    if not any(p.name == ad for p in dosyalar):
        eksik.append(f"bırakılan dosyanın ({ad}) kopyası")
    if s["anahtar"] and not any(h["yabanci_anahtar"] in t for t in metinler.values()):
        eksik.append("root'un authorized_keys kopyası (yabancı anahtarı içeren)")
    if eksik:
        return Sonuc(False, "`kanit_kopyasi/` içinde eksik: " + "; ".join(eksik) + ". Kopyayı temizlemeden ÖNCE al.", yakin=True)
    sis = b.lab / "sistem"
    passwd = (sis / "etc/passwd").read_text(errors="replace")
    if re.search(rf"^{re.escape(yeni)}:", passwd, re.M):
        return Sonuc(False, f"`{yeni}` hesabı hâlâ sistem/etc/passwd içinde.", yakin=True)
    for y in h["yoneticiler"]:
        if not re.search(rf"^{re.escape(y)}:", passwd, re.M):
            return Sonuc(False, f"Meşru kullanıcı `{y}` silinmiş; sadece saldırganın hesabını kaldır.")
    cron = (sis / "var/spool/cron/crontabs/root").read_text(errors="replace")
    if ikili in cron:
        return Sonuc(False, "Şüpheli cron görevi hâlâ root'un crontab'ında.", yakin=True)
    if "yedek_al.sh" not in cron or "run-parts" not in cron:
        return Sonuc(False, "Meşru cron görevlerini de silmişsin; sadece şüpheli satırı kaldır.")
    if (sis / ikili.lstrip("/")).exists():
        return Sonuc(False, f"Saldırganın bıraktığı dosya ({ikili}) hâlâ sistemde.", yakin=True)
    if s["anahtar"]:
        ak = (sis / "root/.ssh/authorized_keys").read_text(errors="replace")
        if h["yabanci_anahtar"] in ak:
            return Sonuc(False, "root'un `authorized_keys` dosyasında yabancı (tanımadığın) anahtar duruyor.", yakin=True)
        if not all(k in ak for k in h["anahtarlar"] if k != h["yabanci_anahtar"]):
            return Sonuc(False, "Meşru yöneticilerin anahtarlarını da silmişsin; sadece yabancı anahtarı kaldır.")
    return Sonuc(True, "Kanıt kopyası alındı, ardından hesap, cron görevi, dosya (ve anahtar) temizlendi.")


def _sira_hata(verilen, beklenen, b):
    if len(verilen) != 6:
        return None
    no = b.senaryo["faz_no"]
    pos = {n: verilen.index(n) for n in verilen if n in verilen}
    if no["yok_etme"] in pos and no["kanit"] in pos and pos[no["yok_etme"]] < pos[no["kanit"]]:
        return "Temizledikten sonra kopya almanın anlamı yok: silinen şey artık kopyalanamaz. Kanıt, temizlikten önce."
    if no["yok_etme"] in pos and no["sinirlama"] in pos and pos[no["yok_etme"]] < pos[no["sinirlama"]]:
        return "Önce sınırla: saldırgan hâlâ bağlıyken temizlik yapmak, o fark edip yeni bir kapı açmasına yol açar."
    if verilen == sorted(verilen):
        return "Dosyadaki numara sırasına göre yazmışsın; adımlar karışık verildi. Önce hangisinin ne olduğunu belirle."
    return None


def _ip_hata(g, beklenen, b):
    brute = b.senaryo["ssh"]["brute"]["ip"]
    if g == brute:
        return "Bu IP en çok başarısız denemeyi yapan; ama root'a giremedi. Aradığın IP, **başarıyla giren** ve root olan."
    return None


def _pid_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen - 40:
        return "Bu, saldırganın SSH oturumunun PID'i. Aradığın, yeni kullanıcının çalıştırdığı şüpheli sürecin PID'i."
    return None


def coz(lab: Path, s: dict) -> dict:
    yeni = sh("grep 'new user:' kanit/auth.log | head -1 | grep -o 'name=[^,]*' | cut -d= -f2", lab)
    ip = sh("grep 'Accepted password' kanit/auth.log | grep -oE 'from [0-9.]+' | cut -d' ' -f2 | sort -u", lab)
    pid = sh(f"awk -v k={yeni} '$1==k {{print $2}}' kanit/ps_listesi.txt", lab)
    ikili = sh("grep -E '^[^#].*/var/tmp/' sistem/var/spool/cron/crontabs/root | awk '{print $6}'", lab)
    c2 = sh(f"grep 'pid={pid}' kanit/ss_ciktisi.txt | grep -oE '[0-9.]+:8443' | cut -d: -f1", lab)
    sira = []
    for _, _, kw in ADIMLAR_SIRALI:
        sira.append(sh(f"grep -m1 '{kw}' mudahale_adimlari.txt | cut -d. -f1", lab))
    ad = ikili.rsplit("/", 1)[-1]
    kopya = (f"mkdir kanit_kopyasi && cp -a sistem/etc/passwd kanit_kopyasi/passwd && "
             f"cp -a sistem/var/spool/cron/crontabs/root kanit_kopyasi/crontab_root && cp -a sistem{ikili} kanit_kopyasi/{ad}")
    if s["anahtar"]:
        kopya += " && cp -a sistem/root/.ssh/authorized_keys kanit_kopyasi/authorized_keys"
    sh(kopya, lab)
    sh(f"sed -i '/^{yeni}:/d' sistem/etc/passwd; sed -i '\\#{ikili}#d' sistem/var/spool/cron/crontabs/root; rm -f sistem{ikili}", lab)
    if s["anahtar"]:
        sh("sed -i '/destek@gecici-laptop/d' sistem/root/.ssh/authorized_keys", lab)
    return sec_doldur({1: yeni, 2: ip, 3: pid, 4: ikili, 5: c2, 6: " ".join(sira), 7: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Altı aşama: panik değil, plan", """
Önlemler bir gün başarısız olur. O gün ne yapacağını bilmek, savunmanın en kritik parçasıdır. **Olay
müdahalesi** (incident response) altı aşamadır: **hazırlık** (plan, araç, yetki önceden hazır),
**tespit** (olayı fark et ve doğrula), **sınırlama** (yayılmayı durdur), **yok etme** (saldırganı
ve izlerini temizle), **kurtarma** (sistemi güvenle geri getir) ve **ders çıkarma**.

<<musteri>> vakası: <<hikaye>> Deniz sunucudan iki şey aldı: değiştirmemen gereken `kanit/` klasörü ve
temizlik yapacağın `sistem/` kopyası.
""", komut="ls kanit sistem"),
    Adim("1. İz: kim girdi, ne yaptı?", """
Cilt 6'da bir saldırganın izlerini öğrenmiştin: yeni hesap, yetki yükseltme, kalıcılık. Şimdi aynı
izleri savunmacı olarak `auth.log` içinde arıyoruz. Anahtar kelimeler: yeni hesap (`useradd`), gruba
ekleme (`usermod`), `sudo`:
""", komut="grep -E 'Accepted password|sudo|useradd|usermod' kanit/auth.log", sonra="""
Sıra net: bir IP parolayla girdi (Accepted password), sudo ile root kabuğu açtı, yeni hesap ekleyip
onu sudo grubuna koydu. `Accepted publickey` satırları meşru yöneticilerindir; saldırgan parolayla
girmiş. Brute-force yapan IP ise başka bir IP'dir ve root'a giremedi: sık yapılan karışıklık.
"""),
    Adim("2. İz: beklenmeyen süreç", """
Olay müdahalesinde `ps aux` ile **beklenmeyen süreçlere** bakılır. Sütunlar: kullanıcı, PID, CPU,
bellek... Aşağıdaki, olay anındaki listenin kopyası:
""", komut="cat kanit/ps_listesi.txt", sonra="""
Gördüğün gibi bir sürecin sahibi, `auth.log`'da yeni eklenen hesap ve çalıştırdığı program gizli
(adı nokta ile başlayan) bir dosya, yüksek CPU kullanımı var. Normal sunucu süreçleri (`sshd`, `apache2`,
`cron`) beklenen kullanıcılardan çalışır.
"""),
    Adim("3. İz: dışarıya bağlantı", """
`ss` komutu açık bağlantıları ve onları açan süreçleri gösterir (Cilt 2'de görmüştün). Yeni hesabın
sürecinin PID'sini bu listede ara; bağlantı kuran süreç, saldırganın dışarıyla bağını gösterir:
""", komut="cat kanit/ss_ciktisi.txt", sonra="""
`ESTAB` (kurulmuş) bir bağlantının `Peer Address` sütunu, sürecin konuştuğu uzak adrestir. Sunucunun
kendi iç servisleri `127.0.0.1` ya da iç IP'dedir; **dış IP'ye giden bağlantı**, açıklanması gereken
şeydir.
"""),
    Adim("4. İz: kalıcılık", """
Saldırgan, sunucudan çıkarılsa bile geri dönmek ister: **kalıcılık**. İlk yerler: kullanıcı listesi
(`/etc/passwd`), zamanlanmış görevler (`cron`) ve SSH yetkili anahtarları (`authorized_keys`). Root'un
crontab'ına bak:
""", komut="cat sistem/var/spool/cron/crontabs/root", sonra="""
Bir cron satırı beş zaman alanı ve bir komuttan oluşur. `*/10 * * * *` "her 10 dakikada bir" demektir.
Meşru satırlar `/usr/local/bin` ya da `run-parts` gibi tanıdık yerlere işaret eder; `/var/tmp` altında
gizli bir dosyayı çalıştıran satır olağandışıdır.
"""),
    Adim("Sıra önemlidir", """
Cilt 1'in küçük olay görevinde "önce kopya, sonra temizlik" demiştik. İşte doğru sıra:

1. **Doğrula**: gerçek mi? Kapsamı anla.
2. **Sınırla**: ağdan ayır (makineyi **kapatma**; bellekteki kanıt kaybolur).
3. **Kanıt**: disk ve bellek kopyası, kritik dosyaların kopyası.
4. **Temizle**: hesap, cron, dosya, anahtar.
5. **Kurtar**: parolalar, temiz yedek, izleme.
6. **Ders**: rapor, kök neden, kapatılan boşluklar.

Neden önce sınırlama sonra analiz? Yayılan bir saldırı, sen incelerken başka sistemlere de yayılır. "Önce
kanamayı durdur, sonra teşhis koy." Ve acele ederek kanıtı yok etmemek de önemlidir: **adli analiz**
(forensics) için kopya alınır. Kanıt kopyasını şöyle alırsın (örnek; görevde sen yazacaksın):

```
mkdir kanit_kopyasi
cp -a sistem/etc/passwd kanit_kopyasi/
```

`cp -a` dosyanın zamanını ve izinlerini korur; kanıtın bütünlüğü için önemlidir.
"""),
    Adim("Hacker gözüyle: saldırganın adımları = senin arama listen", """
**Hacker gözüyle:** Cilt 6'da saldırgan olarak kabuk açar, yetki yükseltir, kalıcılık kurardın (cron,
yeni kullanıcı, SSH anahtarı). Olay müdahalesinde tam bu izleri ararsın: `/etc/passwd`'de yeni
kullanıcılar, şüpheli cron görevleri, bilinmeyen SSH anahtarları, garip açık portlar (`ss -tulpn`),
beklenmeyen süreçler (`ps aux`). Saldırganın adımlarını bildiğin için nereye bakacağını bilirsin.
Şimdi görevlere geç; olayı kur, sonra temizle.
"""),
]

GOREVLER = [
    Gorev("`kanit/auth.log` içinde saldırganın oluşturduğu **yeni kullanıcı hesabının adı** nedir?",
          Metin("yeni", bicim="kullanıcı adı"),
          ("Yeni hesap oluşturan komutun adı `useradd`.",
           "`grep useradd kanit/auth.log` yeni kullanıcı satırlarını verir. `name=` alanına bak.",
           "`grep 'new user:' kanit/auth.log | grep -o 'name=[^,]*'`; eşittirden sonrası cevap."),
          puan=30, baslik="Yeni hesap"),
    Gorev("Hesaba **parolayla başarıyla giren** ve ardından root kabuğu açan IP hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Başarılı giriş ile başarısız deneme ayrı satırlardır.",
           "`Accepted password` satırlarını ara; `Accepted publickey` olanlar meşru yöneticilerdir.",
           "`grep 'Accepted password' kanit/auth.log`; `from` kelimesinden sonraki IP."),
          puan=30, baslik="Giren IP"),
    Gorev("`kanit/ps_listesi.txt` içinde yeni kullanıcının çalıştırdığı **şüpheli sürecin PID'i** kaç?",
          Sayi("pid", sik_hatalar=_pid_hata),
          ("Süreçler sahibine göre listelenir; ilk görev cevabındaki kullanıcıyı ara.",
           "`grep KULLANICI kanit/ps_listesi.txt` o kullanıcının süreçlerini verir; PID ikinci sütundur.",
           "`awk '$1==\"<<yeni_ad>>\" {print $2}' kanit/ps_listesi.txt`"),
          puan=30, baslik="Şüpheli süreç"),
    Gorev("Root'un crontab'ına eklenen şüpheli görev **hangi dosyayı çalıştırıyor?** (dosya adını ya da yolunu yaz)",
          Metin("ikili", sadece_ad=True, bicim="dosya adı"),
          ("Meşru görevler tanıdık yerleri çalıştırır; birisi gizli bir dosyaya işaret ediyor.",
           "`cat sistem/var/spool/cron/crontabs/root`; `/var/tmp` altındaki, adı nokta ile başlayan dosyayı ara.",
           "`grep '/var/tmp' sistem/var/spool/cron/crontabs/root`; satırın beşinci zaman alanından sonraki kısım komuttur."),
          puan=30, baslik="Cron'daki dosya"),
    Gorev("Şüpheli sürecin PID'ini `kanit/ss_ciktisi.txt` içinde ara: bu süreç **hangi dış IP'ye** bağlanmış? (8443 portu)",
          IP("c2"),
          ("`ss` çıktısının son sütunu bağlantıyı açan süreci ve PID'ini gösterir.",
           "Şüpheli sürecin PID'ini (üçüncü görev) `grep` ile ss çıktısında ara.",
           "`grep 'pid=PID' kanit/ss_ciktisi.txt`; `Peer Address` sütunundaki IP."),
          puan=40, baslik="Dışarıya bağlantı"),
    Gorev("`mudahale_adimlari.txt` içindeki altı müdahale adımını **doğru sıraya** diz (ilk yapılan başta). Cevap "
          "olarak dosyadaki **numaraları** sırayla yaz (örn. `4 1 6 2 3 5`).",
          Sira("sira", sik_hatalar=_sira_hata),
          ("Altı aşamayı hatırla: tespit, sınırlama, yok etme, kurtarma, ders. Kanıt nereye girer?",
           "Önce doğrula, sonra yayılmayı durdur; silmeden önce kopya al; sonra temizle, kurtar, rapor yaz.",
           "Her adımın cümlesini aşamayla eşle (doğrula=tespit, izole=sınırlama, kopya=kanıt...), sonra numaralarını o sırayla yaz."),
          puan=40, baslik="Müdahale sırası"),
    Gorev("`sistem/` kopyasını müdahale sırasına uygun temizle: **önce** lab klasöründe `kanit_kopyasi/` oluşturup içine "
          "passwd, crontab, bırakılan dosya (varsa root'un `authorized_keys` dosyası) kopyalarını koy; **sonra** "
          "saldırganın hesabını, cron satırını, dosyasını (ve yabancı anahtarı) sil. Meşru kullanıcılara, cron görevlerine "
          "ve anahtarlara dokunma. Bitince `cevap 7`.",
          Durum(_temizlik_kontrol, "kanit_kopyasi/ içine cp -a ile kopyalar, sonra sed ile satır silme ve rm"),
          ("Sıra: kanıt kopyası, sonra temizlik. Temizlik, tek tek satır ve dosya silmektir.",
           "`mkdir kanit_kopyasi`, `cp -a ... kanit_kopyasi/`; sonra `sed -i '/desen/d' dosya` ile satır sil, `rm` ile dosyayı kaldır.",
           "`sed -i '/^<<yeni_ad>>:/d' sistem/etc/passwd`; cron için `sed -i '\\#/var/tmp/#d' sistem/var/spool/cron/crontabs/root`."),
          puan=70, baslik="Kanıt, sonra temizlik"),
    Gorev("Bir ihlalde neden önce **sınırlama** (izolasyon), sonra analiz gelir?",
          Secmeli([
              ("Yayılan bir saldırı, analiz sürerken başka sistemlere de zarar verir; önce kanamayı durdurursun",
               "Doğru. Önce yayılmayı durdur, sonra ne olduğunu incele."),
              ("Analiz hep daha uzun sürer, bu yüzden en kısa olan işlem her zaman başa alınır",
               "Yanlış. Sıra süreye göre değil, zararı sınırlama önceliğine göre belirlenir."),
              ("Yöneticiler sınırlamayı sevdiği için bu adım dokümanda ilk sıraya konmuştur",
               "Yanlış. Sıra tercih değil, mantıktır: saldırgan etkin kaldıkça zarar büyür."),
              ("Önce analiz yapılırsa saldırganın kullandığı açık hiçbir zaman kapatılamaz hale gelir",
               "Yanlış. Analiz açığı kapatmayı engellemez; sorun, analiz sırasında saldırının sürmesidir."),
          ], dogru=0),
          ("Bir yangında önce neyi yaparsın: sebebini araştırmak mı, yayılmasını durdurmak mı?",
           "Saldırgan hâlâ sistemde ve başka makinelere erişimi var. Her dakika ne anlama gelir?",
           "Doğru cevap, analiz sürerken zararın büyümesini engellemekten bahsediyor."),
          puan=20, baslik="Neden önce sınırla"),
    Gorev("Adli analiz için sistemi hemen kapatıp temizlemek yerine neden önce **kopya** alınır?",
          Secmeli([
              ("Kapatma bellekteki geçici kanıtı (açık bağlantılar, çalışan süreçler) siler, temizlik ise diskteki izleri",
               "Doğru. Kopya, hem uçucu kanıtı hem diskteki izleri korur; sonradan kanıt toplanamaz."),
              ("Kopya almak sistemi daha hızlı çalıştırır ve temizliği otomatik olarak yapar",
               "Yanlış. Kopya almanın hızla ya da otomatik temizlikle ilgisi yok; amacı kanıtı korumak."),
              ("Kopyalar saldırganı otomatik olarak geri izler ve kimliğini mahkemeye bildirir",
               "Yanlış. Kopya pasif bir kanıttır; kimseyi kendiliğinden izlemez ya da bildirmez."),
              ("Yasa gereği her sunucunun her gün tam kopyası zaten alınmak zorundadır",
               "Yanlış. Kopya alma kararı olay anındaki bir adli analiz ihtiyacıdır, günlük bir yasal zorunluluk değil."),
          ], dogru=0),
          ("Sistemi kapattığında bellekte olan şeylere ne olur?",
           "Temizlediğin dosyayı sonradan inceleyebilir misin?",
           "Doğru cevap hem bellekteki geçici kanıttan hem de diskteki izlerden bahsediyor."),
          puan=20, baslik="Neden kopya"),
]


def _kapanis():
    return """
Bu olayda saldırgan dört iz bıraktı: `auth.log`'da parolayla giriş ve yeni hesap, süreç listesinde yüksek
CPU'lu gizli bir süreç, `ss`'te dışarıya bağlantı, cron'da (ve bazen `authorized_keys`'te) kalıcılık.
Cilt 6'da bunları sen kuruyordun; şimdi hepsini sildin. Saldırgan açısından ders: bu dört yer, ilk
bakılan yerlerdir. Savunma dersi: sıra her şeydir; sınırla, kopya al, sonra temizle ve temizlikten sonra
parolaları, anahtarları değiştir ve sistemi temiz yedekten geri getir, çünkü saldırganın başka kapı
bırakmadığından asla %100 emin olamazsın.
"""


SEVIYE = Seviye(
    kimlik="c07b05",
    cilt=7,
    bolum=5,
    baslik="Olay Müdahalesi",
    brifing="""
Gece 03:12. Deniz Kara telefonu açıyor: "**<<musteri>>**, **<<sunucu>>** sunucusunda alarm: gece
saatinde parolayla bir giriş ve CPU'su %38 olan bir süreç. <<hikaye>>"

Deniz, sunucudan aldığı iki klasörü sana yolluyor: "`kanit/` bozulmayacak, `sistem/` üzerinde müdahale
edeceksin. Önce olayı yeniden kur: kim girdi, hangi hesabı ekledi, ne çalışıyor, nereye bağlanıyor. Sonra
doğru sırayla müdahale et. Unutma: kanıt silinirse olay ispatlanamaz, ama saldırgan içerideyken de bekleyemeyiz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Maersk ve NotPetya 2017:** Dünyanın en büyük konteyner taşıyıcılarından Maersk,
  NotPetya saldırısında ağının büyük bölümünü yitirdi; kamuya açık anlatımlara göre alan denetleyicilerinin
  tek sağlam kopyası, o sırada çevrimdışı kalmış tek bir sunucuda bulunduğu için kurtarma mümkün oldu. Ders:
  **kurtarma** aşaması için çevrimdışı ve test edilmiş yedek, planın en değerli parçasıdır.
- **Colonial Pipeline 2021:** Şirket fidye saldırısı sonrası boru hattı işletimini önlem olarak durdurdu.
  Zararı sınırlamak için kendi sistemlerini bile kapatmak, "önce sınırla" ilkesinin en görünür örneğidir.
  Tespit/önleme tarafında ise MFA'sız eski VPN hesabı kapatılabilseydi olay başlamazdı.
- **Kalıcılık izleri:** Olay müdahale kontrol listelerinin değişmez maddeleri yeni kullanıcılar,
  zamanlanmış görevler, yetkili SSH anahtarları, beklenmeyen süreçler ve dış bağlantılardır; tam bu
  bölümdeki artefaktlar. Pek çok sızma testi ve olay raporunda saldırgan, ilk erişim kapatıldıktan sonra
  bu kalıcılık izleri sayesinde geri döner.
""",
    sure_hedef_dk=45,
)
