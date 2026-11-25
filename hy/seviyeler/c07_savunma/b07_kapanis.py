"""Cilt 7 · Bölüm 7 — Kapanış Görevi: Tam Olay Müdahalesi.

Yeni bir şey öğretmez; cildin bütün becerilerini tek bir birleşik vakada toplar: üç logu ilişkilendirmek
(Bölüm 3), olayı saldırı zincirine oturtmak (Bölüm 1), kanıt kopyası alıp temizlemek (Bölüm 5), kök
nedeni bulup sertleştirmek (Bölüm 2) ve raporu yazmak.

Loglar `ortak.tam_olay` ile (web + SSH + güvenlik duvarı, tek aktör), ele geçirilmiş sunucunun izleri
`ortak.host_izleri` ile üretilir. Vakalar: her tohumda farklı müşteri, güvenlik duvarı log biçimi,
yabancı SSH anahtarının olup olmaması ve parola girişi ayarının yeri (ana dosya ya da alt dosya).
Kanıtı olmayan halkalar (yanal hareket, hedefe ulaşma) bilerek boştur: kanıtsız iddia etme.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Kume, Metin, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec
from hy.seviyeler.c07_savunma import ortak
from hy.seviyeler.c07_savunma.b02_sertlestirme import sshd_etkili
from hy.seviyeler.c07_savunma.b05_olay_mudahalesi import _temizlik_kontrol
from hy.seviyeler.c07_savunma.ortak import OLAY_ADLARI, Sira, sec_doldur, sh

KLASORLER = ["loglar", "kayitlar", "olay_loglari", "toplanan"]
ZINCIR = ["Keşif", "İlk erişim", "Yer edinme", "Yetki yükseltme", "Yanal hareket", "Hedefe ulaşma"]


def uret(rng):
    m = musteri_sec(rng)
    klasor = rng.choice(KLASORLER)
    bicim = rng.choice(ortak.FW_BICIMLERI)
    o = ortak.tam_olay(rng, m, bicim)
    ssh, ele = o["ssh"], o["ssh"]["ele_gecirme"]
    giris = datetime.combine(ssh["baslangic"].date(), datetime.strptime(ele["zaman"], "%H:%M:%S").time())
    anahtar = rng.random() < 0.5
    h = ortak.host_izleri(rng, m, ele["yeni_kullanici"], ele["ip"], giris, anahtar, ssh["hesaplar"][1:])
    perm = list(range(6))
    rng.shuffle(perm)
    beklenen = [perm.index(e) + 1 for e in o["sira"]]
    parola_dropin = rng.random() < 0.5
    yedek = o["web"]["saldirilar"]["tarama"]["dosya"]
    return {
        "vaka": f"{m['ad']} — {m['sektor']}: birleşik olay ({'yabancı SSH anahtarlı' if anahtar else 'cron + yeni hesaplı'})",
        "m": m, "klasor": klasor, "bicim": bicim, "o": o, "h": h, "anahtar": anahtar, "perm": perm,
        "parola_dropin": parola_dropin,
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "klasor": klasor, "hikaye": m["hikaye"],
                  "yeni_ad": ele["yeni_kullanici"], "hassas": m["hassas_veri"]},
        "cevaplar": {
            "ip": o["ip"], "yeni": ele["yeni_kullanici"], "sira": beklenen, "halkalar": [1, 2, 3, 4],
            "dosya": yedek,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    k, o, h, m = lab / s["klasor"], s["o"], s["h"], s["m"]
    u.yaz(k / "access.log", loglar.metin(o["web"]))
    u.yaz(k / "auth.log", loglar.metin(o["ssh"]))
    u.yaz(k / "guvenlik_duvari.log", "\n".join(o["fw"]["satirlar"]) + "\n")
    olaylar = [f"{i + 1}. {OLAY_ADLARI[e]}" for i, e in enumerate(s["perm"])]
    u.yaz(lab / "olay_listesi.txt", "Olay çizelgesi için altı olay (karışık sırada):\n" + "\n".join(olaylar) + "\n")
    u.yaz(lab / "saldiri_zinciri.txt", "\n".join(f"{i}. {a}" for i, a in enumerate(ZINCIR, 1)) + "\n")
    u.yaz(lab / "sistem/etc/passwd", h["passwd"])
    u.yaz(lab / "sistem/var/spool/cron/crontabs/root", h["cron"])
    u.yaz(lab / ("sistem" + h["ikili"]), "LAB YER TUTUCUSU: zararsız metin dosyası (gerçek bir program değildir).\n", mod=0o644)
    if s["anahtar"]:
        u.yaz(lab / "sistem/root/.ssh/authorized_keys", "\n".join(h["anahtarlar"]) + "\n")
    ana = ["# sshd_config — kurgusal kopya", "Include /etc/ssh/sshd_config.d/*.conf", "", "Port 22",
           "PermitRootLogin yes", "PasswordAuthentication " + ("no" if s["parola_dropin"] else "yes"),
           "PermitEmptyPasswords no", "UsePAM yes", "X11Forwarding yes"]
    u.yaz(lab / "sistem/etc/ssh/sshd_config", "\n".join(ana) + "\n")
    if s["parola_dropin"]:
        u.yaz(lab / "sistem/etc/ssh/sshd_config.d/50-cloud-init.conf", "# otomatik üretilen ayar\nPasswordAuthentication yes\n")
    else:
        (lab / "sistem/etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} / {m['sunucu']} birleşik olay klasörü (KURGUSAL).\n"
          f"{s['klasor']}/ : web, SSH ve güvenlik duvarı kayıtları (dokunma).  sistem/ : sunucunun canlı kopyası (temizlik burada).\n"
          f"Selin'den not: {m['hikaye']} Etkilenen veri türü: {m['hassas_veri']}.\n"
          "Raporunu `cevap 9 \"...\"` ile gönder; tırnak içinde, kendi cümlelerinle.\n")


# ----------------------------------------------------------------------------- kontroller

def _ssh_kontrol(b) -> Sonuc:
    etkili = sshd_etkili(b.lab / "sistem")
    for anahtar, ad in (("permitrootlogin", "PermitRootLogin"), ("passwordauthentication", "PasswordAuthentication")):
        e = etkili.get(anahtar)
        if e is None or e[0] != "no":
            durum = f"`{ad} {e[0]}` ({e[1]}, satır {e[2]})" if e else "satır yok"
            return Sonuc(False, f"sshd'nin gördüğü etkili ayar: {durum}. İkisi de `no` olmalı. sshd ilk eşleşen satırı kullanır, "
                                "`Include` ile okunan alt dosyalara da bak.", yakin=True)
    return Sonuc(True, "root girişi ve parola girişi kapalı; yalnızca anahtarla giriş.")


def _ip_hata(g, beklenen, b):
    o = b.senaryo["o"]
    if g == o["ssh"]["brute"]["ip"]:
        return "Bu IP, SSH'ta root'a parola deneyen; ama güvenlik duvarında engellenen ve web logunda da görünen o değil."
    if g in o["web"]["mesru"]:
        return "Bu meşru bir kullanıcı/yönetici IP'si. Saldırganın güvenlik duvarında DROP kaydı var."
    return None


def _sira_hata(verilen, beklenen, b):
    if verilen == sorted(verilen):
        return "Listedeki sıraya göre yazmışsın; her olayın saatini loglardan bulup saate göre dizmelisin."
    return None


def _halka_hata(g, beklenen, b):
    veri = {int(x) for x in g.split() if x.isdigit()}
    if veri & {5, 6}:
        return "Yanal hareket (5) ve hedefe ulaşma (6) için loglarda doğrudan kanıt yok. Şüphe kanıt değildir; sadece kanıtlananları yaz."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["klasor"]
    fw, web, auth = f"{k}/guvenlik_duvari.log", f"{k}/access.log", f"{k}/auth.log"
    ip = sh(f"comm -12 <(comm -12 <(grep -i drop {fw} | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort -u) "
            f"<(cut -d' ' -f1 {web} | sort -u)) <(grep -oE 'from [0-9.]+' {auth} | cut -d' ' -f2 | sort -u)", lab)
    yeni = sh(f"grep 'new user:' {auth} | head -1 | grep -o 'name=[^,]*' | cut -d= -f2", lab)
    dosya = sh(f"grep -w '{ip}' {web} | grep ' 200 ' | grep -v robots | grep -oE 'GET [^ ]+' | cut -d' ' -f2", lab)
    sat = r"(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}"
    komutlar = {
        "Güvenlik duvarında": f"grep -wm1 '{ip}' {fw} | grep -oP '{sat}' | head -1",
        "yedek dosyanın": f"grep -F '{dosya}' {web} | grep ' 200 ' | grep -w '{ip}' | head -1 | grep -oP '{sat}'",
        "parolayla başarılı": f"grep 'Accepted password' {auth} | grep -w '{ip}' | head -1 | grep -oP '{sat}'",
        "sudo ile root": f"grep 'COMMAND=/bin/bash' {auth} | head -1 | grep -oP '{sat}'",
        "useradd": f"grep 'new user:' {auth} | head -1 | grep -oP '{sat}'",
        "root hesabına ilk": f"grep -m1 'Failed password for root' {auth} | grep -oP '{sat}'",
    }
    zamanlar = []
    for satir in (lab / "olay_listesi.txt").read_text().splitlines()[1:]:
        no = int(satir.split(".", 1)[0])
        for anahtar, komut in komutlar.items():
            if anahtar in satir:
                zamanlar.append((sh(komut, lab), no))
    sira = " ".join(str(no) for _, no in sorted(zamanlar))
    halkalar = sh(
        f"[ $(grep -i drop {fw} | grep -w '{ip}' | grep -oiE '(dpt|dport)=[0-9]+' | sort -u | wc -l) -ge 10 ] && echo 1; "
        f"(grep -w '{ip}' {web} | grep -q ' 200 ' && grep -q 'Accepted password' {auth}) && echo 2; "
        f"(grep -q 'new user:' {auth} && grep -q '/var/tmp/' sistem/var/spool/cron/crontabs/root) && echo 3; "
        f"grep -q 'COMMAND=/bin/bash' {auth} && echo 4; true", lab)
    ikili = sh("grep -E '^[^#].*/var/tmp/' sistem/var/spool/cron/crontabs/root | awk '{print $6}'", lab)
    ad = ikili.rsplit("/", 1)[-1]
    kopya = (f"mkdir kanit_kopyasi && cp -a sistem/etc/passwd kanit_kopyasi/passwd && "
             f"cp -a sistem/var/spool/cron/crontabs/root kanit_kopyasi/crontab_root && cp -a sistem{ikili} kanit_kopyasi/{ad}")
    if s["anahtar"]:
        kopya += " && cp -a sistem/root/.ssh/authorized_keys kanit_kopyasi/authorized_keys"
    sh(kopya, lab)
    sh(f"sed -i '/^{yeni}:/d' sistem/etc/passwd; sed -i '\\#{ikili}#d' sistem/var/spool/cron/crontabs/root; rm -f sistem{ikili}", lab)
    if s["anahtar"]:
        sh("sed -i '/destek@gecici-laptop/d' sistem/root/.ssh/authorized_keys", lab)
    sh("sed -i -E 's/^PermitRootLogin[[:space:]]+yes/PermitRootLogin no/; s/^PasswordAuthentication[[:space:]]+yes/PasswordAuthentication no/' "
       "sistem/etc/ssh/sshd_config sistem/etc/ssh/sshd_config.d/*.conf 2>/dev/null; true", lab)
    rapor = ("Saldırgan önce güvenlik duvarında port taradı, sonra web kökündeki yedek dosyayı indirdi, aynı IP ile SSH'a parolayla girdi, "
             "sudo ile root oldu ve yeni hesap ile cron görevi bıraktı. Kök neden yedek dosyanın açıkta olması ve parola girişiydi; "
             "ilk önlemler dosyayı kaldırmak, parola girişini kapatmak ve alarm kuralı yazmaktır.")
    return sec_doldur({1: ip, 2: yeni, 3: sira, 4: " ".join(halkalar.split()), 5: dosya, 6: "", 7: "", 9: rapor}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Elinde ne var?", """
Bu bölüm yeni bir şey öğretmez; cildin bütün becerilerini tek bir olayda toplar. Cilt 1'in kapanış
görevinde bir saldırıyı "bir IP çok deneme yapmış" diye anlatıyordun. Şimdi aynı olayı bir savunmacı gibi
ele alacağız: **tespit, kapsam, sınırlama, kök neden, sertleştirme, rapor.**

<<musteri>> (<<sektor>>) vakası: <<hikaye>> Elinde üç log (web, SSH, güvenlik duvarı) ve sunucunun
canlı kopyası (`sistem/`) var. Klasörlere bak:
""", komut="ls -l <<klasor>> sistem"),
    Adim("1. Tespit: üç logun ortak IP'si", """
Bölüm 3'te öğrendiğin gibi: üç kaynağı ortak IP üzerinden bağla. Saldırganı ayıran şey güvenlik
duvarında **engellenmiş (DROP)** kaydı olmasıdır. Önce duvarın engellediği IP'leri çıkar:
""", komut="grep -i drop <<klasor>>/guvenlik_duvari.log | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -3", sonra="""
En çok engellenen IP bir aday. Gerçek saldırgan ise **aynı zamanda web logunda ve SSH logunda da**
görünendir; `comm -12` ile kesişimi alırsın (Bölüm 3).
"""),
    Adim("2. Kapsam: zincirin hangi halkaları kanıtlı?", """
Siber saldırı zincirinde saldırganın nereye kadar geldiğini söylemek, kapsamı belirler. Kural: **sadece
kanıtı olan halkayı yaz**. "Veri çalmış olabilir" bir şüphedir, kanıt değildir. Halkalar:
""", komut="cat saldiri_zinciri.txt", sonra="""
Her halka için loglarda ne arayacağını düşün: **keşif** (duvarda çok porta bağlantı), **ilk erişim**
(yedek dosyanın indirilmesi, parolayla giriş), **yer edinme** (yeni hesap, cron), **yetki yükseltme**
(sudo ile root), **yanal hareket** (başka makineye SSH/RDP), **hedefe ulaşma** (veri çıkışı ya da
şifreleme). Hangi halkalar için loglarda gerçekten kayıt var, hangileri için yok?
"""),
    Adim("3. Sınırlama ve kanıt kopyası", """
Bölüm 5'teki sıra: **sınırla, kanıt al, temizle, kurtar, ders çıkar.** Bu olayda sunucu canlı kopyada.
Önce kanıt:

```
mkdir kanit_kopyasi
cp -a sistem/etc/passwd kanit_kopyasi/
```

Temizlikte arayacağın yerler: yeni hesap (`passwd`), şüpheli cron satırı, bırakılan dosya,
varsa `authorized_keys`'teki yabancı anahtar. Saldırganın kullandığı hesabın parolası da yenilenmeli
(kurtarma aşaması).
"""),
    Adim("4. Kök neden: her başarılı adım hangi açık yüzünden mümkündü?", """
**Kök neden analizi** "ne oldu"dan "neden oldu"ya geçmektir. Saldırgan yedek dosyayı indirebildi (web
kökünde yetkisiz erişilebilir bir yedek vardı), sonra aynı IP parolayla SSH'a girdi (parola girişi açıktı),
sudo ile root oldu (yetki sınırı yoktu). Yani en az üç yapılandırma hatası zincirde birbirine bağlı.
Bölüm 2'deki sertleştirme ayarlarına bak:
""", komut="cat sistem/etc/ssh/sshd_config", sonra="""
`PermitRootLogin yes` ve parola girişinin açık olması bu olayı kolaylaştıran ayarlardır. Ayarın
bir yerde `no` demesi yetmez: `Include` ile okunan `sshd_config.d` dosyaları ve sshd'nin **ilk
eşleşen satırı kullanması** unutulmasın (`ls sistem/etc/ssh/sshd_config.d`).
"""),
    Adim("5. Her açığı bir önlemle eşle", """
Raporun en değerli kısmı **öneriler**dir ve her bulgu bir önlemle eşleşmelidir:

- Web kökünde unutulmuş yedek dosya: dosyayı kaldır, yedekleri web dışı bir yere al, düzenli tarama yap (Bölüm 6).
- Parolayla SSH girişi ve root girişi: anahtarla girişe geç (Bölüm 2).
- Port taraması ve brute-force görülmedi/alarm yok: güvenlik duvarı ve auth.log için SIEM kuralı yaz (Bölüm 3).
- İzinsiz yeni hesap ve cron: yetkili değişiklikleri izleyen alarm (Bölüm 4) ve sudo kısıtlaması (Bölüm 2).
- Yedekten geri dönüş ve olay planı (Bölüm 5).

Katmanlar farklı türde: önleme, tespit, kurtarma. Tek bir önleme güvenme.
"""),
    Adim("Mor takım: iki taraf da sende", """
**Hacker gözüyle:** Bu olayın her adımını Cilt 4-6'da kendin yapmıştın: tarama, açık yedek dosya, parola
denemesi, sudo, yeni hesap, cron. Şimdi aynı adımları loglarda **iz** olarak okudun ve her birine bir
önlem koydun. Saldırıyı bilen, savunmanın nereye konacağını bilir; iki tarafı da bilen kişi **mor
takım**dır ve iş piyasasının en değerli profillerinden biridir. Görevlere geç; rapor en sonda.
"""),
]

GOREVLER = [
    Gorev("<<musteri>>'in `<<klasor>>/` klasöründe: güvenlik duvarında **engellenmiş (DROP)** kaydı olan ve aynı "
          "zamanda web logunda ve `auth.log`'da da görünen saldırgan IP hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Üç kümenin kesişimi: DROP gören IP'ler, web IP'leri, auth.log IP'leri.",
           "`comm -12` iki sıralı listenin ortak satırlarını verir; üç listeyi iki adımda kesiştir.",
           "DROP IP'leri: `grep -i drop <<klasor>>/guvenlik_duvari.log | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort -u`; diğerlerini benzer çıkarıp `comm -12` ile birleştir."),
          puan=40, baslik="Saldırgan IP"),
    Gorev("Saldırganın sunucuda oluşturduğu **yeni hesabın adı** nedir?",
          Metin("yeni", bicim="kullanıcı adı"),
          ("Hesap oluşturan komut `useradd`'dir ve `auth.log`'a kaydedilir.",
           "`grep useradd <<klasor>>/auth.log` ile satırı bul; `name=` alanına bak.",
           "`grep 'new user:' <<klasor>>/auth.log | grep -o 'name=[^,]*'`"),
          puan=30, baslik="Yeni hesap"),
    Gorev("`olay_listesi.txt` içindeki altı olayı **gerçekleşme sırasına** diz. Cevap olarak listedeki **numaraları** "
          "sırayla yaz (örn. `4 2 1 6 3 5`).",
          Sira("sira", sik_hatalar=_sira_hata),
          ("Her olayın saatini ilgili logdan bulman gerek: güvenlik duvarı, web, auth.log.",
           "Saatleri `grep -oP '(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}'` ile çek; web logunda saat yılın yanında durur.",
           "Altı saati yan yana yaz, sonra saate göre sırala ve olay numaralarını o sırayla oku."),
          puan=60, baslik="Zaman çizelgesi"),
    Gorev("Saldırı zincirinin **hangi halkaları için loglarda doğrudan kanıt var?** `saldiri_zinciri.txt` numaralarını yaz "
          "(örn. `1 2 3`). Şüpheyi kanıt sayma.",
          Kume("halkalar", tur="sayi", sik_hatalar=_halka_hata, bicim="halka numaraları, virgülle ayrılmış"),
          ("Her halka için loglarda ne olması gerektiğini düşün; gerçekten var mı?",
           "Keşif: duvarda çok porta bağlantı. İlk erişim: yedek indirildi + parolayla giriş. Yer edinme: yeni hesap/cron. Yetki: sudo. Başka makineye geçiş ya da veri çıkışı kaydı var mı?",
           "Dördüncü halkaya (yetki yükseltme) kadar kayıt var. Yanal hareket (başka makineye bağlantı) ve hedefe ulaşma (veri çıkışı/şifreleme) için hiçbir kayıt yok."),
          puan=50, baslik="Kanıtlı halkalar"),
    Gorev("Saldırganın **web sunucusundan indirdiği hassas dosya** hangisi? (dosya adı)",
          Metin("dosya", sadece_ad=True, bicim="dosya adı"),
          ("Saldırgan IP'nin web logundaki isteklerine bak; hangi isteğe sunucu 200 döndü?",
           "`grep IP access.log | grep ' 200 '`; `robots.txt` normal bir dosya, yedek ya da yapılandırma kopyasına benzeyen dosyayı ara.",
           "`grep SALDIRGAN_IP <<klasor>>/access.log | grep ' 200 ' | grep -v robots`; istek yolundaki dosya adı cevaptır."),
          puan=30, baslik="Sızan dosya"),
    Gorev("`sistem/` kopyasını müdahale sırasına uygun temizle: **önce** `kanit_kopyasi/` oluşturup içine passwd, crontab, "
          "bırakılan dosya (varsa root'un `authorized_keys` dosyası) kopyalarını koy; **sonra** saldırganın hesabını, cron "
          "satırını, dosyasını (ve yabancı anahtarı) sil. Meşru olan hiçbir şeye dokunma. Bitince `cevap 6`.",
          Durum(_temizlik_kontrol, "kanit_kopyasi/ içine cp -a ile kopyalar, sonra sed ile satır silme ve rm"),
          ("Sıra: kanıt kopyası, sonra temizlik.",
           "`mkdir kanit_kopyasi`, `cp -a ... kanit_kopyasi/`; sonra `sed -i '/desen/d' dosya` ve `rm`.",
           "`sed -i '/^<<yeni_ad>>:/d' sistem/etc/passwd`; cron için `sed -i '\\#/var/tmp/#d' sistem/var/spool/cron/crontabs/root`; `rm sistem/var/tmp/.DOSYA`."),
          puan=70, baslik="Kanıt, sonra temizlik"),
    Gorev("Olayın tekrar etmemesi için `sistem/etc/ssh` altındaki yapılandırmayı sertleştir: sshd'nin gördüğü etkili ayarlar "
          "`PermitRootLogin no` **ve** `PasswordAuthentication no` olsun. Bitince `cevap 7`.",
          Durum(_ssh_kontrol, "PermitRootLogin no ve PasswordAuthentication no (etkili satırlar)"),
          ("İki ayar var ve aynı ayar birden çok dosyada geçebilir.",
           "`grep -rn -iE 'PermitRootLogin|PasswordAuthentication' sistem/etc/ssh` bütün satırları gösterir; sshd ilk eşleşeni kullanır.",
           "`yes` yazan etkili satırları `no` yap; ana dosya `no` diyorsa `sshd_config.d` altındaki dosyaya bak."),
          puan=40, baslik="SSH sertleştirme"),
    Gorev("Raporunda **kök neden** olarak hangisini yazarsın?",
          Secmeli([
              ("Web kökündeki yedek dosyanın yetkisiz indirilebilmesi ve sunucuda parolayla SSH girişinin açık olması",
               "Doğru. Bu iki yapılandırma hatası, tarama ardından ilk erişimi mümkün kıldı; logların kanıtladığı zincir budur."),
              ("Saldırganın çok hızlı bir bilgisayar ve geniş bir internet bağlantısı kullanması",
               "Yanlış. Saldırganın araçları olayın nedeni değil; savunmasız bırakılan yapılandırma nedendir."),
              ("Sunucuda IDS ya da SIEM kurulu olmaması; bu olmasaydı saldırı hiç gerçekleşmezdi",
               "Yanlış. Tespit eksikliği olayın fark edilmesini geciktirir ama olayın nedeni değildir; kök neden zafiyetlerdir."),
              ("Şirketin düzenli yedek alıyor olması; yedekler her zaman saldırganı çeker",
               "Yanlış. Yedek almak doğrudur. Sorun yedeğin web kökünde, yetkisiz erişime açık bırakılmasıdır."),
          ], dogru=0),
          ("Kök neden, olayı mümkün kılan hatadır; olayı geç fark ettiren eksik tespittir.",
           "Loglarda saldırganın ilk başarılı adımlarına bak: neyi indirdi, hangi kapıdan girdi?",
           "İlk başarılı iki adım (yedek indirme, parolayla SSH) iki yapılandırma hatasına dayanır."),
          puan=30, baslik="Kök neden"),
    Gorev("**Olay müdahale raporunun özetini** yaz (en az 25 kelime, tırnak içinde): saldırganın nereye kadar geldiğini, kök nedeni "
          "ve alacağın ilk üç önlemi anlat. Bitince `cevap 9 \"...\"`.",
          Serbest("Saldırgan <<sunucu>> sunucusunu önce taradı, web kökündeki yedek dosyayı indirdi (etkilenen veri türü: <<hassas>>), "
                  "sonra aynı IP'den SSH'a parolayla girip sudo ile root oldu ve yeni bir hesap ile cron görevi bıraktı. "
                  "Kanıtlı halkalar: keşif, ilk erişim, yer edinme, yetki yükseltme; yanal hareket ve veri çıkışı için kanıt yok. "
                  "Kök neden: web kökünde açık yedek dosya ve parolayla SSH girişi. İlk önlemler: yedeği kaldırıp sızan parolaları "
                  "yenilemek, SSH'ta parola ve root girişini kapatmak, tarama/brute-force için SIEM alarm kuralı yazmak.", min_kelime=25),
          ("Bir olay raporu: özet, zaman çizelgesi, etki, kök neden, öneriler. Burada kısa bir özet yeterli.",
           "Önce saldırganın ne yaptığını tek cümlede, sonra neden başarılı olduğunu, sonra önlemleri yaz.",
           "`cevap 9 \"Saldırgan ... kanıtlı halkalar ... kök neden ... önlemler ...\"` biçiminde, tırnak içinde yaz."),
          puan=60, baslik="Rapor özeti"),
]


def _kapanis():
    return """
Altı cilt önce, bir saldırıyı "bir IP çok deneme yapmış" diye tarif ediyordun. Şimdi aynı olayı zincirin
halkalarına, kök nedenlere ve katmanlı önlemlere bölebiliyorsun: kim, nasıl, nereye kadar, neden ve bir
daha nasıl olmaz. Saldırgan olarak her halkada seni yakalayabilecek bir katman olduğunu bilmek, daha
sessiz olmayı gerektirir; savunmacı olarak ise her halkaya, üç farklı türde, bir önlem koymak gerekir:
önleme, tespit, kurtarma. Mor takım zihniyeti tam budur.
"""


SEVIYE = Seviye(
    kimlik="c07b07",
    cilt=7,
    bolum=7,
    baslik="Kapanış Görevi: Tam Olay Müdahalesi",
    brifing="""
Selin Aksoy, Deniz Kara ve Mert Yavuz masanın etrafında: "Bu senin cilt sınavın." Önünüzde **<<musteri>>**
(<<sektor>>) olayının tam dosyası: üç log, ele geçirilen **<<sunucu>>** sunucusunun canlı kopyası ve bir
müşteri bekliyor. <<hikaye>>

Selin: "Tespit et, kapsamı çiz, sınırla, kök nedeni bul, sertleştir, raporla. Bir de şu: *kanıtı olmayan
halkayı yazma*." Mert gülüyor: "Altı cilt önce 'bir IP çok deneme yapmış' diyordun. Bakalım şimdi ne
diyeceksin."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Equifax 2017:** Saldırı, yaması haftalar önce yayımlanmış bir uygulama zafiyeti üzerinden başladı ve
  uzun süre fark edilmedi; kamuya açık raporlara göre trafiği inceleyen bir güvenlik cihazının sertifikası
  süresi dolduğu için trafik incelenemiyordu.
  Önleme (yama), tespit (işleyen izleme) ve kurtarma/olay planı katmanlarının hepsi bu kapanış görevindeki
  zincirle aynı mantıkla bağlanır.
- **Colonial Pipeline 2021:** Saldırının girişi kamuoyuna, MFA'sı olmayan eski bir VPN hesabı olarak
  açıklandı ve şirket zararı sınırlamak için boru hattı işletimini bir süre durdurdu. İlk halkada (ilk
  erişim) MFA ve hesap temizliği önleyebilirdi; olay sonrasında ise sınırlama ve iyileştirme planı
  belirleyici oldu.
- **Uber 2022:** Saldırı, kamuya açık anlatıma göre bir çalışanın MFA onay bildirimleriyle yorulup onay
  vermesiyle (MFA yorgunluğu) ilerledi. Kimlik doğrulama günlüklerinde peş peşe onay istekleri
  alarm kuralıyla yakalanabilir; bu, SIEM'in korelasyon kuralıyla tespit edebileceği bir kalıptır.
""",
    sure_hedef_dk=60,
)
