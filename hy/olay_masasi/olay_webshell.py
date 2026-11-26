"""Olay Masası — Web Shell Avı.

Bir müşterinin web sunucusuna yükleme dizininden bir web shell bırakılmış. Analist iki kanıtı
birleştirir: web kökünün dosya listesi (`ls -la` benzeri) ve erişim logu. Shell'in içeriği
yoktur; yalnızca varlığının ve erişiminin izi vardır.
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

KOK = "/var/www/html"
SHELL_ADLARI = ["x.php", "up0.php", "s.php", "a1.php", "0.php", "img.php", "cache_.php", "wp-tmp.php"]
DIZINLER = [("uploads", "/yukle.php"), ("yazilar", "/yazi-ekle.php")]
UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
UA_SALDIRGAN = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1"


def _ls(izin: str, boyut: int, t: datetime, yol: str, bugun: datetime) -> str:
    ay = u.AYLAR_EN[t.month - 1]
    zaman = f"{t:%H:%M}" if (bugun - t).days < 180 else f"{t.year:>5}"
    return f"{izin} 1 www-data www-data {boyut:>7} {ay} {t.day:>2} {zaman} {yol}"


def uret(rng):
    m = musteri_sec(rng)
    dizin, yukle = rng.choice(DIZINLER)
    shell_ad = rng.choice(SHELL_ADLARI)
    yol = f"/{dizin}/{shell_ad}"
    boyut = rng.randint(380, 3900)
    gun = u.gun(rng)
    saldirgan, *mesru = u.benzersiz(rng, u.dis_ip, 8)

    # --- access.log ---
    ham = []  # (zaman, satır)
    sayfalar = m["normal_sayfalar"]
    resimler = [f"/{dizin}/foto-{i}.jpg" for i in range(1, 7)]
    for ip in mesru[:6]:
        ua = rng.choice(UA_NORMAL)
        for t in u.zamanlar(rng, gun + timedelta(hours=8, minutes=rng.randint(0, 120)), rng.randint(6, 12), 20, 700):
            if rng.random() < 0.7:
                p, boy = rng.choice(sayfalar), rng.randint(2400, 18000)
            else:
                p, boy = rng.choice(resimler), rng.randint(20000, 90000)
            ham.append((t, u.apache_satiri(ip, t, "GET", p, 200, boy, ua, referer=f"https://{m['alan']}/")))
    # meşru içerik yükleyici: kendi resmini yükler
    yonetici = mesru[6]
    ty = gun + timedelta(hours=9, minutes=rng.randint(0, 50), seconds=rng.randint(0, 59))
    ua_y = rng.choice(UA_NORMAL)
    ham.append((ty, u.apache_satiri(yonetici, ty, "GET", yukle, 200, 3120, ua_y)))
    ty2 = ty + timedelta(seconds=rng.randint(20, 90))
    ham.append((ty2, u.apache_satiri(yonetici, ty2, "POST", yukle, 200, 412, ua_y,
                                     referer=f"https://{m['alan']}{yukle}")))
    # saldırgan
    t_form = gun + timedelta(hours=rng.randint(10, 15), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    t_red = t_form + timedelta(seconds=rng.randint(15, 60))
    t_yukle = t_red + timedelta(seconds=rng.randint(20, 80))
    ham.append((t_form, u.apache_satiri(saldirgan, t_form, "GET", yukle, 200, 3120, UA_SALDIRGAN)))
    ham.append((t_red, u.apache_satiri(saldirgan, t_red, "POST", yukle, 403, 287, UA_SALDIRGAN,
                                       referer=f"https://{m['alan']}{yukle}")))
    ham.append((t_yukle, u.apache_satiri(saldirgan, t_yukle, "POST", yukle, 200, 418, UA_SALDIRGAN,
                                         referer=f"https://{m['alan']}{yukle}")))
    adet = rng.randint(4, 11)
    for t in u.zamanlar(rng, t_yukle + timedelta(seconds=rng.randint(30, 120)), adet, 15, 900):
        ham.append((t, u.apache_satiri(saldirgan, t, "POST", yol, 200, rng.randint(150, 4800), UA_SALDIRGAN)))
    ham.sort(key=lambda x: x[0])
    log = "\n".join(s for _, s in ham) + "\n"

    # --- dosya listesi ---
    def eski():
        return gun - timedelta(days=rng.randint(200, 700), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))

    satirlar = []
    for d in ["", "/css", "/img", "/admin"]:
        satirlar.append(_ls("drwxr-xr-x", 4096, eski(), KOK + d, gun))
    for d, _ in DIZINLER:
        izin = "drwxrwxrwx" if d == dizin else "drwxr-xr-x"
        satirlar.append(_ls(izin, 4096, eski(), f"{KOK}/{d}", gun))
    for p in sayfalar:
        satirlar.append(_ls("-rw-r--r--", rng.randint(2200, 19000), eski(), KOK + p.split("?")[0], gun))
    for ad in ["/css/site.css", "/css/tema.css", "/img/logo.png", "/img/banner.jpg", "/admin/panel.php",
               "/yukle.php", "/yazi-ekle.php", "/robots.txt"]:
        satirlar.append(_ls("-rw-r--r--", rng.randint(300, 22000), eski(), KOK + ad, gun))
    for i in range(1, 7):
        satirlar.append(_ls("-rw-r--r--", rng.randint(20000, 90000), eski(), f"{KOK}/{dizin}/foto-{i}.jpg", gun))
    satirlar.append(_ls("-rw-r--r--", rng.randint(20000, 90000), ty2, f"{KOK}/{dizin}/yeni-urun.jpg", gun))
    satirlar.append(_ls("-rw-r--r--", boyut, t_yukle, f"{KOK}{yol}", gun))
    satirlar = sorted(set(satirlar), key=lambda s: s.split()[-1])
    liste = f"toplam {len(satirlar) * 8}\n" + "\n".join(satirlar) + "\n"

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {m['sunucu']} web kökü",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "yol": [yol, shell_ad],
            "saat": [f"{t_yukle:%H:%M:%S}"],
            "ip": saldirgan,
            "adet": adet,
            "dizin": [f"/{dizin}", dizin, f"{KOK}/{dizin}"],
            "boyut": boyut,
        },
        "_log": log,
        "_liste": liste,
        "_mesru": set(mesru),
        "_yonetici_saat": f"{ty2:%H:%M:%S}",
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "access.log", s["_log"])
    u.yaz(lab / "dosya_listesi.txt", s["_liste"])


def _ip_hata(g, beklenen, b):
    if g in b.senaryo["_mesru"]:
        return "Bu IP normal sayfa ve resim isteyen bir ziyaretçi. Şüpheli dosyayı **POST** ile çağıranı ara."
    return None


def _saat_hata(g, beklenen, b):
    if g == b.senaryo["_yonetici_saat"]:
        return "Bu, meşru içerik yükleyicinin (yöneticinin) yüklemesi. Saldırgan IP'sinin başarılı (200) POST'unu ara."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    tam = _sh("grep -E '/(uploads|yazilar)/.*\\.php$' dosya_listesi.txt | awk '{print $NF}'", lab)
    yol = tam.replace("/var/www/html", "", 1)
    ip = _sh(f"awk '$7==\"{yol}\" {{print $1}}' access.log | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    saat = _sh(f"awk '$1==\"{ip}\" && $6==\"\\\"POST\" && $9==200 {{print $4}}' access.log | head -1 | cut -d: -f2-", lab)
    adet = _sh(f"awk '$7==\"{yol}\"' access.log | wc -l", lab)
    dizin = _sh("grep '^drwxrwxrwx' dosya_listesi.txt | awk '{print $NF}'", lab)
    boyut = _sh(f"grep '{yol}$' dosya_listesi.txt | awk '{{print $5}}'", lab)
    secim = SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]
    return {1: yol, 2: ip, 3: saat, 4: adet, 5: dizin, 6: boyut, 7: secim}


GOREVLER = [
    Gorev("`dosya_listesi.txt` web kökünün listesi. **Yükleme dizininde** yeni tarihli, tuhaf adlı bir `.php` "
          "var. Dosyanın web yolunu yaz (örn. `/uploads/ornek.php`).",
          Metin("yol", sadece_ad=True, bicim="/dizin/dosya.php"),
          ("Resim yükleme dizininde `.php` uzantılı dosya olmamalı. Dizin dizin bak.",
           "`grep` ile yükleme dizinlerindeki `.php` dosyalarını süz; yalnızca birinin tarihi yeni ve adı tuhaf.",
           "`grep -E '/(uploads|yazilar)/.*\\.php$' dosya_listesi.txt`"),
          puan=20, baslik="Shell dosyası"),
    Gorev("Bu dosyayı `access.log` içinde çağıran **saldırgan IP** hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Meşru ziyaretçiler bu dosyayı hiç istemez. Dosya yolunu içeren satırlara bak.",
           "Yol 7. alandır. O yolu isteyen satırların IP'sini (1. alan) al.",
           "`awk '$7==\"<yol>\" {print $1}' access.log | sort | uniq -c`"),
          puan=20, baslik="Saldırgan IP"),
    Gorev("Saldırgan dosyayı **hangi saatte yükledi**? Başarılı (200) yükleme POST'unun saatini yaz (SS:DD:SS).",
          Metin("saat", sik_hatalar=_saat_hata, bicim="SS:DD:SS"),
          ("Saldırgan önce bir yükleme denemesi yapmış ve reddedilmiş olabilir. Hangisi başarılı?",
           "Saldırgan IP'sinin satırlarını süz: POST ve durum kodu 200 olan ilk satırın saati. Meşru yöneticinin de yüklemesi var, karıştırma.",
           "`awk '$1==\"<IP>\" && $9==200' access.log | grep POST | head -1` — köşeli parantezden sonraki saat kısmı."),
          puan=20, baslik="Yükleme saati"),
    Gorev("Shell dosyasına logda **kaç kez** erişilmiş?",
          Sayi("adet"),
          ("Dosyanın yolunu isteyen tüm satırları say.",
           "Yol 7. alan: `awk '$7==\"<yol>\"'` ile süz, `wc -l` ile say.",
           "`awk '$7==\"/dizin/dosya.php\"' access.log | wc -l` — `grep` alt dizgiyi de eşler, tam eşleşme için awk kullan."),
          puan=15, baslik="Erişim sayısı"),
    Gorev("Listede **herkes tarafından yazılabilir** (`rwxrwxrwx`) bir dizin var. Web sunucusunda böyle "
          "olmaması gereken bu dizinin yolunu yaz.",
          Metin("dizin", sadece_ad=True, bicim="/dizin"),
          ("Listede `d` ile başlayanlar dizindir. İzin sütununa bak.",
           "Üç grubun da yazma yetkisi olanı ara: `drwxrwxrwx`.",
           "`grep '^drwxrwxrwx' dosya_listesi.txt`"),
          puan=15, baslik="Yazılabilir dizin"),
    Gorev("Shell dosyasının boyutu **kaç bayt**?",
          Sayi("boyut"),
          ("`ls -la` çıktısında boyut, kullanıcı/grup adından sonraki sayıdır.",
           "Shell dosyasının satırını bul ve boyut sütununu (5. alan) al.",
           "`grep '<dosya>$' dosya_listesi.txt | awk '{print $5}'`"),
          puan=10, baslik="Dosya boyutu"),
    Gorev("Shell bulundu. **En doğru müdahale** hangisi?",
          Secmeli([
              ("Kanıtı kopyala (imaj/log), dosyayı kaldır, sunucuyu ağdan izole et, yüklemenin kök nedenini (doğrulamasız yükleme) bul ve kapat, sonra sunucudaki kimlik bilgilerini yenile",
               "Doğru. Önce kanıt, sonra temizlik ve izolasyon; kök neden kapanmazsa saldırgan aynı açıktan döner. "
               "Shell erişim sağladığı için sunucudaki parola ve anahtarlar da ele geçmiş sayılır."),
              ("Dosyayı sil ve başka bir şey yapma",
               "Dosya tek iz olmayabilir: başka shell, zamanlanmış görev ya da çalınmış kimlik bilgisi kalır. Kök neden açık olduğundan saldırgan geri gelir."),
              ("Saldırgan IP'sini güvenlik duvarında engelle, dosyaya dokunma",
               "IP değişir; shell yerinde durduğu sürece başka biri de kullanabilir. Dosya kaldırılmalı ve kök neden kapatılmalı."),
              ("Sunucuyu hemen kapatıp diski formatla",
               "Kanıtı yok eder: saldırganın ne yaptığını ve neye eriştiğini bir daha öğrenemezsin. Önce imaj ve log alınmalı."),
          ]),
          ("Sadece dosyayı silmek yetmez; acele edip kanıtı da yok etme.",
           "Sıra: kanıtı koru, dosyayı kaldır, izole et, kök nedeni bul. Kimlik bilgilerini de unutma.",
           "Doğru şık kanıt + kaldırma + izolasyon + kök neden + kimlik bilgisi yenilemeyi birlikte sayar."),
          puan=15, baslik="Müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_webshell",
    cilt=5,
    bolum=110,
    baslik="Web Shell Avı",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize **<<sunucu>>** web sunucusundan iki dosya gönderdi: web kökünün dosya listesi
(`dosya_listesi.txt`, `ls -la` benzeri: izin, boyut, tarih, yol) ve erişim logu (`access.log`)."

"Yükleme dizininde olmaması gereken bir dosya var gibi. Önce listede onu bul, sonra logda kim
yüklemiş ve kaç kez çağırmış çıkar. Dosyanın içeriğine bakmıyoruz; varlığı ve erişim izi yeter."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Web shell, sunucuya bırakılmış bir uzaktan komut kapısıdır ve genellikle bir yükleme formunun
doğrulamasız olmasından doğar. Üç savunma katmanı kapatır: yüklenen dosyanın türünü ve içeriğini
doğrulamak (uzantı izin listesi, yeniden adlandırma), yükleme dizininde betik çalıştırmayı
engellemek (dizin herkese yazılabilir olmamalı, sunucu orada `.php` yorumlamamalı) ve dosya
bütünlüğünü izlemek (web kökünde yeni ya da değişen dosya alarmı). Log ve dosya listesi birlikte
okununca olay dakikasına kadar yeniden kurulabilir.
""",
    gercek_hayat="""
- **China Chopper:** Tek satırlık küçük bir web shell istemcisi; yıllardır gerçek saldırılarda
  (ör. 2021'de Exchange sunucularındaki ProxyLogon açığının ardından binlerce sunucuda) bırakılan
  shell'lerin en bilinenlerindendir. Boyutu çok küçüktür, trafiği sade POST isteğine benzer; bu
  yüzden dosya listesi ve erişim logu korelasyonu onu yakalamanın başlıca yoludur.
- **Doğrulamasız dosya yükleme:** OWASP'ın bilinen zafiyet sınıflarından "unrestricted file
  upload": resim yükleme formu `.php` dosyasını da kabul edince saldırgan kendi betiğini sunucuya
  yerleştirir. Birçok içerik yönetim sistemi eklentisi bu açıkla gerçek sitelerde ele geçirildi.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c05b07",),
)
