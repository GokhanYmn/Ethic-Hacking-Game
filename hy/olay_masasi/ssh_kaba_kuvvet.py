"""Olay Masası — SSH Kaba Kuvvet İncelemesi.

Her vakada başka bir sunucunun auth.log'u: kaba kuvvet denemesi her zaman var; sonunda
root parolasını bulup bulmadığı, ayrıca başka bir IP'nin parolayla girip root olup olmadığı
ve kalıcılık bırakıp bırakmadığı vakadan vakaya değişir.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

HAYIR = ["hayır", "hayir", "yok", "bulamadı", "bulamadi"]


def uret(rng):
    m = musteri_sec(rng)
    brute_basari = rng.random() < 0.35
    ele = rng.random() < 0.6
    ssh = loglar.ssh_logu(rng, m, brute=True, brute_basari=brute_basari, ele_gecirme=ele)
    oz, br, eg = ssh["ozet"], ssh["brute"], ssh["ele_gecirme"]
    log = loglar.metin(ssh)
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {ssh['sunucu']} SSH kayıtları",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": ssh["sunucu"]},
        "cevaplar": {
            "ip": oz["en_cok_basarisiz_ip"],
            "sayi": oz["en_cok_basarisiz"],
            "gecersiz": oz["gecersiz_kullanicilar"],
            "brute": [br["zaman"]] if br["basarili"] else HAYIR,
            "hesap": [eg["hesap"]] if eg else ["yok", "hiçbiri", "hicbiri"],
            "kalici": [eg["yeni_kullanici"]] if eg else ["yok", "hiçbiri", "hicbiri"],
        },
        "_log": log,
        "_toplam_failed": sum(1 for s in log.splitlines() if "Failed password" in s),
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "auth.log", s["_log"])


def _sayi_hata(g, beklenen, b):
    if int(g) == b.senaryo["_toplam_failed"] and int(g) != beklenen:
        return "Bu, bütün IP'lerin toplam başarısız denemesi. Sadece en çok deneyen IP'nin sayısını istiyoruz."
    if int(g) == beklenen * 2:
        return "İki katı çıktı: `Failed password` dışında başka bir satır türünü de saymış olabilirsin."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    ust = _sh("grep 'Failed password' auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -1", lab)
    sayi, _, ip = ust.split()
    gecersiz = _sh("grep 'Invalid user' auth.log | sed -E 's/.*Invalid user ([^ ]+) from.*/\\1/' | sort -u", lab)
    giris = _sh(f"grep 'Accepted password for root from {ip} ' auth.log | awk '{{print $3}}' | head -1", lab)
    hesap = _sh("grep 'COMMAND=/bin/bash' auth.log | sed -E 's/.*sudo: +([^ ]+) :.*/\\1/' | head -1", lab)
    kalici = _sh("grep 'new user: name=' auth.log | sed -E 's/.*name=([^,]+),.*/\\1/' | head -1", lab)
    secim = SEVIYE.gorevler[6].kontrol.cevabi_goster(__import__("hy.motor.kontrol", fromlist=["Baglam"]).Baglam(s, lab, 7))[0]
    return {1: ip, 2: sayi, 3: " ".join(gecersiz.split()), 4: giris or "hayır", 5: hesap or "yok",
            6: kalici or "yok", 7: secim}


GOREVLER = [
    Gorev("En çok **başarısız parola denemesi** yapan IP hangisi?",
          IP("ip"),
          ("Başarısız denemeler `Failed password` satırlarında.",
           "Bu satırlardan IP'yi çıkar (`grep -oE 'from [0-9.]+'`) ve say.",
           "`grep 'Failed password' auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn`"),
          puan=15, baslik="Saldırgan"),
    Gorev("O IP kaç başarısız parola denemesi yapmış?",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Bir önceki görevin boru hattı sayıyı da veriyor.",
           "`uniq -c` çıktısındaki ilk sütun sayıdır.",
           "Aynı komutun ilk satırındaki sayı."),
          puan=15, baslik="Deneme sayısı"),
    Gorev("Saldırgan hangi **var olmayan** kullanıcı adlarını denemiş?",
          Kume("gecersiz", bicim="boşlukla ayrılmış kullanıcı adları"),
          ("Var olmayan kullanıcılar için sshd özel bir satır yazar.",
           "`grep 'Invalid user' auth.log`",
           "`grep 'Invalid user' auth.log | awk '{print $8}' | sort -u` (alan numarasını kendi çıktına göre ayarla)."),
          puan=20, baslik="Geçersiz adlar"),
    Gorev("Kaba kuvvet sonunda root parolası bulundu mu? Bulunduysa girişin saatini (SS:DD:SS), "
          "bulunmadıysa `hayır` yaz.",
          Metin("brute", bicim="SS:DD:SS ya da hayır"),
          ("Başarılı parola girişi `Accepted password` satırıdır.",
           "Saldırgan IP'sinden root için bir `Accepted password` satırı var mı?",
           "`grep 'Accepted password for root from <IP>' auth.log` — satırın 3. alanı saat."),
          puan=20, baslik="Root düştü mü"),
    Gorev("Başka bir IP bir hesaba **parolayla** girip `sudo` ile root kabuğu açmış mı? Açtıysa "
          "**hesabın** adını, açmadıysa `yok` yaz.",
          Metin("hesap", bicim="hesap adı ya da yok"),
          ("sudo ile çalıştırılan komutlar `COMMAND=` ile loglanır.",
           "`grep 'COMMAND=' auth.log` — root kabuğu açmak `/bin/bash` çalıştırmaktır.",
           "`grep 'COMMAND=/bin/bash' auth.log` satırında `sudo:` sonrasındaki ilk kelime hesap adıdır."),
          puan=20, baslik="Root kabuğu"),
    Gorev("Saldırgan geri dönebilmek için yeni bir kullanıcı açmış mı (kalıcılık)? Açtıysa adını, "
          "açmadıysa `yok` yaz.",
          Metin("kalici", bicim="kullanıcı adı ya da yok"),
          ("Kullanıcı ekleme işlemi `useradd` satırı bırakır.",
           "`grep useradd auth.log`",
           "`grep 'new user: name=' auth.log` — `name=` ile virgül arasındaki kelime."),
          puan=20, baslik="Kalıcılık"),
    Gorev("Bu sunucuda parola tahmin saldırılarını **kökten** bitirecek en etkili önlem hangisi?",
          Secmeli([
              ("SSH'ta parolayla girişi kapatıp yalnızca anahtarla girişe izin vermek",
               "Doğru. `PasswordAuthentication no` ile tahmin edilecek bir parola kalmaz; deneme ne kadar sürerse sürsün sonuç vermez."),
              ("SSH portunu 22'den 2222 gibi standart olmayan bir porta taşımak",
               "Otomatik taramaların gürültüsünü azaltır ama hedefli bir saldırganı durdurmaz; port taramasıyla bulunur."),
              ("Root parolasını daha uzun ve karmaşık bir parolayla değiştirmek",
               "Faydalı ama denemeler sürer; diğer hesapların zayıf parolaları hâlâ risk."),
              ("auth.log dosyasını her gece temizleyip diskte yer açmak",
               "Bu sadece kanıtı yok eder; saldırıyı durdurmaz, tespiti imkânsızlaştırır."),
          ]),
          ("Saldırgan neyi tahmin etmeye çalışıyor?",
           "Tahmin edilecek bir parola hiç olmasaydı ne olurdu?",
           "SSH'ta anahtar tabanlı kimlik doğrulama ve `PasswordAuthentication no`."),
          puan=15, baslik="Savunma"),
]

SEVIYE = Seviye(
    kimlik="olay_ssh",
    cilt=1,
    bolum=92,
    baslik="SSH Kaba Kuvvet İncelemesi",
    brifing="""
Deniz'in SIEM ekranında kırmızı bir satır yanıp sönüyor: "**<<musteri>>**'nin
**<<sunucu>>** sunucusunda dakikada onlarca başarısız SSH girişi. `auth.log` dosyası
laboratuvarında."

"Sadece kimin denediğini değil, **içeri girip girmediğini** bilmem lazım. Girdiyse root
oldu mu, geri dönmek için bir kapı bıraktı mı? Müşteriye ne söyleyeceğimiz buna bağlı."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
İnternete açık her SSH sunucusu durmaksızın parola denemesi alır; çoğu gürültüdür.
Asıl soru şudur: deneme **başarıya** dönüştü mü? Bu yüzden analist önce `Failed`, sonra
`Accepted`, sonra `sudo` ve `useradd` satırlarına bakar: giriş, yetki yükseltme,
kalıcılık. Saldırgan kalıcılık için sıradan görünen bir kullanıcı adı seçer; savunmacı
yeni hesapları ve `sudo` grubuna eklenenleri düzenli denetler.
""",
    gercek_hayat="""
- **Mirai, 2016:** Mirai botneti, internete açık cihazlara Telnet üzerinden varsayılan
  kullanıcı adı/parola listesiyle giriş deneyerek yüz binlerce cihazı ele geçirdi ve
  büyük DDoS saldırılarında kullandı. Parola tahmini en eski ama hâlâ en çok işe yarayan
  saldırılardandır.
- **Fail2ban ve anahtarla giriş:** Sunucu sertleştirme rehberleri, SSH için parola yerine
  anahtar kullanmayı ve tekrarlayan başarısız denemeleri otomatik engelleyen araçları
  (örn. fail2ban) standart öneri olarak verir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c01b04",),
)
