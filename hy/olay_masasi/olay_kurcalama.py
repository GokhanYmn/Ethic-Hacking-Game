"""Olay Masası — Log Kurcalama Tespiti (Anti-Adli).

Saldırgan izini örtmek için logdan bir aralığı silmiş. Her satırın ARTAN bir sıra numarası
(seq=N) var; silinen satırlar sıra numarasında bir boşluk bırakır. Analist boşluğu, hemen
öncesindeki/sonrasındaki izi ve zaman sıçramasını bularak kurcalamayı yakalar.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

GURULTU = [
    "cron: (root) CMD (/usr/local/bin/yedek.sh)",
    "kernel: eth0: link up 1000Mbps",
    "systemd: Started Daily apt download activities",
    "nginx: worker process reloaded",
    "sshd: Accepted publickey session opened",
    "app: scheduled job completed in {ms}ms",
    "sudo: pam_unix(sudo:session) session closed",
    "ntpd: time synchronized",
    "app: health check OK",
    "logrotate: rotation check finished",
]


def _satir(seq, t, sunucu, kullanici, ip, mesaj):
    return f"seq={seq} {t:%Y-%m-%d %H:%M:%S} {sunucu} user={kullanici} ip={ip} {mesaj}"


def uret(rng):
    m = musteri_sec(rng)
    sunucu = m["sunucu"]
    gun = u.gun(rng)
    baslangic = gun + timedelta(hours=rng.randint(1, 4), minutes=rng.randint(0, 59))
    ilk_seq = rng.randint(100, 160)
    onceki = ilk_seq + rng.randint(55, 110)          # boşluktan önceki son görünen seq
    silinen = rng.randint(14, 45)                    # silinen satır sayısı
    sonraki = onceki + silinen + 1                   # boşluktan sonraki ilk görünen seq
    son_seq = sonraki + rng.randint(40, 80)

    isimler = u.isimler(rng, 5)
    saldirgan = isimler[0]
    normal = isimler[1:]
    sal_ip = u.dis_ip(rng)
    ip_havuzu = {k: u.ic_ip(rng) for k in normal}

    toplam_gorunen = (onceki - ilk_seq + 1) + (son_seq - sonraki + 1)
    zamanlar = u.zamanlar(rng, baslangic, toplam_gorunen, en_az=2, en_cok=40)
    # silinen satırların kaybolan süresi: belirgin zaman sıçraması
    sicrama = timedelta(seconds=silinen * rng.randint(25, 60))
    onceki_idx = onceki - ilk_seq
    zamanlar = zamanlar[:onceki_idx + 1] + [t + sicrama for t in zamanlar[onceki_idx + 1:]]

    seqler = list(range(ilk_seq, onceki + 1)) + list(range(sonraki, son_seq + 1))
    satirlar = []
    for seq, t in zip(seqler, zamanlar):
        if seq == onceki - 2:
            satirlar.append(_satir(seq, t, sunucu, saldirgan, sal_ip,
                                   "auth: Accepted password for " + saldirgan + " via ssh"))
        elif seq == onceki - 1:
            satirlar.append(_satir(seq, t, sunucu, saldirgan, sal_ip,
                                   "sudo: " + saldirgan + " : COMMAND=/bin/bash"))
        elif seq == onceki:
            satirlar.append(_satir(seq, t, sunucu, saldirgan, sal_ip,
                                   'bash: cmd="vi /var/log/syslog; sed -i 1,\\$d /var/log/app.log"'))
        elif seq == sonraki:
            satirlar.append(_satir(seq, t, sunucu, saldirgan, sal_ip, 'bash: cmd="history -c; exit"'))
        else:
            k = rng.choice(normal)
            mesaj = rng.choice(GURULTU).format(ms=rng.randint(40, 900))
            satirlar.append(_satir(seq, t, sunucu, k, ip_havuzu[k], mesaj))

    onceki_zaman = zamanlar[onceki_idx].strftime("%H:%M:%S")
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {sunucu} olay.log",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": sunucu, "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "ilk_silinen": onceki + 1,
            "silinen_sayi": silinen,
            "onceki_saat": onceki_zaman,
            "saldirgan_ip": sal_ip,
            "saldirgan_kullanici": saldirgan,
        },
        "_log": "\n".join(satirlar) + "\n",
        "_onceki": onceki,
        "_sonraki": sonraki,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "olay.log", s["_log"])


def _sayi_hata_son(g, beklenen, b):
    if int(g) == b.senaryo["_onceki"] and int(g) != beklenen:
        return "Bu, boşluktan ÖNCEKİ son görünen seq. Silme bir sonraki numaradan başlar."
    if int(g) == b.senaryo["_sonraki"] and int(g) != beklenen:
        return "Bu, boşluktan SONRAKİ ilk görünen seq. Silinen aralığın başını sor."
    return None


def _sayi_hata_adet(g, beklenen, b):
    if int(g) == beklenen + 1:
        return "Fark ile sayıyı karıştırdın: ardışık fark 1 fazla çıkar (silinen = fark - 1)."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _sec_cevap(s: dict, lab: Path, no: int) -> str:
    return SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]


def coz(lab: Path, s: dict) -> dict:
    # ardışık seq farkı 1'den büyük olan ilk yer: "önceki_seq sonraki_seq"
    bosluk = _sh("awk '{split($1,a,\"=\"); n=a[2]+0; if (NR>1 && n-p>1) {print p, n; exit} p=n}' olay.log", lab)
    onceki, sonraki = bosluk.split()[:2]
    ilk = _sh(f"echo $(({onceki}+1))", lab)
    adet = _sh(f"echo $(({sonraki}-{onceki}-1))", lab)
    saat = _sh(f"awk '$1==\"seq={onceki}\" {{print $3}}' olay.log", lab)
    ip = _sh(f"awk '$1==\"seq={onceki}\" {{sub(\"ip=\",\"\",$6); print $6}}' olay.log", lab)
    kullanici = _sh(f"awk '$1==\"seq={onceki}\" {{sub(\"user=\",\"\",$5); print $5}}' olay.log", lab)
    return {1: ilk, 2: adet, 3: saat, 4: ip, 5: kullanici, 6: _sec_cevap(s, lab, 6), 7: _sec_cevap(s, lab, 7)}


GOREVLER = [
    Gorev("`olay.log` her satırda artan bir `seq=N` numarası taşıyor. Saldırgan bir aralığı sildi. "
          "Silinen **ilk** satırın seq numarası nedir?",
          Sayi("ilk_silinen", sik_hatalar=_sayi_hata_son),
          ("Numaralar 1'er 1'er artmalı. Atlayan yeri bulmalısın.",
           "`awk` ile 1. alanı `=` işaretinden böl, bir önceki satırın numarasıyla farkına bak; fark 1'den büyükse boşluk var.",
           "`awk '{split($1,a,\"=\"); n=a[2]+0; if (NR>1 && n-p>1) print p, n; p=n}' olay.log` — silinen ilk seq = soldaki sayı + 1."),
          puan=20, baslik="Silinen ilk seq"),
    Gorev("Toplam **kaç satır** silinmiş?",
          Sayi("silinen_sayi", sik_hatalar=_sayi_hata_adet),
          ("Boşluğun iki ucundaki numaraları kullan.",
           "Silinen = sonraki seq - önceki seq - 1.",
           "Önceki adımdaki awk çıktısındaki iki sayıyı çıkar, 1 düş."),
          puan=15, baslik="Boşluk büyüklüğü"),
    Gorev("Boşluktan **hemen önceki** son kayıt saat kaçta yazılmış? (SS:DD:SS)",
          Metin("onceki_saat", bicim="SS:DD:SS"),
          ("Önceki seq'i taşıyan satırı bul; saat 3. alan.",
           "`awk '$1==\"seq=<N>\" {print $3}' olay.log`",
           "Bu saatten sonraki ilk kayda bakınca zaman sıçramasını da görürsün: silinen satırlar kadar süre kaybolmuş."),
          puan=15, baslik="Boşluk öncesi saat"),
    Gorev("Boşluktan hemen önce **aktif olan dış IP** hangisi? (saldırganın kaynağı)",
          IP("saldirgan_ip"),
          ("Boşluğun hemen öncesindeki satırlara bak; IP `ip=` alanında.",
           "O satırların 6. alanı IP; son üç satırı `grep -E 'seq=<N-2> |seq=<N-1> |seq=<N> '` ile süz.",
           "Diğer kullanıcılar iç ağdan; dış (192.0.2 / 198.51.100 / 203.0.113) olan saldırgan."),
          puan=20, baslik="Saldırgan IP"),
    Gorev("Boşluktan hemen önce **hangi kullanıcı** aktifti (komutları çalıştıran hesap)?",
          Metin("saldirgan_kullanici", bicim="kullanıcı adı"),
          ("Aynı satırlarda `user=` alanı var.",
           "Boşluktan önceki son satırlara bak: giriş, sudo ve silme komutu hep aynı hesaptan.",
           "`awk '$1==\"seq=<N>\" {print $5}' olay.log` — `user=` önekini at."),
          puan=15, baslik="Aktif kullanıcı"),
    Gorev("Saldırgan bu satırları **neden** sildi?",
          Secmeli([
              ("Girişini ve çalıştırdığı komutları gizleyip izini örtmek için",
               "Doğru. Anti-adli: delil olan satırlar silinince olay yeniden kurulamaz."),
              ("Disk alanı açmak için",
               "Silinen aralık tam saldırganın giriş ve komutlarının olduğu yer; tesadüf değil."),
              ("Normal log rotasyonu yüzünden kendiliğinden silindi",
               "Rotasyon dosyayı baştan keser, ortadan bir aralık koparmaz; ayrıca saldırgan komutu logda görünüyor."),
              ("Sunucunun performansını artırmak için",
               "Hiçbir yönetici ortadan bir aralık silerek performans artırmaz."),
          ]),
          ("Silinen aralığın hemen çevresinde ne var?",
           "Önceki satırlarda giriş ve log silme komutu, sonraki satırda `history -c` var.",
           "Hepsi izi örtmeye işaret ediyor."),
          puan=15, baslik="Silme amacı"),
    Gorev("Bu tür kurcalamaya karşı **en doğru savunma** hangisi?",
          Secmeli([
              ("Logları anında merkezi bir sunucuya ilet ve orada değiştirilemez (append-only / WORM) sakla",
               "Doğru. Saldırgan yerel logu silse bile kopya başka yerde, değiştirilemez durumda durur."),
              ("Log dosyasının izinlerini sadece yerel sunucuda sıkılaştır",
               "Root olan saldırgan izinleri aşar; yerel log tek başına güvenilmez."),
              ("Logları haftada bir elle kontrol et",
               "Çok geç ve elle: saldırgan hafta boyunca iz silebilir, boşluğu da görmeyebilirsin."),
              ("Disk alanını büyüt",
               "Alan sorunu çözmez; kurcalamayı engellemez."),
          ]),
          ("Saldırgan sunucuda yetkiliyse yereldeki her şeyi değiştirebilir.",
           "Logun saldırganın erişemeyeceği bir kopyası gerek.",
           "Merkezi + değiştirilemez (append-only/WORM) loglama."),
          puan=20, baslik="Doğru savunma"),
]

SEVIYE = Seviye(
    kimlik="olay_kurcalama",
    cilt=7,
    bolum=114,
    baslik="Log Kurcalama Tespiti",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> **<<sunucu>>** sunucusunun logunu gönderdi: `olay.log`. Log tam görünüyor, yine de
sıra numaralarında bir tuhaflık var gibi."

"Her satırın başında `seq=N` var ve numaralar artmalı. Saldırgan izini örtmek için logdan bir
aralığı silmiş olabilir: boşluğu bul, hemen öncesindeki ve sonrasındaki izi çıkar, zamandaki
sıçramayı doğrula."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Silinen satır yok olur, ama sıra numarası ve saat sıçraması bir ize dönüşür. Savunmanın özü:
logları saldırganın erişemeyeceği merkezi bir sunucuya gerçek zamanlı ilet, orada
değiştirilemez (append-only / WORM) sakla. Log bütünlüğü için ardışık sıra numarası ve hash
zinciri (her satır bir öncekinin özetini taşır) kurcalamayı otomatik görünür kılar; bir
boşluk alarm üretmelidir.
""",
    gercek_hayat="""
- **Log temizleme:** Gerçek saldırganlar sisteme girdikten sonra `/var/log` altını silmeyi,
  `history -c` çalıştırmayı ya da Windows'ta `wevtutil cl` ile olay günlüklerini temizlemeyi
  rutin olarak dener; Windows'ta günlük temizleme (Event ID 1102) başlı başına alarm sebebidir.
- **Timestomping:** Saldırganlar dosya zaman damgalarını değiştirerek (MITRE ATT&CK T1070)
  kötü amaçlı dosyayı eski gösterir. Yerel zamana güvenmek yerine merkezi kayıt ve sıra
  numarası tutarlılığı kontrol edilir.
- **Merkezi loglamanın değeri:** Pek çok olay incelemesinde yerel loglar silinmişken SIEM'e
  ya da uzak sysloga giden kopyalar saldırının izini kurtarmıştır.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b05",),
)
