"""Olay Masası — Olay Zaman Çizelgesi.

Tek bir ihlalin izi üç ayrı logda durur: web erişim logu (tarama ve dosya yükleme), SSH/auth logu
(ele geçirilen hesapla giriş) ve güvenlik duvarı logu (dışarıya veri çıkışı). Analist üç logu saat
sırasına dizip olayın zaman çizelgesini kurar. Yalnızca kanıt incelenir; saldırı kodu yoktur.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

GECERLI_YOLLAR = ["/index.php", "/urunler.php", "/iletisim.php", "/hakkimizda.php", "/css/site.css",
                  "/js/app.js", "/img/logo.png", "/sss.php"]
TARAMA_YOLLARI = ["/admin/", "/backup/", "/old/", "/test/", "/phpmyadmin/", "/config/", "/dev/", "/tmp/",
                  "/staging/", "/db/", "/panel/", "/yonetim/", "/eski/", "/dosyalar/"]
HESAPLAR = ["destek", "bakim", "yedek_svc", "sistem", "monitor", "guncelleme"]


def _hms(t) -> str:
    return t.strftime("%H:%M:%S")


def _saniye(hms: str) -> int:
    s, d, sn = (int(x) for x in hms.split(":"))
    return s * 3600 + d * 60 + sn


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)
    t_tarama = gun + timedelta(hours=rng.randint(9, 15), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))

    sal, c2, *ziyaretci = u.benzersiz(rng, u.dis_ip, 6)
    sunucu_ip = u.ic_ip(rng, "10.0.0")
    sunucu = m["sunucu"]
    hesap = rng.choice(HESAPLAR)
    mesru_kullanicilar = u.isimler(rng, 3, haric={hesap})
    ofis_ipleri = u.benzersiz(rng, lambda r: u.ic_ip(r, "192.168.10"), 3)
    kabuk = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(8)) + ".php"
    arsiv = "yedek_" + "".join(rng.choice("0123456789abcdef") for _ in range(5)) + ".tgz"

    # --- olay anları ---
    n_tarama = rng.randint(10, 13)
    tarama_t = u.zamanlar(rng, t_tarama - timedelta(seconds=1), n_tarama, 1, 3)
    t_ilk_tarama = tarama_t[0]
    t_yukle_red = tarama_t[-1] + timedelta(seconds=rng.randint(20, 90))
    t_yukle = t_yukle_red + timedelta(seconds=rng.randint(15, 60))
    kabuk_t = u.zamanlar(rng, t_yukle, rng.randint(3, 5), 10, 60)
    n_hata = rng.randint(3, 6)
    t_ssh0 = t_yukle + timedelta(minutes=rng.randint(6, 15), seconds=rng.randint(0, 59))
    hata_t = u.zamanlar(rng, t_ssh0, n_hata, 2, 9)
    t_giris = hata_t[-1] + timedelta(seconds=rng.randint(3, 15))
    t_sudo = t_giris + timedelta(minutes=rng.randint(2, 6), seconds=rng.randint(0, 59))
    t_sizma0 = t_sudo + timedelta(minutes=rng.randint(5, 14), seconds=rng.randint(0, 59))
    sizma_t = [t_sizma0] + u.zamanlar(rng, t_sizma0, rng.randint(2, 4), 60, 240)
    t_son = sizma_t[-1]
    pencere0, pencere1 = t_tarama - timedelta(minutes=25), t_son + timedelta(minutes=15)

    def rastgele_an():
        return pencere0 + timedelta(seconds=rng.randint(0, int((pencere1 - pencere0).total_seconds())))

    # --- web erişim logu ---
    ua_ziyaretci = {ip: rng.choice(u.TARAYICI_UA) for ip in ziyaretci}
    web = []
    for i, t in enumerate(tarama_t):
        yol = TARAMA_YOLLARI[i % len(TARAMA_YOLLARI)]
        kod = 404 if i < 8 else rng.choice([404, 404, 403])
        web.append((t, 1, u.apache_satiri(sal, t, "GET", yol, kod, rng.randint(150, 290), u.ARAC_UA["gobuster"])))
    ua_k = "curl/8.5.0"
    web.append((t_yukle_red, 1, u.apache_satiri(sal, t_yukle_red, "POST", "/yukle.php", 403, 199, ua_k)))
    web.append((t_yukle, 1, u.apache_satiri(sal, t_yukle, "POST", "/yukle.php", 200, rng.randint(300, 600), ua_k)))
    for t in kabuk_t:
        web.append((t, 1, u.apache_satiri(sal, t, "GET", "/uploads/" + kabuk, 200, rng.randint(40, 900), ua_k)))
    for _ in range(rng.randint(26, 34)):
        t = rastgele_an()
        ip = rng.choice(ziyaretci)
        web.append((t, 0, u.apache_satiri(ip, t, "GET", rng.choice(GECERLI_YOLLAR), 200,
                                          rng.randint(800, 48000), ua_ziyaretci[ip])))
    t = rastgele_an()
    web.append((t, 0, u.apache_satiri(ziyaretci[0], t, "GET", "/favicon.ico", 404, 196, ua_ziyaretci[ziyaretci[0]])))
    web.sort(key=lambda x: (x[0], x[1]))
    web_metin = "\n".join(x[2] for x in web) + "\n"

    # --- auth / ssh logu ---
    auth = []
    pid = rng.randint(1200, 8000)
    for kul, ip in zip(mesru_kullanicilar, ofis_ipleri):
        for _ in range(rng.randint(1, 2)):
            t = rastgele_an()
            pid += rng.randint(3, 40)
            auth.append((t, 0, u.ssh_satiri(t, sunucu, pid, f"Accepted publickey for {kul} from {ip} "
                                                            f"port {rng.randint(40000, 60000)} ssh2")))
    t = rastgele_an()
    pid += rng.randint(3, 40)
    auth.append((t, 0, u.ssh_satiri(t, sunucu, pid, f"Failed password for {mesru_kullanicilar[0]} from "
                                                    f"{ofis_ipleri[0]} port {rng.randint(40000, 60000)} ssh2")))
    pid += 17
    for t in hata_t:
        pid += rng.randint(1, 4)
        auth.append((t, 1, u.ssh_satiri(t, sunucu, pid, f"Failed password for {hesap} from {sal} "
                                                        f"port {rng.randint(40000, 60000)} ssh2")))
    pid += 3
    auth.append((t_giris, 1, u.ssh_satiri(t_giris, sunucu, pid, f"Accepted password for {hesap} from {sal} "
                                                                f"port {rng.randint(40000, 60000)} ssh2")))
    auth.append((t_sudo, 1, f"{u.syslog_zamani(t_sudo)} {sunucu} sudo: {hesap} : TTY=pts/0 ; "
                            f"PWD=/home/{hesap} ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/{arsiv} /srv/veri"))
    auth.sort(key=lambda x: (x[0], x[1]))
    auth_metin = "\n".join(x[2] for x in auth) + "\n"

    # --- güvenlik duvarı logu ---
    def fw(t, hedef, port, bayt):
        return f"{t:%Y-%m-%d %H:%M:%S} ACTION=ALLOW SRC={sunucu_ip} DST={hedef} PROTO=TCP DPT={port} BYTES={bayt}"

    guvenlik = []
    hedefler = ziyaretci[:3]
    for _ in range(rng.randint(14, 20)):
        t = rastgele_an()
        guvenlik.append((t, 0, fw(t, rng.choice(hedefler), rng.choice([443, 443, 80, 53]),
                                  rng.randint(300, 90000))))
    toplam = 0
    for t in sizma_t:
        b = rng.randint(40, 400) * 1_000_000
        toplam += b
        guvenlik.append((t, 1, fw(t, c2, 443, b)))
    guvenlik.sort(key=lambda x: (x[0], x[1]))
    fw_metin = "\n".join(x[2] for x in guvenlik) + "\n"

    dwell = int((_saniye(_hms(sizma_t[0])) - _saniye(_hms(t_ilk_tarama))) / 60)
    mb = toplam // 1_000_000

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {sunucu} ihlal zaman çizelgesi",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": sunucu, "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "saldirgan": sal,
            "ilk_tarama": _hms(t_ilk_tarama),
            "yukleme": _hms(t_yukle),
            "hesap": hesap,
            "c2": c2,
            "dwell": dwell,
        },
        "_web": web_metin,
        "_auth": auth_metin,
        "_fw": fw_metin,
        "_sizan_mb": mb,
        "_ilk_sizma": _hms(sizma_t[0]),
        "_giris": _hms(t_giris),
        "_basarisiz": n_hata,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "access.log", s["_web"])
    u.yaz(lab / "auth.log", s["_auth"])
    u.yaz(lab / "firewall.log", s["_fw"])


def _saldirgan_hata(g, beklenen, b):
    if g and g != beklenen:
        return "Tarama araçları çok sayıda 404 üretir. 404 alan IP'leri say, en çok alanı seç: `awk '$9==404'`."
    return None


def _c2_hata(g, beklenen, b):
    if g == b.senaryo["cevaplar"]["saldirgan"]:
        return "Bu, içeri girmeye çalışan IP. Veri sızdırma ise sunucudan **dışarı** giden akışta aranır."
    return None


def _dwell_hata(g, beklenen, b):
    if int(g) == b.senaryo["cevaplar"]["dwell"] + 1 or int(g) == b.senaryo["cevaplar"]["dwell"] - 1:
        return "Çok yakın: dakikayı yuvarlama, saniyeleri farka kat ve tam dakikaya aşağı yuvarla."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    sal = _sh("awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    ilk = _sh(f"grep '^{sal} ' access.log | head -1 | awk '{{print substr($4,14,8)}}'", lab)
    yukleme = _sh(f"grep '^{sal} ' access.log | grep 'POST /yukle.php' | awk '$9==200 {{print substr($4,14,8)}}' "
                  "| head -1", lab)
    hesap = _sh(f"grep Accepted auth.log | grep 'from {sal} ' | awk '{{print $9}}' | head -1", lab)
    c2 = _sh("awk '{sub(\"DST=\",\"\",$5); sub(\"BYTES=\",\"\",$8); t[$5]+=$8} END {for (k in t) print t[k], k}' "
             "firewall.log | sort -rn | head -1 | awk '{print $2}'", lab)
    sizma = _sh(f"grep 'DST={c2} ' firewall.log | head -1 | awk '{{print $2}}'", lab)
    dwell = _sh(f"echo '{ilk} {sizma}' | awk '{{split($1,x,\":\"); split($2,y,\":\"); "
                "print int(((y[1]*3600+y[2]*60+y[3])-(x[1]*3600+x[2]*60+x[3]))/60)}'", lab)
    sira = Baglam(s, lab, 7)
    return {1: sal, 2: ilk, 3: yukleme, 4: hesap, 5: c2, 6: dwell,
            7: SEVIYE.gorevler[6].kontrol.cevabi_goster(sira)[0]}


GOREVLER = [
    Gorev("Saldırgan IP'yi bul: `access.log`'ta **en çok 404** alan istemci hangisi? (Tarama araçları "
          "olmayan sayfaları yoklar.)",
          IP("saldirgan", sik_hatalar=_saldirgan_hata),
          ("Olmayan sayfa istendiğinde sunucu 404 döner; 9. alan durum kodudur.",
           "404'leri süz, IP'leri say: `awk '$9==404 {print $1}'` sonra `sort | uniq -c | sort -rn`.",
           "`awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head -3`"),
          puan=15, baslik="Saldırgan IP"),
    Gorev("Bu IP'nin **ilk isteği** saat kaçta? (Zaman çizelgesinin başlangıcı, SS:DD:SS)",
          Metin("ilk_tarama", bicim="SS:DD:SS"),
          ("Log zaman sırasındadır; saldırganın satırlarını süzünce ilki ilk istektir.",
           "`grep '^<IP> ' access.log | head -1` — saat, köşeli parantez içindeki alanın sonundadır.",
           "`grep '^<IP> ' access.log | head -1 | awk '{print substr($4,14,8)}'`"),
          puan=15, baslik="İlk iz"),
    Gorev("Saldırgan `/yukle.php`'ye yaptığı **başarılı (200) POST** ile sunucuya bir dosya bıraktı. "
          "Bu başarılı yüklemenin saati nedir? (SS:DD:SS)",
          Metin("yukleme", bicim="SS:DD:SS"),
          ("Önce bir 403 ile reddedilmiş, sonra bir 200 almış olabilir: ikisini ayır.",
           "Saldırganın satırlarında `POST /yukle.php` ara ve 9. alanı 200 olanı seç.",
           "`grep '^<IP> ' access.log | grep 'POST /yukle.php' | awk '$9==200 {print $4}'`"),
          puan=20, baslik="Yükleme anı"),
    Gorev("Aynı IP, kısa süre sonra SSH ile **içeri girdi**. Hangi kullanıcı hesabıyla başarılı giriş yaptı?",
          Metin("hesap", bicim="kullanıcı adı"),
          ("`auth.log`'ta `Failed` hatalı, `Accepted` başarılı girişlerdir.",
           "Başarılı girişleri süz ve saldırganın IP'sine göre daralt.",
           "`grep Accepted auth.log | grep '<IP> '` — `for` kelimesinden sonraki alan kullanıcı adıdır."),
          puan=20, baslik="Ele geçen hesap"),
    Gorev("`firewall.log`'a göre sunucudan **en çok veri alan dış IP** hangisi? (Veri sızdırma adayı: "
          "`BYTES=` toplamını hedef IP'ye göre topla.)",
          IP("c2", sik_hatalar=_c2_hata),
          ("Sunucudan çıkan akışlarda hedef `DST=`, veri miktarı `BYTES=` alanındadır.",
           "Alanlardaki `DST=` ve `BYTES=` önekini at, bayt değerlerini hedefe göre `awk` ile topla.",
           "`awk '{sub(\"DST=\",\"\",$5); sub(\"BYTES=\",\"\",$8); t[$5]+=$8} END {for (k in t) print t[k], k}' "
           "firewall.log | sort -rn | head -3`"),
          puan=25, baslik="Veri nereye gitti"),
    Gorev("İlk tarama isteğinden bu IP'ye **ilk büyük veri akışına** kaç **dakika** geçti? "
          "(Tam dakika, aşağı yuvarla; ihlalin 'bekleme süresi'.)",
          Sayi("dwell", sik_hatalar=_dwell_hata),
          ("İki saati bulmalısın: saldırganın ilk web isteği ve güvenlik duvarında ilk akış.",
           "Saatleri saniyeye çevirip çıkar: `SS*3600+DD*60+SN`; farkı 60'a böl ve tam kısmını al.",
           "`awk '{split($1,x,\":\"); split($2,y,\":\"); print int(((y[1]*3600+y[2]*60+y[3])-"
           "(x[1]*3600+x[2]*60+x[3]))/60)}'` — girdi: `<ilk_tarama_saati> <ilk_akis_saati>`"),
          puan=25, baslik="Bekleme süresi"),
    Gorev("Üç logu saat sırasına dizdiğinde ihlalin **doğru aşama sırası** hangisi?",
          Secmeli([
              ("Web taraması → dosya yükleme → SSH ile giriş → dışarıya veri akışı",
               "Doğru. Her aşama bir öncekinin saatinden sonra gelir: önce keşif, sonra giriş kapısı, "
               "sonra hesapla yerleşme, en son veri çıkışı."),
              ("SSH ile giriş → web taraması → dosya yükleme → dışarıya veri akışı",
               "Hayır. SSH girişinin saati, yüklemeden sonradır; zaman damgalarını karşılaştır."),
              ("Dışarıya veri akışı → web taraması → dosya yükleme → SSH ile giriş",
               "Hayır. Veri çıkışı en son saatte; önce erişim sağlanmış olmalıydı."),
              ("Dosya yükleme → web taraması → dışarıya veri akışı → SSH ile giriş",
               "Hayır. Tarama, yüklemeden önce başlar ve SSH girişi veri çıkışından önce gelir."),
          ]),
          ("Üç dosyada da zaman damgası var; en erken ve en geç olayı belirle.",
           "Her aşamanın saatini daha önce bulduğun cevaplardan al ve sırala.",
           "Tarama (ilk iz) → yükleme → SSH girişi → ilk büyük akış."),
          puan=20, baslik="Doğru sıra"),
]

SEVIYE = Seviye(
    kimlik="olay_zaman",
    cilt=1,
    bolum=101,
    baslik="Olay Zaman Çizelgesi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize **<<sunucu>>** sunucusunun üç logunu gönderdi: `access.log` (web),
`auth.log` (SSH) ve `firewall.log` (giden trafik)."

"Tek tek her log küçük bir parça. Müşteri ise sadece şunu soruyor: ne zaman başladı, nasıl
içeri girdiler, veri ne zaman çıktı? Üç logu saat sırasına diz, olayın zaman çizelgesini kur
ve saldırganın içeride ne kadar kaldığını hesapla."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Tek bir log olayın yalnızca bir karesini gösterir; hikâye ancak loglar saat sırasına dizilince
çıkar. Zaman çizelgesi üç soruyu yanıtlar: saldırgan nereden ve ne zaman girdi, içeride ne yaptı,
veri ne zaman çıktı. İlk iz ile veri çıkışı arasındaki süre (bekleme süresi, "dwell time") ne kadar
kısaysa zarar o kadar küçüktür. Savunmacı için ders: logları tek yerde topla, saatlerin
senkron olduğundan emin ol (NTP) ve ilk izdeki tarama gürültüsünü alarm kuralına çevir.
""",
    gercek_hayat="""
- **Target, 2013:** Saldırganlar bir iklimlendirme tedarikçisinin kimlik bilgileriyle ağa girdi ve
  haftalarca içeride kaldı. Güvenlik ürünü uyarı üretmişti ama uyarılar zamanında ele alınmadı;
  milyonlarca ödeme kartı verisi dışarı çıktı. Parçalar logda duruyordu, zaman çizelgesi
  kurulunca bütün hikâye okunabilir hale geldi.
- **Bekleme süresi (dwell time):** Sektör raporları, saldırganın tespit edilmeden önce ağda
  kaldığı ortalama süreyi haftalar ya da aylarla ölçer. Olay müdahale ekipleri bu süreyi kısaltmayı
  temel hedef sayar; ölçmenin tek yolu logları birleştirip saat sırasına dizmektir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c03b06",),
)
