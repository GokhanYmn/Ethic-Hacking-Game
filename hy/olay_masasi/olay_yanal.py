"""Olay Masası — Yanal Hareket Tespiti.

Müşterinin iç ağında ele geçmiş bir hesap makineden makineye atlıyor (lateral movement).
Dört beş iç hosttan gelen birleşik kimlik doğrulama logunda, kaynağı başka bir sunucunun
IP'si olan girişleri izleyerek pivot zincirini çıkarmak gerekir. Her vakada zincir, hesap
ve host'lar değişir.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

WS = ["ws01", "ws02", "ws03"]
SUNUCU = ["app01", "dosya01", "db01", "dc01"]
SON_ADAYLAR = ["dosya01", "db01", "dc01"]


def _satir(t, host, kullanici, ip, sonuc):
    return t, f"{t:%Y-%m-%d %H:%M:%S} {host} {kullanici} {ip} {sonuc}"


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)

    # Zincir: bir istasyonla başlar, 1-2 ara host, bir sunucuyla biter.
    son = rng.choice(SON_ADAYLAR)
    ilk = rng.choice(WS)
    ara_havuz = [h for h in WS + SUNUCU if h not in (ilk, son)]
    zincir = [ilk] + rng.sample(ara_havuz, rng.randint(1, 2)) + [son]

    kullanicilar = u.isimler(rng, 9)
    ele = kullanicilar[0]
    normaller = kullanicilar[1:8]
    admin = "adm_" + kullanicilar[8]

    kullanilan = set()

    def ip_al(ag):
        ip = u.benzersiz(rng, lambda r: u.ic_ip(r, ag), 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    hostip = {h: ip_al("10.10.5") for h in WS + SUNUCU}
    istasyon_ip = {k: ip_al("192.168.10") for k in normaller + [admin]}
    vpn_ip = ip_al("10.99.0")        # ele geçmiş hesabın içeri girdiği ilk kaynak
    yedek_ip = ip_al("10.10.9")
    tum_hostlar = WS + SUNUCU

    olaylar = []

    # YEM: gündüz normal girişler (her kullanıcı kendi istasyon IP'sinden)
    for k in normaller:
        for _ in range(rng.randint(7, 14)):
            t = gun + timedelta(seconds=rng.randint(8 * 3600, 18 * 3600 + 1800))
            host = rng.choice(tum_hostlar)
            if rng.random() < 0.07:
                olaylar.append(_satir(t, host, k, istasyon_ip[k], "BASARISIZ"))
                t += timedelta(seconds=rng.randint(5, 40))
            olaylar.append(_satir(t, host, k, istasyon_ip[k], "BASARILI"))

    # YEM: BT yöneticisi birkaç hosta kendi istasyonundan girer (yıldız şeklinde, zincir değil)
    for h in rng.sample(tum_hostlar, 4):
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        olaylar.append(_satir(t, h, admin, istasyon_ip[admin], "BASARILI"))

    # YEM: gece yedek hesabı sabit bir yedek sunucu IP'sinden girer
    for h in ("dosya01", "db01"):
        t = gun + timedelta(seconds=rng.randint(3600, 3600 + 900))
        olaylar.append(_satir(t, h, "svc_yedek", yedek_ip, "BASARILI"))

    # SALDIRI: ele geçmiş hesap host→host ilerler
    basla = gun + timedelta(seconds=rng.randint(2 * 3600, 3 * 3600 + 1800))
    zamanlar = u.zamanlar(rng, basla, 12, 40, 420)
    zi = 0
    basarisiz = 0
    onceki_ip = vpn_ip
    for host in zincir:
        for _ in range(rng.randint(0, 2)):
            olaylar.append(_satir(zamanlar[zi], host, ele, onceki_ip, "BASARISIZ"))
            zi += 1
            basarisiz += 1
        olaylar.append(_satir(zamanlar[zi], host, ele, onceki_ip, "BASARILI"))
        zi += 1
        onceki_ip = hostip[host]

    olaylar.sort(key=lambda x: x[0])
    log = "\n".join(s for _, s in olaylar) + "\n"
    hostlar = "".join(f"{h} {hostip[h]}\n" for h in tum_hostlar)
    son_ip = hostip[zincir[-2]]

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — iç ağ kimlik doğrulama kayıtları",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"]},
        "cevaplar": {
            "hesap": [ele],
            "giris": [zincir[0]],
            "son": [zincir[-1]],
            "host_sayisi": len(zincir),
            "ip": [son_ip],
            "basarisiz": basarisiz,
        },
        "_log": log,
        "_hostlar": hostlar,
        "_vpn_ip": vpn_ip,
        "_admin": admin,
        "_zincir": zincir,
        "_toplam_host": len(tum_hostlar),
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "auth_birlesik.log", s["_log"])
    u.yaz(lab / "hostlar.txt", s["_hostlar"])


def _hesap_hata(g, beklenen, b):
    if g == b.senaryo["_admin"]:
        return "Bu BT yöneticisi birçok hosta kendi istasyonundan giriyor; host→host zinciri değil, yıldız şekli."
    if g == "svc_yedek":
        return "Yedek hesabı her gece sabit bir yedek IP'sinden girer; kaynağı bir sunucunun IP'si değil."
    return None


def _giris_hata(g, beklenen, b):
    if g == b.senaryo["_zincir"][-1] and g not in beklenen:
        return "Bu zincirin sonu. Giriş host'u, hesabın **ilk** başarılı girişinin yapıldığı makinedir."
    return None


def _son_hata(g, beklenen, b):
    if g == b.senaryo["_zincir"][0] and g not in beklenen:
        return "Bu zincirin başı. Aradığın, hesabın **en son** başarılı girdiği host."
    return None


def _sayi_hata(g, beklenen, b):
    if int(g) == beklenen - 1:
        return "Atlama sayısını bulmuşsun; soru dokunulan **host** sayısını istiyor (atlama + 1)."
    if int(g) == b.senaryo["_toplam_host"]:
        return "Bu, ağdaki toplam host sayısı. Sadece ele geçmiş hesabın başarıyla girdiği hostlar sayılır."
    return None


def _ip_hata(g, beklenen, b):
    if g == b.senaryo["_vpn_ip"]:
        return "Bu hesabın içeri girdiği ilk kaynak. Soru, **son host'a** giren IP'yi istiyor: bir önceki host'un IP'si."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    hesap = _sh("awk 'NR==FNR {h[$2]=1; next} $6==\"BASARILI\" && ($5 in h) {print $4}' "
                "hostlar.txt auth_birlesik.log | sort -u | head -1", lab)
    giris = _sh(f"awk -v u={hesap} '$4==u && $6==\"BASARILI\" {{print $3; exit}}' auth_birlesik.log", lab)
    son = _sh(f"awk -v u={hesap} '$4==u && $6==\"BASARILI\" {{h=$3}} END {{print h}}' auth_birlesik.log", lab)
    sayi = _sh(f"awk -v u={hesap} '$4==u && $6==\"BASARILI\" {{print $3}}' auth_birlesik.log | sort -u | wc -l", lab)
    ip = _sh(f"awk -v u={hesap} '$4==u && $6==\"BASARILI\" {{k=$5}} END {{print k}}' auth_birlesik.log", lab)
    basarisiz = _sh(f"awk -v u={hesap} '$4==u && $6==\"BASARISIZ\"' auth_birlesik.log | wc -l", lab)
    from hy.motor.kontrol import Baglam
    secim = SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]
    return {1: hesap, 2: giris, 3: son, 4: sayi, 5: ip, 6: basarisiz, 7: secim}


GOREVLER = [
    Gorev("Ele geçmiş hesap hangisi? Girişlerinin **kaynağı başka bir iç host'un IP'si** olan hesabı bul "
          "(`hostlar.txt` host-IP eşleşmesini verir).",
          Metin("hesap", sik_hatalar=_hesap_hata, bicim="kullanıcı adı"),
          ("Normal kullanıcılar hosta kendi istasyonlarından girer. Kaynağı bir sunucunun IP'si olan kim?",
           "`hostlar.txt`'deki IP'leri `auth_birlesik.log`'un 5. alanıyla (kaynak IP) karşılaştır; "
           "yalnızca `BASARILI` satırlara bak.",
           "`awk 'NR==FNR {h[$2]=1; next} $6==\"BASARILI\" && ($5 in h) {print $4}' hostlar.txt auth_birlesik.log | sort -u`"),
          puan=20, baslik="Ele geçmiş hesap"),
    Gorev("Bu hesap iç ağa **hangi host'tan** girdi (ilk başarılı girişi)?",
          Metin("giris", sik_hatalar=_giris_hata, bicim="host adı"),
          ("Log tarih sırasındadır; ilk başarılı satır ilk girişidir.",
           "Hesabın satırlarını süz, `BASARILI` olanın ilkini al; host 3. alan.",
           "`awk '$4==\"<hesap>\" && $6==\"BASARILI\"' auth_birlesik.log | head -1`"),
          puan=15, baslik="Giriş host'u"),
    Gorev("Saldırgan hesap **en son hangi host'a** ulaştı?",
          Metin("son", sik_hatalar=_son_hata, bicim="host adı"),
          ("Aynı satırlara bu kez sondan bak.",
           "Hesabın başarılı girişlerinin sonuncusu zincirin ucudur.",
           "`awk '$4==\"<hesap>\" && $6==\"BASARILI\"' auth_birlesik.log | tail -1`"),
          puan=15, baslik="Ulaşılan son host"),
    Gorev("Hesap **kaç farklı host'a** başarıyla girdi?",
          Sayi("host_sayisi", sik_hatalar=_sayi_hata),
          ("Hesabın başarılı girişlerinin 3. alanındaki host adlarını tekilleştir.",
           "Kalıp: süz → host alanını al → `sort -u` → say.",
           "`awk '$4==\"<hesap>\" && $6==\"BASARILI\" {print $3}' auth_birlesik.log | sort -u | wc -l`"),
          puan=15, baslik="Dokunulan host"),
    Gorev("Saldırgan **son host'a** hangi iç kaynak IP'den girdi? (Yani bir önceki atlama noktasının IP'si.)",
          IP("ip", sik_hatalar=_ip_hata),
          ("Zincirde her atlamanın kaynak IP'si, bir önceki ele geçmiş makinenin IP'sidir.",
           "Hesabın son başarılı satırının 5. alanı.",
           "`awk '$4==\"<hesap>\" && $6==\"BASARILI\" {print $5}' auth_birlesik.log | tail -1` — "
           "çıkan IP'yi `hostlar.txt` ile eşleştirip hangi makine olduğunu da gör."),
          puan=20, baslik="Pivot kaynağı"),
    Gorev("Hesabın logda **kaç başarısız** (`BASARISIZ`) giriş denemesi var?",
          Sayi("basarisiz"),
          ("Sonuç alanı satırın sonundadır (6. alan).",
           "Hesabı ve `BASARISIZ` sonucunu birlikte süz, satırları say.",
           "`awk '$4==\"<hesap>\" && $6==\"BASARISIZ\"' auth_birlesik.log | wc -l`"),
          puan=15, baslik="Başarısız deneme"),
    Gorev("Bu tür **yanal hareketi** ağ içinde en etkili biçimde kısıtlayacak savunma hangisi?",
          Secmeli([
              ("Ağı segmentlere bölmek, host→host girişini kısıtlamak, yönetim girişlerinde MFA zorunlu kılmak ve "
               "ele geçen hesabı hemen izole edip parolasını sıfırlamak",
               "Doğru. Segmentasyon atlamayı zorlaştırır, MFA çalınmış parolayı/özeti yetersiz bırakır, "
               "hesap izolasyonu ilerleyişi durdurur."),
              ("Sadece çevre güvenlik duvarını güçlendirmek",
               "Saldırgan zaten içeride; çevre duvarı iç ağdaki host→host trafiğini görmez."),
              ("Tüm kullanıcıların parolasını her hafta değiştirmek",
               "Pass-the-hash gibi tekniklerde parolaya gerek kalmaz; tek başına yeterli değil."),
              ("Kimlik doğrulama loglarını kapatıp performansı artırmak",
               "Log olmadan yanal hareketi hiç göremezsin; savunmayı kör eder."),
          ]),
          ("Saldırgan içeride; sorun sınır değil, içerideki serbest dolaşım.",
           "Hem ağı bölmek, hem kimliği korumak, hem de ele geçeni hızla durdurmak gerekir.",
           "Segmentasyon + MFA + hesap izolasyonu."),
          puan=15, baslik="Savunma"),
]

SEVIYE = Seviye(
    kimlik="olay_yanal",
    cilt=6,
    bolum=111,
    baslik="Yanal Hareket Tespiti",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize birkaç iç sunucunun ve istasyonun birleşik kimlik doğrulama kaydını gönderdi:
`auth_birlesik.log`. Her satır: `tarih saat HOST kullanıcı kaynak-IP sonuç`. Host'ların IP
eşleşmesi `hostlar.txt` içinde."

"Bir hesabın ele geçtiğinden şüpheleniyoruz. Saldırgan bir makineden diğerine atlıyor
olabilir. Normal kullanıcılar hosta kendi istasyonundan girer; **kaynağı başka bir
sunucunun IP'si** olan giriş şüphelidir. Zinciri çıkar: nereden girdi, nereye vardı?"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Yanal hareket, saldırganın tek bir kapıdan girip ağın içinde yayılmasıdır; her atlama logda
"kaynağı başka bir sunucu olan giriş" olarak görünür. Savunmacı bu deseni arar: normalde
istasyondan sunucuya giden trafik, sunucudan sunucuya akıyorsa alarm vardır. Kalıcı çözüm
ağ segmentasyonu, en az yetki ilkesi, yönetim girişlerinde MFA, kimlik izleme ve host→host
trafiğini yalnızca gereken yollarla sınırlamaktır.
""",
    gercek_hayat="""
- **NotPetya, 2017:** Zararlı, ağ içinde Mimikatz ile çıkardığı kimlik bilgilerini ve
  pass-the-hash tekniğini kullanarak makineden makineye atladı; düz (segmentasyonsuz) iç
  ağlarda saatler içinde on binlerce bilgisayarı etkiledi.
- **Büyük ihlaller:** Target (2013) gibi olaylarda saldırgan önce küçük bir erişim noktasından
  girip ağ içinde ilerleyerek asıl hedefe ulaştı. Pivot, ihlallerde sızmadan sonraki en
  yaygın adımdır; tespiti için dahili kimlik doğrulama logları kritik veridir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c06b07",),
)
