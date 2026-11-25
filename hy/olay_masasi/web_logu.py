"""Olay Masası — Web Logunda Saldırgan Avı.

Her vakada başka bir müşteri ve başka bir saldırı karışımı (kaba kuvvet, SQL enjeksiyonu,
otomatik tarayıcı, dizin atlama); her biri bazen başarılı bazen değil. Cilt 1 Bölüm 4'ün
boru hattı becerilerini sınırsız vakayla pekiştirir.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Metin, Sayi
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

HAYIR = ["hayır", "hayir", "yok", "başarısız", "basarisiz", "olmadı", "olmadi"]


def uret(rng):
    m = musteri_sec(rng)
    turler = tuple(rng.sample(loglar.SALDIRI_TURLERI, rng.randint(2, 4)))
    basari = {"brute": rng.random() < 0.6, "tarama": rng.random() < 0.6}
    web = loglar.web_logu(rng, m, saldirilar=turler, basari=basari)
    oz, sal = web["ozet"], web["saldirilar"]
    brute = sal.get("brute")
    log = loglar.metin(web)
    sizan = oz["sizan_dosya"]
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {m['sunucu']} erişim logu",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "ip_sayisi": oz["ip_sayisi"],
            "en_cok": oz["en_cok_ip"],
            "sayi_401": oz["sayi_401"],
            "saldirganlar": oz["saldirgan_ipler"],
            "tarayici": [oz["tarayici"]] if oz["tarayici"] else ["yok", "hayır", "hayir"],
            "sizan": [sizan, sizan.lstrip("/")] if sizan else ["yok", "hayır", "hayir"],
            "brute": [brute["zaman"]] if brute and brute["basarili"] else HAYIR,
        },
        "_log": log,
        "_mesru": set(oz["mesru_ipler"]) | {web["admin_ip"]},
        "_ardisik": oz["ardisik_en_cok_ip"],
        "_grep401": sum(1 for s in log.splitlines() if "401" in s),
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "access.log", s["_log"])


def _en_cok_hata(g, beklenen, b):
    if g == b.senaryo["_ardisik"] and g not in beklenen:
        return "Bu IP, `uniq -c`'nin yan yana gelen satırlarda bulduğu en büyük blok. `uniq`'ten önce `sort` ekle."
    return None


def _401_hata(g, beklenen, b):
    if int(g) == b.senaryo["_grep401"] and int(g) != beklenen:
        return "`grep 401` boyut alanındaki ya da yoldaki 401'leri de sayıyor. Durum kodunu hedefle: `awk '$9==401'`."
    return None


def _saldirgan_hata(g, beklenen, b):
    if set(g.split()) & b.senaryo["_mesru"]:
        return "Listende meşru bir kullanıcı var: birkaç hatalı giriş ya da normal sayfa gezintisi saldırı değildir."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    ip_sayisi = _sh("cut -d' ' -f1 access.log | sort -u | wc -l", lab)
    en_cok = _sh("cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    sayi_401 = _sh("awk '$9==401' access.log | wc -l", lab)
    brute_ip = _sh("awk '$9==401 {print $1}' access.log | sort | uniq -c | awk '$1>=5 {print $2}'", lab)
    sqli = _sh("grep -iE \"union|select|%27|'|sleep\\(|1=1\" access.log | cut -d' ' -f1 | sort -u", lab)
    trav = _sh("grep -iE '\\.\\./|%2e%2e|\\.\\.%2f|%5c|\\.\\.\\.\\./' access.log | cut -d' ' -f1 | sort -u", lab)
    tarayan = _sh("grep -E 'Nikto|gobuster|Fuzz Faster' access.log | cut -d' ' -f1 | sort -u", lab)
    saldirganlar = sorted(set((brute_ip + "\n" + sqli + "\n" + trav + "\n" + tarayan).split()))
    arac = _sh("grep -oE 'Nikto|gobuster|Fuzz Faster U Fool' access.log | head -1", lab)
    arac = {"Fuzz Faster U Fool": "ffuf"}.get(arac, arac) or "yok"
    sizan = _sh("grep -E 'Nikto|gobuster|Fuzz Faster' access.log | awk '$9==200 {print $7}' "
                "| grep -v robots.txt | head -1", lab) or "yok"
    brute = "hayır"
    if brute_ip:
        zaman = _sh(f"grep '^{brute_ip} ' access.log | grep '\"POST ' | awk '$9==200 {{print $4}}' | head -1", lab)
        if zaman:
            brute = zaman.split(":", 1)[1]
    return {1: ip_sayisi, 2: en_cok, 3: sayi_401, 4: " ".join(saldirganlar), 5: arac, 6: sizan, 7: brute}


GOREVLER = [
    Gorev("Logda kaç **farklı** IP adresi var?",
          Sayi("ip_sayisi"),
          ("İlk alan IP. Tekrarları atıp saymalısın.",
           "`cut -d' ' -f1` ile IP'leri al, `sort -u` ile teke indir, `wc -l` ile say.",
           "`cut -d' ' -f1 access.log | sort -u | wc -l`"),
          puan=15, baslik="IP sayısı"),
    Gorev("En çok istek gönderen IP hangisi?",
          IP("en_cok", sik_hatalar=_en_cok_hata),
          ("Her IP'nin kaç kez geçtiğini saymalısın.",
           "Kalıp: IP'leri kes → sırala → `uniq -c` → büyükten küçüğe sırala.",
           "`cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head -3`"),
          puan=15, baslik="En gürültülü"),
    Gorev("Sunucu kaç kez **401** (yetkisiz) cevabı vermiş?",
          Sayi("sayi_401", sik_hatalar=_401_hata),
          ("Durum kodu satırın belirli bir alanında; satırın başka yerlerinde de 401 geçebilir.",
           "Boşlukla bölünce durum kodu 9. alan: `awk '$9==401'`.",
           "`awk '$9==401' access.log | wc -l`"),
          puan=15, baslik="401"),
    Gorev("Saldırgan IP'lerin hepsini yaz (kaba kuvvet, SQL enjeksiyonu, tarayıcı, dizin atlama).",
          Kume("saldirganlar", tur="ip", sik_hatalar=_saldirgan_hata, bicim="boşlukla ayrılmış IP'ler"),
          ("Dört imzaya ayrı ayrı bak: çok sayıda 401, SQL karakterleri, araç adı geçen User-Agent, `../`.",
           "`grep -iE \"union|select|'\"`, `grep -E '\\.\\./|%2e%2e'`, `grep -E 'Nikto|gobuster|Fuzz'` ve 401 sayımı.",
           "Her grep'in sonuna `| cut -d' ' -f1 | sort -u` ekle; kaba kuvvet için 401 alan IP'leri `uniq -c` ile say."),
          puan=30, baslik="Saldırganlar"),
    Gorev("Otomatik bir tarama aracı kullanılmış mı? Kullanıldıysa adı ne, kullanılmadıysa `yok` yaz.",
          Metin("tarayici", bicim="araç adı ya da yok"),
          ("Araçlar kendilerini User-Agent alanında tanıtır.",
           "`awk -F'\"' '{print $6}' access.log | sort | uniq -c | sort -rn`",
           "Listede Nikto, gobuster ya da 'Fuzz Faster U Fool' (ffuf) var mı?"),
          puan=15, baslik="Tarayıcı"),
    Gorev("Tarayıcı bir yedek ya da gizli dosyayı **indirmeyi başardı mı**? Başardıysa yolunu yaz, "
          "başaramadıysa `yok` yaz.",
          Metin("sizan", bicim="dosya yolu ya da yok"),
          ("Tarayıcının isteklerinden hangileri 200 (başarılı) almış?",
           "Tarayıcının satırlarını süz, durum kodu 200 olanların yolunu yazdır (9. alan kod, 7. alan yol).",
           "`grep -E 'Nikto|gobuster|Fuzz' access.log | awk '$9==200 {print $7}'` — robots.txt herkese açıktır, sayma."),
          puan=20, baslik="Sızan dosya"),
    Gorev("Kaba kuvvet (brute-force) saldırısı başarılı oldu mu? Olduysa başarılı girişin saatini "
          "(SS:DD:SS) yaz, olmadıysa `hayır` yaz.",
          Metin("brute", bicim="SS:DD:SS ya da hayır"),
          ("Peş peşe 401 alan IP sonunda aynı sayfadan 200 almış mı?",
           "Kaba kuvvet yapan IP'nin POST isteklerine bak; 401'lerden sonra 200 var mı?",
           "`grep '^<IP> ' access.log | grep POST | awk '$9==200 {print $4}'` — köşeli parantezden sonraki saat kısmı."),
          puan=20, baslik="Kaba kuvvet"),
]

SEVIYE = Seviye(
    kimlik="olay_web",
    cilt=1,
    bolum=91,
    baslik="Web Logunda Saldırgan Avı",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize **<<sunucu>>** sunucusunun erişim logunu gönderdi: `access.log`."

"Kim saldırmış, nasıl, ne kadar ilerlemiş? Her saldırganın imzası farklıdır: biri parola
dener, biri SQL karakterleri yollar, biri bir aracın adını User-Agent'ta bırakır. Hepsini
bul."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Her saldırı türü logda kendine özgü bir iz bırakır: kaba kuvvet çok sayıda 401, SQL
enjeksiyonu tırnak ve `UNION`, tarayıcı kendi adını, dizin atlama `../`. Saldırgan bu
izleri azaltmak için yavaşlar, User-Agent'ını değiştirir. Savunmacı ise aynı dört boru
hattını bir betiğe koyup her saat çalıştırır; pahalı bir ürün olmadan bile saldırıların
çoğu böyle yakalanır.
""",
    gercek_hayat="""
- **Equifax, 2017:** Saldırganlar yamalanmamış bir Apache Struts açığından girdi ve
  aylarca fark edilmedi. Sonraki incelemeler, şüpheli trafiği görmesi gereken izleme
  araçlarından birinin süresi dolmuş bir sertifika yüzünden uzun süre çalışmadığını ortaya
  koydu: log var ama okuyan yoksa saldırı görünmez.
- **Otomatik tarayıcılar:** İnternete açık her web sunucusunun logu, dakikalar içinde
  `/.env`, `/.git/HEAD`, `/wp-config.php.bak` gibi yolları arayan otomatik taramalarla
  dolar. Bu yüzden yedek dosyaları web kökünde bırakmak sızma testi raporlarının en sık
  bulgularındandır.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c01b04",),
)
