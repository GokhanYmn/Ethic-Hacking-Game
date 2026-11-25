"""Cilt 1 · Bölüm 7 — Kapanış Görevi: Küçük Bir Olay Müdahalesi.

Yeni bir şey öğretmez; Cilt 1'in becerilerini (find, grep, cut|sort|uniq, awk, izinler,
süreçler) tek bir olayda birleştirir. Web + SSH logları `hy.ortak.loglar.olay_uret` ile
üretilir: tarayıcı yedek dosyayı indirir, panel brute-force ile ele geçirilir, biri SSH ile
girip sudo ile root olur ve kalıcılık için yeni bir kullanıcı ekler.

Vakalar: her tohumda farklı müşteri, farklı ek saldırılar (SQL injection, path traversal),
SSH'a giren aktörün yedeği indirenle aynı olup olmaması, saldırgan IP'leri ve zamanlar değişir.

Not: Kitaptaki "acil üç adım" sorusu, rehberin "seviye başına en fazla bir Serbest" kuralı
nedeniyle, Mert'in taslak listesinden en acil üç maddeyi seçtiren kontrol edilebilir bir
göreve çevrildi. Olay raporu Serbest görevdir.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Metin, Sayi, Serbest
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import loglar
from hy.ortak.vakalar import musteri_sec

LOG_KLASORLERI = ["loglar", "gelen_loglar", "olay_kanitlari", "kayitlar"]
AYLAR_TR = ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim",
            "Kasım", "Aralık"]
YANLIS_ONERILER = [
    ("Disk dolmasın diye access.log ve auth.log dosyalarının hemen silinmesi",
     "Logları silmek kanıtı yok eder; ne olduğunu bir daha kimse kanıtlayamaz. Loglar korunur, kopyası alınır."),
    ("Saldırgan IP adreslerine karşı bizim de tarama ve saldırı başlatmamız (karşı saldırı)",
     "Karşı saldırı (hack back) yasa dışıdır ve IP'ler çoğu zaman başkasına ait, ele geçirilmiş makinelerdir."),
    ("Paniğe yol açmamak için müşteri yönetimine ve ilgililere hiçbir şey söylenmemesi",
     "Olay gizlenmez; yönetim bilgilendirilir. Kişisel veri sızdıysa KVKK'ya göre bildirim yükümlülüğü de doğabilir."),
    ("Sitenin ana sayfa tasarımının yenilenip yeni bir tema yüklenmesi",
     "Görüntüyle ilgili bir değişiklik olayı çözmez; saldırganın erişimi ve sızan parolalar yerinde kalır."),
    ("Sunucunun kanıtlar incelenmeden hemen formatlanıp aynı ayarlarla yeniden açılması",
     "Kanıt incelenmeden formatlamak neyin sızdığını öğrenmeyi imkânsız kılar; aynı ayarlarla açmak da aynı açıkları geri getirir."),
]


def uret(rng):
    m = musteri_sec(rng)
    log_k = rng.choice(LOG_KLASORLERI)
    o = loglar.olay_uret(rng, m)
    web, ssh = o["web"], o["ssh"]
    sa = web["saldirilar"]
    brute, tarama = sa["brute"], sa["tarama"]
    ele = ssh["ele_gecirme"]
    gun = web["baslangic"]
    dogru = [
        f"{ele['hesap']} SSH hesabının, web panelinin ve sızan dosyadaki veritabanı parolasının hemen "
        "değiştirilmesi; saldırgan IP'lerinin engellenmesi",
        f"{tarama['dosya']} dosyasının web kökünden kaldırılması ve kökte başka yedek ya da yapılandırma "
        "dosyası kalıp kalmadığının taranması",
        f"Sunucunun ele geçirilmiş kabul edilmesi: {ele['yeni_kullanici']} hesabının ve diğer kalıcılık izlerinin "
        "(cron, SSH anahtarları, sudo grubu) incelenmesi, mümkünse temiz yedekten yeniden kurulum",
    ]
    yanlis = rng.sample(YANLIS_ONERILER, 4)
    maddeler = [(t, None) for t in dogru] + yanlis
    rng.shuffle(maddeler)
    acil = [i + 1 for i, (_, a) in enumerate(maddeler) if a is None]
    ekler = []
    if "sqli" in sa:
        ekler.append(f"{sa['sqli']['ip']} adresi {sa['sqli']['hedef']} sayfasında SQL injection denedi")
    if "traversal" in sa:
        ekler.append(f"{sa['traversal']['ip']} adresi {sa['traversal']['hedef']} sayfasında dizin atlama (../) denedi")
    ek_metin = ("Ayrıca " + "; ".join(ekler) + ".") if ekler else ""
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — olay müdahalesi",
        "musteri": m,
        "log_k": log_k,
        "access": loglar.metin(web),
        "auth": loglar.metin(ssh),
        "maddeler": maddeler,
        "web": {"ozet": web["ozet"], "saldirilar": sa, "admin_ip": web["admin_ip"], "mesru": web["mesru"]},
        "ssh": {"ozet": ssh["ozet"], "brute": ssh["brute"], "ele": ele, "mesru": ssh["mesru"]},
        "metin": {
            "musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"], "sunucu": m["sunucu"],
            "alan": m["alan"], "log_k": log_k, "giris": m["giris"], "hassas": m["hassas_veri"],
            "tarih": f"{gun.day} {AYLAR_TR[gun.month - 1]} {gun.year}",
            "tarama_ip": tarama["ip"], "tarayici": tarama["arac"], "sizan": tarama["dosya"], "sizma_saat": tarama["zaman"],
            "brute_ip": brute["ip"], "brute_deneme": brute["deneme"], "panel_saat": brute["zaman"],
            "ssh_ip": ele["ip"], "hesap": ele["hesap"], "ssh_saat": ele["zaman"], "root_saat": ele["root_zaman"],
            "yeni": ele["yeni_kullanici"], "ek_saldirilar": ek_metin,
            "ayni_aktor": ("Aynı IP önce yedeği indirmiş, sonra SSH'a girmiş: sızan parola tekrar kullanılmış olabilir."
                           if o["ozet"]["ayni_aktor"] else ""),
        },
        "cevaplar": {
            "ip_sayisi": web["ozet"]["ip_sayisi"],
            "saldirganlar": web["ozet"]["saldirgan_ipler"],
            "panel_saat": brute["zaman"],
            "sizan": tarama["dosya"],
            "sizan_ip": tarama["ip"],
            "ssh_ip": ele["ip"],
            "yeni_kullanici": ele["yeni_kullanici"],
            "acil": acil,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    v = s["metin"]
    (lab / s["log_k"]).mkdir(parents=True, exist_ok=True)
    (lab / s["log_k"] / "access.log").write_text(s["access"], encoding="utf-8")
    (lab / s["log_k"] / "auth.log").write_text(s["auth"], encoding="utf-8")
    (lab / "OKUBENI.txt").write_text(
        f"Kimden : {m['kisi']} — {m['ad']}\n"
        f"Konu   : ACİL — {m['sunucu']}\n\n"
        f"{v['tarih']} günü sunucuda bir şeyler oldu, emin değilim. {m['hikaye']}\n"
        f"Web sunucusunun ve SSH'ın loglarını {s['log_k']}/ klasörüne koydum.\n"
        "Neler olduğunu, ne zaman olduğunu ve ne yapmamız gerektiğini anlatabilir misiniz?\n", encoding="utf-8")
    satirlar = [f"Mert'in taslak eylem listesi — {m['ad']} olayı",
                "(Selin'in notu: \"Hepsi aynı derecede acil değil, bazıları düpedüz zararlı. En acil üçünü seç.\")", ""]
    satirlar += [f"{i}. {t}" for i, (t, _) in enumerate(s["maddeler"], 1)]
    (lab / "oneri_taslagi.txt").write_text("\n".join(satirlar) + "\n", encoding="utf-8")
    (lab / "rapor_sablonu.md").write_text(
        f"# Olay Raporu — {m['ad']} ({m['sunucu']})\n\n"
        "## Ne oldu? (bir-iki cümlelik özet)\n\n## Ne zaman? (zaman çizelgesi)\n\n"
        "## Kanıtlar (log satırları, IP'ler, komutlar)\n\n## Etki (ne sızdı, kim etkilendi)\n\n"
        "## Ne yapılmalı? (acil ve kalıcı önlemler)\n", encoding="utf-8")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: Cilt 1 boru hatlarıyla olayı yeniden kurgular."""
    from hy.motor.kontrol import Baglam
    a, au = f"{s['log_k']}/access.log", f"{s['log_k']}/auth.log"
    ip_sayisi = _sh(f"cut -d' ' -f1 {a} | sort -u | wc -l", lab)
    saldirgan = _sh(
        f"{{ grep '\" 401 ' {a} | cut -d' ' -f1 | sort | uniq -c | awk '$1>=3{{print $2}}'; "
        f"grep -iE 'nikto|gobuster|fuzz faster' {a} | cut -d' ' -f1; "
        f"grep -iE \"union|select|%27|'|\\.\\./|\\.\\.%2f|%2e%2e|%5c\" {a} | cut -d' ' -f1; }} | sort -u", lab)
    brute_ip = _sh(f"grep '\" 401 ' {a} | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    panel = _sh(f"grep '^{brute_ip} ' {a} | grep POST | grep '\" 200 ' | head -1 | cut -d: -f2-4 | cut -d' ' -f1", lab)
    tarama = f"grep -iE 'nikto|gobuster|fuzz faster' {a} | grep '\" 200 ' | grep -v robots.txt"
    sizan = _sh(f"{tarama} | awk '{{print $7}}'", lab)
    sizan_ip = _sh(f"{tarama} | cut -d' ' -f1", lab)
    hesap = _sh(f"grep 'COMMAND=/bin/bash' {au} | awk '{{print $6}}'", lab)
    ssh_ip = _sh(f"grep 'Accepted password for {hesap} ' {au} | grep -oE 'from [0-9.]+' | cut -d' ' -f2", lab)
    yeni = _sh(f"grep 'new user' {au} | grep -oE 'name=[^,]+' | cut -d= -f2", lab)
    acil = SEVIYE.gorevler[7].kontrol.cevabi_goster(Baglam(s, lab, 8))
    rapor = ("Web sunucusunda tarayıcı yedek dosyayı indirdi, panel brute-force ile ele geçirildi, ardından bir IP "
             "SSH ile parolayla girip sudo ile root oldu ve kalıcılık için yeni bir kullanıcı ekledi. Parolalar "
             "değiştirilmeli, yedek kaldırılmalı, sunucu incelenip temiz yedekten kurulmalı.")
    return {1: ip_sayisi, 2: ",".join(saldirgan.split()), 3: panel, 4: sizan, 5: sizan_ip, 6: ssh_ip, 7: yeni,
            8: acil, 9: rapor}


# ---------------------------------------------------------------- sık hatalar

def _ip_sayisi_hata(g, beklenen, b):
    n = int(g)
    if n == b.senaryo["web"]["ozet"]["ardisik_blok_sayisi"]:
        return "`uniq` sadece yan yana duran tekrarları birleştirir. Önce `sort`, sonra `uniq` (ya da `sort -u`)."
    if n == b.senaryo["web"]["ozet"]["toplam"]:
        return "Bu toplam istek sayısı. Soru kaç farklı IP olduğunu soruyor."
    return None


def _saldirgan_hata(g, beklenen, b):
    verilen = set(g.split())
    w = b.senaryo["web"]
    fazla = verilen - set(beklenen)
    if w["admin_ip"] in fazla:
        return (f"{w['admin_ip']} ofisten gelen meşru yönetici: panele normal yoldan girmiş, sayfaları gezmiş. "
                "Yazım hatasından doğan bir iki 401, onlarca denemelik bir brute-force ile aynı şey değildir.")
    mesru = fazla & set(w["mesru"])
    if mesru:
        return (f"{', '.join(sorted(mesru))} normal sayfaları gezen ziyaretçi(ler). Bir `favicon.ico` 404'ü saldırı "
                "göstergesi değildir.")
    eksik = set(beklenen) - verilen
    sa = w["saldirilar"]
    for tur, aciklama in (("sqli", "URL'ye tırnak ve UNION/SELECT koyan"), ("traversal", "URL'ye ../ koyan")):
        if tur in sa and sa[tur]["ip"] in eksik:
            return f"Tarayıcı kullanmadan saldıran biri eksik: {aciklama} bir IP var. `grep -iE` ile imzaları ara."
    return None


def _panel_hata(g, beklenen, b):
    w = b.senaryo["web"]
    if g == str(beklenen)[:5]:
        return "Dakika doğru; saniyeyi de yaz (SS:DD:SS)."
    yol = b.lab / b.senaryo["log_k"] / "access.log"
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for satir in satirlar:
        if f":{g} " in satir:
            if satir.startswith(w["admin_ip"] + " "):
                return "Bu saatteki başarılı giriş ofisteki meşru yöneticiye ait. Brute-force yapan IP'nin girişini ara."
            if '" 401 ' in satir:
                return "Bu saatteki istek 401 almış, yani başarısız bir deneme. Başarılı olan 200 alır."
    return None


def _sizan_hata(g, beklenen, b):
    if g in ("robots.txt", "/robots.txt"):
        return "`robots.txt` herkese açık, zararsız bir dosya. Tarayıcının 200 aldığı hassas dosya başka."
    return None


def _sizan_ip_hata(ip, beklenen, b):
    if ip == b.senaryo["web"]["saldirilar"]["brute"]["ip"]:
        return "Bu IP panele brute-force ile girdi; yedeği indiren tarayıcı başka bir IP'den geliyor olabilir."
    return None


def _ssh_ip_hata(ip, beklenen, b):
    ssh = b.senaryo["ssh"]
    if ssh["brute"] and ip == ssh["brute"]["ip"]:
        return "Bu IP çok parola denedi ama hiç `Accepted` almadı. Başarılı girişi ve ardından gelen `sudo` satırını ara."
    if ip in ssh["mesru"]:
        return "Bu IP `publickey` ile giren meşru yönetici. Saldırgan parolayla (`Accepted password`) girdi."
    return None


def _yeni_hata(g, beklenen, b):
    if g == b.senaryo["ssh"]["ele"]["hesap"].casefold():
        return "Bu, saldırganın girdiği hesap. Root olduktan sonra oluşturduğu yeni hesap başka (`new user`)."
    return None


def _acil_hata(g, beklenen, b):
    verilen = {int(x) for x in g.split() if x.isdigit()}
    for no in sorted(verilen):
        if 1 <= no <= len(b.senaryo["maddeler"]):
            aciklama = b.senaryo["maddeler"][no - 1][1]
            if aciklama:
                return f"{no}. madde: {aciklama}"
    return None


ADIMLAR = [
    Adim("Olay müdahalesi nasıl yürür?", """
Bu bölüm yeni bir şey öğretmiyor; öğrendiklerini birleştirmeni istiyor. Olay müdahalesinin
kabaca dört evresi vardır:

1. **Hazırlık:** loglar tutuluyor mu, kimi arayacağız?
2. **Tespit ve analiz:** ne oldu, ne zaman, kim, nereden? (bugünkü işin)
3. **Sınırlama, temizleme, kurtarma:** saldırganın erişimini kes, izlerini temizle, sistemi
   güvenle geri getir.
4. **Olay sonrası:** ders çıkar, raporu yaz, önlemleri kalıcı yap.

Altın kural: **kanıtı koru.** Logları silme, değiştirme; analizi kopya üzerinde yap.
"""),
    Adim("Önce kopya", """
Analize başlamadan logların bir çalışma kopyasını al. Asıllar kanıttır.
""", komut="mkdir -p calisma && cp <<log_k>>/*.log calisma/ && ls -l calisma"),
    Adim("Genel tablo", """
Her logda kaç satır var? Büyüklük, ne kadar zaman ayıracağını söyler.
""", komut="wc -l <<log_k>>/*.log"),
    Adim("Zaman çizelgesi", """
İlk ve son satır, olayın penceresini verir. Raporda "ne zaman" sorusunun cevabı buradan başlar.
""", komut="head -n 1 <<log_k>>/access.log && tail -n 1 <<log_k>>/access.log"),
    Adim("Cevap kodlarının dağılımı", """
Kaç 200, kaç 401, kaç 404? Normal bir günde 401 ve 404 azdır. Çok sayıda 401 parola denemesi,
çok sayıda 404 bir tarama demektir.
""", komut="cut -d' ' -f9 <<log_k>>/access.log | sort | uniq -c | sort -rn"),
    Adim("auth.log'da kim konuşuyor?", """
auth.log'da her satırın 5. alanı, kaydı yazan programdır: `sshd`, `CRON`, `sudo`... Hangi
programların kayıt bıraktığına bak:
""", komut="awk '{print $5}' <<log_k>>/auth.log | cut -d'[' -f1 | sort | uniq -c | sort -rn", sonra="""
`sshd` ve `CRON` her sunucuda olur. Ama `useradd`, `usermod` ve `passwd`? Bir gün içinde
**yeni bir kullanıcı** eklenmiş, bir gruba alınmış ve parolası belirlenmiş. Bunu kim yaptı?
"""),
    Adim("Rapor", """
Her bulguyu, onu bulduğun komutla birlikte not et. Bir pentester'ın ya da olay müdahalecisinin
müşteriye teslim ettiği tek somut ürün **rapordur**: ne oldu, ne zaman oldu, kanıtlar neler,
etkisi ne, ne yapılmalı? Laboratuvarındaki `rapor_sablonu.md` bu beş soruyu sıralıyor.

Teknik olarak parlak ama kötü anlatılmış bir bulgu, müşterinin gözünde hiç bulunmamış bir
bulgudur.
"""),
]

GOREVLER = [
    Gorev("Web sunucusunun logunda (`access.log`) kaç **farklı** IP adresi görülüyor?",
          Sayi("ip_sayisi", sik_hatalar=_ip_sayisi_hata),
          ("IP her satırın ilk alanı; tekrarları ayıklayıp say.",
           "`cut -d' ' -f1` ile IP'leri al, `sort -u` ile tekrarları at, `wc -l` ile say.",
           "`cut -d' ' -f1 <<log_k>>/access.log | sort -u | wc -l`"),
          puan=25, baslik="Kaç kişi"),
    Gorev("Bu IP'lerden hangileri **saldırgan** gibi davranıyor? Hepsini virgülle ayırarak yaz "
          "(meşru ziyaretçileri ve ofisteki yöneticiyi dahil etme).",
          Kume("saldirganlar", tur="ip", sik_hatalar=_saldirgan_hata, bicim="virgülle ayrılmış IP'ler"),
          ("Her IP'nin ne yaptığına bak: normal sayfalar mı, yoksa parola denemesi, tarama, garip URL'ler mi?",
           "Üç iz ara: çok sayıda 401 (brute-force), tarayıcı User-Agent'ı, URL'de `'`, `UNION`, `../` gibi imzalar.",
           "`grep '\" 401 '` + `uniq -c`; `awk -F'\"' '{print $6}'`; `grep -iE \"union|select|\\.\\./|%27\"` — üçünün IP'lerini birleştir."),
          puan=40, baslik="Kim saldırgan"),
    Gorev("Yönetim paneline (`<<giris>>`) brute-force ile **başarılı** giriş hangi saatte gerçekleşti? (SS:DD:SS)",
          Metin("panel_saat", on_ekleri_at=("saat",), sik_hatalar=_panel_hata, bicim="SS:DD:SS"),
          ("Önce brute-force yapan IP'yi bul: en çok 401 alan.",
           "O IP'nin POST isteklerinden 401 yerine 200 alanı ara.",
           "`grep '^IP ' <<log_k>>/access.log | grep POST | grep '\" 200 '` — köşeli parantezdeki saat."),
          puan=35, baslik="Panel düştü"),
    Gorev("Hassas bilgi içeren bir dosya dışarı sızmış. Hangisi?",
          Metin("sizan", sadece_ad=True, sik_hatalar=_sizan_hata, bicim="dosya yolu"),
          ("Tarayıcının istekleri çoğunlukla 404 alır; 200 alanlara bak.",
           "Tarayıcının satırlarını User-Agent'ından `grep`'le, `grep '\" 200 '` ile süz.",
           "`grep -iE 'nikto|gobuster|fuzz' <<log_k>>/access.log | grep '\" 200 '` — robots.txt dışındaki dosya."),
          puan=30, baslik="Sızan dosya"),
    Gorev("Bu dosya hangi IP adresine gönderildi?",
          IP("sizan_ip", sik_hatalar=_sizan_ip_hata),
          ("Sızan dosyanın satırını bulduysan cevap aynı satırda.",
           "Satırın ilk alanı isteği yapan IP.",
           "`grep '<dosya>' <<log_k>>/access.log | grep '\" 200 ' | cut -d' ' -f1`"),
          puan=20, baslik="Kime"),
    Gorev("SSH tarafında başarılı bir saldırı var: biri parolayla girip `sudo` ile root kabuğu açmış. "
          "Bu kişi hangi IP'den bağlandı?",
          IP("ssh_ip", sik_hatalar=_ssh_ip_hata),
          ("`auth.log`'da root kabuğu açan `sudo` satırını ve ondan hemen önceki başarılı girişi bul.",
           "`grep \"COMMAND=/bin/bash\"` hangi hesabın root olduğunu söyler; o hesabın `Accepted password` satırına bak.",
           "`grep \"Accepted password\" <<log_k>>/auth.log` — `from` sonrası IP."),
          puan=35, baslik="Root'a giden yol"),
    Gorev("Saldırgan root olduktan sonra **kalıcılık** için yeni bir kullanıcı oluşturdu. Adı ne?",
          Metin("yeni_kullanici", sik_hatalar=_yeni_hata, bicim="kullanıcı adı"),
          ("Yeni kullanıcı ekleyen program da auth.log'a yazar.",
           "`useradd` satırlarına bak: `new user: name=...`",
           "`grep \"new user\" <<log_k>>/auth.log` — `name=` sonrası, virgüle kadar."),
          puan=30, baslik="Arka kapı hesabı"),
    Gorev("`oneri_taslagi.txt` Mert'in taslak eylem listesi. Yöneticiye önereceğin **en acil üç** adımın "
          "numaralarını yaz (virgülle ayır).",
          Kume("acil", tur="sayi", sik_hatalar=_acil_hata, bicim="üç madde numarası, örn. 1,4,6"),
          ("Önce erişimi kes, sonra sızıntının kaynağını kapat, sonra sunucuya güvenmeyi bırak.",
           "Kanıtı yok eden, yasa dışı olan ya da olayı gizleyen maddeler acil değil, zararlıdır.",
           "Parolaları değiştirmek + sızan dosyayı kaldırmak + sunucuyu ele geçirilmiş sayıp incelemek."),
          puan=30, baslik="Acil üç adım"),
    Gorev("Son olarak kısa bir **olay raporu** yaz: ne oldu, ne zaman oldu, kanıtlar neler, etkisi ne, "
          "ne yapılmalı? (`rapor_sablonu.md` yol gösterir; cevabı tırnak içinde yaz.)",
          Serbest("""
**<<tarih>> — <<musteri>> (<<sunucu>>) olay raporu**

- **Ne oldu?** <<tarama_ip>> adresi <<tarayici>> ile web sunucusunu taradı ve saat <<sizma_saat>>'te
  `<<sizan>>` dosyasını 200 koduyla indirdi; dosyada veritabanı bağlantı bilgileri (parola) vardı.
  <<brute_ip>> adresi `<<giris>>` sayfasına <<brute_deneme>> başarısız denemeden sonra <<panel_saat>>'te
  giriş yaptı. SSH'ta <<ssh_ip>> adresi `<<hesap>>` hesabına parolayla girdi (<<ssh_saat>>), <<root_saat>>'te
  `sudo` ile root kabuğu açtı ve kalıcılık için `<<yeni>>` kullanıcısını oluşturup sudo grubuna ekledi.
  <<ek_saldirilar>> <<ayni_aktor>>
- **Kanıtlar:** access.log'daki 401 dizisi ve ardından gelen 200; tarayıcı User-Agent'lı satırlar;
  auth.log'daki `Accepted password`, `COMMAND=/bin/bash`, `useradd` ve `usermod` satırları.
- **Etki:** Sunucu tam olarak ele geçirilmiş kabul edilmeli; <<hassas>> risk altında.
- **Ne yapılmalı?** Bütün parolaları değiştir, saldırgan IP'lerini engelle, yedek dosyayı web kökünden
  kaldır, `<<yeni>>` hesabını ve diğer kalıcılık izlerini incele, sunucuyu temiz yedekten yeniden kur;
  SSH'ta parola girişini kapatıp yalnızca anahtarla girişe izin ver.
""", min_kelime=30),
          ("Rapor beş soruya cevap verir; şablon dosyası bunları sıralıyor.",
           "Bulduğun her şeyi zaman sırasına koy: tarama, sızıntı, panel girişi, SSH girişi, root, yeni kullanıcı.",
           "Her cümlede bir kanıt (IP, saat, dosya, log satırı) olsun; sonunda acil önlemleri yaz."),
          puan=40, baslik="Olay raporu"),
]


SEVIYE = Seviye(
    kimlik="c01b07",
    cilt=1,
    bolum=7,
    baslik="Kapanış Görevi: Küçük Bir Olay Müdahalesi",
    brifing="""
Akşam altıya geliyor, telefon çalıyor. **<<musteri>>**'den <<kisi>>, sesi gergin: "<<tarih>>
günü sunucuda bir şeyler oldu, emin değilim. <<hikaye>> Web ve SSH loglarını size gönderdim.
Neler olduğunu anlatabilir misiniz?"

Selin telefonu kapatıp sana dönüyor: "Bu sefer adım adım yönlendirmeyeceğim. Cilt 1'de
öğrendiğin her şey elinin altında. Deniz yanında, ama klavye sende."

Deniz sandalyesini yaklaştırıyor: "Önce kopya al. Sonra kim, ne zaman, nereden. Mert de bir
eylem listesi taslağı yazdı; ona da göz at, ama her yazdığına güvenme."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bir saldırı nadiren tek adımdır: tarama bir yedeği bulur, yedekteki parola bir kapıyı açar,
açılan kapıdan root'a, root'tan kalıcılığa gidilir. Saldırgan her adımda iz bırakır; bu
cildin araçlarıyla (`grep`, `cut | sort | uniq -c`, `awk`) o izleri zaman sırasına dizebilirsin.
Savunma tarafının dersi de zincirin her halkasında: web kökünde yedek bırakma, panele hız
sınırı koy, SSH'ta parola yerine anahtar kullan, `sudo` ve yeni kullanıcı olaylarına alarm
kur ve olay anında **kanıtı koru**.
""",
    gercek_hayat="""
- **Equifax (2017):** Saldırganlar, yamalanmamış bir Apache Struts açığı üzerinden girdi ve
  sistemlerde aylarca fark edilmeden kaldı; yaklaşık 147 milyon kişinin kişisel verisi etkilendi.
  Olay, "yama yönetimi" kadar "loglara bakan ve anormalliği zamanında gören biri" eksikliğinin de
  örneği olarak anlatılır.
- **NIST SP 800-61:** ABD standart kurumu NIST'in olay müdahalesi rehberinin 2012'de yayımlanan
  2. sürümü, bu bölümdeki dört evreyi (hazırlık; tespit ve analiz; sınırlama, temizleme ve
  kurtarma; olay sonrası faaliyetler) tanımlar. Bu döngü uzun yıllardır pek çok kurumun olay
  müdahale planının temelidir.
- **Kanıtın korunması:** Olay müdahalesi rehberleri, logları silmenin ya da sistemi incelemeden
  yeniden kurmanın, neyin sızdığını ve saldırganın nasıl girdiğini öğrenmeyi imkânsız
  kılabileceği konusunda uyarır. Önce kopya, sonra analiz.
""",
    sure_hedef_dk=45,
)
