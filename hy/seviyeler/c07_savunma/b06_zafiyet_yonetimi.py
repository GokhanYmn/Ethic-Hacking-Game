"""Cilt 7 · Bölüm 6 — Zafiyet Yönetimi ve Yama.

Beceri: varlık envanteri ile zafiyet listesini birleştirip CVSS'yi bağlamla (internete açıklık ×
kritiklik) önceliklendirmek ve bir yama planı yazmak (acil / 30 gün / rutin).

Dikkat: bütün CVE kimlikleri (`CVE-2026-7xxx`) ve ürün adları **kurgusaldır**; gerçek bir zafiyeti
ya da ürünü göstermez. Açıklamalar yalnızca zafiyet sınıfını anlatır, saldırı yükü içermez.

Vakalar: e-ticaret, hastane, belediye; her vakada varlıklar, açıklık durumları ve zafiyetler farklıdır.
Her tohumda "en yüksek CVSS" ile "en acil" zafiyet farklı sistemlerdedir (CVSS tek başına yetmez).
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Secmeli, Sonuc, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import ascii_norm, sec_doldur, sh

SINIFLAR = ["Kimlik doğrulama atlatma", "Uzaktan kod çalıştırma", "Bilgi ifşası", "Hizmet reddi", "Yetki yükseltme",
            "Yol (dizin) geçişi", "Yanlış yetkilendirme"]
CVSS_HAVUZ = [4.3, 5.3, 5.9, 6.5, 7.2, 7.5, 8.1, 8.8, 9.1]

# host, rol, ürün (kurgusal), internete açık (True/False/None=rastgele), kritiklik, sahibi
VAKALAR = [
    {
        "ad": "Pazarix — e-ticaret altyapısı", "musteri": "Pazarix", "kod": "pazarix",
        "hostlar": [
            ("pzx-web01", "ana web sitesi", "WebPortal Pro 4.2", True, 4, "web ekibi"),
            ("pzx-api01", "mobil uygulama API", "ApiKapi 2.8", True, 4, "mobil ekip"),
            ("pzx-odeme-db", "ödeme veritabanı", "SQL-Motor 8.0", False, 5, "veri ekibi"),
            ("pzx-admin", "yönetim paneli", "PanelYonet 3.1", None, 3, "web ekibi"),
            ("pzx-mail01", "e-posta sunucusu", "PostaSun 6.4", True, 2, "BT"),
            ("pzx-test", "test ortamı", "WebPortal Pro 4.0", None, 1, "web ekibi"),
            ("pzx-yedek", "yedek dosya sunucusu", "DosyaHub 2.1", False, 3, "BT"),
        ],
        "sahne": "Kampanya haftası öncesi Pazarix, 'hangi açıkları önce kapatalım?' diye soruyor.",
    },
    {
        "ad": "Medora Sağlık — hastane ağı", "musteri": "Medora Sağlık", "kod": "medora",
        "hostlar": [
            ("medora-portal", "hasta portalı", "RandevuNet 5.0", True, 4, "bilgi işlem"),
            ("medora-randevu-db", "randevu veritabanı", "SQL-Motor 8.0", False, 5, "veri ekibi"),
            ("medora-goruntu", "tıbbi görüntü arşivi", "GoruntuArsiv 3.3", False, 5, "radyoloji BT"),
            ("medora-vpn", "uzaktan erişim geçidi", "VPNGecit 5.3", True, 4, "ağ ekibi"),
            ("medora-yazici", "yazıcı yönetimi", "YazdirYonet 1.9", False, 1, "BT"),
            ("medora-wifi", "misafir Wi-Fi denetleyicisi", "AgYonetici 7.2", True, 1, "ağ ekibi"),
            ("medora-dizin", "personel dizin sunucusu", "DizinSun 10.1", None, 4, "bilgi işlem"),
        ],
        "sahne": "KVKK denetimi öncesi Medora, açık zafiyetlerin önceliklendirilmesini ve bir yama takvimi istiyor.",
    },
    {
        "ad": "Yeşiltepe Belediyesi — e-hizmet ortamı", "musteri": "Yeşiltepe Belediyesi", "kod": "yesiltepe",
        "hostlar": [
            ("ytb-ebelediye", "e-belediye portalı", "EvrakPortal 4.6", True, 4, "bilgi işlem"),
            ("ytb-evrak", "evrak takip sistemi", "EvrakTakip 2.2", None, 3, "yazı işleri"),
            ("ytb-borc-db", "vergi ve borç veritabanı", "SQL-Motor 8.0", False, 5, "mali hizmetler"),
            ("ytb-wifi", "kent Wi-Fi denetleyicisi", "AgYonetici 7.0", True, 2, "ağ ekibi"),
            ("ytb-kamera", "güvenlik kamera kayıtçısı", "KameraKayit 3.5", None, 3, "güvenlik"),
            ("ytb-dosya", "dosya sunucusu", "DosyaHub 2.0", False, 3, "bilgi işlem"),
            ("ytb-meclis", "meclis yayın sitesi", "WebPortal Pro 3.9", True, 2, "basın"),
        ],
        "sahne": "Bilgi işlem müdürü yıllık bütçe için 'hangisi acil, hangisi bekleyebilir?' listesi istiyor.",
    },
]


def _puan10(cvss: float, krit: int, acik: bool) -> int:
    return int(round(cvss * 10)) * krit * (2 if acik else 1)


def _sinif(p10: int) -> str:
    return "acil" if p10 >= 600 else "30gun" if p10 >= 300 else "rutin"


def uret(rng):
    v = rng.choice(VAKALAR)
    for _ in range(500):
        hostlar = []
        for host, rol, urun, acik, krit, sahip in v["hostlar"]:
            a = rng.random() < 0.5 if acik is None else acik
            hostlar.append({"host": host, "rol": rol, "urun": urun, "acik": a, "krit": krit, "sahip": sahip})
        ic = [h for h in hostlar if not h["acik"] and h["krit"] >= 5]
        dis = [h for h in hostlar if h["acik"] and h["krit"] >= 4]
        if not ic or not dis:
            continue
        h_ic, h_dis = rng.choice(ic), rng.choice(dis)
        bulgular = []
        for h in hostlar:
            adet = 1 if h in (h_ic, h_dis) else rng.randint(1, 2)
            for _ in range(adet):
                if h is h_ic:
                    cvss = 9.8
                elif h is h_dis:
                    cvss = rng.choice([7.5, 8.1, 8.8])
                else:
                    cvss = rng.choice(CVSS_HAVUZ)
                bulgular.append({"host": h["host"], "cvss": cvss, "yama": rng.random() < 0.8,
                                 "sinif": rng.choice(SINIFLAR), "urun": h["urun"]})
        ids = u.benzersiz(rng, lambda r: f"CVE-2026-{r.randint(7000, 7999)}", len(bulgular))
        for b, c in zip(bulgular, ids):
            b["cve"] = c
        rng.shuffle(bulgular)
        by = {h["host"]: h for h in hostlar}
        for b in bulgular:
            b["p10"] = _puan10(b["cvss"], by[b["host"]]["krit"], by[b["host"]]["acik"])
        cv = sorted(bulgular, key=lambda b: -b["cvss"])
        pu = sorted(bulgular, key=lambda b: -b["p10"])
        if cv[0]["cvss"] == cv[1]["cvss"] or pu[0]["p10"] == pu[1]["p10"] or cv[0]["cve"] == pu[0]["cve"]:
            continue
        if by[cv[0]["host"]]["acik"] or not by[pu[0]["host"]]["acik"]:
            continue
        if any(abs(b["p10"] - 300) < 5 or abs(b["p10"] - 600) < 5 for b in bulgular):
            continue
        if not any(b["p10"] >= 600 for b in bulgular) or not any(b["p10"] < 300 for b in bulgular):
            continue
        break
    else:
        raise RuntimeError("Uygun zafiyet seti üretilemedi")
    acik_adet = sum(1 for h in hostlar if h["acik"])
    hizli = sum(1 for b in bulgular if b["yama"] and by[b["host"]]["acik"])
    return {
        "vaka": v["ad"], "v": v, "hostlar": hostlar, "bulgular": bulgular, "en_cvss": cv[0], "en_acil": pu[0],
        "metin": {"musteri": v["musteri"], "sahne": v["sahne"]},
        "cevaplar": {
            "acik_adet": acik_adet, "en_cvss": cv[0]["cve"], "en_acil": pu[0]["cve"],
            "acil": sorted(b["cve"] for b in bulgular if b["p10"] >= 600), "hizli": hizli,
            "plan": {b["cve"]: _sinif(b["p10"]) for b in bulgular},
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "varlik_envanteri.csv", "host;rol;internete_acik;kritiklik;sahibi\n" + "\n".join(
        f"{h['host']};{h['rol']};{'evet' if h['acik'] else 'hayir'};{h['krit']};{h['sahip']}" for h in s["hostlar"]) + "\n")
    u.yaz(lab / "zafiyetler.csv",
          "# KURGUSAL: bu CVE kimlikleri ve ürünler gerçek değildir (egzersiz verisi).\n"
          "cve;host;urun;cvss;sinif;yama_var\n" + "\n".join(
              f"{b['cve']};{b['host']};{b['urun']};{b['cvss']};{b['sinif']};{'evet' if b['yama'] else 'hayir'}"
              for b in s["bulgular"]) + "\n")
    u.yaz(lab / "oncelik_kurali.txt",
          "ÖNCELİK KURALI (şirket politikası)\n"
          "puan  = CVSS x kritiklik (1-5) x yayın çarpanı\n"
          "yayın çarpanı: internete açıksa 2, değilse 1\n\n"
          "sınıf : puan >= 60        -> acil   (7 gün içinde)\n"
          "        30 <= puan < 60   -> 30gun  (30 gün içinde)\n"
          "        puan < 30         -> rutin  (90 gün, normal bakım penceresinde)\n"
          "Not: yaması henüz olmayan zafiyetin sınıfı yine puana göre belirlenir; yama çıkana kadar geçici önlem "
          "(erişimi kısıtla, servisi kapat) uygulanır.\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['musteri']} zafiyet yönetimi klasörü (KURGUSAL). Tarama çıktısı zafiyetler.csv, envanter varlik_envanteri.csv.\n"
          "Selin'den not: puan hesaplamadan önce her zafiyetin hangi makinede olduğuna ve o makinenin ne işe yaradığına bak.\n"
          "Yama planını yama_plani.txt olarak bu klasöre yaz: satır başına `CVE-2026-XXXX sınıf`.\n")


def _plan_kontrol(b) -> Sonuc:
    yol = None
    for d in (b.calisma_dizini, b.lab):
        if d and (Path(d) / "yama_plani.txt").is_file():
            yol = Path(d) / "yama_plani.txt"
            break
    if yol is None:
        return Sonuc(False, "`yama_plani.txt` bulunamadı. Lab klasöründe oluştur; her satır: `CVE-2026-7xxx acil` gibi.")
    beklenen = b.senaryo["cevaplar"]["plan"]
    verilen = {}
    for ham in yol.read_text(errors="replace").splitlines():
        m = re.match(r"^\s*(CVE-\d{4}-\d{4,})\W+(.+?)\s*$", ham, re.I)
        if m:
            verilen[m.group(1).upper()] = re.sub(r"[\s_\-]+", "", ascii_norm(m.group(2)))
    if not verilen:
        return Sonuc(False, "Dosyada `CVE-2026-7xxx acil` biçiminde satır bulamadım.")
    eksik = [c for c in beklenen if c not in verilen]
    if eksik:
        return Sonuc(False, f"{len(beklenen)} zafiyetin hepsi planda olmalı; eksik: {eksik[0]} (ve {len(eksik) - 1} tane daha).", yakin=True)
    yanlis = [c for c in beklenen if verilen[c] != beklenen[c]]
    if yanlis:
        return Sonuc(False, f"{len(yanlis)} satırın sınıfı yanlış, örneğin {sorted(yanlis)[0]}. Puanı hesaplarken internete açıklık "
                            "ve kritiklik çarpanlarını kullandın mı? Sınırlar 60 ve 30.", yakin=len(yanlis) < len(beklenen))
    return Sonuc(True, "Plan, kurala göre doğru.")


def _en_acil_hata(g, beklenen, b):
    if g == b.senaryo["en_cvss"]["cve"].lower():
        return ("Bu, en yüksek CVSS'li zafiyet; ama o sistem internete kapalı. Puan = CVSS x kritiklik x yayın çarpanı: "
                "bağlamı hesaba kat.")
    return None


def _acik_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == len(b.senaryo["hostlar"]):
        return "Bütün varlıkları saymışsın. Sadece `internete_acik` sütunu `evet` olanlar."
    return None


def _hizli_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    acik = sum(1 for x in b.senaryo["bulgular"] if b.senaryo["hostlar"] and
               next(h for h in b.senaryo["hostlar"] if h["host"] == x["host"])["acik"])
    if n == acik:
        return "Yaması olmayanları da saymışsın. Yaması mevcut olanları say (`yama_var` = evet)."
    return None


def coz(lab: Path, s: dict) -> dict:
    acik = sh("awk -F';' 'NR>1 && $3==\"evet\"' varlik_envanteri.csv | wc -l", lab)
    en_cvss = sh("grep -v '^#' zafiyetler.csv | tail -n +2 | sort -t';' -k4,4 -rn | head -1 | cut -d';' -f1", lab)
    puanlama = ("awk -F';' 'NR==FNR { if (FNR>1) {a[$1]=($3==\"evet\")?2:1; k[$1]=$4}; next } "
                "!/^#/ && FNR>2 { printf \"%.1f %s %s %s\\n\", $4*k[$2]*a[$2], $1, $2, $6 }' varlik_envanteri.csv zafiyetler.csv")
    en_acil = sh(f"{puanlama} | sort -rn | head -1 | awk '{{print $2}}'", lab)
    acil = sh(f"{puanlama} | awk '$1>=60 {{print $2}}'", lab).split()
    hizli = sh("awk -F';' 'NR==FNR { if (FNR>1 && $3==\"evet\") o[$1]=1; next } !/^#/ && FNR>2 && o[$2] && $6==\"evet\"' "
               "varlik_envanteri.csv zafiyetler.csv | wc -l", lab)
    sh(f"{puanlama} | awk '{{s=($1>=60)?\"acil\":($1>=30)?\"30gun\":\"rutin\"; print $2, s}}' > yama_plani.txt", lab)
    return sec_doldur({1: acik, 2: en_cvss, 3: en_acil, 4: " ".join(acil), 5: hizli, 6: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Döngü: tara, önceliklendir, yamala, doğrula", """
Saldırıların büyük çoğunluğu, **bilinen ve yaması çıkmış** zafiyetleri kullanır. **Zafiyet yönetimi** bu
açıkları saldırgandan önce bulup kapatma sürecidir ve çoğu ihlali önleyen, en az "havalı" ama en etkili
savunmadır. Sürekli bir döngü: **tara** (bilinen açıkları bul), **önceliklendir**, **yama/düzelt**,
**doğrula** (gerçekten kapandı mı?) ve **tekrarla**; çünkü her gün yeni zafiyet açıklanır.

<<sahne>> Elimizde şirketin önceliklendirme politikası var:
""", komut="cat oncelik_kurali.txt"),
    Adim("Önce envanter: neyin var?", """
Sahip olduğunu bilmediğin şeyi yamalayamazsın. **Varlık envanteri** her sistemin ne işe yaradığını,
**internete açık olup olmadığını** ve ne kadar kritik olduğunu (1-5) söyler:
""", komut="cat varlik_envanteri.csv", sonra="""
Aynı zafiyet, internete açık bir portalda ile iç ağdaki bir yedek sunucuda çok farklı risk taşır.
Zafiyet taraması 'ne var' sorusunu, envanter 'ne kadar önemli' sorusunu cevaplar.
"""),
    Adim("Tarama çıktısı", """
Zafiyet tarayıcıları (OpenVAS/Greenbone, Nessus gibi) bilinen zafiyetleri otomatik bulur ve bir CVSS
skoru (0-10) verir. Aşağıdaki çıktı **kurgusaldır**; CVE kimlikleri ve ürünler gerçek değildir:
""", komut="cat zafiyetler.csv"),
    Adim("Sadece CVSS'ye göre sıralamak", """
En kolay yol, CVSS'ye göre sıralamaktır. `sort -t';' -k4,4 -rn` dördüncü sütuna göre sayısal ve
tersten sıralar. Başlık ve yorum satırlarını atmak için `grep -v '^#'` kullanıyoruz:
""", komut="grep -v '^#' zafiyetler.csv | sort -t';' -k4,4 -rn | head -3", sonra="""
En üstteki, en yüksek CVSS'li zafiyet. Ama CVSS **teknik** kritikliği ölçer; hangi sistemde olduğunu,
internete açık olup olmadığını, hangi veriyi tuttuğunu bilmez. Bağlamsız sıralama yanlış yere
mesai harcatır.
"""),
    Adim("Bağlam: puan hesaplamak", """
Politikaya göre puan = CVSS x kritiklik x yayın çarpanı. İki dosyayı birleştirmek için `awk`
önce envanteri hafızaya alır (`NR==FNR`), sonra zafiyetleri okurken host'a göre bilgiyi eşler:
""", komut="awk -F';' 'NR==FNR { if (FNR>1) {a[$1]=($3==\"evet\")?2:1; k[$1]=$4}; next } !/^#/ && FNR>2 { printf \"%.1f %s %s\\n\", $4*k[$2]*a[$2], $1, $2 }' varlik_envanteri.csv zafiyetler.csv | sort -rn | head -5", sonra="""
Sıralama değişti: üstteki, CVSS'si en yüksek olan olmayabilir. İnternete açık, kritik bir sistemde
orta-yüksek bir zafiyet, iç ağdaki zor erişilen daha yüksek skorlu bir zafiyetten daha acildir. Bu
bağlamdır. Aynı çıktıyı `awk '$1>=60'` ile süzersen **acil** sınıfı bulursun.
"""),
    Adim("Yama planı ve 'yama yok' durumu", """
Önceliklendirmenin sonucu bir **plan**dır: kim, neyi, ne zamana kadar? Acil olanlar günler içinde,
diğerleri bakım penceresinde. Bazen yama henüz çıkmamıştır; o zaman **geçici önlem** uygularsın:
erişimi kısıtla, servisi kapat, iç ağa al. Plan yapılınca bir de **doğrulama** gerekir: yamadan
sonra yeniden tara, zafiyet gerçekten kapandı mı?

Görevde planı bir dosyaya yazacaksın: her satır `CVE-2026-7xxx sınıf` biçiminde olsun; sınıf `acil`,
`30gun` ya da `rutin`. `awk` çıktısını `>` ile bir dosyaya yönlendirmek yeterli.
"""),
    Adim("Hacker gözüyle: saldırganın listesi", """
**Hacker gözüyle:** Cilt 4 ve 6'daki "sürüm, CVE, exploit" zincirini hatırla. Zafiyet yönetimi bu zinciri
**saldırgandan önce kendin çalıştırmaktır**: kendi sistemlerini tarar, saldırganın bulacağı açığı önce
sen bulursun. Pentest ile zafiyet taraması farklıdır ama tamamlayıcıdır: tarama bilinen açıkların geniş
listesini otomatik verir (kapsam), pentest ise bir insanın yaratıcılığıyla bunları zincirleyip gerçek
etkiyi gösterir (derinlik). Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`varlik_envanteri.csv` içinde **internete açık** kaç varlık var?",
          Sayi("acik_adet", sik_hatalar=_acik_hata),
          ("Envanterde `internete_acik` adlı bir sütun var.",
           "Başlık satırını atlayıp üçüncü sütunu `evet` olan satırları say.",
           "`awk -F';' 'NR>1 && $3==\"evet\"' varlik_envanteri.csv | wc -l`"),
          puan=20, baslik="İnternete açık varlıklar"),
    Gorev("**En yüksek CVSS** skoruna sahip zafiyetin kimliğini (CVE-2026-...) yaz.",
          Metin("en_cvss", bicim="CVE-2026-xxxx"),
          ("CVSS dördüncü sütunda; en yüksek olanı bul.",
           "Yorum (`#`) ve başlık satırlarını atarak sütuna göre sayısal ve tersten sırala.",
           "`grep -v '^#' zafiyetler.csv | tail -n +2 | sort -t';' -k4,4 -rn | head -1`; ilk sütun kimliktir."),
          puan=20, baslik="En yüksek CVSS"),
    Gorev("Şirket politikasına göre (puan = CVSS x kritiklik x yayın çarpanı) **en acil** zafiyetin kimliğini yaz.",
          Metin("en_acil", sik_hatalar=_en_acil_hata, bicim="CVE-2026-xxxx"),
          ("Sadece CVSS'ye bakma; hangi makinede olduğu ve o makinenin özellikleri önemli.",
           "Her zafiyetin host'unu envanterle eşleştirip kritiklik ve internete açıklığı çarpana kat; en yüksek puanlıyı seç.",
           "Eğitimdeki `awk` birleştirme komutunu çalıştır ve `sort -rn | head -1`; satırdaki ikinci sütun kimliktir."),
          puan=50, baslik="Bağlamla en acil"),
    Gorev("Puanı **60 ve üzeri** olan (`acil` sınıfı) bütün zafiyetlerin kimliklerini yaz (virgül ya da boşlukla).",
          Kume("acil", bicim="CVE kimlikleri, virgülle ayrılmış"),
          ("Önce her zafiyetin puanını hesaplaman gerek; sonra eşiği uygula.",
           "Eğitimdeki `awk` komutu puanı ilk sütunda yazar; `awk '$1>=60'` ile süz.",
           "`... | awk '$1>=60 {print $2}'` acil olanların kimliklerini yazar."),
          puan=50, baslik="Acil sınıf"),
    Gorev("**İnternete açık** sistemlerdeki zafiyetlerden kaçının **yaması mevcut** (`yama_var` = evet)? "
          "Bunlar en hızlı kazanılan işlerdir.",
          Sayi("hizli", sik_hatalar=_hizli_hata),
          ("İki şart birden: sistem internete açık ve yama var.",
           "Önce internete açık host'ları belirle, sonra zafiyetler.csv'de o host'lardaki, son sütunu `evet` olan satırları say.",
           "Açık host'ların adlarını `awk` ile hafızaya al, zafiyet satırlarında host'u ve `$6==\"evet\"` koşulunu birlikte ara."),
          puan=40, baslik="Hızlı kazanç"),
    Gorev("Politikaya göre bir **yama planı** yaz: lab klasöründe `yama_plani.txt` dosyası oluştur; her zafiyet için bir "
          "satır `CVE-2026-xxxx sınıf` (sınıf: `acil`, `30gun` ya da `rutin`). Bitince `cevap 6`.",
          Durum(_plan_kontrol, "yama_plani.txt: her CVE için puana göre acil / 30gun / rutin"),
          ("Önce her zafiyetin puanını bul, sonra sınıfı belirle; sonuçları bir dosyaya yaz.",
           "Eğitimdeki `awk` komutunu genişlet: puana göre `acil`, `30gun`, `rutin` yazdır ve `> yama_plani.txt` ile dosyaya yönlendir.",
           "`... | awk '{s=($1>=60)?\"acil\":($1>=30)?\"30gun\":\"rutin\"; print $2, s}' > yama_plani.txt`"),
          puan=70, baslik="Yama planı"),
    Gorev("CVSS skoru neden **tek başına** önceliklendirme için yeterli değildir?",
          Secmeli([
              ("Skor teknik kritikliği ölçer; sistemin internete açık olup olmadığını ve taşıdığı veriyi bilmez",
               "Doğru. Bağlam (açıklık, istismar kolaylığı, veri önemi) olmadan skor öncelik belirlemez."),
              ("CVSS puanları her gün değiştiği için hiçbir zaman güvenilir bir sayı vermez",
               "Yanlış. Skor, zafiyet açıklanınca belirlenir; sorun kararlılığı değil, bağlamsızlığıdır."),
              ("CVSS yalnızca eski sistemler için tanımlıdır, yeni ürünlerde skor üretilemez",
               "Yanlış. CVSS her tür ürün için kullanılır; eksik olan, ortam bağlamıdır."),
              ("Skor yüksekse yama zaten otomatik yüklenir, bu yüzden ek bir karar gerekmez",
               "Yanlış. Yamayı sen planlar ve uygularsın; öncelik kararı senin bağlam bilgine bağlıdır."),
          ], dogru=0),
          ("Aynı skor iki farklı sistemde aynı risk midir?",
           "Skor 'zafiyet ne kadar kötü' der; 'bu sistem ne kadar önemli ve ne kadar erişilebilir' demez.",
           "Doğru cevap, bağlamın (açıklık, kritiklik, veri) skorda olmadığını söylüyor."),
          puan=20, baslik="CVSS ve bağlam"),
    Gorev("Zafiyet yönetimi döngüsünün doğru sıralaması hangisidir?",
          Secmeli([
              ("Tara, önceliklendir, yamala/düzelt, doğrula, tekrarla",
               "Doğru. Döngü hiç bitmez, çünkü her gün yeni zafiyet açıklanır."),
              ("Yamala, tara, önceliklendir, doğrula, sonlandır",
               "Yanlış. Neyi yamalayacağını bilmeden yamalamak olmaz; ve döngü sonlanmaz."),
              ("Önceliklendir, doğrula, tara, yamala, sonlandır",
               "Yanlış. Önce neyin açık olduğunu taramadan öncelik ve doğrulama yapılamaz."),
              ("Tara, yamala, sonlandır; önceliklendirme yalnızca büyük firmalara özgüdür",
               "Yanlış. Her ölçekte kaynaklar sınırlıdır; önceliklendirme küçük ekipte daha da önemlidir."),
          ], dogru=0),
          ("Neyi yamalayacağını bilmen için önce ne yapmalısın?",
           "Yamadan sonra gerçekten kapandığını nasıl bilirsin?",
           "Tara, önceliklendir, yama, doğrula, tekrarla: sürekli bir döngü."),
          puan=20, baslik="Döngü"),
    Gorev("Zafiyet taraması ile pentest arasındaki fark nedir ve neden ikisi de gerekir?",
          Secmeli([
              ("Tarama bilinen açıkların geniş listesini otomatik verir (kapsam); pentest açıkları zincirleyip gerçek etkiyi gösterir (derinlik)",
               "Doğru. Tarama kapsam, pentest derinlik sağlar; biri diğerinin yerini tutmaz."),
              ("Pentest yalnızca otomatik çalışır ve daha ucuzdur; tarama ise yalnızca elle yapılır",
               "Yanlış. Tam tersi: tarama otomatiktir, pentest bir insanın yaratıcılığına dayanır."),
              ("İkisi aynı işi yapar; yalnızca raporun rengi ve şirketin adı farklıdır",
               "Yanlış. Yöntem, derinlik ve çıktı farklıdır; zincirleme ve gerçek etki gösterimi pentestin işidir."),
              ("Tarama yalnızca saldırgan tarafında kullanılır; savunmacı için pentest yeterlidir",
               "Yanlış. Tarama savunmacının sürekli yaptığı bir iştir; pentest düzenli aralıklarla tamamlar."),
          ], dogru=0),
          ("Biri 'geniş ve otomatik', diğeri 'derin ve insanla' çalışır.",
           "Bir tarama aracı iki zafiyeti birbirine bağlayıp gerçek etkiyi gösterebilir mi?",
           "Tarama = kapsam, pentest = derinlik. Doğru cevap bu ikisini söylüyor."),
          puan=20, baslik="Tarama ve pentest"),
]


def _kapanis():
    return """
Tablo değişti: en yüksek CVSS'li zafiyet iç ağdaki bir veritabanındaydı, ama en acil olanı internete
açık bir sistemdeki daha düşük skorluydu. Saldırgan da böyle düşünür: dışarıdan erişebildiği,
yamasız ve iş açısından değerli ilk sistemi seçer. Savunma dersi: envanterini bil, CVSS'yi bağlamla
çarp, internete açık ve yaması hazır olanları hemen kapat, yama çıkmamış açıklar için geçici önlem
(erişimi kısıtla) uygula ve yamadan sonra gerçekten kapandığını yeniden tarayarak doğrula.
"""


SEVIYE = Seviye(
    kimlik="c07b06",
    cilt=7,
    bolum=6,
    baslik="Zafiyet Yönetimi ve Yama",
    brifing="""
Selin Aksoy bir CSV dosyasıyla geliyor: "**<<musteri>>** için zafiyet taraması bitti. <<sahne>> Karşında
iki dosya var: varlık envanteri ve tarama çıktısı. **Bütün CVE kimlikleri kurgusaldır**, gerçek bir
ürünü göstermez."

Deniz ekliyor: "Tarama çıktısı skor sıralı geliyor ve herkes en üstteki zafiyete koşuyor. Sen bağlama
bak: o makine internete açık mı, ne kadar kritik? Sonra bir yama planı yaz; hangisi 7 günde, hangisi 30
günde, hangisi rutin bakımda?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Equifax 2017:** Kamuya açık anlatıma göre, saldırıda kullanılan Apache Struts zafiyetinin yaması
  haftalar önce yayımlanmıştı ve şirket, etkilenen sistemi yamalamamış ya da taramalar onu
  yakalamamıştı. Bu bölümdeki döngü (tara, önceliklendir, yamala, **doğrula**) tam bu boşluğu kapatmak içindir.
- **WannaCry 2017:** Saldırının kullandığı Windows zafiyeti için üretici yamasını, saldırıdan haftalar
  önce yayımlamıştı; yamasız kalan sistemler etkilendi. İnternete açık ve yaması mevcut sistemler
  (bölümdeki "hızlı kazanç") önceliğin en başındadır.
- **Log4Shell 2021:** Pek çok kurum için en büyük sorun, Log4j kütüphanesinin **nerelerde
  kullanıldığını bilmemekti**. Güncel bir varlık ve yazılım envanteri, yama önceliklendirmesinin
  ön koşuludur; "neyin var?" sorusunu cevaplayamayan "neyi yamalayacağım?" sorusunu da cevaplayamaz.
""",
    sure_hedef_dk=40,
)
