"""Cilt 7 · Bölüm 9 — Kimlik Merkezli Saldırılar: Kırmak Yerine Giriş Yapmak.

TAMAMEN SAVUNMACI/ADLİ: oyuncu, saldırıya uğrayan kurumun analistidir. Gerçek zararlı, gerçek çerez
ya da gerçek hesap yoktur; her şey kurgusal, dosya-tabanlı sahte veridir. İki dosya gelir:
`girisler.csv` (kimlik sağlayıcının giriş dökümü) ve `uc_nokta.log` (uç nokta güvenlik kaydı).

Bu bölümde TEK veri setinde üç ayrı iz birlikte gömülüdür (öğretici olsun diye ayrı ayrı kullanıcılarda):
- imkânsız seyahat + oturum çalma (kullanıcı A): aynı `oturum_id` iki ayrı IP'den,
- MFA yorgunluğu (kullanıcı B): art arda onay istekleri, sonunda "onaylandı",
- altta infostealer (bilgi çalan zararlı) izi: uç nokta kaydında veri sızdırma satırı.
Ayrıca gürültü: makul seyahat (C) ve kullanıcı tekrar denemesi (E) saldırı değildir.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem `yaz`
aynı `_akis(alt)` ile veriyi yeniden üretir (`_tohum` motor tarafından ezildiği için ayrı anahtar).

Bu modüldeki genel yardımcılar (kullanicilar, profiller, normal_trafik, uc_gurultu, zararli_satirlari...)
`hy.olay_masasi.olay_kimlik` tarafından da kullanılır.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

# ----------------------------------------------------------------------------- ortak yardımcılar

SOYADLAR = ["kaya", "demir", "sahin", "celik", "yildiz", "aydin", "ozturk", "arslan", "dogan", "kilic",
            "aslan", "cetin", "koc", "kurt", "ozkan", "polat", "tekin", "bulut", "gunes", "aksoy"]
EV_SEHIR = ["İstanbul", "Ankara", "İzmir", "Bursa", "Antalya", "Konya", "Adana", "Kocaeli"]
UZAK_SEHIR = ["Frankfurt", "Singapur", "Lagos", "São Paulo", "Mumbai", "Varşova", "Hanoi", "Toronto",
              "Johannesburg", "Jakarta"]
CIHAZ_EV = ["win11-dizustu", "macbook-pro", "win10-masaustu", "thinkpad-x1"]
CIHAZ_TEL = ["iphone-15", "android-14"]
CIHAZ_SALDIRGAN = ["linux-bilinmeyen", "chrome-headless", "bilinmeyen-ua"]
NORMAL_MFA = ["totp-onaylandi", "push-onaylandi", "anahtar-onaylandi"]
ZARARLI_AD = ["SessizTopla", "CerezAvcisi", "KasaKemirgen", "YankiOkuyucu", "GolgeSepeti", "TozKapani"]
ENGEL_AD = ["ReklamTik", "EkranRengi", "HizliPDF", "OyunHizlandirici"]
UYGULAMA = ["chrome.exe", "outlook.exe", "teams.exe", "onedrive.exe", "excel.exe", "msedge.exe",
            "zoom.exe", "acrobat.exe"]
BASLIK = "zaman,kullanici,kaynak_ip,sehir,cihaz,sonuc,mfa,oturum_id"


class SidUret:
    """Birbirinden farklı oturum kimlikleri üretir."""

    def __init__(self, rng):
        self.rng = rng
        self.goruldu: set = set()

    def __call__(self) -> str:
        while True:
            s = "S-" + "".join(self.rng.choice("0123456789abcdef") for _ in range(10))
            if s not in self.goruldu:
                self.goruldu.add(s)
                return s


def kullanicilar(rng, n: int) -> list:
    return u.benzersiz(rng, lambda r: f"{r.choice(u.ISIMLER)}.{r.choice(SOYADLAR)}", n)


def profiller(rng, kul: list, haric_ip: set) -> dict:
    """Her kullanıcının sabit ev IP'si/şehri/cihazı ve uç nokta makinesi."""
    ipler = u.benzersiz(rng, u.dis_ip, len(kul), haric=haric_ip)
    hostlar = u.benzersiz(rng, lambda r: f"PC-{r.choice(u.DEPARTMANLAR).upper()}-{r.randint(1, 99):02d}", len(kul))
    return {k: {"ip": ip, "sehir": rng.choice(EV_SEHIR), "cihaz": rng.choice(CIHAZ_EV), "host": h}
            for k, ip, h in zip(kul, ipler, hostlar)}


def satir(t, kul, ip, sehir, cihaz, sonuc, mfa, sid) -> tuple:
    return (t, kul, ip, sehir, cihaz, sonuc, mfa, sid)


def ev_satiri(p: dict, kul: str, t, sonuc: str, mfa: str, sid: str, ip: str | None = None) -> tuple:
    return satir(t, kul, ip or p["ip"], p["sehir"], p["cihaz"], sonuc, mfa, sid)


def normal_trafik(rng, prof: dict, D: datetime, sid_uret, atla: set, gunler: int = 9) -> list:
    """Hafta içi sıradan girişler: giriş + o oturumla birkaç kullanım (hep aynı IP/şehir)."""
    rows = []
    for d in range(gunler, -1, -1):
        gun = D - timedelta(days=d)
        if gun.weekday() >= 5:
            continue
        for k, p in prof.items():
            if (k, d) in atla or rng.random() < 0.12:
                continue
            t = gun + timedelta(hours=8, minutes=rng.randint(0, 100), seconds=rng.randint(0, 59))
            if rng.random() < 0.06:
                rows.append(ev_satiri(p, k, t - timedelta(seconds=rng.randint(20, 90)), "basarisiz", "-", "-"))
            s = sid_uret()
            rows.append(ev_satiri(p, k, t, "basarili", rng.choice(NORMAL_MFA), s))
            for _ in range(rng.randint(1, 3)):
                rows.append(ev_satiri(p, k, t + timedelta(minutes=rng.randint(8, 300)), "oturum_kullanimi", "-", s))
    return rows


def csv_metni(rows: list) -> str:
    rows = sorted(rows, key=lambda r: (r[0], r[1]))
    return BASLIK + "\n" + "".join(
        f"{r[0]:%Y-%m-%d %H:%M:%S},{r[1]},{r[2]},{r[3]},{r[4]},{r[5]},{r[6]},{r[7]}\n" for r in rows)


def uc_gurultu(rng, prof: dict, D: datetime, gunler: int = 9) -> list:
    """Normal uç nokta olayları: [(zaman, metin)]."""
    out = []
    kul = list(prof)
    for _ in range(rng.randint(130, 190)):
        k = rng.choice(kul)
        t = D - timedelta(days=rng.randint(0, gunler)) + timedelta(hours=rng.randint(8, 17),
                                                                      minutes=rng.randint(0, 59),
                                                                      seconds=rng.randint(0, 59))
        if rng.random() < 0.72:
            ad = rng.choice(UYGULAMA)
            out.append((t, f"host={prof[k]['host']} kullanici={k} olay=surec_basladi surec={ad} "
                           f"yol=C:\\Program Files\\Uygulamalar\\{ad}"))
        else:
            out.append((t, f"host={prof[k]['host']} kullanici={k} olay=tarama sonuc=temiz"))
    return out


def zararli_satirlari(rng, t0: datetime, host: str, kul: str, c2: str, ad: str, cerez: bool) -> list:
    """Kurgusal infostealer izi (yalnızca düz metin kayıt satırları)."""
    ust = rng.choice(["outlook.exe", "msedge.exe", "chrome.exe"])
    yem = rng.choice(["fatura_ek_0412.pdf.exe", "teklif_formu.scr", "guncelleme_yardimcisi.exe"])
    on = f"host={host} kullanici={kul}"
    t = t0
    out = [(t, f"{on} olay=surec_basladi surec={ad} yol=C:\\Users\\{kul}\\AppData\\Local\\Temp\\{ad}.exe "
               f"ust_surec={ust} tetikleyen={yem}")]
    t += timedelta(seconds=rng.randint(2, 9))
    out.append((t, f"{on} olay=dosya_okuma surec={ad} hedef=tarayici_parola_deposu"))
    if cerez:
        t += timedelta(seconds=rng.randint(1, 6))
        out.append((t, f"{on} olay=dosya_okuma surec={ad} hedef=tarayici_cerez_deposu"))
    t += timedelta(seconds=rng.randint(3, 15))
    icerik = "tarayici_parolasi+tarayici_cerezi" if cerez else "tarayici_parolasi"
    out.append((t, f"{on} olay=veri_sizdirma surec={ad} hedef={c2}:443 icerik={icerik} bayt={rng.randint(40000, 900000)}"))
    t += timedelta(seconds=rng.randint(2, 10))
    out.append((t, f"{on} olay=kendini_silme surec={ad}"))
    return out


def engel_satiri(rng, t: datetime, prof_k: dict, kul: str) -> tuple:
    return (t, f"host={prof_k['host']} kullanici={kul} olay=engellendi surec={rng.choice(ENGEL_AD)} sonuc=karantina")


def log_metni(satirlar: list) -> str:
    return "".join(f"{t:%Y-%m-%d %H:%M:%S} {m}\n" for t, m in sorted(satirlar, key=lambda x: x[0]))


def uzak_sehir(rng, haric: set | None = None) -> str:
    return rng.choice([c for c in UZAK_SEHIR if c not in (haric or set())])


# Kontrol/çözüm için ortak awk betikleri (b09 ve olay_kimlik)
AWK_SEYAHAT = ("$1!=\"zaman\" && ($6==\"basarili\"||$6==\"oturum_kullanimi\") {"
               "split($1,a,/[- :]/); t=mktime(a[1]\" \"a[2]\" \"a[3]\" \"a[4]\" \"a[5]\" \"a[6]); "
               "if ($2==pu && $4!=pc && t-pt<10800) print $2; pu=$2; pc=$4; pt=t}")


def seyahat_cozumu(dosya: str, lab: Path) -> str:
    """Zamana göre sıralı tabloda, 3 saatten kısa sürede şehir değiştiren kullanıcı."""
    return sh(f"LC_ALL=C sort -t, -k2,2 -k1,1 {dosya} | awk -F, '{AWK_SEYAHAT}' | sort -u | head -1", lab)


# ----------------------------------------------------------------------------- vaka üretimi

SENARYOLAR = [
    {"musteri": "Karaca Danışmanlık", "sektor": "yönetim danışmanlığı", "kisi": "BT sorumlusu Nesrin Hanım",
     "klasor": "kimlik_kayitlari",
     "hikaye": "Bir danışmanın bulut posta ve proje paylaşım hesabından, kendisinin haberi olmadan müşteri "
               "dosyaları indirildi. Parola değiştirildi ama saldırgan yine içeride görünüyor."},
    {"musteri": "Atlas Altyapı", "sektor": "BT hizmetleri", "kisi": "Güvenlik müdürü Tarık Bey",
     "klasor": "giris_dokumu",
     "hikaye": "Gece yarısı, bir yöneticinin telefonuna onlarca onay bildirimi düştü; ertesi sabah aynı "
               "hesaptan yönetim paneline girilmiş. Şirket 'kimse parolayı kırmadı' diyor."},
    {"musteri": "Ege Lojistik", "sektor": "lojistik ve depolama", "kisi": "Operasyon müdürü Hülya Hanım",
     "klasor": "idp_loglari",
     "hikaye": "Şirketin uzaktan erişim (VPN) portalına, MFA sorulmadan, yurt dışından bir bağlantı kurulmuş. "
               "Kullanıcı o sırada ofisinde çalışıyordu."},
]


def _akis(alt: int) -> dict:
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    D = u.gun(rng)
    kul = kullanicilar(rng, 14)
    ua, ub, uc, ue = kul[0], kul[1], kul[2], kul[3]
    ipx = u.benzersiz(rng, u.dis_ip, 3)               # [A saldırgan, B saldırgan, zararlı sunucusu (C2)]
    prof = profiller(rng, kul, set(ipx))
    sid = SidUret(rng)
    rows = normal_trafik(rng, prof, D, sid, {(ua, 0), (uc, 7), (ue, 7)})

    # A: oturum çalma. Meşru giriş -> çalıntı çerez -> aynı oturum başka IP'den (MFA hiç sorulmaz)
    pa = prof[ua]
    tA = D + timedelta(hours=9, minutes=rng.randint(0, 90), seconds=rng.randint(0, 59))
    sA = sid()
    rows.append(ev_satiri(pa, ua, tA, "basarili", "push-onaylandi", sA))
    for dk in sorted(rng.sample(range(5, 36), rng.randint(2, 4))):
        rows.append(ev_satiri(pa, ua, tA + timedelta(minutes=dk), "oturum_kullanimi", "-", sA))
    sehir_a = uzak_sehir(rng)
    cihaz_a = rng.choice(CIHAZ_SALDIRGAN)
    t = tA + timedelta(minutes=rng.randint(30, 70))
    for _ in range(rng.randint(3, 6)):
        t += timedelta(minutes=rng.randint(2, 9), seconds=rng.randint(0, 59))
        rows.append(satir(t, ua, ipx[0], sehir_a, cihaz_a, "oturum_kullanimi", "-", sA))
    stealer_t = tA + timedelta(minutes=rng.randint(8, 20))

    # B: MFA yorgunluğu, gece yarısından sonra; sabaha kadar evde etkinlik yok (seyahat kuralına takılmaz)
    pb = prof[ub]
    sehir_b = uzak_sehir(rng, {sehir_a})
    cihaz_b = rng.choice(CIHAZ_SALDIRGAN)
    nB = rng.randint(9, 16)
    t = D + timedelta(hours=1, minutes=rng.randint(50, 99), seconds=rng.randint(0, 59))
    for _ in range(nB):
        t += timedelta(seconds=rng.randint(35, 90))
        rows.append(satir(t, ub, ipx[1], sehir_b, cihaz_b, "mfa_istegi", "push-gonderildi", "-"))
    t += timedelta(seconds=rng.randint(20, 80))
    sB = sid()
    rows.append(satir(t, ub, ipx[1], sehir_b, cihaz_b, "basarili", "push-onaylandi", sB))
    for _ in range(rng.randint(1, 3)):
        t += timedelta(minutes=rng.randint(1, 8))
        rows.append(satir(t, ub, ipx[1], sehir_b, cihaz_b, "oturum_kullanimi", "-", sB))

    # C: makul seyahat (sabah evde, akşama başka Türk şehrinde; 7+ saat) — saldırı değil
    pc = prof[uc]
    gun7 = D - timedelta(days=7)
    sc1 = sid()
    rows.append(ev_satiri(pc, uc, gun7 + timedelta(hours=8, minutes=rng.randint(0, 40)), "basarili", "totp-onaylandi", sc1))
    sehir_c = rng.choice([c for c in EV_SEHIR if c != pc["sehir"]])
    ip_c = u.benzersiz(rng, u.dis_ip, 1, haric=set(ipx) | {p["ip"] for p in prof.values()})[0]
    sc2 = sid()
    tc = gun7 + timedelta(hours=16, minutes=rng.randint(10, 50))
    rows.append(satir(tc, uc, ip_c, sehir_c, rng.choice(CIHAZ_TEL), "basarili", "push-onaylandi", sc2))
    rows.append(satir(tc + timedelta(minutes=rng.randint(5, 40)), uc, ip_c, sehir_c, "iphone-15",
                      "oturum_kullanimi", "-", sc2))

    # E: kullanıcı onay bildirimine geç baktı: 3 istek sonra onay (ev IP'si, aynı şehir) — saldırı değil
    pe = prof[ue]
    te = gun7 + timedelta(hours=8, minutes=rng.randint(30, 59), seconds=rng.randint(0, 59))
    for i in range(3):
        rows.append(ev_satiri(pe, ue, te + timedelta(seconds=25 * i), "mfa_istegi", "push-gonderildi", "-"))
    rows.append(ev_satiri(pe, ue, te + timedelta(seconds=85), "basarili", "push-onaylandi", sid()))

    # uç nokta kaydı
    log = uc_gurultu(rng, prof, D)
    ad = rng.choice(ZARARLI_AD)
    log += zararli_satirlari(rng, stealer_t - timedelta(seconds=20), pa["host"], ua, ipx[2], ad, cerez=True)
    for k in rng.sample([x for x in kul if x not in (ua, ub)], 2):
        log.append(engel_satiri(rng, D - timedelta(days=rng.randint(0, 6), hours=-rng.randint(9, 15)), prof[k], k))

    return {"sen": sen, "rows": rows, "log": log, "kul": {"a": ua, "b": ub, "c": uc, "e": ue},
            "ip_a": ipx[0], "ip_b": ipx[1], "c2": ipx[2], "ev_ip_a": pa["ip"], "sid_a": sA, "sid_b": sB,
            "n_b": nB, "zararli": ad, "host_a": pa["host"]}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — kimlik merkezli saldırı izleri",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "klasor": sen["klasor"], "kul_c": v["kul"]["c"]},
        "cevaplar": {
            "seyahat": v["kul"]["a"],
            "oturum": v["sid_a"],
            "saldirgan_ip": v["ip_a"],
            "mfa_sayi": v["n_b"],
            "zararli": v["zararli"],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    k = lab / v["sen"]["klasor"]
    u.yaz(k / "girisler.csv", csv_metni(v["rows"]))
    u.yaz(k / "uc_nokta.log", log_metni(v["log"]))
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} kimlik kayıtları ({v['sen']['klasor']}/). KURGUSAL.\n"
          "girisler.csv : kimlik sağlayıcının giriş dökümü (zaman,kullanici,kaynak_ip,sehir,cihaz,sonuc,mfa,oturum_id)\n"
          "uc_nokta.log : çalışan makinelerin uç nokta güvenlik kaydı\n")


# ----------------------------------------------------------------------------- kontroller

def _seyahat_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["kul"]["b"]:
        return ("Bu kullanıcı da farklı şehirlerden girmiş ama aradaki SÜREYE bak: saatler var. "
                "Hızlı şehir değişimini ara (kısa sürede çok uzak iki şehir).")
    if g == v["kul"]["c"]:
        return "Şehir değişmiş ama sabahtan akşama; İstanbul'dan Ankara'ya günün içinde gitmek mümkün. İmkânsız olan dakikalar içinde kıta değiştirmek."
    if g == v["kul"]["e"]:
        return "Bu kullanıcı hep aynı şehirden giriyor; sorun şehir değişimi."
    return None


def _oturum_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["sid_b"].casefold():
        return "Bu oturum tek bir IP'de kullanılmış (saldırganın kendi açtığı oturum). Aranan: İKİ ayrı IP'de görünen oturum_id."
    return None


def _ip_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["ev_ip_a"]:
        return "Bu, kullanıcının kendi (meşru) IP'si. Çalıntı oturumu SONRADAN başka bir IP'den kullanan adresi ara."
    if g == v["c2"]:
        return "Bu, zararlının veri gönderdiği sunucu (uc_nokta.log). Saldırganın giriş yaptığı IP girisler.csv'de."
    if g == v["ip_b"]:
        return "Bu IP başka bir hesaba (MFA yorgunluğu) saldırmış; çalıntı oturumu kullanan IP değil."
    return None


def _mfa_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["n_b"] + 1:
        return "Son satır istek değil, onay (`basarili`). Sadece `mfa_istegi` satırlarını say."
    if n == v["n_b"] + 3:
        return "Başka bir kullanıcının üç denemesini de eklemişsin. İstekleri kullanıcı bazında ayır (`cut -d, -f2 | sort | uniq -c`)."
    return None


def _zararli_hata(g, beklenen, b):
    if g.endswith(".exe"):
        return "Süreç adını `.exe` olmadan yaz (satırdaki `surec=` değeri, örn. `Ad`)."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["metin"]["klasor"]
    g, l = f"{k}/girisler.csv", f"{k}/uc_nokta.log"
    seyahat = seyahat_cozumu(g, lab)
    oturum = sh(f"awk -F, '$1!=\"zaman\" && $8!=\"-\" {{print $8\",\"$3}}' {g} | sort -u | cut -d, -f1 | uniq -d | head -1", lab)
    ip = sh(f"LC_ALL=C sort {g} | awk -F, -v s='{oturum}' '$8==s {{ if (!p) p=$3; else if ($3!=p) print $3 }}' | sort -u | head -1", lab)
    mfa = sh(f"grep mfa_istegi {g} | cut -d, -f2 | sort | uniq -c | sort -rn | head -1 | awk '{{print $1}}'", lab)
    zararli = sh(f"grep veri_sizdirma {l} | grep -o 'surec=[^ ]*' | cut -d= -f2 | head -1", lab)
    return sec_doldur({1: seyahat, 2: oturum, 3: ip, 4: mfa, 5: zararli}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- adımlar

ADIMLAR = [
    Adim("Kırmak yerine giriş yapmak", """
Eskiden saldırgan kapıyı kırmaya çalışırdı. Bugün **anahtarı çalıp kapıdan girer**. 2026'da en çok
görülen saldırı yolu budur: kimlik merkezli saldırılar. Üç ana yol var:

- **Infostealer** (bilgi çalan zararlı): kullanıcının bilgisayarında sessizce çalışır, tarayıcıdaki
  kayıtlı parolaları ve çerezleri (oturum anahtarlarını) toplayıp dışarı yollar.
- **Oturum çalma** (session hijack): çalınan **çerez/oturum belirteci** ile saldırgan, parola ve MFA
  (çok adımlı doğrulama) sorulmadan, zaten açık bir oturumun içine biner.
- **MFA yorgunluğu**: parolayı bilen saldırgan, kullanıcının telefonuna durmadan onay isteği yağdırır;
  bıkan kullanıcı bir noktada "Onayla" der.

Sen bu kurumun analistisin: kimin hesabı ele geçti, nasıl, hangi zararlıyla? <<musteri>> verisine bak:
""", komut="ls <<klasor>>"),
    Adim("Giriş dökümü: girisler.csv", """
Kimlik sağlayıcı her girişi kaydeder: zaman, kullanıcı, kaynak IP, şehir, cihaz, sonuç, MFA yöntemi ve
**oturum_id** (başarılı girişte doğan, sonraki isteklerde tekrar tekrar gösterilen oturum anahtarı).
İlk satırlara bak:
""", komut="head -n 5 <<klasor>>/girisler.csv", sonra="""
`sonuc` sütununda dört değer görürsün: `basarili` (giriş), `basarisiz`, `mfa_istegi` (kullanıcıya
onay bildirimi gitti) ve `oturum_kullanimi` (açık oturumla yeni bir istek). Her şey sütunlarda; bu yüzden
`grep`, `cut`, `sort`, `awk` yeter.
"""),
    Adim("Tek kullanıcının hikâyesi: grep ve sort", """
Bir kullanıcıyı izlemenin ilk yolu `grep` ile onun satırlarını almak, `sort` ile **zamana** dizmektir.
`-t,` ayırıcının virgül olduğunu, `-k1` 1. sütuna (zaman) göre sıralamayı söyler. Önce zararsız bir
örnek: `<<kul_c>>` kullanıcısının sabahtan akşama izi:
""", komut="grep <<kul_c>> <<klasor>>/girisler.csv | sort -t, -k1", sonra="""
Sabah bir şehirde, akşam başka bir **Türkiye şehrinde**. Arada saatler var: bu **makul seyahat**. Bir kullanıcının
şehir değiştirmesi tek başına alarm değildir; **ne kadar sürede** değiştirdiği belirleyicidir.
"""),
    Adim("Şehir değiştirenleri bul: cut, sort -u, uniq -d", """
Hangi kullanıcılar birden fazla şehirden girmiş? `cut` kullanıcı ve şehir sütunlarını alır, `sort -u`
tekrarları siler, ikinci `cut` yalnız kullanıcıyı bırakır, `uniq -d` **birden fazla** görünenleri (tekrar
edenleri) listeler:
""", komut="cut -d, -f2,4 <<klasor>>/girisler.csv | sort -u | cut -d, -f1 | uniq -d", sonra="""
Listede birden fazla isim var: bazıları makul seyahat, bazısı **imkânsız seyahat** (aynı kullanıcı kısa
sürede çok uzak iki şehirden). Şimdi adayları saatlerine göre ayıracaksın. Başka bir araç: `awk`.
"""),
    Adim("awk ile bir kullanıcının girişleri", """
`awk -F,` satırı virgüllerden böler; `$2` kullanıcı, `$4` şehir, `$1` zaman. Koşulu `{ ... }` önüne
yazarsın. `<<kul_c>>` için başarılı girişlerin zamanı ve şehri:
""", komut="awk -F, '$2==\"<<kul_c>>\" && $6==\"basarili\" {print $1, $4}' <<klasor>>/girisler.csv", sonra="""
Aynı yöntemi şüpheli adaylara uygula: iki giriş arasındaki süre **dakikalarsa** ve şehirler birbirinden
bin kilometre uzaksa, o hesapta bir insan iki yerde birden olamaz. Görevlerde adayları kendin ayıklayacaksın.
"""),
    Adim("Oturum çalma: aynı oturum_id, iki IP", """
Meşru bir oturum anahtarı **tek bir yerden** kullanılır. Aynı `oturum_id` iki farklı IP'de görünüyorsa
anahtar çalınmıştır. Komut: `oturum_id,IP` çiftlerini tekilleştir, yalnız oturum_id'yi bırak, tekrar edeni (`uniq -d`)
yaz. (`$8!="-"` oturumu olmayan satırları eler.)
""", komut="awk -F, '$8!=\"-\" {print $8\",\"$3}' <<klasor>>/girisler.csv | sort -u | cut -d, -f1 | uniq -d",
         sonra="""
Çıkan oturum anahtarı iki IP'de dolaşıyor. Hangisi kullanıcının gerçek IP'si? **İlk görülen** (girişin
yapıldığı) IP meşru; sonradan beliren, başka şehirdeki IP saldırgandır. Dikkat: o IP'den **MFA isteği yok**: çerez
MFA'yı tamamen atladı. Bu yüzden "MFA var" demek tek başına koruma değildir.
"""),
    Adim("MFA yorgunluğu: tekrarları say", """
Kısa sürede çok `mfa_istegi` görmek şüphelidir. Önce dosyadaki **toplam** istek sayısına bak:
""", komut="grep -c mfa_istegi <<klasor>>/girisler.csv", sonra="""
Bu sayı tüm kullanıcıların toplamı; saldırıyı bulmak için kullanıcı bazında ayırman gerek:
`grep mfa_istegi dosya | cut -d, -f2 | sort | uniq -c | sort -rn`. En çok isteği alan hesabın aldığı sayı,
yorgunluk saldırısının büyüklüğüdür. Normal bir kullanıcı da arada iki-üç kez yanlış bildirime bakabilir:
**dakikalar içinde onlarca** istek ise saldırıdır.
"""),
    Adim("Uç nokta kaydı: infostealer izi", """
`uc_nokta.log` her makinenin uç nokta güvenlik yazılımından gelir. Antivirüsün **engellediği** şeyler
`olay=engellendi` ile yazılır:
""", komut="grep engellendi <<klasor>>/uc_nokta.log", sonra="""
Engellenen zararsızdır: karantinaya girdi, veri sızmadı. **Asıl tehlike**, engellenmeyen, sessizce çalışıp işini
bitirip kendini silen süreçtir: `olay=veri_sizdirma` ve `olay=kendini_silme` satırlarını arayacaksın.

**Hacker gözüyle:** Saldırganın işi kolaylaştı: çalınan oturum, bir parolayı kırmaktan çok daha ucuz. Savunmacının
işi de değişti: "doğru parola girildi mi?" sorusu yetmez; "bu giriş **bu kullanıcının** alışkanlığına uyuyor mu?"
sorusu sorulur (şehir, cihaz, süre, MFA tekrarı). Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`<<klasor>>/girisler.csv` içinde, **imkânsız seyahat** yapan kullanıcı kim? (Kısa sürede, birbirinden "
          "çok uzak iki şehirden başarılı giriş / oturum kullanımı. Saatler arayla şehir değiştirenler "
          "makuldür, onları eleyin.)",
          Metin("seyahat", sik_hatalar=_seyahat_hata, bicim="kullanıcı adı (ad.soyad)"),
          ("Önce birden fazla şehirden girenleri listele; sonra her adayın girişleri arasındaki süreye bak.",
           "`cut -d, -f2,4 ... | sort -u | cut -d, -f1 | uniq -d` aday verir. Adayı `grep <ad> girisler.csv | sort -t, -k1` ile zamana diz: "
           "iki giriş arası saatler mi, dakikalar mı?",
           "Adaylardan birinde iki farklı şehirden girişler arası 1-2 saatten kısa ve şehirler çok uzak (Türkiye / yurt dışı). "
           "Diğer adaylarda ya saatler var ya da şehirler Türkiye içinde."),
          puan=40, baslik="İmkânsız seyahat"),
    Gorev("Bu hesapla ilgili **çalınmış oturumun kimliği** (`oturum_id`) nedir? Bir oturum anahtarı meşru "
          "olarak tek yerden kullanılır; aranan, **iki farklı IP**'den görünen oturum.",
          Metin("oturum", sik_hatalar=_oturum_hata, bicim="S-... biçiminde oturum kimliği"),
          ("Aynı oturum_id iki farklı IP'de görünüyor. IP ve oturum_id sütunlarını birlikte tekilleştir.",
           "`awk -F, '$8!=\"-\" {print $8\",\"$3}' girisler.csv | sort -u | cut -d, -f1 | uniq -d` iki IP'si olan oturum kimliklerini verir.",
           "Çıkan tek oturum_id'yi `grep` ile ara: kullanıcının meşru girişi ile yabancı IP'nin kullanımı yan yana görünür."),
          puan=40, baslik="Çalınan oturum"),
    Gorev("Çalıntı oturumu kullanan **saldırgan IP** hangisi?",
          IP("saldirgan_ip", sik_hatalar=_ip_hata),
          ("Aynı oturum_id'nin geçtiği satırlarda iki IP var: biri girişin yapıldığı, biri sonradan belirmiş.",
           "`grep S-... girisler.csv | cut -d, -f1,3,4,6`: ilk satır (`basarili`) meşru IP'yi verir; ondan farklı olanı seç.",
           "Meşru IP'nin şehri Türkiye'de; yabancı şehirde görünen IP'nin satırlarında `mfa` sütunu `-` (MFA sorulmamış)."),
          puan=40, baslik="Saldırgan IP"),
    Gorev("Bu veri setinde **MFA yorgunluğu** saldırısı da var. En çok `mfa_istegi` alan hesabın aldığı "
          "**istek sayısı** kaç? (Yalnızca istek satırlarını say; sonda gelen onay istek değildir.)",
          Sayi("mfa_sayi", sik_hatalar=_mfa_hata),
          ("İstekleri kullanıcı bazında saymalısın; toplam sayı birkaç kullanıcıyı karıştırır.",
           "`grep mfa_istegi girisler.csv | cut -d, -f2 | sort | uniq -c | sort -rn | head`. En üstteki sayı.",
           "Çıkan ilk satırdaki sayı bu soruyu cevaplar. İkinci satırdaki sayı normal bir kullanıcının 2-3 denemesidir."),
          puan=40, baslik="MFA yorgunluğu"),
    Gorev("`uc_nokta.log` içinde **veri sızdıran** (`olay=veri_sizdirma`) zararlı sürecin adı nedir? "
          "(`surec=` değeri, `.exe` yok.)",
          Metin("zararli", sik_hatalar=_zararli_hata, bicim="süreç adı"),
          ("Antivirüsün engellediği süreç zararsızdır; asıl iz, veriyi dışarı gönderen satırdadır.",
           "`grep veri_sizdirma uc_nokta.log` tek satır verir; satırdaki `surec=` alanına bak.",
           "`grep veri_sizdirma <<klasor>>/uc_nokta.log | grep -o 'surec=[^ ]*'`"),
          puan=40, baslik="Infostealer süreci"),
    Gorev("Zararlı, kurbanın tarayıcısından hem parolaları hem **çerezleri** (oturum anahtarları) çalmış. "
          "Müşteri 'parolayı değiştirdik, iş bitti' diyor ama saldırgan hâlâ içeride. **Neden?**",
          Secmeli([
              ("Çalınan oturum çerezi, parolanın yerine geçen bir anahtardır; parola değişse bile oturum geçerli kalır, "
               "oturumlar ayrıca iptal edilmelidir",
               "Doğru. Oturum, girişten sonra doğan ayrı bir anahtardır. Parola değişimi onu otomatik öldürmez; "
               "oturumları (token'ları) iptal etmek ve zararlıyı makineden temizlemek gerekir."),
              ("Saldırgan yeni parolayı da tahmin etmiştir, çünkü yeni parolalar eski parolaya çok benzer olur ve "
               "bu yüzden listede ilk denenir",
               "Yanlış. Logda parola denemesi yok; saldırgan zaten oturum anahtarını elinde tutuyor. Sorun parolanın "
               "tahmin edilmesi değil, oturumun geçerli kalması."),
              ("Kimlik sağlayıcı yeni parolayı hemen işlemez ve eski parola bir süre daha geçerli kalır, "
               "bu da saldırganın girişine izin verir",
               "Yanlış. Parola değişimi anında işler. Saldırgan parolaya hiç ihtiyaç duymadan, daha önce açılmış oturumu "
               "kullanıyor."),
              ("Saldırgan MFA cihazını ele geçirmiştir; bu yüzden hesaba parola olmadan da istediği zaman "
               "yeniden girebilir",
               "Yanlış. Bu vakada saldırgan IP'sinden hiç MFA isteği yok; MFA cihazına ihtiyaç duymadı. Çerez MFA'yı da "
               "parola gibi atladı."),
          ], dogru=0),
          ("Çerez, girişten SONRA doğan bir şeydir. Parola o anda ne işe yarar?",
           "Oturum anahtarı (çerez/token) sunucuda geçerli olduğu sürece sahibi parola ve MFA sormadan içeri alınır.",
           "Doğru cevap 'oturum çerezi parola değişse de geçerli kalır; oturumlar ayrıca iptal edilir' fikrini söyler."),
          puan=40, baslik="Neden parola yetmedi"),
]


def _kapanis():
    return """
Bu vakada kimse kapıyı kırmadı. Bir tarafta zararlı, parolayı ve çerezi sessizce çalıp kendini sildi; bir tarafta
yorgun kullanıcı bir bildirime "Onayla" dedi. İkisinde de saldırgan "doğru kimlik bilgisiyle" içeri girdi. Savunma
dersi: kimliği **bir kez** doğrulayıp unutmak yetmez; her girişi alışkanlıkla karşılaştır (şehir, cihaz, süre, MFA
tekrarı), çalınan oturumu iptal edebil, MFA'da sayı eşleştirmeli ya da donanım anahtarlı (parola-sızdırmaz) yöntemlere
geç ve uç noktadaki zararlıyı temizle. Parola sıfırlamak tek başına asla yeterli değildir.
"""


SEVIYE = Seviye(
    kimlik="c07b09",
    cilt=7,
    bolum=9,
    baslik="Kimlik Merkezli Saldırılar: Kırmak Yerine Giriş Yapmak",
    brifing="""
Deniz Kara dosyaları ekrana açıyor: "**<<musteri>>** (<<sektor>>) için bir acil çağrı geldi. <<hikaye>>
<<kisi>> bize iki dosya yolladı: `<<klasor>>/girisler.csv` (kimlik sağlayıcının giriş dökümü) ve
`<<klasor>>/uc_nokta.log` (makinelerin güvenlik kaydı). Hepsi kurgusal."

"Bu kez kimse kapıyı kırmadı," diye devam ediyor Deniz. "2026'nın en yaygın saldırısı bu: parola tahmini değil,
**çalınmış kimlik**. Bir zararlı tarayıcıdaki parolayı ve çerezi çalıyor; biri çerezle MFA'ya hiç takılmadan giriyor;
biri de telefona onay yağdırıp kullanıcıyı yoruyor. Sen analistsin: hangi iz hangi saldırıya ait?" Mert ekliyor:
"Saldırganın cihazına değil, **kendi** loglarımıza bak. Tek komut bile yetebilir."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Snowflake müşteri hesapları, 2024:** Mandiant'ın (Google) kamuya açıkladığı soruşturmaya göre, bir saldırgan
  grubu çok sayıda Snowflake müşteri hesabına, **infostealer zararlılarıyla önceden çalınmış kimlik bilgileriyle**
  ve hesapta MFA etkin olmadığı için girdi. Yani bir yazılım açığı değil, çalıntı kimlik bilgisi ve eksik MFA vardı.
  Bu bölümdeki beceri tam budur: giriş dökümünde "doğru parola, yanlış alışkanlık" izini görmek.
- **Uber, 2022:** Saldırgan, çalıntı parolayla giriş yapıp çalışanın telefonuna art arda MFA bildirimi yolladı
  (MFA yorgunluğu) ve bir noktada onay alındı. Önleme: sayı eşleştirmeli onay ya da donanım anahtarı; tespit:
  kısa sürede çok MFA isteği alarmı.
- **Infostealer ekosistemi:** Lumma (Mayıs 2025'te hukuki/teknik operasyonla aksatıldı) ve RedLine (Ekim 2024'te
  Operation Magnus ile hedef alındı) gibi ailelerin çaldığı kimlik bilgileri ve oturum çerezleri yeraltı pazarlarında
  satılır. Önleme: yönetilen tarayıcı politikası, uç nokta koruması ve **oturum ömrünü kısaltmak**; tespit: oturumun
  yeni IP/cihazdan yeniden kullanımı ve imkânsız seyahat alarmı.
""",
    sure_hedef_dk=35,
)
