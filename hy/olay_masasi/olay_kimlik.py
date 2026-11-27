"""Olay Masası — Kimlik Merkezli Saldırı: Hesabı Kim Devraldı?

TAMAMEN SAVUNMACI/ADLİ: oyuncu, saldırıya uğrayan kurumun analistidir. Her şey kurgusal, dosya-tabanlı
sahte veridir. İki dosya gelir: `girisler.csv` (kimlik sağlayıcı dökümü) ve `uc_nokta.log` (uç nokta kaydı).
Tek bir hesap devralınmıştır; yöntem vakaya göre ya oturum çalma (çerez) ya MFA yorgunluğudur. Gürültü:
makul seyahat, aynı şehirde IP değiştiren kullanıcı, tekrar eden onay, başka hesaba başarısız brute-force
ve zararlı bulaşmış ama hesabı kötüye kullanılmamış başka bir makine.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem `yaz`
aynı `_akis(alt)` ile veriyi yeniden üretir. (`_tohum` motor tarafından ezildiği için ayrı anahtar.)
Genel yardımcılar `hy.seviyeler.c07_savunma.b09_kimlik` modülündedir.
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli, Sonuc, norm
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.b09_kimlik import (
    CIHAZ_SALDIRGAN, CIHAZ_TEL, EV_SEHIR, ZARARLI_AD, SidUret, csv_metni, engel_satiri, ev_satiri,
    kullanicilar, log_metni, normal_trafik, profiller, satir, seyahat_cozumu, uc_gurultu, uzak_sehir,
    zararli_satirlari,
)
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

SENARYOLAR = [
    {"musteri": "Karaca Danışmanlık", "sektor": "yönetim danışmanlığı", "kisi": "BT sorumlusu Nesrin Hanım",
     "yontem": 0, "yonetici": False,
     "hikaye": "Bir danışmanın bulut posta hesabından müşteri dosyaları indirildi. Danışman o sırada kendi "
               "bilgisayarında çalışıyordu ve hiçbir şüpheli onay bildirimi görmedi."},
    {"musteri": "Atlas Altyapı", "sektor": "BT hizmetleri", "kisi": "Güvenlik müdürü Tarık Bey",
     "yontem": 1, "yonetici": True,
     "hikaye": "Bir sistem yöneticisinin telefonuna çalışma saatinde art arda onay bildirimleri düştü; kısa süre "
               "sonra aynı yönetici hesabıyla yönetim paneline yurt dışından girilmiş."},
    {"musteri": "Ege Lojistik", "sektor": "lojistik ve depolama", "kisi": "Operasyon müdürü Hülya Hanım",
     "yontem": 0, "yonetici": False,
     "hikaye": "Uzaktan erişim (VPN) portalına, MFA hiç sorulmadan, yurt dışından bir bağlantı kurulmuş. "
               "İlgili çalışan o sırada ofisteydi ve VPN'e kendisi bağlıydı."},
]


def _akis(alt: int) -> dict:
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    D = u.gun(rng)
    kul = kullanicilar(rng, 16)
    if sen["yonetici"]:
        kul[0] = "adm." + kul[0]
    v, c, d, e, f, g = kul[:6]
    ipler = u.benzersiz(rng, u.dis_ip, 5)    # saldırgan, brute-force kaynağı, C2, başka zararlının C2'si, ikinci IP (d için)
    ipx, ipf, c2, c2g, ip_d2 = ipler
    prof = profiller(rng, kul, set(ipler))
    sid = SidUret(rng)
    yontem = sen["yontem"]
    rows = normal_trafik(rng, prof, D, sid, {(v, 0), (c, 7), (d, 2), (e, 7)})

    # --- kurban (v): meşru giriş + meşru bir onay isteği
    pv = prof[v]
    tA = D + timedelta(hours=9, minutes=rng.randint(0, 60), seconds=rng.randint(0, 59))
    sA = sid()
    rows.append(ev_satiri(pv, v, tA - timedelta(seconds=20), "mfa_istegi", "push-gonderildi", "-"))
    rows.append(ev_satiri(pv, v, tA, "basarili", "push-onaylandi", sA))
    for dk in sorted(rng.sample(range(5, 51), rng.randint(2, 3))):
        rows.append(ev_satiri(pv, v, tA + timedelta(minutes=dk), "oturum_kullanimi", "-", sA))
    sehir_x = uzak_sehir(rng)
    cihaz_x = rng.choice(CIHAZ_SALDIRGAN)
    if yontem == 0:        # oturum çalma
        sid_x = sA
        mfa_sayi = 0
        t = tA + timedelta(minutes=rng.randint(30, 75))
        for _ in range(rng.randint(3, 7)):
            t += timedelta(minutes=rng.randint(1, 8), seconds=rng.randint(0, 59))
            rows.append(satir(t, v, ipx, sehir_x, cihaz_x, "oturum_kullanimi", "-", sA))
        stealer_t = tA + timedelta(minutes=rng.randint(8, 20))
        cerez = True
    else:                  # MFA yorgunluğu
        mfa_sayi = rng.randint(9, 16)
        t = tA + timedelta(minutes=rng.randint(70, 100))
        for _ in range(mfa_sayi):
            t += timedelta(seconds=rng.randint(35, 90))
            rows.append(satir(t, v, ipx, sehir_x, cihaz_x, "mfa_istegi", "push-gonderildi", "-"))
        t += timedelta(seconds=rng.randint(20, 80))
        sid_x = sid()
        rows.append(satir(t, v, ipx, sehir_x, cihaz_x, "basarili", "push-onaylandi", sid_x))
        for _ in range(rng.randint(2, 5)):
            t += timedelta(minutes=rng.randint(1, 8))
            rows.append(satir(t, v, ipx, sehir_x, cihaz_x, "oturum_kullanimi", "-", sid_x))
        stealer_t = D + timedelta(hours=6, minutes=rng.randint(0, 90))
        cerez = False

    # --- yem 1: makul seyahat (c)
    pc = prof[c]
    gun7 = D - timedelta(days=7)
    rows.append(ev_satiri(pc, c, gun7 + timedelta(hours=8, minutes=rng.randint(0, 40)), "basarili", "totp-onaylandi", sid()))
    sehir_c = rng.choice([x for x in EV_SEHIR if x != pc["sehir"]])
    ip_c = u.benzersiz(rng, u.dis_ip, 1, haric=set(ipler) | {p["ip"] for p in prof.values()})[0]
    sc = sid()
    tc = gun7 + timedelta(hours=16, minutes=rng.randint(10, 50))
    rows.append(satir(tc, c, ip_c, sehir_c, rng.choice(CIHAZ_TEL), "basarili", "push-onaylandi", sc))

    # --- yem 2: aynı şehirde IP değiştiren kullanıcı (d): oturum_id iki IP'de ama meşru
    pd_ = prof[d]
    gun2 = D - timedelta(days=2)
    td = gun2 + timedelta(hours=9, minutes=rng.randint(0, 40))
    sd = sid()
    rows.append(ev_satiri(pd_, d, td, "basarili", "totp-onaylandi", sd))
    rows.append(ev_satiri(pd_, d, td + timedelta(minutes=rng.randint(10, 30)), "oturum_kullanimi", "-", sd))
    for dk in (rng.randint(40, 60), rng.randint(70, 90)):
        rows.append(ev_satiri(pd_, d, td + timedelta(minutes=dk), "oturum_kullanimi", "-", sd, ip=ip_d2))

    # --- yem 3: kullanıcı onay bildirimine geç baktı: 3 istek (e)
    pe = prof[e]
    te = gun7 + timedelta(hours=8, minutes=rng.randint(30, 59), seconds=rng.randint(0, 59))
    for i in range(3):
        rows.append(ev_satiri(pe, e, te + timedelta(seconds=25 * i), "mfa_istegi", "push-gonderildi", "-"))
    rows.append(ev_satiri(pe, e, te + timedelta(seconds=85), "basarili", "push-onaylandi", sid()))

    # --- yem 4: başka hesaba başarısız parola denemesi (f): yabancı IP, hiç giriş yok
    sehir_f = uzak_sehir(rng, {sehir_x})
    t = D + timedelta(hours=3, minutes=rng.randint(0, 50), seconds=rng.randint(0, 59))
    for _ in range(rng.randint(6, 9)):
        t += timedelta(seconds=rng.randint(2, 6))
        rows.append(satir(t, f, ipf, sehir_f, "bilinmeyen-ua", "basarisiz", "-", "-"))

    # --- uç nokta kaydı: kurbanın makinesi + zararlı bulaşmış ama kötüye kullanılmamış başka makine (g)
    log = uc_gurultu(rng, prof, D)
    ad, ad2 = rng.sample(ZARARLI_AD, 2)
    log += zararli_satirlari(rng, stealer_t - timedelta(seconds=20), pv["host"], v, c2, ad, cerez=cerez)
    log += zararli_satirlari(rng, D - timedelta(days=rng.randint(2, 5), hours=-rng.randint(9, 15)),
                             prof[g]["host"], g, c2g, ad2, cerez=False)
    for k in rng.sample([x for x in kul if x not in (v, g)], 2):
        log.append(engel_satiri(rng, D - timedelta(days=rng.randint(0, 6), hours=-rng.randint(9, 15)), prof[k], k))

    return {"sen": sen, "rows": rows, "log": log, "v": v, "c": c, "d": d, "e": e, "f": f, "g": g,
            "ip_x": ipx, "ip_f": ipf, "c2": c2, "c2g": c2g, "ev_ip": pv["ip"], "ip_d2": ip_d2,
            "sid_x": sid_x, "sid_a": sA, "mfa_sayi": mfa_sayi, "host": pv["host"], "yontem": yontem,
            "sid_d": sd}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — hesap devralma incelemesi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"], "hikaye": sen["hikaye"]},
        "cevaplar": {
            "hesap": v["v"],
            "ip": v["ip_x"],
            "yontem": v["yontem"],
            "oturum": v["sid_x"],
            "mfa_sayi": v["mfa_sayi"],
            "makine": v["host"],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    u.yaz(lab / "girisler.csv", csv_metni(v["rows"]))
    u.yaz(lab / "uc_nokta.log", log_metni(v["log"]))
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} olay dosyaları. KURGUSAL.\n"
          "girisler.csv : kimlik sağlayıcı dökümü (zaman,kullanici,kaynak_ip,sehir,cihaz,sonuc,mfa,oturum_id)\n"
          "               sonuc: basarili | basarisiz | mfa_istegi | oturum_kullanimi\n"
          "uc_nokta.log : çalışan makinelerin uç nokta güvenlik kaydı (anahtar=değer)\n")


# ----------------------------------------------------------------------------- kontroller

class YontemSecmeli(Secmeli):
    """Doğru şık vakaya göre değişir (oturum çalma ya da MFA yorgunluğu)."""

    def __init__(self, secenekler: list, aciklama):
        super().__init__([(m, "açıklama vakaya göre değişir") for m in secenekler])
        self.aciklama = aciklama

    @staticmethod
    def _dogru(b) -> int:
        return int(b.senaryo["cevaplar"]["yontem"])

    def dogrula(self, girdi, b):
        g = norm(girdi)[:1]
        harfler = "abcdefgh"
        sira = self._sira(b)
        if not g or g not in harfler[: len(sira)]:
            return Sonuc(False, f"Şıklardan birini yaz: {', '.join(harfler[:len(sira)])}.")
        secilen = sira[harfler.index(g)]
        return Sonuc(secilen == self._dogru(b), self.aciklama(secilen, self._dogru(b)))

    def cevabi_goster(self, b) -> str:
        d = self._dogru(b)
        return f"{'abcdefgh'[self._sira(b).index(d)]}) {self.secenekler[d][0]}"


def _yontem_aciklama(i: int, dogru: int) -> str:
    if i == 0:
        return ("Doğru. Saldırgan IP'sinden hiç MFA isteği yok ve oturum_id kurbanın meşru girişinde doğmuş: çerez çalınmış, "
                "MFA hiç sorulmamış." if dogru == 0 else
                "Yanlış. Saldırgan IP'sinde başka IP'den devralınmış bir oturum_id yok; kendi oturumunu açmış ve öncesinde art arda "
                "MFA isteği gelmiş.")
    if i == 1:
        return ("Doğru. Saldırgan IP'sinden dakikalar içinde art arda MFA isteği gitmiş ve sonunda 'onaylandı' gelmiş." if dogru == 1
                else "Yanlış. Saldırgan IP'sinden tek bir MFA isteği bile yok; çerez MFA'yı tamamen atlamış, bir yorgunluk saldırısı yok.")
    if i == 2:
        return ("Yanlış. Saldırgan IP'sinde başarısız parola satırı yok; parola zaten elindeydi (zararlı çaldı). Başarısız "
                "denemeleri yapan IP başka bir hesaba saldırıyordu ve hiç giriş yapamadı.")
    return ("Yanlış. Kurban o sırada kendi cihazıyla evdeki/ofisteki IP'den çalışıyordu; farklı kıtadaki bilinmeyen cihaz ve "
            "makinedeki zararlı izi saldırganı gösteriyor, kullanıcıyı değil.")


YONTEM_SIKLARI = [
    "Oturum çalma: saldırgan, çalınan çerezle zaten açık oturuma bindi ve MFA ekranını hiç görmedi",
    "MFA yorgunluğu: saldırgan çalıntı parolayla girip kullanıcıya onay isteği yağdırdı, biri onaylandı",
    "Parola tahmini: saldırgan çok sayıda parola deneyip doğrusunu buldu ve MFA devreye girmedi",
    "İç tehdit: kullanıcının kendisi, kimliğini başka kıtadaki bir cihazdan bilerek kullandı",
]


def _hesap_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["c"]:
        return "Bu kullanıcı şehir değiştirmiş ama sabahtan akşama, Türkiye içinde: makul. İmkânsız olan, dakikalar içinde çok uzak şehir."
    if g == v["d"]:
        return "Bu kullanıcının oturumu iki IP'de ama ikisi de aynı şehirde (telefon/ofis geçişi). Şehir farkı ve süre aranıyor."
    if g == v["f"]:
        return "Bu hesaba başarısız parola denemesi yapılmış ama hiç başarılı giriş yok; hesap devralınmamış."
    if g == v["g"]:
        return "Bu kullanıcının makinesinde zararlı var ama hesabından anormal giriş yok. Girişler dosyasında seyahat izi arayan hesap."
    return None


def _ip_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["ev_ip"]:
        return "Bu, kurbanın kendi (meşru) IP'si. Hesaba farklı bir şehirden girenin IP'sini ara."
    if g == v["c2"]:
        return "Bu, zararlının veri gönderdiği sunucu (`uc_nokta.log`). Saldırganın GİRİŞ yaptığı IP `girisler.csv`'de."
    if g == v["ip_f"]:
        return "Bu IP başka bir hesaba başarısız parola denemesi yapmış; kurbanın hesabına girmiş IP değil."
    if g == v["ip_d2"]:
        return "Bu, meşru bir kullanıcının aynı şehirdeki ikinci IP'si (telefon). Kurbanın hesabında yabancı şehirden giren IP lazım."
    return None


def _oturum_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["sid_d"].casefold():
        return "Bu oturum iki IP'de ama ikisi de aynı şehirde, meşru kullanıcı. Saldırganın IP'sinin kullandığı oturumu ara."
    if g == v["sid_a"].casefold() and g != v["sid_x"].casefold():
        return "Bu, kurbanın kendi evdeki IP'sinden açtığı oturum. Saldırganın IP'sinin satırlarındaki oturum_id aranıyor."
    return None


def _mfa_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["mfa_sayi"] + 1:
        return ("Kurbanın kendi, meşru girişindeki tek isteği de saymışsın. Sadece SALDIRGAN IP'sinden gelenleri say "
                "(`mfa_istegi` + o IP).")
    if n == v["mfa_sayi"] + 4 or (v["mfa_sayi"] == 0 and n == 4):
        return "Başka kullanıcıların isteklerini de eklemişsin. Hesap ve saldırgan IP'sine göre filtrele."
    return None


def _makine_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == b.senaryo["cevaplar"]["hesap"].casefold():
        return "Bu hesabın kullanıcı adı. Makine adı `host=` alanındadır (örn. PC-...)."
    if g == norm(_akis(b.senaryo["_alt"])["g"]):
        return "Bu, başka bir kullanıcı adı. Ele geçen hesabın kendi `kullanici=` satırlarındaki `host=` değeri lazım."
    return None


def coz(lab: Path, s: dict) -> dict:
    hesap = seyahat_cozumu("girisler.csv", lab)
    ip = sh(f"LC_ALL=C sort girisler.csv | awk -F, -v k='{hesap}' '$2==k && $1!=\"zaman\" {{ if (!h) h=$4; "
            f"else if ($4!=h) print $3 }}' | sort -u | head -1", lab)
    # yöntem: saldırgan IP'sinden MFA isteği var mı? (kontrolün şıkları tohumla karışır; 'yontem' sayısı doğrudan çözülmez,
    # Secmeli için harf, kontrolün kendi cevabi_goster'inden alınır — rehber bölüm 10)
    mfa = sh(f"grep mfa_istegi girisler.csv | grep -c ',{hesap},{ip},'", lab)
    oturum = sh(f"awk -F, -v k='{hesap}' -v i='{ip}' '$2==k && $3==i && $8!=\"-\" {{print $8}}' girisler.csv | sort -u | head -1", lab)
    makine = sh(f"grep 'kullanici={hesap} ' uc_nokta.log | grep veri_sizdirma | grep -o 'host=[^ ]*' | cut -d= -f2 | head -1", lab)
    return sec_doldur({1: hesap, 2: ip, 4: oturum, 5: mfa, 6: makine}, GOREVLER, lab, s)


GOREVLER = [
    Gorev("`girisler.csv` içinde bir kullanıcı hesabı devralınmış. **İmkânsız seyahat** yapan hesap hangisi? "
          "(Kısa sürede, çok uzak iki şehirden başarılı giriş ya da oturum kullanımı.)",
          Metin("hesap", sik_hatalar=_hesap_hata, bicim="kullanıcı adı"),
          ("Birden fazla şehirden girenleri listele, sonra aralarındaki süreye bak. Saatler değil dakikalar arıyoruz.",
           "`cut -d, -f2,4 girisler.csv | sort -u | cut -d, -f1 | uniq -d` aday verir; adayı `grep <ad> girisler.csv | sort -t, -k1` "
           "ile zamana diz. Yalnız `basarili` ve `oturum_kullanimi` satırları giriş sayılır.",
           "Aday kullanıcılardan birinde Türkiye şehri ile yurt dışı şehri arasında 3 saatten kısa süre var; diğerlerinde ya "
           "saatler var ya şehirler yakın ya da hiç başarılı giriş yok."),
          puan=15, baslik="Ele geçen hesap"),
    Gorev("Bu hesaba, kullanıcının kendi şehri dışından giren **saldırganın kaynak IP**'si hangisi? (Zararlının veri "
          "gönderdiği sunucu bu değildir.)",
          IP("ip", sik_hatalar=_ip_hata),
          ("Kullanıcının hep aynı şehirden girdiğini görürsün; farklı şehirden gelen satırların IP'sine bak.",
           "`grep <hesap> girisler.csv | cut -d, -f1,3,4,6,7`: kullanıcının olağan IP/şehri ile yabancı şehirdeki IP.",
           "`awk -F, '$2==\"<hesap>\" && $4!=\"<kullanıcının şehri>\" {print $3}' girisler.csv | sort -u`"),
          puan=15, baslik="Saldırgan IP"),
    Gorev("Saldırgan hesabı **hangi yöntemle** devraldı? Kanıt hem girişlerde (MFA isteği var mı, oturum nereden "
          "doğdu?) hem uç nokta kaydında (hangi veri çalınmış?) aranır.",
          YontemSecmeli(YONTEM_SIKLARI, _yontem_aciklama),
          ("Saldırgan IP'sinin satırlarında `mfa_istegi` ve `oturum_id` sütunlarına bak: kullanıcıdan onay istenmiş mi?",
           "`grep <saldırgan IP> girisler.csv | cut -d, -f6,7,8`; ayrıca `grep <hesap> uc_nokta.log | grep veri_sizdirma`: "
           "`icerik=` alanı hangi veriyi söylüyor?",
           "Saldırgan IP'sinde MFA isteği YOKSA ve `icerik` çerezi içeriyorsa oturum çalma; art arda MFA istekleri ve sonda "
           "`push-onaylandi` varsa MFA yorgunluğu."),
          puan=20, baslik="Devralma yöntemi"),
    Gorev("Saldırganın IP'sinin içeride kullandığı **oturum_id** nedir?",
          Metin("oturum", sik_hatalar=_oturum_hata, bicim="S-... oturum kimliği"),
          ("Saldırgan IP'sinin satırlarının `oturum_id` sütununa bak.",
           "`awk -F, '$3==\"<saldırgan IP>\" && $8!=\"-\" {print $8}' girisler.csv | sort -u`",
           "Sonuç tek bir oturum_id olmalı; değilse yanlış IP'ye bakıyorsun. Başka IP'lerde aynı oturum_id'yi ayrıca görebilirsin, "
           "yanıltmasın."),
          puan=15, baslik="Çalınan/kullanılan oturum"),
    Gorev("Saldırganın IP'sinden bu hesaba kaç **MFA isteği** (`mfa_istegi`) gönderilmiş? (Hiç yoksa 0 yaz. "
          "Kurbanın kendi girişindeki isteği sayma.)",
          Sayi("mfa_sayi", sik_hatalar=_mfa_hata),
          ("Sadece saldırganın IP'sinden gelen `mfa_istegi` satırlarını say, hesaba da dikkat et.",
           "`grep mfa_istegi girisler.csv | grep ',<hesap>,<saldırgan IP>,' | wc -l` ya da `grep -c`.",
           "Sonuç 0 çıkabilir: bazı saldırılarda MFA hiç sorulmaz. Bu da cevabın bir parçasıdır, yöntemi ele verir."),
          puan=15, baslik="MFA istek sayısı"),
    Gorev("Kurbanın kimlik bilgilerini sızdıran zararlı hangi **makinede** çalışmış? `uc_nokta.log` içinde ele geçen "
          "hesabın `veri_sizdirma` satırındaki `host=` değerini yaz. (Başka bir makinede de zararlı izi var; hesabı "
          "kullanan makine aranıyor.)",
          Metin("makine", sik_hatalar=_makine_hata, bicim="host adı (PC-...)"),
          ("Uç nokta kaydında kullanıcı adıyla ara; hangi satırlar veri dışarı göndermiş?",
           "`grep 'kullanici=<hesap> ' uc_nokta.log | grep veri_sizdirma`: satırın `host=` alanı.",
           "`grep 'kullanici=<hesap> ' uc_nokta.log | grep veri_sizdirma | grep -o 'host=[^ ]*'`"),
          puan=15, baslik="Bulaşan makine"),
    Gorev("Bulgularla şimdi **en doğru müdahale** hangisi?",
          Secmeli([
              ("Hesabın tüm açık oturumlarını iptal et, parolayı sıfırla, MFA'yı yeniden kaydettir ve bulaşan makineyi "
               "ağdan ayırıp temizle",
               "Doğru. Çalınan oturum parolayla ölmez: oturumları iptal etmek şart; parola ve MFA kaydı da güvenilmez olduğu "
               "için yenilenir; zararlı temizlenmezse hepsi tekrar çalınır."),
              ("Yalnızca parolayı sıfırla ve kullanıcıya yeni parolayı güçlü seçmesini söyle; oturum ve MFA kayıtları "
               "olduğu gibi kalsın",
               "Yanlış. Saldırgan çalıntı oturumla ya da onaylanmış MFA ile içeride; parola değişimi ne açık oturumu "
               "kapatır ne de zararlıyı temizler."),
              ("Saldırganın IP'sini güvenlik duvarında engelle ve olayı kapat; IP değişirse yeniden bakarız, "
               "başka işlem gerekmez",
               "Yanlış. Saldırgan IP'sini bir dakikada değiştirir; üstelik çalınan oturum ve zararlı olduğu yerde duruyor. "
               "IP engeli bir eksiktir, çözüm değildir."),
              ("Kullanıcıya hesabında şüpheli işlem olduğunu e-postayla bildir ve bir hafta boyunca girişleri izle; "
               "o sürede başka işlem yapma",
               "Yanlış. Bir hafta boyunca saldırganın veriyi çekmesine izin verilir. İzleme gerekli ama oturum iptali ve "
               "parola/MFA sıfırlama beklemeden yapılmalı."),
          ], dogru=0),
          ("Saldırganın elinde ne var: yalnızca parola mı, yoksa ondan bağımsız bir şey de mi?",
           "Parola değişimi, çalınmış oturumu ve çalınmış/onaylanmış MFA kaydını ortadan kaldırmaz; zararlı makinede kalırsa yenisini de çalar.",
           "Doğru cevap hepsini birden yapar: oturumları iptal, parola sıfırla, MFA yeniden kaydet ve makineyi temizle."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_kimlik",
    cilt=7,
    bolum=116,
    baslik="Kimlik Merkezli Saldırı: Hesabı Kim Devraldı?",
    brifing="""
Deniz Kara ekranını sana çeviriyor: "**<<musteri>>** (<<sektor>>) acil yardım istedi. <<hikaye>> <<kisi>> bize iki dosya
yolladı: `girisler.csv` (kimlik sağlayıcının giriş dökümü) ve `uc_nokta.log` (makinelerin güvenlik kaydı)."

"Kimse parolayı kırmamış; kapıdan **anahtarla** girmişler. Ya çalınmış bir oturum çerezi ya da yorgun bir kullanıcıya
yağdırılmış onay bildirimleri. Hangi hesap, hangi IP, hangi yöntem? Kayıtları oku, yöntemi kanıtla, sonra ne yapacağımıza
karar ver. Hepsi kurgusal, güvenle oku." Mert ekliyor: "Dosyalarda gürültü çok: makul seyahatler, telefona geçen
kullanıcılar, başka hesaba başarısız denemeler. Hepsi saldırı değil."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Saldırgan için en ucuz yol artık kırmak değil, çalmak: bilgi çalan zararlı parolayı ve çerezi alır, çerez
MFA'yı bile atlar; çalıntı parolayla da kullanıcıyı yorarak onay koparılır. Savunmacı için ders: giriş kaydındaki şehir, cihaz,
süre ve MFA tekrarını alışkanlıkla karşılaştır; çalınan oturum parola değişince ölmez, o yüzden oturum iptali olay müdahalesinin
ilk adımıdır. Önleme tarafında: sayı eşleştirmeli ya da donanım anahtarlı MFA, kısa oturum ömrü, oturumu cihaza bağlama,
imkânsız seyahat ve tekrarlı MFA alarmı, uç noktada bilgi çalan zararlı tespiti.
""",
    gercek_hayat="""
- **Snowflake müşteri hesapları, 2024:** Mandiant'ın (Google) kamuya açıkladığı soruşturmaya göre, bir saldırgan grubu çok
  sayıda Snowflake müşteri hesabına **infostealer zararlılarıyla çalınmış kimlik bilgileriyle** ve MFA olmadığı için girdi.
  Bu görevdeki beceri: giriş dökümünde doğru parola ama yanlış alışkanlık izini görmek.
- **Uber, 2022:** Saldırgan çalıntı parolayla giriş yapıp çalışana art arda MFA bildirimi yolladı ve bir onay aldı. Önleme:
  sayı eşleştirme ya da donanım anahtarı; tespit: kısa sürede çok sayıda MFA isteği alarmı.
- **Infostealer ekosistemi:** Lumma (Mayıs 2025'te hukuki/teknik operasyonla aksatıldı) ve RedLine (Ekim 2024, Operation Magnus)
  gibi ailelerin çaldığı parola ve oturum çerezleri yeraltında satılır. Önleme: uç nokta koruması, yönetilen tarayıcı
  politikası, kısa oturum ömrü; tespit: oturumun yeni IP/cihazdan kullanımı ve imkânsız seyahat.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b09",),
)
