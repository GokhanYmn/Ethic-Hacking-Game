"""Hayat Modu (Aşama 1-2) — hacker kariyeri / yaşam simülasyonu çerçevesi.

Mevcut oyunu **sarar, yeniden yazmaz**: gerçek görevler yine mevcut motorla çalışır
(`lab_kur` + `gorev_kabugu`); bu modül etrafına kariyer çerçevesi örer:

    daire → gelen kutusu (farklı kuruluş/zorluk/hikâye) → kabul/reddet/ertele
          → gerçek terminal görevi → maaş (para/itibar/XP, zorluğa göre)
          → "Gerçek Hayatta" debrief → hikâye kıpırtısı → uyu (gün +1)

Aşama 2 ekler: kalıcı gelen kutusu (günler arası), **itibar kademeleri** (daha çok itibar =
daha büyük işler + daha iyi ödeme), **dükkân/ekipman** (parayı harca, kalıcı fayda al),
rütbe + günlük seri göstergesi, isteğe bağlı "ana ekran yap" düğmesi.

İçerik (ev lab, komplo hikâyesi, 2-3× görev) sonraki aşamalarda. Terminal işi hiç değişmez.
"""
from __future__ import annotations

import random
import re
import time

from hy.motor import arayuz as ui
from hy.motor import zorluk
from hy.motor.kabuk import gorev_kabugu, lab_kur
from hy.motor.kayit import Kayit
from hy.motor.rutbe import rutbe
from hy.olay_masasi import izin_denetimi, olay_bulut, olay_zaman, ssh_kaba_kuvvet, web_logu

# ------------------------------------------------------------------ sahne / ASCII

MASA = r"""
        .------------------.
        |  $ _             |
        |                  |
        |                  |
        '------------------'
       /====================\
"""

DK = "╭────╮\n│ DK │\n╰────╯"  # Deniz Kara avatarı

# ------------------------------------------------------------------ iş aileleri (anahtarla)
# Aileler dosya tabanlı ve servissiz; her iş: aile × kuruluş × zorluk × hikâye.

ISLER = {
    "web": {
        "sv": web_logu.SEVIYE,
        "konu": "Erişim logunda bir saldırgan var",
        "cerceve": "{kurulus} ({sektor}) saldırıya uğradı. Erişim logunu gönderdiler — kim, "
                   "nasıl, ne kadar ilerlemiş? Saldırgan IP'leri çıkar, imzaları ayır.",
        "taban": 130,
    },
    "ssh": {
        "sv": ssh_kaba_kuvvet.SEVIYE,
        "konu": "SSH'a gece boyu kaba kuvvet yağmış",
        "cerceve": "{kurulus} ({sektor}) sunucusuna yüzlerce başarısız SSH girişi gelmiş. "
                   "Kayıtları incele: biri içeri girdi mi, kalıcılık bıraktı mı?",
        "taban": 130,
    },
    "izin": {
        "sv": izin_denetimi.SEVIYE,
        "konu": "Bir sunucuda yetki denetimi lazım",
        "cerceve": "{kurulus} ({sektor}) bir sunucuda tuhaflık seziyor. İzinleri, cron'u ve "
                   "SUID'leri denetle: açık kapı, arka kapı hesap, şüpheli SUID var mı?",
        "taban": 150,
    },
    "zaman": {
        "sv": olay_zaman.SEVIYE,
        "konu": "Bir ihlalin zaman çizelgesini çıkar",
        "cerceve": "{kurulus} ({sektor}) ihlal edildi ama kimse sıralamayı bilmiyor. Loglardan "
                   "zaman çizelgesini kur: nereden girdiler, hangi hesap düştü, ne sızdı, ne kadar "
                   "fark edilmediler?",
        "taban": 160,
    },
    "bulut": {
        "sv": olay_bulut.SEVIYE,
        "konu": "Bulut yapılandırmasını denetle",
        "cerceve": "{kurulus} ({sektor}) buluta taşındı ama kimse ayarlara bakmadı. Depolama, IAM "
                   "ve güvenlik gruplarını denetle: herkese açık kaynak, aşırı yetki, internete açık "
                   "port, sızmış anahtar var mı?",
        "taban": 170,
    },
}

# İtibar kademeleri: (eşik, ad, uygun aileler, uygun zorluklar, ödül çarpanı)
KADEMELER = [
    (0,   "Çaylak Freelancer", ["web", "ssh"],                           ["kolay", "normal"],        1.00),
    (25,  "Tanınan İsim",      ["web", "ssh", "izin", "zaman"],          ["kolay", "normal", "zor"], 1.15),
    (70,  "Aranan Uzman",      ["web", "ssh", "izin", "zaman", "bulut"], ["normal", "zor"],          1.30),
    (150, "Kurumsal Danışman", ["web", "ssh", "izin", "zaman", "bulut"], ["normal", "zor"],          1.50),
]

# Ekipman: parayla alınır, kalıcı fayda verir (etkiler bu katmanda uygulanır).
EKIPMAN = {
    "kahve":      {"ad": "İyi Kahve Makinesi", "fiyat": 400,  "aciklama": "Her yeni günde +₺50",      "gunluk": 50},
    "genis_masa": {"ad": "Geniş Masa",          "fiyat": 700,  "aciklama": "Gelen kutusu +1 iş tutar", "kutu": 1},
    "pazarlikci": {"ad": "Pazarlıkçı",          "fiyat": 1100, "aciklama": "İş ödemesi +%15",          "pay": 0.15},
    "menajer":    {"ad": "İtibar Menajeri",     "fiyat": 1600, "aciklama": "Tamamlanan işte +2 itibar","itibar": 2},
}

KUTU_TABAN = 3  # gelen kutusunda tutulacak aktif iş sayısı (+ Geniş Masa)

# Ev lab kademeleri: (fiyat, ad, günlük_pasif_gelir, açıklama). Kademe 0 = lab yok.
LAB_KADEMELERI = [
    (0,    "—",                   0,   "Lab yok."),
    (1500, "Köşe Lab",            80,  "Eski bir dizüstü + bir anahtar. Küçük ama seninki."),
    (4000, "Donanımlı Lab",       200, "Raspberry Pi kümesi + switch. Artık ciddi iş çıkar."),
    (9000, "Tam Teşekküllü Lab",  450, "Raf, sanallaştırma, ayrı ağ. Evinde bir SOC."),
]

HIKAYELER = [
    "Deniz: *\"İlk işini kapattın. Küçük ama temiz — bu çevrede isim böyle yayılır.\"*",
    "Deniz: *\"Biri seni sormuş bugün. İyi anlamda... sanırım.\"* Adın dolaşmaya başladı.",
    "Deniz: *\"Rakip bir isim — 'Kestane' — aynı müşteriye talip olmuş. Hızlı olmakta fayda var.\"*",
    "Masanda bir not: *son vakalardaki saldırgan IP'leri garip biçimde aynı bloklardan çıkıyor.* "
    "Tesadüf mü, yoksa bir örüntü mü? Deniz omuz silkti ama gözleri gülmüyordu.",
]


# ------------------------------------------------------------------ durum / yardımcılar

def _durumu(kayit: Kayit) -> dict:
    dur = kayit.veri.setdefault("yasam", {})
    dur.setdefault("gun", 1)
    dur.setdefault("para", 0)
    dur.setdefault("itibar", 0)
    dur.setdefault("tamamlanan_is", 0)
    dur.setdefault("ekipman", [])
    dur.setdefault("kutu", [])
    dur.setdefault("sonraki_no", 1)
    dur.setdefault("gorulen_kademe", 0)
    dur.setdefault("tanisildi", False)
    dur.setdefault("lab", 0)        # ev lab kademesi (0 = yok)
    return dur


def _sv(anahtar: str):
    return ISLER[anahtar]["sv"]


def _kademe(itibar: int):
    idx = 0
    for i, k in enumerate(KADEMELER):
        if itibar >= k[0]:
            idx = i
    return idx, KADEMELER[idx]


def _ekipman_etki(dur: dict) -> dict:
    etki = {"gunluk": 0, "kutu": 0, "pay": 0.0, "itibar": 0}
    for a in dur.get("ekipman", []):
        e = EKIPMAN.get(a, {})
        for k in etki:
            etki[k] += e.get(k, 0)
    return etki


def _odul_max(job: dict, dur: dict) -> int:
    """İşin tam çözümde ödeyeceği para (güncel kademe + ekipmanla)."""
    sab = ISLER[job["anahtar"]]
    _, kad = _kademe(dur["itibar"])
    gear = _ekipman_etki(dur)
    kat = zorluk.ZORLUKLAR[job["zorluk"]]["xp"] * kad[4] * (1 + gear["pay"])
    return round(sab["taban"] * len(sab["sv"].gorevler) * kat)


def _teaser(sv) -> str | None:
    m = re.search(r"\*\*(.+?)\*\*", getattr(sv, "gercek_hayat", "") or "")
    return m.group(1).rstrip(":").strip() if m else None


def _temiz(metin: str) -> str:
    return re.sub(r"<<[^>]+>>", "", metin or "")


def _zorluk_rozet(z: str) -> str:
    d = zorluk.ZORLUKLAR[z]
    renk = {"kolay": "yesil", "normal": "camgobegi", "zor": "sari", "gercekci": "kirmizi"}.get(z, "camgobegi")
    return ui.r(f"{d['simge']} {d['ad']}", renk, "kalin")


def _is_uret(anahtar: str, zorluk_key: str, no: int) -> dict:
    """Serileştirilebilir bir iş teklifi (kutuda saklanır). Tohum sabitlenir: kuruluş/hikâye kalıcı."""
    sv = _sv(anahtar)
    tohum = random.SystemRandom().randrange(1, 10 ** 9)
    metin = sv.senaryo(tohum).get("metin", {})
    return {
        "no": no, "anahtar": anahtar, "zorluk": zorluk_key, "tohum": tohum,
        "kurulus": metin.get("musteri", "bir müşteri"), "sektor": metin.get("sektor", ""),
        "durum": "yeni",
    }


def _kutu_doldur(kayit: Kayit) -> dict:
    """Gelen kutusunu, mevcut kademeye uygun işlerle hedef sayıya tamamlar. Ertelenenler korunur."""
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    aileler, zorluklar = kad[2], kad[3]
    zor_secenek = [x for x in ("kolay", "normal", "zor") if x in zorluklar]
    hedef = KUTU_TABAN + _ekipman_etki(dur)["kutu"]
    # bitmiş/reddedilmiş işleri at (kutuyu küçük tut); kalanları say
    dur["kutu"] = [j for j in dur["kutu"] if j["durum"] in ("yeni", "ertelendi")]
    varolan = {(j["anahtar"], j["kurulus"]) for j in dur["kutu"]}
    while len(dur["kutu"]) < hedef:
        job = None
        for _ in range(6):   # aynı kuruluş/aile tekrarından kaçınmaya çalış (çeşitlilik)
            aday = _is_uret(random.choice(aileler), random.choice(zor_secenek), dur["sonraki_no"])
            if (aday["anahtar"], aday["kurulus"]) not in varolan:
                job = aday
                break
        if job is None:
            job = aday
        varolan.add((job["anahtar"], job["kurulus"]))
        dur["kutu"].append(job)
        dur["sonraki_no"] += 1
    return dur


def _vaka_kur(kayit: Kayit, sv, tohum: int) -> None:
    """Seviye durumuna SABİT tohumlu bir vaka yazar (yeni_deneme'nin sabit-tohumlu hali)."""
    d = kayit.seviye(sv.kimlik)
    d["tohum"] = tohum
    d["deneme"] = int(d.get("deneme", 0)) + 1
    d["carpan"] = 1.0
    d["cozulen"], d["ipucu"], d["yanlis"] = {}, {}, {}
    d["baslangic"] = time.strftime("%Y-%m-%d %H:%M")
    d["bitis"] = None
    d["iz"], d["iz_uyari"] = 0, False
    kayit.kaydet()


# ------------------------------------------------------------------ ekranlar

def _hud(kayit: Kayit) -> str:
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    rb = rutbe(kayit.veri["xp"])
    seri = kayit.veri.get("seri", {}).get("gun_sayisi", 0)
    ad = kayit.veri["oyuncu"].get("ad") or "Stajyer"
    s1 = (f"  {ui.r('Gün ' + str(dur['gun']), 'kalin')}   "
          f"{ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}   "
          f"{ui.r('İtibar ' + str(dur['itibar']), 'sari')}   {ui.r(ad, 'gri')}")
    s2 = (f"  {ui.r(kad[1], 'mor', 'kalin')}   ·   Rütbe {rb['ad']} ({kayit.veri['xp']} XP)"
          + (f"   ·   🔥 {seri} gün" if seri and seri > 1 else ""))
    return s1 + "\n" + s2


def _daire(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Daire · gece", "mor"))
    print(ui.r(MASA, "gri"))
    print(ui.r("  Pencerede yağmur. Kahven soğumuş, terminal açık.", "gri"))
    print()
    print(_hud(kayit))


def _eposta_goster(job: dict, dur: dict) -> None:
    sv = _sv(job["anahtar"])
    sab = ISLER[job["anahtar"]]
    teaser = _teaser(sv)
    govde = sab["cerceve"].format(kurulus=ui.r(job["kurulus"], "kalin"), sektor=job["sektor"])
    satirlar = [
        "**Kimden:** Deniz Kara  (fikser)",
        f"**Konu:** {sab['konu']}",
        "",
        govde,
        "",
        f"Zorluk: {_zorluk_rozet(job['zorluk'])}   ·   Ödül: "
        f"{ui.r('₺' + str(_odul_max(job, dur)), 'yesil')} (tam çözümde) + itibar + XP",
    ]
    if teaser:
        satirlar.append(f"Not: geçmişte benzer bir olay — **{teaser}**.")
    ui.temizle()
    for ln in DK.splitlines():
        print("  " + ui.r(ln, "camgobegi"))
    print(ui.kutu("GELEN KUTUSU", "\n".join(satirlar), "mavi"))


def _dukkan(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        ui.temizle()
        print(ui.baslik_cubugu("Dükkân · ekipman", "camgobegi"))
        print(ui.r("  Kazandığın parayı kalıcı faydaya çevir.", "gri"))
        print(f"\n  Kasanda: {ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}\n")
        secenekler = []
        for i, (a, e) in enumerate(EKIPMAN.items(), 1):
            if a in dur["ekipman"]:
                durum = ui.r("✔ sende", "yesil")
            elif dur["para"] >= e["fiyat"]:
                durum = ui.r("₺" + str(e["fiyat"]), "sari", "kalin")
            else:
                durum = ui.r(f"₺{e['fiyat']} (yetersiz)", "gri")
            print(f"  [{ui.r(str(i), 'camgobegi', 'kalin')}] {e['ad']} — {e['aciklama']}   {durum}")
            secenekler.append((str(i), a, e))
        print(f"\n  [{ui.r('q', 'camgobegi')}] Geri")
        secim = ui.sor("\n  Ne alalım? ").lower().strip()
        if secim == "q":
            return
        es = next((x for x in secenekler if x[0] == secim), None)
        if not es:
            continue
        _, a, e = es
        if a in dur["ekipman"]:
            print(ui.bilgi("Zaten sende."))
            ui.bekle()
        elif dur["para"] < e["fiyat"]:
            print(ui.hata("Paran yetmiyor. Birkaç iş daha kapat."))
            ui.bekle()
        else:
            dur["para"] -= e["fiyat"]
            dur["ekipman"].append(a)
            kayit.kaydet()
            print(ui.basari(f"{e['ad']} alındı! {e['aciklama']}"))
            ui.bekle()


def _lab_gelir(dur: dict) -> int:
    return LAB_KADEMELERI[dur.get("lab", 0)][2]


def _pratik(kayit: Kayit) -> None:
    """Ev lab'ında ücretsiz antrenman: rastgele bir aile; para/itibar yok, sadece XP."""
    sv = _sv(random.choice(list(ISLER)))
    tohum = random.SystemRandom().randrange(1, 10 ** 9)
    _vaka_kur(kayit, sv, tohum)
    xp_once = kayit.veri["xp"]
    lab = lab_kur(sv, sv.senaryo(tohum))
    print(ui.bilgi(f"Antrenman: {sv.baslik}. Para yok, sadece pratik ve XP. "
                   f"Çıkmak için kabukta {ui.r('cik', 'camgobegi')} yaz."))
    ui.bekle("Hazırsan Enter")
    gorev_kabugu(sv, lab)
    kazanc = Kayit().veri["xp"] - xp_once
    print(ui.basari(f"Antrenman bitti. +{kazanc} XP.") if kazanc else ui.r("  Antrenman bitti.", "gri"))
    ui.bekle()


def _lab_ekrani(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        kademe = dur["lab"]
        ui.temizle()
        print(ui.baslik_cubugu("Ev Lab", "camgobegi"))
        if kademe:
            print(f"  Mevcut: {ui.r(LAB_KADEMELERI[kademe][1], 'kalin')}  ·  "
                  f"pasif gelir {ui.r('₺' + str(_lab_gelir(dur)) + '/gün', 'yesil')}")
        else:
            print(ui.r("  Henüz lab'ın yok. Kendi poligonun: hem pasif gelir hem bedava antrenman.", "gri"))
        print(f"  Kasanda: {ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}\n")
        secenekler = []
        if kademe < len(LAB_KADEMELERI) - 1:
            fiyat, ad, gelir, acik = LAB_KADEMELERI[kademe + 1]
            etk = (ui.r("₺" + str(fiyat), "sari", "kalin") if dur["para"] >= fiyat
                   else ui.r(f"₺{fiyat} (yetersiz)", "gri"))
            print(f"  [{ui.r('y', 'camgobegi', 'kalin')}] {'Lab kur' if not kademe else 'Yükselt'}: "
                  f"{ad} — {acik}  (+₺{gelir}/gün)  {etk}")
            secenekler.append("y")
        if kademe:
            print(f"  [{ui.r('p', 'camgobegi', 'kalin')}] Antrenman yap (bedava, XP kazan)")
            secenekler.append("p")
        print(f"\n  [{ui.r('q', 'camgobegi')}] Geri")
        secim = ui.sor("\n  Ne yapalım? ").lower().strip()
        if secim == "q":
            return
        if secim == "y" and "y" in secenekler:
            fiyat, ad, gelir, _ = LAB_KADEMELERI[kademe + 1]
            if dur["para"] < fiyat:
                print(ui.hata("Paran yetmiyor. Birkaç iş daha kapat."))
                ui.bekle()
            else:
                dur["para"] -= fiyat
                dur["lab"] = kademe + 1
                kayit.kaydet()
                print(ui.basari(f"{ad} kuruldu! Her gün +₺{gelir} ve bedava antrenman."))
                ui.bekle()
        elif secim == "p" and "p" in secenekler:
            _pratik(kayit)


def _is_oyna(kayit: Kayit, job: dict, oyuncu_zorluk: str) -> dict:
    """İşi gerçek terminalde oynatır; zorluğu geçici uygular, sonra geri yükler. Maaş döndürür."""
    sv = _sv(job["anahtar"])
    _vaka_kur(kayit, sv, job["tohum"])
    kayit.veri["ayarlar"]["zorluk"] = job["zorluk"]
    kayit.kaydet()
    xp_once = kayit.veri["xp"]
    rutbe_once = rutbe(xp_once)["ad"]

    senaryo = sv.senaryo(job["tohum"])
    lab = lab_kur(sv, senaryo)
    print(ui.bilgi(f"İşe giriyorsun: {ui.r(job['kurulus'], 'kalin')} — {sv.baslik} "
                   f"({_zorluk_rozet(job['zorluk'])}). Menüye dönmek için kabukta "
                   f"{ui.r('cik', 'camgobegi')} yaz."))
    ui.bekle("Hazırsan Enter")
    gorev_kabugu(sv, lab)

    kayit = Kayit()
    d = kayit.seviye(sv.kimlik)
    cozulen = len(d.get("cozulen", {}))
    toplam = len(sv.gorevler)
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    gear = _ekipman_etki(dur)
    z_xp = zorluk.ZORLUKLAR[job["zorluk"]]["xp"]
    para = round(ISLER[job["anahtar"]]["taban"] * cozulen * z_xp * kad[4] * (1 + gear["pay"]))
    itibar = round(cozulen * z_xp) + (gear["itibar"] if cozulen else 0)
    xp_kazanc = kayit.veri["xp"] - xp_once
    rutbe_sonra = rutbe(kayit.veri["xp"])["ad"]

    dur["para"] += para
    dur["itibar"] += itibar
    tam = cozulen == toplam and bool(toplam)
    if tam:
        dur["tamamlanan_is"] += 1
    kayit.veri["ayarlar"]["zorluk"] = oyuncu_zorluk
    kayit.kaydet()
    return {"kayit": kayit, "cozulen": cozulen, "toplam": toplam, "para": para,
            "itibar": itibar, "xp": xp_kazanc, "tam": tam,
            "rutbe_atladi": rutbe_sonra if rutbe_sonra != rutbe_once else None}


def _maas_ekrani(sonuc: dict, sv) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Maaş günü", "yesil"))
    oran = sonuc["cozulen"] / max(1, sonuc["toplam"])
    print("  " + ui.ilerleme(oran, 24) + f"  {sonuc['cozulen']}/{sonuc['toplam']} görev")
    print()
    if sonuc["cozulen"] == 0:
        print(ui.r("  İşi yarıda bıraktın — bu sefer ödeme yok. Olur böyle, yeni gün yeni fırsat.", "gri"))
    else:
        print(f"  Kazanç:  {ui.r('+₺' + str(sonuc['para']), 'yesil', 'kalin')}"
              f"   ·   İtibar {ui.r('+' + str(sonuc['itibar']), 'sari')}"
              f"   ·   XP {ui.r('+' + str(sonuc['xp']), 'camgobegi')}")
        if sonuc["tam"]:
            print(ui.basari("Tam çözüm! Müşteri memnun, adın bir çevre daha genişledi."))
    if sonuc.get("rutbe_atladi"):
        print(ui.kutu("RÜTBE ATLADIN", f"Yeni rütbe: **{sonuc['rutbe_atladi']}**. Deniz başını salladı: *\"Hak ettin.\"*", "sari"))
    if getattr(sv, "gercek_hayat", ""):
        print()
        print(ui.kutu("GERÇEK HAYATTA", _temiz(sv.gercek_hayat), "mor"))
    ui.bekle()


def _terfi_kontrol(kayit: Kayit) -> None:
    dur = _durumu(kayit)
    idx, kad = _kademe(dur["itibar"])
    if idx > dur.get("gorulen_kademe", 0):
        dur["gorulen_kademe"] = idx
        kayit.kaydet()
        print(ui.kutu("TERFİ", f"İtibarın yükseldi: **{kad[1]}**. Daha büyük işler ve daha iyi "
                              f"ödemeler açıldı. Gelen kutun artık farklı.", "sari"))
        ui.bekle()


def _hikaye_kipirti(kayit: Kayit) -> None:
    dur = _durumu(kayit)
    idx = min(dur["tamamlanan_is"], len(HIKAYELER)) - 1
    if idx < 0:
        idx = random.randrange(len(HIKAYELER))
    ui.temizle()
    print(ui.baslik_cubugu("Gün biterken", "mor"))
    print(ui.kutu("HABER", HIKAYELER[idx], "camgobegi"))


# ------------------------------------------------------------------ ana döngü

def yasam_modu(kayit: Kayit) -> None:
    """Hayat Modu: kariyer / günlük iş döngüsü."""
    if not kayit.veri["oyuncu"].get("ad"):
        from hy.motor.oyun import karsilama
        karsilama(kayit)
        kayit = Kayit()
    kayit.gun_isaretle()
    oyuncu_zorluk = zorluk.anahtar(kayit)
    dur = _durumu(kayit)
    kayit.kaydet()

    if not dur["tanisildi"]:
        ui.temizle()
        print(ui.baslik_cubugu("Hayat Modu", "mor"))
        print(ui.md("""
Burası senin köşen. Gelen kutusuna işler düşer; okur, **kabul eder / reddeder / ertelersin**.
Kabul ettiğini **gerçek terminalde** çözersin — **para, itibar ve XP** kazanırsın. Zor işler
daha çok öder ama SOC seni arar. Parayı **dükkânda ekipmana** çevir; itibarın yükseldikçe
daha büyük işler açılır.

*(İlerlemen normal oyunla aynı kayıtta; `[a]` ile bunu oyunun ana ekranı yapabilirsin.)*
"""))
        dur["tanisildi"] = True
        kayit.kaydet()
        ui.bekle("Başlamak için Enter")

    _kutu_doldur(kayit)
    kayit.kaydet()

    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        _daire(kayit)
        print()
        aktif = [j for j in dur["kutu"] if j["durum"] in ("yeni", "ertelendi")]
        if not aktif:
            print(ui.r("  Gelen kutusu boş. Uyuyup yeni bir gün bekleyebilirsin.", "gri"))
        for j in aktif:
            etiket = ui.r(" (ertelendi)", "gri") if j["durum"] == "ertelendi" else ""
            print(f"  [{ui.r(str(j['no']), 'camgobegi', 'kalin')}] {ISLER[j['anahtar']]['konu']} — "
                  f"{ui.r(j['kurulus'], 'kalin')} · {_zorluk_rozet(j['zorluk'])} · "
                  f"{ui.r('₺' + str(_odul_max(j, dur)), 'yesil')}{etiket}")
        ana = kayit.veri["ayarlar"].get("hayat_ana")
        print(f"\n  [{ui.r('u', 'camgobegi')}] Uyu (yeni gün)   [{ui.r('s', 'camgobegi')}] Dükkân   "
              f"[{ui.r('l', 'camgobegi')}] Ev Lab   "
              f"[{ui.r('a', 'camgobegi')}] {'Normal menüye dön' if ana else 'Ana ekran yap'}   "
              f"[{ui.r('q', 'camgobegi')}] Çıkış")
        secim = ui.sor("\n  Ne yapalım? ").lower().strip()

        if secim == "q":
            kayit.kaydet()
            print(ui.r("\n  İyi geceler. Adın yayılıyor.", "gri"))
            return
        if secim == "u":
            dur["gun"] += 1
            kazanc = _ekipman_etki(dur)["gunluk"] + _lab_gelir(dur)
            if kazanc:
                dur["para"] += kazanc
            kayit.kaydet()
            _kutu_doldur(kayit)
            kayit.kaydet()
            if kazanc:
                print(ui.bilgi(f"Yeni gün. Pasif gelir: +₺{kazanc}."))
                time.sleep(0.8)
            continue
        if secim == "s":
            _dukkan(kayit)
            continue
        if secim == "l":
            _lab_ekrani(kayit)
            continue
        if secim == "a":
            yeni = not kayit.veri["ayarlar"].get("hayat_ana")
            kayit.veri["ayarlar"]["hayat_ana"] = yeni
            kayit.kaydet()
            print(ui.bilgi("Oyun artık doğrudan Hayat Modu'yla açılacak." if yeni
                           else "Oyun normal menüyle açılacak. (Hayat Modu menüde [d].)"))
            ui.bekle()
            continue
        if not secim.isdigit():
            continue
        job = next((j for j in dur["kutu"] if str(j["no"]) == secim and j["durum"] in ("yeni", "ertelendi")), None)
        if not job:
            continue

        _eposta_goster(job, dur)
        print(f"  [{ui.r('k', 'camgobegi', 'kalin')}] Kabul et    "
              f"[{ui.r('e', 'camgobegi')}] Ertele    "
              f"[{ui.r('r', 'camgobegi')}] Reddet    "
              f"[{ui.r('g', 'camgobegi')}] Geri")
        karar = ui.sor("\n  Kararın? ").lower().strip()
        if karar == "r":
            job["durum"] = "reddedildi"
            kayit.kaydet()
        elif karar == "e":
            job["durum"] = "ertelendi"
            kayit.kaydet()
        elif karar == "k":
            sonuc = _is_oyna(kayit, job, oyuncu_zorluk)
            k = sonuc["kayit"]
            for j in _durumu(k)["kutu"]:
                if j["no"] == job["no"]:
                    j["durum"] = "bitti"
            k.kaydet()
            _maas_ekrani(sonuc, _sv(job["anahtar"]))
            _terfi_kontrol(k)
            _kutu_doldur(k)
            k.kaydet()
            _hikaye_kipirti(k)
            ui.bekle()
