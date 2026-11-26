"""Hayat Modu (Aşama 1 prototipi) — hacker kariyeri yaşam-simülasyonu çerçevesi.

Mevcut oyunu **sarar, yeniden yazmaz**: gerçek görevler yine mevcut motorla çalışır
(`lab_kur` + `gorev_kabugu`); bu modül yalnızca etrafına bir "hayattan bir gün" çerçevesi örer:

    daire → gelen kutusu (farklı kuruluş/zorluk/hikâye) → kabul/reddet/ertele
          → gerçek terminal görevi → maaş (para/itibar/XP, zorluğa göre)
          → "Gerçek Hayatta" debrief → hikâye kıpırtısı → uyu (gün +1)

Bu bir prototip: ekonomi, ev lab, fraksiyon ve komplo omurgası sonraki aşamalarda gelir.
Terminal işi ve mevcut 940 görev hiç değişmez.
"""
from __future__ import annotations

import random
import re
import time

from hy.motor import arayuz as ui
from hy.motor import zorluk
from hy.motor.kabuk import gorev_kabugu, lab_kur
from hy.motor.kayit import Kayit
from hy.olay_masasi import izin_denetimi, ssh_kaba_kuvvet, web_logu

# ------------------------------------------------------------------ sahne / ASCII

MASA = r"""
        .------------------.
        |  $ _             |
        |                  |
        |                  |
        '------------------'
       /====================\
"""

DK = "╭────╮\n│ DK │\n╰────╯"  # Deniz Kara avatarı (satır satır kullanılır)

# ------------------------------------------------------------------ iş aileleri (prototip)
# Her iş bir kombinasyon: aile × kuruluş × zorluk × hikâye. Aileler dosya tabanlı ve servissiz.

ISLER = [
    {
        "anahtar": "web",
        "sv": web_logu.SEVIYE,
        "konu": "Erişim logunda bir saldırgan var",
        "cerceve": "{kurulus} ({sektor}) saldırıya uğradı. Erişim logunu gönderdiler — kim, "
                   "nasıl, ne kadar ilerlemiş? Saldırgan IP'leri çıkar, imzaları ayır.",
        "taban": 130,
    },
    {
        "anahtar": "ssh",
        "sv": ssh_kaba_kuvvet.SEVIYE,
        "konu": "SSH'a gece boyu kaba kuvvet yağmış",
        "cerceve": "{kurulus} ({sektor}) sunucusuna yüzlerce başarısız SSH girişi gelmiş. "
                   "Kayıtları incele: biri içeri girdi mi, kalıcılık bıraktı mı?",
        "taban": 130,
    },
    {
        "anahtar": "izin",
        "sv": izin_denetimi.SEVIYE,
        "konu": "Bir sunucuda yetki denetimi lazım",
        "cerceve": "{kurulus} ({sektor}) bir sunucuda tuhaflık seziyor. İzinleri, cron'u ve "
                   "SUID'leri denetle: açık kapı, arka kapı hesap, şüpheli SUID var mı?",
        "taban": 150,
    },
]

ZORLUK_HAVUZ = ["kolay", "normal", "zor"]      # prototipte Gerçekçi yok (çok sert)
ZORLUK_AGIRLIK = [3, 4, 3]

HIKAYELER = [
    "Deniz: *\"İlk işini kapattın. Küçük ama temiz — bu çevrede isim böyle yayılır.\"*",
    "Deniz: *\"Biri seni sormuş bugün. İyi anlamda... sanırım.\"* Adın dolaşmaya başladı.",
    "Deniz: *\"Rakip bir isim — 'Kestane' — aynı müşteriye talip olmuş. Hızlı olmakta fayda var.\"*",
    "Masanda bir not: *son üç vakadaki saldırgan IP'leri garip biçimde aynı bloklardan çıkıyor.* "
    "Tesadüf mü, yoksa bir örüntü mü? Deniz omuz silkti ama gözleri gülmüyordu.",
]


# ------------------------------------------------------------------ yardımcılar

def _durumu(kayit: Kayit) -> dict:
    return kayit.veri.setdefault(
        "yasam", {"gun": 1, "para": 0, "itibar": 0, "tamamlanan_is": 0}
    )


def _teaser(sv) -> str | None:
    """`gercek_hayat` kutusundaki ilk kalın ifadeyi (örn. 'Equifax, 2017') cevabı ele vermeden alır."""
    m = re.search(r"\*\*(.+?)\*\*", getattr(sv, "gercek_hayat", "") or "")
    return m.group(1).rstrip(":").strip() if m else None


def _temiz(metin: str) -> str:
    return re.sub(r"<<[^>]+>>", "", metin or "")


def _zorluk_rozet(z: str) -> str:
    d = zorluk.ZORLUKLAR[z]
    renk = {"kolay": "yesil", "normal": "camgobegi", "zor": "sari", "gercekci": "kirmizi"}.get(z, "camgobegi")
    return ui.r(f"{d['simge']} {d['ad']}", renk, "kalin")


def _is_uret(sablon: dict, zorluk_key: str, no: int) -> dict:
    """Bir iş teklifi üretir: tohumu şimdi sabitler (ertelenince kuruluş/hikâye değişmesin)."""
    sv = sablon["sv"]
    tohum = random.SystemRandom().randrange(1, 10 ** 9)
    senaryo = sv.senaryo(tohum)
    metin = senaryo.get("metin", {})
    kurulus = metin.get("musteri", "bir müşteri")
    sektor = metin.get("sektor", "")
    kat = zorluk.ZORLUKLAR[zorluk_key]["xp"]
    odul_max = round(sablon["taban"] * len(sv.gorevler) * kat)
    return {
        "no": no,
        "sablon": sablon,
        "sv": sv,
        "zorluk": zorluk_key,
        "tohum": tohum,
        "kurulus": kurulus,
        "sektor": sektor,
        "odul_max": odul_max,
        "durum": "yeni",
    }


def _kutu_uret(adet: int, no_baslangic: int = 1) -> list[dict]:
    secili = random.sample(ISLER, min(adet, len(ISLER)))
    isler = []
    for i, sablon in enumerate(secili):
        z = random.choices(ZORLUK_HAVUZ, weights=ZORLUK_AGIRLIK)[0]
        isler.append(_is_uret(sablon, z, no_baslangic + i))
    return isler


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
    d = _durumu(kayit)
    ad = kayit.veri["oyuncu"].get("ad") or "Stajyer"
    return (f"  {ui.r('Gün ' + str(d['gun']), 'kalin')}   "
            f"{ui.r('₺' + str(d['para']), 'yesil', 'kalin')}   "
            f"{ui.r('İtibar ' + str(d['itibar']), 'sari')}   "
            f"{ui.r(ad, 'gri')}   ·   XP {kayit.veri['xp']}")


def _daire(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Daire · gece", "mor"))
    print(ui.r(MASA, "gri"))
    print(ui.r("  Pencerede yağmur. Kahven soğumuş, terminal açık. Gelen kutusunda işler var.", "gri"))
    print()
    print(_hud(kayit))


def _eposta_goster(job: dict) -> None:
    sv = job["sv"]
    sab = job["sablon"]
    teaser = _teaser(sv)
    govde = sab["cerceve"].format(kurulus=ui.r(job["kurulus"], "kalin"), sektor=job["sektor"])
    satirlar = [
        f"**Kimden:** Deniz Kara  (fikser)",
        f"**Konu:** {sab['konu']}",
        "",
        govde,
        "",
        f"Zorluk: {_zorluk_rozet(job['zorluk'])}   ·   Ödül: {ui.r('₺' + str(job['odul_max']), 'yesil')} (tam çözümde) + itibar + XP",
    ]
    if teaser:
        satirlar.append(f"Not: geçmişte benzer bir olay — **{teaser}**.")
    ui.temizle()
    for ln in DK.splitlines():
        print("  " + ui.r(ln, "camgobegi"))
    print(ui.kutu("GELEN KUTUSU", "\n".join(satirlar), "mavi"))


def _is_oyna(kayit: Kayit, job: dict, oyuncu_zorluk: str) -> dict:
    """İşi gerçek terminalde oynatır; zorluğu geçici uygular, sonra geri yükler. Maaş bilgisini döndürür."""
    sv = job["sv"]
    # 1) sabit tohumlu vakayı kur + zorluğu bu işe ayarla (alt süreçler save'den okur)
    _vaka_kur(kayit, sv, job["tohum"])
    kayit.veri["ayarlar"]["zorluk"] = job["zorluk"]
    kayit.kaydet()
    xp_once = kayit.veri["xp"]

    # 2) lab + gerçek görev kabuğu (mevcut motor, değişmeden)
    senaryo = sv.senaryo(job["tohum"])
    lab = lab_kur(sv, senaryo)
    print(ui.bilgi(f"İşe giriyorsun: {ui.r(job['kurulus'], 'kalin')} — "
                   f"{sv.baslik} ({_zorluk_rozet(job['zorluk'])}). "
                   f"Menüye dönmek için kabukta {ui.r('cik', 'camgobegi')} yaz."))
    ui.bekle("Hazırsan Enter")
    gorev_kabugu(sv, lab)

    # 3) sonuç: save'i yeniden oku (alt süreçler güncelledi), zorluğu geri yükle
    kayit = Kayit()
    d = kayit.seviye(sv.kimlik)
    cozulen = len(d.get("cozulen", {}))
    toplam = len(sv.gorevler)
    kat = zorluk.ZORLUKLAR[job["zorluk"]]["xp"]
    para = round(job["sablon"]["taban"] * cozulen * kat)
    itibar = round(cozulen * kat)
    xp_kazanc = kayit.veri["xp"] - xp_once

    dur = _durumu(kayit)
    dur["para"] += para
    dur["itibar"] += itibar
    if cozulen == toplam and toplam:
        dur["tamamlanan_is"] += 1
    kayit.veri["ayarlar"]["zorluk"] = oyuncu_zorluk  # oyuncunun kendi ayarı geri gelir
    kayit.kaydet()
    return {"kayit": kayit, "cozulen": cozulen, "toplam": toplam,
            "para": para, "itibar": itibar, "xp": xp_kazanc, "tam": cozulen == toplam and bool(toplam)}


def _maas_ekrani(sonuc: dict, sv) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Maaş günü", "yesil"))
    oran = sonuc["cozulen"] / max(1, sonuc["toplam"])
    print("  " + ui.ilerleme(oran, 24) + f"  {sonuc['cozulen']}/{sonuc['toplam']} görev")
    print()
    if sonuc["cozulen"] == 0:
        print(ui.r("  İşi yarıda bıraktın — bu sefer ödeme yok. Olur böyle, ertesi gün yeni fırsat.", "gri"))
    else:
        print(f"  Kazanç:  {ui.r('+₺' + str(sonuc['para']), 'yesil', 'kalin')}"
              f"   ·   İtibar {ui.r('+' + str(sonuc['itibar']), 'sari')}"
              f"   ·   XP {ui.r('+' + str(sonuc['xp']), 'camgobegi')}")
        if sonuc["tam"]:
            print(ui.basari("Tam çözüm! Müşteri memnun, adın bir çevre daha genişledi."))
    # Gerçek Hayatta debrief (pekiştirme)
    if getattr(sv, "gercek_hayat", ""):
        print()
        print(ui.kutu("GERÇEK HAYATTA", _temiz(sv.gercek_hayat), "mor"))
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
    """Hayat Modu prototipi: günlük iş döngüsü."""
    oyuncu_zorluk = zorluk.anahtar(kayit)   # oyuncunun kendi zorluğu (işler arası korunur)
    _durumu(kayit)
    kayit.kaydet()

    ui.temizle()
    print(ui.baslik_cubugu("Hayat Modu — deney (Aşama 1)", "mor"))
    print(ui.md("""
Bu, oyunun **kariyer / yaşam** çerçevesinin ilk tadımı. Gelen kutusuna işler düşer; okur,
**kabul eder / reddeder / ertelersin**. Kabul ettiğini **gerçek terminalde** çözersin — para,
itibar ve XP kazanırsın. Zor işler daha çok öder ama SOC seni arar.

*(Prototip: ekonomi, ev lab ve ana hikâye sonraki aşamalarda. İlerlemen normal oyunla aynı kayıtta.)*
"""))
    ui.bekle("Başlamak için Enter")

    kutu = _kutu_uret(3)
    sonraki_no = len(kutu) + 1

    while True:
        kayit = Kayit()
        _daire(kayit)
        print()
        aktif = [j for j in kutu if j["durum"] in ("yeni", "ertelendi")]
        if not aktif:
            print(ui.r("  Gelen kutusu boş. Uyuyup yeni bir gün bekleyebilirsin.", "gri"))
        for j in aktif:
            etiket = ui.r(" (ertelendi)", "gri") if j["durum"] == "ertelendi" else ""
            print(f"  [{ui.r(str(j['no']), 'camgobegi', 'kalin')}] {j['sablon']['konu']} — "
                  f"{ui.r(j['kurulus'], 'kalin')} · {_zorluk_rozet(j['zorluk'])} · "
                  f"{ui.r('₺' + str(j['odul_max']), 'yesil')}{etiket}")
        print(f"\n  [{ui.r('u', 'camgobegi')}] Uyu (yeni gün)    [{ui.r('q', 'camgobegi')}] Çıkış")
        secim = ui.sor("\n  Ne yapalım? ").lower().strip()

        if secim == "q":
            kayit.kaydet()
            print(ui.r("\n  İyi geceler. Adın yayılıyor.", "gri"))
            return
        if secim == "u":
            dur = _durumu(kayit)
            dur["gun"] += 1
            # yeni bir iş düşebilir
            if random.random() < 0.8 and len(aktif) < 4:
                yeni = _kutu_uret(1, sonraki_no)
                sonraki_no += 1
                kutu += yeni
            kayit.kaydet()
            continue

        if not secim.isdigit():
            continue
        job = next((j for j in kutu if j["no"] == int(secim) and j["durum"] in ("yeni", "ertelendi")), None)
        if not job:
            continue

        _eposta_goster(job)
        print(f"  [{ui.r('k', 'camgobegi', 'kalin')}] Kabul et    "
              f"[{ui.r('e', 'camgobegi')}] Ertele    "
              f"[{ui.r('r', 'camgobegi')}] Reddet    "
              f"[{ui.r('g', 'camgobegi')}] Geri")
        karar = ui.sor("\n  Kararın? ").lower().strip()
        if karar == "r":
            job["durum"] = "reddedildi"
        elif karar == "e":
            job["durum"] = "ertelendi"
        elif karar == "k":
            sonuc = _is_oyna(kayit, job, oyuncu_zorluk)
            job["durum"] = "bitti"
            _maas_ekrani(sonuc, job["sv"])
            _hikaye_kipirti(sonuc["kayit"])
            ui.bekle()
        # 'g' ya da başka: geri dön
