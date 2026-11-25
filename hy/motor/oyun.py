"""Oyun akışı: ana menü, harita, seviye ekranı, eğitim ve kabuk içi komutlar."""
from __future__ import annotations

import os
import random
import signal
import sys
import threading
import time
from pathlib import Path

from hy import SURUM
from hy.hikaye import sahne
from hy.motor import arayuz as ui
from hy.motor import harita
from hy.motor.kabuk import gorev_kabugu, komut_calistir, lab_dizini, lab_kur, servisler
from hy.motor.kayit import Kayit
from hy.motor.kontrol import Baglam
from hy.motor.rutbe import (IPUCU_KESINTI, TEKRAR_CARPANI, gorev_puani, rozet_bilgi, ROZETLER,
                            rutbe)
from hy.motor.seviye import seviye_al, sirali_seviyeler, yer_tut
from hy.motor import basvuru, sinav, zorluk

LOGO = r"""
  ╦ ╦╔═╗╔═╗╦╔═╔═╗╦═╗  ╦ ╦╔═╗╦  ╦ ╦
  ╠═╣╠═╣║  ╠╩╗║╣ ╠╦╝  ╚╦╝║ ║║  ║ ║
  ╩ ╩╩ ╩╚═╝╩ ╩╚═╝╩╚═   ╩ ╚═╝╩═╝╚═╝"""


def _simdi() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- durum yardımcıları

def yeni_deneme(kayit: Kayit, sv) -> dict:
    """Seviye için yeni bir senaryo (vaka) başlatır."""
    d = kayit.seviye(sv.kimlik)
    d["tohum"] = random.SystemRandom().randrange(1, 10**9)
    d["deneme"] = int(d.get("deneme", 0)) + 1
    d["carpan"] = 1.0 if (d["deneme"] == 1 or sv.olay_masasi) else TEKRAR_CARPANI
    d["cozulen"], d["ipucu"], d["yanlis"] = {}, {}, {}
    d["baslangic"], d["bitis"] = _simdi(), None
    d["iz"], d["iz_uyari"] = 0, False
    return d


def _iz_ekle(kayit: Kayit, sv, d: dict, miktar: int, yakalanabilir: bool = True) -> bool:
    """Tespit metresine gürültü ekler. Eşik aşılırsa (ve yakalanabilir ise) True döner.

    Uyarı eşiğinde SOC bir kez uyarır. Sadece Zor+ zorlukta çalışır.
    """
    z = zorluk.al(kayit)
    if not z.get("tespit"):
        return False
    d["iz"] = d.get("iz", 0) + miktar
    if yakalanabilir and d["iz"] >= z["yakala"]:
        return True
    if d["iz"] >= z["uyari"] and not d.get("iz_uyari"):
        d["iz_uyari"] = True
        print(ui.kutu("DİKKAT", "SOC ekranında kıpırtı var — Deniz: *\"Loglarda tekrar eden "
                      "başarısız denemeler görüyorum, biri uğraşıyor.\"* Yavaşla; her hamlen iz bırakıyor.",
                      "kirmizi"))
    return False


def _yakalandi(kayit: Kayit, sv) -> None:
    """Tespit metresi doldu: savunma devreye girer, hedef kilitleri değişir (lab sıfırlanır)."""
    print(ui.kutu("YAKALANDIN", "**Savunma devreye girdi.** Çok gürültü çıkardın; SOC seni fark "
                  "etti, hesapları kilitledi ve bilgileri değiştirdi. Hedef sıfırlandı: artık bayrak "
                  "ve ayrıntılar farklı, baştan keşif yapman gerek.\n\nYeni ortama girmek için "
                  "`lab` yaz. Ders: gerçek bir işte gürültü, işin bitmesi demektir.".replace("`", ""),
                  "kirmizi"))
    kayit.veri["istatistik"]["tespit"] = kayit.veri["istatistik"].get("tespit", 0) + 1
    yeni_deneme(kayit, sv)
    yeni = sv.senaryo(kayit.seviye(sv.kimlik)["tohum"])
    lab_kur(sv, yeni, zorla=True)


def _durum_ve_senaryo(kayit: Kayit, sv):
    d = kayit.seviye(sv.kimlik)
    if d["tohum"] is None:
        yeni_deneme(kayit, sv)
        kayit.kaydet()
    return d, sv.senaryo(d["tohum"])


def _rutbe_satiri(kayit: Kayit) -> str:
    xp = kayit.veri["xp"]
    rb = rutbe(xp)
    if rb["sonraki_ad"]:
        return (f"  Rütbe: {ui.r(rb['ad'], 'kalin', 'sari')}  {ui.ilerleme(rb['oran'])}  "
                f"{xp} XP · sonraki: {rb['sonraki_ad']} ({rb['sonraki_esik']})")
    return f"  Rütbe: {ui.r(rb['ad'], 'kalin', 'sari')}  {xp} XP · zirvedesin"


# ---------------------------------------------------------------- kabuk içi komutlar

def _kabuk_baglami():
    kimlik = os.environ.get("HY_SEVIYE")
    if not kimlik:
        print(ui.hata("Bu komut görev kabuğunun içinde çalışır. Önce `hackeryolu` ile bir görev aç."))
        sys.exit(2)
    kayit = Kayit()
    sv = seviye_al(kimlik)
    d, senaryo = _durum_ve_senaryo(kayit, sv)
    return kayit, sv, d, senaryo, lab_dizini(sv)


def _gorev_listesi(sv, d, senaryo, lab, kayit=None) -> None:
    cozulen = d["cozulen"]
    print(ui.baslik_cubugu(sv.etiket))
    ust = []
    if senaryo.get("vaka"):
        ust.append(f"Vaka: {ui.r(senaryo['vaka'], 'sari')}")
    ust.append(f"Çözülen: {len(cozulen)}/{len(sv.gorevler)}")
    ust.append(f"Bu vakadan: +{sum(v['puan'] for v in cozulen.values())} XP")
    print("  " + "   ".join(ust))
    if kayit is not None:
        cubuk = _iz_cubugu(kayit, d)
        if cubuk:
            print(cubuk)
    print()
    for i, g in enumerate(sv.gorevler, 1):
        b = Baglam(senaryo, lab, i)
        soru = yer_tut(g.soru, senaryo)
        if str(i) in cozulen:
            c = cozulen[str(i)]
            etiket = ui.r("✔", "yesil") + " "
            ek = ui.r(" (pes)" if c.get("pes") else f" (+{c['puan']} XP)", "gri")
            print(ui.md(f"{i}. {soru}", girinti=2).replace(f"  {i}.", f"{etiket}{i}.", 1) + ek)
        else:
            etiket = ui.r("○", "sari") + " "
            print(ui.md(f"{i}. {soru}", girinti=2).replace(f"  {i}.", f"{etiket}{i}.", 1))
            ek = yer_tut(g.kontrol.ek_metin(b), senaryo)
            if ek:
                print(ek)
            kademe = d["ipucu"].get(str(i), 0)
            alt = f"Cevap biçimi: {g.kontrol.bicim}   ·   {g.puan} XP"
            if kademe:
                alt += f"   ·   ipucu {kademe}/3 açık"
            print(ui.r("     " + alt, "gri"))
        print()
    print(ui.r("  Komutlar: ", "gri") + ui.r("cevap <no> <cevabın>", "camgobegi") + ui.r(" · ", "gri")
          + ui.r("ipucu <no>", "camgobegi") + ui.r(" · pes <no> · gorev · durum · sifirla · lab · cik", "gri"))


def cmd_gorev(args) -> int:
    kayit, sv, d, senaryo, lab = _kabuk_baglami()
    _gorev_listesi(sv, d, senaryo, lab, kayit)
    return 0


def _gorev_no(sv, d, args):
    if args and args[0].isdigit():
        no = int(args[0])
        if 1 <= no <= len(sv.gorevler):
            return no
        print(ui.hata(f"Bu seviyede 1-{len(sv.gorevler)} arası görev var."))
        return None
    if args:
        print(ui.hata("Önce görev numarasını yaz. Örnek: cevap 2 FLAG{...}"))
        return None
    for i in range(1, len(sv.gorevler) + 1):
        if str(i) not in d["cozulen"]:
            return i
    print(ui.bilgi("Bu vakadaki bütün görevleri çözdün."))
    return None


def _rozet(kayit: Kayit, kimlik: str) -> None:
    if kayit.rozet_ver(kimlik):
        ad, aciklama = rozet_bilgi(kimlik)
        print(ui.r(f"  ★ Yeni rozet: {ad}", "kalin", "sari") + ui.r(f" — {aciklama}", "gri"))


def _seviye_bitis_kontrol(kayit: Kayit, sv, d, senaryo) -> None:
    if len(d["cozulen"]) < len(sv.gorevler) or d.get("bitis"):
        return
    ilk = not d["tamamlandi"]
    ipucusuz = all(v.get("ipucu", 0) == 0 and not v.get("pes") for v in d["cozulen"].values())
    bonus = round(sv.tamamlama_bonusu * d["carpan"] * zorluk.al(kayit)["xp"] * (1.25 if ipucusuz else 1.0))
    kayit.veri["xp"] += bonus
    d["bitis"] = _simdi()
    if ilk:
        d["tamamlandi"] = True
        d["ilk_ipucusuz"] = ipucusuz
    print()
    print(ui.kutu("BAŞARI", f"**Vaka kapandı!** Tamamlama bonusu: **+{bonus} XP**"
                  + (" (ipucusuz bitirdiğin için %25 fazlası)" if ipucusuz else "")))
    if ipucusuz:
        _rozet(kayit, "kendi_basina")
    try:
        basla = time.mktime(time.strptime(d["baslangic"], "%Y-%m-%d %H:%M:%S"))
        if time.time() - basla <= sv.sure_hedef_dk * 60:
            _rozet(kayit, "hizli")
    except (TypeError, ValueError):
        pass
    if sv.cilt == 0 and not sv.olay_masasi:
        kayit.veri["oyuncu"]["etik_onay"] = _simdi()
        _rozet(kayit, "yemin")
    if sv.olay_masasi:
        ist = kayit.veri["istatistik"]
        ist["olay"] += 1
        ist["olay_seri"] = ist["olay_seri"] + 1 if ipucusuz else 0
        if ist["olay"] >= 5:
            _rozet(kayit, "olay_5")
        if ist["olay_seri"] >= 3:
            _rozet(kayit, "olay_seri_3")
    elif ilk and harita.cilt_tamam(kayit, sv.cilt) and sv.cilt > 0:
        _rozet(kayit, f"cilt_{sv.cilt}")
        if all(kayit.seviye(s.kimlik).get("ilk_ipucusuz") for s in harita.cilt_seviyeleri(sv.cilt)):
            _rozet(kayit, "yalniz_kurt")
    if sv.kapanis:
        print(ui.kutu("HACKER GÖZÜYLE", yer_tut(sv.kapanis, senaryo)))
    if sv.gercek_hayat:
        print(ui.kutu("GERÇEK HAYATTA", yer_tut(sv.gercek_hayat, senaryo)))
    print(ui.bilgi("Menüye dönmek için `cik` yaz. Aynı beceriyi başka bir vakada pekiştirmek "
                   "istersen menüden **Yeni vaka**'yı seç.".replace("`", "").replace("**", "")))


def cmd_cevap(args) -> int:
    kayit, sv, d, senaryo, lab = _kabuk_baglami()
    no = _gorev_no(sv, d, args[:1])
    if no is None:
        print(ui.r("  Kullanım: cevap <no> <cevabın>   örn: cevap 2 FLAG{abc}", "gri"))
        return 1
    gorev = sv.gorevler[no - 1]
    girdi = " ".join(args[1:]).strip()
    if str(no) in d["cozulen"]:
        print(ui.bilgi(f"{no}. görevi zaten çözdün. Sıradaki için `gorev` yaz.".replace("`", "")))
        return 0
    if not girdi and not gorev.kontrol.girdi_gerekmez:
        print(ui.hata(f"Cevabı da yaz. Biçim: {gorev.kontrol.bicim}"))
        print(ui.r(f"  Örnek: cevap {no} <cevabın>", "gri"))
        return 1
    rb_once = rutbe(kayit.veri["xp"])["ad"]
    b = Baglam(senaryo, lab, no, Path.cwd())
    sonuc = gorev.kontrol.dogrula(girdi, b)
    ist = kayit.veri["istatistik"]
    z = zorluk.al(kayit)
    if sonuc.dogru:
        kademe = d["ipucu"].get(str(no), 0)
        puan = gorev_puani(gorev.puan, kademe, d["carpan"], z["ipucu_carpan"], z["xp"])
        d["cozulen"][str(no)] = {"puan": puan, "ipucu": kademe, "pes": False, "zaman": _simdi()}
        kayit.veri["xp"] += puan
        ist["dogru"] += 1
        print(ui.basari(f"Doğru! +{puan} XP"))
        if sonuc.mesaj:
            print(ui.md(yer_tut(sonuc.mesaj, senaryo), girinti=4))
        _rozet(kayit, "ilk_bayrak")
        if d["yanlis"].get(str(no), 0) >= 5:
            _rozet(kayit, "pes_etmeyen")
        kalan = len(sv.gorevler) - len(d["cozulen"])
        if kalan:
            print(ui.r(f"  Kalan görev: {kalan}. Listeyi görmek için `gorev`.".replace("`", ""), "gri"))
        _seviye_bitis_kontrol(kayit, sv, d, senaryo)
    else:
        yanlis = d["yanlis"].get(str(no), 0) + 1
        d["yanlis"][str(no)] = yanlis
        ist["yanlis"] += 1
        mesaj = yer_tut(sonuc.mesaj or "Bu değil.", senaryo)
        print(ui.hata(("Çok yakın! " if sonuc.yakin else "Olmadı. ")))
        print(ui.md(mesaj, girinti=4))
        if _iz_ekle(kayit, sv, d, z.get("iz_yanlis", 0)):
            _yakalandi(kayit, sv)
            kayit.kaydet()
            return 1
        if yanlis >= 2 and d["ipucu"].get(str(no), 0) < z["ipucu_tavan"]:
            print(ui.r(f"  Takıldıysan: ipucu {no}", "gri"))
        elif yanlis >= 5:
            print(ui.r(f"  Çok uğraştın. Cevabı görüp öğrenmek de bir yöntemdir: pes {no}", "gri"))
    rb_sonra = rutbe(kayit.veri["xp"])["ad"]
    if rb_sonra != rb_once:
        print(ui.kutu("BAŞARI", f"**Rütbe atladın: {rb_sonra}!**"))
    kayit.kaydet()
    return 0 if sonuc.dogru else 1


def cmd_ipucu(args) -> int:
    kayit, sv, d, senaryo, lab = _kabuk_baglami()
    no = _gorev_no(sv, d, args[:1])
    if no is None:
        return 1
    gorev = sv.gorevler[no - 1]
    anahtar = str(no)
    kademe = d["ipucu"].get(anahtar, 0)
    cozuldu = anahtar in d["cozulen"]
    z = zorluk.al(kayit)
    tavan = z["ipucu_tavan"]

    def goster(k):
        for i in range(k):
            print(ui.kutu(f"İPUCU {i + 1}/3", yer_tut(gorev.ipuclari[i], senaryo), "mavi"))

    if cozuldu:
        print(ui.bilgi("Bu görevi çözdün; ipuçlarını puan kaybetmeden okuyabilirsin."))
        goster(3)
        return 0
    if kademe >= tavan:
        goster(kademe)
        if tavan < 3:
            print(ui.r(f"  {z['ad']} modda son ipucu kapalı. Takıldıysan: pes {no} (cevabı gösterir, puan vermez)", "gri"))
        else:
            print(ui.r(f"  Bütün ipuçları açık. Hâlâ takıldıysan: pes {no} (cevabı gösterir, puan vermez)", "gri"))
        return 0
    yeni = kademe + 1
    if kademe:
        goster(kademe)
    yuzde = int(IPUCU_KESINTI[yeni] * z["ipucu_carpan"] * 100)
    if not ui.onay(f"İpucu {yeni}/3 açılsın mı? Bu görevden alacağın puan %{yuzde} azalacak."):
        return 0
    d["ipucu"][anahtar] = yeni
    kayit.veri["istatistik"]["ipucu"] += 1
    _iz_ekle(kayit, sv, d, z.get("iz_ipucu", 0), yakalanabilir=False)   # ipucu uyarır, yakalamaz
    kayit.kaydet()
    print(ui.kutu(f"İPUCU {yeni}/3", yer_tut(gorev.ipuclari[yeni - 1], senaryo), "mavi"))
    return 0


def cmd_pes(args) -> int:
    kayit, sv, d, senaryo, lab = _kabuk_baglami()
    no = _gorev_no(sv, d, args[:1])
    if no is None:
        return 1
    if str(no) in d["cozulen"]:
        print(ui.bilgi("Bu görevi zaten çözdün."))
        return 0
    if not ui.onay(f"{no}. görevin cevabı gösterilsin mi? Bu görevden puan alamazsın."):
        return 0
    gorev = sv.gorevler[no - 1]
    b = Baglam(senaryo, lab, no, Path.cwd())
    print(ui.kutu("CEVAP", yer_tut(str(gorev.kontrol.cevabi_goster(b)), senaryo), "sari"))
    print(ui.kutu("NASIL BULUNURDU", yer_tut(gorev.ipuclari[-1], senaryo), "mavi"))
    print(ui.r("  Öğrenmenin yolu: şimdi aynı sonuca kendin ulaşmayı dene.", "gri"))
    d["cozulen"][str(no)] = {"puan": 0, "ipucu": 3, "pes": True, "zaman": _simdi()}
    kayit.veri["istatistik"]["pes"] += 1
    _iz_ekle(kayit, sv, d, zorluk.al(kayit).get("iz_ipucu", 0), yakalanabilir=False)
    _seviye_bitis_kontrol(kayit, sv, d, senaryo)
    kayit.kaydet()
    return 0


def _iz_cubugu(kayit, d) -> str:
    z = zorluk.al(kayit)
    if not z.get("tespit"):
        return ""
    oran = min(1.0, d.get("iz", 0) / z["yakala"])
    renk = "kirmizi" if oran >= 0.55 else ("sari" if oran >= 0.3 else "yesil")
    return "  " + ui.r("Tespit: ", "gri") + ui.r("▓" * round(oran * 12) + "░" * (12 - round(oran * 12)), renk)


def cmd_durum(args) -> int:
    kayit = Kayit()
    print(_rutbe_satiri(kayit))
    z = zorluk.al(kayit)
    print(f"  Zorluk: {z['simge']} {z['ad']}")
    kimlik = os.environ.get("HY_SEVIYE")
    if kimlik:
        sv = seviye_al(kimlik)
        d = kayit.seviye(kimlik)
        print(f"  Görev: {sv.etiket} — {len(d['cozulen'])}/{len(sv.gorevler)} çözüldü")
        cubuk = _iz_cubugu(kayit, d)
        if cubuk:
            print(cubuk)
    print(f"  Rozet: {len(kayit.veri['rozetler'])}/{len(ROZETLER)}")
    s = kayit.veri["seri"]
    if s.get("gun_sayisi"):
        print(f"  Günlük seri: {s['gun_sayisi']} gün (rekor {s['en_uzun']})")
    return 0


def cmd_not(args) -> int:
    """Kişisel bilgi bankası: not ekle ya da notları göster. ~/.hackeryolu/notlar.md"""
    kayit = Kayit()
    yol = kayit.notlar_yolu()
    metin = " ".join(args).strip()
    if not metin:
        print(ui.baslik_cubugu("Not defterim"))
        if yol.exists():
            satirlar = yol.read_text(encoding="utf-8").rstrip().split("\n")
            for s in satirlar[-20:]:
                print("  " + s)
            print(ui.r(f"\n  Tümü: {yol}", "gri"))
        else:
            print(ui.bilgi("Henüz not yok."))
        kimlik = os.environ.get("HY_SEVIYE")
        ornek = "`not SQL enjeksiyonunu tek tırnakla test ettim`" if kimlik else "`hackeryolu not \"...\"`"
        print(ui.r("  Not eklemek için: " + ornek.replace("`", ""), "gri"))
        return 0
    kimlik = os.environ.get("HY_SEVIYE")
    baslik = seviye_al(kimlik).etiket if kimlik else "Genel"
    yol.parent.mkdir(parents=True, exist_ok=True)
    with open(yol, "a", encoding="utf-8") as f:
        f.write(f"\n## {baslik} — {_simdi()}\n{metin}\n")
    print(ui.basari("Not eklendi. (Altı ay sonra kendi bilgi bankan olacak.)"))
    return 0


def _basvuru_yaz(kayitlar: list, tur: str) -> None:
    if not kayitlar:
        print(ui.bilgi("Eşleşme yok. Farklı bir kelime dene."))
        return
    for k in kayitlar[:12]:
        if tur == "terim":
            tr = f" ({k['tr']})" if k.get("tr") else ""
            cilt = ui.r(f"  [Cilt {k['cilt']}]", "gri") if k.get("cilt") else ""
            print(ui.r("  " + k["terim"] + tr, "kalin", "camgobegi") + cilt)
            print(ui.md(k["aciklama"], girinti=4))
        else:
            print(ui.r("  " + k["ad"], "kalin", "camgobegi") + ui.r(f"  · {k.get('kategori', '')}", "gri"))
            print(ui.md(k["aciklama"], girinti=4))
            if k.get("ornek"):
                print(ui.r("    örn: " + k["ornek"], "gri"))
        print()
    if len(kayitlar) > 12:
        print(ui.r(f"  ... {len(kayitlar) - 12} eşleşme daha. Aramanı daraltabilirsin.", "gri"))


def cmd_sozluk(args) -> int:
    kayitlar = basvuru.terimler()
    if not kayitlar:
        print(ui.hata("Sözlük verisi bulunamadı."))
        return 1
    print(ui.baslik_cubugu("Sözlük" + (f": {' '.join(args)}" if args else "")))
    _basvuru_yaz(basvuru.terim_ara(" ".join(args)) if args else sorted(kayitlar, key=lambda x: x["terim"].lower()),
                 "terim")
    if not args:
        print(ui.r("  Arama: sozluk <kelime>", "gri"))
    return 0


def cmd_komut(args) -> int:
    kayitlar = basvuru.komutlar()
    if not kayitlar:
        print(ui.hata("Komut başvurusu verisi bulunamadı."))
        return 1
    print(ui.baslik_cubugu("Komut başvurusu" + (f": {' '.join(args)}" if args else "")))
    _basvuru_yaz(basvuru.komut_ara(" ".join(args)) if args else sorted(kayitlar, key=lambda x: (x.get("cilt", 0), x["ad"].lower())),
                 "komut")
    if not args:
        print(ui.r("  Arama: komut <kelime>  (örn. komut grep)", "gri"))
    return 0


def cmd_sifirla(args) -> int:
    kayit, sv, d, senaryo, lab = _kabuk_baglami()
    if not ui.onay("Lab dosyaları aynı vakayla baştan kurulsun mu? (ilerlemen korunur)"):
        return 0
    lab_kur(sv, senaryo, zorla=True)
    print(ui.basari(f"Lab yeniden kuruldu: {lab}"))
    return 0


def cmd_yardim(args) -> int:
    print(ui.md(YARDIM))
    return 0


YARDIM = """
# Nasıl oynanır?

Her görev bir **vaka**dır: önce **brifing**'i okursun, sonra **eğitim** adımlarında yeni
komutları kendi elinle yazarsın, en sonda **saha görevine** girersin. Saha görevi seni
gerçek bir bash kabuğuna bırakır; vakayı orada, öğrendiğin komutlarla çözersin.

Görev kabuğundaki komutlar:

- `gorev` — görev listesi ve soruları
- `cevap <no> <cevabın>` — cevap gönder (örn. `cevap 2 FLAG{abc}`)
- `ipucu <no>` — 3 kademeli ipucu; her kademe o görevin puanını biraz azaltır
- `pes <no>` — cevabı göster (puan yok, ama ilerlemen durmaz)
- `durum` — rütbe ve ilerleme
- `sifirla` — lab dosyalarını bozduysan aynı vakayı baştan kur
- `not <metin>` — kişisel bilgi bankana not ekle (altı ay sonra çok değerli olur)
- `sozluk <kelime>` — bir terimin anlamına bak
- `komut <kelime>` — bir komutun ne işe yaradığına bak
- `lab` — lab dizinine dön
- `cik` — menüye dön

İpuçları: 1. kademe yön gösterir (-%10), 2. kademe yöntemi söyler (-%25), 3. kademe çözüme
çok yaklaştırır (-%50). Bir vakayı bitirdikten sonra **Yeni vaka** ile aynı beceriyi farklı
bir hikâyede pekiştirebilirsin; her seferinde IP'ler, isimler ve bayraklar değişir.

**Zorluk:** Çalışma planı ekranından Kolay/Normal/Zor/Gerçekçi seç. **Zor** ve üstünde
savunma seni izler: çok yanlış deneme ya da çok ipucu bir **tespit metresini** doldurur;
dolarsa SOC seni fark eder, hedefin kilitlerini değiştirir ve baştan keşif yaparsın. Sessiz
ve planlı çalış — gerçek bir işte gürültü, yakalanmak demektir.

Cevabında boşluk veya özel karakter varsa tırnak içinde yaz: `cevap 3 "iki kelime"`.
"""


# ---------------------------------------------------------------- servis süreci

def cmd_servis(args) -> int:
    """Dahili: seviyenin yerel servislerini çalıştırır (görev kabuğu başlatır)."""
    sv = seviye_al(args[0])
    kayit = Kayit()
    d, senaryo = _durum_ve_senaryo(kayit, sv)
    dur = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: dur.set())
    signal.signal(signal.SIGINT, lambda *_: dur.set())
    sv.servis(senaryo, lab_dizini(sv), dur)
    return 0


# ---------------------------------------------------------------- menüler

def _eslesir(girdi: str, adim, senaryo) -> bool:
    def n(s):
        return " ".join(s.split())
    adaylar = [yer_tut(adim.komut, senaryo)] + [yer_tut(a, senaryo) for a in adim.alternatifler]
    return n(girdi) in {n(a) for a in adaylar}


def egitim(kayit: Kayit, sv, senaryo, lab: Path) -> None:
    d = kayit.seviye(sv.kimlik)
    n = len(sv.adimlar)
    with servisler(sv):
        for i, adim in enumerate(sv.adimlar):
            print()
            print(ui.baslik_cubugu(f"Eğitim {i + 1}/{n} · {adim.baslik}", "sari"))
            print(ui.md(yer_tut(adim.metin, senaryo)))
            if adim.komut:
                komut = yer_tut(adim.komut, senaryo)
                while True:
                    print()
                    print("  " + ui.r("▶ Şimdi sen yaz: ", "sari", "kalin") + ui.r(komut, "camgobegi"))
                    girdi = ui.sor(ui.r("  lab$ ", "yesil", "kalin"))
                    if girdi.lower() == "q":
                        kayit.kaydet()
                        return
                    if girdi.lower() == "g":
                        break
                    if _eslesir(girdi, adim, senaryo):
                        if adim.calistir:
                            komut_calistir(girdi, lab, adim.etkilesimli)
                        if adim.sonra:
                            print(ui.md(yer_tut(adim.sonra, senaryo)))
                        if i not in d["egitim"]:
                            d["egitim"].append(i)
                        break
                    print(ui.hata("Bu adımda tam olarak gösterilen komutu yaz (kopyalamadan, kendi elinle). "
                                  + ui.r("[g] geç  [q] menü", "gri")))
                if not ui.bekle():
                    kayit.kaydet()
                    return
            else:
                if i not in d["egitim"]:
                    d["egitim"].append(i)
                if not ui.bekle():
                    kayit.kaydet()
                    return
    kayit.kaydet()
    print()
    print(ui.basari("Eğitim bitti. Şimdi saha görevine girme zamanı."))


def _sahne_goster(kayit: Kayit, cilt: int) -> None:
    gorulen = kayit.veri["oyuncu"].setdefault("sahneler", [])
    metin = sahne(cilt)
    if metin and cilt not in gorulen:
        ui.temizle()
        print(ui.baslik_cubugu(f"{'Bölüm 0' if cilt == 0 else f'Cilt {cilt}'} · {harita.CILTLER[cilt]}", "mor"))
        print(ui.md(metin))
        gorulen.append(cilt)
        kayit.kaydet()
        ui.bekle()


def seviye_ekrani(kayit: Kayit, sv) -> None:
    acik, neden = harita.acik_mi(kayit, sv)
    if not acik:
        print(ui.hata(f"Bu görev kilitli. {neden}"))
        ui.bekle()
        return
    if not sv.olay_masasi:
        _sahne_goster(kayit, sv.cilt)
    d, senaryo = _durum_ve_senaryo(kayit, sv)
    lab = lab_kur(sv, senaryo)
    ilk_giris = not d.get("brifing_goruldu")
    while True:
        kayit = Kayit()
        d, senaryo = _durum_ve_senaryo(kayit, sv)
        lab = lab_kur(sv, senaryo)
        if ilk_giris:
            ilk_giris = False
            secim = "1"
        else:
            ui.temizle()
            print(ui.baslik_cubugu(sv.etiket))
            if senaryo.get("vaka"):
                print(f"  Vaka: {ui.r(senaryo['vaka'], 'sari')}" + (f"   (deneme {d['deneme']})" if d['deneme'] > 1 else ""))
            print(f"  Görevler: {len(d['cozulen'])}/{len(sv.gorevler)}  {ui.ilerleme(len(d['cozulen']) / max(1, len(sv.gorevler)), 15)}"
                  + ("   " + ui.r("✔ tamamlandı", "yesil") if d["tamamlandi"] else ""))
            print(ui.r(f"  Lab: {lab}", "gri"))
            print()
            secenekler = [("1", "Brifing")]
            if sv.adimlar:
                secenekler.append(("2", f"Eğitim — adım adım ({len(d['egitim'])}/{len(sv.adimlar)})"))
            secenekler.append(("3", "Saha görevine gir"))
            if d["tamamlandi"]:
                secenekler.append(("4", "Kapanış: Hacker Gözüyle + Gerçek Hayatta"))
            if d["tamamlandi"] or sv.olay_masasi:
                secenekler.append(("5", "Yeni vaka (aynı beceri, farklı hikâye)"))
            secenekler.append(("6", "Lab'ı sıfırla (aynı vaka)"))
            secenekler.append(("q", "Geri"))
            for k, ad in secenekler:
                print(f"  [{ui.r(k, 'camgobegi', 'kalin')}] {ad}")
            secim = ui.sor("\n  Seçimin: ").lower()
            if secim not in {k for k, _ in secenekler}:
                if secim == "q":
                    return
                continue
        if secim == "q":
            return
        if secim == "1":
            ui.temizle()
            print(ui.baslik_cubugu(sv.etiket))
            print(ui.kutu("BRİFİNG", sv.brifing_metni(senaryo)))
            d["brifing_goruldu"] = True
            kayit.kaydet()
            if sv.adimlar and not d["egitim"] and not d["cozulen"]:
                print()
                if ui.onay("Eğitim adımlarına geçelim mi? (h: doğrudan saha görevine)"):
                    egitim(kayit, sv, senaryo, lab)
                    if ui.onay("Saha görevine girelim mi?"):
                        gorev_kabugu(sv, lab)
                elif ui.onay("Saha görevine girelim mi?"):
                    gorev_kabugu(sv, lab)
            else:
                ui.bekle()
        elif secim == "2" and sv.adimlar:
            egitim(kayit, sv, senaryo, lab)
            ui.bekle()
        elif secim == "3":
            gorev_kabugu(sv, lab)
        elif secim == "4" and d["tamamlandi"]:
            ui.temizle()
            if sv.kapanis:
                print(ui.kutu("HACKER GÖZÜYLE", yer_tut(sv.kapanis, senaryo)))
            if sv.gercek_hayat:
                print(ui.kutu("GERÇEK HAYATTA", yer_tut(sv.gercek_hayat, senaryo)))
            ui.bekle()
        elif secim == "5" and (d["tamamlandi"] or sv.olay_masasi):
            yeni_deneme(kayit, sv)
            d = kayit.seviye(sv.kimlik)
            d["brifing_goruldu"] = False
            kayit.kaydet()
            ilk_giris = True
        elif secim == "6":
            if ui.onay("Lab dosyaları aynı vakayla baştan kurulsun mu?"):
                lab_kur(sv, senaryo, zorla=True)


def harita_ekrani(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        ui.temizle()
        print(ui.baslik_cubugu("Harita"))
        print(_rutbe_satiri(kayit) + "\n")
        for cilt, ad in harita.CILTLER.items():
            seviyeler = harita.cilt_seviyeleri(cilt)
            etiket = "Bölüm 0" if cilt == 0 else f"Cilt {cilt:>2}"
            if not seviyeler:
                print(ui.r(f"   {etiket}  {ad}  · yakında", "gri"))
                continue
            biten = sum(kayit.tamam_mi(s.kimlik) for s in seviyeler)
            acik = harita.acik_mi(kayit, seviyeler[0])[0]
            if biten == len(seviyeler):
                isaret = ui.r("✔", "yesil")
            elif acik:
                isaret = ui.r("▶", "sari")
            else:
                isaret = ui.r("×", "gri")
            satir = f" {isaret} {etiket}  {ad}  {ui.r(f'{biten}/{len(seviyeler)}', 'gri')}"
            print(satir if acik else ui.r(f" × {etiket}  {ad}  {biten}/{len(seviyeler)}", "gri"))
        secim = ui.sor("\n  Cilt numarası (0 = Bölüm 0, q = geri): ").lower()
        if secim == "q":
            return
        if secim.isdigit() and int(secim) in harita.CILTLER:
            cilt_ekrani(kayit, int(secim))


def cilt_ekrani(kayit: Kayit, cilt: int) -> None:
    seviyeler = harita.cilt_seviyeleri(cilt)
    if not seviyeler:
        print(ui.bilgi("Bu bölge bir sonraki fazda gelecek."))
        ui.bekle()
        return
    while True:
        kayit = Kayit()
        ui.temizle()
        baslik = "Bölüm 0" if cilt == 0 else f"Cilt {cilt}"
        print(ui.baslik_cubugu(f"{baslik} · {harita.CILTLER[cilt]}"))
        for i, sv in enumerate(seviyeler, 1):
            d = kayit.veri["seviyeler"].get(sv.kimlik, {})
            acik, _ = harita.acik_mi(kayit, sv)
            if d.get("tamamlandi"):
                isaret = ui.r("✔", "yesil")
            elif acik:
                isaret = ui.r("▶", "sari")
            else:
                isaret = ui.r("×", "gri")
            ad = f"Bölüm {sv.bolum} — {sv.baslik}" if cilt else sv.baslik
            print(f"  [{ui.r(str(i), 'camgobegi')}] {isaret} {ad if acik else ui.r(ad, 'gri')}")
        secim = ui.sor("\n  Görev numarası (q = geri): ").lower()
        if secim == "q":
            return
        if secim.isdigit() and 1 <= int(secim) <= len(seviyeler):
            seviye_ekrani(kayit, seviyeler[int(secim) - 1])


def olay_masasi_ekrani(kayit: Kayit) -> None:
    aileler = sirali_seviyeler(olay=True)
    while True:
        kayit = Kayit()
        ui.temizle()
        print(ui.baslik_cubugu("Olay Masası — sınırsız vaka", "mor"))
        print(ui.md("""
Deniz Kara'nın SOC masası. Burada vakalar hiç bitmez: her seferinde yeni bir şirket,
yeni bir saldırgan, yeni izler. Öğrendiklerini pekiştirmenin en hızlı yolu.
"""))
        ist = kayit.veri["istatistik"]
        print(f"\n  Kapatılan vaka: {ist['olay']}   Ipucusuz seri: {ist['olay_seri']}\n")
        if not aileler:
            print(ui.bilgi("Olay Masası vakaları hazırlanıyor."))
            ui.bekle()
            return
        for i, sv in enumerate(aileler, 1):
            acik, neden = harita.acik_mi(kayit, sv)
            satir = f"  [{ui.r(str(i), 'camgobegi')}] {sv.baslik}"
            print(satir if acik else ui.r(satir + f"  ({neden})", "gri"))
        biten = [s for s in sirali_seviyeler() if kayit.tamam_mi(s.kimlik) and s.cilt > 0]
        print(f"  [{ui.r('k', 'camgobegi')}] Karışık pekiştirme: bitirdiğin {len(biten)} görevden rastgele biri, yepyeni bir vakayla")
        secim = ui.sor("\n  Vaka türü (q = geri): ").lower()
        if secim == "q":
            return
        if secim == "k":
            if not biten:
                print(ui.bilgi("Önce en az bir görevi bitir; karışık pekiştirme bitirdiğin görevlerden seçer."))
                ui.bekle()
                continue
            sv = random.SystemRandom().choice(biten)
            yeni_deneme(kayit, sv)
            kayit.seviye(sv.kimlik)["brifing_goruldu"] = False
            kayit.kaydet()
            print(ui.bilgi(f"Masaya gelen vaka: {sv.etiket}"))
            time.sleep(1.2)
            seviye_ekrani(kayit, sv)
            continue
        if secim.isdigit() and 1 <= int(secim) <= len(aileler):
            sv = aileler[int(secim) - 1]
            d = kayit.seviye(sv.kimlik)
            if d["tohum"] is None or d.get("bitis"):
                yeni_deneme(kayit, sv)
                kayit.kaydet()
            seviye_ekrani(kayit, sv)


def rozet_ekrani(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Rozetler ve istatistik"))
    print(_rutbe_satiri(kayit) + "\n")
    kazanilan = kayit.veri["rozetler"]
    for kimlik, (ad, aciklama) in ROZETLER.items():
        if kimlik in kazanilan:
            print(f"  {ui.r('★', 'sari')} {ui.r(ad, 'kalin')} — {aciklama} {ui.r(kazanilan[kimlik], 'gri')}")
        else:
            print(ui.r(f"  ☆ {ad} — {aciklama}", "gri"))
    ist = kayit.veri["istatistik"]
    print(f"\n  Doğru cevap: {ist['dogru']}   Yanlış: {ist['yanlis']}   İpucu: {ist['ipucu']}   "
          f"Pes: {ist['pes']}   Olay Masası: {ist['olay']}")
    ui.bekle()


def sinav_ekrani(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Kendini Sına", "mor"))
    sorular = sinav.sinav_hazirla(kayit, 10)
    if not sorular:
        print(ui.bilgi("Sınav için önce birkaç cilt bitir; sorular bitirdiğin ciltlerden gelir."))
        ui.bekle()
        return
    print(ui.md(f"""
Bitirdiğin ciltlerden **{len(sorular)} karışık soru**. Hepsi senaryoları yeni; ezber işe
yaramaz. Her soruda a/b/c/d yaz, çıkmak için q.
"""))
    if not ui.bekle("Başlamak için Enter"):
        return
    dogru = 0
    yanlislar = []
    for i, soru in enumerate(sorular, 1):
        sv, no, senaryo = soru["sv"], soru["no"], soru["senaryo"]
        g = sv.gorevler[no - 1]
        b = Baglam(senaryo, lab_dizini(sv), no)
        ui.temizle()
        print(ui.baslik_cubugu(f"Soru {i}/{len(sorular)}  ·  {sv.etiket}", "mor"))
        print(ui.md(yer_tut(g.soru, senaryo)))
        print(yer_tut(g.kontrol.ek_metin(b), senaryo))
        cevap = ui.sor("\n  Cevabın (a/b/c/d, q=çık): ").lower()
        if cevap == "q":
            break
        sonuc = g.kontrol.dogrula(cevap, b)
        if sonuc.dogru:
            dogru += 1
            print(ui.basari("Doğru!"))
        else:
            print(ui.hata("Yanlış. Doğrusu: " + g.kontrol.cevabi_goster(b)))
            yanlislar.append((sv, yer_tut(g.soru, senaryo), g.kontrol.cevabi_goster(b)))
        if sonuc.mesaj:
            print(ui.md(yer_tut(sonuc.mesaj, senaryo), girinti=4))
        if not ui.bekle("Sonraki soru için Enter"):
            break
    toplam = i if cevap == "q" else len(sorular)
    yuzde = round(100 * dogru / max(1, toplam))
    ui.temizle()
    print(ui.baslik_cubugu("Sınav bitti", "mor"))
    print(ui.kutu("SONUÇ", f"**{dogru}/{toplam} doğru  ·  %{yuzde}**"))
    xp = dogru * 6
    kayit.veri["xp"] += xp
    if yuzde > kayit.veri["seri"].get("sinav_en_iyi", 0):
        kayit.veri["seri"]["sinav_en_iyi"] = yuzde
        print(ui.r("  Yeni rekor!", "sari", "kalin"))
    print(ui.basari(f"+{xp} XP"))
    kayit.kaydet()
    if yanlislar:
        print("\n  Tekrar bakman iyi olur:")
        for sv, soru, dc in yanlislar:
            print(ui.r(f"  • {sv.etiket}", "gri"))
    ui.bekle()


FAZLAR = [
    ("Temeller", range(1, 4), "Linux, ağ, otomasyon"),
    ("Keşif ve saldırı", range(4, 7), "keşif, web, sızma"),
    ("Savunma ve meslek", range(7, 11), "mavi takım, meslek, lab, finans"),
    ("Uzmanlık", range(11, 24), "AD, bulut, mobil, finans dünyası ve dahası"),
    ("Capstone", range(24, 25), "uçtan uca senaryolar"),
]


def zorluk_ekrani(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Zorluk seçimi"))
    print(ui.md("""
Zorluk; kazandığın XP'yi, ipuçlarının maliyetini ve **savunmanın seni ne kadar kovaladığını**
belirler. İstediğin an değiştirebilirsin.
"""))
    simdi = zorluk.anahtar(kayit)
    for i, a in enumerate(zorluk.SIRA, 1):
        z = zorluk.ZORLUKLAR[a]
        isaret = ui.r("●", "yesil") if a == simdi else ui.r(str(i), "camgobegi")
        xp = f"×{z['xp']} XP"
        tespit = "tespit açık" if z.get("tespit") else "tespit yok"
        print(f"  [{isaret}] {ui.r(z['simge'] + ' ' + z['ad'], 'kalin')}  {ui.r(f'({xp}, {tespit})', 'gri')}")
        print(ui.md(z["aciklama"], girinti=6))
    secim = ui.sor("\n  Seçimin (1-4, q=geri): ").lower()
    if secim.isdigit() and 1 <= int(secim) <= len(zorluk.SIRA):
        kayit.veri["ayarlar"]["zorluk"] = zorluk.SIRA[int(secim) - 1]
        kayit.kaydet()
        z = zorluk.al(kayit)
        print(ui.basari(f"Zorluk: {z['simge']} {z['ad']}"))
        ui.bekle()


def plan_ekrani(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        ui.temizle()
        print(ui.baslik_cubugu("Çalışma planı"))
        s = kayit.veri["seri"]
        z = zorluk.al(kayit)
        if s.get("gun_sayisi"):
            alev = "🔥 " if s["gun_sayisi"] >= 3 else ""
            print(f"  {alev}Günlük seri: {ui.r(str(s['gun_sayisi']) + ' gün', 'kalin', 'sari')}  (rekor {s['en_uzun']})"
                  f"   ·   Zorluk: {z['simge']} {z['ad']}")
        else:
            print(f"  Günlük seri: henüz başlamadı — bugün bir görev bitir.   ·   Zorluk: {z['simge']} {z['ad']}")
        toplam = [sv for sv in sirali_seviyeler() if sv.cilt > 0]
        biten = sum(kayit.tamam_mi(sv.kimlik) for sv in toplam)
        print(f"  İlerleme: {biten}/{len(toplam)} bölüm  {ui.ilerleme(biten / max(1, len(toplam)))}\n")
        for ad, ciltler, konu in FAZLAR:
            svler = [sv for sv in toplam if sv.cilt in ciltler]
            if not svler:
                continue
            b = sum(kayit.tamam_mi(sv.kimlik) for sv in svler)
            isaret = ui.r("✔", "yesil") if b == len(svler) else (ui.r("▶", "sari") if b else ui.r("·", "gri"))
            print(f"  {isaret} {ui.r(ad, 'kalin')}  {b}/{len(svler)}  {ui.r('— ' + konu, 'gri')}")
        sonraki = harita.siradaki(kayit)
        print()
        if sonraki:
            print(ui.kutu("BUGÜN", f"Sıradaki görevin: **{sonraki.etiket}**.\n"
                          "Günde bir bölüm, haftada bir de Kendini Sına: altı ayda bu kitabı bitirirsin."))
        else:
            print(ui.kutu("BUGÜN", "Açık bütün görevleri bitirdin! Olay Masası ve Kendini Sına ile "
                          "formunu koru, yeni fazlar geldiğinde devam et."))
        secim = ui.sor("\n  [z] zorluk değiştir · [Enter] geri: ").lower()
        if secim != "z":
            return
        zorluk_ekrani(kayit)


def basvuru_ekrani(kayit: Kayit) -> None:
    while True:
        ui.temizle()
        print(ui.baslik_cubugu("Başvuru"))
        print(ui.md(f"""
Takıldığın bir terim ya da komut mu var? Burada ara.

- `s <kelime>` — sözlükte terim ara ({len(basvuru.terimler())} terim)
- `k <kelime>` — komut başvurusunda ara ({len(basvuru.komutlar())} komut)
- `n` — not defterim
- `q` — geri
"""))
        g = ui.sor("  > ").strip()
        if g.lower() in ("q", ""):
            return
        if g.lower() == "n":
            ui.temizle()
            cmd_not([])
            ui.bekle()
            continue
        parca = g.split(None, 1)
        anahtar, sorgu = parca[0].lower(), (parca[1] if len(parca) > 1 else "")
        ui.temizle()
        if anahtar == "s":
            cmd_sozluk([sorgu] if sorgu else [])
        elif anahtar == "k":
            cmd_komut([sorgu] if sorgu else [])
        else:
            cmd_sozluk([g])   # düz yazılan kelimeyi terim araması say
        ui.bekle()


def karsilama(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.r(LOGO, "yesil", "kalin"))
    print(ui.r(f"  Etik Hacker Yolu — oyun sürümü {SURUM}\n", "gri"))
    print(ui.md("""
Bu oyun, **Etik Hacker Yolu** kitabını adım adım oynanan vakalara çevirir. Her vaka gerçek
hayattan bir duruma dayanır; komutları kendi elinle yazar, takıldığında ipucu alırsın.

Bütün pratik **kendi makinende**, oyunun kurduğu laboratuvarda yapılır. Burada öğrendiğin
hiçbir tekniği izin almadığın bir sistemde deneme.
"""))
    ad = ui.sor("\n  Sana nasıl hitap edelim? ")
    if ad.lower() == "q":
        ad = ""
    kayit.veri["oyuncu"]["ad"] = ad or "Stajyer"
    kayit.veri["oyuncu"]["baslangic"] = _simdi()
    print(ui.md("""
Zorluk **Normal**'de başlıyorsun. Hazır hissedince Çalışma planı ekranından **Zor** ya da
**Gerçekçi**'ye geçebilirsin: daha çok XP, ama savunma seni kovalamaya başlar.
"""))
    kayit.kaydet()


def ana_menu() -> int:
    kayit = Kayit()
    if not kayit.veri["oyuncu"].get("ad"):
        karsilama(kayit)
        kayit = Kayit()
    gun = kayit.gun_isaretle()
    kayit.kaydet()
    ilk_tur = gun["yeni_gun"]
    while True:
        kayit = Kayit()
        ui.temizle()
        print(ui.r(LOGO, "yesil", "kalin"))
        print(f"\n  Merhaba {ui.r(kayit.veri['oyuncu'].get('ad', ''), 'kalin')}.")
        s = kayit.veri["seri"]
        if ilk_tur and s.get("gun_sayisi", 0) > 1:
            print(ui.r(f"  🔥 {s['gun_sayisi']} günlük seri" + ("  · yeni rekor!" if gun["rekor"] else "") + " — devam!", "sari"))
        ilk_tur = False
        print(_rutbe_satiri(kayit) + "\n")
        sv = harita.siradaki(kayit)
        devam = sv.etiket if sv else "Açık görevlerin hepsi bitti — Olay Masası'na ne dersin?"
        print(f"  [{ui.r('1', 'camgobegi', 'kalin')}] Devam et: {devam}")
        print(f"  [{ui.r('2', 'camgobegi', 'kalin')}] Harita")
        print(f"  [{ui.r('3', 'camgobegi', 'kalin')}] Olay Masası (sınırsız vaka)")
        print(f"  [{ui.r('4', 'camgobegi', 'kalin')}] Kendini Sına (karışık sınav)")
        print(f"  [{ui.r('5', 'camgobegi', 'kalin')}] Çalışma planı ve serim")
        print(f"  [{ui.r('6', 'camgobegi', 'kalin')}] Başvuru: sözlük, komutlar, notlarım")
        print(f"  [{ui.r('7', 'camgobegi', 'kalin')}] Rozetler ve istatistik")
        print(f"  [{ui.r('8', 'camgobegi', 'kalin')}] Nasıl oynanır?")
        print(f"  [{ui.r('q', 'camgobegi', 'kalin')}] Çıkış")
        secim = ui.sor("\n  Seçimin: ").lower()
        if secim == "q":
            print(ui.r("  Görüşmek üzere. Önce izin, sonra iz.", "gri"))
            return 0
        if secim == "1":
            if sv:
                seviye_ekrani(kayit, sv)
            else:
                olay_masasi_ekrani(kayit)
        elif secim == "2":
            harita_ekrani(kayit)
        elif secim == "3":
            olay_masasi_ekrani(kayit)
        elif secim == "4":
            sinav_ekrani(kayit)
        elif secim == "5":
            plan_ekrani(kayit)
        elif secim == "6":
            basvuru_ekrani(kayit)
        elif secim == "7":
            rozet_ekrani(kayit)
        elif secim == "8":
            ui.temizle()
            print(ui.md(YARDIM))
            ui.bekle()


def cmd_ayar(args) -> int:
    kayit = Kayit()
    if len(args) == 2 and args[0] == "serbest" and args[1] in ("acik", "kapali"):
        kayit.veri["ayarlar"]["serbest"] = args[1] == "acik"
        kayit.kaydet()
        print(ui.basari(f"Serbest mod {'açık: Bölüm 0 sonrası tüm görevler açık' if args[1] == 'acik' else 'kapalı'}."))
        return 0
    if len(args) == 2 and args[0] == "zorluk" and args[1] in zorluk.ZORLUKLAR:
        kayit.veri["ayarlar"]["zorluk"] = args[1]
        kayit.kaydet()
        z = zorluk.ZORLUKLAR[args[1]]
        print(ui.basari(f"Zorluk: {z['simge']} {z['ad']} — {z['aciklama']}"))
        return 0
    print("Kullanım: hackeryolu ayar serbest acik|kapali")
    print("          hackeryolu ayar zorluk kolay|normal|zor|gercekci")
    return 1


def cmd_oyna(args) -> int:
    if not args:
        print("Kullanım: hackeryolu oyna <seviye_kimliği>  (örn. c01b02)")
        return 1
    kayit = Kayit()
    if not kayit.veri["oyuncu"].get("ad"):
        karsilama(kayit)
        kayit = Kayit()
    seviye_ekrani(kayit, seviye_al(args[0]))
    return 0


def cmd_liste(args) -> int:
    for sv in sirali_seviyeler() + sirali_seviyeler(olay=True):
        print(f"{sv.kimlik:10} {sv.etiket}  ({len(sv.gorevler)} görev)")
    return 0


def cmd_oztest(args) -> int:
    """Kurulumu doğrular: her seviyeyi geçici dizinde üretip çözer (ilerlemene dokunmaz)."""
    import subprocess
    kok = Path(__file__).resolve().parents[2]
    if not (kok / "testler").is_dir():
        print(ui.hata("Test dosyaları bu kurulumda yok."))
        return 1
    print(ui.bilgi("Bütün seviyeler geçici bir dizinde kurulup çözülüyor (ilerlemene dokunulmaz)..."))
    ortam = os.environ.copy()
    for k in ("HY_SEVIYE", "HY_EV", "HY_LAB_KOKU"):
        ortam.pop(k, None)
    p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "testler", "-t", "."],
                       cwd=str(kok), env=ortam, capture_output=True, text=True)
    son = [s for s in (p.stdout + p.stderr).strip().splitlines() if s.strip() != "HAZIR"]
    print("\n".join("  " + s for s in son[-12:]))
    if p.returncode == 0:
        print(ui.basari("Kurulum sağlam: bütün testler geçti."))
    else:
        print(ui.hata("Bazı testler geçmedi. Yukarıdaki çıktıyı not et."))
    return p.returncode


KOMUTLAR = {
    "gorev": cmd_gorev, "cevap": cmd_cevap, "ipucu": cmd_ipucu, "pes": cmd_pes,
    "durum": cmd_durum, "sifirla": cmd_sifirla, "yardim": cmd_yardim, "servis": cmd_servis,
    "ayar": cmd_ayar, "oyna": cmd_oyna, "liste": cmd_liste, "oztest": cmd_oztest,
    "not": cmd_not, "sozluk": cmd_sozluk, "komut": cmd_komut,
}


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if sys.platform == "win32":
        print("Hacker Yolu Linux/Kali için tasarlandı. Kali makinende çalıştır.")
        return 1
    if not argv:
        return ana_menu()
    if argv[0] in ("-v", "--surum", "surum"):
        print(f"Hacker Yolu {SURUM}")
        return 0
    if argv[0] in ("-h", "--help", "yardim") and not os.environ.get("HY_SEVIYE"):
        print(ui.md(YARDIM))
        print("\n  Menüyü açmak için: hackeryolu")
        return 0
    komut = KOMUTLAR.get(argv[0])
    if komut is None:
        print(f"Bilinmeyen komut: {argv[0]}. Menü için sadece `hackeryolu` yaz.")
        return 1
    return komut(argv[1:]) or 0
