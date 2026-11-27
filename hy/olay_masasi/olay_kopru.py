"""Olay Masası — Köprü Takibi: Zincirler Arası Kaçış (blockchain adli analizi).

TAMAMEN SAVUNMACI/ADLİ: oyuncu, hırsızlığa uğrayan protokolün yanındaki analisttir. Gerçek
blockchain, adres ya da köprü yoktur; her şey kurgusal, dosya-tabanlı sahte veridir.
`olay_zincir`'in ileri kardeşi: saldırgan parayı bir **köprü** (iki blockchain arasında varlık
geçiren hizmet) üzerinden BAŞKA bir zincire kaçırır. Oyuncu iki ayrı defteri (`zincir_a.csv`,
`zincir_b.csv`) köprü kayıtlarıyla (`kopru_kayitlari.csv`) birleştirerek izi sürer.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem
`yaz`, aynı `_akis(alt)` ile veriyi yeniden üretir (`_tohum` motor tarafından ezildiği için
ayrı anahtar).
"""
from __future__ import annotations

import random
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur

MIKSER_AD = ["Sis", "Duman", "Bulut", "Pus", "Gölge", "Girdap"]
BORSA_AD = ["Lale", "Karadeniz", "Pusula", "Zeytin", "Kervan", "Martı", "Ceviz", "Sedir"]
DIGER_ETIKET = ["DEX-Yonlendirici", "Stake-Havuzu", "Cok-Imzali-Hazine", "NFT-Pazar", "Oyun-Kasasi"]

SENARYOLAR = [
    {"musteri": "Kervan Köprü", "sektor": "zincirler arası köprü", "kisi": "Köprü ekibinin lideri Ece Hanım",
     "kurban_etiket": "Kervan-Kopru-Kilit-Kasasi", "kopru_ad": "Kervan-Kopru", "tutar": (300, 800),
     "a": "Ayaz", "b": "Bora",
     "hikaye": "Köprünün onaycı (doğrulayıcı) anahtarlarının çoğu ele geçirildi; saldırgan sahte çekim "
               "onayları imzalayıp kilit kasasını boşalttı."},
    {"musteri": "Akın Takas", "sektor": "DeFi protokolü", "kisi": "Protokolün güvenlik sorumlusu Kaan Bey",
     "kurban_etiket": "Akin-Takas-Havuz-Kasasi", "kopru_ad": "Gecit-Kopru", "tutar": (200, 600),
     "a": "Ayaz", "b": "Bora",
     "hikaye": "Merkeziyetsiz takas protokolünün havuzunda bir akıllı sözleşme hatası (sözleşmenin "
               "kendi kurallarındaki açık) yüzünden havuz boşaldı."},
    {"musteri": "Meridyen Borsa", "sektor": "kripto borsası", "kisi": "Operasyon müdürü Tuncay Bey",
     "kurban_etiket": "Meridyen-Sicak-Cuzdan", "kopru_ad": "Ufuk-Kopru", "tutar": (350, 900),
     "a": "Ayaz", "b": "Bora",
     "hikaye": "Müşteri çekimlerini karşılayan sıcak cüzdanın (internete bağlı, hep açık duran cüzdan) "
               "anahtarı sızdı ve bakiye tek seferde boşaltıldı."},
]


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _tut(x) -> str:
    return str(x) if isinstance(x, int) else f"{x:.2f}"


def _akis(alt: int) -> dict:
    """Alt-tohumdan tüm vakayı (iki zincir, köprü kayıtları, etiketler, cevaplar) üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    gorulen: set = set()
    txler: set = set()

    def A() -> str:
        while True:
            a = "0x" + _hex(rng, rng.randint(8, 10))
            if a not in gorulen:
                gorulen.add(a)
                return a

    def TX() -> str:
        while True:
            x = "0x" + _hex(rng, 12)
            if x not in txler:
                txler.add(x)
                return x

    kurban = A()
    na = rng.choice([3, 4])
    za = [A() for _ in range(na)]
    pa = [A() for _ in range(na - 1)]
    nb = rng.choice([2, 3])
    zb = [A() for _ in range(nb)]
    pb = [A() for _ in range(nb - 1)]
    KA, KB = A(), A()
    mikserler = [A(), A()]
    borsa_b = [A(), A(), A()]
    borsa_a = [A(), A()]
    gur_a = [A() for _ in range(26)]
    gur_b = [A() for _ in range(26)]
    mik_ad = rng.sample(MIKSER_AD, 2)
    bor_ad = rng.sample(BORSA_AD, 5)           # 3 B zinciri + 2 A zinciri
    cikis_mikser = rng.random() < 0.5
    gm, gb = rng.randrange(2), rng.randrange(3)
    if cikis_mikser:
        cikis, cikis_et = mikserler[gm], f"Mikser-{mik_ad[gm]}"
        yem_cikis = borsa_b[gb]
    else:
        cikis, cikis_et = borsa_b[gb], f"Borsa-{bor_ad[gb]}"
        yem_cikis = borsa_b[(gb + 1) % 3]

    t0 = u.gun(rng) + timedelta(hours=rng.randint(9, 18), minutes=rng.randint(0, 59))
    olay_zamani = t0.strftime("%Y-%m-%d %H:%M")
    ra, rb, kayit = [], [], []     # (zaman, tx, gonderen, alici, tutar) / (zaman, tx_a, kaynak, hedef, tutar)

    def kopruden(zaman, kaynak, hedef, tutar, tx_a=None):
        """A'da köprüye yatırma + köprü kaydı + B'de köprünün bıraktığı işlem."""
        tx_a = tx_a or TX()
        ra.append((zaman, tx_a, kaynak, KA, tutar))
        zb_zaman = zaman + timedelta(seconds=rng.randint(90, 420))
        kayit.append((zaman + timedelta(seconds=rng.randint(5, 30)), tx_a, kaynak, hedef, tutar))
        rb.append((zb_zaman, TX(), KB, hedef, tutar))
        return zb_zaman

    # 1) Hırsızlık: kurban -> za[0], üç parça
    T = rng.randint(*sen["tutar"])
    p1 = rng.randint(T // 4, T // 2)
    p2 = rng.randint(T // 5, T // 4)
    t = t0
    for p in (p1, p2, T - p1 - p2):
        t += timedelta(seconds=rng.randint(8, 70))
        ra.append((t, TX(), kurban, za[0], p))

    # 2) A zincirinde soyma zinciri; son adres köprüye yatırır; bir peel dalı da küçük köprü yapar
    bakiye, k = T, rng.randrange(na - 1)
    yem_peel_adres, yem_peel_tutar = pa[k], 0
    zb_zaman = t
    for i in range(na):
        t += timedelta(minutes=rng.randint(6, 40), seconds=rng.randint(0, 59))
        if i < na - 1:
            peel = max(5, bakiye * rng.randint(5, 12) // 100)
            ana = bakiye - peel
            ra.append((t, TX(), za[i], za[i + 1], ana))
            ra.append((t + timedelta(seconds=rng.randint(3, 40)), TX(), za[i], pa[i], peel))
            if i == k:
                yem_peel_tutar = peel - 1
                kopruden(t + timedelta(minutes=rng.randint(3, 20)), pa[i], A(), yem_peel_tutar)
            bakiye = ana
        else:
            zb_zaman = kopruden(t, za[i], zb[0], bakiye)
    kopru_tutar = bakiye

    # 3) B zincirinde soyma zinciri; son adres mikser/borsaya çıkar; bir peel dalı yem borsaya gider
    tb, bb, kb = zb_zaman, bakiye, rng.randrange(nb - 1)
    for j in range(nb):
        tb += timedelta(minutes=rng.randint(5, 35), seconds=rng.randint(0, 59))
        if j < nb - 1:
            peel = max(4, bb * rng.randint(5, 12) // 100)
            ana = bb - peel
            rb.append((tb, TX(), zb[j], zb[j + 1], ana))
            rb.append((tb + timedelta(seconds=rng.randint(3, 40)), TX(), zb[j], pb[j], peel))
            if j == kb:
                rb.append((tb + timedelta(minutes=rng.randint(3, 20)), TX(), pb[j], yem_cikis, peel - 1))
            bb = ana
        else:
            rb.append((tb, TX(), zb[j], cikis, bb))

    # 4) Gürültü: normal köprü trafiği + iki zincirde sıradan işlemler
    for _ in range(rng.randint(12, 18)):
        i = rng.randrange(len(gur_a))
        tut = rng.choice([rng.randint(5, 300), rng.randint(5, 120)])
        kopruden(t0 + timedelta(seconds=rng.randint(-8 * 3600, 10 * 3600)), gur_a[i], gur_b[i], tut)
    for fark in (0, rng.randint(15, 90)):            # yem: aynı/yakın tutarlı başka kullanıcı köprüsü
        i = rng.randrange(len(gur_a))
        kopruden(t0 + timedelta(seconds=rng.randint(-9000, 30000)), gur_a[i], gur_b[i], kopru_tutar + fark)
    for _ in range(rng.randint(70, 100)):            # Zincir A
        zaman = t0 + timedelta(seconds=rng.randint(-8 * 3600, 10 * 3600))
        tut = rng.choice([rng.randint(1, 40), round(rng.uniform(0.05, 60), 2)])
        x = rng.random()
        if x < 0.10:
            zaman = t0 - timedelta(seconds=rng.randint(180, 8 * 3600))
            g, a = (kurban, rng.choice(gur_a)) if rng.random() < 0.5 else (rng.choice(gur_a), kurban)
        elif x < 0.30:
            g, a = rng.choice(gur_a), rng.choice(borsa_a)
        else:
            g, a = rng.sample(gur_a, 2)
        ra.append((zaman, TX(), g, a, tut))
    for _ in range(rng.randint(70, 100)):            # Zincir B
        zaman = t0 + timedelta(seconds=rng.randint(-8 * 3600, 10 * 3600))
        tut = rng.choice([rng.randint(1, 40), round(rng.uniform(0.05, 60), 2)])
        x = rng.random()
        if x < 0.20:
            g, a = rng.choice(gur_b), rng.choice(borsa_b)
        elif x < 0.38:
            g, a = rng.choice(gur_b), rng.choice(mikserler)
        else:
            g, a = rng.sample(gur_b, 2)
        rb.append((zaman, TX(), g, a, tut))
    for _ in range(rng.randint(2, 3)):               # büyük ama alakasız transferler
        g, a = rng.sample(gur_a, 2)
        ra.append((t0 + timedelta(seconds=rng.randint(-20000, 30000)), TX(), g, a, rng.randint(T // 3, T)))
        g, a = rng.sample(gur_b, 2)
        rb.append((t0 + timedelta(seconds=rng.randint(-20000, 30000)), TX(), g, a, rng.randint(T // 3, T)))

    def bicim(sat):
        return [(z.strftime("%Y-%m-%d %H:%M:%S"), *r) for z, *r in sorted(sat, key=lambda x: x[0])]

    bilinen = [(kurban, "A", sen["kurban_etiket"]), (KA, "A", f"Kopru-{sen['kopru_ad']}-Giris-A"),
               (KB, "B", f"Kopru-{sen['kopru_ad']}-Cikis-B")]
    bilinen += [(a, "B", f"Mikser-{n}") for a, n in zip(mikserler, mik_ad)]
    bilinen += [(a, "B", f"Borsa-{n}") for a, n in zip(borsa_b, bor_ad[:3])]
    bilinen += [(a, "A", f"Borsa-{n}") for a, n in zip(borsa_a, bor_ad[3:])]
    for adr, et in zip(rng.sample(gur_a, 2), rng.sample(DIGER_ETIKET, 2)):
        bilinen.append((adr, "A", et))
    rng.shuffle(bilinen)

    return {
        "sen": sen, "kurban": kurban, "olay_zamani": olay_zamani, "T": T,
        "a": bicim(ra), "b": bicim(rb), "kayit": bicim(kayit), "bilinen": bilinen,
        "za": za, "zb": zb, "kopru_tutar": kopru_tutar, "cikis": cikis, "cikis_et": cikis_et,
        "yem_peel_adres": yem_peel_adres, "yem_peel_tutar": yem_peel_tutar,
        "borsa_a_et": [f"Borsa-{n}" for n in bor_ad[3:]], "borsa_b_et": [f"Borsa-{n}" for n in bor_ad[:3]],
    }


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — köprüden kaçan fonun takibi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "kurban_adres": v["kurban"],
                  "kurban_etiket": sen["kurban_etiket"], "olay_zamani": v["olay_zamani"]},
        "cevaplar": {
            "ilk": [v["za"][0]],
            "yatiran": [v["za"][-1]],
            "hedef": [v["zb"][0]],
            "tutar": v["kopru_tutar"],
            "dizi": list(v["za"]) + list(v["zb"]),
            "cikis": [v["cikis_et"], v["cikis"]],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    bas = "zaman,tx,gonderen,alici,tutar\n"
    u.yaz(lab / "zincir_a.csv", bas + "".join(",".join(map(str, r)) + "\n" for r in
                                              [(z, tx, g, a, _tut(t)) for z, tx, g, a, t in v["a"]]))
    u.yaz(lab / "zincir_b.csv", bas + "".join(",".join(map(str, r)) + "\n" for r in
                                              [(z, tx, g, a, _tut(t)) for z, tx, g, a, t in v["b"]]))
    u.yaz(lab / "kopru_kayitlari.csv", "zaman,kaynak_zincir_tx,kaynak_adres,hedef_zincir_adres,tutar\n"
          + "".join(f"{z},{tx},{k},{h},{_tut(t)}\n" for z, tx, k, h, t in v["kayit"]))
    u.yaz(lab / "bilinen_adresler.csv", "adres,zincir,etiket\n"
          + "".join(f"{a},{z},{e}\n" for a, z, e in v["bilinen"]))


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


# Bir dosyada, başlangıç adresinden en büyük tutarlı çıkışı izleyip etiketli adrese (köprü/mikser/borsa) kadar yürür.
_ZIN = r"""zin(){ awk -F, -v s="$2" 'FNR==NR{ if($3 ~ /^(Kopru|Mikser|Borsa)-/) st[$1]=1; next } FNR==1{next} """ \
       r"""$5+0>m[$3]{m[$3]=$5+0;n[$3]=$4} END{c=s; while((c in n)&&!(c in st)){print c; c=n[c]}}' """ \
       r"""bilinen_adresler.csv "$1"; }; """


def _ilk_hata(g, beklenen, b):
    if g == b.senaryo["metin"]["kurban_adres"].casefold():
        return "Bu kurbanın kendi adresi. Parayı kimin ALDIĞINI soruyoruz: `alici` sütunu."
    return None


def _yatiran_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["yem_peel_adres"].casefold():
        return ("Bu adres de köprüyü kullanmış ama zincirin ana akışında değil, küçük bir dal. Ana akışı "
                "(en büyük tutarlı çıkışları) sonuna kadar izle.")
    if g == b.senaryo["metin"]["kurban_adres"].casefold():
        return "Kurban köprüyü kullanmadı; saldırganın adreslerinden birini ara."
    return None


def _tutar_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["T"]:
        return "Bu, kurbandan çalınan toplam. Yolda küçük dallar ayrıldığı için köprüye giren tutar daha az."
    if n == v["yem_peel_tutar"]:
        return "Bu, küçük dalın köprüden geçirdiği tutar. Ana akışın köprü kaydındaki tutarını soruyoruz."
    return None


def _dizi_hata(verilen, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    za = [x.casefold() for x in v["za"]]
    if sorted(verilen) == sorted(beklenen):
        return "Adresler doğru ama sıra yanlış: para zamanda ilerler; önce A zinciri, sonra köprü, sonra B zinciri."
    if verilen == za:
        return "A zincirinde durdun. Köprüden sonra B zincirindeki adresleri de ekle (çıkış adresi hariç)."
    if v["kurban"].casefold() in verilen:
        return "Kurbanın adresi dizide olmamalı; yalnızca saldırgan adresleri."
    return None


def _cikis_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g in [x.casefold() for x in v["borsa_a_et"]]:
        return "Bu etiketli adres Zincir A tarafında. Para köprüden geçti; son çıkışı B zincirinde ara."
    if g.startswith("kopru-"):
        return "Köprü bir ara duraktı, çıkış değil. B zincirinde paranın nereye gittiğine bak."
    return None


def coz(lab: Path, s: dict) -> dict:
    kurban, zaman = s["metin"]["kurban_adres"], s["metin"]["olay_zamani"]
    ilk = _sh(f"awk -F, -v k='{kurban}' -v t='{zaman}' 'NR>1 && $3==k && $1>=t' zincir_a.csv | sort | head -1 "
              "| cut -d, -f4", lab)
    zinA = _sh(_ZIN + f"zin zincir_a.csv '{ilk}'", lab).split()
    kume = " ".join(zinA)
    yatiran = _sh(f"awk -F, -v z='{kume}' 'BEGIN{{n=split(z,a,\" \");for(i=1;i<=n;i++)c[a[i]]=1}} "
                  "NR>1 && ($3 in c){print $3}' kopru_kayitlari.csv | head -1", lab)
    hedef = _sh(f"awk -F, -v y='{yatiran}' 'NR>1 && $3==y{{print $4}}' kopru_kayitlari.csv | head -1", lab)
    tutar = _sh(f"awk -F, -v y='{yatiran}' 'NR>1 && $3==y{{print $5}}' kopru_kayitlari.csv | head -1", lab)
    zinB = _sh(_ZIN + f"zin zincir_b.csv '{hedef}'", lab).split()
    son = zinB[-1] if zinB else ""
    cikis_adr = _sh(f"awk -F, -v s='{son}' 'NR>1 && $3==s{{print $4}}' zincir_b.csv | head -1", lab)
    cikis = _sh(f"grep '^{cikis_adr},' bilinen_adresler.csv | cut -d, -f3", lab)
    cozum = {1: ilk, 2: yatiran, 3: hedef, 4: tutar, 5: " ".join(zinA + zinB), 6: cikis, 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("İki zincirin defteri var: `zincir_a.csv` (kaynak zincir) ve `zincir_b.csv` (hedef zincir), ikisi de "
          "`zaman,tx,gonderen,alici,tutar`. Saldırı <<olay_zamani>> sularında Zincir A'da başladı; kurban "
          "adresi `<<kurban_adres>>`. Çalınan fonu **ilk alan** saldırgan adresi hangisi?",
          Metin("ilk", sik_hatalar=_ilk_hata, bicim="0x... adres"),
          ("Kurban adresi `gonderen` sütununda; olay saatinden sonrasına, yalnız `zincir_a.csv`'ye bak.",
           "`awk -F, -v k='<kurban>' -v t='<olay zamanı>' 'NR>1 && $3==k && $1>=t' zincir_a.csv`: 4. alan alıcı.",
           "Çıktıyı `| sort | head -1 | cut -d, -f4` ile ilk alıcıya indir."),
          puan=10, baslik="İlk alıcı (Zincir A)"),
    Gorev("Saldırgan parayı Zincir A'da adresten adrese aktardı (her adımda küçük bir dal ayırıp büyük kısmı "
          "taşıdı). Son adres, **köprüye yatırma** yaptı. `kopru_kayitlari.csv` "
          "(`zaman,kaynak_zincir_tx,kaynak_adres,hedef_zincir_adres,tutar`) köprüye yatıranları listeler, "
          "ama kayıtlar arasında başka kullanıcılar da var. Saldırganın **ana akışından** köprüye yatıran "
          "adres hangisi?",
          Metin("yatiran", sik_hatalar=_yatiran_hata, bicim="0x... adres"),
          ("Önce ilk alıcıdan başlayıp parayı sonuna kadar izle: her adresin giden işlemleri arasında "
           "en büyük tutarlı olan zincirin devamıdır.",
           "`awk -F, '$3==\"<adres>\"' zincir_a.csv` ile giden işlemleri listele; en büyük tutarın alıcısı sıradaki "
           "adres. Köprü adresine (`Kopru-` etiketli) varınca dur.",
           "Zincirdeki adreslerden biri `kopru_kayitlari.csv` içinde `kaynak_adres` olarak geçer: "
           "`grep <adres> kopru_kayitlari.csv`. Küçük dallardan köprüye yatıranlar da olabilir; ana akışı seç."),
          puan=20, baslik="Köprüye yatıran adres"),
    Gorev("Köprü bu yatırımı Zincir B'de hangi **adrese bıraktı**? (Köprü kaydında yatıran adresin "
          "karşısındaki `hedef_zincir_adres`.)",
          Metin("hedef", bicim="0x... adres"),
          ("Köprü kayıtları iki zinciri birbirine bağlar: yatıran adresin satırını bul.",
           "`grep '<yatıran adres>' kopru_kayitlari.csv`; 4. alan Zincir B'deki alıcı.",
           "`awk -F, -v y='<yatıran>' 'NR>1 && $3==y {print $4}' kopru_kayitlari.csv`. Doğrulamak için "
           "bu adresi `zincir_b.csv`'de köprü çıkış adresinden gelen işlem olarak ara."),
          puan=15, baslik="B zincirindeki varış adresi"),
    Gorev("Saldırganın köprüden geçirdiği **tutar** kaç? (Köprü kaydındaki `tutar`; bu vakada tam sayı. "
          "Kayıtlar arasında benzer tutarlı başka kullanıcılar da olabilir, doğru satırı adrese göre seç.)",
          Sayi("tutar", sik_hatalar=_tutar_hata),
          ("Tutar, doğru satırın 5. alanı. Satırı tutara göre değil, yatıran adrese göre seç.",
           "`awk -F, -v y='<yatıran>' 'NR>1 && $3==y {print $5}' kopru_kayitlari.csv`",
           "Çalınan toplamdan küçük olmalı: yolda peel dalları ayrıldı."),
          puan=10, baslik="Köprüden geçen tutar"),
    Gorev("Şimdi iki zinciri birleştir: saldırganın **tüm adres sırasını** yaz. Önce Zincir A'daki saldırgan "
          "adresleri (ilk alıcıdan köprüye yatıran adrese kadar), ardından köprüden sonra Zincir B'deki "
          "saldırgan adresleri (varış adresinden, **mikser/borsaya çıkmadan önceki son adrese** kadar). "
          "Köprü sözleşmesinin ve etiketli adreslerin kendisini yazma.",
          Dizi("dizi", sik_hatalar=_dizi_hata, bicim="adresler sırayla, boşlukla ayrılmış"),
          ("A zincirini zaten çıkardın; B'de varış adresinden başla ve aynı kuralı uygula: en büyük "
           "tutarlı çıkış zincirin devamı.",
           "`awk -F, '$3==\"<adres>\"' zincir_b.csv` ile giden işlemleri gör; küçük dallar zincir değildir.",
           "B'de zincir, etiketli bir adrese (`Mikser-`/`Borsa-`) ulaşınca biter; o etiketli adres listeye girmez."),
          puan=20, baslik="A → köprü → B hop sırası"),
    Gorev("Saldırganın Zincir B'deki **son çıkışı** neresi? `bilinen_adresler.csv`'deki etiketle yaz "
          "(`Mikser-...` ya da `Borsa-...`). Zincirden ayrılan küçük dallar başka etiketli adreslere de "
          "gidiyor; ana akışın çıkışını seç.",
          Metin("cikis", on_ekleri_at=(), sik_hatalar=_cikis_hata, bicim="Mikser-... / Borsa-... etiketi (ya da adres)"),
          ("Önceki görevdeki B zincirinin son adresi parayı kime gönderdi?",
           "`awk -F, -v s='<B son adres>' 'NR>1 && $3==s {print $4}' zincir_b.csv`; sonra "
           "`grep <o adres> bilinen_adresler.csv`.",
           "Etiket 3. alan. Çıkış B zincirinde olmalı (`zincir` sütunu `B`)."),
          puan=15, baslik="B zincirindeki son çıkış"),
    Gorev("Bulgularınla şimdi **en doğru müdahale** hangisi?",
          Secmeli([
              ("Her iki zincirdeki ilgili borsaları ve köprü ekibini hemen uyar, çıkış adresine gelen "
               "parayı dondurmalarını iste; iki zincirin kayıtlarını MASAK'a ve kolluğa bildir",
               "Doğru. Para artık iki zincire yayıldı; dondurabilecek taraflar (borsalar, köprü ekibi, mikser "
               "yaptırımı uygulayan hizmetler) iki zincirde de var. Resmi bildirim kanıt zincirini korur."),
              ("Yalnız kaynak zincirdeki (A) borsaları uyaralım; para köprüden geçince bizi ilgilendirmez",
               "Yanlış. Para Zincir B'de ve çıkışı orada; yalnız A'daki borsaları uyarmak dondurulabilecek tek "
               "yeri atlamak demektir."),
              ("Köprünün Zincir B'deki kasasına kendimiz sahte işlem gönderip parayı geri çekmeyi deneyelim",
               "Yanlış ve yasadışı. İzinsiz erişim ve karşı saldırı (hack-back) hukuken suçtur, davayı zayıflatır "
               "ve zaten teknik olarak mümkün değildir."),
              ("Para köprüden geçtiği için izin koptuğunu kabul edip kimseye haber vermeyelim",
               "Yanlış. Köprü kaydı iki defteri bağlar; iz kopmaz. Bekleyip haber vermemek, kurtarılabilecek "
               "parayı kaçırmaktır."),
          ]),
          ("Kurtarılabilir para şu an hangi zincirde ve onu kim durdurabilir?",
           "Zincirde işlem geri alınamaz; ama borsalar ve köprü ekibi kendi tarafında dondurabilir. "
           "Hukuka uygun yolları seç.",
           "Her iki zincirde ilgili tarafları uyar, dondurma iste, resmi kuruma bildir; saldırıya girişme."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_kopru",
    cilt=22,
    bolum=124,
    baslik="Köprü Takibi: Zincirler Arası Kaçış",
    brifing="""
Selin Aksoy telefonu sana uzatıyor: "**<<musteri>>** (<<sektor>>) yine bizi aradı. <<hikaye>>
<<kisi>> dört dosya yolladı: `zincir_a.csv` (kaynak zincirin işlem defteri), `zincir_b.csv`
(hedef zincirin defteri), `kopru_kayitlari.csv` (iki zinciri bağlayan köprünün kayıtları) ve
`bilinen_adresler.csv` (etiket listesinin kurgusu). Kurban adresi `<<kurban_adres>>`
(`<<kurban_etiket>>`), saldırı <<olay_zamani>> sularında Zincir A'da başladı."

"Bu sefer hırsız parayı bir **köprüden** geçirip başka bir blockchain'e taşımış. Köprü, bir zincirde
kilitlenen varlığın karşılığını öbür zincirde veren hizmettir; saldırgan umuyor ki iz iki defter
arasında kopsun. Kopmaz: köprü kayıtları iki defteri birbirine bağlar. Bunlar gerçek zincir değil,
kurgusal metin dosyaları: güvenle oku. Ucu A'dan al, köprüden geç, B'de sonuna kadar sür; sonra
iki zincirde kime ne diyeceğimize karar ver."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Köprüler, zincirler arasındaki en zengin ve en zayıf hedeflerdir: kasada çok para
birikir, güvenlik ise az sayıda onaycı anahtara ya da bir sözleşme koduna dayanır. Saldırgan parayı
köprüden geçirince izin koptuğunu sanır; oysa köprü kendi kayıtlarını tutar ve iki defter birleştirilebilir.
Savunmacı için yöntem aynı: ilk alıcıyı bul, ana akışı izle, köprü kaydıyla öbür zincire geç, orada
etiketli çıkışa (borsa, mikser) ulaşana kadar sür. Dondurma şansı çıkışlardadır, bu yüzden iki zincirdeki
tüm ilgili tarafı hızla uyar ve resmi kurumlara bildir. Önleme: çok sayıda bağımsız onaycı, onaycı
anahtarlarını ayrı yerlerde tutmak, köprüden çıkışlara günlük limit, anormal çekimde otomatik duraklatma
ve bağımsız denetim. Hack-back asla.
""",
    gercek_hayat="""
- **Köprüler büyük hırsızlıkların hedefi oldu:** **Ronin köprüsü (Mart 2022)** ve **Wormhole köprüsü
  (Şubat 2022)** yüz milyonlarca dolarlık fonun çalındığı en bilinen köprü saldırılarındandır. Ronin'de
  onaycı anahtarlarının ele geçirilmesi, Wormhole'da ise sözleşme açığı kullanıldı.
- **İz sürme gerçekten işe yarar:** ABD FBI, Ronin saldırısını 2022 Nisan'ında Kuzey Kore bağlantılı
  Lazarus grubuna bağladı; zincir analiz firmaları (Chainalysis, Elliptic, TRM) çalıntı fonun
  köprüler ve mikserler üzerinden hareketini izleyip borsalara bildirdi.
- **Önleme:** Köprü ekipleri çekim limiti, çok imzalı onay ve gerçek zamanlı uyarı sistemleri kurar;
  borsalar da şüpheli adreslerden gelen fonları dondurmak için bu etiket listelerini kullanır.
""",
    sure_hedef_dk=18,
    tamamlama_bonusu=35,
    olay_masasi=True,
    on_kosul=("c22b04",),
)
