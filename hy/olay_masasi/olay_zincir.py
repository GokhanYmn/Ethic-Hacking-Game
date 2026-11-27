"""Olay Masası — Zincir Takibi: Çalınan Fonun İzi (blockchain adli analizi).

TAMAMEN SAVUNMACI/ADLİ: oyuncu, hırsızlığa uğrayan borsa/protokolün yanındaki analisttir.
Gerçek blockchain, gerçek adres ya da gerçek borsa yoktur; her şey kurgusal, dosya-tabanlı
sahte veridir. İki dosya gelir: `islemler.csv` (zincir üstü işlem dökümü) ve
`bilinen_adresler.csv` (adli firmaların etiket listesinin kurgusu). Oyuncu parayı grep/awk/sort
ile takip eder: ilk alıcı, toplam, aktarma zinciri, mikser, borsa çıkışı ve doğru müdahale.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem
`yaz`, aynı `_akis(alt)` ile veriyi yeniden üretir. (`_tohum` motor tarafından üzerine
yazıldığı için ayrı bir anahtar kullanılır.)
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

MIKSER_AD = ["Sis", "Duman", "Bulut", "Pus", "Gölge", "Girdap", "Karışık"]
BORSA_AD = ["Lale", "Karadeniz", "Pusula", "Zeytin", "Kervan", "Martı", "Ceviz", "Sedir"]
DIGER_ETIKET = ["DEX-Yonlendirici", "Stake-Havuzu", "Cok-Imzali-Hazine", "NFT-Pazar", "Oyun-Kasasi"]

SENARYOLAR = [
    {"musteri": "Akın Takas", "sektor": "DeFi protokolü", "kisi": "Protokolün güvenlik sorumlusu Kaan Bey",
     "kurban_etiket": "Akin-Takas-Havuz-Kasasi", "tutar": (180, 520),
     "hikaye": "Merkeziyetsiz takas protokolünün likidite havuzunda, bir akıllı sözleşme hatası "
               "(sözleşmenin kendi kurallarındaki bir açık) yüzünden havuz kasası kısa sürede boşaldı."},
    {"musteri": "Meridyen Borsa", "sektor": "kripto borsası", "kisi": "Operasyon müdürü Tuncay Bey",
     "kurban_etiket": "Meridyen-Sicak-Cuzdan", "tutar": (300, 900),
     "hikaye": "Müşteri para çekmelerini karşılayan sıcak cüzdanın (internete bağlı, işlem için hep "
               "açık duran cüzdan) anahtarı sızdı ve içindeki bakiye tek seferde boşaltıldı."},
    {"musteri": "Pusula Köprü", "sektor": "zincirler arası köprü", "kisi": "Köprü ekibinin lideri Ece Hanım",
     "kurban_etiket": "Pusula-Kopru-Kilit-Kasasi", "tutar": (250, 700),
     "hikaye": "Bir zincirden diğerine varlık geçiren köprünün kilit kasasından, sahte bir onay "
               "mesajıyla izinsiz çekim yapıldı; kasa dakikalar içinde eridi."},
]


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _adres(rng: random.Random, goruldu: set) -> str:
    while True:
        a = "0x" + _hex(rng, rng.randint(8, 10))
        if a not in goruldu:
            goruldu.add(a)
            return a


def _tutar(x) -> str:
    return str(x) if isinstance(x, int) else f"{x:.2f}"


def _akis(alt: int) -> dict:
    """Alt-tohumdan tüm vakayı (işlemler, etiketler, cevaplar) deterministik üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    gorulen: set = set()

    def A() -> str:
        return _adres(rng, gorulen)

    kurban = A()
    n = rng.choice([3, 4, 5])
    zincir = [A() for _ in range(n)]
    peeller = [A() for _ in range(n - 1)]
    mikserler = [A(), A()]
    borsalar = [A(), A(), A()]
    gurultu = [A() for _ in range(rng.randint(28, 40))]
    mik_ad = rng.sample(MIKSER_AD, 2)
    bor_ad = rng.sample(BORSA_AD, 3)
    gercek_mikser = rng.randrange(2)
    gercek_borsa = rng.randrange(3)

    t0 = u.gun(rng) + timedelta(hours=rng.randint(9, 18), minutes=rng.randint(0, 59))
    olay_zamani = t0.strftime("%Y-%m-%d %H:%M")
    satirlar = []           # (zaman, gonderen, alici, tutar)

    # 1) Hırsızlık: kurban -> saldırgan-1, üç parça halinde
    T = rng.randint(*sen["tutar"])
    p1 = rng.randint(T // 4, T // 2)
    p2 = rng.randint(T // 5, T // 4)
    parcalar = [p1, p2, T - p1 - p2]
    t = t0
    for p in parcalar:
        t = t + timedelta(seconds=rng.randint(8, 70))
        satirlar.append((t, kurban, zincir[0], p))

    # 2) Soyma zinciri (peel chain): her adım küçük bir dal ayırır, büyük kısmı taşır
    bakiye = T
    k = rng.randrange(n - 1)            # borsaya sızan dalın çıktığı adım
    borsa_tutari = 0
    for i in range(n):
        t = t + timedelta(minutes=rng.randint(6, 45), seconds=rng.randint(0, 59))
        if i < n - 1:
            peel = max(5, bakiye * rng.randint(5, 12) // 100)
            ana = bakiye - peel
            satirlar.append((t, zincir[i], zincir[i + 1], ana))
            satirlar.append((t + timedelta(seconds=rng.randint(3, 40)), zincir[i], peeller[i], peel))
            if i == k:
                borsa_tutari = peel - 1
                tb = t + timedelta(minutes=rng.randint(3, 25), seconds=rng.randint(0, 59))
                satirlar.append((tb, peeller[i], borsalar[gercek_borsa], borsa_tutari))
            bakiye = ana
        else:
            satirlar.append((t, zincir[i], mikserler[gercek_mikser], bakiye))

    # 3) Gürültü: alakasız normal işlemler (ve kurbanın olay öncesi normal işlemleri)
    tum_bilinen = mikserler + borsalar
    adet = rng.randint(130, 190)
    for _ in range(adet):
        tur = rng.random()
        zaman = t0 + timedelta(seconds=rng.randint(-8 * 3600, 10 * 3600))
        tut = rng.choice([rng.randint(1, 40), round(rng.uniform(0.05, 60), 2)])
        if tur < 0.10:
            zaman = t0 - timedelta(seconds=rng.randint(180, 8 * 3600))
            if rng.random() < 0.5:
                satirlar.append((zaman, kurban, rng.choice(gurultu), tut))
            else:
                satirlar.append((zaman, rng.choice(gurultu), kurban, tut))
        elif tur < 0.30:
            satirlar.append((zaman, rng.choice(gurultu), rng.choice(borsalar), tut))
        elif tur < 0.48:
            satirlar.append((zaman, rng.choice(gurultu), rng.choice(mikserler), tut))
        else:
            g, a = rng.sample(gurultu, 2)
            satirlar.append((zaman, g, a, tut))
    # yem: aynı borsaya E'den büyük/küçük başka yatırımlar, kurbana olay sonrası gelen küçük girişler
    for fark in (rng.randint(20, 300), -rng.randint(1, 4)):
        satirlar.append((t0 + timedelta(seconds=rng.randint(-7000, 30000)), rng.choice(gurultu),
                         borsalar[gercek_borsa], max(2, borsa_tutari + fark)))
    for _ in range(rng.randint(2, 4)):
        satirlar.append((t0 + timedelta(seconds=rng.randint(600, 30000)), rng.choice(gurultu), kurban,
                         round(rng.uniform(0.1, 5), 2)))
    for _ in range(rng.randint(2, 3)):      # büyük ama alakasız transferler
        g, a = rng.sample(gurultu, 2)
        satirlar.append((t0 + timedelta(seconds=rng.randint(-20000, 30000)), g, a, rng.randint(T // 3, T)))

    satirlar.sort(key=lambda x: x[0])
    txs = set()
    islemler = []
    for z, g, a, tut in satirlar:
        while True:
            tx = "0x" + _hex(rng, 12)
            if tx not in txs:
                txs.add(tx)
                break
        et = rng.choice(["transfer", "transfer", "transfer", "takas", "stake"]) if (g in gurultu) else "transfer"
        islemler.append((z.strftime("%Y-%m-%d %H:%M:%S"), tx, g, a, _tutar(tut), et))

    mik_et = [f"Mikser-{x}" for x in mik_ad]
    bor_et = [f"Borsa-{x}" for x in bor_ad]
    bilinen = [(kurban, sen["kurban_etiket"])]
    bilinen += list(zip(mikserler, mik_et)) + list(zip(borsalar, bor_et))
    for adr, et in zip(rng.sample(gurultu, 3), rng.sample(DIGER_ETIKET, 3)):
        bilinen.append((adr, et))
    rng.shuffle(bilinen)

    kurban_giden_hepsi = sum(float(x[4]) for x in islemler if x[2] == kurban)
    return {
        "sen": sen, "kurban": kurban, "olay_zamani": olay_zamani, "islemler": islemler,
        "bilinen": bilinen, "zincir": zincir, "toplam": T,
        "mikser": mikserler[gercek_mikser], "mikser_etiket": mik_et[gercek_mikser],
        "borsa_etiket": bor_et[gercek_borsa], "borsa_ad": bor_ad[gercek_borsa],
        "borsa_tutar": borsa_tutari, "peel_tutar": borsa_tutari + 1,
        "mikser_tutar": bakiye, "kurban_giden_hepsi": kurban_giden_hepsi,
    }


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — çalınan fonun zincir takibi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "kurban_adres": v["kurban"],
                  "kurban_etiket": sen["kurban_etiket"], "olay_zamani": v["olay_zamani"]},
        "cevaplar": {
            "ilk": [v["zincir"][0]],
            "toplam": v["toplam"],
            "zincir": list(v["zincir"]),
            "mikser": [v["mikser"], v["mikser_etiket"]],
            "borsa_tutar": v["borsa_tutar"],
            "borsa": [v["borsa_etiket"], v["borsa_ad"]],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    u.yaz(lab / "islemler.csv", "zaman,tx,gonderen,alici,tutar_eth,etiket\n"
          + "".join(f"{z},{tx},{g},{a},{t},{e}\n" for z, tx, g, a, t, e in v["islemler"]))
    u.yaz(lab / "bilinen_adresler.csv",
          "adres,etiket\n" + "".join(f"{a},{e}\n" for a, e in v["bilinen"]))


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _ilk_hata(g, beklenen, b):
    if g == b.senaryo["metin"]["kurban_adres"].casefold():
        return "Bu kurbanın kendi adresi. Parayı kimin ALDIĞINI soruyoruz: `alici` sütunu."
    return None


def _toplam_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == int(round(v["kurban_giden_hepsi"])):
        return "Olay saatinden ÖNCEKİ normal işlemleri de toplamışsın; yalnızca saldırı saatinden sonra çıkanları say."
    if n == v["mikser_tutar"]:
        return "Bu, miksere giren tutar; saldırgan yolda küçük dallar ayırdı. Kurbandan çıkan toplamı soruyoruz."
    return None


def _zincir_hata(verilen, beklenen, b):
    if sorted(verilen) == sorted(beklenen):
        return "Adresler doğru ama sıra yanlış: para zamanda ilerler, ilk alıcıdan başla."
    kurban = b.senaryo["metin"]["kurban_adres"].casefold()
    if kurban in verilen:
        return "Kurbanın adresi zincire dahil değil; zincir saldırgan adreslerinden oluşur."
    if len(verilen) == len(beklenen) - 1 and verilen == beklenen[:-1]:
        return "Son saldırgan adresi eksik; miksere giren adres de zincirin parçası."
    return None


def _borsa_tutar_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == v["peel_tutar"]:
        return "Bu, zincirden ayrılan dalın tutarı. Borsaya yatırılan tutar işlem ücreti kadar eksik; yatırım satırını oku."
    return None


def coz(lab: Path, s: dict) -> dict:
    kurban = s["metin"]["kurban_adres"]
    zaman = s["metin"]["olay_zamani"]
    ilk = _sh(f"awk -F, -v k='{kurban}' -v t='{zaman}' 'NR>1 && $3==k && $1>=t' islemler.csv | sort | head -1 "
              "| cut -d, -f4", lab)
    toplam = _sh(f"awk -F, -v k='{kurban}' -v t='{zaman}' 'NR>1 && $3==k && $1>=t {{s+=$5}} END{{print s}}' "
                 "islemler.csv", lab)
    zincir = _sh("awk -F, -v s='" + ilk + "' 'NR>1 && $5+0>m[$3] {m[$3]=$5+0; n[$3]=$4} "
                 "END{c=s; while (c in n) {print c; c=n[c]}}' islemler.csv | tr '\\n' ' '", lab)
    son = zincir.split()[-1] if zincir.split() else ""
    mikser = _sh(f"awk -F, -v s='{son}' '$3==s {{print $4}}' islemler.csv | head -1", lab)
    ortak = ("awk -F, -v z='" + zincir + "' 'BEGIN{n=split(z,a,\" \");for(i=1;i<=n;i++)c[a[i]]=1} "
             "FNR==NR{if($2~/^Borsa-/)b[$1]=$2; if($2~/^Mikser-/)mk[$1]=1; next} FNR==1{next} "
             "($3 in c)&&!($4 in c)&&!($4 in mk){p[$4]=1} "
             "($3 in p)&&($4 in b){print $5\",\"b[$4]}' bilinen_adresler.csv islemler.csv")
    borsa_tutar = _sh(ortak + " | head -1 | cut -d, -f1", lab)
    borsa = _sh(ortak + " | head -1 | cut -d, -f2", lab)
    cozum = {1: ilk, 2: toplam, 3: zincir, 4: mikser, 5: borsa_tutar, 6: borsa, 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("`islemler.csv` zincir üstü işlem dökümü (`zaman,tx,gonderen,alici,tutar_eth,etiket`). Saldırı "
          "<<olay_zamani>> sularında başladı; kurban adresi `<<kurban_adres>>` o andan sonra para yolladı. "
          "Çalınan fonu **ilk alan** saldırgan adresi hangisi?",
          Metin("ilk", sik_hatalar=_ilk_hata, bicim="0x... adres"),
          ("Kurbanın adresi `gonderen` sütununda; olay saatinden sonrasına bak. Para kime gitti?",
           "CSV'yi virgülle böl: `awk -F,`. 3. alan gönderen, 4. alan alıcı, 1. alan zaman. Zaman metni "
           "karşılaştırılabilir (YYYY-AA-GG SS:DD:SS).",
           "`awk -F, -v k='<kurban>' -v t='<olay zamanı>' '$3==k && $1>=t' islemler.csv | sort | head -1` "
           "— çıkan satırın 4. alanı sorduğumuz adres."),
          puan=15, baslik="İlk alıcı"),
    Gorev("Kurbandan olay saatinden sonra çıkan **toplam tutar** kaç ETH? (Tutarlar bu vakada tam sayı; "
          "hırsızlık birkaç parçada yapıldı.)",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Hırsızlık tek işlemde değil, art arda birkaç işlemde yapılmış; hepsini toplamalısın.",
           "Önceki görevdeki filtreyi koru, `tutar_eth` (5. alan) değerlerini `awk` ile topla: `{s+=$5} END{print s}`.",
           "`awk -F, -v k='<kurban>' -v t='<olay zamanı>' '$3==k && $1>=t {s+=$5} END{print s}' islemler.csv`"),
          puan=10, baslik="Çalınan toplam"),
    Gorev("Saldırgan parayı tek adreste tutmadı: adresten adrese aktardı (her adım küçük bir parça ayırıp "
          "büyük kısmı taşıyan **soyma zinciri**, peel chain). İlk alıcıdan başlayarak, **miksere girmeden "
          "önceki son adrese kadar** saldırgan adreslerini sırayla yaz.",
          Dizi("zincir", sik_hatalar=_zincir_hata, bicim="adresler sırayla, boşlukla ayrılmış"),
          ("Her adresin giden işlemlerine bak: parayı kime taşıdı? Küçük dallar zincirin devamı değil.",
           "Bir adresten çıkan işlemler arasında en BÜYÜK tutarlı olan, zincirin devamıdır: "
           "`grep \",<adres>,\" islemler.csv | sort -t, -k5 -n | tail -1`. Bunu her adres için tekrarla.",
           "Önce ilk alıcının giden işlemlerini listele: `awk -F, '$3==\"<adres>\"' islemler.csv`; en büyük "
           "tutarın alıcısı sıradaki adres. Alıcı artık kimseye göndermeyene (mikser) kadar sürdür."),
          puan=20, baslik="Aktarma zinciri"),
    Gorev("Zincirin son adresinden çıkan para bir **mikser**e (parayı başkalarınınkiyle karıştırıp izini "
          "bulandıran hizmet) girmiş. `bilinen_adresler.csv` ile eşleştirerek miksere ait adresi yaz. "
          "(Listede birden fazla mikser var; doğrusunu zincir belirler.)",
          Metin("mikser", on_ekleri_at=(), bicim="0x... adres (ya da etiket)"),
          ("Zincirin son adresinin parayı kime gönderdiğine bak; sonra o adresin etiketine.",
           "Son adresin giden işlemi: `awk -F, '$3==\"<son adres>\" {print $4}' islemler.csv`. Etiket için "
           "`grep <adres> bilinen_adresler.csv`.",
           "`grep \"$(awk -F, '$3==\"<son adres>\" {print $4}' islemler.csv),\" bilinen_adresler.csv` — "
           "adres ve etiket birlikte çıkar."),
          puan=15, baslik="Mikser adresi"),
    Gorev("Saldırgan acele etmiş: zincirden ayrılan **küçük bir dal** mikserden geçmeden doğrudan bir "
          "**borsa**ya yatırılmış. O borsa yatırımının **tutarı** kaç ETH? (Önce borsa adreslerini "
          "`bilinen_adresler.csv`'den bul; yatırım yapan adres, zincir adreslerinden birinin peel dalıdır.)",
          Sayi("borsa_tutar", sik_hatalar=_borsa_tutar_hata),
          ("Zincirdeki adreslerin küçük (ana akış dışı) alıcılarına bak; biri sonradan bir borsaya para yollamış.",
           "Önce `grep '^.*,Borsa-' bilinen_adresler.csv` ile borsa adreslerini çıkar. Sonra zincirden ayrılan dal "
           "adreslerini bul ve onların borsaya gönderdiği işlemi ara. Aynı borsaya yatıran başka (alakasız) adresler de var.",
           "Dalın alıcısı: `awk -F, '$3==\"<zincir adresi>\"' islemler.csv` çıktısındaki küçük tutarlı satır. "
           "Sonra `grep \"^[^,]*,[^,]*,<dal adresi>,\" islemler.csv` ile o adresin borsaya yolladığı satırı oku; "
           "tutar 5. alan."),
          puan=15, baslik="Borsaya giden tutar"),
    Gorev("Bu yatırımı alan **borsanın** etiketi nedir? (Örnek biçim: `Borsa-Xxx`.)",
          Metin("borsa", on_ekleri_at=("borsa-",), bicim="Borsa-... etiketi"),
          ("Yatırımın `alici` adresi bilinen adresler listesinde etiketlenmiş.",
           "Borsa adresini `grep` ile `bilinen_adresler.csv` içinde ara: `grep <adres> bilinen_adresler.csv`.",
           "Önceki görevde bulduğun yatırım satırının 4. alanı borsa adresi; "
           "`grep \"<o adres>\" bilinen_adresler.csv` etiketi verir."),
          puan=10, baslik="Borsa"),
    Gorev("Zincirdeki bulgularla şimdi **en doğru müdahale** hangisi?",
          Secmeli([
              ("İlgili borsayı hemen uyar, yatırımın dondurulmasını iste; adres ve işlem "
               "kayıtlarını MASAK'a ve kolluğa bildir",
               "Doğru. Borsa, yatırımı dondurabilecek tek taraf ve süre kısa; resmi bildirim de bu dondurmaya "
               "hukuki dayanak ve ileriki takip için kanıt zinciri sağlar."),
              ("Saldırganın adreslerine kendimiz art arda küçük işlemler gönderip hesapları meşgul edelim ki para kıpırdamasın",
               "Yanlış ve etkisiz. Zincirde bir adresi 'meşgul etmek' diye bir şey yok; saldırgan parayı yine "
               "taşır. Üstelik kanıt akışını kirletir ve başkasının adresine izinsiz işlem göndermek sorun yaratır."),
              ("Saldırganın cüzdan anahtarını kırıp parayı kendi cüzdanımıza çekmeyi deneyelim; böylece hepsi geri gelir",
               "Yanlış ve yasadışı. Karşı saldırı (hack-back) izinsiz erişimdir; hukuken suç olur, davayı zayıflatır "
               "ve zaten teknik olarak mümkün değildir."),
              ("Para bir mikserden geçtiği için iz kalmadığını kabul edip borsaya haber vermeden olayı bekleyelim",
               "Yanlış. Mikserden geçmeyen bir dal doğrudan borsada; dondurma için zaman dar. Bekleyip haber "
               "vermemek, kurtarılabilecek parayı kaçırmak demek."),
          ]),
          ("Kurtarılabilir para şu an hangi adreste duruyor ve onu kim durdurabilir?",
           "Zincirde işlemi geri alamazsın; ama borsa kendi içindeki hesabı dondurabilir. Hukuka uygun yolları seç.",
           "Borsa uyar, dondurma iste, resmi kuruma bildir; kendi başına saldırıya girişme."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_zincir",
    cilt=22,
    bolum=115,
    baslik="Zincir Takibi: Çalınan Fonun İzi",
    brifing="""
Selin Aksoy telefonu sana uzatıyor: "**<<musteri>>** (<<sektor>>) acil yardım istedi. <<hikaye>>
<<kisi>> bize iki dosya yolladı: `islemler.csv` (zincir üstü işlem dökümü) ve `bilinen_adresler.csv`
(adli analiz firmalarının tuttuğu etiket listesinin kurgusu). Kurban adresi `<<kurban_adres>>`
(`<<kurban_etiket>>`), saldırı <<olay_zamani>> sularında başladı."

"Bunlar gerçek blockchain değil, kurgusal birer metin dosyası: güvenle oku. Blockchain'de
herkesin işlemi herkese açıktır; hırsız adres değiştirebilir ama izini silemez. Saldırganın
etiketsiz ara adreslerini sen takip edeceksin: parayı kim aldı, kaç adresten geçti, hangi mikserle
karıştırılmaya çalışıldı, hangi borsaya çıkmaya uğraştı. Sonra borsaya ne diyeceğimize karar ver."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Blockchain'de işlemler geri alınamaz ama gizli de değildir. Savunmacı için zincir bir
adli kayıt defteridir: ilk alıcıyı bul, aktarma zincirini sırayla izle, etiket listeleriyle
(borsa, mikser, bilinen hizmetler) eşleştir. Saldırganın en zayıf anı çıkıştır; para bir borsaya
ulaştığında dondurma şansı doğar. Bu yüzden hız önemlidir: borsaya ve resmi kurumlara hemen haber
ver. Önleme tarafında: sıcak cüzdan bakiyesini düşük tut, işlemleri çoklu imzayla onayla,
anormal çekimlerde otomatik duraklatma (kill switch) kur ve akıllı sözleşmeleri yayından önce
bağımsız denetimden geçir. Hiçbir zaman "karşı saldırı" ile parayı kendin geri almaya çalışma.
""",
    gercek_hayat="""
- **Zincir analizi gerçek bir meslektir:** Chainalysis, Elliptic ve TRM gibi firmalar, borsa ve
  mikser adreslerini etiketleyip çalıntı fonları izler; kolluk kuvvetleri bu raporları soruşturmada
  kullanır. 2016'daki Bitfinex hırsızlığına ait fonların yıllar sonra, 2022'de zincir takibiyle
  ele geçirilmesi iyi bilinen bir örnektir.
- **Mikser yaptırımı:** ABD Hazine Bakanlığı (OFAC) 2022'de Tornado Cash adreslerini yaptırım
  listesine aldı; bu yüzden birçok borsa bu adreslerden gelen parayı artık kabul etmez ya da
  dondurur. Bu, mikserden çıkan paranın da borsa tarafında yakalanabildiğini gösterir.
- **Tespit ve önleme:** Büyük köprü saldırılarında (ör. 2022 Ronin köprüsü) fonlar önce adresten
  adrese taşınmıştı; kasa hareketlerini izleyen gerçek zamanlı uyarı sistemleri bu ilk
  dakikaları yakalamak için kurulur.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c22b01",),
)
