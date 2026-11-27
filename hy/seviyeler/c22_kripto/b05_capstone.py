"""Cilt 22 · Bölüm 5 — Birleşik Capstone: Açığı Bul, Parayı İzle.

İki beceriyi tek vakada birleştirir: (b02) kurgusal bir Solidity sözleşmesini **okuyup** açığı bulmak ve
(b04) o açıkla çalınan fonun zincirdeki izini (drenaj -> hop -> mikser -> borsa) sürmek.

TAMAMEN SAVUNMACI/ADLİ: Hiçbir istismar kodu yazılmaz; yalnızca açığın DESENİ görünür. Sözleşme, adresler,
borsalar ve mikserler kurgusaldır; gerçek bir zincir yoktur, her şey dosya tabanlı sahte veridir.

Determinizm: `Seviye.senaryo` `s["_tohum"]` değerini ezer; bu yüzden uret içinde ayrı bir alt-tohum
(`s["_alt"]`) üretilir, hem `uret` hem `yaz` hem sık-hata geri bildirimleri aynı `random.Random(_alt)` ile
veriyi yeniden üretir.
"""
from __future__ import annotations

import random
import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli, Sonuc, norm
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

BORSALAR = ["Yildiz Takas", "Mavi Liman Borsa", "Kuzey Takas", "Atlas Kripto"]
MIKSERLER = ["Sis Havuzu", "Bulut Karistirici", "Duman Transfer"]
BASLIK_ISLEM = "zaman,tx,gonderen,alici,tutar_eth,etiket"
BASLIK_ADRES = "adres,etiket"
TURLER = ["r", "a", "t"]
CEK_ADLARI = ["paraCek", "bakiyeCek", "hakCek", "geriOde"]
ZAYIF_ADLARI = ["yoneticiDegistir", "sahipAta", "yetkiDevret"]
KURTAR_ADLARI = ["acilCekim", "kasayiBosalt"]


def _hex(rng: random.Random, n: int = 8) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


# ---------------------------------------------------------------- sözleşme üretimi

def _govde_blok(blok: list, rng: random.Random) -> list:
    """Ayrı işlev bloklarını karışık sırayla, aralarına boş satır koyarak birleştirir."""
    rng.shuffle(blok)
    L: list = []
    for i, b in enumerate(blok):
        if i:
            L.append("")
        L += b
    return L


def sozlesme_uret(rng: random.Random, ad: str, kod: str, tur: str) -> tuple:
    """(metin, bilgi): bilgi = satır numarası (1'den), zafiyetli işlev adı, sözleşme adı."""
    C = "".join(ch for ch in kod.capitalize() if ch.isalnum()) + "Havuzu"
    L = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.20;"]
    if rng.random() < 0.5:
        L.append(f"// sürüm notu: {rng.choice(['v0.3', 'v0.5', 'v0.9', 'v1.1'])} taslak")
    L += ["", f"// {ad} — kurgusal örnek. Müşteri bakiyelerini tutan küçük bir kasa sözleşmesi.",
          f"contract {C} {{", "    mapping(address => uint256) public bakiyeler;", "    address public sahip;"]
    yatir = ["    function yatir() external payable {", "        bakiyeler[msg.sender] += msg.value;", "    }"]
    ctor = ["    constructor() {", "        sahip = msg.sender;", "    }"]
    if tur == "r":
        cek = rng.choice(CEK_ADLARI)
        L += ["    uint256 public komisyon;", ""] + ctor + [""]
        L += _govde_blok([
            yatir,
            [f"    function {cek}(uint256 miktar) external {{",
             '        require(bakiyeler[msg.sender] >= miktar, "yetersiz bakiye");',
             '        (bool ok, ) = msg.sender.call{value: miktar}("");',
             '        require(ok, "gonderim basarisiz");',
             "        bakiyeler[msg.sender] -= miktar;", "    }"],
            ["    function komisyonAyarla(uint256 yeni) external {",
             '        require(msg.sender == sahip, "yetki yok");', "        komisyon = yeni;", "    }"],
        ], rng)
        fonk = cek
    elif tur == "t":
        cek = rng.choice(CEK_ADLARI)
        L += ["    uint256 public komisyon;", ""] + ctor + [""]
        L += _govde_blok([
            yatir,
            [f"    function {cek}(address payable alici, uint256 miktar) external {{",
             '        require(tx.origin == sahip, "yetki yok");', "        alici.transfer(miktar);", "    }"],
            ["    function komisyonAyarla(uint256 yeni) external {",
             '        require(msg.sender == sahip, "yetki yok");', "        komisyon = yeni;", "    }"],
        ], rng)
        fonk = cek
    else:
        zayif, kurtar = rng.choice(ZAYIF_ADLARI), rng.choice(KURTAR_ADLARI)
        L += ["    bool public durdu;", "",
              "    modifier sadeceSahip() {", '        require(msg.sender == sahip, "yetki yok");', "        _;", "    }",
              ""] + ctor + [""]
        L += _govde_blok([
            yatir,
            [f"    function {zayif}(address yeni) external {{", "        sahip = yeni;", "    }"],
            [f"    function {kurtar}(address payable hedef) external sadeceSahip {{",
             "        hedef.transfer(address(this).balance);", "    }"],
            ["    function durdur() external sadeceSahip {", "        durdu = true;", "    }"],
        ], rng)
        fonk = zayif
    L.append("}")
    isaret = {"r": ".call{value", "t": "tx.origin", "a": f"function {fonk}("}[tur]
    satir = next(i for i, x in enumerate(L, 1) if isaret in x)
    return "\n".join(L) + "\n", {"satir": satir, "fonk": fonk, "sozlesme": C}


# ---------------------------------------------------------------- işlem defteri üretimi

def veri_uret(rng: random.Random) -> dict:
    """Bütün vakayı üretir (aynı rng -> aynı vaka)."""
    m = musteri_sec(rng)
    tur = rng.choice(TURLER)
    metin, bilgi = sozlesme_uret(rng, m["ad"], m["kod"], tur)

    kul: set = set()
    kul_tx: set = set()

    def adr() -> str:
        while True:
            a = "0x" + _hex(rng, 8)
            if a not in kul:
                kul.add(a)
                return a

    def tx() -> str:
        while True:
            t = "0x" + _hex(rng, 12)
            if t not in kul_tx:
                kul_tx.add(t)
                return t

    havuz = adr()
    musteriler = [adr() for _ in range(rng.randint(5, 7))]
    zincir = [adr() for _ in range(rng.randint(2, 3))]           # zincir[0] = saldırgan
    mikser, mikser2 = adr(), adr()
    mik_ad = rng.sample(MIKSERLER, 2)
    borsa_ad = rng.sample(BORSALAR, 3)                           # [gerçek, yedek, üçüncü]
    borsa_adr = {b: adr() for b in borsa_ad}
    gercek, yedek_b, _ = borsa_ad
    kullanicilar = [adr() for _ in range(rng.randint(9, 13))]
    saldirgan = zincir[0]

    bilinen = [(havuz, f"HAVUZ {bilgi['sozlesme']} sozlesmesi"),
               (mikser, f"MIKSER {mik_ad[0]}"), (mikser2, f"MIKSER {mik_ad[1]}")]
    bilinen += [(borsa_adr[b], f"BORSA {b} yatirim") for b in borsa_ad]
    bilinen += [(a, f"MUSTERI hesap {i}") for i, a in enumerate(musteriler, 1)]

    sat: list = []                                               # (zaman, gonderen, alici, tutar, etiket)
    gun = u.gun(rng)
    for _ in range(rng.randint(8, 12)):
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        sat.append((t, rng.choice(musteriler), havuz, rng.randint(20, 150), "yatirim"))
    for _ in range(rng.randint(3, 5)):
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        sat.append((t, havuz, rng.choice(musteriler), rng.randint(5, 60), "cekim"))

    # sömürü: açık türüne göre farklı drenaj kalıbı
    t0 = gun + timedelta(days=1, hours=rng.randint(1, 3), minutes=rng.randint(0, 50))
    parca = 0
    if tur == "r":                                               # aynı tutar, art arda çok sayıda çekim
        n, parca = rng.randint(4, 6), rng.randint(40, 120)
        toplam = n * parca
        for i in range(n):
            sat.append((t0 + timedelta(seconds=15 * i + rng.randint(0, 8)), havuz, saldirgan, parca, "cekim"))
        t_son = t0 + timedelta(seconds=15 * n + 8)
    elif tur == "a":                                             # önce yetki devri (0 ETH çağrı), sonra tek büyük çekim
        toplam = rng.randint(300, 1500)
        sat.append((t0, saldirgan, havuz, 0, "sozlesme-cagrisi"))
        sat.append((t0 + timedelta(minutes=rng.randint(1, 4)), havuz, saldirgan, toplam, "cekim"))
        t_son = t0 + timedelta(minutes=5)
    else:                                                        # tek büyük çekim
        toplam = rng.randint(300, 1500)
        sat.append((t0, havuz, saldirgan, toplam, "cekim"))
        t_son = t0

    # hop'lar ve mikser girişi
    t = t_son + timedelta(minutes=15)
    for i in range(len(zincir) - 1):
        t += timedelta(minutes=rng.randint(12, 80))
        sat.append((t, zincir[i], zincir[i + 1], toplam, "transfer"))
    t += timedelta(minutes=rng.randint(10, 60))
    t_mikser = t
    sat.append((t_mikser, zincir[-1], mikser, toplam, "transfer"))

    for _ in range(rng.randint(10, 14)):
        sat.append((t0 + timedelta(minutes=rng.randint(-300, 600)), rng.choice(kullanicilar), mikser,
                    rng.randint(8, 90), "transfer"))
    for _ in range(rng.randint(8, 12)):
        sat.append((t0 + timedelta(minutes=rng.randint(-300, 600)), rng.choice(kullanicilar), mikser2,
                    rng.randint(8, 90), "transfer"))

    # mikser çıkışları: biri gerçek borsaya; yedek mikserin biri başka borsaya (tuzak)
    n_out = rng.randint(5, 7)
    taban = toplam * 97 // 100
    w = [rng.randint(5, 25) for _ in range(n_out)]
    parcalar = [taban * x // sum(w) for x in w]
    parcalar[-1] += taban - sum(parcalar)
    hedefler = [adr() for _ in range(n_out)]
    hedefler[rng.randrange(n_out)] = borsa_adr[gercek]
    tc = t_mikser + timedelta(hours=rng.randint(3, 9), minutes=rng.randint(0, 50))
    for i in range(n_out):
        tc += timedelta(minutes=rng.randint(10, 90))
        sat.append((tc, mikser, hedefler[i], parcalar[i], "transfer"))
    n_y = rng.randint(3, 4)
    iy = rng.randrange(n_y)
    tc2 = t0 + timedelta(hours=rng.randint(2, 6))
    for i in range(n_y):
        tc2 += timedelta(minutes=rng.randint(20, 100))
        sat.append((tc2, mikser2, borsa_adr[yedek_b] if i == iy else adr(), rng.randint(15, 70), "transfer"))

    # gürültü
    for _ in range(rng.randint(12, 18)):
        a, b = rng.sample(kullanicilar, 2)
        sat.append((gun + timedelta(seconds=rng.randint(0, 2 * 86400)), a, b, rng.randint(1, 200), "transfer"))
    for b in borsa_ad:
        for _ in range(rng.randint(2, 4)):
            sat.append((gun + timedelta(seconds=rng.randint(0, 2 * 86400)), rng.choice(kullanicilar),
                        borsa_adr[b], rng.randint(3, 60), "transfer"))

    sat.sort(key=lambda x: x[0])
    satirlar = [(f"{z:%Y-%m-%dT%H:%M:%S}", tx(), g, a, tu, et) for z, g, a, tu, et in sat]
    tum_cikis = sum(r[4] for r in satirlar if r[2] == havuz)
    rng.shuffle(satirlar)
    rng.shuffle(bilinen)
    return {"m": m, "tur": tur, "sozlesme": metin, "bilgi": bilgi, "satirlar": satirlar, "bilinen": bilinen,
            "havuz": havuz, "saldirgan": saldirgan, "zincir": zincir, "mikser": mikser, "mikser2": mikser2,
            "toplam": toplam, "parca": parca, "tum_cikis": tum_cikis, "gercek": gercek, "yedek_b": yedek_b,
            "borsa_adr": borsa_adr[gercek]}


def _borsa_kabul(ad: str) -> list:
    return [ad, ad.replace(" ", ""), ad.replace(" ", "_"), ad.replace(" ", "-")]


def _veri(b) -> dict:
    return veri_uret(random.Random(b.senaryo["_alt"]))


def uret(rng):
    alt = rng.randint(1, 10**9)
    d = veri_uret(random.Random(alt))
    m = d["m"]
    return {
        "vaka": f"{m['ad']} — açığı bul, parayı izle",
        "_alt": alt,
        "musteri": m,
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "havuz": d["bilgi"]["sozlesme"],
                  "havuz_adr": d["havuz"],
                  "olay": f"{m['ad']} ({m['sektor']}), zincir üstünde çalışan **{d['bilgi']['sozlesme']}** adlı "
                          "kasa sözleşmesinden izinsiz bir çıkış tespit etti. Para şu an zincirde hareket ediyor."},
        "cevaplar": {
            "tur": d["tur"],
            "fonk": d["bilgi"]["fonk"],
            "satir": d["bilgi"]["satir"],
            "saldirgan": d["saldirgan"],
            "tutar": d["toplam"],
            "borsa": _borsa_kabul(d["gercek"]),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    d = veri_uret(random.Random(s["_alt"]))
    u.yaz(lab / "sozlesme.sol", d["sozlesme"])
    u.yaz(lab / "islemler.csv",
          BASLIK_ISLEM + "\n" + "\n".join(",".join(str(c) for c in r) for r in d["satirlar"]) + "\n")
    u.yaz(lab / "bilinen_adresler.csv",
          BASLIK_ADRES + "\n" + "\n".join(f"{a},{e}" for a, e in d["bilinen"]) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{d['m']['ad']} — birleşik vaka klasörü (kurgusal veri)\n\n"
          "sozlesme.sol         : olaya karışan kasa sözleşmesinin kaynak kodu (içinde tek bir açık var)\n"
          "islemler.csv         : zincirden derlenen işlem defteri (satırlar karışık)\n"
          "                       sütunlar: zaman, tx (işlem kodu), gonderen, alici, tutar_eth, etiket\n"
          "bilinen_adresler.csv : analiz ekibinin bildiği adresler (sözleşme, mikser, borsa yatırım adresleri,\n"
          "                       müşteriler). Listede olmayan adres = bilinmeyen.\n\n"
          f"Sözleşmenin zincirdeki adresi: {d['havuz']}\n"
          "Not: Tutarlar tam ETH olarak yazılmıştır. Her şey kurgusaldır; çalıştırılacak bir kod yoktur.\n")


# ---------------------------------------------------------------- sık hata geri bildirimleri

class TurSecmeli(Secmeli):
    """Açık türü: doğru şık senaryodaki türe göre değişir (şıklar sabit, doğru olan tohuma bağlı)."""
    SIRA = ["r", "a", "t", "o"]

    def _dogru_no(self, b) -> int:
        return self.SIRA.index(b.senaryo["cevaplar"]["tur"])

    def dogrula(self, girdi, b):
        g = norm(girdi)[:1]
        harfler = "abcd"
        sira = self._sira(b)
        if not g or g not in harfler:
            return Sonuc(False, "Şıklardan birini yaz: a, b, c veya d.")
        secilen = sira[harfler.index(g)]
        dogru = secilen == self._dogru_no(b)
        return Sonuc(dogru, ("Doğru. " if dogru else "Bu dosyada bu kalıp yok. ") + self.secenekler[secilen][1])

    def cevabi_goster(self, b):
        i = self._dogru_no(b)
        return f"{'abcd'[self._sira(b).index(i)]}) {self.secenekler[i][0]}"


def _satir_hata(g, beklenen, b):
    n = int(g)
    d = _veri(b)
    satirlar = d["sozlesme"].splitlines()
    if n == beklenen + 1 or n == beklenen - 1:
        return "Bir satır kaymış. `grep -n` numarayı dosyadaki gerçek satır numarasıyla verir; `cat -n` de aynısını gösterir."
    if 1 <= n <= len(satirlar):
        x = satirlar[n - 1]
        if d["tur"] == "r" and "bakiyeler[msg.sender] -=" in x:
            return ("Bu, bakiyeyi güncelleyen satır. Sorun satırın kendisi değil, **para gönderen çağrıdan sonra** "
                    "gelmesi. Çağrının kendisi hangi satırda?")
        if "contract " in x or x.strip().startswith("pragma"):
            return "Bu dosyanın başlığı. Zafiyetin olduğu işlevin içine bak."
    return None


def _fonk_hata(g, beklenen, b):
    if g in ("yatir", "komisyonayarla", "durdur", "constructor"):
        return "Bu işlev ya sıradan bir iş yapıyor ya da düzgün korunuyor. Açığı taşıyan işlevi ara."
    return None


def _saldirgan_hata(g, beklenen, b):
    d = _veri(b)
    if g == d["havuz"]:
        return "Bu, sözleşmenin (kurbanın) kendi adresi. Para ondan çıktı; parayı alan adresi ara."
    if g in d["zincir"][1:]:
        return "Bu adres zincirin ilerisinde bir hop. Sözleşmeden parayı **doğrudan** alan adres aranıyor."
    if g in (d["mikser"], d["mikser2"]):
        return "Bu bir mikser (paranın izini karıştıran havuz); ilk alıcı değil, sonraki bir halka."
    return None


def _tutar_hata(g, beklenen, b):
    d = _veri(b)
    n = int(g)
    if n == d["tum_cikis"] and n != beklenen:
        return ("Sözleşmenin bütün çıkışlarını topladın; müşterilere yapılan meşru çekimler de içinde. Sadece "
                "`bilinen_adresler.csv`'de **olmayan** adrese giden çıkışları topla.")
    if d["parca"] and n == d["parca"]:
        return "Tek bir çekimi aldın; açık, aynı çekimin art arda tekrarlanmasına izin vermiş. Hepsini topla."
    return None


def _borsa_hata(g, beklenen, b):
    d = _veri(b)
    yedek = {x.casefold().replace("ı", "i") for x in _borsa_kabul(d["yedek_b"])}
    if g in yedek:
        return ("Bu borsa yedek mikserin çıkışlarında geçiyor; saldırganın parası o mikserden geçmedi. Önce zinciri "
                "hop hop izleyip hangi mikserin kullanıldığını bul.")
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    # Faz 1: açığı bul (gerçek grep/awk)
    if sh("grep -c 'call{value' sozlesme.sol", lab) != "0":
        tur, satir = "r", sh("grep -n 'call{value' sozlesme.sol | cut -d: -f1", lab)
    elif sh("grep -c 'tx.origin' sozlesme.sol", lab) != "0":
        tur, satir = "t", sh("grep -n 'tx.origin' sozlesme.sol | cut -d: -f1", lab)
    else:
        tur = "a"
        satir = sh(r"awk '/function/{h=$0;n=NR;getline nx; if (h !~ /sadeceSahip/ && h !~ /payable/ "
                   r"&& nx !~ /require\(msg.sender/) print n}' sozlesme.sol", lab)
    fonk = sh(f"awk -v n={satir} 'NR<=n && /function /{{f=$0}} END{{print f}}' sozlesme.sol "
              "| sed -E 's/.*function ([A-Za-z0-9_]+)\\(.*/\\1/'", lab)
    # Faz 2: parayı izle
    havuz = sh("grep HAVUZ bilinen_adresler.csv | cut -d, -f1", lab)
    birlestir = "NR==FNR{b[$1]=1;next}"
    saldirgan = sh(f"awk -F, -v h={havuz} '{birlestir} $3==h && !($4 in b){{print $4}}' "
                   "bilinen_adresler.csv islemler.csv | sort -u | head -1", lab)
    tutar = sh(f"awk -F, -v h={havuz} '{birlestir} $3==h && !($4 in b){{s+=$5}} END{{print s}}' "
               "bilinen_adresler.csv islemler.csv", lab)
    mikser, cur = "", saldirgan
    for _ in range(12):
        sonraki = sh(f"grep -F '{cur}' islemler.csv | awk -F, -v a={cur} '$3==a{{print $4}}' | sort -u | head -1", lab)
        if not sonraki:
            break
        if sh(f"grep -c '^{sonraki},MIKSER' bilinen_adresler.csv", lab) == "1":
            mikser = sonraki
            break
        cur = sonraki
    ex = sh(f"awk -F, -v m={mikser} 'NR==FNR{{e[$1]=$2;next}} $3==m && ($4 in e) && e[$4] ~ /^BORSA/ {{print $4}}' "
            "bilinen_adresler.csv islemler.csv | head -1", lab)
    borsa = sh(f"grep '^{ex},' bilinen_adresler.csv | cut -d, -f2 | sed 's/^BORSA //; s/ yatirim$//'", lab)
    cozum = {1: "", 2: fonk, 3: satir, 4: saldirgan, 5: tutar, 6: borsa, 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


# ---------------------------------------------------------------- eğitim adımları (hafif)

ADIMLAR = [
    Adim("İki fazlı vaka", """
Selin: "Bu sefer iş iki parçalı. **Faz 1:** sözleşmeyi okuyup açığın ne olduğunu ve tam olarak nerede olduğunu
bul. **Faz 2:** o açıkla çıkan parayı zincirde izle: kim aldı, hangi adreslerden geçti, hangi borsaya
girdi? İkisini de daha önce ayrı ayrı yaptın; şimdi birleştireceksin." Klasörün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Faz 1: işlevleri listele", """
Önce sözleşmenin hangi işlevleri olduğunu ve her birinin kimin çağırabileceğini görmek gerekir. `grep -n`
satır numarasıyla birlikte eşleşen satırları yazar:
""", komut="grep -n 'function' sozlesme.sol", sonra="""
Her `external` işlev için tek soru: **bunu kim çağırabilir?** Para ya da yetki yöneten bir işlev
korumasızsa ya da koruması yanlışsa açık oradadır.
"""),
    Adim("Faz 1: açık desenini tara", """
Açık kalıplarının kendine özgü izleri var: para gönderen harici çağrı (`call`), yetki için işlemi başlatana
bakmak (`origin`) ve yetki kontrolleri (`msg.sender`). Üçünü birden tara:
""", komut="grep -n -E 'call|origin|msg.sender' sozlesme.sol", sonra="""
Çıktıyı oku: bir dış çağrıdan **sonra** durum güncelleniyorsa reentrancy; yetkiyi işlemi başlatan kişiye
bağlayan satır varsa tx.origin; yönetici işlevlerinden biri hiç kontrol içermiyorsa eksik erişim kontrolü.
Satır numaraları görevde lazım olacak.
"""),
    Adim("Faz 2: sözleşmeden çıkan parayı yakala", """
Şimdi zincire geç. Sözleşmenin adresinden **bilinmeyen** (listede olmayan) bir adrese giden her çıkış
şüphelidir; meşru müşteri çekimleri bilinen adreslere gider. `awk` iki dosyayı birleştirir:
""", komut="awk -F, -v h=<<havuz_adr>> 'NR==FNR{b[$1]=1;next} $3==h && !($4 in b)' bilinen_adresler.csv islemler.csv",
         sonra="""
Gördüğün satırlar açığın sömürüldüğü anın zincirdeki izi. Satır sayısı ve tutarların deseni açık türüyle
tutarlı mı? (Art arda aynı tutar, tek büyük çekim...) Alıcı adres saldırganın ilk durağıdır.
"""),
    Adim("Faz 2: hop'tan borsaya", """
Saldırgan adresten başlayarak her adresin **giden** işlemini `grep` ile izle; zincir bir mikserde (paranın
izini karıştıran havuz) biter, mikserin çıkışlarından biri de bir borsaya gider. Bilinen mikser ve borsaları
listele:
""", komut="grep -E 'MIKSER|BORSA' bilinen_adresler.csv", sonra="""
Dikkat: birden fazla mikser ve borsa var. Hangisinin saldırganın parasını aldığını sadece zinciri **elle
izleyerek** anlarsın; borsa, dondurma talebinin gideceği adrestir.
"""),
]

# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`sozlesme.sol` içinde tek bir açık var. Hangi **açık türü**?",
          TurSecmeli([
              ("Reentrancy: para gönderen harici çağrı, bakiye güncellenmeden önce yapılıyor",
               "Reentrancy'nin izi: `call{value` satırı, bakiyeyi düşüren satırdan önce gelir."),
              ("Eksik erişim kontrolü: yönetici yetkisini değiştiren bir işlev kimseye sormuyor",
               "Eksik erişim kontrolünün izi: bir yönetici işlevi `sadeceSahip` ya da `require(msg.sender == ...)` "
               "içermez."),
              ("`tx.origin` ile yetkilendirme: yetki, işlemi başlatan kişiye göre kontrol ediliyor",
               "`tx.origin` izi: yetki `require(tx.origin == ...)` ile kontrol edilir; arada başka bir sözleşme "
               "girerse kullanıcı kandırılabilir."),
              ("Tamsayı taşması: çıkarma işlemi sınırı aşıp başa dönüyor",
               "Solidity 0.8 ve sonrasında taşma varsayılan olarak işlemi geri alır; dosyanın `pragma` satırı 0.8.20."),
          ]),
          ("`cat -n sozlesme.sol` ile oku; her `external` işlev için \"bunu kim çağırabilir, ne zaman günceller?\" "
           "diye sor.",
           "`grep -n -E 'call|origin|msg.sender' sozlesme.sol` üç açık türünün de izini aynı anda tarar.",
           "`call{value` varsa reentrancy, `tx.origin` varsa yetki hatası; ikisi de yoksa korumasız bir yönetici "
           "işlevi aranır."),
          puan=30, baslik="Açık türü"),
    Gorev("Açığı taşıyan **işlevin adı** nedir? (Yalnızca ad, örn. `paraCek`.)",
          Metin("fonk", sik_hatalar=_fonk_hata, bicim="işlev adı"),
          ("Açığı taşıyan satırın hangi `function` bloğunun içinde olduğuna bak.",
           "`grep -n 'function' sozlesme.sol` işlevlerin satır numaralarını verir; açık satırından hemen önceki "
           "`function` başlığı cevaptır.",
           "Eksik erişim kontrolünde işlevin kendisi korumasızdır; diğer iki türde açık işlevin içindeki bir satırdır."),
          puan=25, baslik="Zafiyetli işlev"),
    Gorev("Zafiyetin **satır numarası** kaç? (Reentrancy'de para gönderen `call` satırı, `tx.origin`'de yetki "
          "kontrol satırı, eksik erişim kontrolünde korumasız işlevin `function` başlık satırı.)",
          Sayi("satir", sik_hatalar=_satir_hata),
          ("Satır numarasını `grep -n` ya da `cat -n` verir; elle sayma.",
           "Önceki görevde bulduğun türe göre `grep -n 'call{' sozlesme.sol`, `grep -n 'tx.origin' sozlesme.sol` ya da "
           "`grep -n 'function <ad>' sozlesme.sol`.",
           "Çıktının başındaki sayı (iki nokta üst üsteye kadar) satır numarasıdır."),
          puan=30, baslik="Zafiyet satırı"),
    Gorev("**Faz 2:** Bu açıkla sözleşmeden (`<<havuz_adr>>`) para çeken **saldırgan adresi** hangisi? (Para "
          "sözleşmeden bilinmeyen bir adrese gitmiş.)",
          Metin("saldirgan", sik_hatalar=_saldirgan_hata, bicim="0x... adres"),
          ("Meşru müşteri çekimleri bilinen adreslere gider; hırsızlık bilinmeyen birine.",
           "`awk` iki dosyayı birleştirir: `NR==FNR{b[$1]=1;next}`; `!($4 in b)` bilinmeyen alıcıları seçer.",
           "`awk -F, -v h=<<havuz_adr>> 'NR==FNR{b[$1]=1;next} $3==h && !($4 in b){print $4}' bilinen_adresler.csv "
           "islemler.csv | sort -u`"),
          puan=30, baslik="Saldırgan adresi"),
    Gorev("Açığın sömürülmesiyle sözleşmeden çıkan **toplam tutar** kaç ETH? (Sözleşmeden bilinmeyen adrese giden "
          "bütün çıkışlar.)",
          Sayi("tutar", sik_hatalar=_tutar_hata),
          ("Birden fazla çıkış olabilir; hepsini topla, meşru müşteri çekimlerini hariç tut.",
           "Önceki görevdeki süzgeç `!($4 in b)`; 5. sütunu toplayacaksın.",
           "`awk -F, -v h=<<havuz_adr>> 'NR==FNR{b[$1]=1;next} $3==h && !($4 in b){s+=$5} END{print s}' "
           "bilinen_adresler.csv islemler.csv`"),
          puan=35, baslik="Çalınan tutar"),
    Gorev("Saldırgan parayı hop hop ilerletip bir mikserden geçirdi; mikserin çıkışlarından biri bir **borsanın** "
          "yatırım adresine gitti. Hangi borsa? (Sadece adı, örn. `Yildiz Takas`.)",
          Metin("borsa", sik_hatalar=_borsa_hata, bicim="borsa adı (en fazla iki-üç kelime)"),
          ("Önce saldırgan adresten başlayıp her adresin **giden** işlemini izle; son halka bir mikserdir.",
           "`grep -F ADRES islemler.csv | awk -F, '$3==\"ADRES\"{print $4}'` ile bir sonraki adrese geç; alıcı "
           "`bilinen_adresler.csv`'de MIKSER etiketliyse dur. Sonra mikserin çıkışlarına bak.",
           "Mikserden çıkan işlemlerin alıcılarını `bilinen_adresler.csv` ile birleştir ve etiketi `BORSA` ile "
           "başlayanı seç; yedek mikserin çıkışındaki borsa tuzaktır."),
          puan=40, baslik="Borsa çıkışı"),
    Gorev("Hem açığı hem parasının borsaya girdiğini buldun. **En doğru müdahale** hangisi?",
          Secmeli([
              ("Açığı yamala (düzeltilmiş sözleşmeyi yayınla ya da sözleşmeyi durdur), kanıtı (adresler, tx kodları) "
               "borsanın uyum ekibine ilet, dondurma iste ve resmî suç duyurusu yap",
               "Doğru. Hem kanamayı durdurursun hem de kimlik doğrulaması yapan borsa üzerinden parayı yakalama "
               "şansı doğar."),
              ("Sadece borsaya yaz, sözleşmeyi olduğu gibi çalışır halde bırak",
               "Yeni bir saldırı aynı açıktan tekrar para çekebilir; önce açık kapatılmalı."),
              ("Sözleşmeyi yamamadan saldırganla pazarlık edip parayı geri iste",
               "Zaman kaybı ve risk: açık açık kalır, para borsadan çıkabilir; resmî ve hızlı bildirim öncelik olmalı."),
              ("Mikser adresine karşı saldırı yapıp içindeki parayı kendi cüzdanına çek",
               "Yasadışı (hack-back) ve masum kişilerin parasına zarar verir; müdahale yasal kanallardan olur."),
          ]),
          ("Hem açığın kendisini hem çalınan parayı düşün; ikisi de ele alınmalı.",
           "Borsalar kimlik doğrulaması tutar ve dondurma yetkisi onlardadır; saldırgana karşı kendi başına saldırı "
           "suçtur.",
           "Doğru şık: açığı yamala + kanıt ve dondurma talebi + resmî duyuru."),
          puan=30, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="c22b05",
    cilt=22,
    bolum=5,
    baslik="Capstone: Açığı Bul, Parayı İzle",
    brifing="""
**<<musteri>>** (<<sektor>>): <<olay>> Yönetim acil destek istiyor.

Selin klasörü masaya bırakıyor: "Sözleşme kaynak kodu `sozlesme.sol`, zincirden derlenen işlemler
`islemler.csv`, bildiğimiz adresler `bilinen_adresler.csv`. Önce **açığı bul**: ne tür, hangi işlev, hangi
satır. Sonra o açıkla çıkan **parayı izle**: kim aldı, ne kadar, hangi borsada durdu?" Mert ekliyor: "Önceki
iki bölümde ayrı ayrı yaptığın şeyleri tek vakada birleştireceksin." Deniz: "Biz mavi tarafız: bulur, izler,
raporlarız. İstismar kodu yazmak yok."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Saldırgan açısından yayınlanmış bir sözleşme herkesin okuyabileceği açık koddur ve açık bir kez
sömürülünce her adım zincire kalıcı yazılır. Savunmacı açısından ders iki yönlü: **önleme** (her dış çağrıyı
Checks-Effects-Interactions sırasıyla yaz, yetki için `msg.sender` kullan, her `external` işleve "bunu kim
çağırabilir?" diye sor, yayından önce bağımsız denetim yaptır) ve **müdahale** (kanıtı hızlı topla, açığı kapat,
borsalarla önceden kurulmuş kanaldan dondurma iste, hack-back yapma). Kanamayı durdurmadan parayı kovalamak yarım
iştir; parayı kovalamadan açığı kapatmak da öyle.
""",
    gercek_hayat="""
- **The DAO (2016):** Ethereum üzerindeki bu fon sözleşmesinde, para gönderildikten sonra bakiye güncellemesi gibi
  bir reentrancy (yeniden giriş) açığı çok büyük bir varlık kaybına yol açtı; paranın akıbeti ağda uzun
  tartışmalara neden oldu. Sonraki yıllarda reentrancy türü drenajlar birçok protokolde tekrar görüldü; ders:
  Checks-Effects-Interactions sırası ve yeniden-giriş kilidi.
- **Zincir izleme ve borsa dondurma:** Büyük hırsızlıklarda analiz firmaları ve kolluk, çalınan paranın izini
  adres adres sürer; para nakde dönmek için çoğu zaman kimlik doğrulaması yapan bir borsaya girer ve dondurma
  talebi orada sonuç verebilir. Ağustos 2022'de ABD Hazine Bakanlığı (OFAC) Tornado Cash adlı mikser hizmetine
  yaptırım uyguladı; borsalar ve analistler bu tür adreslere gelen/giden parayı işaretleyebilir.
- **Hazırlık:** Olaydan önce borsalarla iletişim kanalı, bilinen adres listeleri, acil durdurma (pause) işlevi ve
  bağımsız kod denetimi hazır olan kurum, hem açığı daha hızlı kapatır hem parayı daha çok yakalar.
""",
    sure_hedef_dk=35,
)
