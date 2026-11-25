"""Cilt 22 · Bölüm 2 — Akıllı Sözleşme Açıkları.

Beceri: kurgusal Solidity parçalarını **okuyup** açık kalıbını tanımak (reentrancy, eksik erişim kontrolü,
tx.origin ile yetkilendirme, tamsayı taşması), zafiyetli satırı bulmak ve düzeltmek. Akıllı sözleşme
denetimi (audit) güvenli kod okuma işidir; bu seviyede hiçbir istismar kodu yazılmaz ve çalıştırılmaz.

Laboratuvar: her biri tek açık taşıyan dört küçük sözleşme dosyası. Derleyici gerekmez; analiz grep, sed
ve göz iledir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

VAKALAR = [
    {"kod": "paramix", "ad": "Paramix", "kisi": "Ece Hanım",
     "c": {"r": "HakedisKasasi", "a": "KomisyonYoneticisi", "t": "OdemeGonderici", "o": "SadakatPuani"},
     "bakiye": "hakedis", "yatir": "hakedisYatir", "cek": "hakedisCek", "sahip": "yonetici",
     "zayif": "yoneticiDegistir", "ayar": "komisyonAyarla", "durdur": "acilDurdur",
     "olay": "Paramix, tedarikçi hakedişlerini ve sadakat puanlarını zincir üstünde tutan dört küçük sözleşme "
             "yayınlamaya hazırlanıyor. Yayınlandıktan sonra kod değiştirilemeyecek."},
    {"kod": "ferahbank", "ad": "Ferah Bank", "kisi": "Kaan Bey",
     "c": {"r": "TeminatKasasi", "a": "LimitYoneticisi", "t": "TahsilatCuzdani", "o": "SubePuani"},
     "bakiye": "teminat", "yatir": "teminatYatir", "cek": "teminatCek", "sahip": "sorumlu",
     "zayif": "limitGuncelle", "ayar": "oranAyarla", "durdur": "islemleriDurdur",
     "olay": "Ferah Bank'ın inovasyon ekibi, kurumsal müşteriler için zincir üstü teminat ve limit sözleşmeleriyle "
             "bir pilot çalışma yapıyor. İç denetim, yayından önce kod incelemesi istedi."},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "kisi": "Serdar Bey",
     "c": {"r": "EmanetHesabi", "a": "NavlunYoneticisi", "t": "HakedisCuzdani", "o": "TeslimJetonu"},
     "bakiye": "emanet", "yatir": "emanetYatir", "cek": "emanetCek", "sahip": "operator",
     "zayif": "navlunBedeliGuncelle", "ayar": "kesintiAyarla", "durdur": "sevkiyatiDurdur",
     "olay": "Kuzgun Lojistik, taşeronlarla emanet ve navlun ödemesi yapan küçük sözleşmeler geliştirdi ve "
             "yayınlamadan önce bağımsız bir okuma bekliyor."},
]

TURLER = {"r": "reentrancy (harici çağrıdan sonra durum güncelleme)", "a": "eksik erişim kontrolü",
          "t": "tx.origin ile yetkilendirme", "o": "tamsayı taşması (overflow/underflow)"}
KOD_ADI = {"r": "reentrancy: işlem bitmeden sözleşmenin tekrar çağrılabilmesi",
           "a": "erişim kontrolü: yetkisiz kişinin yönetici işlevini çağırabilmesi",
           "t": "tx.origin: işlemi başlatan kişiyle doğrudan çağıranı karıştırmak",
           "o": "taşma: tamsayının sınırı aşıp başa dönmesi"}
HEADER = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.8.20;", ""]


def _r(v, rng, varyant):
    B, C, YT, CK = v["bakiye"], v["c"]["r"], v["yatir"], v["cek"]
    L = list(HEADER) + [f"// {v['ad']} — kurgusal örnek. Müşteri bakiyesini tutar ve geri öder.",
                        f"contract {C} {{", f"    mapping(address => uint256) public {B};", "",
                        f"    function {YT}() external payable {{", f"        {B}[msg.sender] += msg.value;", "    }", ""]
    if varyant == 0:
        L += [f"    function {CK}() external {{", f"        uint256 miktar = {B}[msg.sender];",
              '        require(miktar > 0, "bakiye yok");',
              '        (bool ok, ) = msg.sender.call{value: miktar}("");',
              '        require(ok, "gonderim basarisiz");', f"        {B}[msg.sender] = 0;", "    }"]
    else:
        L += [f"    function {CK}(uint256 miktar) external {{",
              f'        require({B}[msg.sender] >= miktar, "yetersiz bakiye");',
              '        (bool ok, ) = msg.sender.call{value: miktar}("");',
              '        require(ok, "gonderim basarisiz");', f"        {B}[msg.sender] -= miktar;", "    }"]
    L += ["}"]
    return L


def _a(v, rng, varyant):
    C, SH = v["c"]["a"], v["sahip"]
    L = list(HEADER) + [f"// {v['ad']} — kurgusal örnek. Yönetici ayarları değiştirebilir.", f"contract {C} {{",
                        f"    address public {SH};", "    uint256 public oran;", "    bool public durdu;", "",
                        f"    modifier sadeceYonetici() {{", f'        require(msg.sender == {SH}, "yetki yok");', "        _;",
                        "    }", "", "    constructor() {", f"        {SH} = msg.sender;", "    }", "",
                        f"    function {v['ayar']}(uint256 yeni) external sadeceYonetici {{", "        oran = yeni;", "    }", "",
                        f"    function {v['zayif']}(address yeni) external {{", f"        {SH} = yeni;", "    }", "",
                        f"    function {v['durdur']}() external sadeceYonetici {{", "        durdu = true;", "    }", "}"]
    if varyant == 1:                      # ayar işlevi require ile korunuyor (stil farkı)
        i = next(k for k, x in enumerate(L) if v["ayar"] in x)
        L[i] = f"    function {v['ayar']}(uint256 yeni) external {{"
        L.insert(i + 1, f'        require(msg.sender == {SH}, "yetki yok");')
    return L


def _t(v, rng, varyant):
    C, SH = v["c"]["t"], v["sahip"]
    L = list(HEADER) + [f"// {v['ad']} — kurgusal örnek. Sözleşme bakiyesini yalnızca sahibi gönderebilir.",
                        f"contract {C} {{", f"    address public {SH};", "", "    constructor() {", f"        {SH} = msg.sender;", "    }", "",
                        "    receive() external payable {}", "",
                        "    function gonder(address payable alici, uint256 miktar) external {",
                        f'        require(tx.origin == {SH}, "yetki yok");', "        alici.transfer(miktar);", "    }", "}"]
    if varyant == 1:
        i = next(k for k, x in enumerate(L) if "receive()" in x)
        L.insert(i + 1, "")
        L.insert(i + 2, "    event Gonderildi(address alici, uint256 miktar);")
        j = next(k for k, x in enumerate(L) if "alici.transfer" in x)
        L.insert(j + 1, "        emit Gonderildi(alici, miktar);")
    return L


def _o(v, rng, varyant):
    C, B = v["c"]["o"], "puan"
    L = ["// SPDX-License-Identifier: MIT", "pragma solidity ^0.6.12;", "",
         f"// {v['ad']} — kurgusal örnek. Puan aktarımı. (Solidity 0.8 öncesi: taşma denetimi otomatik değil)",
         f"contract {C} {{", f"    mapping(address => uint256) public {B};", "    address public sahip;", "",
         "    constructor() public {", "        sahip = msg.sender;", "    }", "",
         "    function puanVer(address kime, uint256 miktar) external {", '        require(msg.sender == sahip, "yetki yok");',
         f"        {B}[kime] += miktar;", "    }", "",
         "    function aktar(address kime, uint256 miktar) external {",
         f'        require({B}[msg.sender] - miktar >= 0, "yetersiz puan");',
         f"        {B}[msg.sender] -= miktar;", f"        {B}[kime] += miktar;", "    }", "}"]
    return L


URETICI = {"r": _r, "a": _a, "t": _t, "o": _o}


def sozlesme_uret(rng, v, tur: str) -> tuple:
    """(metin, bilgi). bilgi: ana satır numarası (1'den), sözleşme adı."""
    L = URETICI[tur](v, rng, rng.randint(0, 1))
    if rng.random() < 0.5:                       # başa bir sürüm notu (satır numaraları değişsin)
        L.insert(2 if tur != "o" else 2, f"// sürüm notu: {rng.choice(['v0.3', 'v0.5', 'v0.9', 'v1.1'])} taslak")
    if tur == "r":
        ana = next(i for i, x in enumerate(L, 1) if ".call{value" in x)
    elif tur == "t":
        ana = next(i for i, x in enumerate(L, 1) if "tx.origin" in x)
    elif tur == "o":
        ana = next(i for i, x in enumerate(L, 1) if "- miktar >= 0" in x)
    else:
        ana = next(i for i, x in enumerate(L, 1) if v["zayif"] in x)
    return "\n".join(L) + "\n", {"ana": ana, "ad": v["c"][tur]}


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    kodlar = list("rato")
    rng.shuffle(kodlar)
    dosyalar, bilgi = {}, {}
    for i, k in enumerate(kodlar, 1):
        metin, b = sozlesme_uret(rng, v, k)
        ad = f"{i:02d}_{b['ad']}.sol"
        dosyalar[ad] = metin
        bilgi[k] = {"dosya": ad, **b}
    return {
        "vaka": f"{m['ad']} — zincir üstü sözleşmeler",
        "musteri": m, "v": v, "kodlar": kodlar, "dosyalar": dosyalar, "bilgi": bilgi,
        "metin": {"musteri": m["ad"], "olay": v["olay"], "kisi": v["kisi"], "cek": v["cek"],
                  "sahip": v["sahip"], "r_dosya": bilgi["r"]["dosya"], "t_dosya": bilgi["t"]["dosya"],
                  "a_dosya": bilgi["a"]["dosya"], "r_ad": bilgi["r"]["ad"], "bakiye": v["bakiye"]},
        "cevaplar": {
            "dizi": kodlar,
            "r_satir": bilgi["r"]["ana"],
            "t_satir": bilgi["t"]["ana"],
            "zayif": v["zayif"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    for ad, metin in s["dosyalar"].items():
        u.yaz(lab / "sozlesmeler" / ad, metin)
    liste = "\n".join(f"  {ad}" for ad in sorted(s["dosyalar"]))
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — sözleşme inceleme klasörü (kurgusal kod)\n\n"
          f"sozlesmeler/ altında dört dosya var, her birinde tek bir açık kalıbı:\n{liste}\n\n"
          "Açık kalıpları (eşleme kodları):\n" + "\n".join(f"  {k}) {t}" for k, t in KOD_ADI.items()) + "\n\n"
          "Çalıştırılacak bir şey yok; sadece okunacak ve düzeltilecek. Düzeltmeyi dosyanın kendisinde yap\n"
          "(nano ya da sed -i ile).\n")
    u.yaz(lab / "ornekler" / "denetim_listesi.txt", DENETIM, mod=0o644)
    u.yaz(lab / "ornekler" / "duzeltme_kaliplari.txt", DUZELTME, mod=0o644)


DENETIM = """Akıllı sözleşme okuma listesi (grep ile ilk tarama)

- Harici çağrı:     grep -n 'call{' *.sol   |  .transfer(  |  .send(
                    Çağrıdan SONRA durum değişkeni güncelleniyor mu?
- Yetkilendirme:    grep -n 'tx.origin' *.sol
                    Yönetici işlevlerinde 'require(msg.sender == ...)' ya da bir modifier var mı?
- Aritmetik:        grep -n 'pragma' *.sol   (0.8'den eski sürüm = taşma denetimi yok)
                    'uint - uint >= 0' gibi her zaman doğru olan koşullar
- Her 'external' ya da 'public' işlev için sor: bunu KİM çağırabilir?
"""

DUZELTME = """Genel düzeltme kalıpları (kavramsal)

1) Reentrancy -> Checks-Effects-Interactions (kontrol, etki, etkileşim) sırası:
       require(...)             // 1. kontroller
       durum_degiskeni -= x;    // 2. durumu GÜNCELLE
       (bool ok,) = hedef.call{value: x}("");   // 3. en son dış dünyayla konuş

2) tx.origin -> msg.sender:
       require(msg.sender == sahip, "yetki yok");
   (tx.origin işlemi başlatan kişidir; arada başka bir sözleşme varsa msg.sender doğrudan çağıranı verir.)

3) Eksik erişim kontrolü -> işleve bir koruma ekle:
       function f(...) external sadeceYonetici { ... }
   ya da gövdeye: require(msg.sender == sahip, "yetki yok");

4) Taşma -> Solidity >= 0.8 kullan (varsayılan denetimli aritmetik) ya da önce kontrol et:
       require(bakiye[msg.sender] >= miktar, "yetersiz");
"""


# ---------------------------------------------------------------- durum denetimi

def _gövde(metin: str, fonk: str) -> list:
    """`function fonk(`'tan eşleşen süslü parantezin kapanışına kadar olan satırlar (0 tabanlı sıra, satır)."""
    satirlar = metin.splitlines()
    for i, x in enumerate(satirlar):
        if re.search(rf"\bfunction\s+{re.escape(fonk)}\s*\(", x):
            derin, sonuc = 0, []
            for j in range(i, len(satirlar)):
                sonuc.append((j, satirlar[j]))
                derin += satirlar[j].count("{") - satirlar[j].count("}")
                if derin == 0 and "{" in "".join(y for _, y in sonuc):
                    return sonuc
            return sonuc
    return []


def _oku(b: Baglam, dosya: str) -> tuple:
    yol = Path(b.lab) / "sozlesmeler" / dosya
    if not yol.is_file():
        return None, f"`sozlesmeler/{dosya}` dosyası yok. Lab'ı bozduysan `sifirla` ile yeniden kur."
    return yol.read_text(encoding="utf-8", errors="replace"), ""


def _r_duzeltildi(b: Baglam) -> Sonuc:
    s = b.senaryo
    ad = s["bilgi"]["r"]["dosya"]
    metin, hata = _oku(b, ad)
    if hata:
        return Sonuc(False, hata)
    govde = _gövde(metin, s["v"]["cek"])
    if not govde:
        return Sonuc(False, f"`{s['v']['cek']}` işlevi bulunamadı; işlevi silmeden düzelt.")
    B = s["v"]["bakiye"]
    cagri = [j for j, x in govde if ".call{" in x or ".transfer(" in x or ".send(" in x]
    guncelle = [j for j, x in govde if re.search(rf"{B}\[msg\.sender\]\s*(=|-=)", x)]
    if not cagri:
        return Sonuc(False, "Para gönderen çağrıyı silmişsin; işlev artık geri ödeme yapmıyor. Çağrı kalmalı, sadece "
                     "sırası değişmeli.")
    if not guncelle:
        return Sonuc(False, f"`{B}[msg.sender]` güncelleyen satır kalmamış. Bakiye mutlaka düşürülmeli.")
    if min(guncelle) < min(cagri):
        return Sonuc(True, "Bakiye artık para gönderilmeden **önce** güncelleniyor (Checks-Effects-Interactions). "
                           "Sözleşme dışarıdan geri çağrılsa bile bakiye zaten sıfırlanmış olur.")
    return Sonuc(False, "Bakiyeyi güncelleyen satır hâlâ para gönderen `call` satırından **sonra**. Güncellemeyi "
                 "çağrının üstüne taşı (kontroller -> durum güncelleme -> dış çağrı).", yakin=True)


def _t_duzeltildi(b: Baglam) -> Sonuc:
    s = b.senaryo
    ad = s["bilgi"]["t"]["dosya"]
    metin, hata = _oku(b, ad)
    if hata:
        return Sonuc(False, hata)
    if "tx.origin" in metin:
        return Sonuc(False, "Dosyada hâlâ `tx.origin` geçiyor. Yetki kontrolünde doğrudan çağıranı veren `msg.sender` "
                     "kullan.")
    govde = " ".join(x for _, x in _gövde(metin, "gonder"))
    if not re.search(rf"require\(\s*msg\.sender\s*==\s*{s['v']['sahip']}", govde):
        return Sonuc(False, f"`gonder` işlevinde `require(msg.sender == {s['v']['sahip']}, ...)` kontrolü olmalı. "
                     "Kontrolü silmek açığı kapatmaz, yetkiyi tamamen kaldırır.", yakin=True)
    return Sonuc(True, "Yetki kontrolü artık `msg.sender` üzerinden yapılıyor: arada başka bir sözleşme olsa bile "
                       "yetkiyi doğrudan çağıran belirler, işlemi başlatan kişi değil.")


def _r_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    metin = b.senaryo["dosyalar"][b.senaryo["bilgi"]["r"]["dosya"]].splitlines()
    B = b.senaryo["v"]["bakiye"]
    if 1 <= n <= len(metin) and re.search(rf"{B}\[msg\.sender\]\s*(=|-=)", metin[n - 1]):
        return ("Bu, bakiyeyi güncelleyen satır. Sorun satırın kendisi değil, **para gönderen çağrıdan sonra** "
                "gelmesi. Çağrının kendisi hangi satırda?")
    if n == beklenen + 1 or n == beklenen - 1:
        return "Bir satır kaymış. `grep -n` numarayı dosyadaki gerçek satır numarasıyla verir; `cat -n` de aynısını gösterir."
    return None


def _t_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1 or n == beklenen - 1:
        return "Bir satır kaymış. `grep -n 'tx.origin' dosya` doğrudan doğru numarayı verir."
    return None


def coz(lab: Path, s: dict) -> dict:
    r, t, a = s["bilgi"]["r"]["dosya"], s["bilgi"]["t"]["dosya"], s["bilgi"]["a"]["dosya"]
    # eşleme: her dosya için kalıba göre tür kodu
    kodlar = []
    for ad in sorted(s["dosyalar"]):
        yol = f"sozlesmeler/{ad}"
        if sh(f"grep -c 'call{{value' {yol}", lab) != "0":
            kodlar.append("r")
        elif sh(f"grep -c 'tx.origin' {yol}", lab) != "0":
            kodlar.append("t")
        elif sh(f"grep -c 'pragma solidity \\^0.6' {yol}", lab) != "0":
            kodlar.append("o")
        else:
            kodlar.append("a")
    r_satir = sh(f"grep -n 'call{{' sozlesmeler/{r} | cut -d: -f1", lab)
    t_satir = sh(f"grep -n 'tx.origin' sozlesmeler/{t} | cut -d: -f1", lab)
    # korumasız işlev: 'external' ve bir koruma içermeyen
    zayif = sh(r"awk '/function/{h=$0; getline n; if (h !~ /sadeceYonetici/ && n !~ /require\(msg.sender/) print h}' "
               rf"sozlesmeler/{a} | sed -E 's/.*function ([A-Za-z]+)\(.*/\1/'", lab)
    # düzeltmeler: gerçekten yapılır
    B, cek = s["v"]["bakiye"], s["v"]["cek"]
    sh(f"f=sozlesmeler/{r}; upd=$(grep -E '{B}\\[msg.sender\\] (=|-=)' $f | head -1); "
       f"grep -v -F \"$upd\" $f > $f.tmp; "
       f"awk -v upd=\"$upd\" '/call{{value/ && !yapildi {{print upd; yapildi=1}} {{print}}' $f.tmp > $f && rm $f.tmp", lab)
    sh(f"sed -i 's/tx.origin/msg.sender/' sozlesmeler/{t}", lab)
    cozum = {1: " ".join(kodlar), 2: r_satir, 3: t_satir, 4: zayif, 5: "", 6: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Kod kanundur, hata da kanundur", """
Selin: "Bir akıllı sözleşme (smart contract), zincir üstünde çalışan ve parayı otomatik yöneten
programdır. Yayınlandıktan sonra çoğu zaman değiştirilemez. Yani koddaki hata da **kanunun** parçasıdır
ve hata = geri alınamaz para kaybı demektir." Bugün bir **denetçi** (auditor) gibi çalışacaksın:
çalıştırmadan, **okuyarak** açık bulacaksın. Klasörün haritası:
""", komut="cat OKUBENI.txt", sonra="""
Dört dosya, dört açık kalıbı. Bu kalıpların hepsi senin zaten bildiğin açıkların zincire taşınmış
hali: erişim kontrolü (Cilt 5) ve iş mantığı hatası (Cilt 10).
"""),
    Adim("Bir sözleşmeyi okumak", """
Solidity'de `contract` bir sınıf gibidir; `function` işlevleri, `mapping` bir sözlüğü, `msg.sender`
**doğrudan çağıranı**, `require(koşul, "mesaj")` bir kontrolü (koşul sağlanmazsa işlem geri alınır) ifade
eder. Dosyaları satır numarasıyla gör (`cat -n`):
""", komut="cat -n sozlesmeler/01_*.sol"),
    Adim("Denetim listesi", """
Denetçiler önce sistematik bir tarama yapar: önce `grep`, sonra okuma. Bu bölümün listesi:
""", komut="cat ornekler/denetim_listesi.txt", sonra="""
Her `external`/`public` işlev için tek soru: **bunu kim çağırabilir?** Cevap "herkes" ise ve işlev para ya da
yetki yönetiyorsa, açık oradadır.
"""),
    Adim("Sürüm ve taşma", """
Solidity 0.8'den önce tamsayılar sınırı aşınca sessizce başa dönerdi (overflow/underflow); denetim için
ayrı bir kütüphane gerekirdi. Sürümlere bak:
""", komut="grep -n 'pragma' sozlesmeler/*.sol", sonra="""
Bir dosya diğerlerinden eski sürümde. Eski sürümde `uint` bir değerden büyük bir sayıyı çıkarırsan
sonuç eksiye değil, **dev bir pozitif sayıya** döner. Bu yüzden `değer - x >= 0` koşulu işaretsiz
sayılarda **her zaman doğrudur**.
"""),
    Adim("Reentrancy'yi anlamak", """
Reentrancy (yeniden giriş), bir sözleşmenin para gönderdiği adresin **kendisi bir sözleşme** olup,
para gelince sizin işlevinizi **işlem bitmeden tekrar çağırabilmesidir**. Bakiye hâlâ eskisi gibi
görünürken ikinci bir çekim denenir. Sorun, sırada: önce para gönder, sonra bakiyeyi düşür.
Çözüm: önce bakiyeyi düşür, sonra para gönder (**Checks-Effects-Interactions**).

Düzeltme kalıpları dosyasına bak (kavramsal, çalıştırılacak bir şey değil):
""", komut="cat ornekler/duzeltme_kaliplari.txt", sonra="""
**Hacker gözüyle:** Reentrancy, "geri alma düğmesi olmayan" bir ortamda klasik bir yarış durumu
(race condition) hatasıdır. Savunma: kontroller, durum güncellemesi, harici çağrı sırasını her zaman bu
sırada yaz; kritik işlevlere ek olarak bir yeniden-giriş kilidi koyabilirsin.
"""),
    Adim("sed ile düzeltme", """
Düzeltmeyi dosyanın kendisinde yapacaksın. Küçük, tek satırlık değişiklikler için `sed -i 's/eski/yeni/'`
işini görür; satır taşımak içinse `nano` kullan. Önce bir kopya üzerinde dene, `sed` metni değiştirmeden
önce çıktıyı gösterir (`-i` olmadan dosyaya yazmaz):
""", komut="echo 'require(tx.origin == sahip);' | sed 's/tx.origin/msg.sender/'", sonra="""
`tx.origin` işlemi **başlatan kişidir**; `msg.sender` ise o işlevi **doğrudan çağıran** adrestir. Araya başka
bir sözleşme girerse `tx.origin` hâlâ kullanıcı olarak kalır; kullanıcıyı kandırıp kötü niyetli bir
sözleşmeye işlem yaptırmak, sahibin yetkisini aşmak anlamına gelebilir. Yetki için hep `msg.sender`.
"""),
]

GOREVLER = [
    Gorev("`sozlesmeler/` altındaki 4 dosyayı **numara sırasıyla** (01, 02, 03, 04) açık kalıbına eşle. "
          "Kodlar `OKUBENI.txt`'de: `r` reentrancy, `a` eksik erişim kontrolü, `t` tx.origin, `o` tamsayı taşması. "
          "Cevap: dört harf (örn. `o r a t`).",
          Dizi("dizi", bicim="dört kod sırayla, örn. o r a t"),
          ("`ornekler/denetim_listesi.txt`'deki grep komutlarıyla her dosyayı tara.",
           "`grep -n 'call{' sozlesmeler/*.sol`, `grep -n 'tx.origin' ...`, `grep -n 'pragma' ...`. Hiçbiri "
           "eşleşmeyen dosyada yetkisiz bir işlev vardır.",
           "`call{` eşleşen = r, `tx.origin` eşleşen = t, `pragma solidity ^0.6` eşleşen = o, kalan = a. "
           "Sonra dosya numarasına göre sırala."),
          puan=40, baslik="Açık kalıbını tanı"),
    Gorev("`sozlesmeler/<<r_dosya>>`: bu sözleşmede reentrancy açığı var. Zafiyetin kaynağı olan "
          "**para gönderen `call` satırı** dosyanın kaçıncı satırı?",
          Sayi("r_satir", sik_hatalar=_r_hata),
          ("Satır numarasını `grep -n` ya da `cat -n` verir. Para gönderen ifade `.call{value: ...}`.",
           "`grep -n 'call{' sozlesmeler/<<r_dosya>>`",
           "Çıktının başındaki sayı (iki nokta üst üsteye kadar) satır numarasıdır."),
          puan=30, baslik="Reentrancy satırı"),
    Gorev("`sozlesmeler/<<t_dosya>>`: bu sözleşme yetkiyi `tx.origin` ile kontrol ediyor. Bu kontrolün olduğu "
          "satır kaçıncı satır?",
          Sayi("t_satir", sik_hatalar=_t_hata),
          ("Aranacak kelime tam olarak `tx.origin`.",
           "`grep -n 'tx.origin' sozlesmeler/<<t_dosya>>`",
           "Çıktının başındaki sayı."),
          puan=25, baslik="tx.origin satırı"),
    Gorev("`sozlesmeler/<<a_dosya>>`: yöneticiyle ilgili işlevlerden **biri** hiçbir yetki kontrolü içermiyor; "
          "herkes çağırabilir. Bu işlevin adı nedir?",
          Metin("zayif", bicim="işlev adı", sik_hatalar=lambda g, b, bg: (
              "Bu işlev `sadeceYonetici` ya da `require(msg.sender == ...)` ile korunuyor. Korumasız olanı ara."
              if g in (bg.senaryo["v"]["ayar"].lower(), bg.senaryo["v"]["durdur"].lower()) else None)),
          ("Her `external` işleve bak: gövdesinde ya da başlığında bir koruma var mı?",
           "`cat -n sozlesmeler/<<a_dosya>>` ile oku; `sadeceYonetici` modifier'ı ve `require(msg.sender == ...)` "
           "satırlarını işaretle.",
           "Üç işlevden ikisi korunuyor; yetkiyi başkasına devreden (yöneticiyi değiştiren) işlevin korumasız olması "
           "en tehlikelisidir."),
          puan=30, baslik="Korumasız işlev"),
    Gorev("**Düzelt:** `sozlesmeler/<<r_dosya>>` içindeki `<<cek>>` işlevinde `<<bakiye>>[msg.sender]` güncellemesi "
          "para gönderen çağrıdan **sonra** yapılıyor. Güncellemeyi çağrının **önüne** taşı (Checks-Effects-"
          "Interactions). Çağrıyı silme. Bitince `cevap 5` yaz.",
          Durum(_r_duzeltildi, "bakiye güncelleme satırını `call` satırının üstüne taşı"),
          ("Sorun kodun içeriğinde değil, **sırasında**.",
           "`nano sozlesmeler/<<r_dosya>>` ile bakiyeyi güncelleyen satırı kes, `call` satırının hemen üstüne yapıştır. "
           "(`cat ornekler/duzeltme_kaliplari.txt` kalıbı gösterir.)",
           "Sıra: `require(...)` kontrolleri, sonra `<<bakiye>>[msg.sender] = 0;` (ya da `-= miktar;`), en son "
           "`(bool ok, ) = msg.sender.call{value: ...}(\"\");` ve onun `require(ok, ...)`'ı."),
          puan=45, baslik="Reentrancy düzeltmesi"),
    Gorev("**Düzelt:** `sozlesmeler/<<t_dosya>>` içinde `tx.origin` yerine doğrudan çağıranı veren `msg.sender` "
          "kullan. Yetki kontrolü (`require`) kalmalı. Bitince `cevap 6` yaz.",
          Durum(_t_duzeltildi, "tx.origin -> msg.sender"),
          ("Kontrolü silme; sadece yetkiyi hangi adresten aldığını değiştir.",
           "`sed -i 's/tx.origin/msg.sender/' sozlesmeler/<<t_dosya>>`",
           "Sonra `grep -n 'tx.origin' sozlesmeler/<<t_dosya>>` çıktı vermemeli, `grep -n 'msg.sender' ...` kontrolü "
           "göstermeli."),
          puan=30, baslik="tx.origin düzeltmesi"),
    Gorev("Reentrancy açığının doğru düzeltme ilkesi hangisidir?",
          Secmeli([
              ("Önce kontrolleri yap, sonra durumu güncelle, en son dış çağrıyı yap",
               "Doğru: Checks-Effects-Interactions. Bakiye düştükten sonra tekrar çağrılsan bile ikinci çekim "
               "başarısız olur."),
              ("Önce parayı gönder, sonra bakiyeyi sıfırla; böylece gönderim başarısızsa bakiye kaybolmaz",
               "Tam tersi açığın kendisidir: gönderim sırasında bakiye hâlâ eski değerdedir."),
              ("İşlevin gövdesine daha fazla `require` ekle ve sırayı değiştirme",
               "Ek kontrol, sıradan doğan sorunu çözmez; bakiye hâlâ çağrıdan sonra düşüyor."),
              ("Sözleşmeyi herkese kapatıp yalnızca sahibin çağırmasına izin ver",
               "Meşru müşteriler de çekim yapamaz; ayrıca sorun yetki değil işlem sırasıdır."),
          ]),
          ("Düzeltme görevinde yaptığın değişikliği hatırla.",
           "Hangi iş önce bitmeli: bakiyeyi düşürmek mi, parayı göndermek mi?",
           "Checks-Effects-Interactions."),
          puan=25, baslik="Düzeltme ilkesi"),
    Gorev("Solidity 0.8 öncesinde `puan[x] - miktar >= 0` gibi bir koşul neden güvenilmezdir? Sürüm 0.8 ve "
          "sonrasında ne değişti?",
          Secmeli([
              ("İşaretsiz sayıda çıkarma sınırı aşınca başa döner; koşul hep doğru olur. 0.8'den itibaren taşma varsayılan "
               "olarak işlemi geri alır",
               "Doğru. Eski sürümlerde ayrı kütüphane (SafeMath) kullanılırdı; 0.8 denetimli aritmetiği varsayılan yaptı."),
              ("Koşul ancak sayı negatifse yanlış olur, o yüzden güvenlidir",
               "`uint` hiçbir zaman negatif olamaz; sonuç başa dönüp dev bir pozitif sayı olur."),
              ("Solidity'de çıkarma işlemi tamamen yasaktır",
               "Çıkarma serbesttir; sorun taşma denetimi olmamasıydı."),
              ("0.8 sürümü bütün açıkları, reentrancy dahil, kendiliğinden kapatır",
               "Sadece aritmetik taşmayı kapatır; reentrancy, yetki hataları ve diğerleri hâlâ kod yazarına aittir."),
          ]),
          ("`uint` negatif olabilir mi?",
           "Çıkarma sınırın altına inince ne olur?",
           "Dosyadaki `pragma` satırı sürümü söylüyor."),
          puan=25, baslik="Taşma"),
]

SEVIYE = Seviye(
    kimlik="c22b02",
    cilt=22,
    bolum=2,
    baslik="Akıllı Sözleşme Açıkları",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> bağımsız bir okuma istiyor.

Selin klasörü masaya bırakıyor: "Dört küçük sözleşme. Çalıştırmayacaksın, derleyici de yok; bir denetçi
gibi **okuyacaksın**. Hangi sözleşmede hangi açık var, hangi satır, ve nasıl düzeltilir?" Mert gülüyor:
"Normal bir uygulamada hatayı yamayıp yeniden yayınlarsın. Burada yayınladığın kod bir daha değişmeyebilir.
Yani **okuyup bulmak** tek şansın." Deniz ekliyor: "İstismar kodu yazmak yok. Biz mavi tarafız: bul, anlat,
düzelt."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Dört küçük dosyada üç kalıp ve bir sürüm sorunu: para gönderdikten sonra bakiye güncellemek (reentrancy),
yetkiyi `tx.origin`'e bağlamak, yönetici işlevini korumasız bırakmak ve eski sürümde işaretsiz çıkarma.
Hepsi satırı satırına okunarak bulundu ve hiçbirini çalıştırman gerekmedi. Saldırgan için ders: yayınlanmış
sözleşmeler herkesin okuyabileceği açık koddur; açık arayan ilk bakacağı yerleri bilir. Savunma için ders:
her dış çağrıyı Checks-Effects-Interactions sırasıyla yaz, yetki için `msg.sender` kullan, her `public`/`external`
işleve "bunu kim çağırabilir?" diye sor, bağımsız bir denetimden geçmeden yayınlama.
""",
    gercek_hayat="""
- **The DAO (2016):** Ethereum üzerindeki bu fon sözleşmesindeki reentrancy türü bir açık, çok büyük bir
  varlık kaybına yol açtı ve ağın nasıl yanıt vereceği konusunda uzun tartışmalara neden oldu. Bu bölümdeki
  Checks-Effects-Interactions ilkesi, o olaydan sonra sözleşme yazımının temel kuralı haline geldi.
  Tespit: kod incelemesinde "çağrıdan sonra durum değişikliği" araması; önlem: işlem sırası ve yeniden-giriş kilidi.
- **Denetim kültürü:** Akıllı sözleşmeler yayınlanmadan önce bağımsız güvenlik denetiminden geçirilir; çünkü
  yayınlanan kodun düzeltilmesi çoğu zaman mümkün değildir ya da pahalıdır. Denetçiler her işlev için
  "kim çağırabilir?" sorusunu sorar ve yetki kontrollerini, harici çağrıları ve aritmetiği tek tek inceler.
- **Aritmetik taşma:** Solidity 0.8 öncesi sözleşmelerde taşma hataları iyi bilinen bir sorun sınıfıydı
  ve bu yüzden SafeMath gibi kütüphaneler yaygınlaştı. Sürüm 0.8 denetimli aritmetiği varsayılan yaptı;
  eski sürümde yazılmış sözleşmeler denetimde özellikle bu açıdan taranır.
""",
    sure_hedef_dk=40,
)
