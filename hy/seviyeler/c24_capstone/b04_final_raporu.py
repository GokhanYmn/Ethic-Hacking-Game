"""Cilt 24 · Bölüm 4 — Capstone'u tamamlamak: final raporu.

Önceki üç vakanın bulguları bir bulgu defterinde toplanmıştır (etki ve olasılık puanlarıyla). Oyuncu puanlama
ölçeğiyle önem derecelerini hesaplar ve kitabın Ek E'sindeki yapıya uygun bir `rapor.md` yazar:
Yönetici Özeti, Kapsam ve Metodoloji, Bulgular (önem sırasına göre; her bulguda Önem, Etki, Kanıt, Öneri),
Sonuç. `Durum` kontrolleri bölümleri, özet sayılarını, alanları ve tutarlılığı (önem = etki x olasılık,
kanıt anahtarı, sıralama) denetler. Yönetici özeti ayrıca `Serbest` ile yazılır. Seviye, stajın sonu hikâyesiyle biter.

Vakalar: aynı bulgu havuzundan farklı müşteri (Paramix, Ferah Bank, Pazarix) ve farklı bulgu karışımı.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c24_capstone.ortak import ascii_kucuk, sec_doldur, sh

MUSTERILER = ["paramix", "ferahbank", "pazarix"]
SEVIYELER = ["Kritik", "Yüksek", "Orta", "Düşük"]

HAVUZ = {
    1: [
        ("Web uygulamasında girdi doğrulaması eksik (komut, sorgu ya da yükleme açığı)", (4, 5), (4, 5), "ip"),
        ("Web sunucusu hesabına (www-data) parolasız sudo yetkisi verilmiş", (4, 5), (3, 4), "sudoers"),
        ("Yükleme dizininde betik çalıştırmaya izin veriliyor", (3, 4), (3, 4), "uploads"),
        ("Web kökünde unutulmuş yedek dosya erişilebilir", (3, 4), (2, 3), "config.php.bak"),
        ("Sunucu yazılımı ve sürümü yanıt başlıklarında ifşa ediliyor", (1, 2), (4, 5), "Server: Apache"),
    ],
    2: [
        ("DMZ'den iç ağa gereğinden fazla güvenlik duvarı kuralı açık", (5, 5), (4, 5), "kurallar.rules"),
        ("Sunucular arasında aynı servis hesabı parolası paylaşılıyor", (4, 5), (3, 4), "svc"),
        ("İç sunucularda parolayla SSH girişi açık", (3, 4), (3, 4), "PasswordAuthentication"),
        ("İç ağdaki tarama ve beklenmeyen bağlantılar için alarm yok", (3, 4), (4, 5), "yakalama.pcap"),
    ],
    3: [
        ("Negatif tutarlı ödeme onaylanıyor", (5, 5), (4, 5), "tutar_gecerli_mi"),
        ("İade tutarı orijinal ve önceki iadelerle sınırlanmıyor", (4, 5), (3, 4), "iade_gecerli_mi"),
        ("Kupon başına kullanım sınırı yok", (2, 3), (4, 5), "kupon"),
        ("3-D Secure adımı atlanarak ödeme tamamlanabiliyor", (4, 5), (3, 4), "atlandi"),
        ("Tam kart numarası (PAN) logda açık yazılıyor", (5, 5), (3, 4), "LOG_KART_NO"),
        ("Kişisel veri (TCKN, telefon) hata ayıklama logunda açık", (4, 4), (3, 4), "DEBUG"),
        ("Eski TLS sürümü (1.0) kabul ediliyor", (3, 4), (2, 3), "TLS_MIN_SURUM"),
        ("Gizli anahtar yapılandırmada düz metin duruyor", (4, 4), (2, 3), "HMAC_ANAHTAR"),
    ],
}
ADET = {1: 2, 2: 2, 3: 3}


def onem_adi(p: int) -> str:
    return "Kritik" if p >= 15 else "Yüksek" if p >= 10 else "Orta" if p >= 6 else "Düşük"


def _bulgular(rng) -> list:
    for _ in range(500):
        liste = []
        for alan in (1, 2, 3):
            for i, (baslik, e, o, kanit) in enumerate(rng.sample(HAVUZ[alan], ADET[alan]), 1):
                if kanit == "ip":
                    kanit = u.dis_ip(rng)
                elif kanit == "svc":
                    kanit = rng.choice(["svc_depo", "svc_yedek", "svc_randevu", "svc_borc"])
                liste.append({"id": f"B{alan}-{i:02d}", "alan": alan, "baslik": baslik, "etki": rng.randint(*e),
                              "olas": rng.randint(*o), "kanit": kanit})
        puanlar = sorted((x["etki"] * x["olas"] for x in liste), reverse=True)
        yuksek = {a: sum(1 for x in liste if x["alan"] == a and x["etki"] * x["olas"] >= 10) for a in (1, 2, 3)}
        sirali = sorted(yuksek.values(), reverse=True)
        kritik = sum(1 for p in puanlar if p >= 15)
        if puanlar[0] > puanlar[1] and sirali[0] > sirali[1] and 1 <= kritik <= 4:
            return liste
    raise RuntimeError("bulgu seti kurulamadı")


def uret(rng):
    m = musteri(rng.choice(MUSTERILER))
    liste = _bulgular(rng)
    for x in liste:
        x["puan"] = x["etki"] * x["olas"]
        x["onem"] = onem_adi(x["puan"])
    rng.shuffle(liste)                      # defterde karışık; ID'ye göre sıralanır
    liste.sort(key=lambda x: x["id"])
    kritik = sum(1 for x in liste if x["onem"] == "Kritik")
    en_riskli = max(liste, key=lambda x: x["puan"])["id"]
    yuksek = {a: sum(1 for x in liste if x["alan"] == a and x["puan"] >= 10) for a in (1, 2, 3)}
    alan = max(yuksek, key=yuksek.get)
    gun = u.gun(rng)
    return {
        "vaka": f"{m['ad']} — {m['sektor']}: birleşik değerlendirme raporu",
        "m": m, "liste": liste, "gun": gun,
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "hikaye": m["hikaye"], "toplam": str(len(liste))},
        "cevaplar": {"kritik": kritik, "riskli": en_riskli, "alan": alan},
    }


def yaz(lab: Path, s: dict) -> None:
    m, liste = s["m"], s["liste"]
    satirlar = ["# ID | Alan | Başlık | Etki (1-5) | Olasılık (1-5) | Kanıt anahtarı",
                "# Alan: 1 = Web'den root'a, 2 = Ağda ilerleme, 3 = Finansal uygulama"]
    for x in liste:
        satirlar.append(f"{x['id']} | {x['alan']} | {x['baslik']} | {x['etki']} | {x['olas']} | {x['kanit']}")
    u.yaz(lab / "bulgu_defteri.txt", "\n".join(satirlar) + "\n")
    u.yaz(lab / "puanlama.txt",
          "Önem = Etki x Olasılık (her biri 1-5):\n"
          "  15 ve üzeri : Kritik\n  10 - 14     : Yüksek\n  6 - 9       : Orta\n  5 ve altı   : Düşük\n"
          "Raporda önem, bu hesaptan çıkan değerle birebir aynı yazılmalıdır.\n")
    u.yaz(lab / "ek_e_yapi.txt",
          "Rapor yapısı (kitabın Ek E'si, Markdown olarak rapor.md):\n"
          "1. Yönetici Özeti: teknik olmayan yöneticiler için; bulgu sayılarını önem derecesine göre yaz (örn. `Kritik: 2`).\n"
          "2. Kapsam ve Metodoloji: neyi, ne zaman, hangi yöntemle inceledin; müşteri adını yaz.\n"
          "3. Bulgular: **önem sırasına göre** (Kritik en üstte). Her bulgu için:\n"
          "     ### Bulgu <ID> — <başlık>\n"
          "     - Önem: ...\n     - Etki: ...\n     - Kanıt: ...\n     - Öneri: ...\n"
          "4. Sonuç: kısa değerlendirme ve düzeltmelerden sonra doğrulama testi önerisi.\n"
          "Başlıklar `#` ile, alanlar `-` madde işaretiyle yazılır. Kanıt satırı, defterdeki kanıt anahtarını içermelidir.\n")
    u.yaz(lab / "vaka_ozeti.txt",
          f"{m['ad']} ({m['sektor']}) birleşik değerlendirme (KURGUSAL), {s['gun']:%d.%m.%Y}\n"
          "Alan 1 (Web'den root'a): web sunucusunun olay incelemesi; web logundan sistem loguna zincir.\n"
          "Alan 2 (Ağda ilerleme): iç ağda makineden makineye geçişin incelemesi; log, pcap ve güvenlik duvarı kuralları.\n"
          "Alan 3 (Finansal uygulama): ödeme uygulamasının kod, yapılandırma ve işlem logu değerlendirmesi (PCI-DSS, KVKK).\n"
          f"Müşteri bağlamı: {m['hikaye']}\n"
          "Bulguların hepsi bulgu_defteri.txt içinde; her biri puanlanmış ve kanıt anahtarı verilmiştir.\n")


# ----------------------------------------------------------------------------- rapor ayrıştırma

def _basliklar(metin: str) -> list:
    """[(satır_no, seviye, ascii_küçük_başlık, ham_başlık)]"""
    cikti = []
    for i, sat in enumerate(metin.splitlines()):
        mm = re.match(r"^(#{1,6})\s*(.*?)\s*#*\s*$", sat)
        if mm:
            cikti.append((i, len(mm.group(1)), ascii_kucuk(mm.group(2)), mm.group(2)))
    return cikti


def _bolum(metin: str, basliklar: list, desen: str):
    """Başlığı `desen` ile eşleşen bölümün metni (aynı ya da üst düzey bir sonraki başlığa kadar)."""
    satirlar = metin.splitlines()
    for k, (i, sev, ad, _) in enumerate(basliklar):
        if re.match(r"^(\d+[.)]?\s*)?" + desen, ad):
            son = len(satirlar)
            for j, sv2, _, _ in basliklar[k + 1:]:
                if sv2 <= sev:
                    son = j
                    break
            return i, "\n".join(satirlar[i + 1:son])
    return None


def _oku(b):
    yol = b.lab / "rapor.md"
    if not yol.exists() or not yol.read_text(errors="replace").strip():
        return None
    return yol.read_text(errors="replace")


def _sayilar(liste) -> dict:
    return {ad: sum(1 for x in liste if x["onem"] == ad) for ad in SEVIYELER}


def _iskelet_kontrol(b) -> Sonuc:
    metin = _oku(b)
    if metin is None:
        return Sonuc(False, "Lab klasöründe `rapor.md` yok ya da boş. `nano rapor.md` ile oluştur; yapı için `ek_e_yapi.txt` dosyasına bak.")
    bas = _basliklar(metin)
    bolumler = {}
    for ad, desen in (("Yönetici Özeti", r"yonetici ozeti"), ("Kapsam ve Metodoloji", r"kapsam"),
                      ("Bulgular", r"bulgular\b"), ("Sonuç", r"sonuc\b")):
        r = _bolum(metin, bas, desen)
        if r is None:
            return Sonuc(False, f"Zorunlu bölüm eksik: **{ad}** (bir `#` başlığı olarak yaz). Sıra: Yönetici Özeti, Kapsam ve Metodoloji, Bulgular, Sonuç.", yakin=True)
        bolumler[ad] = r
    sira = [bolumler[a][0] for a in ("Yönetici Özeti", "Kapsam ve Metodoloji", "Bulgular", "Sonuç")]
    if sira != sorted(sira):
        return Sonuc(False, "Bölümlerin sırası yanlış: Yönetici Özeti, Kapsam ve Metodoloji, Bulgular, Sonuç.", yakin=True)
    s = b.senaryo
    ozet = bolumler["Yönetici Özeti"][1]
    if len(ozet.split()) < 15:
        return Sonuc(False, "Yönetici Özeti çok kısa: durumu birkaç cümleyle anlat ve bulgu sayılarını önem derecesine göre ekle.", yakin=True)
    for ad, n in _sayilar(s["liste"]).items():
        if n == 0:
            continue
        o = ascii_kucuk(ozet)
        a = ascii_kucuk(ad)
        adaylar = {int(x) for x in re.findall(a + r"\D{0,15}(\d+)", o)} | {int(x) for x in re.findall(r"(\d+)\s*(?:adet\s*)?" + a, o)}
        if not adaylar:
            return Sonuc(False, f"Yönetici Özeti'nde **{ad}** bulgu adedi yok; her önem derecesinin adedini yaz (örn. `{ad}: {n}`).", yakin=True)
        if n not in adaylar:
            return Sonuc(False, f"Yönetici Özeti'ndeki **{ad}** adedi tutarsız: puanlama ölçeğini defterdeki etki x olasılık değerlerine uygula ve say.", yakin=True)
    if ascii_kucuk(s["m"]["ad"]) not in ascii_kucuk(bolumler["Kapsam ve Metodoloji"][1]):
        return Sonuc(False, f"Kapsam ve Metodoloji bölümünde müşteri adı ({s['m']['ad']}) geçmeli.", yakin=True)
    if len(bolumler["Sonuç"][1].split()) < 8:
        return Sonuc(False, "Sonuç bölümü çok kısa: kısa bir değerlendirme ve doğrulama testi önerisi yaz.", yakin=True)
    return Sonuc(True, "Rapor iskeleti tamam: dört bölüm sırasıyla yerinde ve yönetici özetindeki adetler puanlamayla tutarlı.")


def _bulgu_kontrol(b) -> Sonuc:
    metin = _oku(b)
    if metin is None:
        return Sonuc(False, "`rapor.md` yok ya da boş.")
    s = b.senaryo
    bas = _basliklar(metin)
    satirlar = metin.splitlines()
    bloklar = []
    for k, (i, sev, ad, ham) in enumerate(bas):
        mm = re.match(r"^bulgu\s+(b\d-\d\d)\b", ad)
        if mm:
            son = bas[k + 1][0] if k + 1 < len(bas) else len(satirlar)
            bloklar.append((mm.group(1).upper(), "\n".join(satirlar[i + 1:son])))
    kimlikler = [x for x, _ in bloklar]
    gerekli = {x["id"]: x for x in s["liste"]}
    eksik = [i for i in gerekli if i not in kimlikler]
    if eksik:
        return Sonuc(False, f"{len(eksik)} bulgu için blok yok (ilk eksik: {eksik[0]}). Her bulgu `### Bulgu <ID> — <başlık>` başlığıyla yazılır.", yakin=len(eksik) < len(gerekli))
    fazla = [i for i in kimlikler if i not in gerekli]
    if fazla:
        return Sonuc(False, f"Defterde olmayan bir bulgu yazmışsın: {fazla[0]}. Kanıtsız bulgu raporda olmaz.", yakin=True)
    if len(set(kimlikler)) != len(kimlikler):
        return Sonuc(False, "Aynı bulguyu iki kez yazmışsın.", yakin=True)
    sira_sev = []
    for kimlik, govde in bloklar:
        alan = {}
        for sat in govde.splitlines():
            mm = re.match(r"^\s*[-*]?\s*\**\s*(onem|etki|kanit|oneri|cozum)\s*\**\s*[:：]\s*\**\s*(.+)$", ascii_kucuk(sat))
            if mm:
                anahtar = "oneri" if mm.group(1) == "cozum" else mm.group(1)
                alan[anahtar] = mm.group(2).strip()
        for gerek, ad in (("onem", "Önem"), ("etki", "Etki"), ("kanit", "Kanıt"), ("oneri", "Öneri")):
            if gerek not in alan:
                return Sonuc(False, f"{kimlik}: **{ad}** alanı eksik. Her bulguda `- Önem:`, `- Etki:`, `- Kanıt:`, `- Öneri:` satırları olmalı.", yakin=True)
        x = gerekli[kimlik]
        if not alan["onem"].startswith(ascii_kucuk(x["onem"])):
            return Sonuc(False, f"{kimlik}: Önem tutarsız. Etki x olasılık hesabını (`puanlama.txt`) bu bulgu için yeniden yap.", yakin=True)
        if ascii_kucuk(x["kanit"]) not in alan["kanit"]:
            return Sonuc(False, f"{kimlik}: Kanıt satırı defterdeki kanıt anahtarını (`{x['kanit']}`) içermeli.", yakin=True)
        if len(alan["etki"].split()) < 4:
            return Sonuc(False, f"{kimlik}: Etki satırı çok kısa; saldırganın bununla ne yapabileceğini en az dört kelimeyle anlat.", yakin=True)
        if len(alan["oneri"].split()) < 3:
            return Sonuc(False, f"{kimlik}: Öneri satırı çok kısa; somut bir düzeltme yaz.", yakin=True)
        sira_sev.append(SEVIYELER.index(x["onem"]))
    if sira_sev != sorted(sira_sev):
        return Sonuc(False, "Bulgular önem sırasına göre değil: Kritik en üstte, sonra Yüksek, Orta, Düşük gelmeli.", yakin=True)
    return Sonuc(True, f"{len(bloklar)} bulgunun hepsi doğru önem derecesi, kanıt ve öneriyle ve önem sırasıyla yazılmış.")


def _kritik_hata(g, beklenen, b):
    n = sum(1 for x in b.senaryo["liste"] if x["puan"] >= 10)
    if g.isdigit() and int(g) == n and n != int(beklenen):
        return "Yüksek bulguları da saymışsın; Kritik eşiği 15 ve üzeri (Yüksek 10-14)."
    return None


def _riskli_hata(g, beklenen, b):
    liste = b.senaryo["liste"]
    en_etki = max(liste, key=lambda x: (x["etki"], -x["olas"]))
    if g == ascii_kucuk(en_etki["id"]) and en_etki["id"] != beklenen:
        return "Yalnızca etkiye bakmışsın. Risk, etki ile **olasılığın çarpımıdır**; ikisini de hesaba kat."
    return None


def _alan_hata(g, beklenen, b):
    if g == "3" and int(beklenen) != 3:
        return "Alan 3 en çok bulgusu olan alan olabilir; ama sorulan, en çok **Yüksek ve Kritik** bulgusu olan alan."
    return None


def coz(lab: Path, s: dict) -> dict:
    satir = "awk -F' [|] ' '!/^#/ && NF>=6'"
    kritik = sh(f"{satir} bulgu_defteri.txt | awk -F' [|] ' '$4*$5>=15' | wc -l", lab)
    riskli = sh(f"{satir} bulgu_defteri.txt | awk -F' [|] ' '{{print $4*$5, $1}}' | sort -rn | head -1 | awk '{{print $2}}'", lab)
    alan = sh(f"{satir} bulgu_defteri.txt | awk -F' [|] ' '$4*$5>=10 {{c[$2]++}} END{{for(a in c) print c[a], a}}' | sort -rn | head -1 | awk '{{print $2}}'", lab)
    betik = r'''
awk -F' [|] ' '!/^#/ && NF>=6 {p=$4*$5; r=(p>=15)?0:((p>=10)?1:((p>=6)?2:3)); s=(r==0)?"Kritik":((r==1)?"Yüksek":((r==2)?"Orta":"Düşük")); printf "%d|%d|%s|%s|%s|%s\n", r, 100-p, $1, $3, s, $6}' bulgu_defteri.txt | sort -t'|' -k1,1n -k2,2n > siralama.tmp
{
printf '# Değerlendirme Raporu\n\n## Yönetici Özeti\n\n'
printf 'MUSTERI icin yapılan birleşik değerlendirmede web sunucusu, iç ağ ve ödeme uygulaması incelendi. Tespit edilen açıklar para kaybına ve veri ihlaline yol açabilir; en yüksek riskli bulguların öncelikle kapatılması önerilir.\n\n'
for s in Kritik Yüksek Orta Düşük; do printf -- '- %s: %s\n' "$s" "$(awk -F'|' -v s="$s" '$5==s' siralama.tmp | wc -l)"; done
printf '\n## Kapsam ve Metodoloji\n\nMUSTERI sistemleri üç alanda incelendi: web sunucusu olayı, iç ağ olayı ve ödeme uygulaması. Yöntem log, paket kaydı, yapılandırma ve kod incelemesidir.\n\n## Bulgular\n\n'
awk -F'|' '{printf "### Bulgu %s — %s\n- Önem: %s\n- Etki: saldırgan bu zayıflıkla veriye ulaşabilir veya sistemi ele geçirebilir\n- Kanıt: %s\n- Öneri: zayıflığı kapatmak için ayarı ve kodu düzeltmek\n\n", $3, $4, $5, $6}' siralama.tmp
printf '## Sonuç\n\nBulguların hepsi kanıtlıdır. Düzeltmelerden sonra bir doğrulama testi yapılması önerilir.\n'
} > rapor.md
rm -f siralama.tmp
'''.replace("MUSTERI", s["m"]["ad"])
    sh(betik, lab)
    ozet = ("Ödeme ve altyapı değerlendirmesinde birkaç Kritik ve Yüksek bulgu tespit edildi: saldırgan web sunucusundan başlayıp iç ağda ilerleyebilir ve "
            "ödeme uygulamasında doğrudan para kaybına ya da kart verisi ihlaline yol açabilir. En acil iş, kritik bulguların bu hafta kapatılması; ardından "
            "kalan açıkların planlanması ve doğrulama testidir.")
    return sec_doldur({1: kritik, 2: riskli, 3: alan, 4: "", 5: "", 6: "", 7: ozet, 8: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Üç vakanın sonunda", """
Üç vakayı bitirdin: bir web sunucusunun olayı, bir iç ağdaki sıçrama ve bir finansal uygulama. Şimdi hepsinin
sonucunu **tek bir rapora** dönüştüreceksin. Çünkü müşteri senin loglarını okumaz; **raporunu** okur. İşin %50'si bulmak,
%50'si yazmaktır.

<<musteri>> (<<sektor>>) için birleşik değerlendirme: <<hikaye>> Önce vaka özetine bak:
""", komut="cat vaka_ozeti.txt"),
    Adim("1. Bulgu defteri", """
Üç vakadan çıkan <<toplam>> bulgu `bulgu_defteri.txt` içinde: ID, alan, başlık, **etki** (1-5), **olasılık** (1-5) ve
**kanıt anahtarı** (raporda kanıt olarak göstereceğin somut iz: bir IP, dosya adı, ayar adı). Hepsini oku:
""", komut="cat bulgu_defteri.txt"),
    Adim("2. Önemi hesaplamak", """
Rapor "önemli" gibi duygusal sözcüklerle değil, **tutarlı bir ölçekle** yazılır. Burada ölçek: **önem = etki x olasılık**.
Ölçeği oku:
""", komut="cat puanlama.txt", sonra="""
Bu ölçek, aynı iki bulgunun farklı kişilerce farklı önemde yazılmasını engeller. Raporda yazdığın önem,
bu hesabın sonucuyla birebir aynı olmalıdır; bir bulguya "keyfi" önem yazmak raporun güvenilirliğini bitirir.
"""),
    Adim("3. Hesabı komutla yap", """
Her bulgu için etki ile olasılığı çarpıp en riskliden başlayarak sıralayabilirsin. Satır ayırıcısı ` | ` (boşluk, dikey çizgi,
boşluk) olduğundan `awk -F' [|] '` kullanılır; `!/^#/` yorum satırlarını atlar:
""", komut="awk -F' [|] ' '!/^#/ && NF>=6 {print $4*$5, $1}' bulgu_defteri.txt | sort -rn", sonra="""
İlk sütun puan, ikinci sütun bulgu ID'si. 15 ve üzeri **Kritik**, 10-14 **Yüksek**, 6-9 **Orta**, 5 ve altı **Düşük**.
Kritik sayısı, en yüksek puan ve hangi alanda kaç Yüksek+ bulgu olduğu, görevlerde ve yönetici özetinde işine yarayacak.
"""),
    Adim("4. Raporun yapısı (Ek E)", """
Kitabın Ek E'sindeki örnek rapor dört bölümden oluşur. Burada beklenen yapıyı oku:
""", komut="cat ek_e_yapi.txt", sonra="""
Önemli üç kural: bulgular **önem sırasına göre**, her bulguda **dört alan** (Önem, Etki, Kanıt, Öneri), ve **tutarlılık**:
yönetici özetindeki sayılar, bulgu bloklarındaki önemlerle uyuşmalı. Bir sayfada "2 Kritik" yazıp başka sayfada üç Kritik
bulgu göstermek, raporu okuyan CISO'nun ilk fark edeceği hatadır.
"""),
    Adim("5. Yönetici özeti ve yazım ipuçları", """
**Yönetici özeti** raporun en çok okunan sayfasıdır; okuyanların çoğu teknik değildir. Komut, log satırı ya da kısaltma
yok: ne oldu (en kötü ihtimal), ne kadar ciddi (adetlerle), ne yapılmalı (ilk iki karar). Bulgu bloklarında ise tersi:
**kanıt** somuttur (IP, dosya, ayar adı), **etki** saldırganın bununla neler yapabileceğini söyler, **öneri** düzeltmeyi
kimin yapabileceği kadar net yazar. Raporu `nano rapor.md` ile yazabilirsin; Markdown başlıkları için `#`, maddeler için `-`.
"""),
    Adim("6. Düzeltmeden sonra: doğrulama", """
Rapor teslim edilince iş bitmez. Müşteri düzeltmeleri yaptığında bir **doğrulama testi** (retest) ile gerçekten
kapandığını teyit edersin; aksi hâlde "kapattık" sözü kanıtsız kalır. Ek E'deki sonuç bölümü de bunu önerir.
"""),
    Adim("7. Stajın sonu", """
Selin Aksoy ofisin ışıklarını söndürürken sana dönüyor. Üç vakanın dosyaları, final raporun ve yönetici özetin masada
duruyor. "Bir yıl önce buraya klavyeden başka bir şey bilmeyen biri geldi," diyor. "Bugün loglardan bir olayı yeniden
kurup rapor yazabilen bir analist var karşımda."

Mert Yavuz kapıdan başını uzatıyor: "Raporu kim yazdı? Sen. Bu yeter." Deniz Kara gülümsüyor: "Kırmızı takımda saldırıyı,
mavi takımda izi okumayı biliyorsun. Mor takım böyle doğar."

Selin cebinden bir anahtar çıkarıp masaya bırakıyor: "Kalkan Güvenlik'te sana bir masa ayırdım, yarın dokuzda burada ol.
Stajyer değil, ekibin yeni **pentester**ı olarak." Raporunu bitir; sonra masana geç.
"""),
]

GOREVLER = [
    Gorev("`puanlama.txt` ölçeğine göre defterdeki kaç bulgu **Kritik** (etki x olasılık ≥ 15)?",
          Sayi("kritik", sik_hatalar=_kritik_hata),
          ("Her bulgu için etki ile olasılığı çarp; eşiğe bak.",
           "`awk -F' [|] '` ile dördüncü ve beşinci sütunları çarpıp koşulu sınayabilirsin; yorum satırlarını atla.",
           "`awk -F' [|] ' '!/^#/ && $4*$5>=15' bulgu_defteri.txt | wc -l`"),
          puan=30, baslik="Kritik bulgu sayısı"),
    Gorev("En yüksek riskli (en yüksek etki x olasılık puanlı) **tek bulgunun ID'si** nedir?",
          Metin("riskli", bicim="bulgu ID'si, örn. B2-01", sik_hatalar=_riskli_hata),
          ("Risk tek başına etki ya da olasılık değil, çarpımdır.",
           "Puanı hesaplayıp azalan sıralayınca en üstteki satır cevaptır.",
           "`awk -F' [|] ' '!/^#/ && NF>=6 {print $4*$5, $1}' bulgu_defteri.txt | sort -rn | head -1`"),
          puan=30, baslik="En riskli bulgu"),
    Gorev("Hangi **alan** (1, 2 ya da 3) en çok **Yüksek ve Kritik** (puanı 10 ve üzeri) bulguya sahip? Alanın numarasını yaz.",
          Sayi("alan", sik_hatalar=_alan_hata),
          ("Önce puanı 10 ve üzeri olan bulguları süz, sonra alan sütununa göre say.",
           "İkinci sütun alandır; `sort | uniq -c` ile sayılabilir.",
           "`awk -F' [|] ' '!/^#/ && $4*$5>=10 {print $2}' bulgu_defteri.txt | sort | uniq -c | sort -rn`"),
          puan=40, baslik="En riskli alan"),
    Gorev("Yönetici özeti **kimin için** yazılır ve nasıl yazılır?",
          Secmeli([
              ("Teknik olmayan yöneticiler için; sade dille genel risk, bulgu adetleri ve alınacak kararlar",
               "Doğru. Yönetici özeti, karar verecek kişinin tek başına okuyup eyleme geçebileceği sayfadır."),
              ("Sistem yöneticileri için; her bulgunun komut çıktıları ve yapılandırma satırlarıyla",
               "Yanlış. Komut çıktıları bulgu bloklarındaki kanıta aittir; yönetici özeti teknik detay taşımaz."),
              ("Denetçiler için; incelenen her log satırının eksiksiz bir kopyası olarak",
               "Yanlış. Ham kanıt ek olarak verilir; özet sayfası okunabilir ve kısa olmak zorundadır."),
              ("Bir sonraki sızma testi ekibi için; kullanılan araçların ve parametrelerin ayrıntılı listesi",
               "Yanlış. Yöntem ayrıntıları Kapsam ve Metodoloji bölümüne gider, özete değil."),
          ], dogru=0),
          ("Raporu kimin okuyacağını ve o kişinin ne yapmasının beklendiğini düşün.",
           "Özet, karar verici içindir: komut ve kısaltma değil, risk ve karar.",
           "Doğru şık, sade dil, adetler ve kararlar vurgusunu birlikte söyleyen şıktır."),
          puan=30, baslik="Yönetici özeti kimin için"),
    Gorev("Lab klasöründe `rapor.md` dosyasını oluştur: **Yönetici Özeti**, **Kapsam ve Metodoloji**, **Bulgular**, **Sonuç** bölümleri sırasıyla (`#` başlıklarıyla); "
          "Yönetici Özeti'nde her önem derecesinin adedini yaz (örn. `Kritik: 2`), Kapsam'da müşteri adını an. Bulgular bölümünü sonraki görevde dolduracaksın. "
          "Bitince `cevap 5`.",
          Durum(_iskelet_kontrol, "rapor.md: dört bölüm, yönetici özetinde önem adetleri, kapsamda müşteri adı"),
          ("Bölüm başlıkları ve yönetici özetindeki adetler kontrol ediliyor. `ek_e_yapi.txt`'e bak; adetleri 3. adımdaki hesapla bul.",
           "`nano rapor.md` ile yaz. Her bölüm `#` ya da `##` başlığıyla başlar; adetler `Kritik: N`, `Yüksek: N`... biçiminde olabilir.",
           "`# Rapor`, `## Yönetici Özeti` (birkaç cümle + adetler), `## Kapsam ve Metodoloji` (müşteri adı), `## Bulgular`, `## Sonuç` (birkaç cümle ve doğrulama testi)."),
          puan=60, baslik="Rapor iskeleti"),
    Gorev("`rapor.md` içindeki **Bulgular** bölümünü doldur: defterdeki **her bulgu** için `### Bulgu <ID> — <başlık>` başlığı ve `- Önem:`, `- Etki:`, `- Kanıt:`, `- Öneri:` "
          "satırları yaz. Önem, etki x olasılık hesabıyla aynı olsun; kanıt satırı defterdeki kanıt anahtarını içersin; bulgular önem sırasına göre dizilsin "
          "(Kritik en üstte). Bitince `cevap 6`.",
          Durum(_bulgu_kontrol, "her bulgu için başlık ve dört alan; doğru önem; kanıt anahtarı; önem sırası"),
          ("Yedi bulgunun hepsi gerekli. Her birinin önemini hesapla; sıralamayı önem derecesine göre yap.",
           "Kontrol: ID ile başlık, dört alan, doğru önem, kanıt anahtarı, etki ≥ 4 kelime, öneri ≥ 3 kelime, Kritik'ten Düşük'e sıra.",
           "Bir bulgu: `### Bulgu B1-01 — başlık` altında dört madde satırı. Önemi ve sıralamayı 3. adımdaki hesapla belirle."),
          puan=90, baslik="Bulgu blokları"),
    Gorev("**Yönetici özetini** yaz (en az 40 kelime, tırnak içinde): teknik olmayan bir yöneticinin okuyacağı sade dille en kötü senaryoyu, "
          "bulguların genel ciddiyetini (adetlerle) ve ilk iki kararı anlat. Bitince `cevap 7 \"...\"`.",
          Serbest("<<musteri>> için yapılan değerlendirmede, dışarıdan bir saldırganın web sunucusundan başlayıp iç ağda ilerleyebileceği ve ödeme uygulamasındaki "
                  "kurallar yüzünden doğrudan para kaybına ya da kart verisinin ele geçirilmesine yol açabileceği gösterildi. Toplam <<toplam>> bulgudan Kritik ve Yüksek "
                  "olanlar acil müdahale gerektiriyor. İlk iki karar: kritik bulguların bu hafta kapatılması ve düzeltmelerden sonra doğrulama testinin yapılması.", min_kelime=40),
          ("Yönetici özeti, karar verici içindir: komut yok, kısaltma yok, ne kadar kötü ve ne yapılacak var.",
           "Üç cümle: en kötü olasılık, adetlerle genel durum, iki karar. Jargon yerine sonuç yaz (para kaybı, veri ihlali).",
           "`cevap 7 \"Değerlendirmede ... gösterildi. Toplam ... bulgudan Kritik ve Yüksek ... İlk iki karar: ...\"` biçiminde, tırnak içinde yaz."),
          puan=60, baslik="Yönetici özeti"),
    Gorev("Müşteri düzeltmeleri yaptığını söylüyor. Rapor teslimi sonrasında **ilk işin** ne olmalı?",
          Secmeli([
              ("Düzeltmelerin gerçekten yapıldığını kanıtlayan bir doğrulama testi (retest) yapmak",
               "Doğru. Bir bulgu, kapandığı doğrulanmadıkça kapanmış sayılmaz; ilk iş aynı kanıtla yeniden test etmektir."),
              ("Raporun bir kopyasını güvenlik forumunda yayımlayıp topluluğun görüşünü almak",
               "Yanlış. Rapor müşterinin gizli verisidir; izinsiz paylaşmak sözleşmeyi ve etiği ihlal eder."),
              ("Bulguları raporda sileceğin ve müşteriyi memnun edeceğin biçimde yeniden önemlendirmek",
               "Yanlış. Önem, kanıta ve ölçeğe göre yazılır; müşteri memnuniyeti için değiştirilmez."),
              ("Aynı müşterinin başka sistemlerine izinsiz bir tarama yapıp ek bulgu aramak",
               "Yanlış. Kapsam dışına çıkmak izinsiz erişimdir; kapsam genişleyecekse yeni yazılı izin gerekir."),
          ], dogru=0),
          ("Bir bulgu, düzeltildiği ispatlanana kadar açık sayılır.",
           "İki ihtimal sözleşmeyle çelişir (paylaşmak, kapsam dışına çıkmak); bir ihtimal etiğe aykırı (önemi değiştirmek).",
           "Doğru şık, kapatıldığını **ölçerek** doğrulayan şıktır."),
          puan=30, baslik="Doğrulama testi"),
]


def _kapanis():
    return """
Üç vaka, tek bir mesaj: bulmak yetmez, **anlatabilmek** gerekir. Final raporunda zinciri (kanıttan kök nedene), kök nedeni
(kod, yetki, ağ, kural), önemi (hesaplanmış, tutarlı) ve düzeltmeyi (somut, doğrulanabilir) tek bir belgeye bağladın.
Saldırganı bilen savunmayı, savunmayı bilen saldırıyı daha iyi yazar; bu cildin ve kitabın bütün amacı buydu.
Selin'in masası seni bekliyor; bundan sonrası pratik: her vakada logu oku, zinciri kur, bulguyu yaz, doğrulatmayı unutma.
Doğru tarafta kal ve her çözdüğünü yaz.
"""


SEVIYE = Seviye(
    kimlik="c24b04",
    cilt=24,
    bolum=4,
    baslik="Capstone'u Tamamlamak: Final Raporu",
    brifing="""
Selin Aksoy üç klasörü masaya diziyor: "Web'den root'a, ağda ilerleme, finansal uygulama. Hepsi bitti. Şimdi **<<musteri>>**
(<<sektor>>) için tek bir rapor lazım. <<hikaye>> Müşteri loglarını okumayacak; raporunu okuyacak."

Mert Yavuz masaya yaslanıyor: "Raporu kim yazacak diye hep sorardım. Bu sefer cevap sensin." Deniz Kara bir uyarı yapıyor:
"Sayılar tutarlı olsun: özette dört Kritik, gövdede üç Kritik varsa ilk soru bu olur."

Görevin: bulgu defterinden önemleri hesaplamak, kitabın Ek E yapısına uygun bir `rapor.md` yazmak, yönetici özetini kaleme almak
ve raporu teslim etmek. Bu, stajının son görevi.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Raporun değeri:** Pek çok sızma testi sözleşmesinde asıl teslim edilen şey rapordur: yönetici özeti karar vericiye, bulgu blokları
  teknik ekibe hitap eder. PTES gibi çerçeveler ve OWASP rehberleri, rapor yapısını (özet, kapsam, bulgu, öneri) bu nedenle tarif eder.
- **Capital One 2019:** Kamuya açık anlatımlara göre olay, birden çok halkanın (uygulama açığı, aşırı yetkili bir rol, yapılandırma)
  birleşmesiyle oluştu. İyi bir rapor bu tür zincirleri tek tek bulgu olarak değil, **kök neden zinciri** olarak anlatır;
  önleme tarafında en az yetki, tespit tarafında alışılmadık erişim kayıtlarının izlenmesi öne çıkar.
- **Doğrulama testi:** PCI-DSS gibi çerçeveler, sızma testi sonrasında bulunan açıkların düzeltilmesini ve düzeltmenin yeniden test
  edilerek doğrulanmasını bekler. "Kapattık" sözünü ölçerek teyit etmek hem uyum hem güven için standart uygulamadır.
""",
    sure_hedef_dk=60,
)
