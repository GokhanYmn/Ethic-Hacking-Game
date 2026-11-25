"""Cilt 8 · Bölüm 4 — CTF: Oyunla Öğrenmek.

Beceri: lab'da zararsız küçük CTF bulmacaları çözmek: base64 ve hex kodlu bayrak, Sezar/ROT kaydırmalı
mesaj, gizli (nokta ile başlayan) dosya, ikili bir dosyanın içinde saklı metin; çözümleri bir writeup'a
yazmak. Saldırı, exploit ya da ağ erişimi yoktur: yalnızca kodlama/çözme ve dosya keşfi vardır.

Vakalar: lojistik şirketi kulübü, hastane BT ekibi, e-ticaret güvenlik kulübü, kafe sahibi.
Her tohumda bayraklar, kaydırma miktarı ve dosya içerikleri farklıdır.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path

from hy.motor.kontrol import Bayrak, Durum, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

VAKALAR = {
    "kuzgun": {"ad": "Kuzgun Lojistik — dahili güvenlik kulübü CTF'i", "musteri": "Kuzgun Lojistik", "klasor": "kargo_ctf",
               "kisi": "Serdar Bey (IT sorumlusu)",
               "sahne": "Kuzgun'un depo çalışanlarından oluşan küçük güvenlik kulübü, kendi mini CTF'ini kurdu ve hazırlayanlar senden bir deneme çözümü yazmanı istiyor."},
    "medora": {"ad": "Medora Sağlık — BT ekibi eğitim CTF'i", "musteri": "Medora Sağlık", "klasor": "bt_egitim_ctf",
               "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
               "sahne": "Medora'nın BT ekibi eğitim için zararsız bir CTF hazırladı; hiç gerçek hasta verisi içermiyor. Senden deneme çözümünü bir writeup olarak yazmanı istiyorlar."},
    "pazarix": {"ad": "Pazarix — çalışanlar arası CTF yarışması", "musteri": "Pazarix", "klasor": "yarisma_ctf",
                "kisi": "Tuncay Bey (sistem yöneticisi)",
                "sahne": "Pazarix yazılım ekibinin içindeki güvenlik meraklıları ayda bir mini CTF düzenliyor; bu ayın bulmacalarını sen deniyorsun."},
    "atolye": {"ad": "Atölye Kahve — meraklı barista CTF'i", "musteri": "Atölye Kahve", "klasor": "kafe_ctf",
               "kisi": "Berk (kafenin sahibi)",
               "sahne": "Atölye Kahve'nin sahibi Berk, bilgisayardan anlayan bir müşterinin önerisiyle eğlence için küçük bir CTF kurdu ve doğru çözümü merak ediyor."},
}
KOMUTLAR = ["base64", "tr", "grep", "find", "ls", "python3", "cat", "sha256sum", "strings", "awk"]


def _kaydir(metin: str, n: int) -> str:
    cikti = []
    for ch in metin:
        if "a" <= ch <= "z":
            cikti.append(chr((ord(ch) - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            cikti.append(chr((ord(ch) - 65 + n) % 26 + 65))
        else:
            cikti.append(ch)
    return "".join(cikti)


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    bayraklar = u.benzersiz(rng, lambda r: u.bayrak(r), 5)
    kayma = rng.choice([3, 13])
    ikili = bytearray(rng.randbytes(rng.randint(400, 700)))
    for i in range(len(ikili)):                         # rastgele baytlar arasında "FLAG{" tesadüfen oluşmasın
        if ikili[i] == ord("F"):
            ikili[i] = ord("f")
    konum = rng.randint(120, 300)
    ikili[konum:konum] = b"\x00\x01" + bayraklar[4].encode() + b"\x02\x00"
    gizli_klasor = rng.choice(["kasa", "arsiv", "depo", "dolap"])
    gizli_dosya = "." + rng.choice(["anahtar", "not", "sir", "kilit"]) + rng.choice(["_x", "_old", "2", ""])
    s = {
        "vaka": v["ad"], "v": v, "bayraklar": bayraklar, "kayma": kayma, "ikili": bytes(ikili),
        "gizli": (gizli_klasor, gizli_dosya),
        "metin": {"musteri": v["musteri"], "klasor": v["klasor"], "kisi": v["kisi"], "sahne": v["sahne"], "kayma": kayma,
                  "gizli_klasor": gizli_klasor},
        "cevaplar": {f"b{i + 1}": bayraklar[i] for i in range(5)},
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    k = s["v"]["klasor"]
    b = s["bayraklar"]
    u.yaz(lab / k / "bulmaca1_not.txt", "Bulmaca 1 — Bir not bulundu. Satırın sonundaki yazı garip görünüyor:\n"
          + base64.b64encode(b[0].encode()).decode() + "\n")
    u.yaz(lab / k / "bulmaca2_veri.txt", "Bulmaca 2 — Sadece 0-9 ve a-f karakterlerinden oluşan bir veri:\n" + b[1].encode().hex() + "\n")
    u.yaz(lab / k / "bulmaca3_mesaj.txt", f"Bulmaca 3 — Eski usul bir şifre (Sezar şifresi, kaydırma {s['kayma']}):\n"
          + _kaydir(b[2], s["kayma"]) + "\n")
    gk, gd = s["gizli"]
    u.yaz(lab / k / gk / "okubeni.txt", "Burada görünen bir şey yok. Ama her şey göründüğü gibi değildir.\n")
    u.yaz(lab / k / gk / gd, f"Bulmaca 4 — gizli dosyayı buldun: {b[3]}\n")
    (lab / k / "bulmaca5.bin").write_bytes(s["ikili"])
    u.yaz(lab / k / "ornek.bin", "")
    (lab / k / "ornek.bin").write_bytes(b"\x00\x01\xfe" + b"FLAG{ornek_deneme_000000}" + b"\x00\xff\x10")
    u.yaz(lab / ".not_defteri", "Bu bir tuzak değil, yalnızca alıştırma dosyası. Gerçek bayraklar " + k + "/ içinde.\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']}\n\n{k}/bulmaca1_not.txt   {k}/bulmaca2_veri.txt   {k}/bulmaca3_mesaj.txt\n"
          f"{k}/{gk}/ (içinde gizli bir dosya var)   {k}/bulmaca5.bin\n{k}/ornek.bin   deneme için örnek ikili dosya (bayrak değil)\n\n"
          "Her bulmacanın cevabı FLAG{...} biçiminde bir bayrak. Çözümlerini writeup.md dosyasına yaz (görev 6).\n")


def _writeup(b) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "writeup.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `writeup.md` yok. Çözümlerini bu dosyaya yaz.")
    t = yol.read_text(encoding="utf-8", errors="replace")
    alanlar = o.alan_oku(t.replace("#", ""), ["Özet", "Adımlar", "Bayrak", "Bayraklar"])
    basliklar = set(o.ascii_norm(m.group(1)) for m in re.finditer(r"(?m)^\s*#+\s*(.+?)\s*$", t))
    var = {o.ascii_norm(x) for x in ("Özet", "Adımlar", "Bayrak")}
    bulunan = {h for h in basliklar if any(h.startswith(v) for v in var)} | set(alanlar)
    eksik = [x for x in ("ozet", "adimlar", "bayrak") if not any(h.startswith(x) for h in bulunan)]
    if eksik:
        return Sonuc(False, "Writeup'ta şu bölümler eksik: " + ", ".join(eksik) + ". `# Özet`, `# Adımlar`, `# Bayrak` başlıklarını kullan.", yakin=True)
    dogru = [f for f in s["bayraklar"] if f in t]
    if len(dogru) < 2:
        return Sonuc(False, f"Writeup'ta çözdüğün bayraklardan en az ikisi tam biçimde yazılı olmalı (şu an {len(dogru)}).", yakin=True)
    kullanilan = [c for c in KOMUTLAR if re.search(rf"\b{re.escape(c)}\b", t)]
    if len(kullanilan) < 2:
        return Sonuc(False, "Adımlar bölümünde kullandığın komutları yaz (örn. `base64 -d`, `tr`, `grep -a`). En az iki farklı komut.", yakin=True)
    if len(t.split()) < 30:
        return Sonuc(False, "Writeup çok kısa. Başkasının izleyebileceği kadar ayrıntı ver (en az ~30 kelime).", yakin=True)
    return Sonuc(True, f"Writeup tamam: üç bölüm, {len(dogru)} doğru bayrak ve kullandığın komutlar var. Bu portföyüne girebilecek bir yazı.")


def coz(lab: Path, s: dict) -> dict:
    k = s["v"]["klasor"]
    b1 = o.sh(f"tail -1 {k}/bulmaca1_not.txt | base64 -d", lab)
    b2 = o.sh(f"python3 -c \"import sys; print(bytes.fromhex(open('{k}/bulmaca2_veri.txt').read().splitlines()[-1]).decode())\"", lab)
    tr = "'A-Za-z' 'N-ZA-Mn-za-m'" if s["kayma"] == 13 else "'D-ZA-Cd-za-c' 'A-Za-z'"
    b3 = o.sh(f"tail -1 {k}/bulmaca3_mesaj.txt | tr {tr}", lab)
    b4 = o.sh(f"cat $(find {k} -name '.*' -type f) | grep -o 'FLAG{{[^}}]*}}'", lab)
    b5 = o.sh(f"grep -a -o 'FLAG{{[^}}]*}}' {k}/bulmaca5.bin", lab)
    (lab / "writeup.md").write_text(
        "# Özet\nBeş küçük bulmacayı çözdüm: kodlama, şifre, gizli dosya ve ikili dosya içi arama.\n\n"
        f"# Adımlar\n1. base64 -d ile ilk bayrağı çözdüm: {b1}\n2. python3 ile hex veriyi metne çevirdim: {b2}\n"
        f"3. tr ile Sezar kaydırmasını geri aldım: {b3}\n4. find ile gizli dosyayı bulup cat ile okudum: {b4}\n"
        f"5. grep -a ile ikili dosyadan metni ayıkladım: {b5}\n\n# Bayrak\n{b1}\n", encoding="utf-8")
    cozum = {1: b1, 2: b2, 3: b3, 4: b4, 5: b5, 6: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("CTF nedir?", """
**CTF** (Capture The Flag), güvenlik becerilerini oyunlaştıran yarışmalardır: bir bulmacayı ya da makineyi çözüp
**bayrak** (`FLAG{...}`) bulursun. En değerli yanı, **güvenli bir ortamda başarısız olabilmendir**: gerçek bir
sistemde yanlış bir adım felaket olabilir, CTF'te yeniden başlatırsın. Bu bölümde beş küçük bulmaca çözeceksin;
hepsi zararsız kodlama ve keşif bulmacası. Klasöre bak:
""", komut="ls -la <<klasor>>"),
    Adim("Kodlama şifreleme değildir: base64", """
**Base64**, ikili veriyi harf-rakamlarla yazmanın bir yoludur (e-posta ekleri, kimlik belirteçleri bununla
taşınır). Bir **şifre değil, kodlamadır**: anahtarı yoktur, herkes çözebilir. Sonu `=` ile biten karışık harfli
yazılar sık sık base64'tür. Kendin dene (`-d` çöz demek):
""", komut="echo SGVsbG8= | base64 -d", sonra="""
Çıktı `Hello`. Gerçek hayatta "şifreli" sanılan pek çok şey aslında sadece base64'tür; bu yüzden **kodlamayı
şifreleme sanmak** klasik bir hatadır.
"""),
    Adim("Hex: iki karakter bir bayt", """
**Hex** (onaltılık), her baytı iki karakterle (0-9, a-f) yazar. `48656c6c6f`, `H e l l o`'dur. Python ile
çözmek kolay: `bytes.fromhex(...)` sayıları baytlara, `.decode()` baytları metne çevirir:
""", komut="python3 -c \"print(bytes.fromhex('48656c6c6f').decode())\""),
    Adim("Sezar şifresi: harfleri kaydır", """
Sezar şifresinde her harf alfabede **n kadar** kaydırılır. n=13 özel bir durumdur (ROT13): iki kez uygularsan
başa dönersin. `tr` karakterleri birbirine çevirir; bu komut ROT13'ü çözer (aynı komut kodlar da):
""", komut="echo 'Uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m'", sonra="""
Başka bir kaydırma miktarı (örn. 3) için formül: çözmek için `tr 'D-ZA-Cd-za-c' 'A-Za-z'`. Genel kural: `n`
kaydırma için ilk küme, alfabenin `n+1`. harfinden başlar ve başa sarar.
"""),
    Adim("Gizli dosyalar", """
Adı **nokta ile başlayan** dosyalar `ls`'te görünmez. `ls -a` hepsini gösterir. Bu lab'ın ana klasöründe
bir tane var; ona bak:
""", komut="ls -a", sonra="""
Klasörlerin içinde de gizli dosya olabilir; `find <klasör> -name ".*" -type f` hepsini bulur. Alıştırma dosyasını
oku: `cat .not_defteri`.
"""),
    Adim("İkili dosyanın içindeki yazı", """
Bir ikili dosyanın (program, resim, veri) içinde okunabilir metin parçaları saklanabilir. `grep -a`
dosyayı metinmiş gibi taramaya zorlar, `-o` yalnızca eşleşen kısmı yazar. Örnek ikili dosyada deneme bayrağı var:
""", komut="grep -a -o 'FLAG{[^}]*}' <<klasor>>/ornek.bin", sonra="""
Bu **deneme** bayrağı; gerçek bayrak `bulmaca5.bin` içinde.

**Hacker gözüyle:** CTF becerileri doğrudan işe aktarılır. Çoğu pentest sertifikası (OSCP, eJPT, PNPT)
CTF formatındadır: bir makineyi ele geçir, kanıtla, raporla. Her bulmaca için bir **writeup** (çözüm yazısı)
yazmak, öğrendiğini pekiştirir ve portföyün olur.
"""),
]

GOREVLER = [
    Gorev("`<<klasor>>/bulmaca1_not.txt` içindeki yazı garip görünüyor. Çöz ve **bayrağı** yaz.",
          Bayrak("b1"),
          ("Sonu `=` ile biten karışık harfli bir satır görüyorsun. Bu bir kodlama; eğitimde ilkini gördün.",
           "`tail -1 dosya` son satırı verir; `base64 -d` çözer. İkisini `|` ile bağla.",
           "`tail -1 <<klasor>>/bulmaca1_not.txt | base64 -d`"),
          puan=30, baslik="Base64"),
    Gorev("`<<klasor>>/bulmaca2_veri.txt` içindeki 0-9 ve a-f karakterlerinden oluşan veriyi çöz ve **bayrağı** yaz.",
          Bayrak("b2"),
          ("Yalnızca 0-9 ve a-f karakterleri: bu hex kodlaması. Eğitimde Python ile çözdün.",
           "Dosyanın son satırını alıp `bytes.fromhex(...).decode()` ile çözmelisin.",
           "`python3 -c \"print(bytes.fromhex(open('<<klasor>>/bulmaca2_veri.txt').read().splitlines()[-1]).decode())\"`"),
          puan=30, baslik="Hex"),
    Gorev("`<<klasor>>/bulmaca3_mesaj.txt` Sezar şifresiyle (kaydırma <<kayma>>) yazılmış. Çöz ve **bayrağı** yaz.",
          Bayrak("b3"),
          ("Not, kaydırma miktarını söylüyor. Eğitimdeki `tr` komutunu o miktar için uyarlaman gerek.",
           "Kaydırma 13 ise `tr 'A-Za-z' 'N-ZA-Mn-za-m'`; 3 ise `tr 'D-ZA-Cd-za-c' 'A-Za-z'`. Son satırı `tail -1` ile ver.",
           "`tail -1 <<klasor>>/bulmaca3_mesaj.txt | tr` ve notta yazan kaydırmaya uygun iki kümeyi ver."),
          puan=40, baslik="Sezar"),
    Gorev("`<<klasor>>/<<gizli_klasor>>/` klasöründe görünen tek dosya işe yaramıyor ama içinde **gizli bir dosya** var. "
          "Bul, oku ve **bayrağı** yaz.",
          Bayrak("b4"),
          ("Adı nokta ile başlayan dosyalar `ls`'te görünmez.",
           "`ls -a <<klasor>>/<<gizli_klasor>>` ile gizli dosyayı gör; `cat` ile oku.",
           "`ls -a <<klasor>>/<<gizli_klasor>>` sonra `cat <<klasor>>/<<gizli_klasor>>/.<dosya adı>`."),
          puan=30, baslik="Gizli dosya"),
    Gorev("`<<klasor>>/bulmaca5.bin` ikili bir dosya ama içinde okunabilir bir bayrak saklı. Bul ve **bayrağı** yaz.",
          Bayrak("b5"),
          ("İkili dosyayı `cat` ile açma, terminali bozar. Metin parçalarını arayan bir araç kullan.",
           "`grep -a` ikili dosyayı metinmiş gibi tarar; `-o` yalnızca eşleşen kısmı yazar.",
           "`grep -a -o 'FLAG{[^}]*}' <<klasor>>/bulmaca5.bin`"),
          puan=40, baslik="İkili dosyada metin"),
    Gorev("**Writeup yaz:** `writeup.md` dosyasına çözümünü yaz: `# Özet`, `# Adımlar` (kullandığın komutlarla) ve "
          "`# Bayrak` başlıkları olsun, çözdüğün bayraklardan en az ikisini içersin. Bitince `cevap 6` yaz.",
          Durum(_writeup, cozum="`# Özet`, `# Adımlar` (en az iki komutla), `# Bayrak` başlıkları ve en az iki gerçek bayrak."),
          ("Writeup, çözümü başkasının izleyebileceği biçimde yazmaktır: ne gördün, ne yaptın, ne buldun.",
           "Üç başlık kullan. Adımlarda her bulmaca için hangi komutu çalıştırdığını yaz (örn. `base64 -d`, `tr`, `grep -a`).",
           "`nano writeup.md` ile aç. Örnek iskelet: `# Özet`, `# Adımlar`, `1. base64 -d ...`, `# Bayrak`, ardından bayraklar."),
          puan=50, baslik="Writeup"),
    Gorev("CTF'te \"başarısız olabilmek\" neden bir **avantajdır**?",
          Secmeli([
              ("Güvenli ortamda cesur denemeler yapıp hatalardan hızla öğrenirsin", "Doğru: gerçek bir sistemde yanlış çalıştırılan bir araç felaket olabilir; CTF'te yeniden başlatırsın. Bu özgürlük hızlı öğrenmenin anahtarıdır."),
              ("Başarısız olunca puanın silinmez, o yüzden risk almanın bir maliyeti yoktur", "Yanlış: CTF'lerde başarısızlığın puan ya da kural boyutu değil, öğrenme boyutu önemlidir; asıl kazanç denemeden gelen deneyimdir."),
              ("Başarısızlık yarışmayı otomatik olarak sıfırlayıp ilk hâline döndürür", "Yanlış: her yarışmada sıfırlama mekanizması yoktur; asıl avantaj, hatanın gerçek hasar vermemesidir."),
              ("Başkalarının çözümlerini okumak yasak olduğundan kendi başına öğrenirsin", "Yanlış: takıldığında başkalarının writeup'larını okumak öğrenmenin meşru bir parçasıdır."),
          ], dogru=0),
          ("Gerçek bir müşteri sisteminde yanlış bir adım atarsan ne olur, bir CTF makinesinde ne olur?",
           "Kitabın CTF bölümündeki 'Hacker gözüyle' kutusunun ilk cümlesini hatırla.",
           "Doğru şık, güvenli ortamda hata yapıp hızlı öğrenmeyi söyleyen şık."),
          puan=20, baslik="Başarısız olabilmek"),
    Gorev("CTF becerileri neden OSCP, eJPT ve PNPT gibi pentest sertifikalarına doğrudan aktarılabilir?",
          Secmeli([
              ("Sınavlar da makineyi ele geçirip kanıtlamak ve raporlamak üzerine, yani CTF formatında", "Doğru: çoğu uygulamalı pentest sertifikasında bir makineyi ele geçirir, kanıtlar ve raporlarsın; CTF alışkanlığı birebir karşılık bulur."),
              ("Bu sertifikalar CTF'lerde kazanılan puanlarla, herhangi bir sınav olmadan otomatik verilir", "Yanlış: sertifikalar kendi sınavlarıyla verilir; CTF puanı sertifika yerine geçmez."),
              ("CTF'lerde kullanılan bütün araçlar bu sertifikaların sınavlarında kesinlikle yasaklanmıştır", "Yanlış: araç politikası sertifikaya göre değişir; asıl aktarılan beceridir, yasak listesi değil."),
              ("Sertifika sınavları yalnızca çoktan seçmeli yazılı sorulardan oluşan bir testten ibarettir", "Yanlış: bu sertifikaların ortak özelliği uygulamalı formatlarıdır."),
          ], dogru=0),
          ("Bu sertifikaların sınav biçimini hatırla: test mi, uygulama mı?",
           "Bir makineyi ele geçir, kanıtla, raporla: hangi etkinlikte yapıyorsun?",
           "Doğru şık 'makineyi ele geçirip kanıtlamak ve raporlamak' ifadesini içeren şık."),
          puan=20, baslik="CTF'ten sertifikaya"),
]


def _kapanis():
    return """
CTF'in sihri, kısa bir süre içinde pek çok farklı fikri güvenli biçimde denemene izin vermesidir. Bu bölümdeki
beş bulmaca tek bir ortak derse bağlanıyor: **kodlama şifreleme değildir** (base64, hex ve Sezar'ın anahtarı yok),
**gizli** olan görünmeyendir (nokta ile başlayan dosya, ikili dosyanın içindeki yazı) ve **sistematik** gitmek
rastgele denemekten çok daha hızlıdır. Saldırgan bakışıyla bu, gerçek bir sistemde açıkta kalmış bir parola ya da
yedek dosya bulmanın küçük bir provasıdır. Savunma bakışıyla ders: "karışık görünen" bir metni sır saklamak için
kullanma; gerçek bir sırrı kodlamayla değil, doğru şifreleme ve erişim denetimiyle koru. Ve yaptığın her bulmaca için
bir writeup yaz: öğrenmeyi pekiştirir ve portföyünü büyütür.
"""


SEVIYE = Seviye(
    kimlik="c08b04",
    cilt=8,
    bolum=4,
    baslik="CTF: Oyunla Öğrenmek",
    brifing="""
<<sahne>> <<kisi>> beş bulmacanın bir klasörde durduğunu söylüyor: "Hepsi zararsız; sadece kodlama, gizli dosya,
ikili dosyada metin. Doğru çözümü yazıya dökebilir misin?" Selin gülümsüyor: "Bu senin CTF antrenmanın. Her bulmacada
kendine şunu sor: **bu bir kodlama mı, bir şifre mi, yoksa bir saklama mı?** Sonra hepsini bir **writeup** olarak yaz."

Mert ekliyor: "Takılırsan başkalarının writeup'larını oku, yasaktır diye bir şey yok. Ama kendi yazını da bırak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **CTF bir öğrenme yöntemidir:** bayrak avı, tersine mühendislik, kripto ve web bulmacaları gerçek
  becerileri oyunlaştırır. Bu beceriyi **kendi laboratuvarında** pekiştirirsin: bu oyundaki bayrak
  görevleri, Olay Masası vakaları ve Cilt 9'da kuracağın kendi hedeflerin. Kendi kurduğun bulmacaları
  çözmek, hazır bir yarışmayı çözmekle aynı kası çalıştırır.
- **Kodlama ≠ şifreleme (gerçekten):** Pek çok sızma testi raporunda "hassas veri base64 ile 'korunmuş'"
  bulgusu sık görülür: kimlik bilgisi ya da belirteç yalnızca base64 kodlu olarak bir yapılandırma dosyasında
  ya da çerezde durur. Saldırgan bunu saniyeler içinde çözer. Tespit için yapılandırma ve kod incelemesinde
  base64/hex kalıplarını aratmak yeterlidir; önlemek için gerçek sırlar bir sır yöneticisinde ve şifreli
  saklanır.
- **Writeup kültürü:** Güvenlik topluluğunda çözüm yazıları (writeup) yaygın bir paylaşım biçimidir ve iş
  başvurularında portföy olarak sıkça gösterilir. Bir writeup'ta başkasının çalışmasını ve sır içeren
  gerçek verileri paylaşmamaya dikkat edilir.
""",
    sure_hedef_dk=30,
)
