"""Cilt 1 · Bölüm 1 — Laboratuvarını Kur.

Oyunda laboratuvar otomatik kurulduğu için bu bölüm, oyuncunun görev kabuğunu tanıdığı bir
giriş görevidir: komut istemi ($ ve # farkı), lab klasöründe dolaşmak, kurulumu doğrulayan
betiği çalıştırıp bayrağı almak ve Kali/snapshot/sudo kavramları. sudo gerektiren hiçbir
şey yaptırılmaz.

Vakalar: ilk gün masasına bırakılan "hazırlık dosyası" her seferinde başka bir müşteri için;
klasör adları, betik adı, kod adı ve kaynak dosyaları değişir.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from hy.motor.kontrol import Bayrak, Dinamik, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

DUZENLER = [
    # (masa klasörü, kurulum klasörü, doğrulama betiği, kaynak klasörü)
    ("masa", "kurulum", "lab-kontrol.sh", "kaynaklar"),
    ("calisma_masasi", "dogrulama", "kontrol.sh", "okuma_listesi"),
    ("ilk_gun", "kurulum_testi", "lab_test.sh", "belgeler"),
    ("stajyer", "lab_kontrol", "hazir_mi.sh", "kutuphane"),
]
KOD_KOKLERI = ["KARTAL", "MARTI", "VASAK", "SAHIN", "ATMACA", "TURNA", "LEYLEK", "BAYKUS", "DOGAN", "KUGU"]
KAYNAKLAR = ["linux_temelleri.pdf", "komut_listesi.txt", "kali_ilk_adimlar.md", "snapshot_rehberi.txt",
             "terminal_kisayollari.txt", "bandit_notlari.md", "etik_kurallar.pdf", "not_alma_sablonu.md",
             "ag_temelleri_on_okuma.txt"]


def uret(rng):
    m = musteri_sec(rng)
    masa, kurulum, betik, kaynak = rng.choice(DUZENLER)
    kod_adi = f"{rng.choice(KOD_KOKLERI)}-{rng.randint(2, 99)}"
    kaynak_dosyalari = rng.sample(KAYNAKLAR, rng.randint(3, 7))
    return {
        "vaka": f"İlk gün — {m['ad']} ({m['sektor']}) hazırlık dosyası",
        "musteri": m,
        "duzen": (masa, kurulum, betik, kaynak),
        "kaynak_dosyalari": kaynak_dosyalari,
        "metin": {
            "musteri": m["ad"], "sektor": m["sektor"], "hikaye": m["hikaye"], "masa": masa,
            "kurulum": kurulum, "betik": betik, "kaynak": kaynak,
        },
        "cevaplar": {
            "kod_adi": kod_adi,
            "kaynak_sayi": len(kaynak_dosyalari),
            "bayrak": u.bayrak(rng, rng.choice(["ilk_adim", "acik_pencere", "anahtar", "sinyal"])),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    masa, kurulum, betik, kaynak = s["duzen"]
    m = s["musteri"]
    c = s["cevaplar"]
    u.yaz(lab / "OKUBENI.txt", f"""KALKAN GÜVENLİK — STAJYER LABORATUVARI
======================================
Hoş geldin! Bu klasör senin laboratuvarın. Burada istediğin kadar deneme yapabilir,
bir şeyleri bozabilirsin; bozarsan görev kabuğunda `sifirla` yazman yeter.

Bugünkü yol haritan:
  1. {masa}/ klasöründe Selin'in sana bıraktığı notu oku.
  2. {kurulum}/ klasöründeki doğrulama betiğini çalıştır:  bash {betik}
  3. {kaynak}/ klasörüne göz at; ilk haftanın okuma listesi orada.

Hazırlanan ilk müşteri dosyası: {m['ad']} ({m['sektor']})
""")
    u.yaz(lab / masa / "hosgeldin.txt", f"""Selin'den not
-------------
Hoş geldin. Bu hafta {m['ad']} işine hazırlanacağız.
Kalkan Güvenlik kayıtlarında senin kod adın: {c['kod_adi']}
Notlarına ve rapor taslaklarına bu kod adıyla imza at.

Not: Kahve makinesi mutfakta. Mert'in kupasını kullanma, alınıyor.
""")
    u.yaz(lab / masa / f"{m['kod']}_dosyasi.txt", f"""Müşteri : {m['ad']} ({m['alan']})
Sektör  : {m['sektor']}
İrtibat : {m['kisi']}
Durum   : {m['hikaye']}
Yapılacak: Yetkilendirme mektubu imzalandıktan sonra keşfe başlanacak. Önce izin, sonra iz.
""")
    u.yaz(lab / kurulum / betik, f"""#!/bin/bash
# Kalkan Güvenlik — laboratuvar doğrulama betiği
# Kullanım: bash {betik}
LAB="$(cd "$(dirname "$0")/.." && pwd)"
echo "Laboratuvar denetleniyor: $LAB"
eksik=0
for k in {masa} {kurulum} {kaynak}; do
  if [ -d "$LAB/$k" ]; then echo "  [tamam] $k/"; else echo "  [EKSIK] $k/"; eksik=1; fi
done
if [ "$eksik" -ne 0 ]; then
  echo "Bazı klasörler eksik. Görev kabuğunda 'sifirla' yazıp tekrar dene."
  exit 1
fi
echo "Laboratuvar hazır: $LAB"
echo "Kurulum doğrulama bayrağı: {c['bayrak']}"
""", mod=0o755)
    for ad in s["kaynak_dosyalari"]:
        u.yaz(lab / kaynak / ad, f"{ad} — Kalkan Güvenlik stajyer okuma listesi.\n")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _istem_karakteri(b) -> list:
    if os.geteuid() == 0:
        return ["#", "diyez", "kare", "diyez işareti"]
    return ["$", "dolar", "dolar işareti", "dolar isareti"]


def _lab_yolu(b) -> list:
    yollar = {str(b.lab), os.path.realpath(b.lab)}
    ev = os.path.expanduser("~")
    for y in list(yollar):
        if y.startswith(ev + "/"):
            yollar.add("~" + y[len(ev):])
    return sorted(yollar | {y + "/" for y in yollar})


def _lab_yolu_hata(g, beklenen, b):
    if g in ("~", "/home/kali", os.path.expanduser("~").casefold()):
        return "Bu ev dizinin. Lab, ev dizininin altında birkaç klasör daha içeride; `lab` yazıp sonra `pwd` dene."
    if not g.startswith(("/", "~")):
        return "Tam (mutlak) yol `/` ile başlar. `pwd` çıktısının tamamını yaz."
    return None


def _kaynak_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 2:
        return "`.` ve `..` girdilerini de saymışsın; onlar dosya değil. Düz `ls` kullan."
    return None


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: oyuncunun yazacağı komutlarla çözer."""
    from hy.motor.kontrol import Baglam
    masa, kurulum, betik, kaynak = s["duzen"]
    istem = _sh("""[ "$(id -u)" -eq 0 ] && echo '#' || echo '$'""", lab)
    yol = _sh("pwd", lab)
    sayi = _sh(f"ls {kaynak} | wc -l", lab)
    kod = _sh(f"grep 'kod adın:' {masa}/hosgeldin.txt | awk '{{print $NF}}'", lab)
    bayrak = _sh(f"cd {kurulum} && bash {betik} | grep -o 'FLAG{{[^}}]*}}'", lab)
    harf = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (2, 7, 8, 9)}
    return {1: istem, 2: harf[2], 3: yol, 4: sayi, 5: kod, 6: bayrak, 7: harf[7], 8: harf[8], 9: harf[9]}


ADIMLAR = [
    Adim("Atölyen: Kali ve laboratuvar", """
Hacker'ın atölyesi laboratuvarıdır. **Kali Linux**, Debian tabanlı ve güvenlik testleri için
yüzlerce aracı hazır getiren bir dağıtımdır. Önemli not: Kali bir **araç kutusudur**, günlük
kullanım için tasarlanmamıştır. İnternette gezmek, e-posta okumak gibi işleri ana sisteminde
yap.

Kitap üç kurulum seçeneği sayar:

- **Sanal makine** (VirtualBox/VMware): en güvenlisi, bozulursa **snapshot**'tan (anlık kayıt)
  geri dönülür; ama en az 8 GB RAM ister.
- **Raspberry Pi**: ayrı, sürekli açık bir cihaz; ARM mimarisi (telefonlardaki işlemci ailesi)
  yüzünden bazı araçlar yavaş ya da eksik olabilir. Sen şu an büyük olasılıkla buradasın.
- **WSL2** (Windows içinde): hızlı kurulur ama ağ ve donanım erişimi kısıtlıdır.

Kitaptaki `lab-kur.sh` betiğini çalıştırmana gerek yok: oyun her görev için laboratuvarı
kendisi kurar. Bu görevin lab'ı <<musteri>> hazırlık dosyasını içeriyor.
"""),
    Adim("Komut istemi: $ ve #", """
Kali'de terminali açınca şuna benzer bir satır görürsün:

```
┌──(kali㉿kali)-[~]
└─$
```

Buna **komut istemi** (prompt) denir: kullanıcı adın `kali`, bilgisayarın adı `kali`, bulunduğun
klasör `~` (ev dizinin). Sondaki `$` **normal kullanıcı** olduğunu, `#` ise **root** (yönetici)
olduğunu gösterir. Oyunun görev kabuğunda istem `HY:c01b01 ~/... $` gibi görünür; sondaki
işaret aynı anlamı taşır.

`id -u` kullanıcı numaranı yazar. Root'un numarası her zaman **0**'dır.
""", komut="id -u", sonra="""
Çıktı 0 değilse normal kullanıcısın; isteminin sonunda `$` görürsün. Bu iyi bir şey: root
olarak çalışmak, tek bir yanlış komutla bütün sistemi bozabilmek demektir.
"""),
    Adim("sudo: geçici yetki", """
Kitap ilk iş sistemi güncellemeni söyler: `sudo apt update` ve `sudo apt full-upgrade -y`.
`sudo` "bu komutu yönetici yetkisiyle çalıştır" demektir ve parolanı sorar. **Parolayı yazarken
ekranda hiçbir şey görünmez, yıldız bile.** Bu bir arıza değil, güvenlik önlemidir: yazıp
Enter'a bas.

Bu oyunda **sudo gerektiren hiçbir görev yok**. Güncellemeyi istersen oyunun dışında, kendi
terminalinde yaparsın. Kali'nin varsayılan kullanıcı adı ve parolası `kali` / `kali`'dir;
değiştirmediysen ilk fırsatta `passwd` ile değiştir.
"""),
    Adim("Neredeyim?", """
Terminalde her zaman bir klasörün "içinde" durursun. `pwd` (print working directory)
bulunduğun klasörün tam yolunu yazar.
""", komut="pwd", sonra="""
Bu yol senin laboratuvarın. Görev kabuğunda kaybolursan `lab` yazman seni buraya geri getirir.
"""),
    Adim("Etrafına bak", """
`ls` bulunduğun klasördeki dosya ve klasörleri listeler. Bir klasörün içine bakmak için
adını yanına yazarsın: `ls <<kaynak>>`.
""", komut="ls"),
    Adim("Dosya okumak", """
`cat` bir dosyanın içeriğini ekrana basar. Laboratuvarın kökündeki yönlendirme notunu oku.
""", komut="cat OKUBENI.txt", sonra="""
Notta üç adım var. Saha görevinde bunları sırayla yapacaksın: Selin'in notunu okumak,
doğrulama betiğini çalıştırmak ve kaynak klasörüne göz atmak.
"""),
    Adim("Kabuğun kısayolları ve oyun komutları", """
Terminalde hız, kısayollardan gelir:

- **Tab**: dosya ya da klasör adının başını yazıp Tab'a bas, gerisini kabuk tamamlar.
- **Yukarı ok**: önceki komutları geri getirir.
- **Ctrl+C**: takılan ya da uzun süren bir komutu durdurur.
- **Ctrl+L** ya da `clear`: ekranı temizler.
- `cd klasor` bir klasöre girer, `cd ..` bir üst klasöre çıkar (Bölüm 2'de ayrıntısıyla).

Görev kabuğunda bunlara ek olarak oyunun komutları çalışır: `gorev` (soru listesi),
`cevap <no> <cevabın>`, `ipucu <no>`, `pes <no>`, `lab` (lab'a dön), `sifirla` (lab'ı baştan
kur) ve `cik` (menüye dön).

**Hacker gözüyle:** Bu laboratuvarı istediğin kadar bozabilirsin. Gerçek sistemlerde bu
lüksün olmayacak; o yüzden riskli denemeleri hep burada yap.
"""),
]

GOREVLER = [
    Gorev("Görev kabuğundaki komut isteminin (prompt) **en sonundaki** karakter ne?",
          Dinamik(_istem_karakteri, bicim="tek karakter ($ ya da #)"),
          ("İmlecin hemen solundaki işarete bak.",
           "Normal kullanıcı ile root'un istemleri farklı bir işaretle biter. `id -u` 0 mı?",
           "Normal kullanıcıysan istem `$` ile biter: `cevap 1 '$'` yaz. (Root isen `#`; tırnak "
           "içinde yaz, yoksa kabuk onu yorum sanar.)"),
          puan=20, baslik="İstem"),
    Gorev("Bir gün isteminin sonunda `$` yerine `#` gördün. Bu sana ne söyler?",
          Secmeli([
              ("Root yetkisiyle çalışıyorsun; her komutun bütün sistemi etkileyebilir",
               "Doğru. `#` root istemidir. Bu durumda her komutu iki kez düşün; işin bitince `exit` ile normal kullanıcıya dön."),
              ("Kabuk yorum moduna geçti; yazdığın satırlar çalışmadan geçmişe kaydedilir",
               "Böyle bir mod yok. `#` satırın içinde yorum başlatır, ama istemin sonundaki `#` root olduğunu gösterir."),
              ("Terminal başka bir makineye bağlandı; komutların uzaktaki sunucuda çalışıyor",
               "Uzak bağlantıda istemdeki makine adı değişir; sondaki `#` ise kullanıcının root olduğunu söyler."),
              ("Önceki komut hata verdi; istem, sorun çözülene dek `#` ile uyarı veriyor",
               "Hata durumu istemin sonundaki işareti değiştirmez. `$` normal kullanıcı, `#` root demektir."),
          ]),
          ("Eğitimdeki komut istemi adımını hatırla.",
           "İki işaret iki farklı kullanıcı türünü gösterir: normal kullanıcı ve ...",
           "`$` normal kullanıcı, `#` yönetici (root)."),
          puan=20, baslik="Diyez"),
    Gorev("Laboratuvar klasörünün **tam yolu** ne? (`/` ile başlayan mutlak yol)",
          Dinamik(_lab_yolu, bicim="tam yol (örn. /home/...)", sik_hatalar=_lab_yolu_hata),
          ("Terminal sana nerede olduğunu söyleyebilir.",
           "Görev kabuğu açıldığında zaten lab'dasın; değilse önce `lab` yaz. Sonra yolu soran komutu çalıştır.",
           "`pwd` çıktısının tamamını kopyala: `cevap 3 /home/...`"),
          puan=20, baslik="Neredeyim"),
    Gorev("`<<kaynak>>` klasöründe kaç dosya var?",
          Sayi("kaynak_sayi", sik_hatalar=_kaynak_hata),
          ("Bir klasörün içini görmek için listeleme komutunu klasör adıyla birlikte kullan.",
           "`ls <<kaynak>>` yaz ve satırları say.",
           "Saymayı terminale de yaptırabilirsin: `ls <<kaynak>> | wc -l` (bu boru hattını Bölüm 4'te öğreneceksin)."),
          puan=20, baslik="Kaynaklar"),
    Gorev("Selin sana bir **kod adı** verdi. Kod adın ne?",
          Metin("kod_adi", bicim="kod adı (örn. KARTAL-7)"),
          ("OKUBENI.txt'deki yol haritasının ilk adımı, notun nerede olduğunu söylüyor.",
           "Not `<<masa>>` klasöründe. Önce `ls <<masa>>`, sonra notu `cat` ile oku.",
           "`cat <<masa>>/hosgeldin.txt` çıktısında 'kod adın' yazan satıra bak."),
          puan=25, baslik="Kod adı"),
    Gorev("Laboratuvar kurulumunu doğrula: `<<kurulum>>` klasöründeki betiği çalıştır ve verdiği "
          "**doğrulama bayrağını** gönder.",
          Bayrak("bayrak"),
          ("OKUBENI.txt'nin ikinci adımı tam olarak bunu anlatıyor.",
           "Önce klasöre gir (`cd <<kurulum>>`), sonra betiği `bash` ile çalıştır.",
           "`cd <<kurulum>>` ve ardından `bash <<betik>>`. Son satırdaki FLAG{...} değerini gönder."),
          puan=35, baslik="Kurulum doğrulama"),
    Gorev("Kitap, sanal makineyi ilk açtığında hiçbir şey yapmadan önce bir **snapshot** almanı "
          "söylüyor. Snapshot ne işe yarar?",
          Secmeli([
              ("Makinenin o anki halini saklar; bir şeyi bozarsan o ana dönersin",
               "Doğru. 'Temiz kurulum' adında bir snapshot, bozmaktan korkmadan denemeni sağlar."),
              ("Ekranın görüntüsünü kaydeder; rapora koyacağın kanıtlar için kullanılır",
               "O ekran görüntüsüdür (screenshot). Snapshot, makinenin bütün durumunun kaydıdır."),
              ("Kali'yi en son sürüme günceller ve eksik araçları kendiliğinden kurar",
               "Güncelleme `apt` ile yapılır. Snapshot hiçbir şey kurmaz, sadece durumu saklar."),
              ("Sanal makinenin belleğini artırır; ağır araçlar böylece hızlı çalışır",
               "Snapshot performansla ilgili değildir; geri dönülebilecek bir kayıt noktasıdır."),
          ]),
          ("İpucu kutusundaki 'temiz kurulum' adını düşün.",
           "Snapshot kelimesi 'anlık fotoğraf' demek. Neyin fotoğrafı?",
           "Makinenin o anki durumunun kaydı: bozarsan saniyeler içinde geri dönersin."),
          puan=20, baslik="Snapshot"),
    Gorev("Kitap, Kali'yi internette gezmek ve e-posta okumak gibi günlük işler için kullanmamanı "
          "söylüyor. Neden?",
          Secmeli([
              ("Kali, güvenlik testleri için bir araç kutusu; günlük iş için yapılmadı",
               "Doğru. Yüzlerce saldırı aracı ve test için yapılmış ayarlarla gelir; günlük kullanım için ana sistemin daha uygundur."),
              ("Kali'de web tarayıcısı yoktur; internete yalnızca terminalden çıkılabilir",
               "Kali'de Firefox kurulu gelir. Mesele tarayıcı değil, sistemin tasarım amacı."),
              ("Kali'nin lisansı, test dışındaki her türlü kullanımı yasal olarak yasaklar",
               "Kali özgür yazılımdır; böyle bir lisans yasağı yok. Mesele tasarım amacı ve risk."),
              ("Kali her açılışta bütün dosyaları siler; kaydettiğin şeyler hep kaybolur",
               "Bu yalnızca kalıcılık açılmamış 'live' (USB'den canlı) modda olur. Normal kurulumda dosyaların durur."),
          ]),
          ("Eğitimin ilk adımındaki 'önemli not'u hatırla.",
           "Kali'nin neyi hazır getirdiğini düşün: yüzlerce ... aracı.",
           "Kali bir araç kutusudur; günlük işleri ana sisteminde yap."),
          puan=20, baslik="Araç kutusu"),
    Gorev("`sudo` bir komut için parolanı sordu; yazarken ekranda hiçbir şey, yıldız bile "
          "görünmüyor. Ne yaparsın?",
          Secmeli([
              ("Normal; parolamı yazıp Enter'a basarım, görünmemesi bir önlemdir",
               "Doğru. Linux parolayı yazarken hiçbir iz göstermez; omzunun üstünden bakan biri uzunluğunu bile göremez."),
              ("Klavye bağlantısı kopmuştur; terminali kapatıp yeni bir pencerede denerim",
               "Klavye çalışıyor; tuşların gidiyor ama ekrana basılmıyor. Yazıp Enter'a bas."),
              ("Caps Lock açık kalmıştır; kapatıp parolayı en baştan bir kez daha yazarım",
               "Caps Lock parolayı yanlış yapabilir ama görünmemenin sebebi o değil. Görünmemesi normal."),
              ("sudo kilitlenmiştir; Ctrl+C ile durdurup aynı komutu sudo'suz çalıştırırım",
               "sudo bekliyor, kilitlenmedi. sudo'suz çalıştırmak, yönetici yetkisi gereken komutu başarısız yapar."),
          ]),
          ("Eğitimdeki 'sudo: geçici yetki' adımında bu durumdan bahsettik.",
           "Bu bir arıza mı, yoksa bilerek yapılmış bir şey mi?",
           "Parola yazılırken ekranda görünmez; bu normaldir. Yaz ve Enter'a bas."),
          puan=20, baslik="Görünmeyen parola"),
]


SEVIYE = Seviye(
    kimlik="c01b01",
    cilt=1,
    bolum=1,
    baslik="Laboratuvarını Kur",
    brifing="""
Selin, Kali kurulu dizüstü bilgisayarı önüne bırakıyor: "Laboratuvarın hazır. Gelecek hafta
**<<musteri>>** (<<sektor>>) ile çalışacağız; dosyası lab'ında duruyor. Kısaca durum şu:
<<hikaye>>"

"Ama bugün müşteriye dokunmak yok. Bugün terminalle tanışacaksın: istemi okumayı, lab'da
dolaşmayı ve kurulumunun gerçekten çalıştığını doğrulamayı öğreneceksin. Masanda benden bir
not var, onu da bul."

Mert sandalyesini çevirip gülümsüyor: "Burada bozduğun her şey `sifirla` ile geri gelir.
Korkmadan kurcala. Gerçek sunucularda o lüksün olmayacak."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bir hacker'ın ilk refleksi, nerede ve kim olduğunu bilmektir: istemin sonundaki `$` ya da
`#`, `pwd` ile görünen yol ve klasörde ne olduğu. Saldırgan tarafında root olmak hedeftir;
savunma tarafında ise **gereksiz yere root olarak çalışmamak** en temel kuraldır. Bozmaktan
korkmayan daha hızlı öğrenir, ama bunu yalnızca geri dönebileceği bir laboratuvarda yapar:
snapshot, yedek ve `sifirla` bu yüzden var.
""",
    gercek_hayat="""
- **Kali'nin root'tan vazgeçmesi:** Kali uzun yıllar varsayılan olarak root kullanıcısıyla
  geliyordu. 2020.1 sürümünden itibaren varsayılan olarak normal bir kullanıcıyla (`kali`)
  geliyor ve yönetici işleri için `sudo` kullanılıyor. Sebep bu bölümün dersiyle aynı: her
  işi root olarak yapmak gereksiz risk demek.
- **Varsayılan parolalar ve Mirai (2016):** Mirai zararlısı, üreticiden çıktığı gibi varsayılan
  kullanıcı adı/parolasıyla bırakılmış çok sayıda IoT cihazını (kamera, modem) ele geçirip
  dev bir botnet kurdu ve büyük hizmet engelleme saldırılarında kullandı. Kitabın "ilk iş
  `kali`/`kali` parolasını değiştir" uyarısı bu yüzden önemli.
- **Analiz makineleri:** Zararlı yazılım analistleri ve pentester'lar riskli denemeleri
  genellikle snapshot alınmış sanal makinelerde yapar; bir şey ters giderse makine temiz
  duruma geri döndürülür.
""",
    sure_hedef_dk=15,
)
