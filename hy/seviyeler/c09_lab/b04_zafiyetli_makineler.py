"""Cilt 9 · Bölüm 4 — Zafiyetli Makineleri Kur.

Beceri: VulnHub / Metasploitable gibi zafiyetli sanal makine kavramı; bu makinelerin x86 için
hazırlandığını ve Raspberry Pi (arm64) üzerinde çalışmayacağını görmek; Docker tabanlı hedefler,
ayrı x86 makine ve çevrimiçi yasal platformlar gibi alternatifler; indirilen imajın SHA-256
özetini `sha256sum -c` ile doğrulamak.

Lab dosyaları kurguseldir: `indirilenler/` altındaki "imajlar" birkaç KB'lık sahte dosyalardır,
katalogdaki makine adları uydurmadır.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

VAKALAR = [
    {
        "ad": "Kalkan Güvenlik — stajyerin Cilt 6 hedefleri", "uzanti": "ova", "on": "kalkan",
        "brifing": """
Selin masasındaki Pi'yi gösteriyor: "Cilt 6'nın yetki yükseltme pratiği için tam bir işletim
sistemi hedefe ihtiyacın var; klasik adaylar Metasploitable ve VulnHub makineleri. Ama dikkat: bu
makinelerin çoğu x86 için hazırlanmış, sen ise bir Pi kullanıyorsun."

Mert: "Bir de indirdiğin dosyanın bütünlüğünü doğrulamadan açma. Geçen yıl biri bozuk bir imajla
iki gün uğraştı; hata imajda değil, yarım inen dosyadaydı."

Dosyalar: `makine_katalogu.txt` ve `indirilenler/` klasörü.
""",
    },
    {
        "ad": "Kuzgun Lojistik — depo ekibi eğitim ağı", "uzanti": "vmdk", "on": "kuzgun",
        "brifing": """
Serdar Bey (Kuzgun Lojistik IT sorumlusu) anlatıyor: "Depo ekibine sızma testi eğitimi vereceğiz.
Eğitim için internetten zafiyetli makineler indirip bir sunucuya koyacağız. Birkaç dosya yanlış
indi, hangisi sağlam hangisi bozuk bilmiyoruz."

Selin sana dönüyor: "Katalogdan Pi'lerde çalışabilecek olanları ayıkla, indirilen dosyaları
özet değerleriyle (hash) doğrula. Sağlam olmayan bir imajı eğitim ağına sokmayacağız."

Dosyalar: `makine_katalogu.txt` ve `indirilenler/` klasörü.
""",
    },
    {
        "ad": "Mert'in Pi'si — çalışmayan VM'ler", "uzanti": "ova", "on": "mert",
        "brifing": """
Mert yorgun görünüyor: "Üç akşamdır Pi'ye bir zafiyetli VM kurmaya uğraşıyorum, hiçbiri açılmıyor.
Hata mesajı da garip. Neyi yanlış yapıyorum?"

Selin gülümsüyor: "Muhtemelen mimari. Mert'e katalogu gösterip hangi hedeflerin Pi'ye uygun
olduğunu çıkar; ayrıca indirdiği dosyaları da doğrula, belki biri bozuktur."

Dosyalar: `makine_katalogu.txt` ve `indirilenler/` klasörü.
""",
    },
]

SOZ_A = ["eski", "zayif", "acik", "sinav", "ornek", "kasa", "depo", "yedek", "kurgu", "deneme"]
SOZ_B = ["sunucu", "panel", "portal", "kutu", "istasyon", "ag"]


def _icerik(rng, n: int) -> bytes:
    satirlar = [f"KURGUSAL-IMAJ blok {i:04d} " + "".join(rng.choice("0123456789abcdef") for _ in range(48))
                for i in range(n)]
    return ("\n".join(satirlar) + "\n").encode()


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    # indirilen dosyalar
    adlar = u.benzersiz(rng, lambda r: f"{r.choice(SOZ_A)}-{r.choice(SOZ_B)}-{r.randint(1, 9)}", 4)
    dosyalar = {}
    for ad in adlar:
        dosyalar[f"{ad}.{v['uzanti']}"] = _icerik(rng, rng.randint(40, 70))
    isimler = list(dosyalar)
    bozuk = rng.choice(isimler)
    ozet_dosya = rng.choice([x for x in isimler if x != bozuk])
    saglam = [x for x in isimler if x != bozuk]
    # katalog
    limit = rng.choice([1024, 1536, 2048])
    while True:
        mak = []
        kadlar = u.benzersiz(rng, lambda r: f"{r.choice(SOZ_A)}-{r.choice(SOZ_B)}-{r.randint(10, 99)}", 7)
        desen = [("vm", "amd64"), ("vm", "amd64"), ("vm", "arm64"), ("konteyner", "amd64+arm64"),
                 ("konteyner", "amd64+arm64"), ("konteyner", "arm64"), ("konteyner", "amd64")]
        for ad, (tur, mim) in zip(kadlar, desen):
            ram = rng.randrange(256, 2561, 128) if tur == "konteyner" else rng.randrange(1024, 2561, 256)
            mak.append((ad, tur, mim, ram))
        rng.shuffle(mak)
        uygun = sorted(a for a, t, m, r in mak if "arm64" in m and r <= limit)
        if 2 <= len(uygun) <= 4:
            break
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v,
        "dosyalar": {k: x.hex() for k, x in dosyalar.items()},   # JSON'a uygun, saf veri
        "isimler": isimler, "bozuk": bozuk, "ozet_dosya": ozet_dosya, "saglam": saglam,
        "mak": mak, "limit": limit,
        "metin": {"ozet_dosya": ozet_dosya, "limit": str(limit), "bozuk_sayi": "1"},
        "cevaplar": {"uygun": uygun, "bozuk": bozuk,
                     "ozet12": hashlib.sha256(dosyalar[ozet_dosya]).hexdigest()[:12]},
    }


def yaz(lab: Path, s: dict) -> None:
    kok = lab / "indirilenler"
    sums = []
    for ad in s["isimler"]:
        icerik = bytes.fromhex(s["dosyalar"][ad])
        sums.append(f"{hashlib.sha256(icerik).hexdigest()}  {ad}\n")   # yayıncının listelediği (özgün) özet
        gercek = icerik
        if ad == s["bozuk"]:
            gercek = icerik.replace(b"KURGUSAL-IMAJ blok 0003", b"KURGUSAL-IMAJ blok 0X03", 1)
        (kok).mkdir(parents=True, exist_ok=True)
        (kok / ad).write_bytes(gercek)
    u.yaz(kok / "SHA256SUMS", "".join(sums))
    satir = ["# Kurgusal makine kataloğu. Adlar uydurmadır.\n",
             f"pi_ram_siniri_mb: {s['limit']}\n",
             "# Pi: arm64 işlemci. Bir makine çalışabilmek için hem mimari hem RAM uygun olmalı.\n"]
    for ad, tur, mim, ram in s["mak"]:
        satir.append(f"makine: {ad} | tur: {tur} | mimari: {mim} | ram_mb: {ram}\n")
    u.yaz(lab / "makine_katalogu.txt", "".join(satir))


# ------------------------------------------------------------------ kontroller

def _ozet_hata(g, beklenen, b):
    if len(g) == 64:
        return "Özetin tamamını yazmışsın; istenen yalnızca ilk 12 karakter. `cut -c1-12` kullanabilirsin."
    return None


def _dogrulama(b: Baglam) -> Sonuc:
    ad = "dogrulama.txt"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    s = b.senaryo
    verilen = []
    for satir in yol.read_text(encoding="utf-8", errors="replace").splitlines():
        t = satir.strip()
        if t.startswith("./"):
            t = t[2:]
        if t.startswith("indirilenler/"):
            t = t[len("indirilenler/"):]
        if t.endswith(": OK"):
            t = t[:-4]
        if t:
            verilen.append(t)
    if not verilen:
        return Sonuc(False, "`dogrulama.txt` boş. İçine doğrulamadan geçen dosyaların adlarını yaz (satır başına bir tane).")
    if s["bozuk"] in verilen:
        return Sonuc(False, f"`{s['bozuk']}` listede ama özeti uyuşmuyor (FAILED). Yalnızca doğrulamadan geçenleri yaz.", yakin=True)
    bilinmeyen = [x for x in verilen if x not in s["isimler"]]
    if bilinmeyen:
        return Sonuc(False, f"`{bilinmeyen[0]}` indirilenler klasöründe yok. Yalnızca dosya adlarını yaz (satır başına bir tane).", yakin=True)
    eksik = [x for x in s["saglam"] if x not in verilen]
    if eksik:
        return Sonuc(False, f"{len(eksik)} sağlam dosya listede yok. `sha256sum -c` çıktısında `OK` yazanların hepsini ekle.", yakin=True)
    if len(set(verilen)) != len(verilen):
        return Sonuc(False, "Bir dosya adı birden fazla kez yazılmış. Her dosya bir kez geçmeli.", yakin=True)
    return Sonuc(True, "Doğrulama raporu tamam: yalnızca özeti uyuşan dosyalar listede. Uyuşmayanı lab'a sokma, yeniden indir.")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Zafiyetli makine nedir?", """
Cilt 4-6'nın tam işletim sistemi pratiği için kasıtlı olarak zayıf bırakılmış hazır **sanal
makineler** vardır. İki bilinen kaynak:

- **Metasploitable 2:** Eski, çok sayıda açık servisi olan klasik bir Linux hedefi.
- **VulnHub:** Topluluğun hazırladığı, ücretsiz ve çevrimdışı çalıştırılabilen yüzlerce makine.

Bunlar genelde `.ova`/`.vmdk` dosyası olarak indirilir ve bir sanallaştırma programına aktarılır.
Bu seviyedeki makine kataloğu kurguseldir:
""", komut="cat makine_katalogu.txt", sonra="""
`tur: vm` tam bir işletim sistemi, `tur: konteyner` ise bir Docker hedefidir. `mimari` sütunu
bu bölümün kilidi: bir makine hangi işlemci mimarisi için hazırlandıysa orada çalışır.
"""),
    Adim("ARM'da çalışmama sorunu", """
Bu makinelerin çoğu **x86 (amd64)** işlemci için hazırlanmıştır. Raspberry Pi **arm64** işlemcidir.
Mimari uyuşmayan bir imajı Pi'de olduğu gibi açamazsın; "tam hızda" çalıştırmanın bir yolu yoktur.
Katalogda yalnızca ad ve mimariye bakalım:
""", komut="grep '^makine:' makine_katalogu.txt | cut -d'|' -f1,3", sonra="""
Mimarisinde `arm64` geçenler Pi'ye uygun adaylardır. Ama yetmez: RAM de yetmeli (Bölüm 1).
"""),
    Adim("Alternatifler", """
Pi'de x86 VM çalışmıyorsa elinde dört yol var:

1. **Docker tabanlı hedefler:** Hafiftir, arm64 imajı varsa Pi'de çalışır (Bölüm 3'teki gibi).
   Ama çekirdek açıkları gibi işletim sistemi derinliği gerektiren konularda yetersizdir.
2. **Ayrı bir x86 makine:** Eski bir dizüstü ya da mini PC'de VM çalıştır; Pi'yi Kali olarak kullan,
   ikisini izole bir ağda birleştir.
3. **Çevrimiçi yasal platformlar:** Kendi makineni kurmadan, hedeflerini sunan eğitim
   platformları (kuralları ve süre sınırlarıyla).
4. **Hepsini birden:** Web için Pi'de Docker, işletim sistemi için ayrı x86 makine.

`indirilenler/` klasöründeki dosyalar, bir x86 VM için "indirilmiş" kurgusal imajlar:
""", komut="ls -l indirilenler"),
    Adim("İndirdiğin imajı doğrula: sha256sum", """
İnternetten indirdiğin bir imaj **yarım inmiş, bozulmuş ya da değiştirilmiş** olabilir. Yayıncı
çoğunlukla bir **SHA-256 özeti** (hash) verir: dosyanın parmak izi gibi, tek bir bayt
değişse özet tamamen değişir. Kendi indirdiğinin özetini hesaplayıp yayıncınınkiyle karşılaştırırsın.
`indirilenler/SHA256SUMS` yayıncının listesidir; `sha256sum -c` her dosyanın özetini hesaplayıp
listeyle karşılaştırır:
""", komut="cd indirilenler && sha256sum -c SHA256SUMS", sonra="""
`OK` özeti uyuşan, `FAILED` uyuşmayan dosya demektir; en altta kaç dosyanın uyuşmadığı yazar.
`FAILED` çıkan imajı **açma**, yeniden indir. Bir dosyanın tek özetini görmek için
`sha256sum dosya` yazılır.
"""),
    Adim("Özetin kendisine ne kadar güvenebilirsin?", """
Özet, dosyanın bozulmadığını gösterir ama **özetin geldiği yer** de güvenilir olmalı. Dosyayı da
özeti de aynı saldırgana ait bir sayfadan alıyorsan ikisini birden değiştirebilir. Bu yüzden
özeti mümkünse yayıncının **başka bir kanalından** (resmi site, imzalı duyuru) da karşılaştırırsın.
""", komut="cat indirilenler/SHA256SUMS"),
    Adim("Hacker gözüyle: indirilen VM zararlı olabilir", """
Zafiyetli makineler zaten zayıf olduğu için, kötü niyetli biri sahte bir "hazır lab" paketine
gerçek bir zararlı koyabilir. İndirilen her VM'i **internetsiz, izole bir ağda** (Host-Only/Internal)
ilk kez aç, ana makinenle paylaşılan klasör/pano gibi özellikleri kapat ve resmi/tanınmış
kaynaklardan indir. İzolasyon, imaj kötü niyetli çıksa bile hasarı sınırlar.
"""),
]

GOREVLER = [
    Gorev("Kitapta Metasploitable 2'yi VirtualBox'a aktarmayı öğrendin. Aynı adımlar Pi'nde neden "
          "olduğu gibi işe yaramaz?",
          Secmeli([
              ("Bu makineler x86 (amd64) işlemci için hazırlanmıştır; Pi'nin arm64 işlemcisi onları çalıştıramaz",
               "Doğru: işlemci mimarisi uyuşmadığı için imaj olduğu gibi açılmaz."),
              ("Pi'de hiçbir sanallaştırma yazılımı çalışmaz; sanal makine kavramı yalnızca masaüstü bilgisayarlara özgüdür",
               "Sorun 'sanal makine kavramı' değil, imajın hazırlandığı işlemci mimarisidir."),
              ("Zafiyetli makineler yalnızca Windows ana makinelerde çalışacak biçimde yazılmıştır, Linux'ta açılmaz",
               "Bunlar Linux ana makinelerde de çalışır; sorun ana makinenin işletim sistemi değil işlemcisidir."),
              ("Pi'nin belleği yalnızca konteynerlere ayrılabilir, sanal makinelere hiçbir bellek verilemez",
               "Bellek bu şekilde ayrılmış değildir; asıl engel mimari uyuşmazlığıdır."),
          ], dogru=0),
          ("Soruda iki ayrı mimari var: makinenin hazırlandığı ve Pi'nin kendi işlemcisi.",
           "Bu bölümde `makine_katalogu.txt`'te 'mimari' sütununa neden dikkat ediyorduk?",
           "x86/amd64 için yapılmış imaj, arm64 işlemcide çalışmaz."),
          puan=20, baslik="ARM sorunu"),
    Gorev("`makine_katalogu.txt`: Pi'de **gerçekten çalışabilecek** makineler hangileri? (Mimarisinde "
          "`arm64` geçen **ve** RAM ihtiyacı `pi_ram_siniri_mb` değerini aşmayan makinelerin adları)",
          Kume("uygun", tur="metin", bicim="makine adları, virgülle ayrılmış"),
          ("İki koşul var: mimari ve bellek. İkisi de sağlanmalı.",
           "`grep arm64 makine_katalogu.txt` mimari koşulunu sağlayanları verir; ardından `ram_mb` değerlerini sınırla karşılaştır.",
           "`grep '^makine:' makine_katalogu.txt | grep arm64` çıktısındaki satırlardan `ram_mb` değeri sınırdan büyük olanları ele."),
          puan=40, baslik="Pi'ye uygun olanlar"),
    Gorev("`indirilenler/` klasöründeki dosyalardan hangisinin SHA-256 özeti `SHA256SUMS` listesiyle "
          "**uyuşmuyor** (bozuk ya da değiştirilmiş)? Dosya adını yaz.",
          Metin("bozuk", sadece_ad=True, bicim="dosya adı"),
          ("Özet doğrulama aracı bir listeyle karşılaştırır ve her dosya için sonuç yazar.",
           "`cd indirilenler` ile klasöre gir, `sha256sum -c SHA256SUMS` çalıştır; `FAILED` yazanı bul.",
           "`cd indirilenler && sha256sum -c SHA256SUMS 2>&1 | grep FAILED` bozuk dosyanın adını yazar."),
          puan=30, baslik="Bozuk imaj"),
    Gorev("`<<ozet_dosya>>` dosyasının SHA-256 özetinin **ilk 12 karakteri** nedir?",
          Metin("ozet12", sik_hatalar=_ozet_hata, bicim="12 karakterlik onaltılık özet"),
          ("Bir dosyanın özetini hesaplayan komutun adı ünlü: sha ve 256.",
           "`sha256sum dosya` özeti ve dosya adını yazar; dosya `indirilenler/` içinde. Çıktının başındaki 12 karakteri al.",
           "`sha256sum indirilenler/<<ozet_dosya>> | cut -c1-12`"),
          puan=30, baslik="Özet hesapla"),
    Gorev("Doğrulama raporu hazırla: lab klasöründe `dogrulama.txt` oluştur ve içine **özeti uyuşan "
          "(OK) dosyaların adlarını** yaz, her satıra bir ad. Bozuk olanı yazma. Hazır olunca `cevap 5`.",
          Durum(_dogrulama, "```\ncd indirilenler && sha256sum -c SHA256SUMS 2>/dev/null | grep ': OK' | cut -d: -f1 > ../dogrulama.txt\n```"),
          ("Doğrulama aracının çıktısında her dosya `OK` ya da `FAILED` ile biter.",
           "`sha256sum -c` çıktısından yalnızca `OK` satırlarını `grep` ile ayıkla, sonra yalnızca dosya adını al (`cut`).",
           "`cd indirilenler && sha256sum -c SHA256SUMS 2>/dev/null | grep ': OK' | cut -d: -f1 > ../dogrulama.txt`"),
          puan=40, baslik="Doğrulama raporu"),
    Gorev("Bir forumda 'hazır zafiyetli makine paketi' paylaşılmış. İndirme bağlantısının hemen yanında "
          "aynı kişinin yazdığı bir SHA-256 değeri de var. Dosyanın özeti bu değerle uyuşuyor. Ne yaparsın?",
          Secmeli([
              ("Özeti yayıncının başka bir kanalından da karşılaştırır ve imajı yalnızca izole ağda açarım",
               "Doğru: özet, kaynağı güvenilir kanaldan doğrulanınca anlam kazanır; ayrıca izole ağ riski sınırlar."),
              ("Uyuştuğu için dosyanın kesinlikle güvenli olduğunu kabul eder ve ana ağda çalıştırırım; başka kontrol gerekmez",
               "Aynı kişi hem dosyayı hem özeti değiştirebilir; uyuşma, kaynağın güvenilir olduğunu göstermez."),
              ("Dosyayı önce ana makinemde bir kez çalıştırırım; zararlıysa antivirüs yazılımı beni zaten uyarır",
               "Antivirüs her zararlıyı yakalamaz; zafiyetli lab makinelerini zaten zararlıdan ayırmak zordur. İzole olmayan açılış risklidir."),
              ("Boyutu ilanla aynıysa içerik de aynıdır; özet bakmak yalnızca zaman kaybettirir ve gereksizdir",
               "Aynı boyutta farklı içerik üretmek kolaydır; boyut bir doğrulama sayılmaz."),
          ], dogru=0),
          ("Özet, bir dosyanın bozulmadığını gösterir. Özetin nerede durduğu önemli mi?",
           "Aynı saldırgan hem dosyayı hem özeti koyuyorsa özeti neye karşı karşılaştırıyorsun?",
           "Güvenilir ikinci kanal + izole ağ."),
          puan=30, baslik="Forum paketi"),
    Gorev("Cilt 6'daki yetki yükseltmenin bir türü **çekirdek (kernel) açıklarıdır**. Bu türü Docker "
          "konteyneri olarak çalışan zafiyetli bir hedefte pratik edebilir misin?",
          Secmeli([
              ("Genelde hayır: konteynerler çekirdeği ana makineyle paylaşır; çekirdek denemeleri için ayrı çekirdekli VM gerekir",
               "Doğru: konteynerin ayrı bir çekirdeği yoktur; çekirdek açıkları için gerçek bir VM gerekir."),
              ("Evet; her konteynerin kendi çekirdeği vardır ve istediğin çekirdek sürümünü seçerek açıkları deneyebilirsin",
               "Konteynerler çekirdek taşımaz; ana makinenin çekirdeğini kullanır."),
              ("Evet, ama yalnızca konteyneri `--privileged` ile çalıştırırsan; o zaman çekirdek de konteynere göre değişir",
               "`--privileged` çekirdeği değiştirmez, yalnızca konteynere ana makineye yakın yetki verir; bu lab'ı tehlikeli kılar."),
              ("Hayır, çünkü konteynerler içlerinde hiçbir işletim sistemi dosyası taşımaz, yalnızca uygulamanın kendisini ve kodunu içerir",
               "Konteynerlerde işletim sistemi dosyaları (kullanıcı alanı) bulunur; eksik olan ayrı bir çekirdektir."),
          ], dogru=0),
          ("Konteyner ile VM'in en temel farkını hatırla: çekirdek kimde?",
           "Çekirdek açığını denemek için hedefin kendi çekirdeği olmalı. Konteynerde bu var mı?",
           "Konteynerler çekirdeği paylaşır; VM'in kendi çekirdeği vardır."),
          puan=30, baslik="Çekirdek pratiği"),
]


def _kapanis():
    return """
İndirilen bir zafiyetli makine, bir hedef olduğu kadar bir **tedarik zinciri** riskidir. Saldırgan
gözüyle: bir "hazır lab" paketi, şüphelenilmeyen bir yazılımı hedefin içine sokmanın kolay bir yoludur.
Savunma gözüyle: kaynağı doğrula, özeti ikinci bir kanaldan karşılaştır, imajı yalnızca izole ağda aç
ve Pi'de mimari uyuşmayan imajla uğraşma. Bu bölümde yaptığın `sha256sum -c` kontrolü, kurumsal
dünyada yazılım güncellemelerini doğrulamak için kullanılan aynı fikrin küçük bir hâlidir.
"""


SEVIYE = Seviye(
    kimlik="c09b04",
    cilt=9,
    bolum=4,
    baslik="Zafiyetli Makineleri Kur",
    brifing="Zafiyetli makineleri Pi'de çalıştırmaya hazırlanıyorsun; mimari ve indirme bütünlüğü kontrol edilecek.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **SolarWinds (2020):** Saldırganlar, yaygın kullanılan bir yönetim yazılımının güncelleme
  paketini derleme sürecinde değiştirdi; zararlı paket meşru kanaldan dağıtıldı. Ders: bir
  özet ya da imza, **geldiği kanal da güvenilirse** anlam taşır; yazılımı yalnızca özetle değil,
  imza ve kaynak denetimiyle birlikte doğrularsın. Olay, bir güvenlik firmasının kendi
  hesaplarındaki olağandışı bir etkinliği incelemesiyle fark edildi.
- **Zararlı konteyner imajları:** Güvenlik şirketlerinin raporları, herkese açık imaj
  depolarında kripto madenciliği gibi zararlı yazılım taşıyan imajların bulunduğunu defalarca
  göstermiştir. Önlem: yalnızca resmi/tanınmış yayıncıların imajlarını kullanmak, özet ve etiket
  sabitlemek, bilinmeyen imajları izole ortamda denemek.
- **Mimari uyuşmazlığı:** Pi gibi arm64 cihazlarda, x86 için hazırlanmış VM'ler çalışmaz. Bu
  hem lab planlamasında hem şirketlerde (ARM tabanlı sunucuların yaygınlaşmasıyla) gerçek bir
  uyumluluk sorunudur: imajın mimarisi daima kontrol edilir.
""",
    sure_hedef_dk=30,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    limit = sh("awk -F': ' '/^pi_ram_siniri_mb/{print $2}' makine_katalogu.txt")
    uygun = sh("grep '^makine:' makine_katalogu.txt | grep arm64 | awk -F'|' -v L=" + limit +
               " '{ split($4,a,\": \"); if (a[2]+0 <= L) { split($1,n,\": \"); print n[2] } }'").split()
    bozuk = sh("cd indirilenler && sha256sum -c SHA256SUMS 2>&1 | grep FAILED | cut -d: -f1")
    ozet = sh("sha256sum indirilenler/" + s["metin"]["ozet_dosya"] + " | cut -c1-12")
    sh("cd indirilenler && sha256sum -c SHA256SUMS 2>/dev/null | grep ': OK' | cut -d: -f1 > ../dogrulama.txt")
    return {1: SEVIYE.gorevler[0].kontrol.cevabi_goster(Baglam(s, lab, 1))[0], 2: " ".join(uygun), 3: bozuk,
            4: ozet, 5: "",
            6: SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0],
            7: SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]}
