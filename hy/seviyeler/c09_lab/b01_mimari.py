"""Cilt 9 · Bölüm 1 — Laboratuvar Mimarisi.

Beceri: lab = saldırgan makine + hedefler + aralarında yalıtılmış ağ; NAT / Köprü (Bridged) /
Host-Only / Internal ağ türleri; Docker ile VM farkı; Raspberry Pi'nin (arm64, sınırlı RAM)
kaynak planı; ağ planı dosyasında yalıtımı bozan hatayı bulup düzeltmek.

Vakalar: Kalkan Güvenlik'in stajyer lab'ı, Medora Sağlık'ın eğitim ortamı, Mert'in evdeki Pi'si.
Bütün donanım/ağ planları kurgusaldır (lab dosyaları); gerçek bir sisteme dokunulmaz.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Secmeli, Sayi, Durum, Metin, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

VAKALAR = [
    {
        "kod": "kalkan",
        "ad": "Kalkan Güvenlik — yeni stajyer lab'ı",
        "ortam": "Kalkan Güvenlik stajyer laboratuvarı",
        "hedefler": ["stajyer-web", "ik-portal", "dosya-paylasim", "yedek-servis", "bilet-sistemi", "wiki-sunucu"],
        "dis_ag": "ofis-lan",
        "brifing": """
Selin odaya giriyor, elinde küçük bir Raspberry Pi kutusu var. "Stajyer lab'ını sen kuracaksın.
Bütçe yok, ofiste boş bir Pi 4 var. Ama önce kâğıt üstünde plan istiyorum: hangi hedef aynı
anda çalışır, hangisi çalışmaz, ağ nasıl yalıtılır? Yanlış plan, ofis ağına zayıf bir sunucu
bırakmak demek."

Mert araya giriyor: "Geçen yıl biri test sunucusunu ofis ağına bağlı unuttu. Deniz'in SOC
ekranı bir hafta o sunucudan alarm yağdırdı. Planı bu sefer doğru yap."

Planlar `donanim.txt`, `hedefler.txt` ve `ag_plani.txt` dosyalarında.
""",
    },
    {
        "kod": "medora",
        "ad": "Medora Sağlık — BT eğitim ortamı",
        "ortam": "Medora Sağlık BT eğitim salonu",
        "hedefler": ["randevu-portal", "hasta-kayit", "lab-sonuc", "eczane-api", "personel-ik", "goruntu-arsiv"],
        "dis_ag": "hastane-lan",
        "brifing": """
Dr. Aslı Hanım telefonda: "Bilgi işlem ekibimize güvenlik eğitimi vereceksiniz. Eğitim salonunda
Raspberry Pi'ler var. Ama eğitim ortamı hastane ağından **kesinlikle ayrı** kalmalı; içinde
zafiyetli uygulamalar olacak, yanlışlıkla hasta sistemlerine bulaşırsa felaket olur."

Selin sana dönüyor: "Eğitim ortamının planını çıkar: Pi'ye neler sığar, ağ nasıl yalıtılır?
Müşteri planı görmeden tek bir konteyner kalkmayacak."

Planlar `donanim.txt`, `hedefler.txt` ve `ag_plani.txt` dosyalarında.
""",
    },
    {
        "kod": "mert",
        "ad": "Mert'in evdeki Pi'si",
        "ortam": "Mert'in ev laboratuvarı",
        "hedefler": ["ev-nas", "kamera-panel", "blog-motoru", "akilli-priz-hub", "medya-sunucu", "ders-notlari"],
        "dis_ag": "ev-wifi",
        "brifing": """
Mert öğle arasında telefonunu uzatıyor: "Evdeki Pi'mi lab yapmaya karar verdim ama ev Wi-Fi'ına
bağlı. Çocuklar, misafirler, akıllı televizyon... hepsi aynı ağda. Planımı bir de sen incele,
stajyer gözüyle."

Selin ekliyor: "Mert kendi ağını riske atıyor mu, bakalım. Aynı zamanda Pi'nin ne kadarına
neyin sığacağını da hesaplayın; RAM gerçek bir sınır."

Planlar `donanim.txt`, `hedefler.txt` ve `ag_plani.txt` dosyalarında.
""",
    },
]

AG_ADLARI = ["lab-ic", "izole-lab", "hedef-agi", "kum-havuzu"]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    toplam = rng.choice([2048, 4096, 4096])
    sistem = rng.choice([768, 1024, 1280])
    kalan = toplam - sistem
    # Hedefler: arm64 konteynerler + 1 amd64 konteyner + 1 amd64 VM. Cevap: RAM'e sığan en fazla arm64 hedef.
    n_arm = 4
    adlar = rng.sample(v["hedefler"], n_arm + 2) if len(v["hedefler"]) >= n_arm + 2 else list(v["hedefler"])
    while True:
        rams = [rng.randrange(256, 1281, 64) for _ in range(n_arm)]
        s = sorted(rams)
        sigan, t = 0, 0
        for r in s:
            t += r
            if t <= kalan:
                sigan += 1
        if 2 <= sigan <= n_arm - 1:
            break
    satirlar = [(adlar[i], rams[i], "konteyner", "arm64") for i in range(n_arm)]
    satirlar.append((adlar[n_arm], rng.randrange(256, 769, 64), "konteyner", "amd64"))
    satirlar.append((adlar[n_arm + 1] if n_arm + 1 < len(adlar) else "eski-vm", rng.choice([1024, 1536, 2048]),
                     "vm", "amd64"))
    rng.shuffle(satirlar)
    lab_ag = rng.choice(AG_ADLARI)
    lab_tur = rng.choice(["internal", "host-only"])
    dis_tur = rng.choice(["nat", "bridge"])
    arm_adlari = [x[0] for x in satirlar if x[3] == "arm64"]
    hatali = rng.choice(arm_adlari)
    hostlar = [x[0] for x in satirlar]
    return {
        "vaka": v["ad"],
        "brifing": v["brifing"],
        "toplam": toplam, "sistem": sistem, "kalan": kalan,
        "satirlar": satirlar, "lab_ag": lab_ag, "lab_tur": lab_tur, "dis_ag": v["dis_ag"], "dis_tur": dis_tur,
        "hostlar": hostlar, "hatali": hatali, "ortam": v["ortam"],
        "alt_ag_lab": f"10.{rng.randint(20, 99)}.{rng.randint(0, 200)}.0/24",
        "alt_ag_dis": f"192.168.{rng.randint(0, 99)}.0/24",
        "metin": {"ortam": v["ortam"], "lab_ag": lab_ag, "dis_ag": v["dis_ag"], "toplam": str(toplam),
                  "sistem": str(sistem), "hatali": hatali},
        "cevaplar": {"kalan_ram": kalan, "sigan": sigan, "hatali": hatali},
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "donanim.txt",
          f"# {s['ortam']} — kurgusal donanım envanteri\n"
          "cihaz: Raspberry Pi (arm64, yani ARM işlemci)\n"
          f"toplam_ram_mb: {s['toplam']}\n"
          "# Pi OS/Kali + Docker servisi + tarayıcı + Burp için ayrılan pay\n"
          f"sistem_payi_mb: {s['sistem']}\n"
          "depolama: SD kart veya NVMe\n")
    u.yaz(lab / "hedefler.txt",
          "# Lab'a konması planlanan hedefler (kurgusal). ram_mb: çalışırken ihtiyaç duyduğu bellek.\n"
          "# mimari: hedefin hazır imajının hangi işlemci mimarisi için olduğu.\n"
          + "".join(f"hedef: {ad} | ram_mb: {ram} | tur: {tur} | mimari: {mim}\n" for ad, ram, tur, mim in s["satirlar"]))
    ag = ["# Ağ planı (kurgusal). tur: nat, bridge, host-only, internal\n",
          f"ag: {s['lab_ag']} | tur: {s['lab_tur']} | alt_ag: {s['alt_ag_lab']}\n",
          f"ag: {s['dis_ag']} | tur: {s['dis_tur']} | alt_ag: {s['alt_ag_dis']}\n",
          f"host: kali-pi | aglar: {s['lab_ag']}, {s['dis_ag']}\n"]
    for h in s["hostlar"]:
        if h == s["hatali"]:
            ag.append(f"host: {h} | aglar: {s['dis_ag']}\n")
        else:
            ag.append(f"host: {h} | aglar: {s['lab_ag']}\n")
    u.yaz(lab / "ag_plani.txt", "".join(ag))


# ------------------------------------------------------------------ kontroller

def _kalan_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    s = b.senaryo
    if n == s["toplam"]:
        return "Bu Pi'nin **toplam** RAM'i. Sistemin kendisi (Kali, Docker, tarayıcı) de RAM kullanır; `sistem_payi_mb`'yi düşmelisin."
    if n == s["toplam"] // 1024 or n == s["sistem"]:
        return "Sonuç MB cinsinden bir fark olmalı: `toplam_ram_mb` eksi `sistem_payi_mb`."
    return None


def _sigan_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    s = b.senaryo
    arm = [x for x in s["satirlar"] if x[3] == "arm64"]
    if n == len(s["satirlar"]):
        return "Bütün hedefleri saydın. `mimari: amd64` olanlar bir arm64 Pi'de çalışmaz; ayrıca RAM sınırını da unutma."
    if n == len(arm):
        return "Bütün arm64 hedefleri saydın ama hepsi birden RAM'e sığmıyor. En küçüklerden başla, toplamı kalan RAM'le karşılaştır."
    if n > beklenen:
        return "Toplam kalan RAM'i aşıyorsun. En küçük hedeflerden başlayıp topla; kalanı geçtiğin yerde dur."
    return None


def _plan_oku(metin: str):
    aglar = {k["ag"]: k for k in o.kayitlar(metin, "ag")}
    hostlar = {}
    for k in o.kayitlar(metin, "host"):
        hostlar[k["host"]] = [a.strip() for a in k.get("aglar", "").split(",") if a.strip()]
    return aglar, hostlar


IZOLE = {"internal", "host-only"}


def _duzeltilmis(b: Baglam) -> Sonuc:
    ad = "ag_plani_duzeltilmis.txt"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    s = b.senaryo
    aglar, hostlar = _plan_oku(yol.read_text(encoding="utf-8", errors="replace"))
    if set(aglar) != {s["lab_ag"], s["dis_ag"]}:
        return Sonuc(False, "Dosyadaki `ag:` satırları orijinalle uyuşmuyor. Orijinal planı kopyalayıp sadece hatalı satırı değiştir.")
    beklenen_hostlar = set(s["hostlar"]) | {"kali-pi"}
    if set(hostlar) != beklenen_hostlar:
        return Sonuc(False, "Dosyada eksik ya da fazla `host:` satırı var. Hiçbir hedefi silme; sadece ağını düzelt.")
    for h, ag_listesi in hostlar.items():
        if h == "kali-pi":
            if s["lab_ag"] not in ag_listesi:
                return Sonuc(False, "`kali-pi` lab ağından çıkmış; saldırgan makine hedeflere ulaşabilmeli.")
            continue
        acik = [a for a in ag_listesi if aglar.get(a, {}).get("tur") not in IZOLE]
        if acik:
            return Sonuc(False, f"`{h}` hâlâ yalıtılmamış `{acik[0]}` ağına bağlı. Hedefler yalnızca izole (internal/host-only) ağda olmalı.")
        if not ag_listesi:
            return Sonuc(False, f"`{h}` hiçbir ağa bağlı değil; lab ağına bağlı olmalı.")
        if s["lab_ag"] not in ag_listesi:
            return Sonuc(False, f"`{h}` lab ağına (`{s['lab_ag']}`) bağlı olmalı ki Kali ona ulaşabilsin.")
    return Sonuc(True, f"Plan düzeldi: `{s['hatali']}` artık yalnızca `{s['lab_ag']}` ağında; ev/ofis ağı ile bağı yok.")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Lab iki parçadır", """
İyi bir lab'ın iki parçası vardır: **saldırgan makine** (senin Kali'n) ve **hedefler**. Aralarına
dış dünyadan yalıtılmış bir ağ konur. Yalıtım iki şey için şarttır: zayıf hedefler seni ve
çevreni tehlikeye atmasın, yaptığın saldırılar yalnızca lab içinde kalsın.

Önce bu ortamın donanım envanterine bakalım. Dosyalar kurgusaldır, gerçek bir cihaza
dokunmuyoruz:
""", komut="cat donanim.txt", sonra="""
`toplam_ram_mb` Pi'nin bütün belleği. `sistem_payi_mb` ise Kali'nin, Docker servisinin ve
tarayıcının zaten kullandığı kısım: hedeflere **kalan** bellek kadarı gider.
"""),
    Adim("Ağ türleri: NAT, Köprü, Host-Only, Internal", """
Sanal makine ve Docker dünyasında dört ağ türü karşına çıkar:

- **NAT:** Hedefin internete çıkmasına izin verir, dışarıdan ona girilmez. Hedef internete
  konuşabildiği için lab yalıtımı **zayıftır**.
- **Köprü (Bridged):** Hedef, gerçek ağında (ev Wi-Fi'ı, ofis ağı) sıradan bir cihaz gibi
  görünür. Ağdaki herkes ona ulaşır. Lab için **tehlikeli**.
- **Host-Only:** Hedef yalnızca ana makineyle (senin Kali'nle) konuşur. İnternet yok.
- **Internal:** Sadece aynı iç ağdaki sanal makineler birbirini görür; ana makine bile dışarıda.

Plana bakalım:
""", komut="cat ag_plani.txt", sonra="""
Gördüğün her `host:` satırı bir makineyi, `aglar:` o makinenin bağlı olduğu ağları gösterir.
Bir hedef, **yalıtılmamış** (nat/bridge) bir ağa bağlıysa lab sızdırıyor demektir.
"""),
    Adim("Docker mı, sanal makine mi?", """
**Docker konteyneri** bir uygulamayı bağımlılıklarıyla paketler; saniyede kalkar, çok az RAM
kullanır. Web hedefleri için idealdir (Cilt 5). **Sanal makine (VM)** ise çekirdeğiyle birlikte
tam bir işletim sistemidir; yetki yükseltme gibi işletim sistemi derinliğine inen konular
(Cilt 6) için gerekir, ama her VM için 1-2 GB RAM ayırman gerekir.

Hedef listesine bakıp kaç tane olduğunu sayalım:
""", komut="grep -c '^hedef:' hedefler.txt"),
    Adim("Mimari: arm64 ve amd64", """
Raspberry Pi'nin işlemcisi **ARM** (arm64) mimarisindedir; çoğu bilgisayarın işlemcisi **amd64**
(x86-64) mimarisindedir. Bir imaj yalnızca hazırlandığı mimaride çalışır. `amd64` için yapılmış
bir imaj ya da VM, bir Pi'de **olduğu gibi çalışmaz** (yavaş bir taklit yöntemi vardır ama lab
için pratik değildir).

Kendi makinenin mimarisini şöyle görürsün:
""", komut="uname -m", sonra="""
Bir Pi'de `aarch64` (yani arm64) görürsün. Docker'da bir imajın hangi mimarileri desteklediğini
Bölüm 3'te `docker manifest inspect` ile kontrol etmeyi öğreneceksin.
"""),
    Adim("Kaynak planı: RAM gerçek bir sınırdır", """
Planlamada üç soru sorarsın: **Hedef bu mimaride çalışır mı? Bellek yeter mi? Aynı anda hangileri
gerekli?** Hedef listesindeki bellek ihtiyaçlarını toplayalım:
""", komut="awk -F'ram_mb: ' '/^hedef:/{s+=$2} END{print s}' hedefler.txt", sonra="""
Bu toplam, **kalan** RAM'i aşıyorsa hepsini aynı anda çalıştıramazsın. Çözüm: Cilt'e göre
sadece gereken hedefi kaldır, gerisini `docker compose down` ile durdur. Hatırla: hedefleri
elle seçmek lab'ın bir parçasıdır.
"""),
    Adim("Hacker gözüyle: yalıtım bir etik zorunluluktur", """
Savunmasız bir makineyi internete ya da ortak ağa açık bırakırsan, gerçek saldırganlar onu
otomatik taramalarla bulabilir ve kötüye kullanabilir; bu senin sorumluluğundadır. Lab'ın ağı
önce **kâğıt üstünde** planlanır, sonra kurulur. Elindeki planı yalnızca bir kez daha oku:
""", komut="grep '^ag:' ag_plani.txt"),
]

GOREVLER = [
    Gorev("Kali senin ana makinende (bir VM değil) çalışıyor. Hedef sanal makinelerin **internete "
          "çıkamamasını** ama senin Kali'nin onlara **ulaşabilmesini** istiyorsun. Hangi ağ türünü seçersin?",
          Secmeli([
              ("Host-Only (yalnızca ana makine ile konuşan ağ)",
               "Doğru: hedefler yalnızca ana makineyle, yani Kali'nle konuşur; internet yolu yoktur."),
              ("NAT (hedef, ana makinenin internet bağlantısını paylaşır)",
               "NAT, hedefin internete çıkmasını sağlar; senin istediğinin tam tersi."),
              ("Köprü / Bridged (hedef gerçek ağda sıradan bir cihaz gibi görünür)",
               "Köprüde hedef ev/ofis ağındaki herkese görünür; en tehlikeli seçenek."),
              ("Internal (yalnızca aynı iç ağdaki sanal makineler birbirini görür)",
               "Internal ağda ana makine de dışarıdadır; Kali ana makinede olduğu için hedeflere ulaşamazsın."),
          ], dogru=0),
          ("Dört ağ türünü eğitimdeki tanımlarla karşılaştır; ikisi internete yol verir.",
           "İnternete yol verenleri ele. Kalanlardan hangisinde **ana makine** hedefle konuşabilir?",
           "Ana makine ile hedefin konuştuğu, internetin olmadığı tür Host-Only'dir."),
          puan=25, baslik="Ağ türü seçimi"),
    Gorev("`donanim.txt` dosyasına göre, hedeflere ayrılabilecek **kalan RAM** kaç MB? "
          "(Toplam RAM eksi sistem payı)",
          Sayi("kalan_ram", sik_hatalar=_kalan_hata),
          ("Dosyada iki sayı var; birini diğerinden çıkaracaksın.",
           "`cat donanim.txt` ile `toplam_ram_mb` ve `sistem_payi_mb` değerlerini oku.",
           "`toplam_ram_mb` değerinden `sistem_payi_mb` değerini çıkar. Sonuç MB cinsindendir."),
          puan=25, baslik="Kalan RAM"),
    Gorev("Pi arm64 olduğu için yalnızca `mimari: arm64` hedefler çalışır. `hedefler.txt`'ye göre, "
          "kalan RAM'e sığacak şekilde aynı anda **en fazla kaç hedef** çalıştırabilirsin? "
          "(İpucu: en az RAM isteyenlerden başla.)",
          Sayi("sigan", sik_hatalar=_sigan_hata),
          ("Önce uygun mimarideki hedefleri ayır, sonra RAM'lerini küçükten büyüğe diz.",
           "`grep 'mimari: arm64' hedefler.txt` uygun olanları gösterir. `ram_mb` değerlerini küçükten büyüğe sırala.",
           "Küçükten başlayıp topla; toplam görev 2'deki kalan RAM'i geçmeden önce kaç hedef eklediğini say."),
          puan=40, baslik="Kaç hedef sığar"),
    Gorev("`ag_plani.txt`'ye göre lab'ı **dışarıya sızdıran** hedef hangisi? (Yalıtılmamış bir ağa bağlı "
          "olan hedefin adı)",
          Metin("hatali", sadece_ad=True, bicim="hedef adı"),
          ("Önce hangi ağın izole olmadığına bak: türü `nat` ya da `bridge` olan.",
           "`grep '^ag:' ag_plani.txt` ağları gösterir. Sonra `host:` satırlarında o ağın adını ara.",
           "`kali-pi` hariç, `aglar:` kısmında `nat`/`bridge` ağının adı geçen `host:` satırının adı cevaptır."),
          puan=35, baslik="Sızıntı"),
    Gorev("Sızıntıyı kapat: `ag_plani.txt`'nin bir kopyasını `ag_plani_duzeltilmis.txt` adıyla kaydet ve "
          "hatalı hedefi **yalnızca lab ağına** bağla. Başka hiçbir satırı bozma. Hazır olunca `cevap 5`.",
          Durum(_duzeltilmis, "```\nsed 's/^host: <<hatali>> .*/host: <<hatali>> | aglar: <<lab_ag>>/' ag_plani.txt "
                              "> ag_plani_duzeltilmis.txt\n```"),
          ("Önce dosyayı kopyala, sonra yalnızca bir satırı değiştir.",
           "`cp ag_plani.txt ag_plani_duzeltilmis.txt`, sonra `nano` ya da `sed` ile hatalı `host:` satırının `aglar:` değerini lab ağı yap.",
           "`sed 's/^host: HEDEF .*/host: HEDEF | aglar: LABAG/' ag_plani.txt > ag_plani_duzeltilmis.txt` "
           "(HEDEF ve LABAG'ı kendi değerlerinle değiştir)."),
          puan=40, baslik="Planı düzelt"),
    Gorev("Mert, Pi'sine x86 (amd64) işlemci için hazırlanmış, tam işletim sistemli bir zafiyetli VM "
          "(`.ova` dosyası) kurmak istiyor. Pi'nin işlemcisi arm64. Ne önerirsin?",
          Secmeli([
              ("VM'i Pi'de çalıştırmam; arm64 imajlı Docker hedefi ararım ya da VM'i x86 bir bilgisayarda çalıştırırım",
               "Doğru: mimari uyuşmazsa imaj olduğu gibi çalışmaz; ya uyumlu bir imaj bulunur ya da VM başka bir makinede çalışır."),
              ("VirtualBox'ı Pi'ye kur ve `.ova` dosyasını olduğu gibi içe aktar; sanallaştırma işlemci farkını kendisi çevirir",
               "Sanallaştırma işlemci mimarisini çevirmez; amd64 bir VM'i arm64 işlemcide hızla çalıştıramaz."),
              ("Takas alanını (swap) büyütürüm; mimari uyuşmazlığı aslında bellek eksikliğinden kaynaklanır ve swap bunu çözer",
               "Sorun bellek değil mimari; swap bunu çözmez."),
              ("`.ova` dosyasının sha256 değerini doğrularım; özeti uyuşan bir imaj her işlemci mimarisinde sorunsuz çalışır",
               "Sha256 yalnızca dosyanın bozulmadığını gösterir; mimariyle ilgisi yoktur (Bölüm 4)."),
          ], dogru=0),
          ("Soruda iki mimari var: hedef için olan ve Pi'nin kendisi.",
           "Mimari uyuşmayan bir imaj ya da VM'i tam hızla çalıştırmanın bir yolu var mı? Alternatifi düşün.",
           "İmaj uygun değilse ya uygun imaj bulursun ya da farklı bir makine kullanırsın."),
          puan=30, baslik="Pi ve x86 VM"),
]


def _kapanis():
    return """
Lab planı bir **saldırı yüzeyi** (dışarıdan erişilebilecek her yer) planıdır. Saldırgan tarafında
bu, "hangi makineyi kolayca bulurum?" sorusudur; savunma tarafında "neyi hiç açığa çıkarmam?".
Bu bölümde yaptığın şey, Cilt 7'deki ağ bölümlendirmesinin küçük bir kopyası: hedefler izole
ağda, saldırgan makine iki ağa bağlı tek geçit. Lab'ını kurmadan önce planı yaz, `ag:` ve
`host:` satırlarını kontrol et, bir hedef bile yalıtımın dışında kalmasın. Bir yalıtım hatası
yalnızca senin evini değil, o ağdaki herkesi ilgilendirir.
"""


SEVIYE = Seviye(
    kimlik="c09b01",
    cilt=9,
    bolum=1,
    baslik="Laboratuvar Mimarisi",
    brifing="""
**<<ortam>>** için bir hedef laboratuvarı planlanıyor. Önce kâğıt üstünde plan: Pi'ye hangi
hedefler sığar, ağ nasıl yalıtılır?
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **Unutulan test ortamları:** Pek çok güvenlik olayı raporunda, internete açık bırakılmış
  unutulmuş "test" ya da "staging" sistemleri saldırganların ilk giriş noktası olarak anılır.
  Savunmasız bir lab hedefi ev ya da ofis ağına açık kalırsa aynı riski taşır. Tespit için
  `docker ps` çıktısında `0.0.0.0:` ile başlayan port eşlemelerine ve ağdaki cihaz envanterine
  bakılır; önlem de bu bölümdeki gibi baştan yalıtılmış ağ planıdır.
- **Mirai (2016):** Varsayılan parolalı, internete bağlı IoT cihazlarını otomatik tarayıp ele
  geçiren Mirai botnet'i, zayıf bir cihazın internetten aranıp bulunduğunun en bilinen örneğidir.
  Lab hedeflerinin dışarıdan erişilemez olması bu yüzden kesin bir kuraldır.
- **Mimari uyumu:** Raspberry Pi'nin ARM işlemcisi nedeniyle yalnızca `amd64` olarak yayımlanan
  imajlar ve VM'ler Pi'de çalışmaz. Gerçek işlerde bu, "hangi hedefi nerede çalıştıracağım" kararının
  parçasıdır; lab planı hazırlanırken imajın mimarisi önce kontrol edilir.
""",
    sure_hedef_dk=25,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    kalan = sh("echo $(( $(awk -F': ' '/^toplam_ram_mb/{print $2}' donanim.txt) "
               "- $(awk -F': ' '/^sistem_payi_mb/{print $2}' donanim.txt) ))")
    sigan = sh("kalan=" + kalan + "; grep '^hedef:' hedefler.txt | grep 'mimari: arm64' "
               "| sed 's/.*ram_mb: \\([0-9]*\\).*/\\1/' | sort -n "
               "| awk -v k=$kalan '{t+=$1; if (t<=k) n++} END{print n+0}'")
    dis = sh("grep -E 'tur: (nat|bridge)' ag_plani.txt | awk '{print $2}'")
    lab_ag = sh("grep -E 'tur: (internal|host-only)' ag_plani.txt | awk '{print $2}'")
    hatali = sh(f"grep '^host:' ag_plani.txt | grep -v kali-pi | grep '{dis}' | awk '{{print $2}}'")
    sh(f"sed 's/^host: {hatali} .*/host: {hatali} | aglar: {lab_ag}/' ag_plani.txt > ag_plani_duzeltilmis.txt")
    return {1: SEVIYE.gorevler[0].kontrol.cevabi_goster(Baglam(s, lab, 1))[0], 2: kalan, 3: sigan, 4: hatali,
            5: "", 6: SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]}
