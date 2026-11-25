"""Cilt 6 · Bölüm 1 — Sızmanın Anatomisi.

Beceri: zafiyet / exploit / payload ayrımı, keşiften kalıcılığa aşamalar, servis envanterini
güvenlik bültenleriyle eşleyip yama önceliği çıkarmak.

Savunma odaklı: oyuncu hiçbir şey istismar etmez; "hangi sürüm hangi bültenden etkileniyor,
önce neyi yamalamalıyım?" sorusunu yanıtlar. Bültenler ve ürünler tamamen kurgusaldır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Secmeli, Sonuc, Durum
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import satirlar, sh

# Her vaka: müşteri kodu, (host, ağ, ürün, port) satırları. Ürünler kurgusaldır.
VAKALAR = [
    {
        "kod": "pazarix", "tur": "e-ticaret sitesi",
        "hostlar": [
            ("pzx-web01", "DIS", "Nginova", 443), ("pzx-web02", "DIS", "Sepetix", 8443),
            ("pzx-odeme", "DIS", "OdemeKapi", 443), ("pzx-db01", "IC", "VeriKasa", 5432),
            ("pzx-depo", "IC", "DepoSenk", 8080), ("pzx-mail", "DIS", "PostaCan", 25),
            ("pzx-vpn", "DIS", "TunelVPN", 1194), ("pzx-yedek", "IC", "YedekBekci", 9000),
        ],
        "yabanci": ["FaturaNet", "KampanyaBot"],
        "olay": "Kampanya haftası öncesi yönetim, internete açık hiçbir sistemin yamasız kalmamasını istiyor.",
    },
    {
        "kod": "medora", "tur": "hastane portalı",
        "hostlar": [
            ("medora-portal", "DIS", "PortalMotoru", 443), ("medora-randevu", "DIS", "RandevuMatik", 8443),
            ("medora-pacs", "IC", "GoruntuArsiv", 11112), ("medora-hisdb", "IC", "HastaKayit", 1521),
            ("medora-lab", "IC", "LabAkis", 8080), ("medora-vpn", "DIS", "UzakKapi", 4433),
            ("medora-ftp", "DIS", "DosyaTasi", 21), ("medora-yedek", "IC", "YedekBekci", 9000),
        ],
        "yabanci": ["EczaneBag", "NobetCizelge"],
        "olay": "Bilgi işlem, denetimden önce hangi sistemin hangi bültenden etkilendiğini tek sayfada görmek istiyor.",
    },
    {
        "kod": "yesiltepe", "tur": "e-belediye altyapısı",
        "hostlar": [
            ("ytb-ebelediye", "DIS", "BelediyePortal", 443), ("ytb-ihale", "DIS", "IhaleSis", 8443),
            ("ytb-meclis", "DIS", "MeclisYayin", 1935), ("ytb-borcdb", "IC", "BorcSorgu", 3306),
            ("ytb-dosya", "IC", "DosyaTasi", 21), ("ytb-vpn", "DIS", "UzakKapi", 4433),
            ("ytb-posta", "DIS", "PostaCan", 25), ("ytb-yedek", "IC", "YedekBekci", 9000),
        ],
        "yabanci": ["ImarGuncel", "ZabitaMobil"],
        "olay": "Müdürlük, çok sayıda eski sistemin hangisinden başlanması gerektiğini bilmek istiyor.",
    },
]


def _surum(rng):
    return rng.randint(1, 4), rng.randint(0, 9), rng.randint(5, 9)


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    hostlar = list(v["hostlar"])
    dis = [h for h in hostlar if h[1] == "DIS"]
    ic = [h for h in hostlar if h[1] == "IC"]
    a = rng.choice(dis)
    c = rng.choice([h for h in dis if h != a])
    b = rng.choice(ic)
    d = rng.choice([h for h in hostlar if h not in (a, b, c)])

    envanter = []       # (host, ag, port, urun, surum)
    bulten = []         # (id, urun, etkilenen_liste, duzeltilen, ciddiyet, istismar)
    kimlik_sayac = rng.randint(100, 400)
    etkilenen_hostlar = []
    for h in hostlar:
        ma, mi, pa = _surum(rng)
        surum = f"{ma}.{mi}.{pa}"
        envanter.append((h[0], h[1], h[3], h[2], surum))
        if h in (a, b, c):
            kimlik_sayac += rng.randint(3, 40)
            etk = [f"{ma}.{mi}.{pa - 1}", surum, f"{ma}.{mi}.{pa + 1}"]
            duz = f"{ma}.{mi}.{pa + 2}"
            if h == a:
                ciddiyet, ist = "KRITIK", "EVET"
            elif h == b:
                ciddiyet, ist = "KRITIK", "HAYIR"
            else:
                ciddiyet, ist = "YUKSEK", "HAYIR"
            bulten.append([f"KRG-CVE-2026-{kimlik_sayac:04d}", h[2], etk, duz, ciddiyet, ist, h[0], surum])
            etkilenen_hostlar.append(h[0])
        elif h == d:
            kimlik_sayac += rng.randint(3, 40)
            # Bu hostun sürümü düzeltilmiş sürümden yeni: bültende ürün var ama host etkilenmiyor
            etk = [f"{ma}.{mi}.{pa - 4}", f"{ma}.{mi}.{pa - 3}", f"{ma}.{mi}.{pa - 2}"]
            bulten.append([f"KRG-CVE-2026-{kimlik_sayac:04d}", h[2], etk, f"{ma}.{mi}.{pa - 1}",
                           rng.choice(["KRITIK", "YUKSEK"]), "EVET", h[0], surum])
    for yabanci in v["yabanci"]:
        kimlik_sayac += rng.randint(3, 40)
        ma, mi, pa = _surum(rng)
        bulten.append([f"KRG-CVE-2026-{kimlik_sayac:04d}", yabanci,
                       [f"{ma}.{mi}.{pa - 1}", f"{ma}.{mi}.{pa}"], f"{ma}.{mi}.{pa + 1}",
                       rng.choice(["ORTA", "YUKSEK"]), rng.choice(["EVET", "HAYIR"]), "-", "-"])
    rng.shuffle(bulten)
    rng.shuffle(envanter)
    bulten_a = next(x for x in bulten if x[6] == a[0])
    bulten_d = next(x for x in bulten if x[6] == d[0])
    return {
        "vaka": f"{m['ad']} — {v['tur']}",
        "musteri": m,
        "envanter": envanter,
        "bulten": [x[:6] for x in bulten],
        "a": a[0], "d": d[0], "yamali": d[0],
        "brifing": f"""
**{m['ad']}** ({v['tur']}) için bir yama önceliklendirme toplantısı var. Selin masana bir
envanter ve bir bülten listesi bırakıyor: "{v['olay']} Elimizde sunucuların yazılım sürümleri
ve bu yazılımları etkileyen **kurgusal** güvenlik bültenleri var. Hangi sunucu hangi
bültenden etkileniyor? Hangisini önce yamalamalıyız?"

Deniz ekliyor: "Sızma testinin ilk iki aşaması, saldırganın da yaptığı iş: ne var, hangi
sürümde. Biz aynı bilgiyi **önce biz** çıkaracağız. Her bülteni her sunucuya uygulamaya çalışma;
sadece sürümü etkilenenler listesinde olanlar gerçekten risklidir."
""",
        "metin": {"musteri": m["ad"], "sunucu": a[0], "ornek_urun": bulten_d[1], "tur": v["tur"]},
        "cevaplar": {
            "etkilenen": etkilenen_hostlar,
            "oncelik": a[0],
            "duzeltilen": bulten_a[3],
            "surum_a": bulten_a[3],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} sistem envanteri ve güvenlik bülteni listesi.\n"
          "ÖNEMLİ: Bültenlerdeki CVE kimlikleri ve ürünler KURGUSALDIR; eğitim için uydurulmuştur.\n"
          "Bu lab'da hiçbir sistem istismar edilmez; sadece envanter ve bülten karşılaştırılır.\n")
    satir = ["# host|ağ(DIS=internetten erişilebilir, IC=iç ağ)|port|ürün|sürüm"]
    satir += [f"{h}|{ag}|{port}|{urun}|{surum}" for h, ag, port, urun, surum in s["envanter"]]
    u.yaz(lab / "envanter" / "servisler.txt", "\n".join(satir) + "\n")
    satir = ["# KURGUSAL güvenlik bülteni listesi (gerçek CVE değildir)",
             "# id|ürün|etkilenen sürümler (; ile ayrılmış)|düzeltilmiş sürüm|ciddiyet|istismar kodu yaygın mı"]
    satir += [f"{i}|{urun}|{';'.join(etk)}|{duz}|{cid}|{ist}" for i, urun, etk, duz, cid, ist in s["bulten"]]
    u.yaz(lab / "bulten" / "bulten.txt", "\n".join(satir) + "\n")
    u.yaz(lab / "bulten" / "ciddiyet_aciklama.txt",
          "KRITIK: uzaktan, kimlik doğrulamasız ele geçirmeye izin verebilir.\n"
          "YUKSEK: ciddi etki, ama koşullar ya da yetki gerektirir.\n"
          "ORTA: sınırlı etki.\n"
          "İstismar kodu yaygın = EVET ise saldırganlar için hazır araç var; süre hızla daralır.\n")


def _eslesme_awk() -> str:
    return ("awk -F'|' '/^#/{next} FNR==NR{n=split($3,v,\";\");for(i=1;i<=n;i++)k[$2\"@\"v[i]]=$1\"|\"$5\"|\"$6;next} "
            "(($4\"@\"$5) in k){print $1\"|\"$2\"|\"k[$4\"@\"$5]}' bulten/bulten.txt envanter/servisler.txt")


def coz(lab: Path, s: dict) -> dict:
    eslesen = sh(_eslesme_awk(), lab)
    hostlar = sh(f"{_eslesme_awk()} | cut -d'|' -f1", lab).replace("\n", " ")
    oncelik = sh(f"{_eslesme_awk()} | awk -F'|' '$2==\"DIS\" && $4==\"KRITIK\" && $5==\"EVET\" {{print $1}}'", lab)
    urun = sh(f"grep '^{s['a']}|' envanter/servisler.txt | cut -d'|' -f4", lab)
    duz = sh(f"grep -F '|{urun}|' bulten/bulten.txt | cut -d'|' -f4", lab)
    # Envanteri düzelt: sürümü düzeltilmiş sürüme çek
    sh(f"awk -F'|' -v OFS='|' '$1==\"{s['a']}\"{{$5=\"{duz}\"}}1' envanter/servisler.txt > envanter/.gecici "
       "&& mv envanter/.gecici envanter/servisler.txt", lab)
    from hy.motor.kontrol import Baglam
    sec = {}
    for no in (1, 5, 6):
        sec[no] = SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    assert eslesen
    return {1: sec[1], 2: hostlar, 3: oncelik, 4: duz, 5: sec[5], 6: sec[6], 7: ""}


def _hostlar_hata(girdi, beklenen, b):
    verilen = set(girdi.split())
    if b.senaryo["yamali"].casefold() in verilen:
        return ("Bir sunucunun ürünü bültende geçiyor diye etkilenmiş olmaz. Sürümünün 'etkilenen sürümler' "
                "listesinde olması gerekir; bir tanesi bu yüzden eleniyor, çünkü zaten yamalı.")
    return None


def _oncelik_hata(girdi, beklenen, b):
    if girdi in {x.casefold() for x in b.senaryo["cevaplar"]["etkilenen"]}:
        return ("Bu sunucu etkileniyor ama öncelik sırasında ilk değil. Üç şeye birlikte bak: ciddiyet KRITIK mi, "
                "sunucu internetten (DIS) erişilebilir mi, istismar kodu yaygın mı (EVET)?")
    return None


def _surum_duzeldi(b) -> Sonuc:
    satirlar_ = satirlar(b.lab / "envanter" / "servisler.txt")
    host = b.senaryo["a"]
    for x in satirlar_:
        p = x.split("|")
        if p[0] == host:
            if p[4] == b.senaryo["cevaplar"]["duzeltilen"]:
                return Sonuc(True, "Envanter güncellendi. Gerçek hayatta bunu yamayı uyguladıktan sonra "
                                   "tarayıcıyla doğrularsın; kayıt yalnızca yamanın kanıtıdır.")
            return Sonuc(False, f"{host} satırında sürüm {p[4]}. Bültendeki **düzeltilmiş** sürümü yazmalısın.",
                         yakin=True)
    return Sonuc(False, f"`envanter/servisler.txt` içinde {host} satırı bulunamadı. Satırı silmek çözüm değil.")


ADIMLAR = [
    Adim("Üç kavram: zafiyet, exploit, payload", """
Bu ciltte saldırganın nasıl içeri girdiğini **izlerinden ve yanlış yapılandırmalardan** okumayı
öğreneceksin. Önce üç kelimeyi ayır, çünkü karıştıran biri neyi savunduğunu bilmez:

- **Zafiyet (vulnerability):** sistemdeki zayıflık. Kilitlenmemiş pencere.
- **Exploit (istismar):** o zayıflığı kullanma yöntemi. Pencereden girme biçimi.
- **Payload (yük):** içeri girildikten sonra yapılan iş. İçeride ne yapıldığı.

Bu oyunda exploit ya da payload yazmayacaksın. Pencerenin açık olduğunu **önce sen** bulacaksın.
Laboratuvarını tanı:
""", komut="cat OKUBENI.txt", sonra="""
Dosyadaki **kurgusal** uyarısı önemli: bültenlerdeki CVE (bilinen zafiyet kimliği) numaraları ve ürün
adları bu lab için uydurulmuştur. Gerçek bir CVE'yi bu lab'da aramana gerek yok.
"""),
    Adim("Aşamalar: keşiften kalıcılığa", """
Bir sızma genelde şu sırayla ilerler. Her aşamada savunmacının görebileceği bir iz vardır:

1. **Keşif:** hangi sunucu, hangi port, hangi sürüm. İz: kısa sürede çok porta gelen istekler.
2. **Zafiyet eşleme:** sürüm bilinen bir bültende mi? İz: genelde yok, bu aşama saldırganın masasında geçer.
3. **İlk erişim:** zafiyetle içeri girmek. İz: servis loglarında alışılmadık istekler.
4. **Yerel keşif:** içeri girince "kimim, neler var?". İz: alışılmadık komutlar.
5. **Yetki yükseltme:** düşük yetkiden tam yetkiye geçmek. İz: sudo/su kayıtları, yeni SUID.
6. **Kalıcılık:** kapıyı arkadan açık bırakmak (yeni hesap, zamanlanmış görev, SSH anahtarı).

**Hacker gözüyle:** Zincirin 2. halkası, savunmacının **kırabileceği** halkadır. Bilinen zafiyet
kapanmışsa saldırgan ilerleyemez. Şimdi envantere bak:
""", komut="cat envanter/servisler.txt", sonra="""
`DIS` = internetten erişilebilen, `IC` = yalnızca iç ağ. Saldırganın ilk görebileceği yer `DIS`
olanlardır; bu yüzden onlar önceliğe girer.
"""),
    Adim("Güvenlik bülteni nedir?", """
Bir yazılımda zafiyet bulunursa üretici ya da bir kuruluş **bülten** yayımlar: hangi sürümler
etkileniyor, hangi sürümde düzeltildi, ne kadar ciddi. Her ciddi zafiyete bir **CVE kimliği**
(örneğin `CVE-2021-44228`) verilir; böylece herkes aynı hatadan söz ettiğini bilir.

Aşağıdaki liste **kurgusaldır**, kimlikleri `KRG-CVE-...` diye başlar:
""", komut="cat bulten/bulten.txt", sonra="""
Sütunlar: `id | ürün | etkilenen sürümler | düzeltilmiş sürüm | ciddiyet | istismar kodu yaygın mı`.
Etkilenen sürümler noktalı virgülle ayrılmış tam sürüm listesidir.
"""),
    Adim("Eşleme: ürün adı yetmez, sürüm de tutmalı", """
Envanterdeki bir ürünün adı bültende geçiyor diye sistem etkilenmiş sayılmaz. **Sürüm,
etkilenenler listesinde mi?** Örnek ürünü iki dosyada birden ara:
""", komut="grep -F <<ornek_urun>> envanter/servisler.txt bulten/bulten.txt", sonra="""
Ürünün sunucudaki sürümünü bültendeki **etkilenen sürümler** ve **düzeltilmiş sürüm** ile karşılaştır.
Sürüm düzeltilmiş sürümden yeniyse sistem **zaten yamalıdır**; bu bültenden etkilenmez.
"""),
    Adim("Yama önceliği: dört soru", """
Yüzlerce bülten aynı anda gelir; hepsini birden yamalayamazsın. Önceliği dört soru belirler:

1. Ciddiyet ne? (**KRITIK** önce)
2. Sistem internetten (**DIS**) erişilebilir mi?
3. İstismar kodu yaygın mı? (**EVET** ise saldırgan hazır araca sahip)
4. Sistemde ne tutuluyor? (ödeme, hasta verisi, vatandaş verisi)

Kritik bültenlerin listesi:
""", komut="awk -F'|' '$5==\"KRITIK\"' bulten/bulten.txt", sonra="""
Bu liste **ürün bazlı**. Hangi **sunucuların** gerçekten etkilendiğini bulmak için envanterle
birleştirmek gerekir; görevlerde bunu yapacaksın.
"""),
    Adim("Dışarıdan görünen yüzey", """
Saldırganın ilk erişim için önce baktığı yer internetten erişilebilen sistemlerdir. Kaç tane
`DIS` sunucu var?
""", komut="grep -c '|DIS|' envanter/servisler.txt", sonra="""
Bu sayı, **saldırı yüzeyinin** (saldırganın deneyebileceği kapı sayısı) kabaca ölçüsüdür. Yüzeyi
küçültmek (gereksiz servisi kapatmak) yama kadar değerlidir.
"""),
]

GOREVLER = [
    Gorev("Bir sistemde kilitlenmemiş bir pencere olduğunu düşün. **Zafiyet, exploit ve payload** "
          "kavramlarından hangisi \"pencerenin kendisi\" yani sistemdeki zayıflıktır?",
          Secmeli([
              ("Zafiyet; sistemdeki yazılım ya da ayar zayıflığı",
               "Doğru. Zafiyet pencerenin açık olmasıdır; exploit ve payload onun üstüne kurulan şeylerdir."),
              ("Exploit; sistemi yavaşlatan ya da bozan her tür hata",
               "Exploit bir hata değil, bir hatadan yararlanma yöntemidir. Hata zafiyettir."),
              ("Payload; sistem içindeki en savunmasız servis",
               "Payload servis değil, içeri girildikten sonra çalışan iştir."),
              ("Bülten; zayıflığı kullanan küçük bir program",
               "Bülten duyurudur, program değil. Zayıflığı kullanan şeye exploit denir."),
          ]),
          ("Üç kelimenin benzetmesini hatırla: pencere, pencereden girme biçimi, içeride yapılan iş.",
           "Pencerenin kendisi sistemde bulunan bir şey; onu kullanan yöntem ve sonrası ayrı kavramlar.",
           "Açık pencere = hata/zayıflık."),
          puan=15, baslik="Üç kavram"),
    Gorev("`envanter/servisler.txt` ve `bulten/bulten.txt` dosyalarını eşle: sürümü bir bültenin "
          "**etkilenen sürümler** listesinde olan sunucuların adlarını yaz (virgülle ayırarak).",
          Kume("etkilenen", sik_hatalar=_hostlar_hata, bicim="sunucu adları, virgülle ayrılmış"),
          ("Her bülten satırında etkilenen sürümler ayrı alanda; envanterde her sunucunun bir sürümü var.",
           "Ürün adı ve sürüm **birlikte** tutmalı. Elle bakabilirsin ya da `grep -F ürünadı` ile iki dosyada ara.",
           "Üç sunucu etkileniyor. Her ürün için bülten satırındaki sürüm listesini, sunucudaki sürümle karşılaştır."),
          puan=35, baslik="Etkilenen sunucular"),
    Gorev("Etkilenen sunuculardan hangisi **ilk** yamalanmalı? (KRITIK, internetten erişilebilir "
          "ve istismar kodu yaygın olan)",
          Metin("oncelik", sik_hatalar=_oncelik_hata, bicim="sunucu adı"),
          ("Etkilenen üç sunucunun ağ (DIS/IC), ciddiyet ve istismar bilgilerini yan yana koy.",
           "Üç koşulu birden sağlayan tek sunucu var: KRITIK + DIS + istismar EVET.",
           "Etkilenen sunucuların bülten satırlarında `KRITIK`, `EVET` yazanını bul; envanterde ağı `DIS` mi bak."),
          puan=30, baslik="Yama önceliği"),
    Gorev("İlk yamalanacak sunucunun ürünü için bültenin **düzeltilmiş sürümü** hangisi?",
          Metin("duzeltilen", bicim="sürüm numarası, örn. 2.4.7"),
          ("Önce o sunucunun ürününün adını envanterden öğren.",
           "Ürün adıyla bülten dosyasında ara; dördüncü alan düzeltilmiş sürümdür.",
           "`grep '^<sunucu>|' envanter/servisler.txt` ürünü verir; sonra ürünü `bulten/bulten.txt` içinde `grep -F` ile ara."),
          puan=25, baslik="Düzeltilmiş sürüm"),
    Gorev("Zincir \"açık port → sürüm → bilinen zafiyet → exploit → erişim\" biçiminde ilerliyor. "
          "Savunmacı için bu zinciri **en ucuz ve en kalıcı** biçimde kırabileceği halka hangisidir?",
          Secmeli([
              ("Bilinen zafiyet halkası: yamayı uygulayarak sürümü düzeltmek",
               "Doğru. Güncel sürümde bilinen exploit çalışmaz; zincir bu halkada kopar."),
              ("Açık port halkası: bütün portları kapatmak, hizmetleri durdurmak",
               "İşe yarar ama iş durur. Hizmet vermek için bazı portlar açık kalmalı; asıl kalıcı çözüm yama."),
              ("Exploit halkası: saldırganın kullandığı araçların listesini engellemek",
               "Araç listesi sürekli değişir; araç engellemek sürüm açığını kapatmaz."),
              ("Erişim halkası: yöneticilerin parolasını sık sık değiştirmek",
               "Parola yenilemek zayıf bir sürümün açığını kapatmaz. Zafiyet yamayla kapanır."),
          ]),
          ("Zincirin hangi halkası \"zaten çözümü bilinen\" bir hatadır?",
           "Bilinen zafiyetlerin çözümü üreticinin yayımladığı düzeltmedir.",
           "Cilt 6 girişindeki ilke: ihlallerin çoğunu önleyen şey yama yönetimidir."),
          puan=20, baslik="Zinciri kır"),
    Gorev("Bir sızmanın aşamaları aşağıdakilerden hangisinde **doğru sırayla** verilmiştir?",
          Secmeli([
              ("keşif, zafiyet eşleme, ilk erişim, yetki yükseltme, kalıcılık",
               "Doğru. Önce ne var öğrenilir, sonra içeri girilir, yetki artırılır, en sonda kalıcılık bırakılır."),
              ("keşif, kalıcılık, ilk erişim, zafiyet eşleme, yetki yükseltme",
               "Kalıcılık, içeri girip yetki aldıktan sonra gelir; erişim yokken kalıcılık bırakılamaz."),
              ("ilk erişim, keşif, yetki yükseltme, zafiyet eşleme, kalıcılık",
               "Zafiyeti bilmeden ilk erişim denenmez; eşleme erişimden önce gelir."),
              ("zafiyet eşleme, yetki yükseltme, keşif, ilk erişim, kalıcılık",
               "Önce neyin var olduğunu bulmak (keşif) gerekir; yetki yükseltme erişimden sonradır."),
          ]),
          ("Aşamalar mantıksal bir sırayı izler: önce bilgi, sonra erişim, sonra yetki, en son izini bırakmak.",
           "Önce keşif gelir; kalıcılık en sona kalır.",
           "keşif → eşleme → erişim → yükseltme → kalıcılık."),
          puan=15, baslik="Aşama sırası"),
    Gorev("İlk yamalanacak sunucunun envanter kaydını güncelle: `envanter/servisler.txt` içinde o "
          "sunucunun sürümünü bültendeki düzeltilmiş sürüme çek (yamayı uyguladığını varsay). "
          "Bitince `cevap 7` yaz.",
          Durum(_surum_duzeldi, "envanter satırındaki sürüm alanını bültendeki düzeltilmiş sürümle değiştir"),
          ("Dosya `|` ile ayrılmış alanlardan oluşuyor; sürüm son alan.",
           "Bir metin düzenleyici ya da `sed -i` ile yalnızca o sunucunun satırındaki sürümü değiştir.",
           "Örnek: `sed -i '/^<sunucu>|/s/|<eski>$/|<yeni>/' envanter/servisler.txt`."),
          puan=25, baslik="Envanteri güncelle"),
]


def _kapanis():
    return """
Saldırganın gözüyle: sızmanın büyük kısmı yeni bir açık bulmak değil, **bilinen açığı yamalanmamış
bir sistemde bulmaktır**. Keşif, sürüm, bülten eşlemesi: bunları o sana yapmadan önce sen yaptın.
Savunmanın gözüyle: envanterin güncel olmadan yama yönetimi yapılmaz; "elimizde ne var?" sorusu
her yama sürecinin ilk adımıdır. Önceliği ciddiyet, internetten erişilebilirlik ve istismar
kodunun yaygınlığı belirler. Bu cildin uygulamalı saldırı pratiğini **kendi laboratuvarında** yap:
Cilt 9'da Kali'nde kuracağın savunmasız hedefler ve bu oyunun yerel vakaları. Yalnızca sahibi
olduğun, izole ortamlarda çalış.
"""


SEVIYE = Seviye(
    kimlik="c06b01",
    cilt=6,
    bolum=1,
    baslik="Sızmanın Anatomisi",
    brifing="""
**<<musteri>>** için sunucu envanteri ve **kurgusal** bülten listesi hazır. Selin: "Hangi sunucu
hangi bültenden etkileniyor, hangisini önce yamalayalım?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Equifax 2017:** Kamuya açık raporlara göre ihlalde, bir web uygulama çerçevesindeki (Apache
  Struts) **bilinen ve yaması yayımlanmış** bir zafiyet kullanıldı. Düzeltme mevcuttu ama ilgili
  sistem zamanında yamalanmamıştı. Bu bölümdeki envanter-bülten eşlemesi tam olarak bu boşluğu görünür kılar.
- **Tespit ve önleme:** Güncel bir **varlık envanteri**, düzenli zafiyet taraması ve yama için süre
  hedefleri (örneğin kritik olanlar için günler) ilk savunmadır. Önceliklendirmede ciddiyet puanına
  (CVSS) ek olarak "gerçekte istismar ediliyor mu?" bilgisi de kullanılır; CISA'nın yayımladığı
  "Bilinen İstismar Edilen Zafiyetler" (KEV) kataloğu bunun bir kaynağıdır.
- **Sızma testlerinde:** Raporlarda en sık görülen bulgulardan biri, yaması bulunan ama
  uygulanmamış eski sürümlerdir.
""",
    sure_hedef_dk=20,
)
