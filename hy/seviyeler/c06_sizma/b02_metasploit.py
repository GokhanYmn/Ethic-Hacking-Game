"""Cilt 6 · Bölüm 2 — Metasploit Framework (kavramsal, tespit odaklı).

Beceri: bir sızma test çerçevesinin bileşenlerini (exploit, payload, auxiliary, post) ayırt etmek;
çerçevenin neden gürültülü olduğunu, savunmanın onu hangi izlerden gördüğünü okumak.

Hiçbir modül, komut ya da yük yazılmaz. Modül adları ve imzalar kurgusaldır. Oyuncu, kurgusal IDS ve
uç nokta (EDR) loglarından tarama izini ve imza eşleşmesini bulur.
"""
from __future__ import annotations

import random
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

PORTLAR = [21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 5900, 8080]

VAKALAR = [
    {"kod": "medora", "servis": "FTP", "port": 21, "hostlar": ["medora-ftp", "medora-portal", "medora-pacs", "medora-lab"],
     "ag": "10.20.0", "sinyal": "Dosya aktarım servisine art arda sürüm/oturum sorgusu",
     "olay": "Hastanenin dosya aktarım sunucusuna gece yarısından sonra anormal trafik geldi."},
    {"kod": "paramix", "servis": "API", "port": 8443, "hostlar": ["pmx-api01", "pmx-api02", "pmx-panel", "pmx-db01"],
     "ag": "172.16.4", "sinyal": "API ağ geçidine hızlı servis keşfi ve sürüm sorgusu",
     "olay": "Üye işyeri ödeme API'sinde, trafiği olmayan bir saatte tuhaf bir istek dalgası görüldü."},
    {"kod": "kuzgun", "servis": "SMB", "port": 445, "hostlar": ["kzg-depo", "kzg-muhasebe", "kzg-filo", "kzg-yedek"],
     "ag": "192.168.10", "sinyal": "Dosya paylaşım servisine sürüm sorgusu ve kimlik denemeleri",
     "olay": "Depo dosya sunucusunda gece vardiyasında kimsenin açıklayamadığı bir erişim dalgası var."},
]

MODUL_HAVUZ = {
    "exploit": (["servis_arka_kapi_a", "web_yukleme_hatasi_b", "dosya_paylasim_tasma_c", "vpn_kimlik_hatasi_d", "rpc_tasma_e"],
                "Bilinen bir zafiyeti kullanan modül", "ORTA"),
    "payload": (["oturum_yuku_a", "komut_yuku_b", "dinleyici_yuku_c"],
                "İstismar sonrası çalışacak iş (kurgusal tanım)", "ORTA"),
    "auxiliary": (["servis_surum_tarayici", "port_tarayici", "kimlik_deneme", "dizin_listeleyici", "banner_okuyucu"],
                  "Yük çalıştırmadan bilgi toplayan ya da deneyen yardımcı modül", "YUKSEK"),
    "post": (["bilgi_toplayici", "hesap_listeleyici", "ag_haritalayici", "dosya_arayici", "kayit_okuyucu"],
             "İçeri girildikten sonra çalışan modül", "DUSUK"),
}


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    saldirgan = u.dis_ip(rng)
    gurultu_ip = u.dis_ip(rng)
    while gurultu_ip == saldirgan:
        gurultu_ip = u.dis_ip(rng)
    tarayici = u.ic_ip(rng, v["ag"])
    hedef = u.ic_ip(rng, v["ag"])
    post_adet = rng.randint(2, 5)
    adetler = {"exploit": rng.randint(3, 5), "payload": rng.randint(2, 3),
               "auxiliary": rng.randint(3, 5), "post": post_adet}
    moduller = []
    for tur, adet in adetler.items():
        for ad in rng.sample(MODUL_HAVUZ[tur][0], adet):
            moduller.append((tur, f"{tur}/kurgusal/{ad}"))
    rng.shuffle(moduller)
    ports = sorted(set([v["port"]] + rng.sample(PORTLAR, rng.randint(6, 9))))
    olay_host = rng.choice(v["hostlar"])
    davranis_host = rng.choice([h for h in v["hostlar"] if h != olay_host])
    gun = u.gun(rng)
    return {
        "vaka": f"{m['ad']} — {v['servis']} sunucusuna gece trafiği",
        "musteri": m, "v": v, "saldirgan": saldirgan, "gurultu_ip": gurultu_ip, "tarayici": tarayici,
        "hedef": hedef, "moduller": moduller, "ports": ports, "olay_host": olay_host,
        "davranis_host": davranis_host, "gun": gun,
        "brifing": f"""
Deniz Kara SOC ekranından döndü: "**{m['ad']}**'in {v['servis']} servisinde bir şey var. {v['olay']} Kendi
sızma test araçlarımızı bilen biri gibi davranan bir kaynak görüyorum. Sen Metasploit gibi
çerçeveleri iyi tanıyorsan, **izlerinden** onu bulabilirsin."

Selin ekliyor: "Bu bölümde bir saldırı çerçevesini **kullanmıyoruz**, sadece tanıyoruz. Önce çerçevenin
parçalarını ayır, sonra IDS ve uç nokta loglarında bıraktığı gürültüyü oku. Modül ve imza adları
kurgusaldır."
""",
        "metin": {"musteri": m["ad"], "servis": v["servis"], "host": v["hostlar"][0]},
        "cevaplar": {
            "post_adet": post_adet,
            "saldirgan": saldirgan,
            "port_sayisi": len(ports),
            "olay_host": olay_host,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} gece trafiği incelemesi. Modül ve imza adları KURGUSALDIR.\n"
          "Bu lab'da hiçbir araç çalıştırılmaz; yalnızca liste ve log okunur.\n")
    satir = ["# tür|modül adı (kurgusal)|ne yapar|gürültü seviyesi"]
    for tur, ad in s["moduller"]:
        satir.append(f"{tur}|{ad}|{MODUL_HAVUZ[tur][1]}|{MODUL_HAVUZ[tur][2]}")
    u.yaz(lab / "kurgusal_modul_listesi.txt", "\n".join(satir) + "\n")

    # IDS uyarıları: saldırgan çok port, tarayıcı (iç) en çok uyarı, gürültü IP az
    rng_log = random.Random(f"{s['saldirgan']}:{s['hedef']}")
    olaylar = []
    t0 = s["gun"].replace(hour=2, minute=3)
    zam = u.zamanlar(rng_log, t0, 120, 5, 60)
    adaylar = []
    for port in s["ports"]:
        adaylar.append((s["saldirgan"], port, f"KRG-1001 \"{v['sinyal']}\""))
    for _ in range(rng_log.randint(10, 16)):
        adaylar.append((s["saldirgan"], rng_log.choice(s["ports"]), "KRG-1001 \"" + v["sinyal"] + "\""))
    for _ in range(len(adaylar) + rng_log.randint(8, 14)):
        adaylar.append((s["tarayici"], rng_log.choice(PORTLAR), "KRG-0900 \"Kurumsal zafiyet tarayıcısı (planlı)\""))
    for _ in range(rng_log.randint(3, 5)):
        adaylar.append((s["gurultu_ip"], rng_log.choice([80, 443]), "KRG-0500 \"Web istemcisi anormal kullanıcı bilgisi\""))
    rng_log.shuffle(adaylar)
    for (kaynak, port, aciklama), t in zip(adaylar, zam):
        sig, _, metin = aciklama.partition(" ")
        olaylar.append(f"{t:%Y-%m-%d %H:%M:%S} UYARI {sig} {kaynak}:{rng_log.randint(30000, 60000)} -> "
                       f"{s['hedef']}:{port} {metin}")
    u.yaz(lab / "kayitlar" / "ids_uyarilari.log", "\n".join(olaylar) + "\n")

    hostlar = v["hostlar"]
    edr = [f"{s['gun']:%Y-%m-%d} 01:5{i} host={h} olay=TEMIZ_TARAMA ozet=sorun_yok" for i, h in enumerate(hostlar)]
    edr.append(f"{s['gun']:%Y-%m-%d} 02:41:09 host={s['davranis_host']} olay=DAVRANIS_UYARISI guven=DUSUK "
               "ozet=alisilmadik_surec_zinciri")
    edr.append(f"{s['gun']:%Y-%m-%d} 02:47:33 host={s['olay_host']} olay=IMZA_ESLESMESI "
               "imza=\"Backdoor.KRG.OturumBenzeri\" islem=KARANTINA")
    edr.append(f"{s['gun']:%Y-%m-%d} 03:05:12 host={hostlar[0]} olay=TEMIZ_TARAMA ozet=sorun_yok")
    u.yaz(lab / "kayitlar" / "uc_nokta.log", "\n".join(edr) + "\n")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    post = sh("grep -c '^post|' kurgusal_modul_listesi.txt", lab)
    dis = sh("cut -d' ' -f5 kayitlar/ids_uyarilari.log | cut -d: -f1 | grep '^\\(192\\.0\\.2\\|198\\.51\\.100\\|203\\.0\\.113\\)\\.' "
             "| sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    port = sh(f"grep -F '{dis}:' kayitlar/ids_uyarilari.log | cut -d' ' -f7 | cut -d: -f2 | sort -u | wc -l", lab)
    host = sh("grep IMZA_ESLESMESI kayitlar/uc_nokta.log | grep -o 'host=[^ ]*' | cut -d= -f2", lab)
    sec = {n: SEVIYE.gorevler[n - 1].kontrol.cevabi_goster(Baglam(s, lab, n))[0] for n in (1, 6, 7, 8)}
    return {1: sec[1], 2: post, 3: dis, 4: port, 5: host, 6: sec[6], 7: sec[7], 8: sec[8]}


def _ip_hata(girdi, beklenen, b):
    if girdi == b.senaryo["tarayici"]:
        return ("Bu iç ağdaki planlı zafiyet tarayıcısı: uyarı sayısı yüksek ama kaynağı bilinen bir araç. "
                "Soru **dış** (internetten gelen) kaynağı soruyor.")
    if girdi == b.senaryo["gurultu_ip"]:
        return "Bu IP dışarıdan geliyor ama uyarı sayısı çok az. En çok uyarı üretene bak."
    return None


def _port_hata(girdi, beklenen, b):
    try:
        n = int(girdi)
    except ValueError:
        return None
    if n > beklenen:
        return ("Uyarı sayısını saymışsın. Soru **farklı** hedef port sayısını soruyor: aynı portu tekrar sayma "
                "(`sort -u`).")
    return None


ADIMLAR = [
    Adim("Çerçeve ne demek?", """
**Metasploit**, sızma testlerinde kullanılan, açık kaynaklı bir **çerçevedir**: birçok exploit
(zafiyeti kullanan parça), payload (yük) ve yardımcı modülü tek yerde toplar. Bu oyunda onu
**kullanmayacaksın**. Bir savunmacı için önemli olan, saldırganın bunu kullandığında **ne tür iz
bıraktığını** bilmek.

Önce çerçevenin parçalarına bak. Lab'daki liste kurgusaldır:
""", komut="cat kurgusal_modul_listesi.txt", sonra="""
Listede dört tür var: `exploit`, `payload`, `auxiliary` ve `post`. Şimdi her birinin ne işe yaradığına bakalım.
"""),
    Adim("Dört bileşen", """
- **exploit:** bir zafiyeti kullanan modül. Zafiyet "pencere", exploit "pencereden girme yöntemi".
- **payload:** exploit başarılı olunca çalışan iş. Kurgusal benzetmeyle, "içeri girince yapılan şey".
- **auxiliary:** yardımcı modül. **Yük çalıştırmaz**; tarar, dener, bilgi toplar.
- **post:** içeri girildikten **sonra** çalışan modül (keşif, bilgi toplama).

Bir de **oturum (session)** kavramı var: exploit ve payload başarılı olursa saldırgan ile hedef arasında
açılan canlı bağlantıya oturum denir.

Türlere göre kaç modül var?
""", komut="cut -d'|' -f1 kurgusal_modul_listesi.txt | grep -v '^#' | sort | uniq -c", sonra="""
`cut` alanı kesti, `sort | uniq -c` sayım yaptı. Bu desen log analizinin temel taşıdır.
"""),
    Adim("Çerçevenin mantığı (kavramsal)", """
Çerçevenin mantığı her zaman aynıdır: **bir modül seçilir, modülün seçenekleri doldurulur, çalıştırılır.**
Seçeneklerden iki adres önemlidir: **LHOST** (saldırganın kendi tarafı, geri bağlantının geleceği adres)
ve **RHOST** (hedefin adresi). Başarılı olursa bir oturum açılır.

Burada bir komut öğrenmiyorsun. Önemli olan şu: savunmacı olarak senin loglarında **RHOST** görünür
(ona gelen istekler), **LHOST** ise saldırganın kaynak IP'sidir.

Gürültü seviyesi yüksek olan modülleri listele:
""", komut="awk -F'|' '$4==\"YUKSEK\"' kurgusal_modul_listesi.txt", sonra="""
`YUKSEK` gürültülü olanlar genelde `auxiliary` taramalarıdır: tek hedefe çok sayıda bağlantı denemesi yapar.
"""),
    Adim("Neden gürültülü?", """
Çerçevedeki modüller **genel amaçlıdır**: aynı davranışı herkes için aynı biçimde yaparlar.
Bu yüzden hem ağ trafiğinde hem sistemde tanınabilir izler bırakırlar:

- Tarama modülleri kısa sürede çok sayıda port/servis sorgular.
- Aynı modül her seferinde benzer paket ve istek kalıpları üretir (imza).
- Yük (payload) standart olduğunda antivirüs ve EDR onu tanıyabilir.

**Hacker gözüyle:** Metasploit güçlüdür ama sessiz değildir. Bu yüzden gerçek sızma testlerinde
müşteriye "mavi takım bizi yakaladı mı?" sorusunun cevabı da rapora girer. OSCP gibi sınavlar da aracın
değil, altındaki tekniğin öğrenilmesini istediği için çerçeve kullanımını sınırlar.

Şimdi IDS (saldırı tespit sistemi) uyarılarının ilk satırlarına bak:
""", komut="head -8 kayitlar/ids_uyarilari.log", sonra="""
Satır biçimi: `tarih saat UYARI sinyal-kimliği kaynak:port -> hedef:port "açıklama"`.
Beşinci alan kaynak, yedinci alan hedeftir.
"""),
    Adim("Kim ne kadar uyarı üretiyor?", """
IDS logunu kaynağa göre grupla: 5. alanı al, `:` sonrasını (portu) at, sırala ve say:
""", komut="cut -d' ' -f5 kayitlar/ids_uyarilari.log | cut -d: -f1 | sort | uniq -c | sort -rn", sonra="""
En üstte iç ağdan bir IP olabilir: kurumsal **zafiyet tarayıcıları** da gürültülüdür ve IDS'i öter.
Bu yüzden önce "bu kaynak bilinen bir araç mı?" diye sorarsın. Dışarıdan gelen ve çok port deneyen
kaynak ise asıl şüphelidir.
"""),
    Adim("Uç nokta (EDR) logu", """
**EDR**, uç noktalarda (sunucu, bilgisayar) çalışan ve süreç davranışını izleyen güvenlik yazılımıdır.
Bilinen bir yükün imzası eşleşirse "imza eşleşmesi" üretir. Davranış tabanlı uyarılar ise daha belirsizdir.
""", komut="cat kayitlar/uc_nokta.log", sonra="""
İki farklı uyarı türü var: `IMZA_ESLESMESI` (bilinen bir şeyle eşleşti, **kesin**) ve
`DAVRANIS_UYARISI` (alışılmadık, düşük güvenli). Önce kesin olandan başla.
"""),
    Adim("Savunma nerede kırar?", """
Bir çerçeve kullanımına karşı savunma **katmanlıdır**:

1. **Yama:** exploit'in hedef aldığı zafiyet kapalıysa modül başarısız olur.
2. **Ağ tespiti (IDS/IPS):** tarama ve bilinen istek kalıplarını yakalar.
3. **Uç nokta koruma (EDR/antivirüs):** bilinen yükleri ve şüpheli süreç zincirlerini durdurur.
4. **Çıkış filtreleme:** içeri girse bile dışarıya geri bağlanmasını engeller (Bölüm 3).
5. **Log izleme:** tarama izlerini erken yakalar.

İmza eşleşmesi kaç tane?
""", komut="grep -c IMZA_ESLESMESI kayitlar/uc_nokta.log", sonra="""
Bir satır yeterli: o uç nokta büyük olasılıkla ele geçirilmeye çalışılmış. Görevlerde onu bulacaksın.
"""),
]

GOREVLER = [
    Gorev("Bir sızma çerçevesinde **yük çalıştırmadan**, yalnızca tarama ve bilgi toplama yapan "
          "yardımcı modül türü hangisidir?",
          Secmeli([
              ("auxiliary; tarar, dener, bilgi toplar, yük çalıştırmaz",
               "Doğru. Auxiliary modüller yardımcıdır; sürüm sorgusu, port taraması gibi işler yapar."),
              ("exploit; zafiyeti kullanır ve hedefte işlem yürütmeye başlar",
               "Exploit bir zafiyeti kullanır; yük çalıştırmaya yol açabilir. Soru yük çalıştırmayan türü soruyor."),
              ("payload; içeri girdikten sonra çalışan iş parçacığını temsil eder",
               "Payload tam tersine, çalışan işin kendisidir."),
              ("post; sistem içinde önceden hazırlanmış kalıcı bir hesap oluşturur",
               "Post modülleri içeri girildikten sonra çalışır; yük çalıştıran aşamadır."),
          ]),
          ("Dört türü hatırla: exploit, payload, auxiliary, post. Hangisi \"yardımcı\" anlamına geliyor?",
           "Adı \"yardımcı\" anlamına gelen tür yük taşımaz.",
           "İngilizce \"auxiliary\" = yardımcı."),
          puan=15, baslik="Yardımcı modül"),
    Gorev("`kurgusal_modul_listesi.txt` içinde türü `post` olan kaç modül var?",
          Sayi("post_adet", sik_hatalar=lambda g, beklenen, b: (
              "Tüm modülleri saymış olabilirsin; yalnızca türü `post` olanları say." if int(g) > beklenen else None)),
          ("Liste `tür|modül|...` biçiminde; ilk alan türü söylüyor.",
           "`grep` ile yalnızca `post` ile başlayan satırları seç ve say.",
           "`grep -c '^post|' kurgusal_modul_listesi.txt`"),
          puan=20, baslik="Post modülleri"),
    Gorev("`kayitlar/ids_uyarilari.log` içinde **dışarıdan** (internetten) gelen ve **en çok** uyarı "
          "üreten IP hangisi? (Kurumun kendi planlı tarayıcısını sayma.)",
          IP("saldirgan", sik_hatalar=_ip_hata),
          ("Kaynak IP 5. alanda ve `:port` ile birlikte yazılmış.",
           "Kaynağı `cut` ile kes, `sort | uniq -c | sort -rn` ile say. İç ağ IP'leri `10.`, `172.16.`, `192.168.` ile başlar.",
           "`cut -d' ' -f5 kayitlar/ids_uyarilari.log | cut -d: -f1 | sort | uniq -c | sort -rn`; iç IP'yi atlayıp dış olan ilk satırı al."),
          puan=30, baslik="Tarama kaynağı"),
    Gorev("Bu dış IP, **kaç farklı hedef portu** denemiş? (Aynı portu tekrar sayma.)",
          Sayi("port_sayisi", sik_hatalar=_port_hata),
          ("Hedef alanı `ip:port` biçiminde, 7. alan. Sadece o IP'nin satırlarına bak.",
           "Önce IP'ye göre `grep` ile süz, sonra port kısmını kes, tekrarları `sort -u` ile at, sayıyı `wc -l` ile al.",
           "`grep -F '<ip>:' kayitlar/ids_uyarilari.log | cut -d' ' -f7 | cut -d: -f2 | sort -u | wc -l`"),
          puan=30, baslik="Farklı port"),
    Gorev("`kayitlar/uc_nokta.log` içinde **imza eşleşmesi** (`IMZA_ESLESMESI`) üreten uç noktanın "
          "adı (host) ne?",
          Metin("olay_host", bicim="host adı",
                sik_hatalar=lambda g, beklenen, b: (
                    "Bu host yalnızca düşük güvenli bir **davranış uyarısı** üretmiş; sorulan, kesin **imza eşleşmesi**."
                    if g == b.senaryo["davranis_host"].casefold() else None)),
          ("İki tür uyarı var; birisi kesin, öbürü belirsiz.",
           "`grep` ile yalnızca `IMZA_ESLESMESI` içeren satırı bul; satırdaki `host=` alanına bak.",
           "`grep IMZA_ESLESMESI kayitlar/uc_nokta.log`"),
          puan=25, baslik="İmza eşleşmesi"),
    Gorev("Bu çerçevenin bir tarama modülü, neden savunma tarafında **kolay fark edilir**?",
          Secmeli([
              ("Kısa sürede çok port ve servis sorgular; normal kullanıcıdan çok farklıdır",
               "Doğru. Tek kaynaktan, kısa sürede, çok porta gelen istekler IDS ve log analizinde belirgin bir kalıptır."),
              ("Her modül, hedef sunucunun disk içeriğini sildiği için sistem hemen uyarı verir",
               "Tarama modülleri veri silmez; sadece sorgu gönderir. Fark edilme sebebi trafik kalıbıdır."),
              ("Çerçeve yalnızca internet dışı ağlarda çalıştığı için dış trafik anında şüphelidir",
               "Çerçeve hem iç hem dış ağlarda kullanılabilir; sorun kullanım yeri değil, davranış kalıbıdır."),
              ("Tarama sırasında hedef cihazın saati değiştiği için loglar tutarsız görünür",
               "Taramalar hedefin saatini değiştirmez. Fark edilme sebebi ağ trafiği kalıbıdır."),
          ]),
          ("Normal bir kullanıcı bir sunucunun kaç portunu dener?",
           "Tarama, kısa sürede çok sayıda bağlantı denemesidir.",
           "IDS'in gördüğü şey trafiğin kalıbıdır: tek kaynak, çok port, kısa süre."),
          puan=20, baslik="Neden gürültülü"),
    Gorev("Bir kurumun, bu tür çerçeve kullanımına karşı **tek başına** en etkili ve kalıcı "
          "önlemi hangisidir?",
          Secmeli([
              ("Zafiyetleri yamalamak; hedef alınan hata kapanınca modül başarısız olur",
               "Doğru. Exploit'ler belirli bir zafiyeti hedefler; yama kapatınca modül çalışmaz. Diğer katmanlar yama eksiklerini yakalamak içindir."),
              ("Uç noktalardaki antivirüsü kapatmak; böylece saldırgan fark edilmeden araç kullanamaz",
               "Antivirüsü kapatmak savunmayı zayıflatır; saldırganın işini kolaylaştırır."),
              ("Bütün log kayıtlarını silmek; saldırganın görebileceği iz kalmaz",
               "Log silmek senin görüşünü kaybettirir; saldırgan için hiçbir şey değişmez."),
              ("Çerçevenin bilinen bütün modül adlarını güvenlik duvarında engellemek",
               "Güvenlik duvarı modül adı görmez; trafik kalıbına göre çalışır. Adlar da kolayca değişir."),
          ]),
          ("Exploit neye dayanıyor? Onu ortadan kaldıran şey ne?",
           "Cilt 6 girişindeki ilke: bilinen zafiyet kapanırsa zincir kopar.",
           "Yama yönetimi."),
          puan=20, baslik="En etkili önlem"),
    Gorev("IDS logundaki `kaynak -> hedef` alanlarında, çerçevenin **RHOST** seçeneği log tarafında "
          "hangisine karşılık gelir?",
          Secmeli([
              ("Hedef (okun sağı); saldırıya uğrayan sunucu",
               "Doğru. RHOST hedef adrestir; logda gelen isteğin gittiği yerdir."),
              ("Kaynak (ok işaretinin solu); isteği gönderen taraf",
               "Kaynak saldırganın tarafıdır; çerçevede LHOST'a (saldırganın kendi adresi) karşılık gelir."),
              ("Log satırındaki sinyal kimliği; kuralı üreten imza",
               "Sinyal kimliği IDS kuralının adıdır; bir ağ adresi değildir."),
              ("Satırdaki tarih ve saat; olayın ne zaman olduğu",
               "Tarih/saat zaman bilgisidir; adres değildir."),
          ]),
          ("RHOST kime ait: saldıran mı, saldırılan mı?",
           "Log satırında ok (->) trafiğin yönünü gösterir.",
           "Hedef adres okun ucundaki taraftır."),
          puan=15, baslik="RHOST nerede"),
]


def _kapanis():
    return """
Saldırganın gözüyle: Metasploit gibi çerçeveler işi hızlandırır ama herkes için aynı kalıpları
üretir; kalıp, tanınabilir demektir. Savunmanın gözüyle: tarama bir imzadır (tek kaynak, çok port,
kısa süre), bilinen yük bir imzadır, ve her ikisi de loglara yazılır. Kurumun kendi zafiyet
tarayıcısı da aynı gürültüyü çıkarır; bu yüzden "bilinen araçlar" listesi tutmak yanlış alarmı
azaltır. Çerçeveyi uygulamalı öğrenmek için **kendi laboratuvarını** kullan: Cilt 9'da Kali'nde
kuracağın savunmasız hedefler.
"""


SEVIYE = Seviye(
    kimlik="c06b02",
    cilt=6,
    bolum=2,
    baslik="Metasploit Çerçevesi: Tanı ve İz Sür",
    brifing="""
**<<musteri>>** sunucusunda (<<servis>>) gece yarısından sonra bir tarama dalgası var. Deniz:
"Kurgusal modül listesini ve IDS/EDR loglarını oku, saldırganın izini bul."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Metasploit gerçek bir projedir:** Rapid7 tarafından desteklenen açık kaynaklı bir çerçevedir;
  hem sızma testçileri hem savunmacılar (zafiyet doğrulama, tespit kuralı geliştirme) kullanır.
  Yani çerçevenin var olması kötü değildir; yetkisiz kullanımı suçtur.
- **WannaCry 2017:** Kullandığı SMB zafiyeti için Microsoft yaması saldırıdan yaklaşık iki ay önce (Mart 2017) yayımlanmıştı;
  yamasız sistemler etkilendi. Tespit/önleme: yama, SMB'nin internete açılmaması, ağ bölümleme.
- **Tespit ve önleme:** Tek kaynaktan kısa sürede çok porta gelen istekler (tarama) IDS ve güvenlik
  duvarı loglarında kolayca yakalanır. Standart yükler antivirüs/EDR imzalarına takılır. Hepsinden
  önce yama ve gereksiz servisleri kapatmak gelir.
""",
    sure_hedef_dk=20,
)
