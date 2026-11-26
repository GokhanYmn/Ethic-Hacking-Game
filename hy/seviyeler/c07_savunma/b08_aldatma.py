"""Cilt 7 · Bölüm 8 — Aldatma: Bal Küpü (Honeypot).

Beceri: savunmada aldatma fikrini anlamak (honeypot, canary token), meşru kullanıcının dokunmadığı
bir tuzağın neden düşük yanlış pozitifli bir alarm olduğunu kavramak ve bir honeypot erişim kaydından
tuzağa dokunan IP'yi, ilk dokunuş saatini, dokunuş sayısını ve tetiklenen tuzağı çıkarmak.

Vakalar: banka, hastane, lojistik. Her vakada iki tuzak kurulu (sahte yedek paylaşımı + canary dosya);
biri tetiklenir. Saldırı içeriği yok; kayıtlar düz metindir.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Secmeli, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

VAKALAR = [
    {"kod": "ferahbank", "ag": "10.30.0", "klasor": "honeypot_kayitlari",
     "sahne": "İç ağda yeni kurulan tuzaklar ilk kez alarm verdi; yönetim 'bu gerçek bir saldırı mı?' diye soruyor."},
    {"kod": "medora", "ag": "10.40.0", "klasor": "tuzak_erisim",
     "sahne": "BT ekibi hastane ağına iki tuzak yerleştirmişti; sabah bunlardan birinin kaydında hareket görüldü."},
    {"kod": "kuzgun", "ag": "10.50.0", "klasor": "bal_kupu",
     "sahne": "Depo ağında sahte bir yedek paylaşımı ve bir canary dosya duruyordu; erişim kaydı ilk kez doldu."},
]

TUZAKLAR = {
    "hp-yedek-paylasim": "Sahte 'yedek' ağ paylaşımı (içinde cazip görünen ama sahte dosyalar)",
    "hp-canary-maaslar": "Canary token: 'maaslar_2026.xlsx' adlı tuzak dosya (açılınca alarm üretir)",
}
GERCEK = ["web01", "mail01", "vpn01", "dosya01"]
GERCEK_EYLEM = {"web01": "HTTP_GET /", "mail01": "IMAP_LOGIN", "vpn01": "VPN_LOGIN", "dosya01": "SMB_OPEN rapor.docx"}
EYLEMLER = {
    "hp-yedek-paylasim": ["SMB_LIST", "SMB_OPEN yedek_2025.zip", "SMB_READ yedek_2025.zip"],
    "hp-canary-maaslar": ["FILE_OPEN maaslar_2026.xlsx", "FILE_COPY maaslar_2026.xlsx", "FILE_OPEN maaslar_2026.xlsx"],
}


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    tuzak = rng.choice(sorted(TUZAKLAR))
    saldirgan = u.dis_ip(rng)
    dokunus = rng.randint(3, 6)
    bas = u.gun(rng) + timedelta(hours=rng.randint(7, 12), minutes=rng.randint(0, 59))
    ilk = bas + timedelta(minutes=rng.randint(40, 120), seconds=rng.randint(0, 59))
    return {
        "vaka": m["ad"], "v": v, "m": m, "tuzak": tuzak, "saldirgan": saldirgan, "dokunus": dokunus,
        "bas": bas.isoformat(), "ilk": ilk.isoformat(), "tohum": rng.randint(1, 10**6),
        "metin": {"musteri": m["ad"], "kl": v["klasor"], "sahne": v["sahne"]},
        "cevaplar": {"ip": saldirgan, "saat": f"{ilk:%H:%M:%S}", "adet": dokunus, "tuzak": tuzak},
    }


def _satirlar(s: dict) -> list:
    rng = random.Random(s["tohum"])
    bas, ilk = datetime.fromisoformat(s["bas"]), datetime.fromisoformat(s["ilk"])
    ag = s["v"]["ag"]
    olaylar = []

    def ekle(t, sensor, ip, ayrinti, sonuc="OK"):
        olaylar.append((t, f"{t:%Y-%m-%d %H:%M:%S} sensor={sensor} src={ip} action={ayrinti} result={sonuc}"))

    kullanilan = {s["saldirgan"]}
    for _ in range(rng.randint(30, 45)):                        # meşru gündelik trafik
        t = bas + timedelta(seconds=rng.randint(0, 3 * 3600))
        if rng.random() < 0.75:
            ip = u.ic_ip(rng, ag)
        else:
            ip = u.dis_ip(rng)
            while ip in kullanilan:
                ip = u.dis_ip(rng)
        sensor = rng.choice(GERCEK)
        ekle(t, sensor, ip, GERCEK_EYLEM[sensor])
    for _ in range(rng.randint(2, 4)):                          # saldırgan önce gerçek sistemleri yoklar
        ekle(ilk - timedelta(minutes=rng.randint(3, 30), seconds=rng.randint(0, 59)), rng.choice(GERCEK),
             s["saldirgan"], rng.choice(["HTTP_GET /admin", "VPN_LOGIN", "SMB_LIST"]), rng.choice(["DENIED", "OK"]))
    t = ilk                                                     # tuzak dokunuşları (ilki tam `ilk` anında)
    for i in range(s["dokunus"]):
        ekle(t, s["tuzak"], s["saldirgan"], EYLEMLER[s["tuzak"]][i % 3], "OK")
        t += timedelta(minutes=rng.randint(1, 9), seconds=rng.randint(1, 59))
    olaylar.sort(key=lambda x: x[0])
    return [x[1] for x in olaylar]


def yaz(lab: Path, s: dict) -> None:
    k = lab / s["v"]["klasor"]
    m = s["m"]
    u.yaz(k / "erisim.log", "\n".join(_satirlar(s)) + "\n")
    u.yaz(k / "tuzaklar.txt",
          "# Kurulu tuzaklar (sensör adı  açıklama). Gerçek kullanıcıların bunlarla işi YOKTUR.\n"
          + "".join(f"{ad}  {ac}\n" for ad, ac in TUZAKLAR.items())
          + "# Gerçek sistemler: " + ", ".join(GERCEK) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} tuzak erişim kayıtları ({s['v']['klasor']}/). KURGUSAL.\n"
          f"Deniz'den not: {s['v']['sahne']}\n"
          "erisim.log: tüm sensörlerin ortak kaydı. tuzaklar.txt: hangi sensör tuzak, hangisi gerçek sistem.\n")


def _ip_hata(g, beklenen, b):
    if g.startswith(b.senaryo["v"]["ag"]):
        return "Bu iç ağdan bir IP; meşru bir kullanıcı olabilir. Tuzak sensörüne (`hp-` ile başlayan) dokunan IP'yi ara."
    return None


def _saat_hata(g, beklenen, b):
    g = g.strip()
    if g != beklenen and any(f" {g} " in satir for satir in _satirlar(b.senaryo)):
        return "Bu saatte kayıt var ama ilk **tuzak** dokunuşu değil. Saldırgan önce gerçek sistemleri yoklamış olabilir; yalnızca `hp-` sensörlerine bak."
    return None


def _adet_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Gerçek sistem satırlarını da saymış olabilirsin. Sadece `sensor=hp-` olanları say."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["v"]["klasor"]
    log = f"{k}/erisim.log"
    ip = sh(f"grep 'sensor=hp-' {log} | grep -o 'src=[^ ]*' | cut -d= -f2 | sort -u", lab)
    saat = sh(f"grep 'sensor=hp-' {log} | head -1 | awk '{{print $2}}'", lab)
    adet = sh(f"grep -c 'sensor=hp-' {log}", lab)
    tuzak = sh(f"grep 'sensor=hp-' {log} | grep -o 'sensor=[^ ]*' | sort -u | cut -d= -f2", lab)
    return sec_doldur({1: ip, 2: saat, 3: adet, 4: tuzak}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Aldatma nedir? Honeypot ve canary", """
Şimdiye kadar savunmayı hep **izleyerek** yaptık: log oku, alarm bak. **Aldatma** (deception) farklı
bir fikirdir: saldırganın önüne bilerek **cazip bir tuzak** koyarsın. İki ana tür var:
- **Honeypot (bal küpü):** gerçek gibi görünen ama hiçbir işe yaramayan sahte bir sunucu, servis ya da
  paylaşım. Tek amacı: kim dokunuyor, ne yapıyor görmek.
- **Canary token:** ortaya bırakılmış sahte bir dosya, bağlantı ya da hesap. Açıldığında ya da
  kullanıldığında sessizce alarm gönderir (maden ocağındaki kanarya kuşu gibi).

<<sahne>> Tuzak kayıtlarının bulunduğu klasörde ne var?
""", komut="ls -l <<kl>>"),
    Adim("Neden bu kadar değerli: meşru kullanıcı dokunmaz", """
Tuzağın sihri şu: **hiçbir meşru kullanıcının ona dokunmak için sebebi yoktur.** Çalışanlar sahte
yedek paylaşımını da, `maaslar_2026.xlsx` tuzak dosyasını da iş için kullanmaz; çünkü sistemde
resmen yoktur. Dolayısıyla tuzağa gelen **her** dokunuş şüphelidir. Bu, normal alarmların tersidir:
IDS'te yanlış pozitif çok olur, tuzakta **yanlış pozitif neredeyse sıfırdır**. Hangisi tuzak,
hangisi gerçek sistem, kurulum listesi söyler:
""", komut="cat <<kl>>/tuzaklar.txt", sonra="""
`hp-` ile başlayan sensör adları tuzaktır. Gerçek sistemler (web01, mail01...) normal trafik alır;
tuzaklar ise sessiz kalmalıdır. Sessizlik bozulduysa biri kurcalıyordur.
"""),
    Adim("Tuzak kurmak: ne gerekir?", """
İyi bir tuzak üç şey ister: **inandırıcı olmalı** (adı cazip: yedek, maaş, parola), **hiç gerçek veri
içermemeli** (sahte dosyalar) ve **izlenmeli** (her erişim kayda ve alarma düşmeli). Ayrıca gerçek
sistemlerden **izole** edilir; tuzak ele geçse bile ilerisi açık olmamalıdır. Pratikte sahte bir ağ
paylaşımı, sahte bir veritabanı sunucusu ya da bir klasöre bırakılmış canary dosya yeterlidir.
Erişim kaydının ilk satırlarına bakalım:
""", komut="head -n 5 <<kl>>/erisim.log", sonra="""
Her satır: zaman, `sensor=` (hangi sistem/tuzak), `src=` (kim), `action=` (ne yaptı), `result=`.
"""),
    Adim("Tuzak vuruşlarını okumak", """
Kayıt gerçek trafikle doludur; tuzak vuruşları samanlıktaki az sayıda iğnedir. Sadece tuzak sensörlerini
süzmek tüm gürültüyü atar:
""", komut="grep 'sensor=hp-' <<kl>>/erisim.log", sonra="""
Kalan satırlar yalnızca tuzağa dokunanlardır. `src=` alanı kimliğini, saat alanı ne zaman başladığını
verir. Aynı IP'nin tuzağa kaç kez, hangi eylemle (`SMB_OPEN`, `FILE_COPY`...) dokunduğuna dikkat et.
"""),
    Adim("Kim, kaç kez? Sayıp doğrulamak", """
Tuzak satırlarındaki `src=` değerlerini sayarsan, tuzağa dokunan IP'leri ve kaç kez dokunduklarını
görürsün:
""", komut="grep 'sensor=hp-' <<kl>>/erisim.log | grep -o 'src=[^ ]*' | sort | uniq -c", sonra="""
Bu IP için işin yarısı bitti. Gerçek işe şimdi başlıyorsun: o IP'nin **gerçek sistemlerdeki** izlerini de
ara (tuzaktan önce neyi yoklamış?). Doğru aksiyon: IP'yi engelle/izole et, gerçek sistemlerdeki izlerini
incele, kayıtları delil olarak sakla. Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`<<kl>>/erisim.log` içinde **tuzak sensörüne** (sensor=hp-...) dokunan saldırgan IP hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Gerçek sistemler normal trafik alır; sadece `hp-` ile başlayan sensörler tuzaktır.",
           "Önce yalnızca tuzak satırlarını süz, sonra `src=` alanını çek.",
           "`grep 'sensor=hp-' <<kl>>/erisim.log | grep -o 'src=[^ ]*' | sort -u`"),
          puan=30, baslik="Tuzağa dokunan IP"),
    Gorev("Bu IP'nin tuzağa **ilk dokunduğu** saat nedir? (SS:DD:SS)",
          Metin("saat", sik_hatalar=_saat_hata, bicim="SS:DD:SS"),
          ("Saldırgan tuzaktan önce gerçek sistemleri de yoklamış olabilir; onlar sayılmaz.",
           "Sadece tuzak satırlarında, en erken olanın saatini al (kayıt zamana göre sıralı).",
           "`grep 'sensor=hp-' <<kl>>/erisim.log | head -1 | awk '{print $2}'`"),
          puan=30, baslik="İlk dokunuş saati"),
    Gorev("Tuzak sensörleri toplam **kaç kez** dokunuldu (tuzak satırı sayısı)?",
          Sayi("adet", sik_hatalar=_adet_hata),
          ("Gerçek sistem satırları sayıya girmez.",
           "Tuzak satırlarını süz ve say.",
           "`grep -c 'sensor=hp-' <<kl>>/erisim.log`"),
          puan=30, baslik="Dokunuş sayısı"),
    Gorev("Hangi **tuzak** tetiklendi? (sensör adını yaz, `hp-` ile başlar)",
          Metin("tuzak", bicim="sensör adı, hp- ile başlar"),
          ("Tuzak satırlarında `sensor=` alanının değerine bak.",
           "İki tuzak var (`tuzaklar.txt`); kayıtta yalnızca biri geçiyor.",
           "`grep 'sensor=hp-' <<kl>>/erisim.log | grep -o 'sensor=[^ ]*' | sort -u`"),
          puan=30, baslik="Tetiklenen tuzak"),
    Gorev("Bir tuzağa gelen dokunuş neden **özellikle değerli** bir alarmdır?",
          Secmeli([
              ("Meşru kullanıcının ona erişmek için sebebi yoktur; bu yüzden yanlış pozitif oranı düşüktür",
               "Doğru. Tuzak sessiz olmalıdır; her dokunuş şüphelidir ve alarm güvenilirdir."),
              ("Tuzak, saldırganı otomatik olarak yakalayıp hapse gönderir",
               "Yanlış. Tuzak yalnızca erken uyarı ve bilgi sağlar; yakalama ya da yaptırım yapmaz."),
              ("Tuzağa gelen trafik her zaman en yüksek hacimli trafiktir",
               "Yanlış. Tuzak az dokunulur; değeri hacimde değil, güvenilirliğindedir."),
              ("Tuzak, gerçek sistemlerin güvenlik duvarının yerini tutar",
               "Yanlış. Tuzak bir tespit aracıdır; engelleme yapmaz ve güvenlik duvarının yerini tutmaz."),
          ], dogru=0),
          ("Normal alarmlarda en büyük dert yanlış alarmdır. Tuzakta bu nasıl değişir?",
           "Çalışanlar sahte yedek paylaşımını neden kullanmaz?",
           "Meşru erişim olmadığı için her dokunuş anlamlıdır: düşük yanlış pozitif."),
          puan=20, baslik="Tuzağın değeri"),
    Gorev("Tuzağa dokunan IP'yi tespit ettin. **Doğru aksiyon** hangisidir?",
          Secmeli([
              ("IP'yi engelle/izole et ve aynı IP'nin gerçek sistemlerdeki izlerini incele",
               "Doğru. Tuzak erken uyarıdır; arkasından gerçek sistemlerde ne yaptığına bakmak ve engellemek gerekir."),
              ("Alarmı yok say; tuzak zaten sahte, zarar yok",
               "Yanlış. Tuzağın kendisi sahte ama dokunan kişi gerçek ve ağın içinde; gerçek sistemlere de yönelebilir."),
              ("Tuzağı hemen kapat ve kayıtları sil",
               "Yanlış. Kayıtlar delildir ve saldırganın yöntemini gösterir; silmek öğrenmeyi ve kanıtı yok eder."),
              ("Tüm çalışanların parolasını anında sıfırla, başka bir şeye bakma",
               "Yanlış. Bu aşırı ve hedefsiz bir tepkidir; önce kapsamı (hangi IP, hangi sistem) daralt."),
          ], dogru=0),
          ("Tuzak yalnızca ilk haberdir; bundan sonra ne yaparsın?",
           "Kanıtı silmek ve alarmı umursamamak seçenek değil.",
           "Engelle/izole et, sonra gerçek sistemlerdeki izlerini ara."),
          puan=30, baslik="Doğru aksiyon"),
]


def _kapanis():
    return """
Saldırgan için tuzak, ağın içinde tek yanlış adımdır: cazip görünen bir 'yedek' paylaşımı ya da maaş
dosyası kayıtsız kalınamayacak kadar çekicidir; bu yüzden deneyimli saldırganlar fazla kolay görünen
hedeflerden şüphelenir. Savunmacı için değer şu: gürültülü bir ortamda tek ve güvenilir bir sinyal.
Tuzağa gelen her dokunuşu ciddiye al, IP'yi engelle, gerçek sistemlerdeki izlerini ara ve kayıtları
delil olarak sakla.
"""


SEVIYE = Seviye(
    kimlik="c07b08",
    cilt=7,
    bolum=8,
    baslik="Aldatma: Bal Küpü",
    brifing="""
Deniz Kara bir kayıt dosyasını ekrana çeviriyor: "**<<musteri>>** için iki tuzak kurduk: sahte bir
yedek paylaşımı ve bir canary dosya. <<sahne>> Normalde ikisi de sessiz kalmalıydı."

"Sorular basit: tuzağa kim dokundu, ne zaman başladı, kaç kez dokundu ve hangi tuzak tetiklendi?
Sonra da bunun neden değerli olduğunu ve ne yapılacağını söylemeni istiyorum."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Canarytokens (Thinkst):** Ücretsiz/ticari canary token hizmeti; sahte bir Word dosyası, URL ya da
  AWS anahtarı bırakırsın, biri açtığında e-posta ile haber verir. Birçok kurum sızıntıyı bu sayede
  dakikalar içinde fark etmiştir.
- **Erken uyarı değeri:** Bal küpleri, saldırganın ağda ilerleyişini (lateral movement) veriye
  ulaşmadan yakalar; kurulumu ucuzdur, yanlış alarmı azdır. Araştırmacılar internete açık honeypot'larla
  yeni saldırı tekniklerini de gözlemler.
- **Dikkat:** Tuzak, gerçek ağdan izole edilmezse saldırganın sıçrama noktası olabilir; bu yüzden
  ayrı segmentte, gerçek veri içermeden kurulur.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=False,
    on_kosul=("c07b07",),
)
