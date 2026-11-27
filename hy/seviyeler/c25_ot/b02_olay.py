"""Cilt 25 · Bölüm 2 — Bir OT Olayı: Anormal Komut.

SAVUNMACI/ADLİ: oyuncu, olaydan sonra kayıtları okuyan OT güvenlik analistidir. Hiçbir cihaza
bağlanılmaz. Kurgusal dört kayıt gelir: `modbus_trafik.csv` (ağ izleme), `varliklar.csv` (envanter),
`alarm.log` (SCADA alarmları), `operator_defteri.txt` (vardiya defteri). Olayın zaman çizelgesi bu
dört kaynağa dağılmıştır; oyuncu bunları birleştirir.

Olay (kronolojik): keşif okumaları, tehlikeli yazma, alarm, operatörün fark etmesi, yetkili
düzeltme, güvenlik duvarında engelleme. Veri üreticisi 1. bölümle ortaktır (`trafik_uret`).

Determinizm: `_alt` alt-tohumu; `uret` ve `yaz` aynı akıştan türetir.
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, csv_yaz, sec_doldur, sh
from hy.seviyeler.c25_ot.b01_temeller import SENARYOLAR, trafik_uret

# kronolojik sıra
EVENTLER = [
    "Yetkisiz IP, ağdaki PLC'leri okuma istekleriyle yoklar (keşif)",
    "Yetkisiz IP bir PLC register'ına tehlikeli bir değer yazar",
    "SCADA, değer sınırı aşıldığı için kritik alarm üretir",
    "Operatör ekranda anormal değeri fark edip deftere not düşer",
    "Yetkili HMI, register'ı normal değere geri döndürür",
    "BT ekibi şüpheli kaynağı güvenlik duvarında engeller",
]
ANAHTAR = ["yoklar", "tehlikeli", "kritik alarm", "anormal", "geri döndürür", "engeller"]


def _kodlar(alt: int) -> list:
    r = random.Random(alt + 1)
    k = list("abcdef")
    while True:
        r.shuffle(k)
        if k != sorted(k):
            return k


def olay_dosyalari(alt: int, v: dict) -> dict:
    d = trafik_uret(random.Random(alt), v)
    rng = random.Random(alt + 2)
    t = d["t"]
    gun = t["yazma"].replace(hour=6, minute=0, second=0)
    alarm = []
    for _ in range(rng.randint(5, 8)):                  # olay dışı, olaydan uzak alarm gürültüsü
        tt = gun + timedelta(seconds=rng.randint(0, 10800))
        if abs((tt - t["yazma"]).total_seconds()) < 600 or abs((tt - t["engel"]).total_seconds()) < 300:
            continue
        p = rng.choice(d["plc"])
        alarm.append((tt, f"{tt:%Y-%m-%d %H:%M:%S} {rng.choice(['UYARI', 'BILGI'])} {p['ad']} "
                          f"{rng.choice(['haberlesme gecikmesi', 'sensör kalibrasyon hatırlatması', 'yedek besleme testi'])}"))
    hedef = next(p for p in d["plc"] if p["ip"] == d["hedef_ip"])
    reg = d["reg"]
    alarm.append((t["alarm"], f"{t['alarm']:%Y-%m-%d %H:%M:%S} KRITIK {hedef['ad']} {reg} "
                              f"limit asildi deger={d['tehlike']} limit={hedef['yaz'][0][2]}"))
    alarm.sort(key=lambda x: x[0])
    defter = [(gun, f"{gun:%H:%M}  Vardiya devir teslim yapıldı, ekipman durumları olağan.")]
    for dk, metin in [(75, "Rutin saha turu yapıldı, bir sorun yok."), (140, "Yedek jeneratör haftalık testi tamamlandı.")]:
        tt = gun + timedelta(minutes=dk)
        if abs((tt - t["yazma"]).total_seconds()) > 900:
            defter.append((tt, f"{tt:%H:%M}  {metin}"))
    defter.append((t["fark"], f"{t['fark']:%H:%M}  {reg} değeri ekranda anormal görünüyor; alarm çaldı, HMI'dan kontrol ediyorum."))
    defter.append((t["duzelt"], f"{t['duzelt']:%H:%M}  {reg} değeri HMI-1'den elle normale çekildi."))
    defter.append((t["engel"], f"{t['engel']:%H:%M}  BT ekibi şüpheli kaynağı güvenlik duvarında engelledi; olay kaydı açıldı."))
    defter.sort(key=lambda x: x[0])
    return {"d": d, "alarm": [x[1] for x in alarm], "defter": [x[1] for x in defter], "kodlar": _kodlar(alt)}


def uret(rng):
    v = dict(rng.choice(SENARYOLAR))
    alt = rng.randint(1, 10**9)
    o = olay_dosyalari(alt, v)
    d = o["d"]
    t = d["t"]
    return {
        "vaka": f"{v['musteri']} — anormal Modbus komutu olayı",
        "_alt": alt, "v": v, "kodlar": o["kodlar"],
        "metin": {"musteri": v["musteri"], "sektor": v["sektor"], "kisi": v["kisi"], "olay": v["olay"]},
        "cevaplar": {
            "dizi": o["kodlar"],
            "kaynak": d["saldirgan"],
            "kesif": d["n_kesif"],
            "gecikme": int((t["alarm"] - t["yazma"]).total_seconds()),
            "duzelt": d["duzelt_deger"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    o = olay_dosyalari(s["_alt"], v)
    d = o["d"]
    csv_yaz(lab / "varliklar.csv", "ip,ad,tur,gorev,yazma_yetkisi", d["varlik"])
    csv_yaz(lab / "modbus_trafik.csv", "zaman,kaynak,hedef_plc,fonksiyon,register,deger", d["trafik"])
    u.yaz(lab / "alarm.log", "\n".join(o["alarm"]) + "\n")
    u.yaz(lab / "operator_defteri.txt", f"{v['musteri']} — operatör vardiya defteri (KURGUSAL)\n" + "\n".join(o["defter"]) + "\n")
    satirlar = "\n".join(f"{o['kodlar'][i]}) {EVENTLER[i]}" for i in range(6))
    satirlar = "\n".join(sorted(satirlar.splitlines()))
    u.yaz(lab / "olaylar.txt", f"{v['musteri']} — olayın adımları (sırası KARIŞIK; zamanları kayıtlardan bul)\n\n{satirlar}\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['musteri']} — OT olay inceleme klasörü (hepsi KURGUSAL; hiçbir cihaza bağlanılmaz)\n\n"
          "modbus_trafik.csv     : Modbus istekleri (zaman, kaynak, hedef_plc, fonksiyon, register, deger)\n"
          "varliklar.csv         : cihaz envanteri; yazma_yetkisi=evet olanlar yazabilir\n"
          "alarm.log             : SCADA alarm kaydı (tam zaman damgalı)\n"
          "operator_defteri.txt  : operatörün elle tuttuğu defter (yalnızca saat:dakika)\n"
          "olaylar.txt           : olayın 6 adımı, harf kodlu ve karışık sırada\n\n"
          "Modbus fonksiyon kodları:  3 = OKU   6 = tek register YAZ   16 = çok register YAZ\n")


def coz(lab: Path, s: dict) -> dict:
    sorgu = ("awk -F, 'NR==FNR{if($5==\"evet\")y[$1]=1;next} ($4==6||$4==16)&&!($2 in y){print %s}' "
             "varliklar.csv modbus_trafik.csv | sort -u")
    ip = sh(sorgu % "$2", lab)
    reg = sh(sorgu % "$5", lab)
    t_kesif = sh(f"awk -F, '$2==\"{ip}\"{{print $1; exit}}' modbus_trafik.csv", lab)
    t_yazma = sh(sorgu % "$1", lab)
    t_alarm = sh("grep KRITIK alarm.log | head -1 | cut -c1-19", lab)
    gun = t_yazma[:10]
    hhmm = sh("grep anormal operator_defteri.txt | head -1 | cut -c1-5", lab)
    t_fark = f"{gun} {hhmm}:00"
    t_duzelt = sh(f"awk -F, -v r={reg} -v s='{t_yazma}' '$5==r && $4==6 && $1>s {{print $1; exit}}' modbus_trafik.csv", lab)
    hhmm = sh("grep engelledi operator_defteri.txt | head -1 | cut -c1-5", lab)
    t_engel = f"{gun} {hhmm}:00"
    olaylar = {"yoklar": t_kesif, "tehlikeli": t_yazma, "kritik alarm": t_alarm, "anormal": t_fark,
               "geri döndürür": t_duzelt, "engeller": t_engel}
    sirali = sorted(olaylar, key=lambda k: olaylar[k])
    harfler = []
    for k in sirali:
        satir = sh(f"grep -F '{k}' olaylar.txt | head -1", lab)
        harfler.append(satir[0])
    n_kesif = sh(f"awk -F, '$2==\"{ip}\" && $4==3' modbus_trafik.csv | wc -l", lab)
    gecikme = sh(f"awk -v a='{t_alarm}' -v y='{t_yazma}' 'BEGIN{{gsub(/[-:]/,\" \",a); gsub(/[-:]/,\" \",y); "
                 f"print mktime(a)-mktime(y)}}'", lab)
    duzelt = sh(f"awk -F, -v r={reg} -v s='{t_yazma}' '$5==r && $4==6 && $1>s {{print $6; exit}}' modbus_trafik.csv", lab)
    cozum = {1: " ".join(harfler), 2: ip, 3: n_kesif, 4: gecikme, 5: duzelt}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


def _dizi_hata(verilen, beklenen, b):
    if len(verilen) == len(beklenen) and verilen == sorted(verilen):
        return "Harfleri alfabetik sıraya dizmişsin; olaylar.txt'deki sıra karışık. **Zamana** göre sırala."
    return None


def _kesif_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Yazma komutunu da saymış olabilirsin. Keşif = yalnızca **okuma** (fonksiyon 3) istekleri."
    return None


def _gecikme_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen // 60:
        return "Bu dakika olabilir; soru **saniye** istiyor."
    return None


def _duzelt_hata(g, beklenen, b):
    d = trafik_uret(random.Random(b.senaryo["_alt"]), b.senaryo["v"])
    if g == str(d["tehlike"]):
        return "Bu, saldırganın yazdığı tehlikeli değer. Düzeltmeyi **sonradan** yetkili HMI yapmış."
    return None


ADIMLAR = [
    Adim("Olay günü: dört kayıt", """
Selin: "Bir OT olayında tek bir kayıt hikâyenin tamamını anlatmaz. Ağ izleme kaydı **ne gönderildi**yi,
alarm kaydı **sistemin ne zaman fark ettiği**ni, operatör defteri **insanın ne zaman fark ettiği**ni
söyler. Analistin işi bunları **tek bir zaman çizelgesinde birleştirmek**."

Klasöre bak:
""", komut="cat OKUBENI.txt", sonra="""
Dikkat: operatör defterinde yalnızca saat ve dakika var, diğer kayıtlarda saniyeye kadar zaman. Zamanları
karşılaştırırken bunu hesaba kat. Hiçbir cihaza bağlanmıyoruz; yalnızca geçmiş kayıtları okuyoruz.
"""),
    Adim("Yetkisiz kaynağı bul", """
Önceki bölümdeki yöntem: yazma komutları (6 ve 16) ve yetkili kaynak listesi. Yazma yapanların kaynaklarını
sayarak başla:
""", komut="awk -F, '$4==6||$4==16{print $2}' modbus_trafik.csv | sort | uniq -c", sonra="""
Listedeki IP'lerden biri `varliklar.csv`'de yazma yetkili değil. Sende bir şüpheli IP var. Şimdi onu
**başından sonuna** takip edelim.
"""),
    Adim("Şüphelinin tüm izi", """
Bir şüpheli IP'nin **bütün** isteklerine bakmak saldırının biçimini anlatır. Önce kaynak IP'lerin kaç
istek gönderdiğini say (2. sütun):
""", komut="cut -d, -f2 modbus_trafik.csv | tail -n +2 | sort | uniq -c | sort -rn", sonra="""
SCADA yüzlerce istek gönderiyor; operatör istasyonları daha az; şüpheli IP ise yalnızca **birkaç satır**.
`grep` ile o IP'nin satırlarını getirirsen önce okuma isteklerini (**keşif**: "hangi PLC var, neyi tutuyor?"),
sonra tek yazmayı görürsün. Tehlikeli sıra budur: yokla, anla, tek komutla bozmak.
"""),
    Adim("Alarm kaydı", """
Sistem, bir değer sınırı aştığında alarm üretir. Önemli (kritik) alarmları ayır:
""", komut="grep KRITIK alarm.log", sonra="""
Alarmın zamanı ile yazma komutunun zamanı arasındaki fark, **sistemin tepki süresi**dir. OT'de
saniyeler önemlidir: pompa, fırın ya da koruma röle ayarı o sürede fiziksel zarara yol açabilir.
"""),
    Adim("Operatör defteri", """
Operatör alarmı gördü mü, ne yaptı? Defterde "anormal" ya da "elle" kelimelerine bak:
""", komut="cat operator_defteri.txt", sonra="""
Defter, insanın gözünden zaman çizelgesidir: operatör anormal değeri fark etti, **elle** düzeltti ve BT
ekibi engelleme yaptı. Düzeltmeyi ağ kaydında da görebilirsin: yetkili HMI'dan aynı register'a **sonradan**
yazılan normal değer.
"""),
    Adim("Zaman çizelgesini birleştir", """
Şimdi altı olayı sıralayabilirsin. `olaylar.txt` adımları harf kodlu ve karışık sırada veriyor:
""", komut="cat olaylar.txt", sonra="""
Zamanı kayıtlardan bul, harfleri **zamana göre** sırala. Bunu yapan analist, "ne zaman fark ettik, ne zaman
müdahale ettik, ne kadar gecikti?" sorularına cevap verir. Bu çizelge hem olay raporunun hem de ağ ayrımı
(segmentasyon) kararlarının temelidir.

**Hacker gözüyle:** Saldırgan, keşfi yazmadan hemen önce yapar çünkü PLC'nin hangi register'ı neyi kontrol
ettiğini bilmesi gerekir. Savunmacı için ders: yetkisiz bir kaynaktan gelen **ilk okuma** bile bir
uyarıdır; yazma gelmeden önce fark etmek en ucuz savunmadır.
"""),
]

GOREVLER = [
    Gorev("`olaylar.txt`'deki altı adımı **gerçekleştikleri zamana göre** sırala. Zamanları `modbus_trafik.csv`, "
          "`alarm.log` ve `operator_defteri.txt` içinden bul. Cevap: harfler sırayla (örn. `c a e b d f`).",
          Dizi("dizi", sik_hatalar=_dizi_hata),
          ("Her adımın bir kaydı var: ağ trafiği, alarm, defter. Önce her adımın zamanını yaz.",
           "Defterde yalnızca saat:dakika var; diğerleri saniyeli. Sıralarken defter zamanını dakikanın başı kabul et.",
           "Beklenen mantık: keşif, yazma, alarm, operatör fark eder, düzeltme, engelleme. Hangi harf hangi adım, "
           "`olaylar.txt`'de yazıyor."),
          puan=45, baslik="Olay sırası"),
    Gorev("Yetkisiz yazmayı yapan kaynak IP hangisi?",
          IP("kaynak"),
          ("Yazma komutları (6 ve 16) ve envanterdeki yetkili IP'ler.",
           "`awk -F, '$4==6||$4==16{print $2}' modbus_trafik.csv | sort -u` ile yazanları listele; envanterde `evet` olmayan IP'yi seç.",
           "`awk -F, '$5==\"evet\"{print $1}' varliklar.csv` yetkililer; listede olmayan kaynak aranan IP."),
          puan=35, baslik="Yetkisiz kaynak"),
    Gorev("Bu kaynak yazmadan önce PLC'leri **kaç okuma isteğiyle** yokladı? (Yalnızca fonksiyon 3 satırları.)",
          Sayi("kesif", sik_hatalar=_kesif_hata),
          ("Kaynağın bütün satırlarından yalnızca okumaları say.",
           "`grep` ile IP'nin satırlarını al; fonksiyon sütunu 3 olanları ayıkla.",
           "`awk -F, '$2==\"IP\" && $4==3' modbus_trafik.csv | wc -l`"),
          puan=35, baslik="Keşif sayısı"),
    Gorev("Tehlikeli yazma ile SCADA'nın kritik alarmı arasında **kaç saniye** geçti? (Zamanlar aynı günde; "
          "yazma satırı `modbus_trafik.csv`'de, alarm `alarm.log`'da.)",
          Sayi("gecikme", sik_hatalar=_gecikme_hata),
          ("İki tam zaman damgasına ihtiyacın var: yazmanın ve alarmın zamanı.",
           "Saat:dakika:saniye farkını saniyeye çevir (dakika × 60 + saniye farkı).",
           "Yazma ve alarm zamanını yan yana yaz; saatler aynı ise `(dk2-dk1)*60 + (sn2-sn1)`."),
          puan=40, baslik="Alarm gecikmesi"),
    Gorev("Operatör register'ı normale çevirdikten sonra HMI'dan **hangi değeri** yazdı? (Saldırganın yazmasından "
          "sonra gelen ilk yetkili yazma.)",
          Sayi("duzelt", sik_hatalar=_duzelt_hata),
          ("Saldırganın yazdığı satırdan **sonraki**, aynı register'a yapılan yetkili yazmaya bak.",
           "Satırlar zaman sıralı: yazma satırından sonra aynı register adını geçen, kaynağı HMI olan satırı ara.",
           "`grep REGISTER_ADI modbus_trafik.csv | awk -F, '$4==6||$4==16'` ve saldırgan satırının hemen altındaki."),
          puan=35, baslik="Düzeltme değeri"),
    Gorev("Bu olaya **en doğru müdahale** hangisidir?",
          Secmeli([
              ("Ağı bölüp PLC'lere yalnızca yetkili cihazlardan yazma izni vermek; kritik PLC'lerde fiziksel salt-okunur anahtarı kullanmak",
               "Doğru. Segmentasyon (ağı bölmek) ve fiziksel kilit, Modbus'un kimlik doğrulaması olmamasından doğan açığı kapatır; "
               "süreç de durmaz."),
              ("Bütün PLC'leri anında kapatıp tesisi durdurmak, nedeni sonra aramak",
               "Aniden durdurma OT'de kendi başına tehlike olabilir (basınç, ısı, şebeke dengesi); önce kontrollü müdahale."),
              ("Şüpheli IP'ye karşı tarama ve sızma denemesi yaparak onu geri 'hacklemek'",
               "Savunmacı yetkisi dışına çıkmak yasaldır ve riskli; üstelik canlı süreci tehlikeye atabilir. İzle, engelle, raporla."),
              ("Sadece PLC'nin parolasını değiştirip diğer önlemleri sonraya bırakmak",
               "Modbus protokolünde kimlik doğrulama yoktur; ağdan erişebilen herkes parolasız yazabilir. Tek başına çözüm değil."),
          ]),
          ("Sorun: yetkisiz bir cihaz PLC'ye ulaşabiliyor. Kökü nerede kapatılır?",
           "Hem ağ katmanında (kim ulaşabilir) hem fiziksel katmanda (anahtar) düşün.",
           "Doğru cevap ağı bölmeyi ve salt-okunur korumayı birleştirir; tesisi aniden durdurmaz."),
          puan=30, baslik="Doğru müdahale"),
    Gorev("Modbus kullanan bir ortamda **yalnızca izleme (ağ kaydı) neden yetmez**, ek olarak ne gerekir?",
          Secmeli([
              ("Protokolde kimlik doğrulama yoktur; ağ ayrımı ve yazma kaynaklarını sınırlayan kurallar da gerekir",
               "Doğru. İzleme olayı **fark ettirir**, ağ ayrımı ise **engeller**. İkisi birlikte savunma katmanını oluşturur."),
              ("İzleme yeterlidir; saldırgan kayıt tutulduğunu görünce kendiliğinden vazgeçer",
               "Kayıt caydırıcı olabilir ama saldırıyı durdurmaz; yazma komutu kayıt tutulurken de işler."),
              ("Modbus şifreli bir protokoldür, bu yüzden izlemede içeriği görmek mümkün değildir",
               "Klasik Modbus şifresizdir; asıl sorun şifre olmayışı ve kimlik doğrulamanın bulunmamasıdır."),
              ("İzleme yerine PLC'lerin internete açılması gerekir ki dış uzmanlar bakabilsin",
               "OT cihazlarını internete açmak risk yaratır; erişim kontrollü, kapalı ağlarda tutulur."),
          ]),
          ("Kayıt tutmak olayı **sonradan** gösterir. Önlemek için ne gerekir?",
           "Modbus'ta 'kimsin?' sorusu yok: kim ulaşabilirse yazabilir.",
           "Çözüm iki katmanlı: görünürlük (izleme) ve erişim kısıtı (ağ ayrımı)."),
          puan=25, baslik="İzleme tek başına yetmez"),
]

SEVIYE = Seviye(
    kimlik="c25b02",
    cilt=25,
    bolum=2,
    baslik="Bir OT Olayı: Anormal Komut",
    brifing="""
Selin kayıtları masaya koydu: "**<<musteri>>** (<<sektor>>): <<olay>> <<kisi>> bu sabahki olayın
dört kaydını gönderdi: ağ izleme, envanter, alarm kaydı ve operatör defteri."

Deniz soruyor: "Kim, nereden, ne zaman, hangi PLC'ye ne gönderdi; sistem ve operatör ne zaman fark etti?"
Mert hatırlatıyor: "Biz yalnızca **geçmiş kayıtları** okuyoruz; hiçbir cihaza bağlanmıyoruz. Amaç, olayın
zaman çizelgesini çıkarıp doğru savunmayı önermek."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Olay, klasik bir OT dizisiydi: yetkisiz bir IP önce PLC'leri okuyarak tanıdı, sonra tek bir yazma komutuyla
süreci tehlikeli bir değere çekti. Alarm kısa sürede çaldı, operatör fark edip elle düzeltti ve BT ekibi kaynağı
engelledi. Saldırgan perspektifi: Modbus'ta kimlik doğrulama olmadığından erişen yazabilir; keşif yazmadan önce
gelir. Savunma perspektifi: ağı bölmek, yazma kaynaklarını yetkili cihazlara sınırlamak, kritik PLC'lerde fiziksel
salt-okunur anahtar kullanmak ve ilk yetkisiz okumada bile uyarı üretmek. Alarm gecikmesini ve operatör müdahale
süresini ölçmek bir sonraki olayı kısaltır.
""",
    gercek_hayat="""
- **Ukrayna elektrik şebekesi (Aralık 2015 ve Aralık 2016):** Saldırganlar önce ağa yerleşip keşif yaptı,
  sonra bölgesel dağıtım şirketlerinde SCADA üzerinden kesicileri uzaktan açtı; yüz binlerce kişi saatlerce
  elektriksiz kaldı. 2016'daki olayda endüstriyel protokolleri konuşan özel bir zararlı kullanıldı. Ders:
  ağ ayrımı, çok faktörlü uzaktan erişim ve elle (manuel) işletme prosedürü hayati.
- **Oldsmar su tesisi (Şubat 2021):** ABD'de bir su arıtma tesisinde uzaktan erişimle kimyasal dozu tehlikeli
  seviyeye çıkarma girişimi, bir operatörün ekranda hareket eden imleci fark etmesiyle geri alındı.
  Ders: operatör dikkati ve izleme birbirini tamamlar; uzaktan erişim kısıtlanmalı.
- **Pratikte:** OT olay müdahalesinde önce **süreci güvenli tutmak** gelir (aniden durdurmak da risktir), sonra
  kayıtlardan zaman çizelgesi çıkarılır. Tipik önlemler: segmentasyon, yazma kaynağı beyaz listesi, protokol
  izleme ve fiziksel salt-okunur anahtarlar.
""",
    sure_hedef_dk=35,
)
