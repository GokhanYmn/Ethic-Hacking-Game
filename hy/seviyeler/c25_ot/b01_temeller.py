"""Cilt 25 · Bölüm 1 — Endüstriyel Sistemlere Giriş ve İzleme.

SAVUNMACI/İZLEME ODAKLI: oyuncu bir tesisin OT (operasyonel teknoloji) güvenlik analistidir. Hiçbir
endüstriyel cihaza bağlanılmaz, hiçbir komut gönderilmez; yalnızca kurgusal bir Modbus trafik
kaydı (`modbus_trafik.csv`) ve cihaz envanteri (`varliklar.csv`) okunur.

Veri: çoğunlukla okuma (fonksiyon 3); yetkili HMI/mühendislik istasyonlarının normal yazmaları
(6 ve 16) gürültüdür. İçine yetkisiz bir IP'den gelen TEK tehlikeli yazma gömülüdür.

Vakalar: su arıtma, enerji dağıtımı, metal üretim hattı (hepsi kurgusal). Bu modülün veri üreticisi
(`trafik_uret`, `SENARYOLAR`) 2. bölüm tarafından da kullanılır.

Determinizm: `uret` ağır veriyi saklamaz, `_alt` alt-tohumunu saklar; `uret` ve `yaz` aynı
`random.Random(_alt)` ile veriyi yeniden üretir (`_tohum` motor tarafından ezilir).
"""
from __future__ import annotations

import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import csv_yaz, sec_doldur, sh

# okunan register: (ad, alt, üst); yazılan register: (ad, alt, üst). İlk PLC tehlikeli hedeftir.
SENARYOLAR = [
    {"kod": "su", "musteri": "Berrak Su Arıtma Tesisi", "sektor": "su arıtma", "kisi": "Hüseyin Bey (tesis müdürü)",
     "olay": "Tesisin içme suyu hattında klor dozu ayarı bir ara kendiliğinden oynadı; operatörler ekranda tuhaf bir değer gördü.",
     "plcler": [
         ("PLC-KLOR", "klor dozaj pompası", [("klor_ppm_olcum", 1, 3), ("pompa_durum", 0, 1)], [("klor_hedef_ppm", 2, 3)]),
         ("PLC-TERFI", "terfi pompaları", [("debi_m3s", 40, 90), ("basinc_bar", 3, 6)], [("pompa_hiz_yuzde", 55, 80)]),
         ("PLC-FILTRE", "filtre yıkama", [("filtre_fark_basinc", 1, 4)], [("yikama_suresi_dk", 10, 20)]),
         ("PLC-PH", "pH kontrolü", [("ph_olcum_x10", 68, 76)], [("ph_hedef_x10", 70, 74)]),
     ],
     "tehlike": [300, 350, 400]},
    {"kod": "enerji", "musteri": "Anadolu Enerji Dağıtım Trafo Merkezi", "sektor": "enerji dağıtımı",
     "kisi": "Ayşe Hanım (SCADA sorumlusu)",
     "olay": "Trafo merkezinde koruma röleleriyle ilgili bir alarm düştü; ekip ağdaki trafiğin kayda alındığını hatırladı.",
     "plcler": [
         ("PLC-ROLE", "koruma rölesi", [("hat_akim_a", 150, 380), ("kesici_durum", 0, 1)], [("asiri_akim_esik_a", 400, 450)]),
         ("PLC-TRAFO", "trafo soğutma", [("trafo_sicaklik_c", 45, 70)], [("fan_kademe", 1, 3)]),
         ("PLC-HAT", "hat gerilim ayarı", [("gerilim_kv", 33, 35)], [("gerilim_hedef_kv", 33, 35)]),
         ("PLC-SAYAC", "sayaç ve ölçüm", [("aktif_guc_kw", 800, 2400)], [("olcum_periyot_sn", 5, 15)]),
     ],
     "tehlike": [9000, 9500, 9999]},
    {"kod": "uretim", "musteri": "Çelikpar Metal Üretim", "sektor": "metal üretim hattı",
     "kisi": "Orhan Bey (üretim mühendisi)",
     "olay": "Döküm hattında fırın ısısı bir an olması gerekenden çok yüksek görününce vardiya amiri alarma bastı.",
     "plcler": [
         ("PLC-FIRIN", "ergitme fırını", [("firin_sicaklik_c", 830, 890), ("yakit_debi", 20, 60)], [("firin_hedef_c", 840, 880)]),
         ("PLC-BANT", "taşıma bandı", [("bant_hiz_m_dk", 10, 25)], [("bant_hiz_hedef", 10, 25)]),
         ("PLC-PRES", "şekillendirme presi", [("pres_basinc_bar", 120, 160)], [("pres_esik_bar", 120, 160)]),
         ("PLC-SOGUTMA", "soğutma suyu", [("su_debi_lt", 40, 60)], [("su_debi_hedef", 40, 60)]),
     ],
     "tehlike": [1650, 1700, 1750]},
]


def trafik_uret(rng: random.Random, v: dict) -> dict:
    """Varlık envanteri, Modbus trafiği, olay zamanları. Aynı rng aynı veriyi üretir."""
    ag = rng.choice(["10.20.1", "10.30.5", "172.16.20"])
    no = rng.sample(range(10, 40), 4)
    plc = [{"ip": f"{ag}.{n}", "ad": p[0], "gorev": p[1], "oku": p[2], "yaz": p[3]} for n, p in zip(no, v["plcler"])]
    hak = {"SCADA-SUNUCU": f"{ag}.5", "HMI-1": f"{ag}.51", "HMI-2": f"{ag}.52", "MUH-ISTASYONU": f"{ag}.60"}
    arsiv = f"{ag}.70"
    saldirgan = u.dis_ip(rng)
    varlik = [f"{p['ip']},{p['ad']},PLC,{p['gorev']},-" for p in plc]
    varlik += [f"{hak['SCADA-SUNUCU']},SCADA-SUNUCU,SCADA,izleme ve veri toplama,evet",
               f"{hak['HMI-1']},HMI-1,HMI,operatör paneli (vardiya 1),evet",
               f"{hak['HMI-2']},HMI-2,HMI,operatör paneli (vardiya 2),evet",
               f"{hak['MUH-ISTASYONU']},MUH-ISTASYONU,MUHENDIS,PLC programlama ve bakım,evet",
               f"{arsiv},VERI-ARSIVI,ARSIV,tarihsel veri kaydı (salt okunur),hayir"]
    gun = u.gun(rng) + timedelta(hours=6)
    satir = []

    def ekle(t, kaynak, p, fc, reg, deger):
        satir.append((t, kaynak, p["ip"], fc, reg, deger))

    def deg(r):
        return rng.randint(r[1], r[2])

    for k in range(0, 10800, 300):                      # SCADA her 5 dakikada her PLC'yi yoklar
        for p in plc:
            r = rng.choice(p["oku"])
            ekle(gun + timedelta(seconds=k + rng.randint(0, 20)), hak["SCADA-SUNUCU"], p, 3, r[0], deg(r))
    for _ in range(70):
        p = rng.choice(plc)
        r = rng.choice(p["oku"])
        ekle(gun + timedelta(seconds=rng.randint(0, 10800)), hak[rng.choice(["HMI-1", "HMI-2"])], p, 3, r[0], deg(r))
    for _ in range(25):
        p = rng.choice(plc)
        r = rng.choice(p["oku"])
        ekle(gun + timedelta(seconds=rng.randint(0, 10800)), arsiv, p, 3, r[0], deg(r))
    hedef = plc[0]
    yaz_reg = hedef["yaz"][0][0]
    for i in range(9):                                  # yetkili operatör yazmaları (gürültü)
        p = hedef if i < 3 else rng.choice(plc)
        r = rng.choice(p["yaz"])
        ekle(gun + timedelta(seconds=rng.randint(60, 10700)), hak[rng.choice(["HMI-1", "HMI-2"])], p, 6, r[0], deg(r))
    for _ in range(2):
        p = rng.choice(plc)
        r = rng.choice(p["yaz"])
        ekle(gun + timedelta(seconds=rng.randint(60, 10700)), hak["MUH-ISTASYONU"], p, 16, r[0], deg(r))
    # ---- olay
    t_yaz = gun + timedelta(seconds=rng.randint(3600, 8400))
    t_alarm = t_yaz + timedelta(seconds=rng.randint(35, 110))
    t_fark = t_alarm + timedelta(seconds=rng.randint(60, 150))
    t_duzelt = t_fark + timedelta(seconds=rng.randint(40, 120))
    t_engel = t_duzelt + timedelta(seconds=rng.randint(600, 1200))
    # olay penceresinde aynı register'a başka (gürültü) yazma kalmasın: düzeltme açıkça ayırt edilsin
    satir = [x for x in satir if not (x[2] == hedef["ip"] and x[4] == yaz_reg and x[3] in (6, 16)
                                      and t_yaz - timedelta(seconds=60) <= x[0] <= t_duzelt + timedelta(seconds=60))]
    n_kesif = rng.randint(3, 5)
    for i in range(n_kesif):
        p = plc[i % 4]
        r = p["oku"][0]
        ekle(t_yaz - timedelta(seconds=150 - i * 25 + rng.randint(0, 5)), saldirgan, p, 3, r[0], deg(r))
    tehlike = rng.choice(v["tehlike"])
    fc = rng.choice([6, 16])
    ekle(t_yaz, saldirgan, hedef, fc, yaz_reg, tehlike)
    duzelt_deger = rng.randint(hedef["yaz"][0][1], hedef["yaz"][0][2])
    ekle(t_duzelt, hak["HMI-1"], hedef, 6, yaz_reg, duzelt_deger)
    satir.sort(key=lambda x: x[0])
    trafik = [f"{t:%Y-%m-%d %H:%M:%S},{k},{h},{f},{r},{d}" for t, k, h, f, r, d in satir]
    return {
        "plc": plc, "hak": hak, "varlik": varlik, "trafik": trafik, "saldirgan": saldirgan,
        "hedef_ip": hedef["ip"], "hedef_ad": hedef["ad"], "reg": yaz_reg, "tehlike": tehlike,
        "yazma_sayisi": sum(1 for x in satir if x[3] in (6, 16)), "n_kesif": n_kesif,
        "duzelt_deger": duzelt_deger,
        "t": {"yazma": t_yaz, "alarm": t_alarm, "fark": t_fark,
              "duzelt": t_duzelt, "engel": t_engel},
    }


def uret(rng):
    v = dict(rng.choice(SENARYOLAR))
    alt = rng.randint(1, 10**9)
    d = trafik_uret(random.Random(alt), v)
    return {
        "vaka": f"{v['musteri']} — Modbus trafiği",
        "_alt": alt, "v": v,
        "metin": {"musteri": v["musteri"], "sektor": v["sektor"], "kisi": v["kisi"], "olay": v["olay"]},
        "cevaplar": {"kaynak": d["saldirgan"], "hedef": d["hedef_ip"], "reg": d["reg"],
                     "deger": d["tehlike"], "yazma_sayisi": d["yazma_sayisi"]},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = trafik_uret(random.Random(s["_alt"]), v)
    csv_yaz(lab / "varliklar.csv", "ip,ad,tur,gorev,yazma_yetkisi", d["varlik"])
    csv_yaz(lab / "modbus_trafik.csv", "zaman,kaynak,hedef_plc,fonksiyon,register,deger", d["trafik"])
    u.yaz(lab / "OKUBENI.txt",
          f"{v['musteri']} — OT ağ izleme klasörü (hepsi KURGUSAL; hiçbir cihaza bağlanılmaz)\n\n"
          "varliklar.csv      : PLC / HMI / SCADA envanteri; son sütun hangi cihazın PLC'ye YAZMA yetkisi olduğunu söyler\n"
          "modbus_trafik.csv  : ağ izleme cihazının kaydettiği Modbus istekleri\n"
          "                     (zaman, kaynak, hedef_plc, fonksiyon, register, deger)\n\n"
          "Modbus fonksiyon kodları:  3 = register OKU   6 = tek register YAZ   16 = çok register YAZ\n")


def coz(lab: Path, s: dict) -> dict:
    sorgu = ("awk -F, 'NR==FNR{if($5==\"evet\")y[$1]=1;next} ($4==6||$4==16)&&!($2 in y){print %s}' "
             "varliklar.csv modbus_trafik.csv | sort -u")
    cozum = {
        1: sh(sorgu % "$2", lab),
        2: sh(sorgu % "$3", lab),
        3: sh(sorgu % "$5", lab),
        4: sh(sorgu % "$6", lab),
        5: sh("awk -F, '$4==6||$4==16' modbus_trafik.csv | wc -l", lab),
    }
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


def _kaynak_hata(g, beklenen, b):
    d = trafik_uret(random.Random(b.senaryo["_alt"]), b.senaryo["v"])
    if g in d["hak"].values():
        return "Bu IP envanterde yazma yetkisi **olan** bir cihaz (operatör ya da mühendislik). Yetkisiz olanı ara."
    return None


def _hedef_hata(g, beklenen, b):
    d = trafik_uret(random.Random(b.senaryo["_alt"]), b.senaryo["v"])
    if g == d["saldirgan"]:
        return "Bu, komutu gönderen (kaynak) IP. Soru, komutu **alan** PLC'yi soruyor."
    return None


def _deger_hata(g, beklenen, b):
    d = trafik_uret(random.Random(b.senaryo["_alt"]), b.senaryo["v"])
    if g == str(d["duzelt_deger"]):
        return "Bu, yetkili bir operatörün yazdığı normal değer. Yetkisiz kaynağın yazdığına bak."
    return None


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n in (beklenen + 1, beklenen - 1):
        return "Bir fark var: başlık satırını saymış ya da fonksiyon 16'yı atlamış olabilirsin (yazma = 6 **ve** 16)."
    return None


ADIMLAR = [
    Adim("OT nedir, IT'den farkı ne?", """
Selin: "Şimdiye kadar hep bilgi işlem (IT) ağlarına baktık: bilgisayarlar, sunucular, veri. Bugün
**OT (operasyonel teknoloji)** var: **fiziksel süreci** yöneten sistemler. Su arıtma, trafo merkezi,
döküm hattı. Orada bir bilgisayar komutu bir pompayı, bir valfi, bir fırını hareket ettirir."

Parçalar şunlar:
- **PLC** (programlanabilir mantık denetleyici): sahadaki küçük endüstriyel bilgisayar; sensörü okur, pompayı/valfi sürer.
- **HMI** (insan-makine arayüzü): operatörün ekranı; değerleri görür, ayar yapar.
- **SCADA**: tesisteki tüm PLC'leri uzaktan izleyen ve toplayan merkezi sistem.
- **Modbus**: bunların konuştuğu eski ve çok yaygın protokol (iletişim dili). Kimlik doğrulaması yoktur.

Bu ortamın klasörüne bak (hiçbir cihaza bağlanmıyoruz, yalnızca kayıtlı trafiği okuyoruz):
""", komut="cat OKUBENI.txt", sonra="""
IT'de öncelik sırası **gizlilik > bütünlük > erişilebilirlik**tir. OT'de tersine döner:
**erişilebilirlik ve güvenlik** (süreç durmasın, kimse zarar görmesin) önce gelir. Bir sunucuyu
yeniden başlatmak olağandır; bir su arıtmayı ya da şebekeyi aniden durdurmak olağan değildir.
"""),
    Adim("Cihaz envanteri", """
OT'de savunmanın ilk kuralı: **ne var, kim neye ne yapabilir** bilmek. Envanter dosyasına bak:
""", komut="cat varliklar.csv", sonra="""
PLC'ler hedeftir. SCADA sunucusu, HMI'lar ve mühendislik istasyonu **yazma yetkili** (`evet`).
Veri arşivi yalnızca **okur** (`hayir`). Envanterde olmayan bir IP'nin PLC ile konuşması başlı
başına bir alarm sebebidir.
"""),
    Adim("Modbus trafiğine ilk bakış", """
Ağ izleme cihazı, ağdaki Modbus isteklerini kaydediyor. Her satır: kim, hangi PLC'ye, hangi
işlemi (`fonksiyon`), hangi register'a (PLC'nin bellek hücresi, örn. bir ayar değeri) ne `deger`le.
""", komut="head -5 modbus_trafik.csv", sonra="""
Sütunlar: `zaman, kaynak, hedef_plc, fonksiyon, register, deger`. Çoğu satır `3` yani **okuma**:
SCADA ve HMI'lar değerleri sürekli yoklar. Normal trafik budur: sıkıcı, düzenli, tekrarlı.
"""),
    Adim("Fonksiyon koduna göre say", """
Önce trafiğin dağılımına bak: hangi fonksiyondan kaç tane var? `cut` ile 4. sütunu al, `sort | uniq -c`
ile say.
""", komut="cut -d, -f4 modbus_trafik.csv | tail -n +2 | sort | uniq -c | sort -rn", sonra="""
Okuma (3) açık ara en çok. **Yazma** (6 ve 16) azdır; ama fiziksel süreci değiştirebilen tek şey
yazmadır. İzleme stratejisi: az olan ve tehlikeli olan şeye odaklan, yazmaları incele.
"""),
    Adim("awk ile yazma komutlarını ayıkla", """
`awk -F,` satırı virgülden böler; `$4` dördüncü sütun (fonksiyon). `||` "ya da" demektir.
Fonksiyonu 6 **ya da** 16 olan satırları listele:
""", komut="awk -F, '$4==6||$4==16' modbus_trafik.csv", sonra="""
Bunların çoğu meşru: operatörler ayar değiştirir, mühendis bakım yapar. Soru şu: **kaynak IP'si yazma
yetkili listede mi?** Kaynağın olduğu sütun `$2`.
"""),
    Adim("Yetkili kaynaklar", """
Envanterde `yazma_yetkisi` sütunu (5.) `evet` olanların IP'lerini çıkar:
""", komut="awk -F, '$5==\"evet\"{print $1}' varliklar.csv", sonra="""
Şimdi iki liste var: yazma yetkili IP'ler ve yazma komutlarının kaynakları. Aradığın, ikincide olup
birincide **olmayan** IP. (Liste kısa; gözle karşılaştırabilirsin.)

**Hacker gözüyle:** Modbus'ta parola ya da kimlik doğrulama yoktur: PLC'ye ulaşabilen herkes
yazabilir. Bu yüzden OT güvenliği "kim ulaşabilir?" sorusuna (ağ ayrımı, güvenlik duvarı) ve
"kim ne yazdı?" sorusuna (izleme) dayanır. Biz burada yalnızca ikincisini yapıyoruz.
"""),
]

GOREVLER = [
    Gorev("`modbus_trafik.csv`'de envanterde **yazma yetkisi olmayan** bir kaynaktan PLC'ye yazma komutu "
          "(fonksiyon 6 ya da 16) gelmiş. Bu **kaynak IP** hangisi?",
          IP("kaynak", sik_hatalar=_kaynak_hata),
          ("Önce yazma komutlarını ayıkla; sonra kaynaklarını `varliklar.csv`'deki yetkili IP'lerle karşılaştır.",
           "`awk -F, '$4==6||$4==16{print $2}' modbus_trafik.csv | sort -u` yazma yapan tüm kaynakları verir; "
           "hangisi `varliklar.csv`'de yok ya da `hayir`?",
           "`awk -F, '$5==\"evet\"{print $1}' varliklar.csv` yetkililer; bu listede **olmayan** kaynak aranan IP."),
          puan=40, baslik="Yetkisiz kaynak"),
    Gorev("Bu yetkisiz kaynak **hangi PLC'ye** yazma komutu göndermiş? PLC'nin IP adresini yaz.",
          IP("hedef", sik_hatalar=_hedef_hata),
          ("Kaynağı bulduktan sonra aynı satırın `hedef_plc` sütununa bak.",
           "`grep` ile o IP'nin satırlarını süz; yazma olan satırın 3. sütunu hedeftir.",
           "`grep KAYNAK_IP modbus_trafik.csv | awk -F, '$4==6||$4==16'` ve çıktıdaki 3. sütun."),
          puan=35, baslik="Hedef PLC"),
    Gorev("Yetkisiz kaynak **hangi register'a** yazmış? Register adını yaz.",
          Metin("reg", bicim="register adı (örn. xxx_yyy)"),
          ("Aynı satırda register sütunu var.",
           "5. sütun: `awk -F, '...{print $5}'`.",
           "`grep KAYNAK_IP modbus_trafik.csv | awk -F, '$4==6||$4==16{print $5}'`"),
          puan=35, baslik="Register"),
    Gorev("Yetkisiz kaynağın o register'a yazdığı **değer** nedir? Aynı register'a yetkili operatörler de "
          "yazmış; o normal değerlere değil, yetkisizin yazdığına bak.",
          Sayi("deger", sik_hatalar=_deger_hata),
          ("Değer, satırın son sütunu.",
           "`grep KAYNAK_IP modbus_trafik.csv | awk -F, '$4==6||$4==16{print $6}'`",
           "Aynı register'a yazılan normal değerlerle kıyasla: yetkisizin yazdığı, olağan aralığın çok dışında."),
          puan=35, baslik="Yazılan değer"),
    Gorev("Trafik kaydında yetkili olanlar **dahil** toplam kaç yazma komutu (fonksiyon 6 ve 16) var?",
          Sayi("yazma_sayisi", sik_hatalar=_toplam_hata),
          ("Yazma = fonksiyon 6 **ya da** 16. Başlık satırına dikkat.",
           "Önce `awk` ile süz, sonra satır say: `... | wc -l`.",
           "`awk -F, '$4==6||$4==16' modbus_trafik.csv | wc -l` (başlık satırı süzülmez: fonksiyon sütununda sayı yok)"),
          puan=30, baslik="Yazma sayısı"),
    Gorev("OT ortamında güvenlik öncelikleri IT'den nasıl ayrışır?",
          Secmeli([
              ("Erişilebilirlik ve güvenlik (süreç durmamalı, kimse zarar görmemeli) önce gelir; gizlilik sonra",
               "Doğru. OT'de bir şebekeyi ya da arıtmayı aniden durdurmak ağır sonuç doğurur; bu yüzden "
               "yama ve yeniden başlatma bile planlı bakım penceresi ister."),
              ("Gizlilik her zaman birinci önceliktir, çünkü PLC'ler müşteri verisi tutar ve saklar",
               "PLC'ler müşteri verisi değil, süreç verisi (sıcaklık, basınç, ayar) tutar; asıl risk fiziksel etkidir."),
              ("OT'de güvenlik önceliği yoktur; yalnızca üretim hızı ve maliyet önemlidir, hep öyledir",
               "Tersine: güvenlik (can ve çevre) ve süreklilik OT'de en yüksek önceliklerdir."),
              ("Cihazlar her hafta yamalanır ve yeniden başlatılır; kesinti hiçbir zaman sorun olmaz",
               "Sürekli çalışan bir süreçte yeniden başlatma kolay değildir; bu IT alışkanlığı OT'de zarar verebilir."),
          ]),
          ("IT'de en kritik şey veri sızıntısıdır. OT'de en kritik şey ne olabilir?",
           "Bir pompa ya da fırın durursa ya da yanlış çalışırsa neler olur?",
           "OT'de öncelik: süreç sürekliliği ve insan/çevre güvenliği."),
          puan=25, baslik="IT ve OT farkı"),
    Gorev("Bulduğun yetkisiz yazma komutu neden **bir veri sızıntısından çok daha tehlikeli** olabilir?",
          Secmeli([
              ("Komut fiziksel süreci (dozaj, ısı, elektrik) değiştirir; zarar insana ve ekipmana yansır",
               "Doğru. OT'de yazma, gerçek dünyada bir şeyin hareket etmesi demektir; geri alması çoğu zaman mümkün değildir."),
              ("Yazma komutu PLC'deki kayıtları silip veriyi yok eder, fiziksel bir etkisi olmaz",
               "PLC'ye yazılan değer bir ayardır ve süreci doğrudan sürer; asıl etki fizikseldir."),
              ("Yazma komutu yalnızca HMI ekranındaki rakamı değiştirir, süreci hiç etkilemez",
               "Register bir ekran etiketi değil, denetleyicinin kullandığı gerçek ayardır."),
              ("Yazma komutları internet bağlantısını keser ve tesisi uzaktan erişime kapatır",
               "Modbus yazması ağ bağlantısını kesmez; yaptığı şey süreci sürmek ya da bozmaktır."),
          ]),
          ("Yazılan register'ın bir ayar olduğunu düşün: pompa, fırın ya da koruma eşiği.",
           "Yanlış bir ayar fiziksel dünyada ne yapar? Veri sızıntısında ise sadece bilgi dışarı çıkar.",
           "Fark: sızıntı bilgiyi etkiler; yetkisiz yazma süreci ve dolayısıyla insanları etkiler."),
          puan=25, baslik="Fiziksel sonuç"),
]

SEVIYE = Seviye(
    kimlik="c25b01",
    cilt=25,
    bolum=1,
    baslik="Endüstriyel Sistemlere Giriş ve İzleme",
    brifing="""
Selin yeni bir cilt açtı: "Bugün sunucu değil, **fiziksel süreç** konuşacağız. **<<musteri>>**
(<<sektor>>): <<olay>> <<kisi>> ağ izleme cihazının kaydını ve cihaz envanterini bize verdi."

Mert uyarıyor: "Burada **saldırı yok, yalnızca izleme var**. Hiçbir PLC'ye bağlanmıyoruz, hiçbir komut
göndermiyoruz; kayıtları okuyup anormal olanı buluyoruz." Deniz ekliyor: "Hedefimiz: kim, hangi PLC'ye,
neyi, hangi değerle yazdı ve buna yetkisi var mıydı?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Trafiğin neredeyse tamamı okumaydı; tehlikeli olan tek şey, envanterde yazma yetkisi olmayan bir IP'nin
tek bir PLC register'ına yazdığı olağandışı değerdi. Saldırgan perspektifi: Modbus kimlik doğrulaması
istemez, PLC'ye ulaşabilen yazabilir; keşif okumalarıyla ortamı tanır ve tek komutla süreci bozar.
Savunma perspektifi: envanteri bil, yazma komutlarını ayrıca izle, yetkili kaynak listesiyle karşılaştır
ve ağı bölerek yalnızca yetkili cihazların PLC'ye ulaşmasına izin ver. OT'de önce süreç sürekliliği ve
insan güvenliği gelir.
""",
    gercek_hayat="""
- **Stuxnet (2010'da keşfedildi):** İran'daki nükleer zenginleştirme tesisinde PLC mantığını sessizce
  değiştirerek santrifüjlere zarar verdiği anlaşılan zararlı yazılım; ekranda her şey normal görünürken
  fiziksel süreç bozulmuştu. Ders: kontrol verisi ve komutlar güvenilir değilse operatör ekranı da güvenilmez.
- **Oldsmar su tesisi (Şubat 2021):** ABD'de bir su arıtma tesisinde uzaktan erişimle sodyum hidroksit
  (lye) dozu tehlikeli seviyeye çıkarıldı; bir operatör imlecin ekranda kendiliğinden hareket ettiğini
  fark edip değeri geri aldı. Ders: izleme, erişim kısıtı ve dikkatli operatör birlikte çalışmalı.
- **Pratikte:** OT izlemede amaç, protokol trafiğinden "kim, kime, ne yazdı" sorusunu çıkarmak; yetkili
  yazma listesi dışındaki her yazma komutu uyarı üretir. Önlem ağ segmentasyonu (ağı bölmek) ve salt-okunur
  yetkilerdir.
""",
    sure_hedef_dk=30,
)
