"""Cilt 22 · Bölüm 3 — Cüzdan, DeFi ve Savunma.

Beceri: cüzdan envanterini okuyup riski görmek (sıcak/soğuk/donanım, imza eşiği, anahtarın yeri),
kurgusal bir kripto borsası olay raporunu ve yönetim konsolu logunu çözümlemek, olaydan ders çıkarmak
(çoklu imza, anahtarın dışa aktarılamaması, limit ve izleme) ve düzeltmeyi veride uygulamak. MASAK/uyum
konusu genel ve doğru düzeyde anlatılır; ayrıntılı düzenleme maddesi verilmez.

Vakalar: üç kurgusal kripto borsası (Liman Kripto, Kasa-X Borsa, Ayrıt Dijital Varlık). Tüm adresler
ve hesaplar kurgusaldır; gerçek bir zincir ya da cüzdan yoktur.
"""
from __future__ import annotations

import csv
import random
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, IP, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur, sh

VAKALAR = [
    {"ad": "Liman Kripto Borsası", "alan": "limankripto.lab", "kisi": "Aylin Hanım (güvenlik sorumlusu)",
     "login_ek": "mfa=sifirlandi_yeni_cihaz", "limit_ek": "onaylayan=-",
     "kok_neden": "Bir operasyon yöneticisinin hesabı, kimlik avı sonrası MFA sıfırlamasıyla ele geçirildi. Hesabın "
                  "sıcak cüzdan anahtarlarını dışa aktarma yetkisi vardı.",
     "olay": "Liman Kripto Borsası'nın sıcak cüzdanlarından birinden gece saatlerinde izinsiz çıkış oldu."},
    {"ad": "Kasa-X Borsa", "alan": "kasax.lab", "kisi": "Barış Bey (altyapı müdürü)",
     "login_ek": "oturum=ci_jetonu", "limit_ek": "onaylayan=-",
     "kok_neden": "Bir yazılım ekibinin derleme (CI) sistemindeki yönetim jetonu, bir hata ayıklama çıktısında düz "
                  "metin olarak yazılıp ortak bir kanala düşmüştü. O jetonla yönetim konsoluna girilebiliyordu.",
     "olay": "Kasa-X Borsa'nın izleme sistemi, sıcak cüzdanlardan birinde alışılmadık büyük bir çıkış alarmı verdi."},
    {"ad": "Ayrıt Dijital Varlık", "alan": "ayrit.lab", "kisi": "Merve Hanım (iç denetim)",
     "login_ek": "oturum=vpn_disi", "limit_ek": "onaylayan=kendi_kendine",
     "kok_neden": "Bir yöneticinin ele geçirilen hesabı hem çekim limitini yükseltebiliyor hem de kendi talebini "
                  "kendisi onaylayabiliyordu: ikinci bir onaylayıcı (maker-checker) zorunlu değildi.",
     "olay": "Ayrıt Dijital Varlık'ta müşteri çekimleri aniden durdu; iç denetim sıcak cüzdan hareketlerinde "
             "tutarsızlık buldu."},
]

ASAMALAR = {
    "giris": "Yönetici hesabına yabancı bir IP'den giriş",
    "export": "Sıcak cüzdan anahtarının dışa aktarılması",
    "limit": "Cüzdanın çekim limitinin yükseltilmesi",
    "transfer": "Dış adreslere para çıkışı",
    "alarm": "İzleme sisteminin büyük çıkış alarmı vermesi",
}
DOGRU_SIRA = ["giris", "export", "limit", "transfer", "alarm"]
BASLIK = "cuzdan,tur,varlik,bakiye_tl,imza,anahtar_yeri"


def _hex(rng, n=8):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def veri_uret(rng: random.Random, v: dict) -> dict:
    limit = rng.choice([2000000, 2500000, 3000000])
    cuz = []
    for i in range(1, rng.randint(3, 4) + 1):
        cuz.append([f"COLD-{i:02d}", "soguk", rng.choice(["BTC", "ETH", "USDT"]), rng.randint(40, 120) * 1_000_000, "3/5", "kasa"])
    for i in range(1, 3):
        cuz.append([f"HW-{i:02d}", "donanim", rng.choice(["BTC", "ETH"]), rng.randint(8, 25) * 1_000_000, "2/3",
                    "donanim_cihazi"])
    # sıcak cüzdanlar: üç tanesi tek imzalı (ikisi eşiğin üstünde), biri çok imzalı büyük bakiyeli (dokunulmamalı)
    en_buyuk = limit + rng.randint(2, 6) * 500_000
    sicak = [
        ["HOT-01", "sicak", "BTC", en_buyuk, "1/1", "sunucu_dosyasi"],
        ["HOT-02", "sicak", "ETH", limit + rng.randint(1, 3) * 100_000, "1/1", rng.choice(["sunucu_dosyasi", "yonetici_laptopu"])],
        ["HOT-03", "sicak", "USDT", limit - rng.randint(3, 8) * 100_000, "1/1", "sunucu_dosyasi"],
        ["HOT-04", "sicak", "BTC", limit + rng.randint(3, 9) * 500_000, "2/3", "hsm"],
    ]
    rng.shuffle(sicak)
    ad = {x[0]: i for i, x in enumerate(sicak)}
    # dosyada numaralar karışık dursun ama kimlikler sabit kalsın
    cuz += sicak
    rng.shuffle(cuz)
    hedef = max((x for x in cuz if x[4] == "1/1"), key=lambda x: x[3])[0]
    return {"cuzdanlar": cuz, "limit": limit, "hedef": hedef}


def log_uret(rng: random.Random, v: dict, d: dict) -> dict:
    gun = u.gun(rng)
    kullanicilar = [f"ops-{x}" for x in u.isimler(rng, 4)]
    kurban = rng.choice(kullanicilar)
    sald_ip = u.dis_ip(rng)
    satirlar = []

    def ekle(t, kul, eylem, ip, ek=""):
        satirlar.append((t, f"{t:%Y-%m-%dT%H:%M:%S}+03:00 user={kul} action={eylem} ip={ip}" + (f" {ek}" if ek else "")))

    cuzdanlar = [x[0] for x in d["cuzdanlar"]]
    ic = {k: f"10.20.{rng.randint(1, 9)}.{rng.randint(10, 250)}" for k in kullanicilar}
    for k in kullanicilar:                              # gündüz: gerçek yönetici trafiği
        for _ in range(rng.randint(5, 9)):
            t = gun + timedelta(seconds=rng.randint(8 * 3600 + 1800, 18 * 3600))
            ekle(t, k, "LOGIN", ic[k], "result=ok")
            ekle(t + timedelta(minutes=2), k, rng.choice(["VIEW_BALANCE", "REPORT_EXPORT", "LIMIT_VIEW"]), ic[k],
                 f"wallet={rng.choice(cuzdanlar)} result=ok")
    sus = rng.choice([k for k in kullanicilar if k != kurban])   # reddedilen meşru deneme (yanlış alarm tuzağı)
    t = gun + timedelta(hours=11, minutes=rng.randint(0, 50))
    ekle(t, sus, "KEY_EXPORT", ic[sus], f"wallet={rng.choice(cuzdanlar)} result=denied")
    for _ in range(rng.randint(3, 5)):                  # meşru iç aktarımlar (soğuk cüzdana süpürme)
        t = gun + timedelta(seconds=rng.randint(9 * 3600, 17 * 3600))
        ekle(t, "otomasyon", "TRANSFER", "10.20.0.5",
             f"wallet=HOT-0{rng.randint(1, 4)} to=int:COLD-01 amount_tl={rng.randint(5, 40) * 100000} result=ok")
    hedef = d["hedef"]
    bas = gun + timedelta(days=1, hours=rng.randint(1, 2), minutes=rng.randint(0, 50))
    ekle(bas, kurban, "LOGIN", sald_ip, f"result=ok {v['login_ek']}")
    ekle(bas + timedelta(minutes=2, seconds=rng.randint(0, 50)), kurban, "KEY_EXPORT", sald_ip, f"wallet={hedef} result=ok")
    ekle(bas + timedelta(minutes=5, seconds=rng.randint(0, 50)), kurban, "LIMIT_CHANGE", sald_ip,
         f"wallet={hedef} yeni_limit=99999999 result=ok {v['limit_ek']}")
    toplam = 0
    t = bas + timedelta(minutes=8)
    for _ in range(rng.randint(3, 5)):
        t += timedelta(minutes=rng.randint(1, 4), seconds=rng.randint(0, 50))
        tutar = rng.randint(4, 18) * 100000
        toplam += tutar
        ekle(t, kurban, "TRANSFER", sald_ip, f"wallet={hedef} to=ext:0xKRG{_hex(rng, 10)} amount_tl={tutar} result=ok")
    ekle(t + timedelta(minutes=rng.randint(3, 9)), "izleme", "ALARM", "10.20.0.9", f"wallet={hedef} kural=buyuk_cikis result=ok")
    satirlar.sort(key=lambda x: x[0])
    return {"satirlar": [s for _, s in satirlar], "kurban": kurban, "sald_ip": sald_ip, "toplam": toplam,
            "sus": sus}


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    tohum = rng.randint(1, 10**9)
    d = veri_uret(random.Random(tohum), v)
    o = log_uret(random.Random(tohum + 1), v, d)
    sira = list(ASAMALAR)
    rng.shuffle(sira)
    numara = {k: i for i, k in enumerate(sira, 1)}
    return {
        "vaka": f"{v['ad']} — sıcak cüzdan olayı",
        "v": v, "tohum": tohum, "sira": sira, "limit": d["limit"],
        "metin": {"musteri": v["ad"], "kisi": v["kisi"], "olay": v["olay"], "limit": f"{d['limit']:,}".replace(",", "."),
                  "hedef": d["hedef"], "limit_ham": d["limit"]},
        "cevaplar": {
            "tek_imza": d["hedef"],
            "kullanici": o["kurban"],
            "ip": o["sald_ip"],
            "toplam": o["toplam"],
            "dizi": [numara[k] for k in DOGRU_SIRA],
            "sicak_sayi": sum(1 for x in d["cuzdanlar"] if x[1] == "sicak" and x[4] == "1/1"),
        },
        "_sus": o["sus"],
        "_limit_cuz": [x[0] for x in d["cuzdanlar"] if x[4] == "1/1" and x[3] >= d["limit"]],
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    d = veri_uret(random.Random(s["tohum"]), v)
    o = log_uret(random.Random(s["tohum"] + 1), v, d)
    u.yaz(lab / "cuzdanlar.csv", BASLIK + "\n" + "\n".join(",".join(str(c) for c in x) for x in d["cuzdanlar"]) + "\n")
    u.yaz(lab / "olay" / "yonetim_konsolu.log", "\n".join(o["satirlar"]) + "\n")
    u.yaz(lab / "olay" / "asamalar.txt",
          "Olayın beş aşaması (sırası karışık):\n\n" + "\n".join(f"{i}. {ASAMALAR[k]}" for i, k in enumerate(s["sira"], 1)) + "\n")
    u.yaz(lab / "olay" / "olay_raporu.txt",
          f"{v['ad']} — olay raporu (kurgusal, taslak)\n\n"
          f"Özet\n  {v['olay']} Yönetim konsolu logları ve cüzdan envanteri aşağıdaki klasörlerde.\n\n"
          f"Kök neden (inceleme ekibinin ön değerlendirmesi)\n  {v['kok_neden']}\n\n"
          "Etki\n  Müşteri varlıklarının bir kısmı sıcak cüzdandan dış adreslere çıktı; soğuk ve donanım cüzdanlarına\n"
          "  dokunulmadı. Çıkış yapan işlemler zincirde geri alınamaz.\n\n"
          "Aksiyonlar (taslak)\n  - Etkilenen yönetici hesapları kapatıldı, anahtarlar döndürülecek\n"
          "  - Cüzdan politikası yeniden yazılacak (ders çıkarma bölümü boş, doldurulacak)\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — olay inceleme klasörü (kurgusal veri)\n\n"
          "cuzdanlar.csv            : cüzdan envanteri (bakiye_tl = TL karşılığı, imza = gereken/toplam imza)\n"
          "olay/olay_raporu.txt     : inceleme ekibinin taslak raporu\n"
          "olay/yonetim_konsolu.log : yönetim konsolu işlem günlüğü\n"
          "olay/asamalar.txt        : olayın aşamaları (sırası karışık)\n\n"
          f"Yeni politika taslağı: bakiyesi {s['metin']['limit']} TL ve üstü olan HER tek imzalı (1/1) cüzdan\n"
          "çoklu imzaya (2/3) geçirilecek. Düzeltmeyi cuzdanlar_duzeltilmis.csv olarak kaydet.\n")


# ---------------------------------------------------------------- Durum

def _duzeltme(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = Path(b.lab) / "cuzdanlar_duzeltilmis.csv"
    if not yol.is_file():
        return Sonuc(False, "`cuzdanlar_duzeltilmis.csv` yok. `cuzdanlar.csv`'yi değiştirip bu adla kaydet "
                     "(orijinali bozma).")
    d = veri_uret(random.Random(s["tohum"]), s["v"])
    try:
        satirlar = list(csv.reader(yol.read_text(encoding="utf-8").splitlines()))
    except (OSError, csv.Error) as e:
        return Sonuc(False, f"Dosya okunamadı: {e}")
    if not satirlar or ",".join(satirlar[0]) != BASLIK:
        return Sonuc(False, f"Başlık satırı aynen şu olmalı: {BASLIK}", yakin=True)
    gelen = {r[0]: r for r in satirlar[1:] if r}
    if len(gelen) != len(d["cuzdanlar"]):
        return Sonuc(False, f"{len(d['cuzdanlar'])} cüzdan olmalı, dosyada {len(gelen)} var. Satır kaybetme ya da ekleme.", yakin=True)
    for x in d["cuzdanlar"]:
        orijinal = [str(c) for c in x]
        r = gelen.get(x[0])
        if r is None:
            return Sonuc(False, f"{x[0]} cüzdanı dosyada yok.")
        degismeli = x[4] == "1/1" and x[3] >= s["limit"]
        if degismeli:
            if r[:4] != orijinal[:4] or r[5] != orijinal[5]:
                return Sonuc(False, f"{x[0]}: sadece imza sütununu değiştir, diğer alanlara dokunma.", yakin=True)
            if r[4] not in ("2/3", "3/5"):
                return Sonuc(False, f"{x[0]} hâlâ `{r[4]}`: bakiyesi {s['metin']['limit']} TL ve üstü, `2/3` olmalı.", yakin=True)
        elif r != orijinal:
            return Sonuc(False, f"{x[0]} değişmemeli (bakiyesi eşiğin altında ya da zaten çok imzalı). "
                         "Sadece tek imzalı **ve** eşiğin üstündeki cüzdanları değiştir.", yakin=True)
    return Sonuc(True, "Eşiğin üstündeki tek imzalı sıcak cüzdanlar `2/3` oldu; diğerlerine dokunulmadı. Gerçek hayatta bu "
                       "değişiklik cüzdanın yeniden kurulmasını ve anahtarların yeniden dağıtılmasını gerektirir.")


def _tek_hata(g, beklenen, b):
    d = veri_uret(random.Random(b.senaryo["tohum"]), b.senaryo["v"])
    cuz = {x[0]: x for x in d["cuzdanlar"]}
    x = cuz.get(g.upper())
    if x and x[4] != "1/1":
        return f"{x[0]} çok imzalı ({x[4]}). Sadece `1/1` olanlar arasında en çok bakiyeliyi ara."
    if x and x[4] == "1/1":
        return f"{x[0]} tek imzalı ama bakiyesi en yüksek olan değil; tek imzalılar içinde sırala."
    return None


def _kullanici_hata(g, beklenen, b):
    if g == b.senaryo["_sus"].lower():
        return "Bu hesap anahtarı dışa aktarmayı denemiş ama sistem reddetmiş (`result=denied`). Başarılı olanı ara."
    return None


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Fazla: iç aktarımları (`to=int:`) da toplamışsın. Sadece dış adrese (`to=ext:`) çıkanlar."
    return None


def coz(lab: Path, s: dict) -> dict:
    tek = sh("awk -F, 'NR>1 && $5==\"1/1\"' cuzdanlar.csv | sort -t, -k4 -n -r | head -1 | cut -d, -f1", lab)
    kul = sh("grep 'KEY_EXPORT' olay/yonetim_konsolu.log | grep 'result=ok' | awk '{print $2}' | cut -d= -f2", lab)
    ip = sh("grep 'KEY_EXPORT' olay/yonetim_konsolu.log | grep 'result=ok' | grep -o 'ip=[0-9.]*' | cut -d= -f2", lab)
    toplam = sh("grep 'to=ext:' olay/yonetim_konsolu.log | sed 's/.*amount_tl=\\([0-9]*\\).*/\\1/' | awk '{t+=$1} END{print t}'", lab)
    # olay sırası: her aşamanın ilk zaman damgası
    zaman = {}
    kalip = {"giris": f"action=LOGIN ip={ip} ", "export": "action=KEY_EXPORT .*result=ok", "limit": "action=LIMIT_CHANGE",
             "transfer": "to=ext:", "alarm": "action=ALARM"}
    for k, p in kalip.items():
        zaman[k] = sh(f"grep -E '{p}' olay/yonetim_konsolu.log | head -1 | cut -d' ' -f1", lab)
    sira = {k: i for i, k in enumerate(s["sira"], 1)}
    dizi = " ".join(str(sira[k]) for k in sorted(zaman, key=lambda k: zaman[k]))
    sh("awk -F, -v OFS=, -v l=" + str(s["limit"]) + " 'NR>1 && $4>=l && $5==\"1/1\"{$5=\"2/3\"} 1' cuzdanlar.csv "
       "> cuzdanlar_duzeltilmis.csv", lab)
    cozum = {1: tek, 2: kul, 3: ip, 4: toplam, 5: dizi, 6: "", 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Anahtarını kontrol eden varlığını kontrol eder", """
Selin: "Blockchain'de banka da, 'şifremi unuttum' da yok. Varlığın sahibi, **özel anahtarı** kontrol eden
kişidir. Bu yüzden bir borsada güvenliğin kalbi **cüzdan ve anahtar yönetimidir**." Üç cüzdan türü:

- **Sıcak cüzdan:** internete bağlı, kullanışlı ama riskli. Günlük çekimler için küçük bakiyeyle tutulur.
- **Soğuk cüzdan:** çevrimdışı, güvenli; büyük bakiye burada.
- **Donanım cüzdanı:** anahtarı fiziksel cihazda tutar ve dışarı vermez.

Olay klasörünün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Cüzdan envanteri", """
`cuzdanlar.csv`, her cüzdanın türünü, varlığını, bakiyesini (TL karşılığı), **imza eşiğini** (gereken imza /
toplam imza) ve anahtarın nerede durduğunu söyler. İlk satırlar:
""", komut="head -6 cuzdanlar.csv", sonra="""
`1/1` tek imza demektir: tek bir anahtar işlemi onaylayabilir. `2/3` üç yetkiliden **ikisinin** onayı
gerekir. Bu, Cilt 10'daki **maker-checker**'ın (çift onay) kripto karşılığı, yani **çoklu imza** (multi-sig).
"""),
    Adim("Varlığa göre toplam", """
Envanterde awk ile gruplayıp toplamak, risk analizinin ilk adımıdır: hangi varlıkta ne kadar bakiye var?
""", komut="awk -F, 'NR>1{t[$3]+=$4} END{for(k in t) print k, t[k]}' cuzdanlar.csv | sort"),
    Adim("İmza eşiği dağılımı", """
Kaç cüzdan hangi imza düzeninde? Tek imzalı sıcak cüzdan, tek bir hesabın ele geçirilmesiyle boşalabilecek
cüzdan demektir:
""", komut="awk -F, 'NR>1{print $2, $5}' cuzdanlar.csv | sort | uniq -c", sonra="""
Sıcak cüzdanların bir kısmı tek imzalı. Hangilerinin **büyük** bakiyeli olduğuna görevde bakacaksın.
"""),
    Adim("Konsol logunu okumak", """
Yönetim konsolu her işlemi `user=... action=... ip=...` biçiminde yazıyor. Eylem türlerinin sayısına bak;
`KEY_EXPORT` (anahtar dışa aktarma) normalde **çok nadir ve çok sıkı denetimli** olmalıdır:
""", komut="awk '{print $3}' olay/yonetim_konsolu.log | sort | uniq -c | sort -rn", sonra="""
Gündüz trafiği (`LOGIN`, `VIEW_BALANCE`...) normal; ama `KEY_EXPORT`, `LIMIT_CHANGE` ve `TRANSFER` gibi
nadir ve kritik eylemlere zaman çizelgesinde ayrı bak. **Reddedilen** bir deneme (`result=denied`) de bir
sinyaldir ama saldırı olması gerekmez.
"""),
    Adim("Kimin, nereden?", """
Olağandışı bir eylemi bulduğunda sorular: **kim**, **hangi IP'den**, **hangi saatte**? İç ağ adresleri
`10.20.x.x`; yabancı bir IP içeri girmişse hemen göze çarpar. Anahtar dışa aktarma satırlarına bak:
""", komut="grep KEY_EXPORT olay/yonetim_konsolu.log", sonra="""
**Hacker gözüyle:** Saldırgan anahtarı bir kez dışa aktarabildiyse artık konsola ihtiyacı yoktur: anahtar onda,
varlığı istediği zaman çıkarabilir. Bu yüzden savunmanın özü **anahtarın hiç dışarı çıkamaması**
(HSM/donanım cüzdanı), çıkış için çoklu imza ve limit, ve her kritik eyleme ikinci onay koymaktır.
"""),
    Adim("Olay raporu", """
Son olarak ekibin taslak raporunu oku; kök neden bölümü olayın "neden mümkün oldu" kısmını anlatıyor:
""", komut="cat olay/olay_raporu.txt"),
]

GOREVLER = [
    Gorev("Cüzdan envanterinde **tek imzalı (1/1)** cüzdanlar arasında **en yüksek bakiyeli** olanı bul. Cüzdan adı?",
          Metin("tek_imza", sik_hatalar=_tek_hata, bicim="cüzdan adı (örn. HOT-02)"),
          ("Önce `imza` sütununa göre süz (1/1), sonra bakiyeye göre sırala.",
           "`awk -F, 'NR>1 && $5==\"1/1\"' cuzdanlar.csv | sort -t, -k4 -n -r`",
           "Sıralamanın ilk satırının ilk sütunu cevaptır: `... | head -1 | cut -d, -f1`"),
          puan=30, baslik="Tek imzalı en büyük"),
    Gorev("`olay/yonetim_konsolu.log`: **başarıyla** (`result=ok`) bir cüzdan anahtarını dışa aktaran kullanıcı "
          "kim?",
          Metin("kullanici", sik_hatalar=_kullanici_hata, bicim="kullanıcı adı (örn. ops-...)"),
          ("Aradığın eylem `KEY_EXPORT`. Birden fazla satır olabilir; sonucuna bak.",
           "`grep KEY_EXPORT olay/yonetim_konsolu.log`",
           "`result=ok` olan satırın ikinci alanı `user=...`."),
          puan=30, baslik="Anahtarı kim çıkardı"),
    Gorev("Aynı olayda anahtarın dışa aktarıldığı oturumun **IP adresi** nedir? (İç ağ dışında, yabancı bir adres.)",
          IP("ip"),
          ("Aynı `KEY_EXPORT result=ok` satırında `ip=` alanı var.",
           "`grep KEY_EXPORT olay/yonetim_konsolu.log | grep result=ok`",
           "`... | grep -o 'ip=[0-9.]*'`"),
          puan=25, baslik="Saldırgan IP"),
    Gorev("Saldırgan oturumundan **dış adreslere** (`to=ext:`) çıkan toplam tutar kaç TL? "
          "(`amount_tl` alanlarının toplamı; iç aktarımlar `to=int:` sayılmaz.)",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Sadece `to=ext:` içeren satırlar; tutar `amount_tl=` alanında.",
           "`grep 'to=ext:' olay/yonetim_konsolu.log` ile satırları süz, `amount_tl=` sonrasındaki sayıyı çıkar.",
           "`grep 'to=ext:' olay/yonetim_konsolu.log | sed 's/.*amount_tl=\\([0-9]*\\).*/\\1/' | awk '{t+=$1} END{print t}'`"),
          puan=35, baslik="Çıkan tutar"),
    Gorev("`olay/asamalar.txt` dosyasında olayın beş aşaması karışık sırada. Logdaki **zaman sırasına** göre doğru "
          "sırayı numaralarla yaz (örn. `2 5 1 3 4`).",
          Dizi("dizi", bicim="numaralar sırayla, örn. 2 5 1 3 4"),
          ("Her aşamanın logdaki ilk satırını bul ve zaman damgalarını karşılaştır.",
           "Aşamalar: `LOGIN` (saldırgan IP), `KEY_EXPORT`, `LIMIT_CHANGE`, `TRANSFER ... to=ext:`, `ALARM`.",
           "Her biri için `grep ... | head -1` ile ilk zamanı al, en erkenden en geçe sırala; sonra dosyadaki numaralarla eşle."),
          puan=30, baslik="Olay çizelgesi"),
    Gorev("**Düzelt:** Yeni politika (OKUBENI.txt): bakiyesi **<<limit>> TL ve üstü** olan her **tek imzalı (1/1)** "
          "cüzdan çoklu imzaya (`2/3`) geçecek. `cuzdanlar.csv`'yi bu kurala göre düzeltip "
          "`cuzdanlar_duzeltilmis.csv` olarak kaydet; **başka hiçbir satıra ya da sütuna dokunma**. Bitince "
          "`cevap 6` yaz.",
          Durum(_duzeltme, "awk ile imza sütununu koşula göre değiştirip yeni dosyaya yaz"),
          ("Bir koşul: bakiye (4. sütun) eşiğe eşit ya da büyük **ve** imza (5. sütun) `1/1`.",
           "`awk -F, -v OFS=, 'NR>1 && koşul {$5=\"2/3\"} 1' cuzdanlar.csv > cuzdanlar_duzeltilmis.csv`; `-v OFS=,` "
           "çıktıyı yine virgülle birleştirir, sondaki `1` her satırı yazdırır (başlık dahil).",
           "`awk -F, -v OFS=, 'NR>1 && $4>=<<limit_ham>> && $5==\"1/1\" {$5=\"2/3\"} 1' cuzdanlar.csv > cuzdanlar_duzeltilmis.csv` "
           "(eşik burada noktasız yazılı)."),
          puan=45, baslik="Politika düzeltmesi"),
    Gorev("Bu olaydan çıkarılacak **en temel savunma dersi** hangisi?",
          Secmeli([
              ("Tek bir hesabın ya da anahtarın ele geçirilmesi tüm sıcak cüzdanı boşaltabilmemeli: çoklu imza, anahtarı "
               "dışa aktarmama, limit ve ikinci onay şart",
               "Doğru. Savunma katmanlıdır; tek bir halkanın çökmesi varlığı götürmemeli."),
              ("Sıcak cüzdan kullanmayı bırakıp bütün işlemi elle ve haftada bir yapmak",
               "Tamamen sıcak cüzdansız çalışmak iş modelini bitirir; asıl çare sıcak cüzdanı küçük tutup korumaktır."),
              ("Yönetici hesaplarının parolalarını daha uzun yapmak",
               "Parola uzunluğu tek başına kimlik avı, sıfırlanan MFA ya da sızan jetonu engellemez; asıl sorun yetkilerin "
               "tek hesapta toplanmasıdır."),
              ("Logları daha az tutmak, böylece saldırgan iz bulamaz",
               "Log silmek hem saldırganı hem savunmacıyı kör eder; tespit ve soruşturma logsuz yapılamaz."),
          ]),
          ("Olayın hangi adımı tek bir hesaba bağlıydı?",
           "Maker-checker'ı ve çoklu imzayı düşün.",
           "Savunma tek bir halkaya bağlı olmamalı."),
          puan=25, baslik="Temel ders"),
    Gorev("Türkiye'de kripto varlık hizmet sağlayıcılarının kara para aklamayla mücadele (MASAK) yükümlülükleri "
          "hakkında hangisi doğrudur?",
          Secmeli([
              ("Düzenleme kapsamındadırlar; müşteri kimliğini doğrulama ve şüpheli işlem bildirimi gibi yükümlülükleri vardır",
               "Doğru (genel çerçeve). Ayrıntılar ve güncel mevzuat sürekli gelişir; her zaman resmî kaynaktan takip edilmeli."),
              ("Kripto adresleri anonim olduğu için müşteri tanıma yapılmaz",
               "Hizmet sağlayıcıların müşteri tanıma yükümlülüğü vardır; adresin anonim görünmesi bunu kaldırmaz."),
              ("Yükümlülükler yalnızca bankalar için geçerlidir, borsaları kapsamaz",
               "Kripto varlık hizmet sağlayıcıları da düzenleme kapsamına alınmıştır."),
              ("Şüpheli işlem bildirimi yalnızca müşteri zarar ettiğinde yapılır",
               "Bildirim, işlemin şüpheli olmasına bağlıdır; zarar doğup doğmaması ölçüt değildir."),
          ]),
          ("Kitaptaki 'Türkiye bağlamı' kutusunu hatırla.",
           "MASAK'ın kimlik doğrulama ve şüpheli işlem bildirimi yükümlülükleri kriptoya da uygulanıyor.",
           "Ayrıntı (eşik, süre, madde) yerine genel çerçeveyi seç."),
          puan=20, baslik="MASAK ve uyum"),
]

SEVIYE = Seviye(
    kimlik="c22b03",
    cilt=22,
    bolum=3,
    baslik="Cüzdan, DeFi ve Savunma",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> acil bir inceleme istiyor.

Selin: "Elimizde üç şey var: cüzdan envanteri, yönetim konsolunun günlüğü ve ekibin taslak raporu. Bana
şunu söyle: kim, nereden, hangi sırayla, ne kadar? Sonra bu bir daha olmasın diye politikayı düzeltelim."
Deniz ekliyor: "Zincirde çıkan para geri gelmez. Bu yüzden önlemin **olaydan önce** hazır olması gerekiyordu."
Mert: "Bu olayda saldırgan zekice bir şey yapmadı; kapı zaten tek kilitliydi."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Olay, bir kod açığı değil, **tek bir halkaya bağlı güvenlik** hikâyesiydi: tek bir yönetici hesabı hem girip
hem anahtarı dışa aktarıp hem limiti yükseltebiliyordu ve tek imzalı sıcak cüzdan boşalabiliyordu. Saldırgan
için bu, zinciri tek bir halkadan kırmak demek; savunmacı için çare katmanlama: büyük bakiye soğuk ve donanım
cüzdanda, sıcak cüzdan küçük, kritik işlemde çoklu imza ve ikinci onaylayıcı (maker-checker), anahtarın
dışarı çıkamaması, çekim limiti ve hızlı alarm. Kripto geri alma imkânı vermediği için bu kontrollerin hepsi
olaydan **önce** devrede olmalı; uyum tarafı (kimlik doğrulama, şüpheli işlem bildirimi) güvenlikle birlikte
yürütülür.
""",
    gercek_hayat="""
- **Anahtar çoğunluğunun ele geçirilmesi (Ronin köprüsü, 2022):** Oyun dünyasına bağlı bir köprü ağında,
  çoklu imza eşiğini sağlayacak sayıda doğrulayıcı anahtar ele geçirildi ve çok büyük bir varlık çıkışı oldu.
  Ders: çoklu imza yalnızca anahtar sayısına değil, anahtarların **gerçekten bağımsız** korunmasına bağlıdır.
  Tespit: büyük çıkışlarda otomatik alarm ve gecikmeli çekim; önlem: anahtarların farklı kurumlarda/cihazlarda tutulması.
- **Sıcak cüzdan disiplini:** Kripto borsaları büyük bakiyeyi çevrimdışı (soğuk) tutup yalnızca günlük
  çekim ihtiyacı kadar bakiyeyi sıcak cüzdanda bırakmayı yaygın bir iyi uygulama olarak benimser; böylece
  bir ihlalde kayıp sınırlı kalır.
- **Uyum ve güvenlik birlikte:** Türkiye'de kripto varlık hizmet sağlayıcıları düzenleme kapsamındadır ve
  MASAK yükümlülükleri (kimlik doğrulama, şüpheli işlem bildirimi) uygulanır. Bir olay sonrasında hem
  teknik inceleme hem yükümlülüklerin gereği olan bildirim süreçleri birlikte yürütülür; mevzuatın güncel
  ayrıntıları için resmî kaynaklar takip edilmelidir.
""",
    sure_hedef_dk=40,
)
