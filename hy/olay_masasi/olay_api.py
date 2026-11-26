"""Olay Masası — API Kötüye Kullanımı Tespiti.

Bir müşterinin API erişim logunda üç ayrı kötüye kullanım gizli: kimlik bilgisi doldurma
(credential stuffing), kullanıcı ID'lerini ardışık gezen numaralandırma/IDOR (OWASP API
Top 10: BOLA) ve aşırı hızlı kazıma. Yalnızca log kanıtı okunur; saldırı kodu yoktur.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Hepsi, IP, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

KAZIMA_ESIK = 60      # bundan çok istek atan IP kazıyıcıdır (meşru en yoğun ~45)
UA_MESRU = u.TARAYICI_UA


def _satir(ip, t, kullanici, metod, yol, kod, boyut, ua):
    return (f'{ip} - {kullanici} [{u.apache_zamani(t)}] "{metod} {yol} HTTP/1.1" '
            f'{kod} {boyut} "-" "{ua}"')


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)
    olaylar = []   # (zaman, satır)

    def ekle(ip, t, kul, metod, yol, kod, ua, boyut=None):
        olaylar.append((t, _satir(ip, t, kul, metod, yol, kod, boyut or rng.randint(120, 4800), ua)))

    ikinci = rng.random() < 0.5
    n_mesru = rng.randint(10, 14)
    ipler = u.benzersiz(rng, u.dis_ip, n_mesru + 3 + (1 if ikinci else 0))
    mesru = ipler[:n_mesru]
    doldurucu, idorcu, kaziyici = ipler[n_mesru:n_mesru + 3]
    kaziyici2 = ipler[-1] if ikinci else None
    kullanicilar = u.isimler(rng, n_mesru + 6)

    # --- Meşru trafik (hiçbiri 60 istek ya da 10 hatalı girişe yaklaşmaz) ---
    for i, ip in enumerate(mesru):
        kul = kullanicilar[i]
        ua = rng.choice(UA_MESRU)
        yogun = (i == 0)   # tuzak: yoğun ama meşru bir ortak istemci
        n = rng.randint(32, 45) if yogun else rng.randint(4, 16)
        t = gun + timedelta(hours=rng.randint(8, 18), minutes=rng.randint(0, 59))
        if rng.random() < 0.4:   # birkaç yanlış parola, sonra doğru giriş
            for _ in range(rng.randint(1, 3)):
                t += timedelta(seconds=rng.randint(4, 15))
                ekle(ip, t, kul, "POST", "/api/login", 401, ua, 64)
        t += timedelta(seconds=rng.randint(3, 10))
        ekle(ip, t, kul, "POST", "/api/login", 200, ua, 212)
        for _ in range(n):
            t += timedelta(seconds=rng.randint(5, 90))
            yol = rng.choice(["/api/urunler", "/api/profil", "/api/siparisler", "/api/urunler?sayfa=1",
                              "/api/bildirimler"])
            ekle(ip, t, kul, "GET", yol, 200, ua)
        for _ in range(rng.randint(0, 2)):   # meşru kullanıcı yalnız kendi kaydına bakar
            t += timedelta(seconds=rng.randint(5, 90))
            ekle(ip, t, kul, "GET", f"/api/kullanici/{1000 + i}", 200, ua)

    # --- (a) Kimlik bilgisi doldurma: çok 401, en sonda tek 200 ---
    ua = rng.choice(u.KOMUT_SATIRI_UA)
    hesaplar = u.benzersiz(rng, lambda r: f"{r.choice(u.ISIMLER)}{r.randint(1, 99)}", rng.randint(28, 44))
    basarili = hesaplar.pop()
    t0 = gun + timedelta(hours=rng.randint(1, 5), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    zs = u.zamanlar(rng, t0, len(hesaplar) + 1, 1, 3)
    for hesap, t in zip(hesaplar, zs):
        ekle(doldurucu, t, hesap, "POST", "/api/login", 401, ua, 64)
    ekle(doldurucu, zs[-1], basarili, "POST", "/api/login", 200, ua, 212)
    basari_saat = f"{zs[-1]:%H:%M:%S}"
    for k in range(2):
        ekle(doldurucu, zs[-1] + timedelta(seconds=2 + k), basarili, "GET", "/api/profil", 200, ua)

    # --- (b) IDOR / numaralandırma: ardışık kullanıcı ID'leri ---
    ua = rng.choice(u.KOMUT_SATIRI_UA)
    ben = kullanicilar[-1]
    bas = rng.randint(2, 300)
    t1 = gun + timedelta(hours=rng.randint(9, 20), minutes=rng.randint(0, 59))
    ekle(idorcu, t1, ben, "POST", "/api/login", 200, ua, 212)
    zi = u.zamanlar(rng, t1, rng.randint(18, 32), 1, 4)
    for j, t in enumerate(zi):
        kod = 403 if rng.random() < 0.15 else 200
        ekle(idorcu, t, ben, "GET", f"/api/kullanici/{bas + j}", kod, ua)

    # --- (c) Hız sınırı aşımı / kazıma ---
    def kazi(ip, n, bas_saat):
        ua_k = rng.choice(u.KOMUT_SATIRI_UA)
        kul = kullanicilar[-2]
        tk = gun + timedelta(hours=bas_saat, minutes=rng.randint(0, 59))
        ekle(ip, tk, kul, "POST", "/api/login", 200, ua_k, 212)
        for p, t in enumerate(u.zamanlar(rng, tk, n, 0, 1)):
            ekle(ip, t, kul, "GET", f"/api/urunler?sayfa={p + 1}", 200, ua_k)

    n_kaz = rng.randint(150, 260)
    kazi(kaziyici, n_kaz, rng.randint(10, 20))
    n_kaz += 1  # giriş satırı da istek sayılır
    if kaziyici2:
        kazi(kaziyici2, rng.randint(70, 110), rng.randint(10, 20))

    olaylar.sort(key=lambda e: e[0])   # kararlı sıralama: aynı saniyede ekleme sırası korunur
    log = "\n".join(s for _, s in olaylar) + "\n"
    saldirganlar = [doldurucu, idorcu, kaziyici] + ([kaziyici2] if kaziyici2 else [])
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — API erişim logu",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "kisi": m["kisi"],
                  "hikaye": m["hikaye"], "alan": m["alan"]},
        "cevaplar": {
            "doldurucu": doldurucu,
            "basari_saat": basari_saat,
            "hesap": basarili,
            "idor": idorcu,
            "en_cok_ip": kaziyici,
            "en_cok_sayi": n_kaz,
            "saldirganlar": saldirganlar,
        },
        "_log": log,
        "_mesru": set(mesru),
        "_doldurucu": doldurucu,
        "_idor": idorcu,
        "_kaziyici": kaziyici,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "api_access.log", s["_log"])


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["_idor"] and g != beklenen:
        return "Bu IP parola denemiyor; kullanıcı ID'lerini geziyor. Burada `/api/login` yolundaki 401'lere bak."
    if g == s["_kaziyici"] and g != beklenen:
        return "Bu IP çok istek atıyor ama parola denemesi başka bir IP'de. 401 alan `/api/login` isteklerini say."
    if g in s["_mesru"]:
        return "Bu meşru bir kullanıcı: birkaç hatalı giriş saldırı değildir. Onlarca 401 alan IP'yi ara."
    return None


def _idor_hata(g, beklenen, b):
    s = b.senaryo
    if g == s["_doldurucu"]:
        return "Bu IP parola deniyor. IDOR için `/api/kullanici/<sayı>` yolunu ardışık gezen IP'yi ara."
    if g in s["_mesru"]:
        return "Meşru kullanıcılar kendi kayıtlarına bir-iki kez bakar. Onlarca farklı ID isteyen IP'yi ara."
    return None


def _en_cok_hata(g, beklenen, b):
    if g in b.senaryo["_mesru"]:
        return "Bu IP yoğun ama meşru. Saydığında en tepedeki IP başkası."
    return None


def _saldirgan_hata(g, beklenen, b):
    if set(g.split()) & b.senaryo["_mesru"]:
        return "Listende meşru bir kullanıcı var: birkaç hatalı giriş ya da normal gezinti saldırı değildir."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]


def coz(lab: Path, s: dict) -> dict:
    stuf = ("awk '$7==\"/api/login\" && $9==401 {print $1}' api_access.log | sort | uniq -c "
            "| sort -rn | head -1 | awk '{print $2}'")
    doldurucu = _sh(stuf, lab)
    saat = _sh(f"awk -v ip={doldurucu} '$1==ip && $7==\"/api/login\" && $9==200 {{print substr($4,14)}}' "
               "api_access.log | head -1", lab)
    hesap = _sh(f"awk -v ip={doldurucu} '$1==ip && $7==\"/api/login\" && $9==200 {{print $3}}' "
                "api_access.log | head -1", lab)
    idor = _sh("grep -E 'GET /api/kullanici/[0-9]+ ' api_access.log | cut -d' ' -f1 | sort | uniq -c "
               "| sort -rn | head -1 | awk '{print $2}'", lab)
    en_cok = _sh("cut -d' ' -f1 api_access.log | sort | uniq -c | sort -rn | head -1 | awk '{print $1, $2}'", lab)
    sayi, ip = en_cok.split()
    fazla_401 = _sh("awk '$7==\"/api/login\" && $9==401 {print $1}' api_access.log | sort | uniq -c "
                    "| awk '$1>=10 {print $2}'", lab)
    idor_ler = _sh("grep -E 'GET /api/kullanici/[0-9]+ ' api_access.log | cut -d' ' -f1 | sort | uniq -c "
                   "| awk '$1>=10 {print $2}'", lab)
    kaziyanlar = _sh(f"cut -d' ' -f1 api_access.log | sort | uniq -c | awk '$1>={KAZIMA_ESIK} {{print $2}}'", lab)
    saldirganlar = sorted(set((fazla_401 + "\n" + idor_ler + "\n" + kaziyanlar).split()))
    return {1: doldurucu, 2: saat, 3: hesap, 4: idor, 5: f"{ip} {sayi}",
            6: " ".join(saldirganlar), 7: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("**Kimlik bilgisi doldurma** (credential stuffing) yapan IP hangisi? (Çok sayıda hatalı girişten sonra tek bir başarılı giriş.)",
          IP("doldurucu", sik_hatalar=_ip_hata),
          ("Başarısız giriş `401` durum koduyla döner ve yol `/api/login` olur. Hangi IP'nin bunlardan onlarcası var?",
           "Yol 7. alan, durum kodu 9. alan: `awk '$7==\"/api/login\" && $9==401 {print $1}'`; sonra `sort | uniq -c | sort -rn`.",
           "`awk '$7==\"/api/login\" && $9==401 {print $1}' api_access.log | sort | uniq -c | sort -rn | head -3`"),
          puan=15, baslik="Parola doldurucu"),
    Gorev("Bu IP'nin **başarılı girişinin saati** nedir? (SS:DD:SS)",
          Metin("basari_saat", bicim="SS:DD:SS"),
          ("Aynı IP'nin `/api/login` isteklerinden biri `200` almış. Zaman damgası 4. alanda.",
           "Önce IP'yi ve 200'ü süz; saat, `[gg/Ay/yyyy:` önekinden sonra gelir: `substr($4,14)`.",
           "`awk '$1==\"<IP>\" && $7==\"/api/login\" && $9==200 {print substr($4,14)}' api_access.log`"),
          puan=15, baslik="Başarılı giriş saati"),
    Gorev("Saldırganın **ele geçirdiği hesap** hangisi? (Başarılı girişteki kullanıcı adı.)",
          Metin("hesap", bicim="kullanıcı adı"),
          ("Kullanıcı adı log satırının 3. alanındadır.",
           "Aynı satırı süz ve 3. alanı yazdır.",
           "`awk '$1==\"<IP>\" && $7==\"/api/login\" && $9==200 {print $3}' api_access.log`"),
          puan=15, baslik="Ele geçirilen hesap"),
    Gorev("**Numaralandırma / IDOR** deneyen IP hangisi? (`/api/kullanici/1`, `/2`, `/3`... diye ardışık ID gezen.)",
          IP("idor", sik_hatalar=_idor_hata),
          ("Meşru kullanıcı yalnızca kendi kullanıcı kaydına bakar. Çok sayıda farklı ID isteyen kim?",
           "`/api/kullanici/<sayı>` isteklerini süz, IP'ye göre say: `grep -E 'GET /api/kullanici/[0-9]+ '`.",
           "`grep -E 'GET /api/kullanici/[0-9]+ ' api_access.log | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -3`"),
          puan=20, baslik="IDOR deneyen"),
    Gorev("**En çok istek atan** IP hangisi ve **kaç istek** atmış? (örn. `203.0.113.7 250`)",
          Hepsi([IP("en_cok_ip", sik_hatalar=_en_cok_hata), Sayi("en_cok_sayi")], bicim="IP ve istek sayısı"),
          ("Her IP'nin satır sayısını bul; hız sınırı olmayan bir API'de kazıyıcı hepsini geçer.",
           "Kalıp: IP'leri kes, sırala, `uniq -c`, büyükten küçüğe sırala.",
           "`cut -d' ' -f1 api_access.log | sort | uniq -c | sort -rn | head -3`"),
          puan=20, baslik="En çok istek"),
    Gorev("Logdaki **tüm saldırgan IP'leri** yaz (parola doldurma, IDOR ve aşırı hızlı kazıma).",
          Kume("saldirganlar", tur="ip", sik_hatalar=_saldirgan_hata, bicim="boşlukla ayrılmış IP'ler"),
          ("Üç imza var: onlarca 401, ardışık kullanıcı ID'leri, çok yüksek istek sayısı. Kazıyıcı bir tane olmayabilir.",
           "Her imza için ayrı `sort | uniq -c` çalıştır ve eşiği geçen IP'leri topla (`awk '$1>=10'`, `awk '$1>=60'`).",
           "İstek sayısı listesinde üstte kalan, meşru kullanıcıların çok üstündeki IP'ler kazıyıcıdır; üç sonucu birleştir."),
          puan=30, baslik="Saldırganlar"),
    Gorev("Bu üç kötüye kullanıma karşı **en doğru savunma** hangisi?",
          Secmeli([
              ("Hız sınırı + MFA + nesne düzeyinde yetki kontrolü (kullanıcı yalnız kendi kaydına erişsin) + anormal davranış uyarısı",
               "Doğru. Hız sınırı kazımayı ve parola denemesini yavaşlatır, MFA çalınan parolayı işe yaramaz kılar, "
               "BOLA kontrolü ID gezmeyi boşa çıkarır, anomali uyarısı da hepsini erken yakalar."),
              ("Sadece log'daki saldırgan IP'lerini engelle",
               "Saldırgan IP değiştirir (proxy, botnet). Engel geçici olur; asıl açıklar (sınırsız deneme, yetkisiz nesne erişimi) açık kalır."),
              ("Kullanıcı ID'lerini ardışık sayı yerine uzun rastgele kodla değiştir, başka bir şey yapma",
               "Tahmin zorlaşır ama yetki kontrolü yoksa sızan bir ID yine herkesin verisini açar; ayrıca parola doldurma ve kazıma sürer."),
              ("Parola uzunluğunu artır ve API'yi herkese açık bırak",
               "Doldurmada saldırgan başka sızıntılardan gerçek parolaları dener; uzunluk tek başına yetmez. Hız sınırı ve MFA gerekir."),
          ]),
          ("Üç ayrı açık var: sınırsız deneme, çalınmış parola, nesne düzeyinde yetki eksikliği.",
           "Tek bir önlem hepsini kapatmaz; her açığa karşılık gelen kontrolü ara.",
           "Doğru şık dört parçayı birlikte sayar: hız sınırı, MFA, BOLA/IDOR kapatma ve anormal davranış uyarısı."),
          puan=15, baslik="Savunma"),
]

SEVIYE = Seviye(
    kimlik="olay_api",
    cilt=5,
    bolum=107,
    baslik="API Kötüye Kullanımı Tespiti",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize **<<sunucu>>** üzerindeki API'nin erişim logunu gönderdi: `api_access.log`."

"Satır biçimi: `IP - kullanıcı [zaman] "METOD /yol HTTP/1.1" durum boyut`. Yani 1. alan IP,
3. alan kullanıcı, 7. alan yol, 9. alan durum kodu. Birisi parola dolduruyor, birisi başkalarının
kullanıcı kayıtlarını ID ID geziyor, birisi de API'yi kazıyor olabilir. Kanıtı logdan çıkar."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Üç saldırı üç ayrı iz bırakır: parola doldurma `/api/login`'de bir IP'den onlarca 401 ve ardından
tek bir 200, IDOR ardışık nesne kimlikleri, kazıma da insanın atamayacağı kadar yüksek istek hızı.
Savunma da katmanlıdır: hız sınırı denemeleri ve kazımayı yavaşlatır; MFA çalınmış parolayı
değersiz kılar; nesne düzeyinde yetki (BOLA) kontrolü her istekte "bu kayıt bu kullanıcıya mı ait?"
diye sorar; anormal davranış tespiti de insan görmeden önce alarm üretir.
""",
    gercek_hayat="""
- **Kimlik bilgisi doldurma:** Başka sitelerden sızan kullanıcı adı/parola çiftleri botlarla
  API'lerde denenir. 2023'te 23andMe'de bu yolla ele geçirilen birkaç bin hesap, "DNA Relatives"
  özelliği üzerinden milyonlarca kullanıcının verisine ulaşılmasına yol açtı. MFA ve hız sınırı
  bu saldırının birincil ilacıdır.
- **BOLA / IDOR (OWASP API Güvenlik Top 10 listesinin 1 numarası):** 2022'de Optus'ta kimlik
  doğrulamasız bir API'nin ardışık müşteri kimliklerini döndürdüğü bildirildi; milyonlarca kayıt
  numara numara çekildi. Nesne düzeyinde yetki kontrolü ve tahmin edilemez kimlikler birlikte
  gerekir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c05b07",),
)
