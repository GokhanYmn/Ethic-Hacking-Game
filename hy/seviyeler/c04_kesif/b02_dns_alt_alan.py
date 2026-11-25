"""Cilt 4 · Bölüm 2 — DNS ve Alt Alan Adı Keşfi.

Beceri: `dig` ile kayıt türlerini sorgulamak (NS/TXT/CNAME/A), alan transferi reddedilince kelime listesiyle
alt alan adı bulmak (oyuncu küçük bir döngü yazar), sertifika kaydından alt alan adı çıkarıp DNS'te doğrulamak,
sahipsiz kalmış bir CNAME'i (subdomain takeover adayı) fark etmek.

Servis: müşterinin yetkili DNS sunucusunun kopyası 127.0.0.1'de rastgele portta (UDP+TCP). Alan transferi
bilerek KAPALI (doğru yapılandırma): oyuncu kaba kuvvet ve sertifika kaydına başvurmak zorunda.

Vakalar: banka (Ferah Bank), hastane (Medora Sağlık), fintech (Paramix).
"""
from __future__ import annotations

import json
from pathlib import Path

from hy.motor.kontrol import IP, Baglam, Metin, Secmeli, Sonuc
from hy.motor.kontrol import Durum
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import calistir
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

VAKALAR = [
    {
        "kod": "ferahbank", "acik": ["sube", "kurumsal", "mobil-api", "kampanya", "yatirim", "kariyer"],
        "ct_only": ["swift-test", "kart-yonetim", "hsm-ic"], "dangling": ["etkinlik", "anket", "duyuru"],
        "saglam": ["blog", "haber"], "bayat": ["eski-portal", "sube2", "yeni-sube-deneme"],
        "kelime": "alan_kelimeleri.txt", "ct": "sertifika_kaydi.json",
        "brifing": """
**Ferah Bank**'ın bilgi güvenliği müdürü Kaan Bey yıllık sızma testinin ilk adımını istiyor: "Bir saldırgan
internet şubemizin etrafındaki alt alan adlarını bulabilir mi?" Bankanın yetkili DNS sunucusunun kopyası
laboratuvarında **127.0.0.1**, port **<<port>>** üzerinde çalışıyor.

Selin: "Alan transferi (AXFR) kapalı, banka bunu doğru yapılandırmış. Yani elimizde iki yol kaldı: kelime
listesiyle ad denemek ve sertifika kayıtlarına bakmak."

Deniz: "Kelime listesiyle yapacağın her sorgu bizim DNS sunucumuzun loguna düşer. Gürültü yaptığını unutma."
""",
    },
    {
        "kod": "medora", "acik": ["randevu", "portal", "lab-sonuc", "e-recete", "kariyer", "doktorlar"],
        "ct_only": ["pacs-test", "his-yonetim", "lab-cihaz-gw"], "dangling": ["kampanya", "anket", "check-up"],
        "saglam": ["blog", "haber"], "bayat": ["eski-randevu", "portal-v1"],
        "kelime": "tahmin_listesi.txt", "ct": "ct_cikti.json",
        "brifing": """
**Medora Sağlık** yeni hasta portalını duyurmadan önce dış keşif istedi. Bilgi işlem sorumlusu Dr. Aslı
Hanım: "Tedarikçilerle onlarca alt alan adı açtık, hangisi hâlâ yaşıyor bilmiyoruz." Hastanenin yetkili DNS
sunucusunun kopyası laboratuvarında **127.0.0.1**, port **<<port>>** üzerinde.

Selin: "Alan transferini denersen reddettiğini göreceksin. Önce kelime listesini dene, sonra sertifika
kaydıyla karşılaştır."

Mert: "Hastane için dikkat: her bulduğun adın sağlık verisi tutan bir sisteme çıkma ihtimali var. Not al,
dokunma."
""",
    },
    {
        "kod": "paramix", "acik": ["api", "odeme", "panel", "gelistirici", "destek", "durum"],
        "ct_only": ["sandbox-ic", "test-gw", "admin-eski"], "dangling": ["docs", "status", "demo"],
        "saglam": ["blog", "haber"], "bayat": ["pos-v1", "eski-panel"],
        "kelime": "kelime_havuzu.txt", "ct": "crt_kayitlari.json",
        "brifing": """
**Paramix** yeni ödeme API'sini yayına almadan önce dış keşif istedi. CTO Ece Hanım: "Bir saldırgan bizim
alan adımız altında neleri bulabilir? Listeyi ben de görmek istiyorum." Şirketin yetkili DNS sunucusunun
kopyası laboratuvarında **127.0.0.1**, port **<<port>>** üzerinde.

Selin: "Alt alan adı keşfi modern web testinin kalbidir. Ana site iyi korunur; asıl risk unutulmuş alt
alanlardadır."

Mert: "Ve bazen bir alt alan, artık var olmayan bir bulut hizmetine hâlâ işaret ediyordur. Gözünü aç."
""",
    },
]

ORTAK_KELIMELER = ["ftp", "vpn", "test", "dev", "admin", "shop", "intranet", "webmail", "staging", "cdn", "git",
                   "jenkins", "owa", "remote", "beta", "old", "backup", "db", "files", "login", "mobile", "secure",
                   "static", "media", "support", "app", "crm", "erp", "wiki", "monitor"]
SAGLAYICILAR = ["postakutusu.lab", "guvenliposta.lab", "kamuposta.lab", "saglikposta.lab"]
BULUTLAR = ["bulutdepo.lab", "sitebarinak.lab", "hizlisayfa.lab"]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    port = rng.randint(20000, 45000)
    kullanilan: set = set()

    def dis():
        ip = u.benzersiz(rng, u.dis_ip, 1, kullanilan)[0]
        kullanilan.add(ip)
        return ip

    ana_ip = dis()
    ns = [(f"ns{i}", dis()) for i in (1, 2)]
    mx = [(10, "mx1", dis()), (20, "mx2", dis())]
    acik = rng.sample(v["acik"], 3)
    dangling = rng.choice(v["dangling"])
    saglam = rng.choice(v["saglam"])
    ct_only = rng.choice(v["ct_only"])
    bayat = rng.choice(v["bayat"])
    bulut = rng.choice(BULUTLAR)
    bulut_olu = f"{v['kod']}-{rng.randint(10, 99)}.{bulut}"
    bulut_canli = f"{v['kod']}-{rng.randint(10, 99)}.{bulut}"
    bulut_ip = dis()
    ip_map = {a: dis() for a in acik + [ct_only, "www"]}
    bulunan = sorted(["www"] + acik + [dangling, saglam])
    zon_adlari = set(bulunan) | {ct_only, "ns1", "ns2", "mx1", "mx2"}
    decoy = [k for k in ORTAK_KELIMELER if k not in zon_adlari]
    kelimeler = bulunan + rng.sample(decoy, 18)
    rng.shuffle(kelimeler)
    saglayici = rng.choice(SAGLAYICILAR)
    # Sertifika kaydı: bulunan bazı adlar + sadece-CT adı (DNS'te var) + bayat ad (DNS'te yok)
    ct_adlari = ["www", ct_only, bayat] + rng.sample(acik, 2)
    sertler = []
    for i, ad in enumerate(ct_adlari):
        sertler.append({
            "issuer_ca_id": 7001, "issuer_name": "C=XX, O=Lab Sertifika Otoritesi, CN=Lab Alan Adi CA 1",
            "common_name": f"{ad}.{alan}", "name_value": f"{ad}.{alan}", "id": 91000000 + rng.randint(1, 99999),
            "not_before": f"2025-{rng.randint(1, 9):02d}-0{rng.randint(1, 9)}T09:00:00",
            "not_after": f"2026-{rng.randint(1, 9):02d}-0{rng.randint(1, 9)}T09:00:00",
        })
    rng.shuffle(sertler)
    return {
        "vaka": f"{m['ad']} — alt alan adı keşfi ({alan})",
        "brifing": v["brifing"],
        "v": v, "m": m, "alan": alan, "port": port, "ana_ip": ana_ip, "ns": ns, "mx": mx, "acik": acik,
        "dangling": dangling, "saglam": saglam, "ct_only": ct_only, "bayat": bayat, "bulut": bulut,
        "bulut_olu": bulut_olu, "bulut_canli": bulut_canli, "bulut_ip": bulut_ip, "ip_map": ip_map,
        "bulunan": bulunan, "kelimeler": kelimeler, "saglayici": saglayici, "sertler": sertler,
        "metin": {
            "musteri": m["ad"], "alan": alan, "port": port, "kelime": v["kelime"], "ct": v["ct"],
            "saglam": saglam, "bulut": bulut,
        },
        "cevaplar": {
            "saglayici": [saglayici, f"_spf.{saglayici}"],
            "ana_ip": ana_ip,
            "ct_only": [f"{ct_only}.{alan}", ct_only],
            "ct_only_ip": ip_map[ct_only],
            "dangling": [f"{dangling}.{alan}", dangling],
        },
    }


def _bolgeler(s: dict) -> list:
    alan = s["alan"]
    b = ag.Bolge(alan, axfr=False)
    for ad, _ip in s["ns"]:
        b.ekle("@", "NS", ad)
    b.ekle("@", "A", s["ana_ip"])
    for on, ad, _ip in s["mx"]:
        b.ekle("@", "MX", (on, ad))
    b.ekle("@", "TXT", f"v=spf1 mx include:_spf.{s['saglayici']} ~all")
    for ad, ip in s["ns"]:
        b.ekle(ad, "A", ip)
    for _on, ad, ip in s["mx"]:
        b.ekle(ad, "A", ip)
    for ad in ["www"] + s["acik"] + [s["ct_only"]]:
        b.ekle(ad, "A", s["ip_map"][ad])
    b.ekle(s["dangling"], "CNAME", s["bulut_olu"] + ".")      # hedefi artık yok
    b.ekle(s["saglam"], "CNAME", s["bulut_canli"] + ".")      # hedefi yaşıyor
    bulut = ag.Bolge(s["bulut"], axfr=False)
    bulut.ekle("@", "NS", "ns1").ekle("ns1", "A", s["ns"][0][1])
    bulut.ekle(s["bulut_canli"] + ".", "A", s["bulut_ip"])
    return [b, bulut]


def yaz(lab: Path, s: dict) -> None:
    v, alan = s["v"], s["alan"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['metin']['musteri']} yetkili DNS sunucusunun kopyası bu görev boyunca çalışıyor:\n"
          f"  adres: 127.0.0.1   port: {s['port']}   (UDP ve TCP)\n\n"
          f"  {v['kelime']}   deneyeceğin alt alan adı kelimeleri (her satırda bir tane)\n"
          f"  {v['ct']}   alanın sertifika şeffaflık kaydı (kurgusal crt.sh çıktısı)\n\n"
          f"  dig @127.0.0.1 -p {s['port']} {alan}\n")
    u.yaz(lab / v["kelime"], "\n".join(s["kelimeler"]) + "\n")
    u.yaz(lab / v["ct"], json.dumps(s["sertler"], indent=2, ensure_ascii=False) + "\n")


def servis(s: dict, lab: Path, dur) -> None:
    calistir(ag.dns_sunuculari("127.0.0.1", s["port"], _bolgeler(s)), dur)


# ---------------------------------------------------------------- kontroller

def _alt_alan_dosyasi(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = o.dosya_bul(b, "alt_alanlar.txt")
    if yol is None:
        return Sonuc(False, "`alt_alanlar.txt` bulunamadı. Döngünün çıktısını `>` ile bu dosyaya yönlendir "
                     "(bulunduğun klasörde).")
    alan = s["alan"]
    verilen = set()
    for satir in yol.read_text(encoding="utf-8", errors="replace").splitlines():
        ad = satir.strip().lower().rstrip(".")
        if not ad:
            continue
        verilen.add(ad if "." in ad else f"{ad}.{alan}")
    beklenen = {f"{k}.{alan}" for k in s["bulunan"]}
    if not verilen:
        return Sonuc(False, "`alt_alanlar.txt` boş. Döngü hiçbir ad bulamadı: dig'e `+short` ekledin mi, "
                     "adresi doğru kurdun mu (`$k.<<alan>>`)?".replace("<<alan>>", alan))
    if verilen == beklenen:
        return Sonuc(True, f"Döngün çalışıyor: {len(beklenen)} alt alan adı bulundu ve dosyaya yazıldı.")
    fazla, eksik = verilen - beklenen, beklenen - verilen
    if any(f.startswith(s["ct_only"] + ".") for f in verilen):
        return Sonuc(False, "Dosyada kelime listesinde olmayan bir ad var. Bu görevde yalnızca "
                     f"`{s['v']['kelime']}` içindeki kelimelerle DNS'te cevap alınanlar yazılır.", yakin=True)
    if fazla:
        return Sonuc(False, f"{len(fazla)} satır DNS'te cevap vermeyen bir ad: döngü sadece cevabı boş olmayan "
                     "adları yazmalı (`dig ... +short` çıktısı boşsa ad yoktur).", yakin=len(verilen & beklenen) > 0)
    return Sonuc(False, f"Şu an {len(verilen)} ad var, {len(eksik)} ad eksik. Listenin tamamını denediğinden "
                 "emin ol.", yakin=len(verilen & beklenen) > 0)


def _ana_hata(g, beklenen, b):
    if g in [ip for _a, ip in b.senaryo["ns"]]:
        return "Bu bir isim sunucusunun adresi. Alan adının kendi A kaydını sor."
    if g in [ip for _o, _a, ip in b.senaryo["mx"]]:
        return "Bu e-posta sunucusunun adresi. Soru alan adının kendisinin A kaydını istiyor."
    return None


def _ct_ip_hata(g, beklenen, b):
    if g == b.senaryo["ana_ip"]:
        return "Bu ana alan adının IP'si. Sorduğun ad `<ad>.<alan>` olmalı, alan adının kendisi değil."
    return None


def _ct_hata(g, beklenen, b):
    s = b.senaryo
    if g in (s["bayat"], f"{s['bayat']}.{s['alan']}"):
        return ("Bu ad sertifika kaydında var ama DNS'te `status: NXDOMAIN` veriyor: eski bir kayıt, artık yok. "
                "Kayıtta olup DNS'te de yaşayan adı ara.")
    if g.rstrip(".").split(".")[0] in s["bulunan"]:
        return "Bu adı kelime listesiyle zaten buluyorsun. Listede OLMAYAN adı ara."
    return None


def _dangling_hata(g, beklenen, b):
    s = b.senaryo
    if g.rstrip(".").split(".")[0] == s["saglam"]:
        return "Bu da bir CNAME ama hedefi çözülüyor (yaşıyor). Hedefi `NXDOMAIN` veren adı ara."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    d = f"dig @127.0.0.1 -p {s['port']}"
    a = s["alan"]
    saglayici = o.sh(f"{d} {a} TXT +short | grep -o '_spf\\.[a-z.]*' | sed 's/^_spf\\.//'", lab)
    ana = o.sh(f"{d} {a} +short", lab)
    o.sh(f"for k in $(cat {v['kelime']}); do r=$({d} +short $k.{a}); "
         f"[ -n \"$r\" ] && echo $k.{a}; done > alt_alanlar.txt", lab)
    ct_adlar = o.sh(f"grep -o '\"name_value\": \"[^\"]*\"' {v['ct']} | cut -d'\"' -f4", lab).split()
    ct_ad = ""
    for ad in sorted(set(ct_adlar)):
        kisa = ad.split(".")[0]
        if o.sh(f"grep -c '^{kisa}$' {v['kelime']}", lab) == "0" and o.sh(f"{d} +short {ad}", lab):
            ct_ad = ad
    ct_ip = o.sh(f"{d} +short {ct_ad}", lab)
    dangling = o.sh(
        f"for k in $(sed 's/\\..*//' alt_alanlar.txt); do t=$({d} +short $k.{a} CNAME); "
        f"[ -n \"$t\" ] && {d} $t | grep -q NXDOMAIN && echo $k.{a}; done", lab)
    return {1: saglayici, 2: ana, 3: "", 4: ct_ad, 5: ct_ip, 6: dangling,
            7: o.secmeli_cevap(SEVIYE, s, lab, 7), 8: o.secmeli_cevap(SEVIYE, s, lab, 8)}


ADIMLAR = [
    Adim("DNS keşfi neden değerli?", """
Cilt 2'de DNS'in nasıl çalıştığını öğrendin. Şimdi onu bir **keşif aracı** olarak kullanacaksın. Bir
kurumun alan adı altındaki **alt alan adları** (`vpn.`, `test.`, `jenkins.`, `eski.`) çoğu zaman en zayıf
halkalardır: ana site (`www`) her gün izlenir, ama geçen yıl açılmış bir test alt alanı kimsenin aklında
değildir.

Bu görevde <<musteri>>'nin yetkili DNS sunucusunun kopyasına doğrudan soracağız: 127.0.0.1, port <<port>>.
Önce klasik kayıtlarla başlayalım: alan adını **kimin yönettiği** (NS kaydı).
""", komut="dig @127.0.0.1 -p <<port>> <<alan>> NS +short", sonra="""
İki isim sunucusu (ns1, ns2). Bir alan adının NS kayıtları, onu hangi altyapının yönettiğini ele verir
(kendi sunucusu mu, bir bulut DNS servisi mi?).
"""),
    Adim("TXT kayıtları ele verir", """
**TXT** kayıtları serbest metindir. E-posta güvenliği için kullanılan **SPF** kaydı hangi e-posta
sağlayıcılarının kurumun adına posta gönderebileceğini listeler, yani saldırgana kurumun hangi
dış servisleri kullandığını söyler:
""", komut="dig @127.0.0.1 -p <<port>> <<alan>> TXT +short", sonra="""
`include:_spf.<sağlayıcı>` kısmı e-posta sağlayıcısını gösterir. Bu bilgi, kuruma gönderilecek ikna edici
bir sahte e-postayı hazırlarken de işe yarar; savunmacı için ders: SPF'te sadece gerçekten kullandığın
sağlayıcıları tut.
"""),
    Adim("Alan transferi denemesi", """
Önceki cilt'te yanlış yapılandırılmış bir sunucudan **AXFR** (alan transferi) ile bütün bölgeyi
dökmüştün. Doğru yapılandırılmış bir sunucu bunu reddeder. <<musteri>> bu konuda dikkatli mi?
""", komut="dig @127.0.0.1 -p <<port>> <<alan>> AXFR", sonra="""
`Transfer failed.`: sunucu reddetti, yani doğru yapılandırılmış. Bu durumda rehberi tek seferde alamayız;
**tahminle** (kelime listesi) ve **başka kaynaklarla** (sertifika kayıtları) ilerleriz.
"""),
    Adim("Tek bir adı sormak", """
Kaba kuvvet (brute force) yöntemi basit bir fikirdir: bir kelime listesindeki her kelimeyi `<kelime>.<alan>`
olarak sor. **Cevap varsa ad vardır; yoksa yoktur.** `+short` ile cevap boşsa ad tanımsızdır.
Önce tek bir adı elle deneyelim:
""", komut="dig @127.0.0.1 -p <<port>> +short www.<<alan>>", sonra="""
`www` için bir IP geldi. Peki listedeki diğer yüz kelime için? Elle sormak yerine bir **döngü** yazarsın:

```
for k in $(cat <<kelime>>); do
  r=$(dig @127.0.0.1 -p <<port>> +short $k.<<alan>>)
  [ -n "$r" ] && echo $k.<<alan>>
done
```

Satır satır: dosyadaki her `k` kelimesi için sorguyu yap, sonucu `r`'ye koy, **boş değilse** adı yazdır.
Görevde bu döngünün çıktısını bir dosyaya yönlendireceksin.
"""),
    Adim("Sertifika kaydı: ikinci kaynak", """
Kelime listesi tahmindir; tahmin edemediğin adlar kalır. **Sertifika şeffaflık** kayıtları ise hedefin
kendi verdirdiği sertifikalardan gelir. Kaydın biçimi (kurgusal `crt.sh` çıktısı):
""", komut="grep name_value <<ct>>", sonra="""
Bu adlardan bazılarını kelime listesiyle de buluyorsun; bazıları listede yok. Ama **dikkat:** kayıt
geçmişi de tutar, yani bir adın sertifikası alınmış olması adın **şu an** DNS'te olduğunu garanti etmez.
Her adı `dig` ile doğrulamalısın.
"""),
    Adim("CNAME'ler ve sahipsiz kalan ad", """
Bir alt alan adı çoğu zaman bir bulut ya da barındırma hizmetine **CNAME** (takma ad) ile bağlanır.
Hizmet kapatılır ama CNAME silinmezse alt alan adı artık var olmayan bir hedefe işaret eder:
buna **sahipsiz CNAME** denir. Saldırgan o hedef adı kendi adına açabilirse alt alanı ele geçirir (**subdomain
takeover**). Sağlam bir CNAME'e bakalım:
""", komut="dig @127.0.0.1 -p <<port>> <<saglam>>.<<alan>> CNAME +short", sonra="""
Hedefi (`...<<bulut>>`) ayrıca sorarsan cevap alırsın: yaşıyor. Hedefi `status: NXDOMAIN` veren bir
CNAME ise sahipsizdir. Görevde bunlardan birini bulacaksın.

**Hacker gözüyle:** Sahipsiz CNAME bir **hesap devralma** fırsatıdır; ölçek büyüdükçe en sık raporlanan
alt alan bulgularından biridir. Savunma dersi: DNS kayıtlarının envanterini tut ve bir hizmeti
kapatırken önce CNAME'ini sil.
"""),
    Adim("Bu aktif mi, pasif mi?", """
Sertifika kaydına bakmak **pasiftir**: sorguyu hedefe değil, herkese açık kayıt defterine gönderirsin.
Kelime listesiyle yaptığın `dig` döngüsü ise **hedefin yetkili DNS sunucusuna** doğrudan sorgu gönderir. Yüzlerce
`NXDOMAIN` cevabı sunucunun logunda görünür. Yani DNS keşfi **karışık** bir teknik: bazı kısmı pasif, bazı kısmı
aktiftir. Hangi kaynağı kullandığını raporuna yaz: müşteri neyin izini bıraktığını bilmeli.
""", calistir=False),
]

GOREVLER = [
    Gorev("<<alan>> alanının SPF kaydı (TXT) hangi e-posta sağlayıcısını (`_spf.` ile başlayan alan adı) "
          "kullandığını gösteriyor? Sağlayıcının alan adını yaz.",
          Metin("saglayici", son_ekleri_at=(".",), bicim="alan adı"),
          ("SPF bilgisi TXT kayıtlarında durur.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> TXT +short` çıktısında `include:` ifadesini ara.",
           "`include:_spf.` ile başlayan kısmın devamı sağlayıcının alan adıdır (`_spf.` önekini atabilirsin)."),
          puan=20, baslik="E-posta sağlayıcısı"),
    Gorev("<<alan>> alan adının kendisinin IPv4 adresi (A kaydı) nedir?",
          IP("ana_ip", sik_hatalar=_ana_hata),
          ("Tür yazmazsan dig A kaydını sorar.",
           "`dig @127.0.0.1 -p <<port>> <<alan>> +short`",
           "Çıktıdaki tek IP adresi cevaptır."),
          puan=15, baslik="Ana IP"),
    Gorev("`<<kelime>>` listesindeki **her kelimeyi** `<kelime>.<<alan>>` olarak DNS'e sor. Cevap alan (A ya da "
          "CNAME kaydı olan) adları, her satırda bir tam ad olacak biçimde `alt_alanlar.txt` dosyasına yaz. "
          "(Dosyayı bulunduğun klasörde oluştur; sonra `cevap <no>` yaz.)",
          Durum(_alt_alan_dosyasi,
                "for k in $(cat <<kelime>>); do r=$(dig @127.0.0.1 -p <<port>> +short $k.<<alan>>); "
                "[ -n \"$r\" ] && echo $k.<<alan>>; done > alt_alanlar.txt"),
          ("Adım 4'teki döngüyü kullan. Çıktıyı ekranda değil, bir dosyada istiyoruz.",
           "Döngünün sonuna `done > alt_alanlar.txt` yazarak bütün çıktıyı dosyaya yönlendir.",
           "`for k in $(cat <<kelime>>); do r=$(dig @127.0.0.1 -p <<port>> +short $k.<<alan>>); "
           "[ -n \"$r\" ] && echo $k.<<alan>>; done > alt_alanlar.txt`"),
          puan=40, baslik="Kendi döngün"),
    Gorev("<<ct>> kaydında olup `<<kelime>>` listesinde **bulunmayan** ve DNS'te **gerçekten tanımlı** olan "
          "alt alan adı hangisi? (Tam adı yaz.)",
          Metin("ct_only", son_ekleri_at=(".",), sik_hatalar=_ct_hata, bicim="tam alt alan adı"),
          ("Kayıttaki adlardan bazıları listede de var; bazıları artık DNS'te yok. Biri hem listede yok hem canlı.",
           "Kayıttaki her ad için `dig +short` çalıştır; boş dönenler eski kayıtlardır. Sonra `grep` ile listede ara.",
           "`grep name_value <<ct>>` ile adları al; her birine `dig @127.0.0.1 -p <<port>> +short <ad>`; cevap veren "
           "ve `grep -c '^<ilk etiket>$' <<kelime>>` ile 0 çıkan ad aradığındır."),
          puan=35, baslik="Listede olmayan ad"),
    Gorev("Bir önceki görevde bulduğun alt alan adının IPv4 adresi nedir?",
          IP("ct_only_ip", sik_hatalar=_ct_ip_hata),
          ("Adın A kaydını sor.",
           "`dig @127.0.0.1 -p <<port>> +short <bulduğun ad>`",
           "Çıktıdaki IP'yi yaz."),
          puan=15, baslik="Gizli adın IP'si"),
    Gorev("`alt_alanlar.txt` içindeki adlardan biri bir CNAME ile bir bulut hizmetine bağlı ve o hedef artık "
          "**yok** (`NXDOMAIN`). Bu sahipsiz (takeover adayı) alt alan hangisi? (Tam adı yaz.)",
          Metin("dangling", son_ekleri_at=(".",), sik_hatalar=_dangling_hata, bicim="tam alt alan adı"),
          ("Listedeki adlardan yalnızca iki tanesi CNAME; hedeflerini ayrıca sorgulaman gerek.",
           "Her ad için `dig ... <ad> CNAME +short` çalıştır; cevap varsa o hedef adı sor ve `status:` satırına bak.",
           "`dig @127.0.0.1 -p <<port>> <hedef> | grep status`: `NXDOMAIN` veren CNAME'in sahibi adı yaz."),
          puan=40, baslik="Sahipsiz CNAME"),
    Gorev("Sertifika şeffaflık kayıtlarından alt alan adı bulmak neden **pasif** keşiftir?",
          Secmeli([
              ("Sorgu hedefe değil, herkese açık bir üçüncü taraf kayda gönderilir",
               "Doğru. Hedefin sunucuları senin sorgunu hiç görmez; bu yüzden pasiftir."),
              ("Sertifika kayıtları şifrelidir, bu yüzden hedefin logları bu sorguyu okuyamaz",
               "Kayıtlar şifreli değil, tam tersi herkese açık. Pasif olmasının nedeni sorunun hedefe gitmemesi."),
              ("Sorgu hedefin DNS sunucusuna gider ama cevabı önbellekten döndüğü için iz bırakmaz",
               "Sertifika kaydı sorgusu hedefin DNS sunucusuna hiç gitmez; önbellek bu işte yoktur."),
              ("Bu kayıtları yalnızca hedefin kendi yöneticileri okuyabilir, o yüzden izin gerekmez",
               "Kayıtlara herkes erişebilir. İzin gerekmemesinin nedeni verinin açık olması, erişimin kısıtlı olması değil."),
          ], dogru=0),
          ("Sorguyu kime gönderdiğini düşün.",
           "Hedefin sunucuları bu işlemden haberdar oluyor mu?",
           "Pasif keşifte hedefe hiç paket gitmez."),
          puan=20, baslik="Neden pasif"),
    Gorev("Kelime listesiyle `dig` döngüsü çalıştırdın. Hedef açısından bu ne anlama gelir?",
          Secmeli([
              ("Sorgular hedefin DNS sunucusuna ulaşır ve loglanabilir; bu aktif keşiftir",
               "Doğru. Yüzlerce sorgu, özellikle çoğu `NXDOMAIN` ise, sunucunun logunda tarama izi olarak görünür."),
              ("Pasiftir, çünkü DNS herkese açık olduğu için bu sorgular hiçbir yerde loglanmaz",
               "DNS'in herkese açık olması loglanmadığı anlamına gelmez; yetkili sunucular genellikle sorguları kaydeder."),
              ("Pasiftir, çünkü bir DNS sorgusu paket sayılmaz, yalnızca bir soru sorar",
               "DNS sorgusu da bir ağ paketidir; sunucuya ulaşır ve cevap bekler."),
              ("Yasaktır, çünkü alt alan adı sorgusu hiçbir koşulda izinsiz gönderilemez",
               "Bu sorgular teknik olarak normaldir; sorun izinsiz ve kapsam dışı yapılması. Kapsam içindeyse sorun yoktur."),
          ], dogru=0),
          ("Kelime listesi sorguları kime gidiyor?",
           "Yetkili sunucu her sorguyu işler; sorgu sayısı loglarda nasıl görünür?",
           "Hedefin kendi sunucusuna giden sorgu, pasif değil aktiftir."),
          puan=20, baslik="Bu aktif mi"),
]

SEVIYE = Seviye(
    kimlik="c04b02",
    cilt=4,
    bolum=2,
    baslik="DNS ve Alt Alan Adı Keşfi",
    brifing="""
**<<musteri>>** dış keşif istedi. Yetkili DNS sunucusunun kopyası 127.0.0.1, port **<<port>>** üzerinde
çalışıyor. Alan transferi kapalı: kelime listesi ve sertifika kaydı elinde. Selin: "Bir saldırganın
bulacağı her adı sen de bul."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
DNS keşfi iki kaynaktan beslendi: tahmin (kelime listesi) ve kayıt (sertifika şeffaflığı). İkisi birbirini
tamamladı: listede olmayan bir test adı sertifika kaydında çıktı; kayıttaki bir ad ise artık yoktu.
Sahipsiz bir CNAME de hesap devralma adayı olarak ortaya çıktı. Savunma tarafı için sonuç net: alt alan adlarının
envanterini tut, kullanılmayan kayıtları sil, hizmeti kapatırken CNAME'i de kaldır, iç sistemlerin adlarını genel
DNS'e ve sertifika kaydına koyma ve alan transferini sadece yedek isim sunucularına aç.
""",
    gercek_hayat="""
- **Alt alan adı devralma (subdomain takeover):** Silinmiş bir bulut ya da barındırma kaynağına CNAME ile
  işaret etmeyi sürdüren alt alan adlarının devralınabilmesi, bug bounty programlarında yıllardır sık görülen
  bir bulgu türüdür. Tespit: DNS envanterindeki her CNAME'in hedefini düzenli sorgulamak (NXDOMAIN ya da
  "kaynak bulunamadı" sayfası uyarı işaretidir). Önleme: hizmeti kapatmadan önce DNS kaydını silmek.
- **Sertifika şeffaflığı:** Sertifika şeffaflık kayıtları, izinsiz sertifika verilmesini yakalamak için
  oluşturuldu; aynı kayıtlar saldırgana da alt alan adı listesi verir. Savunma: kendi alan adların için CT
  izleme uyarısı kur; iç sistem adlarını herkese açık sertifikalara yazma (iç CA kullan).
- **Gürültülü kelime listesi taraması:** Kısa sürede yüzlerce `NXDOMAIN` üreten bir istemci, DNS loglarında
  bariz bir iz bırakır. Tespit: DNS sunucu loglarında tek kaynaktan gelen yüksek `NXDOMAIN` oranına
  alarm kurmak.
""",
    sure_hedef_dk=30,
)
