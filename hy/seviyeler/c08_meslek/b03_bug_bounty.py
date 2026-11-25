"""Cilt 8 · Bölüm 3 — Bug Bounty: İzinli Avcılık.

Beceri: bir programın kapsam dosyasını doğru okumak (joker karakter + istisnalar + üçüncü taraf),
aday bulguları kapsama ve bilinen bulgulara (kopya/duplicate) göre ayıklamak, beklenen ödülü
hesaplamak, sorumlu bildirimin kurallarını bilmek ve düzgün bir bildirim yazmak.

Vakalar: e-ticaret programı, banka programı, ödeme/cüzdan programı. Hosts, kurallar, ödül tablosu
ve adaylar her vakada farklıdır. Bütün adlar kurgusaldır; saldırı yükü ya da araç yoktur.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

VAKALAR = {
    "pazarix": {
        "ad": "Pazarix Hata Ödül Programı", "musteri": "Pazarix", "alan": "pazarix.lab",
        "ic": ["magaza", "api", "hesap", "destek"], "dis": [("odeme", "üçüncü taraf ödeme sağlayıcısı"), ("test", "eski test ortamı")],
        "ucuncu": "kargo-ortagi.lab", "kisi": "Tuncay Bey (sistem yöneticisi)",
        "kurallar": ["Hizmet reddi (DoS) testi yasaktır.", "Sosyal mühendislik ve fiziksel saldırı yasaktır.",
                     "Başka müşterilerin gerçek verisini indirmek yasaktır; yalnızca kendi test hesabını kullan."],
        "odul": {"kritik": 15000, "yuksek": 6000, "orta": 2000, "dusuk": 500},
    },
    "ferah": {
        "ad": "Ferah Bank Sorumlu Bildirim Programı", "musteri": "Ferah Bank", "alan": "ferahbank.lab",
        "ic": ["sube", "api", "kampanya", "destek"], "dis": [("swift", "kapsam dışı finansal mesajlaşma altyapısı"), ("test", "eski test ortamı")],
        "ucuncu": "kartortagi.lab", "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)",
        "kurallar": ["Gerçek para hareketi oluşturan hiçbir test yapılamaz.", "Müşteri verisine erişirsen derhal durup bildirmelisin.",
                     "Hizmet reddi ve sosyal mühendislik yasaktır."],
        "odul": {"kritik": 40000, "yuksek": 15000, "orta": 5000, "dusuk": 1000},
    },
    "paramix": {
        "ad": "Paramix Güvenlik Programı", "musteri": "Paramix", "alan": "paramix.lab",
        "ic": ["cuzdan", "api", "gelistirici", "destek"], "dis": [("sandbox", "ayrı yönetilen deneme ortamı"), ("kurumsal", "kurumsal müşteri portalı")],
        "ucuncu": "bankaortagi.lab", "kisi": "Ece Hanım (CTO)",
        "kurallar": ["Hizmet reddi testi yasaktır.", "Yalnızca kendi cüzdan hesabını ve test bakiyesini kullan.",
                     "Bulguyu kamuya açmadan önce yazılı izin al."],
        "odul": {"kritik": 20000, "yuksek": 8000, "orta": 3000, "dusuk": 750},
    },
}
TURLER = ["IDOR", "yansıtılan XSS", "kimlik doğrulama atlatma", "yedek dosya ifşası", "CSRF", "açık yönlendirme"]
SEVIYE_SIRA = {"kritik": 4, "yuksek": 3, "orta": 2, "dusuk": 1}


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    for _ in range(300):
        turler = rng.sample(TURLER, 6)
        ic_hostlar = [f"{x}.{v['alan']}" for x in v["ic"]]
        dis_host = [f"{x}.{v['alan']}" for x, _ in v["dis"]]
        adaylar = []
        hostlar = ic_hostlar + [rng.choice(dis_host), v["ucuncu"]]
        rng.shuffle(hostlar)
        for i, (h, t) in enumerate(zip(hostlar, turler), 1):
            adaylar.append({"no": i, "varlik": h, "tur": t, "onem": rng.choice(list(SEVIYE_SIRA)),
                            "kapsam": h in ic_hostlar})
        kapsamda = [a for a in adaylar if a["kapsam"]]
        kopya = rng.choice(kapsamda)
        gecerli = [a for a in kapsamda if a is not kopya]
        ranks = sorted((SEVIYE_SIRA[a["onem"]] for a in gecerli), reverse=True)
        if ranks[0] != ranks[1]:
            break
    else:
        raise RuntimeError("Uygun aday seti üretilemedi")
    bilinen = [(kopya["varlik"], kopya["tur"])]
    diger = [a for a in kapsamda if a is not kopya]
    bilinen.append((diger[0]["varlik"], rng.choice([t for t in TURLER if t != diger[0]["tur"]])))      # aynı host, farklı tür
    bilinen.append((f"{rng.choice(['eski', 'yedek'])}.{v['alan']}", rng.choice(TURLER)))
    rng.shuffle(bilinen)
    odul = v["odul"]
    en_yuksek = max(gecerli, key=lambda a: SEVIYE_SIRA[a["onem"]])
    s = {
        "vaka": v["ad"], "v": v, "adaylar": adaylar, "bilinen": bilinen, "gecerli": gecerli, "en_yuksek": en_yuksek,
        "dis_hostlar": [a["varlik"] for a in adaylar if not a["kapsam"]],
        "metin": {"musteri": v["musteri"], "kisi": v["kisi"], "program": v["ad"], "alan": v["alan"],
                  "e_no": en_yuksek["no"], "e_varlik": en_yuksek["varlik"], "e_tur": en_yuksek["tur"]},
        "cevaplar": {
            "kapsam_ici": [a["no"] for a in kapsamda],
            "kopya": kopya["no"],
            "odul": sum(odul[a["onem"]] for a in gecerli),
        },
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "program" / "kapsam.txt",
          f"{v['ad']}\n\nKAPSAM İÇİ: *.{v['alan']} (bütün alt alanlar)\n" + "".join(
              f"KAPSAM DIŞI: {x}.{v['alan']} ({neden})\n" for x, neden in v["dis"])
          + f"KAPSAM DIŞI: {v['ucuncu']} (programın sahibi değil)\n\nKURALLAR:\n" + "".join(f"- {k}\n" for k in v["kurallar"])
          + "- Aynı açığın ilk bildirimi ödül alır; sonrakiler kopya (duplicate) sayılır.\n")
    u.yaz(lab / "program" / "odul_tablosu.csv", "onem;odul_tl\n" + "".join(f"{k};{t}\n" for k, t in v["odul"].items()))
    u.yaz(lab / "program" / "bilinen_bulgular.txt", "".join(f"{h};{t}\n" for h, t in s["bilinen"]))
    u.yaz(lab / "bulgularim.csv", "no;varlik;tur;onem\n" + "".join(
        f"{a['no']};{a['varlik']};{a['tur']};{a['onem']}\n" for a in s["adaylar"]))
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']}\n\nprogram/kapsam.txt             programın kapsamı ve kuralları\n"
          "program/odul_tablosu.csv      önem derecesine göre ödül (TL)\n"
          "program/bilinen_bulgular.txt  daha önce bildirilmiş bulgular (varlık;tür)\n"
          "bulgularim.csv                senin 6 aday bulgun\n"
          "bildirim.md                   SENİN yazacağın bildirim (görev 5)\n")


def _bildirim(b) -> Sonuc:
    s = b.senaryo
    e = s["en_yuksek"]
    yol = b.lab / "bildirim.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `bildirim.md` yok. En önemli geçerli bulgun için bildirimini bu dosyaya yaz.")
    t = yol.read_text(encoding="utf-8", errors="replace")
    k = t.casefold()
    if e["varlik"].casefold() not in k:
        return Sonuc(False, f"Bildirimde etkilenen varlık (`{e['varlik']}`) geçmiyor. Bildirim hangi sistemde olduğunu açıkça söylemeli.", yakin=True)
    parcalar = [w for w in re.split(r"\W+", e["tur"].casefold()) if len(w) > 3] or [e["tur"].casefold()]
    if not any(p in k for p in parcalar):
        return Sonuc(False, f"Bildirimde açığın türü (`{e['tur']}`) anlatılmamış.", yakin=True)
    for dh in s["dis_hostlar"]:
        if dh.casefold() in k:
            return Sonuc(False, f"Bildirimde kapsam dışı bir sistem (`{dh}`) adı geçiyor. Kapsam dışı sistemler için ayrı bildirim yazılmaz.", yakin=True)
    adim_sayisi = len(re.findall(r"(?m)^\s*\d+[.)]\s+\S", t))
    if adim_sayisi < 3:
        return Sonuc(False, "Yeniden üretme adımlarını numaralı liste olarak yaz (`1. ...`, `2. ...`, `3. ...`). En az 3 adım.", yakin=True)
    eksik = []
    if "etki" not in k:
        eksik.append("etki")
    if not any(x in k for x in ("çözüm", "cozum", "öneri", "oneri")):
        eksik.append("çözüm önerisi")
    if eksik:
        return Sonuc(False, "Bildirimde şu bölümler eksik: " + ", ".join(eksik) + ".", yakin=True)
    if len(t.split()) < 35:
        return Sonuc(False, "Bildirim çok kısa. Güvenlik ekibi tek başına anlayıp yeniden üretebilmeli (en az ~35 kelime).", yakin=True)
    return Sonuc(True, "Bildirimin güvenlik ekibinin işini kolaylaştırıyor: varlık, tür, adımlar, etki ve çözüm var; kapsam dışına taşmıyor.")


def coz(lab: Path, s: dict) -> dict:
    kapsam = o.sh("alan=$(grep 'KAPSAM İÇİ' program/kapsam.txt | sed 's/.*\\*\\.//' | cut -d' ' -f1); "
                  "dis=$(grep 'KAPSAM DIŞI:' program/kapsam.txt | sed 's/KAPSAM DIŞI: *//' | cut -d' ' -f1 | tr '\\n' ' '); "
                  "awk -F';' -v alan=\"$alan\" -v dis=\"$dis\" 'NR>1{n=split(dis,d,\" \"); ok=($2 ~ (\"\\\\.\" alan \"$\")); "
                  "for(i=1;i<=n;i++) if($2==d[i]) ok=0; if(ok) print $1}' bulgularim.csv", lab)
    ids = kapsam.split()
    kopya = ""
    gecerli = []
    for i in ids:
        satir = o.sh(f"awk -F';' '$1=={i}{{print $2\";\"$3}}' bulgularim.csv", lab)
        if o.sh(f"grep -cFx '{satir}' program/bilinen_bulgular.txt", lab) == "1":
            kopya = i
        else:
            gecerli.append(i)
    alt = "|".join(gecerli)
    odul = o.sh("awk -F';' 'NR==FNR{o[$1]=$2; next} FNR>1 && $1 ~ /^(" + alt + ")$/ {s+=o[$4]} END{print s}' "
                "program/odul_tablosu.csv bulgularim.csv", lab)
    e = s["en_yuksek"]
    (lab / "bildirim.md").write_text(
        f"# Bildirim: {e['tur']} — {e['varlik']}\n\nÖzet: {e['varlik']} üzerinde {e['tur']} sınıfında bir açık buldum.\n\n"
        f"Adımlar:\n1. Kendi test hesabımla {e['varlik']} adresine giriş yaptım.\n2. İlgili isteği normal akıştan farklı bir değerle gönderdim.\n"
        "3. Yanıtın beklenenden fazlasını gösterdiğini doğruladım ve durdum.\n\n"
        "Etki: Kullanıcı verilerinin yetkisiz görülmesine yol açabilir.\nÇözüm önerisi: Sunucu tarafında yetki kontrolü uygulanmalı.\n"
        "Kanıt: İstek ve yanıt kaydı ekte; gerçek müşteri verisi indirilmedi.\n", encoding="utf-8")
    cozum = {1: kapsam, 2: kopya, 3: odul, 4: "", 5: "", 6: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Bug bounty nedir?", """
**Bug bounty**, şirketlerin sistemlerini test etmen için sana **açıkça izin verdiği** (ve bulduğun açıklara
ödül verdiği) programlardır. Yasal olarak pratik yapmanın ve hatta para kazanmanın bir yoludur. Ama izin
**yalnızca kapsam içindedir**: kapsam dışı bir sistemi test etmek, program genel bir izin vermiş olsa bile
suçtur. Önce programın kapsam dosyasını oku:
""", komut="cat program/kapsam.txt", sonra="""
Üç şeye dikkat: **joker karakter** (`*.alan` bütün alt alanlar demek), joker karaktere rağmen **istisnalar**
(açıkça kapsam dışı listelenen alt alanlar) ve alan adı farklı olan **üçüncü taraf** sistemler. Kuralları da
oku: yasak teknikler programa göre değişir.
"""),
    Adim("Kendi aday bulguların", """
Bir hafta test ettin ve altı aday bulgun var. Hepsini bildirmeden önce **ayıklamalısın**: kapsam dışı olanlar
ödenmez ve bildirilmemelidir; zaten bilinenler kopya sayılır. Adaylara bak:
""", komut="cat bulgularim.csv"),
    Adim("Kopya (duplicate) kontrolü", """
Programlar daha önce bildirilmiş bulguları tutar. Aynı **varlık + tür** daha önce bildirildiyse senin raporun
kopyadır ve ödül almaz. (Bu yüzden **ilk bildiren** olmak önemli.) Bilinenlere bak:
""", komut="cat program/bilinen_bulgular.txt", sonra="""
Dikkat: aynı hostta **farklı** türde bir açık kopya değildir; kopya olması için hem varlık hem tür aynı olmalı.
"""),
    Adim("Ödül tablosu", """
Ödül, onaylanan bulgunun **önem derecesine** göre belirlenir:
""", komut="cat program/odul_tablosu.csv"),
    Adim("Tablodan ödül hesabı", """
`awk` iki dosyayı birlikte okuyup birleştirebilir: ilk dosyadaki `onem → odul` eşlemesini belleğe alır
(`NR==FNR`), ikinci dosyada her bulgunun ödülünü yazar. Hangi aday bulguların ne kadar ödül getireceğini gör:
""", komut="awk -F';' 'NR==FNR{o[$1]=$2; next} FNR>1{print $1, $4, o[$4]}' program/odul_tablosu.csv bulgularim.csv", sonra="""
Bu liste **tüm** adayları içerir; geçerli olmayanlar (kapsam dışı, kopya) ödemeye dahil değil. Gerçek ödemede
yalnızca geçerli bulguların ödülü toplanır.

**Hacker gözüyle:** En iyi başlangıç, tek bir açık türünde uzmanlaşmak ve **VDP** (ödül vermeyen ama yasal
pratik sunan programlar) ile deneyim kazanmaktır. İlk geçerli bulgu, yüzlerce "duplicate" ve "informative"
sonrasında gelebilir; sabır bu işin parçası.
"""),
]

GOREVLER = [
    Gorev("`program/kapsam.txt`'e göre, `bulgularim.csv` içindeki hangi adayların varlığı **kapsam içindedir**? "
          "(bulgu numaraları)",
          Kume("kapsam_ici", tur="sayi", bicim="bulgu numaraları (örn. 1 2 4 5)",
               sik_hatalar=lambda g, b, bg: "Joker karakter (`*.alan`) bütün alt alanları kapsar ama listelenen istisnaları ve "
               "alan adı farklı olan üçüncü taraf sistemleri kapsamaz."),
          ("Kapsamı üç adımda oku: joker karakter, istisnalar, farklı alan adı.",
           "Önce `*.alan` kuralına uymayanları ele, sonra `KAPSAM DIŞI` olarak adı geçen alt alanları çıkar.",
           "`bulgularim.csv`'deki her varlığı kapsam dosyasıyla karşılaştır: alan adı farklıysa ya da istisna listesindeyse dışarıda."),
          puan=40, baslik="Kapsam okuma"),
    Gorev("Kapsam içindeki adaylardan **hangisi kopyadır** (varlık ve tür daha önce bildirilmiş)? (bulgu numarası)",
          Metin("kopya", bicim="bulgu numarası"),
          ("`program/bilinen_bulgular.txt` ile kapsam içi adayları karşılaştır: hem varlık hem tür aynı mı?",
           "Aynı hostta farklı bir tür kopya değildir; ikisinin birlikte eşleşmesi gerekir.",
           "Aday satırının `varlık;tür` kısmını `grep -F` ile bilinen bulgular dosyasında ara."),
          puan=40, baslik="Kopya bulgu"),
    Gorev("Geçerli bulgularının (kapsam içi ve kopya olmayan) **beklenen toplam ödülü kaç TL**'dir?",
          Sayi("odul", sik_hatalar=lambda g, b, bg: "Kapsam dışı ya da kopya bir bulgunun ödülünü de toplamış olabilirsin. "
                "Sadece geçerli olanlar toplanır." if g.isdigit() and int(g) > b else None),
          ("Önce geçerli bulguları belirle (önceki iki görev), sonra her birinin ödülünü tablodan bul.",
           "Tabloyla eşleştiren `awk` komutunu eğitimde gördün; geçerli numaralarla süz ve topla.",
           "Geçerli bulguların `onem` değerlerine bakıp `program/odul_tablosu.csv`'den ödülleri elle ya da `awk` ile topla."),
          puan=40, baslik="Beklenen ödül"),
    Gorev("Bir kapsam içi alt alanı test ederken, **binlerce gerçek kullanıcının** bilgilerini içeren bir liste "
          "açık olarak karşına çıktı. Doğru davranış hangisidir?",
          Secmeli([
              ("Durmak, veriyi indirmemek ve maskeli tek örnekle hemen bildirmek", "Doğru: gerçek kullanıcı verisi hassastır; amaç açığı kanıtlamaktır, veriyi toplamak değil. Minimum kanıt, maksimum koruma."),
              ("Hepsini indirip bildirime ek olarak göndermek, kanıt tam olsun diye", "Yanlış: gerçek kişilerin verisini toplamak programın kurallarını ve çoğu zaman hukuku ihlal eder; kanıt için tek maskeli örnek yeter."),
              ("Daha çok açık bulmak için birkaç gün daha aynı veriyi gözlemlemeye devam etmek", "Yanlış: erişimi sürdürmek zararı ve hukuki riski artırır; durup bildirmek gerekir."),
              ("Arkadaşlarına durumu anlatıp ne yapılacağını birlikte oylamak", "Yanlış: bulguyu üçüncü kişilerle paylaşmak, açık kapanmadan sızıntı riskini artırır."),
          ], dogru=0),
          ("Amacın açığı kanıtlamak mı, veriyi toplamak mı?",
           "Gerçek kişilerin verisine karşı sorumluluğunu düşün: ne kadar kanıt yeter?",
           "Doğru şık, 'durmak ve indirmeden bildirmek' diyen şık."),
          puan=30, baslik="Veriyle karşılaşınca"),
    Gorev("**Bildir:** En önemli **geçerli** bulgun (`<<e_no>>` numaralı, `<<e_varlik>>`, `<<e_tur>>`) için `bildirim.md` "
          "dosyasına bir bildirim yaz: varlık, açığın türü, **en az 3 numaralı** yeniden üretme adımı, etki ve çözüm önerisi. "
          "Kapsam dışı bir sistemden söz etme. Bitince `cevap 5` yaz.",
          Durum(_bildirim, cozum="`bildirim.md`: başlıkta varlık ve tür; `1.` `2.` `3.` adımları; `Etki:`; `Çözüm önerisi:`; kapsam dışı host adı yok."),
          ("İyi bildirim güvenlik ekibinin işini kolaylaştırır: ne, nerede, nasıl, etkisi ne, nasıl düzeltilir.",
           "Önce özet, sonra `1.` `2.` `3.` numaralı adımlar, ardından `Etki:` ve `Çözüm önerisi:` bölümleri.",
           "`nano bildirim.md`; ilk satırda varlığı (`<<e_varlik>>`) ve türü (`<<e_tur>>`) yaz; 3 adımı numaralandır; yalnızca kendi test hesabını kullandığını belirt."),
          puan=70, baslik="Bildirimi yaz"),
    Gorev("Bildirimini gönderdin ve cevap gelmedi. Doğru davranış hangisidir?",
          Secmeli([
              ("Programın kurallarına uymak: nazikçe takip etmek, süre tanımak, yayımlamamak", "Doğru: sorumlu bildirim, açığın düzeltilmesine zaman tanıyıp koordineli yayımlamaktır; kamuya açmadan önce program/izin kuralları aranır."),
              ("Hemen blogda ayrıntılı bir yazı yayımlayıp şirketi kamuoyu baskısı altına almak", "Yanlış: açık düzeltilmeden ayrıntı vermek gerçek kullanıcıları riske atar ve programın kurallarını ihlal eder."),
              ("Açığı başka bir şirkete ya da üçüncü bir alıcıya ücret karşılığı satmak", "Yanlış: izinsiz satış sorumlu bildirim değildir ve ciddi hukuki sonuçlar doğurabilir."),
              ("Açığı bir kez daha kullanıp etkisini daha etkileyici göstermeye çalışmak", "Yanlış: kanıt verdiğin noktada durmalısın; ek istismar kapsam ve etik sınırlarını aşar."),
          ], dogru=0),
          ("Amaç şirketi cezalandırmak mı, açığın kapanmasını sağlamak mı?",
           "'Sorumlu bildirim' tabirini düşün: sorumluluk kime karşı?",
           "Doğru şık, programın kurallarına uymayı ve izinsiz yayımlamamayı söyleyen şık."),
          puan=30, baslik="Sorumlu bildirim"),
    Gorev("Yeni başlayan biri için aşağıdakilerden hangisi iyi bir bug bounty başlangıç stratejisidir?",
          Secmeli([
              ("VDP programlarıyla deneyim kazanmak ve tek bir açık türünde uzmanlaşmak", "Doğru: VDP ödül vermese de yasal pratik sunar; dar bir alanda derinleşmek rekabetin yoğun olduğu yerde fark yaratır."),
              ("Bütün açık türlerini yüzeysel öğrenip aynı anda her programa girmek", "Yanlış: yüzeysel bilgi kopya ve 'informative' bulgularla sonuçlanır; derinlik fark yaratır."),
              ("Önce kapsam okumadan hızla test edip sonra neyin kapsamda olduğuna bakmak", "Yanlış: kapsam dışına çıkmak ödül yerine yasal sorun getirir; kapsamı önce oku."),
              ("Yalnızca en yüksek ödüllü programlara başvurmak, çünkü rekabet orada azdır", "Yanlış: en yüksek ödüllü programlarda rekabet en yoğundur."),
          ], dogru=0),
          ("Kitabın 'Hacker gözüyle' kutusunda hangi iki öneri vardı?",
           "VDP ile ödüllü programın farkı ne, ve neden dar alan?",
           "Doğru şık VDP ve uzmanlaşmayı birlikte öneren şık."),
          puan=20, baslik="Başlangıç stratejisi"),
]


def _kapanis():
    return """
Bug bounty, izin ile suç arasındaki çizginin **kapsam**dan geçtiğini en açık gösteren alandır: aynı istek, kapsam
içinde bir bulgu; kapsam dışında bir suçtur. Bu bölümde bulgularını üç süzgeçten geçirdin: kapsam, kopya ve
etik. Saldırgan bakışıyla düşünürsen, kapsam kuralları şirketin "buraya dokunma" dediği yerleri de gösterir;
savunma bakışıyla ise programın kendisi, dış araştırmacıları sistemli ve yasal bir kanaldan faydalı kılmaktır.
En değerli alışkanlık: bildirimi güvenlik ekibinin işini kolaylaştıracak şekilde yazmak, gerçek kullanıcı
verisine mümkün olduğunca az dokunmak ve açık kapanana kadar sessiz kalmak.
""".rstrip() + "\n"


SEVIYE = Seviye(
    kimlik="c08b03",
    cilt=8,
    bolum=3,
    baslik="Bug Bounty: İzinli Avcılık",
    brifing="""
**<<program>>**'ne bir hafta boyunca test yaptın ve altı aday bulgun var. Selin kahve tazelerken sana soruyor: "Hepsini
gönderirsen ne olur?" Cevabı kendin verirsin: "Kapsam dışı olanlar ödenmez, hatta suç olur; kopyalar ödenmez; bir de
bildirimini iyi yazmazsan güvenlik ekibi yeniden üretemez."

Mert gülüyor: "<<kisi>> bu programı sıkı tutuyor. Önce kapsamı oku; joker karakterin altında bile istisna var."

Görevin: adayları ayıkla, beklenen ödülü hesapla ve en önemli geçerli bulgunu düzgünce bildir.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Hack the Pentagon (2016):** ABD Savunma Bakanlığı, devletin ilk büyük bug bounty programlarından birini
  yürüttü; dışarıdan araştırmacıların belirli kapsamdaki sistemlerde açık bulup bildirmesine izin verdi.
  Program, izin ve kapsamın yazılı olduğu bir bug bounty'nin devlet düzeyinde de kullanıldığını gösterdi.
- **Güvenlik iletişim bilgisi:** Pek çok şirket, kendi sitesinde `/.well-known/security.txt` dosyası
  (RFC 9116) yayımlayarak araştırmacılara güvenlik bildirimlerini nereye göndereceklerini söyler. Böyle
  bir kanal varsa bildirim oraya yapılır; yoksa şirketin resmî güvenlik iletişim kanalı aranır.
- **Tespit ve önleme:** Programlar, kapsam dışı istekleri ayırt etmek için araştırmacıdan kendi hesaplarını
  ve belirli başlıkları kullanmasını isteyebilir; şirketler gelen bildirimleri hızlıca üretim kopyası
  olmayan ortamda yeniden üretmeli, kopya yönetimi ve ödül süreçlerini açık tutmalıdır.
""",
    sure_hedef_dk=30,
)
