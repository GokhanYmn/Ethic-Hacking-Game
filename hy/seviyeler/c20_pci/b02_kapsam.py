"""Cilt 20 · Bölüm 2 — PCI-DSS İlkeleri: Kapsam ve Segmentasyon.

Beceri: kurgusal bir ağ envanterinden ve güvenlik duvarı kurallarından PCI-DSS kapsamını (kart ortamı, CDE)
belirlemek, segmentasyonu delen bir kuralı bulmak ve düzeltmek. `cevap <no>` komutu kural dosyasının son
halini kontrol eder (Durum görevi).

Basitleştirilmiş kapsam kuralı (lab içinde geçerli): kapsam = kart verisini saklayan/işleyen/ileten sistemler
+ kart ortamı (CDE) segmentindeki tüm sistemler + CDE'ye **her porttan** (`port=any`) erişebilen segmentlerdeki
tüm sistemler. Vakalar: e-ticaret, fintech, hastane tahsilat ağı.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c20_pci.ortak import sec_doldur, sh

# sistem: (ad, segment_anahtari, kart_verisi, açıklama)
VAKALAR = [
    {"vaka": "Pazarix — e-ticaret ağı", "musteri": "Pazarix", "klasor": "ag", "kisi": "Tuncay Bey (sistem yöneticisi)",
     "seg": {"ofis": "ofis_agi", "dmz": "dmz_web", "cde": "kart_ortami", "yonetim": "yonetim_agi", "misafir": "misafir_wifi"},
     "sistemler": [("odeme_uygulamasi", "cde", "isler", "kartı sağlayıcıya iletir"),
                   ("kart_veritabani", "cde", "saklar", "şifreli PAN deposu"),
                   ("token_servisi", "cde", "isler", "PAN yerine token üretir"),
                   ("web_vitrin", "dmz", "iletir", "ödeme formu sayfası"),
                   ("api_gecidi", "dmz", "yok", "mağaza API'si"),
                   ("muhasebe_pc", "ofis", "yok", "muhasebe"),
                   ("destek_pc", "ofis", "yok", "müşteri hizmetleri"),
                   ("eski_raporlama", "ofis", "saklar", "eski satış raporları (maskesiz PAN içeriyor)"),
                   ("yedek_sunucusu", "yonetim", "yok", "gece yedekleri"),
                   ("izleme_sunucusu", "yonetim", "yok", "sunucu izleme"),
                   ("bastion", "yonetim", "yok", "yönetici sıçrama sunucusu"),
                   ("misafir_ap", "misafir", "yok", "ziyaretçi kablosuz ağı")],
     "sahne": "Pazarix, PCI-DSS denetçisine ağ envanterini ve güvenlik duvarı kurallarını sunacak. Tuncay Bey: "
              "\"Denetçi 'kapsamınız ne' diye soracak ve ben 'her şey' demekten korkuyorum. Gerçekten hangi "
              "sistemler kapsamda, bakar mısın?\""},
    {"vaka": "Paramix — ödeme geçidi ağı", "musteri": "Paramix", "klasor": "pci_ag", "kisi": "Ece Hanım (CTO)",
     "seg": {"ofis": "kurumsal_lan", "dmz": "api_bolgesi", "cde": "cde_vlan30", "yonetim": "ops_agi", "misafir": "gelistirme_agi"},
     "sistemler": [("pmx-odeme01", "cde", "isler", "ödeme yetkilendirme"),
                   ("pmx-vault", "cde", "saklar", "şifreli PAN kasası"),
                   ("pmx-token", "cde", "isler", "token servisi"),
                   ("pmx-checkout", "dmz", "iletir", "üye işyeri ödeme sayfası"),
                   ("pmx-api", "dmz", "yok", "üye işyeri API'si"),
                   ("pmx-ik", "ofis", "yok", "İK sistemi"),
                   ("pmx-crm", "ofis", "yok", "müşteri ilişkileri"),
                   ("pmx-eski-rapor", "ofis", "saklar", "eski mutabakat dosyaları (maskesiz PAN)"),
                   ("pmx-yedek", "yonetim", "yok", "yedekleme"),
                   ("pmx-izleme", "yonetim", "yok", "izleme paneli"),
                   ("pmx-bastion", "yonetim", "yok", "yönetim sıçrama sunucusu"),
                   ("pmx-dev01", "misafir", "yok", "geliştirme sunucusu")],
     "sahne": "Paramix, bir banka iş ortaklığı için PCI-DSS uyum değerlendirmesine giriyor. Ece Hanım: \"Kapsamı "
              "ne kadar dar tutabilirsek maliyet o kadar düşer. Ama önce hangi sistemlerin gerçekten içeride "
              "olduğunu bilmeliyiz.\""},
    {"vaka": "Medora Sağlık — tahsilat ağı", "musteri": "Medora Sağlık", "klasor": "tahsilat_agi",
     "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
     "seg": {"ofis": "hastane_lan", "dmz": "portal_dmz", "cde": "tahsilat_cde", "yonetim": "bt_yonetim", "misafir": "hasta_wifi"},
     "sistemler": [("tahsilat_app", "cde", "isler", "kartlı tahsilat uygulaması"),
                   ("tahsilat_db", "cde", "saklar", "şifreli kart kayıtları"),
                   ("token_gecidi", "cde", "isler", "token üretir"),
                   ("hasta_portali", "dmz", "iletir", "online ödeme sayfası"),
                   ("randevu_api", "dmz", "yok", "randevu servisi"),
                   ("hekim_pc", "ofis", "yok", "hekim iş istasyonu"),
                   ("kayit_pc", "ofis", "yok", "hasta kabul"),
                   ("eski_muhasebe", "ofis", "saklar", "eski tahsilat dosyaları (maskesiz PAN)"),
                   ("yedek_nas", "yonetim", "yok", "yedek depolama"),
                   ("izleme_vm", "yonetim", "yok", "izleme"),
                   ("bt_bastion", "yonetim", "yok", "yönetici sıçrama sunucusu"),
                   ("hasta_ap", "misafir", "yok", "hasta kablosuz ağı")],
     "sahne": "Medora Sağlık'ın tahsilat ağı bankanın PCI-DSS denetiminden geçecek. Dr. Aslı Hanım: \"Hastane ağı "
              "dümdüz bir ağ; kart işleyen yerlerle işlemeyenler karışmış olabilir. Önce kapsamı çıkaralım.\""},
]


def _kapsam(s: dict) -> set:
    v = s["v"]
    kapsam = set()
    for ad, seg, kart, _ in v["sistemler"]:
        if kart != "yok" or seg == "cde" or seg == s["any_kaynak"]:
            kapsam.add(ad)
    return kapsam


def uret(rng):
    v = rng.choice(VAKALAR)
    any_kaynak = rng.choice(["yonetim", "ofis"])
    s = {"vaka": v["vaka"], "v": v, "any_kaynak": any_kaynak}
    seg = v["seg"]
    kurallar = [
        ("izin", "ofis", "dmz", "443"), ("izin", "misafir", "dmz", "443"), ("izin", "dmz", "cde", "8443"),
        ("izin", "ofis", "yonetim", "22"), ("izin", any_kaynak, "cde", "any"),
    ]
    kurallar.append(("izin", "yonetim", "ofis", "22,3389"))
    rng.shuffle(kurallar)
    s["kurallar"] = kurallar
    no = [i for i, k in enumerate(kurallar, 1) if k[3] == "any"][0]
    s["no_any"] = no
    direkt = sorted(ad for ad, _, kart, _ in v["sistemler"] if kart != "yok")
    s["metin"] = {"musteri": v["musteri"], "sahne": v["sahne"], "kisi": v["kisi"], "klasor": v["klasor"],
                  "cde": seg["cde"]}
    s["cevaplar"] = {"direkt": direkt, "kapsam_sayi": len(_kapsam(s)), "kural_no": no}
    return s


def _kural_satiri(i: int, k: tuple, seg: dict) -> str:
    return f"K{i:02d} {k[0]} {seg[k[1]]} -> {seg[k[2]]} port={k[3]}"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    seg = v["seg"]
    k = lab / v["klasor"]
    u.yaz(lab / "OKUBENI.txt", f"{v['musteri']} PCI-DSS kapsam çalışması (kurgusal).\n"
          "Kapsam kuralı (basitleştirilmiş): kart verisini saklayan/işleyen/ileten sistemler + kart ortamı (CDE) "
          "segmentindeki tüm sistemler + CDE'ye HER PORTTAN (port=any) erişebilen segmentlerdeki tüm sistemler.\n"
          f"{v['klasor']}/ : envanter.csv, ag_diyagrami.txt, guvenlik_duvari.rules\n")
    u.yaz(k / "envanter.csv", "sistem,segment,kart_verisi,aciklama\n" + "".join(
        f"{ad},{seg[sg]},{kart},{ac}\n" for ad, sg, kart, ac in v["sistemler"]))
    sistemler_by = {}
    for ad, sg, _, _ in v["sistemler"]:
        sistemler_by.setdefault(sg, []).append(ad)
    diyagram = ["  [internet]", "      |"]
    for sg in ("dmz", "ofis", "misafir", "yonetim", "cde"):
        diyagram.append(f"  ( {seg[sg]} )  :  " + ", ".join(sistemler_by[sg]))
    diyagram += ["", "  Segmentler arası geçişi yalnızca güvenlik duvarı kuralları belirler (guvenlik_duvari.rules)."]
    u.yaz(k / "ag_diyagrami.txt", "\n".join(diyagram) + "\n")
    satirlar = ["# kural_no eylem kaynak -> hedef port", "# kurallar sırayla değerlendirilir; hiçbiri uymazsa varsayılan geçerli"]
    satirlar += [_kural_satiri(i, kk, seg) for i, kk in enumerate(s["kurallar"], 1)]
    satirlar.append("varsayilan: reddet")
    u.yaz(k / "guvenlik_duvari.rules", "\n".join(satirlar) + "\n")


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    k = v["klasor"]
    cde = v["seg"]["cde"]
    direkt = sh(f"awk -F, 'NR>1 && $3!=\"yok\" {{print $1}}' {k}/envanter.csv", lab).replace("\n", " ")
    any_seg = sh(f"grep 'port=any' {k}/guvenlik_duvari.rules | grep -- '-> {cde} ' | awk '{{print $3}}'", lab)
    sayi = sh(f"awk -F, -v c={cde} -v a={any_seg} 'NR>1 && ($3!=\"yok\" || $2==c || $2==a) {{n++}} END {{print n}}' {k}/envanter.csv", lab)
    no = sh(f"grep -- 'port=any' {k}/guvenlik_duvari.rules | grep -- '-> {cde} ' | awk '{{print $1}}' | tr -d K", lab)
    sh(f"sed -i '/port=any/d' {k}/guvenlik_duvari.rules", lab)
    return sec_doldur({2: direkt, 3: sayi, 4: no, 5: ""}, GOREVLER, lab, s)


def _kural_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    seg = v["seg"]
    try:
        metin = (b.lab / v["klasor"] / "guvenlik_duvari.rules").read_text(encoding="utf-8")
    except OSError:
        return Sonuc(False, "Kural dosyası okunamadı.")
    kurallar = []
    for satir in metin.splitlines():
        m = re.match(r"^K\d+\s+izin\s+(\S+)\s+->\s+(\S+)\s+port=(\S+)", satir.strip())
        if m:
            kurallar.append(m.groups())
    if "varsayilan: reddet" not in metin:
        return Sonuc(False, "Varsayılan 'reddet' satırını silmişsin; kuralların dışındaki her şey artık serbest kalır.")
    gecis = [x for x in kurallar if x[0] == seg["dmz"] and x[1] == seg["cde"]]
    if not gecis:
        return Sonuc(False, "Ödeme akışının ihtiyacı olan meşru kuralı (dmz -> kart ortamı) silmişsin; ödemeler çalışmaz.")
    delik = [x for x in kurallar if x[1] == seg["cde"] and (x[2] == "any" or not re.fullmatch(r"\d+(,\d+)*", x[2]))]
    if delik:
        return Sonuc(False, f"Kart ortamına `{delik[0][2]}` portu açık bir kural hâlâ duruyor ({delik[0][0]} kaynaklı). "
                            "Kaldır ya da yalnızca gereken portlara indir.", yakin=True)
    if len(kurallar) < 4:
        return Sonuc(False, "Çok fazla kural silmişsin; yalnızca segmentasyonu delen kuralı düzelt.")
    return Sonuc(True, "Kart ortamına artık yalnızca belirli portlardan erişiliyor; segmentasyon tamam.")


def _kapsam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    v = b.senaryo["v"]
    direkt = sum(1 for x in v["sistemler"] if x[2] != "yok")
    cde = sum(1 for x in v["sistemler"] if x[1] == "cde")
    if n == direkt:
        return "Yalnızca kart verisine doğrudan dokunanları saymışsın. CDE segmentindeki ve CDE'ye `port=any` ile erişen segmentlerdeki sistemler de kapsamda."
    if n == len(v["sistemler"]):
        return "Bütün envanteri saymışsın; kapsamı daraltma işi tam da bu: her sistem kapsamda değil."
    return None


ADIMLAR = [
    Adim("Envanter: kim kart görüyor?", """
PCI-DSS'te en önemli soru **kapsam**tır: kart verisine dokunan her sistem denetime girer. Önce envantere bak.
Her satırda sistem, ağ bölümü (segment) ve kart verisiyle ilişkisi var: `saklar`, `isler`, `iletir`, `yok`.
""", komut="cat <<klasor>>/envanter.csv", sonra="""
Kart verisini **saklayan, işleyen ya da ileten** her sistem kapsamdadır. `yok` yazan bir sistem bile başka
nedenlerle kapsama girebilir (aşağıda göreceksin).
"""),
    Adim("Ağ diyagramı", """
Segmentler, ağın duvarlarla ayrılmış odalarıdır. Hangi sistem hangi odada?
""", komut="cat <<klasor>>/ag_diyagrami.txt", sonra="""
Kart ortamı (**CDE**, Cardholder Data Environment) `<<cde>>` segmentidir. Bir sistem kart görmese bile
**CDE'nin içindeyse kapsamdadır**: çünkü aynı segmentte duran bir sistem, kart sistemlerine doğrudan
ulaşabilir.
"""),
    Adim("Duvarlardaki kapılar: güvenlik duvarı kuralları", """
Segmentler arası geçişi güvenlik duvarı kuralları belirler. Her kural: kimden, kime, hangi porttan:
""", komut="cat <<klasor>>/guvenlik_duvari.rules", sonra="""
İyi bir kural **dar**dır: tek kaynak, tek hedef, tek port. `port=any` ise "her porttan gir" demektir; bu kapıyı
kullanabilen tüm sistemler fiilen CDE'nin parçası olur ve **kapsama girer**.
"""),
    Adim("Kapsamda olanları süzmek", """
`awk -F,` virgülle ayrılmış envanterde sütunlarla çalışır: `$3` üçüncü sütun (kart verisi). `!=` "eşit değil"
demektir. Kart verisine doğrudan dokunan sistemleri listele:
""", komut="awk -F, 'NR>1 && $3!=\"yok\" {print $1}' <<klasor>>/envanter.csv", sonra="""
`NR>1` başlık satırını atlar. Bu liste **doğrudan** kapsamdır; CDE segmentindekiler ve `port=any` ile bağlı
segmentler buna eklenir.
"""),
    Adim("Delik kapıyı bulmak", """
`grep` ile segmentasyonu delen kuralı bul: hedefi kart ortamı olup porta kısıtı olmayan kural:
""", komut="grep 'port=any' <<klasor>>/guvenlik_duvari.rules", sonra="""
**Hacker gözüyle:** Saldırganın bir ofis bilgisayarını ele geçirip kart ortamına sıçraması, ağ yatay
hareketinin klasik örneğidir (Cilt 6). Segmentasyon bunu engelleyen duvardır; `port=any` ise duvardaki kapıdır.
Denetçi için de iyi haber: kapıyı kapatınca kapsam da küçülür.
"""),
    Adim("Düzeltme: sed", """
`sed -i '/desen/d' dosya` eşleşen satırı **siler**; `sed -i 's/eski/yeni/' dosya` değiştirir. Silmeden
önce neyi sileceğini gör (`-n` ve `p` yalnızca yazdırır):
""", komut="sed -n '/port=any/p' <<klasor>>/guvenlik_duvari.rules", sonra="""
Delik kuralı **kaldırmak** ya da yalnızca gereken **belirli portlara indirmek** iki geçerli çözümdür. Ama
ödeme akışının ihtiyaç duyduğu meşru kuralı (dmz -> CDE) ve varsayılan `reddet` satırını silme.
"""),
]

GOREVLER = [
    Gorev("PCI-DSS'te 'kapsamı daraltmak' neden en önemli stratejik karardır?",
          Secmeli([
              ("Denetlenen sistem sayısı azaldıkça koruma ve denetim yükü de azalır",
               "Doğru. Kapsam küçüldükçe hem maliyet hem saldırı yüzeyi küçülür."),
              ("Kapsam daraldığında standart gereksinimleri kalkar ve sistemler denetimden muaf olur",
               "Yanlış. Kapsam içindeki sistemler için gereksinimler aynen geçerlidir; kapsam dışı kalanlar zaten kart görmez."),
              ("Denetçi yalnızca bildirilen sistemlere bakar; bu yüzden listeyi kısa tutmak yeterlidir",
               "Yanlış. Kapsamı denetçi ve ağ gerçeği belirler; sistemleri saklamak uyumu değil riski artırır."),
              ("Kapsamı daraltmak yalnızca kart numaralarının uzunluğunu kısaltmak anlamına gelir",
               "Yanlış. Kapsam, kart verisine dokunan sistemler kümesidir; numara uzunluğuyla ilgisi yok."),
          ], dogru=0),
          ("Kitaptaki cümleyi hatırla: kapsam her şeydir.",
           "Denetlenecek sistem sayısı azalırsa ne azalır?",
           "Cevap: koruma ve denetim yükü, saldırı yüzeyi."),
          puan=20, baslik="Kapsam"),
    Gorev("`<<klasor>>/envanter.csv` içinde kart verisini **doğrudan saklayan, işleyen ya da ileten** sistemler hangileri? "
          "Adları boşlukla yaz.",
          Kume("direkt", tur="metin", bicim="sistem adları, boşlukla ayrılmış"),
          ("Envanterin `kart_verisi` sütununa bak: `yok` olmayanlar.",
           "`awk -F,` ile üçüncü sütunu `yok`'a eşit olmayanları süz.",
           "`awk -F, 'NR>1 && $3!=\"yok\" {print $1}' <<klasor>>/envanter.csv`"),
          puan=40, baslik="Doğrudan dokunanlar"),
    Gorev("Toplam **kapsamdaki sistem sayısı** kaç? (Basit kural OKUBENI'de: doğrudan dokunanlar + CDE segmentindekiler "
          "+ CDE'ye `port=any` ile erişen segmentlerdeki sistemler; her sistem bir kez sayılır.)",
          Sayi("kapsam_sayi", sik_hatalar=_kapsam_hata),
          ("Üç kümenin birleşimi: doğrudan dokunan, CDE'deki, `port=any` kaynağındaki. Birden fazla kümede olan sistemi tek say.",
           "Önce `port=any` kuralının **kaynak segmentini** bul; sonra o segmentin sistemlerini ekle.",
           "`awk -F, -v c=<<cde>> -v a=KAYNAK_SEGMENT 'NR>1 && ($3!=\"yok\" || $2==c || $2==a) {n++} END {print n}' <<klasor>>/envanter.csv`"),
          puan=50, baslik="Kapsam büyüklüğü"),
    Gorev("`<<klasor>>/guvenlik_duvari.rules` içinde **segmentasyonu delen** kural hangisi? Kural numarasını yaz "
          "(örn. K03 için 3). Delen kural: kart ortamına her porttan (`port=any`) izin veriyor.",
          Sayi("kural_no"),
          ("`port=any` içeren, hedefi kart ortamı olan satırı ara.",
           "`grep 'port=any' <<klasor>>/guvenlik_duvari.rules` çıktısının ilk sütunu kural numarası.",
           "Çıktıdaki `K` harfinden sonraki sayıyı yaz (başındaki sıfırı önemseme)."),
          puan=30, baslik="Delik kural"),
    Gorev("Segmentasyonu düzelt: kart ortamına her porttan izin veren kuralı kaldır (ya da yalnızca belirli port(lar)a "
          "indir). Ödeme akışının meşru kuralını (dmz -> kart ortamı) ve `varsayilan: reddet` satırını silme. Sonra "
          "`cevap 5`.",
          Durum(_kural_kontrol, "sed -i '/port=any/d' guvenlik_duvari.rules"),
          ("Düzeltilecek tek satır var; diğerlerine dokunma.",
           "`sed -i '/desen/d' dosya` eşleşen satırı siler. Desen olarak `port=any` işe yarar.",
           "`sed -i '/port=any/d' <<klasor>>/guvenlik_duvari.rules` (başka kural `port=any` taşımıyor)."),
          puan=50, baslik="Segmentasyonu düzelt"),
    Gorev("PCI-DSS'e uyumlu olmak neden **gerçekten güvenli olmayı** garanti etmez?",
          Secmeli([
              ("Standart bir taban çizgisidir; belirli bir tarihteki durumu ölçer ve her saldırıyı kapsamaz",
               "Doğru. Uyum denetimi bir an görüntüsüdür; güvenlik sürekli bir çabadır."),
              ("Standardın gereksinimleri teknik olduğundan denetçiler çoğunlukla kontrol etmeden onay verir",
               "Yanlış. Denetim titizdir; sorun, uyumun yeterli değil gerekli bir taban olmasıdır."),
              ("Uyumlu sistemler kart verisi tutmadığı için saldırganlar için hedef olmaktan çıkar",
               "Yanlış. Uyumlu sistemler de kart verisi işler; hedef olmaya devam eder."),
              ("PCI-DSS yalnızca ağ cihazlarını kapsar, uygulama ve kullanıcı davranışını hiç ele almaz",
               "Yanlış. Standart uygulamaları, erişimi ve izlemeyi de kapsar; garanti vermemesi başka bir konu."),
          ], dogru=0),
          ("Uyum bir gün geçerli bir görüntüdür; güvenlik her gün.",
           "Cilt 10'daki 'uyum ≠ güvenlik' ilkesini hatırla.",
           "Cevap: taban çizgisi, garanti değil."),
          puan=20, baslik="Uyum ≠ güvenlik"),
]


def _kapanis():
    return """
Kapsam, PCI-DSS'in para birimidir: her sistem bir maliyet, bir risk ve bir denetim yükü demektir. Saldırgan
gözüyle kart ortamına açılan tek bir `port=any` kapısı, yüzlerce sistemi kart ortamının parçası yapar. Savunma
gözüyle önce kart verisini az sisteme sok, sonra segmentasyonu **kuralla** değil **kuralları denetleyerek**
koru: her kapıda "bu gerçekten gerekli mi" diye sor. Kapsamı daraltmak, ucuz güvenlik ve ucuz denetimdir.
"""


SEVIYE = Seviye(
    kimlik="c20b02", cilt=20, bolum=2, baslik="PCI-DSS İlkeleri: Kapsam ve Segmentasyon",
    brifing="""
<<sahne>>

Selin: "Envanter, ağ diyagramı ve güvenlik duvarı kuralları `<<klasor>>/` klasöründe. Kapsamı çıkaracağız, sonra
segmentasyondaki deliği kapatacağız. Dikkat: 'kartı hiç görmeyen' sistemler de kapsama girebilir."

Deniz: "Kart ortamının kapısı ne kadar dar olursa denetçi o kadar az sistem sayar. Dar kapı, ucuz denetim."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Segmentasyonla kapsamı daraltmak:** PCI-DSS rehberleri, kart ortamını geri kalan ağdan doğru segmentasyonla
  ayırmanın kapsamı ve maliyeti küçülttüğünü belirtir. Hatalı segmentasyon ise kapsamın beklenmedik biçimde
  büyümesine yol açar; bu yüzden denetçiler segmentasyonu test ederek doğrular.
- **Yatay hareket ve tespit:** Pek çok kart verisi ihlalinde saldırganın önce daha az korunan bir sisteme sızıp sonra
  kart ortamına yatay hareket ettiği kamuya açık olay raporlarında görülür. Tespit: güvenlik duvarı günlüklerinde
  kart ortamına gelen, beklenmedik kaynaklı bağlantıları aramak.
- **Önleme:** Kuralları "en az yetki" ilkesiyle yazmak, `any` kurallarını düzenli taramak, değişiklikleri onaya
  bağlamak ve kart ortamına yönetim erişimini tek bir sıçrama sunucusundan vermek.
""",
    sure_hedef_dk=35,
)
