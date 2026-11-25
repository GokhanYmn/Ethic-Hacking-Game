"""Cilt 9 · Bölüm 5 — Çok Makineli Ağ ve Active Directory.

Beceri: docker compose'ta birden fazla ağ (frontend / backend, `internal: true`); bir compose
dosyasından "hangi servis hangisine doğrudan ulaşabilir, hangisi internete çıkabilir" çıkarımı;
düz ağı bölümlere ayırarak yanal hareketi (lateral movement) zorlaştırmak; Active Directory'nin
neden Pi'de değil ayrı bir makinede kurulacağı (kavramsal).

Vakalar: Kalkan'ın stajyer lab'ı, Ferah Bank'ın şube eğitim ortamı, Mert'in blog Pi'si.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

VAKALAR = [
    {
        "ad": "Kalkan Güvenlik — stajyer çok katmanlı lab", "roller": ("web", "api", "db", "onbellek"),
        "imajlar": ("nginx:1.27-alpine", "python:3.12-slim", "mariadb:10.11", "redis:7-alpine"), "db_port": 3306,
        "brifing": """
Selin yeni görevi anlatıyor: "Gerçek ağlar tek makineden oluşmaz. Cilt 6'daki yanal hareket
alıştırmaları için çok katmanlı bir lab gerek: web, api, veritabanı. Ama kimin kime ulaşabildiğini
**dosyadan okuyabilmen** lazım; yanlış yapılandırılmış bir ağ, bir saldırganın web'den veritabanına
yürüyüşüdür."

Deniz telefonda ekliyor: "SOC tarafında en sevdiğim soru: 'web ele geçirilirse sıradaki durak
neresi?' Cevabı compose dosyasından çıkarıyorsan, doğru yoldasın."

Dosyalar: `lab-ag.yml`, `duz-ag.yml`, `rol_notu.txt`.
""",
    },
    {
        "ad": "Ferah Bank — şube portalı eğitim ortamı", "roller": ("sube-web", "odeme-api", "hesap-db", "izleme"),
        "imajlar": ("nginx:1.27-alpine", "python:3.12-slim", "postgres:16-alpine", "redis:7-alpine"), "db_port": 5432,
        "brifing": """
Kaan Bey (Ferah Bank bilgi güvenliği müdürü): "Şube portalının eğitim kopyasını Raspberry Pi'lerde
çalıştıracağız: web, ödeme servisi, hesap veritabanı ve bir izleme servisi. Eğitimde şunu
göstermek istiyoruz: ağlar bölünmediğinde web'e giren hesap veritabanına da ulaşıyor."

Selin: "Önce mevcut yapılandırmayı oku: kim kime konuşabilir, kim internete çıkabilir? Sonra düz ağı
bölümlere ayır. Eğitim ortamı dışarıdan **hiçbir** servise açılmayacak."

Dosyalar: `lab-ag.yml`, `duz-ag.yml`, `rol_notu.txt`.
""",
    },
    {
        "ad": "Mert'in Pi'si — blog ve veritabanı", "roller": ("blog", "yonetim-api", "blog-db", "arama"),
        "imajlar": ("nginx:1.27-alpine", "python:3.12-slim", "mariadb:10.11", "redis:7-alpine"), "db_port": 3306,
        "brifing": """
Mert evdeki Pi'sinde bir blog motoru, yönetim API'si, veritabanı ve bir arama servisi
çalıştırıyor. "Hepsi tek bir ağda, ama bir yerlerde bölmem gerektiğini hissediyorum. Ağ
yapılandırmamı okuyup kimin neye ulaşabildiğini söyler misin?"

Selin: "Önce Mert'in `lab-ag.yml` dosyasını oku. Sonra aynı servisleri bölümlere ayırıp
veritabanını iç ağa al. Aynı dosya bir gün gerçek bir saldırganın haritası olabilir."

Dosyalar: `lab-ag.yml`, `duz-ag.yml`, `rol_notu.txt`.
""",
    },
]

AG_ISIMLERI = [("frontend", "backend"), ("on-ag", "arka-ag"), ("dis-ag", "ic-ag"), ("web-agi", "veri-agi")]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    web, api, db, ek = v["roller"]
    on, arka = rng.choice(AG_ISIMLERI)
    varyant = rng.choice(["T1", "T2", "DUZ"])
    ag = {web: [on], api: [on, arka], db: [arka], ek: [arka]}
    if varyant == "T2":
        ag[ek] = [on, arka]
    if varyant == "DUZ":
        ag[db] = [on, arka]
    hp = rng.randrange(8080, 8180)
    ulasir = sorted(k for k in ag if k != web and set(ag[k]) & set(ag[web]))
    internet = sorted(k for k, a in ag.items() if on in a)
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v, "ag": ag, "on": on, "arka": arka, "hp": hp,
        "varyant": varyant, "sifre": "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(8)),
        "metin": {"web": web, "api": api, "db": db, "ek": ek, "on": on, "arka": arka, "hp": str(hp)},
        "cevaplar": {"ulasir": ulasir, "internet": internet,
                     "db_erisim": ["evet"] if db in ulasir else ["hayır", "hayir"]},
    }


def _servis_blogu(s: dict, ad: str, imaj: str, aglar, port=None, ortam=None, yerel=True) -> list:
    satir = [f"  {ad}:", f"    image: {imaj}"]
    if aglar:
        satir.append(f"    networks: [{', '.join(aglar)}]")
    if port:
        satir += ["    ports:", f'      - "{port}"']
    if ortam:
        satir += ["    environment:", f"      {ortam}"]
    satir.append("    restart: unless-stopped")
    return satir


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    web, api, db, ek = v["roller"]
    im = dict(zip(v["roller"], v["imajlar"]))
    ortam = {db: ("MARIADB_ROOT_PASSWORD: " if "maria" in im[db] else "POSTGRES_PASSWORD: ") + s["sifre"]}
    satir = ["services:"]
    for ad in (web, api, db, ek):
        satir += _servis_blogu(s, ad, im[ad], s["ag"][ad], port=f"127.0.0.1:{s['hp']}:80" if ad == web else None,
                               ortam=ortam.get(ad))
    satir += ["networks:", f"  {s['on']}:", "    driver: bridge", f"  {s['arka']}:", "    internal: true"]
    u.yaz(lab / "lab-ag.yml", "\n".join(satir) + "\n")
    # düz ağ: hiçbir servis ağ belirtmiyor (varsayılan tek ağ), veritabanı portunu da yayımlıyor
    duz = ["services:"]
    for ad in (web, api, db, ek):
        port = f"127.0.0.1:{s['hp']}:80" if ad == web else (f"{v['db_port']}:{v['db_port']}" if ad == db else None)
        duz += _servis_blogu(s, ad, im[ad], None, port=port, ortam=ortam.get(ad))
    u.yaz(lab / "duz-ag.yml", "\n".join(duz) + "\n")
    u.yaz(lab / "rol_notu.txt",
          "# Servis rolleri (Selin)\n"
          f"web: {web}\napi: {api}\ndb: {db}\nek: {ek}\n"
          f"web_ana_makine_portu: {s['hp']}\n"
          "# Hedef: web yalnızca api'ye, api hem web'e hem db'ye ulaşabilsin; db'ye web ulaşamasın.\n")


# ------------------------------------------------------------------ kontroller

def _bolumlu(b: Baglam) -> Sonuc:
    ad = "bolumlu.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    hata, d = o.compose_denetle(yol, ad)
    if hata:
        return hata
    s = b.senaryo
    v = s["v"]
    web, api, db, ek = v["roller"]
    sv = o.servisler(d)
    for r in (web, api, db, ek):
        if r not in sv:
            return Sonuc(False, f"`{r}` servisi dosyada yok. Dört servisi de koru: {o.adlar_tr(v['roller'])}.")
    for r, imaj in zip(v["roller"], v["imajlar"]):
        if o.imaj_depo(sv[r].get("image")) != o.imaj_depo(imaj):
            return Sonuc(False, f"`{r}` servisinin imajı `{imaj}` olarak kalmalı.")
    aw, aa, ad_ = (set(o.servis_aglari(d, x)) for x in (web, api, db))
    if aw & ad_:
        return Sonuc(False, f"`{web}` ve `{db}` hâlâ ortak bir ağda (`{sorted(aw & ad_)[0]}`). Web ele geçirilirse veritabanına doğrudan ulaşılır.",
                     yakin=True)
    if not (aa & aw):
        return Sonuc(False, f"`{api}`, `{web}` ile ortak bir ağda olmalı; yoksa web ona istek gönderemez.", yakin=True)
    if not (aa & ad_):
        return Sonuc(False, f"`{api}`, `{db}` ile ortak bir ağda olmalı; yoksa veritabanına bağlanamaz.", yakin=True)
    if any(not o.ag_ic_mi(d, x) for x in o.servis_aglari(d, db)):
        return Sonuc(False, f"`{db}` internete çıkabilen bir ağda duruyor. Veritabanı yalnızca `internal: true` bir ağda olmalı.", yakin=True)
    if o.portlar(sv[db]):
        return Sonuc(False, f"`{db}` hâlâ port yayımlıyor. Veritabanına ana makineden/dışarıdan erişim kapalı olmalı: `ports:` bölümünü kaldır.",
                     yakin=True)
    web_port = [p for p in o.portlar(sv[web]) if p.get("host") == s["hp"] and p.get("konteyner") == 80]
    if not web_port or not all(p.get("lokal") for p in o.portlar(sv[web])):
        return Sonuc(False, f"`{web}` yalnızca `\"127.0.0.1:{s['hp']}:80\"` ile yayımlanmalı (kurulum_notu'ndaki gibi).", yakin=True)
    for r in (api, ek):
        if o.portlar(sv[r]):
            return Sonuc(False, f"`{r}` port yayımlamamalı; yalnızca web dışarıya (127.0.0.1'e) açılır.", yakin=True)
    return Sonuc(True, f"Bölümlendirme tamam: `{web}` ile `{db}` arasında doğrudan yol yok; veritabanı iç ağda, "
                       "dışarıya kapalı. Saldırganın web'den veritabanına yürüyüşü artık api'yi de ele geçirmeyi gerektirir.")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Gerçek ağlar çok makinelidir", """
Tek bir hedef iyi bir başlangıçtır ama gerçek ağlar birden çok makineden oluşur: bir web sunucusu,
bir uygulama (API) sunucusu, bir veritabanı. Saldırganlar çoğu zaman önce bir makineyi ele geçirir,
sonra ondan diğerine ilerler (**yanal hareket**, lateral movement). Bu yolun uzunluğunu
**ağ tasarımı** belirler. Müşterinin yapılandırmasına bakalım:
""", komut="cat lab-ag.yml", sonra="""
Her servisin `networks:` satırı, hangi ağlara bağlı olduğunu söyler. En altta ağların kendisi
tanımlı.
"""),
    Adim("Aynı ağ = doğrudan erişim", """
Docker'da iki konteyner **en az bir ortak ağdaysa** birbirlerine adlarıyla doğrudan
ulaşabilir. Ortak ağları yoksa ulaşamazlar. Bu yüzden "kim kime ulaşabilir" sorusunun cevabı,
`networks:` satırlarını karşılaştırmaktır. Servis adlarını ve ağ satırlarını yan yana görelim:
""", komut="grep -E '^  [a-z0-9-]+:$|networks:' lab-ag.yml", sonra="""
Her servis adının altında onun ağlarını okuyabilirsin. Bir servisin iki ağda olması, o iki
ağı birbirine bağlayan bir **köprü** olduğu anlamına gelir: ele geçirilirse iki tarafa da geçit olur.
"""),
    Adim("internal: true", """
Bir ağı `internal: true` olarak tanımlarsan, o ağdaki konteynerler **yalnızca birbirleriyle**
konuşabilir; internete çıkamaz. Veritabanı gibi dış dünyayla işi olmayan servisleri bu ağa koymak
hem dışarıya veri sızdırmayı hem de dışarıdan indirilen zararlı araçları zorlaştırır.
""", komut="grep -B1 'internal' lab-ag.yml", sonra="""
Ağların biri `internal: true`, diğerinin yanında bu satır yok: o ağ internete çıkar.
Bir servis hem internal olmayan bir ağda hem de internal ağda ise internete çıkabilir.
"""),
    Adim("Servis rolleri ve hedef", """
Bölümlendirmenin amacı, bir saldırganın tek bir ele geçirmeyle bütün ağı yürümesini engellemektir.
Selin'in notu hedefi söylüyor:
""", komut="cat rol_notu.txt", sonra="""
Kural: **web**, doğrudan **veritabanına** ulaşmamalı. Araya api girer; saldırgan veritabanına
ulaşmak için iki makineyi ele geçirmek zorunda kalır. Bu, **kademeli savunma**dır (defense in depth).
"""),
    Adim("Düz ağ neden kötü?", """
`duz-ag.yml`'de hiçbir servis ağ belirtmiyor: hepsi tek varsayılan ağda. Üstelik veritabanı bir de
port yayımlıyor. Bu, bir saldırgan için ideal haritadır:
""", komut="cat duz-ag.yml", sonra="""
Hepsi aynı ağda: web'e giren herkes api'ye **ve** veritabanına doğrudan ulaşır. Veritabanı portu ayrıca
yayımlanmışsa dışarıdan bile. Görevde bunu bölümlere ayıracaksın.
"""),
    Adim("Active Directory: neden Pi'de değil?", """
Cilt 6'daki **Active Directory** (AD, kurumsal ağlarda kullanıcı ve bilgisayarları yöneten Microsoft
dizin hizmeti) çalışmak için tipik olarak birkaç **Windows Server** makinesi ister (alan
denetleyicisi, üye sunucular, istemciler). Bunlar x86 için hazırlanmış tam sanal makinelerdir ve her
biri ciddi bellek harcar. Pi'nin arm64 işlemcisi ve sınırlı RAM'i buna uygun değildir. AD
laboratuvarı için ayrı bir x86 makine (güçlü bir mini PC ya da dizüstü) ayır; Pi'yi Kali olarak
kullan, ikisini izole ağda birleştir. Bunu Cilt 8'deki sertifika hazırlığı sırasında kurmak mantıklıdır.
"""),
]

GOREVLER = [
    Gorev("Bir compose ağını `internal: true` olarak tanımladın. Bu ağın etkisi nedir?",
          Secmeli([
              ("Bu ağdaki konteynerler yalnızca birbirleriyle konuşur; internete çıkamazlar",
               "Doğru: `internal: true` ağdan dışarıya çıkışı kapatır; ağ içi trafik serbest kalır."),
              ("Ağdaki konteynerler birbirleriyle bile konuşamaz; her biri tek başına izole kalır",
               "Tersine: internal ağda konteynerler birbiriyle konuşabilir; kapanan şey dışarı çıkıştır."),
              ("Ağdaki konteynerlerin yayımlanan portları otomatik olarak yalnızca 127.0.0.1'e bağlanır",
               "`internal` port bağlarını değiştirmez; `ports:` satırındaki adres ayrı bir ayardır."),
              ("Ağ yalnızca ana makineden erişilebilir olur ve konteynerler arası trafik tamamen kesilir",
               "Konteynerler arası trafik kesilmez; internal yalnızca dışarıyla bağlantıyı kısar."),
          ], dogru=0),
          ("`internal` kelimesi 'dışarıya kapalı' anlamına gelir; peki içeriye?",
           "Dışarı çıkış yok, ama aynı ağdaki servislerin birbirleriyle konuşması serbest.",
           "Çıkış kapalı, ağ içi trafik açık."),
          puan=25, baslik="internal: true"),
    Gorev("`lab-ag.yml` dosyasına göre **<<web>>** servisi hangi servislere **doğrudan** ulaşabilir? "
          "(En az bir ağı paylaştığı diğer servisler)",
          Kume("ulasir", tur="metin", bicim="servis adları, virgülle ayrılmış"),
          ("`networks:` satırlarını karşılaştır; kendisiyle ortak ağı olan servisleri bul.",
           "Önce <<web>>'in ağlarına bak, sonra her diğer servisin ağ listesinde bunlardan biri var mı kontrol et.",
           "`grep -E '^  [a-z0-9-]+:$|networks:' lab-ag.yml` servisleri ve ağlarını yan yana yazar."),
          puan=35, baslik="Kim kime ulaşır"),
    Gorev("Hangi servisler **internete çıkabilir**? (Internal olmayan bir ağa bağlı servisler)",
          Kume("internet", tur="metin", bicim="servis adları, virgülle ayrılmış"),
          ("Önce hangi ağın `internal: true` olduğunu bul. Internal olmayan ağlara bağlı servisler çıkabilir.",
           "Dosyanın sonundaki `networks:` bölümünde hangisinin altında `internal: true` yazıyor?",
           "Internal olmayan ağın adını (<<on>> ya da <<arka>>, hangisinde `internal` yoksa) `networks:` satırlarında arayan servisler cevaptır."),
          puan=35, baslik="İnternet çıkışı"),
    Gorev("<<web>> servisi ele geçirilirse, saldırgan **<<db>>** veritabanına doğrudan ağ erişimi kazanır mı? "
          "(`evet` ya da `hayır`)",
          Metin("db_erisim", bicim="evet / hayır"),
          ("Bir önceki görevde bulduğun listeyi kullan.",
           "<<db>>, <<web>>'in doğrudan ulaşabildiği servisler arasında mı?",
           "Listede varsa `evet`, yoksa `hayır`."),
          puan=25, baslik="Yanal hareket"),
    Gorev("Düz ağı bölümlere ayır: `duz-ag.yml`'nin bir kopyasını `bolumlu.yml` olarak kaydet ve "
          "düzenle: `<<web>>` ile `<<db>>` ortak ağda olmasın; `<<api>>` ikisiyle de konuşabilsin; `<<db>>` "
          "yalnızca `internal: true` bir ağda dursun ve **port yayımlamasın**; yalnızca `<<web>>` "
          "(`127.0.0.1:<<hp>>:80`) dışarıya açılsın. Dört servisi koru. Hazır olunca `cevap 5`.",
          Durum(_bolumlu, "```\nservices:\n  <<web>>:  (networks: [<<on>>], ports: 127.0.0.1:<<hp>>:80)\n"
                          "  <<api>>:  (networks: [<<on>>, <<arka>>])\n  <<db>>:   (networks: [<<arka>>], port yok)\n"
                          "  <<ek>>:   (networks: [<<arka>>])\nnetworks:\n  <<on>>:\n  <<arka>>:\n    internal: true\n```"),
          ("Üç bölüm: web ağı, api'yi iki ağa bağlayan köprü, veritabanı ağı. Veritabanı ağı internal olmalı.",
           "İki ağ tanımla (biri `internal: true`). Her servise `networks: [...]` ekle; veritabanının `ports:` bölümünü sil.",
           "web: `networks: [<<on>>]`; api: `networks: [<<on>>, <<arka>>]`; db ve <<ek>>: `networks: [<<arka>>]`; en altta `<<arka>>` ağına `internal: true`."),
          puan=60, baslik="Ağı böl"),
    Gorev("Cilt 6'daki **Active Directory** lab'ını neden Pi'de değil, ayrı bir makinede kurmalısın?",
          Secmeli([
              ("AD birkaç Windows Server sanal makinesi ister; bunlar x86 içindir ve Pi'nin arm64 işlemcisine ve RAM'ine sığmaz",
               "Doğru: hem mimari uyuşmazlığı hem bellek ihtiyacı AD'yi Pi'de gerçekçi olmaktan çıkarır."),
              ("AD yalnızca Linux çekirdeğinde çalışır; Pi'nin ağ kartı AD protokolünü tanımadığı için bağlantı kurulamaz hale gelir",
               "AD bir Microsoft hizmetidir (Windows Server); sorun ağ kartı değil mimari ve bellektir."),
              ("AD konteynerlerde çalışmaz çünkü Docker yalnızca web uygulamalarını destekler, işletim sistemi hizmetlerini değil",
               "Docker yalnızca web uygulamalarına özgü değildir; AD'nin sorunu Windows ve ağır kaynak gereksinimidir."),
              ("AD'yi Pi'ye kurmak yasaktır; Microsoft lisansı ARM işlemcili cihazlarda eğitim amaçlı kullanımı açıkça engeller",
               "Böyle bir yasak bu bölümün konusu değil; sorun teknik: mimari ve bellek."),
          ], dogru=0),
          ("Hem mimariyi hem belleği düşün: AD için kaç makine ve hangi işletim sistemi gerekir?",
           "Bölüm 1'deki ve Bölüm 4'teki x86/arm64 dersini hatırla; birkaç sunucu aynı anda çalışacak.",
           "Windows Server x86 VM'leri, çok RAM: ayrı bir x86 makine."),
          puan=25, baslik="AD neden ayrı"),
]


def _kapanis():
    return """
Bir ağda bir makineyi ele geçirmek çoğu zaman ilk adımdır; asıl hedefe giden yol ağ tasarımıyla
belirlenir. Saldırgan gözüyle: ortak ağı olan her servis bir sonraki duraktır, iki ağı birleştiren
her servis bir köprüdür. Savunma gözüyle: hangi servisin hangi ağda olduğunu dosyadan okuyabilmek,
veritabanını `internal: true` bir ağa almak ve dışarıya yalnızca gerekeni (127.0.0.1'e) açmak,
saldırganın yolunu uzatır ve gürültülü hâle getirir. Bu, Cilt 7'deki ağ bölümlendirmesinin
birebir uygulamasıdır.
"""


SEVIYE = Seviye(
    kimlik="c09b05",
    cilt=9,
    bolum=5,
    baslik="Çok Makineli Ağ ve Active Directory",
    brifing="Çok katmanlı bir lab'ın ağ yapılandırmasını okuyacak ve düz ağı bölümlere ayıracaksın.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **İç ağda ilerleme:** Pek çok iyi belgelenmiş ihlalde (örneğin 2013'teki Target olayında bir
  tedarikçinin kimlik bilgileriyle ağa girilmesi sonrasında iç ağda ilerlenmesi sık anılır) asıl
  hasar ilk girişten değil, ağın iyi bölümlenmemiş olmasından doğmuştur. Önlem: ağ bölümlendirmesi
  ve en az erişim; tespit: iç ağdaki olağandışı bağlantıları (örneğin web sunucusundan veritabanına
  alışılmadık sorgular) izlemek.
- **İnternete açık veritabanları:** Parolasız ve internete açık bırakılmış MongoDB, Elasticsearch
  gibi veritabanlarının otomatik taramalarla bulunup verilerinin silindiği ya da fidye için
  kullanıldığı olaylar (örneğin 2017'deki MongoDB fidye dalgası, 2020'deki "Meow" saldırısı)
  çok kez raporlanmıştır. Veritabanını `internal: true` ağda tutmak ve port yayımlamamak bu
  sınıf olayı kökten engeller.
- **Active Directory laboratuvarları:** Profesyoneller AD pratiği için ayrı bir sanallaştırma
  sunucusu ya da güçlü bir makine kullanır; bu, laboratuvar planlamasında RAM ve mimari
  kısıtlarının doğrudan sonucudur.
""",
    sure_hedef_dk=30,
)


_AWK_AGLAR = ("awk '/^  [a-z0-9_-]+:$/ {s=$1; sub(\":\",\"\",s)} "
              "/^    networks:/ {n=$0; sub(/.*\\[/,\"\",n); sub(/\\].*/,\"\",n); gsub(/ /,\"\",n); print s, n}' ")


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    web = sh("awk -F': ' '/^web:/{print $2}' rol_notu.txt")
    api = sh("awk -F': ' '/^api:/{print $2}' rol_notu.txt")
    db = sh("awk -F': ' '/^db:/{print $2}' rol_notu.txt")
    ek = sh("awk -F': ' '/^ek:/{print $2}' rol_notu.txt")
    hp = sh("awk -F': ' '/^web_ana_makine_portu/{print $2}' rol_notu.txt")
    harita = _AWK_AGLAR + "lab-ag.yml"
    ulasir = sh(harita + " | awk -v X=" + web + " '{nets[$1]=$2} END { split(nets[X],a,\",\"); "
                "for (k in nets) if (k != X) { split(nets[k],b,\",\"); f=0; "
                "for (i in a) for (j in b) if (a[i]==b[j]) f=1; if (f) print k } }'").split()
    ic = sh("awk '/^networks:/{t=1} t && /^  [a-z0-9_-]+:$/ {n=$1; sub(\":\",\"\",n)} t && /internal: true/ {print n}' lab-ag.yml")
    internet = sh("ic=\" " + ic.replace("\n", " ") + " \"; " + harita +
                  " | while read s n; do for x in ${n//,/ }; do case \"$ic\" in *\" $x \"*) ;; *) echo $s; break;; esac; done; done").split()
    evet = "evet" if db in ulasir else "hayır"
    on = [x for x in sh("awk '/^networks:/{t=1} t && /^  [a-z0-9_-]+:$/ {n=$1; sub(\":\",\"\",n); print n}' lab-ag.yml").split()
          if x not in ic.split()][0]
    arka = ic.split()[0]
    imaj = lambda ad: sh(f"awk '/^  {ad}:$/{{f=1}} f && /image:/{{print $2; exit}}' duz-ag.yml")  # noqa: E731
    env = sh(f"awk '/^  {db}:$/{{f=1}} f && /_PASSWORD:/{{print $1\" \"$2; exit}}' duz-ag.yml")
    yml = ["services:",
           f"  {web}:", f"    image: {imaj(web)}", f"    networks: [{on}]", "    ports:", f"      - \"127.0.0.1:{hp}:80\"",
           f"  {api}:", f"    image: {imaj(api)}", f"    networks: [{on}, {arka}]",
           f"  {db}:", f"    image: {imaj(db)}", f"    networks: [{arka}]", "    environment:", f"      {env}",
           f"  {ek}:", f"    image: {imaj(ek)}", f"    networks: [{arka}]",
           "networks:", f"  {on}:", f"  {arka}:", "    internal: true"]
    (lab / "bolumlu.yml").write_text("\n".join(yml) + "\n")
    return {1: SEVIYE.gorevler[0].kontrol.cevabi_goster(Baglam(s, lab, 1))[0], 2: " ".join(ulasir),
            3: " ".join(internet), 4: evet, 5: "",
            6: SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]}
