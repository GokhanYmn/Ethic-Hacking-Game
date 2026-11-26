"""Olay Masası — E-posta Başlık Adli İncelemesi.

Tek bir şüpheli e-posta (`supheli.eml`): görünen ad, From/Return-Path/Reply-To adresleri,
Received zinciri, Authentication-Results ve Message-ID. Olay Masası'ndaki sekiz postalık
oltalama avının aksine burada tek postanın başlık zinciri baştan sona çözümlenir.
Her vakada sahtecilik izleri (benzer alan adı, Reply-To, başarısız doğrulama, köken IP) değişir.
Her şey kurgusaldır; adresler `.lab`, IP'ler belgeleme (TEST-NET) bloklarındandır.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

ROLE_ALANLARI = ["postaservis.lab", "hizlimail.lab", "toplupost.lab", "bulutposta.lab"]
YANIT_ALANLARI = ["ucuzposta.lab", "yardimmerkezi.lab", "odemelerim.lab", "hizlicevap.lab"]
KONULAR = ["Acil: ödeme talimatı değişti", "Hesabınız için son uyarı", "Fatura onayı bekleniyor",
           "Gizli: yöneticiden acil istek", "Banka bilgisi güncellemesi"]
KIMLIK_ALANLARI = ("spf", "dkim", "dmarc")


def _eml(ad, adres, rp, reply, to, konu, tarih, mid, received, auth) -> str:
    sat = [f"Return-Path: <{rp}>"] + received + [
        f"Authentication-Results: mx.lab; {auth}",
        f'From: "{ad}" <{adres}>',
        f"Reply-To: {reply}",
        f"To: {to}",
        f"Subject: {konu}",
        f"Date: {tarih}",
        f"Message-ID: <{mid}>",
        "Content-Type: text/plain; charset=utf-8", "",
        "Merhaba,", "",
        "Bugün içinde yapılması gereken acil bir işlem var. Ayrıntılar için bu e-postayı",
        "yanıtlayın; telefonla aramayın, toplantıdayım.", "", "-- gönderim sonu --", ""]
    return "\n".join(sat)


def uret(rng):
    m = musteri_sec(rng)
    alan, kisa = m["alan"], m["ad"].split()[0]
    kok = alan[:-4]
    benzer = rng.choice([f"{kok}-destek.lab", f"{kok}-guvenlik.lab", f"{kok}portal.lab",
                         f"{kok}-online.lab", f"{kok[:-1]}{kok[-1] * 2}.lab"])
    rel = rng.choice(ROLE_ALANLARI)
    reply_alan = rng.choice(YANIT_ALANLARI)
    kimlik = rng.choice(KIMLIK_ALANLARI)   # hangi mekanizma `fail` veriyor
    orijin, ip_a, ip_b = u.benzersiz(rng, u.dis_ip, 3)
    alici = f"{rng.choice(u.ISIMLER)}@{alan}"
    yonetici = rng.choice(u.ISIMLER)
    gun = u.gun(rng).replace(hour=rng.randint(7, 17), minute=rng.randint(0, 59), second=rng.randint(0, 40))

    def zaman(sn):
        from datetime import timedelta
        return (gun + timedelta(seconds=sn)).strftime("%a, %d %b %Y %H:%M:%S +0300")

    adres = f"{yonetici}@{benzer}"
    received = [
        f"Received: from gw.{rel} ([{ip_b}]) by mx.lab with ESMTPS; {zaman(6)}",
        f"Received: from srv1.{rel} ([{ip_a}]) by gw.{rel} with ESMTP; {zaman(3)}",
        f"Received: from pc-{rng.randint(10, 99)} ([{orijin}]) by srv1.{rel} with ESMTPA; {zaman(0)}",
    ]
    if kimlik == "spf":
        rp = adres
        auth = (f"spf=fail smtp.mailfrom={benzer}; dkim=none header.d={benzer}; "
                f"dmarc=none header.from={benzer}")
    elif kimlik == "dkim":
        rp = adres
        auth = (f"spf=pass smtp.mailfrom={benzer}; dkim=fail header.d={benzer}; "
                f"dmarc=none header.from={benzer}")
    else:
        rp = f"bounce@{rel}"
        auth = (f"spf=pass smtp.mailfrom={rel}; dkim=pass header.d={rel}; "
                f"dmarc=fail header.from={benzer}")
    mid = f"{rng.randint(10**8, 10**9)}.{rng.randint(1000, 9999)}@{rel}"
    eml = _eml(f"{kisa} Genel Müdür {yonetici.capitalize()}", adres, rp, f"{yonetici}@{reply_alan}", alici,
               rng.choice(KONULAR), zaman(0), mid, received, auth)
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — şüpheli e-posta başlıkları",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"],
                  "alan": alan, "kisa": kisa},
        "cevaplar": {"orijin": [orijin], "kimlik": [kimlik], "reply": [reply_alan], "from_alan": [benzer],
                     "ara_ip": [ip_b]},
        "_eml": eml,
        "_ara": {ip_a, ip_b},
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "supheli.eml", s["_eml"])


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _kokenhata(g, beklenen, b):
    if g in b.senaryo["_ara"]:
        return ("Bu, zincirin ortasındaki ya da en üstteki bir röle. Received satırları **aşağıdan yukarı** "
                "okunur; gerçek köken en alttaki satırdadır.")
    return None


def coz(lab: Path, s: dict) -> dict:
    ip = r"grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'"
    orijin = _sh(f"grep '^Received:' supheli.eml | tail -1 | {ip}", lab)
    kimlik = _sh("grep '^Authentication-Results:' supheli.eml | grep -oE '(spf|dkim|dmarc)=fail' | cut -d= -f1",
                 lab)
    reply = _sh("grep -i '^Reply-To:' supheli.eml | sed 's/.*@//; s/>.*//'", lab)
    from_alan = _sh("grep '^From:' supheli.eml | sed 's/.*@//; s/>.*//'", lab)
    ara = _sh(f"grep '^Received:' supheli.eml | head -1 | {ip}", lab)
    sahte = SEVIYE.gorevler[4].kontrol.cevabi_goster(Baglam(s, lab, 5))[0]
    aksiyon = SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]
    return {1: orijin, 2: kimlik, 3: reply, 4: from_alan, 5: sahte, 6: aksiyon, 7: ara}


GOREVLER = [
    Gorev("`supheli.eml` e-postasını gönderen bilgisayarın **gerçek köken IP**'si hangisi?",
          IP("orijin", sik_hatalar=_kokenhata),
          ("Her sunucu mesajı iletirken başa bir `Received:` satırı ekler.",
           "En yeni satır en üsttedir; mesajın doğduğu yer **en alttaki** `Received:` satırıdır.",
           "`grep '^Received:' supheli.eml | tail -1` — satırdaki köşeli parantez içindeki IP."),
          puan=20, baslik="Köken IP"),
    Gorev("`Authentication-Results` satırında **hangi doğrulama `fail`** sonucu veriyor? "
          "(`spf`, `dkim` ya da `dmarc`)",
          Metin("kimlik", bicim="spf, dkim ya da dmarc"),
          ("Posta sunucumuz gelen e-postayı üç mekanizmayla denetleyip sonucu başlığa yazar.",
           "Satırdaki `spf=...`, `dkim=...`, `dmarc=...` değerlerine bak; `pass` olmayanı ara.",
           "`grep '^Authentication-Results' supheli.eml | grep -oE '(spf|dkim|dmarc)=fail'`"),
          puan=15, baslik="Başarısız doğrulama"),
    Gorev("`Reply-To` adresinin **alan adı**, `From` adresinin alan adından farklı mı? "
          "Farklıysa Reply-To alan adını yaz. (örn. ornek.lab)",
          Metin("reply", bicim="alan adı"),
          ("\"Yanıtla\"ya basınca cevap `From`'a değil `Reply-To`'ya gider.",
           "`Reply-To:` satırındaki `@` işaretinden sonrasını al.",
           "`grep -i '^Reply-To:' supheli.eml | sed 's/.*@//'`"),
          puan=15, baslik="Reply-To tuzağı"),
    Gorev("`From` satırındaki **adresin alan adı** ne? Görünen ad <<kisa>> adını taşıyor; "
          "adresin gerçekten <<alan>> alan adından olup olmadığına bak.",
          Metin("from_alan", bicim="alan adı"),
          ("Görünen ad kolay taklit edilir; asıl kimlik `<...>` içindeki adrestir.",
           "`From:` satırında `@`'ten sonra `>`'ye kadar olan kısmı al.",
           "`grep '^From:' supheli.eml | sed 's/.*@//; s/>.*//'` — <<alan>> ile karşılaştır."),
          puan=15, baslik="Görünen gönderen"),
    Gorev("Bu e-posta sahte mi? Başlıklara göre doğru sonuç ve gerekçesi hangisi?",
          Secmeli([
              ("Evet: alan adı kurumunkine benziyor ama farklı, Reply-To başka alana gidiyor, doğrulama başarısız "
               "ve köken kurumun dışında",
               "Doğru. Tek bir iz yetmeyebilir ama dördü birden bu e-postanın sahte olduğunu gösterir."),
              ("Hayır: görünen ad <<kisa>> kurumunu taşıyor, demek ki iç kaynaklı",
               "Görünen ad herkes tarafından yazılabilir; güvenilir olan adres ve doğrulama sonuçlarıdır."),
              ("Hayır: e-postada Message-ID var, sahte posta Message-ID taşımaz",
               "Message-ID'yi saldırgan da üretir; doğrulama kanıtı değildir."),
              ("Evet, ama sadece konu acil olduğu için",
               "Acil konu bir tehlike işaretidir ama kanıt değil; başlıklardaki teknik izler karar verdirir."),
          ]),
          ("Tek ipucuna bakma; başlıklardaki izleri birlikte değerlendir.",
           "From alan adı, Reply-To, Authentication-Results ve Received zincirini sırayla gözden geçir.",
           "Alan adı taklit, Reply-To uyuşmazlığı ve başarısız doğrulama birleşince karar nettir."),
          puan=20, baslik="Sahte mi?"),
    Gorev("Doğru **aksiyon** hangisi?",
          Secmeli([
              ("E-postayı karantinaya al, kullanıcıyı uyar, benzer alan adını e-posta ağ geçidinde engelle",
               "Doğru. Tehdidi izole eder, kullanıcıyı bilgilendirir ve aynı alandan gelecek yenilerini keser."),
              ("Sadece e-postayı sil, kimseye haber verme",
               "Diğer kullanıcılar da aynı e-postayı almış olabilir; uyarı ve engelleme eksik."),
              ("Reply-To adresine yanıt yazıp bilgi iste",
               "Saldırganla temas kurmak onu doğrular; yanıtlama."),
              ("Hiçbir şey yapma: kullanıcı zaten tıklamaz",
               "Oltalama başarı oranı düşük değildir; savunma kullanıcının dikkatine bırakılmaz."),
          ]),
          ("Savunmada üç ayak vardır: izole et, bilgilendir, tekrarını önle.",
           "Tek bir e-postayı silmek yetmez; aynı gönderen ve benzer alan adı yeniden denenir.",
           "Karantina + kullanıcı uyarısı + benzer alan adı engeli."),
          puan=20, baslik="Aksiyon"),
    Gorev("Mesajı posta sunucumuza **en son ileten röle sunucunun IP**'si (en üstteki `Received:` satırı) nedir?",
          IP("ara_ip"),
          ("En üstteki `Received:` satırı, mesajı bize doğrudan teslim eden sunucuyu gösterir.",
           "Bu IP gerçek köken değil, son duraktır; ayrımı akılda tut.",
           "`grep '^Received:' supheli.eml | head -1`"),
          puan=15, baslik="Son röle"),
]

SEVIYE = Seviye(
    kimlik="olay_eposta",
    cilt=16,
    bolum=113,
    baslik="E-posta Başlık Adli İncelemesi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> şüpheli bir e-postayı tam başlıklarıyla `.eml` olarak iletti: `supheli.eml`."

"Genel Müdür'den geliyormuş gibi görünüyor ama bir şey tuhaf. Bu kez sekiz posta yok, tek posta
var: başlıkları satır satır oku. Kim gönderdi, nereden geldi, kimlik doğrulama ne dedi, yanıt
kime gidecek? Sonra ne yapılacağına karar ver."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
E-posta başlıkları bir adli bilişim raporudur. `Received` zincirini her zaman sondan (en alttan)
oku: gerçek köken oradadır, üstündeki satırları sonradan gelen röleler ekler. `From` görünen adı
ve adresi kolay taklit edilir; `Reply-To` ise yanıtları sessizce saldırgana yönlendirir. Kurumun
alan adında DMARC politikasını `reject` yapmak, taklit e-postaların henüz kutuya düşmeden
reddedilmesini sağlar. Başlık okumayı bir betiğe dökersen yüzlerce postayı dakikalar içinde
sınıflandırırsın.
""",
    gercek_hayat="""
- **İş e-postası dolandırıcılığı (BEC):** FBI IC3 raporlarına göre BEC kayıpları yıllardır
  milyarlarca dolar düzeyinde; çoğu "genel müdür acil ödeme istiyor" kalıbında, benzer alan adı ve
  farklı Reply-To ile gerçekleşir. Ödeme değişikliklerinde telefonla ikinci kanaldan doğrulama
  bu saldırıların büyük kısmını durdurur.
- **Facebook ve Google, 2013-2015:** Bir saldırgan tedarikçi firmayı taklit eden sahte faturalarla
  iki devden toplam yüz milyon doların üzerinde para çekti. SPF/DKIM/DMARC ve ödeme onay
  süreçlerinin birlikte kullanılması bu tür taklidi çok zorlaştırır.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c16b02",),
)
