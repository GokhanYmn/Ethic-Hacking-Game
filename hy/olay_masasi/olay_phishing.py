"""Olay Masası — Şüpheli E-posta Masası.

Her vakada başka bir kurumun gelen kutusundan toplanmış sekiz kurgusal `.eml` dosyası:
bir kısmı meşru, bir kısmı oltalama. Oltalamalar farklı izlerle ele verir: SPF/DMARC hatası,
benzer alan adı, Reply-To uyuşmazlığı, görünen link ile gerçek bağlantı farkı.
Hiçbir ek ya da zararlı yük yoktur; bağlantılar kurgusal `http://ornek.lab/...` adresleridir.
"""
from __future__ import annotations

import subprocess
import zlib
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

TEDARIKCILER = [("Bulutyedek Faturalama", "bulutyedek.lab", "fatura"),
                ("Kargonet Müşteri", "kargonet.lab", "bilgi"),
                ("Ofisbir Lisans", "ofisbir.lab", "lisans"),
                ("Tekservis Destek", "tekservis.lab", "destek")]
BULTENLER = [("Sektör Haber Bülteni", "sektorhaber.lab"), ("Siber Gündem", "sibergundem.lab"),
             ("Dijital Dergi", "dijitaldergi.lab")]
KONULAR_SAHTE = ["Hesabınız askıya alınacak", "Parolanızın süresi doluyor", "Ödeme onayı bekleniyor",
                 "Acil: fatura düzeltmesi", "Kargo teslim edilemedi", "Posta kutunuz dolu"]
KONULAR_MESRU = ["Haftalık toplantı notları", "Bayram mesai düzeni", "Aylık fatura özeti",
                 "Lisans yenileme hatırlatması", "Bu haftanın haberleri", "Bakım penceresi duyurusu"]


def _eml(ad, adres, to, konu, tarih, ip, spf, dkim, dmarc, metin, href, gorunen, reply=None):
    alan = adres.split("@")[1]
    sat = [f'From: "{ad}" <{adres}>', f"To: {to}"]
    if reply:
        sat.append(f"Reply-To: {reply}")
    sat += [f"Subject: {konu}", f"Date: {tarih}",
            f"Message-ID: <{zlib.crc32(konu.encode()) % 99999}.{ip}@{alan}>",
            f"Received: from mail.{alan} ([{ip}]) by mx.lab with ESMTP",
            f"Authentication-Results: mx.lab; spf={spf} smtp.mailfrom={alan}; "
            f"dkim={dkim} header.d={alan}; dmarc={dmarc} header.from={alan}",
            "Content-Type: text/html; charset=utf-8", "", metin,
            f'<a href="{href}">{gorunen}</a>', "", "-- gönderim sonu --", ""]
    return "\n".join(sat)


def uret(rng):
    m = musteri_sec(rng)
    alan, kisa = m["alan"], m["ad"].split()[0]
    kok = alan[:-4]
    alici = f"{rng.choice(u.ISIMLER)}@{alan}"
    gun = u.gun(rng)

    def tarih():
        return gun.replace(hour=rng.randint(7, 17), minute=rng.randint(0, 59)).strftime("%a, %d %b %Y %H:%M:%S +0300")

    def k():
        return f"http://ornek.lab/{rng.choice(['giris', 'dogrula', 'ode', 'kutu'])}/{rng.randint(1000, 9999)}"

    konu_s = rng.sample(KONULAR_SAHTE, 4)
    konu_m = rng.sample(KONULAR_MESRU, 4)
    benzer = rng.choice([f"{kok}-destek.lab", f"{kok}-guvenlik.lab", f"{kok}portal.lab",
                         f"{kok}-online.lab", f"{kok[:-1]}{kok[-1] * 2}.lab"])
    ted = rng.choice(TEDARIKCILER)
    bulten = rng.choice(BULTENLER)
    ic1 = rng.choice(u.ISIMLER)
    fu = rng.randint(1000, 9999)
    ud, d1, bu = rng.randint(100, 999), rng.randint(10, 99), rng.randint(10, 99)
    msgs = []
    # meşrular
    msgs.append(("l1", _eml(f"{kisa} İK", f"ik@{alan}", alici, konu_m[0], tarih(), u.ic_ip(rng, "10.0.0"),
                            "pass", "pass", "pass", f"Merhaba, {ic1} tarafından hazırlandı.",
                            f"http://intranet.{alan}/duyuru/{d1}", f"http://intranet.{alan}/duyuru/{d1}")))
    # Reply-To farklı ama aynı alanda: sayılmaması gereken tuzak
    msgs.append(("l2", _eml(f"{kisa} Bilgi İşlem" if rng.random() < .5 else "BT Destek Hattı", f"bt@{alan}", alici,
                            konu_m[1], tarih(), u.ic_ip(rng, "10.0.0"), "pass", "pass", "pass",
                            "Sorularınız için yanıtlayın.", f"http://bt.{alan}/bilet/{ud}",
                            f"http://bt.{alan}/bilet/{ud}", reply=f"destek@{alan}")))
    msgs.append(("l3", _eml(ted[0], f"{ted[2]}@{ted[1]}", alici, konu_m[2], tarih(), u.dis_ip(rng),
                            "pass", "pass", "pass", "Bu ayın özetine bağlantıdan bakabilirsiniz.",
                            f"http://portal.{ted[1]}/f/{fu}", f"http://portal.{ted[1]}/f/{fu}")))
    msgs.append(("l4", _eml(bulten[0], f"bulten@{bulten[1]}", alici, konu_m[3], tarih(), u.dis_ip(rng),
                            "pass", "pass", "pass", "Haftanın öne çıkanları.", f"http://www.{bulten[1]}/s/{bu}",
                            f"http://www.{bulten[1]}/s/{bu}")))
    # oltalamalar
    p1_link = rng.random() < 0.6
    p1_reply = rng.random() < 0.4
    msgs.append(("p1", _eml(
        f"{kisa} Destek", f"destek@{benzer}", alici, konu_s[0], tarih(), u.dis_ip(rng),
        "fail", "none", "fail", "Hesabınızı korumak için bilgilerinizi doğrulayın.",
        k() if p1_link else f"http://{benzer}/giris",
        f"http://portal.{alan}/giris" if p1_link else f"http://{benzer}/giris",
        reply=f"yardim@{rng.choice(['ucuzposta.lab', 'hizlimail.lab'])}" if p1_reply else None)))
    p2_link = rng.random() < 0.5
    msgs.append(("p2", _eml(
        f"{kisa} Yönetim", f"yonetim@{alan}", alici, konu_s[1], tarih(), u.dis_ip(rng),
        "fail", "none", "fail", "Yöneticiniz onay bekliyor.",
        k() if p2_link else f"http://intranet.{alan}/onay", f"http://intranet.{alan}/onay")))
    rd = rng.choice(["odemelerim.lab", "ucuzposta.lab", "hizlimail.lab", "yardimmerkezi.lab"])
    msgs.append(("p3", _eml(
        ted[0], f"{ted[2]}@{ted[1]}", alici, konu_s[2], tarih(), u.dis_ip(rng),
        "pass", "pass", "pass", "Banka bilgileriniz değişti; yeni hesaba ödeme yapın.",
        f"http://portal.{ted[1]}/f/{fu + 1}", f"http://portal.{ted[1]}/f/{fu + 1}", reply=f"muhasebe@{rd}")))
    kargo = rng.random() < 0.5
    msgs.append(("p4", _eml(
        "Kargo Takip" if kargo else f"{kisa} Kampanya",
        f"bilgi@{ted[1]}" if kargo else f"kampanya@{alan}", alici, konu_s[3], tarih(), u.dis_ip(rng),
        "pass", "pass", "pass", "Paketiniz için adres onayı gerekli.",
        k(), f"http://takip.{alan}/paket/{rng.randint(100, 999)}")))
    rng.shuffle(msgs)
    isim = {a: f"msg_{i:02d}.eml" for i, (a, _) in enumerate(msgs, 1)}
    link_farkli = sorted(isim[a] for a, _ in msgs if a == "p4" or (a == "p1" and p1_link) or (a == "p2" and p2_link))
    kurumsal = sum(1 for _, e in msgs if kisa in e.split("\n")[0].split("<")[0])
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — şüpheli e-posta kutusu",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "kisa": kisa, "alan": alan,
                  "p3": isim["p3"], "hikaye": m["hikaye"]},
        "cevaplar": {"spf": 2, "taklit": [isim["p2"]], "benzer": [benzer],
                     "reply": 1 + (1 if p1_reply else 0), "link": link_farkli, "kurumsal": kurumsal},
        "_msgs": [(isim[a], e) for a, e in msgs],
        "_oltalama": sorted(isim[x] for x in ("p1", "p2", "p3", "p4")),
    }


def yaz(lab: Path, s: dict) -> None:
    for ad, e in s["_msgs"]:
        u.yaz(lab / "posta" / ad, e)


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _karantina(b) -> Sonuc:
    k = b.lab / "karantina"
    if not k.is_dir():
        return Sonuc(False, "`karantina/` klasörü yok. Önce oluştur (`mkdir karantina`).")
    var = sorted(p.name for p in k.iterdir())
    olt = b.senaryo["_oltalama"]
    if any(x not in olt for x in var):
        return Sonuc(False, "Karantinada meşru bir e-posta var; sadece oltalamaları taşı.")
    if len(var) < len(olt):
        return Sonuc(False, f"Karantinada {len(var)} dosya var ama {len(olt)} oltalama olmalı.", yakin=bool(var))
    return Sonuc(True, "Oltalamalar karantinada. Gerçek sistemde bunları posta ağ geçidinden de geri çekersin.")


def _reply_hata(g, beklenen, b):
    if int(g) > beklenen:
        return ("`grep Reply-To` meşru bir e-postayı da sayıyor: Reply-To'nun **alan adı** From'dakinden "
                "farklıysa şüphelidir; aynı alandaki farklı adres normaldir.")
    return None


def coz(lab: Path, s: dict) -> dict:
    alan, kisa = s["metin"]["alan"], s["metin"]["kisa"]
    spf = _sh("grep -l 'spf=fail' posta/* | wc -l", lab)
    taklit = _sh(f"for f in $(grep -l 'spf=fail' posta/*); do grep -q '^From:.*@{alan}>' $f && echo $f; done",
                 lab).split("/")[-1]
    benzer = _sh(f"grep -h '^From:' posta/* | grep -i '{kisa}' | sed 's/.*@//; s/>//' | grep -v '^{alan}$'", lab)
    reply = _sh("for f in posta/*; do awk -F'[<>@]' '/^From:/{a=$(NF-1)} /^Reply-To:/{r=$0; sub(/.*@/,\"\",r); "
                "if (r!=a) print FILENAME}' $f; done | wc -l", lab)
    link = _sh("awk '/<a href/{split($0,a,\"\\\"\"); t=$0; sub(/.*\">/,\"\",t); sub(/<\\/a>.*/,\"\",t); "
               "if (a[2]!=t) print FILENAME}' posta/* | sed 's#.*/##'", lab).split()
    kurumsal = _sh(f"awk -F'<' '/^From:/ && tolower($1) ~ tolower(\"{kisa}\")' posta/* | wc -l", lab)
    secim = SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]
    _sh("mkdir -p karantina && for f in " + " ".join(s["_oltalama"]) + "; do mv posta/$f karantina/; done", lab)
    return {1: spf, 2: taklit, 3: benzer, 4: reply, 5: " ".join(link), 6: secim, 7: kurumsal, 8: ""}


GOREVLER = [
    Gorev("`posta/` içindeki e-postalardan kaçında **SPF kontrolü başarısız** (`spf=fail`)?",
          Sayi("spf"),
          ("Doğrulama sonucu başlıklarda, `Authentication-Results` satırında yazar.",
           "O satırda `spf=pass` ya da `spf=fail` geçer. Dosyaları bu ifadeye göre süz.",
           "`grep -l 'spf=fail' posta/* | wc -l`"),
          puan=15, baslik="SPF hatası"),
    Gorev("Gönderen adresi **birebir <<alan>>** görünen ama SPF'i başarısız olan e-postanın dosya adı ne? "
          "(örn. msg_03.eml)",
          Metin("taklit", bicim="dosya adı", sadece_ad=True),
          ("Bu e-posta kurumun kendi alan adını taklit ediyor; gerçekten kurumdan gelseydi SPF geçerdi.",
           "Önce SPF'i başarısız olanları bul, sonra `From:` satırında adresin alan adına bak.",
           "`grep -l 'spf=fail' posta/*` çıktısındaki dosyalardan hangisinin From adresi `@<<alan>>` ile bitiyor?"),
          puan=20, baslik="Alan adı sahteciliği"),
    Gorev("Bir e-posta kurumun adını (**<<kisa>>**) kullanıyor ama **benzer görünen başka bir alan adından** "
          "geliyor. Gönderenin gerçek alan adı ne? (örn. ornek.lab)",
          Metin("benzer", bicim="alan adı"),
          ("Görünen ad kolayca taklit edilir; asıl bilgi `<...>` içindeki adrestedir.",
           "Tüm `From:` satırlarını listele; `<<alan>>` olmayan ama görünen adı kurumu andıranı ara.",
           "`grep -h '^From:' posta/*` — @'ten sonrası, `<<alan>>`'a çok benzeyen ama farklı olan alan."),
          puan=20, baslik="Benzer alan adı"),
    Gorev("Kaç e-postada **Reply-To adresinin alan adı From'dakinden farklı**? (aynı alanda farklı adres "
          "normaldir, sayma)",
          Sayi("reply", sik_hatalar=_reply_hata),
          ("Cevapla'ya basınca yanıt, From'a değil Reply-To'ya gider.",
           "Reply-To olan e-postalara bak, @'ten sonrasını From'daki alanla karşılaştır.",
           "`grep -E '^(From|Reply-To):' posta/*` ile yan yana oku; meşru olan, aynı alandan Reply-To kullanır."),
          puan=20, baslik="Reply-To tuzağı"),
    Gorev("Hangi e-postalarda **görünen link ile gerçek bağlantı (href)** birbirinden farklı? "
          "Dosya adlarını yaz (örn. msg_02.eml msg_05.eml).",
          Kume("link", bicim="boşlukla ayrılmış dosya adları"),
          ("Her e-postada `<a href=\"GERÇEK\">GÖRÜNEN</a>` biçiminde bir satır var.",
           "`grep '<a href' posta/*` ile satırları dök; tırnak içindeki adres ile `>`'dan sonraki yazıyı karşılaştır.",
           "Farkı gözle ya da `awk` ile bul; meşru e-postalarda ikisi birebir aynıdır."),
          puan=25, baslik="Link uyuşmazlığı"),
    Gorev("`<<p3>>` dosyasında SPF, DKIM ve DMARC **geçiyor**, yine de oltalama. Onu ele veren iz hangisi?",
          Secmeli([
              ("Reply-To, gönderenden farklı bir alan adına gidiyor",
               "Doğru. Hesap ele geçirilmiş ya da meşru kanal kullanılmış; kimlik doğrulama geçse de yanıtlar saldırgana gider."),
              ("SPF başarısız, gönderen sunucu yetkili değil",
               "Bu e-postada SPF geçiyor; başlıklara tekrar bak."),
              ("Gönderen alan adı kurumunkine benziyor ama farklı",
               "Bu e-postanın alan adı gerçek tedarikçinin; benzerlik izi yok."),
              ("Link metni ile href farklı",
               "Bu e-postada görünen link ile href birebir aynı."),
          ]),
          ("Kimlik doğrulama geçtiyse sorun başlıklarda başka yerde.",
           "`From:` ile `Reply-To:` satırlarını yan yana oku.",
           "Reply-To'nun alan adı From'dakinden farklı mı?"),
          puan=20, baslik="Gizli iz"),
    Gorev("Gönderen **görünen adında <<kisa>> geçen** (yani kurumsal bir gönderen gibi duran) kaç e-posta var? "
          "(meşru olanlar dahil)",
          Sayi("kurumsal"),
          ("Sadece `From:` satırındaki görünen ada bak; `<` işaretinden önceki kısım.",
           "Adres kısmında geçen alan adı sayılmaz; yalnızca insanın gördüğü ad.",
           "`awk -F'<' '/^From:/ {print $1}' posta/*` çıktısında <<kisa>> geçenleri say."),
          puan=15, baslik="Kurumsal görünüm"),
    Gorev("Oltalama e-postalarının **hepsini** `karantina/` klasörüne taşı (meşruları dokunma). "
          "Bitince `cevap 8` yaz.",
          Durum(_karantina, "mkdir karantina; mv posta/<oltalama dosyaları> karantina/"),
          ("Önce klasörü oluşturman gerekir.",
           "`mkdir karantina`, sonra oltalama dosyalarını `mv` ile taşı.",
           "Oltalamalar: SPF fail olanlar, benzer alan adlı, Reply-To tuzaklı ve link uyuşmazlıklı e-postalar."),
          puan=30, baslik="Karantina"),
]

SEVIYE = Seviye(
    kimlik="olay_phishing",
    cilt=1,
    bolum=93,
    baslik="Şüpheli E-posta Masası",
    brifing="""
Deniz Kara kahvesini bırakıp ekranı döndürüyor: "**<<musteri>>** (<<sektor>>) çalışanları sekiz
şüpheli e-posta iletmiş. <<hikaye>> <<kisi>> hepsini `posta/` klasörüne koydu."

"Bazıları gerçekten iş e-postası, bazıları oltalama. Bir oltalama her zaman aynı yerden
yakalanmaz: kimi kimlik doğrulamada çuvallar, kimi alan adını taklit eder, kimi Reply-To'da ya
da linkte saklanır. Hepsini ayıkla, sahtelerini karantinaya al."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Tek bir ipucu yetmez: SPF/DKIM/DMARC geçen bir e-posta bile Reply-To ya da linkle sizi kandırabilir,
alan adı birebir doğru görünen biri ise SPF'ten düşer. Deneyimli analist başlıkları, alan adını,
Reply-To'yu ve gerçek linki birlikte okur. Bu dört bakış açısı çoğu oltalamayı daha kimse
tıklamadan yakalar.
""",
    gercek_hayat="""
- **İş e-postası dolandırıcılığı (BEC):** Saldırgan tedarikçinin gerçek hesabını ele geçirir ya da
  Reply-To'yu kendi adresine çevirir; "banka hesabımız değişti" e-postası kimlik doğrulamadan geçer.
  Tespit: ödeme bilgisi değişikliklerini telefonla ikinci kanaldan doğrulamak.
- **Benzer alan adı (typosquatting):** `kurum.com` yerine `kurum-destek.com` ya da `kurumm.com`.
  Önlem: e-posta ağ geçidinde benzer alan adı uyarısı, DMARC `reject` politikası ve çalışanlara
  "şüpheli bildir" düğmesi.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c16b02",),
)
