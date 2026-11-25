"""Cilt 15 · Bölüm 3 — Kablosuz Savunma ve Lab.

Beceri: kurgusal bir erişim noktası yapılandırmasını (router.conf) DÜZELTMEK: kurumsal ağı WPA3 ya da 802.1X'e
taşımak, WPS'yi kapatmak, misafir ağını iç ağdan ayırmak (VLAN + erişim reddi + istemci yalıtımı), misafir ağında
güçlü şifreleme ve parola kullanmak, korumalı yönetim karelerini (PMF) zorunlu kılmak.

Vakalar: Atölye Kahve, Kuzgun Lojistik, Medora Sağlık, Ferah Bank. Yapılandırma kurgusal ve satıcıdan bağımsız,
düz metin bir dosyadır; gerçek bir cihaza dokunulmaz.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Durum, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c15_kablosuz.ortak import ini_oku, sec_doldur, sh, vaka_sec

SIFRELEMELER_KURUMSAL = ("wpa2-enterprise", "wpa3-enterprise", "wpa3-sae")
SIFRELEMELER_MISAFIR = ("wpa2-psk", "wpa3-sae", "wpa2-wpa3")


def uret(rng):
    v = vaka_sec(rng)
    radius = f"10.{rng.randint(0, 40)}.{rng.randint(1, 20)}.{rng.randint(10, 60)}"
    misafir_eski = rng.choice(["open", "wep"])
    vlan_k = rng.choice([1, 10, 20])
    return {
        "vaka": f"{v['ad']} — {v['yer']} kablosuz sertleştirme",
        "v": v, "radius": radius, "misafir_eski": misafir_eski, "vlan_k": vlan_k,
        "metin": {"musteri": v["ad"], "kurum": v["kurum"], "misafir": v["misafir"], "yer": v["yer"],
                  "hikaye": v["hikaye"], "radius": radius, "vlan_k": str(vlan_k)},
        "cevaplar": {"radius_dummy": radius},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} erişim noktası yapılandırma kopyası (router.conf). KURGUSAL, satıcıdan bağımsız.\n"
          "Selin'den not: Düzeltmeleri doğrudan ap/router.conf içinde yap; her biri için `cevap <no>` yaz.\n")
    misafir_sifre = "" if s["misafir_eski"] == "open" else "ab12cd34ef"
    u.yaz(lab / "ap" / "router.conf",
          f"# router.conf — {v['ad']} erişim noktası (KURGUSAL)\n"
          "# Yorum satırları '#' ile başlar. Değerleri anahtar=değer biçiminde yaz.\n\n"
          "[kurumsal]\n"
          f"ssid={v['kurum']}\n"
          "encryption=wpa2-psk\n"
          f"passphrase={v['weak']}\n"
          "radius_server=\n"
          "wps=on\n"
          "pmf=disabled\n"
          f"vlan={s['vlan_k']}\n"
          "client_isolation=off\n"
          "lan_access=allow\n"
          "hide_ssid=off\n\n"
          "[misafir]\n"
          f"ssid={v['misafir']}\n"
          f"encryption={s['misafir_eski']}\n"
          f"passphrase={misafir_sifre}\n"
          "radius_server=\n"
          "wps=on\n"
          "pmf=disabled\n"
          f"vlan={s['vlan_k']}\n"
          "client_isolation=off\n"
          "lan_access=allow\n"
          "hide_ssid=on\n")
    u.yaz(lab / "ap" / "ag_plani.txt",
          f"{v['ad']} ağ planı (BT ekibi)\n"
          f"  Kurumsal ağ VLAN numarası : {s['vlan_k']}\n"
          "  Misafir ağı için ayrılan VLAN : kurumsaldan farklı herhangi bir numara (örn. 30)\n"
          f"  RADIUS sunucusu (802.1X)  : {s['radius']} (kurumsal kimlik doğrulama bunu kullanır)\n"
          "  Misafir ağı kuralı        : iç ağa erişim yok, istemciler birbirini görmez\n")


def coz(lab: Path, s: dict) -> dict:
    r = s["radius"]
    sh("sed -i '/^\\[kurumsal\\]/,/^\\[misafir\\]/{"
       "s/^encryption=.*/encryption=wpa2-enterprise/; "
       f"s/^radius_server=.*/radius_server={r}/; "
       "s/^pmf=.*/pmf=required/}' ap/router.conf", lab)
    sh("sed -i 's/^wps=.*/wps=off/' ap/router.conf", lab)
    sh("sed -i '/^\\[misafir\\]/,${"
       "s/^vlan=.*/vlan=30/; s/^lan_access=.*/lan_access=deny/; s/^client_isolation=.*/client_isolation=on/; "
       "s/^encryption=.*/encryption=wpa2-psk/; s/^passphrase=.*/passphrase=Misafir-Ziyaret-2026!/}' ap/router.conf", lab)
    return sec_doldur({}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- durum kontrolleri

def _cfg(b):
    hata, c = ini_oku(b.lab / "ap" / "router.conf")
    if hata:
        return hata, {}
    for bolum in ("kurumsal", "misafir"):
        if bolum not in c:
            return f"[{bolum}] bölümü bulunamadı; bölüm başlıklarını silme.", {}
    return None, c


def _ssid_ok(b, c):
    v = b.senaryo["v"]
    if c["kurumsal"].get("ssid") != v["kurum"] or c["misafir"].get("ssid") != v["misafir"]:
        return "Ağ adlarını (ssid) değiştirme; yalnızca güvenlik ayarlarını düzelt."
    return None


def _kurumsal(b) -> Sonuc:
    hata, c = _cfg(b)
    if hata:
        return Sonuc(False, hata)
    if m := _ssid_ok(b, c):
        return Sonuc(False, m)
    k = c["kurumsal"]
    enc = k.get("encryption", "").lower()
    v = b.senaryo["v"]
    if enc not in SIFRELEMELER_KURUMSAL:
        if enc == "wpa2-psk":
            return Sonuc(False, "Kurumsal ağ hâlâ paylaşılan parolalı `wpa2-psk`. 802.1X (`wpa2-enterprise`) ya da `wpa3-sae` kullan.",
                         yakin=True)
        return Sonuc(False, f"`encryption={enc}` kurumsal ağ için kabul edilmiyor.")
    if enc.endswith("enterprise"):
        if k.get("radius_server") != b.senaryo["radius"]:
            return Sonuc(False, f"802.1X için `radius_server` satırına RADIUS sunucusunun adresini ({b.senaryo['radius']}) yaz "
                                "(adres `ap/ag_plani.txt` içinde).", yakin=True)
        return Sonuc(True)
    p = k.get("passphrase", "")
    if len(p) < 14 or p == v["weak"]:
        return Sonuc(False, "`wpa3-sae` seçtin ama parola hâlâ zayıf: en az 14 karakterlik, eskisinden farklı bir parola yaz.",
                     yakin=True)
    return Sonuc(True)


def _wps(b) -> Sonuc:
    hata, c = _cfg(b)
    if hata:
        return Sonuc(False, hata)
    acik = [bol for bol in ("kurumsal", "misafir") if c[bol].get("wps", "on").lower() != "off"]
    if acik:
        return Sonuc(False, f"WPS şu bölümlerde hâlâ açık: {', '.join(acik)}.", yakin=len(acik) == 1)
    return Sonuc(True)


def _misafir_ayrim(b) -> Sonuc:
    hata, c = _cfg(b)
    if hata:
        return Sonuc(False, hata)
    k, m = c["kurumsal"], c["misafir"]
    try:
        vk, vm = int(k.get("vlan", "")), int(m.get("vlan", ""))
    except ValueError:
        return Sonuc(False, "`vlan` değeri bir sayı olmalı.")
    eksik = []
    if vk == vm:
        eksik.append("misafir ağı kurumsalla aynı VLAN'da")
    if m.get("lan_access", "").lower() != "deny":
        eksik.append("`lan_access` `deny` değil")
    if m.get("client_isolation", "").lower() != "on":
        eksik.append("`client_isolation` `on` değil")
    if k.get("vlan") != str(b.senaryo["vlan_k"]):
        return Sonuc(False, "Kurumsal ağın VLAN numarasına dokunma; değiştirilecek olan **misafir** ağı.")
    if eksik:
        return Sonuc(False, "Eksik: " + "; ".join(eksik) + ".", yakin=len(eksik) < 3)
    return Sonuc(True)


def _misafir_sifre(b) -> Sonuc:
    hata, c = _cfg(b)
    if hata:
        return Sonuc(False, hata)
    m, k = c["misafir"], c["kurumsal"]
    enc = m.get("encryption", "").lower()
    if enc not in SIFRELEMELER_MISAFIR:
        return Sonuc(False, f"Misafir ağında `encryption={enc}` yetersiz. `wpa2-psk` ya da `wpa3-sae` kullan (açık ya da WEP olmaz).",
                     yakin=True)
    p = m.get("passphrase", "")
    if len(p) < 12:
        return Sonuc(False, "Misafir parolası en az 12 karakter olmalı.", yakin=True)
    if p == k.get("passphrase") or p == b.senaryo["v"]["weak"]:
        return Sonuc(False, "Misafir parolası kurumsal ağın parolasıyla aynı olmamalı.")
    return Sonuc(True)


def _pmf(b) -> Sonuc:
    hata, c = _cfg(b)
    if hata:
        return Sonuc(False, hata)
    if c["kurumsal"].get("pmf", "").lower() != "required":
        return Sonuc(False, "Kurumsal ağda `pmf` hâlâ `required` değil (korumalı yönetim kareleri zorunlu olmalı).")
    return Sonuc(True)


ADIMLAR = [
    Adim("Savunma ilkeleri", """
Kablosuz savunmanın beş ilkesi:

1. **Güçlü şifreleme:** WPA3; olmuyorsa WPA2.
2. **Güçlü parola:** uzun, rastgele, sözlük saldırısına dayanıklı.
3. **Kurumsal kimlik:** 802.1X ile kişiye özel kimlik doğrulama.
4. **Ağ ayrımı:** misafir ağı iç ağdan ayrı.
5. **İzleme:** sahte erişim noktalarını tespit.

Bu seviyede kurgusal bir erişim noktası yapılandırmasını **kendin düzelteceksin**. Önce dosyaya bak:
""", komut="cat ap/router.conf"),
    Adim("Ağ planı", """
BT ekibi hangi VLAN'ı ve RADIUS sunucusunu kullanacağını bir plana yazmış. VLAN, fiziksel olarak aynı kablosuz cihazın
sanal olarak ayrı ağlar yayınlamasını sağlar; Cilt 6'daki ağ bölümlendirmesinin kablosuz hâlidir.
""", komut="cat ap/ag_plani.txt"),
    Adim("Ayarları satır satır görmek", """
`grep -n` ile bir ayarın kaç yerde geçtiğini ve hangi bölümde olduğunu gör:
""", komut="grep -n -E '^\\[|encryption|wps|pmf' ap/router.conf", sonra="""
Aynı ayar iki bölümde de var. Doğru bölümü düzenlemek önemli: `[kurumsal]` ve `[misafir]` ayrı ağlardır.
"""),
    Adim("Düzenleme: sed ile bölüm bazlı", """
Bir ayarı değiştirmenin yolları: `nano ap/router.conf` ile elle, ya da `sed -i`. Tüm dosyada geçen bir ayarı tek komutla
değiştirmek için (WPS'yi iki ağda da kapatmak gibi):

```
sed -i 's/^wps=.*/wps=off/' ap/router.conf
```

Yalnızca belirli bir bölümde değiştirmek için adres aralığı kullanılır: `sed -i '/^\\[misafir\\]/,$ {s/ESKİ/YENİ/}' dosya`
(`[misafir]` satırından dosya sonuna kadar). `nano` ile çalışmak istersen onu da kullanabilirsin; sonuç aynıdır.
"""),
    Adim("Misafir ağı: ayrım ve izolasyon", """
Misafir Wi-Fi'ından iç sisteme (kasa, depo, hasta kayıtları) ulaşılabiliyorsa ağ ayrımı yoktur. Üç şey birlikte gerekir:
ayrı VLAN, iç ağa erişim reddi (`lan_access=deny`) ve istemci yalıtımı (`client_isolation=on`: misafirler birbirlerinin
cihazını da göremez). Şu an misafir bölümü:
""", komut="sed -n '/^\\[misafir\\]/,$p' ap/router.conf"),
    Adim("WPS ve gizli SSID üzerine", """
**WPS** (kolay bağlanma PIN'i) kapatılmalıdır: PIN doğrulaması parçalı yapıldığı için az sayıda denemeyle bulunabilir. **SSID
gizlemek** ise güvenlik sağlamaz: ağ adı cihazların sorgularında yine açığa çıkar; kablosuz güvenlik ağ adının gizliliğine
değil şifrelemeye dayanır. Gizli SSID'yi bir önlem sayma; asıl işi şifreleme ve kimlik doğrulama yapar.

**Hacker gözüyle:** Kablosuz, fiziksel güvenlik ile ağ güvenliği arasındaki köprüdür; saldırgan binaya girmeden ağa ulaşabiliyorsa
kablolu güvenliğin ne kadar iyi olduğunun önemi kalmaz. Kendi ağını düzenli test etmek (kendi cihazın, kendi parolanla) hem
kişisel güvenlik hem profesyonel beceridir.
"""),
]

GOREVLER = [
    Gorev("**<<kurum>>** ağı hâlâ paylaşılan parolalı `wpa2-psk`. Güvenliğini yükselt: ya `wpa2-enterprise` (802.1X; "
          "`radius_server` satırına <<radius>> adresini yaz) ya da `wpa3-sae` (en az 14 karakterlik **yeni** parola). "
          "Yalnızca `[kurumsal]` bölümünü düzenle. Bitince `cevap 1`.",
          Durum(_kurumsal, "[kurumsal] encryption=wpa2-enterprise + radius_server=<RADIUS adresi> (ya da wpa3-sae + yeni uzun parola)"),
          ("Düzeltilecek ayar `[kurumsal]` bölümündeki `encryption` satırı. 802.1X seçersen sunucu adresi de gerekir.",
           "802.1X için `encryption=wpa2-enterprise` ve `radius_server=<<radius>>`; adres `ap/ag_plani.txt` içinde de yazıyor.",
           "`sed -i '/^\\[kurumsal\\]/,/^\\[misafir\\]/{s/^encryption=.*/encryption=wpa2-enterprise/; s/^radius_server=.*/radius_server=<<radius>>/}' ap/router.conf`"),
          puan=45, baslik="Kurumsal ağı yükselt"),
    Gorev("Her iki ağda da **WPS'yi kapat** (`wps=off`). Bitince `cevap 2`.",
          Durum(_wps, "iki bölümde de wps=off"),
          ("`wps` satırı iki bölümde de var.",
           "`grep -n wps ap/router.conf` ile gör; ikisini de `off` yap.",
           "`sed -i 's/^wps=.*/wps=off/' ap/router.conf`"),
          puan=30, baslik="WPS'yi kapat"),
    Gorev("**<<misafir>>** ağını iç ağdan ayır: `[misafir]` bölümünde `vlan` değeri kurumsaldan (**<<vlan_k>>**) farklı olsun, "
          "`lan_access=deny` olsun ve `client_isolation=on` olsun. Kurumsal bölüme dokunma. Bitince `cevap 3`.",
          Durum(_misafir_ayrim, "[misafir] vlan farklı, lan_access=deny, client_isolation=on"),
          ("Üç ayar birlikte gerekiyor: ayrı VLAN, iç ağ erişimi reddi, istemci yalıtımı.",
           "Yalnızca `[misafir]` bölümünü düzenle; VLAN için `ap/ag_plani.txt` içinde önerilen numara var.",
           "`sed -i '/^\\[misafir\\]/,${s/^vlan=.*/vlan=30/; s/^lan_access=.*/lan_access=deny/; s/^client_isolation=.*/client_isolation=on/}' ap/router.conf`"),
          puan=45, baslik="Misafir ağını ayır"),
    Gorev("Misafir ağının şifrelemesi zayıf (`open`/`wep`). `[misafir]` bölümünde `encryption=wpa2-psk` (ya da `wpa3-sae`) yap "
          "ve **en az 12 karakterlik**, kurumsal parolayla aynı olmayan bir parola yaz. Bitince `cevap 4`.",
          Durum(_misafir_sifre, "[misafir] encryption=wpa2-psk, passphrase en az 12 karakter ve kurumsaldan farklı"),
          ("İki ayar: `encryption` ve `passphrase`; ikisi de `[misafir]` bölümünde.",
           "Parolanı kendin belirle (uzun, tahmin edilemez); kurumsal parolayı yeniden kullanma.",
           "`sed -i '/^\\[misafir\\]/,${s/^encryption=.*/encryption=wpa2-psk/; s/^passphrase=.*/passphrase=YeniMisafirParolam2026!/}' ap/router.conf`"),
          puan=40, baslik="Misafir şifrelemesi"),
    Gorev("Kurumsal ağda **korumalı yönetim karelerini (PMF) zorunlu** yap: `[kurumsal]` bölümünde `pmf=required`. "
          "Bitince `cevap 5`.",
          Durum(_pmf, "[kurumsal] pmf=required"),
          ("PMF, deauth gibi yönetim karelerinin sahtelenmesini engeller; ayar adı `pmf`.",
           "Değer `required` olmalı (`disabled` değil).",
           "`sed -i '/^\\[kurumsal\\]/,/^\\[misafir\\]/s/^pmf=.*/pmf=required/' ap/router.conf`"),
          puan=30, baslik="PMF zorunlu"),
    Gorev("WPS'yi kapatmanın nedeni nedir?",
          Secmeli([
              ("WPS PIN doğrulaması parçalıdır, az denemeyle bulunur; güçlü parola işe yaramaz",
               "Doğru. WPS PIN doğrulaması iki yarıya bölündüğü için PIN'in tahmini kolaydır."),
              ("WPS bütün trafiği şifresiz hâle getirir ve ağdaki herkesin birbirini görmesine neden olur",
               "Yanlış. WPS bağlanma kolaylığı sunar; trafik şifrelemesini kapatmaz."),
              ("WPS yalnızca eski cihazlarda çalışır, yeni cihazlarda ağı yavaşlatır ve bağlantıyı koparır",
               "Yanlış. Sorun hız ya da cihaz yaşı değil, PIN yönteminin zayıflığıdır."),
              ("WPS ağ adını (SSID) gizler; bu yüzden cihazların ağı bulması ve bağlanması imkânsızlaşır",
               "Yanlış. WPS SSID ile ilgili değildir; bir eşleşme yöntemidir."),
          ], dogru=0),
          ("WPS'te bir PIN kullanılır; PIN'in kaç hane olduğunu ve nasıl doğrulandığını düşün.",
           "PIN iki yarıya bölünüp ayrı ayrı doğrulanıyorsa deneme sayısı ne olur?",
           "Doğru şık PIN yönteminin zayıflığını anlatan şık."),
          puan=25, baslik="Neden WPS kapalı"),
    Gorev("Misafir ağının iç ağdan ayrılması **neden** önemlidir?",
          Secmeli([
              ("Ziyaretçi ya da saldırgan misafir ağından iç sistemlere ulaşamasın diye",
               "Doğru. Misafir ağı iç sistemlere erişememelidir; Cilt 6'daki ağ bölümlendirmesinin kablosuz uygulamasıdır."),
              ("Misafir ağı iç ağdan daha hızlı ve daha az kalabalık olsun, bant genişliği paylaşılmasın diye",
               "Yanlış. Ayrımın nedeni hız değil, güvenlik sınırıdır."),
              ("Çalışanlar yanlışlıkla misafir ağına bağlanıp iş verisi göndermesin ve cihazları karışmasın diye",
               "Yanlış. Amaç kimin bağlanacağını kısıtlamak değil, bağlananın nereye erişebileceğini sınırlamaktır."),
              ("Erişim noktasının sinyal gücünü azaltıp yayın alanını daraltmak ve enerji tasarrufu sağlamak için",
               "Yanlış. VLAN ayrımı sinyal gücünü değiştirmez; trafik akışını ayırır."),
          ], dogru=0),
          ("Misafir Wi-Fi'ına bağlanan herkes iç ağdaki kasa ya da sunucuları görebilirse ne olur?",
           "Cilt 6'daki ağ bölümlendirmesini hatırla.",
           "Doğru şık, misafirin iç sistemlere erişememesini anlatan şık."),
          puan=25, baslik="Neden ağ ayrımı"),
    Gorev("`hide_ssid=on` ile ağ adını gizlemek **güvenlik sağlar mı**?",
          Secmeli([
              ("Hayır: ağ adı yine açığa çıkar; asıl koruma şifreleme ve kimlik doğrulamadır",
               "Doğru. Gizli SSID bir güvenlik önlemi sayılmaz; kullanıcıları da gereksiz yere zorlar."),
              ("Evet: ağı hiç göremeyen bir saldırgan o ağa saldıramaz, bu yüzden ek önlem gerekmez",
               "Yanlış. Ağ adı gizlense de cihaz sorguları ve kayıtlar adı açığa çıkarır."),
              ("Evet, ama yalnızca 5 GHz bandında yayın yapan ve WPA3 kullanan ağlarda geçerlidir",
               "Yanlış. Bant fark etmez; ağ adı her bantta görünür hâle gelebilir."),
              ("Hayır: gizli SSID, WPA3'ü devre dışı bırakır ve ağı daha savunmasız hâle getirir",
               "Yanlış. Gizli SSID şifreleme sürümünü değiştirmez; sadece güvenlik sağlamaz."),
          ], dogru=0),
          ("Cihazın ağa bağlanabilmesi için ağ adını bir şekilde duyurması gerekir.",
           "Güvenlik, bir şeyin bilinmemesine mi yoksa kanıtlanamamasına mı dayanmalı?",
           "Doğru şık, gizli SSID'nin gerçek koruma sağlamadığını söyleyen şık."),
          puan=25, baslik="Gizli SSID"),
]

SEVIYE = Seviye(
    kimlik="c15b03",
    cilt=15,
    bolum=3,
    baslik="Kablosuz Savunma ve Lab",
    brifing="""
Kalkan'ın kablosuz raporu **<<musteri>>**'ye ulaştı: "Kurumsal ağ paylaşılan, zayıf bir parolayla korunuyor; misafir ağı zayıf
şifreli ve iç ağla aynı VLAN'da; WPS açık." <<hikaye>> Müşteri şimdi düzeltmeyi bekliyor.

Selin erişim noktası yapılandırmasının bir kopyasını laboratuvarına bıraktı: "**<<kurum>>** ve **<<misafir>>** için ayarları
sen düzelteceksin. RADIUS sunucusu <<radius>> adresinde; kurumsal ağın VLAN numarası <<vlan_k>>." Mert: "Gizli SSID
ayarına aldanma; asıl iş şifreleme ve ayrım." Deniz: "Düzelttikten sonra ben tarama kayıtlarında kontrol ederim."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Savunma açısından kablosuz güvenlik beş maddelik bir kontrol listesidir: güçlü şifreleme, güçlü parola ya da 802.1X, ağ ayrımı
(misafir iç ağdan uzak), WPS kapalı ve izleme. Saldırgan açısından her eksik madde bir kapıdır: kısa parola çevrimdışı tahmin
edilir, ayrımsız misafir ağı iç ağa köprü olur, açık WPS PIN'iyle ağı verir. Düzeltmeleri doğrulamak için de kayıtları (tarama,
WIDS) izlemeye devam et.
""",
    gercek_hayat="""
- **Misafir ağı ve iç ağ:** Pek çok kablosuz değerlendirmesinde misafir Wi-Fi'ının iç ağla aynı ağ bölümünde olduğu görülür.
  Ağ bölümlendirme (VLAN, güvenlik duvarı kuralları) bu hatayı önleyen en temel kontroldür.
- **Önleme:** WPA3 ya da 802.1X (sunucu sertifikasının doğrulanmasıyla), PMF, WPS'nin kapatılması, misafir ağında istemci
  yalıtımı ve ayrı VLAN. **Tespit:** WIDS/WIPS ile yetkisiz erişim noktaları ve olağandışı deauth yoğunluğu izlenir; yapılandırma
  değişiklikleri denetlenir (yapılandırma sapması taraması).
- **WPS riski:** WPS PIN yönteminin parçalı doğrulama yüzünden az denemeyle kırılabilmesi 2011'de yayımlanan çalışmayla
  kamuoyunun gündemine girdi; bu yüzden güvenlik rehberleri WPS'nin kapatılmasını önerir.
""",
    sure_hedef_dk=30,
)
