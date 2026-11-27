"""Olay Masası — AI Ajanı Prompt-Injection Olayı.

Bir AI ajanının eylem günlüğü ve MCP araç tanımları statik dosya olarak gelir. Oyuncu yalnızca okur:
enjeksiyonu yapan kullanıcı, kötüye kullanılan yetkisiz araç, hedeflenen veri, sızdırma adresi,
aşırı yetkili MCP aracı ve doğru müdahale. Kayıtlar kurgusaldır; üretici `c18b04` ile ortaktır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.seviyeler.c18_ai.b04_ajan import ajan_coz, ajan_uret, ajan_yaz, _arac_hata, _kullanici_hata
from hy.seviyeler.c18_ai.ortak import sec_doldur


def uret(rng):
    return ajan_uret(rng)


def yaz(lab: Path, s: dict) -> None:
    ajan_yaz(lab, s)


def coz(lab: Path, s: dict) -> dict:
    c = ajan_coz(lab)
    cozum = {1: c["kullanici"], 2: c["arac"], 3: c["hedef"], 4: c["alici"], 5: c["asiri"], 6: c["sayi"]}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("`ajan_gunluk.log` içinde, ajanı **izinli listesinde olmayan** bir araca iten kullanıcı kim? (Talimatı ezmeye "
          "çalışıp reddedilen başka biri de var; o değil.)",
          Metin("kullanici", sik_hatalar=_kullanici_hata, bicim="kullanıcı adı"),
          ("Ajanın izinli listesi `mcp_araclar.json` içinde; günlükteki araç sütunuyla karşılaştır.",
           "Günlüğün 4. alanı araç, 2. alanı kullanıcı: `awk -F' [|] ' '{print $2, $4}' ajan_gunluk.log`.",
           "İzinli listede olmayan aracı çağıran satırın kullanıcısı; araç sütunu `-` olan reddedilmiş satır değil."),
          puan=20, baslik="Enjeksiyonu yapan"),
    Gorev("Enjeksiyonun ajana çağırttığı, **izinli listede olmayan** araç hangisi?",
          Metin("arac", sik_hatalar=_arac_hata, bicim="araç adı"),
          ("Önceki görevdeki kullanıcının satırlarındaki araç adlarına bak.",
           "`sort | uniq -c` ile araçları say; az çağrılan ve listede olmayan araç aranan.",
           "O kullanıcının `eposta_gonder` dışındaki aracı."),
          puan=15, baslik="Kötüye kullanılan araç"),
    Gorev("Enjeksiyon hangi **veriyi** (tablo adı ya da dosya yolu) hedefledi?",
          Metin("hedef", bicim="tablo adı ya da dosya yolu"),
          ("Aracın girdisi günlüğün 5. alanında; `tablo=` ya da `yol=` ile başlar.",
           "Yetkisiz araç satırlarının 5. alanını yazdır.",
           "İlk satırdaki eşittirden sonraki değer; `sayfa=` kısmı değil."),
          puan=15, baslik="Hedeflenen veri"),
    Gorev("Aynı kullanıcı veriyi hangi **dış adrese** e-postayla göndermiş?",
          Metin("alici", bicim="e-posta adresi"),
          ("Aynı kullanıcının `eposta_gonder` satırlarına bak.",
           "`grep eposta_gonder ajan_gunluk.log` ile alıcıları karşılaştır; biri kurum dışı.",
           "`alici=` den sonraki adres; kurumun kendi alan adı olmayan."),
          puan=15, baslik="Sızdırma adresi"),
    Gorev("`mcp_araclar.json` içinde **aşırı geniş yetkili** (kapsamı bütün dosya sistemi) ve ajanın izinli listesinde "
          "olan MCP aracı hangisi?",
          Metin("asiri", bicim="araç adı"),
          ("Kapsam alanlarını karşılaştır; dar klasörler arasında kök dizin yazan bir araç var.",
           "`python3 -c` ile `json.load` kullanıp her aracın adını ve kapsamını yazdır.",
           "Kapsamı `/` ya da `/*` olan araç."),
          puan=20, baslik="Aşırı yetkili araç"),
    Gorev("Ajan, izinli listede olmayan araçtan **kaç kez** veri çekti?",
          Sayi("sayi"),
          ("Yetkisiz araç satırlarını sayman gerekiyor; e-posta çağrıları bu sayıya girmez.",
           "Günlükte yetkisiz aracın geçtiği satırları `grep` ile süz.",
           "`grep -c '<yetkisiz araç>' ajan_gunluk.log`"),
          puan=15, baslik="Yetkisiz çağrı sayısı"),
    Gorev("Canlı ajanda bu bulgulardan sonra **doğru müdahale** hangisi?",
          Secmeli([
              ("Araç kapsamlarını daralt ve izinli listeyi sunucuda uygula, girdiyi süz, ajanı yalıtılmış (sandbox) ortamda çalıştır",
               "Doğru. Katmanlı çözüm: yetki daraltılır, girdi denetlenir, kandırılan ajan zarar veremeyecek bir ortama kapatılır."),
              ("Sistem istemine 'önceki talimatları yok sayma' cümlesini üç kez ekle ve ajanı olduğu gibi açık bırak",
               "Yanlış. İstem de metindir; enjeksiyon onu geçersiz kılabilir. Yetki ve ortam değişmediği için risk sürer."),
              ("Yalnızca saldırgan kullanıcının hesabını kapat; ajanın yapılandırmasına dokunma",
               "Yanlış. Başka bir hesap aynı yolu kullanır; aşırı geniş araç ve eksik denetim yerinde kalır."),
              ("Ajanı kalıcı olarak kapat ve bir daha hiçbir otomasyonda yapay zekâ kullanma",
               "Yanlış. Aşırı tepkidir; risk yetki sınırı, denetim ve izleme ile yönetilebilir."),
          ]),
          ("Tek bir önlem yetmez; birden çok katman gerekir.",
           "Hangi şık hem yetkiyi hem girdiyi hem de çalışma ortamını ele alıyor?",
           "Kapsamı daralt, girdiyi süz, ajanı sandbox'a al."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_prompt",
    cilt=18,
    bolum=117,
    baslik="AI Ajanı Prompt-Injection Olayı",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>> <<kisi>> **<<ajan>>** adlı
<<tur>>nın kayıtlarını çıkardı: `ajan_gunluk.log` (ajanın eylem günlüğü) ve `mcp_araclar.json` (ajana tanımlı MCP
araçları ve izinli liste)."

"Bunlar gerçek sistem değil, düz metin dosyaları; jq yok, grep, awk ve python3 ile oku. Talimatı ezen kullanıcıyı,
kötüye kullanılan aracı, hedeflenen veriyi ve sızdırma adresini bul. Yapılandırmadaki aşırı geniş aracı yakala.
Sonra canlı ajanda ne yapacağımıza karar ver."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Ajan olaylarında hasar, modelin söylediğinden çok **araçların yaptığıyla** ölçülür. Zincir tanıdıktır:
talimatı ezen istem, izinli listede olmayan ama engellenmeyen bir araç, sonra dışarı çıkan veri. Müdahale
tek hamle değil katmandır: araç kapsamını daralt, izinli listeyi sunucuda uygula, girdiyi ve çıktıyı süz, ajanı
sandbox'ta çalıştır, riskli eylemleri insan onayına bağla ve her araç çağrısını kaydet. Kayıt yoksa bu
inceleme de olmazdı.
""",
    gercek_hayat="""
- **Aşırı yetki:** **OWASP'ın LLM uygulamaları risk listesi "aşırı yetki" (excessive agency) riskini ayrı bir madde
  olarak sayar**; ajanlara gereğinden geniş araç vermek, enjeksiyonun etkisini doğrudan büyütür.
- **Dolaylı enjeksiyon:** 2025'te güvenlik araştırmacıları, MCP ile bağlanan bir ajanın okuduğu bir kayıttaki gizli
  talimatla özel verileri dışarı sızdırabildiğini kamuya açık olarak gösterdi. Ajanın okuduğu her metin komut olabilir.
- **Tespit ve önleme:** İzinli liste dışı araç çağrısı, kurum dışı alıcıya e-posta ve olağandışı veri hacmi alarm
  kuralına bağlanmalı; araç kapsamları işe göre daraltılmalı, riskli eylemler insan onayından geçmeli.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c18b02",),
)
