"""Cilt 16 · Bölüm 1 — İnsan Neden Hedeftir?

Beceri: kurgusal vaka notlarında saldırganın hangi ikna ilkesini (otorite, aciliyet, korku, güven/tanıdıklık,
yardımseverlik) kullandığını tanımak; hangi notun kimlik bilgisi istediğini bulmak; phishing, spear phishing ve
whaling farkını bilmek; "doğrula, sonra güven" refleksini kazanmak.

Vakalar: Ferah Bank, Paramix, Kuzgun Lojistik, Yeşiltepe Belediyesi, Medora Sağlık. Notlar kısa ve kurgusaldır;
bu seviyede hiçbir kullanılabilir mesaj şablonu, kimlik avı sayfası ya da araç yoktur.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c16_sosyal.ortak import Esle, sec_doldur, sh, vaka_sec

ILKELER = ["Otorite", "Aciliyet", "Korku", "Güven / tanıdıklık", "Yardımseverlik"]

# ilke: [(kanal seçenekleri, kimden, istenen, metin şablonu)]
SABLON = {
    "Otorite": [
        (["telefon", "e-posta"], "{bt} yöneticisi olduğunu söyleyen biri", "parola",
         "Ben {bt} yöneticisiyim. Güvenlik denetimi yapıyoruz; {sistem} parolanı şimdi bana söyle. "
         "Yöneticine sormana gerek yok, yetkim var."),
        (["e-posta", "telefon"], "{yonetici} adına yazan bir 'asistan'", "para transferi",
         "{yonetici} adına yazıyorum. Kendisi müsait değil ama bu ödemenin hemen yapılmasını istedi; "
         "onay sürecini beklemeden hesaba aktarın."),
    ],
    "Aciliyet": [
        (["e-posta", "SMS"], "{sistem} bildirim servisi gibi görünen gönderen", "bağlantı tıklama",
         "{sistem} hesabınız 1 saat içinde kapatılacak. Kapanmaması için hemen aşağıdaki bağlantıya "
         "tıklayıp bilgilerinizi doğrulayın."),
        (["SMS", "e-posta"], "bir ödeme servisi gibi görünen gönderen", "bağlantı tıklama",
         "Ödemeniz için son 30 dakika! Süre dolunca işlem iptal olacak; hemen bağlantıdan onaylayın."),
    ],
    "Korku": [
        (["SMS", "e-posta"], "bir icra dairesi gibi görünen gönderen", "ek dosya açma",
         "Hakkınızda yasal işlem başlatıldı. Ekteki tebligat dosyasını açmazsanız dosya doğrudan mahkemeye "
         "gönderilecektir."),
        (["e-posta", "SMS"], "bir vergi dairesi gibi görünen gönderen", "SMS kodu",
         "Hesabınızda usulsüzlük tespit edildi, cezai işlem başlayacak. Hemen telefonunuza gelen doğrulama "
         "kodunu bu mesaja yanıt olarak yazın."),
    ],
    "Güven / tanıdıklık": [
        (["e-posta", "sohbet"], "tanıdık bir meslektaş gibi yazan biri", "bağlantı tıklama",
         "Selam, geçen ay {birim} toplantısında tanışmıştık. Yeni formu paylaşıyorum, bir göz atıp bilgilerini "
         "güncelleyebilir misin? (ortak dosya bağlantısı)"),
        (["e-posta", "sohbet"], "her zamanki iş ortağının logosunu taşıyan gönderen", "ek dosya açma",
         "Her zamanki iş ortağınız olarak sizi yeni sürüm hakkında bilgilendiriyoruz; ekteki dosyayı açıp "
         "ayarlarınızı gözden geçirin."),
    ],
    "Yardımseverlik": [
        (["telefon", "sohbet"], "yeni başladığını söyleyen sahte bir personel", "SMS kodu",
         "Merhaba, bugün işe başladım ve {sistem}'e giremiyorum, işim durdu. Çok yardımın dokunur: "
         "telefonuna gelen doğrulama kodunu bana okur musun?"),
        (["telefon", "sohbet"], "bir tedarikçi çalışanı gibi konuşan biri", "parola",
         "Faturayı yetiştirmem lazım, sistem beni dışarıda bıraktı. Senin hesabınla bir kereliğine girmeme "
         "izin verir misin, parolanı yazar mısın?"),
    ],
}
KANAL_SECENEKLERI = ["telefon", "e-posta", "SMS", "sohbet"]


def uret(rng):
    v = vaka_sec(rng)
    sira = list(ILKELER)
    rng.shuffle(sira)
    kat = list(ILKELER)
    rng.shuffle(kat)
    harf = {k: "abcde"[i] for i, k in enumerate(kat)}
    notlar = []
    for no, ilke in enumerate(sira, 1):
        kanallar, kimden, istenen, metin = rng.choice(SABLON[ilke])
        kanal = rng.choice(kanallar)
        notlar.append({"no": no, "ilke": ilke, "kanal": kanal, "kimden": kimden.format(**v),
                       "istenen": istenen, "metin": metin.format(**v)})
    esle = {str(n["no"]): harf[n["ilke"]] for n in notlar}
    esle_metni = ("\n".join(f"{n['no']}) vaka_{n['no']}.txt" for n in notlar) +
                  "\n\nİlkeler:\n" + "\n".join(f"{harf[k]}) {k}" for k in kat))
    kimlik_isteyen = [n["no"] for n in notlar if n["istenen"] in ("parola", "SMS kodu")]
    eposta = sum(1 for n in notlar if n["kanal"] == "e-posta")
    return {
        "vaka": f"{v['ad']} — {v['birim']} birimine gelen şüpheli mesajlar",
        "v": v, "notlar": notlar,
        "metin": {"musteri": v["ad"], "birim": v["birim"], "sistem": v["sistem"], "yonetici": v["yonetici"],
                  "hikaye": v["hikaye"], "esle": esle_metni},
        "cevaplar": {"esle": esle, "kimlik": kimlik_isteyen, "eposta": eposta},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} çalışanlarının bildirdiği KURGUSAL şüpheli mesajlar (kısa notlar). Gerçek kişi ya da kurum yoktur.\n"
          "Selin'den not: Amacımız bu mesajları tanımak. Her vaka dosyasında kanal, kimden, istenen ve mesajın özeti var.\n")
    for n in s["notlar"]:
        u.yaz(lab / "vakalar" / f"vaka_{n['no']}.txt",
              f"KANAL: {n['kanal']}\nKIMDEN: {n['kimden']}\nISTENEN: {n['istenen']}\n"
              f"MESAJ ÖZETİ: \"{n['metin']}\"\n")
    u.yaz(lab / "ikna_ilkeleri.txt",
          "Sosyal mühendisin kullandığı bilinen ikna tetikleyicileri\n"
          "  Otorite             'Ben yöneticiyim, söyle' (yetkili biri gibi davranmak)\n"
          "  Aciliyet            'Bir saat içinde kapanacak' (düşünmeye zaman bırakmamak)\n"
          "  Korku               'Yasal işlem başlatıldı' (kaygıyla karar verdirmek)\n"
          "  Güven / tanıdıklık  Tanıdık bir kişi ya da markayı taklit etmek\n"
          "  Yardımseverlik      İnsanların yardım etme eğilimini kullanmak\n")


def coz(lab: Path, s: dict) -> dict:
    kimlik = sh("grep -l -E 'ISTENEN: (parola|SMS kodu)' vakalar/*.txt | grep -o '[0-9]' | tr '\\n' ' '", lab)
    eposta = sh("grep -l 'KANAL: e-posta' vakalar/*.txt | wc -l", lab)
    esle = GOREVLER[1].kontrol.cevabi_goster(Baglam(s, lab, 2))
    return sec_doldur({2: esle, 3: kimlik, 4: eposta}, GOREVLER, lab, s)


def _eposta_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == 5 - beklenen:
        return "Bu, e-posta **olmayan** kanalların sayısı. Soru e-posta kanalını soruyor."
    return None


ADIMLAR = [
    Adim("Teknolojiyi yamalarsın, insanı yamalayamazsın", """
En güçlü güvenlik duvarı bile bir insanı kandırmaya karşı çaresizdir. Saldırıların çok büyük bir kısmı teknik bir açıktan değil,
bir insanın **ikna edilmesinden** başlar: kapıyı saldırgan kırmaz, kurban açar. Bu yüzden insan çoğu zaman en kolay giriş
noktasıdır. Bu bölümde ikna tetikleyicilerini tanımayı öğreneceksin.

Önce müşterinin bildirdiği vaka dosyalarını listele:
""", komut="ls vakalar"),
    Adim("Bir vaka notunu okumak", """
Her vaka notunda dört satır var: **KANAL** (mesaj nereden geldi), **KIMDEN** (iddia edilen kimlik), **ISTENEN** (saldırgan
senden ne istiyor) ve mesajın özeti.
""", komut="cat vakalar/vaka_1.txt"),
    Adim("İkna ilkeleri", """
Sosyal mühendisler psikolojinin bilinen tetikleyicilerini kullanır:
""", komut="cat ikna_ilkeleri.txt", sonra="""
Bunların hepsi **normal insani eğilimler**: yetkiye saygı, hızlı karar baskısı, korku, tanıdıklık, yardım etme isteği.
Kimsenin 'saf' olması gerekmez; saldırgan doğal davranışları kullanır.
"""),
    Adim("Hepsini bir arada okumak", """
`cat` birden çok dosyayı art arda gösterir. Hepsini oku ve her notta hangi tetikleyicinin öne çıktığını düşün:
""", komut="cat vakalar/*.txt"),
    Adim("Ne isteniyor?", """
Saldırganın asıl hedefi hep bir **eylem**: bağlantıya tıklatmak, dosya açtırmak, parola ya da SMS doğrulama kodu almak, para
transfer ettirmek. `grep` ile 'istenen' satırlarını yan yana al:
""", komut="grep ISTENEN vakalar/*.txt", sonra="""
Meşru bir kurum **parolanı ya da SMS doğrulama kodunu asla** telefonda, e-postada ya da sohbette istemez. Bunlardan birini
isteyen her mesaj, ikna tekniği ne olursa olsun, neredeyse kesin bir saldırı işaretidir.
"""),
    Adim("Kanal sayımı ve dosya listesi", """
`grep -l` eşleşen **dosyaların adlarını** verir; `wc -l` sayar. Kaç not telefonla geldi?
""", komut="grep -l 'KANAL: telefon' vakalar/*.txt | wc -l", sonra="""
**Hacker gözüyle:** Sosyal mühendislik bu kitaptaki tüm teknik savunmaları atlayabilir; tek bir tıklama aylarca süren bir savunmayı
boşa çıkarabilir. Savunma dersi: düzenli farkındalık eğitimi, şüpheli mesajları bildirme kültürü ve **"doğrula, sonra güven"**
alışkanlığı: mesajı gönderen kanalı değil, bildiğin başka bir kanalı kullanarak teyit et.
"""),
]

GOREVLER = [
    Gorev("`<<birim>>` biriminden belirli bir çalışanın adını, yöneticisinin adını ve devam eden bir projeyi içeren, **yalnızca ona "
          "yazılmış** bir e-posta geliyor. Bu saldırı türünün adı nedir?",
          Secmeli([
              ("Spear phishing: kişiye özel hazırlanmış hedefli oltalama",
               "Doğru. Kişiye özel bilgiler içeren, tek bir hedefe yönelik mesaj spear phishing'dir."),
              ("Genel (toplu) phishing: aynı mesaj binlerce kişiye aynı anda gider",
               "Yanlış. Toplu phishing kişiye özel bilgi içermez; burada tek bir kişi hedef alınıyor."),
              ("Whaling: yalnızca üst düzey yöneticileri hedef alan oltalama",
               "Yanlış. Whaling'de hedef genel müdür gibi üst düzey yöneticidir; burada sıradan bir çalışan hedef."),
              ("Vishing: telefonla yapılan sosyal mühendislik",
               "Yanlış. Vishing telefon kanalıdır; burada kanal e-postadır."),
          ], dogru=0),
          ("Mesajda kişiye özel ayrıntılar var; bu, toplu gönderimin işareti mi?",
           "Phishing (genel), spear phishing (bir kişiye özel), whaling (üst düzey yönetici) arasındaki farkı hatırla.",
           "Hedef sıradan bir çalışan ve mesaj ona özel: doğru şık 'hedefli' olanı anlatan şık."),
          puan=25, baslik="Hangi tür?"),
    Gorev("`vakalar/` klasöründeki beş notun her birinde saldırgan **hangi ikna ilkesine** dayanıyor? Eşle "
          "(numara + harf, örn. `1c 2a 3e 4b 5d`):\n\n<<esle>>",
          Esle("esle"),
          ("Her notu oku ve öne çıkan duyguyu bul: yetki mi, süre baskısı mı, korku mu, tanıdıklık mı, yardım isteği mi?",
           "`cat vakalar/vaka_1.txt` ile başla; `ikna_ilkeleri.txt` her ilkenin kısa tanımını verir.",
           "'Yöneticiyim/yetkim var' otorite; 'bir saat kaldı' aciliyet; 'yasal işlem' korku; 'tanıdık kişi/marka' güven; 'yardım et' yardımseverlik."),
          puan=50, baslik="İlke eşleme"),
    Gorev("Hangi vaka dosyaları **parola ya da SMS doğrulama kodu** istiyor? Dosya numaralarını yaz (virgülle ayır).",
          Kume("kimlik", tur="sayi", bicim="dosya numaraları, virgülle ayrılmış"),
          ("Her notta `ISTENEN:` satırı var. Hangi değerler kimlik bilgisi anlamına geliyor?",
           "`grep ISTENEN vakalar/*.txt` bütün istenenleri listeler.",
           "`grep -l -E 'ISTENEN: (parola|SMS kodu)' vakalar/*.txt` eşleşen dosyaların adlarını verir; adlardaki numaralar cevaptır."),
          puan=35, baslik="Kimlik bilgisi isteyenler"),
    Gorev("Kaç not **e-posta** kanalıyla geldi?",
          Sayi("eposta", sik_hatalar=_eposta_hata),
          ("Her notta `KANAL:` satırı var.",
           "`grep -l 'KANAL: e-posta' vakalar/*.txt` eşleşen dosyaları listeler.",
           "`grep -l 'KANAL: e-posta' vakalar/*.txt | wc -l`"),
          puan=25, baslik="E-posta kanalı"),
    Gorev("Biri seni arayıp 'BT yöneticisiyim, hemen parolanı söyle' diyor ve sesi çok emin. **En doğru tepki** hangisi?",
          Secmeli([
              ("Parolayı vermemek, aramayı kapatıp BT'yi resmi numaradan aramak",
               "Doğru. 'Doğrula, sonra güven': kanalı sen seçersin; meşru BT parolanı hiçbir zaman istemez."),
              ("Önce birkaç soru sorup arayan güvenilir görünüyorsa parolayı vermek",
               "Yanlış. İyi bir saldırgan güvenilir görünür; ses tonuna göre karar verilmez."),
              ("Parolanın yalnızca yarısını söyleyip kalan yarısını yazılı olarak ayrıca iletmek",
               "Yanlış. Yarım parola da saldırgana yeterli bilgi verir ve asıl hata (parola paylaşımı) sürer."),
              ("Aramanın ardından yöneticinin e-postasından onay gelmesini beklemek",
               "Yanlış. E-posta da sahte olabilir; teyit saldırganın verdiği bir kanaldan değil, senin bildiğin bir kanaldan gelmeli."),
          ], dogru=0),
          ("Meşru bir BT ekibi parolanı sorar mı?",
           "Aramayı kimin başlattığı önemli: teyidi sen başlatırsan saldırganın seçtiği bir kanala bağımlı kalmazsın.",
           "Doğru şık, aramayı sonlandırıp bildiğin resmi numaradan teyit etmeyi söyleyen şık."),
          puan=30, baslik="Doğrula, sonra güven"),
    Gorev("Sosyal mühendislik, bu kitaptaki teknik savunmaları (güvenlik duvarı, yama, şifreleme) **neden atlayabilir**?",
          Secmeli([
              ("Karar veren insandır: kurban kapıyı kendi eliyle açar, teknik kontrol engelleyemez",
               "Doğru. Teknik savunmalar insanın verdiği 'evet' kararını durduramaz."),
              ("Çünkü güvenlik duvarları ve filtreler e-postaları ve bağlantıları hiçbir şekilde taramaz",
               "Yanlış. Filtreler birçok mesajı yakalar; ama ikna edilmiş bir kullanıcı filtreyi de atlatan bir eylem yapabilir."),
              ("Çünkü sosyal mühendislik yalnızca eski, yamalanmamış ve desteği bitmiş sistemlerde işe yarar",
               "Yanlış. Bu saldırılar en yeni sistemlere karşı da etkilidir; hedef teknoloji değil insandır."),
              ("Çünkü yamalar, yazılımla birlikte insan davranışını da otomatik olarak güncelleyip düzeltir",
               "Yanlış. Tam tersi: insan davranışı bir yazılım gibi güncellenemez."),
          ], dogru=0),
          ("Saldırı, bir yazılım açığını mı yoksa bir kişinin kararını mı hedef alıyor?",
           "'İnsanı yamalayamazsın' cümlesini düşün.",
           "Doğru şık, kararın insanda olduğunu söyleyen şık."),
          puan=25, baslik="Neden teknik savunma yetmez"),
]

SEVIYE = Seviye(
    kimlik="c16b01",
    cilt=16,
    bolum=1,
    baslik="İnsan Neden Hedeftir?",
    brifing="""
**<<musteri>>**'de <<birim>> birimi tedirgin. <<hikaye>> Müşteri, çalışanlarının bildirdiği mesajları kısa vaka notları hâlinde
Kalkan'a gönderdi.

Selin: "Bu bir sızma testi değil; bir **tanıma** egzersizi. Saldırgan her notta insanın hangi doğal eğilimini kullanıyor?
Dosyaları oku, ilkeleri eşle." Mert ekliyor: "Teknik açığı yamayınca kapanır; insanı yamayamazsın. O yüzden en iyi savunma
farkındalık." Deniz: "SOC'ta en çok sevdiğim şey, çalışanın 'bu tuhaf' deyip bildirmesi."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Sosyal mühendis, teknik bir kapıyı zorlamak yerine bir insanın doğal eğilimlerine başvurur: yetkiye saygı, zaman baskısı, korku,
tanıdıklık, yardım etme isteği. Kapıyı kurban kendi eli ile açar. Savunma dersi: bu tetikleyicileri tanı (bir mesaj acele
ettiriyor ya da korkutuyorsa dur), parola ve SMS kodunu kimseyle paylaşma, teyidi **kendi bildiğin** kanaldan yap ve
şüpheli mesajı bildirmekten çekinme. Kurum tarafında eğitim ve bildirme kültürü bunun temelidir.
""",
    gercek_hayat="""
- **Uber 2022:** Saldırgan, bir çalışana sürekli MFA onay isteği göndererek (MFA yorgunluğu) ve BT personeli gibi davranarak
  onay almayı başardı; olay sosyal mühendisliğin güçlü bir kimlik doğrulamayı da aşabildiğini gösterdi. Savunma: MFA onay
  isteklerini sınırlamak, onay istemini bağlam gösterecek biçimde tasarlamak ve çalışanlara 'beklemediğin onayı reddet ve
  bildir' kuralını öğretmek.
- **Önleme:** Düzenli farkındalık eğitimi, sorgusuz sualsiz parola/kod paylaşılmaması kuralı, hassas işlemlerde çift onay
  (maker-checker) ve doğrulama süreçleri. **Tespit:** Şüpheli mesajları bildirme düğmesi ve olağandışı oturum açmaları
  izleyen bir SOC; bildirilen her mesajın aynı anda tüm posta kutularında aranması.
- **Kimlik bilgisi isteği:** Meşru kurumlar parolayı ve tek kullanımlık kodları telefonda ya da e-postada istemez; bu kural
  bankaların ve kamu kurumlarının dolandırıcılık uyarılarında sıkça yinelenir.
""",
    sure_hedef_dk=20,
)
