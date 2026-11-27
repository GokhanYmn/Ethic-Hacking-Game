"""Ana hikâye: karakterler ve bölge (cilt) açılış sahneleri.

Tüm kişi ve şirket adları kurgusaldır. Müşteri alan adları `.lab` uzantılıdır ki gerçek
bir kurumla karışmasın.

Karakterler (seviye metinlerinde tutarlı kullanılmalı):
  - Selin Aksoy    — Kalkan Güvenlik'in kurucusu ve senin mentorun. Sakin, titiz,
                     "önce izin, sonra iz" der. Her vakayı o atar.
  - Mert Yavuz     — Kıdemli pentester. Esprili, biraz alaycı; kestirme yolları sever ama
                     her seferinde "raporu kim yazacak?" diye sorar.
  - Deniz Kara     — SOC (güvenlik operasyon merkezi) analisti. Mavi takımın sesi;
                     saldırının savunmadan nasıl göründüğünü anlatır.
  - Oyuncu         — Kalkan Güvenlik'e yeni katılan stajyer pentester.

Sık geçen kurgusal müşteriler (vakalarda dönüşümlü kullanılır):
  - Pazarix (pazarix.lab)            — e-ticaret sitesi
  - Medora Sağlık (medora.lab)       — özel hastane zinciri, randevu ve hasta portalı
  - Ferah Bank (ferahbank.lab)       — küçük bir katılım bankası, internet şubesi
  - Kuzgun Lojistik (kuzgun.lab)     — kargo ve depo yönetimi
  - Paramix (paramix.lab)            — fintech / ödeme kuruluşu
  - Yeşiltepe Belediyesi (yesiltepe.lab) — e-belediye hizmetleri
  - Atölye Kahve (atolye.lab)        — küçük işletme, tek sunuculu web sitesi
"""
from __future__ import annotations

SAHNELER = {
    0: """
Pazartesi sabahı, saat 09.00. **Kalkan Güvenlik**'in Kadıköy'deki küçük ofisine ilk
adımını atıyorsun. Duvarda kocaman bir yazı: **"Önce izin, sonra iz."**

Kurucu **Selin Aksoy** kahvesini uzatıp gülümsüyor: "Hoş geldin. Burada sistemlere
saldırarak para kazanıyoruz, ama sadece sahibi bizden bunu **yazılı olarak** istediğinde.
Aynı komutu izinsiz yazan biri suçlu olur. Teknik bilgi aynıdır; aradaki fark bir kâğıttır.
O yüzden ilk görevin klavyeyle değil, kurallarla."
""",
    1: """
Selin bir dizüstü bilgisayarı önüne koyuyor: "Kali kurulu. Bu hafta müşteri yok; sana
**Atölye Kahve**'nin eski sunucusunun bir kopyasını verdim. Sahibi tatilde, sunucunun
kopyası bizim laboratuvarımızda. Linux'ta yolunu bulmayı öğrenmeden kimseye
saldıramazsın."

Kıdemli pentester **Mert Yavuz** masasından sesleniyor: "Fareyi unut. Bundan sonra en
iyi arkadaşın terminal."
""",
    2: """
İkinci haftan. Selin beyaz tahtaya bir zarf çiziyor: "Her mesaj bir zarfın içinde gider:
gönderenin adresi, alıcının adresi, kapı numarası. Ağ dediğimiz şey bu zarfların
yolculuğu."

SOC analisti **Deniz Kara** başını monitörden kaldırıyor: "Ben bütün gün o zarfları
okuyorum. Saldırganı yakalamanın yolu, onun zarflarını tanımaktan geçer. Bu hafta
benimle çalışacaksın."
""",
    3: """
Mert bir kahve daha koyup yanına oturuyor: "Bir şeyi üçüncü kez elle yapıyorsan, o iş
bir betik olmak istiyor demektir. Gerçek pentester'ları ayıran şey araç ezberi değil,
gerektiğinde kendi aracını yazabilmeleridir."

Selin ekliyor: "Bu hafta Kuzgun Lojistik ve Pazarix'ten küçük işler var. Hepsini
otomatikleştirerek çözeceksin."
""",
}


SAHNELER.update({
    4: """
Selin beyaz tahtaya büyük harflerle yazıyor: **"Bilmediğin şeye saldıramazsın."**

"Bir sızma testinin yarısı keşiftir. Müşterinin bize söylediği sistemler var, bir de
unuttukları. Biz ikisini de bulmalıyız; ama sadece kapsamın içinde kalarak." Mert gülüyor:
"Ve kimseye fark ettirmeden. Pasif keşif sessizdir, aktif keşif kapıyı çalar."
""",
    5: """
Pazartesi sabahı ekibin önünde bir yığın web projesi var. Mert ekrana bir giriş formu
açıyor: "Şirketlerin internete açtığı şeylerin çoğu web uygulaması. Ve çoğu, bir
geliştiricinin cuma akşamı acele ettiği bir satır yüzünden açık."

Selin ekliyor: "Bu hafta açığı bulmak yetmeyecek. Her bulduğun açığı **kodda düzelteceksin**.
Müşteri bize 'ne bozuk' diye değil, 'nasıl düzelir' diye para ödüyor."
""",
    6: """
Gece yarısı telefon çalıyor. Deniz: "Bir müşterinin sunucusu ele geçirilmiş. Saldırgan
içeri girmiş, root olmuş, iz bırakmış. Sabaha kadar nasıl olduğunu bulmamız lazım."

Selin sakin: "Saldırganın her adımı, bir yanlış yapılandırmanın üzerine basar. Bu hafta
o basamakları tek tek bulacak ve söküp atacaksın. Saldırganın gözüyle bakacağız ama
elimiz savunmacının elinde olacak."
""",
    7: """
Deniz Kara seni SOC odasına çağırıyor. Duvarda altı ekran, hepsinde akan loglar.
"Saldırganın bir kez haklı olması yeter; bizim her seferinde haklı olmamız gerekir.
Bu hafta mavi takımdasın."

"Sertleştireceksin, izleyeceksin, alarmları ayıklayacaksın ve bir olay olduğunda paniğe
kapılmadan sırayla müdahale edeceksin."
""",
    8: """
Selin seni toplantı odasına alıyor. Masada basılı bir sızma testi raporu var.
"Bugüne kadar teknik öğrendin. Ama müşterinin eline geçen tek şey bu: rapor."

"Bu hafta mesleği konuşacağız: metodoloji, rapor yazımı, bug bounty, CTF ve kariyer.
İyi bir pentester ile harika bir pentester arasındaki fark çoğu zaman buradadır."
""",
    9: """
Mert bir Raspberry Pi'yi masana koyuyor: "Kendi laboratuvarın olmadan gelişemezsin.
Çevrimiçi platformların saat sınırı var; burada yok."

"Ama bir kuralım var: lab'ındaki hedefler kasten savunmasızdır. Onları internete açık
bırakırsan, eğitim ortamın başkasının saldırı üssü olur. Önce yalıtım."
""",
    10: """
**Ferah Bank** ve **Paramix** aynı hafta sözleşme imzaladı. Selin ciddileşiyor:
"Finansal sistemlerde açık, doğrudan para demek. Ve en tehlikeli açıklar tarayıcıların
bulamadığı açıklardır: iş mantığı hataları."

"Negatif bir tutar, iki kez kullanılan bir kupon, yanlış yuvarlanan bir kuruş... Bu
hafta bir bankacının ve bir saldırganın gözüyle aynı anda bakacaksın."
""",
    11: """
Bir holdingin bilgi işlem müdürü arıyor: "Bütün şirket Active Directory'de. Bir kullanıcı
ele geçirilirse nereye kadar gidebilir, bilmiyoruz."

Deniz: "AD'de saldırgan tek bir açık aramaz; yetkiden yetkiye atlayan bir yol arar.
Biz o yolları haritalayıp en zayıf halkayı keseceğiz."
""",
    12: """
Paramix tamamen buluta taşınmış. Ece Hanım: "Sunucu yok, her şey bulutta, o yüzden
güvendeyiz sanıyorduk." Selin gülümsüyor: "Bulut başkasının bilgisayarıdır. Güvenliğin
bir kısmı onun, bir kısmı hâlâ sizin."

Bu hafta IAM politikalarını, depolama izinlerini ve uygulama kodunu denetleyeceksin.
""",
    13: """
Kuzgun Lojistik bütün uygulamalarını konteynerlere taşımış. Serdar Bey gururlu: "Artık
her şey izole." Mert kaşını kaldırıyor: "Konteyner bir duvar değil, bir perde. Nasıl
yapılandırıldığına bağlı."

Dockerfile'ları, compose dosyalarını ve Kubernetes tanımlarını tek tek denetleyeceksin.
""",
    14: """
Ferah Bank'ın mobil uygulaması yeni sürüme hazırlanıyor. Kaan Bey: "Müşterilerimizin
çoğu artık sadece telefondan giriyor. Uygulamanın içinde ne var, bir bakın."

Selin: "Bir mobil uygulama, müşterinin cebindeki bir sunucu kopyası gibidir. İçine ne
gömüldüyse herkes okuyabilir."
""",
    15: """
Medora'nın yeni hastanesinde misafir ağı ile cihaz ağı aynı yayında mı, kimse emin
değil. Deniz elinde bir dizüstüyle geliyor: "Kablosuz ağın duvarı yoktur; sinyal
binanın dışına taşar."

Bu hafta kablosuz ağların şifrelemesini, zayıflıklarını ve savunmasını öğreneceksin;
tamamen hazır kayıtlar ve çıktılar üzerinden.
""",
    16: """
Yeşiltepe Belediyesi'nde bir çalışan sahte bir e-postaya parolasını girmiş. Nurcan Hanım
üzgün: "Bütün teknik önlemleri aldık ama..."

Selin: "En güçlü güvenlik duvarı bile, kapıyı içeriden açan birini durduramaz. Bu hafta
insanı anlayacağız: neden kanar, sahte bir e-posta nasıl tanınır, kurum nasıl korunur."
""",
    17: """
Deniz'in ekranında karantinaya alınmış şüpheli bir dosya var. "Bunun ne yaptığını
anlamamız lazım ama **asla** gerçek bir makinede çalıştırmayacağız."

"Zararlı yazılım analizi bir bomba imha işi gibidir: izole ortam, sabır ve not. Bu hafta
zararsız örnekler üzerinde göstergeleri çıkarmayı öğreneceksin."
""",
    18: """
Paramix müşteri hizmetlerine bir yapay zekâ asistanı koymuş. Ece Hanım: "Kullanıcılar
ona her şeyi sorabiliyor." Mert: "Her şeyi mi? Peki ona her şeyi **yaptırabiliyorlar** mı?"

Bu hafta yapay zekâ sistemlerinin yeni saldırı yüzeyini ve onları güvenle kullanmayı
öğreneceksin.
""",
    19: """
Ferah Bank açık bankacılık API'lerini dışarıya açıyor. Kaan Bey: "Başka uygulamalar
müşterinin izniyle hesap bilgisine erişecek." Selin: "İzin, token ve kapsam. Üçünden biri
yanlışsa kapı ardına kadar açılır."
""",
    20: """
Pazarix kart ödemelerini kendi sunucusunda işlemeye başlamış. Selin endişeli: "Kart
verisine dokunan her sistem PCI-DSS kapsamına girer. Kart numarası yanlış yerde bir log
satırında bile duruyorsa, sorun büyüktür."
""",
    21: """
Paramix'te garip işlemler: gece üçte, aynı karttan, farklı şehirlerden. Deniz: "Bu bir
saldırı değil, dolandırıcılık. Kural motorları ve veriyle yakalanır."

Bu hafta işlem kayıtlarından dolandırıcılığı ayıran kuralları kendin yazacaksın.
""",
    22: """
Bir kripto girişimi akıllı sözleşmesini denetletmek istiyor. Mert: "Blokzincirde bir
hata yayına girdiyse geri alınamaz. Kod kanundur, hata da kanunun parçası olur."

Bu hafta anahtar yönetimini, akıllı sözleşme açıklarını ve cüzdan güvenliğini
öğreneceksin; tamamen okuma ve analiz üzerinden. Ve bir kasa boşaldığında iş bitmez:
çalınan fonu adresten adrese, mikserden borsaya zincirde takip etmeyi — paranın
bıraktığı izi okumayı — da öğreneceksin.
""",
    23: """
Kuzgun Lojistik e-fatura ve e-irsaliyeye geçiyor; bordro da SGK ile entegre. Serdar Bey:
"Her şey birbirine bağlandı, bir yerde sorun olursa her yere yayılır mı?"

Bu hafta Türkiye'nin e-Dönüşüm ekosistemini, entegratörleri ve uyumu inceleyeceksin.
""",
    24: """
Selin seni odasına çağırıyor. Masada üç dosya var. "Stajın bitiyor. Bu üç vaka, öğrendiğin
her şeyi birleştirmeni isteyecek. Başarırsan, Kalkan Güvenlik'te bir masan olacak."

Mert kapıdan sesleniyor: "Raporu unutma!"
""",
    25: """
Selin bir dosya daha uzatıyor: "Bu farklı. Burada hedef bir sunucu değil — bir fabrika,
bir su tesisi, bir trafo. Endüstriyel sistemler (OT). Bir hata ekranda değil, fiziksel
dünyada patlar. Burada 'çalışır durumda kalmak' her şeyden önce gelir."

Bu bölgede SCADA, PLC ve Modbus trafiğini izlemeyi; normalin içinden tehlikeli bir komutu
ayıklamayı öğreneceksin.
""",
})


def sahne(cilt: int) -> str | None:
    return SAHNELER.get(cilt)
