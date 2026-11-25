# Seviye Yazım Rehberi

Bu rehber, *Etik Hacker Yolu* kitabının bir bölümünü oynanabilir bir **Hacker Yolu**
seviyesine çevirmek içindir. Yazmaya başlamadan önce iki örnek seviyeyi baştan sona oku:

- `hy/seviyeler/c00_etik.py` — çoktan seçmeli ağırlıklı, dosya okuma görevli seviye
- `hy/seviyeler/c01_linux/b02_terminal.py` — **referans seviye**: lab üretimi, gizli dosya,
  dinamik kontrol, sık hata geri bildirimi, test çözücüsü

Motor kodu `hy/motor/` altındadır. **Motor dosyalarını değiştirme.** Bir motor değişikliği
gerekiyorsa yapma; raporunda ne gerektiğini ve nedenini yaz.

## 1. Oyuncu ve ton

- Oyuncu Türkçe konuşan, etik hackerlığı sıfırdan öğrenen biri. Sade Türkçe yaz.
- Bir terimi ilk kullandığında parantez içinde açıkla: "SYN paketi (bağlantı isteği)".
- Kitabın anlatımına sadık kal ama kısalt. PDF metnini olduğu gibi kopyalama; oyunlaştır.
- Kaynak metinler: `araclar/kaynak/cXX_*.txt`. Her cildin cevapları ayrı bir dosyada
  (`*_cevaplar.txt`). Ek A: lab betiği, Ek B: komut başvurusu.

## 2. Hikâye

Hikâye kuralları `hy/hikaye.py` dosyasının başındaki açıklamada. Özet:

- Oyuncu, kurgusal güvenlik firması **Kalkan Güvenlik**'te stajyer pentester.
- Tekrar eden karakterler: **Selin Aksoy** (mentor, vakaları atar), **Mert Yavuz** (kıdemli
  pentester, esprili), **Deniz Kara** (SOC analisti, mavi takımın sesi). Karakterleri
  tutarlı kullan.
- Müşteriler `hy/ortak/vakalar.py` içinde: Pazarix, Medora Sağlık, Ferah Bank, Kuzgun
  Lojistik, Yeşiltepe Belediyesi, Paramix, Atölye Kahve. Gerekirse kendi seviyende yeni
  kurgusal müşteri tanımlayabilirsin. Alan adları `.lab` ile bitmeli, gerçek şirket adı
  kullanılmamalı.
- **Brifing** bir sahne gibi yazılır: kim arıyor, ne oldu, senden ne isteniyor. 4-8 cümle.

## 3. Vaka çeşitliliği (zorunlu)

Kullanıcı her konuyu **farklı biçimlerde** görerek pekiştirmek istiyor. Bu yüzden:

- Her seviyenin `uret(rng)` fonksiyonu en az **3 farklı vaka** arasından seçim yapmalı.
  Vakalar farklı sektör, farklı hikâye ve farklı dosya/klasör adları kullanmalı; sadece
  sayıların değişmesi yetmez. Örnek: log analizi bir vakada e-ticaret sitesinde, birinde
  hastane randevu sisteminde, birinde belediye borç sorgulamada.
- Vakanın adını `senaryo["vaka"]` içine yaz (menüde görünür).
- Vakaya özel brifing gerekiyorsa `senaryo["brifing"]` ver; yoksa `Seviye.brifing` içinde
  `<<ad>>` yer tutucuları kullan (`senaryo["metin"]["ad"]`).
- IP'ler, isimler, saatler, bayraklar her tohumda değişmeli. Test, 3 tohumun aynı cevapları
  üretmediğini kontrol eder.

## 4. Seviye modülü yapısı

Her bölüm `hy/seviyeler/cXX_<ad>/bYY_<ad>.py` dosyasıdır ve modül düzeyinde
`SEVIYE = Seviye(...)` tanımlar. Motor bunu otomatik bulur. Kimlik biçimi: `c01b04`.

| Alan | Açıklama |
|---|---|
| `uret(rng)` | **Saf** fonksiyon. `{"vaka", "metin", "cevaplar", ...}` döndürür. Dosya yazmaz. Sadece verilen `rng`'yi kullanır, `random` modülünü doğrudan kullanmaz. |
| `yaz(lab, senaryo)` | Lab dosyalarını `lab` dizinine yazar. Yardımcılar `hy/ortak/uretec.py` içinde. |
| `servis(senaryo, lab, dur)` | (İsteğe bağlı) Görev boyunca çalışan yerel servisler. `hy/motor/servis.py` yardımcılarıyla kurulur ve `calistir(sunucular, dur)` ile bloklar. **Sadece 127.x.x.x** üzerinde dinler. Portlar `uret` içinde `rng` ile 20000-45000 arasından seçilir. |
| `adimlar` | 5-9 eğitim adımı (`Adim`). |
| `gorevler` | 5-9 görev (`Gorev`). |
| `coz(lab, senaryo)` | **Sadece test içindir.** `{görev_no: cevap_metni}` döndürür. |
| `kapanis` | "Hacker Gözüyle": saldırı ve savunma tarafından ders. 3-6 cümle. |
| `gercek_hayat` | "Gerçek Hayatta": 2-3 madde. Bkz. bölüm 8. |
| `sure_hedef_dk` | Hızlı Müdahale rozeti için makul hedef süre. |

## 5. Eğitim adımları (`Adim`)

- Her adım tek bir fikri öğretir, ardından genellikle **tek bir komutu** oyuncuya yazdırır
  (`komut=`). Oyuncu komutu birebir yazmak zorunda; o yüzden komutlar kısa olmalı.
- Komutlar lab dizininde (`cwd=lab`) çalıştırılır. `sudo`, paket kurulumu, internete
  çıkan komutlar **yasak**. Ağ komutları yalnızca 127.0.0.1'e gider.
- `less`, `man`, `nano` gibi ekranı ele geçiren komutlar için `etkilesimli=True` ver ya
  da `calistir=False` yap.
- `sonra=` ile komut çıktısını yorumla: "Gördüğün X aslında Y demek."
- Kitaptaki "Hacker Gözüyle" kutularını uygun adımlara `**Hacker gözüyle:**` diye yerleştir.

## 6. Görevler (`Gorev`) ve kontroller

Görevler kitabın **Alıştırmalar** bölümünden türetilir. sudo/apt/internet gerektiren ya da
oyuncunun sisteminde iz bırakan alıştırmaları lab tabanlı bir eşdeğere çevir veya çıkar.
Her görev **tek bir şey** sorar.

Kontrol türleri (`hy/motor/kontrol.py`):

| Tür | Ne zaman |
|---|---|
| `Bayrak("anahtar")` | Lab'da gizlenmiş `FLAG{...}` (üretmek için `u.bayrak(rng, "kelime")`) |
| `Sayi("anahtar", sik_hatalar=...)` | Tek sayı (istek sayısı, port...) |
| `IP("anahtar")` | Tek IP; beklenen bir liste de olabilir |
| `Metin("anahtar", kabul=[...], on_ekleri_at=(...), sadece_ad=True)` | Kelime, dosya adı, yol, parola |
| `Kume("anahtar", tur="metin"/"ip"/"sayi")` | Sırasız liste (kullanıcı adları, açık portlar) |
| `Secmeli([(metin, açıklama), ...], dogru=0)` | Kavram/karar sorusu. Şıklar otomatik karışır. |
| `Durum(fonk, cozum)` | Oyuncu bir şey **yapar** (chmod, dosya oluşturma, süreç öldürme); `cevap <no>` sistemi kontrol eder. `fonk(baglam) -> Sonuc`. `baglam.calisma_dizini`, oyuncunun komutu yazdığı dizindir. |
| `Dinamik(hesapla, tur=...)` | Cevap oyuncunun kendi sistemine bağlı (whoami, kendi IP'si) |
| `Serbest(ornek, min_kelime)` | Kısa rapor/gerekçe yazdırma; kabul edip örnek cevabı gösterir. Seviye başına en fazla 1 tane. |
| `Hepsi([...])` | Aynı cevapta iki parça (örn. IP + sayı). Mümkünse iki ayrı görev tercih et. |

Kendi özel kontrolüne ihtiyacın olursa, kendi modülünde `Kontrol`'den türet (motoru
değiştirmeden). Oyuncunun yazdığı betiği çalıştırıp çıktısını doğrulamak gibi.

**Çoktan seçmeli kuralı:** Doğru şık en uzun ya da en ayrıntılı şık **olmamalı**. Bütün
şıklar benzer uzunlukta ve inandırıcı olmalı. Her yanlış şıkkın açıklaması neden yanlış
olduğunu öğretmeli.

**Sık hata geri bildirimi (`sik_hatalar`):** Oyuncunun büyük olasılıkla yapacağı hataları
öngör ve yönlendir. Bu oyunun en değerli özelliklerinden biri. Örnekler:

- Sayım `+1` çıktı → "Başlık satırını da saymış olabilirsin."
- `uniq`'i `sort`'suz kullandı → "Tekrarlar yan yana değilse `uniq` onları birleştiremez."
- Gizli dosya sayısı `+2` → "`.` ve `..`'yı da saydın, `ls -A` dene."

Fonksiyon biçimi: `sik_hatalar(girdi_norm, beklenen, baglam) -> str | None`.

## 7. İpuçları

Her görevde tam 3 kademe vardır. Puan kesintisi motor tarafından yapılır.

1. **Dürtme:** Nereye bakmalı, hangi kavram? Komut verme.
2. **Yöntem:** Hangi komut ya da araç, hangi seçenekle?
3. **Neredeyse çözüm:** Komut zinciri neredeyse hazır, ama cevabı **doğrudan yazma**.
   Oyuncu yine de çalıştırıp sonucu okumalı.

## 8. Gerçek Hayatta (doğruluk kuralı)

- Sadece **iyi belgelenmiş, kamuya açık** olayları ve gerçekleri kullan. Örnekler: Equifax
  2017 (yamalanmamış Apache Struts), Capital One 2019 (SSRF ile bulut metadata servisine
  erişim), Uber 2022 (MFA yorgunluğu ve sosyal mühendislik), Log4Shell 2021, Mirai 2016
  (varsayılan parolalı IoT cihazlar), Heartbleed 2014, SolarWinds 2020.
- Emin olmadığın sayı, tarih, isim ya da ceza miktarı **yazma**. Emin değilsen olayı genel
  anlat ("pek çok sızma testi raporunda ... sık görülür").
- Olayı konuyla bağla: "Bu bölümdeki X becerisi, o olayda şu şekilde fark yaratırdı."

## 9. Güvenlik sınırları (kesin)

- Lab'daki tüm dış IP'ler TEST-NET bloklarından olmalı (`u.dis_ip(rng)`): 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24. İç IP'ler RFC1918 aralığından. Alan adları `.lab`.
- Servisler yalnızca `127.x.x.x` üzerinde dinler. Hiçbir görev oyuncuyu internetteki bir
  hedefe yönlendirmez.
- Gerçek zararlı yazılım, çalışır exploit, reverse shell tek satırlıkları ya da AV
  imzalarına takılabilecek yükler (payload) **yazma**. Bu faz bunları gerektirmiyor.
  Log satırlarında saldırı izleri, örneğin `UNION SELECT`, `../` ya da `<script>` geçebilir;
  bunlar sadece metindir.
- Lab Raspberry Pi'de (ARM, sınırlı RAM) çalışacak. Üretilen dosyaların toplamı birkaç MB'ı
  geçmesin, servisler hafif olsun.

## 10. Test çözücüsü (`coz`) ve testler

- `coz`, cevapları **kitabın öğrettiği komutları gerçekten çalıştırarak** bulmalı:
  `subprocess.run(["bash", "-c", komut], cwd=lab, ...)`. `senaryo["cevaplar"]`'dan
  kopyalamak yasak. İstisnalar: `Secmeli` için `kontrol.cevabi_goster(Baglam(s, lab, no))[0]`
  ve `Dinamik` görevler.
- `Durum` görevlerinde `coz` düzeltmeyi gerçekten yapar (chmod vb.) ve `""` döndürür.
- Servisli seviyelerde test altyapısı servisi bir iş parçacığında başlatır; `coz` servise
  127.0.0.1 üzerinden bağlanabilir.
- Testi çalıştırma (Windows Git Bash'ten; konteyner Ubuntu 24.04, kullanıcı `kali`, root
  değil; kurulu araçlar: coreutils, grep, awk, sed, find, curl, dig, nc, tcpdump, ss, ip,
  file, python3 3.12):

```
HEDEF=/home/kali/hy_<senin_harfin> bash araclar/test_konteyner.sh c01b03,c01b04
```

  Her seviye, tohum 1, 2 ve 3 ile hatasız geçmeli. Ayrıca `test_yapi`, `test_yer_tutucular_dolu`
  ve `test_vakalar_cesitli` testleri de geçmeli.

## 11. Biçim (md-lite)

Metinlerde boş satır paragraf ayırır; ``` kod bloğu; `- ` madde; `1. ` numaralı madde;
`# ` alt başlık; satır içi `kod` ve **kalın**. Yer tutucu: `<<ad>>`. Python stringlerinde
`<<ad>>`'ı f-string içine koyma; motor doldurur.

## 12. Faz 2 ek kuralları (Cilt 4, 5, 7, 9)

- **Saldırı içeriği sınırı:** Çalışır exploit kodu, saldırı yükü (payload), reverse/bind shell
  komutları, antivirüs/EDR atlatma, kimlik bilgisi çalma araçları **yazılmaz**. Görevler bir
  zafiyeti **bulma, anlama, kanıtını okuma, tespit etme ve düzeltme** üzerine kurulur.
- **Hedefler:** Oyuncunun eylemleri yalnızca oyunun kendi 127.x servislerine ve lab dosyalarına
  yöneliktir. İnternetteki hiçbir sisteme (Shodan, crt.sh, whois dahil) gerçek sorgu yapılmaz;
  bu kaynaklar lab'a konan **kurgusal çıktı dosyalarıyla** taklit edilir.
- **Araçlar:** Oyuncunun Kali'sinde nmap, whatweb, gobuster, Docker bulunabilir; görev metni
  bunları önerebilir. Ama test konteynerinde (ve şirket bilgisayarında) bu araçlar **yoktur ve
  kurulmaz**. Bu yüzden kontroller aracın kendisini değil, bulunan **gerçeği** doğrular (açık
  port listesi, servis sürümü, bulunan yol...). `coz` yalnızca stdlib, coreutils, curl, dig, nc,
  ss ile çözer.
- **Docker gerektiren görevler (Cilt 9):** Kontrol, Docker varsa canlı durumu (`docker ps`),
  yoksa oyuncunun yazdığı dosyayı (compose/Dockerfile) statik olarak doğrulamalı ki testler
  Docker'sız geçsin. Önerilen imajlar arm64 destekli olmalı (Raspberry Pi).
- **Gerçek hayat örnekleri:** Bu fazda konular saldırıya yakın; "Gerçek Hayatta" kutularında
  olayın **nasıl tespit edilebileceği / nasıl önlenebileceği** de mutlaka yer alsın.
