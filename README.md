# Hacker Yolu

*Etik Hacker Yolu* kitabının oyun sürümü. Her bölüm gerçek hayattan bir vakaya dönüşür:
brifingi okursun, yeni komutları adım adım kendi elinle yazarsın, sonra gerçek bir
terminalde vakayı çözersin. Takıldığında ipucu alırsın, bitirdiğinde aynı beceriyi başka
bir şirkette, başka bir hikâyeyle tekrar oynayabilirsin.

## Nasıl kurarım? İki yol var

- **Docker ile (Windows, Mac, Linux — her yerde birebir aynı):** Oyun özünde bir Linux
  programı (gerçek `bash` + GNU araçları + Unix izinleri). Windows/Mac'te doğrudan sadık
  çalışmaz. Docker, oyunu kendi minik Linux'uyla paketler; host ne olursa olsun deneyim her
  yerde aynı olur. **Kişisel Windows/Mac için önerilen yol budur.** Bkz. _Kurulum — Docker ile_.
- **Native (Linux / Raspberry Pi):** Kali/Pi gibi gerçek bir Linux'tasın. En hafif ve en hızlı
  yol; Docker gerekmez. Bkz. _Kurulum — Raspberry Pi / Kali (native)_.

## Gereksinimler

- **Docker yolu:** Docker Desktop (Windows/Mac) ya da `docker` (Linux). Başka bir şey gerekmez;
  Python, bash ve tüm araçlar imajın içinde gelir.
- **Native yol:** Kali Linux (Raspberry Pi dahil) ya da herhangi bir Linux; Python 3.10+ ve bash
  (Kali'de ikisi de hazır gelir). İnternet gerekmez; ek paket kurulmaz.

## Kurulum — Docker ile (Windows / Mac / Linux)

Önce **Docker**: Windows ve Mac'te [Docker Desktop](https://www.docker.com/products/docker-desktop)
kurup bir kez başlat. Linux'ta `sudo apt install docker.io`.

Sonra işletim sistemine göre `baslaticilar/` klasöründeki başlatıcıyı **çift tıkla**:

| İşletim sistemi | Dosya |
|---|---|
| Windows | `baslaticilar\hackeryolu.bat` |
| macOS | `baslaticilar/hackeryolu.command` (ilk sefer: `chmod +x hackeryolu.command`) |
| Linux | `baslaticilar/hackeryolu.sh` (ilk sefer: `chmod +x hackeryolu.sh`) |

Başlatıcı, imajı ilk sefer otomatik indirir ve oyunu açar. **İlerlemen kalıcıdır:** oyun,
verini `hackeryolu_data` adlı bir Docker volume'ünde tutar; konteyner kapansa da kaybolmaz.

> Elle çalıştırmak istersen:
> ```
> docker run -it --rm -v hackeryolu_data:/home/kali ghcr.io/gokhanymn/hackeryolu:latest
> ```
> İnternetsiz (USB) kurulum için `docker load -i hackeryolu-imaj-<sürüm>.tar` sonra aynı komutu
> `HY_IMAJ=hackeryolu:<sürüm>` ile çalıştır.

## Kurulum — Raspberry Pi / Kali (native)

Depo herkese açık (public); Pi'de hiçbir kimlik gerekmez:

```
sudo apt install git           # yoksa
git clone https://github.com/GokhanYmn/Ethic-Hacking-Game.git
cd Ethic-Hacking-Game
./install.sh
```

Güncelleme geldiğinde: depo klasöründe `git pull && ./install.sh` — ilerlemen korunur.

## Kurulum — USB ile (internetsiz)

1. `hackeryolu-<sürüm>.tar.gz` dosyasını USB bellekle Kali'ye kopyala. Örneğin USB bellek
   `/media/kali/USB` altına bağlandıysa:

   ```
   cp /media/kali/USB/hackeryolu-*.tar.gz ~/
   ```

   Ağ üzerinden göndermek istersen, kendi bilgisayarından:
   `scp hackeryolu-*.tar.gz kali@<pi-ip-adresi>:~/`

2. Aç ve kur:

   ```
   cd ~
   tar xzf hackeryolu-*.tar.gz
   cd hackeryolu-*/
   ./install.sh
   ```

3. Yeni bir terminal aç ve başlat:

   ```
   hackeryolu
   ```

İsteğe bağlı: `hackeryolu oztest` bütün görevleri geçici bir klasörde kurup çözerek
kurulumun sağlam olduğunu doğrular. İlerlemene dokunmaz.

## Nasıl oynanır

- **Ana menü** → *Devam et* seni sıradaki göreve götürür. *Harita* tüm bölgeleri gösterir.
- Her görevde: **Brifing** (hikâye) → **Eğitim** (komutları adım adım yazarsın) → **Saha
  görevi** (gerçek bash kabuğu).
- Saha görevindeki komutlar:

  | Komut | Ne yapar |
  |---|---|
  | `gorev` | Soruları listeler |
  | `cevap <no> <cevabın>` | Cevap gönderir, örn. `cevap 2 FLAG{abc}` |
  | `ipucu <no>` | 3 kademeli ipucu (her kademe o görevin puanını biraz azaltır) |
  | `pes <no>` | Cevabı gösterir (puan yok, ama ilerlemen durmaz) |
  | `durum` | Rütbe ve ilerleme |
  | `sifirla` | Lab dosyalarını bozduysan aynı vakayı baştan kurar |
  | `not <metin>` | Kişisel bilgi bankana not ekler (altı ay sonra çok değerli olur) |
  | `sozluk <kelime>` | Bir terimin anlamına bakar |
  | `komut <kelime>` | Bir komutun ne işe yaradığına bakar |
  | `lab` | Lab klasörüne döner |
  | `cik` | Menüye döner |

- Ana menüde ayrıca: **Kendini Sına** (bitirdiğin ciltlerden karışık sınav), **Çalışma planı
  ve serim** (günlük seri, ilerleme, bugünkü öneri), **Başvuru** (sözlük, komut başvurusu ve
  not defterin). Notların `~/.hackeryolu/notlar.md` dosyasında birikir; istediğin zaman o
  Markdown dosyasını açıp okuyabilir ya da dışarı taşıyabilirsin.

- Bir görevi bitirince **Yeni vaka** seçeneği açılır: aynı beceri, farklı şirket, farklı
  hikâye, farklı cevaplar.
- **Olay Masası**: SOC masasında sınırsız vaka; öğrendiklerini pekiştirmek için.
  **Karışık pekiştirme** seçeneği, bitirdiğin görevlerden rastgele birini yepyeni bir vakayla açar.
- İçerik: Bölüm 0 + 24 cilt, 119 görev bölümü, 900'den fazla soru. Cilt 6 ve Capstone savunma
  odaklıdır (saldırganın izlerini okuma, kapıları kapatma). Uygulamalı saldırı pratiğinin tamamını
  **kendi laboratuvarında**, internete hiç çıkmadan yaparsın: oyunun Kali'nde çalıştırdığı
  savunmasız hedefler, Olay Masası vakaları ve Cilt 9'da kuracağın kendi atış poligonun
  (DVWA, Juice Shop, WebGoat).

## Docker (Cilt 9 için, isteğe bağlı)

> Not: Bu bölüm, oyunu Docker'da **çalıştırmak**la (yukarıdaki _Kurulum — Docker ile_) karıştırılmasın.
> Burada anlatılan, Cilt 9'da **kendi laboratuvarını** kurman için Docker'dır — ayrı bir konu.

Native kurulumda oyunun kendisi Docker istemez. Cilt 9'da kendi laboratuvarını Docker ile kurmayı
öğrenirsin; Docker yoksa oyun yazdığın dosyaları yine de kontrol eder. Kurmak istersen:

```
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER     # sonra oturumu kapatıp aç
```

Dikkat: Cilt 1'de öğrendiğin gibi `docker` grubuna üye olmak root yetkisine eşdeğerdir. Pi'n
sadece laboratuvar olarak kullanılıyorsa bu kabul edilebilir; değilse grubu eklemeyip Docker
komutlarını `sudo` ile çalıştır.

Raspberry Pi ARM işlemcilidir: bir imajı çalıştırmadan önce
`docker manifest inspect <imaj>` ile arm64 desteği olup olmadığına bak (Cilt 9 bunu öğretir).
- Kitabın sırası korunur: önce Bölüm 0 (Etik), sonra Cilt 1, 2, 3... Kendi sıranla
  ilerlemek istersen: `hackeryolu ayar serbest acik` (Bölüm 0'ı bitirmek yine şart).

## Dosyalar nerede

- Oyun: `~/.local/share/hackeryolu`
- İlerlemen: `~/.hackeryolu/kayit.json`
- Laboratuvar dosyaları: `~/hackeryolu/lab/<görev>`

## Güncelleme (yeni fazlar geldiğinde)

Yeni paketi aynı şekilde açıp `./install.sh` çalıştır. İlerlemen korunur.

## Kaldırma

```
~/.local/share/hackeryolu/install.sh --kaldir           # oyunu kaldırır, ilerlemen kalır
~/.local/share/hackeryolu/install.sh --hepsini-kaldir   # ilerleme ve lab dosyaları dahil her şeyi siler
```

## Sorun giderme

- **`hackeryolu: command not found`** → Yeni bir terminal aç ya da `source ~/.zshrc` yaz.
  Ya da doğrudan `~/.local/bin/hackeryolu` ile başlat.
- **"Görevin yerel servisleri başlatılamadı"** → Bazı görevler kendi makinende
  (127.0.0.1) küçük servisler açar. Seçilen port başka bir programdaysa menüden *Yeni vaka*
  seç; farklı portlar üretilir.
- **Renkler bozuk görünüyor** → `NO_COLOR=1 hackeryolu` ile renksiz başlat.

## Güvenlik

Bütün pratik kendi makinende, oyunun kurduğu laboratuvarda ve yalnızca 127.0.0.1 üzerinde
yapılır. Hiçbir görev internetteki bir sisteme dokunmaz. Burada öğrendiğin hiçbir tekniği
sahibinden yazılı izin almadığın bir sistemde deneme. **Önce izin, sonra iz.**
