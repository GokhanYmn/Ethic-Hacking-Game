# Hacker Yolu

*Etik Hacker Yolu* kitabının oyun sürümü. Her bölüm gerçek hayattan bir vakaya dönüşür:
brifingi okursun, yeni komutları adım adım kendi elinle yazarsın, sonra gerçek bir
terminalde vakayı çözersin. Takıldığında ipucu alırsın, bitirdiğinde aynı beceriyi başka
bir şirkette, başka bir hikâyeyle tekrar oynayabilirsin.

## Gereksinimler

- Kali Linux (Raspberry Pi dahil) ya da herhangi bir Linux
- Python 3.10 veya üstü ve bash (Kali'de ikisi de hazır gelir)
- İnternet **gerekmez**; ek paket kurulmaz.

## Kurulum — GitHub'dan (Raspberry Pi için önerilen)

Depo **özeldir (private)**, bu yüzden Pi'nin bir kez GitHub'a kimlik tanıtması gerekir.
En kolay yol, Pi'de `gh` ile giriş yapmak:

```
sudo apt install gh git        # yoksa
gh auth login                  # tarayıcı/kod ile bir kez giriş
gh repo clone GokhanYmn/Ethic-Hacking-Game
cd Ethic-Hacking-Game
./install.sh
```

`gh` kurmak istemezsen, GitHub'dan bir **token** (Settings → Developer settings → Personal
access tokens → bu depoya "Contents: read") alıp:

```
git clone https://<TOKEN>@github.com/GokhanYmn/Ethic-Hacking-Game.git
cd Ethic-Hacking-Game && ./install.sh
```

Güncelleme geldiğinde: depo klasöründe `git pull && ./install.sh` — ilerlemen korunur.

> Depoyu herkese açık (public) yaparsan Pi'de hiçbir kimlik gerekmez, `git clone` tek başına
> çalışır. İstersen bunu senin için açabilirim.

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

Oyunun kendisi Docker istemez. Cilt 9'da kendi laboratuvarını Docker ile kurmayı öğrenirsin;
Docker yoksa oyun yazdığın dosyaları yine de kontrol eder. Kurmak istersen:

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
