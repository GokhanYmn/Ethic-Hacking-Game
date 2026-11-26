# Hacker Yolu — her işletim sisteminde aynı Linux deneyimini vermek için konteyner.
#
# Oyun özünde bir Linux programı (gerçek bash + GNU araçları + Unix izinleri). Windows/Mac'te
# "native" sadık çalışmaz. Bu imaj oyunu kendi minik Linux'uyla paketler; host ne olursa olsun
# içeride hep gerçek Linux çalışır ve deneyim her yerde birebir aynı olur.
#
# NOT: sqlmap/gobuster/ffuf/nikto/hydra gibi SALDIRI araçları KURULMAZ. Oyun onları çalıştırmaz;
# yalnızca ürettiği logların içinde adları (User-Agent) geçer ve sen Python karşılıklarını yazarsın.
# Buradaki araçlar standart ağ/metin/analiz araçları: öğretilen beceriler için gerekli.
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
      bash \
      gawk \
      sed \
      grep \
      coreutils \
      findutils \
      procps \
      iproute2 \
      iputils-ping \
      traceroute \
      curl \
      ca-certificates \
      bind9-dnsutils \
      netcat-openbsd \
      nmap \
      tcpdump \
      file \
      binutils \
      sqlite3 \
      git \
      zip \
      unzip \
      less \
      nano \
      vim-tiny \
 && rm -rf /var/lib/apt/lists/*

# Normal (root olmayan) kullanıcı: SUID/izin denetimi görevleri ancak normal kullanıcıda
# anlamlıdır; Pi'deki native kurulumda da oyuncu kali kullanıcısıdır.
RUN useradd --create-home --shell /bin/bash --uid 1000 kali

# Oyun kodu salt okunur, root'a ait. Oyuncu verisi /home/kali altına (volume) yazılır.
COPY . /opt/hackeryolu
RUN rm -rf /opt/hackeryolu/.git /opt/hackeryolu/dist /opt/hackeryolu/araclar/kaynak \
           /opt/hackeryolu/baslaticilar \
 && find /opt/hackeryolu -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null; true

ENV HOME=/home/kali \
    TERM=xterm-256color \
    PYTHONDONTWRITEBYTECODE=1 \
    HY_KONTEYNER=1

USER kali
WORKDIR /home/kali

# Oyunu doğrudan başlat; argümansız çağrı ana menüye düşer.
ENTRYPOINT ["python3", "/opt/hackeryolu/hackeryolu.py"]

# ghcr paketini GitHub deposuna bağlar (org.opencontainers.image.source). En sonda: önbellek korunur.
LABEL org.opencontainers.image.source="https://github.com/GokhanYmn/Ethic-Hacking-Game" \
      org.opencontainers.image.title="Hacker Yolu" \
      org.opencontainers.image.description="Etik Hacker Yolu kitabinin oyunlastirilmis terminal surumu"
