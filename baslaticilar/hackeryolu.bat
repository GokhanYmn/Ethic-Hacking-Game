@echo off
REM Hacker Yolu - Docker ile baslatici (Windows). Cift tikla calistir.
REM Mesajlar bilerek ASCII: cmd kod sayfasinda Turkce karakter bozulur.
setlocal
chcp 65001 >nul 2>nul
if "%HY_IMAJ%"=="" set "HY_IMAJ=ghcr.io/gokhanymn/hackeryolu:latest"
if "%HY_VOLUME%"=="" set "HY_VOLUME=hackeryolu_data"

where docker >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop kurulu degil.
  echo Kur: https://www.docker.com/products/docker-desktop
  echo.
  pause
  exit /b 1
)

docker info >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop calismiyor. Once Docker Desktop uygulamasini baslat, sonra tekrar dene.
  echo.
  pause
  exit /b 1
)

docker image inspect %HY_IMAJ% >nul 2>nul
if errorlevel 1 (
  echo Imaj ilk kez indiriliyor: %HY_IMAJ%
  docker pull %HY_IMAJ%
)

docker run -it --rm -v %HY_VOLUME%:/home/kali -e TERM=xterm-256color %HY_IMAJ% %*
endlocal
