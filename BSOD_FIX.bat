@echo off
title BSOD FIX - HEXWARE CHECKER
color 0c

echo.
echo ========================================
echo    BSOD FIX - HEXWARE CHECKER
echo ========================================
echo.

echo [1/8] Verification de l'integrite du systeme...
sfc /scannow /quiet

echo [2/8] Verification de l'integrite des fichiers Windows...
DISM /Online /Cleanup-Image /RestoreHealth /quiet

echo [3/8] Nettoyage du cache DNS...
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew

echo [4/8] Nettoyage des fichiers temporaires...
del /q /f %temp%\*.*
del /q /f C:\Windows\Temp\*.*
del /q /f C:\Windows\Prefetch\*.*

echo [5/8] Verification et reparation du disque...
chkdsk C: /f /r /x

echo [6/8] Nettoyage du registre Windows...
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f

echo [7/8] Redemarrage des services critiques...
net stop wuauserv
net start wuauserv
net stop bits
net start bits
net stop cryptsvc
net start cryptsvc

echo [8/8] Optimisation de la memoire...
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset create name="C:\pagefile.sys",initialsize=2048,maximumsize=8192

echo.
echo ========================================
echo    CORRECTIONS TERMINEES !
echo ========================================
echo.
echo Les corrections suivantes ont ete appliquees :
echo - Verification de l'integrite du systeme
echo - Nettoyage des fichiers temporaires
echo - Reparation du disque dur
echo - Nettoyage du registre
echo - Redemarrage des services Windows
echo - Optimisation de la memoire virtuelle
echo.
echo Un redemarrage est recommande pour appliquer
echo completement toutes les corrections.
echo.
pause
