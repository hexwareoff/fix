@echo off
title ALLFIX - HEXWARE CHECKER
color 0a

echo.
echo ========================================
echo    ALLFIX - HEXWARE CHECKER
echo ========================================
echo.

echo [1/12] Verification de l'integrite du systeme...
sfc /scannow /quiet

echo [2/12] Verification de l'integrite des fichiers Windows...
DISM /Online /Cleanup-Image /RestoreHealth /quiet

echo [3/12] Nettoyage du cache DNS...
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew

echo [4/12] Nettoyage des fichiers temporaires...
del /q /f %temp%\*.*
del /q /f C:\Windows\Temp\*.*
del /q /f C:\Windows\Prefetch\*.*

echo [5/12] Verification et reparation du disque...
chkdsk C: /f /r /x

echo [6/12] Nettoyage du registre Windows...
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f

echo [7/12] Redemarrage des services critiques...
net stop wuauserv
net start wuauserv
net stop bits
net start bits
net stop cryptsvc
net start cryptsvc

echo [8/12] Optimisation de la memoire...
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset create name="C:\pagefile.sys",initialsize=2048,maximumsize=8192

echo [9/12] Desactivation de Windows Defender...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

echo [10/12] Desactivation de l'isolation du noyau...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f

echo [11/12] Desactivation de la liste noire des pilotes...
powershell -Command "Set-MpPreference -EnableBlockAtFirstSeen $false"

echo [12/12] Optimisation des performances...
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg /changename 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c "Performance"

echo.
echo ========================================
echo    TOUTES LES CORRECTIONS TERMINEES !
echo ========================================
echo.
echo Les corrections suivantes ont ete appliquees :
echo - Verification de l'integrite du systeme
echo - Nettoyage des fichiers temporaires
echo - Reparation du disque dur
echo - Nettoyage du registre
echo - Redemarrage des services Windows
echo - Optimisation de la memoire virtuelle
echo - Desactivation de Windows Defender
echo - Desactivation de l'isolation du noyau
echo - Desactivation de la liste noire des pilotes
echo - Optimisation des performances
echo.
echo Un redemarrage est NECESSAIRE pour appliquer
echo completement toutes les corrections.
echo.
pause
