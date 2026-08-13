@echo off
rem ==========================================================================
rem build-driver.bat -- compile + link dlpflt.sys (SPEC section 7).
rem
rem This is the PROVEN recipe: invoke cl + link directly (the VS WDK MSBuild
rem targets are NOT installed on this machine). It already produced a valid
rem .sys from the smoke driver; only the source/obj/output names change here.
rem
rem   km\crt FIRST in INCLUDE so the kernel CRT headers shadow MSVC's user-mode
rem   ones. /kernel auto-defines _KERNEL_MODE (never redefine it). /WX stays on;
rem   /wd4324 /wd4201 /wd4214 suppress benign WDK system-header warnings only.
rem ==========================================================================
setlocal

set MSVC=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%SDKROOT%\Include\%SDKVER%\km\crt;%MSVC%\include;%SDKROOT%\Include\%SDKVER%\km;%SDKROOT%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDKROOT%\Lib\%SDKVER%\km\x64

rem Build from the driver root (parent of this build\ dir) so src\*.c resolves.
cd /d "%~dp0.."

if not exist build\out mkdir build\out

echo === compile dlpflt.c ===
cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
  /Fobuild\out\dlpflt.obj src\dlpflt.c
if errorlevel 1 goto :fail

echo === compile comms.c ===
cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
  /Fobuild\out\comms.obj src\comms.c
if errorlevel 1 goto :fail

echo === compile wfpcallout.c ===
cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
  /Fobuild\out\wfpcallout.obj src\wfpcallout.c
if errorlevel 1 goto :fail

echo === link dlpflt.sys ===
link.exe /NOLOGO /OUT:build\out\dlpflt.sys /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry ^
  /NODEFAULTLIB /RELEASE /INTEGRITYCHECK /GUARD:CF ^
  build\out\dlpflt.obj build\out\comms.obj build\out\wfpcallout.obj ^
  fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib fwpkclnt.lib ndis.lib BufferOverflowFastFailK.lib
if errorlevel 1 goto :fail

echo === SUCCESS ===
dir build\out\dlpflt.sys
goto :eof

:fail
echo === BUILD FAILED ===
exit /b 1
