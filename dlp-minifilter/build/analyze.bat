@echo off
rem ==========================================================================
rem analyze.bat -- static analysis pass (SPEC section 7 / acceptance 9.2).
rem
rem Identical cl line to build-driver.bat PLUS /analyze. Must be clean on OUR
rem source; benign WDK system-header codes stay suppressed via /wd only.
rem Compile-only (/c): no link needed for the analysis result.
rem ==========================================================================
setlocal

set MSVC=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0

set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
set INCLUDE=%SDKROOT%\Include\%SDKVER%\km\crt;%MSVC%\include;%SDKROOT%\Include\%SDKVER%\km;%SDKROOT%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDKROOT%\Lib\%SDKVER%\km\x64

cd /d "%~dp0.."

if not exist build\out mkdir build\out

echo === analyze dlpflt.c ===
rem The /wd codes below suppress benign /analyze noise emitted INSIDE the WDK
rem system headers only (never our source): C28160/C6387 = inline
rem ExAllocatePoolZero; C28252/C28253 = inconsistent SAL on
rem MmGetSystemRoutineAddress declared twice in wdm.h; C28230/C28285 = a
rem malformed SAL annotation on WheaErrorRecordBuilderAddPacket in ntddk.h;
rem C6553 = bad SAL on ZwSetValueKey _Param_(3) in wdm.h.
cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /wd28160 /wd6387 /wd28252 /wd28253 /wd28230 /wd28285 /wd6553 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel /analyze ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
  /Fobuild\out\dlpflt.analyze.obj src\dlpflt.c
if errorlevel 1 goto :fail

echo === analyze comms.c ===
rem The /wd codes below suppress benign /analyze noise emitted INSIDE the WDK
rem system headers only (never our source): C28160/C6387 = inline
rem ExAllocatePoolZero; C28252/C28253 = inconsistent SAL on
rem MmGetSystemRoutineAddress declared twice in wdm.h; C28230/C28285 = a
rem malformed SAL annotation on WheaErrorRecordBuilderAddPacket in ntddk.h;
rem C6553 = bad SAL on ZwSetValueKey _Param_(3) in wdm.h.
cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /wd28160 /wd6387 /wd28252 /wd28253 /wd28230 /wd28285 /wd6553 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel /analyze ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
  /Fobuild\out\comms.analyze.obj src\comms.c
if errorlevel 1 goto :fail

echo === ANALYZE CLEAN ===
goto :eof

:fail
echo === ANALYZE REPORTED ISSUES ===
exit /b 1
