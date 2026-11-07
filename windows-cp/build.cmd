@echo off
rem Builds CageCredentialProvider.dll and the core unit tests with the installed MSVC Build Tools (x64).
setlocal
set VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" (echo MSVC Build Tools not found & exit /b 1)
call "%VCVARS%" >nul || exit /b 1
cd /d "%~dp0"
if not exist out mkdir out
set CFLAGS=/nologo /std:c++17 /EHsc /O2 /W4 /WX /sdl /guard:cf /Qspectre /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN
cl %CFLAGS% /Fo:out\ /Fe:out\core_test.exe tests\core_test.cpp src\core.cpp ole32.lib /link /DYNAMICBASE /NXCOMPAT || exit /b 1
cl %CFLAGS% /LD /Fo:out\ /Fe:out\CageCredentialProvider.dll src\core.cpp src\provider.cpp src\dll.cpp ^
   ole32.lib shlwapi.lib /link /DEF:src\dll.def /DYNAMICBASE /NXCOMPAT /GUARD:CF || exit /b 1
cl /nologo /std:c++17 /EHsc /W4 /WX /DUNICODE /D_UNICODE /Fo:out\ /Fe:out\provider_harness.exe tests\provider_harness.cpp ole32.lib advapi32.lib || exit /b 1
out\core_test.exe >nul || (echo core tests FAILED & exit /b 1)
out\provider_harness.exe >nul || (echo provider harness FAILED & exit /b 1)
echo Built out\CageCredentialProvider.dll; core tests and provider harness passed
