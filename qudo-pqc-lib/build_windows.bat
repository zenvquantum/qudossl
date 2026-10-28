@echo off
setlocal enabledelayedexpansion
REM QUDO PQC Crypto Library — Windows Build Script
REM Builds libqudo-pqc (ML-KEM, ML-DSA, SLH-DSA)
REM
REM Usage:
REM   build_windows.bat              - Standard MSVC build
REM   build_windows.bat --fips       - FIPS 140-3 module build
REM   build_windows.bat --mingw      - Build with MinGW
REM   build_windows.bat --test       - Build and run tests
REM   build_windows.bat --check      - Diagnostic mode (check toolchain)
REM   build_windows.bat -c, --clean  - Remove all build directories (no rebuild)
REM   build_windows.bat --fips --test - FIPS build + run tests

echo ======================================
echo QUDO PQC Crypto Library — Windows Build
echo ======================================
echo.

REM Parse arguments
set "FIPS_BUILD=0"
set "RUN_TESTS=0"
set "BUILD_ACVP=0"
set "USE_MINGW=0"
set "DIAGNOSTIC=0"
set "CLEAN=0"

REM Flags match build.sh. MinGW is selected with --mingw only (-m is
REM MemorySanitizer in build.sh). -f/--force is accepted; the Windows build
REM always cleans first.
:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="--fips"  ( set "FIPS_BUILD=1" & shift & goto :parse_args )
if /i "%~1"=="-F"      ( set "FIPS_BUILD=1" & shift & goto :parse_args )
if /i "%~1"=="--test"  ( set "RUN_TESTS=1"  & shift & goto :parse_args )
if /i "%~1"=="-t"      ( set "RUN_TESTS=1"  & shift & goto :parse_args )
if /i "%~1"=="--mingw" ( set "USE_MINGW=1"  & shift & goto :parse_args )
if /i "%~1"=="--acvp"  ( set "BUILD_ACVP=1" & shift & goto :parse_args )
if /i "%~1"=="--check" ( set "DIAGNOSTIC=1" & shift & goto :parse_args )
if /i "%~1"=="--clean" ( set "CLEAN=1"      & shift & goto :parse_args )
if /i "%~1"=="-c"      ( set "CLEAN=1"      & shift & goto :parse_args )
if /i "%~1"=="--force" ( shift & goto :parse_args )
if /i "%~1"=="-f"      ( shift & goto :parse_args )
if /i "%~1"=="--help"  goto :show_help
if /i "%~1"=="-h"      goto :show_help
echo Unknown option: %~1
echo Run 'build_windows.bat --help' for options.
exit /b 1
:done_args

if "%CLEAN%"=="1" goto :clean
if "%DIAGNOSTIC%"=="1" goto :diagnostic
if "%USE_MINGW%"=="1" goto :use_mingw

REM ====================================================================== REM
REM  MSVC Detection                                                         REM
REM ====================================================================== REM

REM Check if cl.exe is already in PATH (Developer Command Prompt)
where cl.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found MSVC compiler in PATH
    set "COMPILER=MSVC"
    set "GENERATOR=NMake Makefiles"
    goto :build_msvc
)

REM Try vswhere (VS 2017+)
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
            echo Found Visual Studio via vswhere
            call "%%i\VC\Auxiliary\Build\vcvars64.bat"
            set "COMPILER=MSVC"
            set "GENERATOR=NMake Makefiles"
            goto :build_msvc
        )
    )
)

REM Try standard VS 2022 paths
for %%E in (Community Professional Enterprise) do (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        echo Found Visual Studio 2022 %%E
        call "C:\Program Files\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
        set "COMPILER=MSVC"
        set "GENERATOR=NMake Makefiles"
        goto :build_msvc
    )
)

REM Try VS 2022 Build Tools
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    echo Found Visual Studio Build Tools 2022
    call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    set "COMPILER=MSVC"
    set "GENERATOR=NMake Makefiles"
    goto :build_msvc
)

REM Try VS 2019
for %%E in (Community Professional Enterprise) do (
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        echo Found Visual Studio 2019 %%E
        call "C:\Program Files (x86)\Microsoft Visual Studio\2019\%%E\VC\Auxiliary\Build\vcvars64.bat"
        set "COMPILER=MSVC"
        set "GENERATOR=NMake Makefiles"
        goto :build_msvc
    )
)

echo.
echo MSVC not found. Use --mingw for MinGW build, or --check for diagnostics.
exit /b 1

REM ====================================================================== REM
REM  MSVC Build                                                             REM
REM ====================================================================== REM

:build_msvc
cd /d "%~dp0"
echo.
echo Compiler: Microsoft Visual C++ (MSVC)
echo.

REM Check for CMake
where cmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found. Download from: https://cmake.org/download/
    exit /b 1
)

REM Select build directory
if "%FIPS_BUILD%"=="1" (
    set "BUILD_DIR=build-fips"
    echo Build mode: FIPS 140-3 Module
) else (
    set "BUILD_DIR=build"
    echo Build mode: Standard
)

REM Clean build directory
if exist %BUILD_DIR% (
    echo Cleaning %BUILD_DIR%...
    rmdir /s /q %BUILD_DIR%
)
mkdir %BUILD_DIR%

REM Configure cmake options
set "CMAKE_OPTS=-DCMAKE_BUILD_TYPE=Release"

if "%FIPS_BUILD%"=="1" (
    set "CMAKE_OPTS=%CMAKE_OPTS% -DQUDO_FIPS_MODULE=ON"
)

if "%RUN_TESTS%"=="1" (
    set "CMAKE_OPTS=%CMAKE_OPTS% -DQUDO_PQC_BUILD_TESTS=ON"
) else (
    set "CMAKE_OPTS=%CMAKE_OPTS% -DQUDO_PQC_BUILD_TESTS=OFF"
)

if "%BUILD_ACVP%"=="1" (
    set "CMAKE_OPTS=%CMAKE_OPTS% -DBUILD_ACVP=ON"
)

REM OpenSSL is not required: libqudo-pqc uses internal crypto
REM (QUDO_PQC_USE_OPENSSL=OFF). RNG uses BCryptGenRandom on Windows.
echo.

REM Configure
echo Configuring with CMake...
cmake -S . -B %BUILD_DIR% -G "%GENERATOR%" %CMAKE_OPTS%
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed
    exit /b 1
)

REM Build
echo.
echo Building...
cmake --build %BUILD_DIR% --config Release
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo Build completed successfully.
echo   Library: %BUILD_DIR%\lib\qudo-pqc.dll
echo   Static:  %BUILD_DIR%\lib\qudo-pqc.lib

REM FIPS: generate qudofipsmodule.cnf (HMAC-SHA-256 of qudo-pqc.dll).
REM Windows uses the external-cnf integrity path; the embedded HMAC is
REM supported only on ELF/Mach-O.
REM
REM Inside parenthesized blocks %VAR% expands at parse time, so ERRORLEVEL
REM is read via !ERRORLEVEL! (delayed expansion).

if "%FIPS_BUILD%"=="1" (
    if exist "%BUILD_DIR%\tools\qudo_fipsinstall.exe" (
        echo.
        echo Generating FIPS integrity config ^(qudofipsmodule.cnf^)...
        "%BUILD_DIR%\tools\qudo_fipsinstall.exe" -module "%CD%\%BUILD_DIR%\lib\qudo-pqc.dll" -out "%CD%\%BUILD_DIR%\qudofipsmodule.cnf"
        if !ERRORLEVEL! NEQ 0 (
            echo ERROR: fipsinstall -out failed
            exit /b 1
        )
    )
)

REM Run tests if requested
if "%RUN_TESTS%"=="1" (
    echo.
    echo ======================================
    echo   Running Tests
    echo ======================================
    echo.
    REM Prepend build\lib to PATH so tests can load qudo-pqc.dll at runtime
    REM (Windows searches the exe's directory and PATH, not the cwd).
    set "PATH=%CD%\%BUILD_DIR%\lib;%PATH%"
    REM FIPS: no env vars. The cnf path is passed to each test binary as
    REM --fips-cnf <path> via CMake's add_test (QUDO_TEST_FIPS_ARGS).
    cd %BUILD_DIR%
    ctest --output-on-failure -C Release
    if !ERRORLEVEL! NEQ 0 (
        echo.
        echo TESTS FAILED
        cd /d "%~dp0"
        exit /b 1
    )
    cd /d "%~dp0"
    echo.
    echo All tests passed.
)

echo.
echo Done.
goto :end

REM ====================================================================== REM
REM  MinGW Build                                                            REM
REM ====================================================================== REM

:use_mingw
set "MSYS2_ROOT="
REM Prefer MSYS2_LOCATION set by msys2/setup-msys2 GitHub Action.
if defined MSYS2_LOCATION (
    if exist "%MSYS2_LOCATION%\mingw64\bin\gcc.exe" set "MSYS2_ROOT=%MSYS2_LOCATION%"
)
if not defined MSYS2_ROOT (
    if exist "%RUNNER_TEMP%\msys64\mingw64\bin\gcc.exe" set "MSYS2_ROOT=%RUNNER_TEMP%\msys64"
)
if not defined MSYS2_ROOT (
    if exist "C:\msys64\mingw64\bin\gcc.exe" set "MSYS2_ROOT=C:\msys64"
)
if not defined MSYS2_ROOT (
    if exist "C:\msys2\mingw64\bin\gcc.exe" set "MSYS2_ROOT=C:\msys2"
)
if not defined MSYS2_ROOT (
    echo.
    echo ERROR: MSYS2 MinGW not found!
    echo Install from: https://www.msys2.org/
    echo Then run: pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake
    exit /b 1
)

echo Found MSYS2 at: %MSYS2_ROOT%
echo.

REM Select build directory
if "%FIPS_BUILD%"=="1" (
    set "BUILD_DIR=build-fips"
    set "FIPS_OPT=-DQUDO_FIPS_MODULE=ON"
) else (
    set "BUILD_DIR=build"
    set "FIPS_OPT="
)

set "TEST_OPT="
if "%RUN_TESTS%"=="1" (
    set "TEST_OPT=-DQUDO_PQC_BUILD_TESTS=ON"
)

echo Building with MinGW...
call %MSYS2_ROOT%\msys2_shell.cmd -defterm -here -no-start -mingw64 -c "rm -rf %BUILD_DIR% && mkdir %BUILD_DIR% && cd %BUILD_DIR% && cmake -G 'MinGW Makefiles' -DCMAKE_PREFIX_PATH=/mingw64 -DCMAKE_BUILD_TYPE=Release %FIPS_OPT% %TEST_OPT% .. && mingw32-make -j4"

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    exit /b 1
)

REM FIPS: generate qudofipsmodule.cnf (cnf-mode integrity, see MSVC section).
if "%FIPS_BUILD%"=="1" (
    echo.
    echo Generating FIPS integrity config ^(qudofipsmodule.cnf^)...
    call %MSYS2_ROOT%\msys2_shell.cmd -defterm -here -no-start -mingw64 -c "cd %BUILD_DIR% && if [ -x tools/qudo_fipsinstall.exe ]; then tools/qudo_fipsinstall.exe -module \"$PWD/lib/libqudo-pqc.dll\" -out \"$PWD/qudofipsmodule.cnf\"; fi"
    if !ERRORLEVEL! NEQ 0 (
        echo ERROR: fipsinstall -out failed
        exit /b 1
    )
)

if "%RUN_TESTS%"=="1" (
    echo.
    echo Running tests...
    REM Prepend build/lib to PATH so tests can load libqudo-pqc.dll at runtime.
    REM No env vars for FIPS — the cnf path is passed to each test binary
    REM as --fips-cnf <path> via CMake's add_test (QUDO_TEST_FIPS_ARGS).
    if "%FIPS_BUILD%"=="1" (
        call %MSYS2_ROOT%\msys2_shell.cmd -defterm -here -no-start -mingw64 -c "cd %BUILD_DIR% && export PATH=\"$PWD/lib:$PATH\" && ctest --output-on-failure"
    ) else (
        call %MSYS2_ROOT%\msys2_shell.cmd -defterm -here -no-start -mingw64 -c "cd %BUILD_DIR% && export PATH=\"$PWD/lib:$PATH\" && ctest --output-on-failure"
    )
    if !ERRORLEVEL! NEQ 0 (
        echo.
        echo TESTS FAILED
        exit /b 1
    )
)

echo.
echo Build completed successfully.
echo   Library: %BUILD_DIR%\lib\libqudo-pqc.dll
goto :end

REM ====================================================================== REM
REM  Clean (-c, --clean): remove all build directories and exit             REM
REM ====================================================================== REM

:clean
cd /d "%~dp0"
echo Removing all build directories...
if exist "build" (
    echo   Removing build\
    rmdir /s /q "build"
)
for /d %%D in (build-* coverage-report* scan-report*) do (
    echo   Removing %%D\
    rmdir /s /q "%%D"
)
echo Clean complete.
goto :end

REM ====================================================================== REM
REM  Diagnostic Mode                                                        REM
REM ====================================================================== REM

:diagnostic
echo.
echo ========================================
echo   Toolchain Diagnostic Check
echo ========================================
echo.

REM Check MSVC
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    echo [OK] Visual Studio Installer found
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do (
        echo [OK] Visual Studio: %%i
    )
) else (
    echo [MISSING] Visual Studio Installer
)
echo.

where cl.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] MSVC compiler: & where cl.exe
) else (
    echo [MISSING] MSVC compiler cl.exe
)
echo.

where cmake.exe >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] CMake: & where cmake.exe
) else (
    echo [MISSING] CMake — download from https://cmake.org/download/
)
echo.

if exist "C:\msys64\mingw64\bin\gcc.exe" (
    echo [OK] MinGW GCC: C:\msys64\mingw64\bin\gcc.exe
) else (
    echo [OPTIONAL] MinGW not found — install MSYS2 for alternative
)
echo.

REM Check OpenSSL
if exist "C:\Program Files\OpenSSL-Win64\include\openssl\ssl.h" (
    echo [OK] OpenSSL: C:\Program Files\OpenSSL-Win64
) else if exist "C:\OpenSSL-Win64\include\openssl\ssl.h" (
    echo [OK] OpenSSL: C:\OpenSSL-Win64
) else (
    echo [OPTIONAL] Windows OpenSSL not found — BCryptGenRandom will be used
)
echo.

echo ========================================
goto :end

REM ====================================================================== REM
REM  Help                                                                   REM
REM ====================================================================== REM

:show_help
echo Usage: build_windows.bat [OPTIONS]
echo.
echo Options:
echo   --fips, -F     Build as FIPS 140-3 module
echo   --test, -t     Build and run tests
echo   --mingw        Use MinGW instead of MSVC
echo   --acvp         Build ACVP test runner binaries
echo   --check        Diagnostic mode (check toolchain)
echo   --clean, -c    Remove all build directories and exit
echo   --force, -f    Clean rebuild (Windows builds always start clean)
echo   --help, -h     Show this help
echo.
echo Examples:
echo   build_windows.bat                  Standard MSVC build
echo   build_windows.bat --fips --test    FIPS build + run tests
echo   build_windows.bat --mingw          MinGW build
goto :end

:end
