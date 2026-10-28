@echo off
REM Build script for Windows

echo ======================================
echo ML-DSA Post-Quantum Signature Build
echo ======================================
echo.

REM Check for Visual Studio
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Visual Studio C++ compiler not found
    echo Please run this from "Developer Command Prompt for VS"
    exit /b 1
)

REM Check for CMake
where cmake.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake not found
    echo Please install CMake from https://cmake.org/download/
    exit /b 1
)

echo Platform: Windows
echo.

REM Build configuration
set BUILD_TYPE=Release
set BUILD_DIR=build

echo Build configuration:
echo   Type: %BUILD_TYPE%
echo   Directory: %BUILD_DIR%
echo.

REM Create build directory
echo Creating build directory...
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
mkdir %BUILD_DIR%
cd %BUILD_DIR%

REM Configure with CMake
echo.
echo Configuring with CMake...
cmake .. ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DBUILD_SHARED_LIBS=ON ^
    -DBUILD_EXAMPLES=ON ^
    -DBUILD_TESTS=ON

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: CMake configuration failed
    cd ..
    exit /b 1
)

REM Build
echo.
echo Building...
cmake --build . --config %BUILD_TYPE% -j 4

if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Build failed
    cd ..
    exit /b 1
)

echo.
echo ======================================
echo Build completed successfully!
echo ======================================
echo.
echo To install:
echo   cd %BUILD_DIR% ^&^& cmake --install .
echo.
echo To run tests:
echo   cd %BUILD_DIR% ^&^& ctest -C %BUILD_TYPE%
echo.
echo To run examples:
echo   cd %BUILD_DIR%\examples\%BUILD_TYPE%
echo   speed_mldsa.exe
echo.

cd ..
