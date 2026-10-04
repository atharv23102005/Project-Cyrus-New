@echo off
echo ====================================================================
echo 🛡️ Building CYRUS C++ Security Engine & REST Backend...
echo ====================================================================

if not exist bin mkdir bin

echo Compiling C++ files with g++...
g++ -std=c++17 -O3 CyrusEngine.cpp main.cpp -o cyrus_backend.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Build Successful! Executable created at cyrus_backend.exe
    echo Running CYRUS CLI Test...
    echo.
    cyrus_backend.exe
) else (
    echo.
    echo ❌ Build failed. Please ensure g++, clang++, or MSVC cl is installed.
)
pause
