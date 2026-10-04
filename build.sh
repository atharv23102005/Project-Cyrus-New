#!/bin/bash
echo "===================================================================="
echo "🛡️ Building CYRUS C++ Security Engine & REST Backend..."
echo "===================================================================="

mkdir -p bin
g++ -std=c++17 -O3 CyrusEngine.cpp main.cpp -o cyrus_backend

if [ $? -eq 0 ]; then
    echo -e "\n✅ Build Successful! Executable created at cyrus_backend"
    echo "Running CYRUS CLI Test..."
    echo ""
    ./cyrus_backend
else
    echo -e "\n❌ Build failed. Please check compiler flags."
fi
