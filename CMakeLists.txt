# =====================================================================================
# PROJECT CYRUS — Next-Gen C++ LLM Security Firewall & Guardrail Engine
# CMake Build Configuration File
# 
# 🎓 INTERVIEW PREP: CMAKE & MODERN C++ BUILD SYSTEM BEST PRACTICES
# - CMake is a cross-platform meta-build generator creating Native Makefiles, Visual Studio
#   solutions (.sln), or Ninja build files.
# - Target-based CMake (`target_include_directories`, `target_compile_features`) is preferred
#   over global directory commands (`include_directories`).
# =====================================================================================

cmake_minimum_required(VERSION 3.14)
project(CYRUS_LLM_FIREWALL VERSION 1.0.0 LANGUAGES CXX)

# Require C++17 Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler Warnings Optimization
if(MSVC)
    add_compile_options(/W4 /EHsc /O2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O3)
endif()

# Include Headers Directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Define Source Files
set(CYRUS_SOURCES
    src/CyrusEngine.cpp
    src/main.cpp
)

# Define Main Executable Target
add_executable(cyrus_backend ${CYRUS_SOURCES})

# Target Include Directories
target_include_directories(cyrus_backend PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

message(STATUS "CYRUS C++ Firewall configured successfully. C++ Standard: ${CMAKE_CXX_STANDARD}")
