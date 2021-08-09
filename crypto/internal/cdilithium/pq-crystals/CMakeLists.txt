cmake_minimum_required(VERSION 3.10)

project(dilithium C ASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

enable_testing()

#find_package(OpenSSL REQUIRED)
#include_directories(${OPENSSL_INCLUDE_DIR})

add_subdirectory(ref)
#add_subdirectory(avx2)
