cmake_minimum_required(VERSION 3.3)
project(AESCrypter)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
list(APPEND LIB_LIST ${OPENSSL_LIBRARIES})
list(APPEND LIB_LIST ${OPENSSL_ROOT_DIR}/lib/)

set(SOURCE_FILES main.cpp crypter.cpp crypter.h)
add_executable(aescrypter ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(aescrypter ssl)
TARGET_LINK_LIBRARIES(aescrypter crypto)
