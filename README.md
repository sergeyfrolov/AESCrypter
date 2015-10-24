# AESCrypter
Small class for encryption and decryption of strings in C++ using OpenSSL
## Building
You will have to link it against OpenSSL libraries(libssl and libcrypto),
either by yourself or let CMake handle that.
## Usage
AESCrypter has encrypt() and decrypt() functions for string and uchar.
Initialize AESCrypter it with uchar arrays 'key' and 'iv' or with provide
some random chars to generate those for you.

