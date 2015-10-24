// Copyright 2015 Sergey Frolov. All rights reserved.
// Use of this source code is governed by a LGPL license that can be
// found in the LICENSE file.

#ifndef DFS_SSL_CRYPTER_H
#define DFS_SSL_CRYPTER_H

#include <string>
#include <openssl/evp.h>

using std::string;

class AESCrypter {
private:
    unsigned char key[32];
    unsigned char iv[32];
    EVP_CIPHER_CTX encrypt_ctx;
    EVP_CIPHER_CTX decrypt_ctx;

    void construct();

public:
    AESCrypter(const char *seed, int num);
    AESCrypter(unsigned char input_key[32], unsigned char input_iv[32]);

    string encrypt(const string &input);
    string decrypt(const string &input);

    unsigned char *encrypt(const unsigned char *input, const int *input_len, int *output_len);
    unsigned char *decrypt(const unsigned char *input, const int *input_len, int *output_len);

    ~AESCrypter();
};

#endif //DFS_SSL_CRYPTER_H
