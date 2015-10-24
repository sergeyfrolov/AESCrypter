// Copyright 2015 Sergey Frolov. All rights reserved.
// Use of this source code is governed by a LGPL license that can be
// found in the LICENSE file.

#include "crypter.h"

#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/conf.h>

#include <random>

AESCrypter::AESCrypter(unsigned char input_key[32], unsigned char input_iv[32]) {
    for (int i = 0; i < 32; i++) {
        key[i] = input_key[i];
    }
    for (int i = 0; i < 32; i++) {
        iv[i] = input_iv[i];
    }
    construct();
}

AESCrypter::AESCrypter(const char *seed, int num) {
    std::seed_seq seq_seed(seed, seed + num);

    std::default_random_engine rng(seq_seed);
    std::uniform_int_distribution<int> rng_dist(0, 255);
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<unsigned char>(rng_dist(rng));
    }
    for (int i = 0; i < 32; i++) {
        iv[i] = static_cast<unsigned char>(rng_dist(rng));
    }
    construct();
}

void AESCrypter::construct() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    if (!EVP_EncryptInit(&encrypt_ctx, EVP_aes_256_cbc(), key, iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("AEScrypter: &encrypt_ctx EVP_EncryptInit failed!");
    }

    if (!EVP_DecryptInit(&decrypt_ctx, EVP_aes_256_cbc(), key, iv)) {
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("AEScrypter: &decrypt_ctx EVP_DecryptInit failed!");
    }
}


string AESCrypter::encrypt(const string &input) {
    int output_size;
    int input_size = input.size();
    unsigned char *output_uchar;
    unsigned char *input_uchar_ptr = (unsigned char *) (input.data());

    output_uchar = AESCrypter::encrypt(input_uchar_ptr, &(input_size), &(output_size));

    string output(output_uchar, output_uchar + output_size);
    return output;
}

string AESCrypter::decrypt(const string &input) {
    int output_size;
    int input_size = input.size();
    unsigned char *output_uchar;
    unsigned char *input_uchar_ptr = (unsigned char *) (input.data());

    output_uchar = AESCrypter::decrypt(input_uchar_ptr, &(input_size), &(output_size));

    string output(output_uchar, output_uchar + output_size);
    return output;
}

unsigned char *AESCrypter::encrypt(const unsigned char *input, const int *input_len, int *output_len) {
    int encrypted_text_len = 0;
    int encrypted_text_pad_len = 0;;

    unsigned char *encrypted_text;
    encrypted_text = new unsigned char[*input_len + AES_BLOCK_SIZE];
    memset(encrypted_text, 0, *input_len + AES_BLOCK_SIZE);

    if (!EVP_EncryptUpdate(&encrypt_ctx, encrypted_text, &encrypted_text_len, input, *input_len)) {
        ERR_print_errors_fp(stderr);
        delete[] encrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherUpdate() failed!");
    }

    if (!EVP_EncryptFinal_ex(&encrypt_ctx, encrypted_text + encrypted_text_len, &encrypted_text_pad_len)) {
        ERR_print_errors_fp(stderr);
        delete[] encrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherFinal_ex() failed!");
    }

    if (output_len != nullptr)
        *output_len = encrypted_text_len + encrypted_text_pad_len;
    else
        throw std::runtime_error("AESCrypter: crypt(): output_len is nullptr!");

    return encrypted_text;
}

unsigned char *AESCrypter::decrypt(const unsigned char *input, const int *input_len, int *output_len) {
    int decrypted_text_len = 0;
    int decrypted_text_pad_len = 0;;

    unsigned char *decrypted_text;
    decrypted_text = new unsigned char[*input_len];
    memset(decrypted_text, 0, *input_len);

    if (!EVP_DecryptUpdate(&decrypt_ctx, decrypted_text, &decrypted_text_len, input, *input_len)) {
        ERR_print_errors_fp(stderr);
        delete[] decrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherUpdate() failed!");
    }

    if (!EVP_DecryptFinal_ex(&decrypt_ctx, decrypted_text + decrypted_text_len, &decrypted_text_pad_len)) {
        ERR_print_errors_fp(stderr);
        delete[] decrypted_text;
        throw std::runtime_error("AESCrypter: crypt(): EVP_CipherFinal_ex() failed!");
    }

    if (output_len != nullptr)
        *output_len = decrypted_text_len + decrypted_text_pad_len;
    else
        throw std::runtime_error("AESCrypter: crypt(): output_len is nullptr!");

    return decrypted_text;
}


AESCrypter::~AESCrypter() {
    EVP_CIPHER_CTX_cleanup(&encrypt_ctx);
    EVP_CIPHER_CTX_cleanup(&decrypt_ctx);
    EVP_cleanup();
    ERR_free_strings();
}
