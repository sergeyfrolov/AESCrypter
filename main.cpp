// Copyright 2015 Sergey Frolov. All rights reserved.
// Use of this source code is governed by a LGPL license that can be
// found in the LICENSE file.

#include <iostream>

#include "crypter.h"

int main() {
    // Just an example of usage
    string seed = "It is a good idea to generate a strong key and iv, instead of cryptographic seed like that.";
    AESCrypter Crypt(seed.data(), seed.size());

    string plain_text("The Advanced Encryption Standard (AES), also known as Rijndael (its original name), "
             "is a specification for the encryption of electronic data established by the U.S. National Institute of "
             "Standards and Technology (NIST) in 2001. AES is based on the Rijndael cipher developed by two Belgian "
             "cryptographers, Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES"
             "selection process. Rijndael is a family of ciphers with different key and block sizes.");
    string crypted_text, decrypted_text;

    std::cout << "Original text: " << plain_text << std::endl;

    crypted_text = Crypt.encrypt(plain_text);
    std::cout << "Encrypted text: " << crypted_text << std::endl;

    decrypted_text = Crypt.decrypt(crypted_text);
    std::cout << "Decrypted text: " << decrypted_text << std::endl;

    if (plain_text == decrypted_text) {
        std::cout << "Decrypted text is the same, as original." << std::endl;
        return 0;
    }
    else {
        std::cerr << "Error! Decrypted text is NOT the same, as original." << std::endl;
        return -1;
    }
}