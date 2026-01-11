#pragma once

#include <string>
#include "bignum.hpp"

namespace crypto::rsa
{
    struct PublicKey
    {
        bn::bignum module;
        bn::bignum enc_exp;
        bool valid;
    };

    struct PrivateKey
    {
        bn::bignum module;
        bn::bignum dec_exp;
        bool valid;
    };

    struct Keys
    {
        PublicKey public_key;
        PrivateKey private_key;
        bool valid;
    };

    Keys GenerateKey(const bn::bignum& prime_p, const bn::bignum& prime_q, const bn::bignum& e = 65537);

    std::string EncryptMessage(const PublicKey& public_key, const std::string& plain_text);
    std::string DecryptMessage(const PrivateKey& private_key, const std::string& chiper_text);
}
