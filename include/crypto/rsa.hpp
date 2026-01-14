#pragma once

#include <string>
#include "bignum.hpp"

namespace crypto::rsa
{
    struct public_key
    {
        bn::bignum module;
        bn::bignum enc_exp;
        bool valid;
    };

    struct private_key
    {
        bn::bignum module;
        bn::bignum dec_exp;
        bool valid;
    };

    struct keys
    {
        public_key pub_key;
        private_key pri_key;
    };

    keys generate_keys(const bn::bignum& prime_p, const bn::bignum& prime_q, const bn::bignum& e = 65537);

    std::vector<uint8_t> encrypt_message(const public_key& pub_key, const std::string& plain_text, const std::string& label = "");
    std::string decrypt_message(const private_key& pri_key, const std::vector<uint8_t>& chiper_text, const std::string& label = "");
}
