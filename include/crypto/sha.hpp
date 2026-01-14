#pragma once

#include <crypto/bignum.hpp>
#include <string>

namespace crypto::sha
{
    enum class algorithm
    {
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512
    };

    bn::bignum hash_string(const std::string& msg, algorithm algorithm = algorithm::Sha1);
    bn::bignum hash_file(const std::string& filename, algorithm algorithm = algorithm::Sha1);
}
