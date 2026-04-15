#pragma once

#include "bignum.hpp"

namespace crypto::dh
{
    bn::bignum generate_shared(const bn::bignum& a, const bn::bignum& p, const bn::bignum& g = 2);
    bn::bignum generate_key(const bn::bignum& a, const bn::bignum& b);
}
