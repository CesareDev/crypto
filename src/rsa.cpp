#include <crypto/rsa.hpp>
#include <sstream>
#include <algorithm>

static crypto::bn::bignum string_to_bignum(const std::string& s)
{
    crypto::bn::bignum result;
    for (auto c : s)
        result = result * 256 + c;
    return result;
}

static std::string bignum_to_string(const crypto::bn::bignum& n)
{
    std::string result;
    size_t size_bytes { (n.bit_count() + 7) / 8 } ;
    for (size_t i {}; i < size_bytes; ++i)
    {
        char c = (int)((n >> (i * 8)) & 0xFF);
        result.push_back(c);
    }
    std::reverse(result.begin(), result.end());
    return result;
}

namespace crypto::rsa
{
    Keys GenerateKey(const bn::bignum& prime_p, const bn::bignum& prime_q, const bn::bignum& e)
    {
        Keys keys;
        bn::bignum n { prime_p * prime_q };
        bn::bignum phi_n { (prime_p - 1) * (prime_q - 1) };
        if (gcd(e, phi_n) != 1)
        {
            keys.valid = false;
            return keys;
        }
        bn::bignum d { bn::inverse_mod(e, phi_n) };
        if (d == 0)
        {
            keys.valid = false;
            return keys;
        }
        keys.public_key.module = n;
        keys.public_key.enc_exp = e;
        keys.private_key.module = n;
        keys.private_key.dec_exp = d;
        keys.valid = true;
        return keys;
    }

    std::string EncryptMessage(const PublicKey& public_key, const std::string& plain_text)
    {
        std::ostringstream res;
        bn::bignum input = string_to_bignum(plain_text);
        if (input > public_key.module)
            return res.str();
        bn::bignum enc = bn::exp_mod(input, public_key.enc_exp, public_key.module);
        res << enc;
        return res.str();
    }

    std::string DecryptMessage(const PrivateKey& private_key, const std::string& chiper_text)
    {
        bn::bignum input(chiper_text, 10);
        bn::bignum dec = bn::exp_mod(input, private_key.dec_exp, private_key.module);
        std::string dec_s = bignum_to_string(dec);
        std::ostringstream res;
        res << dec_s;
        return res.str();
    }
}
