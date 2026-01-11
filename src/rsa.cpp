#include <crypto/rsa.hpp>
#include <sstream>
#include <algorithm>

static crypto::bn::bignum gcd(const crypto::bn::bignum& e, const crypto::bn::bignum& phi_n)
{
    size_t res { std::min(e, phi_n) };
    while (res > 1) {
        if (e % res == 0 && phi_n % res == 0)
            break;
        res--;
    }
    return res;
}

static crypto::bn::bignum inverse(crypto::bn::bignum e, const crypto::bn::bignum& module)
{
    crypto::bn::bignum t;
    crypto::bn::bignum r { module };
    crypto::bn::bignum new_t { 1 };
    crypto::bn::bignum new_r { e };

    while (new_r != 0)
    {
        crypto::bn::bignum quotient { r / new_r };

        crypto::bn::bignum tmp_t { t };
        t = new_t;
        new_t = tmp_t - quotient * new_t;

        crypto::bn::bignum tmp_r { r };
        r = new_r;
        new_r = tmp_r - quotient * new_r;
    }

    if (r > 1)
        return 0;
    if (t < 0)
        t += module;

    return t;
}

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
        bn::bignum d { inverse(e, phi_n) };
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
