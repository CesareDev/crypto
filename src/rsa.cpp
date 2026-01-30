#include <crypto/hash.hpp>
#include <crypto/rsa.hpp>
#include <crypto/random.hpp>

static crypto::bn::bignum array_to_bignum(const std::vector<uint8_t>& arr)
{
    crypto::bn::bignum result;
    for (auto c : arr)
        result = result * 256 + c;
    return result;
}

// Big endian
static std::vector<uint8_t> bignum_to_array(const crypto::bn::bignum& n, uint64_t len)
{
    std::vector<uint8_t> result(len, 0);
    for (uint64_t i {}; i < result.size(); i++)
        result[i] = (int)((n >> ((result.size() - 1 - i) * 8)) & 0xFF);;
    return result;
}

// Big endian
static std::vector<uint8_t> i2osp(uint64_t n, uint64_t size)
{
    std::vector<uint8_t> tmp;
    tmp.resize(8);
    for (uint8_t i {}; i < tmp.size(); ++i)
        tmp[i] = (uint8_t)((n >> ((7 - i) * 8)) & 0xFF);
    return std::vector<uint8_t>(tmp.end() - size, tmp.end());
}

static std::vector<uint8_t> mgf1(const std::vector<uint8_t>& seed, uint64_t len)
{
    uint64_t h_len { 32 };
    std::vector<uint8_t> res;
    if (len > h_len * (1ULL << 32))
        // Error
        return {};
    std::vector<uint8_t> t;
    uint64_t counter {};
    while (t.size() < len)
    {
        std::vector<uint8_t> c { i2osp(counter, 4) };
        std::vector<uint8_t> spc;
        spc.resize(seed.size() + c.size());
        for (uint64_t i {}; i < spc.size(); ++i)
        {
            if (i < seed.size())
                spc[i] = (seed[i]);
            else
                spc[i] = c[i - seed.size()];
        }
        std::string input(spc.begin(), spc.end());
        std::vector<uint8_t> hash { crypto::hash::hash_string(input, crypto::hash::algorithm::SHA256).get_byte_array(true) };
        for (uint8_t byte : hash)
            t.push_back(byte);
        ++counter;
    }
    return std::vector<uint8_t>(t.begin(), t.begin() + len);
}

namespace crypto::rsa
{
    keys generate_keys(const bn::bignum& prime_p, const bn::bignum& prime_q, const bn::bignum& e)
    {
        keys k {};
        bn::bignum n { prime_p * prime_q };
        bn::bignum phi_n { (prime_p - 1) * (prime_q - 1) };
        if (bn::gcd(e, phi_n) != 1)
            return k;
        bn::bignum d { bn::inverse_mod(e, phi_n) };
        if (d == 0)
            return k;
        k.pub_key.module = n;
        k.pub_key.enc_exp = e;
        k.pub_key.valid = true;
        k.pri_key.module = n;
        k.pri_key.dec_exp = d;
        k.pri_key.valid = true;
        return k;
    }

    // www.rfc-editor.org/rfc/rfc3447#section-7.1.1
    std::vector<uint8_t> encrypt_message(const public_key& pub_key, const std::string& plain_text, const std::string& label)
    {
        if (!pub_key.valid)
            throw std::runtime_error("[RSA] Publick key non valid");

        std::vector<uint8_t> msg(plain_text.begin(), plain_text.end());
        std::vector<uint8_t> l_hash = crypto::hash::hash_string(label, hash::algorithm::SHA256).get_byte_array(true);

        uint64_t k { pub_key.module.byte_count() };
        uint64_t h_len { 32 };
        uint64_t m_len { msg.size() };
        int64_t ps_len = k - m_len - 2 * h_len - 2;

        if (ps_len < 0)
            throw std::runtime_error("[RSA] Encoding error (ps_len)");

        std::vector<uint8_t> ps(ps_len, 0);
        std::vector<uint8_t> db;

        for (uint8_t byte : l_hash)
            db.push_back(byte);
        for (uint8_t byte : ps)
            db.push_back(byte);
        db.push_back(0x01);
        for (uint8_t byte : msg)
            db.push_back(byte);

        std::vector<uint8_t> seed;
        seed.reserve(h_len);
        for (uint64_t i {}; i < h_len; ++i)
            seed.push_back(rng::u8());

        std::vector<uint8_t> db_mask { mgf1(seed, k - h_len - 1) };
        uint64_t masked_db_len = k - h_len - 1;
        std::vector<uint8_t> masked_db(masked_db_len);
        for (uint64_t i {}; i < masked_db_len; ++i)
            masked_db[i] = db[i] ^ db_mask[i];

        std::vector<uint8_t> seed_mask { mgf1(masked_db, h_len) };
        std::vector<uint8_t> masked_seed(h_len);
        for (uint64_t i {}; i < h_len; ++i)
            masked_seed[i] = seed[i] ^ seed_mask[i];

        std::vector<uint8_t> em;
        em.reserve(k);
        em.push_back(0x00);
        for (uint64_t i {}; i < masked_seed.size(); ++i)
            em.push_back(masked_seed[i]);
        for (uint64_t i {}; i < masked_db.size(); ++i)
            em.push_back(masked_db[i]);

        // Encryption
        bn::bignum m { array_to_bignum(em) };
        if (m >= pub_key.module)
            throw std::runtime_error("[RSA] Encoding error (em too long)");
        bn::bignum c { bn::exp_mod(m, pub_key.enc_exp, pub_key.module) };
        std::vector<uint8_t> C { bignum_to_array(c, k) };
        return C;
    }

    std::string decrypt_message(const private_key& pri_key, const std::vector<uint8_t>& chiper_text, const std::string& label)
    {
        uint64_t k { pri_key.module.byte_count() };
        if (chiper_text.size() != k)
            throw std::runtime_error("[RSA] Chiper text non valid");
        uint64_t h_len { 32 };
        if (!pri_key.valid)
            throw std::runtime_error("[RSA] Private key non valid");
        bn::bignum c { array_to_bignum(chiper_text) };
        bn::bignum m { bn::exp_mod(c, pri_key.dec_exp, pri_key.module) };
        std::vector<uint8_t> em { bignum_to_array(m, k) };
        std::vector<uint8_t> l_hash { hash::hash_string(label, hash::algorithm::SHA256).get_byte_array(true) };
        uint8_t y = em[0];
        if (y != 0x00)
            throw std::runtime_error("[RSA] Decoding error (y != 0x00)");
        std::vector<uint8_t> masked_seed(em.begin() + 1, em.begin() + 1 + h_len);
        std::vector<uint8_t> masked_db(em.begin() + 1 + h_len, em.end());
        std::vector<uint8_t> seed_mask { mgf1(masked_db, h_len) };
        std::vector<uint8_t> seed(h_len, 0);
        for (uint64_t i {}; i < h_len; ++i)
            seed[i] = masked_seed[i] ^ seed_mask[i];
        uint64_t db_len = k - h_len - 1;
        std::vector<uint8_t> db_mask { mgf1(seed, db_len) };
        std::vector<uint8_t> db(db_len, 0);
        for (uint64_t i {}; i < db_len; ++i)
            db[i] = masked_db[i] ^ db_mask[i];
        std::vector<uint8_t> l_hash1(db.begin(), db.begin() + h_len);
        if (l_hash != l_hash1)
            throw std::runtime_error("[RSA] Decoding error (l_hash != l_hash')");
        uint64_t index = h_len;
        while (index < db.size() && db[index] == 0x00)
            ++index;
        if (index >= db.size() || db[index] != 0x01)
            throw std::runtime_error("[RSA] Decoding error (No 0x01 sepator)");
        ++index;
        std::vector<uint8_t> msg(db.begin() + index, db.end());
        return std::string(msg.begin(), msg.end());
    }
}
