#include <algorithm>

#include <crypto/bignum.hpp>

namespace crypto::bn
{
    bignum::bignum()
    {
        mpz_init(m_Internal);
    }

    bignum::bignum(const bignum& other)
    {
        mpz_init_set(m_Internal, other.m_Internal);
    }

    bignum::bignum(bignum&& other) noexcept
    {
        mpz_init(m_Internal);
        mpz_swap(m_Internal, other.m_Internal);
    }

    bignum::bignum(int n)
    {
        mpz_init_set_si(m_Internal, n);
    }

    bignum::bignum(size_t n)
    {
        mpz_init_set_ui(m_Internal, n);
    }

    bignum::bignum(const std::string& string_rep, int base)
    {
        mpz_init_set_str(m_Internal, string_rep.c_str(), base);
    }

    bignum::~bignum()
    {
        mpz_clear(m_Internal);
    }

    std::ostream& operator<<(std::ostream& stream, const bignum& bignum)
    {
        char* str = mpz_get_str(NULL, 10, bignum.m_Internal);
        stream << str;
        free(str);
        return stream;
    }

    bignum operator+(bignum lhs, const bignum& rhs)
    {
        return lhs += rhs;
    }

    bignum operator-(bignum lhs, const bignum& rhs)
    {
        return lhs -= rhs;
    }

    bignum operator*(bignum lhs, const bignum& rhs)
    {
        return lhs *= rhs;
    }

    bignum operator/(bignum lhs, const bignum& rhs)
    {
        return lhs /= rhs;
    }

    bignum operator%(bignum lhs, const bignum& rhs)
    {
        return lhs %= rhs;
    }

    bignum operator+(bignum lhs, size_t rhs)
    {
        return lhs += rhs;
    }

    bignum operator-(bignum lhs, size_t rhs)
    {
        return lhs -= rhs;
    }

    bignum operator*(bignum lhs, size_t rhs)
    {
        return lhs *= rhs;
    }

    bignum operator/(bignum lhs, size_t rhs)
    {
        return lhs /= rhs;
    }

    bignum operator%(bignum lhs, size_t rhs)
    {
        return lhs %= rhs;
    }

    bignum operator+(bignum lhs, int rhs)
    {
        return lhs += rhs;
    }

    bignum operator-(bignum lhs, int rhs)
    {
        return lhs -= rhs;
    }

    bignum operator*(bignum lhs, int rhs)
    {
        return lhs *= rhs;
    }

    bignum operator/(bignum lhs, int rhs)
    {
        return lhs /= rhs;
    }

    bignum operator%(bignum lhs, int rhs)
    {
        return lhs %= rhs;
    }

    bignum& bignum::operator+=(const bignum& other)
    {
        mpz_add(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator-=(const bignum& other)
    {
        mpz_sub(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator*=(const bignum& other)
    {
        mpz_mul(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator/=(const bignum& other)
    {
        mpz_tdiv_q(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator%=(const bignum& other)
    {
        mpz_mod(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator+=(size_t other)
    {
        mpz_add_ui(m_Internal, m_Internal, other);
        return *this;
    }

    bignum& bignum::operator-=(size_t other)
    {
        mpz_sub_ui(m_Internal, m_Internal, other);
        return *this;
    }

    bignum& bignum::operator*=(size_t other)
    {
        mpz_mul_ui(m_Internal, m_Internal, other);
        return *this;
    }

    bignum& bignum::operator/=(size_t other)
    {
        mpz_tdiv_q_ui(m_Internal, m_Internal, other);
        return *this;
    }

    bignum& bignum::operator%=(size_t other)
    {
        mpz_mod_ui(m_Internal, m_Internal, other);
        return *this;
    }

    bignum& bignum::operator+=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_add(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator-=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_sub(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator*=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_mul(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator/=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_tdiv_q(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator%=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_mul(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bool operator==(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) == 0;
    }

    bool operator!=(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) != 0;
    }

    bool operator<(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) < 0;
    }

    bool operator<=(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) <= 0;
    }

    bool operator>(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) > 0;
    }

    bool operator>=(const bignum& lhs, const bignum& rhs)
    {
        return mpz_cmp(lhs.m_Internal, rhs.m_Internal) >= 0;
    }

    bool operator==(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) == 0;
    }

    bool operator!=(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) != 0;
    }

    bool operator<(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) < 0;
    }

    bool operator<=(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) <= 0;
    }

    bool operator>(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) > 0;
    }

    bool operator>=(const bignum& lhs, size_t rhs)
    {
        return mpz_cmp_ui(lhs.m_Internal, rhs) >= 0;
    }

    bool operator==(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) == 0;
    }

    bool operator!=(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) != 0;
    }

    bool operator<(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) < 0;
    }

    bool operator<=(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) <= 0;
    }

    bool operator>(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) > 0;
    }

    bool operator>=(const bignum& lhs, int rhs)
    {
        return mpz_cmp_si(lhs.m_Internal, rhs) >= 0;
    }

    bignum bignum::operator-() const
    {
        bignum neg;
        mpz_neg(neg.m_Internal, m_Internal);
        return neg;
    }

    bignum bignum::operator+() const
    {
        return *this;
    }

    bignum& bignum::operator++()
    {
        *this += 1;
        return *this;
    }

    bignum bignum::operator++(int)
    {
        bignum tmp = *this;
        *this += 1;
        return tmp;
    }

    bignum& bignum::operator--()
    {
        *this -= 1;
        return *this;
    }

    bignum bignum::operator--(int)
    {
        bignum tmp = *this;
        *this -= 1;
        return tmp;
    }

    bignum& bignum::operator=(const bignum& other)
    {
        if (this != &other)
            mpz_set(m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator=(bignum&& other) noexcept
    {
        if (this != &other)
            mpz_swap(m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator&=(const bignum& other)
    {
        mpz_and(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator|=(const bignum& other)
    {
        mpz_ior(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum& bignum::operator^=(const bignum& other)
    {
        mpz_xor(m_Internal, m_Internal, other.m_Internal);
        return *this;
    }

    bignum operator&(bignum lhs, const bignum& rhs)
    {
        return lhs &= rhs;
    }

    bignum operator|(bignum lhs, const bignum& rhs)
    {
        return lhs |= rhs;
    }

    bignum operator^(bignum lhs, const bignum& rhs)
    {
        return lhs ^= rhs;
    }

    bignum& bignum::operator&=(size_t other)
    {
        mpz_t tmp;
        mpz_init_set_ui(tmp, other);
        mpz_and(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator|=(size_t other)
    {
        mpz_t tmp;
        mpz_init_set_ui(tmp, other);
        mpz_ior(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator^=(size_t other)
    {
        mpz_t tmp;
        mpz_init_set_ui(tmp, other);
        mpz_xor(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum operator&(bignum lhs, size_t rhs)
    {
        return lhs &= rhs;
    }

    bignum operator|(bignum lhs, size_t rhs)
    {
        return lhs |= rhs;
    }

    bignum operator^(bignum lhs, size_t rhs)
    {
        return lhs ^= rhs;
    }

    bignum& bignum::operator&=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_and(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator|=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_ior(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum& bignum::operator^=(int other)
    {
        mpz_t tmp;
        mpz_init_set_si(tmp, other);
        mpz_xor(m_Internal, m_Internal, tmp);
        mpz_clear(tmp);
        return *this;
    }

    bignum operator&(bignum lhs, int rhs)
    {
        return lhs &= rhs;
    }

    bignum operator|(bignum lhs, int rhs)
    {
        return lhs |= rhs;
    }

    bignum operator^(bignum lhs, int rhs)
    {
        return lhs ^= rhs;
    }

    bignum& bignum::operator<<=(size_t n)
    {
        mpz_mul_2exp(m_Internal, m_Internal, n);
        return *this;
    }

    bignum& bignum::operator>>=(size_t n)
    {
        mpz_fdiv_q_2exp(m_Internal, m_Internal, n);
        return *this;
    }

    bignum operator<<(bignum lhs, size_t n)
    {
        return lhs <<= n;
    }

    bignum operator>>(bignum lhs, size_t n)
    {
        return lhs >>= n;
    }

    bignum& bignum::operator<<=(int n)
    {
        mpz_mul_2exp(m_Internal, m_Internal, n);
        return *this;
    }

    bignum& bignum::operator>>=(int n)
    {
        mpz_fdiv_q_2exp(m_Internal, m_Internal, n);
        return *this;
    }

    bignum operator<<(bignum lhs, int n)
    {
        return lhs <<= n;
    }

    bignum operator>>(bignum lhs, int n)
    {
        return lhs >>= n;
    }

    bignum::operator size_t() const
    {
        return mpz_get_ui(m_Internal);
    }

    bignum::operator int() const
    {
        return mpz_get_si(m_Internal);
    }

    bignum exp_mod(const bignum& base, const bignum& exponent, const bignum& mod)
    {
        bignum res;
        mpz_powm(res.m_Internal, base.m_Internal, exponent.m_Internal, mod.m_Internal);
        return res;
    }

    bignum inverse_mod(const bignum& n, const bignum& mod)
    {
        bignum res;
        mpz_invert(res.m_Internal, n.m_Internal, mod.m_Internal);
        return res;
    }

    bignum gcd(const bignum& a, const bignum& b)
    {
        bignum res;
        mpz_gcd(res.m_Internal, a.m_Internal, b.m_Internal);
        return res;
    }

    size_t bignum::bit_count() const
    {
        return mpz_sizeinbase(m_Internal, 2);
    }

    size_t bignum::byte_count() const
    {
        return (bit_count() + 7) / 8;
    }

    std::string bignum::get_string(int base) const
    {
        char* tmp = mpz_get_str(NULL, base, m_Internal);
        std::string res { tmp };
        free(tmp);
        return res;
    }

    std::vector<uint8_t> bignum::get_byte_array(bool big_endian) const
    {
        size_t size = byte_count();
        std::vector<uint8_t> res;
        res.reserve(size);
        for (size_t i {}; i < size; ++i)
        {
            uint8_t b = static_cast<int>(*this >> (i * 8)) & 0xFF;
            res.push_back(b);
        }
        if (big_endian)
            std::reverse(res.begin(), res.end());
        return res;
    }
}
