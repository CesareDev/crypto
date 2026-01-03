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

    bignum::bignum(const std::string& string_rep, int32_t base)
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
}
