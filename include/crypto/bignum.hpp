#pragma once

#include <cstdint>
#include <ostream>
#include <gmp.h>

namespace crypto::bn
{
    class bignum
    {
        public:
            bignum();
            bignum(const bignum& other);
            bignum(bignum&& other) noexcept;
            bignum(const std::string& string_rep, int32_t base);
            ~bignum();

            friend std::ostream& operator<<(std::ostream& stream, const bignum& bignum);

            friend bignum operator+(bignum lhs, const bignum& rhs);
            friend bignum operator-(bignum lhs, const bignum& rhs);
            friend bignum operator*(bignum lhs, const bignum& rhs);
            friend bignum operator/(bignum lhs, const bignum& rhs);
            friend bignum operator%(bignum lhs, const bignum& rhs);

            friend bignum operator+(bignum lhs, size_t rhs);
            friend bignum operator-(bignum lhs, size_t rhs);
            friend bignum operator*(bignum lhs, size_t rhs);
            friend bignum operator/(bignum lhs, size_t rhs);
            friend bignum operator%(bignum lhs, size_t rhs);

            bignum& operator+=(const bignum& other);
            bignum& operator-=(const bignum& other);
            bignum& operator*=(const bignum& other);
            bignum& operator/=(const bignum& other);
            bignum& operator%=(const bignum& other);

            bignum& operator+=(size_t other);
            bignum& operator-=(size_t other);
            bignum& operator*=(size_t other);
            bignum& operator/=(size_t other);
            bignum& operator%=(size_t other);

            friend bool operator==(const bignum& lhs, const bignum& rhs);
            friend bool operator!=(const bignum& lhs, const bignum& rhs);
            friend bool operator<(const bignum& lhs, const bignum& rhs);
            friend bool operator<=(const bignum& lhs, const bignum& rhs);
            friend bool operator>(const bignum& lhs, const bignum& rhs);
            friend bool operator>=(const bignum& lhs, const bignum& rhs);

            friend bool operator==(const bignum& lhs, size_t rhs);
            friend bool operator!=(const bignum& lhs, size_t rhs);
            friend bool operator<(const bignum& lhs, size_t rhs);
            friend bool operator<=(const bignum& lhs, size_t rhs);
            friend bool operator>(const bignum& lhs, size_t rhs);
            friend bool operator>=(const bignum& lhs, size_t rhs);

            bignum operator-() const;
            bignum operator+() const;

            bignum& operator++();
            bignum operator++(int);
            bignum& operator--();
            bignum operator--(int);

            bignum& operator=(const bignum& other);
            bignum& operator=(bignum&& other) noexcept;

            bignum& operator&=(const bignum& other);
            bignum& operator|=(const bignum& other);
            bignum& operator^=(const bignum& other);

            friend bignum operator&(bignum lhs, const bignum& rhs);
            friend bignum operator|(bignum lhs, const bignum& rhs);
            friend bignum operator^(bignum lhs, const bignum& rhs);

            bignum& operator<<=(size_t n);
            bignum& operator>>=(size_t n);

            friend bignum operator<<(bignum lhs, size_t n);
            friend bignum operator>>(bignum lhs, size_t n);

        private:
            mpz_t m_Internal;
    };
}
