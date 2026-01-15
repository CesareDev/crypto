#pragma once

#include <cstdint>
#include <ostream>
#include <gmp.h>
#include <vector>

namespace crypto::bn
{
    class bignum
    {
        public:
            bignum();
            bignum(const bignum& other);
            bignum(bignum&& other) noexcept;
            bignum(int n);
            bignum(size_t n);
            bignum(const std::string& string_rep, int base);
            bignum(const std::vector<uint8_t>& byte_array, bool big_endian);
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

            friend bignum operator+(bignum lhs, int rhs);
            friend bignum operator-(bignum lhs, int rhs);
            friend bignum operator*(bignum lhs, int rhs);
            friend bignum operator/(bignum lhs, int rhs);
            friend bignum operator%(bignum lhs, int rhs);

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

            bignum& operator+=(int other);
            bignum& operator-=(int other);
            bignum& operator*=(int other);
            bignum& operator/=(int other);
            bignum& operator%=(int other);

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

            friend bool operator==(const bignum& lhs, int rhs);
            friend bool operator!=(const bignum& lhs, int rhs);
            friend bool operator<(const bignum& lhs, int rhs);
            friend bool operator<=(const bignum& lhs, int rhs);
            friend bool operator>(const bignum& lhs, int rhs);
            friend bool operator>=(const bignum& lhs, int rhs);

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

            bignum& operator&=(size_t other);
            bignum& operator|=(size_t other);
            bignum& operator^=(size_t other);

            friend bignum operator&(bignum lhs, size_t rhs);
            friend bignum operator|(bignum lhs, size_t rhs);
            friend bignum operator^(bignum lhs, size_t rhs);

            bignum& operator&=(int other);
            bignum& operator|=(int other);
            bignum& operator^=(int other);

            friend bignum operator&(bignum lhs, int rhs);
            friend bignum operator|(bignum lhs, int rhs);
            friend bignum operator^(bignum lhs, int rhs);

            bignum& operator<<=(size_t n);
            bignum& operator>>=(size_t n);

            friend bignum operator<<(bignum lhs, size_t n);
            friend bignum operator>>(bignum lhs, size_t n);
            
            bignum& operator<<=(int n);
            bignum& operator>>=(int n);

            friend bignum operator<<(bignum lhs, int n);
            friend bignum operator>>(bignum lhs, int n);

            operator size_t() const;
            operator int() const;

            friend bignum exp_mod(const bignum& base, const bignum& exponent, const bignum& mod);
            friend bignum inverse_mod(const bignum& n, const bignum& mod);
            friend bignum gcd(const bignum& a, const bignum& b);

            size_t bit_count() const;
            size_t byte_count() const;
            std::string get_string(int base) const;
            std::vector<uint8_t> get_byte_array(bool big_endian = false) const;

        private:
            mpz_t m_Internal;
    };

    bignum exp_mod(const bignum& base, const bignum& exponent, const bignum& mod);
    bignum inverse_mod(const bignum& n, const bignum& mod);
    bignum gcd(const bignum& a, const bignum& b);
}
