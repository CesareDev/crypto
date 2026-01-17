/**
 * @file bignum.hpp
 * @brief In this file there is the definition of the class that represents the arbitrary precions number.
 * Here are included the class and some related mathematical functions used for cryptographic purposes.
 */

#pragma once

#include <cstdint>
#include <ostream>
#include <gmp.h>
#include <vector>

/**
 * \namespace crypto::bn
 * @brief Arbitrary precision number class and and related functions.
 */
namespace crypto::bn
{
    /**
     * @brief This class implements an arbitrary precision number and all its important functions.
     * This class is a wrapper to the [gmp](https://gmplib.org/) library.
     */
    class bignum
    {
        public:
            /**
             * @brief Default constructor, initialize the bignum and set its value to 0.
             */
            bignum();

            /**
             * @brief Copy contructor.
             */
            bignum(const bignum& other);

            /**
             * @brief Move constructor.
             */
            bignum(bignum&& other) noexcept;

            /**
             * @brief Construct a bignum from an int32_t.
             * @param n The integer from which the bignum is built.
             */
            bignum(int32_t n);

            /**
             * @brief Construct a bignum from an int64_t.
             * @param n The integer from which the bignum is built.
             */
            bignum(int64_t n);

            /**
             * @brief Construct a bignum from a uint64_t.
             * @param n The integer from which the bignum is built.
             */
            bignum(uint64_t n);

            /**
             * @brief Construct a bignum from its string representation indicating also the base for the representation.
             * For example:
             * @code{.cpp}
             * bignum("123456", 10);
             * @endcode
             * construct the bignum as 123456 because it's 10 base, so decimal.
             * @param string_rep The representation of the number using a string.
             * @param base The base of the string representation.
             */
            bignum(const std::string& string_rep, int base);

            /**
             * @brief Construct a bignum from a binary vector representation, indicating also the layout.
             * @param byte_array The representation of the bignum using a binary vector.
             * @param big_endian Whether the vector is representing a bignum in big endian or little endian format.
             */
            bignum(const std::vector<uint8_t>& byte_array, bool big_endian);

            /**
             * @brief Destructor. Free the memory used by the bignum and its internal state.
             */
            ~bignum();

            /**
             * @brief Operator to make the bignum printable to the standard output or any other stream.
             * Be aware that using this operator will treat the bignum as 10 based.
             * @param stream The output stream.
             * @param bignum The bignum.
             * @return The reference to the stream.
             */
            friend std::ostream& operator<<(std::ostream& stream, const bignum& bignum);

            friend bignum operator+(bignum lhs, const bignum& rhs);
            friend bignum operator-(bignum lhs, const bignum& rhs);
            friend bignum operator*(bignum lhs, const bignum& rhs);
            friend bignum operator/(bignum lhs, const bignum& rhs);
            friend bignum operator%(bignum lhs, const bignum& rhs);

            friend bignum operator+(bignum lhs, int32_t rhs);
            friend bignum operator-(bignum lhs, int32_t rhs);
            friend bignum operator*(bignum lhs, int32_t rhs);
            friend bignum operator/(bignum lhs, int32_t rhs);
            friend bignum operator%(bignum lhs, int32_t rhs);

            friend bignum operator+(bignum lhs, int64_t rhs);
            friend bignum operator-(bignum lhs, int64_t rhs);
            friend bignum operator*(bignum lhs, int64_t rhs);
            friend bignum operator/(bignum lhs, int64_t rhs);
            friend bignum operator%(bignum lhs, int64_t rhs);

            friend bignum operator+(bignum lhs, uint64_t rhs);
            friend bignum operator-(bignum lhs, uint64_t rhs);
            friend bignum operator*(bignum lhs, uint64_t rhs);
            friend bignum operator/(bignum lhs, uint64_t rhs);
            friend bignum operator%(bignum lhs, uint64_t rhs);

            bignum& operator+=(const bignum& other);
            bignum& operator-=(const bignum& other);
            bignum& operator*=(const bignum& other);
            bignum& operator/=(const bignum& other);
            bignum& operator%=(const bignum& other);

            bignum& operator+=(int32_t other);
            bignum& operator-=(int32_t other);
            bignum& operator*=(int32_t other);
            bignum& operator/=(int32_t other);
            bignum& operator%=(int32_t other);

            bignum& operator+=(int64_t other);
            bignum& operator-=(int64_t other);
            bignum& operator*=(int64_t other);
            bignum& operator/=(int64_t other);
            bignum& operator%=(int64_t other);

            bignum& operator+=(uint64_t other);
            bignum& operator-=(uint64_t other);
            bignum& operator*=(uint64_t other);
            bignum& operator/=(uint64_t other);
            bignum& operator%=(uint64_t other);

            friend bool operator==(const bignum& lhs, const bignum& rhs);
            friend bool operator!=(const bignum& lhs, const bignum& rhs);
            friend bool operator<(const bignum& lhs, const bignum& rhs);
            friend bool operator<=(const bignum& lhs, const bignum& rhs);
            friend bool operator>(const bignum& lhs, const bignum& rhs);
            friend bool operator>=(const bignum& lhs, const bignum& rhs);

            friend bool operator==(const bignum& lhs, int32_t rhs);
            friend bool operator!=(const bignum& lhs, int32_t rhs);
            friend bool operator<(const bignum& lhs, int32_t rhs);
            friend bool operator<=(const bignum& lhs, int32_t rhs);
            friend bool operator>(const bignum& lhs, int32_t rhs);
            friend bool operator>=(const bignum& lhs, int32_t rhs);

            friend bool operator==(const bignum& lhs, int64_t rhs);
            friend bool operator!=(const bignum& lhs, int64_t rhs);
            friend bool operator<(const bignum& lhs, int64_t rhs);
            friend bool operator<=(const bignum& lhs, int64_t rhs);
            friend bool operator>(const bignum& lhs, int64_t rhs);
            friend bool operator>=(const bignum& lhs, int64_t rhs);

            friend bool operator==(const bignum& lhs, uint64_t rhs);
            friend bool operator!=(const bignum& lhs, uint64_t rhs);
            friend bool operator<(const bignum& lhs, uint64_t rhs);
            friend bool operator<=(const bignum& lhs, uint64_t rhs);
            friend bool operator>(const bignum& lhs, uint64_t rhs);
            friend bool operator>=(const bignum& lhs, uint64_t rhs);

            bignum operator-() const;
            bignum operator+() const;

            bignum& operator++();
            bignum operator++(int32_t);
            bignum& operator--();
            bignum operator--(int32_t);

            bignum& operator=(const bignum& other);
            bignum& operator=(bignum&& other) noexcept;

            friend bignum operator&(bignum lhs, const bignum& rhs);
            friend bignum operator|(bignum lhs, const bignum& rhs);
            friend bignum operator^(bignum lhs, const bignum& rhs);

            bignum& operator&=(const bignum& other);
            bignum& operator|=(const bignum& other);
            bignum& operator^=(const bignum& other);

            friend bignum operator&(bignum lhs, int32_t rhs);
            friend bignum operator|(bignum lhs, int32_t rhs);
            friend bignum operator^(bignum lhs, int32_t rhs);
            friend bignum operator<<(bignum lhs, int32_t n);
            friend bignum operator>>(bignum lhs, int32_t n);

            bignum& operator&=(int32_t other);
            bignum& operator|=(int32_t other);
            bignum& operator^=(int32_t other);
            bignum& operator<<=(int32_t n);
            bignum& operator>>=(int32_t n);

            friend bignum operator&(bignum lhs, int64_t rhs);
            friend bignum operator|(bignum lhs, int64_t rhs);
            friend bignum operator^(bignum lhs, int64_t rhs);
            friend bignum operator<<(bignum lhs, int64_t n);
            friend bignum operator>>(bignum lhs, int64_t n);

            bignum& operator&=(int64_t other);
            bignum& operator|=(int64_t other);
            bignum& operator^=(int64_t other);
            bignum& operator<<=(int64_t n);
            bignum& operator>>=(int64_t n);

            friend bignum operator&(bignum lhs, uint64_t rhs);
            friend bignum operator|(bignum lhs, uint64_t rhs);
            friend bignum operator^(bignum lhs, uint64_t rhs);
            friend bignum operator<<(bignum lhs, uint64_t n);
            friend bignum operator>>(bignum lhs, uint64_t n);

            bignum& operator&=(uint64_t other);
            bignum& operator|=(uint64_t other);
            bignum& operator^=(uint64_t other);
            bignum& operator<<=(uint64_t n);
            bignum& operator>>=(uint64_t n);

            operator int32_t() const;
            operator int64_t() const;
            operator uint64_t() const;
            
            /**
             * @brief Return the number of bit used by the bignum.
             * @return The number of bit.
             */
            size_t bit_count() const;

            /**
             * @brief Return the number of byte used by the bignum.
             * @return The number of byte.
             */
            size_t byte_count() const;

            /**
             * @brief Return the string representation of the number in \p base base.
             * @param base The base of which the number will be represented.
             * @return The string representation of the bignum.
             */
            std::string get_string(int base) const;

            /**
             * @brief Return the binary vector representation of the bignum in \p big_endian layout.
             * @param big_endian Whether the vector will represent a bignum in big endian or little endian format.
             * @return The binary vector representation of the bignum.
             */
            std::vector<uint8_t> get_byte_array(bool big_endian = false) const;

            /**
             * @brief Return the binary string representation of the bignum in \p big_endian layout.
             * @param big_endian Whether the vector will represent a bignum in big endian or little endian format.
             * @return The binary string representation of the bignum.
             */
            std::string get_byte_string(bool big_endian = false) const;

            friend bignum exp(const bignum& base, size_t exponent);
            friend bignum exp_mod(const bignum& base, const bignum& exponent, const bignum& mod);
            friend bignum inverse_mod(const bignum& n, const bignum& mod);
            friend bignum gcd(const bignum& a, const bignum& b);
            friend bignum next_prime(const bignum& n);
            friend bignum generate_prime(size_t bit_size);

        private:
            mpz_t m_Internal;
    };

    /**
     * @brief Compute \p base raised to \p exponent: \f$base^{exponent}\f$.
     * @param base The base.
     * @param exponent The exponent.
     * @return Return the result of \f$base^{exponent}\f$.
     */
    bignum exp(const bignum& base, size_t exponent);

    /**
     * @brief Compute \p base raised to the \p exponent modulo \p mod: \f$base^{exponent}\pmod{mod}\f$.
     * @param base The base.
     * @param exponent The exponent.
     * @param mod The modulo.
     * @return Return the result of \f$base^{exponent}\pmod{mod}\f$.
     */
    bignum exp_mod(const bignum& base, const bignum& exponent, const bignum& mod);
    
    /**
     * @brief Compute the inverse of \p n modulo \p mod, \f$n^{-1}\pmod{mod}\f$.
     * @param n The number that need to be inverted.
     * @param mod The modulo.
     * @return The inverse of \p n modulo \p mod.
     */
    bignum inverse_mod(const bignum& n, const bignum& mod);

    /**
     * @brief Compute the greatest commond divisor between \p a and \p b.
     * @param a The first number.
     * @param b The second number.
     * @return The greatest commond divisor between \p a and \p b.
     */
    bignum gcd(const bignum& a, const bignum& b);

    /**
     * @brief Compute the next prime number right after \p n.
     * @param n The starting number.
     * @return The next prime number right after \p n.
     */
    bignum next_prime(const bignum& n);

    /**
     * @brief Generate a random prime number of \p bit_size bits.
     * @param bit_size The size in bits of the random prime number.
     * @return A random prime number of \p bit_size bits.
     */
    bignum generate_prime(size_t bit_size);
}
