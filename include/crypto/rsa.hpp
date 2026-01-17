#pragma once

#include <string>
#include "bignum.hpp"

/**
 * \namespace crypto::rsa
 * @brief RSA functions for key generation, encrypting and decrypting messagges.
 */
namespace crypto::rsa
{
    /**
     * @brief Structure representing the public key of the RSA protocol.
     */
    struct public_key
    {
        /**
         * @brief Bignum representing the module of the public key.
         */
        bn::bignum module;

        /**
         * @brief Bignum representing the encryption exponent of the public key.
         */
        bn::bignum enc_exp;

        /**
         * @brief A flag indicating if the generated publick key is valid.
         */
        bool valid;
    };

    /**
     * @brief Structure representing the private key of the RSA protocol.
     */
    struct private_key
    {
        /**
         * @brief Bignum representing the module of the private key.
         */
        bn::bignum module;

        /**
         * @brief Bignum representing the decryption exponent of the private key.
         */
        bn::bignum dec_exp;

        /**
         * @brief A flag indicating if the generated private key is valid.
         */
        bool valid;
    };

    /**
     * @brief Structure containig both private and public key.
     */
    struct keys
    {
        /**
         * @brief The public key.
         */
        public_key pub_key;

        /**
         * @brief The private key.
         */
        private_key pri_key;
    };

    /**
     * @brief Function to generate the pair of public and private key. This function expect \p p and \p q to be prime.
     * Generally is suggested to use at least 1024 bit prime number.
     * @param prime_p A prime number p.
     * @param prime_q A prime number q.
     * @param e The exponent used for the publick key.
     * @return A structure containig the public and private key.
     */
    keys generate_keys(const bn::bignum& prime_p, const bn::bignum& prime_q, const bn::bignum& e = 65537);

    /**
     * @brief Function to encrypt a message using the public key. Be aware that this function can throw an error.
     * @param pub_key The public key.
     * @param plain_text The message represented in plain text.
     * @param label The optional label used in the encryption process. [RFC3447](https://www.rfc-editor.org/rfc/rfc3447#section-7.1.1)
     * @return A raw binary vector containing the encrypted message.
     */
    std::vector<uint8_t> encrypt_message(const public_key& pub_key, const std::string& plain_text, const std::string& label = "");

    /**
     * @brief Function to decrypt a binary vector input using the private key. Be aware that this function can throw an error.
     * @param pri_key The private key.
     * @param chiper_text The binary vector representig the chiper text.
     * @param label The optional label used in the decryption process. [RFC3447](https://www.rfc-editor.org/rfc/rfc3447#section-7.1.2)
     * @return A string representig the decrypted message.
     */
    std::string decrypt_message(const private_key& pri_key, const std::vector<uint8_t>& chiper_text, const std::string& label = "");
}
