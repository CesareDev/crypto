#pragma once

#include "bignum.hpp"

/**
 * \namespace crypto::aes
 * @brief AES functions for encrypting and decrypting messagges. For now there is only the ECB modality.
 */
namespace crypto::aes
{
    /**
     * @brief Enumerator used for deciding which encryption algorithm is used.
     */
    enum class algorithm
    {
        AES128,
        AES192,
        AES256,
    };

    /**
     * @brief Structure representing the symmetric key used in the encryption process.
     */
    struct key
    {
        /**
         * @brief Bignum representing the key.
         */
        bn::bignum symmetric_key;
    };

    /**
     * @brief Function to encrypt a \p plain_text input. Be aware that this function can throw an error. (ECB + PKCS7 Padding).
     * @param key The symmetric key.
     * @param plain_text The string representing the plain text to encrypt.
     * @param algorithm The algorithm to use for encryption
     * @return A vector of bytes containing the encrypted text.
     */
    std::vector<uint8_t> encrypt_message(const key& key, const std::string& plain_text, algorithm algorithm = algorithm::AES128);
    
    /**
     * @brief Function to decrypt a \p chiper_text input. Be aware that this function can throw an error. (ECB + PKCS7 Padding).
     * @param key The symmetric key.
     * @param chiper_text The vector of bytes representing the chiper text to decrypt.
     * @param algorithm The algorithm to use for decryption. It must match the algorithm used for encryption.
     * @return A string containing the decrypted text.
     */
    std::string decrypt_message(const key& key, const std::vector<uint8_t>& chiper_text, algorithm algorithm = algorithm::AES128);
}
