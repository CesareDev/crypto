/**
 * @file hash.hpp
 * @brief In this file there are functions used to perform hashing operation with variours algorithms.
 */

#pragma once

#include <string>
#include "bignum.hpp"

/**
 * \namespace crypto::hash
 * @brief Hashing functions.
 */
namespace crypto::hash
{
    /**
     * @brief Enumerator used for deciding which algorithm is used during the hashing process
     */
    enum class algorithm
    {
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        MD5
    };
    
    /**
     * @brief Function to hash a string with a hashing algorithm. The default one is sha1. Since the function returns a 
     * bignum is possible to convert the hash into a hex string using the builtint function of the bignum class
     * @code{cpp}
     * auto res = hash_string("Hello");
     * std::cout << res.get_string(16) << std::endl;
     * @endcode
     * @param msg The string to be hashed.
     * @param algorithm The hashing algorithm to be used.
     * @return A bignum representing the digest.
     */
    bn::bignum hash_string(const std::string& input, algorithm algorithm = algorithm::Sha1);

    /**
     * @brief Function to hash a file with a hashing algorithm. The default one is sha1. Since the function returns a 
     * bignum is possible to convert the hash into a hex string using the builtint function of the bignum class
     * @code{cpp}
     * auto res = hash_string("/path/to/some/file");
     * std::cout << res.get_string(16) << std::endl;
     * @endcode
     * @param filename The path of the file to be hashed.
     * @param algorithm The hashing algorithm to be used.
     * @return A bignum representing the digest.
     */
    bn::bignum hash_file(const std::string& input_file, algorithm algorithm = algorithm::Sha1);
}
