#pragma once

#include <string>

/**
 * \namespace crypto::b64
 * @brief Base64 encoding and decoding functions for strings and files.
 */
namespace crypto::b64
{
    /**
     * @brief Function to encode a string into Base64 encoding.
     * @param input The string that needed to be encoded.
     * @return The \p input string encoded.
     */
    std::string encode_string(const std::string& input);

    /**
     * @brief Function to encode a file into Base64 encoding.
     * @param input_file The string that represent the path of the file.
     * @return The content of the \p input_file encoded.
     */
    std::string encode_file(const std::string& input_file);

    /**
     * @brief Function to decode a file from Base64 encoding. Be aware that this function can throw an error.
     * @param input The string that needed to be decoded.
     * @return The \p input string decoded.
     */
    std::string decode_string(const std::string& input);

    /**
     * @brief Function to decode a file from Base64 encoding.
     * @param input_file The string that represent the path of the file.
     * @return The content of the \p input_file decoded.
     */
    std::string decode_file(const std::string& input_file);
}
