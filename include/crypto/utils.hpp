#pragma once

#include <cstdint>
#include <vector>
#include <string>

/**
 * \namespace crypto::utils
 * @brief Utilities functions for reading and writing to files and conversion.
 */
namespace crypto::utils
{
    /**
     * @brief Function to convert a string to a vector of byte.
     * @param string The string to convert.
     * @return A vector of byte representing the \p string.
     */
    std::vector<uint8_t> string_to_vector(const std::string& string);

    /**
     * @brief Function to convert a vector of byte to a string.
     * @param vector The vector of byte to convert.
     * @return A string representing the \p vector.
     */
    std::string vector_to_string(const std::vector<uint8_t>& vector);

    /**
     * @brief Function to read a file and put its content into a string. Be aware that this function can throw an error.
     * @param input_file The path of the file.
     * @return A string containing the content of \p input_file.
     */
    std::string read_file_string(const std::string& input_file);

    /**
     * @brief Function to read a file and put its content into a vector. Be aware that this function can throw an error.
     * @param input_file The path of the file.
     * @return A vector of byte containing the content of \p input_file.
     */
    std::vector<uint8_t> read_file_vector(const std::string& input_file);

    /**
     * @brief Function to wrte to a file content from a string. Be aware that this function can throw an error.
     * @param output_file The path where the file will be saved.
     * @param string A string containing data.
     */
    void write_file(const std::string& output_file, const std::string& string);

    /**
     * @brief Function to wrte to a file content from a vector of byte. Be aware that this function can throw an error.
     * @param output_file The path where the file will be saved.
     * @param vector A vector of byte containing data.
     */
    void write_file(const std::string& output_file, const std::vector<uint8_t>& vector);

    /**
     * @brief Function to remove the file from the filesystem. Be aware that this function can throw an error.
     * @param input_file The file to be removed.
     */
    void delete_file(const std::string& input_file);
}
