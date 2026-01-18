#include <crypto/utils.hpp>

#include <fstream>

namespace crypto::utils
{
    std::vector<uint8_t> string_to_vector(const std::string& string)
    {
        return std::vector<uint8_t>(string.begin(), string.end());
    }

    std::string vector_to_string(const std::vector<uint8_t>& vector)
    {
        return std::string(vector.begin(), vector.end());
    }

    std::string read_file_string(const std::string& input_file)
    {
        std::ifstream file_stream(input_file, std::ios::binary | std::ios::ate);

        if (!file_stream.is_open())
            throw std::runtime_error("[UTILS] Error opening file: " + input_file);

        uint64_t file_size = file_stream.tellg();
        file_stream.seekg(std::ios::beg);

        std::string output(file_size, 0);
        if (!file_stream.read(output.data(), file_size).good())
            throw std::runtime_error("[UTILS] Error reading file: " + input_file);

        return output;
    }

    std::vector<uint8_t> read_file_vector(const std::string& input_file)
    {
        std::ifstream file_stream(input_file, std::ios::binary | std::ios::ate);

        if (!file_stream.is_open())
            throw std::runtime_error("[UTILS] Error opening file: " + input_file);

        uint64_t file_size = file_stream.tellg();
        file_stream.seekg(std::ios::beg);

        std::string output(file_size, 0);
        if (!file_stream.read(output.data(), file_size).good())
            throw std::runtime_error("[UTILS] Error reading file: " + input_file);

        return string_to_vector(output);
    }

    void write_file(const std::string& output_file, const std::string& string)
    {
        std::ofstream file_stream(output_file, std::ios::binary | std::ios::out);

        if (!file_stream.is_open())
            throw std::runtime_error("[UTILS] Error creating file: " + output_file);

        file_stream << string;
    }

    void write_file(const std::string& output_file, const std::vector<uint8_t>& vector)
    {
        std::ofstream file_stream(output_file, std::ios::binary | std::ios::out);

        if (!file_stream.is_open())
            throw std::runtime_error("[UTILS] Error creating file: " + output_file);

        std::string input = vector_to_string(vector);
        file_stream << input;
    }

    void delete_file(const std::string& input_file)
    {
        int res { remove(input_file.c_str()) };
        if (res != 0)
            throw std::runtime_error("[UTILS] Error deleting the file: " + input_file);
    }
}
