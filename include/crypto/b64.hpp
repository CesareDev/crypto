#pragma once

#include <string>

namespace crypto::b64
{
    std::string encode_string(const std::string& input);
    std::string encode_file(const std::string& input_file);

    std::string decode_string(const std::string& input);
    std::string decode_file(const std::string& input_file);
}
