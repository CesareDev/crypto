#pragma once

#include <string>

namespace crypto::b64
{
    std::string EncodeString(const std::string& input);
    std::string EncodeFile(const std::string& input_file);

    std::string DecodeString(const std::string& input);
    std::string DecodeFile(const std::string& input_file);
}
