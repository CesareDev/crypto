#include <crypto/b64.hpp>

#include <cstdint>
#include <unordered_map>
#include <fstream>

static uint8_t encoding[] =
{
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static std::unordered_map<uint8_t, uint8_t> decoding =
{
    { 'A', 0 }, { 'B', 1 }, { 'C', 2 }, { 'D', 3 },
    { 'E', 4 }, { 'F', 5 }, { 'G', 6 }, { 'H', 7 },
    { 'I', 8 }, { 'J', 9 }, { 'K', 10 }, { 'L', 11 },
    { 'M', 12 }, { 'N', 13 }, { 'O', 14 }, { 'P', 15 },
    { 'Q', 16 }, { 'R', 17 }, { 'S', 18 }, { 'T', 19 },
    { 'U', 20 }, { 'V', 21 }, { 'W', 22 }, { 'X', 23 },
    { 'Y', 24 }, { 'Z', 25 }, { 'a', 26 }, { 'b', 27 },
    { 'c', 28 }, { 'd', 29 }, { 'e', 30 }, { 'f', 31 },
    { 'g', 32 }, { 'h', 33 }, { 'i', 34 }, { 'j', 35 },
    { 'k', 36 }, { 'l', 37 }, { 'm', 38 }, { 'n', 39 },
    { 'o', 40 }, { 'p', 41 }, { 'q', 42 }, { 'r', 43 },
    { 's', 44 }, { 't', 45 }, { 'u', 46 }, { 'v', 47 },
    { 'w', 48 }, { 'x', 49 }, { 'y', 50 }, { 'z', 51 },
    { '0', 52 }, { '1', 53 }, { '2', 54 }, { '3', 55 },
    { '4', 56 }, { '5', 57 }, { '6', 58 }, { '7', 59 }, 
    { '8', 60 }, { '9', 61 }, { '+', 62 }, { '/', 63 },
};

struct Char
{
    uint8_t c;
    bool padding;
};

namespace crypto::b64
{
    std::string EncodeString(const std::string& plaintext)
    {
        uint64_t i = 0;
        uint64_t len = plaintext.length();
        uint64_t enconde_len = ((4 * len / 3) + 3) & ~3;

        std::string encoded_buf {};
        encoded_buf.reserve(enconde_len);

        while (i < len)
        {
            Char first_ch = { (uint8_t)plaintext[i], false };
            Char second_ch = { 0, true };
            Char third_ch = { 0, true };

            if (i + 1 < len)
            {
                second_ch.c = plaintext[i + 1];
                second_ch.padding = false;
            }
            if (i + 2 < len)
            {
                third_ch.c = plaintext[i + 2];
                third_ch.padding = false;
            }

            unsigned char first_enc = (first_ch.c & 0b11111100) >> 2;
            unsigned char second_enc = ((first_ch.c & 0b00000011) << 4) | ((second_ch.c & 0b11110000) >> 4);
            unsigned char third_enc = ((second_ch.c & 0b00001111) << 2) | ((third_ch.c & 0b11000000) >> 6);
            unsigned char fourth_enc = third_ch.c & 0b00111111;

            encoded_buf.push_back(encoding[first_enc]);
            encoded_buf.push_back(encoding[second_enc]);
            encoded_buf.push_back(second_ch.padding ? '=' : encoding[third_enc]);
            encoded_buf.push_back(third_ch.padding ? '=' : encoding[fourth_enc]);

            i += 3;
        }

        return encoded_buf;
    }

    std::string DecodeString(const std::string& ciphertext)
    {
        uint64_t i = 0;
        uint64_t len = ciphertext.length();

        if (len % 4 != 0)
            return "";

        uint64_t index = ciphertext.length();
        while (ciphertext[index] == '=')
            index--;
        uint64_t decoded_len = (len / 4) * 3 - (len - index);

        std::string decoded_buffer {};
        decoded_buffer.reserve(decoded_len);

        while (i < len)
        {
            unsigned char first_dec = decoding[ciphertext[i]];
            unsigned char second_dec = decoding[ciphertext[i + 1]];
            unsigned char third_dec = ciphertext[i + 2] == '=' ? 0 : decoding[ciphertext[i + 2]];
            unsigned char fourth_dec = ciphertext[i + 3] == '=' ? 0 : decoding[ciphertext[i + 3]];

            char first_ch = (first_dec << 2) | ((second_dec & 0b00110000) >> 4);
            char second_ch = ((second_dec & 0b00001111) << 4) | ((third_dec & 0b00111100) >> 2);
            char third_ch = ((third_dec & 0b00000011) << 6) | (fourth_dec & 0b00111111);

            decoded_buffer.push_back(first_ch);
            decoded_buffer.push_back(second_ch);
            decoded_buffer.push_back(third_ch);

            i += 4;
        }

        return decoded_buffer;
    }

    std::string EncodeFile(const std::string& input_file)
    {
        std::ifstream input_stream(input_file, std::ios::binary | std::ios::ate);
        if (!input_stream.is_open())
            return "";

        uint64_t file_size = input_stream.tellg();
        input_stream.seekg(std::ios::beg);

        std::string buffer;
        buffer.reserve(file_size);
        if (!input_stream.read(buffer.data(), file_size).good())
            return "";

        return EncodeString(buffer);
    }

    std::string DecodeFile(const std::string& input_file)
    {
        std::ifstream input_stream(input_file, std::ios::binary | std::ios::ate);
        if (!input_stream.is_open())
            return "";

        uint64_t file_size = input_stream.tellg();
        input_stream.seekg(std::ios::beg);

        if (file_size % 4 != 0)
            return "";

        std::string buffer;
        buffer.reserve(file_size);
        if (!input_stream.read(buffer.data(), file_size).good())
            return "";

        return DecodeString(buffer);
    }
}
