#include <cstdint>

#include <crypto/aes.hpp>
#include <crypto/utils.hpp>

// Polynomial 0x11B
static uint8_t gf256_inv_lookup[256]
{
    0x00, 0x01, 0x8D, 0xF6, 0xCB, 0x52, 0x7B, 0xD1,
    0xE8, 0x4F, 0x29, 0xC0, 0xB0, 0xE1, 0xE5, 0xC7,
    0x74, 0xB4, 0xAA, 0x4B, 0x99, 0x2B, 0x60, 0x5F,
    0x58, 0x3F, 0xFD, 0xCC, 0xFF, 0x40, 0xEE, 0xB2,
    0x3A, 0x6E, 0x5A, 0xF1, 0x55, 0x4D, 0xA8, 0xC9,
    0xC1, 0x0A, 0x98, 0x15, 0x30, 0x44, 0xA2, 0xC2,
    0x2C, 0x45, 0x92, 0x6C, 0xF3, 0x39, 0x66, 0x42,
    0xF2, 0x35, 0x20, 0x6F, 0x77, 0xBB, 0x59, 0x19,
    0x1D, 0xFE, 0x37, 0x67, 0x2D, 0x31, 0xF5, 0x69,
    0xA7, 0x64, 0xAB, 0x13, 0x54, 0x25, 0xE9, 0x09,
    0xED, 0x5C, 0x05, 0xCA, 0x4C, 0x24, 0x87, 0xBF,
    0x18, 0x3E, 0x22, 0xF0, 0x51, 0xEC, 0x61, 0x17,
    0x16, 0x5E, 0xAF, 0xD3, 0x49, 0xA6, 0x36, 0x43,
    0xF4, 0x47, 0x91, 0xDF, 0x33, 0x93, 0x21, 0x3B,
    0x79, 0xB7, 0x97, 0x85, 0x10, 0xB5, 0xBA, 0x3C,
    0xB6, 0x70, 0xD0, 0x06, 0xA1, 0xFA, 0x81, 0x82,
    0x83, 0x7E, 0x7F, 0x80, 0x96, 0x73, 0xBE, 0x56,
    0x9B, 0x9E, 0x95, 0xD9, 0xF7, 0x02, 0xB9, 0xA4,
    0xDE, 0x6A, 0x32, 0x6D, 0xD8, 0x8A, 0x84, 0x72,
    0x2A, 0x14, 0x9F, 0x88, 0xF9, 0xDC, 0x89, 0x9A,
    0xFB, 0x7C, 0x2E, 0xC3, 0x8F, 0xB8, 0x65, 0x48,
    0x26, 0xC8, 0x12, 0x4A, 0xCE, 0xE7, 0xD2, 0x62,
    0x0C, 0xE0, 0x1F, 0xEF, 0x11, 0x75, 0x78, 0x71,
    0xA5, 0x8E, 0x76, 0x3D, 0xBD, 0xBC, 0x86, 0x57,
    0x0B, 0x28, 0x2F, 0xA3, 0xDA, 0xD4, 0xE4, 0x0F,
    0xA9, 0x27, 0x53, 0x04, 0x1B, 0xFC, 0xAC, 0xE6,
    0x7A, 0x07, 0xAE, 0x63, 0xC5, 0xDB, 0xE2, 0xEA,
    0x94, 0x8B, 0xC4, 0xD5, 0x9D, 0xF8, 0x90, 0x6B,
    0xB1, 0x0D, 0xD6, 0xEB, 0xC6, 0x0E, 0xCF, 0xAD,
    0x08, 0x4E, 0xD7, 0xE3, 0x5D, 0x50, 0x1E, 0xB3,
    0x5B, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8C,
    0xDD, 0x9C, 0x7D, 0xA0, 0xCD, 0x1A, 0x41, 0x1C
};

static uint8_t r_con[11] =
{
    0x00, // Unused
    0x01, 0x02,0x04, 0x08, 0x10, 
    0x20, 0x40, 0x80, 0x1B, 0x36
};

static uint8_t mix_columns_value[4][4] =
{
    { 0x02, 0x03, 0x01, 0x01 },
    { 0x01, 0x02, 0x03, 0x01 },
    { 0x01, 0x01, 0x02, 0x03 },
    { 0x03, 0x01, 0x01, 0x02 }
};

static uint8_t inv_mix_columns_value[4][4] =
{
    { 0x0E, 0x0B, 0x0D, 0x09 },
    { 0x09, 0x0E, 0x0B, 0x0D },
    { 0x0D, 0x09, 0x0E, 0x0B },
    { 0x0B, 0x0D, 0x09, 0x0E }
};

static uint8_t gf256_mul(uint8_t a, uint8_t b)
{
    uint8_t p {};
    for (uint8_t i {}; i < 8; i++)
    {
        if (b & 1)
            p ^= a;

        bool hi = a & 0x80;

        a <<= 1;
        if (hi)
            // AES polynomial
            a ^= 0x1B;
        b >>= 1;
    }
    return p;
}

static inline uint8_t gf256_inverse(uint8_t n)
{
    return gf256_inv_lookup[n];
}

static inline uint8_t parity8(uint8_t x)
{
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return x & 1;
}

static uint8_t sub_bytes(uint8_t n)
{
    n = gf256_inverse(n);

    static const uint8_t mat[8] =
    {
        0xF1, 0xE3, 0xC7, 0x8F,
        0x1F, 0x3E, 0x7C, 0xF8
    };
    const uint8_t c = 0x63;

    uint8_t res {};
    for (uint8_t i {}; i < 8; i++) {
        uint8_t bit { static_cast<uint8_t>(parity8(n & mat[i]) ^ ((c >> i) & 1)) };
        res |= bit << i;
    }

    return res;
}

static uint8_t inv_affine(uint8_t x)
{
    uint8_t y = 0;
    const uint8_t d = 0x05;

    for (uint8_t i = 0; i < 8; ++i)
    {
        uint8_t bit =
            // ((x >> i) & 1) ^
            ((x >> ((i + 2) & 7)) & 1) ^
            ((x >> ((i + 5) & 7)) & 1) ^
            ((x >> ((i + 7) & 7)) & 1) ^
            ((d >> i) & 1);

        y |= bit << i;
    }

    return y;
}

static inline uint8_t inv_sub_bytes(uint8_t n)
{
    return gf256_inverse(inv_affine(n));
}

static uint32_t word_from_bytes(uint8_t bytes[4])
{
    return
        (static_cast<uint32_t>(bytes[0]) << 24) |
        (static_cast<uint32_t>(bytes[1]) << 16) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        (static_cast<uint32_t>(bytes[3]));
}

static uint32_t word_rotation(uint32_t word)
{
    uint8_t b0 { static_cast<uint8_t>((word >> 24) & 0x000000FF) };
    return (word << 8) | b0;
}

static uint32_t word_sub_bytes(uint32_t word)
{
    uint8_t bytes[] = 
    {
        sub_bytes(static_cast<uint8_t>((word >> 24) & 0x000000FF)),
        sub_bytes(static_cast<uint8_t>((word >> 16) & 0x000000FF)),
        sub_bytes(static_cast<uint8_t>((word >> 8) & 0x000000FF)),
        sub_bytes(static_cast<uint8_t>(word & 0x000000FF))
    };
    return word_from_bytes(bytes);
}

static uint32_t word_r_con(uint64_t index)
{
    return static_cast<uint32_t>(r_con[index]) << 24;
}

static std::vector<uint32_t> key_expansion(const std::vector<uint8_t>& key, uint8_t rounds_count)
{
    uint64_t total_words = 4 * (rounds_count + 1);
    uint64_t nk = key.size() * 8 / 32;

    std::vector<uint32_t> words;
    words.resize(total_words);
    for (uint8_t i {}; i < nk; ++i)
    {
        uint8_t bytes[] =
        {
            key[(i * 4)],
            key[(i * 4) + 1],
            key[(i * 4) + 2],
            key[(i * 4) + 3]
        };
        uint32_t word { word_from_bytes(bytes) };
        words[i] = word;
    }

    for (uint64_t i { nk }; i < total_words; ++i)
    {
        if (i % nk == 0)
            words[i] = words[i - nk] ^ word_sub_bytes(word_rotation(words[i - 1])) ^ word_r_con(i / nk);
        else if (nk > 6 && i % nk == 4)
            words[i] = words[i - nk] ^ word_sub_bytes(words[i - 1]);
        else
            words[i] = words[i - nk] ^ words[i - 1];
    }

    return words;
}

static void mat_sub_bytes(uint8_t state[4][4])
{
    for (uint8_t i {}; i < 4; ++i)
        for (uint8_t j {}; j < 4; ++j)
            state[i][j] = sub_bytes(state[i][j]);
}

static void mat_inv_sub_bytes(uint8_t state[4][4])
{
    for (uint8_t i {}; i < 4; ++i)
        for (uint8_t j {}; j < 4; ++j)
            state[i][j] = inv_sub_bytes(state[i][j]);
}

static void mat_round_key(uint8_t state[4][4], uint8_t r_key[4][4])
{
    for (uint8_t i {}; i < 4; ++i)
        for (uint8_t j {}; j < 4; ++j)
            state[i][j] ^= r_key[i][j];
}

static void shift_rows(uint8_t state[4][4])
{
    uint8_t tmp0 { state[1][0] };
    uint8_t tmp1 { state[1][1] };
    uint8_t tmp2 { state[1][2] };
    uint8_t tmp3 { state[1][3] };
    state[1][0] = tmp1;
    state[1][1] = tmp2;
    state[1][2] = tmp3;
    state[1][3] = tmp0;

    tmp0 = state[2][0];
    tmp1 = state[2][1];
    tmp2 = state[2][2];
    tmp3 = state[2][3];
    state[2][0] = tmp2;
    state[2][1] = tmp3;
    state[2][2] = tmp0;
    state[2][3] = tmp1;

    tmp0 = state[3][0];
    tmp1 = state[3][1];
    tmp2 = state[3][2];
    tmp3 = state[3][3];
    state[3][0] = tmp3;
    state[3][1] = tmp0;
    state[3][2] = tmp1;
    state[3][3] = tmp2;
}

static void inv_shift_rows(uint8_t state[4][4])
{
    uint8_t tmp0 { state[1][0] };
    uint8_t tmp1 { state[1][1] };
    uint8_t tmp2 { state[1][2] };
    uint8_t tmp3 { state[1][3] };
    state[1][0] = tmp3;
    state[1][1] = tmp0;
    state[1][2] = tmp1;
    state[1][3] = tmp2;

    tmp0 = state[2][0];
    tmp1 = state[2][1];
    tmp2 = state[2][2];
    tmp3 = state[2][3];
    state[2][0] = tmp2;
    state[2][1] = tmp3;
    state[2][2] = tmp0;
    state[2][3] = tmp1;

    tmp0 = state[3][0];
    tmp1 = state[3][1];
    tmp2 = state[3][2];
    tmp3 = state[3][3];
    state[3][0] = tmp1;
    state[3][1] = tmp2;
    state[3][2] = tmp3;
    state[3][3] = tmp0;
}

static void mix_columns(uint8_t state[4][4])
{
    for (uint8_t j {}; j < 4; ++j)
    {
        uint8_t s0 = state[0][j];
        uint8_t s1 = state[1][j];
        uint8_t s2 = state[2][j];
        uint8_t s3 = state[3][j];

        for (uint8_t i {}; i < 4; ++i)
        {
            state[i][j] =
                gf256_mul(mix_columns_value[i][0], s0) ^
                gf256_mul(mix_columns_value[i][1], s1) ^
                gf256_mul(mix_columns_value[i][2], s2) ^
                gf256_mul(mix_columns_value[i][3], s3);
        }
    }
}

static void inv_mix_columns(uint8_t state[4][4])
{
    for (uint8_t j = 0; j < 4; ++j)
    {
        uint8_t s0 = state[0][j];
        uint8_t s1 = state[1][j];
        uint8_t s2 = state[2][j];
        uint8_t s3 = state[3][j];

        for (uint8_t i = 0; i < 4; ++i)
        {
            state[i][j] =
                gf256_mul(inv_mix_columns_value[i][0], s0) ^
                gf256_mul(inv_mix_columns_value[i][1], s1) ^
                gf256_mul(inv_mix_columns_value[i][2], s2) ^
                gf256_mul(inv_mix_columns_value[i][3], s3);
        }
    }
}

namespace crypto::aes
{
    std::vector<uint8_t> encrypt_message(const key& key, const std::string& plain_text, algorithm algorithm)
    {
        uint8_t total_round {};
        switch (algorithm)
        {
            case algorithm::AES128:
                if (key.symmetric_key.bit_count() != 128)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 10;
                break;
            case algorithm::AES192:
                if (key.symmetric_key.bit_count() != 192)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 12;
                break;
            case algorithm::AES256:
                if (key.symmetric_key.bit_count() != 256)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 14;
                break;
            default:
                break;
        }

        // PKCS padding
        std::vector<uint8_t> input(plain_text.begin(), plain_text.end());
        uint64_t padding_size { 16 - (input.size() % 16) };
        for (uint64_t i {}; i < padding_size; ++i)
            input.push_back(static_cast<uint8_t>(padding_size));

        std::vector<uint32_t> round_keys { key_expansion(key.symmetric_key.get_byte_array(true), total_round) };
        std::vector<uint8_t> res;

        for (uint64_t block {}; block < input.size() / 16; ++block)
        {
            uint8_t state[4][4] = {};
            for (uint8_t i {}; i < 16; ++i)
            {
                uint8_t row = i % 4;
                uint8_t col = i / 4;
                state[row][col] = input[i + (block * 16)];
            }

            for (uint8_t round {}; round <= total_round; ++round)
            {
                uint8_t r_key[4][4] = {};
                for (uint8_t i {}; i < 16; ++i)
                {
                    uint8_t row = i % 4;
                    uint8_t col = i / 4;
                    r_key[row][col] = (round_keys[(round * 4) + col] >> (24 - 8 * row)) & 0xFF;
                }

                if (round == 0)
                {
                    mat_round_key(state, r_key);
                }
                else if (round < total_round)
                {
                    mat_sub_bytes(state);
                    shift_rows(state);
                    mix_columns(state);
                    mat_round_key(state, r_key);
                }
                else
                {
                    mat_sub_bytes(state);
                    shift_rows(state);
                    mat_round_key(state, r_key);
                }
            }

            for (uint8_t i {}; i < 4; ++i)
                for (uint8_t j {}; j < 4; ++j)
                    res.push_back(state[j][i]);
        }

        return res;
    }

    std::string decrypt_message(const key& key, const std::vector<uint8_t>& chiper_text, algorithm algorithm)
    {
        uint8_t total_round {};
        switch (algorithm)
        {
            case algorithm::AES128:
                if (key.symmetric_key.bit_count() != 128)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 10;
                break;
            case algorithm::AES192:
                if (key.symmetric_key.bit_count() != 192)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 12;
                break;
            case algorithm::AES256:
                if (key.symmetric_key.bit_count() != 256)
                    throw std::runtime_error("[AES] Wrong key size");
                total_round = 14;
                break;
            default:
                break;
        }

        std::vector<uint32_t> round_keys { key_expansion(key.symmetric_key.get_byte_array(true), total_round) };
        std::vector<uint8_t> res;

        for (uint64_t block {}; block < chiper_text.size() / 16; ++block)
        {
            uint8_t state[4][4] = {};
            for (uint8_t i {}; i < 16; ++i)
            {
                uint8_t row = i % 4;
                uint8_t col = i / 4;
                state[row][col] = chiper_text[i + (block * 16)];
            }

            for (int8_t round { static_cast<int8_t>(total_round) }; round >= 0; --round)
            {
                uint8_t r_key[4][4] = {};
                for (uint8_t i {}; i < 16; ++i)
                {
                    uint8_t row = i % 4;
                    uint8_t col = i / 4;
                    r_key[row][col] = (round_keys[(round * 4) + col] >> (24 - 8 * row)) & 0xFF;
                }

                if (round == total_round)
                {
                    mat_round_key(state, r_key);
                }
                else if (round > 0)
                {
                    inv_shift_rows(state);
                    mat_inv_sub_bytes(state);
                    mat_round_key(state, r_key);
                    inv_mix_columns(state);
                }
                else
                {
                    inv_shift_rows(state);
                    mat_inv_sub_bytes(state);
                    mat_round_key(state, r_key);
                }
            }

            for (uint8_t i {}; i < 4; ++i)
                for (uint8_t j {}; j < 4; ++j)
                    res.push_back(state[j][i]);
        }

        uint8_t padding { res.back() };

        if (padding == 0 || padding > 16)
            throw std::runtime_error("[AES] Invalid padding");

        for (uint8_t i {}; i < padding; ++i)
        {
            if (res[res.size() - 1 - i] != padding)
                throw std::runtime_error("Invalid padding");
        }
        std::string res_s { utils::vector_to_string(res) };
        return res_s.substr(0, res_s.size() - padding);
    }
}
