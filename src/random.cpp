#include <random>
#include <chrono>

#include <crypto/random.hpp>

namespace crypto::rng
{
    uint64_t generate_u64()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(0, UINT64_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    int64_t generate_i64()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(INT64_MIN, INT64_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    uint32_t generate_u32()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(0, UINT32_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    int32_t generate_i32()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(INT32_MIN, INT32_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    uint16_t generate_u16()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(0, UINT16_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    int16_t generate_i16()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(INT16_MIN, INT16_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    uint8_t generate_u8()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(0, UINT8_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }

    int8_t generate_i8()
    {
        std::random_device dev;
        std::mt19937 rng(dev());
        auto seed1 { std::uniform_int_distribution<std::mt19937::result_type>(INT8_MIN, INT8_MAX)(rng) };
        auto seed2 { std::chrono::steady_clock::now().time_since_epoch().count() };
        return seed1 ^ seed2;
    }
}
