#include <random>

#include <crypto/random.hpp>

static thread_local std::mt19937_64 engine(std::random_device{}());

namespace crypto::rng
{
    void reseed()
    {
        std::random_device rd;
        std::seed_seq seq
        {
            rd(), rd(), rd(), rd(),
            rd(), rd(), rd(), rd(),
        };
        engine.seed(seq);
    }

    void reseed(uint64_t seed)
    {
        engine.seed(seed);
    }

    double uniform()
    {
        static thread_local std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(engine);
    }

    uint64_t u64()
    {
        static thread_local std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
        return dist(engine);
    }

    int64_t i64()
    {
        static thread_local std::uniform_int_distribution<int64_t> dist(INT64_MIN, INT64_MAX);
        return dist(engine);
    }

    uint32_t u32()
    {
        static thread_local std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);
        return dist(engine);
    }

    int32_t i32()
    {
        static thread_local std::uniform_int_distribution<int32_t> dist(INT32_MIN, INT32_MAX);
        return dist(engine);
    }

    uint16_t u16()
    {
        static thread_local std::uniform_int_distribution<uint16_t> dist(0, UINT16_MAX);
        return dist(engine);
    }

    int16_t i16()
    {
        static thread_local std::uniform_int_distribution<int16_t> dist(INT16_MIN, INT16_MAX);
        return dist(engine);
    }

    uint8_t u8()
    {
        static thread_local std::uniform_int_distribution<uint16_t> dist(0, UINT8_MAX);
        return static_cast<uint8_t>(dist(engine));
    }

    int8_t i8()
    {
        static thread_local std::uniform_int_distribution<int16_t> dist(INT8_MIN, INT8_MAX);
        return static_cast<int8_t>(dist(engine));
    }
}
