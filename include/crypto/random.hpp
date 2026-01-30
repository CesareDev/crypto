#pragma once

#include <cstdint>

/**
 * \namespace crypto::rng
 * @brief Function for generating random numbers with different sizes.
 */
namespace crypto::rng
{
    /**
     * @brief Reseed the random engine.
     */
    void reseed();

    /**
     * @brief Reseed the random engine with a custom seed.
     * @param seed The seed for the engine.
     */
    void reseed(uint64_t seed);

    /**
     * @brief Function to generate a random double between @c 0 and @c 1.
     * @return A random number.
     */
    double uniform();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT64_MAX.
     * @return A random number.
     */
    uint64_t u64();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT64_MIN and @c INT64_MAX.
     * @return A random number.
     */
    int64_t i64();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT32_MAX.
     * @return A random number.
     */
    uint32_t u32();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT32_MIN and @c INT32_MAX.
     * @return A random number.
     */
    int32_t i32();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT16_MAX.
     * @return A random number.
     */
    uint16_t u16();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT16_MAX and @c INT16_MAX.
     * @return A random number.
     */
    int16_t i16();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT8_MAX.
     * @return A random number.
     */
    uint8_t u8();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT8_MAX and @c INT8_MAX.
     * @return A random number.
     */
    int8_t i8();
}
