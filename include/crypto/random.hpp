#pragma once

#include <cstdint>

/**
 * \namespace crypto::rng
 * @brief Function for generating random numbers with different sizes.
 */
namespace crypto::rng
{
    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT64_MAX.
     * @return A random number.
     */
    uint64_t generate_u64();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT64_MIN and @c INT64_MAX.
     * @return A random number.
     */
    int64_t generate_i64();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT32_MAX.
     * @return A random number.
     */
    uint32_t generate_u32();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT32_MIN and @c INT32_MAX.
     * @return A random number.
     */
    int32_t generate_i32();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT16_MAX.
     * @return A random number.
     */
    uint16_t generate_u16();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT16_MAX and @c INT16_MAX.
     * @return A random number.
     */
    int16_t generate_i16();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c 0 and @c UINT8_MAX.
     * @return A random number.
     */
    uint8_t generate_u8();

    /**
     * @brief Function to generate a random unsigned intger of 64 bit between @c INT8_MAX and @c INT8_MAX.
     * @return A random number.
     */
    int8_t generate_i8();
}
