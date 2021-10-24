#pragma once

/* Includes */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

/* Types */

typedef uint8_t MS_UByte;

typedef uintptr_t MS_UPtr;

typedef uint32_t MS_USize;

typedef enum
{
    /* nothing to free, or there's a condition preventing the process */
    MS_FREE_NO = 0,

    /* the data was found present and then freed */
    MS_FREE_YES
} MS_Free;

typedef enum
{
    /* won't be reached unless UTIL_UNSAFE_OPTIMIZATIONS is off */

    /* passed data was NULL */
    MS_BUILD_STATUS_NO_DATA = 0,

    /* data len was 0 */
    MS_BUILD_STATUS_SHORT_DATA,

    /* */

    /* generation has succeeded, status was set to OK */
    MS_BUILD_STATUS_OK
} MS_BuildStatus;

typedef struct MS_Pattern
{
    MS_UByte *     m_data;
    MS_USize       m_size;
    MS_BuildStatus m_status;
} MS_Pattern;

/* Methods */

/**
 * @brief Generate byte code array from byte-code style string
 *
 * @param data Example: "AA BB CC DD EE FF", equivalent to
 * (MS_UByte*)"\xAA\xBB\xCC\xDD\xEE\xFF"
 * @param data_size Size of 'data'
 * @return Refer to MS_Pattern for documentation
 */
extern MS_Pattern
util_build_pattern(const char *data, const MS_USize data_size);

/**
 * @brief Deallocate pattern array after usage
 *
 * @param pattern Reference to the pattern construct
 * @return Refer to MS_Free for documentation
 */
extern MS_Free
util_free_pattern(MS_Pattern *pattern);

/**
 * @brief Convert pointer in numerical form to byteset of MEMSCAN_BYTESET_SIZE
 * bytes
 *
 * @param num Value to convert
 * @param swap_endianness Whether to swap endianness or not
 * @return Value as a MEMSCAN_BYTESET_SIZE bytes array
 */
extern MS_UByte *
util_ptr_to_byteset(const MS_UPtr num, bool swap_endianness);

/* Constants */

#define MEMSCAN_BYTESET_SIZE (sizeof(MS_UPtr) / sizeof(MS_UByte))

#define MEMSCAN_POINTER_BITS (sizeof(MS_UPtr) * CHAR_BIT)