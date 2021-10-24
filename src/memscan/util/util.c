#include "util.h"
#include <stdlib.h>
#include <string.h>

MS_Pattern
util_build_pattern(const char *data, const MS_USize data_size)
{
    MS_Pattern result = {0};

    result.m_data = NULL;
    result.m_size = 0;

#if !UTIL_UNSAFE_OPTIMIZATIONS
    if (data == NULL)
    {
        result.m_status = MS_BUILD_STATUS_NO_DATA;

        goto leave;
    }
#endif

    size_t len = data_size;

#if !UTIL_UNSAFE_OPTIMIZATIONS
    if (len == 0)
    {
        result.m_status = MS_BUILD_STATUS_SHORT_DATA;
        goto leave;
    }
#endif

    /* data */

    char *start = (char *)data;
    char *end   = (char *)(data + len);

    /* precompute allocation size */

    MS_USize size = 0;

    for (char *current = start; current < end; ++current)
    {
        ++size;
    }

    MS_UByte *bytes = (MS_UByte *)malloc(size * sizeof *bytes);

    /* prefetched */

    MS_USize indice = 0;

    for (char *current = start; current < end; ++current)
    {
        /* hex substring conversion */

        bytes[indice++] = strtoul(current, &current, 16);
    }

    result.m_data   = bytes;
    result.m_size   = indice;
    result.m_status = MS_BUILD_STATUS_OK;

leave:
    return result;
}

/* */

MS_Free
util_free_pattern(MS_Pattern *pattern)
{
#if !UTIL_UNSAFE_OPTIMIZATIONS
    if (pattern == NULL)
    {
        return MS_FREE_NO;
    }
#endif

    MS_Free result = MS_FREE_NO;

    if (pattern->m_status == MS_BUILD_STATUS_OK)
    {
        free(pattern->m_data);
        pattern->m_data = NULL;

        result = MS_FREE_YES;
    }

    pattern->m_size = 0;

    return result;
}

MS_UByte *
util_ptr_to_byteset(const MS_UPtr num, bool swap_endianness)
{
    /* data */

    static MS_UByte bytes[MEMSCAN_BYTESET_SIZE] = {0};

    for (MS_USize i = 0; i < MEMSCAN_BYTESET_SIZE; ++i)
    {
        /* shift formation to get current indice */

        bytes[swap_endianness ? i : MEMSCAN_BYTESET_SIZE - i - 1] =
            (MS_UByte)(num >> (i * CHAR_BIT));
    }

    return bytes;
}