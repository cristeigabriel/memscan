#include "memscan.h"

/* Types */

typedef struct MS_Bytes
{
    /* example: {0x55, 0x8B, 0xEC} */
    const MS_UByte *m_data;

    /* the former will result in '3' */
    MS_USize m_size;

    /* the n-th instance of a pattern within range, 0 - first */
    MS_USize m_match;
} MS_Bytes;

typedef struct MS_BytesStr
{
    /* "55 8B EC" => MS_Bytes({0x55, 0x8B, 0xEC}, 3, match)
     *  must be null terminated */
    const char *m_data;

    /* the n-th instance of a pattern within range, 0 - first */
    MS_USize m_match;
} MS_BytesStr;

typedef struct MS_FindBytes
{
    /* example: {0x8B, 0x0D} */
    const MS_UByte *m_data;

    /* the former will result in '3' */
    MS_USize m_size;

    /* the n-th instance of a match within range, 0 - first */
    MS_USize m_match;

    MS_FollowDirection m_direction;
} MS_FindBytes;

typedef struct MS_FindStr
{
    /* "8B 0C" => MS_FindBytes({0x8B, 0x0C}, 2, match, direction)
     *  must be null terminated */
    const char *m_data;

    /* the n-th instance of a match within range, 0 - first */
    MS_USize m_match;

    MS_FollowDirection m_direction;
} MS_FindStr;

typedef struct MS_Xref
{
    /* numerical form of pointer to look for */
    MS_UPtr m_pointer;

    /* the n-th instance of a match within range, 0 - first */
    MS_USize m_match;

    bool m_swap_endianness;
} MS_Xref;

typedef struct MS_StringXref
{
    /* the string to look for */
    const char *m_data;

    /* string size */
    MS_USize m_size;

    /* the n-th instance of the reversed endianness address to the first
     * character of the string, 0 - first */
    MS_USize m_match;
} MS_StringXref;

typedef enum
{
    /* won't be reached if MEMSCAN_UNSAFE_OPTIMIZATIONS are on */

    MS_FOLLOW_STATUS_NO_VALID_FOLLOW_INFO = 0,

    /* */

    /* overbounds on start */
    MS_FOLLOW_STATUS_FAIL_LHS,

    /* overbounds on end */
    MS_FOLLOW_STATUS_FAIL_RHS,

    /* broke before reaching match */
    MS_FOLLOW_STATUS_INCOMPLETE,

    /* follow has succeeded, state was set to OK */
    MS_FOLLOW_STATUS_OK
} MS_FollowStatus;

typedef struct MS_Follow
{
    MS_UPtr         m_address;
    MS_FollowStatus m_status;
} MS_Follow;

/* Methods */

/* Static */

static MS_Follow
follow_until(const MS_UPtr copy, const MS_UPtr start, const MS_UPtr end,
             const MS_FindBytes *restrict find_bytes)
{
    /* data */

    MS_Follow result = {0};

    MS_UPtr address = copy;

#if !MEMSCAN_UNSAFE_OPTIMIZATIONS
    if (find_bytes == NULL ||
        (find_bytes != NULL &&
         (find_bytes->m_data == NULL || find_bytes->m_size == 0)))
    {
        result.m_address = 0;
        result.m_status  = MS_FOLLOW_STATUS_NO_VALID_FOLLOW_INFO;

        goto return_label;
    }
#endif

    /* the following will run at least once, so you can follow regardless of
     * current address. it will break upon a NULL address, or after the first
     * overbounds byte, or upon a match in memory. */

    MS_USize match = MEMSCAN_FIRST_MATCH;

    int status;

retry_label:
    status = -1;

    do
    {
        status =
            memcmp((void *)address, find_bytes->m_data, find_bytes->m_size);

        address +=
            find_bytes->m_direction == MS_FOLLOW_DIRECTION_BACKWARDS ? -1 : 1;
    } while ((void *)address != NULL && address >= (start - 1) &&
             address <= (end + 1) && status != 0);

    /* the address will be at least copy +/- 1 */

    result.m_address = address - 1;

    /* if the address is smaller than start, then it is overbounds on the lhs,
     * otherwise, if it is smaller than end, it is overbounds no the rhs,
     * otherwise, if status is != 0, it is OK, otherwise, it is an incomplete
     * follow */

    result.m_status = (result.m_address < start
                           ? MS_FOLLOW_STATUS_FAIL_LHS
                           : (result.m_address > end
                                  ? MS_FOLLOW_STATUS_FAIL_RHS
                                  : (status != 0 ? MS_FOLLOW_STATUS_INCOMPLETE
                                                 : MS_FOLLOW_STATUS_OK)));

    /* verify match */

    if (match != find_bytes->m_match && result.m_status == MS_FOLLOW_STATUS_OK)
    {
        ++match;
        goto retry_label;
    }

return_label:
    return result;
}

/* */

static MS_Result
memscan_find_pattern_bb_impl(const MS_UPtr start, const MS_UPtr end,
                             const MS_Bytes *restrict bytes,
                             const MS_FindBytes *restrict find_bytes)
{
    MS_Result result = {0};

    result.m_address = 0;

#if !MEMSCAN_UNSAFE_OPTIMIZATIONS
    if (bytes == NULL || (bytes && bytes->m_data == NULL))
    {
        result.m_status = MS_RESULT_NO_VALID_BYTES_INFO;

        goto return_label;
    }
#endif

    /* data */

    /* this value is meant to be used to deduce how many actual bytes were input
     * to the formation, scaling to every platform's sizeof(unsigned char) */

    const MS_USize bytes_len = bytes->m_size / sizeof *bytes->m_data;

    /* here, bytes->m_size is used because we're doing pointer arithmetic */

    const MS_UByte *finish = (MS_UByte *)(end - bytes->m_size);

    MS_USize match = MEMSCAN_FIRST_MATCH;

#if !MEMSCAN_UNSAFE_OPTIMIZATIONS
    if (start >= (MS_UPtr)finish)
    {
        result.m_status = MS_RESULT_NO_VALID_SPAN;

        goto return_label;
    }
#endif

    /* loop over every byte from start to end */

    for (MS_UByte *current = (MS_UByte *)start; current < finish; ++current)
    {
        MS_ResultStatus status = MS_RESULT_STATUS_FOUND;

        /* run a scan from current byte to current byte + bytes_len to verify if
         * we have a match */

        for (MS_USize walker = 0; walker < bytes_len; ++walker)
        {
            /* if the current byte at walker indice isn't equal to the current
             * signature byte if it isn't our wildcard */

            if (current[walker] != bytes->m_data[walker] &&
                bytes->m_data[walker] != k_memscan_wildcard)
            {
                /* declare the state as not found for the current iteration
                 * and go to the next one */

                status = MS_RESULT_STATUS_NOT_FOUND;
                break;
            }
        }

        /* if the state wasn't altered (as in, the checks have passed and the
         * current byte matches our signature) */

        if (status == MS_RESULT_STATUS_FOUND)
        {
            /* verify n-th match */

            if (match != bytes->m_match)
            {
                ++match;
                continue;
            }

            /* pass our address and status to result */

            result.m_address = (MS_UPtr)current;
            result.m_status  = status;

            /* attempt a follow */

            const MS_Follow follow =
                follow_until(result.m_address, start, end, find_bytes);

            switch (follow.m_status)
            {
                case MS_FOLLOW_STATUS_OK:
                {
                    /* change the result address to the follow result,
                     * started from the original one */

                    result.m_address = follow.m_address;
                }
                break;

                case MS_FOLLOW_STATUS_FAIL_LHS:
                case MS_FOLLOW_STATUS_FAIL_RHS:
                {
                    /* this is prioritized over MS_FOLLOW_STATUS_INCOMPLETE */

                    /* deduce if it was either a left side overbounds
                     * failure or right side overbounds failure for the
                     * possibility of still allowing a result depending on
                     * user response */

                    result.m_status =
                        follow.m_status == MS_FOLLOW_STATUS_FAIL_LHS
                            ? MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_LHS
                            : MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_RHS;
                }
                break;

                case MS_FOLLOW_STATUS_INCOMPLETE:
                {
                    /* a condition to break the follow was met before there was
                     * a match in memory between the seeked byte-code and the
                     * byte-code at from it's current address for the seeked
                     * byte-code length */

                    result.m_status =
                        MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_INCOMPLETE;
                }
                break;
            }

            goto return_label;
        }
    }

    /* we haven't found an address for our signature, so we will set result
     * state to NOT FOUND */

    result.m_status = MS_RESULT_STATUS_NOT_FOUND;

return_label:
    return result;
}

/* */

static MS_Result
memscan_find_pattern_bs_impl(const MS_UPtr start, const MS_UPtr end,
                             const MS_Bytes *restrict bytes,
                             const MS_FindStr *restrict find_bytes)
{
    MS_Result result = {0};
    result.m_address = 0;

    if (find_bytes == NULL)
    {
        result = memscan_find_pattern_bb_impl(start, end, bytes, NULL);
    }
    else
    {
        /* data */

        MS_Pattern pattern =
            util_build_pattern(find_bytes->m_data, strlen(find_bytes->m_data));

        MS_FindBytes find_bytes_from_str = {0};
        find_bytes_from_str.m_data       = pattern.m_data;
        find_bytes_from_str.m_size       = pattern.m_size;
        find_bytes_from_str.m_match      = find_bytes->m_match;
        find_bytes_from_str.m_direction  = find_bytes->m_direction;

        /* pass converted data to base implementation */

        result = memscan_find_pattern_bb_impl(start, end, bytes,
                                              &find_bytes_from_str);

        util_free_pattern(&pattern);
    }

    return result;
}

/* */

static MS_Result
memscan_find_pattern_sb_impl(const MS_UPtr start, const MS_UPtr end,
                             const MS_BytesStr *restrict bytes,
                             const MS_FindBytes *restrict find_bytes)
{
    MS_Result result = {0};
    result.m_address = 0;

    if (bytes == NULL || (bytes && bytes->m_data == NULL))
    {
        result = memscan_find_pattern_bb_impl(start, end, NULL, find_bytes);
    }
    else
    {
        /* data */

        MS_Pattern pattern =
            util_build_pattern(bytes->m_data, strlen(bytes->m_data));

        MS_Bytes bytes_from_str = {0};
        bytes_from_str.m_data   = pattern.m_data;
        bytes_from_str.m_size   = pattern.m_size;
        bytes_from_str.m_match  = bytes->m_match;

        /* pass converted data to base implementation */

        result = memscan_find_pattern_bb_impl(start, end, &bytes_from_str,
                                              find_bytes);

        util_free_pattern(&pattern);
    }

    return result;
}

/* */

static MS_Result
memscan_find_pattern_ss_impl(const MS_UPtr start, const MS_UPtr end,
                             const MS_BytesStr *restrict bytes,
                             const MS_FindStr *restrict find_bytes)
{

    MS_Result result = {0};
    result.m_address = 0;

    if (find_bytes == NULL)
    {
        result = memscan_find_pattern_sb_impl(start, end, bytes, NULL);
    }
    else
    {
        /* data */

        MS_Pattern find_pattern =
            util_build_pattern(find_bytes->m_data, strlen(find_bytes->m_data));

        MS_FindBytes find_bytes_from_str = {0};
        find_bytes_from_str.m_data       = find_pattern.m_data;
        find_bytes_from_str.m_size       = find_pattern.m_size;
        find_bytes_from_str.m_match      = find_bytes->m_match;
        find_bytes_from_str.m_direction  = find_bytes->m_direction;

        /* pass data to our string, bytes wrapper */

        result = memscan_find_pattern_sb_impl(start, end, bytes,
                                              &find_bytes_from_str);

        util_free_pattern(&find_pattern);
    }

    return result;
}

/* */

static MS_Result
memscan_find_pattern_nfb_impl(const MS_UPtr start, const MS_UPtr end,
                              const MS_Bytes *restrict bytes)
{
    /* pass data to our base implementation. the data being NULL
     * will prevent a follow from happening */

    return memscan_find_pattern_bb_impl(start, end, bytes, NULL);
}

/* */

static MS_Result
memscan_find_pattern_nfs_impl(const MS_UPtr start, const MS_UPtr end,
                              const MS_BytesStr *restrict bytes)
{
    /* pass data to our string, bytes wrapper. the data being NULL
     * will prevent a follow from happening */

    return memscan_find_pattern_sb_impl(start, end, bytes, NULL);
}

/* */

static MS_Result
memscan_find_xref_b_impl(const MS_UPtr start, const MS_UPtr end,
                         const MS_Xref *restrict xref,
                         const MS_FindBytes *restrict find_bytes)
{
    MS_Result result = {0};

    result.m_address = 0;

#if !MEMSCAN_UNSAFE_OPTIMIZATIONS
    if (xref == NULL /* data is handled in the pattern finder */)
    {
        result.m_status = MS_RESULT_NO_VALID_BYTES_INFO;
        goto return_label;
    }
#endif

    /* data */

    MS_Bytes from_xref = {0};

    from_xref.m_data =
        util_ptr_to_byteset(xref->m_pointer, xref->m_swap_endianness);
    from_xref.m_size  = MEMSCAN_BYTESET_SIZE;
    from_xref.m_match = xref->m_match;

    /* pass data to our no follow, bytes wrapper */

    result = memscan_find_pattern_bb_impl(start, end, &from_xref, find_bytes);

return_label:
    return result;
}

/* */

static MS_Result
memscan_find_xref_s_impl(const MS_UPtr start, const MS_UPtr end,
                         const MS_Xref *restrict xref,
                         const MS_FindStr *restrict find_bytes)
{
    MS_Result result = {0};
    result.m_address = 0;

    if (find_bytes == NULL)
    {
        result = memscan_find_xref_b_impl(start, end, xref, NULL);
    }
    else
    {
        /* data */

        MS_Pattern pattern =
            util_build_pattern(find_bytes->m_data, strlen(find_bytes->m_data));

        MS_FindBytes find_bytes_from_str = {0};
        find_bytes_from_str.m_data       = pattern.m_data;
        find_bytes_from_str.m_size       = pattern.m_size;
        find_bytes_from_str.m_match      = find_bytes->m_match;
        find_bytes_from_str.m_direction  = find_bytes->m_direction;

        result =
            memscan_find_xref_b_impl(start, end, xref, &find_bytes_from_str);

        util_free_pattern(&pattern);
    }

    return result;
}

/* */

static MS_Result
memscan_find_xref_nf_impl(const MS_UPtr start, const MS_UPtr end,
                          const MS_Xref *restrict xref)
{
    return memscan_find_xref_b_impl(start, end, xref, NULL);
}

/* */

static MS_Result
memscan_find_string_b_impl(const MS_UPtr start, const MS_UPtr end,
                           const MS_StringXref *restrict string,
                           const MS_FindBytes *restrict find_bytes)
{
    MS_Result result = {0};

    result.m_address = 0;

#if !MEMSCAN_UNSAFE_OPTIMIZATIONS
    if (string == NULL /* data is handled in the pattern finder */)
    {
        result.m_status = MS_RESULT_NO_VALID_BYTES_INFO;
        goto return_label;
    }
#endif

    /* data */

    MS_Bytes bytes = {0};

    bytes.m_data  = (const MS_UByte *)string->m_data;
    bytes.m_size  = string->m_size;
    bytes.m_match = 0;

    MS_Result string_find = memscan_find_pattern_nfb_impl(start, end, &bytes);

    if (string_find.m_status != MS_RESULT_STATUS_FOUND)
    {
        result.m_status = string_find.m_status;
        goto return_label;
    }

    MS_Xref xref = {0};

    xref.m_pointer         = string_find.m_address;
    xref.m_match           = string->m_match;
    xref.m_swap_endianness = true;

    result = memscan_find_xref_b_impl(start, end, &xref, find_bytes);

return_label:
    return result;
}

static MS_Result
memscan_find_string_s_impl(const MS_UPtr start, const MS_UPtr end,
                           const MS_StringXref *restrict string,
                           const MS_FindStr *restrict find_bytes)
{
    MS_Result result = {0};
    result.m_address = 0;

    if (find_bytes == NULL)
    {
        result = memscan_find_string_b_impl(start, end, string, NULL);
    }
    else
    {
        /* data */

        MS_Pattern pattern =
            util_build_pattern(find_bytes->m_data, strlen(find_bytes->m_data));

        MS_FindBytes find_bytes_from_str = {0};
        find_bytes_from_str.m_data       = pattern.m_data;
        find_bytes_from_str.m_size       = pattern.m_size;
        find_bytes_from_str.m_match      = find_bytes->m_match;
        find_bytes_from_str.m_direction  = find_bytes->m_direction;

        result = memscan_find_string_b_impl(start, end, string,
                                            &find_bytes_from_str);

        util_free_pattern(&pattern);
    }

    return result;
}

static MS_Result
memscan_find_string_nf_impl(const MS_UPtr start, const MS_UPtr end,
                            const MS_StringXref *restrict string)
{
    return memscan_find_string_b_impl(start, end, string, NULL);
}

/* Prototype Bodies */

MS_Result
memscan_find_pattern_bb(const MS_UPtr start, const MS_UPtr end,
                        const MS_UByte *pattern, const MS_USize pattern_size,
                        const MS_USize           pattern_nth_match,
                        const MS_UByte *         follow_pattern,
                        const MS_USize           follow_pattern_size,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction)
{
    /* data */

    MS_Bytes bytes = {0};
    bytes.m_data   = pattern;
    bytes.m_size   = pattern_size;
    bytes.m_match  = pattern_nth_match;

    MS_FindBytes find = {0};
    find.m_data       = follow_pattern;
    find.m_size       = follow_pattern_size;
    find.m_match      = follow_nth_match;
    find.m_direction  = follow_direction;

    /* pass structured data to manager */

    return memscan_find_pattern_bb_impl(start, end, &bytes, &find);
}

/* */

MS_Result
memscan_find_pattern_bs(const MS_UPtr start, const MS_UPtr end,
                        const MS_UByte *pattern, const MS_USize pattern_size,
                        const MS_USize           pattern_nth_match,
                        const char *             follow_pattern,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction)
{
    /* data */

    MS_Bytes bytes = {0};
    bytes.m_data   = pattern;
    bytes.m_size   = pattern_size;
    bytes.m_match  = pattern_nth_match;

    MS_FindStr find  = {0};
    find.m_data      = follow_pattern;
    find.m_match     = follow_nth_match;
    find.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_pattern_bs_impl(start, end, &bytes, &find);
}

/* */

MS_Result
memscan_find_pattern_sb(const MS_UPtr start, const MS_UPtr end,
                        const char *pattern, const MS_USize pattern_nth_match,
                        const MS_UByte *         follow_pattern,
                        const MS_USize           follow_pattern_size,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction)
{
    /* data */

    MS_BytesStr bytes = {0};
    bytes.m_data      = pattern;
    bytes.m_match     = pattern_nth_match;

    MS_FindBytes find = {0};
    find.m_data       = follow_pattern;
    find.m_size       = follow_pattern_size;
    find.m_match      = follow_nth_match;
    find.m_direction  = follow_direction;

    /* pass structured data to manager */

    return memscan_find_pattern_sb_impl(start, end, &bytes, &find);
}

/* */

MS_Result
memscan_find_pattern_ss(const MS_UPtr start, const MS_UPtr end,
                        const char *pattern, const MS_USize pattern_nth_match,
                        const char *             follow_pattern,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction)
{
    /* data */

    MS_BytesStr bytes = {0};
    bytes.m_data      = pattern;
    bytes.m_match     = pattern_nth_match;

    MS_FindStr find  = {0};
    find.m_data      = follow_pattern;
    find.m_match     = follow_nth_match;
    find.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_pattern_ss_impl(start, end, &bytes, &find);
}

/* */

MS_Result
memscan_find_pattern_nfb(const MS_UPtr start, const MS_UPtr end,
                         const MS_UByte *pattern, const MS_USize pattern_size,
                         const MS_USize pattern_nth_match)
{
    /* data */

    MS_Bytes bytes = {0};
    bytes.m_data   = pattern;
    bytes.m_size   = pattern_size;
    bytes.m_match  = pattern_nth_match;

    /* pass structured data to manager */

    return memscan_find_pattern_nfb_impl(start, end, &bytes);
}

/* */

MS_Result
memscan_find_pattern_nfs(const MS_UPtr start, const MS_UPtr end,
                         const char *pattern, const MS_USize pattern_nth_match)
{
    /* data */

    MS_BytesStr bytes = {0};
    bytes.m_data      = pattern;
    bytes.m_match     = pattern_nth_match;

    /* pass structured data to manager */

    return memscan_find_pattern_nfs_impl(start, end, &bytes);
}

/* */

MS_Result
memscan_find_xref_b(const MS_UPtr start, const MS_UPtr end,
                    const MS_UPtr content, const MS_USize content_nth_match,
                    bool swap_endianness, const MS_UByte *follow_pattern,
                    const MS_USize           follow_pattern_size,
                    const MS_USize           follow_nth_match,
                    const MS_FollowDirection follow_direction)
{
    /* data */

    MS_Xref xref = {0};

    xref.m_pointer         = content;
    xref.m_match           = content_nth_match;
    xref.m_swap_endianness = swap_endianness;

    MS_FindBytes find_bytes = {0};

    find_bytes.m_data      = follow_pattern;
    find_bytes.m_size      = follow_pattern_size;
    find_bytes.m_match     = follow_nth_match;
    find_bytes.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_xref_b_impl(start, end, &xref, &find_bytes);
}

/*  */

MS_Result
memscan_find_xref_at_b(const MS_UPtr start, const MS_UPtr end,
                       const MS_UPtr address, const MS_USize nth_match,
                       bool swap_endianness, const MS_UByte *follow_pattern,
                       const MS_USize           follow_pattern_size,
                       const MS_USize           follow_nth_match,
                       const MS_FollowDirection follow_direction)
{
    return memscan_find_xref_b(start, end, *(MS_UPtr *)address, nth_match,
                               swap_endianness, follow_pattern,
                               follow_pattern_size, follow_nth_match,
                               follow_direction);
}

/*  */

MS_Result
memscan_find_xref_s(const MS_UPtr start, const MS_UPtr end,
                    const MS_UPtr content, const MS_USize content_nth_match,
                    bool swap_endianness, const char *follow_pattern,
                    const MS_USize           follow_nth_match,
                    const MS_FollowDirection follow_direction)
{
    /* data */

    MS_Xref xref = {0};

    xref.m_pointer         = content;
    xref.m_match           = content_nth_match;
    xref.m_swap_endianness = swap_endianness;

    MS_FindStr find = {0};

    find.m_data      = follow_pattern;
    find.m_match     = follow_nth_match;
    find.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_xref_s_impl(start, end, &xref, &find);
}

/*  */

MS_Result
memscan_find_xref_at_s(const MS_UPtr start, const MS_UPtr end,
                       const MS_UPtr address, const MS_USize nth_match,
                       bool swap_endianness, const char *follow_pattern,
                       const MS_USize           follow_nth_match,
                       const MS_FollowDirection follow_direction)
{
    return memscan_find_xref_s(start, end, *(MS_UPtr *)address, nth_match,
                               swap_endianness, follow_pattern,
                               follow_nth_match, follow_direction);
}

/* */

MS_Result
memscan_find_xref_nf(const MS_UPtr start, const MS_UPtr end,
                     const MS_UPtr content, const MS_USize content_nth_match,
                     bool swap_endianness)
{
    /* data */

    MS_Xref xref = {0};

    xref.m_pointer         = content;
    xref.m_match           = content_nth_match;
    xref.m_swap_endianness = swap_endianness;

    /* pass structured data to manager */

    return memscan_find_xref_nf_impl(start, end, &xref);
}

/* */

MS_Result
memscan_find_xref_at_nf(const MS_UPtr start, const MS_UPtr end,
                        const MS_UPtr address, const MS_USize nth_match,
                        bool swap_endianness)
{
    return memscan_find_xref_nf(start, end, *(MS_UPtr *)address, nth_match,
                                swap_endianness);
}

/* */

extern MS_Result
memscan_find_string_b(const MS_UPtr start, const MS_UPtr end, const char *text,
                      const MS_USize text_size, const MS_USize nth_match,
                      const MS_UByte *         follow_pattern,
                      const MS_USize           follow_pattern_size,
                      const MS_USize           follow_nth_match,
                      const MS_FollowDirection follow_direction)
{
    /* data */

    MS_StringXref xref = {0};

    xref.m_data  = text;
    xref.m_size  = text_size;
    xref.m_match = nth_match;

    MS_FindBytes find_bytes = {0};

    find_bytes.m_data      = follow_pattern;
    find_bytes.m_size      = follow_pattern_size;
    find_bytes.m_match     = follow_nth_match;
    find_bytes.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_string_b_impl(start, end, &xref, &find_bytes);
}

/* */

MS_Result
memscan_find_string_s(const MS_UPtr start, const MS_UPtr end, const char *text,
                      const MS_USize text_size, const MS_USize nth_match,
                      const char *             follow_pattern,
                      const MS_USize           follow_nth_match,
                      const MS_FollowDirection follow_direction)
{
    /* data */

    MS_StringXref xref = {0};

    xref.m_data  = text;
    xref.m_size  = text_size;
    xref.m_match = nth_match;

    MS_FindStr find = {0};

    find.m_data      = follow_pattern;
    find.m_match     = follow_nth_match;
    find.m_direction = follow_direction;

    /* pass structured data to manager */

    return memscan_find_string_s_impl(start, end, &xref, &find);
}

/* */

MS_Result
memscan_find_string_nf(const MS_UPtr start, const MS_UPtr end, const char *text,
                       const MS_USize text_size, const MS_USize nth_match)
{
    /* data */

    MS_StringXref xref = {0};

    xref.m_data  = text;
    xref.m_size  = text_size;
    xref.m_match = nth_match;

    /* pass structured data to manager */

    return memscan_find_string_nf_impl(start, end, &xref);
}