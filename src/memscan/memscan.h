#pragma once

/* Includes */

#include <stdint.h>

/* Utility */

#include "util/util.h"

/* Types */

typedef enum
{
    /* the search goes backwards (substracts from current address) */
    MS_FOLLOW_DIRECTION_BACKWARDS = 0,

    /* the search goes forwards (adds to current address) */
    MS_FOLLOW_DIRECTION_FORWARDS
} MS_FollowDirection;

typedef enum
{
    /* won't be reached if MEMSCAN_UNSAFE_OPTIMIZATIONS are on */

    MS_RESULT_NO_VALID_BYTES_INFO = 0,

    /* finish <= start */
    MS_RESULT_NO_VALID_SPAN,

    /* */

    /* generic response if not found */
    MS_RESULT_STATUS_NOT_FOUND,

    /* follow led to address being < start and thus was not applied */
    MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_LHS,

    /* follow led to address being > end and thus was not applied */
    MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_RHS,

    /* broke before reaching a match in memory, the former 2 are pioritized */
    MS_RESULT_STATUS_FOUND_FOLLOW_FAIL_INCOMPLETE,

    /* pattern was found, follow has succeeded, status set to FOUND */
    MS_RESULT_STATUS_FOUND
} MS_ResultStatus;

typedef struct MS_Result
{
    MS_UPtr         m_address;
    MS_ResultStatus m_status;
} MS_Result;

/* Methods */

/* Patterns */

/**
 * @brief Bytes, Bytes pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Array of MS_UBytes to match in memory, may contain
 * [k_memscan_wildcard], which allows a mismatch at the opcode's position
 * @param pattern_size Size of pattern
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @param follow_pattern Array of MS_UBytes to look for, from pattern scan
 * address, in a specified direction. Spanned from start to end (failures to
 * meet conditions will be evidentiated in the return)
 * @param follow_pattern_size Size of follow_pattern
 * @param follow_nth_match Same as pattern_nth_match, but with the
 * follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_bb(const MS_UPtr start, const MS_UPtr end,
                        const MS_UByte *pattern, const MS_USize pattern_size,
                        const MS_USize           pattern_nth_match,
                        const MS_UByte *         follow_pattern,
                        const MS_USize           follow_pattern_size,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction);

/**
 * @brief Bytes, String pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Array of MS_UBytes to match in memory, may contain
 * [k_memscan_wildcard], which allows a mismatch at the opcode's position
 * @param pattern_size Size of pattern
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @param follow_pattern Byte-code style string that will be turned into a
 * MS_UByte array for evaluation, example: "8B 4D"
 * @param follow_nth_match Same as pattern_nth_match, but with the
 * follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_bs(const MS_UPtr start, const MS_UPtr end,
                        const MS_UByte *pattern, const MS_USize pattern_size,
                        const MS_USize           pattern_nth_match,
                        const char *             follow_pattern,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction);

/**
 * @brief String, Bytes pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Byte-code style string that will be turned into a MS_UByte
 * array for evaluation, may contain [k_memscan_wildcard], which allows a
 * mismatch at the opcode's position. example: "55 8B EC CC CC CC CC"
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @param follow_pattern Array of MS_UBytes to look for, from pattern scan
 * address, in a specified direction. Spanned from start to end (failures to
 * meet conditions will be evidentiated in the return)
 * @param follow_pattern_size Size of follow_pattern
 * @param follow_nth_match Same as pattern_nth_match, but with the
 * follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_sb(const MS_UPtr start, const MS_UPtr end,
                        const char *pattern, const MS_USize pattern_nth_match,
                        const MS_UByte *         follow_pattern,
                        const MS_USize           follow_pattern_size,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction);

/**
 * @brief String, String pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Byte-code style string that will be turned into a MS_UByte
 * array for evaluation, may contain [k_memscan_wildcard], which allows a
 * mismatch at the opcode's position. example: "55 8B EC CC CC CC CC"
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @param follow_pattern Byte-code style string that will be turned into a
 * MS_UByte array for evaluation, example: "8B 4D"
 * @param follow_nth_match Same as pattern_nth_match, but with the
 * follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_ss(const MS_UPtr start, const MS_UPtr end,
                        const char *pattern, const MS_USize pattern_nth_match,
                        const char *             follow_pattern,
                        const MS_USize           follow_nth_match,
                        const MS_FollowDirection follow_direction);

/**
 * @brief No follow, Bytes pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Array of MS_UBytes to match in memory, may contain
 * [k_memscan_wildcard], which allows a mismatch at the opcode's position
 * @param pattern_size Size of pattern
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_nfb(const MS_UPtr start, const MS_UPtr end,
                         const MS_UByte *pattern, const MS_USize pattern_size,
                         const MS_USize pattern_nth_match);

/**
 * @brief No follow, String pattern-scanning function
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + pattern_size, failure to meet this condition
 * will be evidenciated in the return)
 * @param pattern Byte-code style string that will be turned into a MS_UByte
 * array for evaluation, may contain [k_memscan_wildcard], which allows a
 * mismatch at the opcode's position. example: "55 8B EC CC CC CC CC"
 * @param pattern_nth_match N-th pattern repetition to select, starts at
 * MEMSCAN_FIRST_MATCH
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_pattern_nfs(const MS_UPtr start, const MS_UPtr end,
                         const char *pattern, const MS_USize pattern_nth_match);

/**
 * @brief Xref Bytes Follow finder from a sequence
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param content Content to find  in global address space
 * @param nth_match N-th repetition of content, starts at  MEMSCAN_FIRST_MATCH
 * @param swap_endianness Whether the content should have it's endianness
 * swapped
 * @param follow_pattern Array of MS_UBytes to look for, from xref address, in
 * a specified direction. Spanned from start to end (failures to meet conditions
 * will be evidentiated in the return)
 * @param follow_pattern_size Size of follow_pattern
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_b(const MS_UPtr start, const MS_UPtr end,
                    const MS_UPtr content, const MS_USize content_nth_match,
                    bool swap_endianness, const MS_UByte *follow_pattern,
                    const MS_USize           follow_pattern_size,
                    const MS_USize           follow_nth_match,
                    const MS_FollowDirection follow_direction);

/**
 * @brief Xref Bytes Follow finder from a reference to pointer
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param address Reference to address to find references to in global address
 * space
 * @param nth_match N-th repetition of reference to select, starts at
 * MEMSCAN_FIRST_MATCH, for clarification, matches are looked for from start,
 * not from address
 * @param swap_endianness Whether the contents at address to have their
 * endianness swapped
 * @param follow_pattern Array of MS_UBytes to look for, from xref address, in
 * a specified direction. Spanned from start to end (failures to meet conditions
 * will be evidentiated in the return)
 * @param follow_pattern_size Size of follow_pattern
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_at_b(const MS_UPtr start, const MS_UPtr end,
                       const MS_UPtr address, const MS_USize nth_match,
                       bool swap_endianness, const MS_UByte *follow_pattern,
                       const MS_USize           follow_pattern_size,
                       const MS_USize           follow_nth_match,
                       const MS_FollowDirection follow_direction);

/**
 * @brief Xref String Follow finder from a sequence
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param content Content to find  in global address space
 * @param nth_match N-th repetition of content, starts at  MEMSCAN_FIRST_MATCH
 * @param swap_endianness Whether the content should have it's endianness
 * swapped
 * @param follow_pattern Byte-code style string that will be turned into a
 * MS_UByte array for evaluation, example: "8B 4D"
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_s(const MS_UPtr start, const MS_UPtr end,
                    const MS_UPtr content, const MS_USize content_nth_match,
                    bool swap_endianness, const char *follow_pattern,
                    const MS_USize           follow_nth_match,
                    const MS_FollowDirection follow_direction);

/**
 * @brief Xref String Follow finder from a reference to pointer
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param address Reference to address to find references to in global address
 * space
 * @param nth_match N-th repetition of reference to select, starts at
 * MEMSCAN_FIRST_MATCH, for clarification, matches are looked for from start,
 * not from address
 * @param swap_endianness Whether the contents at address to have their
 * endianness swapped
 * @param follow_pattern Byte-code style string that will be turned into a
 * MS_UByte array for evaluation, example: "8B 4D"
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_at_s(const MS_UPtr start, const MS_UPtr end,
                       const MS_UPtr address, const MS_USize nth_match,
                       bool swap_endianness, const char *follow_pattern,
                       const MS_USize           follow_nth_match,
                       const MS_FollowDirection follow_direction);

/**
 * @brief Xref No follow finder from a sequence
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param content Content to find  in global address space
 * @param nth_match N-th repetition of content, starts at  MEMSCAN_FIRST_MATCH
 * @param swap_endianness Whether the content should have it's endianness
 * swapped
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_nf(const MS_UPtr start, const MS_UPtr end,
                     const MS_UPtr content, const MS_USize content_nth_match,
                     bool swap_endianness);

/**
 * @brief Xref No follow finder from a reference to pointer
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param address Reference to address to find references to in global address
 * space
 * @param nth_match N-th repetition of reference to select, starts at
 * MEMSCAN_FIRST_MATCH, for clarification, matches are looked for from start,
 * not from address
 * @param swap_endianness Whether the contents at address to have their
 * endianness swapped
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_xref_at_nf(const MS_UPtr start, const MS_UPtr end,
                        const MS_UPtr address, const MS_USize nth_match,
                        bool swap_endianness);

/**
 * @brief String, Bytes follow finder from string start pointer to reversed
 * endianness address scan
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param text Compile-time null-terminated string to find (should be found in
 * '.rdata'/it's variations for Windows, or maybe batched in '.text', etc...)
 * @param text_size Size of the 'text'
 * @param nth_match N-th reference to the address of the first character of the
 * string with reversed endianness in memory
 * @param follow_pattern Array of MS_UBytes to look for, from string xref
 * address, in a specified direction. Spanned from start to end (failures to
 * meet conditions will be evidentiated in the return)
 * @param follow_pattern_size Size of follow_pattern
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_string_b(const MS_UPtr start, const MS_UPtr end, const char *text,
                      const MS_USize text_size, const MS_USize nth_match,
                      const MS_UByte *         follow_pattern,
                      const MS_USize           follow_pattern_size,
                      const MS_USize           follow_nth_match,
                      const MS_FollowDirection follow_direction);

/**
 * @brief String, String follow finder from string start pointer to reversed
 * endianness address scan
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param text Compile-time null-terminated string to find (should be found in
 * '.rdata'/it's variations for Windows, or maybe batched in '.text', etc...)
 * @param text_size Size of the 'text'
 * @param nth_match N-th reference to the address of the first character of the
 * string with reversed endianness in memory
 * @param follow_pattern Byte-code style string that will be turned into a
 * MS_UByte array for evaluation, example: "8B 4D"
 * @param follow_nth_match Same as nth_match, but with the follow_pattern
 * @param follow_direction refer to MS_FollowDirection for documentation
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_string_s(const MS_UPtr start, const MS_UPtr end, const char *text,
                      const MS_USize text_size, const MS_USize nth_match,
                      const char *             follow_pattern,
                      const MS_USize           follow_nth_match,
                      const MS_FollowDirection follow_direction);

/**
 * @brief String No Follow finder from string start pointer to reversed
 * endianness address scan
 *
 * @param start Position to start scanning from in global address space
 * @param end Position to stop scanning at in global address space (expected to
 * be, at the very least, start + MEMSCAN_BYTESET_SIZE, failure to meet this
 * condition will be evidenciated in the return)
 * @param text Compile-time null-terminated string to find (should be found in
 * '.rdata'/it's variations for Windows, or maybe batched in '.text', etc...)
 * @param text_size Size of the 'text'
 * @param nth_match N-th reference to the address of the first character of the
 * string with reversed endianness in memory
 * @return Refer to MS_Result for documentation
 */
extern MS_Result
memscan_find_string_nf(const MS_UPtr start, const MS_UPtr end, const char *text,
                       const MS_USize text_size, const MS_USize nth_match);

/* Detail */

static const MS_UByte k_memscan_wildcard = 0xCC;

/* Constants */

#define MEMSCAN_FIRST_MATCH (0)