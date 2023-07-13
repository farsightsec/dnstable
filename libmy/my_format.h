#ifndef MY_NUM_TO_STR_H
#define MY_NUM_TO_STR_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Format bytes as a NUL-terminated hex string, with each byte represented as two characters.
 *
 * Returns the size of the formatted string, up to a maximum of dst_size bytes.
 */
size_t my_bytes_to_hex_str(const uint8_t *src, size_t len, bool is_upper, char *dst, size_t dst_size);

/*
 * Format num as a NUL-terminated hex string of up to dst_size bytes.
 *
 * Returns the size of the formatted string.
 */
size_t my_uint16_to_hex_str(uint16_t num, bool is_upper, char *dst, size_t dst_size);

/*
 * Format num as a numerical NUL-terminated string of up to dst_size bytes.
 * If start is non-NULL, it will receive a pointer to the first digit in
 * the formatted string. The formatted string will end at the end of the
 * dst buffer, which the caller may fill with padding characters if needed.
 *
 * Returns the number of digits in the formatted string.
 */
size_t my_uint64_to_str(uint64_t num, char *dst, size_t dst_size, const char **start);

#endif /* MY_NUM_TO_STR_H */
