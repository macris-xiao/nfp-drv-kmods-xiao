/*
 * crc32.h
 * Header file for crc32
 */

#ifndef CRC32_H
#define CRC32_H

uint32_t crc32_posix_add(uint32_t crc, const void *buff, size_t len);
uint32_t crc32_posix_end(uint32_t crc, size_t total_len);
static inline uint32_t crc32_posix(const void *buff, size_t len)
{
	return crc32_posix_end(crc32_posix_add(0, buff, len), len);
}

#endif /* CRC32_H */
