/* Copyright (C) 2014-2015 Netronome Systems, Inc. All rights reserved.
 *
 * This software may be redistributed under either of two provisions:
 *
 * 1. The GNU General Public License version 2 (see
 *    http://www.gnu.org/licenses/old-licenses/gpl-2.0.html or
 *    COPYING.txt file) when it is used for Linux or other
 *    compatible free software as defined by GNU at
 *    http://www.gnu.org/licenses/license-list.html.
 *
 * 2. Or under a non-free commercial license executed directly with
 *    Netronome. The direct Netronome license does not apply when the
 *    software is used as part of the Linux kernel.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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
