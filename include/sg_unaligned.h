#ifndef SG_UNALIGNED_H
#define SG_UNALIGNED_H

/*
 * Copyright (c) 2014-2015 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Borrowed from the Linux kernel, via mhvtl */

/* In the first section below, functions that copy unsigned integers in
 * a computer's native format, to and from an unaligned big endian sequence
 * of bytes. Big endian byte format "on the wire" is the default used by
 * SCSI standards (www.t10.org). */

static inline uint16_t __get_unaligned_be16(const uint8_t *p)
{
        return p[0] << 8 | p[1];
}

static inline uint32_t __get_unaligned_be32(const uint8_t *p)
{
        return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

/* Assume 48 bit value placed in uint64_t */
static inline uint64_t __get_unaligned_be48(const uint8_t *p)
{
        return (uint64_t)__get_unaligned_be16(p) << 32 |
               __get_unaligned_be32(p + 2);
}

static inline uint64_t __get_unaligned_be64(const uint8_t *p)
{
        return (uint64_t)__get_unaligned_be32(p) << 32 |
               __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(uint16_t val, uint8_t *p)
{
        *p++ = val >> 8;
        *p++ = val;
}

static inline void __put_unaligned_be32(uint32_t val, uint8_t *p)
{
        __put_unaligned_be16(val >> 16, p);
        __put_unaligned_be16(val, p + 2);
}

/* Assume 48 bit value placed in uint64_t */
static inline void __put_unaligned_be48(uint64_t val, uint8_t *p)
{
        __put_unaligned_be16(val >> 32, p);
        __put_unaligned_be32(val, p + 2);
}

static inline void __put_unaligned_be64(uint64_t val, uint8_t *p)
{
        __put_unaligned_be32(val >> 32, p);
        __put_unaligned_be32(val, p + 4);
}

static inline uint16_t sg_get_unaligned_be16(const void *p)
{
        return __get_unaligned_be16((const uint8_t *)p);
}

static inline uint32_t sg_get_unaligned_be24(const uint8_t *p)
{
        return p[0] << 16 | p[1] << 8 | p[2];
}

static inline uint32_t sg_get_unaligned_be32(const void *p)
{
        return __get_unaligned_be32((const uint8_t *)p);
}

/* Assume 48 bit value placed in uint64_t */
static inline uint64_t sg_get_unaligned_be48(const void *p)
{
        return __get_unaligned_be48((const uint8_t *)p);
}

static inline uint64_t sg_get_unaligned_be64(const void *p)
{
        return __get_unaligned_be64((const uint8_t *)p);
}

static inline void sg_put_unaligned_be16(uint16_t val, void *p)
{
        __put_unaligned_be16(val, (uint8_t *)p);
}

static inline void sg_put_unaligned_be24(uint32_t val, void *p)
{
        ((uint8_t *)p)[0] = (val >> 16) & 0xff;
        ((uint8_t *)p)[1] = (val >> 8) & 0xff;
        ((uint8_t *)p)[2] = val & 0xff;
}

static inline void sg_put_unaligned_be32(uint32_t val, void *p)
{
        __put_unaligned_be32(val, (uint8_t *)p);
}

/* Assume 48 bit value placed in uint64_t */
static inline void sg_put_unaligned_be48(uint64_t val, void *p)
{
        __put_unaligned_be48(val, (uint8_t *)p);
}

static inline void sg_put_unaligned_be64(uint64_t val, void *p)
{
        __put_unaligned_be64(val, (uint8_t *)p);
}

/* Since cdb and parameter blocks are often memset to zero before these
 * unaligned function partially fill them, then check for a val of zero
 * and ignore if it is with these variants. */
static inline void sg_nz_put_unaligned_be16(uint16_t val, void *p)
{
        if (val)
                __put_unaligned_be16(val, (uint8_t *)p);
}

static inline void sg_nz_put_unaligned_be24(uint32_t val, void *p)
{
        if (val) {
                ((uint8_t *)p)[0] = (val >> 16) & 0xff;
                ((uint8_t *)p)[1] = (val >> 8) & 0xff;
                ((uint8_t *)p)[2] = val & 0xff;
        }
}

static inline void sg_nz_put_unaligned_be32(uint32_t val, void *p)
{
        if (val)
                __put_unaligned_be32(val, (uint8_t *)p);
}

static inline void sg_nz_put_unaligned_be64(uint64_t val, void *p)
{
        if (val)
            __put_unaligned_be64(val, (uint8_t *)p);
}


/* Below are the little endian equivalents of the big endian functions
 * above. Little endian is used by ATA, networking and PCI.
 * This section could take advantage of the
 * 'uint32_t htonl(uint32_t hostlong)' [and the complementary ntohl()]
 * family of functions but that would introduce a dependency on the
 * <arpa/inet.h> header. Also they don't address moving to and from
 * an unaligned sequence of bytes. The latter would still need to be
 * done.
 */

static inline uint16_t __get_unaligned_le16(const uint8_t *p)
{
        return p[1] << 8 | p[0];
}

static inline uint32_t __get_unaligned_le32(const uint8_t *p)
{
        return p[3] << 24 | p[2] << 16 | p[1] << 8 | p[0];
}

static inline uint64_t __get_unaligned_le64(const uint8_t *p)
{
        return (uint64_t)__get_unaligned_le32(p + 4) << 32 |
               __get_unaligned_le32(p);
}

static inline void __put_unaligned_le16(uint16_t val, uint8_t *p)
{
        *p++ = val;
        *p++ = val >> 8;
}

static inline void __put_unaligned_le32(uint32_t val, uint8_t *p)
{
        __put_unaligned_le16(val >> 16, p + 2);
        __put_unaligned_le16(val, p);
}

static inline void __put_unaligned_le64(uint64_t val, uint8_t *p)
{
        __put_unaligned_le32(val >> 32, p + 4);
        __put_unaligned_le32(val, p);
}

static inline uint16_t sg_get_unaligned_le16(const void *p)
{
        return __get_unaligned_le16((const uint8_t *)p);
}

static inline uint32_t sg_get_unaligned_le24(const void *p)
{
        return (uint32_t)__get_unaligned_le16((const uint8_t *)p) |
               ((const uint8_t *)p)[2] << 16;
}

static inline uint32_t sg_get_unaligned_le32(const void *p)
{
        return __get_unaligned_le32((const uint8_t *)p);
}

/* Assume 48 bit value placed in uint64_t */
static inline uint64_t sg_get_unaligned_le48(const void *p)
{
        return (uint64_t)__get_unaligned_le16((const uint8_t *)p + 4) << 32 |
               __get_unaligned_le32((const uint8_t *)p);
}

static inline uint64_t sg_get_unaligned_le64(const void *p)
{
        return __get_unaligned_le64((const uint8_t *)p);
}

static inline void sg_put_unaligned_le16(uint16_t val, void *p)
{
        __put_unaligned_le16(val, (uint8_t *)p);
}

static inline void sg_put_unaligned_le24(uint32_t val, void *p)
{
        ((uint8_t *)p)[2] = (val >> 16) & 0xff;
        ((uint8_t *)p)[1] = (val >> 8) & 0xff;
        ((uint8_t *)p)[0] = val & 0xff;
}

static inline void sg_put_unaligned_le32(uint32_t val, void *p)
{
        __put_unaligned_le32(val, (uint8_t *)p);
}

/* Assume 48 bit value placed in uint64_t */
static inline void sg_put_unaligned_le48(uint64_t val, void *p)
{
        ((uint8_t *)p)[5] = (val >> 40) & 0xff;
        ((uint8_t *)p)[4] = (val >> 32) & 0xff;
        ((uint8_t *)p)[3] = (val >> 24) & 0xff;
        ((uint8_t *)p)[2] = (val >> 16) & 0xff;
        ((uint8_t *)p)[1] = (val >> 8) & 0xff;
        ((uint8_t *)p)[0] = val & 0xff;
}

static inline void sg_put_unaligned_le64(uint64_t val, void *p)
{
        __put_unaligned_le64(val, (uint8_t *)p);
}

/* Since cdb and parameter blocks are often memset to zero before these
 * unaligned function partially fill them, then check for a val of zero
 * and ignore if it is with these variants. */
static inline void sg_nz_put_unaligned_le16(uint16_t val, void *p)
{
        if (val)
                __put_unaligned_le16(val, (uint8_t *)p);
}

static inline void sg_nz_put_unaligned_le24(uint32_t val, void *p)
{
        if (val) {
                ((uint8_t *)p)[2] = (val >> 16) & 0xff;
                ((uint8_t *)p)[1] = (val >> 8) & 0xff;
                ((uint8_t *)p)[0] = val & 0xff;
        }
}

static inline void sg_nz_put_unaligned_le32(uint32_t val, void *p)
{
        if (val)
                __put_unaligned_le32(val, (uint8_t *)p);
}

static inline void sg_nz_put_unaligned_le64(uint64_t val, void *p)
{
        if (val)
            __put_unaligned_le64(val, (uint8_t *)p);
}

#ifdef __cplusplus
}
#endif

#endif /* SG_UNALIGNED_H */
