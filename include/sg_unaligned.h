#ifndef SG_UNALIGNED_H
#define SG_UNALIGNED_H

/* Borrowed from the Linux kernel, via mhvtl */

/* For the time being, this header contains only cpu order to and from
 * big endian as required by SCSI standards (www.t10.org). Later, to handle
 * (S)ATA (www.t13.org) and network traffic, little endian may be added. */

static inline uint16_t __get_unaligned_be16(const uint8_t *p)
{
        return p[0] << 8 | p[1];
}

static inline uint32_t __get_unaligned_be32(const uint8_t *p)
{
        return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
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

#endif /* SG_UNALIGNED_H */
