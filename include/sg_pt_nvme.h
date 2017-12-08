#ifndef SG_PT_NVME_H
#define SG_PT_NVME_H

/*
 * Copyright (c) 2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* structures copied and slightly modified from <linux/nvme_ioctl.h> which
 * is Copyright (c) 2011-2014, Intel Corporation.  */

#ifdef __GNUC__
#ifndef __clang__
  struct __attribute__((__packed__)) sg_nvme_user_io
#else
  struct sg_nvme_user_io
#endif
#else
struct sg_nvme_user_io
#endif
{
        uint8_t opcode;
        uint8_t flags;
        uint16_t control;
        uint16_t nblocks;
        uint16_t rsvd;
        uint64_t metadata;
        uint64_t addr;
        uint64_t slba;
        uint32_t dsmgmt;
        uint32_t reftag;
        uint16_t apptag;
        uint16_t appmask;
}
#ifdef SG_LIB_FREEBSD
__packed;
#else
;
#endif

/* Using byte offsets and unaligned be/le copies safer than packed
 * structures. These are for sg_nvme_user_io . */
#define SG_NVME_IO_OPCODE 0
#define SG_NVME_IO_FLAGS 1
#define SG_NVME_IO_CONTROL 2
#define SG_NVME_IO_NBLOCKS 4
#define SG_NVME_IO_RSVD 6
#define SG_NVME_IO_METADATA 8
#define SG_NVME_IO_ADDR 16
#define SG_NVME_IO_SLBA 24
#define SG_NVME_IO_DSMGMT 32
#define SG_NVME_IO_REFTAG 36
#define SG_NVME_IO_APPTAG 40
#define SG_NVME_IO_APPMASK 42

#ifdef __GNUC__
#ifndef __clang__
  struct __attribute__((__packed__)) sg_nvme_passthru_cmd
#else
  struct sg_nvme_passthru_cmd
#endif
#else
struct sg_nvme_passthru_cmd
#endif
{
        uint8_t opcode;
        uint8_t flags;
        uint16_t rsvd1;
        uint32_t nsid;
        uint32_t cdw2;
        uint32_t cdw3;
        uint64_t metadata;
        uint64_t addr;
        uint32_t metadata_len;
        uint32_t data_len;
        uint32_t cdw10;
        uint32_t cdw11;
        uint32_t cdw12;
        uint32_t cdw13;
        uint32_t cdw14;
        uint32_t cdw15;

        uint32_t timeout_ms;
        uint32_t result;
}
#ifdef SG_LIB_FREEBSD
__packed;
#else
;
#endif

/* Using byte offsets and unaligned be/le copies safer than packed
 * structures. These are for sg_nvme_passthru_cmd . */
#define SG_NVME_PT_OPCODE 0
#define SG_NVME_PT_FLAGS 1
#define SG_NVME_PT_RSVD1 2
#define SG_NVME_PT_NSID 4
#define SG_NVME_PT_CDW2 8
#define SG_NVME_PT_CDW3 12
#define SG_NVME_PT_METADATA 16
#define SG_NVME_PT_ADDR 24
#define SG_NVME_PT_METADATA_LEN 32
#define SG_NVME_PT_DATA_LEN 36
#define SG_NVME_PT_CDW10 40
#define SG_NVME_PT_CDW11 44
#define SG_NVME_PT_CDW12 48
#define SG_NVME_PT_CDW13 52
#define SG_NVME_PT_CDW14 56
#define SG_NVME_PT_CDW15 60

#define SG_NVME_PT_TIMEOUT_MS 64
#define SG_NVME_PT_RESULT 68

/* Valid namespace IDs (nsid_s) range from 1 to 0xfffffffe, leaving: */
#define SG_NVME_BROADCAST_NSID 0xffffffff
#define SG_NVME_CTL_NSID 0x0

#ifdef __cplusplus
}
#endif

#endif
