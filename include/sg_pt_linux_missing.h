#ifndef SG_PT_LINUX_MISSING_H
#define SG_PT_LINUX_MISSING_H

/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stdbool.h>


/* This header is for internal use by the sg3_utils library (libsgutils)
 * and is Linux specific. Best not to include it directly in code that
 * is meant to be OS independent.
 * This header is only used with Linux if linux/types.h and linux/major.h
 * are not available. This is the case with MUSL libc for example. */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE___U64
/* typedefs if linux/types.h header not available */

typedef uint64_t __u64;
typedef int64_t __s64;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint16_t __u16;
typedef int16_t __s16;
#endif


/* Following if linux/major.h header is not available */
#define MEM_MAJOR               1
#define IDE0_MAJOR              3
#define SCSI_DISK0_MAJOR        8
#define SCSI_TAPE_MAJOR         9
#define SCSI_CDROM_MAJOR        11
#define SCSI_GENERIC_MAJOR	21
#define IDE1_MAJOR              22
#define IDE2_MAJOR              33
#define IDE3_MAJOR              34
#define IDE4_MAJOR              56
#define IDE5_MAJOR              57
#define SCSI_DISK1_MAJOR        65
#define SCSI_DISK2_MAJOR        66
#define SCSI_DISK3_MAJOR        67
#define SCSI_DISK4_MAJOR        68
#define SCSI_DISK5_MAJOR        69
#define SCSI_DISK6_MAJOR        70
#define SCSI_DISK7_MAJOR        71
#define IDE6_MAJOR              88
#define IDE7_MAJOR              89
#define IDE8_MAJOR              90
#define IDE9_MAJOR              91

#ifdef __cplusplus
}
#endif

#endif          /* end of SG_PT_LINUX_MISSING_H */
