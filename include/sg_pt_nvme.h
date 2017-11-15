PROPS-END
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

struct sg_nvme_user_io {
	uint8_t	opcode;
	uint8_t	flags;
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
#ifdef SG_LIB_FREEBSD
} __packed;
#else
};
#endif

struct sg_nvme_passthru_cmd {
	uint8_t	opcode;
	uint8_t	flags;
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
#ifdef SG_LIB_FREEBSD
} __packed;
#else
};
#endif

#ifdef __cplusplus
}
#endif

#endif
