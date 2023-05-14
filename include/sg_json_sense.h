#ifndef SG_JSON_SENSE_H
#define SG_JSON_SENSE_H

/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#include "sg_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These functions' implementations depend on code in sg_lib.c */

/* This function only produces JSON output if jsp is non-NULL and
 * jsp->pr_as_json is true. 'sbp' is assumed to point to sense data as
 * defined by T10 with a length of 'sb_len' bytes. Returns false if an
 * issue is detected, else it returns true. */
bool sgj_js_sense(sgj_state * jsp, sgj_opaque_p jop, const uint8_t * sbp,
                  int sb_len);

/* Decodes a designation descriptor (e.g. as found in the Device
 * Identification VPD page (0x83)) into JSON at position 'jop'.
 * Returns true if successful. */
bool sgj_js_designation_descriptor(sgj_state * jsp, sgj_opaque_p jop,
                                   const uint8_t * ddp, int dd_len);

#ifdef __cplusplus
}
#endif

#endif
