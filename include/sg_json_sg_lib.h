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

/* The in-core JSON tree is printed to 'fp' (typically stdout) by this call.
 * If jsp is NULL, jsp->pr_as_json is false or jsp->basep is NULL then this
 * function does nothing. If jsp->exit_status is true then a new JSON object
 * named "exit_status" and the 'exit_status' value rendered as a JSON integer
 * is appended to jsp->basep. The in-core JSON tree with jsp->basep as its
 * root is streamed to 'fp'.
 * Uses exit_status to call sg_lib::sg_exit2str() and then calls
 * sg_json::xxxxxx */
void sgj_js2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status,
                 FILE * fp);

#ifdef __cplusplus
}
#endif

#endif
