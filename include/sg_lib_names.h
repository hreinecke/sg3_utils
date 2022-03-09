#ifndef SG_LIB_NAMES_H
#define SG_LIB_NAMES_H

/*
 * Copyright (c) 2022 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>

#include "sg_lib_data.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct sg_lib_simple_value_name_t sg_lib_names_mode_arr[];
extern struct sg_lib_simple_value_name_t sg_lib_names_vpd_arr[];

extern const size_t sg_lib_names_mode_len;
extern const size_t sg_lib_names_vpd_len;

#ifdef __cplusplus
}
#endif

#endif  /* end of SG_LIB_NAMES */
