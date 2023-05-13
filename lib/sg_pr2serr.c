/*
 * Copyright (c) 2022-2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "sg_pr2serr.h"

/*
 * Some users of sg_pr2serr may not need fixed and descriptor sense decoded
 * for JSON output. If the following define is commented out the effective
 * compile size of this file is reduced by 800 lines plus dependencies on
 * other large components of the sg3_utils library.
 * Comment out the next line to remove dependency on sg_lib.h and its code.
 */
#define SG_PRSE_SENSE_DECODE 1

#ifdef SG_PRSE_SENSE_DECODE
#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_unaligned.h"
#endif


/* Users of the sg_pr2serr.h header need this function definition */
int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

#ifndef SG_PRSE_SENSE_DECODE

/* Want safe, 'n += snprintf(b + n, blen - n, ...)' style sequence of
 * functions. Returns number of chars placed in cp excluding the
 * trailing null char. So for cp_max_len > 0 the return value is always
 * < cp_max_len; for cp_max_len <= 1 the return value is 0 and no chars are
 * written to cp. Note this means that when cp_max_len = 1, this function
 * assumes that cp[0] is the null character and does nothing (and returns
 * 0). Linux kernel has a similar function called  scnprintf(). Public
 * declaration in sg_pr2serr.h header  */
int
sg_scnpr(char * cp, int cp_max_len, const char * fmt, ...)
{
    va_list args;
    int n;

    if (cp_max_len < 2)
        return 0;
    va_start(args, fmt);
    n = vsnprintf(cp, cp_max_len, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}

int
pr2ws(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

#endif

#ifndef SG_PRSE_SENSE_DECODE
static bool
has_control_char(const uint8_t * up, int len)
{
    int k;
    uint8_t u;

    for (k = 0; k < len; ++k) {
        u = up[k];
        if ((u < 0x20) || (0x7f == u))
            return true;
    }
    return false;
}
#endif

#ifndef SG_PRSE_SENSE_DECODE
static void
h2str(const uint8_t * byte_arr, int num_bytes, char * bp, int blen)
{
    int j, k, n;

    for (k = 0, n = 0; (k < num_bytes) && (n < blen); ) {
        j = sg_scnpr(bp + n, blen - n, "%02x ", byte_arr[k]);
        if (j < 2)
            break;
        n += j;
        ++k;
        if ((0 == (k % 8)) && (k < num_bytes) && (n < blen)) {
            bp[n++] = ' ';
        }
    }
    j = strlen(bp);
    if ((j > 0) && (' ' == bp[j - 1]))
        bp[j - 1] = '\0';    /* chop off trailing space */
}
#endif

