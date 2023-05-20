#ifndef SG_PR2SERR_H
#define SG_PR2SERR_H

/*
 * Copyright (c) 2004-2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* pr2serr and pr2ws are convenience functions that replace the somewhat
 * long-winded fprintf(stderr, ....). The second form (i.e. pr2ws() ) is for
 * internal library use and may place its output somewhere other than stderr;
 * it depends on the external variable sg_warnings_strm which can be set
 * with sg_set_warnings_strm(). By default it uses stderr.
 * Note that this header and its implementation do not depend on sg_lib.[hc]
 * or any other sg3_utils components. */

#if __USE_MINGW_ANSI_STDIO -0 == 1
#define __printf(a, b) __attribute__((__format__(gnu_printf, a, b)))
#elif defined(__GNUC__) || defined(__clang__)
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#else
#define __printf(a, b)
#endif

int pr2serr(const char * fmt, ...) __printf(1, 2);

extern FILE * sg_warnings_strm;

/* Only difference between pr2serr() and pr2ws() is that the former always
 * send output to stderr. By default, pr2ws() also sends it output to
 * stderr. The sg_set_warnings_strm() function found in sg_lib.h (if used)
 * set another FILE * value. The functions in sg_lib.h send their error
 * output to pr2ws() . */
int pr2ws(const char * fmt, ...) __printf(1, 2);

/* Want safe, 'n += snprintf(b + n, blen - n, ...);' pattern that can
 * be called repeatedly. However snprintf() takes an unsigned second argument
 * (size_t) that explodes if 'blen - n' goes negative. This function instead
 * uses signed integers (second argument and return value) and is safe if the
 * second argument is negative. It returns number of chars actually
 * placed in cp excluding the trailing null char. So for cp_max_len > 0 the
 * return value is always < cp_max_len; for cp_max_len <= 1 the return value
 * is 0 and no chars are written to cp. Note this means that when
 * cp_max_len = 1, this function assumes that cp[0] is the null character
 * and does nothing (and returns 0). Linux kernel has a similar function
 * called  scnprintf().  */
int sg_scnpr(char * cp, int cp_max_len, const char * fmt, ...) __printf(3, 4);

/* This function is similar to sg_scnpr() but takes the "n" in that pattern
 * as an extra, third argument where it is renamed 'off'. This function will
 * start writing chars at 'fcp + off' for no more than 'fcp_len - off - 1'
 * characters. The return value is the same as sg_scnpr(). */
int sg_scn3pr(char * fcp, int fcp_len, int off,
              const char * fmt, ...) __printf(4, 5);

#ifdef __cplusplus
}
#endif

#endif
