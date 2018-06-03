#ifndef SG_PR2SERR_H
#define SG_PR2SERR_H

/*
 * Copyright (c) 2004-2018 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* These are convenience functions that replace the somewhat long-winded
 * fprintf(stderr, ....). The second form (i.e. pr2ws() ) is for internal
 * library use and may place its output somewhere other than stderr; it
 * depends on the external variable sg_warnings_strm which can be set
 * with sg_set_warnings_strm(). By default it uses stderr. */

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__GNUC__) || defined(__clang__)
int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));

int pr2ws(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
int pr2serr(const char * fmt, ...);

int pr2ws(const char * fmt, ...);
#endif


#ifdef __cplusplus
}
#endif

#endif
