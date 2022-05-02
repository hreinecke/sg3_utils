#ifndef SG_PR2SERR_H
#define SG_PR2SERR_H

/*
 * Copyright (c) 2004-2022 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* These are convenience functions that replace the somewhat long-winded
 * fprintf(stderr, ....). The second form (i.e. pr2ws() ) is for internal
 * library use and may place its output somewhere other than stderr; it
 * depends on the external variable sg_warnings_strm which can be set
 * with sg_set_warnings_strm(). By default it uses stderr. */

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if 1
enum sg_json_separator_t {
    SG_JSON_SEP_NONE = 0,
    SG_JSON_SEP_SPACE_1,
    SG_JSON_SEP_SPACE_2,
    SG_JSON_SEP_SPACE_3,
    SG_JSON_SEP_SPACE_4,
    SG_JSON_SEP_EQUAL_NO_SPACE,
    SG_JSON_SEP_EQUAL_1_SPACE,
    SG_JSON_SEP_COLON_NO_SPACE,
    SG_JSON_SEP_COLON_1_SPACE,
};
#endif

typedef void * sg_json_opaque_p;

typedef struct sg_json_state_t {
    bool pr_as_json;
    bool pr_pretty;
    bool pr_header;
    bool pr_sorted;
    bool pr_output;
    bool pr_implemented;
    bool pr_unimplemented;
    char pr_format;
    int pr_indent_size;
    int first_bad_char;
    int verbose;
    /* the following hold state information */
    sg_json_opaque_p basep;     /* base JSON object pointer */
    sg_json_opaque_p outputp;   /* 'output' named JSON array pointer */
    sg_json_opaque_p userp;     /* for temporary usage */
} sg_json_state;


#if __USE_MINGW_ANSI_STDIO -0 == 1
#define __printf(a, b) __attribute__((__format__(gnu_printf, a, b)))
#elif defined(__GNUC__) || defined(__clang__)
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#else
#define __printf(a, b)
#endif

int pr2serr(const char * fmt, ...) __printf(1, 2);

int pr2ws(const char * fmt, ...) __printf(1, 2);

/* Want safe, 'n += snprintf(b + n, blen - n, ...)' style sequence of
 * functions. Returns number of chars placed in cp excluding the
 * trailing null char. So for cp_max_len > 0 the return value is always
 * < cp_max_len; for cp_max_len <= 1 the return value is 0 and no chars are
 * written to cp. Note this means that when cp_max_len = 1, this function
 * assumes that cp[0] is the null character and does nothing (and returns
 * 0). Linux kernel has a similar function called  scnprintf().  */
int sg_scnpr(char * cp, int cp_max_len, const char * fmt, ...) __printf(3, 4);

void sgj_pr_hr(sg_json_state * jsp, const char * fmt, ...) __printf(2, 3);

bool sgj_init_state(sg_json_state * jstp, const char * j_optarg);

sg_json_opaque_p sgj_start(const char * util_name, const char * ver_str,
                               int argc, char *argv[], sg_json_state * jstp);

/* Newly created object is un-attached */
sg_json_opaque_p sgj_new_object(sg_json_state * jsp);

sg_json_opaque_p sgj_new_named_object(sg_json_state * jsp,
                                      sg_json_opaque_p jop,
                                      const char * name);

sg_json_opaque_p sgj_add_array_element(sg_json_state * jsp,
                                       sg_json_opaque_p jap,
                                       sg_json_opaque_p ejop);

sg_json_opaque_p sgj_new_named_array(sg_json_state * jsp,
                                     sg_json_opaque_p jop,
                                     const char * name);

sg_json_opaque_p sgj_add_name_vs(sg_json_state * jsp, sg_json_opaque_p jop,
                                 const char * name, const char * value);

sg_json_opaque_p sgj_add_name_vi(sg_json_state * jsp, sg_json_opaque_p jop,
                                 const char * name, int64_t value);

sg_json_opaque_p sgj_add_name_vb(sg_json_state * jsp, sg_json_opaque_p jop,
                                 const char * name, bool value);

void sgj_pr_simple_vs(sg_json_state * jsp, sg_json_opaque_p jop,
                      int leadin_sp, const char * name,
                      enum sg_json_separator_t sep, const char * value);

void sgj_pr_simple_vi(sg_json_state * jsp, sg_json_opaque_p jop,
                      int leadin_sp, const char * name,
                      enum sg_json_separator_t sep, int64_t value);

void sgj_pr_simple_vb(sg_json_state * jsp, sg_json_opaque_p jop,
                      int leadin_sp, const char * name,
                      enum sg_json_separator_t sep, bool value);

void sgj_add_name_pair_ihex(sg_json_state * jsp, sg_json_opaque_p jop,
                            const char * name, uint64_t value);

void sgj_add_name_pair_istr(sg_json_state * jsp, sg_json_opaque_p jop,
                            const char * name, int64_t value,
                            const char * str);

#if 0
void sgj_pr_hr_line_vs(sg_json_state * jsp, sg_json_opaque_p jop,
                       const char * hr_line, const char * name,
                       const char * value);
#endif

void sgj_pr2file(sg_json_state * jsp, sg_json_opaque_p jop, int exit_status,
                 FILE * fp);

void sgj_finish(sg_json_state * jstp);


#ifdef __cplusplus
}
#endif

#endif
