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
 * with sg_set_warnings_strm(). By default it uses stderr. */

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

/* JSON support functions and structures follow. The prefix "sgj_" is used
 * for sg3_utils JSON functions, types and values. */

enum sgj_separator_t {
    SGJ_SEP_NONE = 0,
    SGJ_SEP_SPACE_1,
    SGJ_SEP_SPACE_2,
    SGJ_SEP_SPACE_3,
    SGJ_SEP_SPACE_4,
    SGJ_SEP_EQUAL_NO_SPACE,
    SGJ_SEP_EQUAL_1_SPACE,
    SGJ_SEP_COLON_NO_SPACE,
    SGJ_SEP_COLON_1_SPACE,
};

typedef void * sgj_opaque_p;

/* Apart from the pointers at the end the other fields are initialized
 * from the argument given to --json= . If there is no argument then
 * they initialized as shown. */
typedef struct sgj_state_t {
    bool pr_as_json;            /* = false */
    bool pr_pretty;             /* = true */
    bool pr_header;             /* = true */
    bool pr_sorted;             /* = false (ignored) */
    bool pr_output;             /* = false */
    bool pr_implemented;
    bool pr_unimplemented;
    char pr_format;             /* = '\0' */
    int pr_indent_size;         /* = 4 */
    int first_bad_char;         /* = '\0' */
    int verbose;                /* = 0 */
    /* the following hold state information */
    sgj_opaque_p basep;         /* base JSON object pointer */
    sgj_opaque_p outputp;       /* 'output' named JSON array pointer */
    sgj_opaque_p userp;         /* for temporary usage */
} sgj_state;

/* Prints to stdout like printf(fmt, ...). Further if --json=o option is
 * given that output line is also placed in the JSON 'output' array. */
void sgj_pr_hr(sgj_state * jsp, const char * fmt, ...) __printf(2, 3);

/* Initializes the state object pointed to by jsp based on the argument
 * given to the right of --json= pointed to by j_optarg. If it is NULL
 * then state object gets its default values. Returns true if argument
 * to --json= is decoded properly, else returns false and places the
 * first "bad" character in jsp->first_bad_char . Note that no JSON
 * in-core tree needs to exist when this function is called. */
bool sgj_init_state(sgj_state * jsp, const char * j_optarg);

/* sgj_start() creates a JSON in-core tree and returns a pointer to it (or
 * NULL if the associated heap allocation fails). It should be paired with
 * sgj_finish() to clean up (i.e. remove all heap allocations) all the
 * elements (i.e. JSON objects and arrays) that have been placed in that
 * in-core tree. If jsp is NULL nothing further happens. Otherwise the pointer
 * to be returned is placed in jsp->basep. If jsp->pr_header is true and
 * util_name is non-NULL then a "utility_invoked" JSON object is made with
 * "name", and "version_date" object fields. If the jsp->pr_output field is
 * true a named array called "output" is added to the "utility_invoked" object
 * (creating it in the case when jsp->pr_header is false) and a pointer to
 * that array object is placed in jsp->objectp . The returned pointer is not
 * usually needed but if it is NULL then a heap allocation has failed. */
sgj_opaque_p sgj_start(const char * util_name, const char * ver_str,
                       int argc, char *argv[], sgj_state * jsp);

/* These are low level functions returning a pointer to a newly created JSON
 * object or array. If jsp is NULL or jsp->pr_as_json is false nothing happens
 * and NULL is returned. Note that this JSON object is _not_ placed in the
 * in-core tree controlled by jsp (jsp->basep); it may be added later as the
 * third argument to sgj_add_array_element(), for example. */
sgj_opaque_p sgj_new_unattached_object(sgj_state * jsp);
sgj_opaque_p sgj_new_unattached_array(sgj_state * jsp);

/* If jsp is NULL or jsp->pr_as_json is false nothing happens and NULL is
 * returned. Otherwise it creates a new named object (whose name is what
 * 'name' points to) at 'jop' with an empty object as its value; a pointer
 * to that empty object is returned. If 'jop' is NULL then jsp->basep is
 * used instead. The returned value should always be checked (for NULL)
 * and if not, used. */
sgj_opaque_p sgj_new_named_object(sgj_state * jsp, sgj_opaque_p jop,
                                  const char * name);

/* If jsp is NULL or jsp->pr_as_json is false nothing happens and NULL is
 * returned. Otherwise it creates a new named object (whose name is what
 * 'name' points to) at 'jop' with an empty array as its value; a pointer
 * to that empty array is returned.  If 'jop' is NULL then jsp->basep is
 * used instead. The returned value should always * be checked (for NULL)
 * and if not, used. */
sgj_opaque_p sgj_new_named_array(sgj_state * jsp, sgj_opaque_p jop,
                                 const char * name);

/* If jsp is NULL or jsp->pr_as_json is false or ua_jop is NULL nothing
 * happens and NULL is returned. Otherwise it adds a new array element
 * (ua_jop) to the array ('jap') that was returned by sgj_new_named_array().
 * ua_jop is assumed to not been part of the main JSON in-core tree before
 * this call, and it is after this call. This means that ua_jop must have
 * been created by sgj_new_unattached_object() or similar. */
sgj_opaque_p sgj_add_array_element(sgj_state * jsp, sgj_opaque_p jap,
                                   sgj_opaque_p ua_jop);

sgj_opaque_p sgj_add_name_vs(sgj_state * jsp, sgj_opaque_p jop,
                             const char * name, const char * value);

sgj_opaque_p sgj_add_name_vi(sgj_state * jsp, sgj_opaque_p jop,
                             const char * name, int64_t value);

sgj_opaque_p sgj_add_name_vb(sgj_state * jsp, sgj_opaque_p jop,
                             const char * name, bool value);

sgj_opaque_p sgj_add_name_obj(sgj_state * jsp, sgj_opaque_p jop,
                              const char * name, sgj_opaque_p ua_jop);

void sgj_pr_twin_vs(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                    const char * name, enum sgj_separator_t sep,
                    const char * value);

void sgj_pr_twin_vi(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                    const char * name, enum sgj_separator_t sep,
                    int64_t value);

void sgj_pr_twin_vb(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                    const char * name, enum sgj_separator_t sep, bool value);

void sgj_add_name_pair_ihex(sgj_state * jsp, sgj_opaque_p jop,
                            const char * name, uint64_t value);

void sgj_add_name_pair_istr(sgj_state * jsp, sgj_opaque_p jop,
                            const char * name, int64_t val_i,
                            const char * val_s);

#if 0
void sgj_pr_hr_line_vs(sgj_state * jsp, sgj_opaque_p jop,
                       const char * hr_line, const char * name,
                       const char * value);
#endif

void sgj_pr2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status,
                 FILE * fp);

void sgj_free_unattached(sgj_opaque_p jop);

void sgj_finish(sgj_state * jsp);


#ifdef __cplusplus
}
#endif

#endif
