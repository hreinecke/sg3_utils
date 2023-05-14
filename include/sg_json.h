#ifndef SG_JSON_H
#define SG_JSON_H

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

#ifdef __cplusplus
extern "C" {
#endif

/* JSON support functions and structures follow. The prefix "sgj_" is used
 * for sg3_utils JSON functions, types and values. */

/* Following macro for sgj_pr_hr() which takes printf() like arguments */
#if __USE_MINGW_ANSI_STDIO -0 == 1
#define __printf(a, b) __attribute__((__format__(gnu_printf, a, b)))
#elif defined(__GNUC__) || defined(__clang__)
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#else
#define __printf(a, b)
#endif

enum sgj_separator_t {
    SGJ_SEP_NONE = 0,
    SGJ_SEP_SPACE_1,
    SGJ_SEP_SPACE_2,
    SGJ_SEP_SPACE_3,
    SGJ_SEP_SPACE_4,
    SGJ_SEP_EQUAL_NO_SPACE,
    SGJ_SEP_EQUAL_1_SPACE,
    SGJ_SEP_SPACE_EQUAL_SPACE,
    SGJ_SEP_COLON_NO_SPACE,
    SGJ_SEP_COLON_1_SPACE,
};

typedef void * sgj_opaque_p;

/* Apart from the state information at the end of this structure, the earlier
 * fields are initialized from the command line argument given to the
 * --json= option. If there is no argument then they initialized as shown. */
typedef struct sgj_state_t {
    /* the following set by default, the SG3_UTILS_JSON_OPTS environment
     * variable or command line argument to --json option, in that order. */
    bool pr_as_json;            /* = false (def: is plain text output) */
    bool pr_exit_status;        /* 'e' (def: true) */
    bool pr_hex;                /* 'h' (def: false) */
    bool pr_leadin;             /* 'l' (def: true) */
    bool pr_name_ex;        /* 'n' name_extra (information) (def: false) */
    bool pr_out_hr;             /* 'o' (def: false) */
    bool pr_packed;             /* 'k' (def: false) only when !pr_pretty */
    bool pr_pretty;             /* 'p' (def: true) */
    bool pr_string;             /* 's' (def: true) */
    char pr_format;             /*  (def: '\0') */
    int pr_indent_size;         /* digit (def: 4) */
    int verbose;                /* 'v' (def: 0) incremented each appearance */
    int q_counter;              /* 'q' (def: 0) extra, for using apps */
    int z_counter;              /* 'z' (def: 0) extra, for using apps */

    /* the following hold state information */
    int first_bad_char;         /* = '\0' */
    sgj_opaque_p basep;         /* base JSON object pointer */
    sgj_opaque_p out_hrp;       /* JSON array pointer when pr_out_hr set. Each
                                 * element contains a line of plain text. The
                                 * array's JSON name is 'plain_text_output' */
    sgj_opaque_p userp;         /* for temporary usage */
} sgj_state;

/* This function tries to convert the in_name C string to the "snake_case"
 * convention so the output sn_name only contains lower case ASCII letters,
 * numerals and "_" as a separator. Any leading or trailing underscores
 * are removed as are repeated underscores (e.g. "_Snake __ case_" becomes
 * "snake_case"). Parentheses and the characters between them are removed.
 * Returns sn_name (i.e. the pointer to the output buffer).
 * Note: strlen(in_name) should be <= max_sn_name_len . */
char * sgj_convert2snake_rm_parens(const char * in_name, char * sn_name,
                                   int max_sn_name_len);
/* Returns sn_name which only contains lower case ASCII letters, numerals
 * and "_" as a separator, taken from in_name. All other characters are
 * converted to "_". Any leading or trailing underscores are removed as
 * are repeated underscores (e.g. "_Output  power (mW)!" becomes
 * "output_power_mw". */
char * sgj_convert2snake(const char * in, char * out, int maxlen_out);
/* Is in_name made up of only lower case alphanumerics and underscores? */
bool sgj_is_snake_name(const char * in_name);

/* There are many variants of JSON supporting functions below and some
 * abbreviations are used to shorten their function names:
 *    sgj_  - prefix of all the functions related to (non-)JSON output
 *    hr    - human readable form (same meaning as "plain text")
 *    js    - JSON only output
 *    haj   - human readable and JSON output, if JSON output is selected
 *            then the normal output goes in 'plain_text_output' array
 *    pr    - has printf() like variadic arguments
 *    _r    - suffix indicating the return value should/must be used
 *    nv    - adds a name-value JSON field (or several)
 *    o     - value is the provided JSON object (or array)
 *    i     - value is a JSON integer object (int64_t or uint64_t)
 *    b     - value is a JSON boolean object
 *    s     - value is a JSON string object
 *    str   - same as s
 *    hex   - value is hexadecimal in a JSON string object
 *    _nex  - extra 'name_extra' JSON string object about name
 *    new   - object that needs sgj_free_unattached() if not attached
 *
 *    */

/* If jsp in non-NULL and jsp->pr_as_json is true then this call is ignored
 * unless jsp->pr_out_hrp is true. Otherwise this function prints to stdout
 * like printf(fmt, ...); note that no LF is added. In the jsp->pr_out_hrp is
 * true case, nothing is printed to stdout but instead is placed into a JSON
 * array (jsp->out_hrp) after some preprocessing. That preprocessing involves
 * removing a leading LF from 'fmt' (if present) and up to two trailing LF
 * characters. */
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
 * to be returned is placed in jsp->basep. If jsp->pr_leadin is true and
 * util_name is non-NULL then a "utility_invoked" JSON object is made with
 * "name", and "version_date" object fields. If the jsp->pr_out_hr field is
 * true a named array called "plain_text_output" is added to the
 * "utility_invoked" object  (creating it in the case when jsp->pr_leadin is
 * false) and a pointer to that array object is placed in jsp->objectp . The
 * returned pointer is not usually needed but if it is NULL then a heap
 * allocation has failed. */
sgj_opaque_p sgj_start_r(const char * util_name, const char * ver_str,
                         int argc, char *argv[], sgj_state * jsp);

/* These are low level functions returning a pointer to a newly created JSON
 * object or array. If jsp is NULL or jsp->pr_as_json is false nothing happens
 * and NULL is returned. Note that this JSON object is _not_ placed in the
 * in-core tree controlled by jsp (jsp->basep); it may be added later as the
 * fourth argument to sgj_js_nv_o(), for example. */
sgj_opaque_p sgj_new_unattached_object_r(sgj_state * jsp);
sgj_opaque_p sgj_new_unattached_array_r(sgj_state * jsp);

/* following are similar, useful for leaves */
sgj_opaque_p sgj_new_unattached_string_r(sgj_state * jsp, const char * value);
sgj_opaque_p sgj_new_unattached_str_len_r(sgj_state * jsp, const char * value,
                                          int vlen);
sgj_opaque_p sgj_new_unattached_integer_r(sgj_state * jsp, uint64_t value);
sgj_opaque_p sgj_new_unattached_bool_r(sgj_state * jsp, bool value);
sgj_opaque_p sgj_new_unattached_null_r(sgj_state * jsp);

/* If jsp is NULL or jsp->pr_as_json is false nothing happens and NULL is
 * returned. Otherwise it creates a new named object (whose name is what
 * 'sn_name' points to) at 'jop' with an empty object as its value; a pointer
 * to that empty object is returned. If 'jop' is NULL then jsp->basep is
 * used instead. The returned value should always be checked (for NULL)
 * and if not, used. */
sgj_opaque_p sgj_named_subobject_r(sgj_state * jsp, sgj_opaque_p jop,
                                   const char * sn_name);
sgj_opaque_p sgj_snake_named_subobject_r(sgj_state * jsp, sgj_opaque_p jop,
                                         const char * conv2sname);

/* If jsp is NULL or jsp->pr_as_json is false nothing happens and NULL is
 * returned. Otherwise it creates a new named object (whose name is what
 * 'sn_name' points to) at 'jop' with an empty array as its value; a pointer
 * to that empty array is returned.  If 'jop' is NULL then jsp->basep is
 * used instead. The returned value should always * be checked (for NULL)
 * and if not, used. */
sgj_opaque_p sgj_named_subarray_r(sgj_state * jsp, sgj_opaque_p jop,
                                  const char * sn_name);
sgj_opaque_p sgj_snake_named_subarray_r(sgj_state * jsp, sgj_opaque_p jop,
                                        const char * conv2sname);

/* If either jsp or value is NULL or jsp->pr_as_json is false then nothing
 * happens and NULL is returned. The insertion point is at jop but if it is
 * NULL jsp->basep is used. If 'sn_name' is non-NULL a new named JSON object
 * is added using 'sn_name' and the associated value is a JSON string formed
 * from 'value'. If 'name' is NULL then 'jop' is assumed to be a JSON array
 * and a JSON string formed from 'value' is added. Note that the
 * jsp->pr_string setting is ignored by this function. If successful returns
 * a pointer to the newly formed JSON string. */
sgj_opaque_p sgj_js_nv_s(sgj_state * jsp, sgj_opaque_p jop,
                         const char * sn_name, const char * value);
sgj_opaque_p sgj_js_nv_s_len(sgj_state * jsp, sgj_opaque_p jop,
                             const char * sn_name,
                             const char * value, int vlen);

/* This variant checks 'value' for characters that are not permitted in JSON
 * strings and takes appropriate actions. See sgj_conv2json_string() below. */
sgj_opaque_p sgj_js_nv_s_len_chk(sgj_state * jsp, sgj_opaque_p jop,
                                 const char * sn_name,
                                 const uint8_t * value, int vlen);

/* If either jsp is NULL or jsp->pr_as_json is false then nothing happens and
 * NULL is returned. The insertion point is at jop but if it is NULL
 * jsp->basep is used. If 'sn_name' is non-NULL a new named JSON object is
 * added using 'sn_name' and the associated value is a JSON integer formed
 * from 'value'. If 'sn_name' is NULL then 'jop' is assumed to be a JSON array
 * and a JSON integer formed from 'value' is added. If successful returns a
 * a pointer newly formed JSON integer. */
sgj_opaque_p sgj_js_nv_i(sgj_state * jsp, sgj_opaque_p jop,
                         const char * sn_name, int64_t value);

/* If either jsp is NULL or jsp->pr_as_json is false then nothing happens and
 * NULL is returned. The insertion point is at jop but if it is NULL
 * jsp->basep is used. If 'sn_name' is non-NULL a new named JSON object is
 * added using 'sn_name' and the associated value is a JSON boolean formed
 * from 'value'. If 'name' is NULL then 'jop' is assumed to be a JSON array
 * and a JSON boolean formed from 'value' is added. If successful returns a
 * a pointer newly formed JSON boolean. */
sgj_opaque_p sgj_js_nv_b(sgj_state * jsp, sgj_opaque_p jop,
                         const char * sn_name, bool value);

/* If jsp is NULL, jsp->pr_as_json is false or ua_jop is NULL nothing then
 * happens and NULL is returned. 'jop' is the insertion point but if it is
 * NULL jsp->basep is used instead. If 'sn_name' is non-NULL a new named JSON
 * object is added using 'sn_name' and the associated value is ua_jop. If
 * 'sn_name' is NULL then 'jop' is assumed to be a JSON array and ua_jop is
 * added to it. If successful returns ua_jop . The "ua_" prefix stands for
 * unattached. That should be the case before invocation and it will be
 * attached to jop after a successful invocation. This means that ua_jop
 * must have been created by sgj_new_unattached_object_r() or similar. */
sgj_opaque_p sgj_js_nv_o(sgj_state * jsp, sgj_opaque_p jop,
                         const char * sn_name, sgj_opaque_p ua_jop);

/* This function only produces JSON output if jsp is non-NULL and
 * jsp->pr_as_json is true. It adds a named object at 'jop' (or jop->basep
 * if jop is NULL) along with a value. If jsp->pr_hex is true then that
 * value is two sub-objects, one named 'i' with a 'value' as a JSON integer,
 * the other one named 'hex' with 'value' rendered as hex in a JSON string.
 * If jsp->pr_hex is false then there are no sub-objects and the 'value' is
 * rendered as JSON integer. */
void sgj_js_nv_ihex(sgj_state * jsp, sgj_opaque_p jop,
                    const char * sn_name, uint64_t value);

/* This function only produces JSON output if jsp is non-NULL and
 * jsp->pr_as_json is true. It adds a named object at 'jop' (or jop->basep
 * if jop is NULL) along with a value. If jsp->pr_string is true then that
 * value is two sub-objects, one named 'i' with a 'val_i' as a JSON integer,
 * the other one named str_name with val_s rendered as a JSON string. If
 * str_name is NULL then "meaning" will be used. If jsp->pr_string is false
 * then there are no sub-objects and the 'val_i' is rendered as a JSON
 * integer. */
void sgj_js_nv_istr(sgj_state * jsp, sgj_opaque_p jop,
                    const char * sn_name, int64_t val_i,
                    const char * str_name, const char * val_s);

/* Similar to sgj_js_nv_istr(). The hex output is conditional jsp->pr_hex . */
void sgj_js_nv_ihexstr(sgj_state * jsp, sgj_opaque_p jop,
                       const char * sn_name, int64_t val_i,
                       const char * str_name, const char * val_s);

/* This function only produces JSON output if jsp && jsp->pr_as_json is true.
 * It adds a named object at 'jop' (or jop->basep if jop is NULL) along with
 * a value. If jsp->pr_name_ex is true then that value has two sub-objects,
 * one named 'i' with a 'val_i' as a JSON integer, the other one named
 * "name_extra" with value nex_s rendered as a JSON string. If jsp->pr_hex
 * and 'hex_as_well' are true, then a sub-object named 'hex' with a value
 * rendered as a hex string equal to val_i. If jsp->pr_name_ex is false and
 * either jsp->pr_hex or hex_as_well are false then there are no sub-objects
 * and the 'val_i' is rendered as a JSON  integer. */
void sgj_js_nv_ihex_nex(sgj_state * jsp, sgj_opaque_p jop,
                        const char * sn_name, int64_t val_i, bool hex_as_well,
                        const char * nex_s);

void sgj_js_nv_ihexstr_nex(sgj_state * jsp, sgj_opaque_p jop,
                           const char * sn_name, int64_t val_i,
                           bool hex_as_well, const char * str_name,
                           const char * val_s, const char * nex_s);

/* String value version of above *_nex() functions. If both 'val_s' and
 * 'nex_s' are non-NULL forms sub-object named 'sn_name' with the names
 * "s" and "name_extra" and values of the last two arguments. If one of
 * the last two arguments is NULL similar to sgj_js_nv_s() using the non-NULL
 * argument as the value. */
void sgj_js_nv_s_nex(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                     const char * val_s, const char * nex_s);

/* Add named field whose value is a (large) JSON string made up of num_bytes
 * ASCII hexadecimal bytes (each two hex digits separated by a space) starting
 * at byte_arr. The heap is used for intermediate storage so num_bytes can
 * be arbitrarily large. */
void sgj_js_nv_hex_bytes(sgj_state * jsp, sgj_opaque_p jop,
                         const char * sn_name, const uint8_t * byte_arr,
                         int num_bytes);

/* The '_haj_' refers to generating output both for human readable and/or
 * JSON with a single invocation. If jsp is non-NULL and jsp->pr_out_hr is
 * true then both JSON and plain text output is formed (and the latter is
 * placed in the jsp->out_hrp JSON array). The plain text form will have
 * leadin_sp spaces followed by 'name' then a separator, then 'value' with a
 * trailing LF. If 'name' is NULL then it and the separator are ignored. If
 * there is JSON output, then leadin_sp and sep are ignored. If 'jop' is NULL
 * then basep->basep is used. If 'name' is NULL then a JSON string object,
 * made from 'value' is added to the JSON array pointed to by 'jop'.
 * Otherwise a 'name'-d JSON object whose value is a JSON string object made
 * from 'value' is added at 'jop'. */
void sgj_haj_vs(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep,
                const char * value);

/* Similar to sgj_haj_vs()'s description with 'JSON string object'
 * replaced by 'JSON integer object'. hex_haj when set will cause the value
 * to be output in <0x%x> form (default is a signed decimal 64 bit integer)
 * in the plain text rendering. For JSON output hex_haj has the same
 * effect as hex_as_well.  */
void sgj_haj_vi(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep,
                int64_t value, bool hex_haj);
void sgj_haj_vistr(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                   const char * name, enum sgj_separator_t sep,
                   int64_t value, bool hex_haj, const char * val_s);

/* The '_nex' refers to a "name_extra" (information) sub-object (a JSON
 * string) which explains a bit more about the 'name' entry. This is useful
 * when T10 specifies the name as an abbreviation (e.g. SYSV). Whether this
 * sub-object is shown in the JSON output is controlled by the 'n' control
 * character. */
void sgj_haj_vi_nex(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                    const char * name, enum sgj_separator_t sep,
                    int64_t value, bool hex_haj, const char * nex_s);
void sgj_haj_vistr_nex(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                       const char * name, enum sgj_separator_t sep,
                       int64_t value, bool hex_haj,
                       const char * val_s, const char * nex_s);

/* Similar to above '_haj_' calls but a named sub-object is always formed
 * containing a JSON integer object named "i" whose value is 'value'. The
 * returned pointer is to that sub-object. */
sgj_opaque_p sgj_haj_subo_r(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                            const char * name, enum sgj_separator_t sep,
                            int64_t value, bool hex_haj);

/* Similar to sgj_haj_vs()'s description with 'JSON string object' replaced
 * by 'JSON boolean object'. */
void sgj_haj_vb(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep, bool value);

/* Breaks up the string pointed to by 'sp' into lines and adds them to the
 * jsp->out_hrp array. Treat '\n' in sp as line breaks. Consumes characters
 * from sp until either a '\0' is found or slen is exhausted. Add each line
 * to jsp->out_hrp JSON array (if conditions met). Outputs to stdout. */
void sgj_hr_str_out(sgj_state * jsp, const char * sp, int slen);

/* Nothing in the in-core JSON tree is actually printed to 'fp' (typically
 * stdout) until this call is made. If jsp is NULL, jsp->pr_as_json is false
 * or jsp->basep is NULL then this function does nothing. If jsp->exit_status
 * is true then a new JSON object named "exit_status" and the 'exit_status'
 * value rendered as a JSON integer is appended to jsp->basep. The in-core
 * JSON tree with jsp->basep as its root is streamed to 'fp'. */
void sgj_js2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status,
                 FILE * fp);

/* This function is only needed if the pointer returned from either
 * sgj_new_unattached_object_r() or sgj_new_unattached_array_r() has not
 * been attached into the in-core JSON tree whose root is jsp->basep . */
void sgj_free_unattached(sgj_opaque_p jop);

/* If jsp is NULL or jsp->basep is NULL then this function does nothing.
 * This function does bottom up, heap freeing of all the in-core JSON
 * objects and arrays attached to the root JSON object assumed to be
 * found at jsp->basep . After this call jsp->basep, jsp->out_hrp and
 * jsp->userp will all be set to NULL.  */
void sgj_finish(sgj_state * jsp);

/* Forms a string of the JSON command line options help and assumes,
 * if char_if_not_j is zero, that '-j' is the short form of the of
 * the --json[=JO] command line option.  */
char * sg_json_usage(int char_if_not_j, char * b, int blen);

/* Convert a byte stream that is meant to be printable ASCII or UTF-8 to
 * something that is allowable in a JSON string. This means treating the
 * ASCII control characters (i.e. < 0x20) and DEL as specials. Also '\' and
 * '"' need to be escaped with a preceding '\'. These C escape codes are used
 * in JSON: '\b', '\f', '\n', '\r' and '\t'. Other control characters, and DEL
 * are encoded as '\x<hh>' where <hh> is two hex digits. So the DEL and
 * null ACSII characters in the input will appear as '\x7f' and '\x00'
 * respectively in the output. The output serializer will expand those
 * two to '\\x7f' and '\\x00'. Note that the JSON form of '\u<hhhh>' is
 * _not_ used. The input is pointed to by 'cup' which is 'ulen' bytes long.
 * The output is written to 'op' and will not exceed 'olen_max' bytes. If
 * 'olen_max' is breached, this function returns -1 else it returns the
 * number of bytes written to 'op'. */
int sgj_conv2json_string(const uint8_t * cup, int ulen, char * op,
                         int olen_max);

#ifdef __cplusplus
}
#endif

#endif
